#!/usr/bin/env python3
"""Create and snapshot an adjacent K3 profile with the opt-in stack-size policy."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import tomllib
from pathlib import Path


POLICY = "assume-scalar-independent"


def scoped_profile_bytes(seed_bytes: bytes) -> bytes:
    """Return a seed profile with only the safety policy added."""

    text = seed_bytes.decode("utf-8")
    document = tomllib.loads(text)
    steps = document.get("profile", {}).get("workflow", {}).get("steps", [])
    safety = [step for step in steps if step.get("step") == "safety"]
    if len(safety) != 1:
        raise ValueError(f"expected one safety step, found {len(safety)}")
    current = safety[0].get("parameters", {}).get("unknown_stack_size_policy")
    if current not in (None, "conservative", POLICY):
        raise ValueError(f"seed has unexpected stack-size policy: {current!r}")

    blocks = list(re.finditer(
        r"(?ms)^\[\[profile\.workflow\.steps\]\]\s*\n(?P<body>.*?)(?=^\[|\Z)",
        text,
    ))
    safety_block = next(
        (
            match
            for match in blocks
            if re.search(r'^step\s*=\s*["\']safety["\']\s*$', match.group("body"), re.M)
        ),
        None,
    )
    if safety_block is None:
        raise ValueError("could not locate safety step in TOML source")
    body = safety_block.group("body")
    parameter = re.search(r"(?m)^(?P<prefix>\s*parameters\s*=\s*\{)(?P<items>[^\n}]*)\}(?P<suffix>\s*)$", body)
    if parameter is None:
        raise ValueError("safety step must have a single-line inline parameters table")
    items = parameter.group("items").rstrip()
    if current == POLICY:
        return seed_bytes
    separator = ", " if items.strip() else ""
    if current == "conservative":
        items = re.sub(
            r'unknown_stack_size_policy\s*=\s*["\']conservative["\']',
            f'unknown_stack_size_policy = "{POLICY}"',
            items,
        )
    else:
        items += separator + f'unknown_stack_size_policy = "{POLICY}"'
    replacement = parameter.group("prefix") + items + "}" + parameter.group("suffix")
    new_body = body[: parameter.start()] + replacement + body[parameter.end() :]
    result = text[: safety_block.start("body")] + new_body + text[safety_block.end("body") :]
    # Parse the generated text before writing it anywhere.
    generated = tomllib.loads(result)
    generated_steps = generated["profile"]["workflow"]["steps"]
    generated_safety = [step for step in generated_steps if step.get("step") == "safety"]
    if generated_safety[0].get("parameters", {}).get("unknown_stack_size_policy") != POLICY:
        raise ValueError("generated profile failed policy validation")
    return result.encode("utf-8")


def write_scoped_profile(seed_profile: Path, target_profile: Path, snapshot_dir: Path) -> dict:
    seed_profile = Path(seed_profile)
    target_profile = Path(target_profile)
    snapshot_dir = Path(snapshot_dir)
    if target_profile.resolve() == seed_profile.resolve():
        raise ValueError("target profile must not overwrite the seed profile")
    seed_bytes = seed_profile.read_bytes()
    scoped_bytes = scoped_profile_bytes(seed_bytes)
    target_profile.parent.mkdir(parents=True, exist_ok=True)
    snapshot_dir.mkdir(parents=True, exist_ok=True)
    with target_profile.open("xb") as stream:
        stream.write(scoped_bytes)
    (snapshot_dir / "profile.seed-v20.snapshot.toml").write_bytes(seed_bytes)
    (snapshot_dir / "profile.scoped.snapshot.toml").write_bytes(scoped_bytes)
    record = {
        "schema": "chimera-unknown-stack-scope-profile-v1",
        "policy": POLICY,
        "seed_profile": str(seed_profile.resolve()),
        "scoped_profile": str(target_profile.resolve()),
        "seed_sha256": hashlib.sha256(seed_bytes).hexdigest(),
        "scoped_sha256": hashlib.sha256(scoped_bytes).hexdigest(),
    }
    (snapshot_dir / "profile-scope.json").write_text(
        json.dumps(record, indent=2) + "\n", encoding="utf-8"
    )
    return record


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seed-profile", required=True, type=Path)
    parser.add_argument("--target-profile", required=True, type=Path)
    parser.add_argument("--snapshot-dir", required=True, type=Path)
    args = parser.parse_args()
    record = write_scoped_profile(args.seed_profile, args.target_profile, args.snapshot_dir)
    print(json.dumps(record, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
