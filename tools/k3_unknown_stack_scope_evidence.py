#!/usr/bin/env python3
"""Validate archived gate4 build evidence without trusting stale live-profile hashes."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _manifest(path: Path) -> dict[str, str]:
    entries: dict[str, str] = {}
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        match = re.match(r"^([0-9a-fA-F]{64})\s+[* ]?(.*)$", line)
        if not match:
            continue
        name = Path(match.group(2)).name
        digest = match.group(1).lower()
        previous = entries.get(name)
        if previous is not None and previous != digest:
            raise ValueError(f"conflicting archived hashes for {name}")
        entries[name] = digest
    return entries


def validate_gate4_history(origin: Path, build_dir: Path, decision: Path | None = None) -> dict:
    origin, build_dir = Path(origin), Path(build_dir)
    build_rc = int((origin / "build.exit.txt").read_text(encoding="utf-8").strip())
    timing = (origin / "build.time.txt").read_text(encoding="utf-8")
    if not re.search(r"(?m)^\s*Exit status:\s*0\s*$", timing):
        raise ValueError("recorded GNU time evidence does not report successful build exit 0")
    elf_entries = _manifest(origin / "elf.sha256")
    verified_elfs = {}
    for name in ("xgcc", "cc1"):
        path = build_dir / "gcc" / name
        expected = elf_entries.get(name)
        if expected is None or _sha256(path) != expected:
            raise ValueError(f"existing {name} binary does not match archived ELF hash")
        verified_elfs[name] = {"path": str(path.resolve()), "sha256": expected}

    decision_path = Path(decision) if decision is not None else origin / "gate4.decision.json"
    historical_inputs = _manifest(origin / "inputs.sha256")
    expected_decision = historical_inputs.get("gate4.decision.json")
    if expected_decision is None or _sha256(decision_path) != expected_decision:
        raise ValueError("gate4 decision does not match its archived input-manifest entry")
    return {
        "schema": "chimera-k3-unknown-stack-scope-history-v1",
        "build_exit_file": build_rc,
        "gnu_time_exit": 0,
        "build_exit_interpretation": "gnu-time-status-authoritative",
        "verified_elfs": verified_elfs,
        "decision": {"path": str(decision_path.resolve()), "sha256": expected_decision},
        "stale_live_profile_hashes_ignored": True,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--origin", required=True, type=Path)
    parser.add_argument("--build-dir", required=True, type=Path)
    parser.add_argument("--decision", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    report = validate_gate4_history(args.origin, args.build_dir, args.decision)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
