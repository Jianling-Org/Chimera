"""Publish and validate immutable compile plans produced by check-elf."""

from __future__ import annotations

import hashlib
import json
import os
import shlex
from pathlib import Path
from typing import Any


PLAN_SCHEMA = "chimera.rebuild-plan.v1"
DECISION_SCHEMA = "chimera.rebuild-decision.v1"
_HEX = set("0123456789abcdef")


def _json_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":")).encode("utf-8")


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _valid_digest(value: Any) -> bool:
    return (isinstance(value, str) and len(value) == 64
            and all(char in _HEX for char in value))


def _canonical_scope(scope: Any) -> str:
    if not isinstance(scope, dict):
        raise ValueError("check report has invalid check_scope")
    if set(scope) != {"target", "runtime_abi", "checks"}:
        raise ValueError("check report has unsupported check_scope metadata")
    target = scope.get("target")
    if not isinstance(target, dict) or set(target) != {"os", "arch", "extension", "runtime_scene"}:
        raise ValueError("check report has invalid target scope")
    if not isinstance(target, dict) or not all(
        isinstance(target.get(key), str) and target[key]
        for key in ("os", "arch", "extension", "runtime_scene")
    ):
        raise ValueError("check report has invalid target scope")
    abi = scope.get("runtime_abi")
    if isinstance(abi, bool) or not isinstance(abi, int) or abi <= 0:
        raise ValueError("check report has invalid runtime_abi scope")
    checks = scope.get("checks")
    if not isinstance(checks, list) or not checks:
        raise ValueError("check report must contain nonempty check scope")
    normalized = []
    for item in checks:
        if not isinstance(item, dict):
            raise ValueError("check scope contains an invalid check")
        ident, version, parameters = item.get("id"), item.get("version"), item.get("parameters")
        if not isinstance(ident, str) or not ident.strip():
            raise ValueError("check scope contains an invalid check ID")
        if isinstance(version, bool) or not isinstance(version, int) or version <= 0:
            raise ValueError("check scope contains an invalid check version")
        if not isinstance(parameters, dict):
            raise ValueError("check scope contains invalid check parameters")
        normalized.append({"id": ident, "version": version, "parameters": parameters})
    return _json_bytes({"target": target, "runtime_abi": abi, "checks": normalized}).decode("utf-8")


def _check_identity(item: dict) -> tuple[str, int, bytes]:
    return item["id"], item["version"], _json_bytes(item["parameters"])


def _validate_report(path: Path, *, verify_elf: bool = True) -> tuple[dict, bytes, dict]:
    try:
        raw = path.read_bytes()
        doc = json.loads(raw)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot read check report {path}: {exc}") from exc
    if not isinstance(doc, dict) or doc.get("schema") != "chimera.check.v1":
        raise ValueError(f"invalid check report schema: {path}")
    elf = doc.get("elf")
    if not isinstance(elf, dict) or not isinstance(elf.get("path"), str) or not elf["path"]:
        raise ValueError(f"check report has invalid ELF identity: {path}")
    elf_digest = elf.get("content_sha256")
    elf_path = Path(elf["path"])
    if not _valid_digest(elf_digest):
        raise ValueError(f"check report has invalid ELF hash: {path}")
    if verify_elf and (not elf_path.is_file() or _file_sha256(elf_path) != elf_digest):
        raise ValueError(f"check report ELF identity hash does not match: {elf_path}")
    scope = doc.get("check_scope")
    scope_json = _canonical_scope(scope)
    scope_doc = json.loads(scope_json)
    if doc.get("target") != scope_doc["target"] or doc.get("runtime_abi") != scope_doc["runtime_abi"]:
        raise ValueError(f"check report target/runtime ABI disagrees with its scope: {path}")
    scope_checks = scope_doc["checks"]
    actual_checks = doc.get("checks")
    if not isinstance(actual_checks, list) or not actual_checks:
        raise ValueError(f"check report must contain nonempty checks: {path}")
    projected = []
    for item in actual_checks:
        if not isinstance(item, dict):
            raise ValueError(f"check report contains malformed check metadata: {path}")
        ident, version, parameters = item.get("id"), item.get("version"), item.get("parameters")
        if not isinstance(ident, str) or not ident.strip() or isinstance(version, bool) or not isinstance(version, int) or version <= 0 or not isinstance(parameters, dict):
            raise ValueError(f"check report contains malformed check metadata: {path}")
        if not isinstance(item.get("passed"), bool) or not isinstance(item.get("diagnostics"), dict):
            raise ValueError(f"check report contains malformed check result metadata: {path}")
        projected.append({"id": ident, "version": version, "parameters": parameters})
    if sorted(map(_check_identity, projected)) != sorted(map(_check_identity, scope_checks)):
        raise ValueError(f"check report checks disagree with check_scope: {path}")
    expected = _sha256_bytes(_json_bytes({"elf_sha256": elf_digest, "scope": json.loads(scope_json)}))
    if not _valid_digest(doc.get("check_fingerprint")) or doc["check_fingerprint"] != expected:
        raise ValueError(f"check report fingerprint is invalid: {path}")
    decision = doc.get("decision")
    if not isinstance(decision, dict):
        raise ValueError(f"check report has no decision: {path}")
    strategy = decision.get("strategy")
    vector_gate, gate = decision.get("vector_gate"), decision.get("gate")
    if strategy not in {"gate", "svf", "none"}:
        raise ValueError(f"check report has unsupported decision strategy: {path}")
    if (not isinstance(vector_gate, dict) or not isinstance(vector_gate.get("enabled"), bool)
            or not isinstance(gate, dict) or not isinstance(gate.get("enabled"), bool)
            or not isinstance(decision.get("function_pointer_plugin"), bool)
            or not isinstance(decision.get("stack_object_plugin"), bool)
            or not isinstance(gate.get("names"), list)
            or any(not isinstance(name, str) or not name for name in gate["names"])):
        raise ValueError(f"check report has malformed decision metadata: {path}")
    if any(any(char in name for char in ("\n", "\r", "\x00")) for name in gate["names"]):
        raise ValueError(f"check report has invalid gate name: {path}")
    if vector_gate["enabled"] != (strategy == "gate") or gate["enabled"] != (strategy == "gate"):
        raise ValueError(f"check report decision switches disagree with strategy: {path}")
    if strategy == "svf" and not decision["function_pointer_plugin"]:
        raise ValueError(f"check report SVF strategy lacks function-pointer plugin: {path}")
    if strategy != "svf" and decision["function_pointer_plugin"]:
        raise ValueError(f"check report decision has unsupported function-pointer route: {path}")
    if strategy != "gate" and gate["names"]:
        raise ValueError(f"check report non-gate decision contains gate names: {path}")
    return doc, raw, {"elf_sha256": elf_digest, "check_fingerprint": expected,
                      "check_scope": json.loads(scope_json), "scope_json": scope_json}


def _under(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def _ensure_plain_owned_file(plan_dir: Path, relative: str) -> Path:
    if not isinstance(relative, str) or not relative:
        raise ValueError("rebuild plan path must be a nonempty relative path")
    if "\x00" in relative:
        raise ValueError(f"unsafe path in rebuild plan: {relative!r}")
    if any(part in {"", ".", ".."} for part in relative.replace("\\", "/").split("/")):
        raise ValueError(f"unsafe path in rebuild plan: {relative}")
    candidate = Path(relative)
    if candidate.is_absolute() or any(part in {"", ".", ".."} for part in candidate.parts):
        raise ValueError(f"unsafe path in rebuild plan: {relative}")
    current = plan_dir
    for part in candidate.parts:
        current = current / part
        if current.is_symlink():
            raise ValueError(f"symlink path in rebuild plan: {relative}")
    resolved = current.resolve(strict=True)
    if not _under(resolved, plan_dir.resolve(strict=True)) or not resolved.is_file():
        raise ValueError(f"rebuild plan path escapes its directory: {relative}")
    return resolved


def _entry_script(launcher: list[str], plan_dir: Path, *, cxx: bool) -> bytes:
    if not launcher or any(not isinstance(part, str) or not part for part in launcher):
        raise ValueError("launcher must be a nonempty list of nonempty strings")
    command = [*launcher, "llvm", "--build-plan", os.fspath(plan_dir)]
    if cxx:
        command.append("--cxx")
    command.append("--")
    return ("#!/bin/sh\nexec " + shlex.join(command) + ' "$@"\n').encode("utf-8")


def publish_rebuild_plan(output_dir: Path, *, stage: str, profile: Path,
                         reports: list[Path], launcher: list[str]) -> Path:
    """Validate reports and publish an owned, immutable build plan."""
    output_dir, profile = Path(output_dir), Path(profile)
    if stage not in {"metadata", "gate"}:
        raise ValueError(f"unsupported rebuild stage: {stage}")
    if not output_dir.is_dir():
        raise FileNotFoundError(f"rebuild output directory does not exist: {output_dir}")
    output_dir = output_dir.resolve(strict=True)
    owned = [output_dir / name for name in ("cc", "cxx", "decision.json", "build-plan.json")]
    collision = next((path for path in owned if path.exists() or path.is_symlink()), None)
    if collision:
        raise FileExistsError(f"refusing to overwrite existing rebuild output: {collision}")
    if not profile.is_file() or profile.is_symlink():
        raise FileNotFoundError(f"profile does not exist or is not a regular file: {profile}")
    if not reports:
        raise ValueError("at least one check report is required")
    if not launcher or any(not isinstance(part, str) or not part for part in launcher):
        raise ValueError("launcher must be a nonempty list of nonempty strings")
    cc_bytes = _entry_script(launcher, output_dir, cxx=False)
    cxx_bytes = _entry_script(launcher, output_dir, cxx=True)
    profile_bytes = profile.read_bytes()
    if not profile_bytes.strip():
        raise ValueError("profile is empty")
    checked = [_validate_report(Path(report)) for report in reports]
    scope_json = checked[0][2]["scope_json"]
    if any(item[2]["scope_json"] != scope_json for item in checked[1:]):
        raise ValueError("check reports have inconsistent check scopes or versions/parameters")
    if stage == "gate":
        if any(doc["decision"]["strategy"] == "svf"
               or doc["decision"]["function_pointer_plugin"] for doc, _, _ in checked):
            raise ValueError("gate rebuild cannot consume SVF or function-pointer decisions")
        names = sorted({name for doc, _, _ in checked for name in doc["decision"]["gate"]["names"]})
        strategy = "gate" if any(doc["decision"]["strategy"] == "gate" for doc, _, _ in checked) else "none"
        if strategy == "none" and names:
            raise ValueError("none strategy cannot contain gate names")
    else:
        names, strategy = [], "none"
    decision = {
        "strategy": strategy,
        "vector_gate": {"enabled": strategy == "gate", "names_source": "owned-reports"},
        "function_pointer_plugin": False,
        "stack_object_plugin": True,
        "gate": {"enabled": strategy == "gate", "names": names},
    }
    created: list[Path] = []
    try:
        profile_rel = "profile.snapshot.toml"
        profile_target = output_dir / profile_rel
        with profile_target.open("xb") as stream:
            created.append(profile_target)
            stream.write(profile_bytes)

        report_entries = []
        report_root = output_dir / "reports"
        if report_root.is_symlink():
            raise ValueError("reports directory must not be a symlink")
        report_root.mkdir(parents=True, exist_ok=True)
        if not _under(report_root.resolve(strict=True), output_dir.resolve(strict=True)):
            raise ValueError("reports directory escapes rebuild output directory")
        for index, (source, (_, raw, identity)) in enumerate(zip(reports, checked), start=1):
            source = Path(source)
            source_resolved = source.resolve(strict=True)
            try:
                source_resolved.relative_to(report_root.resolve(strict=True))
                reuse = not source.is_symlink() and source_resolved.is_file()
            except ValueError:
                reuse = False
            if reuse:
                report_path = source_resolved
                rel = report_path.relative_to(output_dir).as_posix()
            else:
                safe_name = source.name or "report.json"
                report_path = report_root / f"{index:04d}-{safe_name}"
                if report_path.exists() or report_path.is_symlink():
                    raise FileExistsError(f"refusing to overwrite report snapshot: {report_path}")
                with report_path.open("xb") as stream:
                    created.append(report_path)
                    stream.write(raw)
                rel = report_path.relative_to(output_dir).as_posix()
            report_entries.append({"path": rel, "sha256": _sha256_bytes(raw),
                                   "elf_sha256": identity["elf_sha256"],
                                   "check_fingerprint": identity["check_fingerprint"],
                                   "check_scope": identity["check_scope"]})

        decision_doc = {"schema": DECISION_SCHEMA, "stage": stage, "decision": decision}
        decision_bytes = (json.dumps(decision_doc, indent=2, ensure_ascii=False) + "\n").encode()
        decision_path = output_dir / "decision.json"
        with decision_path.open("xb") as stream:
            created.append(decision_path)
            stream.write(decision_bytes)
        plan = {
            "schema": PLAN_SCHEMA,
            "stage": stage,
            "decision": {"path": "decision.json", "sha256": _sha256_bytes(decision_bytes)},
            "profile": {"path": profile_rel, "sha256": _sha256_bytes(profile_bytes)},
            "reports": report_entries,
        }
        plan_path = output_dir / "build-plan.json"
        plan_bytes = (json.dumps(plan, indent=2, ensure_ascii=False) + "\n").encode()
        with plan_path.open("xb") as stream:
            created.append(plan_path)
            stream.write(plan_bytes)
        for name, script_bytes in (("cc", cc_bytes), ("cxx", cxx_bytes)):
            entry = output_dir / name
            with entry.open("xb") as stream:
                created.append(entry)
                stream.write(script_bytes)
            entry.chmod(0o755)
        return plan_path
    except BaseException:
        for path in reversed(created):
            try:
                path.unlink()
            except OSError:
                pass
        raise


def load_rebuild_plan(directory: Path) -> tuple[dict, Path]:
    """Validate an owned plan and return its fixed decision and decision path."""
    directory = Path(directory).resolve(strict=True)
    if not directory.is_dir():
        raise ValueError(f"rebuild plan is not a directory: {directory}")
    plan_path = _ensure_plain_owned_file(directory, "build-plan.json")
    try:
        plan = json.loads(plan_path.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"invalid rebuild plan: {exc}") from exc
    if not isinstance(plan, dict) or plan.get("schema") != PLAN_SCHEMA:
        raise ValueError("unsupported rebuild plan schema")
    stage = plan.get("stage")
    if stage not in {"metadata", "gate"}:
        raise ValueError("invalid rebuild plan stage")
    decision_entry = plan.get("decision")
    if not isinstance(decision_entry, dict) or not _valid_digest(decision_entry.get("sha256")):
        raise ValueError("invalid rebuild plan decision identity")
    decision_path = _ensure_plain_owned_file(directory, decision_entry.get("path", ""))
    decision_bytes = decision_path.read_bytes()
    if _sha256_bytes(decision_bytes) != decision_entry["sha256"]:
        raise ValueError("owned decision digest does not match build plan")
    try:
        decision_doc = json.loads(decision_bytes)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("owned decision is invalid JSON") from exc
    if (not isinstance(decision_doc, dict) or decision_doc.get("schema") != DECISION_SCHEMA
            or decision_doc.get("stage") != stage or not isinstance(decision_doc.get("decision"), dict)):
        raise ValueError("owned decision schema or stage does not match build plan")
    decision = decision_doc["decision"]
    expected_names = decision.get("gate", {}).get("names") if isinstance(decision.get("gate"), dict) else None
    valid = (decision.get("stack_object_plugin") is True
             and decision.get("function_pointer_plugin") is False
             and isinstance(decision.get("vector_gate"), dict)
             and isinstance(decision.get("gate"), dict)
             and type(decision["vector_gate"].get("enabled")) is bool
             and type(decision["gate"].get("enabled")) is bool
             and isinstance(expected_names, list)
             and all(isinstance(name, str) and name and not any(char in name for char in ("\n", "\r", "\x00")) for name in expected_names))
    if stage == "metadata":
        valid = valid and decision.get("strategy") == "none" and not expected_names and not decision["vector_gate"].get("enabled") and not decision["gate"].get("enabled")
    else:
        valid = valid and decision.get("strategy") in {"gate", "none"} and decision["vector_gate"].get("enabled") == (decision.get("strategy") == "gate") and decision["gate"].get("enabled") == (decision.get("strategy") == "gate") and (decision.get("strategy") == "gate" or not expected_names)
    if not valid:
        raise ValueError("effective decision fields do not match rebuild stage")

    profile = plan.get("profile")
    if (not isinstance(profile, dict) or profile.get("path") != "profile.snapshot.toml"
            or not _valid_digest(profile.get("sha256"))):
        raise ValueError("invalid rebuild plan profile identity")
    profile_path = _ensure_plain_owned_file(directory, profile.get("path", ""))
    if _file_sha256(profile_path) != profile["sha256"]:
        raise ValueError("owned profile digest does not match build plan")
    reports = plan.get("reports")
    if not isinstance(reports, list) or not reports:
        raise ValueError("rebuild plan has no owned reports")
    scope_json = None
    report_recommendations = []
    for entry in reports:
        if not isinstance(entry, dict) or not all(_valid_digest(entry.get(key)) for key in ("sha256", "elf_sha256", "check_fingerprint")):
            raise ValueError("invalid owned report identity")
        report_path = _ensure_plain_owned_file(directory, entry.get("path", ""))
        raw = report_path.read_bytes()
        if _sha256_bytes(raw) != entry["sha256"]:
            raise ValueError("owned report digest does not match build plan")
        doc, _, identity = _validate_report(report_path, verify_elf=False)
        report_recommendations.append((doc["decision"]["strategy"],
                                       tuple(doc["decision"]["gate"]["names"]),
                                       doc["decision"]["function_pointer_plugin"]))
        if identity["elf_sha256"] != entry["elf_sha256"] or identity["check_fingerprint"] != entry["check_fingerprint"]:
            raise ValueError("owned report identity disagrees with build plan")
        current_scope = _canonical_scope(doc.get("check_scope"))
        if current_scope != _json_bytes(entry.get("check_scope")).decode("utf-8"):
            raise ValueError("owned report scope disagrees with build plan")
        if scope_json is None:
            scope_json = current_scope
        elif scope_json != current_scope:
            raise ValueError("owned reports have inconsistent scopes")
        expected = _sha256_bytes(_json_bytes({"elf_sha256": identity["elf_sha256"], "scope": json.loads(current_scope)}))
        if expected != doc.get("check_fingerprint"):
            raise ValueError("owned report fingerprint is invalid")
    if stage == "metadata":
        expected_names, expected_strategy = [], "none"
    else:
        if any(strategy == "svf" or function_pointer
               for strategy, _, function_pointer in report_recommendations):
            raise ValueError("owned reports contain unsupported SVF decision")
        expected_names = sorted({name for _, names, _ in report_recommendations for name in names})
        expected_strategy = "gate" if any(strategy == "gate" for strategy, _, _ in report_recommendations) else "none"
    if decision["strategy"] != expected_strategy or decision["gate"]["names"] != expected_names:
        raise ValueError("effective decision does not match the owned reports")
    return decision, decision_path
