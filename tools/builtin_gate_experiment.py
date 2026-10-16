#!/usr/bin/env python3
"""Run a narrow, isolated A/B replay for the gate4 builtin symbol."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Callable, Sequence
from unittest.mock import patch

_FORENSIC_SPEC = importlib.util.spec_from_file_location(
    "_builtin_gate_layout_codegen_forensics", Path(__file__).with_name("layout_codegen_forensics.py"))
if _FORENSIC_SPEC is None or _FORENSIC_SPEC.loader is None:
    raise ImportError("layout codegen forensic helpers are unavailable")
forensic = importlib.util.module_from_spec(_FORENSIC_SPEC)
_FORENSIC_SPEC.loader.exec_module(forensic)

SYMBOL = "_ZL26builtin_define_type_minmaxPKcS0_P9tree_node"
SOURCE = "c-family/c-cppbuiltin.cc"
SCHEMA = "chimera-builtin-gate-experiment-v1"
POLICY = "assume-scalar-independent"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _same_path(left: str | Path, right: str | Path) -> bool:
    return os.path.normcase(str(Path(left).resolve())) == os.path.normcase(str(Path(right).resolve()))


def _has_exact_function_header(dump: str) -> bool:
    return sum(1 for line in dump.splitlines()
               if (match := forensic.FUNC_RE.match(line)) and match.group(2) == SYMBOL) == 1


def validate_collection(collection: dict[str, Any], collection_path: Path) -> dict[str, Any]:
    """Validate collected bindings and return normalized paths and explicit caveats."""
    if collection.get("schema") != "chimera-builtin-gate-inputs-v1" or collection.get("symbol") != SYMBOL:
        raise ValueError("collection schema or exact target symbol does not match")
    entries = collection.get("logged_compile_entries")
    if entries is not None and (not isinstance(entries, list) or len(entries) != 1):
        raise ValueError("logged compile entry must be unique")
    entry = collection.get("logged_compile_entry")
    if not isinstance(entry, dict) or not entry.get("argv") or not entry.get("cwd"):
        raise ValueError("unique logged compile argv and cwd are unavailable")
    argv = entry["argv"]
    if len(argv) < 2:
        raise ValueError("logged compile argv is incomplete")
    if argv.count("-c") != 1:
        raise ValueError("logged argv must contain exactly one compile-only flag")
    sources = [token for token in argv if Path(token.replace("\\", "/")).as_posix().endswith(SOURCE)]
    if len(sources) != 1:
        raise ValueError("logged compile command does not uniquely name the source")
    source = Path(entry.get("source", sources[0]))
    cwd = Path(entry["cwd"]).resolve()
    if not source.is_absolute():
        source = cwd / source
    source = source.resolve()
    argv_source = Path(sources[0])
    if not argv_source.is_absolute():
        argv_source = cwd / argv_source
    if source != argv_source.resolve():
        raise ValueError("logged compile source path disagrees with command argv")
    if entry.get("raw_line") and entry.get("raw_line_sha256") != hashlib.sha256(
            entry["raw_line"].encode()).hexdigest():
        raise ValueError("logged command line hash mismatch")

    object_row = collection.get("object") or {}
    obj = Path(object_row.get("path", ""))
    if not obj.is_file() or not object_row.get("sha256") or sha256(obj) != object_row["sha256"]:
        raise ValueError("collected object hash is missing or differs")
    source_rows = [row for row in collection.get("current", {}).get("source_candidates", [])
                   if _same_path(row.get("path", ""), source)]
    if len(source_rows) != 1 or not source.is_file() or sha256(source) != source_rows[0].get("sha256"):
        raise ValueError("logged source identity is missing, ambiguous, or changed")
    cu_matches = []
    for cu in collection.get("dwarf_compile_units", []):
        cu_name = Path(cu.get("name", ""))
        cu_dir = Path(cu.get("comp_dir", ""))
        if not cu_name.is_absolute():
            cu_name = cu_dir / cu_name
        if _same_path(cu_name, source) and _same_path(cu_dir, cwd):
            cu_matches.append(cu)
    if len(cu_matches) != 1:
        raise ValueError("DWARF source and comp_dir do not uniquely match logged compile")
    wrappers = collection.get("historical_wrapper_candidates", [])
    wrapper_matches = [row for row in wrappers if Path(row.get("path", "")).name == "gate4-cxx"]
    if len(wrapper_matches) != 1:
        raise ValueError("archived wrapper copy identity is missing or ambiguous")
    decision = collection.get("historical", {}).get("decision", {})
    decision_path = Path(decision.get("path", ""))
    decision_bound = bool(decision_path.is_file() and decision.get("sha256")
                          and sha256(decision_path) == decision["sha256"])
    wrapper_path = Path(wrapper_matches[0].get("path", ""))
    wrapper_bound = bool(wrapper_path.is_file() and wrapper_matches[0].get("sha256")
                         and sha256(wrapper_path) == wrapper_matches[0]["sha256"])
    archive_copy = collection.get("archived_wrapper_copy", {})
    if archive_copy:
        archive_copy_path = Path(archive_copy.get("path", ""))
        archive_copy_bound = bool(archive_copy_path.is_file() and archive_copy.get("sha256")
                                  and sha256(archive_copy_path) == archive_copy["sha256"]
                                  and archive_copy["sha256"] == wrapper_matches[0].get("sha256"))
    else:
        # Older collections used the archived wrapper path itself as the retained copy.
        archive_copy_path, archive_copy_bound = wrapper_path, wrapper_bound
    if not _same_path(argv[0], wrapper_path):
        raise ValueError("logged argv[0] does not exactly identify archived wrapper path")
    history = collection.get("historical", {})
    if history.get("valid") and decision_bound and wrapper_bound and archive_copy_bound:
        historical_identity = "historical-gate4-elf-and-decision-validated; compiler-plugin-and-object-bindings-incomplete"
    else:
        historical_identity = "incomplete-current-controlled-replay"
    build_log = Path(collection.get("build_log", {}).get("path", ""))
    build_log_bound = bool(build_log.is_file() and collection.get("build_log", {}).get("sha256")
                           and sha256(build_log) == collection["build_log"]["sha256"])
    if not build_log_bound:
        raise ValueError("build log is missing or its hash differs from collection")
    input_spec = importlib.util.spec_from_file_location(
        "_builtin_gate_inputs_for_binding", Path(__file__).with_name("builtin_gate_inputs.py"))
    if input_spec is None or input_spec.loader is None:
        raise ValueError("cannot load compile-log evidence parser")
    inputs = importlib.util.module_from_spec(input_spec)
    input_spec.loader.exec_module(inputs)
    with build_log.open(encoding="utf-8", errors="replace") as stream:
        logged_again = inputs.find_compile(stream)
    if (logged_again["argv"] != argv or not _same_path(logged_again["cwd"], cwd)
            or logged_again["line_number"] != entry.get("line_number")
            or logged_again["raw_line_sha256"] != entry.get("raw_line_sha256")):
        raise ValueError("parsed build log entry differs from collected argv/cwd/line binding")
    if not decision_bound or not wrapper_bound or not archive_copy_bound:
        raise ValueError("historical decision or archived wrapper/archive copy byte hash differs from collection")
    return {"entry": entry, "argv": list(argv), "cwd": cwd, "source": source, "object": obj,
            "decision_path": decision_path, "decision_bound": decision_bound,
            "wrapper_path": wrapper_path, "wrapper_bound": wrapper_bound,
            "archive_copy_path": archive_copy_path, "archive_copy_bound": archive_copy_bound,
            "historical_identity": historical_identity,
            "build_log_bound": build_log_bound,
            "collection_path": collection_path.resolve()}


class _CompileIntercept(BaseException):
    def __init__(self, argv: Sequence[str], kwargs: dict[str, Any]):
        self.argv = list(argv)
        self.kwargs = kwargs


def load_installed_wrapper() -> Callable:
    """Import only the currently installed chimera package, never repo cli/ sources."""
    spec = importlib.util.find_spec("chimera")
    if spec is None or not spec.submodule_search_locations:
        raise RuntimeError("installed chimera package is not available on this Python environment")
    package_root = Path(next(iter(spec.submodule_search_locations))).resolve()
    repo_cli = (Path(__file__).resolve().parent.parent / "cli" / "chimera").resolve()
    if _same_path(package_root, repo_cli):
        raise RuntimeError("refusing to load the wrapper from the repository cli source")
    prefix = Path(sys.prefix).resolve()
    if not package_root.is_relative_to(prefix):
        raise RuntimeError("installed chimera package is outside the active Python environment")
    from chimera.llvm_wrapper import run_llvm_wrapper  # type: ignore[import-not-found]
    return run_llvm_wrapper


def capture_current_wrapper(out: Path, params: Sequence[str], decision_bytes: bytes | str,
                            *, wrapper: Callable | None = None,
                            expected_compiler: Path | None = None) -> dict[str, Any]:
    """Expand installed wrapper argv, interrupting exactly before the compiler call."""
    out = out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    decision_path = out / "decision-A.json"
    decision_path.write_bytes(decision_bytes.encode() if isinstance(decision_bytes, str) else decision_bytes)
    registry = out / "elf-registry.json"
    args = SimpleNamespace(cxx=True, list_path=str(decision_path), no_gate=False,
                           llvm_params=list(params), registry=str(registry))
    invoke = wrapper or load_installed_wrapper()
    captured: list[dict[str, Any]] = []
    original_run = subprocess.run

    def intercept(command, *positional, **kwargs):
        if isinstance(command, (str, bytes)) or not command:
            raise RuntimeError("wrapper attempted a non-compiler subprocess")
        argv = [str(item) for item in command]
        first = Path(argv[0])
        if first.name.lower() not in {"clang++", "clang++.exe"}:
            raise RuntimeError("wrapper attempted a non-compiler subprocess")
        if expected_compiler is not None and not _same_path(first, expected_compiler):
            raise RuntimeError("wrapper compiler target differs from supplied current compiler")
        captured.append({"argv": argv, "kwargs": kwargs})
        if len(captured) > 1:
            raise RuntimeError("wrapper attempted multiple compiler subprocesses")
        raise _CompileIntercept(argv, kwargs)

    try:
        with patch.object(subprocess, "run", side_effect=intercept):
            try:
                invoke(args)
            except _CompileIntercept:
                pass
    except Exception as exc:
        raise RuntimeError(f"current wrapper expansion failed: {exc}") from exc
    finally:
        # The wrapper only receives paths rooted under OUT. Restore run before returning.
        subprocess.run = original_run
    if len(captured) != 1:
        raise RuntimeError(f"expected one compiler invocation, captured {len(captured)}")
    argv = captured[0]["argv"]
    if not argv or Path(argv[0]).name.lower() not in {"clang++", "clang++.exe"}:
        raise RuntimeError("captured invocation did not preserve clang++")
    resolved = Path(argv[0]).resolve()
    return {"status": "captured", "expanded_argv": argv, "compiler_invocation": argv[0],
            "compiler_resolved_path": str(resolved),
            "compiler_sha256": sha256(resolved) if resolved.is_file() else None,
            "decision_path": str(decision_path), "decision_sha256": sha256(decision_path),
            "registry_path": str(registry)}


def _compiler_and_plugins(argv: Sequence[str], cwd: Path,
                          current: dict[str, Any]) -> tuple[Path, list[dict[str, Any]]]:
    compiler = Path(argv[0]).resolve()
    compiler_row = current.get("compiler") or {}
    if not compiler.is_file() or not compiler_row.get("sha256") or sha256(compiler) != compiler_row["sha256"]:
        raise ValueError("expanded current compiler hash differs from collection")
    plugins = forensic._plugin_identities(argv[1:], cwd)
    expected = current.get("plugins", [])
    if len(plugins) != len(expected) or not plugins:
        raise ValueError("expanded current plugin order/count differs from collection")
    for got, wanted in zip(plugins, expected):
        if not _same_path(got.get("path", ""), wanted.get("path", "")) or got.get("sha256") != wanted.get("sha256"):
            raise ValueError("expanded current plugin path/hash/order differs from collection")
    return compiler, plugins


def _decision_variant(original: Path, target: str, destination: Path) -> dict[str, Any]:
    document = json.loads(original.read_text(encoding="utf-8"))
    root = document.get("decision", document)
    gate = root.get("gate") if isinstance(root, dict) else None
    if not isinstance(gate, dict) or not isinstance(gate.get("names"), list):
        raise ValueError("historical decision lacks gate.names")
    names = list(gate["names"])
    if target in names:
        raise ValueError("target symbol is already present in original gate decision")
    gate["names"] = sorted([*names, target])
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(document, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    resulting = json.loads(destination.read_text(encoding="utf-8"))
    after = (resulting.get("decision", resulting).get("gate") or {}).get("names", [])
    if set(after) - set(names) != {target} or set(names) - set(after):
        raise ValueError("B decision differs from A by more than the exact target symbol")
    return {"A_count": len(names), "B_count": len(after), "target": target,
            "target_absent_in_A": True, "only_change": target}


def _run_group(label: str, decision: Path, expanded: Sequence[str], cwd: Path,
               out: Path, objdump: str, readelf: str) -> dict[str, Any]:
    group_dir = out / f"group-{label}"
    group_dir.mkdir(parents=True, exist_ok=True)
    env = forensic.prepare_replay_environment("gate2", decision, group_dir / "plugin-environment", os.environ)
    record = {"directory": str(cwd), "arguments": list(expanded),
              "file": next((x for x in expanded if Path(x).as_posix().endswith(SOURCE)), "")}
    compiler = Path(expanded[0])
    pass_result = forensic._execute_compile_pass(record, group_dir / "baseline", cwd,
        compiler, (), "baseline", env, Path(env["CHIMERA_GATE_LIST"]))
    obj = group_dir / "baseline" / "replay.o"
    group: dict[str, Any] = {"label": label, "decision": str(decision),
        "decision_sha256": sha256(decision), "gate_names_count": len(forensic._decision_gate_names(decision)),
        "target_in_gate_names": SYMBOL in forensic._decision_gate_names(decision),
        "compile": pass_result, "object": str(obj), "object_exists": obj.is_file(),
        "artifacts_directory": str(group_dir)}
    if not obj.is_file():
        group.update(object_coordinates=[], vector_evidence=forensic.vector_evidence(""),
                     function_inspected=False,
                     metadata_section={"status": "unknown", "records": []})
        group["census"] = {"actions": [], "gaps": ["census-file-not-produced"]}
        group["local_source"] = {"status": "incomplete", "gaps": ["group-object-missing"], "facts": {}}
        return group
    header_code, htype = forensic._run_capture([readelf, "-h", str(obj)], group_dir / "baseline", "baseline.header")
    match = re.search(r"Type:\s*(\S+)", htype)
    elf_type = match.group(1) if match else "unknown"
    dump_code, dump = forensic._run_capture([objdump, "-drw", f"--disassemble={SYMBOL}", str(obj)],
                                            group_dir / "baseline", "target-function")
    if header_code != 0 or dump_code != 0 or not _has_exact_function_header(dump) or not match or match.group(1) != "REL":
        group.update(object_coordinates=[], vector_evidence=forensic.vector_evidence(""),
                     function_inspected=False,
                     metadata_section={"status": "unknown", "records": []},
                     census={"actions": [], "gaps": ["target-function-or-object-header-inspection-failed"]},
                     local_source={"status": "incomplete", "facts": {},
                                   "gaps": ["target-function-or-object-header-inspection-failed"]})
        return group
    group["object_coordinates"] = forensic._object_coordinates(dump, elf_type)
    group["vector_evidence"] = forensic.vector_evidence(dump)
    group["function_inspected"] = bool(group["object_coordinates"])
    stackobj = group_dir / "baseline" / "baseline.object-stackobj-map.json"
    if stackobj.is_file():
        group["metadata_section"] = json.loads(stackobj.read_text(encoding="utf-8"))
    else:
        forensic._read_stackobj_section(obj, stackobj)
        group["metadata_section"] = json.loads(stackobj.read_text(encoding="utf-8"))
    census_path = Path(env["CHIMERA_GATE_STATS"])
    census_text = census_path.read_text(encoding="utf-8", errors="replace") if census_path.is_file() else ""
    group["census"] = forensic.filter_census_rows(census_text, SYMBOL)
    if not census_path.is_file():
        group["census"].setdefault("gaps", []).append("census-file-not-produced")
    group["local_source"] = observe_local_source(obj, group_dir / "local-source", label,
                                                  readelf=readelf, objdump=objdump)
    return group


def observe_local_source(obj: Path, out: Path, label: str, *, readelf: str = "readelf",
                         objdump: str = "objdump") -> dict[str, Any]:
    return forensic.local_source_observation(obj, SYMBOL, out,
        SimpleNamespace(readelf=readelf, objdump=objdump), label,
        unknown_stack_size_policy=POLICY)


def _may_run_b(a: dict[str, Any], comparison: dict[str, Any]) -> bool:
    return a.get("compile", {}).get("exit_code") == 0 and comparison.get("status") == "matched"


def _b_evidence_ready(group: dict[str, Any]) -> bool:
    return (group.get("compile", {}).get("exit_code") == 0 and group.get("object_exists")
            and group.get("function_inspected"))


def execute_ab(out: Path, a_decision: Path, b_decision: Path, expanded: Sequence[str], cwd: Path,
               objdump: str, readelf: str, original_coordinates: Sequence[dict[str, Any]],
               *, run_group: Callable[..., dict[str, Any]] | None = None) -> dict[str, Any]:
    """Run A, enforce its object correspondence, then optionally run B and assess evidence."""
    run_one = run_group or _run_group
    groups: dict[str, dict[str, Any]] = {}
    a = run_one("A", a_decision, expanded, cwd, out, objdump, readelf)
    groups["A"] = a
    comparison = forensic.compare_object_coordinates(original_coordinates, a.get("object_coordinates", []))
    a["baseline_object_comparison"] = comparison
    result: dict[str, Any] = {"groups": groups, "A_comparison": comparison,
                              "status": "stopped-before-B"}
    if not _may_run_b(a, comparison):
        result["stopped_reason"] = ("A compile failed" if a.get("compile", {}).get("exit_code") != 0
                                    else "A target instruction/relocation coordinates differ from collected object")
        result["gaps"] = ["A failed or did not match original object; B was not created"]
        return result
    decision_change = _decision_variant(a_decision, SYMBOL, b_decision)
    result["decision_change"] = decision_change
    b = run_one("B", b_decision, expanded, cwd, out, objdump, readelf)
    groups["B"] = b
    vector_ready = _b_evidence_ready(b)
    local_delta = forensic.compare_local_sources(a.get("local_source", {}), b.get("local_source", {}))
    ready = vector_ready and local_delta.get("status") == "complete"
    result["status"] = "completed" if ready else "B-incomplete-unproven"
    result["vector_delta"] = forensic.classify_vector_delta(
        a.get("vector_evidence", {}), b.get("vector_evidence", {}), evidence_ready=vector_ready)
    result["local_source_delta"] = local_delta
    result["vector_evidence_gaps"] = {label: forensic._vector_evidence_gaps(group)
                                      for label, group in groups.items()}
    if not ready:
        reasons = []
        if not vector_ready:
            reasons.append("B failed or target function was not inspected")
        if local_delta.get("status") != "complete":
            reasons.append("A or B local CFG/source analysis is incomplete")
        result["gaps"] = reasons
        result["fully_eliminated"] = None
    else:
        facts = b.get("local_source", {}).get("facts", {})
        local_delta = result["local_source_delta"]
        markers_absent = all(not row.get("present_in_b")
                             for row in local_delta.get("marker_groups", {}).values())
        no_object_call_sites = not facts.get("local_call_sites_carrying_objects", [])
        result["fully_eliminated"] = bool(
            b.get("function_inspected")
            and b.get("vector_evidence", {}).get("vector_instruction_count") == 0
            and local_delta.get("status") == "complete"
            and markers_absent and no_object_call_sites)
        reasons = []
        if b.get("vector_evidence", {}).get("vector_instruction_count") != 0:
            reasons.append("vector instructions remain in B")
        if not markers_absent:
            reasons.append("local stack source markers remain in B")
        if not no_object_call_sites:
            reasons.append("local call sites still carry stack objects in B")
        result["gaps"] = reasons
    return result


def _write_report(path: Path, result: dict[str, Any]) -> None:
    lines = ["# Builtin gate A/B experiment", "",
             "This is a controlled compile replay. Historical compiler and plugin identities may remain unbound.", "",
             f"Status: `{result.get('status')}`; policy: `{result.get('policy')}`.",
             f"Decision size: {result.get('decision_change', {}).get('A_count', 'unknown')} → "
             f"{result.get('decision_change', {}).get('B_count', 'unknown')} names.",
             f"Fully eliminated: `{result.get('fully_eliminated', None)}`.", ""]
    for label, group in result.get("groups", {}).items():
        lines.append(f"- Group {label}: compile exit={group.get('compile', {}).get('exit_code')}; "
                     f"vector instructions={group.get('vector_evidence', {}).get('vector_instruction_count', 0)}; "
                     f"local source={group.get('local_source', {}).get('status', 'incomplete')}.")
    lines.extend(["", "## Gaps", ""])
    lines.extend(f"- {gap}" for gap in result.get("gaps", []))
    if result.get("vector_delta"):
        lines.extend(["", "## Vector evidence", "",
                      json.dumps(result["vector_delta"], sort_keys=True)])
    if result.get("local_source_delta"):
        lines.extend(["", "## Local source evidence", "",
                      json.dumps(result["local_source_delta"], sort_keys=True)])
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def run(args: argparse.Namespace) -> int:
    out = args.out.resolve()
    if out.exists() and (not out.is_dir() or any(out.iterdir())):
        raise ValueError("output directory must be fresh and empty")
    out.mkdir(parents=True, exist_ok=True)
    result: dict[str, Any] = {"schema": SCHEMA, "target_symbol": SYMBOL,
                              "policy": args.policy, "status": "failed", "groups": {}, "gaps": []}
    try:
        collection_path = args.collection.resolve()
        collection = json.loads(collection_path.read_text(encoding="utf-8"))
        binding = validate_collection(collection, collection_path)
        result["binding"] = {key: str(value) if isinstance(value, Path) else value
                             for key, value in binding.items() if key not in {"entry", "argv"}}
        result["gaps"].append("historical compiler/plugin identities are unavailable; conclusions apply to current controlled replay")
        result["gaps"].append("collected object is not hash-bound as an input to the historical gate4 link")
        if not binding["build_log_bound"]:
            result["gaps"].append("build log path/hash could not be revalidated")
        if not binding["decision_bound"] or not binding["wrapper_bound"]:
            result["gaps"].append("historical decision or archived wrapper bytes could not be revalidated")
        history_root = binding["decision_path"].parent
        build_root = Path(collection.get("historical", {}).get("verified_elfs", {}).get("cc1", {}).get("path", "")).parent.parent
        try:
            input_spec = importlib.util.spec_from_file_location(
                "_builtin_gate_inputs", Path(__file__).with_name("builtin_gate_inputs.py"))
            if input_spec is None or input_spec.loader is None:
                raise ImportError("builtin gate input helpers are unavailable")
            inputs = importlib.util.module_from_spec(input_spec)
            input_spec.loader.exec_module(inputs)
            history = inputs.validate_history(history_root, build_root)
        except Exception as exc:
            history = {"valid": False, "gaps": [str(exc)]}
        result["history_validation"] = history
        if not history.get("valid"):
            raise ValueError("historical gate4 ELF/decision validation failed; refusing to compile")
        for key, row in collection.get("historical", {}).get("verified_elfs", {}).items():
            path = Path(row.get("path", ""))
            if not path.is_file() or not row.get("sha256") or sha256(path) != row["sha256"]:
                raise ValueError(f"collected historical {key} ELF hash is unavailable or changed")

        decision = binding["decision_path"]
        raw_decision = decision.read_bytes()
        a_decision = out / "group-A" / "decision.json"
        a_decision.parent.mkdir(parents=True, exist_ok=True)
        a_decision.write_bytes(raw_decision)
        if a_decision.read_bytes() != raw_decision:
            raise ValueError("A decision copy is not byte-identical to collected historical decision")
        if SYMBOL in forensic._decision_gate_names(a_decision):
            raise ValueError("target symbol is already present in the original gate decision")
        captured = capture_current_wrapper(out / "wrapper-capture", binding["argv"][1:],
                                           raw_decision, expected_compiler=Path(collection["current"]["compiler"]["path"]))
        result["wrapper_capture"] = captured
        compiler, plugins = _compiler_and_plugins(captured["expanded_argv"], binding["cwd"], collection["current"])
        result["current_toolchain"] = {"compiler_invocation": captured["compiler_invocation"],
            "compiler_resolved_path": str(compiler), "compiler_sha256": captured["compiler_sha256"],
            "plugins": plugins, "plugin_order": [row["path"] for row in plugins]}

        objdump = shutil.which(args.objdump) or str(Path(args.objdump).resolve())
        readelf = shutil.which(args.readelf) or str(Path(args.readelf).resolve())
        if not Path(objdump).is_file() or not Path(readelf).is_file():
            raise ValueError("objdump and readelf executables must exist")
        original_dump_code, original_dump = forensic._run_capture(
            [objdump, "-drw", f"--disassemble={SYMBOL}", str(binding["object"])],
            out / "original-object", "target-function")
        original_header_code, original_type = forensic._run_capture(
            [readelf, "-h", str(binding["object"])], out / "original-object", "header")
        if original_dump_code != 0 or original_header_code != 0 or not _has_exact_function_header(original_dump):
            raise ValueError("collected object exact target or ELF header could not be inspected")
        type_match = re.search(r"Type:\s*(\S+)", original_type)
        if not type_match or type_match.group(1) != "REL":
            raise ValueError("collected object is not an ET_REL relocatable object")
        original_coordinates = forensic._object_coordinates(original_dump,
            type_match.group(1) if type_match else "unknown")
        result["original_object_coordinates"] = original_coordinates
        ab = execute_ab(out, a_decision, out / "binding" / "decision-B.json",
                        captured["expanded_argv"], binding["cwd"], objdump, readelf,
                        original_coordinates)
        prior_gaps = list(result["gaps"])
        result.update(ab)
        result["gaps"] = [*prior_gaps, *ab.get("gaps", [])]
        result["root_cause_confirmed"] = False
    except Exception as exc:
        result["gaps"].append(f"{type(exc).__name__}: {exc}")
        result.setdefault("root_cause_confirmed", False)
    (out / "result.json").write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    _write_report(out / "report.md", result)
    print(f"builtin gate experiment: {result['status']}; evidence: {out}")
    return 0 if result["status"] == "completed" else 2


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--collection", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--policy", choices=(POLICY,), default=POLICY)
    parser.add_argument("--objdump", required=True)
    parser.add_argument("--readelf", required=True)
    args = parser.parse_args(argv)
    return run(args)


if __name__ == "__main__":
    raise SystemExit(main())
