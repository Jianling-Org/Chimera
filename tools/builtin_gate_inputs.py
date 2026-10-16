#!/usr/bin/env python3
"""Collect read-only gate4 inputs for the builtin minmax experiment.

Recorded compiler commands are evidence only: this program never executes them.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import shlex
import shutil
import subprocess
import sys
import time
from pathlib import Path

SYMBOL = "_ZL26builtin_define_type_minmaxPKcS0_P9tree_node"
SOURCE = "c-family/c-cppbuiltin.cc"
OUTPUT = "c-family/c-cppbuiltin.o"


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with Path(path).open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def identity(path: Path) -> dict:
    p = Path(path)
    return {"path": str(p.resolve()), "sha256": sha256(p) if p.is_file() else None,
            "provenance": "CURRENT", "exists": p.is_file()}


def validate_history(origin: Path, build: Path) -> dict:
    """Bind gate4 xgcc/cc1 and decision to their archived manifests."""
    result = {"valid": False, "provenance": "HISTORICAL_GATE4", "gaps": []}
    try:
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        from k3_unknown_stack_scope_evidence import validate_gate4_history
        checked = validate_gate4_history(Path(origin), Path(build))
        result.update(valid=True, verified_elfs=checked["verified_elfs"], decision=checked["decision"],
                      build_exit_interpretation=checked["build_exit_interpretation"])
    except Exception as exc:
        result["gaps"].append(str(exc))
    return result


def parse_compile(command: str) -> dict:
    if re.search(r"[;&|<>`$\n\r]", command) or re.search(r"\$\(|\$\{|\\\s", command):
        raise ValueError("shell operators, substitutions, or expansions in recorded command")
    try:
        argv = shlex.split(command, posix=True)
    except ValueError as exc:
        raise ValueError(f"cannot tokenize logged command: {exc}") from exc
    if not argv:
        raise ValueError("empty command")
    srcs = [x for x in argv if x.replace("\\", "/").split("/")[-2:] == SOURCE.split("/")]
    out_indices = [i for i, x in enumerate(argv) if x == "-o"]
    if len(out_indices) != 1 or out_indices[0] + 1 >= len(argv):
        raise ValueError("logged compile lacks a simple -o output")
    output = argv[out_indices[0] + 1]
    if "-c" not in argv:
        raise ValueError("logged command is not a compile-only invocation")
    if len(srcs) != 1 or output.replace("\\", "/") != OUTPUT:
        raise ValueError("logged command does not uniquely compile expected source to expected object")
    return {"argv": argv, "source": srcs[0], "output": output,
            "status": "WRAPPER_OR_DRIVER_ENTRY_UNEXPANDED"}


def find_compile(lines) -> dict:
    """Find the one matching log line and its make directory scope."""
    stack: dict[int, set[str]] = {}
    matches = []
    enter = re.compile(r"make\[(\d+)\]: Entering directory ['`](.+?)['`]")
    leave = re.compile(r"make\[(\d+)\]: Leaving directory ['`](.+?)['`]")
    for n, raw in enumerate(lines, 1):
        line = raw.rstrip("\r\n")
        m = enter.search(line)
        if m:
            level, directory = int(m.group(1)), m.group(2)
            dirs_at_level = stack.setdefault(level, set())
            dirs_at_level.add(directory)
        m = leave.search(line)
        if m:
            level = int(m.group(1))
            if level in stack:
                stack[level].discard(m.group(2))
                if not stack[level]:
                    del stack[level]
        if SOURCE in line.replace("\\", "/") and OUTPUT in line.replace("\\", "/"):
            parsed = parse_compile(line)
            deepest = max(stack) if stack else None
            ambiguous = any(len(v) != 1 for v in stack.values())
            ordered = [next(iter(stack[level])) for level in sorted(stack)] if not ambiguous else []
            if ordered:
                ambiguous = any(not Path(ordered[i + 1]).resolve().is_relative_to(Path(ordered[i]).resolve())
                                for i in range(len(ordered) - 1))
            dirs = ordered
            matches.append({**parsed, "line_number": n, "raw_line": line,
                            "raw_line_sha256": hashlib.sha256(line.encode()).hexdigest(),
                            "cwd": dirs[-1] if dirs else None,
                            "cwd_scope_depth": deepest, "cwd_scope_ambiguous": ambiguous})
    if len(matches) != 1:
        raise ValueError(f"expected one matching logged compile entry, found {len(matches)}")
    if matches[0]["cwd_scope_ambiguous"]:
        raise ValueError("parallel make directory scopes overlap; cwd association is ambiguous")
    # find_compile uses cwd only when exactly one directory was active at the deepest level.
    if matches[0]["cwd"] is None:
        raise ValueError("no unique recorded make directory scope contains compile entry")
    return matches[0]


def has_exact_definition(nm_output: str) -> bool:
    return sum(bool(re.fullmatch(r"\s*[0-9a-fA-F]+\s+[tTWiI]\s+" + re.escape(SYMBOL) + r"\s*", line))
               for line in nm_output.splitlines()) == 1


def run_capture(argv: list[str], output: Path) -> dict:
    """Run inspection tools only, saving complete streams directly to disk."""
    try:
        errpath = output.with_suffix(output.suffix + ".stderr.txt")
        started = time.monotonic()
        with output.open("wb") as out, errpath.open("wb") as err:
            p = subprocess.run(argv, stdout=out, stderr=err, check=False)
        return {"argv": argv, "returncode": p.returncode, "elapsed_seconds": time.monotonic() - started,
                "stdout_path": str(output), "stderr_path": str(output.with_suffix(output.suffix + ".stderr.txt"))}
    except Exception as exc:
        return {"argv": argv, "returncode": None, "error": str(exc)}


def read_cu_facts(path: Path) -> list[dict]:
    facts, cur, root_open = [], None, False
    with path.open(encoding="utf-8", errors="replace") as stream:
        for line in stream:
            tag = re.search(r"<(\d+)>.*\(DW_TAG_(\w+)\)", line)
            if tag and int(tag.group(1)) == 0 and tag.group(2) == "compile_unit":
                if cur:
                    facts.append(cur)
                cur = {}
                root_open = True
                continue
            if tag and int(tag.group(1)) > 0:
                root_open = False
            if cur is not None and root_open:
                m = re.search(r"DW_AT_(name|comp_dir)\s*:\s*(?:\([^)]*\):\s*)?(.*)$", line)
                if m and m.group(2).strip():
                    value = m.group(2).strip().rsplit(": ", 1)[-1]
                    cur.setdefault(m.group(1), value)
    if cur:
        facts.append(cur)
    return facts


def collect(run: Path, origin: Path, out: Path, compiler: Path | None, plugins: list[Path]) -> dict:
    if out.exists() and (not out.is_dir() or any(out.iterdir())):
        raise ValueError("output directory must be fresh and empty")
    out.mkdir(parents=True, exist_ok=True)
    report = {"schema": "chimera-builtin-gate-inputs-v1", "symbol": SYMBOL,
              "root_confirmed": False, "compiled": False, "replay_ready": False,
              "gaps": [], "historical": {}, "current": {}}
    try:
        history = validate_history(origin, run / "build-gate4")
        report["historical"] = history
        report["gaps"].extend(history["gaps"])
    except Exception as exc:
        report["gaps"].append(f"history validation error: {exc}")
    log = origin / "build.log"
    try:
        report["build_log"] = {"path": str(log.resolve()), "sha256": sha256(log)}
        with log.open(encoding="utf-8", errors="replace") as f:
            compile_entry = find_compile(f)
        report["logged_compile_entry"] = compile_entry
        (out / "logged-compile-entry.json").write_text(json.dumps(compile_entry, indent=2) + "\n")
    except Exception as exc:
        report["gaps"].append(f"logged compile association: {exc}")
        compile_entry = None
    wrappers = [origin / "wrappers" / "gate4-cxx"] if (origin / "wrappers" / "gate4-cxx").is_file() else []
    wrapper_rows = [{**identity(p), "provenance": "ARCHIVED_UNBOUND_TO_LOGGED_COMPILER"} for p in wrappers]
    report["historical_wrapper_candidates"] = wrapper_rows
    if not wrappers:
        report["gaps"].append("archived wrappers/gate4-cxx missing")
    if compile_entry:
        logged = (Path(compile_entry["cwd"]) / compile_entry["argv"][0]).resolve()
        report["logged_executable"] = str(logged)
        report["wrapper_path_match"] = bool(wrappers and logged == wrappers[0].resolve())
        if not report["wrapper_path_match"]:
            report["gaps"].append("logged executable does not identify archived gate4-cxx wrapper")
        if report["wrapper_path_match"]:
            shutil.copy2(wrappers[0], out / "gate4-cxx")
            report["archived_wrapper_copy"] = identity(out / "gate4-cxx")
            report["archived_wrapper_copy"]["provenance"] = "CURRENT_COPY_OF_ARCHIVED_INPUT"
    report["gaps"].append("logged wrapper command has not been expanded or replay-validated")
    census = origin / "gate4.decision.gate_names.implicit_vector_census.tsv"
    census_matches = []
    try:
        report["census"] = {"path": str(census.resolve()), "sha256": sha256(census),
                            "binding": "ORIGINAL_CENSUS_ONLY_NOT_TU_BOUND", "matches": census_matches}
        with census.open(encoding="utf-8", errors="replace") as f:
            for n, line in enumerate(f, 1):
                fields = line.rstrip("\r\n").split("\t")
                if len(fields) >= 4 and fields[2] == SYMBOL:
                    census_matches.append({"line_number": n, "row": line.rstrip("\r\n")})
    except Exception as exc:
        report["gaps"].append(f"census unavailable: {exc}")
    try:
        decision = json.loads((origin / "gate4.decision.json").read_text(encoding="utf-8"))
        decision_body = decision.get("decision", {})
        gate_names = decision_body.get("gate", {}).get("names", [])
        provenance = decision.get("provenance", {})
        report["historical"]["decision_target"] = {
            "symbol": SYMBOL, "in_gate_names": SYMBOL in gate_names,
            "gate_name_count": len(gate_names), "union_count": provenance.get("union_count"),
            "added_count": provenance.get("added_count"), "removed_count": provenance.get("removed_count"),
            "in_added": SYMBOL in provenance.get("added", []),
            "in_removed": SYMBOL in provenance.get("removed", []),
        }
    except Exception as exc:
        report["gaps"].append(f"decision target census unavailable: {exc}")
    report["current"]["compiler"] = identity(compiler) if compiler else None
    report["current"]["plugins"] = [identity(p) for p in plugins]
    if not report["current"]["compiler"] or not report["current"]["compiler"]["exists"]:
        report["gaps"].append("current compiler identity unavailable")
    if not plugins:
        report["gaps"].append("current plugin identities not supplied")
    for item in report["current"]["plugins"]:
        if not item["exists"]:
            report["gaps"].append("current plugin identity unavailable: " + item["path"])
    report["gaps"].append("historical compiler and plugin identities are unavailable")
    # Optional adjacent GCC source and wrapper source copies retain only identities.
    source_candidates = []
    if compile_entry:
        source_candidates.append(Path(compile_entry["cwd"]) / compile_entry["source"])
    seen = set()
    report["current"]["source_candidates"] = [identity(p) for p in source_candidates
        if p.is_file() and not (str(p.resolve()) in seen or seen.add(str(p.resolve())))]
    if not report["current"]["source_candidates"]:
        report["gaps"].append("logged translation-unit source file unavailable at recorded cwd")
    for p in report["current"]["source_candidates"]:
        pth = Path(p["path"])
        if pth.name == "c-cppbuiltin.cc":
            shutil.copy2(pth, out / "c-cppbuiltin.cc")
            break
    expected_obj = run / "build-gate4" / "gcc" / OUTPUT
    report["object_candidate"] = str(expected_obj)
    if not expected_obj.is_file():
        report["gaps"].append("explicit expected object missing: build-gate4/gcc/c-family/c-cppbuiltin.o")
    else:
        report["gaps"].append("expected object is collected from the run tree but is not hash-bound by archived gate4 manifests")
        obj = out / "c-cppbuiltin.o"
        shutil.copy2(expected_obj, obj)
        report["object"] = identity(obj)
        nm = shutil.which("nm")
        if nm:
            nr = run_capture([nm, "--defined-only", str(obj)], out / "nm-defined.txt")
            report["nm"] = nr
            if nr["returncode"] == 0 and not has_exact_definition((out / "nm-defined.txt").read_text(errors="replace")):
                report["gaps"].append("exact target symbol definition absent from nm output")
            elif nr["returncode"] != 0:
                report["gaps"].append("nm inspection failed")
        else:
            report["gaps"].append("nm tool unavailable")
        for tool, argv in (("objdump", ["-drw", "--disassemble=" + SYMBOL, str(obj)]),
                           ("readelf-sections", ["-SW", str(obj)]), ("readelf-relocations", ["-rW", str(obj)]),
                           ("readelf-cu", ["--debug-dump=info", "--wide", str(obj)])):
            executable = "readelf" if tool.startswith("readelf") else tool
            path = shutil.which(executable)
            if not path:
                report["gaps"].append(f"{executable} unavailable for {tool}")
                continue
            result = run_capture([path, *argv], out / (tool + ".txt"))
            report[tool] = result
            if result["returncode"] != 0:
                report["gaps"].append(f"{tool} inspection failed")
            elif tool == "readelf-cu":
                cu = read_cu_facts(out / "readelf-cu.txt")
                report["dwarf_compile_units"] = cu
                if not any(Path(x.get("name", "")).name == "c-cppbuiltin.cc" for x in cu):
                    report["gaps"].append("DWARF CU source does not identify c-cppbuiltin.cc")
                matches = [x for x in cu if compile_entry and
                           (Path(x.get("comp_dir", "")) / x.get("name", "")).resolve() ==
                           (Path(compile_entry["cwd"]) / compile_entry["source"]).resolve()]
                if compile_entry and len(matches) != 1:
                    report["gaps"].append("DWARF does not uniquely bind source and comp_dir to logged translation unit")
                if compile_entry and len(matches) == 1 and Path(matches[0].get("comp_dir", "")).resolve() != Path(compile_entry["cwd"]).resolve():
                    report["gaps"].append("DWARF comp_dir does not match recorded make cwd")
    cc1 = run / "build-gate4" / "gcc" / "cc1"
    objdump = shutil.which("objdump")
    if cc1.is_file() and objdump:
        report["linked_function"] = run_capture([objdump, "-d", "--disassemble=" + SYMBOL, str(cc1)],
                                                 out / "linked-function.txt")
        if report["linked_function"]["returncode"] != 0:
            report["gaps"].append("linked cc1 exact-function disassembly failed")
    else:
        report["gaps"].append("linked cc1 unavailable for exact-function disassembly")
    report["gaps"] = list(dict.fromkeys(report["gaps"]))
    (out / "collection.json").write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    summary = ["# Builtin gate input collection", "", "Read-only collection completed. No compiler or wrapper was executed.",
               "", f"Historical gate4 binding: {'valid' if report.get('historical', {}).get('valid') else 'incomplete'}.",
               "", "Root confirmed: no. Replay ready: no.", "", "## Gaps", ""]
    summary += [f"- {x}" for x in report["gaps"]] or ["- No collection gaps recorded; this is still not a root-cause verdict."]
    (out / "report.md").write_text("\n".join(summary) + "\n", encoding="utf-8")
    return report


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", required=True, type=Path)
    parser.add_argument("--origin", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--compiler", type=Path)
    parser.add_argument("--plugin", action="append", type=Path, default=[])
    args = parser.parse_args(argv)
    if args.out.exists() and (not args.out.is_dir() or any(args.out.iterdir())):
        print("output directory must be fresh and empty", file=sys.stderr)
        return 2
    try:
        result = collect(args.run, args.origin, args.out, args.compiler, args.plugin)
        print(json.dumps({"root_confirmed": False, "gaps": len(result["gaps"]), "output": str(args.out)}))
        return 0 if result.get("historical", {}).get("valid") else 2
    except Exception as exc:
        args.out.mkdir(parents=True, exist_ok=True)
        failure = {"root_confirmed": False, "compiled": False, "replay_ready": False,
                   "operational_error": str(exc), "gaps": [str(exc)]}
        (args.out / "collection.json").write_text(json.dumps(failure, indent=2) + "\n")
        (args.out / "report.md").write_text("# Builtin gate input collection\n\nOperational failure.\n\n- " + str(exc) + "\n")
        print(str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
