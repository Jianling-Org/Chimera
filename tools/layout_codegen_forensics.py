#!/usr/bin/env python3
"""Read-only collection and isolated compile replay for RVV stack-map gaps."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import time
from collections import Counter
from copy import deepcopy
from pathlib import Path
from typing import Any, Mapping, Sequence


SITES = (0x50D6C, 0x50FB8)
EXPECTED_GATE2_SHA256 = "3b022cb21ef1e5ce80768ac84a8862f14bbf568650b28c75210d884c46a65e1d"
DEFAULT_LAYOUT_SYMBOL = "_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info"
INSN_RE = re.compile(r"^\s*([0-9a-fA-F]+):\s*((?:[0-9a-fA-F]{2,8}\s+)+)\s*([.\w]+)\s*(.*)$")
FUNC_RE = re.compile(r"^\s*([0-9a-fA-F]+)\s+<(.+)>:\s*$")
RELOCATION_RE = re.compile(r"R_[A-Z0-9_]+\s+\S+")

# region gate-experiment vocabulary
#
# The single-function gate experiment is deliberately narrower than `replay`:
# it answers whether adding *one exact mangled symbol* to the gated list
# removes that function's implicit vector code and the local conservative
# source that follows from it.  It never rewrites the production gate list,
# never relinks GCC, never touches a safety criterion, and never maps an
# ET_REL coordinate onto a linked virtual address.

EXPERIMENT_SCHEMA = "chimera-layout-gate-experiment-v1"
EXPERIMENT_GROUPS = ("A", "B")
#: ``stopped-before-B`` is the only non-zero status that means "the experiment
#: refused to continue"; every other non-zero outcome is recorded evidence.
EXPERIMENT_STOPPED_EXIT = 3
#: An RVV mnemonic: ``vse8.v``, ``vs2r.v``, ``vsetvli``, ``vl1re8.v`` ...
#: Nothing else in the RISC-V ISA starts with ``v``.
VECTOR_MNEMONIC_RE = re.compile(r"^(?:th\.)?v[0-9a-z.]*$")
VLEN_READ_RE = re.compile(r"\bvlenb\b", re.IGNORECASE)
VS2R_MNEMONIC = "vs2r.v"
#: Mirrors ``chimera.gate_source_audit``; the census file is produced by the
#: gate plugin into ``CHIMERA_GATE_STATS``.
CENSUS_TAG = "implicit-vector-census"
CENSUS_ACTIONS = ("formed", "blocked")
CENSUS_MECHANISMS = ("LV", "SLP", "MEMOP", "MERGE")
#: Labels objdump prints for compiler-generated local blocks.
LOCAL_LABEL_PREFIXES = (".L", "LBB", "Ltmp", "$L")
#: Control-flow mnemonics whose destination is an operand field.
DIRECT_CALL_MNEMONICS = frozenset({"call", "tail", "jal", "j", "c.j", "c.jal"})
#: Returns: the function body ends here, no in-function edge is missing.
RETURN_MNEMONICS = frozenset({"ret", "c.ret", "mret", "sret", "uret"})
#: ``jr``/``c.jr`` is ``jalr`` with a zero link register: an *unlinked* jump.
#: Its destination is whatever the register holds and may be any block of this
#: function, so it can never be treated as a resolved edge.
INDIRECT_JUMP_MNEMONICS = frozenset({"jr", "c.jr"})
#: ``jalr`` with a link register: an indirect *call*. The destination is
#: unknown but control returns, so it is recorded and kept unknown -- the same
#: treatment an unresolved external call gets.
INDIRECT_CALL_MNEMONICS = frozenset({"jalr", "c.jalr"})
#: Registers whose use in an indirect jump means "return to the caller".
LINK_REGISTERS = frozenset({"ra", "x1"})
#: A zero destination register makes ``jalr``/``jr`` an *unlinked* transfer.
ZERO_REGISTERS = frozenset({"zero", "x0"})
#: Relocation types that legitimately supply a direct branch/call destination.
#: Anything else on a control-flow instruction is not a proven control-flow
#: target, and turning its addend into an edge would invent one.
CONTROL_FLOW_RELOCATIONS = frozenset({
    "R_RISCV_BRANCH", "R_RISCV_JAL", "R_RISCV_CALL", "R_RISCV_CALL_PLT",
    "R_RISCV_RVC_BRANCH", "R_RISCV_RVC_JUMP",
})
#: ``auipc``/``jalr`` call pairs. The relocation on either half names the
#: callee; the address objdump annotates the ``jalr`` with is the *unlinked*
#: placeholder, never a destination inside this function.
CALL_RELOCATIONS = frozenset({"R_RISCV_CALL", "R_RISCV_CALL_PLT"})
#: objdump's resolved-call annotation: ``jalr ra # 16a <layout+0xba>``.
CALL_ANNOTATION_RE = re.compile(r"#\s*(?:0x)?[0-9a-fA-F]+\s+<[^>]*>", re.IGNORECASE)
#: Local-source fields compared between the two groups.  All of them come
#: from the production stack-liveness analyzer running in *binary* mode.
LOCAL_SOURCE_FIELDS = (
    "relevant_accesses",
    "binary_recovered_accesses",
    "conservative_addresses",
    "conservative_object_live_at",
    "irreducible_object_live_at",
    "irreducible_warning_addresses",
    "vlen_frame_marker_live_at",
    "vlen_setup_marker_live_at",
    "local_call_sites_carrying_objects",
    "local_call_sites_carrying_conservative",
    "local_call_sites_carrying_irreducible",
)
CONSERVATIVE_FIELDS = ("conservative_addresses", "conservative_object_live_at",
                       "local_call_sites_carrying_conservative")
#: Marker categories judged by **presence in B**, never by address equality.
#: Gating changes the code layout, so the same marker at a different address is
#: the same source, not a disappeared one.
LOCAL_MARKER_GROUPS = {
    "conservative": CONSERVATIVE_FIELDS,
    "irreducible": ("irreducible_object_live_at", "irreducible_warning_addresses",
                    "local_call_sites_carrying_irreducible"),
    "vlen_frame": ("vlen_frame_marker_live_at", "vlen_setup_marker_live_at"),
}
# endregion


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def peak_rss_kib(time_file: Path) -> int | None:
    try:
        text = time_file.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    match = re.search(r"Maximum resident set size \(kbytes\):\s*(\d+)", text)
    return int(match.group(1)) if match else None


def require_fresh_output(path: Path) -> None:
    if path.exists() and (not path.is_dir() or any(path.iterdir())):
        raise ValueError(f"output directory must be empty: {path}")
    path.mkdir(parents=True, exist_ok=True)


def extract_sites(dump: str, addresses: Sequence[int] = SITES, radius: int = 4) -> list[dict[str, Any]]:
    lines = dump.splitlines()
    parsed: list[tuple[int, str, str, str, int, str, int | None]] = []
    function = "unknown"
    function_start: int | None = None
    for index, line in enumerate(lines):
        header = FUNC_RE.match(line)
        if header:
            function = header.group(2)
            function_start = int(header.group(1), 16)
            continue
        insn = INSN_RE.match(line)
        if insn:
            parsed.append((int(insn.group(1), 16), insn.group(2).strip(), insn.group(3),
                           insn.group(4).strip(), index, function, function_start))
    by_address = {item[0]: item for item in parsed}
    result = []
    for address in addresses:
        match = by_address.get(address)
        gaps: list[str] = []
        if match is None:
            gaps.append("instruction-not-found")
            context: list[str] = []
            function_name, raw, mnemonic, operands, start = "unknown", "", "unknown", "", None
        else:
            _, raw, mnemonic, operands, line_index, function_name, start = match
            context = lines[max(0, line_index - radius): line_index + radius + 1]
        result.append({
            "address": hex(address), "function": function_name,
            "function_start": hex(start) if start is not None else None,
            "function_offset": hex(address - start) if start is not None else None,
            "raw_bytes": raw, "mnemonic": mnemonic, "operands": operands,
            "context": context, "generation_origin": "unknown", "metadata_status": "unknown",
            "gaps": gaps + ["generation-origin-not-proven", "stack-provenance-not-proven"],
        })
    return result


def source_path_from_dwarf_location(location: str) -> str:
    """Remove a trailing line/column suffix without splitting drive letters."""
    match = re.match(r"^(.*):\d+:\d+$", location) or re.match(r"^(.*):\d+$", location)
    return match.group(1) if match else location


def match_compile_commands(records: Sequence[dict[str, Any]], source: str | None) -> list[dict[str, Any]]:
    if not source:
        return []
    wanted = Path(source)
    found: list[dict[str, Any]] = []
    for index, record in enumerate(records):
        cwd = Path(record.get("directory", ".")).resolve()
        file = str(record.get("file", ""))
        candidate = Path(file)
        resolved = candidate if candidate.is_absolute() else cwd / candidate
        if os.path.normcase(str(resolved.resolve())) == os.path.normcase(str(wanted.resolve())):
            found.append({"index": index, "directory": str(cwd), "file": str(resolved.resolve()),
                          "status": "candidate", "record": record})
        elif not wanted.is_absolute() and candidate.name == wanted.name:
            found.append({"index": index, "directory": str(cwd), "file": str(resolved.resolve()),
                          "status": "ambiguous-candidate", "record": record})
    if len(found) > 1:
        for item in found:
            item["status"] = "ambiguous-candidate"
    return found


def _command_tokens(record: dict[str, Any]) -> list[str]:
    if isinstance(record.get("arguments"), list):
        return [str(token) for token in record["arguments"]]
    command = record.get("command")
    if not isinstance(command, str):
        raise ValueError("compile database entry has neither arguments nor command")
    tokens = shlex.split(command, posix=True)
    if any(token in {";", "&&", "||", "|", ">", ">>", "<"} for token in tokens):
        raise ValueError("shell operators in compile command are not executable evidence")
    if any("$" in token or "`" in token for token in tokens):
        raise ValueError("shell expansion in compile command cannot be safely replayed")
    if tokens and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", tokens[0]):
        raise ValueError("environment assignment in compile command is not replayed")
    return tokens


def _has_compile_only(tokens: Sequence[str], cwd: Path,
                      response_stack: tuple[Path, ...] = ()) -> bool:
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token == "-c":
            return True
        if token in {"-Xassembler", "-Xpreprocessor", "-Xclang"}:
            # The following token belongs to the subtool, not the compiler
            # driver's response-file namespace.
            index += 2
            continue
        if token.startswith("@"):
            response = Path(token[1:])
            if not response.is_absolute():
                response = cwd / response
            response = response.resolve()
            if response in response_stack:
                raise ValueError("cyclic response-file reference in compile command")
            if len(response_stack) >= 8:
                raise ValueError("response file nesting exceeds the safety limit")
            if response.is_file() and _has_compile_only(
                    shlex.split(response.read_text(encoding="utf-8"), posix=True), cwd,
                    (*response_stack, response)):
                return True
        index += 1
    return False


def _expanded_response_tokens(tokens: Sequence[str], cwd: Path, depth: int = 0,
                              response_stack: tuple[Path, ...] = ()) -> list[str]:
    if depth > 8:
        raise ValueError("response file nesting exceeds the safety limit")
    expanded: list[str] = []
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token in {"-Xassembler", "-Xpreprocessor", "-Xclang"}:
            expanded.append(token)
            if index + 1 < len(tokens):
                expanded.append(tokens[index + 1])
            index += 2
            continue
        if not token.startswith("@") or len(token) == 1:
            expanded.append(token)
            index += 1
            continue
        response = Path(token[1:])
        if not response.is_absolute():
            response = cwd / response
        response = response.resolve()
        if response in response_stack:
            raise ValueError("cyclic response-file reference in compile command")
        expanded.extend(_expanded_response_tokens(
            shlex.split(response.read_text(encoding="utf-8"), posix=True), cwd, depth + 1,
            (*response_stack, response)))
        index += 1
    return expanded


def _require_direct_compiler(executable: str) -> None:
    name = Path(executable).name.lower()
    if name in {"env", "ccache", "sccache", "distcc", "icecc", "chimera-pkg"}:
        raise ValueError(f"compiler launcher/wrapper must be expanded before isolated replay: {name}")
    path = Path(executable)
    if path.is_file():
        with path.open("rb") as stream:
            if stream.read(4) != b"\x7fELF":
                raise ValueError("compiler command is not a native ELF binary; expand the wrapper first")


def _has_forwarded_side_output(tokens: Sequence[str]) -> bool:
    """Reject output switches forwarded past the driver-level isolation checks."""
    assembler: list[str] = []
    preprocessor: list[str] = []
    frontend: list[str] = []
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token.startswith("-Wa,"):
            assembler.extend(token[4:].split(","))
        elif token.startswith("-Wp,"):
            preprocessor.extend(token[4:].split(","))
        elif token in {"-Xassembler", "-Xpreprocessor", "-Xclang"}:
            if index + 1 >= len(tokens):
                return True
            channel = {"-Xassembler": assembler, "-Xpreprocessor": preprocessor,
                       "-Xclang": frontend}[token]
            channel.append(tokens[index + 1])
            index += 1
        elif token.startswith("-Xassembler="):
            assembler.append(token.split("=", 1)[1])
        elif token.startswith("-Xpreprocessor="):
            preprocessor.append(token.split("=", 1)[1])
        elif token.startswith("-Xclang="):
            frontend.append(token.split("=", 1)[1])
        index += 1

    unsafe_prefixes = (
        "-serialize-diagnostics", "--serialize-diagnostics", "-dependency-file",
        "-fprofile-generate", "-fprofile-instr-generate", "-fprofile-arcs",
        "-ftest-coverage", "-fcoverage-mapping", "-fcoverage-notes", "-fstack-usage",
        "--coverage", "-ftime-trace", "-dumpdir", "-dumpbase", "-fdump-", "-aux-info",
        "-foptimization-record-file", "-fdiagnostics-serialization-file",
        "-fmodules-cache-path", "-fmodule-output", "-gsplit-dwarf",
    )
    dependency_outputs = {"-MD", "-MMD", "-MF", "-MJ"}
    if any(token.startswith("@") and len(token) > 1
           for token in (*assembler, *preprocessor, *frontend)):
        return True
    if any(token.startswith(unsafe_prefixes) for token in (*preprocessor, *frontend)):
        return True
    if any(token in dependency_outputs or token.startswith(tuple(dependency_outputs))
           for token in preprocessor):
        return True
    for token in preprocessor:
        if (token == "-o" or (token.startswith("-o") and token != "-openmp")
                or token.startswith(("-MF=", "-MJ="))):
            return True
    for index, token in enumerate(assembler):
        # GNU as -a[cdghlns]=FILE emits a listing at FILE; -o/--output can
        # override the isolated object destination.
        if re.fullmatch(r"-a[cdghlns]*=.*", token) or token.startswith("--listing="):
            return True
        if (token in {"--listing", "-o", "--output", "--MD", "-save-temps"}
                or token.startswith(("-o=", "--output=", "--MD"))):
            return True
        if token.startswith("-o") and not token.startswith("--") and len(token) > 2:
            return True
    for token in frontend:
        if token == "-o" or token.startswith("-o="):
            return True
    return False


def _rewrite_output_tokens(tokens: list[str], out: Path, response_counter: list[int],
                           cwd: Path, gate_list_path: Path | None = None,
                           response_stack: tuple[Path, ...] = ()) -> tuple[list[str], Path | None]:
    rewritten: list[str] = []
    response_copy: Path | None = None
    i = 0
    while i < len(tokens):
        token = tokens[i]
        if token in {"-Xassembler", "-Xpreprocessor", "-Xclang"}:
            # Do not read or relocate a response file owned by a forwarded
            # compiler subtool. The caller rejects it as an unsafe side output.
            rewritten.append(token)
            if i + 1 < len(tokens):
                rewritten.append(tokens[i + 1])
            i += 2
            continue
        if token.startswith("@") and len(token) > 1:
            original = Path(token[1:])
            if not original.is_absolute():
                original = cwd / original
            original = original.resolve()
            if original in response_stack:
                raise ValueError("cyclic response-file reference in compile command")
            if len(response_stack) >= 8:
                raise ValueError("response file nesting exceeds the safety limit")
            rsp_data = original.read_text(encoding="utf-8", errors="strict")
            nested = shlex.split(rsp_data, posix=True)
            if nested and nested[-1] in {"-Xassembler", "-Xpreprocessor", "-Xclang"}:
                # Reject an option whose value could spill across this response
                # file boundary and be mistaken for a compiler response file.
                raise ValueError("compile command has an unisolated side-output option")
            response_copy = out / f"response-{response_counter[0]}.rsp"
            response_counter[0] += 1
            new_nested, _nested_rsp = _rewrite_output_tokens(
                nested, out, response_counter, cwd, gate_list_path,
                (*response_stack, original))
            response_copy.write_text(shlex.join(new_nested) + "\n", encoding="utf-8")
            rewritten.append("@" + str(response_copy))
            i += 1
            continue
        if token in {"-save-temps", "-save-temps=cwd"}:
            rewritten.append("-save-temps=obj")
            i += 1
            continue
        if gate_list_path is not None and token == "-chimera-gate-list":
            if i + 1 >= len(tokens):
                raise ValueError("missing value after -chimera-gate-list")
            rewritten.extend((token, str(gate_list_path)))
            i += 2
            continue
        if gate_list_path is not None and token.startswith("-chimera-gate-list="):
            rewritten.append("-chimera-gate-list=" + str(gate_list_path))
            i += 1
            continue
        if token in {"-o", "-MF", "-MT", "-MQ", "-MJ"}:
            if i + 1 >= len(tokens):
                raise ValueError(f"missing value after {token}")
            suffix = {"-o": ".o", "-MF": ".d", "-MT": ".target", "-MQ": ".targetq", "-MJ": ".json"}[token]
            rewritten.extend((token, str(out / f"replay{suffix}")))
            i += 2
            continue
        matched = False
        for flag, suffix in (("-o", ".o"), ("-MF", ".d"), ("-MT", ".target"), ("-MQ", ".targetq"), ("-MJ", ".json")):
            if token.startswith(flag) and token != flag and flag in {"-o", "-MF", "-MT", "-MQ", "-MJ"}:
                rewritten.append(flag + str(out / f"replay{suffix}"))
                matched = True
                break
        if not matched:
            rewritten.append(token)
        i += 1
    if not any(t == "-o" or (t.startswith("-o") and not t.startswith(("-openmp", "-objc"))) for t in rewritten):
        rewritten.extend(("-o", str(out / "replay.o")))
    if not any(t == "-MF" or t.startswith("-MF") for t in rewritten):
        rewritten.extend(("-MMD", "-MF", str(out / "replay.d")))
    return rewritten, response_copy


def rewrite_compile_command(record: dict[str, Any], out: Path,
                            gate_list_path: Path | None = None,
                            extra_tokens: Sequence[str] = ()) -> tuple[list[str], Path | None]:
    out = out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    cwd = Path(record.get("directory", ".")).resolve()
    tokens = _command_tokens(record)
    tokens.extend(str(token) for token in extra_tokens)
    if not _has_compile_only(tokens, cwd):
        raise ValueError("compile command is not a single translation-unit compile (-c required)")
    cwd = Path(record.get("directory", ".")).resolve()
    gate_list_path = gate_list_path.resolve() if gate_list_path is not None else None
    rewritten, response = _rewrite_output_tokens(tokens, out, [0], cwd, gate_list_path)
    for index, token in enumerate(rewritten):
        if token in {"-save-temps", "-save-temps=obj", "-save-temps=cwd"}:
            rewritten[index] = "-save-temps=obj"
    # Explicit outputs now live in OUT. Any path-bearing side-output option we
    # do not understand is rejected rather than allowed to touch the source tree.
    unsafe_prefixes = (
        "-serialize-diagnostics", "--serialize-diagnostics", "-fprofile-generate",
        "-fprofile-instr-generate", "-fprofile-arcs", "-ftest-coverage",
        "-fcoverage-mapping", "-fcoverage-notes", "-fstack-usage", "--coverage",
        "-ftime-trace", "-dumpdir", "-dumpbase", "-fdump-", "-aux-info",
        "-foptimization-record-file", "-fdiagnostics-serialization-file",
        "-fmodules-cache-path", "-fmodule-output", "-gsplit-dwarf",
    )
    expanded = _expanded_response_tokens(rewritten, cwd)
    if any(token.startswith(unsafe_prefixes) for token in expanded):
        raise ValueError("compile command has an unisolated side-output option")
    if _has_forwarded_side_output(expanded):
        raise ValueError("compile command has an unisolated side-output option")
    for token in rewritten:
        if token.startswith("@"):
            response_path = Path(token[1:]).resolve()
            if not response_path.is_relative_to(out):
                raise ValueError("response file was not redirected into isolated output")
    if not cwd.is_dir():
        raise ValueError(f"compile working directory is unavailable: {cwd}")
    return rewritten, response


def validate_collected_compile_entry(candidate: dict[str, Any], database: Path,
                                     records: Sequence[dict[str, Any]], index: int) -> dict[str, Any]:
    """Refuse replay if the command database or its response-file expansion changed."""
    database = database.resolve()
    if str(database) != str(Path(candidate.get("database", "")).resolve()):
        raise ValueError("compile database path differs from the collected candidate")
    expected_hash = candidate.get("compile_database_sha256")
    if not expected_hash or sha256(database) != expected_hash:
        raise ValueError("compile database hash differs from collection")
    if index != candidate.get("index") or index < 0 or index >= len(records):
        raise ValueError("compile database entry index differs from collection")
    record = records[index]
    cwd = Path(record.get("directory", ".")).resolve()
    source = Path(record.get("file", ""))
    if not source.is_absolute():
        source = cwd / source
    if str(cwd) != candidate.get("directory") or str(source.resolve()) != candidate.get("file"):
        raise ValueError("compile entry source or working directory differs from collection")
    current_argv = _expanded_response_tokens(_command_tokens(record), cwd)
    if current_argv != candidate.get("original_argv"):
        raise ValueError("compile command differs from the collected response-file expansion")
    object_path = Path(candidate.get("object", ""))
    if not candidate.get("object_exists") or not object_path.is_file() or not candidate.get("object_sha256"):
        raise ValueError("original object is unavailable from collection")
    if sha256(object_path) != candidate["object_sha256"]:
        raise ValueError("original object hash differs from collection")
    if not candidate.get("defines_layout_symbol"):
        raise ValueError("collected object does not define the exact layout symbol")
    return record


def _decision_root(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("decision JSON must contain an object")
    root = value.get("decision", value)
    if not isinstance(root, dict):
        raise ValueError("decision JSON decision field must be an object")
    return root


def _decision_gate_names(path: Path) -> list[str]:
    decision = _decision_root(path)
    gate = decision.get("gate")
    names = gate.get("names") if isinstance(gate, dict) else None
    if not isinstance(names, list) or any(not isinstance(name, str) or not name for name in names):
        raise ValueError("decision must contain a structured gate.names string list")
    return sorted(names)


def _defines_symbol(nm_output: str, symbol: str) -> bool:
    """Match an exact raw symbol table name; don't use demangled substrings."""
    for line in nm_output.splitlines():
        fields = line.split()
        if fields and fields[-1] == symbol:
            return True
    return False


def _archive_members_defining_symbol(nm_output: str, symbol: str) -> list[str]:
    members = []
    current_member: str | None = None
    for line in nm_output.splitlines():
        header = re.match(r"^\s*(.+):\s*$", line)
        if header and not re.match(r"^\s*[0-9a-fA-F]+\s+", line):
            header_value = header.group(1)
            inline_member = re.search(r"(?:\(([^()]*)\)|\[([^\[\]]*)\])$", header_value)
            current_member = (inline_member.group(1) or inline_member.group(2)) if inline_member else Path(header_value).name
            continue
        fields = line.split()
        if not fields or fields[-1] != symbol:
            continue
        prefix = line[:line.rfind(":")] if ":" in line else line
        match = re.search(r"\(([^()]*)\)$", prefix) or re.search(r"\[([^\[\]]*)\]$", prefix)
        if match:
            members.append(match.group(1))
        elif current_member:
            members.append(current_member)
    return members


def _select_archive_member(nm_output: str, ar_listing: str, symbol: str) -> dict[str, Any]:
    candidates = _archive_members_defining_symbol(nm_output, symbol)
    available = ar_listing.splitlines()
    if len(candidates) != 1:
        return {"status": "ambiguous-or-unresolved-member", "members": candidates}
    member = candidates[0]
    if available.count(member) != 1:
        return {"status": "archive-member-name-not-unique", "member": member,
                "listing_count": available.count(member)}
    return {"status": "unique-member", "member": member}


def prepare_replay_environment(stage: str, decision_path: Path, out: Path,
                               inherited: dict[str, str]) -> dict[str, str]:
    """Keep gate plugin inputs and census outputs separate from original builds."""
    out = out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    environment = dict(inherited)
    temporary_dir = out / "tmp"
    temporary_dir.mkdir(parents=True, exist_ok=True)
    environment["TMPDIR"] = str(temporary_dir)
    environment["TMP"] = str(temporary_dir)
    environment["TEMP"] = str(temporary_dir)
    environment.pop("CHIMERA_GATE_LIST", None)
    environment.pop("CHIMERA_GATE_STATS", None)
    if stage == "gate2":
        names = _decision_gate_names(decision_path)
        names_path = out / "gate_names.txt"
        names_path.write_text("".join(name + "\n" for name in names), encoding="utf-8")
        environment["CHIMERA_GATE_LIST"] = str(names_path)
        environment["CHIMERA_GATE_STATS"] = str(out / "implicit_vector_census.tsv")
    elif stage != "stack":
        raise ValueError(f"unknown replay stage: {stage}")
    return environment


def classify_origin(*, site: dict[str, Any], ir_evidence: dict[str, Any] | None,
                    mir_evidence: dict[str, Any] | None) -> dict[str, str]:
    if mir_evidence and mir_evidence.get("frame_index") and mir_evidence.get("attribute") is True:
        origin = "backend-spill"
        metadata = "recorded-before-link" if mir_evidence.get("pcsections") else "backend-record-missing"
    elif ir_evidence and ir_evidence.get("kind") in {"vector-ir", "intrinsic", "inline-asm"}:
        origin = str(ir_evidence["kind"])
        metadata = str(ir_evidence.get("metadata_status", "unknown"))
    else:
        origin, metadata = "unknown", "unknown"
    return {"generation_origin": origin, "metadata_status": metadata}


def finalize_replay_assessment(*, replay_matches_original: bool, toolchain_matches: bool) -> dict[str, bool]:
    return {"root_cause_confirmed": bool(replay_matches_original and toolchain_matches)}


def address_identity(*, elf_type: str, section: str, offset: int,
                     linked_va: int | None = None, relocation: str | None = None) -> dict[str, Any]:
    normalized_type = elf_type.strip().upper()
    if normalized_type.startswith("ET_"):
        normalized_type = normalized_type[3:]
    if normalized_type == "REL":
        return {"coordinate": "section+offset", "section": section, "offset": hex(offset),
                "relocation": relocation, "linked_va": None,
                "directly_comparable_to_linked_va": False}
    if normalized_type in {"EXEC", "DYN"}:
        return {"coordinate": "linked-va", "linked_va": hex(linked_va if linked_va is not None else offset),
                "section": section, "offset": hex(offset), "relocation": relocation,
                "directly_comparable_to_linked_va": True}
    return {"coordinate": "unknown", "linked_va": None, "section": section,
            "offset": hex(offset), "relocation": relocation,
            "directly_comparable_to_linked_va": False}


def _object_coordinates(disassembly: str, elf_type: str) -> list[dict[str, Any]]:
    section = "unknown"
    coordinates: list[dict[str, Any]] = []
    last_instruction: dict[str, Any] | None = None
    for line in disassembly.splitlines():
        section_match = re.search(r"Disassembly of section (.+):", line)
        if section_match:
            section = section_match.group(1)
            continue
        match = INSN_RE.match(line)
        if match:
            operands, inline_relocations = _split_inline_relocation(match.group(4))
            instruction_text = line.strip()
            if inline_relocations:
                first_relocation = RELOCATION_RE.search(line)
                instruction_text = line[:first_relocation.start()].rstrip()
                instruction_text = re.sub(r"\s+[0-9a-fA-F]+:\s*$", "", instruction_text).rstrip()
            last_instruction = {"section": section, "offset": int(match.group(1), 16),
                                "mnemonic": match.group(3), "instruction": instruction_text,
                                "relocations": []}
            last_instruction["relocations"].extend(inline_relocations)
            coordinates.append(last_instruction)
            continue
        if last_instruction:
            last_instruction["relocations"].extend(
                relocation.group(0) for relocation in RELOCATION_RE.finditer(line))
    return [{**address_identity(elf_type=elf_type, section=item["section"],
                                offset=item["offset"], relocation="; ".join(item["relocations"]) or None),
             "mnemonic": item["mnemonic"], "instruction": item["instruction"],
              "relocations": item["relocations"]} for item in coordinates]


def compare_object_coordinates(original: Sequence[dict[str, Any]],
                               replayed: Sequence[dict[str, Any]]) -> dict[str, Any]:
    """Compare the TU object body and attached relocation targets before diagnostics."""
    instruction_signature = lambda rows: [
        (item.get("section"), item.get("offset"), item.get("instruction")) for item in rows
    ]
    relocation_signature = lambda rows: [
        tuple(item.get("relocations", [])) for item in rows
    ]
    if not original or not replayed:
        return {"status": "unknown", "instruction_sequence_matches": False,
                "relocation_targets_match": False,
                "gap": "original-or-replay-object-coordinates-unavailable"}
    instruction_match = instruction_signature(original) == instruction_signature(replayed)
    relocation_match = relocation_signature(original) == relocation_signature(replayed)
    return {"status": "matched" if instruction_match and relocation_match else "mismatch",
            "instruction_sequence_matches": instruction_match,
            "relocation_targets_match": relocation_match,
            "original_instruction_count": len(original), "replay_instruction_count": len(replayed),
            "gap": None if instruction_match and relocation_match else
                "baseline-object-instruction-or-relocation-difference"}


def run(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        require_fresh_output(args.out)
        if args.stage == "collect":
            return collect(args)
        if args.stage == "resolve":
            return resolve(args)
        if args.stage == "gate-experiment":
            return gate_experiment(args)
        return replay(args)
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        output = getattr(args, "out", None)
        if isinstance(output, Path) and output.is_dir():
            try:
                (output / "tool-error.json").write_text(json.dumps({
                    "stage": getattr(args, "stage", "unknown"),
                    "error_type": type(exc).__name__, "error": str(exc),
                    "root_cause_confirmed": False,
                }, indent=2), encoding="utf-8")
            except OSError:
                pass
        print(f"forensics failed: {exc}", file=sys.stderr)
        return 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="stage", required=True)
    for name in ("collect", "resolve", "replay", "gate-experiment"):
        cmd = sub.add_parser(name)
        cmd.add_argument("--repo", type=Path, required=True)
        cmd.add_argument("--run", type=Path, required=True)
        cmd.add_argument("--out", type=Path, required=True)
        cmd.add_argument("--expected-gate2-sha256", required=name != "resolve")
        cmd.add_argument("--gate-list", type=Path)
        cmd.add_argument("--stack-decision", type=Path)
        cmd.add_argument("--wrapper", type=Path,
                         help="the installed Chimera wrapper whose identity should be captured")
        cmd.add_argument("--objdump", default="objdump")
        cmd.add_argument("--readelf", default="readelf")
        cmd.add_argument("--nm", default="nm")
        cmd.add_argument("--ar", default="ar")
        cmd.add_argument("--addr2line", default="addr2line")
        cmd.add_argument("--layout-symbol", default=DEFAULT_LAYOUT_SYMBOL)
    replay_parser = sub.choices["replay"]
    sub.choices["resolve"].add_argument("--collection", type=Path, required=True)
    replay_command_group = replay_parser.add_mutually_exclusive_group(required=True)
    replay_command_group.add_argument("--compile-database", type=Path)
    replay_command_group.add_argument("--compile-entry-json", type=Path,
                                      help="a manually verified single compile_commands-style object")
    replay_parser.add_argument("--collection", type=Path, required=True)
    replay_parser.add_argument("--entry-index", type=int, default=0)
    replay_parser.add_argument("--build-stage", choices=("stack", "gate2"), required=True)
    replay_parser.add_argument("--original-object", type=Path,
                               help="collected stage object for a reviewed explicit compile entry")
    replay_parser.add_argument("--resolution", type=Path,
                               help="identity-checked resolution.json for an archived original object")
    replay_parser.add_argument("--diagnostic-arg", action="append", default=[])
    experiment = sub.choices["gate-experiment"]
    experiment.add_argument("--collection", type=Path, required=True)
    experiment.add_argument("--resolution", type=Path)
    experiment_command_group = experiment.add_mutually_exclusive_group(required=True)
    experiment_command_group.add_argument("--compile-database", type=Path)
    experiment_command_group.add_argument("--compile-entry-json", type=Path,
                                          help="a manually verified single compile_commands-style object")
    experiment.add_argument("--entry-index", type=int, default=0)
    experiment.add_argument("--original-object", type=Path,
                            help="collected stage object for a reviewed explicit compile entry")
    experiment.add_argument("--target-symbol",
                            help="exact mangled symbol added to the gate list; defaults to --layout-symbol")
    experiment.add_argument("--toolchain-manifest", type=Path, required=True,
                            help="JSON declaring the tool, plugin, source, object, decision and "
                                 "existing-evidence hashes this run must reproduce")
    experiment.add_argument("--diagnostic-arg", action="append", default=[])
    return parser


def _run_capture(command: Sequence[str], out: Path, name: str, cwd: Path | None = None) -> tuple[int, str]:
    out.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    stdout_path, stderr_path = out / f"{name}.stdout.txt", out / f"{name}.stderr.txt"
    time_path = out / f"{name}.time.txt"
    time_bin = Path("/usr/bin/time")
    wrapped = [str(time_bin), "-v", "-o", str(time_path), *command] if time_bin.is_file() else list(command)
    capture_env = dict(os.environ, LC_ALL="C", LANG="C")
    with stdout_path.open("wb") as stdout, stderr_path.open("wb") as stderr:
        try:
            completed = subprocess.run(wrapped, cwd=cwd, stdout=stdout, stderr=stderr,
                                       check=False, env=capture_env)
            returncode = completed.returncode
        except OSError as exc:
            stderr.write(f"unable to execute command: {exc}\n".encode("utf-8", errors="replace"))
            returncode = 127
    elapsed = time.monotonic() - started
    metadata = {"argv": list(command), "wrapped_argv": wrapped, "cwd": str(cwd) if cwd else None,
                "exit_code": returncode, "elapsed_seconds": elapsed,
                "peak_memory_file": time_path.name if time_path.exists() else None,
                "peak_rss_kib": peak_rss_kib(time_path),
                "stdout": stdout_path.name, "stderr": stderr_path.name}
    (out / f"{name}.command.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    return returncode, stdout_path.read_text(encoding="utf-8", errors="replace")


def _read_compile_units(obj: Path, readelf: str, out: Path, label: str) -> list[str]:
    """Read top-level CU paths; line-table locations are not compilation units."""
    code, dump = _run_capture([readelf, "--debug-dump=info", str(obj)], out, label + ".dwarf-info")
    if code:
        return []
    units: list[str] = []
    in_unit = False
    name: str | None = None
    directory: str | None = None

    def save() -> None:
        if name:
            path = Path(name)
            if not path.is_absolute() and directory:
                path = Path(directory) / path
            units.append(str(path))

    for line in dump.splitlines():
        # DIE depth/address are stable across readelf locales. A child DIE
        # ends the CU's attributes even if its translated label is undecodable.
        die = re.match(r"^\s*<(\d+)>\s*<[0-9a-fA-F]+>", line)
        if die:
            if in_unit:
                save()
            in_unit = die.group(1) == "0" and "DW_TAG_compile_unit" in line
            name, directory = None, None
            continue
        if not in_unit:
            continue
        match = re.search(r"DW_AT_(name|comp_dir)\s*:\s*(.*)$", line)
        if match:
            # readelf may prefix indexed strings with '(indirect string, ...):'.
            value = match.group(2).rsplit(": ", 1)[-1].strip()
            if match.group(1) == "name":
                name = value
            else:
                directory = value
    if in_unit:
        save()
    return sorted(units)


def _logged_compile_candidates(log: str, source: str, member: str,
                               archive_name: str) -> list[dict[str, Any]]:
    """Parse log lines as data; never pass them to a shell."""
    lines = log.splitlines()
    archived = False
    for line in lines:
        try:
            tokens = _command_tokens({"command": line})
        except ValueError:
            continue
        if tokens and Path(tokens[0]).name == "ar" and archive_name in tokens and member in tokens:
            archived = True
            break
    if not archived:
        return []
    result: list[dict[str, Any]] = []
    for number, line in enumerate(lines, 1):
        try:
            tokens = _command_tokens({"command": line})
        except ValueError:
            continue
        if not tokens or "-c" not in tokens or tokens[-1] != source:
            continue
        outputs = [tokens[index + 1] for index, token in enumerate(tokens[:-1]) if token == "-o"]
        if len(outputs) != 1 or outputs[0] not in (member, "./" + member):
            continue
        result.append({"line": number, "argv": tokens, "raw_line_sha256": hashlib.sha256(
            line.encode("utf-8")).hexdigest()})
    return result


def _collected_original_object(collection: dict[str, Any], stage: str,
                               original: Path) -> dict[str, Any]:
    """Bind an original object to exactly one collected definition."""
    matched: list[dict[str, Any]] = []
    for item in collection.get("stage_object_candidates", []):
        if item.get("stage") == stage and item.get("defines_layout") and Path(
                item.get("path", "")).resolve() == original:
            matched.append({"path": str(original), "sha256": item.get("sha256"),
                            "object_address_coordinates": item.get("object_address_coordinates", []),
                            "kind": "standalone"})
    for item in collection.get("archive_layout_candidates", []):
        if item.get("stage") != stage or item.get("member_selection", {}).get("status") != "unique-member":
            continue
        extracted = item.get("member_object", {})
        if extracted.get("status") != "extracted-et-rel-member" or Path(
                extracted.get("output", "")).resolve() != original:
            continue
        if any(candidate.get("stage") == stage and candidate.get("defines_layout")
               and candidate.get("sha256") != extracted.get("output_sha256")
               for candidate in collection.get("stage_object_candidates", [])):
            raise ValueError("competing standalone definition differs from archived layout member")
        archive = Path(item.get("archive", ""))
        if not archive.is_file() or sha256(archive) != item.get("archive_sha256"):
            raise ValueError("original archive identity changed since collection")
        matched.append({"path": str(original), "sha256": extracted.get("output_sha256"),
                        "object_address_coordinates": item.get("object_address_coordinates", []),
                        "kind": "archive-member", "archive": str(archive),
                        "member": item["member_selection"]["member"]})
    if len(matched) != 1 or not matched[0].get("sha256"):
        raise ValueError("--original-object must uniquely match a collected object defining layout")
    if not original.is_file() or sha256(original) != matched[0]["sha256"]:
        raise ValueError("explicit original object is missing or differs from the collected hash")
    return matched[0]


def _verified_resolution_command(evidence: dict[str, Any], collected_dir: Path,
                                 log_name: str, source: Path, member: str,
                                 archive_name: str) -> list[dict[str, Any]]:
    identity = json.loads((collected_dir / "identity.json").read_text(encoding="utf-8"))
    matches = [entry for entry in identity.get("build_evidence", [])
               if Path(entry.get("path", "")).name == log_name]
    if len(matches) != 1:
        raise ValueError("resolution command log is not uniquely bound to collection")
    copied_log = collected_dir / matches[0].get("raw_copy", "")
    if not copied_log.is_file() or sha256(copied_log) != matches[0].get("sha256"):
        raise ValueError("resolution command log hash differs from collection")
    original = _logged_compile_candidates(copied_log.read_text(encoding="utf-8", errors="replace"),
                                          str(source), member, archive_name)
    if len(original) != 1 or original != evidence.get("command_candidates"):
        raise ValueError("resolution command differs from the collected original build log")
    return original


def resolve(args: argparse.Namespace) -> int:
    """Supplement a collected bundle without changing its original evidence."""
    collected_path, run_dir, out = args.collection.resolve(), args.run.resolve(), args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    collected_dir = collected_path.parent
    collection = json.loads(collected_path.read_text(encoding="utf-8"))
    identity = json.loads((collected_dir / "identity.json").read_text(encoding="utf-8"))
    line_sources = sorted({source_path_from_dwarf_location(line)
                           for site in collection.get("sites", {}).values()
                           for line in site.get("addr2line", [])
                           if re.search(r":\d+(?::\d+)?$", line)})
    stages: dict[str, Any] = {}
    for stage, log_name in (("build-stack", "stack-build.log"),
                            ("build-gate2", "gate2-build.log")):
        evidence: dict[str, Any] = {"stage": stage, "gaps": [], "replay_ready": False,
                                    "historical_toolchain_bound": False}
        stages[stage] = evidence
        elf_name = "stack" if stage == "build-stack" else "gate2"
        elf = run_dir / stage / "gcc/xgcc"
        recorded_elf = identity.get(f"{elf_name}_sha256")
        evidence["elf_matches_collection"] = bool(
            recorded_elf and elf.is_file() and sha256(elf) == recorded_elf)
        if not evidence["elf_matches_collection"]:
            evidence["gaps"].append("stage-elf-hash-changed-or-unavailable")
        matches = [item for item in collection.get("archive_layout_candidates", [])
                   if item.get("stage") == stage and item.get("member_selection", {}).get("status") == "unique-member"]
        if len(matches) != 1:
            evidence["gaps"].append("unique-archive-member-not-established")
            continue
        item = matches[0]
        member = item["member_selection"]["member"]
        archive = Path(item["archive"]).resolve()
        original = Path(item.get("member_object", {}).get("output", "")).resolve()
        expected_object = item.get("member_object", {}).get("output_sha256")
        standalone = [candidate for candidate in collection.get("stage_object_candidates", [])
                      if candidate.get("stage") == stage and candidate.get("defines_layout")]
        competing = [candidate for candidate in standalone
                     if not expected_object or candidate.get("sha256") != expected_object]
        if competing:
            evidence["competing_standalone_objects"] = [candidate.get("path") for candidate in competing]
            evidence["gaps"].append("competing-standalone-definition")
            continue
        evidence["equivalent_standalone_objects"] = [candidate.get("path") for candidate in standalone]
        if not archive.is_file() or sha256(archive) != item.get("archive_sha256"):
            evidence["gaps"].append("archive-hash-changed-or-unavailable")
        if not expected_object or not original.is_file() or sha256(original) != expected_object:
            evidence["gaps"].append("extracted-member-hash-changed-or-unavailable")
            continue
        evidence.update(archive=str(archive), archive_sha256=item.get("archive_sha256"),
                        member=member, object=str(original), object_sha256=expected_object)
        units = _read_compile_units(original, args.readelf, out, stage)
        evidence["compile_units"] = units
        if len(units) != 1 or not Path(units[0]).is_absolute():
            evidence["gaps"].append("compilation-unit-source-not-unique-or-absolute")
            continue
        source = Path(units[0])
        evidence["source"] = str(source)
        evidence["source_sha256"] = sha256(source) if source.is_file() else None
        if not source.is_file():
            evidence["gaps"].append("compilation-unit-source-unavailable")
        cwd = run_dir / stage / "gcc"
        # The archive and the generated Makefile locate the relative ar and -o operands.
        if archive.parent != cwd or not (cwd / "Makefile").is_file():
            evidence["gaps"].append("build-working-directory-not-backed-by-archive-and-makefile")
            continue
        evidence["directory"] = str(cwd)
        log_meta = [entry for entry in identity.get("build_evidence", [])
                    if Path(entry.get("path", "")).name == log_name]
        if len(log_meta) != 1:
            evidence["gaps"].append("original-build-log-not-bound")
            continue
        log_path = collected_dir / log_meta[0].get("raw_copy", "")
        if not log_path.is_file() or sha256(log_path) != log_meta[0].get("sha256"):
            evidence["gaps"].append("original-build-log-hash-changed-or-unavailable")
            continue
        evidence["log_sha256"] = log_meta[0]["sha256"]
        commands = _logged_compile_candidates(log_path.read_text(encoding="utf-8", errors="replace"),
                                                str(source), member, archive.name)
        evidence["command_candidates"] = commands
        if len(commands) != 1:
            evidence["command_status"] = "ambiguous-or-unassociated"
            evidence["gaps"].append("compile-command-not-uniquely-associated")
            continue
        command = commands[0]
        executable = Path(command["argv"][0])
        is_elf = False
        if executable.is_file():
            with executable.open("rb") as stream:
                is_elf = stream.read(4) == b"\x7fELF"
        is_stage_wrapper = executable.is_relative_to(run_dir / "wrappers")
        evidence["command_status"] = ("associated-direct-compiler-command"
                                      if is_elf and not is_stage_wrapper
                                      else "associated-wrapper-command")
        evidence["command_line"] = command["line"]
        evidence["command_line_sha256"] = command["raw_line_sha256"]
        if executable.is_file():
            evidence["executable_current_sha256"] = sha256(executable)
        wrapper_identity = identity.get("stage_wrappers", {}).get(executable.name)
        evidence["executable_collected_sha256"] = (wrapper_identity or {}).get("sha256")
        evidence["executable_matches_collected"] = bool(
            wrapper_identity and executable.is_file()
            and sha256(executable) == wrapper_identity.get("sha256"))
        if evidence["command_status"] == "associated-wrapper-command":
            evidence["gaps"].append("wrapper-not-expanded")
        else:
            evidence["gaps"].append("historical-compiler-identity-not-bound")
    result = {"schema": "chimera-layout-codegen-resolution-v1",
              "collection": str(collected_path), "collection_sha256": sha256(collected_path),
              "instruction_line_sources": line_sources, "stages": stages,
              "root_cause_confirmed": False}
    (out / "resolution.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    _write_report(out / "report.md", result)
    print(f"resolution written: {out}")
    return 0


def collect(args: argparse.Namespace) -> int:
    repo, run_dir, out = args.repo.resolve(), args.run.resolve(), args.out.resolve()
    gate2 = run_dir / "build-gate2/gcc/xgcc"
    stack = run_dir / "build-stack/gcc/xgcc"
    gaps: list[str] = []
    if not gate2.is_file() or not stack.is_file():
        raise ValueError("both build-stack and build-gate2 xgcc inputs are required")
    gate_hash = sha256(gate2)
    stack_hash = sha256(stack)
    if args.expected_gate2_sha256 != EXPECTED_GATE2_SHA256 or gate_hash != args.expected_gate2_sha256:
        raise ValueError("gate2 ELF identity does not match the expected reviewed input")
    identity = {"gate2_sha256": gate_hash, "stack_sha256": stack_hash,
                "repo": str(repo), "run": str(run_dir), "sites": [hex(v) for v in SITES]}
    wrapper = getattr(args, "wrapper", None)
    identity["wrapper"] = ({"path": str(wrapper.resolve()), "sha256": sha256(wrapper)}
                           if wrapper and wrapper.is_file() else None)
    if wrapper and not wrapper.is_file():
        gaps.append("requested-wrapper-not-found")
    elif not wrapper:
        gaps.append("wrapper-identity-not-supplied")
    source_repo = repo / "cli/chimera"
    identity["wrapper_source"] = {
        str(path.relative_to(repo)): sha256(path)
        for path in (source_repo / "cli.py", source_repo / "llvm_wrapper.py") if path.is_file()
    }
    identity["stage_wrappers"] = {}
    for name in ("stack-cxx", "gate2-cxx"):
        script = run_dir / "wrappers" / name
        if script.is_file():
            copy = out / "stage-wrappers" / name
            copy.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(script, copy)
            identity["stage_wrappers"][name] = {
                "path": str(script), "sha256": sha256(script),
                "raw_copy": str(copy.relative_to(out))}
    (out / "identity.json").write_text(json.dumps(identity, indent=2), encoding="utf-8")
    for stage, elf in (("stack", stack), ("gate2", gate2)):
        identity[f"{stage}_stackobj_map"] = _read_stackobj_section(elf, out / f"{stage}.stackobj-map.json")
        if identity[f"{stage}_stackobj_map"].get("gap"):
            gaps.append(f"{stage}-stackobj-map:{identity[f'{stage}_stackobj_map']['gap']}")
    for stage, elf in (("stack", stack), ("gate2", gate2)):
        for flag, output in (("-SW", f"{stage}.sections.txt"), ("-rW", f"{stage}.relocations.txt")):
            code, _ = _run_capture([args.readelf, flag, str(elf)], out,
                                   f"{stage}.readelf-{flag[1:]}")
            if code:
                gaps.append(f"{stage}-readelf-{flag[1:]}-failed:{code}")
        code, _ = _run_capture([args.nm, "-n", "-C", str(elf)], out, f"{stage}.symbols")
        if code:
            gaps.append(f"{stage}-symbol-table-read-failed:{code}")
    sites: dict[str, Any] = {}
    stack_candidates: list[dict[str, Any]] = []
    for stage, elf in (("stack", stack), ("gate2", gate2)):
        code, full_dump = _run_capture(
            [args.objdump, "-d", f"--disassemble={args.layout_symbol}", str(elf)],
            out, f"{stage}.layout-function.objdump")
        (out / f"{stage}.layout-function.txt").write_text(full_dump, encoding="utf-8")
        if code:
            gaps.append(f"{stage}-layout-disassembly-failed")
        if stage == "stack":
            for line in full_dump.splitlines():
                match = INSN_RE.match(line)
                if match and match.group(3).lower() == "vs2r.v":
                    stack_candidates.append({"address": hex(int(match.group(1), 16)),
                                             "mnemonic": match.group(3),
                                             "instruction": line.strip(),
                                             "generation_origin": "unknown"})
            continue
        for address in SITES:
            site = extract_sites(full_dump, (address,))[0]
            source_code, source = _run_capture(
                [args.addr2line, "-f", "-C", "-i", "-e", str(elf), hex(address)],
                out, f"gate2.site-{address:x}.addr2line")
            if source_code:
                gaps.append(f"addr2line-failed:{address:#x}:{source_code}")
            sites[f"gate2:{address:#x}"] = {"site": site, "addr2line": source.strip().splitlines()}
    (out / "stack-layout-vector-store-candidates.json").write_text(
        json.dumps(stack_candidates, indent=2), encoding="utf-8")
    gate_records = identity["gate2_stackobj_map"].get("records", [])
    for record in sites.values():
        address = record["site"]["address"]
        matched_record = next((item for item in gate_records if item.get("linked_va") == address), None)
        record["gate2_map_record"] = matched_record
        map_info = identity["gate2_stackobj_map"]
        record["site"]["metadata_status"] = _metadata_state(map_info, address)
        record["metadata_chain"] = {
            "final_elf_map": map_info.get("status", "unknown"),
            "final_elf_matching_record": "present" if matched_record else
                ("absent" if map_info.get("status") == "section-present" else "unknown"),
            "object_map_record_correlation": "unknown",
            "chimera_stack_object_function_attribute": "unknown-before-replay",
            "pcsections": "unknown-before-replay",
            "machine_frame_index": "unknown-before-replay",
        }
        if matched_record is None:
            record["site"]["gaps"].append("absence-of-map-record-does-not-prove-non-stack")
    (out / "sites.json").write_text(json.dumps(sites, indent=2), encoding="utf-8")
    databases = sorted(run_dir.glob("**/compile_commands.json"))
    candidates: list[dict[str, Any]] = []
    sources = sorted({line for record in sites.values() for line in record["addr2line"]
                      if line and line != "??:0" and re.search(r":\d+(?::\d+)?$", line)})
    source_locations = []
    for location in sources:
        source_path = Path(source_path_from_dwarf_location(location))
        source_locations.append({"location": location, "path": str(source_path),
                                 "exists": source_path.is_file(),
                                 "sha256": sha256(source_path) if source_path.is_file() else None})
    (out / "dwarf-source-locations.json").write_text(
        json.dumps(source_locations, indent=2), encoding="utf-8")
    candidate_index: dict[tuple[str, int], dict[str, Any]] = {}
    for db in databases:
        try:
            rows = json.loads(db.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            gaps.append(f"unreadable-compile-database:{db}:{exc}")
            continue
        for source in sources:
            try:
                matches = match_compile_commands(rows, source_path_from_dwarf_location(source))
            except (OSError, ValueError) as exc:
                gaps.append(f"compile-command-match-failed:{db}:{source}:{exc}")
                continue
            for item in matches:
                record = item["record"]
                try:
                    raw_command = _command_tokens(record)
                except ValueError as exc:
                    gaps.append(f"compile-command-unusable:{db}:{item['index']}:{exc}")
                    continue
                cwd = Path(record.get("directory", ".")).resolve()
                compiler = raw_command[0] if raw_command else ""
                compiler_path = Path(compiler)
                if not compiler_path.is_absolute():
                    resolved_compiler = shutil.which(compiler)
                    compiler_path = Path(resolved_compiler) if resolved_compiler else (cwd / compiler_path).resolve()
                try:
                    command = _expanded_response_tokens(raw_command, cwd)
                except (OSError, ValueError) as exc:
                    gaps.append(f"response-file-unusable:{db}:{item['index']}:{exc}")
                    continue
                object_path = _compile_output_path(command, cwd)
                candidate = {"database": str(db.resolve()),
                                   "build_stage": "stack" if (run_dir / "build-stack").resolve() in db.resolve().parents else
                                                 "gate2" if (run_dir / "build-gate2").resolve() in db.resolve().parents else "unknown",
                                   **{key: value for key, value in item.items() if key != "record"},
                                   "source_sha256": sha256(Path(item["file"])) if Path(item["file"]).is_file() else None,
                                   "compiler": str(compiler_path),
                                   "compiler_sha256": sha256(compiler_path) if compiler_path.is_file() else None,
                                   "compile_database_sha256": sha256(db),
                                   "original_argv": command,
                                   "object": object_path,
                                   "object_exists": bool(object_path and Path(object_path).is_file()),
                                   "object_sha256": sha256(Path(object_path))
                                                    if object_path and Path(object_path).is_file() else None,
                                   "plugin_arguments": [token for token in command if "pass-plugin" in token.lower() or "chimera" in token.lower()]}
                candidate["plugin_identities"] = _plugin_identities(command, cwd)
                key = (candidate["database"], candidate["index"])
                if key in candidate_index:
                    prior = candidate_index[key]
                    prior["matched_dwarf_locations"] = prior.get("matched_dwarf_locations", []) + [source]
                else:
                    candidate["matched_dwarf_locations"] = [source]
                    candidate_index[key] = candidate
    candidates = list(candidate_index.values())
    for index, candidate in enumerate(candidates):
        object_path = Path(candidate["object"]) if candidate.get("object") else None
        if object_path and object_path.is_file():
            status, nm_text = _run_capture([args.nm, "--defined-only", str(object_path)],
                                           out, f"candidate-{index}.object-symbols")
            candidate["nm_exit"] = status
            candidate["defines_layout_symbol"] = _defines_symbol(nm_text, args.layout_symbol)
            for flag, suffix in (("-SW", "sections"), ("-rW", "relocations")):
                readelf_code, _ = _run_capture([args.readelf, flag, str(object_path)], out,
                                               f"candidate-{index}.object-{suffix}")
                if readelf_code:
                    gaps.append(f"compile-command-object-{suffix}-read-failed:{object_path}:{readelf_code}")
            obj_code, object_dump = _run_capture(
                [args.objdump, "-drw", f"--disassemble={args.layout_symbol}", str(object_path)],
                out, f"candidate-{index}.object-layout")
            type_code, header = _run_capture([args.readelf, "-h", str(object_path)], out,
                                             f"candidate-{index}.object-header")
            if status:
                gaps.append(f"compile-command-object-symbol-scan-failed:{object_path}:{status}")
            if type_code:
                gaps.append(f"compile-command-object-header-read-failed:{object_path}:{type_code}")
            elf_type_match = re.search(r"Type:\s*(\S+)", header)
            elf_type = elf_type_match.group(1) if elf_type_match else "unknown"
            candidate["object_elf_type"] = elf_type
            candidate["object_elf_header_exit"] = type_code
            candidate["object_disassembly_exit"] = obj_code
            candidate["object_address_coordinates"] = _object_coordinates(object_dump, elf_type)
            candidate["stackobj_map"] = _read_stackobj_section(
                object_path, out / f"candidate-{index}.object-stackobj-map.json")
            (out / f"candidate-{index}.object-address-coordinates.json").write_text(
                json.dumps(candidate["object_address_coordinates"], indent=2), encoding="utf-8")
            if not candidate["defines_layout_symbol"]:
                gaps.append(f"object-candidate-does-not-define-layout:{object_path}")
        elif candidate.get("object"):
            gaps.append(f"compile-output-object-not-present:{candidate['object']}")
    (out / "compile-command-candidates.json").write_text(json.dumps(candidates, indent=2), encoding="utf-8")
    if not databases:
        gaps.append("compile-commands-not-found")
    if not candidates:
        gaps.append("compile-command-not-located; original build logs were not treated as executable commands")
    if candidates and not any(item.get("defines_layout_symbol") for item in candidates):
        gaps.append("no-linked-object-candidate-proven-to-define-layout")
    if not getattr(args, "gate_list", None) or not args.gate_list.is_file():
        gate_hit = "unknown-gate-list-not-supplied"
        gaps.append("consumed-gate-list-not-supplied")
    else:
        try:
            names = set(_decision_gate_names(args.gate_list))
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            names = set()
            gate_hit = "invalid-gate-decision"
            gaps.append(f"gate-decision-unreadable-or-unstructured:{exc}")
        else:
            gate_hit = "exact-symbol-present" if args.layout_symbol in names else "exact-symbol-not-found"
            if gate_hit == "exact-symbol-not-found":
                gaps.append("layout-symbol-not-in-provided-gate-list")
        decision_copy = out / "decisions/gate2-consumed.json"
        decision_copy.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(args.gate_list, decision_copy)
        identity["consumed_decision"] = {"path": str(args.gate_list.resolve()), "sha256": sha256(args.gate_list),
                                         "copy": str(decision_copy.relative_to(out)),
                                         "provided_as_consumed_decision": True,
                                         "build_consumption_independently_verified": False}
        gaps.append("gate-decision-consumption-is-declared-but-not-independently-proven-by-this-collection")
    stack_decision = getattr(args, "stack_decision", None)
    if stack_decision and stack_decision.is_file():
        decision_copy = out / "decisions/stack-stage.json"
        decision_copy.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(stack_decision, decision_copy)
        identity["stack_stage_decision"] = {"path": str(stack_decision.resolve()),
                                             "sha256": sha256(stack_decision),
                                             "copy": str(decision_copy.relative_to(out)),
                                             "provided_as_consumed_decision": True,
                                             "build_consumption_independently_verified": False}
    else:
        gaps.append("stack-stage-decision-not-supplied")
    source_basenames = {Path(source_path_from_dwarf_location(line)).name for line in sources}
    if not source_basenames:
        gaps.append("dwarf-source-location-unavailable")
    source_paths = [Path(item["path"]) for item in source_locations if item.get("exists")]
    _collect_build_rules(run_dir, out, source_basenames, args.layout_symbol, gaps, source_paths)
    stage_object_candidates: list[dict[str, Any]] = []
    if source_basenames:
        for stage_name in ("build-stack", "build-gate2"):
            stage_root = run_dir / stage_name
            for basename in source_basenames:
                stem = Path(basename).stem
                for object_path in stage_root.rglob(stem + ".o"):
                    number = len([p for p in out.glob(f"{stage_name}.object-candidate-*.json")])
                    status, symbol_text = _run_capture([args.nm, "--defined-only", str(object_path)],
                                                       out, f"{stage_name}.object-candidate-{number}.nm")
                    candidate = {"stage": stage_name, "path": str(object_path),
                                 "sha256": sha256(object_path), "source_basename_match": basename,
                                 "nm_exit": status,
                                 "defines_layout": _defines_symbol(symbol_text, args.layout_symbol)}
                    if status:
                        gaps.append(f"object-candidate-symbol-scan-failed:{object_path}:{status}")
                    candidate["stackobj_map"] = _read_stackobj_section(
                        object_path, out / f"{stage_name}.object-candidate-{number}.stackobj-map.json")
                    for flag, suffix in (("-SW", "sections"), ("-rW", "relocations"), ("-h", "header")):
                        code, _ = _run_capture([args.readelf, flag, str(object_path)], out,
                                               f"{stage_name}.object-candidate-{number}.{suffix}")
                        if code:
                            gaps.append(f"object-candidate-{object_path}:{suffix}-read-failed:{code}")
                    if candidate["defines_layout"]:
                        obj_code, object_dump = _run_capture(
                            [args.objdump, "-drw", f"--disassemble={args.layout_symbol}", str(object_path)],
                            out, f"{stage_name}.object-candidate-{number}.layout")
                        candidate["object_address_coordinates"] = _object_coordinates(object_dump, "ET_REL")
                        if obj_code:
                            gaps.append(f"object-candidate-layout-disassembly-failed:{object_path}:{obj_code}")
                        (out / f"{stage_name}.object-candidate-{number}.coordinates.json").write_text(
                            json.dumps(candidate["object_address_coordinates"], indent=2), encoding="utf-8")
                    stage_object_candidates.append(candidate)
                    (out / f"{stage_name}.object-candidate-{number}.json").write_text(
                        json.dumps(candidate, indent=2), encoding="utf-8")
    archive_candidates = []
    for stage_name in ("build-stack", "build-gate2"):
        archive_candidates.extend(_collect_archive_candidates(
            run_dir / stage_name, stage_name, out, args, gaps, len(archive_candidates)))
    (out / "archive-layout-candidates.json").write_text(
        json.dumps(archive_candidates, indent=2), encoding="utf-8")
    for pattern in ("logs/stack-build.log", "logs/gate2-build.log", "logs/*configure.log"):
        for source in run_dir.glob(pattern):
            target = out / f"build-evidence-{source.name}"
            text = source.read_text(encoding="utf-8", errors="replace")
            terms = ("ChimeraStackObject", "fpass-plugin", "stackobject", "layout", "compile")
            excerpt = "\n".join(f"{index}: {line}" for index, line in enumerate(text.splitlines(), 1)
                                if any(term in line for term in terms))
            target.write_text(excerpt, encoding="utf-8")
            full_copy = out / "raw-build-logs" / source.name
            full_copy.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, full_copy)
            identity["build_evidence"] = identity.get("build_evidence", []) + [
                {"path": str(source), "sha256": sha256(source), "excerpt": target.name,
                 "raw_copy": str(full_copy.relative_to(out))}]
    identity["gate_list_check"] = gate_hit
    (out / "identity.json").write_text(json.dumps(identity, indent=2), encoding="utf-8")
    report = {"schema": "chimera-layout-codegen-forensics-v1", "sites": sites,
              "stack_layout_vector_store_candidates": stack_candidates,
              "dwarf_source_locations": source_locations,
              "compile_command_candidates": candidates,
              "stage_object_candidates": stage_object_candidates,
              "archive_layout_candidates": archive_candidates,
              "gate_list_check": gate_hit,
              "stackobj_map_status": {stage: identity[f"{stage}_stackobj_map"].get("status", "unknown")
                                      for stage in ("stack", "gate2")},
              "gaps": gaps,
              "interpretation": "An instruction mnemonic or absent map record does not identify generation origin or prove non-stack provenance.",
              "root_cause_confirmed": False}
    (out / "collection.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    _write_report(out / "report.md", report)
    print(f"collection written: {out}")
    print(f"source candidates={len(candidates)} gaps={len(gaps)}; root cause remains unconfirmed")
    return 0


def _read_stackobj_section(elf_path: Path, output: Path) -> dict[str, Any]:
    result: dict[str, Any] = {"elf": str(elf_path), "elf_sha256": sha256(elf_path),
                              "status": "unavailable", "records": []}
    try:
        from elftools.elf.elffile import ELFFile
    except ImportError:
        result["gap"] = "pyelftools-unavailable"
        output.write_text(json.dumps(result, indent=2), encoding="utf-8")
        return result
    try:
        with elf_path.open("rb") as stream:
            elf = ELFFile(stream)
            result["elf_type"] = str(elf.header["e_type"])
            section = elf.get_section_by_name(".chimera.stackobj_map")
            if section is None:
                result["status"] = "section-absent"
            else:
                data = bytes(section.data())
                result.update(status="section-present", section_address=hex(int(section["sh_addr"])),
                              section_offset=hex(int(section["sh_offset"])), size=len(data), raw_hex=data.hex())
                if result["elf_type"] != "ET_REL" and len(data) % 12 == 0:
                    import struct
                    result["records"] = [{"linked_va": hex(address), "soid": soid}
                                         for address, soid in struct.iter_unpack("<QI", data)]
                elif result["elf_type"] == "ET_REL":
                    result["gap"] = "ET_REL records require section-relative relocation resolution"
                else:
                    result["gap"] = "section length is not an array of 12-byte records"
    except Exception as exc:
        # A broken or truncated section is a recorded evidence gap, not a reason
        # to discard the other artifacts already collected for this ELF.
        result.update(status="elf-unreadable", gap=f"elf-parse-failed:{type(exc).__name__}:{exc}")
    output.write_text(json.dumps(result, indent=2), encoding="utf-8")
    return result


def _metadata_state(map_info: dict[str, Any], address: str) -> str:
    if map_info.get("status") == "section-absent":
        return "section-absent"
    if map_info.get("status") == "section-present":
        if any(item.get("linked_va") == address for item in map_info.get("records", [])):
            return "record-present"
        return "section-present-no-record-at-address"
    return "unknown-map-state"


def _index_diagnostic_metadata(directory: Path) -> dict[str, Any]:
    terms = {
        "chimera-stack-object-function-attribute": re.compile(r"chimera-stack-object"),
        "pcsections": re.compile(r"PCSections|pcsections", re.IGNORECASE),
        "frame-index": re.compile(r"FrameIndex|frame[- ]index|%stack\.\d+|FI#\d+", re.IGNORECASE),
    }
    evidence: dict[str, list[dict[str, str]]] = {name: [] for name in terms}
    artifacts = []
    for path in sorted(directory.rglob("*")):
        if not path.is_file():
            continue
        artifacts.append(str(path.relative_to(directory)))
        if path.suffix.lower() not in {".ll", ".mir", ".s", ".txt"}:
            continue
        try:
            with path.open("r", encoding="utf-8", errors="replace") as stream:
                for line_number, line in enumerate(stream, 1):
                    for name, pattern in terms.items():
                        if pattern.search(line) and len(evidence[name]) < 200:
                            evidence[name].append({"file": str(path.relative_to(directory)),
                                                   "line": str(line_number),
                                                   "text": line.rstrip()[:1000]})
        except OSError:
            continue
    return {"artifacts": artifacts,
            "observations": {name: {"status": "observed" if rows else "not-observed-in-captured-output",
                                    "evidence": rows} for name, rows in evidence.items()},
            "interpretation": "Not observed in captured output does not establish that the pass or metadata was absent."}


def _decision_document(path: Path) -> tuple[Any, dict[str, Any]]:
    """Load a gate decision as a document plus its ``decision`` root."""
    document = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        raise ValueError("gate decision JSON must contain an object")
    root = document.get("decision", document)
    if not isinstance(root, dict):
        raise ValueError("gate decision JSON decision field must be an object")
    return document, root


def gate_decision_variant(document: Any, target: str) -> tuple[Any, dict[str, Any]]:
    """Return a copy of ``document`` with exactly one name added to the gate list.

    The diff is *structural*, not textual: the variant is rejected unless
    restoring the original ``decision.gate.names`` list reproduces ``document``
    exactly.  A rewrite that also drifts any other semantic field therefore
    cannot pass as "only the names changed".
    """
    if not isinstance(document, dict):
        raise ValueError("gate decision JSON must contain an object")
    root = document.get("decision", document)
    gate = root.get("gate")
    if not isinstance(gate, dict):
        raise ValueError("gate decision must contain a gate object")
    names = gate.get("names")
    if not isinstance(names, list) or any(not isinstance(name, str) or not name for name in names):
        raise ValueError("gate decision must contain a structured gate.names string list")
    if target in names:
        raise ValueError("target symbol is already present in the original gate names")
    variant = deepcopy(document)
    variant_root = variant.get("decision", variant)
    variant_root["gate"]["names"] = sorted({*names, target})
    restored = deepcopy(variant)
    restored_root = restored.get("decision", restored)
    restored_root["gate"]["names"] = list(names)
    if restored != document:
        raise ValueError("decision variant would change more than decision.gate.names")
    similar = sorted(name for name in names
                     if name != target and (target.startswith(name) or name.startswith(target)))
    return variant, {
        "added": [target], "removed": [], "names_before": len(names),
        "names_after": len({*names, target}),
        "only_gate_names_changed": True,
        "similar_symbols_not_matched": similar,
        "target_match_rule": "exact mangled symbol equality; prefix and substring spellings are never the target",
    }


def verify_toolchain_manifest(manifest: dict[str, Any],
                              observed: dict[str, dict[str, str]]) -> dict[str, Any]:
    """Check every declared artifact hash against what this run actually uses.

    A declared artifact this run does not observe is a gap, not a pass: the
    manifest is allowed to be a superset, but nothing declared may disagree.
    """
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, dict) or not artifacts:
        raise ValueError("toolchain manifest must declare a non-empty artifacts object")
    checks: list[dict[str, Any]] = []
    gaps: list[str] = []
    for name in sorted(artifacts):
        entry = artifacts[name]
        if not isinstance(entry, dict):
            raise ValueError(f"toolchain manifest artifact {name} must be an object")
        declared = entry.get("sha256")
        if not declared:
            raise ValueError(f"toolchain manifest artifact {name} must declare sha256")
        actual = observed.get(name)
        if actual is None:
            checks.append({"artifact": name, "status": "not-observed"})
            gaps.append(f"toolchain-manifest-artifact-not-observed:{name}")
            continue
        current = actual.get("sha256")
        declared_path = entry.get("path")
        current_path = actual.get("path")
        path_matches = (declared_path is None or current_path is None
                        or str(Path(declared_path).resolve()) == str(Path(current_path).resolve()))
        sha_matches = bool(current) and current == declared
        checks.append({"artifact": name,
                       "status": "matched" if sha_matches and path_matches else "mismatch",
                       "declared_sha256": declared, "observed_sha256": current,
                       "declared_path": declared_path, "observed_path": current_path,
                       "path_matches": path_matches})
    return {"status": "mismatch" if any(item["status"] == "mismatch" for item in checks) else "matched",
            "checks": checks, "gaps": gaps}


def filter_census_rows(text: str, symbol: str) -> dict[str, Any]:
    """Select census rows by *exact* symbol equality.

    A ``blocked`` row is evidence the gate ran on this symbol.  It is never
    evidence on its own that the vector code or its local markers are gone.
    """
    rows: list[dict[str, Any]] = []
    gaps: list[str] = []
    total = 0
    for number, raw in enumerate(text.splitlines(), 1):
        if not raw.strip():
            continue
        total += 1
        fields = raw.split("\t")
        if len(fields) != 4 or fields[0] != CENSUS_TAG:
            gaps.append(f"census-line-not-parsed:{number}")
            continue
        _, mechanism, name, action = fields
        if name.strip() != symbol:
            continue
        rows.append({"line": number, "mechanism": mechanism, "name": name.strip(),
                     "action": action, "action_recognized": action in CENSUS_ACTIONS,
                     "mechanism_recognized": mechanism in CENSUS_MECHANISMS})
    return {"rows_total": total, "rows_for_exact_symbol": rows,
            "actions": sorted({row["action"] for row in rows}), "gaps": gaps,
            "note": ("a blocked census row proves the gate ran on the exact symbol; "
                     "it does not prove elimination, and a successful compile proves neither")}


def _first_disassembly_section(dump: str) -> str:
    match = re.search(r"Disassembly of section (.+):", dump)
    return match.group(1) if match else "unknown"


def vector_evidence(dump: str) -> dict[str, Any]:
    """Every vector instruction, ``vs2r.v`` and VLEN read in one function body."""
    instructions = _instruction_records(dump)
    vector = [item for item in instructions if VECTOR_MNEMONIC_RE.match(item["mnemonic"].lower())]
    vs2r = [item for item in instructions if item["mnemonic"].lower() == VS2R_MNEMONIC]
    vlen = [item for item in instructions if VLEN_READ_RE.search(item["text"])]
    shape = lambda rows: [{"offset": hex(item["address"]), "mnemonic": item["mnemonic"],
                           "operands": item["operands"], "text": item["text"]} for item in rows]
    return {"instruction_count": len(instructions), "vector_instruction_count": len(vector),
            "vector_instructions": shape(vector),
            "vector_mnemonic_counts": dict(sorted(Counter(item["mnemonic"] for item in vector).items())),
            "vs2r_v": shape(vs2r), "vlen_reads": shape(vlen),
            "section": _first_disassembly_section(dump)}


def classify_vector_delta(before: dict[str, Any], after: dict[str, Any],
                          *, evidence_ready: bool = True) -> dict[str, Any]:
    """Which vector operations disappeared, which remain, which appeared.

    ``evidence_ready`` is false when B did not compile, produced no object, or
    the target function was not disassembled.  An empty instruction list is
    then a *missing observation*, not an elimination, so the verdict stays
    ``None`` / ``unproven`` instead of silently reporting success.
    """
    counts_before = Counter(item["mnemonic"] for item in before["vector_instructions"])
    counts_after = Counter(item["mnemonic"] for item in after["vector_instructions"])
    eliminated = None if not evidence_ready else (after["vector_instruction_count"] == 0)
    status = ("unproven" if not evidence_ready
              else "vector-instructions-absent" if eliminated else "not-eliminated")
    return {
        "vector_mnemonics_disappeared": sorted(m for m in counts_before if m not in counts_after),
        "vector_mnemonics_remaining": sorted(m for m in counts_before if m in counts_after),
        "vector_mnemonics_appeared": sorted(m for m in counts_after if m not in counts_before),
        "vector_instruction_count_before": before["vector_instruction_count"],
        "vector_instruction_count_after": after["vector_instruction_count"],
        "vs2r_v_before": len(before["vs2r_v"]), "vs2r_v_after": len(after["vs2r_v"]),
        "vlen_reads_before": len(before["vlen_reads"]), "vlen_reads_after": len(after["vlen_reads"]),
        "vlen_reads_disappeared": (bool(before["vlen_reads"]) and not after["vlen_reads"])
                                  if evidence_ready else None,
        "vs2r_v_disappeared": (bool(before["vs2r_v"]) and not after["vs2r_v"])
                              if evidence_ready else None,
        "vector_instructions_eliminated": eliminated,
        "evidence_ready": evidence_ready,
        "elimination_status": status,
        "note": ("vector instructions and VLEN reads are listed separately; a census "
                 "'blocked' row or a successful compile never counts as elimination, and "
                 "a missing B object is a missing observation, never an elimination"),
    }


def _control_target_field(item: dict[str, Any]) -> int | None:
    """Operand index holding a direct branch/jump/call destination."""
    mnemonic = item["mnemonic"].lower()
    fields = [field.strip() for field in item["operands"].split(",")]
    if mnemonic in {"j", "tail", "call", "c.j", "c.jal"} and fields:
        return 0
    if mnemonic == "jal" and fields:
        return len(fields) - 1
    if mnemonic in {"c.beqz", "c.bnez"} and len(fields) >= 2:
        return len(fields) - 1
    if mnemonic.startswith(("beq", "bne", "blt", "bge", "bgt", "ble")) and len(fields) >= 2:
        return len(fields) - 1
    return None


def _split_target_identity(relocation_target: str) -> tuple[str, int]:
    identity = _symbol_target_identity(relocation_target)
    match = re.match(r"^(.+?)([+-]0x[0-9a-fA-F]+)$", identity)
    if not match:
        return identity, 0
    suffix = match.group(2)
    sign = -1 if suffix.startswith("-") else 1
    return match.group(1), sign * int(suffix[1:], 16)


def _instruction_sections(dump: str) -> list[str]:
    """Section name per instruction, in ``_instruction_records`` order."""
    sections: list[str] = []
    current = "unknown"
    for line in dump.splitlines():
        match = re.search(r"Disassembly of section (.+):", line)
        if match:
            current = match.group(1)
            continue
        if INSN_RE.match(line):
            sections.append(current)
    return sections


def _indirect_register(operands: str) -> str | None:
    """The register an indirect jump/call reads its destination from."""
    token = operands.strip().split(",")[0].strip()
    inner = re.search(r"\(([^)]*)\)", token)
    if inner:
        token = inner.group(1).strip()
    return token if re.fullmatch(r"(?:[a-z][a-z0-9]*|x\d+)", token) else None


def _annotated_call_target(operands: str) -> str | None:
    """GNU objdump's resolved ``jalr ... # addr <symbol>`` annotation."""
    match = re.search(r"#\s*(?:0x)?[0-9a-fA-F]+\s+<([^>]+)>", operands)
    return match.group(1) if match else None


def _jalr_fields(operands: str) -> tuple[str, str, int]:
    """Return ``(rd, rs1, immediate)`` for every objdump spelling of ``jalr``.

    ``jalr rs1`` and ``jalr imm(rs1)`` are the abbreviated forms objdump prints
    for ``jalr ra, rs1, imm``; the explicit forms are ``jalr rd, rs1, imm`` and
    ``jalr rd, imm(rs1)``.  The destination register decides call vs jump: only
    ``zero``/``x0`` makes it an *unlinked* transfer.
    """
    fields = [field.strip() for field in operands.split(",")]
    memory = lambda token: re.match(r"^(?:(-?(?:0x)?[0-9a-fA-F]+)\s*)?\(([^)]*)\)$", token)
    if len(fields) == 1:
        match = memory(fields[0])
        if match:
            return "ra", match.group(2).strip(), int(match.group(1) or 0, 0)
        return "ra", fields[0], 0
    rd = fields[0]
    match = memory(fields[1])
    if match:
        return rd, match.group(2).strip(), int(match.group(1) or 0, 0)
    return rd, fields[1], int(fields[2], 0) if len(fields) > 2 else 0


def resolve_local_control_flow(dump: str,
                               relocations: Mapping[tuple[str, int], Sequence[dict[str, Any]]] | None = None
                               ) -> dict[str, Any]:
    """Resolve one function's internal control flow from relocations + addends.

    Three rules keep a resolution honest:

    * **Section identity.** A relocation target is only an in-function edge
      when its section is the section this instruction lives in. ``.other+0x8``
      is never accepted just because this function happens to contain ``0x8``.
    * **Relocation type.** Only relocation types that really carry a
      branch/call destination are used; anything else would turn an unrelated
      addend into an invented edge.
    * **Indirect transfers.** ``ret`` ends the body, ``jr ra`` returns, an
      annotated ``jalr`` is an unknown external call, a plain ``jalr`` is an
      unknown indirect call -- but ``jr <non-ra>`` is an *unlinked* jump whose
      destination may be any block of this function, so it is unresolved and
      blocks every local source conclusion.

    ``relocations`` is the ELF relocation table keyed by ``(section, offset)``
    (see :func:`_object_relocations`).  When it is supplied it is the only
    authority for a relocated target: the symbol is identified by its symbol
    *index*, not by the name objdump printed.  Without it the resolver falls
    back to the printed names and stays honest about what it cannot prove.
    """
    instructions = _instruction_records(dump)
    sections = _instruction_sections(dump)
    distinct_sections = set(sections)
    address_indices = {item["address"]: index for index, item in enumerate(instructions)}
    symbol_addresses = _symbol_addresses(dump)
    relocation_table = relocations
    edges: list[dict[str, Any]] = []
    unresolved: list[dict[str, Any]] = []
    external: list[dict[str, Any]] = []
    indirect_jumps: list[dict[str, Any]] = []
    indirect_calls: list[dict[str, Any]] = []

    def note(index: int, mnemonic: str, reason: str) -> None:
        unresolved.append({"index": index, "mnemonic": mnemonic, "reason": reason})

    for index, item in enumerate(instructions):
        mnemonic = item["mnemonic"].lower()
        section = sections[index] if index < len(sections) else "unknown"
        if mnemonic in RETURN_MNEMONICS:
            edges.append({"index": index, "mnemonic": mnemonic, "kind": "return", "target": None})
            continue
        if mnemonic in INDIRECT_JUMP_MNEMONICS:
            register = _indirect_register(item["operands"])
            if register in LINK_REGISTERS:
                edges.append({"index": index, "mnemonic": mnemonic, "kind": "return",
                              "target": None, "register": register})
            else:
                indirect_jumps.append({"index": index, "mnemonic": mnemonic,
                                       "register": register, "section": section})
                note(index, mnemonic, "unresolved-indirect-jump")
            continue
        if mnemonic in INDIRECT_CALL_MNEMONICS:
            rd, rs1, immediate = _jalr_fields(item["operands"])
            unlinked = rd.lower() in ZERO_REGISTERS
            if unlinked and rs1 in LINK_REGISTERS and immediate == 0:
                # ``jalr zero,0(ra)`` / ``jr ra``: a return, not a transfer
                # into the body.
                edges.append({"index": index, "mnemonic": mnemonic, "kind": "return",
                              "target": None, "register": rs1})
                continue
            if unlinked:
                # No link register: the destination may be any block of this
                # function. An objdump annotation does not change that.
                indirect_jumps.append({"index": index, "mnemonic": mnemonic, "rd": rd,
                                       "rs1": rs1, "section": section})
                note(index, mnemonic, "unresolved-indirect-jump")
                continue
            call_relocation = None
            if relocation_table is not None:
                # The relocation on this jalr, or on the auipc it pairs with,
                # is the authoritative callee identity.
                for candidate in ((section, item["address"]), (section, item["address"] - 4)):
                    call_relocation = next(
                        (entry for entry in relocation_table.get(candidate, ())
                         if entry["type"] in CALL_RELOCATIONS and entry.get("symbol")), None)
                    if call_relocation is not None:
                        break
            annotated = _annotated_call_target(item["operands"])
            if call_relocation is not None:
                external.append({"index": index, "mnemonic": mnemonic,
                                 "symbol": call_relocation["symbol"],
                                 "addend": hex(call_relocation["addend"] or 0),
                                 "resolved_by": "paired-call-relocation"})
                edges.append({"index": index, "mnemonic": mnemonic, "kind": "external-unknown",
                              "target": call_relocation["symbol"]})
            elif annotated is not None:
                external.append({"index": index, "mnemonic": mnemonic, "symbol": annotated,
                                 "addend": "0x0"})
                edges.append({"index": index, "mnemonic": mnemonic, "kind": "external-unknown",
                              "target": annotated})
            else:
                indirect_calls.append({"index": index, "mnemonic": mnemonic, "rd": rd,
                                       "rs1": rs1, "section": section})
                edges.append({"index": index, "mnemonic": mnemonic, "kind": "indirect-call",
                              "target": None})
            continue
        field = _control_target_field(item)
        if field is None:
            continue
        printed: list[tuple[str, str]] = []
        for relocation in item.get("relocations", []):
            match = RELOCATION_RE.search(relocation)
            if not match:
                continue
            relocation_type, target = match.group(0).split(None, 1)
            if relocation_type == "R_RISCV_RELAX" or target == "*ABS*":
                continue
            printed.append((relocation_type, target))
        proven: dict[str, Any] | None = None
        if relocation_table is not None:
            usable = [entry for entry in relocation_table.get((section, item["address"]), [])
                      if entry["type"] != "R_RISCV_RELAX"
                      and entry.get("symbol") not in {"", "*ABS*"}]
            if len(usable) > 1:
                note(index, mnemonic, "multiple-relocation-targets")
                continue
            proven = usable[0] if usable else None
            if proven is None and printed:
                # objdump saw a relocation here but the ELF table does not have
                # one -- the table is unusable, so the placeholder operand must
                # not be trusted as a destination.
                note(index, mnemonic, "relocation-printed-but-absent-from-elf-table")
                continue
        elif printed:
            if len(printed) > 1:
                note(index, mnemonic, "multiple-relocation-targets")
                continue
            proven = {"type": printed[0][0], "printed_target": printed[0][1],
                      "symbol": None, "symbol_section": None, "symbol_value": None,
                      "addend": None}
        if proven is not None:
            if proven["type"] not in CONTROL_FLOW_RELOCATIONS:
                note(index, mnemonic, "relocation-type-not-a-control-flow-target")
                continue
            if relocation_table is not None:
                if proven["addend"] is None:
                    note(index, mnemonic, "relocation-addend-unparsable")
                    continue
                # The symbol was resolved through r_info, so its section and
                # value are the ones this relocation really points at.
                if proven["symbol_section"] == section and proven["symbol_value"] is not None:
                    target_index = address_indices.get(
                        proven["symbol_value"] + proven["addend"])
                    if target_index is None:
                        note(index, mnemonic, "relocation-target-outside-function")
                        continue
                    edges.append({"index": index, "mnemonic": mnemonic, "kind": "internal",
                                  "target": target_index, "section": proven["symbol_section"],
                                  "symbol_index": proven["symbol_index"],
                                  "resolved_by": "elf-relocation-symbol-index"})
                    continue
                if mnemonic in DIRECT_CALL_MNEMONICS:
                    external.append({"index": index, "mnemonic": mnemonic,
                                     "symbol": proven["symbol"],
                                     "addend": hex(proven["addend"] or 0),
                                     "relocation": proven["type"]})
                    edges.append({"index": index, "mnemonic": mnemonic,
                                  "kind": "external-unknown", "target": proven["symbol"]})
                    continue
                note(index, mnemonic, "relocation-target-section-mismatch")
                continue
            symbol, addend = _split_target_identity(proven["printed_target"])
            # Order matters: compiler local labels (``.LBB0_1``) also start with
            # a dot, so they must be recognised before the section-relative
            # form, otherwise a label name is mistaken for a section name and
            # rejected as a section mismatch.
            if symbol.startswith(LOCAL_LABEL_PREFIXES):
                base = symbol_addresses.get(symbol)
                if base is None:
                    note(index, mnemonic, "local-label-address-unknown")
                    continue
                target_index = address_indices.get(base + addend)
                if target_index is None:
                    note(index, mnemonic, "local-label-target-outside-function")
                    continue
                edges.append({"index": index, "mnemonic": mnemonic, "kind": "internal",
                              "target": target_index, "section": section,
                              "resolved_by": "relocation-local-label"})
                continue
            if symbol.startswith("."):
                if symbol != section:
                    note(index, mnemonic, "relocation-target-section-mismatch")
                    continue
                target_index = address_indices.get(addend)
                if target_index is None:
                    note(index, mnemonic, "section-offset-target-outside-function")
                    continue
                edges.append({"index": index, "mnemonic": mnemonic, "kind": "internal",
                              "target": target_index, "section": symbol,
                              "resolved_by": "relocation-section-addend"})
                continue
            base = symbol_addresses.get(symbol)
            if base is not None:
                target_index = address_indices.get(base + addend)
                if target_index is None:
                    note(index, mnemonic, "symbol-addend-target-outside-function")
                    continue
                edges.append({"index": index, "mnemonic": mnemonic, "kind": "internal",
                              "target": target_index, "section": section,
                              "resolved_by": "relocation-symbol-addend"})
                continue
            if mnemonic in DIRECT_CALL_MNEMONICS:
                external.append({"index": index, "mnemonic": mnemonic, "symbol": symbol,
                                 "addend": hex(addend), "relocation": relocation_type})
                edges.append({"index": index, "mnemonic": mnemonic, "kind": "external-unknown",
                              "target": symbol})
                continue
            note(index, mnemonic, "branch-target-symbol-not-in-function")
            continue
        fields = [field.strip() for field in item["operands"].split(",")]
        if field >= len(fields):
            note(index, mnemonic, "missing-target-operand")
            continue
        target = fields[field]
        address_match = re.match(r"^(?:0x)?([0-9a-fA-F]+)\b", target)
        if address_match:
            if len(distinct_sections) > 1:
                # Section-relative offsets repeat across sections, so a bare
                # address is not a proven destination here.
                note(index, mnemonic, "numeric-target-ambiguous-across-sections")
                continue
            target_index = address_indices.get(int(address_match.group(1), 16))
            if target_index is None:
                note(index, mnemonic, "numeric-target-outside-function")
                continue
            edges.append({"index": index, "mnemonic": mnemonic, "kind": "internal",
                          "target": target_index, "section": section,
                          "resolved_by": "numeric-operand"})
            continue
        label_match = re.search(r"<([^>]+)>", target)
        if label_match:
            label = label_match.group(1)
            base = symbol_addresses.get(label)
            if base is not None:
                target_index = address_indices.get(base)
                if target_index is None:
                    note(index, mnemonic, "symbol-target-outside-function")
                    continue
                edges.append({"index": index, "mnemonic": mnemonic, "kind": "internal",
                              "target": target_index, "section": section,
                              "resolved_by": "symbol-operand"})
                continue
            if mnemonic in DIRECT_CALL_MNEMONICS:
                external.append({"index": index, "mnemonic": mnemonic, "symbol": label,
                                 "addend": "0x0"})
                edges.append({"index": index, "mnemonic": mnemonic, "kind": "external-unknown",
                              "target": label})
                continue
        note(index, mnemonic, "target-operand-unresolved")
    if not instructions:
        status = "no-instructions"
    elif unresolved:
        status = "unresolved"
    else:
        status = "resolved"
    return {"status": status, "instruction_count": len(instructions), "edges": edges,
            "external_targets_kept_unknown": external, "unresolved": unresolved,
            "indirect_jumps_unresolved": indirect_jumps,
            "indirect_calls_unknown": indirect_calls,
            "relocation_table_used": relocation_table is not None,
            "relocation_entries": sum(len(rows) for rows in relocation_table.values())
                                  if relocation_table is not None else None,
            "sections": sorted(distinct_sections)}


def apply_resolved_control_flow(dump: str, control: dict[str, Any]) -> str:
    """Rewrite control-flow operands to the destinations proven by relocations.

    GNU objdump prints a placeholder destination for a relocated branch in a
    relocatable object (typically ``0x0``) and puts the real target in the
    relocation below the instruction.  The production parser reads the
    *operand*, so handing it the raw dump would build the CFG from placeholder
    destinations while the local check had already proven the real ones.  This
    rewrites the operand field to the resolved target and re-emits the line in
    the exact shape ``LinuxObjdump.parse_format`` expects
    (``addr: machine_code opcode operands``, one machine-code token).
    """
    instructions = _instruction_records(dump)
    edges_by_index: dict[int, list[dict[str, Any]]] = {}
    for edge in control.get("edges", []):
        edges_by_index.setdefault(edge["index"], []).append(edge)
    lines: list[str] = []
    index = -1
    for line in dump.splitlines():
        match = INSN_RE.match(line)
        if match is None:
            lines.append(line)
            continue
        index += 1
        item = instructions[index]
        mnemonic = match.group(3)
        internal = next((edge for edge in edges_by_index.get(index, [])
                         if edge["kind"] == "internal"), None)
        external = next((edge for edge in edges_by_index.get(index, [])
                         if edge["kind"] == "external-unknown"), None)
        field_index = _control_target_field(item)
        operand = match.group(4).strip()
        rewritten: str | None = None
        if field_index is not None:
            fields = [field.strip() for field in operand.split(",")]
            if field_index < len(fields):
                if internal is not None:
                    fields[field_index] = hex(instructions[internal["target"]]["address"])
                    rewritten = ",".join(fields)
                elif external is not None:
                    fields[field_index] = f"<{external['target']}>"
                    rewritten = ",".join(fields)
        elif external is not None and mnemonic.lower() in INDIRECT_CALL_MNEMONICS:
            # objdump annotates a call with the *unlinked* placeholder address
            # (``jalr ra # 16a <layout+0xba>``). The production builder reads
            # that comment as a branch destination, which would invent an
            # in-function edge for an external call. The annotation is removed
            # and the call - and its fallthrough - is kept.
            cleaned = CALL_ANNOTATION_RE.sub("", operand).strip()
            if cleaned != operand:
                rewritten = cleaned
        if rewritten is None:
            lines.append(line)
            continue
        machine_code = match.group(2).strip().split()[0]
        lines.append(f"   {int(match.group(1), 16):x}:\t{machine_code}\t{mnemonic}\t{rewritten}")
    return "\n".join(lines) + "\n"


def verify_cfg_edges(program: Any, instructions: Sequence[dict[str, Any]],
                     control: dict[str, Any]) -> list[str]:
    """Check the CFG the production builder produced against the resolved edges.

    Two failure directions matter and neither may pass silently:

    * a proven internal edge the builder did not create -- the analysis would
      run on a graph that is missing a branch;
    * an instruction we proved points at an unknown external symbol, but the
      builder read the placeholder operand as a jump *inside* the function.
    """
    problems: list[str] = []
    inside = {item["address"] for item in instructions}
    lookup = getattr(program, "instruction_by_address", {})
    for edge in control.get("edges", []):
        if edge["kind"] != "internal":
            continue
        source = instructions[edge["index"]]["address"]
        target = instructions[edge["target"]]["address"]
        node = lookup.get(source)
        if node is None or target not in getattr(node, "jump_targets", ()):
            problems.append(f"missing-edge:{source:#x}->{target:#x}")
    for edge in control.get("edges", []):
        if edge["kind"] != "external-unknown":
            continue
        source = instructions[edge["index"]]["address"]
        node = lookup.get(source)
        if node is None:
            continue
        misread = sorted(target for target in getattr(node, "jump_targets", ())
                         if target in inside)
        if misread:
            problems.append("external-target-misread-as-internal:"
                            f"{source:#x}->{[hex(target) for target in misread]}")
    return problems


def _production_local_facts(dump_text: str, symbol: str, workdir: Path,
                            label: str,
                            control: dict[str, Any] | None = None, *,
                            unknown_stack_size_policy: str = "conservative"
                            ) -> tuple[dict[str, Any], str | None]:
    """Run the production stack-liveness analyzer on one local function.

    Both experiment groups run in **binary mode** (``ChimeraMetadata.empty()``)
    so the comparison cannot silently switch criteria just because one object
    happens to carry a ``.chimera.stackobj_map`` section.  Nothing here writes
    a check credential and nothing here is a safety pass.
    """
    try:
        import chimera  # noqa: F401  registers the chimera.preprocess namespace

        from chimera.preprocess.offline.analysis.arch.riscv.control_flow import (
            is_call_instruction,
        )
        from chimera.preprocess.offline.analysis.arch.riscv.rvv.services import RvvServices
        from chimera.preprocess.offline.analysis.arch.riscv.services import RiscvServices
        from chimera.preprocess.offline.analysis.program_model.parser import parse_dump
        from chimera.preprocess.offline.analysis.safety.stack_liveness.accesses import (
            _VectorAccessPlanner,
            _VLenSensitiveAccessSelector,
        )
        from chimera.preprocess.offline.analysis.safety.stack_liveness.analyzer import (
            StackLivenessAnalyzer,
        )
        from chimera.preprocess.offline.analysis.safety.stack_liveness.frame_liveness import (
            VLEN_STACK_FRAME,
            VLEN_STACK_SETUP,
        )
        from chimera.preprocess.offline.analysis.safety.stack_liveness.model import (
            ChimeraMetadata,
            StackObjectId,
        )
        from chimera.preprocess.offline.analysis.toolchain.objdump import LinuxObjdump
    except Exception as exc:  # noqa: BLE001 - an import failure is evidence, not a crash
        return {}, f"production-analyzer-unavailable:{type(exc).__name__}"
    try:
        workdir.mkdir(parents=True, exist_ok=True)
        # Feed the production pipeline the dump whose control-flow operands
        # carry the relocation-proven destinations, not the raw placeholders.
        prepared = (apply_resolved_control_flow(dump_text, control)
                    if control is not None else dump_text)
        dump_file = workdir / f"{label}.local-function.dump"
        dump_file.write_text(prepared, encoding="utf-8")
        adapter = LinuxObjdump("objdump")
        parsed = parse_dump(dump_file, adapter.parse_format,
                            is_external_trampoline=adapter.is_external_trampoline,
                            retain_dump_lines=False)
        program = RiscvServices(RvvServices()).build_cfg(parsed)
        if control is not None:
            # A CFG that the local check could not resolve is not a CFG to
            # analyse on: verifying only the edges we *did* prove would pass
            # vacuously while an unproven transfer stays unresolved.
            if control.get("status") != "resolved":
                return {}, "local-cfg-not-reliably-resolved"
            problems = verify_cfg_edges(program, _instruction_records(dump_text), control)
            (workdir / f"{label}.cfg-verification.json").write_text(json.dumps({
                "resolved_edges": control.get("edges", []), "problems": problems,
                "applied_operand_rewrite": True}, indent=2), encoding="utf-8")
            if problems:
                # Analysing on a CFG that contradicts the proven edges would be
                # worse than no local verdict at all.
                return {}, ("production-cfg-disagrees-with-resolved-control-flow:"
                            + ";".join(problems))
        function = next((item for item in program.functions if item.name == symbol), None)
        if function is None:
            return {}, "production-analyzer-function-not-found-by-exact-symbol"
        extension = RvvServices()
        config_results = extension.vector_configs(program)
        metadata = ChimeraMetadata.empty()
        analyzer = StackLivenessAnalyzer(min_vlen_bits=256, semantics=extension.stack_semantics,
                                        emit_warnings=False,
                                        unknown_stack_size_policy=unknown_stack_size_policy)
        result = analyzer.analyze_program(program, metadata=metadata,
                                          config_results=config_results)
        local = result.by_function[function.start]
        plan = _VectorAccessPlanner(
            _VLenSensitiveAccessSelector(extension.stack_semantics, 256)
        ).plan(function, metadata, config_results[function.start])
        conservative = StackObjectId("conservative", "possible-stack-data")
        irreducible = StackObjectId("irreducible", f"{function.start:x}")
        call_sites = sorted(instruction.addr for instruction in function.insts
                            if is_call_instruction(instruction))
        live_at_calls = {site: local.live_before.get(site, frozenset()) for site in call_sites}

        def live_with(marker) -> list[str]:
            return [hex(address) for address, objects in sorted(local.live_before.items())
                    if marker in objects]

        def sites_with(marker) -> list[str]:
            return [hex(site) for site, objects in sorted(live_at_calls.items())
                    if marker in objects]

        return {
            "unknown_stack_size_policy": unknown_stack_size_policy,
            "analysis_mode": "binary", "metadata_mode": bool(plan.metadata_mode),
            "function_start": hex(function.start),
            "relevant_accesses": [hex(address) for address in sorted(plan.vlen_sensitive_addresses)],
            "binary_recovered_accesses": [hex(address) for address in sorted(plan.binary_addresses)],
            "compiler_access_ids": {hex(key): value
                                    for key, value in sorted(plan.compiler_access_ids.items())},
            "conservative_addresses": [hex(address) for address in sorted(local.conservative_addresses)],
            "conservative_object_live_at": live_with(conservative),
            "irreducible_object_live_at": live_with(irreducible),
            "irreducible_warning_addresses": [
                hex(address)
                for warning in local.warnings if warning.code == "irreducible-loop-degraded"
                for address in warning.addresses],
            "vlen_frame_marker_live_at": live_with(VLEN_STACK_FRAME),
            "vlen_setup_marker_live_at": live_with(VLEN_STACK_SETUP),
            "local_call_sites_carrying_objects": [hex(site) for site, objects
                                                  in sorted(live_at_calls.items()) if objects],
            "local_call_sites_carrying_conservative": sites_with(conservative),
            "local_call_sites_carrying_irreducible": sites_with(irreducible),
            "warnings": sorted({warning.code for warning in local.warnings}),
        }, None
    except Exception as exc:  # noqa: BLE001 - a failed diagnosis is a recorded gap
        return {}, f"production-analyzer-failed:{type(exc).__name__}"


def _section_index_names(text: str) -> dict[int, str]:
    """Map a section header index to its section name (``readelf -SW``)."""
    index_to_section: dict[int, str] = {}
    for line in text.splitlines():
        match = re.match(r"^\s*\[\s*(\d+)\]\s+(.*)$", line)
        if not match:
            continue
        fields = match.group(2).split()
        if fields and fields[0].startswith("."):
            index_to_section[int(match.group(1))] = fields[0]
    return index_to_section


def _object_symbols_by_index(text: str,
                             index_to_section: Mapping[int, str]) -> dict[int, dict[str, Any]]:
    """Index the ``.symtab`` rows by *symbol index*, never by name.

    Real objects reuse one name for thousands of local labels -- a measured
    gate2 object has 6721 ``.L0`` symbols with 5010 distinct values -- so a
    name is not an identity.  ``r_info`` identifies a relocation's symbol by
    index, and only the index picks the right ``section + value``.
    """
    table: dict[int, dict[str, Any]] = {}
    in_symtab = True
    for line in text.splitlines():
        header = re.search(r"Symbol table '([^']+)'", line)
        if header:
            # Relocations link to .symtab; .dynsym indices would collide.
            in_symtab = header.group(1) == ".symtab"
            continue
        if not in_symtab:
            continue
        match = re.match(
            r"^\s*(\d+):\s+([0-9a-fA-F]+)\s+\S+\s+(\S+)\s+\S+\s+\S+\s+(\S+)\s*(.*)$", line)
        if not match:
            continue
        index, value = int(match.group(1)), int(match.group(2), 16)
        section_index, name = match.group(4), match.group(5).strip()
        section = (index_to_section.get(int(section_index))
                   if section_index.isdigit() else None)
        table[index] = {"index": index, "name": name, "value": value, "section": section}
    return table


def _relocation_name_addend(text: str) -> tuple[str, int | None]:
    """Split readelf's ``name + addend`` column.

    readelf prints ``r_addend`` in **hexadecimal without a 0x prefix** -- a
    measured object shows ``ascii_themeE + 10`` for ``r_addend == 16``.  Reading
    that as decimal (or dropping it when it contains ``a``-``f``) constructs a
    wrong destination, so the literal is always parsed as hex and an unparsable
    one is reported as ``None`` instead of silently becoming zero.
    """
    stripped = text.strip()
    match = re.match(r"^(.*?)\s*([+-])\s*(\S+)$", stripped)
    if not match:
        return stripped, 0
    literal = match.group(3)
    if literal.lower().startswith("0x"):
        literal = literal[2:]
    if not re.fullmatch(r"[0-9a-fA-F]+", literal):
        return match.group(1).strip(), None
    sign = -1 if match.group(2) == "-" else 1
    return match.group(1).strip(), sign * int(literal, 16)


def _parse_relocation_table(sections_text: str, symbols_text: str,
                            relocation_text: str) -> dict[tuple[str, int], list[dict[str, Any]]]:
    """Build the ``(section, offset) -> relocation`` table from readelf output.

    Each entry resolves its symbol through ``r_info``'s symbol index, so the
    target's section, value and addend come from the symbol table row the
    relocation actually points at.  objdump's printed relocation *name* is
    never used as a lookup key: with thousands of same-named labels it cannot
    identify anything, and picking the first or nearest match would invent
    edges.
    """
    index_to_section = _section_index_names(sections_text)
    symbols = _object_symbols_by_index(symbols_text, index_to_section)
    table: dict[tuple[str, int], list[dict[str, Any]]] = {}
    current_section: str | None = None
    for line in relocation_text.splitlines():
        header = re.search(r"Relocation section '([^']+)'", line)
        if header:
            name = header.group(1)
            current_section = name[5:] if name.startswith(".rela") else name
            continue
        if current_section is None:
            continue
        match = re.match(r"^\s*([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s+(\S+)\s*(.*)$", line)
        if not match:
            continue
        offset, info = int(match.group(1), 16), int(match.group(2), 16)
        fields = match.group(4).split()
        if fields and re.fullmatch(r"[0-9a-fA-F]+", fields[0]):
            fields = fields[1:]
        name, addend = _relocation_name_addend(" ".join(fields))
        # ELF64 puts the symbol index in the high 32 bits; ELF32 uses >> 8.
        index = info >> 32
        if index not in symbols:
            index = info >> 8
        entry = symbols.get(index)
        table.setdefault((current_section, offset), []).append({
            "section": current_section, "offset": hex(offset), "type": match.group(3),
            "symbol_index": index, "symbol": (entry or {}).get("name", name),
            "symbol_section": (entry or {}).get("section"),
            "symbol_value": (entry or {}).get("value"), "addend": addend})
    return table


def _object_relocations(obj: Path, out: Path, args: argparse.Namespace,
                        label: str) -> dict[tuple[str, int], list[dict[str, Any]]]:
    """Read the ELF relocation table of an object (``readelf -SW/-sW/-rW``)."""
    sections_rc, sections_text = _run_capture([args.readelf, "-SW", str(obj)], out,
                                    f"{label}.object-sections")
    symbols_rc, symbols_text = _run_capture([args.readelf, "-sW", str(obj)], out,
                                   f"{label}.object-symbols")
    relocations_rc, relocation_text = _run_capture([args.readelf, "-rW", str(obj)], out,
                                      f"{label}.object-relocations")
    if sections_rc or symbols_rc or relocations_rc:
        raise ValueError("elf-relocation-inspection-failed:"
                         f"sections={sections_rc},symbols={symbols_rc},relocations={relocations_rc}")
    return _parse_relocation_table(sections_text, symbols_text, relocation_text)


def local_source_observation(obj: Path, symbol: str, out: Path, args: argparse.Namespace,
                             label: str, *,
                             unknown_stack_size_policy: str = "conservative") -> dict[str, Any]:
    """Build the local analysis input for one group's actual object."""
    observation: dict[str, Any] = {"label": label, "object": str(obj), "symbol": symbol,
                                   "unknown_stack_size_policy": unknown_stack_size_policy,
                                   "status": "incomplete", "gaps": [], "function_identity": None,
                                   "control_flow": None, "facts": {}, "analysis_mode": "binary"}
    out.mkdir(parents=True, exist_ok=True)
    if not obj.is_file():
        observation["gaps"].append("group-object-missing")
        return observation
    header_rc, header = _run_capture([args.readelf, "-h", str(obj)], out, f"{label}.local-header")
    if header_rc:
        observation["gaps"].append(f"object-header-inspection-failed:{header_rc}")
        return observation
    type_match = re.search(r"Type:\s*(\S+)", header)
    elf_type = type_match.group(1) if type_match else "unknown"
    dump_rc, dump = _run_capture([args.objdump, "-drw", f"--disassemble={symbol}", str(obj)],
                           out, f"{label}.local-function")
    if dump_rc:
        observation["gaps"].append(f"target-disassembly-failed:{dump_rc}")
        return observation
    instructions = _instruction_records(dump)
    if not instructions:
        observation["gaps"].append("target-function-not-disassembled")
        return observation
    identity = address_identity(elf_type=elf_type, section=_first_disassembly_section(dump),
                                offset=instructions[0]["address"])
    observation["function_identity"] = {"symbol": symbol,
                                        "section": _first_disassembly_section(dump),
                                        "section_offset": hex(instructions[0]["address"]),
                                        **identity}
    if identity.get("coordinate") != "section+offset":
        # ET_REL raw addresses are section coordinates, never linked addresses.
        observation["gaps"].append("object-is-not-et-rel; raw addresses are not linked addresses")
    try:
        relocation_table = _object_relocations(obj, out, args, label)
    except ValueError as exc:
        observation["gaps"].append(str(exc))
        return observation
    control = resolve_local_control_flow(dump, relocation_table)
    observation["control_flow"] = control
    observation["relocation_table"] = {
        "entries": sum(len(rows) for rows in relocation_table.values()),
        "source": "readelf -rW with r_info symbol indices from readelf -sW/-SW"}
    if control["status"] != "resolved":
        observation["gaps"].append("local-cfg-not-reliably-resolved")
        if not relocation_table:
            observation["gaps"].append("elf-relocation-table-unavailable; relocated "
                                       "targets cannot be resolved from printed names")
    if unknown_stack_size_policy == "conservative":
        # Preserve the original invocation contract for existing consumers.
        facts, error = _production_local_facts(dump, symbol, out, label, control)
    else:
        facts, error = _production_local_facts(
            dump, symbol, out, label, control,
            unknown_stack_size_policy=unknown_stack_size_policy)
    if error:
        observation["gaps"].append(error)
    else:
        observation["facts"] = facts
    if not observation["gaps"]:
        observation["status"] = "complete"
    return observation


def compare_local_sources(before: dict[str, Any], after: dict[str, Any],
                          *, address_correspondence: str = "not-established") -> dict[str, Any]:
    """Did A's local conservative sources disappear in B?

    Marker identity is **presence in B**, not address equality: gating moves
    code, so a conservative marker at ``0x100`` in A and ``0x200`` in B is the
    *same* surviving source.  Per-address "disappeared / remaining / appeared"
    lists are therefore only emitted when an address correspondence has been
    proven (``address_correspondence="established"``); otherwise they stay
    ``None`` rather than silently reporting a relocation as an elimination.

    Every marker category -- conservative, irreducible and the VLEN frame
    markers -- is judged separately, and an ``incomplete`` side never reports
    disappearance at all.
    """
    gaps: list[str] = []
    for side in (before, after):
        for gap in side.get("gaps", []):
            gaps.append(f"{side.get('label', '?')}:{gap}")
    complete = before.get("status") == "complete" and after.get("status") == "complete"
    comparable = address_correspondence == "established"
    fields: dict[str, Any] = {}
    for field in LOCAL_SOURCE_FIELDS:
        prior = set(before.get("facts", {}).get(field, ()) or ())
        current = set(after.get("facts", {}).get(field, ()) or ())
        fields[field] = {"before_count": len(prior), "after_count": len(current),
                         "present_in_a": bool(prior), "present_in_b": bool(current),
                         "disappeared": sorted(prior - current) if comparable else None,
                         "remaining": sorted(prior & current) if comparable else None,
                         "appeared": sorted(current - prior) if comparable else None}

    def verdict(members: Sequence[str]) -> bool | None:
        if not complete:
            return None
        if not any(fields[field]["present_in_a"] for field in members):
            # Nothing in A to disappear: the question is not applicable.
            return None
        return not any(fields[field]["present_in_b"] for field in members)

    groups: dict[str, Any] = {}
    for name, members in LOCAL_MARKER_GROUPS.items():
        present_a = any(fields[field]["present_in_a"] for field in members)
        present_b = any(fields[field]["present_in_b"] for field in members)
        groups[name] = {"fields": list(members), "present_in_a": present_a,
                        "present_in_b": present_b,
                        "count_a": sum(fields[field]["before_count"] for field in members),
                        "count_b": sum(fields[field]["after_count"] for field in members),
                        "disappeared": (present_a and not present_b) if complete else None}
    all_markers = tuple(field for members in LOCAL_MARKER_GROUPS.values() for field in members)
    return {"status": "complete" if complete else "incomplete",
            "address_correspondence": address_correspondence, "fields": fields,
            "marker_groups": groups,
            "markers_still_present_in_b": sorted(name for name, value in groups.items()
                                                 if value["present_in_b"]),
            "markers_remaining": sorted(field for field in LOCAL_SOURCE_FIELDS
                                        if fields[field]["present_in_b"]),
            "conservative_sources_disappeared": verdict(CONSERVATIVE_FIELDS),
            "local_markers_disappeared": verdict(all_markers),
            "gaps": sorted(set(gaps)),
            "note": ("marker identity is presence in B, never address equality: the gate "
                     "moves code, so a relocated marker is a surviving source. Per-address "
                     "deltas are emitted only under a proven address correspondence, and an "
                     "incomplete local source never reports disappearance")}


def _bind_replay_inputs(args: argparse.Namespace, collection: dict[str, Any],
                        collection_path: Path, identity: dict[str, Any],
                        build_stage: str, env_dir: Path, rewrite_dir: Path) -> dict[str, Any]:
    """Verify and bind one compile entry for an isolated replay.

    Shared by ``replay`` and ``gate-experiment`` so that the experiment cannot
    accidentally validate a different toolchain, source, plugin set or
    decision than the reviewed replay does.  ``env_dir`` / ``rewrite_dir`` let
    each caller isolate its gate list, census, dependency file and object.
    """
    run_dir = args.run.resolve()
    stage_dir = "build-stack" if build_stage == "stack" else "build-gate2"
    gate2_hash = sha256(run_dir / "build-gate2/gcc/xgcc")
    current_hash = sha256(run_dir / stage_dir / "gcc/xgcc")
    if gate2_hash != args.expected_gate2_sha256 or gate2_hash != identity["gate2_sha256"]:
        raise ValueError("gate2 ELF hash differs from the collected input")
    if current_hash != identity[f"{build_stage}_sha256"]:
        raise ValueError("selected stage ELF hash differs from the collected input")
    if build_stage == "gate2":
        decision_path = args.gate_list.resolve() if args.gate_list else None
        decision_identity = identity.get("consumed_decision")
        if decision_path is None or not decision_identity:
            raise ValueError("gate2 replay requires the consumed gate decision collected with this build")
        if not decision_path.is_file() or sha256(decision_path) != decision_identity.get("sha256"):
            raise ValueError("gate decision hash differs from the collected decision")
        gate_names = _decision_gate_names(decision_path)
        gate_targeted = args.layout_symbol in gate_names
        gate_decision = _decision_root(decision_path).get("gate", {})
        if not gate_decision.get("enabled"):
            raise ValueError("gate decision is not enabled for the gate2 replay")
    else:
        gate_targeted = False
        decision_path = args.stack_decision.resolve() if args.stack_decision else None
        decision_identity = identity.get("stack_stage_decision")
        if decision_path is None or not decision_identity:
            raise ValueError("stack replay requires the stack decision collected with this build")
        if not decision_path.is_file() or sha256(decision_path) != decision_identity.get("sha256"):
            raise ValueError("stack decision hash differs from the collected decision")
        if not _decision_root(decision_path).get("stack_object_plugin"):
            raise ValueError("stack decision does not enable the stack-object plugin")
    database_path: Path | None = None
    if args.compile_database:
        database_path = args.compile_database.resolve()
        rows = json.loads(database_path.read_text(encoding="utf-8"))
        if args.entry_index < 0 or args.entry_index >= len(rows):
            raise ValueError("compile database entry index is out of range")
        matches = [item for item in collection.get("compile_command_candidates", [])
                   if Path(item["database"]).resolve() == database_path
                   and item["index"] == args.entry_index
                   and item.get("build_stage") == build_stage]
        if len(matches) != 1 or matches[0]["status"] != "candidate":
            raise ValueError("selected compile entry is not a unique source candidate from this collection")
        candidate = matches[0]
        record = validate_collected_compile_entry(candidate, database_path, rows, args.entry_index)
    else:
        candidate = {"status": "explicit-command-review-required", "compiler_sha256": None,
                     "plugin_arguments": []}
        record = json.loads(args.compile_entry_json.read_text(encoding="utf-8"))
        if not isinstance(record, dict):
            raise ValueError("compile-entry JSON must be one compile_commands-style object")
        explicit_tokens = _expanded_response_tokens(
            _command_tokens(record), Path(record.get("directory", ".")).resolve())
        candidate["plugin_arguments"] = [token for token in explicit_tokens
                                         if "pass-plugin" in token.lower() or "chimera" in token.lower()]
        explicit_cwd = Path(record.get("directory", ".")).resolve()
        candidate["plugin_identities"] = _plugin_identities(explicit_tokens, explicit_cwd)
        explicit_source = Path(record["file"])
        if not explicit_source.is_absolute():
            explicit_source = (explicit_cwd / explicit_source).resolve()
        candidate["file"] = str(explicit_source)
        candidate["source_sha256"] = sha256(explicit_source) if explicit_source.is_file() else None
        candidate["compiler_sha256"] = None
        original_object = getattr(args, "original_object", None)
        if original_object is None:
            raise ValueError("explicit compile entry requires --original-object from the collection")
        original_object = original_object.resolve()
        object_candidate = _collected_original_object(collection, stage_dir, original_object)
        if object_candidate["kind"] == "archive-member":
            resolution_path = getattr(args, "resolution", None)
            if resolution_path is None:
                raise ValueError("archived original object requires --resolution identity evidence")
            resolution = json.loads(resolution_path.read_text(encoding="utf-8"))
            evidence = resolution.get("stages", {}).get(stage_dir, {})
            if (resolution.get("collection_sha256") != sha256(collection_path)
                    or evidence.get("object_sha256") != object_candidate["sha256"]
                    or evidence.get("source") != str(explicit_source)
                    or evidence.get("source_sha256") != candidate["source_sha256"]
                    or len(evidence.get("command_candidates", [])) != 1):
                raise ValueError("resolution does not bind this collection, object, source and command")
            _verified_resolution_command(
                evidence, collection_path.parent,
                "stack-build.log" if build_stage == "stack" else "gate2-build.log",
                explicit_source, object_candidate["member"], Path(object_candidate["archive"]).name)
            candidate["resolution"] = str(resolution_path.resolve())
        candidate.update(object=str(original_object), object_sha256=object_candidate["sha256"],
                         object_exists=True, defines_layout_symbol=True,
                         object_address_coordinates=object_candidate.get("object_address_coordinates", []))
    source = Path(candidate["file"])
    if not source.is_file() or (candidate.get("source_sha256") and sha256(source) != candidate["source_sha256"]):
        raise ValueError("translation-unit source is missing or its hash changed since collection")
    original_path = Path(candidate["object"])
    units = _read_compile_units(original_path, args.readelf, env_dir, "original")
    if units != [str(source)]:
        raise ValueError("compile source does not uniquely match the original object's compilation unit")
    cwd = Path(record["directory"]).resolve()
    stage_root = run_dir / stage_dir
    if not cwd.is_relative_to(stage_root):
        raise ValueError("compile entry working directory is outside the selected build stage")
    if not candidate.get("plugin_arguments"):
        raise ValueError("selected compile entry has no recorded Chimera plugin arguments")
    replay_tokens = _expanded_response_tokens(_command_tokens(record), cwd)
    replay_plugins = _plugin_identities(replay_tokens, cwd)
    collected_plugins = candidate.get("plugin_identities", [])
    if collected_plugins and replay_plugins != collected_plugins:
        raise ValueError("plugin identities differ from collected compile entry")
    if not replay_plugins or any(not item.get("sha256") for item in replay_plugins):
        raise ValueError("plugin binary identity is unavailable; refusing a source-attribution replay")
    isolated_env = prepare_replay_environment(build_stage, decision_path, env_dir, os.environ)
    gate_names_path = Path(isolated_env["CHIMERA_GATE_LIST"]) if build_stage == "gate2" else None
    argv, _ = rewrite_compile_command(record, rewrite_dir, gate_names_path)
    compiler = Path(argv[0])
    if not compiler.is_absolute():
        found = shutil.which(argv[0])
        if found:
            compiler = Path(found)
        else:
            compiler = (cwd / compiler).resolve()
    if not compiler.is_file():
        raise ValueError(f"compile tool is unavailable: {compiler}")
    _require_direct_compiler(str(compiler))
    tool_hash = sha256(compiler)
    if candidate.get("compiler_sha256") and tool_hash != candidate["compiler_sha256"]:
        raise ValueError("compiler hash differs from collection; refusing to interpret replay")
    argv[0] = str(compiler)
    return {"stage_dir": stage_dir, "gate2_hash": gate2_hash, "decision_path": decision_path,
            "gate_targeted": gate_targeted, "database_path": database_path, "candidate": candidate,
            "record": record, "source": source, "original_path": original_path, "units": units,
            "cwd": cwd, "compiler": compiler, "tool_hash": tool_hash,
            "replay_plugins": replay_plugins, "isolated_env": isolated_env,
            "gate_names_path": gate_names_path, "argv": argv}


def replay(args: argparse.Namespace) -> int:
    out, run_dir = args.out.resolve(), args.run.resolve()
    collection_path = args.collection.resolve()
    collection = json.loads(collection_path.read_text(encoding="utf-8"))
    identity_path = collection_path.with_name("identity.json")
    identity = json.loads(identity_path.read_text(encoding="utf-8"))
    binding = _bind_replay_inputs(args, collection, collection_path, identity, args.build_stage,
                                  out / "baseline-plugin-environment", out / "baseline")
    stage_dir = binding["stage_dir"]
    decision_path = binding["decision_path"]
    gate_targeted = binding["gate_targeted"]
    database_path = binding["database_path"]
    candidate = binding["candidate"]
    record = binding["record"]
    source = binding["source"]
    original_path = binding["original_path"]
    units = binding["units"]
    cwd = binding["cwd"]
    compiler = binding["compiler"]
    tool_hash = binding["tool_hash"]
    replay_plugins = binding["replay_plugins"]
    isolated_env = binding["isolated_env"]
    gate_names_path = binding["gate_names_path"]
    (out / "replay-identity.json").write_text(json.dumps({
        "stage": args.build_stage, "entry_index": args.entry_index,
        "compile_database": str(database_path) if database_path else None,
        "compile_entry_json": str(args.compile_entry_json.resolve()) if args.compile_entry_json else None,
        "source": str(source),
        "original_object": str(original_path), "original_object_sha256": sha256(original_path),
        "original_compilation_units": units,
        "source_sha256": sha256(source), "cwd": str(cwd), "compiler": str(compiler),
        "compiler_sha256": tool_hash, "plugin_arguments": candidate.get("plugin_arguments", []),
        "plugin_identities": replay_plugins,
        "decision_path": str(decision_path), "decision_sha256": sha256(decision_path),
        "gate_targeted": gate_targeted,
        "plugin_environment_outputs": {name: isolated_env[name] for name in
                                        ("CHIMERA_GATE_LIST", "CHIMERA_GATE_STATS", "TMPDIR") if name in isolated_env},
    }, indent=2), encoding="utf-8")

    baseline = _execute_compile_pass(record, out / "baseline", cwd, compiler, [], "baseline",
                                     isolated_env, gate_names_path)
    pass_results = [baseline]
    original_dump = collection_path.parent / f"{args.build_stage}.layout-function.txt"
    replay_dump = out / "baseline" / "layout-function.objdump.txt"
    if (out / "baseline/replay.o").is_file():
        _run_capture([args.objdump, "-drw", f"--disassemble={args.layout_symbol}",
                      str(out / "baseline/replay.o")], out / "baseline",
                     "layout-function-object-objdump")
        _collect_replay_object(out / "baseline/replay.o", out / "baseline",
                               args, "baseline")
        replay_dump.write_text((out / "baseline/layout-function-object-objdump.stdout.txt").read_text(
            encoding="utf-8", errors="replace"), encoding="utf-8")
    original_text = original_dump.read_text(encoding="utf-8", errors="replace") if original_dump.is_file() else ""
    replay_text = replay_dump.read_text(encoding="utf-8", errors="replace") if replay_dump.is_file() else ""
    stage_comparison = compare_replay_sites(original_text, replay_text, ())
    gate2_reference = collection_path.parent / "gate2.layout-function.txt"
    gate2_text = gate2_reference.read_text(encoding="utf-8", errors="replace") if gate2_reference.is_file() else ""
    site_comparison = compare_replay_sites(gate2_text, replay_text, SITES)
    sequence_matches = stage_comparison["function_correspondence"] == "matched"
    baseline_object_coordinates = (
        json.loads((out / "baseline/baseline.object-address-coordinates.json").read_text(encoding="utf-8"))
        if (out / "baseline/baseline.object-address-coordinates.json").is_file() else [])
    baseline_object_comparison = compare_object_coordinates(
        candidate.get("object_address_coordinates", []), baseline_object_coordinates)
    for site in site_comparison["sites"]:
        index = site.get("linked_function_instruction_index")
        collected = collection.get("sites", {}).get(f"gate2:{site['original_address']}", {})
        site["final_elf_metadata_status"] = collected.get("site", {}).get("metadata_status", "unknown")
        site["object_map_record_correlation"] = "unknown-until-relocations-are-applied"
        site["object_coordinates"] = {"original_et_rel": None, "replay_et_rel": None}
        site["evidence_artifacts"] = ["gate2.layout-function.txt",
                                      f"{args.build_stage}.layout-function.txt",
                                      "baseline/baseline.object-address-coordinates.json"]
        if (isinstance(index, int) and site.get("status") == "sequence-correlated"
                and baseline_object_comparison["status"] == "matched"
                and index < len(candidate.get("object_address_coordinates", []))
                and index < len(baseline_object_coordinates)):
            site["object_coordinates"] = {
                "original_et_rel": candidate["object_address_coordinates"][index],
                "replay_et_rel": baseline_object_coordinates[index],
            }
    comparison = {
        "stage": args.build_stage,
        "selected_stage_function_correspondence": stage_comparison["function_correspondence"],
        "selected_stage_original_instruction_count": stage_comparison["original_instruction_count"],
        "replay_instruction_count": stage_comparison["replay_instruction_count"],
        "gate2_site_function_correspondence": site_comparison["function_correspondence"],
        "gate2_site_original_instruction_count": site_comparison["original_instruction_count"],
        "mnemonic_and_operand_sequence_matches": sequence_matches,
        "sites": site_comparison["sites"],
        "baseline_object_comparison": baseline_object_comparison,
        "linked_address_relocation_resolution_requires_review": True,
    }
    baseline_equivalent = (comparison["baseline_object_comparison"]["status"] == "matched"
                           and sequence_matches)
    if baseline["exit_code"] == 0 and baseline_equivalent:
        diag_dir = out / "diagnostics"
        filter_arg = f"-filter-print-funcs={args.layout_symbol}"
        diagnostic_argv = args.diagnostic_arg or [
            "-mllvm", "-chimera-stackobject-debug", "-mllvm", "-print-before-all",
            "-mllvm", "-print-after-all", "-mllvm", filter_arg,
        ]
        if filter_arg not in diagnostic_argv:
            diagnostic_argv.extend(("-mllvm", filter_arg))
        diagnostic_env = prepare_replay_environment(args.build_stage, decision_path,
                                                    out / "diagnostics-plugin-environment", os.environ)
        diagnostic_gate_list = (Path(diagnostic_env["CHIMERA_GATE_LIST"])
                                if args.build_stage == "gate2" else None)
        diagnostic_argv = [*diagnostic_argv, "-save-temps=obj"]
        diagnostic = _execute_compile_pass(record, diag_dir, cwd, compiler,
                                           diagnostic_argv, "diagnostics", diagnostic_env,
                                           diagnostic_gate_list)
        pass_results.append(diagnostic)
        diagnostic_object = diag_dir / "replay.o"
        if diagnostic["exit_code"] == 0 and diagnostic_object.is_file():
            _collect_replay_object(diagnostic_object, diag_dir, args, "diagnostics")
        diagnostic_index = _index_diagnostic_metadata(diag_dir)
        diagnostic_index["pass_status"] = "completed" if diagnostic["exit_code"] == 0 else "failed-or-option-unsupported"
        (out / "diagnostic-metadata-evidence.json").write_text(
            json.dumps(diagnostic_index, indent=2), encoding="utf-8")
        artifact_report = sorted(str(path.relative_to(out)) for path in out.rglob("*") if path.is_file())
        (out / "diagnostic-capabilities.json").write_text(json.dumps({
            "exit_code": diagnostic["exit_code"],
            "status": "captured" if diagnostic["exit_code"] == 0 else "unsupported-or-failed",
            "requested_args": diagnostic["argv"], "artifacts": artifact_report,
            "note": "A failed diagnostic pass is a gap; baseline replay remains separately recorded.",
        }, indent=2), encoding="utf-8")
    else:
        (out / "diagnostic-capabilities.json").write_text(json.dumps({
            "status": "not-scanned-baseline-failed" if baseline["exit_code"] != 0
                      else "not-scanned-baseline-mismatch-or-object-relocation-difference",
            "artifacts": []
        }, indent=2), encoding="utf-8")
    diagnostic_evidence_exists = (out / "diagnostic-metadata-evidence.json").is_file()
    for site in comparison["sites"]:
        site["diagnostic_metadata_evidence"] = (
            "diagnostic-metadata-evidence.json" if diagnostic_evidence_exists
            else "not-collected; see diagnostic-capabilities.json")
    (out / "replay-comparison.json").write_text(json.dumps(comparison, indent=2), encoding="utf-8")
    (out / "site-assessments.json").write_text(json.dumps({
        "sites": comparison["sites"],
        "rule": "Sites remain unknown unless their instruction position is anchored by an exact function instruction signature match and the baseline object relocation comparison matches.",
    }, indent=2), encoding="utf-8")
    completed_baseline = baseline["exit_code"]
    gaps = []
    toolchain_matches = bool(candidate.get("compiler_sha256") and tool_hash == candidate["compiler_sha256"])
    if not toolchain_matches:
        gaps.append("historical-compiler-identity-not-bound")
    if not sequence_matches:
        gaps.append("replay-function-mismatch; replay outputs are experimental evidence only")
    if comparison["baseline_object_comparison"]["status"] != "matched":
        gaps.append("baseline-object-instruction-or-relocation-targets-not-equivalent")
    if len(pass_results) > 1 and pass_results[1]["exit_code"] != 0:
        gaps.append("diagnostic-arguments-unsupported-or-diagnostic-replay-failed")
    gaps.append("review link-time relocation resolution and stack-object record correlation before assigning either site origin")
    report = {"schema": "chimera-layout-codegen-forensics-replay-v1",
              "passes": pass_results,
              "gate_targeted": gate_targeted,
              "function_correspondence": comparison["selected_stage_function_correspondence"],
              "site_assessments": comparison["sites"],
              "toolchain_matches_collection": toolchain_matches, "root_cause_confirmed": False, "gaps": gaps}
    (out / "replay-result.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    _write_report(out / "report.md", report)
    print(f"baseline replay exit={completed_baseline}; replay evidence written: {out}")
    return _shell_exit_code(completed_baseline)


def _run_experiment_group(label: str, binding: dict[str, Any], decision_path: Path,
                          group_dir: Path, args: argparse.Namespace, target: str,
                          diagnostic_argv: Sequence[str]) -> dict[str, Any]:
    """Compile, collect and diagnose one isolated experiment group.

    The object, dependency file, gate list, census, temporary directory and
    logs of a group all live under ``group_dir``; the compiler argv is
    executed directly (no wrapper, no log text interpretation).
    """
    group_dir.mkdir(parents=True, exist_ok=True)
    environment = prepare_replay_environment("gate2", decision_path,
                                             group_dir / "plugin-environment", os.environ)
    gate_names_path = Path(environment["CHIMERA_GATE_LIST"])
    census_path = Path(environment["CHIMERA_GATE_STATS"])
    group: dict[str, Any] = {
        "label": label, "decision": str(decision_path), "decision_sha256": sha256(decision_path),
        "gate_names_path": str(gate_names_path), "census_path": str(census_path),
        "gate_names_count": len(_decision_gate_names(decision_path)),
        "target_in_gate_names": target in set(_decision_gate_names(decision_path)),
        "compile": _execute_compile_pass(binding["record"], group_dir / "baseline",
                                         binding["cwd"], binding["compiler"], [], "baseline",
                                         environment, gate_names_path),
        "artifacts_directory": str(group_dir),
    }
    obj = group_dir / "baseline" / "replay.o"
    group["object"] = str(obj)
    group["object_exists"] = obj.is_file()
    if obj.is_file():
        _collect_replay_object(obj, group_dir / "baseline", args, "baseline")
        coordinates_file = group_dir / "baseline" / "baseline.object-address-coordinates.json"
        group["object_coordinates"] = (json.loads(coordinates_file.read_text(encoding="utf-8"))
                                       if coordinates_file.is_file() else [])
        _, dump = _run_capture([args.objdump, "-drw", f"--disassemble={target}", str(obj)],
                               group_dir / "baseline", "layout-function-object-objdump")
        (group_dir / "baseline" / "layout-function.txt").write_text(dump, encoding="utf-8")
        group["vector_evidence"] = vector_evidence(dump)
        stackobj_file = group_dir / "baseline" / "baseline.object-stackobj-map.json"
        group["metadata_section"] = (json.loads(stackobj_file.read_text(encoding="utf-8"))
                                     if stackobj_file.is_file()
                                     else {"status": "unknown", "records": []})
    else:
        group["object_coordinates"] = []
        group["vector_evidence"] = vector_evidence("")
        group["metadata_section"] = {"status": "unknown", "records": []}
    census_text = census_path.read_text(encoding="utf-8", errors="replace") if census_path.is_file() else ""
    group["census"] = filter_census_rows(census_text, target)
    if not census_path.is_file():
        group["census"]["gaps"].append("census-file-not-produced")
    group["diagnostics"] = _run_experiment_diagnostics(label, binding, decision_path, group_dir,
                                                       args, target, diagnostic_argv,
                                                       group["object_coordinates"])
    group["local_source"] = local_source_observation(obj, target, group_dir / "local-source",
                                                     args, label)
    return group


def _run_experiment_diagnostics(label: str, binding: dict[str, Any], decision_path: Path,
                                group_dir: Path, args: argparse.Namespace, target: str,
                                diagnostic_argv: Sequence[str],
                                baseline_coordinates: Sequence[dict[str, Any]]) -> dict[str, Any]:
    """Append function-filtered IR/MIR diagnostics to one group's baseline.

    A diagnostic object that differs from its own baseline, or an option the
    compiler does not support, is a recorded gap -- never a gate failure.
    """
    diagnostics_dir = group_dir / "diagnostics"
    environment = prepare_replay_environment("gate2", decision_path,
                                             diagnostics_dir / "plugin-environment", os.environ)
    argv = [*diagnostic_argv, "-save-temps=obj"]
    result = _execute_compile_pass(binding["record"], diagnostics_dir, binding["cwd"],
                                   binding["compiler"], argv, "diagnostics", environment,
                                   Path(environment["CHIMERA_GATE_LIST"]))
    summary: dict[str, Any] = {"exit_code": result["exit_code"], "signal": result.get("signal"),
                               "requested_args": list(argv), "gaps": []}
    diagnostic_object = diagnostics_dir / "replay.o"
    if result["exit_code"] != 0:
        summary["gaps"].append("diagnostic-pass-failed-or-option-unsupported")
        summary["status"] = "diagnostic-gap-only"
    if not diagnostic_object.is_file():
        summary["gaps"].append("diagnostic-object-missing")
        summary.setdefault("status", "diagnostic-gap-only")
        return summary
    _collect_replay_object(diagnostic_object, diagnostics_dir, args, "diagnostics")
    coordinates_file = diagnostics_dir / "diagnostics.object-address-coordinates.json"
    coordinates = (json.loads(coordinates_file.read_text(encoding="utf-8"))
                   if coordinates_file.is_file() else [])
    comparison = compare_object_coordinates(baseline_coordinates, coordinates)
    summary["object_comparison"] = comparison
    if comparison["status"] != "matched":
        summary["gaps"].append("diagnostic-object-differs-from-own-baseline")
        summary.setdefault("status", "diagnostic-gap-only")
    index = _index_diagnostic_metadata(diagnostics_dir)
    summary["metadata_index"] = index
    summary.setdefault("status", "captured")
    return summary


def _vector_evidence_gaps(group: dict[str, Any]) -> list[str]:
    """Why this group's vector evidence cannot support an elimination verdict.

    An empty instruction list is indistinguishable between "the gate removed
    every vector instruction" and "nothing was ever disassembled", so the
    caller must refuse the elimination verdict until these are all gone.
    """
    reasons: list[str] = []
    if group["compile"]["exit_code"] != 0:
        reasons.append(f"compile-exit:{group['compile']['exit_code']}")
    if not group.get("object_exists"):
        reasons.append("object-missing")
    if group.get("vector_evidence", {}).get("instruction_count", 0) == 0:
        reasons.append("target-function-not-disassembled")
    return reasons


def gate_experiment(args: argparse.Namespace) -> int:
    """A/B gate experiment for one exact target symbol.

    A uses the original decision byte-for-byte; B uses a variant whose only
    difference is the added exact symbol.  A must first reproduce the original
    object at the object layer; otherwise B never runs.
    """
    out = args.out.resolve()
    collection_path = args.collection.resolve()
    collection = json.loads(collection_path.read_text(encoding="utf-8"))
    identity = json.loads(collection_path.with_name("identity.json").read_text(encoding="utf-8"))
    target = args.target_symbol or args.layout_symbol
    binding = _bind_replay_inputs(args, collection, collection_path, identity, "gate2",
                                  out / "binding" / "plugin-environment",
                                  out / "binding" / "baseline")
    (out / "experiment-identity.json").write_text(json.dumps({
        "schema": EXPERIMENT_SCHEMA,
        "target_symbol": target, "layout_symbol": args.layout_symbol,
        "source": str(binding["source"]), "source_sha256": sha256(binding["source"]),
        "original_object": str(binding["original_path"]),
        "original_object_sha256": sha256(binding["original_path"]),
        "compile_entry_json": (str(args.compile_entry_json.resolve())
                               if args.compile_entry_json else None),
        "compile_database": (str(args.compile_database.resolve())
                             if args.compile_database else None),
        "resolution": str(args.resolution.resolve()) if args.resolution else None,
        "cwd": str(binding["cwd"]), "compiler": str(binding["compiler"]),
        "compiler_sha256": binding["tool_hash"],
        "plugin_identities": binding["replay_plugins"],
        "plugin_order": [item["path"] for item in binding["replay_plugins"]],
        "gate_decision": str(binding["decision_path"]),
        "gate_decision_sha256": sha256(binding["decision_path"]),
        "collection": str(collection_path), "collection_sha256": sha256(collection_path),
    }, indent=2), encoding="utf-8")

    manifest = json.loads(args.toolchain_manifest.read_text(encoding="utf-8"))
    observed: dict[str, dict[str, str]] = {
        "compiler": {"path": str(binding["compiler"]), "sha256": binding["tool_hash"]},
        "source": {"path": str(binding["source"]), "sha256": sha256(binding["source"])},
        "original_object": {"path": str(binding["original_path"]),
                            "sha256": sha256(binding["original_path"])},
        "gate_decision": {"path": str(binding["decision_path"]),
                          "sha256": sha256(binding["decision_path"])},
        "collection": {"path": str(collection_path), "sha256": sha256(collection_path)},
    }
    for index, plugin in enumerate(binding["replay_plugins"]):
        observed[f"plugin:{index}"] = {"path": plugin.get("path", ""),
                                       "sha256": plugin.get("sha256") or ""}
    if args.resolution:
        observed["resolution"] = {"path": str(args.resolution.resolve()),
                                  "sha256": sha256(args.resolution.resolve())}
    if args.compile_entry_json:
        observed["compile_entry"] = {"path": str(args.compile_entry_json.resolve()),
                                     "sha256": sha256(args.compile_entry_json.resolve())}
    verification = verify_toolchain_manifest(manifest, observed)
    (out / "toolchain-verification.json").write_text(
        json.dumps(verification, indent=2), encoding="utf-8")
    if verification["status"] == "mismatch":
        raise ValueError("toolchain manifest hash mismatch; refusing to run the experiment")

    original_names = _decision_gate_names(binding["decision_path"])
    if target in original_names:
        raise ValueError("target symbol is already in the original gate decision; experiment would be empty")

    document, _root = _decision_document(binding["decision_path"])
    variant, decision_diff = gate_decision_variant(document, target)
    group_a_decision = out / "group-A" / "decision.json"
    group_a_decision.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(binding["decision_path"], group_a_decision)
    if sha256(group_a_decision) != sha256(binding["decision_path"]):
        raise ValueError("group A decision copy is not byte-identical to the original")
    # The variant is staged outside the group directories so that group B is
    # only created if group A actually reproduced the original object.
    variant_path = out / "binding" / "decision-variant.json"
    variant_path.parent.mkdir(parents=True, exist_ok=True)
    variant_path.write_text(json.dumps(variant, indent=2), encoding="utf-8")
    decision_diff["original_decision_sha256"] = sha256(binding["decision_path"])
    decision_diff["group_a_decision_sha256"] = sha256(group_a_decision)
    decision_diff["variant_decision_sha256"] = sha256(variant_path)
    decision_diff["target_absent_from_original_names"] = target not in original_names
    (out / "decision-diff.json").write_text(json.dumps(decision_diff, indent=2), encoding="utf-8")

    filter_arg = f"-filter-print-funcs={target}"
    diagnostic_argv = list(args.diagnostic_arg) or [
        "-mllvm", "-chimera-stackobject-debug", "-mllvm", "-print-before-all",
        "-mllvm", "-print-after-all", "-mllvm", filter_arg,
    ]
    if filter_arg not in diagnostic_argv:
        diagnostic_argv.extend(("-mllvm", filter_arg))

    gaps: list[str] = list(verification["gaps"])
    stopped: str | None = None
    groups: dict[str, dict[str, Any]] = {}
    for label in EXPERIMENT_GROUPS:
        if stopped:
            break
        if label == "A":
            decision = group_a_decision
        else:
            decision = out / "group-B" / "decision.json"
            decision.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(variant_path, decision)
        group = _run_experiment_group(label, binding, decision, out / f"group-{label}",
                                      args, target, diagnostic_argv)
        groups[label] = group
        # A non-zero exit, a signal and a failed diagnostic option are evidence
        # that must survive even when the experiment stops early.
        if group["compile"]["exit_code"] != 0:
            gaps.append(f"group-{label}-compile-exit:{group['compile']['exit_code']}")
        if group["compile"].get("signal"):
            gaps.append(f"group-{label}-compile-signal:{group['compile'].get('signal_number')}")
        for gap in group["diagnostics"].get("gaps", []):
            gaps.append(f"group-{label}-diagnostics:{gap}")
        for gap in group["census"].get("gaps", []):
            gaps.append(f"group-{label}-census:{gap}")
        for gap in group["local_source"].get("gaps", []):
            gaps.append(f"group-{label}-local-source:{gap}")
        if label != "A":
            continue
        comparison = compare_object_coordinates(
            binding["candidate"].get("object_address_coordinates", []),
            group.get("object_coordinates", []))
        group["baseline_object_comparison"] = comparison
        if group["compile"]["exit_code"] != 0:
            stopped = "group-A-compile-failed"
            gaps.append("group-A-compile-failed; B was not run")
        elif comparison["status"] != "matched":
            stopped = "group-A-does-not-reproduce-original-object"
            gaps.append("group-A-object-instructions-or-relocation-targets-differ; B was not run")
        elif not group["object_exists"]:
            stopped = "group-A-object-missing"
            gaps.append("group-A-object-missing; B was not run")

    # The linked sites are never attributed: group B's instructions are not
    # index-mapped onto 0x50d6c / 0x50fb8, and an ET_REL coordinate is not a
    # linked virtual address.
    attribution: dict[str, Any] = {"final_elf_site_attribution": "forbidden-by-design"}
    answers: dict[str, Any] = {}
    if stopped is None:
        before, after = groups["A"], groups["B"]
        # Address correspondence first: only when A and B agree instruction for
        # instruction may per-address deltas be trusted. Gating moves code, so
        # by default marker identity is presence, not address.
        object_correspondence = compare_object_coordinates(before.get("object_coordinates", []),
                                                           after.get("object_coordinates", []))
        address_correspondence = ("established" if object_correspondence["status"] == "matched"
                                  else "not-established")
        local = compare_local_sources(before["local_source"], after["local_source"],
                                      address_correspondence=address_correspondence)
        local["object_correspondence"] = object_correspondence
        # Elimination may only be judged on a real B observation: a failed B
        # compile or a missing disassembly is a missing observation.
        reasons = {"A": _vector_evidence_gaps(before), "B": _vector_evidence_gaps(after)}
        evidence_ready = not reasons["A"] and not reasons["B"]
        delta = classify_vector_delta(before["vector_evidence"], after["vector_evidence"],
                                      evidence_ready=evidence_ready)
        delta["evidence_gaps"] = reasons
        markers_remaining = local["markers_remaining"]
        delta["markers_remaining"] = markers_remaining
        if delta["vector_instructions_eliminated"] is None:
            delta["elimination_status"] = "unproven"
        elif delta["vector_instructions_eliminated"] and markers_remaining:
            delta["elimination_status"] = "vector-instructions-absent-other-markers-remain"
        # A/B object equality is NOT required: a successful gate normally
        # changes the instructions. Object correspondence only licenses the
        # per-address deltas; elimination rests on a complete B observation and
        # a reliable local analysis.
        delta["fully_eliminated"] = bool(
            delta["vector_instructions_eliminated"] and not markers_remaining
            and local["status"] == "complete")
        delta["fully_eliminated_rule"] = (
            "requires: B compiled, target function disassembled, B vector instruction "
            "count 0, no marker category still present in B, and a complete local "
            "analysis; A/B object equality is explicitly not required")
        if local["status"] != "complete":
            gaps.append("local-source-incomplete; the overall elimination conclusion "
                        "stays unproven")
        if not evidence_ready:
            gaps.append(f"vector-evidence-not-ready; elimination stays unproven: {reasons}")
        census_rows = after["census"]["rows_for_exact_symbol"]
        blocked = [row for row in census_rows if row["action"] == "blocked"]
        answers = {
            "target_gate_processing": {
                "status": "confirmed" if blocked else "unproven",
                "gate_list_contains_target": after["target_in_gate_names"],
                "census_rows_for_exact_symbol": census_rows,
                "census_actions": after["census"]["actions"],
                "note": ("a blocked census row proves the gate ran on the exact symbol; "
                         "it does not prove elimination on its own"),
            },
            "vector_operations": delta,
            "local_conservative_sources": local,
            "remaining_limits": [],
        }
        gaps.append("final ELF sites 0x50d6c and 0x50fb8 remain unproven; B instructions are "
                    "never mapped onto them by instruction index")
        gaps.append("no whole-program propagation was run; unresolved external calls in the "
                    "local function were not required to be warning-free")
        answers["remaining_limits"] = gaps
    else:
        answers = {
            "target_gate_processing": {"status": "unproven", "reason": stopped},
            "vector_operations": {"status": "unproven", "reason": stopped},
            "local_conservative_sources": {"status": "incomplete",
                                           "conservative_sources_disappeared": None,
                                           "reason": stopped},
            "remaining_limits": gaps,
        }
    attribution["final_elf_site_correspondence"] = {
        hex(address): {"status": "unproven",
                       "reason": "object-layer evidence only; ET_REL coordinates are not "
                                 "linked virtual addresses and B is never index-mapped onto "
                                 "the linked sites"}
        for address in SITES}
    result = {
        "schema": EXPERIMENT_SCHEMA,
        "target_symbol": target,
        "status": "stopped-before-B" if stopped else "completed",
        "stopped_reason": stopped,
        "decision_diff": decision_diff,
        "toolchain_verification": verification,
        "groups": groups,
        "final_elf_site_correspondence": attribution["final_elf_site_correspondence"],
        "final_elf_site_attribution": "forbidden-by-design",
        "production_artifacts_untouched": {"gate_list_rewritten": False, "gcc_relinked": False,
                                           "safety_criteria_modified": False},
        "answers": answers,
        "root_cause_confirmed": False,
        "gaps": gaps,
    }
    (out / "gate-experiment-result.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    _write_experiment_report(out / "report.md", result)
    exit_code = EXPERIMENT_STOPPED_EXIT if stopped else 0
    print(f"gate experiment status={result['status']}; exit={exit_code}; evidence written: {out}")
    return exit_code


EXPERIMENT_QUESTIONS = (
    "1. Was the target confirmed to be processed by the gate?",
    "2. Which vector operations of the target function disappeared and which remain?",
    "3. Did A's local conservative sources disappear in B?",
    "4. Which conclusions are still limited by IR/MIR, relocation or historical-identity gaps?",
)


def _write_experiment_report(path: Path, data: dict[str, Any]) -> None:
    answers = data.get("answers", {})
    lines = ["# Single-function gate experiment", "",
             "Diagnostic only: the production gate list, the GCC build and every safety "
             "criterion are untouched. Unknown means the artifacts do not prove it.", "",
             "## Groups", ""]
    for label in EXPERIMENT_GROUPS:
        group = data.get("groups", {}).get(label)
        if group is None:
            lines.append(f"- **group {label}**: not run")
            continue
        evidence = group.get("vector_evidence", {})
        lines.append(
            f"- **group {label}**: exit={group['compile']['exit_code']}, "
            f"gate names={group['gate_names_count']}, "
            f"target gated={group['target_in_gate_names']}, "
            f"vector instructions={evidence.get('vector_instruction_count', 0)}, "
            f"vs2r.v={len(evidence.get('vs2r_v', []))}, "
            f"VLEN reads={len(evidence.get('vlen_reads', []))}, "
            f"census actions={group['census'].get('actions', [])}, "
            f"metadata={group['metadata_section'].get('status', 'unknown')}, "
            f"local source={group['local_source'].get('status')}")
    lines.extend(["", "## Answers", ""])
    for question, key in zip(EXPERIMENT_QUESTIONS,
                             ("target_gate_processing", "vector_operations",
                              "local_conservative_sources", "remaining_limits")):
        value = answers.get(key, {})
        rendered = (json.dumps(value, sort_keys=True) if not isinstance(value, list)
                    else "\n" + "\n".join(f"  - {item}" for item in value))
        lines.extend([f"### {question}", "",
                      f"**{key}**: {rendered}"[:4000], ""])
    lines.extend(["## Final-ELF sites", ""])
    for address, record in data.get("final_elf_site_correspondence", {}).items():
        lines.append(f"- `{address}`: {record['status']} -- {record['reason']}")
    lines.extend(["", "## Gaps", ""])
    for gap in data.get("gaps", []):
        lines.append(f"- gap: `{gap}`")
    lines.append(f"- root_cause_confirmed: `{data.get('root_cause_confirmed', False)}`")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _execute_compile_pass(record: dict[str, Any], out: Path, cwd: Path, compiler: Path,
                          extra_args: Sequence[str], label: str,
                          environment: dict[str, str] | None = None,
                          gate_list_path: Path | None = None) -> dict[str, Any]:
    out.mkdir(parents=True, exist_ok=True)
    argv, _ = rewrite_compile_command(record, out, gate_list_path, extra_args)
    argv[0] = str(compiler)
    stdout_path, stderr_path = out / f"{label}.stdout.txt", out / f"{label}.stderr.txt"
    time_path = out / f"{label}.time.txt"
    time_bin = Path("/usr/bin/time")
    wrapped = [str(time_bin), "-v", "-o", str(time_path), *argv] if time_bin.is_file() else argv
    started = time.monotonic()
    with stdout_path.open("wb") as stdout, stderr_path.open("wb") as stderr:
        try:
            completed = subprocess.run(wrapped, cwd=cwd, stdout=stdout, stderr=stderr,
                                       env=environment, check=False)
            returncode = completed.returncode
        except OSError as exc:
            stderr.write(f"unable to execute compile command: {exc}\n".encode("utf-8", errors="replace"))
            returncode = 127
    result = {"name": label, "argv": argv, "wrapped_argv": wrapped,
              "cwd": str(cwd), "exit_code": returncode,
              "signal": returncode < 0 or returncode >= 128,
              "signal_number": (-returncode if returncode < 0 else returncode - 128)
                               if returncode < 0 or returncode >= 128 else None,
              "elapsed_seconds": time.monotonic() - started,
              "time_file": time_path.name if time_path.exists() else None,
              "peak_rss_kib": peak_rss_kib(time_path),
              "controlled_environment": {key: environment[key] for key in
                                         ("CHIMERA_GATE_LIST", "CHIMERA_GATE_STATS", "TMPDIR", "TMP", "TEMP")
                                         if environment and key in environment},
              "stdout": stdout_path.name, "stderr": stderr_path.name}
    (out / f"{label}.command.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    return result


def _split_inline_relocation(operands: str) -> tuple[str, list[str]]:
    relocations = list(RELOCATION_RE.finditer(operands))
    if not relocations:
        return operands.strip(), []
    instruction_operands = operands[:relocations[0].start()]
    instruction_operands = re.sub(r"\s+[0-9a-fA-F]+:\s*$", "", instruction_operands).rstrip()
    return instruction_operands, [relocation.group(0) for relocation in relocations]


def _instruction_records(dump: str) -> list[dict[str, Any]]:
    instructions = []
    last_instruction: dict[str, Any] | None = None
    for line in dump.splitlines():
        match = INSN_RE.match(line)
        if match:
            operands, inline_relocations = _split_inline_relocation(match.group(4))
            last_instruction = {"address": int(match.group(1), 16), "raw_bytes": match.group(2).strip(),
                                "mnemonic": match.group(3).lower(), "operands": operands,
                                "text": line.strip(), "relocations": []}
            last_instruction["relocations"].extend(inline_relocations)
            instructions.append(last_instruction)
            continue
        if last_instruction is not None:
            last_instruction["relocations"].extend(
                relocation.group(0) for relocation in RELOCATION_RE.finditer(line))
    return instructions


def _symbol_addresses(dump: str) -> dict[str, int]:
    addresses: dict[str, int] = {}
    ambiguous: set[str] = set()
    for line in dump.splitlines():
        match = FUNC_RE.match(line)
        if not match:
            continue
        name, address = match.group(2), int(match.group(1), 16)
        previous = addresses.get(name)
        if previous is not None and previous != address:
            ambiguous.add(name)
        else:
            addresses[name] = address
    for name in ambiguous:
        addresses.pop(name, None)
    return addresses


def _direct_target_field(item: dict[str, Any]) -> int | None:
    mnemonic = item["mnemonic"].lower()
    fields = [field.strip() for field in item["operands"].split(",")]
    direct_unconditional = {"j", "call", "tail", "c.j", "c.jal"}
    direct_conditional = mnemonic.startswith(("beq", "bne", "blt", "bge", "c.beqz", "c.bnez"))
    if mnemonic in direct_unconditional and fields:
        return 0
    if mnemonic == "jal" and fields:
        return len(fields) - 1
    if direct_conditional and len(fields) >= 2:
        return len(fields) - 1
    return None


def _symbol_target_identity(target: str) -> str:
    """Keep relocation addends in the identity and normalize decimal/hex spelling."""
    match = re.match(r"^(.+?)([+-](?:0x[0-9a-fA-F]+|[0-9]+))$", target)
    if not match:
        return target
    symbol, suffix = match.groups()
    sign = -1 if suffix.startswith("-") else 1
    amount = suffix[1:]
    addend = sign * int(amount, 16 if amount.lower().startswith("0x") else 10)
    return f"{symbol}{addend:+#x}" if addend else symbol


def _direct_target_identity(item: dict[str, Any], address_indices: dict[int, int],
                            symbol_addresses: dict[str, int]) -> tuple[str, str] | None:
    """Identify a direct branch by its in-function destination or named external target."""
    target_relocations: list[str] = []
    for relocation in item.get("relocations", []):
        match = RELOCATION_RE.search(relocation)
        if match:
            relocation_type, target = match.group(0).split(None, 1)
            if relocation_type == "R_RISCV_RELAX" or target == "*ABS*":
                continue
            target_relocations.append(target)
    if len(target_relocations) > 1:
        return None
    if target_relocations:
        target_identity = _symbol_target_identity(target_relocations[0])
        target = target_identity
        addend_match = re.match(r"^(.+?)([+-]0x[0-9a-fA-F]+)$", target_identity)
        addend = 0
        if addend_match:
            target = addend_match.group(1)
            suffix = addend_match.group(2)
            sign = -1 if suffix.startswith("-") else 1
            addend = sign * int(suffix[1:], 16)
        if target.startswith((".L", "LBB", "Ltmp", "$L")):
            local_address = symbol_addresses.get(target)
            if local_address is None:
                return None
            target_index = address_indices.get(local_address + addend)
            return ("instruction-index", str(target_index)) if target_index is not None else None
        return "symbol", target_identity
    field_index = _direct_target_field(item)
    if field_index is None:
        return None
    fields = [field.strip() for field in item["operands"].split(",")]
    if field_index >= len(fields):
        return None
    target = fields[field_index]
    address_match = re.match(r"^(?:0x)?([0-9a-fA-F]+)\b", target)
    if address_match:
        address = int(address_match.group(1), 16)
        if address in address_indices:
            return "instruction-index", str(address_indices[address])
    symbol = re.search(r"<([^>]+)>", target)
    if symbol:
        label = symbol.group(1)
        if label.startswith((".L", "LBB", "Ltmp", "$L")):
            local_address = symbol_addresses.get(label)
            target_index = address_indices.get(local_address) if local_address is not None else None
            return ("instruction-index", str(target_index)) if target_index is not None else None
        return "symbol", _symbol_target_identity(label)
    return None


def _replay_instruction_signatures(instructions: Sequence[dict[str, Any]],
                                   symbol_addresses: dict[str, int] | None = None
                                   ) -> list[tuple[Any, ...] | None]:
    address_indices = {item["address"]: index for index, item in enumerate(instructions)}
    symbol_addresses = symbol_addresses or {}
    signatures: list[tuple[Any, ...] | None] = []
    for item in instructions:
        mnemonic = item["mnemonic"].lower()
        fields = [field.strip() for field in item["operands"].split(",")]
        target_field = _direct_target_field(item)
        if target_field is None:
            if item.get("relocations"):
                signatures.append(None)
                continue
            signatures.append((mnemonic, item["operands"].strip()))
            continue
        target_identity = _direct_target_identity(item, address_indices, symbol_addresses)
        if target_identity is None:
            signatures.append(None)
            continue
        prefix = ",".join(fields[:target_field])
        signatures.append((mnemonic, prefix, target_identity))
    return signatures


def compare_replay_sites(original_dump: str, replay_dump: str,
                         addresses: Sequence[int] = SITES) -> dict[str, Any]:
    original, replayed = _instruction_records(original_dump), _instruction_records(replay_dump)
    original_signature = _replay_instruction_signatures(original, _symbol_addresses(original_dump))
    replay_signature = _replay_instruction_signatures(replayed, _symbol_addresses(replay_dump))
    matched = bool(original_signature and None not in original_signature
                   and None not in replay_signature and original_signature == replay_signature)
    sites = []
    by_original_address = {item["address"]: index for index, item in enumerate(original)}
    for address in addresses:
        index = by_original_address.get(address)
        mapped = replayed[index] if matched and index is not None and index < len(replayed) else None
        sites.append({"original_address": hex(address),
                      "original_instruction": original[index]["text"] if index is not None else None,
                      "linked_function_instruction_index": index,
                      "replay_instruction_index": index if mapped is not None else None,
                      "replay_instruction": mapped["text"] if mapped is not None else None,
                      "generation_origin": "unknown", "metadata_status": "unknown",
                      "status": "sequence-correlated" if mapped is not None else "unknown",
                      "gap": None if mapped is not None else "replay-function-mismatch-or-site-not-found"})
    return {"original_instruction_count": len(original), "replay_instruction_count": len(replayed),
            "mnemonic_and_operand_sequence_matches": matched,
            "function_correspondence": "matched" if matched else "replay-mismatch-or-insufficient-symbol-data",
            "sites": sites}


def _collect_replay_object(obj: Path, out: Path, args: argparse.Namespace, prefix: str) -> None:
    if not obj.is_file():
        return
    for flag, suffix in (("-SW", "sections"), ("-rW", "relocations"), ("-h", "header")):
        _run_capture([args.readelf, flag, str(obj)], out, f"{prefix}.object-{suffix}")
    _read_stackobj_section(obj, out / f"{prefix}.object-stackobj-map.json")
    _, header = _run_capture([args.readelf, "-h", str(obj)], out, f"{prefix}.object-header-type")
    match = re.search(r"Type:\s*(\S+)", header)
    elf_type = match.group(1) if match else "unknown"
    _, dump = _run_capture([args.objdump, "-drw", f"--disassemble={args.layout_symbol}", str(obj)],
                           out, f"{prefix}.object-layout-coordinates")
    coords = _object_coordinates(dump, elf_type)
    (out / f"{prefix}.object-address-coordinates.json").write_text(
        json.dumps(coords, indent=2), encoding="utf-8")


def _shell_exit_code(returncode: int) -> int:
    return 128 - returncode if returncode < 0 else returncode


def _write_report(path: Path, data: dict[str, Any]) -> None:
    lines = ["# Layout code-generation forensics", "",
             "This report records observations. Unknown means the available artifacts do not prove a classification.", "",
             "## Findings", ""]
    evidence_name = ("collection.json" if data.get("schema") == "chimera-layout-codegen-forensics-v1"
                     else "resolution.json" if "resolution" in data.get("schema", "")
                     else "replay-result.json")
    lines.append(f"Full structured evidence: `{evidence_name}`.\n")
    if "sites" in data and isinstance(data["sites"], dict):
        for key, site in data["sites"].items():
            record = site.get("site", {})
            lines.append(f"- `{key}`: {record.get('mnemonic', 'unknown')}, "
                         f"generation={record.get('generation_origin', 'unknown')}, "
                         f"metadata={record.get('metadata_status', 'unknown')}")
    if "stages" in data:
        for stage, record in data["stages"].items():
            lines.append(f"- **{stage}**: source={record.get('source', 'unknown')}; "
                         f"command={record.get('command_status', 'unknown')}; "
                         f"ready={record.get('replay_ready', False)}; "
                         f"gaps={record.get('gaps', [])}")
    for gap in data.get("gaps", []):
        lines.append(f"- gap: `{gap}`")
    lines.append(f"- root_cause_confirmed: `{data.get('root_cause_confirmed', False)}`")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _decision_names(path: Path) -> set[str]:
    try:
        return set(_decision_gate_names(path))
    except (OSError, ValueError, json.JSONDecodeError):
        return set()


def _compile_output_path(tokens: Sequence[str], cwd: Path) -> str | None:
    for index, token in enumerate(tokens):
        if token == "-o" and index + 1 < len(tokens):
            value = tokens[index + 1]
            path = Path(value)
            return str((cwd / path).resolve() if not path.is_absolute() else path.resolve())
        if token.startswith("-o") and not token.startswith(("-openmp", "-objc")):
            value = token[2:].lstrip("=")
            if value:
                path = Path(value)
                return str((cwd / path).resolve() if not path.is_absolute() else path.resolve())
    return None


def _plugin_identities(tokens: Sequence[str], cwd: Path) -> list[dict[str, Any]]:
    paths: list[str] = []
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if any(flag in token.lower() for flag in ("pass-plugin", "-fplugin=")):
            if "=" in token:
                paths.append(token.split("=", 1)[1])
            elif index + 1 < len(tokens):
                paths.append(tokens[index + 1])
                index += 1
        index += 1
    identities = []
    for value in paths:
        path = Path(value)
        if not path.is_absolute():
            path = (cwd / path).resolve()
        identities.append({"path": str(path), "exists": path.is_file(),
                           "sha256": sha256(path) if path.is_file() else None})
    return identities


def _collect_build_rules(run_dir: Path, out: Path, source_basenames: set[str],
                         symbol: str, gaps: list[str], source_paths: Sequence[Path] = ()) -> None:
    patterns = ("build-stack/Makefile", "build-gate2/Makefile",
                "build-stack/gcc/Makefile", "build-gate2/gcc/Makefile",
                "gcc/Makefile.in", "gcc/Make-lang.in")
    needles = set(source_basenames) | {Path(name).stem + ".o" for name in source_basenames}
    needles.add(symbol)
    found = 0
    seen: set[Path] = set()
    candidates = {path.resolve() for pattern in patterns for path in run_dir.glob(pattern) if path.is_file()}
    for source in source_paths:
        for parent in list(source.resolve().parents)[:5]:
            for name in ("Makefile", "Makefile.in", "Make-lang.in"):
                candidate = parent / name
                if candidate.is_file():
                    candidates.add(candidate.resolve())
    for path in sorted(candidates):
        if path in seen:
            continue
        seen.add(path)
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        selected = [index for index, line in enumerate(lines) if any(needle in line for needle in needles)]
        if not selected:
            continue
        found += 1
        indexes = sorted({pos for index in selected for pos in range(max(0, index - 2), min(len(lines), index + 3))})
        target = out / f"build-rule-{found}-{path.parent.name}-{path.name}.txt"
        target.write_text("\n".join(f"{index + 1}: {lines[index]}" for index in indexes) + "\n", encoding="utf-8")
        raw_copy = out / "raw-build-rules" / f"{found}-{path.parent.name}-{path.name}"
        raw_copy.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, raw_copy)
        with (out / "build-rules-index.jsonl").open("a", encoding="utf-8") as stream:
            stream.write(json.dumps({"source": str(path), "sha256": sha256(path),
                                     "excerpt": target.name,
                                     "raw_copy": str(raw_copy.relative_to(out))}) + "\n")
    if not found:
        gaps.append("matching-build-rule-not-found")


def _extract_archive_member(ar: str, archive: Path, member: str, output: Path,
                            out: Path, label: str) -> dict[str, Any]:
    output.parent.mkdir(parents=True, exist_ok=True)
    stderr_path = out / f"{label}.stderr.txt"
    time_path = out / f"{label}.time.txt"
    command = [ar, "p", str(archive), member]
    time_bin = Path("/usr/bin/time")
    wrapped = [str(time_bin), "-v", "-o", str(time_path), *command] if time_bin.is_file() else command
    started = time.monotonic()
    with output.open("wb") as stream, stderr_path.open("wb") as stderr:
        try:
            completed = subprocess.run(wrapped, stdout=stream, stderr=stderr, check=False)
            code = completed.returncode
        except OSError as exc:
            stderr.write(f"unable to extract archive member: {exc}\n".encode("utf-8", errors="replace"))
            code = 127
    if output.is_file() and output.stat().st_size >= 4:
        with output.open("rb") as stream:
            valid_elf = stream.read(4) == b"\x7fELF"
    else:
        valid_elf = False
    result = {"argv": command, "wrapped_argv": wrapped, "exit_code": code,
              "elapsed_seconds": time.monotonic() - started, "peak_rss_kib": peak_rss_kib(time_path),
              "stderr": stderr_path.name, "output": str(output),
              "output_sha256": sha256(output) if output.is_file() else None,
              "status": "extracted-et-rel-member" if code == 0 and valid_elf else "extract-failed-or-non-elf"}
    (out / f"{label}.command.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    return result


def _collect_archive_candidates(stage_root: Path, stage_name: str, out: Path,
                                args: argparse.Namespace, gaps: list[str],
                                start_index: int = 0) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    if not stage_root.is_dir():
        return candidates
    for archive in sorted(stage_root.rglob("*.a")):
        index = start_index + len(candidates)
        label = f"{stage_name}.archive-candidate-{index}"
        nm_code, nm_output = _run_capture([args.nm, "--defined-only", str(archive)], out, label + ".symbols")
        if nm_code:
            gaps.append(f"archive-symbol-scan-failed:{archive}:{nm_code}")
            continue
        if not _defines_symbol(nm_output, args.layout_symbol):
            continue
        list_code, listing = _run_capture([args.ar, "t", str(archive)], out, label + ".members")
        selection = _select_archive_member(nm_output, listing, args.layout_symbol) if list_code == 0 else {
            "status": "archive-list-failed", "exit_code": list_code}
        candidate: dict[str, Any] = {"stage": stage_name, "archive": str(archive),
                                     "archive_sha256": sha256(archive), "nm_exit": nm_code,
                                     "member_selection": selection, "generation_origin": "unknown"}
        archive_dump_code, archive_dump = _run_capture(
            [args.objdump, "-drw", f"--disassemble={args.layout_symbol}", str(archive)],
            out, label + ".archive-layout")
        candidate["archive_disassembly_exit"] = archive_dump_code
        if archive_dump_code:
            gaps.append(f"archive-layout-disassembly-failed:{archive}:{archive_dump_code}")
        candidate["archive_address_coordinates"] = _object_coordinates(archive_dump, "ET_REL")
        (out / (label + ".archive-coordinates.json")).write_text(
            json.dumps(candidate["archive_address_coordinates"], indent=2), encoding="utf-8")
        if selection.get("status") != "unique-member":
            gaps.append(f"archive-member-not-uniquely-identified:{archive}:{selection.get('status')}")
            candidates.append(candidate)
            (out / f"{label}.json").write_text(json.dumps(candidate, indent=2), encoding="utf-8")
            continue
        member = selection["member"]
        object_path = out / "archive-members" / stage_name / f"{index}-{Path(member).name}"
        extracted = _extract_archive_member(args.ar, archive, member, object_path, out, label + ".extract")
        candidate["member_object"] = extracted
        if extracted["status"] == "extracted-et-rel-member":
            for flag, suffix in (("-SW", "sections"), ("-rW", "relocations"), ("-h", "header")):
                code, _ = _run_capture([args.readelf, flag, str(object_path)], out, label + "." + suffix)
                if code:
                    gaps.append(f"archive-member-{suffix}-read-failed:{archive}({member}):{code}")
            candidate["stackobj_map"] = _read_stackobj_section(object_path, out / (label + ".stackobj-map.json"))
            _, dump = _run_capture([args.objdump, "-drw", f"--disassemble={args.layout_symbol}",
                                    str(object_path)], out, label + ".layout")
            candidate["object_address_coordinates"] = _object_coordinates(dump, "ET_REL")
            (out / (label + ".coordinates.json")).write_text(
                json.dumps(candidate["object_address_coordinates"], indent=2), encoding="utf-8")
        else:
            gaps.append(f"archive-member-extraction-failed:{archive}({member})")
        candidates.append(candidate)
        (out / f"{label}.json").write_text(json.dumps(candidate, indent=2), encoding="utf-8")
    return candidates


if __name__ == "__main__":
    raise SystemExit(run())
