"""Bounded-memory evidence for proactive gate candidates in rebuilt code.

Direct hardware-width reads can become live across a boundary after inlining
or register allocation changes. A compilable host with a real RVV operation
and a direct vlenb read is therefore a candidate even without a current
finding. This never changes a safety verdict or proves the vector producer
implicit: the gate suppresses implicit vectorization and a fresh strict check
must still validate the rebuilt ELF, including any explicit RVV that remains.
"""
from __future__ import annotations

import hashlib
import re
import subprocess
import tempfile
from pathlib import Path

POLICY = "direct-vlenb-vector-hosts-v1"
SCHEMA = "chimera.gate-candidates.v1"
NAMES_SOURCE = "owned-reports+" + POLICY
_LABEL = re.compile(r"^([0-9a-f]+)\s+<([^>]+)>:")
_INSTRUCTION = re.compile(r"^\s*([0-9a-f]+):\s+[0-9a-f]+\s+([\w.]+)\s*(.*)$")
_CSR_READS = {"csrr", "csrrs", "csrrc", "csrrw", "csrrsi", "csrrci", "csrrwi"}
_VSET = {"vsetvl", "vsetvli", "vsetivli"}


def _digest(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def candidates_from_dump(lines):
    """Yield function-local evidence; never join facts from different hosts."""
    current = None
    vector = None
    widths = []

    def candidate():
        if (current is not None and vector is not None and widths
                and not current[1].endswith("@plt")):
            return {"name": current[1], "function_start": hex(current[0]),
                    "vector_instruction": vector, "width_reads": list(widths)}
        return None

    for line in lines:
        label = _LABEL.match(line)
        if label:
            item = candidate()
            if item is not None:
                yield item
            current = (int(label[1], 16), label[2])
            vector, widths = None, []
            continue
        instruction = _INSTRUCTION.match(line)
        if instruction is None or current is None:
            continue
        address, opcode, operand = instruction.groups()
        if opcode.startswith("v") and opcode not in _VSET and vector is None:
            vector = {"address": hex(int(address, 16)), "opcode": opcode}
        if opcode not in _CSR_READS:
            continue
        operands = operand.split("#", 1)[0].replace(" ", "").split(",")
        if (len(operands) >= 2 and operands[0] not in {"zero", "x0"}
                and operands[1] in {"vlenb", "0xc22", "3106"}):
            widths.append({"address": hex(int(address, 16)),
                           "register": operands[0], "kind": "csr-vlenb"})
    item = candidate()
    if item is not None:
        yield item


def scan_width_gate_candidates(elf: Path, objdump: str) -> dict:
    """Scan actual ELF instructions, failing if disassembly or identity changes."""
    elf = Path(elf).resolve(strict=True)
    before = _digest(elf)
    with tempfile.TemporaryFile(mode="w+t", encoding="utf-8") as errors:
        process = subprocess.Popen([objdump, "-d", str(elf)], stdout=subprocess.PIPE,
                                   stderr=errors, text=True, encoding="utf-8",
                                   errors="replace")
        try:
            with process.stdout as lines:
                functions = list(candidates_from_dump(lines))
            code = process.wait()
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()
        if code:
            errors.seek(0)
            raise ValueError(f"gate candidate objdump failed for {elf}: {errors.read(500)}")
    if _digest(elf) != before:
        raise ValueError(f"gate candidate ELF changed while scanning: {elf}")
    return {"elf": {"path": str(elf), "content_sha256": before},
            "functions": functions}


def inventory_names(document: dict, expected_elves: list[dict]) -> set[str]:
    """Validate pinned evidence and its exact correspondence to owned reports."""
    if (not isinstance(document, dict) or document.get("schema") != SCHEMA
            or document.get("policy") != POLICY):
        raise ValueError("unsupported gate candidate inventory policy/schema")
    inputs = document.get("inputs")
    if not isinstance(inputs, list) or len(inputs) != len(expected_elves):
        raise ValueError("gate candidate inventory input count disagrees with reports")
    names = set()
    for entry, expected in zip(inputs, expected_elves):
        if not isinstance(entry, dict) or entry.get("elf") != expected:
            raise ValueError("gate candidate ELF identity disagrees with owned report")
        functions = entry.get("functions")
        if not isinstance(functions, list):
            raise ValueError("invalid gate candidate functions")
        for item in functions:
            if not isinstance(item, dict):
                raise ValueError("invalid gate candidate evidence")
            name = item.get("name")
            if (not isinstance(name, str) or not name or name.endswith("@plt")
                    or any(char in name for char in ("\n", "\r", "\x00"))):
                raise ValueError("invalid gate candidate name")
            vector, widths = item.get("vector_instruction"), item.get("width_reads")
            if (not isinstance(vector, dict) or not isinstance(vector.get("opcode"), str)
                    or not vector["opcode"].startswith("v") or vector["opcode"] in _VSET
                    or not isinstance(widths, list) or not widths):
                raise ValueError("gate candidate requires vector and width evidence")
            for address in [item.get("function_start"), vector.get("address"),
                            *(x.get("address") if isinstance(x, dict) else None for x in widths)]:
                if not isinstance(address, str) or not re.fullmatch(r"0x[0-9a-f]+", address):
                    raise ValueError("invalid gate candidate instruction address")
            if any(x.get("kind") != "csr-vlenb" or not isinstance(x.get("register"), str)
                   or not x["register"] or x["register"] in {"zero", "x0"} for x in widths):
                raise ValueError("invalid gate candidate width evidence")
            names.add(name)
    return names
