#!/usr/bin/env python3
"""Prepare the pinned Q3 GEMM and both state-preserving RVV translations."""

import argparse
import copy
import hashlib
import json
from pathlib import Path
import re
import shutil
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def relabeled(function):
    result = copy.deepcopy(function)
    result.name = "bench_kernel"
    labels = {instruction.address: f".L_bench_kernel_{instruction.address:x}"
              for instruction in result.instructions}
    for instruction in result.instructions:
        instruction.label = labels[instruction.address]
        if instruction.opcode in {"auipc", "jal", "jalr", "call", "tail", "jr"}:
            raise ValueError(f"Review extraction dependency: {instruction}")
        if instruction.target_address is not None:
            if instruction.target_address not in labels:
                raise ValueError(f"External branch: {instruction}")
            instruction.operands[-1] = labels[instruction.target_address]
            instruction.target_symbol = labels[instruction.target_address]
        instruction.op_str = ", ".join(instruction.operands)
    return result


def prepare(references, output, translator_root=ROOT):
    sys.path[:0] = [str(translator_root), str(translator_root / "src")]
    from riscv.frontend.parser import AsmParser
    from rvv_sbt_rvv import translate_function as forward
    from rvv_sbt_rvv1024 import translate_function as reverse

    workload = json.loads((HERE / "workload.json").read_text())
    source = HERE / "source.dump"
    function = next((function for function in AsmParser().parse_file_functions(source)
                     if function.name == workload["primary_symbol"]), None)
    if function is None:
        raise ValueError(f"{source}: missing primary symbol {workload['primary_symbol']!r}")
    encoded = bytearray()
    for match in re.finditer(r"(?m)^\s*([0-9a-f]+):\s+([0-9a-f]+)\s+", source.read_text()):
        pc, word = int(match[1], 16), match[2]
        if function.start_addr <= pc < function.start_addr + 3580:
            if pc != function.start_addr + len(encoded):
                raise ValueError("Noncontiguous source machine code")
            encoded.extend(int(word, 16).to_bytes(len(word) // 2, "little"))
    if hashlib.sha256(encoded).hexdigest() != workload["kernel_sha256"]:
        raise ValueError("Pinned kernel identity changed")
    output.mkdir(parents=True, exist_ok=True)
    (output / "kernel.bin").write_bytes(encoded)
    (output / "kernel.S").write_text(
        '.text\n.globl bench_kernel\n.type bench_kernel,@function\n'
        'bench_kernel:\n.incbin "kernel.bin"\n.size bench_kernel,.-bench_kernel\n'
    )
    for direction, translate in (("forward", forward), ("reverse", reverse)):
        assembly = translate(relabeled(function), tls_state=True, strict=True)
        (output / f"{direction}.S").write_text(assembly + "\n")
    for name in ("translated.c", "build.sh", "run.py", "workload.json",
                 "paired.c", "build_paired.sh", "run_paired.py", "validation.py"):
        shutil.copy2(HERE / name, output / name)
    for name, expected in workload["reference_sha256"].items():
        path = references / f"{name}.ref"
        if sha(path) != expected:
            raise ValueError(f"Reference identity changed: {name}")
        shutil.copy2(path, output / path.name)
    manifest = {
        "symbol": function.name, "source_dump_sha256": sha(source),
        "source_elf_sha256": workload["source_elf_sha256"],
        "kernel_sha256": workload["kernel_sha256"],
        "source_instructions": len(function.instructions),
        "vector_instructions": sum(i.opcode.startswith("v") for i in function.instructions),
        "state_base_mode": "initial-exec", "branch_targets": "per-source-PC local labels",
        "translator_sha256": {str(path.relative_to(translator_root)): sha(path)
                              for path in [translator_root / "rvv_sbt_rvv.py", translator_root / "rvv_sbt_rvv1024.py",
                                           *sorted((translator_root / "src").rglob("*.py"))]},
        "payload_sha256": {path.name: sha(path) for path in sorted(output.iterdir()) if path.is_file()},
    }
    (output / "translation-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--references", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--translator-root", type=Path, default=ROOT)
    args = parser.parse_args()
    prepare(args.references.resolve(), args.out.resolve(), args.translator_root.resolve())
