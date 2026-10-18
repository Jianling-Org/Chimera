#!/usr/bin/env python3
"""Extract reproducible native and translated llama.cpp dot kernels."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]

OPERATORS = {
    "f32": "ggml_vec_dot_f32",
    "f16": "ggml_vec_dot_f16",
    "q5": "ggml_vec_dot_q5_0_q8_0_generic",
}


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def renamed(function, symbol):
    result = copy.deepcopy(function)
    result.name = symbol
    labels = {i.address: f".L_{symbol}_{i.address:x}" for i in result.instructions}
    for instruction in result.instructions:
        instruction.label = labels[instruction.address]
        if instruction.target_address is not None:
            if instruction.target_address not in labels:
                raise ValueError(f"External target in {function.name}")
            instruction.operands[-1] = labels[instruction.target_address]
            instruction.target_symbol = labels[instruction.target_address]
        if instruction.opcode in {"call", "tail", "auipc", "jalr"}:
            raise ValueError(f"Unsupported extraction dependency: {instruction}")
        instruction.op_str = ", ".join(instruction.operands)
    return result


def prepare(sources: Path, output: Path, translator_root: Path) -> None:
    sys.path[:0] = [str(translator_root), str(translator_root / "src")]
    from riscv.frontend.parser import AsmParser
    from rvv_sbt_rvv import translate_function as forward
    from rvv_sbt_rvv1024 import translate_function as reverse
    snapshot = json.loads(sources.read_text())
    output.mkdir(parents=True, exist_ok=True)
    manifest = {
        "source_elf": snapshot["elf"],
        "source_elf_sha256": snapshot["sha256"],
        "git_head": subprocess.check_output(
            ["git", "-C", str(ROOT), "rev-parse", "HEAD"], text=True
        ).strip(),
        "source_sha256": {
            str(path.relative_to(translator_root)): sha(path)
            for path in [translator_root / "rvv_sbt_rvv.py", translator_root / "rvv_sbt_rvv1024.py",
                         *sorted((translator_root / "src").rglob("*.py"))]
        },
        "operators": {},
        "state_base_mode": "initial-exec",
        "forward_profile": "wide_lmul=True",
        "translation_boundary": "one source instruction at a time",
    }
    for key, name in OPERATORS.items():
        source = snapshot["functions"][name]
        function = next(f for f in AsmParser().parse_string_functions(source)
                        if f.name == name)
        manifest["operators"][key] = {
            "symbol": name, "instruction_count": len(function.instructions),
            "objdump_sha256": hashlib.sha256(source.encode()).hexdigest(),
        }
        (output / f"{key}.objdump.s").write_text(source)
        native = renamed(function, f"native_{key}")
        lines = [".text", f".globl {native.name}",
                 f".type {native.name}, @function", f"{native.name}:"]
        for instruction in native.instructions:
            lines.extend((f"{instruction.label}:",
                          f"    {instruction.opcode} {instruction.op_str}"))
        lines.append(f".size {native.name}, .-{native.name}")
        (output / f"native_{key}.S").write_text("\n".join(lines) + "\n")
        for direction, translator in (("forward", forward), ("reverse", reverse)):
            translated = renamed(function, f"translated_{key}")
            assembly = translator(translated, tls_state=True)
            if any(token in assembly.lower()
                   for token in ("fallback", "unimplemented", "# error:")):
                raise ValueError(f"Incomplete translation: {direction}/{name}")
            (output / f"{direction}_{key}.S").write_text(assembly + "\n")
    for name in ("bench.c", "run.py", "paired.py"):
        (output / name).write_bytes(Path(__file__).with_name(name).read_bytes())
    (output / "source-snapshot.json").write_text(json.dumps(snapshot, indent=2) + "\n")
    manifest["payload_sha256"] = {
        path.name: sha(path) for path in sorted(output.iterdir()) if path.is_file()
    }
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps({"output": str(output), "operators": manifest["operators"]}, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sources", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--translator-root", type=Path, default=ROOT)
    args = parser.parse_args()
    prepare(args.sources, args.out, args.translator_root)
