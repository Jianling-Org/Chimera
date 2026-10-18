#!/usr/bin/env python3
"""Extract the real IME2 m4 kernel and the pinned RVV GEMM baseline."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT), str(ROOT / "src")]
from ime_sbt_rvv import translate_assembly
from riscv.frontend.parser import AsmParser


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def translate(assembly, directory):
    source = assembly.read_text()
    counts = {op: len(re.findall(r"^\s*" + re.escape(op) + r"\s", source, re.M))
              for op in ("smt.vmadot", "smt.vpack.vv")}
    if counts != {"smt.vmadot": 16, "smt.vpack.vv": 19}:
        raise ValueError(f"unexpected kernel IME instruction inventory: {counts}")
    translated = translate_assembly(source)
    translated = re.sub(r"\bgemm_ime_native\b", "gemm_ime_translated", translated)
    if re.search(r"^\s*smt\.", translated, re.M):
        raise ValueError("untranslated IME instruction")
    (directory / "ime_translated.S").write_text(translated)
    manifest = json.loads((directory / "manifest.json").read_text())
    manifest.update(ime_sites=counts, native_assembly_sha256=digest(assembly),
                    translated_assembly_sha256=digest(directory / "ime_translated.S"))
    manifest["translator_sources"] = {
        str(p.relative_to(ROOT)): digest(p)
        for p in [ROOT / "ime_sbt_rvv.py", *sorted((ROOT / "src/riscv/extensions/spacemit_ime").glob("*.py"))]
    }
    (directory / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps({"ime_sites": counts, "translated": str(directory / "ime_translated.S")}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--llama-root", type=Path)
    parser.add_argument("--rvv-elf", type=Path)
    parser.add_argument("--objdump", default="llvm-objdump")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--assembly", type=Path, help="translate the GCC-produced IME assembly after extraction")
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    if args.assembly:
        translate(args.assembly, args.out)
        return
    if args.llama_root is None or args.rvv_elf is None:
        parser.error("extraction requires --llama-root and --rvv-elf")
    ime = args.llama_root / "ggml/src/ggml-cpu/spacemit/ime2_kernels.cpp"
    header = args.llama_root / "ggml/src/ggml-cpu/spacemit/ime_kernels.h"
    source = ime.read_text()
    start = source.index("void gemm_kernel_i8i3k_m4(")
    end = source.index("\nvoid gemm_kernel_i8i4_m1(", start)
    function = source[start:end].strip()
    if "#if" in function:
        raise ValueError("review changed conditional compilation before extraction")
    function = function.replace("void gemm_kernel_i8i3k_m4(", 'extern "C" void gemm_ime_native(', 1)
    function = re.sub(r'("\s*)(vmadot|vpack\.vv)(\s)', r'\1smt.\2\3', function)
    text = header.read_text()
    struct_start = text.index("template <int N> struct nrow_block_q3_k {")
    struct_end = text.index("\n};", struct_start) + 3
    preamble = """#include <cstddef>
#include <cstdint>
#include <algorithm>
#define BLOCK_QNK_LEN 256
constexpr size_t q8k_blk_size(size_t n) {
    return sizeof(float) + n * sizeof(int8_t) + sizeof(int16_t) * n / 16;
}
"""
    (args.out / "ime_kernel.cpp").write_text(preamble + text[struct_start:struct_end] + "\n" + function + "\n")
    symbol = "ggml_gemm_q3_K_64x1_q8_K"
    dump = subprocess.check_output([args.objdump, "-d", "--disassemble-symbols=" + symbol, str(args.rvv_elf)], text=True)
    fn = next(f for f in AsmParser().parse_string_functions(dump) if f.name == symbol)
    instructions = [i for i in fn.instructions if i.opcode]
    if any(i.opcode in {"auipc", "jal", "jalr", "call", "tail", "jr"} for i in instructions):
        raise ValueError("RVV baseline now has relocations/calls requiring review")
    labels = {i.address: f".L_rvv_{i.address:x}" for i in instructions}
    output = [".text", ".globl gemm_rvv_baseline", ".type gemm_rvv_baseline,@function", "gemm_rvv_baseline:"]
    for insn in instructions:
        operands = list(insn.operands)
        if insn.target_address is not None:
            operands[-1] = labels[insn.target_address]
        output += [labels[insn.address] + ":", "    " + insn.opcode + " " + ", ".join(operands)]
    output.append(".size gemm_rvv_baseline, .-gemm_rvv_baseline")
    (args.out / "rvv_baseline.S").write_text("\n".join(output) + "\n")
    (args.out / "rvv_source.dump").write_text(dump)
    manifest = {
        "ime_source": str(ime), "ime_source_sha256": digest(ime),
        "ime_function": "spacemit_kernels::ime2::gemm_kernel_i8i3k_m4",
        "ime_changes": ["standalone C linkage", "canonical smt. prefix"],
        "llama_commit": subprocess.check_output(["git", "-C", str(args.llama_root), "rev-parse", "HEAD"], text=True).strip(),
        "rvv_symbol": symbol, "rvv_elf_sha256": digest(args.rvv_elf),
        "rvv_source_address": fn.start_addr, "rvv_instruction_count": len(instructions),
        "rvv_assembly_sha256": digest(args.out / "rvv_baseline.S"),
    }
    (args.out / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
