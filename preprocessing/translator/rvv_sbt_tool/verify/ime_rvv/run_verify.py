#!/usr/bin/env python3
"""Execute emitted RVV on QEMU virt with VLEN=1024, without vendor IME."""

import argparse
import json
import os
import re
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from ime_sbt_rvv import translate_assembly


def wrapper(name, instruction, frame_size):
    lines = [".option norelax", ".text", f".globl {name}", f"{name}:", "    addi sp, sp, -1024"]
    for reg in range(1, 32):
        if reg != 2:
            lines.append(f"    sd x{reg}, {512 + reg * 8}(sp)")
    # Bound the deepest expansion frame with two canaries, including rejection
    # paths. The borrowed-register snapshots above bound its upper end.
    lines += ["    li t0, 0x76543210", f"    sd t0, {-frame_size - 16}(sp)",
              "    not t0, t0", f"    sd t0, {-frame_size - 8}(sp)"]
    lines += ["    la t0, input"]
    for reg in range(32):
        lines += [f"    vl1re8.v v{reg}, (t0)", "    addi t0, t0, 128"]
    lines += ["    la t0, input"]
    lines += [f"    fld f{reg}, {reg * 8}(t0)" for reg in range(32)]
    lines += [
        "    li t0, 128", "    vsetvli zero, t0, e8, m1, tu, mu",
        "    vadd.vi v31, v31, 1", "    la t0, config_vcsr", "    ld t0, 0(t0)", "    csrw vcsr, t0",
        "    li t0, 117", "    csrw fcsr, t0",
        "    la t0, config_vtype", "    ld t1, 0(t0)",
        "    la t0, config_vl", "    ld t0, 0(t0)", "    vsetvl zero, t0, t1",
        "    la t0, config_vstart", "    ld t0, 0(t0)", "    csrw vstart, t0",
        "    la t0, trap_resume", f"    la t1, .L_resume_{name}", "    sd t1, 0(t0)",
        "    la t0, before_csr",
    ]
    for index, csr in enumerate(("vl", "vtype", "vstart", "vcsr", "fcsr")):
        lines += [f"    csrr t1, {csr}", f"    sd t1, {index * 8}(t0)"]
    lines += ["    la t0, before_fpr"]
    lines += [f"    fsd f{reg}, {reg * 8}(t0)" for reg in range(32)]
    for reg in range(1, 32):
        if reg != 2:
            lines.append(f"    li x{reg}, {0x12340000 + 997 * reg}")
    lines += [f"    sd x{reg}, {reg * 8}(sp)" for reg in range(32)]
    lines += [instruction, f".L_resume_{name}:"]
    lines += [f"    sd x{reg}, {256 + reg * 8}(sp)" for reg in range(32)]
    lines += ["    la t0, stack_canary",
              f"    ld t1, {-frame_size - 16}(sp)", "    sd t1, 0(t0)",
              f"    ld t1, {-frame_size - 8}(sp)", "    sd t1, 8(t0)"]
    for symbol, offset in (("before_gpr", 0), ("after_gpr", 256)):
        lines += [f"    la t0, {symbol}"]
        for reg in range(32):
            lines += [f"    ld t1, {offset + reg * 8}(sp)", f"    sd t1, {reg * 8}(t0)"]
    lines += ["    la t0, after_csr"]
    for index, csr in enumerate(("vl", "vtype", "vstart", "vcsr", "fcsr")):
        lines += [f"    csrr t1, {csr}", f"    sd t1, {index * 8}(t0)"]
    # Rejected vstart/vill settings must be captured before enabling dumps.
    lines += ["    csrw vstart, zero", "    vsetivli zero, 1, e8, m1, tu, mu",
              "    vmv1r.v v31, v31", "    la t0, output"]
    for reg in range(32):
        lines += [f"    vs1r.v v{reg}, (t0)", "    addi t0, t0, 128"]
    lines += ["    la t0, after_fpr"]
    lines += [f"    fsd f{reg}, {reg * 8}(t0)" for reg in range(32)]
    for reg in range(1, 32):
        if reg != 2:
            lines.append(f"    ld x{reg}, {512 + reg * 8}(sp)")
    lines += ["    addi sp, sp, 1024", "    ret"]
    return "\n".join(lines) + "\n"


def check_stack_frame(assembly, limit):
    """Check all local control-flow paths against the independent canary bound."""
    instructions, labels = [], {}
    for line in assembly.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        if line.endswith(":"):
            labels[line[:-1]] = len(instructions)
        elif not line.startswith("."):
            instructions.append(line)
    pending, seen, deepest = [(0, 0)], set(), 0
    while pending:
        index, depth = pending.pop()
        if (index, depth) in seen or index == len(instructions):
            continue
        seen.add((index, depth))
        line = instructions[index]
        delta = re.fullmatch(r"addi\s+sp,\s*sp,\s*(-?\d+)", line)
        if delta:
            depth -= int(delta[1])
        if depth < 0 or depth > limit:
            raise ValueError(f"IME stack depth {depth} exceeds independent bound {limit}: {line}")
        deepest = max(deepest, depth)
        opcode = line.split()[0]
        if opcode in {"ret", "unimp", "ebreak"}:
            if opcode == "ret" and depth:
                raise ValueError(f"unbalanced IME stack on return: {depth}")
            continue
        if opcode == "j" or opcode.startswith("b"):
            target = line.replace(",", " ").split()[-1]
            if target not in labels:
                raise ValueError(f"unresolved IME stack-check target: {target}")
            pending.append((labels[target], depth))
            if opcode == "j":
                continue
        pending.append((index+1, depth))
    if deepest != limit:
        raise ValueError(f"IME canary bound {limit} differs from emitted maximum {deepest}")


def generate(directory, integer_only=False):
    sources, native_sources, cases, declarations = [], [], [], []
    frame_bounds = []
    operations = []
    for bits, slide in ((8, 0), (4, 0), (8, 1), (8, 2), (8, 3)):
        for suffix, sa, sb in (("", 1, 1), ("u", 0, 0), ("us", 0, 1), ("su", 1, 0)):
            op = f"smt.vmadot{slide if slide else ''}{suffix}"
            registers = ((0, 2, 31), (2, 0, 1), (30, 0, 0), (16, 1, 2), (16, 31, 1), (0, 30, 30))
            if slide:
                registers = ((0, 2, 31), (2, 0, 1), (30, 0, 0), (16, 2, 3), (0, 30, 31), (0, 30, 30))
            if bits == 8:
                # Exercise temporary conflicts and sources aliasing borrowed registers.
                registers += (((4, 2, 7), (6, 4, 5), (16, 6, 7), (16, 4, 4)) if slide
                              else ((4, 3, 7), (6, 4, 5), (16, 5, 6), (16, 7, 7)))
                registers += tuple((vd, 0, 1) for vd in range(8, 30, 2) if vd != 16)
                registers += ((8, 30, 31),)
            for vd, vs1, vs2 in registers:
                operations.append([(op, vd, vs1, vs2, sa, sb, bits, slide)])
    # Exercise result-to-input dependencies and different frame sizes in one
    # native RVV stream, without reloading architectural state between blocks.
    operations += [
        [("smt.vmadot", 8, 2, 3, 1, 1, 8, 0),
         ("smt.vmadotu", 0, 8, 9, 0, 0, 8, 0),
         ("smt.vmadot3su", 30, 0, 8, 1, 0, 8, 3)],
        [("smt.vmadot", 0, 2, 31, 1, 1, 4, 0),
         ("smt.vmadot1u", 2, 0, 31, 0, 0, 8, 1),
         ("smt.vmadotsu", 30, 0, 2, 1, 0, 8, 0)],
        [("smt.vmadot3us", 0, 30, 31, 0, 1, 8, 3),
         ("smt.vmadotu", 2, 0, 1, 0, 0, 4, 0),
         ("smt.vmadot2su", 30, 0, 3, 1, 0, 8, 2)],
    ]
    # Keep the oracle's operation tags separate from the production registry.
    # Fields after the mnemonic: vd, vs1, vs2, sa, sb, bits, slide, kind, imm.
    operations = [[(*op, 0, 0) for op in sequence] for sequence in operations]
    for kind, name in enumerate(("vpack", "vupack", "vnpack", "vnspack", "vnpack4", "vnspack4"), 1):
        registers = ((0, 0, 1), (2, 0, 2), (16, 16, 17), (30, 31, 30), (0, 31, 31), (16, 1, 2))
        if kind >= 3:
            registers = ((0, 0, 1), (1, 0, 1), (2, 2, 2), (31, 31, 0), (31, 0, 0), (16, 1, 2))
        for imm in range(4):
            for vd, vs1, vs2 in registers:
                operations.append([(f"smt.{name}.vv", vd, vs1, vs2, 0, 0, 0, 0, kind, imm)])
    operations += [
        [("smt.vpack.vv", 0, 2, 3, 0, 0, 0, 0, 1, 0),
         ("smt.vupack.vv", 2, 0, 1, 0, 0, 0, 0, 2, 0),
         ("smt.vmadot", 0, 2, 3, 1, 1, 8, 0, 0, 0)],
        [("smt.vnpack4.vv", 0, 2, 3, 0, 0, 0, 0, 5, 3),
         ("smt.vmadotsu", 30, 0, 1, 1, 0, 4, 0, 0, 0),
         ("smt.vupack.vv", 0, 30, 31, 0, 0, 0, 0, 2, 1)],
    ]
    operations.append([
        ("smt.vpack.vv", 0, 2, 3, 0, 0, 0, 0, 1, 1),
        ("smt.vpack.vv", 2, 0, 1, 0, 0, 0, 0, 1, 2),
        ("smt.vpack.vv", 0, 2, 3, 0, 0, 0, 0, 1, 3),
    ])
    if integer_only:
        operations = [sequence for sequence in operations if all(op[8] == 0 for op in sequence)]
    for sequence in operations:
        name = f"run_{len(cases)}"
        assembly = "\n".join(f"    {op} v{vd}, v{vs1}, v{vs2}, {imm if kind else 'i' + str(bits)}"
                             for op, vd, vs1, vs2, sa, sb, bits, slide, kind, imm in sequence)
        frame_size = max(
            (1616 if op[7] else 1488) if op[6] == 8 else 592 if op[8] == 1 else 848 if op[8] >= 3 else 976
            for op in sequence
        )
        frame_bounds.append(1024 + frame_size)
        sources.append(wrapper(name, assembly, frame_size))
        native_sources.append(wrapper("native_" + name, assembly, frame_size))
        declarations.append(f"extern void {name}(void);\n#ifdef IME_NATIVE\nextern void native_{name}(void);\n#endif")
        entries = ", ".join("{" + ", ".join(str(value) for value in op[1:]) + "}" for op in sequence)
        cases.append(f"    {{{name}, {len(sequence)}, {{{entries}}}\n#ifdef IME_NATIVE\n, native_{name}\n#endif\n}},")
    (directory / "input.s").write_text("".join(sources))
    translated = translate_assembly("".join(sources))
    entries = list(re.finditer(r"(?m)^run_(\d+):[ \t]*$", translated))
    if len(entries) != len(frame_bounds):
        raise ValueError("IME wrapper entry count changed")
    for index, entry in enumerate(entries):
        end = entries[index+1].start() if index+1 < len(entries) else len(translated)
        check_stack_frame(translated[entry.start():end], frame_bounds[index])
    (directory / "translated.s").write_text(translated)
    (directory / "native.s").write_text("".join(native_sources))
    (directory / "cases.h").write_text(
        "\n".join(declarations)
        + "\nstruct Operation { unsigned vd, vs1, vs2, sa, sb, bits, slide, kind, imm; };\n"
        + "struct Case { void (*run)(void); unsigned length; struct Operation operations[3];\n#ifdef IME_NATIVE\nvoid (*native)(void);\n#endif\n};\n"
        + "static const struct Case cases[] = {\n" + "\n".join(cases) + "\n};\n"
    )
    supported_widths = sum(
        all(op[8] < 3 or (sew == 8 if op[8] >= 5 else sew <= 32 and (32 << op[9]) >= 2 * sew)
            for op in sequence)
        for sequence in operations for sew in (8, 16, 32, 64)
    )
    (directory / "case-counts.json").write_text(json.dumps({
        "qemu": len(cases) * 51 * 5,
        "linux": supported_widths * 4 * 3 * 5,
        "native": supported_widths * 4 * 5 * 2,
    }, indent=2) + "\n")
    return len(cases)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cc", default=os.environ.get("IME_GCC", shutil.which("riscv64-elf-gcc")))
    parser.add_argument("--qemu", default=shutil.which("qemu-system-riscv64"))
    parser.add_argument("--build-dir", type=Path)
    parser.add_argument("--native", action="store_true", help="build/run Linux comparison on an A100 core")
    parser.add_argument("--linux", action="store_true", help="run translated positive cases against the oracle on Linux")
    parser.add_argument("--integer-only", action="store_true", help="limit verification to integer dot forms")
    args = parser.parse_args()
    linux = args.linux or args.native
    if not args.cc or (not linux and not args.qemu):
        parser.error("provide --cc (bare-metal RISC-V GCC) and --qemu")
    directory = args.build_dir or Path(tempfile.mkdtemp(prefix="ime-rvv-"))
    directory.mkdir(parents=True, exist_ok=True)
    generate(directory, integer_only=args.integer_only)
    here = Path(__file__).resolve().parent
    elf = directory / "verify.elf"
    flags = ["-DIME_LINUX", "-D_GNU_SOURCE"] if linux else [
        "-nostdlib", "-nostartfiles", "-T", str(here / "link.ld"), str(here / "start.S")]
    if args.native:
        flags.append("-DIME_NATIVE")
    extra_source = [str(directory / "native.s")] if args.native else []
    subprocess.run([
        args.cc, "-march=rv64gcv_xsmtvdotii" if args.native else "-march=rv64gcv",
        "-mabi=lp64d", "-mcmodel=medany", "-O2",
        "-ffreestanding", "-fno-builtin", "-fno-tree-vectorize", "-msmall-data-limit=0",
        *flags, "-I", str(directory), str(here / "main.c"),
        str(directory / "translated.s"), *extra_source, "-o", str(elf),
    ], check=True)
    command = [str(elf)] if linux else [
        args.qemu, "-machine", "virt", "-cpu", "rv64,v=true,vlen=1024,elen=64",
        "-m", "128M", "-smp", "1", "-bios", "none", "-nographic", "-kernel", str(elf),
    ]
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=90)
    except subprocess.TimeoutExpired as error:
        for suffix, value in (("stdout", error.stdout), ("stderr", error.stderr)):
            (directory / f"timeout.{suffix}").write_bytes(
                value if isinstance(value, bytes) else (value or "").encode())
        raise SystemExit(f"IME verification timed out after 90s; output saved in {directory}") from error
    print(result.stdout, end="")
    print(result.stderr, end="", file=sys.stderr)
    print(f"artifacts: {directory}")
    counts = json.loads((directory / "case-counts.json").read_text())
    expected_count = counts["native" if args.native else "linux" if linux else "qemu"]
    if result.returncode != 0 or f"PASS cases={expected_count} " not in result.stdout:
        raise SystemExit(f"RVV execution/state verification failed: expected PASS cases={expected_count}, exit={result.returncode}, observed={result.stdout!r}")


if __name__ == "__main__":
    main()
