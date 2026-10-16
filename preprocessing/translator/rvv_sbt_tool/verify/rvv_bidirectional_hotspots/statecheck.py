#!/usr/bin/env python3
"""Generate native-source versus translated full-state hardware comparisons."""

import argparse
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[2]


def cases(direction):
    if direction == "forward":
        result = [(f"vfwmacc.vv v8, v16, v{source}", sew, lmul, 0, 0)
                  for sew in (16, 32) for lmul in (0.5, 1, 2, 4) for source in (16, 24)]
        result.extend((f"vfwmacc.vv v8, v{8 + lmul}, v16", sew, lmul, 0, 0)
                      for sew in (16, 32) for lmul in (1, 2, 4))
        for sew in (8, 16, 32, 64):
            for lmul in (0.5, 1, 2, 4, 8):
                if sew > 64 * lmul:
                    continue
                for immediate in (-16, 0, 15):
                    result.append((f"vmv.v.i v8, {immediate}", sew, lmul, 0, 0))
        for lmul in (0.5, 1, 2, 4, 8):
            for command in ("vfmacc.vv v8, v16, v24", "vfmacc.vv v8, v8, v24",
                            "vfmacc.vv v8, v16, v16", "vfmacc.vv v8, v16, v24, v0.t"):
                result.append((command, 32, lmul, 0, 0))
            for vd in (0, 8, 24):
                for address in ("a0", "t0", "t1", "t2", "t3", "t6"):
                    for mask in ("", ", v0.t"):
                        if vd == 0 and mask:
                            continue
                        result.append((f"vle32.v v{vd}, ({address}){mask}", 32, lmul, 0, 0))
        return list(dict.fromkeys(result))
    result = []
    for sew, lmul in ((8, 0.5), (8, 1), (16, 2), (32, 1), (32, 4), (64, 1)):
        for command in ("vadd.vv v8, v16, v24", "vadd.vv v8, v8, v16",
                        "vadd.vv v8, v16, v24, v0.t", "vmv.x.s t6, v8"):
            result.append((command, sew, lmul, (1 << 31) if command.startswith("vmv.x") else 0, 0))
    for sew, lmul in ((16, 1), (32, 1), (32, 4), (64, 1)):
        for command in ("vfadd.vv v8, v16, v24", "vfmacc.vv v8, v16, v24",
                        "vfmacc.vf v8, fa0, v8", "vfmv.f.s fa0, v8"):
            result.append((command, sew, lmul, 0, (1 << 10) if command.startswith("vfmv.f") else 0))
    for sew, lmul in ((16, 1), (16, 4), (32, 1)):
        result.append(("vfwmacc.vv v8, v16, v24", sew, lmul, 0, 0))
    for sew in (8, 16, 32):
        result.append(("vnclip.wi v8, v16, 1", sew, 1, 0, 0))
    result.extend((command, 32, 1, 0, 0) for command in ("vle32.v v8, (a0)", "vse32.v v8, (a0)"))
    lmuls = (0.125, 0.25, 0.5, 1, 2, 4, 8)
    for sew in (8, 16, 32, 64):
        for lmul in lmuls:
            if sew > 64 * lmul:
                continue
            for eew in (8, 16, 32, 64):
                if lmul * eew / sew not in lmuls:
                    continue
                for mask in ("", ", v0.t"):
                    result.append((f"vle{eew}.v v8, (a0){mask}", sew, lmul, 0, 0))
    for sew, lmul, eew in ((8, 1, 32), (16, 1, 64), (32, 1, 8),
                           (32, 1, 64), (64, 1, 8), (32, 8, 32)):
        for vd in (0, 8, 24):
            for address in ("t0", "t1", "t2", "t3", "t6"):
                for mask in ("", ", v0.t"):
                    if vd == 0 and mask:
                        continue
                    result.append((f"vle{eew}.v v{vd}, ({address}){mask}", sew, lmul, 0, 0))
    arithmetic = (
        "vfmacc.vv v8, v16, v24", "vfadd.vv v8, v16, v24",
        "vmacc.vv v8, v16, v24", "vadd.vi v8, v16, -16",
        "vadd.vx v8, v16, a1", "vand.vv v8, v16, v24",
        "vand.vx v8, v16, a1", "vand.vi v8, v16, 15",
        "vor.vv v8, v16, v24", "vsll.vv v8, v16, v24",
        "vsll.vi v8, v16, 4", "vsrl.vv v8, v16, v24",
        "vsrl.vi v8, v16, 4", "vsra.vi v8, v16, 4",
    )
    for command in arithmetic:
        for sew in (8, 16, 32, 64):
            if command.startswith("vf") and sew == 8:
                continue
            for lmul in lmuls:
                if sew <= 64 * lmul:
                    result.append((command, sew, lmul, 0, 0))
        for sew, lmul in ((32, 2), (32, 8)):
            for alias in (command.replace("v16", "v8"),
                          command.replace("v24", "v16"),
                          command.replace("v16", "v8").replace("v24", "v8")):
                result.append((alias, sew, lmul, 0, 0))
            if lmul == 2 and not command.startswith(("vfmacc.", "vmacc.")):
                result.append((command + ", v0.t", sew, lmul, 0, 0))
    for command in ("vfwmacc.vv v8, v10, v11", "vfwmacc.vv v8, v9, v16",
                    "vfwmacc.vv v8, v16, v9", "vfwmacc.vv v8, v9, v9",
                    "vfwmacc.vv v8, v16, v16", "vfwmacc.vv v8, v0, v0"):
        result.append((command, 16, 1, 0, 0))
    for lmul in (2, 8):
        for command in ("vadd.vx v8, v16, t6", "vand.vx v8, v16, x31"):
            result.append((command, 32, lmul, 0, 0))
    return list(dict.fromkeys(result))


def wrapper(symbol, body, source_vlenb, native, command):
    saved_gprs = (1, 8, 9, *range(18, 28))
    saved_fprs = (8, 9, *range(18, 28))
    lines = [".text", f".globl {symbol}", f".type {symbol}, @function", f"{symbol}:",
             "    addi sp, sp, -2048", "    addi sp, sp, -512", "    li t0, 0x9191919191919191"]
    lines += [f"    sd t0, {i * 8}(sp)" for i in range(8)]
    lines.append("    addi sp, sp, 512")
    lines += [f"    sd x{reg}, {1024 + i * 8}(sp)" for i, reg in enumerate(saved_gprs)]
    lines += [f"    fsd f{reg}, {1128 + i * 8}(sp)" for i, reg in enumerate(saved_fprs)]
    if native:
        lines.append("    la t0, simulated_cpu_state")
        for reg in range(32):
            lines += [f"    vl1re8.v v{reg}, (t0)", f"    addi t0, t0, {source_vlenb}"]
        lines += ["    la t0, input_vl", "    ld t0, 0(t0)",
                  "    la t1, input_vtype", "    ld t1, 0(t1)", "    vsetvl zero, t0, t1"]
    # The reverse candidate restores guest vcsr, so seed a distinct host value
    # (xor 7) to detect accidental preservation of host state. Native and forward
    # start with guest vcsr; forward preserves the caller's hardware value.
    lines += ["    la t0, input_vcsr", "    ld t0, 0(t0)"] if native or source_vlenb == 128 else ["    li t0, 7", "    la t1, input_vcsr", "    ld t1, 0(t1)", "    xor t0, t0, t1"]
    lines += ["    csrw vcsr, t0", "    csrw vstart, zero", "    la t0, input_fcsr", "    ld t0, 0(t0)", "    csrw fcsr, t0", "    la t0, fp_seed"]
    lines += [f"    fld f{reg}, {reg * 8}(t0)" for reg in range(32)]
    lines += [f"    li x{reg}, {0x12340000 + reg * 313}" for reg in range(5, 32)]
    lines.append("    la a0, memory_data")
    address = re.search(r"\(([a-zA-Z0-9]+)\)", command)
    if address is not None:
        address_register = address.group(1)
        if address_register in {"sp", "x2"}:
            raise ValueError("State comparisons cannot replace the stack pointer")
        if address_register not in {"a0", "x10"}:
            lines.append(f"    la {address_register}, memory_data")
    for base in (0, 512):
        if base:
            lines.extend(body.splitlines())
        lines += [f"    sd x{reg}, {base + reg * 8}(sp)" for reg in range(32)]
        lines += [f"    fsd f{reg}, {base + 256 + reg * 8}(sp)" for reg in range(32)]
    lines += ["    la t0, actual_fcsr", "    csrr t1, fcsr", "    sd t1, 0(t0)",
              "    la t0, actual_vcsr", "    csrr t1, vcsr", "    sd t1, 0(t0)"]
    if native:
        lines.append("    la t0, simulated_cpu_state")
        for reg in range(32):
            lines += [f"    vs1r.v v{reg}, (t0)", f"    addi t0, t0, {source_vlenb}"]
        for csr, offset in (("vstart", 0x1000), ("vcsr", 0x1018), ("vl", 0x1020), ("vtype", 0x1028)):
            lines += ["    la t0, simulated_cpu_state", f"    li t1, {offset}",
                      "    add t0, t0, t1", f"    csrr t1, {csr}", "    sd t1, 0(t0)"]
    for symbol_name, offset in (("register_before", 0), ("register_after", 512)):
        lines.append(f"    la t0, {symbol_name}")
        for i in range(64):
            lines += [f"    ld t1, {offset + i * 8}(sp)", f"    sd t1, {i * 8}(t0)"]
    lines += ["    la t0, stack_guard"]
    for i in range(8):
        lines += [f"    ld t1, {-512 + i * 8}(sp)", f"    sd t1, {i * 8}(t0)"]
    lines += [f"    ld x{reg}, {1024 + i * 8}(sp)" for i, reg in enumerate(saved_gprs)]
    lines += [f"    fld f{reg}, {1128 + i * 8}(sp)" for i, reg in enumerate(saved_fprs)]
    lines += ["    addi sp, sp, 1024", "    addi sp, sp, 1024", "    ret", f".size {symbol}, .-{symbol}"]
    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--direction", choices=("forward", "reverse"), required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--translator-root", type=Path, default=ROOT)
    args = parser.parse_args()
    sys.path[:0] = [str(args.translator_root), str(args.translator_root / "src")]
    from riscv.frontend.parser import AsmParser
    from rvv_sbt_rvv import translate as forward
    from rvv_sbt_rvv1024 import translate as reverse
    translate = forward if args.direction == "forward" else reverse
    source, target = (128, 32) if args.direction == "forward" else (32, 128)
    args.out.mkdir(parents=True, exist_ok=True)
    declarations, entries, native, candidate = [], [], [], []
    selected = cases(args.direction)
    for index, (command, sew, lmul, gpr, fpr) in enumerate(selected):
        assembly = translate(AsmParser().parse_string(command), raw=True, tls_state=False,
                             init_vtype=f"sew={sew},lmul={lmul},tu,mu")
        if "fallback" in assembly.lower():
            raise ValueError(f"Incomplete state case: {command}, e{sew}, m{lmul}")
        assembly = re.sub(r"\.L_[A-Za-z0-9_]+", lambda m: f".L_case_{index}_{m[0][3:]}", assembly)
        native.append(wrapper(f"native_{index}", command, source, True, command))
        candidate.append(wrapper(f"candidate_{index}", assembly, source, False, command))
        declarations += [f"extern void native_{index}(void);", f"extern void candidate_{index}(void);"]
        token = {0.125: 5, 0.25: 6, 0.5: 7, 1: 0, 2: 1, 4: 2, 8: 3}[lmul]
        vtype = ({8: 0, 16: 1, 32: 2, 64: 3}[sew] << 3) | token
        entries.append(f"{{FN({index}), {sew}, {int(source * 8 * lmul / sew)}, {vtype}, {gpr}u, {fpr}u}},")
    header = "\n".join([f"#define SOURCE_VLENB {source}", f"#define TARGET_VLENB {target}", *declarations,
                          "#ifdef NATIVE", "#define FN(n) native_##n", "#else", "#define FN(n) candidate_##n", "#endif",
                          "struct Case { void (*run)(void); unsigned sew, vlmax, vtype; uint32_t gpr, fpr; };",
                          "static const struct Case cases[] = {", *entries, "};", ""])
    (args.out / "cases.h").write_text(header)
    (args.out / "native.S").write_text("\n".join(native))
    (args.out / "candidate.S").write_text("\n".join(candidate))
    (args.out / "main.c").write_bytes(Path(__file__).with_name("statecheck.c").read_bytes())
    (args.out / "cases.json").write_text(json.dumps(selected, indent=2) + "\n")
    print(json.dumps({"direction": args.direction, "static_cases": len(selected), "output": str(args.out)}))


if __name__ == "__main__": main()
