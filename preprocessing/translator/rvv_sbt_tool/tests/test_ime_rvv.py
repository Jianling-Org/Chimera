"""Native IME routing, validation, and assembly integration contracts."""

import shutil
import subprocess
import os
import re
from pathlib import Path

import pytest

from ime_sbt_rvv import translate_assembly
from riscv.extensions.rvv.translation.contracts import InstructionValidationError
from riscv.extensions.spacemit_ime.backend import REGISTRY, NativeContext
from riscv.frontend.parser import AsmParser


@pytest.mark.parametrize("opcode", ["smt.vmadot", "smt.vmadotu", "smt.vmadotus", "smt.vmadotsu"])
@pytest.mark.parametrize("regs", ["v0, v2, v31", "v2, v0, v1", "v30, v0, v0", "v16, v1, v2",
                                  "v4, v3, v7", "v6, v4, v5"])
@pytest.mark.parametrize("dtype", ["i4", "i8"])
def test_lowering_preserves_native_source_and_assembles(tmp_path, opcode, regs, dtype):
    prefix = ".text\n.globl f\nf:\n    vsetivli a0, 7, e16, m1, tu, mu\n    vadd.vv v4, v5, v6\n"
    suffix = "    vmv1r.v v31, v30\n    ret\n.size f, .-f\n"
    result = translate_assembly(prefix + f"    {opcode} {regs}, {dtype}\n" + suffix)
    assert result.startswith(prefix)
    assert result.endswith(suffix)
    assert "smt." not in result
    assert "simulated_cpu_state" not in result
    assert ("vmacc.vv" if dtype == "i8" else "vmacc.vx") in result
    _assemble(tmp_path, result)


def _assemble(tmp_path, result):
    clang = os.environ.get("IME_CLANG") or (
        "/opt/homebrew/opt/llvm/bin/clang" if Path("/opt/homebrew/opt/llvm/bin/clang").exists()
        else shutil.which("clang")
    )
    if clang is None:
        pytest.skip("clang is required for cross assembly")
    source = tmp_path / "ime.s"
    source.write_text(result)
    subprocess.run([clang, "--target=riscv64", "-march=rv64gcv", "-c", str(source),
                    "-o", str(tmp_path / "ime.o")], check=True, capture_output=True)


@pytest.mark.parametrize("slide", [1, 2, 3])
@pytest.mark.parametrize("suffix", ["", "u", "us", "su"])
@pytest.mark.parametrize("regs", ["v0, v2, v31", "v2, v0, v1", "v30, v0, v0", "v0, v30, v31",
                                  "v4, v2, v7", "v6, v4, v5"])
def test_sliding_window_assembles_and_declares_complete_source_group(tmp_path, slide, suffix, regs):
    instruction = AsmParser().parse_string(f"smt.vmadot{slide}{suffix} {regs}, i8")[0]
    context = NativeContext(instruction, lambda name: ".L_" + name)
    plan = REGISTRY.plan(context)
    result = REGISTRY.lower(context, plan)
    vd, vs1, vs2 = regs.split(", ")
    assert result.semantic_outputs == {vd, f"v{int(vd[1:]) + 1}"}
    assert result.semantic_inputs == result.semantic_outputs | {vs1, f"v{int(vs1[1:]) + 1}", vs2}
    assert not result.clobbered_gprs and not result.clobbered_vregs
    _assemble(tmp_path, translate_assembly(f".text\nf:\n {instruction.opcode} {instruction.op_str}\n ret\n"))


@pytest.mark.parametrize("source", [
    "smt.vmadot v1, v4, v8, i8", "smt.vmadot v2, v3, v8, i8",
    "smt.vmadot v2, v4, v2, i8", "smt.vmadot v32, v4, v8, i8",
    "smt.vmadot v2, v4, v8, i16", "smt.vmadot v2, v4, v8",
    "smt.vmadot v2, v4, v8, i8, v0.t", "smt.vmadot1 v2, v4, v8, i4",
    "smt.vfwmadot v2, v4, v8", "smt.unknown v2, v4, v8",
    "smt.vmadot1 v0, v31, v4, i8", "smt.vmadot2 v0, v3, v4, i8",
    "smt.vmadot3u v0, v3, v4, i8", "smt.vmadot3 v2, v2, v8, i8",
    "smt.vmadot2su v4, v2, v5, i8", "smt.vmadot4 v0, v2, v4, i8",
])
def test_invalid_or_unsupported_ime_never_passes_through(source):
    with pytest.raises(InstructionValidationError):
        translate_assembly(source)


@pytest.mark.parametrize("slide", [1, 2, 3])
@pytest.mark.parametrize("suffix", ["", "u", "us", "su"])
def test_all_sliding_forms_reject_int4_and_odd_source(slide, suffix):
    for operands in ("v0, v2, v4, i4", "v0, v31, v4, i8"):
        with pytest.raises(InstructionValidationError):
            translate_assembly(f"smt.vmadot{slide}{suffix} {operands}\n")


@pytest.mark.parametrize("name", ["vpack", "vupack", "vnpack", "vnspack", "vnpack4", "vnspack4"])
@pytest.mark.parametrize("imm", [0, 1, 2, 3])
def test_rearrangements_assemble_and_report_overlapping_operands(tmp_path, name, imm):
    destination = "v0" if name in {"vpack", "vupack"} else "v31"
    instruction = AsmParser().parse_string(f"smt.{name}.vv {destination}, {destination}, v1, {hex(imm)}")[0]
    operands = instruction.operands.copy()
    context = NativeContext(instruction, lambda name: ".L_" + name)
    plan = REGISTRY.plan(context)
    assert plan.normalized_operands[-1] == str(imm)
    result = REGISTRY.lower(context, plan)
    assert instruction.operands == operands
    assert result.semantic_inputs == {destination, "v1"}
    assert result.semantic_outputs == ({"v0", "v1"} if destination == "v0" else {"v31"})
    assert not result.clobbered_gprs and not result.clobbered_vregs
    _assemble(tmp_path, translate_assembly(f".text\nf:\n {instruction.opcode} {instruction.op_str}\n ret\n"))


@pytest.mark.parametrize("source", [
    "smt.vpack.vv v1, v2, v3, 0", "smt.vupack.vv v31, v0, v1, 0",
    "smt.vnpack.vv v32, v0, v1, 0", "smt.vnpack.vv v0, v32, v1, 0",
    "smt.vnspack.vv v0, v1, v2, -1", "smt.vnpack4.vv v0, v1, v2, 4",
    "smt.vnspack4.vv v0, v1, v2, i4", "smt.vpack.vv v0, v1, v2",
    "smt.vupack.vv v0, v1, v2, 0, v0.t",
])
def test_rearrangements_reject_invalid_operands(source):
    with pytest.raises(InstructionValidationError):
        translate_assembly(source)


def test_native_only_input_is_identical():
    source = ".text\nf:\n vsetvli t6, a0, e64, m8, ta, ma\n vcompress.vm v8, v16, v0\n csrr t0, vlenb\n ret\n"
    assert translate_assembly(source) == source


def test_inline_labels_multiple_blocks_and_repeatability():
    source = ".L_chimera_ime_0_row:\n1: smt.vmadot v2, v4, v8, i8\n bnez a0, 1b\n smt.vmadotu v0, v2, v3, i8\n ret\n"
    result = translate_assembly(source)
    labels = [line for line in result.splitlines() if line.endswith(":")]
    assert len(labels) == len(set(labels))
    assert "1:\n" in result and " bnez a0, 1b\n" in result
    assert translate_assembly(source) == result


@pytest.mark.parametrize("source", [
    ".macro foo\nsmt.vmadot v2,v4,v8,i8\n.endm", ".insn 0x1234",
    ".word 0x1234", ".include \"other.s\"", ".if 1\n.endif",
    "smt.vmadot v2,v4,v8,i8; ret", "vmadot v2,v4,v8",
    "vpack.vv v0,v1,v2,0", "vnspack4.vv v0,v1,v2,0",
    "00001000 <f>:\n1000: 00008067 ret", "j 16", "auipc t0, 42",
])
def test_rejects_unexpanded_or_address_fixed_input(source):
    with pytest.raises(ValueError):
        translate_assembly(source)


def test_source_state_and_semantic_operands_are_not_mutated():
    instruction = AsmParser().parse_string("smt.vmadotus v30, v1, v2, i8")[0]
    operands = instruction.operands.copy()
    context = NativeContext(instruction, lambda name: ".L_" + name)
    plan = REGISTRY.plan(context)
    result = REGISTRY.lower(context, plan)
    assert instruction.operands == operands
    assert result.semantic_inputs == {"v30", "v31", "v1", "v2"}
    assert result.semantic_outputs == {"v30", "v31"}
    assert not result.clobbered_gprs and not result.clobbered_vregs


@pytest.mark.parametrize("slide", [0, 1, 2, 3])
@pytest.mark.parametrize("suffix", ["", "u", "us", "su"])
def test_int8_loop_uses_full_vectors_without_vector_loads_or_configuration_changes(slide, suffix):
    source = f"smt.vmadot{slide or ''}{suffix} v6, v4, v5, i8\n"
    result = translate_assembly(source)
    # Each K updates both four-row groups at VL=32. Expensive vector memory or
    # gather operations must stay outside this loop.
    loop = next(line for line in result.splitlines() if line.endswith("_k:"))
    body = result.split(loop, 1)[1].split(f"    bnez t3, {loop[:-1]}", 1)[0]
    assert "vset" not in body
    assert "vlse" not in result
    assert "vle" not in body and "vrgather" not in body
    assert body.count("vmacc.vv") == 2


@pytest.mark.parametrize("imm", range(4))
def test_pack_only_snapshots_inputs_and_borrows_no_vectors(imm):
    result = translate_assembly(f"smt.vpack.vv v2, v12, v13, {imm}\n")
    assert result.count("vs1r.v") == 2
    assert result.count("vl1re8.v") == 2
    assert "vle8.v" not in result and "vse8.v" not in result
    assert "vset" not in result
    assert "csrr t0, vl\n" not in result
    assert result.count("csrr t0, vtype") == 1
    assert not re.search(r", (?:56|64)\(sp\)", result)
    assert not re.search(r"\b(?:ld|sd) t[2-6],", result)
    if imm:
        assert result.count("    sd t0,") == 33  # t0 save plus 32 payload words


def test_pack_expansions_remain_independent_across_source_boundaries():
    instructions = ["smt.vpack.vv v0, v0, v1, 1\n",
                    "smt.vpack.vv v2, v0, v1, 2\n",
                    "vsetivli a0, 7, e16, m1, tu, mu\n",
                    "smt.vpack.vv v0, v2, v3, 0\n"]
    def labels(text):
        return re.sub(r"\.L_chimera_ime_\d+_", ".L_", text)
    assert labels(translate_assembly("".join(instructions))) == labels(
        "".join(translate_assembly(source) for source in instructions))


def test_removes_only_ime_isa_attribute():
    source = '.attribute arch, "rv64i2p1_v1p0_xsmtvdotii1p0"\nret\n'
    assert translate_assembly(source) == '.attribute arch, "rv64i2p1_v1p0"\nret\n'


def test_failed_cli_does_not_overwrite_output(tmp_path):
    import sys
    from pathlib import Path
    source, output = tmp_path / "bad.s", tmp_path / "out.s"
    source.write_text("smt.vmadot1 v2,v4,v8,i4\n")
    output.write_text("preserve me")
    result = subprocess.run([sys.executable, str(Path(__file__).resolve().parents[1] / "ime_sbt_rvv.py"),
                             str(source), "-o", str(output)], capture_output=True)
    assert result.returncode == 2
    assert output.read_text() == "preserve me"


def test_generated_rvv_execution_and_full_state(tmp_path):
    import sys
    cc = os.environ.get("IME_GCC") or shutil.which("riscv64-elf-gcc")
    if cc is None and Path("/opt/homebrew/opt/riscv64-elf-gcc/bin/riscv64-elf-gcc").exists():
        cc = "/opt/homebrew/opt/riscv64-elf-gcc/bin/riscv64-elf-gcc"
    qemu = shutil.which("qemu-system-riscv64")
    if cc is None or qemu is None:
        pytest.skip("bare-metal RISC-V GCC and QEMU system emulator are required")
    runner = Path(__file__).resolve().parents[1] / "verify/ime_rvv/run_verify.py"
    result = subprocess.run([
        sys.executable, str(runner), "--cc", cc, "--qemu", qemu,
        "--build-dir", str(tmp_path),
    ], capture_output=True, text=True, timeout=120)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "PASS cases=130050 " in result.stdout


@pytest.mark.parametrize("vd", range(0, 32, 2))
@pytest.mark.parametrize("slide", range(4))
@pytest.mark.parametrize("suffix,sa,sb", [("", True, True), ("u", False, False),
                                        ("us", False, True), ("su", True, False)])
def test_int8_extraction_and_direct_accumulator(vd, slide, suffix, sa, sb):
    vs1, vs2 = (2, 3) if vd == 0 else (0, 1)
    result = translate_assembly(f"smt.vmadot{slide or ''}{suffix} v{vd}, v{vs1}, v{vs2}, i8\n")
    direct = vd >= 8
    accumulator = vd if direct else 4
    assert f"vmacc.vv v{accumulator}, v3, v6" in result
    assert f"vmacc.vv v{accumulator + 1}, v3, v6" in result
    assert ("vl2re32.v v4" in result) == (not direct)
    assert ("vs2r.v v4" in result) == (not direct)
    assert result.count("vs1r.v") == (9 + bool(slide) if direct else 11 + bool(slide)) + 2
    if direct:
        for reg in (vd, vd + 1):
            assert f"vs1r.v v{reg}," not in result
            assert f"vl1re8.v v{reg}," not in result
    assert "vsll.vv v6, v6, v2" in result
    assert f"{'vsra' if sb else 'vsrl'}.vi v6, v6, 24" in result
    assert result.count("vsll.vv v3, v3, v1") == 2
    assert result.count(f"{'vsra' if sa else 'vsrl'}.vi v3, v3, 24") == 2
    assert "vand.vx" not in result and "vsll.vi v3, v3, 24" not in result


def test_int8_expansions_remain_independent_across_source_boundaries():
    instructions = ["smt.vmadot v8, v2, v3, i8\n",
                    "vsetivli a0, 7, e16, m1, tu, mu\n",
                    "smt.vmadotu v0, v8, v9, i8\n",
                    "smt.vmadot3su v30, v0, v8, i8\n"]
    def labels(text):
        return re.sub(r"\.L_chimera_ime_\d+_", ".L_", text)
    assert labels(translate_assembly("".join(instructions))) == labels(
        "".join(translate_assembly(source) for source in instructions))
