"""PLT target routing: generated code, ELF relocations and RV64 execution."""
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from riscv.codegen.control_flow import ControlFlowContext, ControlFlowEmitter, EmissionOptions
from riscv.frontend.analysis import analyze_structure
from riscv.frontend.parser import AsmParser
from riscv.registers import CALL_CLOBBERED_FPRS, CALL_CLOBBERED_GPRS


def _assert_only_expected_traps(output, profile):
    checked_query = (
        r"    call    query_original_translated_map@plt\n"
        r"    bnez    a0, 1f\n"
        r"    ld      a1, \d+\(sp\)\n"
        rf"    li      a0, {profile}\n"
        r"    ebreak\n1:"
    )
    remainder, guards = re.subn(checked_query, "", output)
    assert guards == output.count("    call    query_original_translated_map@plt")
    assert guards > 0
    reject = r"    # Unsupported no-link indirect target remap\n    ebreak"
    remainder, rejections = re.subn(reject, "", remainder)
    assert rejections == len(re.findall(r"^\.Lchimera_indirect_reject_[0-9a-f]+:", output, re.M))
    assert "ebreak" not in remainder


def _ifunc_program():
    # The 2026-10-08 handoff's scalar libc reproduces the stalled call site.
    fixture = Path(__file__).parent / "fixtures/objdump/libc_printf_ifunc.objdump.s"
    return AsmParser().parse_string_program(fixture.read_text())


@pytest.mark.parametrize("profile", [1, 2])
def test_historical_libc_ifunc_uses_resolved_original_got(profile):
    from rvv_sbt_rvv import translate_program as forward
    from rvv_sbt_rvv1024 import translate_program as reverse

    program = _ifunc_program()
    candidate = analyze_structure(program).plt_candidates[0x47a5a]
    assert (candidate.address, candidate.symbol) == (0x277a0, "*ABS*+0x7ab82@plt")
    assert candidate.got_address == 0x147088
    output = (forward if profile == 1 else reverse)(program)
    block = output.split("branch_j_target_47a5a:\n", 1)[1].split("branch_j_target_47a5e:", 1)[0]
    _assert_only_expected_traps(block, profile)
    assert "%got_pcrel_hi(*ABS*" not in block
    slot_load = f"li      t0, {0x147088}"
    assert slot_load in block
    assert "ld      a1, 0(a1)" in block
    assert block.index("bne     a1, t0") < block.index(slot_load)
    assert block.index(slot_load) < block.index("call    query_original_translated_map@plt")


@pytest.mark.parametrize("profile", [1, 2])
@pytest.mark.parametrize("opcode,operands", [
    ("call", "*ABS*+0x7ab82@plt"),
    ("jal", "*ABS*+0x7ab82@plt"),
    ("jal", "ra, *ABS*+0x7ab82@plt"),
    ("jal", "x0, *ABS*+0x7ab82@plt"),
    ("tail", "*ABS*+0x7ab82@plt"),
    ("j", "*ABS*+0x7ab82@plt"),
])
def test_direct_ifunc_uses_original_got_through_program_pipeline(profile, opcode, operands):
    from rvv_sbt_rvv import translate_program as forward
    from rvv_sbt_rvv1024 import translate_program as reverse

    program = _ifunc_program()
    insn = AsmParser().parse_string(f"{opcode} {operands}")[0]
    insn.address = 0x47a56
    program.functions[1].instructions = [insn]
    assert analyze_structure(program).plt_candidates[0x47a56].got_address == 0x147088
    output = (forward if profile == 1 else reverse)(program)
    _assert_only_expected_traps(output, profile)
    assert f"li      t0, {0x147088}" in output
    assert "call    query_original_translated_map@plt" in output


@pytest.mark.parametrize("jump", ["t1,t3", "x6,0(x28)", "t1,0x0(t3)"])
def test_ifunc_got_decoding_sign_extends_auipc_and_ignores_comments(jump):
    program = _ifunc_program()
    stub = program.functions[0]
    stub.instructions[0].operands[1] = "0xfffff"
    stub.instructions[1].operands[1] = "-8(t3)"
    stub.instructions[1].raw_line = "# 1234 <misleading>"
    stub.instructions[2].operands = jump.split(",")
    assert analyze_structure(program).plt_candidates[0x47a5a].got_address == 0x26798


def test_unsupported_symbol_does_not_silently_use_a_lazy_plt_slot():
    from rvv_sbt_rvv import translate_program

    program = _ifunc_program()
    program.functions[0].name = "memcpy@UNKNOWN@plt"
    with pytest.raises(ValueError, match="cannot resolve PLT target"):
        translate_program(program)


@pytest.mark.parametrize("corruption", ["missing_load", "wrong_base", "wrong_jump", "gap", "unaligned"])
def test_unrecognized_ifunc_stub_rejects_translation(corruption):
    from rvv_sbt_rvv import translate_program

    program = _ifunc_program()
    stub = program.functions[0]
    if corruption == "missing_load":
        stub.instructions[1].opcode = "addi"
    elif corruption == "wrong_base":
        stub.instructions[1].operands[1] = "-1816(t2)"
    elif corruption == "wrong_jump":
        stub.instructions[2].operands[1] = "t2"
    elif corruption == "gap":
        stub.instructions[1].address += 2
    else:
        stub.instructions[1].operands[1] = "-1815(t3)"
    with pytest.raises(ValueError, match="cannot resolve PLT target"):
        translate_program(program)


def _emit(opcode, operands, profile=1, address=0x1000):
    insn = AsmParser().parse_string(f"{opcode} {operands}")[0]
    insn.address = address
    return ControlFlowEmitter(lookup_profile=profile).emit_program_scalar(
        insn, insn.operands, "original_base", context=None,
        active_long_jump_veneers={},
    )


def _pair_program(auipc="t3, 0x2", jalr="ra, 32(t3)", stub=0x3020, *, ifunc=False):
    symbol = "*ABS*+0x5000@plt" if ifunc else "invoke@plt"
    body = f"""
    {stub:x}: 00001e17 auipc t3,0x1
    {stub + 4:x}: fe0e3e03 ld t3,-32(t3)
    {stub + 8:x}: 000e0367 jalr t1,t3
""" if ifunc else f"    {stub:x}: 00000013 nop"
    return AsmParser().parse_string_program(f"""
Disassembly of section .text:
0000000000001000 <caller>:
    1000: 00002e17 auipc {auipc}
    1004: 020e00e7 jalr {jalr}
Disassembly of section .plt:
{stub:016x} <{symbol}>:
{body}
""")


def _emit_pair(profile, bypass=False, tail=False, base="t3", *, ifunc=False):
    program = _pair_program(
        auipc=f"{base}, 0x2", jalr=f"{'x0' if tail else 'ra'}, 32({base})", ifunc=ifunc,
    )
    structure = analyze_structure(program)
    context = ControlFlowContext(structure, EmissionOptions())
    emitter = ControlFlowEmitter(lookup_profile=profile)
    instructions = program.functions[0].instructions
    lines = []
    if bypass:
        # Simulate entering the JALR directly with another live target, with
        # bit zero set to exercise the architectural JALR address masking.
        lines += [f"la {base}, alternate", f"addi {base}, {base}, -31"]
    else:
        lines += emitter.emit_program_scalar(
            instructions[0], instructions[0].operands, "original_base",
            context=context, active_long_jump_veneers={},
        )
    lines += emitter.emit_program_scalar(
        instructions[1], instructions[1].operands, "original_base",
        context=context, active_long_jump_veneers={},
    )
    return lines


@pytest.mark.parametrize("auipc,jalr,stub", [
    ("ra, 0x2", "32(ra)", 0x3020),
    ("t3, 0x2", "ra, 32(t3)", 0x3020),
    ("x28, 0x2", "x0, t3, 32", 0x3020),
    ("t3, 0xfffff", "ra, 32(t3)", 0x20),
    ("ra, 0x2", "-32(ra)", 0x2fe0),
])
def test_pair_candidates_use_operands_not_comments(auipc, jalr, stub):
    program = _pair_program(auipc, jalr, stub)
    structure = analyze_structure(program)
    target = structure.plt_candidates[0x1004]
    assert (target.address, target.symbol) == (stub, "invoke@plt")
    edge = structure.call_graph.edge_for_call(0x1004)
    assert edge is None or not edge.resolved


@pytest.mark.parametrize("auipc,jalr,stub", [
    ("t3, 0x2", "ra, 32(t2)", 0x3020),
    ("t3, 0x2", "ra, 40(t3)", 0x3020),
    ("sp, 0x2", "ra, 32(sp)", 0x3020),
    ("zero, 0x2", "ra, 32(zero)", 0x3020),
])
def test_unmatched_pair_has_no_candidate(auipc, jalr, stub):
    assert not analyze_structure(_pair_program(auipc, jalr, stub)).plt_candidates


def test_glibc_irelative_without_got_does_not_guess_public_symbol():
    program = AsmParser().parse_string_program("""
Disassembly of section .plt:
00000000000277a0 <*ABS*+0x7ab82@plt>:
    277a0: 00000013 nop
Disassembly of section .text:
0000000000047a56 <caller>:
    47a56: fffe0097 auipc ra,0xfffe0
    47a5a: d4a080e7 jalr -694(ra) # 277a0 <*ABS*+0x7ab82@plt>
000000000007ab82 <__libc_memcpy_ifunc>:
    7ab82: 00008067 ret
""")
    structure = analyze_structure(program)
    target = structure.plt_candidates[0x47a5a]
    assert (target.address, target.symbol) == (0x277a0, "*ABS*+0x7ab82@plt")
    context = ControlFlowContext(structure, EmissionOptions())
    caller = next(function for function in program.functions if function.name == "caller")
    with pytest.raises(ValueError, match="cannot resolve PLT target"):
        ControlFlowEmitter(lookup_profile=1).emit_program_scalar(
            caller.instructions[1], caller.instructions[1].operands, "original_base",
            context=context, active_long_jump_veneers={},
        )


def test_unknown_irelative_pair_keeps_synthetic_symbol():
    program = AsmParser().parse_string_program("""
Disassembly of section .plt:
0000000000003020 <*ABS*+0x5000@plt>:
    3020: 00000013 nop
Disassembly of section .text:
0000000000001000 <caller>:
    1000: 00002e17 auipc t3,0x2
    1004: 020e00e7 jalr ra,32(t3)
0000000000005000 <unknown_resolver>:
    5000: 00008067 ret
""")
    target = analyze_structure(program).plt_candidates[0x1004]
    assert target.symbol == "*ABS*+0x5000@plt"


def test_pair_without_contiguous_auipc_has_no_candidate():
    program = _pair_program(jalr="ra, 32(t3)")
    program.functions[0].instructions[0].address = 0xffc
    assert not analyze_structure(program).plt_candidates


def test_pair_has_runtime_address_guard():
    output = "\n".join(_emit_pair(1))
    assert "andi    a1, a1, -2" in output
    assert "bne     a1, t0, .Lchimera_indirect_query_1004" in output
    assert output.index("bne     a1") < output.index("%got_pcrel_hi(invoke)")


@pytest.mark.parametrize("profile", [1, 2])
@pytest.mark.parametrize("opcode, operands, rd", [
    ("call", "invoke@plt", "ra"),
    ("jal", "invoke@plt", "ra"),
    ("jal", "ra, invoke@plt", "ra"),
    ("jal", "x1, invoke@plt", "ra"),
    ("tail", "invoke@plt", "x0"),
    ("j", "invoke@plt", "x0"),
    ("jal", "x0, invoke@plt", "x0"),
])
def test_plt_calls_select_variant(opcode, operands, rd, profile):
    output = "\n".join(_emit(opcode, operands, profile))
    assert "%got_pcrel_hi(invoke)" in output
    assert f"li      a0, {profile}" in output
    assert output.count("call    query_original_translated_map@plt") == 1
    assert "bnez    a0, 1f" in output
    _assert_only_expected_traps(output, profile)
    assert output.index("bnez    a0, 1f") < output.index(f"jalr    {rd}, 0(t1)")
    assert output.endswith(f"jalr    {rd}, 0(t1)")
    assert "call    invoke@plt" not in output


@pytest.mark.parametrize("profile", [1, 2])
@pytest.mark.parametrize("section", [".plt", ".plt.sec", ".plt.got"])
@pytest.mark.parametrize("plt_first", [False, True])
@pytest.mark.parametrize("address,upper,offset,stub,symbol", [
    (0x50faea, 0x10b, -1162, 0x61a660, "__kmpc_fork_call"),
    (0x51083a, 0x10a, -538, 0x61a620, "__kmpc_barrier"),
])
def test_historical_openmp_pair_through_program_pipeline(
    profile, section, plt_first, address, upper, offset, stub, symbol,
):
    from rvv_sbt_rvv import translate_program as forward
    from rvv_sbt_rvv1024 import translate_program as reverse

    text = f"""
Disassembly of section .text:
{address:016x} <caller>:
  {address:x}: {(upper << 12) | 0x97:08x} auipc ra,0x{upper:x}
  {address + 4:x}: {((offset & 0xfff) << 20) | 0x80e7:08x} jalr {offset}(ra) # {stub:x} <{symbol}@plt>
"""
    plt = f"""
Disassembly of section {section}:
{stub - 32:016x} <{section}>:
  {stub - 32:x}: 00000013 nop
{stub:016x} <{symbol}@plt>:
  {stub:x}: 00016e17 auipc t3,0x16
  {stub + 4:x}: 900e3e03 ld t3,-1792(t3)
  {stub + 8:x}: 000e0367 jalr t1,t3
"""
    data = """
Disassembly of section .rodata:
0000000000700000 <not_code>:
  700000: 00000013 nop
"""
    program = AsmParser().parse_string_program(
        (plt + data + text) if plt_first else (text + data + plt)
    )
    assert {function.name for function in program.functions} == {"caller", f"{symbol}@plt"}
    candidate = analyze_structure(program).plt_candidates[address + 4]
    assert (candidate.address, candidate.symbol) == (stub, f"{symbol}@plt")
    output = (forward if profile == 1 else reverse)(program)
    assert f"%got_pcrel_hi({symbol})" in output
    assert f"bne     a1, t0, .Lchimera_indirect_query_{address + 4:x}" in output
    assert f"li      a0, {profile}" in output
    assert f"branch_j_target_{stub:x}:" not in output
    assert f"branch_j_target_{stub - 32:x}:" not in output
    assert f"branch_j_target_{address + 4:x}:" in output
    assert "not_code_translated" not in output


def test_section_switch_does_not_append_instructions_to_previous_function():
    program = AsmParser().parse_string_program("""
Disassembly of section .text:
0000000000001000 <caller>:
    1000: 00000013 nop
Disassembly of section .plt:
    2000: 00000013 nop
0000000000002020 <invoke@plt>:
    2020: 00000013 nop
Disassembly of section .text.hot:
    3000: 00000013 nop
0000000000003020 <other>:
    3020: 00000013 nop
""")
    assert [[i.address for i in f.instructions] for f in program.functions] == [
        [0x1000], [0x2020], [0x3020],
    ]


def test_fragment_parser_still_ignores_plt_sections():
    instructions = AsmParser().parse_string("""
Disassembly of section .text:
0000000000001000 <caller>:
    1000: 00000013 nop
Disassembly of section .plt:
0000000000002020 <invoke@plt>:
    2020: 00000013 nop
""")
    assert [i.address for i in instructions] == [0x1000]


def _tool(name):
    path = shutil.which(name)
    if path is None:
        pytest.skip(f"{name} is required for target validation")
    return path


def _assemble(tmp_path, source):
    asm = tmp_path / "probe.S"
    obj = tmp_path / "probe.o"
    asm.write_text(source)
    subprocess.run([
        _tool("riscv64-elf-as"), "-march=rv64gc", "-mabi=lp64d",
        "-o", str(obj), str(asm),
    ], check=True, capture_output=True, text=True)
    return obj


def test_plt_got_uses_function_address_relocation(tmp_path):
    obj = _assemble(tmp_path, ".text\n.globl entry\nentry:\n" +
                    "\n".join(_emit("call", "invoke@plt")) + "\nret\n")
    result = subprocess.run([
        _tool("riscv64-elf-readelf"), "-rW", str(obj),
    ], check=True, capture_output=True, text=True).stdout
    assert "R_RISCV_GOT_HI20" in result
    assert "R_RISCV_PCREL_LO12_I" in result
    assert "R_RISCV_CALL_PLT" in result
    assert "invoke" in result
    assert "query_original_translated_map" in result


@pytest.mark.parametrize("form", [
    "direct", "pair", "pair_other", "pair_x5",
    "ifunc_direct", "ifunc_pair", "ifunc_other", "ifunc_x5",
])
@pytest.mark.parametrize("tail", [False, True])
@pytest.mark.parametrize("profile", [1, 2])
@pytest.mark.parametrize("missing", ["none", "helper", "callback"])
def test_plt_callback_execution(tmp_path, tail, profile, missing, form):
    """Execute emitted routing with a query stub that destroys volatile state.

    This is a bare-metal ABI/control-flow check, not a Linux loader or libomp
    integration test. The stub models the current Runtime's identity-on-miss.
    """
    qemu = _tool("qemu-system-riscv64")
    fragment = "\n".join(_emit("tail" if tail else "call", "invoke@plt", profile))
    if form == "ifunc_direct":
        program = _pair_program(ifunc=True)
        insn = AsmParser().parse_string(f"{'tail' if tail else 'call'} *ABS*+0x5000@plt")[0]
        insn.address = 0x1000
        program.functions[0].instructions = [insn]
        context = ControlFlowContext(analyze_structure(program), EmissionOptions())
        fragment = "\n".join(ControlFlowEmitter(lookup_profile=profile).emit_program_scalar(
            insn, insn.operands, "original_base", context=context,
            active_long_jump_veneers={},
        ))
    elif form != "direct":
        fragment = "\n".join(_emit_pair(
            profile, bypass=form.endswith("_other"), tail=tail,
            base="x5" if form.endswith("_x5") else "t3", ifunc=form.startswith("ifunc"),
        ))
    return_fragment = "\n".join(_emit("ret", "", profile, address=0x4000))
    callback = "\n".join(_emit("jalr", "t0", profile, address=0x2000))
    poison = "\n".join(
        f"li {reg}, -1" for reg in CALL_CLOBBERED_GPRS
        if reg not in {"ra", "a0"}
    ) + "\n" + "\n".join(
        f"fmv.d.x {reg}, zero" for reg in CALL_CLOBBERED_FPRS
    )
    checks = "\n".join(
        f"li t0, {i * 11}\nbne a{i}, t0, fail" for i in range(1, 8)
    )
    fp_setup = "\n".join(
        f"li t0, {i + 1}\nfmv.d.x {reg}, t0"
        for i, reg in enumerate(CALL_CLOBBERED_FPRS)
    )
    fp_checks = "\n".join(
        f"fmv.x.d t0, {reg}\nli t1, {i + 1}\nbne t0, t1, fail"
        for i, reg in enumerate(CALL_CLOBBERED_FPRS)
    )
    expected_helper = 3 if form.endswith("_other") else (1 if missing == "helper" else 2)
    expected_callback = 1 if missing == "callback" or expected_helper == 1 else 2
    rejects_tail = tail and form in {"pair", "pair_x5", "ifunc_pair", "ifunc_x5"}
    save_gprs = "\n".join(f"sd x{reg}, {reg * 8}(sp)" for reg in range(1, 32) if reg != 2)
    restore_gprs = "\n".join(f"ld x{reg}, {reg * 8}(sp)" for reg in range(1, 32) if reg != 2)
    if rejects_tail:
        # Snapshot the source state after AUIPC, immediately before JALR.
        capture = f"""
    addi sp, sp, -256
    {save_gprs}
    addi t0, sp, 256
    sd t0, 16(sp)
    mv t0, sp
    la t1, expected_state
    li t2, 32
capture_state:
    ld t3, 0(t0)
    sd t3, 0(t1)
    addi t0, t0, 8
    addi t1, t1, 8
    addi t2, t2, -1
    bnez t2, capture_state
    {restore_gprs}
    addi sp, sp, 256
"""
        marker = "    # jalr target remap:"
        assert fragment.count(marker) == 1
        fragment = fragment.replace(marker, capture + marker)
    assert "chimera_jump_mapped_v1" not in fragment + return_fragment
    source = f"""
.option norelax
.option norvc
.text
.globl _start
_start:
    la sp, stack_end
    la t0, rejected_tail
    csrw mtvec, t0
    la t0, actual_state
    csrw mscratch, t0
    li t0, 0x6000
    csrs mstatus, t0
    addi sp, sp, -32
    li t0, 99
    sd t0, 0(sp)
    mv s3, sp
    li s4, 0
    li s5, 0
    la a0, work
    li a1, 11
    li a2, 22
    li a3, 33
    li a4, 44
    li a5, 55
    li a6, 66
    li a7, 77
    {fp_setup}
    li t0, 1
    fscsr t0
    call wrapper
    {"j fail" if rejects_tail else "nop"}
    bne sp, s3, fail
    li t0, 123
    bne a0, t0, fail
    li t0, {expected_helper}
    bne s4, t0, fail
    li t0, {expected_callback}
    bne s5, t0, fail
    fmv.x.d t0, fa0
    li t1, 41
    bne t0, t1, fail
    frcsr t0
    li t1, 1
    bne t0, t1, fail
passed:
    li t0, 0x100000
    li t1, 0x5555
    sw t1, 0(t0)
1:  j 1b
.balign 4
fail:
    li t0, 0x100000
    li t1, 0x13333
    sw t1, 0(t0)
2:  j 2b
wrapper:
    mv s2, ra
    {fragment}
wrapper_end:
    {"j fail" if tail else "jr s2"}
.balign 4
rejected_tail:
    csrrw sp, mscratch, sp
    {save_gprs}
    csrr t0, mscratch
    sd t0, 16(sp)
    {"nop" if rejects_tail else "j fail"}
    csrr t0, mcause
    li t1, 3
    bne t0, t1, fail
    csrr t0, mepc
    la t1, wrapper_end - 4
    bne t0, t1, fail
    la t0, actual_state + 8
    la t1, expected_state + 8
    li t2, 31
check_rejected_state:
    ld t3, 0(t0)
    ld t4, 0(t1)
    bne t3, t4, fail
    addi t0, t0, 8
    addi t1, t1, 8
    addi t2, t2, -1
    bnez t2, check_rejected_state
    {fp_checks}
    frcsr t0
    li t1, 1
    bne t0, t1, fail
    j passed
.balign 8
fake_plt:
    j fail
    {".org fake_plt + 0xfe0" if form.startswith("ifunc") else ""}
    {".quad invoke" if form.startswith("ifunc") else ""}
.balign 4
alternate:
    li s4, 3
    j check_args
invoke:
    li s4, 1
    j check_args
invoke_translated:
    li s4, 2
check_args:
    bne sp, s3, fail
    ld t0, 0(sp)
    li t1, 99
    bne t0, t1, fail
    la t0, work
    bne a0, t0, fail
    {checks}
    {fp_checks}
    frcsr t0
    li t1, 1
    bne t0, t1, fail
    addi sp, sp, -16
    sd ra, 8(sp)
    mv t0, a0
    li t1, 1
    beq s4, t1, native_callback
    {callback}
    j done
native_callback:
    jalr t0
done:
    ld ra, 8(sp)
    addi sp, sp, 16
    ret
work:
    li s5, 1
    j check_callback
work_translated:
    li s5, 2
check_callback:
    {checks}
    {fp_checks}
    frcsr t0
    li t1, 1
    bne t0, t1, fail
    li a0, 123
    li t0, 41
    fmv.d.x fa0, t0
    {return_fragment}
query_original_translated_map:
    li t0, {profile}
    bne a0, t0, fail
    mv a0, a1
    la t0, invoke
    bne a1, t0, query_work
    {"la a0, invoke_translated" if missing != "helper" else "nop"}
    j query_done
query_work:
    la t0, work
    bne a1, t0, query_done
    {"la a0, work_translated" if missing != "callback" else "nop"}
query_done:
    {poison}
    fscsr zero
    ret
.data
.balign 8
original_base:
    .quad fake_plt - 0x3020
.bss
.balign 16
expected_state:
    .skip 256
actual_state:
    .skip 256
stack:
    .skip 8192
stack_end:
"""
    obj = _assemble(tmp_path, source)
    elf = tmp_path / "probe.elf"
    subprocess.run([
        _tool("riscv64-elf-ld"), "-Ttext=0x80000000", "-e", "_start",
        "-o", str(elf), str(obj),
    ], check=True, capture_output=True, text=True)
    result = subprocess.run([
        qemu, "-machine", "virt", "-m", "128M", "-smp", "1",
        "-bios", "none", "-kernel", str(elf), "-nographic",
        "-monitor", "none", "-serial", "none",
    ], capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr


def test_linux_shared_library_callback(tmp_path):
    """Run on a Linux/RV64 host to exercise the real DSO loader and GOT.

    A small external callback library makes helper and callback mapping misses
    distinguishable by result, without requiring a particular libomp build.
    """
    import platform
    import sys

    if sys.platform != "linux" or platform.machine() != "riscv64":
        pytest.skip("requires a Linux/RV64 host for dynamic loader validation")
    cc = _tool("cc")
    helper = tmp_path / "helper.c"
    helper.write_text("int invoke(int (*work)(int), int n) { return work(n) + 1; }\n")
    subprocess.run([
        cc, "-shared", "-fPIC", "-march=rv64gc", "-mabi=lp64d",
        str(helper), "-o", str(tmp_path / "libhelper.so"),
    ], check=True, capture_output=True, text=True)
    direct = "\n".join(_emit("call", "invoke@plt", address=0x5000))
    pair = "\n".join(_emit_pair(1))
    callback = "\n".join(_emit("jalr", "t0", address=0x2000))
    translated = tmp_path / "translated.S"
    translated.write_text(f"""
.text
.globl direct_wrapper
.type direct_wrapper, @function
direct_wrapper:
    addi sp, sp, -16
    sd ra, 8(sp)
    {direct}
    ld ra, 8(sp)
    addi sp, sp, 16
    ret
.globl pair_wrapper
.type pair_wrapper, @function
pair_wrapper:
    addi sp, sp, -16
    sd ra, 8(sp)
    {pair}
    ld ra, 8(sp)
    addi sp, sp, 16
    ret
.globl invoke_translated
.type invoke_translated, @function
invoke_translated:
    addi sp, sp, -16
    sd ra, 8(sp)
    mv t0, a0
    mv a0, a1
    {callback}
    addiw a0, a0, 2
    ld ra, 8(sp)
    addi sp, sp, 16
    ret
fake_plt:
    ebreak
.data
.balign 8
original_base:
    .quad fake_plt - 0x3020
.section .note.GNU-stack,"",@progbits
""")
    driver = tmp_path / "main.c"
    driver.write_text("""
#include <assert.h>
#include <stdint.h>
typedef int (*callback)(int);
extern int invoke(callback, int);
extern int invoke_translated(callback, int);
extern int direct_wrapper(callback, int);
extern int pair_wrapper(callback, int);
static int mode;
static int work(int n) { return n + 100; }
static int translated_work(int n) { return n + 200; }
uintptr_t query_original_translated_map(int profile, uintptr_t address) {
    assert(profile == 1);
    if (address == (uintptr_t)invoke && mode != 1)
        return (uintptr_t)invoke_translated;
    if (address == (uintptr_t)work && mode != 2)
        return (uintptr_t)translated_work;
    return address;
}
int main(void) {
    const int expected[] = {209, 108, 109};
    for (mode = 0; mode < 3; ++mode) {
        assert(direct_wrapper(work, 7) == expected[mode]);
        assert(pair_wrapper(work, 7) == expected[mode]);
    }
    return 0;
}
""")
    binary = tmp_path / "probe"
    subprocess.run([
        cc, "-march=rv64gc", "-mabi=lp64d", "-fPIE", "-pie",
        str(driver), str(translated), "-L", str(tmp_path), "-lhelper",
        "-Wl,-rpath,$ORIGIN", "-o", str(binary),
    ], check=True, capture_output=True, text=True)
    subprocess.run([str(binary)], check=True, capture_output=True, text=True, timeout=10)
