"""Execute failed Runtime lookups at every emitted control-flow boundary."""
import shutil
import subprocess

import pytest

from riscv.codegen.control_flow import ControlFlowContext, ControlFlowEmitter, EmissionOptions
from riscv.frontend.analysis import analyze_structure
from riscv.frontend.parser import AsmParser
from riscv.registers import CALL_CLOBBERED_FPRS, CALL_CLOBBERED_GPRS


def _tool(name):
    path = shutil.which(name)
    if path is None:
        pytest.skip(f"{name} is required for target validation")
    return path


def _fragment(form, profile):
    parser = AsmParser()
    context = None
    setup = ""
    if form.startswith(("plt_", "ifunc_")):
        symbol = "*ABS*+0x5000@plt" if form.startswith("ifunc_") else "invoke@plt"
        tail = form.endswith("tail")
        program = parser.parse_string_program(f"""
Disassembly of section .text:
0000000000001000 <caller>:
    1000: 00002e17 auipc t3,0x2
    1004: 020e00e7 jalr {"x0" if tail else "ra"},32(t3)
Disassembly of section .plt:
0000000000003020 <{symbol}>:
    3020: 00001e17 auipc t3,0x1
    3024: fe0e3e03 ld t3,-32(t3)
    3028: 000e0367 jalr t1,t3
""")
        if "pair" not in form:
            insn = parser.parse_string(f"{'tail' if tail else 'call'} {symbol}")[0]
            insn.address = 0x1000
            program.functions[0].instructions = [insn]
        instructions = program.functions[0].instructions
        context = ControlFlowContext(analyze_structure(program), EmissionOptions())
    else:
        setup, instruction = {
            "ret": ("la ra, invoke", "ret"),
            "jr": ("la t0, invoke\naddi t0, t0, 1", "jr t0"),
            "jr_sp": ("mv s2, sp", "jr sp"),
            "jalr": ("la t0, invoke\naddi t0, t0, -7", "jalr ra, 8(t0)"),
            "jalr_tail": ("la a1, invoke\naddi a1, a1, 1", "jalr x0, a1"),
            "jalr_custom_link": ("la t0, invoke", "jalr t2, t0"),
            "jalr_saved_register": ("la s1, invoke", "jalr s1"),
        }[form]
        instructions = parser.parse_string(instruction)
        instructions[0].address = 0x1000
    emitter = ControlFlowEmitter(lookup_profile=profile)
    lines = [setup]
    for insn in instructions:
        lines.extend(emitter.emit_program_scalar(
            insn, insn.operands, "original_base", context=context,
            active_long_jump_veneers={},
        ))
    return "\n".join(lines)


@pytest.mark.parametrize("profile", [1, 2])
@pytest.mark.parametrize("form", [
    "ret", "jr", "jr_sp", "jalr", "jalr_tail", "jalr_custom_link",
    "jalr_saved_register", "plt_call", "plt_tail", "plt_pair_call",
    "plt_pair_tail", "ifunc_call", "ifunc_tail", "ifunc_pair_call",
    "ifunc_pair_tail",
])
def test_zero_query_traps_with_profile_and_original_target(tmp_path, profile, form):
    """A zero lookup must trap locally, preserving diagnostics across clobbers.

    The machine trap checks the emitted EBREAK and its register context. Linux
    SIGTRAP handling is covered separately by the Runtime's unmapped-trap test.
    """
    qemu = _tool("qemu-system-riscv64")
    fragment = _fragment(form, profile)
    poison = "\n".join(
        f"li {reg}, -1" for reg in CALL_CLOBBERED_GPRS
        if reg not in {"ra", "a0"}
    ) + "\n" + "\n".join(
        f"fmv.d.x {reg}, zero" for reg in CALL_CLOBBERED_FPRS
    )
    asm = tmp_path / "query_failure.S"
    obj = tmp_path / "query_failure.o"
    elf = tmp_path / "query_failure.elf"
    asm.write_text(f"""
.option norelax
.option norvc
.text
.globl _start
_start:
    la sp, stack_end
    la t0, trap
    csrw mtvec, t0
    li t0, 0x6000
    csrs mstatus, t0
    la s2, invoke
    li s4, 0
    call wrapper
    j fail
.balign 4
wrapper:
    {fragment}
wrapper_end:
    j fail
.balign 4
trap:
    csrr t0, mcause
    li t1, 3
    bne t0, t1, fail
    csrr t0, mepc
    la t1, wrapper
    bltu t0, t1, fail
    la t1, wrapper_end
    bgeu t0, t1, fail
    lw t1, 0(t0)
    li t2, 0x00100073
    bne t1, t2, fail
    li t0, {profile}
    bne a0, t0, fail
    bne a1, s2, fail
    li t0, 1
    bne s4, t0, fail
    li t0, 0x100000
    li t1, 0x5555
    sw t1, 0(t0)
1:  j 1b
fail:
    li t0, 0x100000
    li t1, 0x13333
    sw t1, 0(t0)
2:  j 2b
invoke:
    j fail
query_original_translated_map:
    li t0, {profile}
    bne a0, t0, fail
    bne a1, s2, fail
    addi s4, s4, 1
    {poison}
    fscsr zero
    li a0, 0
    ret
.balign 8
fake_plt:
    j fail
    .org fake_plt + 0xfe0
    .quad invoke
.data
.balign 8
original_base:
    .quad fake_plt - 0x3020
.bss
.balign 16
stack:
    .skip 8192
stack_end:
""")
    subprocess.run([
        _tool("riscv64-elf-as"), "-march=rv64gc", "-mabi=lp64d",
        "-o", str(obj), str(asm),
    ], check=True, capture_output=True, text=True)
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
