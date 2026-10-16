"""Execute translated cross-function jumps after final RV64 linking."""

import re
import shutil
import subprocess

import pytest

from riscv.frontend.parser import AsmParser
import rvv_sbt_rvv
import rvv_sbt_rvv1024


TRANSLATORS = (rvv_sbt_rvv, rvv_sbt_rvv1024)


def _tool(name):
    executable = shutil.which(name)
    if executable is None:
        pytest.skip(f"requires {name}")
    return executable


def _run(*arguments):
    return subprocess.run(
        arguments, check=True, capture_output=True, text=True, timeout=30,
    ).stdout


def _translated_program(translator, jump, target, layout):
    caller, callee = (0x2000, 0x1000) if layout == "far-backward" else (0x1000, 0x2000)
    destination = callee + (4 if target == "interior" else 0)
    functions = {
        caller: f"""
{caller:016x} <caller>:
    {caller:x}: 0000006f {jump} {destination:x} <callee{'+0x4' if target == 'interior' else ''}>
""",
        callee: f"""
{callee:016x} <callee>:
    {callee:x}: 00a00513 li a0,10
    {callee + 4:x}: 00100073 ebreak
""",
    }
    source = "\n".join(functions[address] for address in sorted(functions))
    output = translator.translate_program(
        AsmParser().parse_string_program(source), lib_name="cross_function_jump",
    )
    if layout.startswith("far-"):
        first = "callee" if callee < caller else "caller"
        # Model expansion by other translated functions without changing either
        # jump endpoint or separating a target's veneer from its instructions.
        output, count = re.subn(
            rf"(?m)^(\s*\.size\s+{first}_translated,\s*\.-{first}_translated)$",
            r"\1\n    .space 0x110000",
            output,
        )
        assert count == 1
    return output, callee + 4


def _execute_jump(tmp_path, translator, jump, target, layout, ordinary_entry=False):
    qemu = _tool("qemu-system-riscv64")
    output, trap_address = _translated_program(translator, jump, target, layout)
    entry = "callee_translated" if ordinary_entry else "caller_translated"
    initial_registers = "\n".join(
        f"    li x{number}, {0x100 + number}"
        for number in range(1, 32) if number != 2
    )
    saved_registers = "\n".join(
        f"    sd x{number}, {number * 8}(sp)"
        for number in range(1, 32) if number != 2
    )
    expected = {number: str(0x100 + number) for number in range(1, 32)}
    expected[2] = "stack_end"
    if target == "entry" or ordinary_entry:
        expected[10] = "10"
    expected_registers = "\n".join(
        f"    .quad {expected[number]}" for number in range(1, 32)
    )
    assembly = tmp_path / "cross_function_jump.S"
    obj = tmp_path / "cross_function_jump.o"
    elf = tmp_path / "cross_function_jump.elf"
    # The harness deliberately poisons gp, so its own address loads must not
    # relax to gp-relative accesses. Restore relaxation for the generated code.
    assembly.write_text(f"""
.option norvc
.option push
.option norelax
.text
.globl _start
_start:
    la t0, trap
    csrw mtvec, t0
    la t0, saved_registers
    csrw mscratch, t0
    la t0, {entry}
    csrw mepc, t0
    li t0, 0x1800
    csrs mstatus, t0
    la sp, stack_end
{initial_registers}
    mret
.balign 4
trap:
    csrrw sp, mscratch, sp
{saved_registers}
    csrr t0, mscratch
    sd t0, 16(sp)
    li t5, 32
    csrr t0, mcause
    li t1, 3
    bne t0, t1, fail
    li t5, 33
    csrr t0, mepc
    la t1, branch_j_target_{trap_address:x}
    bne t0, t1, fail
    la t0, saved_registers + 8
    la t1, expected_registers
    li t2, 32
    li t5, 1
check_register:
    ld t3, 0(t0)
    ld t4, 0(t1)
    bne t3, t4, fail
    addi t0, t0, 8
    addi t1, t1, 8
    addi t5, t5, 1
    bne t5, t2, check_register
    li t0, 0x100000
    li t1, 0x5555
    sw t1, 0(t0)
1:  j 1b
fail:
    li t0, 0x100000
    slli t1, t5, 16
    li t2, 0x3333
    or t1, t1, t2
    sw t1, 0(t0)
2:  j 2b
.option pop
{output}
.data
.balign 8
expected_registers:
{expected_registers}
.bss
.balign 16
saved_registers:
    .skip 256
stack:
    .skip 4096
stack_end:
""")
    _run(
        _tool("riscv64-elf-as"), "-march=rv64gc", "-mabi=lp64d",
        "-o", str(obj), str(assembly),
    )
    linker_flags = ["--no-relax"] if layout == "near-no-relax" else []
    _run(
        _tool("riscv64-elf-ld"), "-Ttext=0x80000000", "-e", "_start",
        *linker_flags, "-o", str(elf), str(obj),
    )
    if layout.startswith("far-"):
        symbols = _run(_tool("riscv64-elf-readelf"), "-Ws", str(elf))
        addresses = {
            match.group(2): int(match.group(1), 16)
            for match in re.finditer(
                r"(?m)^\s*\d+:\s+([0-9a-f]+).*\b(caller|callee)_translated$", symbols,
            )
        }
        distance = addresses["callee"] - addresses["caller"]
        assert distance > 0x100000 if layout == "far-forward" else distance < -0x100000
    result = subprocess.run([
        qemu, "-machine", "virt", "-m", "128M", "-smp", "1",
        "-bios", "none", "-kernel", str(elf), "-nographic",
        "-monitor", "none", "-serial", "none",
    ], capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, (
        f"register x{result.returncode} changed (32/33 indicate wrong trap cause/PC): "
        f"{result.stderr}"
    )


@pytest.mark.parametrize("translator", TRANSLATORS, ids=lambda item: item.__name__)
@pytest.mark.parametrize("jump", ("j", "jal x0,", "jal zero,"))
@pytest.mark.parametrize("target", ("entry", "interior"))
@pytest.mark.parametrize("layout", ("far-forward", "far-backward", "near-no-relax"))
def test_cross_function_jump_preserves_registers(tmp_path, translator, jump, target, layout):
    """Expansion beyond JAL range and disabled relaxation must preserve every GPR."""
    _execute_jump(tmp_path, translator, jump, target, layout)


@pytest.mark.parametrize("translator", TRANSLATORS, ids=lambda item: item.__name__)
@pytest.mark.parametrize("target", ("entry", "interior"))
def test_ordinary_entry_and_fallthrough_skip_jump_restore(tmp_path, translator, target):
    """An entry or interior veneer must only restore a frame made by a long jump."""
    _execute_jump(
        tmp_path, translator, "j", target, "near-no-relax", ordinary_entry=True,
    )
