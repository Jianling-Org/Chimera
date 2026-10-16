"""Execute guest SP outputs while checking the wrapper's saved machine state."""

import shutil
import subprocess

import pytest

from riscv.extensions.rvv.analysis.config import StateTracker
from riscv.extensions.rvv.backends.scalar.backend import ScalarDispatcher, make_scalar_profile
from riscv.extensions.rvv.runtime.layout import SimulatedStateLayout
from riscv.extensions.rvv.translation.emitter import ProgramEmitter
from riscv.extensions.rvv.translation.pipeline import TranslationPipeline
from riscv.frontend.model import RVFunction, RVProgram
from riscv.frontend.parser import AsmParser
from riscv.registers import CALL_CLOBBERED_FPRS, CALL_CLOBBERED_GPRS
from rvv_sbt_rvv import translate as forward
from riscv.extensions.rvv.runtime.contract import RVV1024_TO_RVV256


CASES = (
    ("vsetivli sp, 4, e32, m1, tu, mu", 4),
    ("vsetivli x2, 0, e32, m1, tu, mu", 0),
    ("vsetvli sp, sp, e32, m1, tu, mu", 32),
    ("vsetvli x2, x2, e32, m1, tu, mu", 32),
    ("vsetvli sp, t6, e32, m1, tu, mu", 6),
    ("vsetvli x2, x31, e32, m1, tu, mu", 6),
    ("vmv.x.s sp, v8", 0xFFFFFFFF80000007),
    ("vmv.x.s x2, v8", 0xFFFFFFFF80000007),
    ("csrr sp, vl", 3),
    ("csrr x2, vlenb", 128),
    ("csrrw sp, vxrm, t6", 3),
)


def _tool(name):
    path = shutil.which(name)
    if path is None:
        pytest.skip(f"requires {name}")
    return path


def _translated(command, backend, helper):
    instructions = AsmParser().parse_string(command)
    if backend == "forward":
        return forward(
            instructions, raw=True, tls_state=helper,
            state_base_mode="helper" if helper else "initial-exec",
            init_vtype="sew=32,lmul=1,tu,mu",
        ), RVV1024_TO_RVV256.non_tls_state_symbol
    pipeline = TranslationPipeline(ProgramEmitter(
        state_base_mode="helper" if helper else "initial-exec",
    ))
    prepared = pipeline.prepare(
        RVProgram(functions=[RVFunction("probe", 0, instructions)]),
        backend_profile=make_scalar_profile(), init_vtype="sew=32,lmul=1,tu,mu",
    )
    return pipeline.emit_function(
        prepared, state_factory=lambda: StateTracker(128),
        allocator_factory=SimulatedStateLayout, dispatcher_factory=ScalarDispatcher,
        raw=True, tls_state=helper,
    ), "simulated_cpu_state"


@pytest.mark.parametrize("command,sp_result,backend,helper", [
    pytest.param(command, sp_result, backend, helper,
                 id=f"{backend}-{'helper' if helper else 'direct'}-{command}")
    for command, sp_result in CASES
    for backend, helper in (
        ("native", False), ("scalar", False), ("scalar", True),
        ("forward", False), ("forward", True),
    )
    if backend != "scalar" or not command.startswith("vmv.x.s")
])
def test_sp_result_commits_after_complete_wrapper_restore(
    tmp_path, command, sp_result, backend, helper,
):
    body, state_symbol = (command, "simulated_cpu_state") if backend == "native" else _translated(command, backend, helper)
    initialize_gprs = "\n".join(
        f"    li x{number}, {6 if number == 31 else 0x100 + number}"
        for number in range(3, 32)
    )
    initialize_fprs = "\n".join(f"    fmv.d.x f{number}, t0" for number in range(32))
    save_gprs = "\n".join(
        f"    sd x{number}, {number * 8}(sp)" for number in range(1, 32) if number != 2
    )
    save_fprs = "\n".join(f"    fsd f{number}, {256 + number * 8}(sp)" for number in range(32))
    poison_gprs = "\n".join(
        f"    li {register}, -1" for register in CALL_CLOBBERED_GPRS
        if register not in {"ra", "a0"}
    )
    poison_fprs = "\n".join(f"    fmv.d.x {register}, zero" for register in CALL_CLOBBERED_FPRS)
    expected = ["after_wrapper", str(sp_result)] + [
        str(6 if number == 31 else 0x100 + number) for number in range(3, 32)
    ]
    expected += ["0x1234"] * 32 + ["0x61"]
    expected_words = "\n".join(f"    .quad {value}" for value in expected)
    assembly = tmp_path / "probe.S"
    assembly.write_text(f"""
.option norelax
.option norvc
.text
.globl _start
_start:
    la sp, guest_sp
    la t0, fail
    csrw mtvec, t0
    la t0, snapshot
    csrw mscratch, t0
    li t0, 0x6600
    csrs mstatus, t0
    vsetivli zero, 3, e32, m1, tu, mu
    li t0, 0x80000007
    vmv.s.x v8, t0
    csrwi vxrm, 3
    li t0, 0x61
    fscsr t0
    li t0, 0x1234
{initialize_fprs}
{initialize_gprs}
    call wrapper
after_wrapper:
    la t0, guest_sp
    bne sp, t0, fail
    ld t1, 0(sp)
    li t2, 0x123456789abcdef
    bne t1, t2, fail
    ld t1, 8(sp)
    li t2, 0x76543210fedcba98
    bne t1, t2, fail
    ld t1, -1024(sp)
    li t2, 0x1111222233334444
    bne t1, t2, fail
    la t0, snapshot + 8
    la t1, expected
    li t2, {len(expected)}
check_snapshot:
    ld t3, 0(t0)
    ld t4, 0(t1)
    bne t3, t4, fail
    addi t0, t0, 8
    addi t1, t1, 8
    addi t2, t2, -1
    bnez t2, check_snapshot
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
{body}
    csrrw sp, mscratch, sp
{save_gprs}
{save_fprs}
    csrr t0, mscratch
    sd t0, 16(sp)
    frcsr t0
    sd t0, 512(sp)
    ld t0, 40(sp)
    la sp, guest_sp
    ret
get_simulated_cpu_state_addr:
{poison_gprs}
{poison_fprs}
    la a0, {state_symbol}
    ret
.data
.balign 128
{state_symbol}:
    .zero 1024
    .word 0x80000007
    .zero {0x1000 - 1024 - 4}
    .quad 0, 0, 3, 6, 3, 16, 128, 0
.balign 8
expected:
{expected_words}
.balign 16
    .zero 7168
    .quad 0x1111222233334444
    .zero 1016
guest_sp:
    .quad 0x123456789abcdef, 0x76543210fedcba98
.bss
.balign 16
snapshot:
    .skip 520
""")
    obj, elf = tmp_path / "probe.o", tmp_path / "probe.elf"
    subprocess.run([
        _tool("riscv64-elf-as"), "-march=rv64gcv", "-mabi=lp64d",
        "-o", str(obj), str(assembly),
    ], check=True, capture_output=True, text=True)
    subprocess.run([
        _tool("riscv64-elf-ld"), "-Ttext=0x80000000", "-e", "_start",
        "-o", str(elf), str(obj),
    ], check=True, capture_output=True, text=True)
    vlen = 1024 if backend == "native" else 256
    result = subprocess.run([
        _tool("qemu-system-riscv64"), "-machine", "virt", "-cpu",
        f"rv64,v=true,vlen={vlen},elen=64", "-m", "128M", "-bios", "none",
        "-kernel", str(elf), "-nographic", "-monitor", "none", "-serial", "none",
    ], capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr
