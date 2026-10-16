"""Execute zero-vstart contracts without mistaking rejection for restart support."""

from pathlib import Path
import subprocess

import pytest

from riscv.extensions.rvv.analysis.config import StateTracker
from riscv.extensions.rvv.backends.scalar.backend import ScalarDispatcher
from riscv.extensions.rvv.backends.rvv256.backend import RVV256Dispatcher
from riscv.extensions.rvv.runtime.contract import RVV1024_TO_RVV256
from riscv.extensions.rvv.runtime.layout import SimulatedStateLayout
from riscv.extensions.rvv.translation.contracts import LoweringStatus, VStartPolicy
from riscv.frontend.parser import AsmParser
from test_review_arithmetic_execution import _compare, _translated
from test_rvv256_vstart import _LINK, riscv_tools


_START = """
.section .text.init
.globl _start
_start:
    la sp, stack_top
    li t0, 0x6600
    csrs mstatus, t0
    la t0, trap
    csrw mtvec, t0
    call main
    li t0, 0x100000
    li t1, 0x3333
    sw t1, 0(t0)
1:  j 1b
.balign 4
trap:
    la sp, stack_top
    csrr a0, mcause
    call trapped
    j trap
.section .bss
.balign 16
    .space 16384
stack_top:
"""

_MAIN = r'''
#include <stdint.h>
uint8_t fixture[0x1040 + 128] __attribute__((aligned(128)));
uint8_t before[sizeof(fixture)];
uint8_t guest[128], guest_before[128];
__asm__(".globl @SYMBOL@\n.set @SYMBOL@, fixture + 64\n");
extern void probe(void);
void trapped(uint64_t cause) {
    unsigned pass = cause == 3;
    for(unsigned i=0;i<sizeof(fixture);i++) pass &= fixture[i] == before[i];
    for(unsigned i=0;i<sizeof(guest);i++) pass &= guest[i] == guest_before[i];
    *(volatile char *)0x10000000 = pass ? 'P' : 'F';
    *(volatile unsigned *)0x100000 = pass ? 0x5555 : 0x3333;
    for(;;) {}
}
int main(void) {
    for(unsigned i=0;i<sizeof(fixture);i++) fixture[i] = (i * 37 + 13) & 255;
    for(unsigned i=0;i<sizeof(guest);i++) guest_before[i] = guest[i] = i ^ 0xa5;
    uint8_t *state = fixture + 64;
    *(uint64_t *)(state + 0x1000) = @INITIAL_START@;
    *(uint64_t *)(state + 0x1020) = @VL@;
    *(uint64_t *)(state + 0x1028) = 18;
    *(uint64_t *)(state + 0x1030) = 128;
    for(unsigned i=0;i<sizeof(fixture);i++) before[i] = fixture[i];
    *(uint64_t *)(before + 64 + 0x1000) = @START@;
    probe();
    *(volatile char *)0x10000000 = 'N';
    return 1;
}
'''


def _reject(tmp_path: Path, riscv_tools, backend, command, start, vl, through_csr=False):
    compiler, qemu = riscv_tools
    symbol = ("simulated_cpu_state" if backend == "scalar" else
              RVV1024_TO_RVV256.non_tls_state_symbol)
    source = f"csrwi vstart,{start}\n{command}" if through_csr else command
    candidate = _translated(source, 32, 4, backend)
    assert "fallback" not in candidate
    assert "unsupported nonzero source vstart" in candidate
    main = _MAIN
    for key, value in {"SYMBOL": symbol, "INITIAL_START": 0 if through_csr else start,
                       "START": start, "VL": vl}.items():
        main = main.replace(f"@{key}@", str(value))
    (tmp_path / "main.c").write_text(main)
    (tmp_path / "start.S").write_text(_START)
    (tmp_path / "link.ld").write_text(_LINK)
    address = "li a0,0x4000000000" if command.startswith("vle") else "la a0,guest"
    (tmp_path / "probe.S").write_text(
        f".text\n.globl probe\nprobe:\n{address}\n{candidate}\nret\n"
    )
    build = subprocess.run([
        compiler, "-march=rv64gcv", "-mabi=lp64d", "-mcmodel=medany", "-msmall-data-limit=0",
        "-fno-tree-vectorize", "-fno-builtin", "-ffreestanding", "-nostdlib", "-O2",
        "-T", "link.ld", "start.S", "main.c", "probe.S", "-o", "probe.elf",
    ], cwd=tmp_path, capture_output=True, text=True, timeout=30)
    assert build.returncode == 0, build.stderr
    result = subprocess.run([
        qemu, "-M", "virt", "-cpu", "rv64,v=true,vlen=256,elen=64", "-m", "128M",
        "-nographic", "-bios", "none", "-kernel", str(tmp_path / "probe.elf"),
    ], capture_output=True, text=True, timeout=20)
    assert result.returncode == 0 and result.stdout == "P", (result.stdout, result.stderr)


@pytest.mark.parametrize("backend", ["scalar", "conservative", "wide"])
@pytest.mark.parametrize("start,vl", [(1, 0), (1, 8), (3, 8), (8, 8), (9, 8)])
def test_nonzero_vstart_rejects_without_mutating_state(tmp_path, riscv_tools, backend, start, vl):
    _reject(tmp_path, riscv_tools, backend, "vadd.vv v8,v16,v24", start, vl)


@pytest.mark.parametrize("backend", ["scalar", "conservative", "wide"])
@pytest.mark.parametrize("command", ["vadd.vv v8,v16,v24,v0.t", "vle32.v v8,(a0)",
                                      "vse32.v v8,(a0)", "vmv1r.v v8,v16"])
def test_guest_csr_writes_cannot_bypass_guard_before_side_effects(tmp_path, riscv_tools, backend, command):
    _reject(tmp_path, riscv_tools, backend, command, 3, 8, through_csr=True)


@pytest.mark.parametrize("backend", ["scalar", "conservative", "wide"])
@pytest.mark.parametrize("recovery", ["csrwi vstart,0", "csrci vstart,3", "csrw vstart,zero",
                                       "csrrw a2,vstart,zero", "vsetivli zero,8,e32,m4,tu,mu"])
def test_csr_and_config_can_restore_zero_vstart(tmp_path, riscv_tools, backend, recovery):
    _compare(tmp_path, riscv_tools,
             f"csrwi vstart,3\n{recovery}\nvadd.vv v8,v16,v24", backend=backend,
             lmul=4, lengths=[8])


@pytest.mark.parametrize("backend", ["scalar", "conservative", "wide"])
def test_zero_vstart_executes_normal_full_state_comparison(tmp_path, riscv_tools, backend):
    _compare(tmp_path, riscv_tools, "vadd.vv v8,v16,v24", backend=backend, lmul=4,
             lengths=[0, 1, 8, 9, 128])


@pytest.mark.parametrize("dispatcher", [ScalarDispatcher, RVV256Dispatcher])
def test_guard_clobber_and_state_effects_are_declared(dispatcher):
    backend = dispatcher()
    state = StateTracker(128)
    state.sew, state.lmul = 32, 4
    instruction = AsmParser().parse_string("vadd.vv v8,v16,v24")[0]
    context = backend.make_context(instruction, state, SimulatedStateLayout())
    plan = backend.plan(context)
    result = backend.lower(context, plan)
    assert result.status is LoweringStatus.LOWERED
    assert plan.spec.vstart_policy is VStartPolicy.REQUIRE_ZERO
    assert "vstart" in result.state_reads and "vstart" in result.state_writes
    guard_register = result.assembly_lines[0].strip().split()[1].rstrip(",")
    assert guard_register in result.clobbered_gprs


def test_general_verify_oracle_uses_zero_vstart_precondition():
    from verify.rvv256_wide.run_verify import _C_HEADER

    assert "*(uint64_t *)(simulated_cpu_state + VSTART_OFFSET) = 0;" in _C_HEADER
    assert "*(uint64_t *)(expected_state + VSTART_OFFSET) = 0;" in _C_HEADER


@pytest.mark.parametrize("csr", ["vstart", "vxrm", "vxsat", "vcsr"])
@pytest.mark.parametrize("form", ["csrr a2,{csr}", "csrw {csr},a2", "csrs {csr},a2",
                                   "csrc {csr},a2", "csrwi {csr},2", "csrsi {csr},2",
                                   "csrci {csr},2", "csrrw a2,{csr},a2", "csrrs a2,{csr},a2",
                                   "csrrc a2,{csr},a2", "csrrwi a2,{csr},2",
                                   "csrrsi a2,{csr},2", "csrrci a2,{csr},2"])
def test_scalar_vector_csr_forms_match_native(tmp_path, riscv_tools, csr, form):
    from test_review_forward_csr import _run

    _run(tmp_path, riscv_tools, form.format(csr=csr), backend="scalar")


@pytest.mark.parametrize("register", ["t6", "x31", "sp", "x2"])
@pytest.mark.parametrize("opcode", ["csrrw", "csrrs", "csrrc"])
def test_scalar_vector_csr_preserves_state_base_and_stack(tmp_path, riscv_tools, register, opcode):
    from test_review_forward_csr import _run

    _run(tmp_path, riscv_tools, f"{opcode} {register},vcsr,{register}", rd=register, backend="scalar")


@pytest.mark.parametrize("csr", ["0xc20", "0xc21", "3106"])
def test_scalar_readonly_csr_zero_source_read(tmp_path, riscv_tools, csr):
    from test_review_forward_csr import _run

    _run(tmp_path, riscv_tools, f"csrrs a2,{csr},zero", backend="scalar")
