"""Execute reviewed memory lowering against full-state references and source RVV."""

from pathlib import Path
import shutil
import subprocess

import pytest

from riscv.frontend.model import RVFunction, RVProgram
from riscv.frontend.parser import AsmParser
from riscv.extensions.rvv.analysis.config import StateTracker
from riscv.extensions.rvv.backends.scalar.backend import ScalarDispatcher, make_scalar_profile
from riscv.extensions.rvv.runtime.contract import RVV1024_TO_RVV256
from riscv.extensions.rvv.runtime.layout import SimulatedStateLayout
from riscv.extensions.rvv.translation.contracts import UnsupportedInstructionError
from riscv.extensions.rvv.translation.emitter import ProgramEmitter
from riscv.extensions.rvv.translation.pipeline import TranslationPipeline
from rvv_sbt_rvv import translate


_START = """
.section .text.init
.globl _start, trap
_start:
    la sp, stack_top
    li t0, 0x6600
    csrs mstatus, t0
    la t0, trap
    csrw mtvec, t0
    call main
finish:
    li t0, 0x100000
    li t1, 0x5555
    sw t1, 0(t0)
1:  j 1b
.balign 4
trap:
    li t0, 0x10000000
    li t1, 84
    sb t1, 0(t0)
    j finish
.section .bss
.balign 16
    .space 16384
stack_top:
"""
_LINK = """
OUTPUT_ARCH(riscv)
ENTRY(_start)
SECTIONS {
    . = 0x80000000;
    .text : { *(.text.init) *(.text*) }
    .rodata : { *(.rodata*) }
    .data : { *(.data*) *(.sdata*) }
    .bss : { *(.bss*) *(.sbss*) *(COMMON) }
}
"""
_MAIN = r"""
#include <stdint.h>
uint8_t fixture[0x10c0] __attribute__((aligned(128)));
uint8_t memory[2176] __attribute__((aligned(128)));
uint8_t expected_state[sizeof(fixture)];
uint8_t expected_memory[sizeof(memory)];
__asm__(".globl @SYMBOL@\n.set @SYMBOL@, fixture + 64\n");
extern void probe(void);
static void put(char c) { *(volatile char *)0x10000000 = c; }
static int same(const uint8_t *a, const uint8_t *b, unsigned n) {
    for (unsigned i=0; i<n; i++) if (a[i] != b[i]) return 0;
    return 1;
}
static void initialize(unsigned vl) {
    for (unsigned i=0; i<sizeof(fixture); i++) fixture[i]=(i*37+13)&255;
    for (unsigned i=0; i<sizeof(memory); i++) memory[i]=(i*17+29)&255;
    for (unsigned i=0x1000; i<0x1040; i++) fixture[64+i]=0;
    *(uint64_t *)(fixture+64+0x1020)=vl;
    *(uint64_t *)(fixture+64+0x1028)=@VTYPE@;
    *(uint64_t *)(fixture+64+0x1030)=128;
    for (unsigned i=0; i<sizeof(fixture); i++) expected_state[i]=fixture[i];
    for (unsigned i=0; i<sizeof(memory); i++) expected_memory[i]=memory[i];
}
static int unchanged(void) {
    return same(fixture,expected_state,sizeof(fixture)) &&
           same(memory,expected_memory,sizeof(memory));
}
int main(void) {
    unsigned lengths[]={@LENGTHS@};
    for (unsigned l=0; l<sizeof(lengths)/sizeof(*lengths); l++) {
        unsigned vl=lengths[l];
        initialize(vl);
        @EXPECTED@
        probe();
        if (!unchanged()) { put('F'); return 1; }
    }
    put('P');
    return 0;
}
"""


@pytest.fixture(scope="module")
def memory_riscv_tools():
    compiler = shutil.which("riscv64-elf-gcc")
    qemu = shutil.which("qemu-system-riscv64")
    if not compiler or not qemu:
        pytest.skip("requires riscv64-elf-gcc and qemu-system-riscv64")
    return compiler, qemu


def _translate(command, sew, lmul, backend):
    instructions = AsmParser().parse_string(command)
    init = f"sew={sew},lmul={lmul},tu,mu"
    if backend == "forward":
        return translate(instructions, init_vtype=init, raw=True, tls_state=False)
    pipeline = TranslationPipeline(ProgramEmitter())
    prepared = pipeline.prepare(
        RVProgram(functions=[RVFunction(name="probe", start_addr=0, instructions=instructions)]),
        backend_profile=make_scalar_profile(), init_vtype=init,
    )
    return pipeline.emit_function(
        prepared, state_factory=lambda: StateTracker(128),
        allocator_factory=SimulatedStateLayout, dispatcher_factory=ScalarDispatcher,
        raw=True, tls_state=False,
    )


def _main(symbol, sew, lmul, lengths, expected):
    vtype = {8: 0, 16: 8, 32: 16, 64: 24}[sew] | {0.125: 5, 0.5: 7, 1: 0, 2: 1, 4: 2, 8: 3}[lmul]
    result = _MAIN
    for key, value in {"SYMBOL": symbol, "VTYPE": vtype,
                       "LENGTHS": ",".join(map(str, lengths)), "EXPECTED": expected}.items():
        result = result.replace(f"@{key}@", str(value))
    return result


def _native(command, symbol, sew, lmul, setup):
    load = "\n".join(f"    li t1,{r*128}\n    add t1,t0,t1\n    vl1re8.v v{r},(t1)" for r in range(32))
    save = "\n".join(f"    li t1,{r*128}\n    add t1,t0,t1\n    vs1r.v v{r},(t1)" for r in range(32))
    token = f"mf{int(1/lmul)}" if lmul < 1 else f"m{lmul}"
    return f"""
    la t0,{symbol}
{load}
    li t1,0x1020
    add t1,t0,t1
    ld t1,0(t1)
    vsetvli zero,t1,e{sew},{token},tu,mu
{setup}
    {command}
    csrr t2,vl
    la t0,{symbol}
    li t1,0x1020
    add t1,t0,t1
    sd t2,0(t1)
{save}
"""


def _execute(path: Path, tools, body, main, vlen, start=_START):
    compiler, qemu = tools
    path.mkdir()
    (path / "start.S").write_text(start)
    (path / "link.ld").write_text(_LINK)
    (path / "main.c").write_text(main)
    (path / "probe.S").write_text(".text\n.globl probe\nprobe:\n" + body + "\n    ret\n")
    build = subprocess.run([
        compiler, "-march=rv64gcv", "-mabi=lp64d", "-mcmodel=medany",
        "-msmall-data-limit=0", "-fno-tree-vectorize", "-fno-builtin", "-ffreestanding",
        "-nostdlib", "-O2", "-T", "link.ld", "start.S", "main.c", "probe.S", "-o", "case.elf",
    ], cwd=path, capture_output=True, text=True, timeout=30)
    (path / "build.log").write_text(build.stdout + build.stderr)
    assert build.returncode == 0, build.stderr
    result = subprocess.run([
        qemu, "-M", "virt", "-cpu", f"rv64,v=true,vlen={vlen},elen=64", "-m", "128M",
        "-nographic", "-bios", "none", "-kernel", str(path / "case.elf"),
    ], capture_output=True, text=True, timeout=20)
    (path / "stdout").write_text(result.stdout)
    (path / "stderr").write_text(result.stderr)
    assert result.returncode == 0, result.stderr
    assert result.stdout == "P", result.stdout


_SCALAR_CASES = [
    ("scalar", op, 64, lmul, "v8", base)
    for op in ("vle64.v", "vse64.v", "vlse64.v", "vsse64.v", "vlseg2e64.v",
               "vsseg2e64.v", "vlsseg2e64.v", "vssseg2e64.v")
    for lmul in (1, 2, 4) for base in ("t6", "x31")
]
_SEGMENT_CASES = [
    ("forward", op, sew, lmul, reg, "a0")
    for op in ("vlseg2e64.v", "vsseg2e64.v", "vlsseg2e64.v", "vssseg2e64.v")
    for sew, lmul, reg in ((64, 1, "v25"), (64, 2, "v8"), (64, 4, "v8"),
                           (32, 1, "v8"), (32, 2, "v8"), (64, 0.5, "v8"), (64, 0.125, "v25"))
]


@pytest.mark.parametrize("backend,op,sew,lmul,reg,base", _SCALAR_CASES + _SEGMENT_CASES + [
    ("scalar", op, sew, lmul, reg, "t6")
    for _, op, sew, lmul, reg, _ in _SEGMENT_CASES
    if sew != 64 or lmul < 1
])
def test_memory_full_state_and_source(tmp_path, memory_riscv_tools, backend, op, sew, lmul, reg, base):
    segmented = "seg" in op
    strided = op.startswith(("vlse", "vsse", "vlsseg", "vssseg")) and not op.startswith(("vlseg", "vsseg"))
    store = op.startswith("vs")
    fields = 2 if segmented else 1
    stride = 24 if strided else fields * 8
    command = f"{op} {reg}, ({base})" + (", a1" if strided else "")
    symbol = RVV1024_TO_RVV256.non_tls_state_symbol if backend == "forward" else "simulated_cpu_state"
    vlmax = int(1024 * lmul / sew)
    lengths = sorted(vl for vl in {0, 1, 3, 4, 5, vlmax} if vl <= vlmax)
    group_regs = max(1, int(lmul * 64 / sew))
    expected = f"""
        for (unsigned i=0; i<vl; i++) for (unsigned f=0; f<{fields}; f++) {{
            unsigned voff=64+({int(reg[1:])}+f*{group_regs})*128+i*8;
            unsigned moff=64+i*{stride}+f*8;
            for (unsigned b=0; b<8; b++)
                {"expected_memory[moff+b]=fixture[voff+b];" if store else "expected_state[voff+b]=memory[moff+b];"}
        }}
    """
    main = _main(symbol, sew, lmul, lengths, expected)
    setup = "    la a0,memory+64\n    la t6,memory+64\n    li a1,24\n"
    candidate = _translate(command, sew, lmul, backend)
    assert "fallback" not in candidate
    check_base = "    la t0,memory+64\n    bne t6,t0,trap\n"
    _execute(tmp_path / "translated", memory_riscv_tools, setup + candidate + check_base, main, 256)
    _execute(tmp_path / "native", memory_riscv_tools,
             _native(command, symbol, sew, lmul, setup), main, 1024)


@pytest.mark.parametrize("sew,lmul,reg,fault_after", [
    (sew, lmul, reg, fault_after)
    for sew, lmul, reg in ((8, 1, "v8"), (8, 2, "v24"), (8, 4, "v16"),
                           (32, 2, "v25"), (64, 1, "v31"),
                           (8, 8, "v0"), (8, 8, "v24"))
    for fault_after in (None, 1, 31, 32, 33, 62, 63, 64, 94, 255, 256, 257, 511, 512, 1023)
])
def test_fof_chunk_path_full_state_and_source(tmp_path, memory_riscv_tools, sew, lmul, reg, fault_after):
    symbol = RVV1024_TO_RVV256.non_tls_state_symbol
    capacity = int(1024 * lmul / sew)
    lengths = sorted({0, 1, min(31, capacity), min(32, capacity), min(33, capacity), capacity})
    if fault_after is not None:
        lengths = sorted(set(lengths) | {
            min(capacity, fault_after - 1), min(capacity, fault_after),
            min(capacity, fault_after + 1),
        })
    command = f"vle8ff.v {reg}, (a0)"
    if fault_after is None:
        expected = f"for (unsigned i=0;i<vl;i++) expected_state[64+{int(reg[1:])*128}+i]=memory[64+i];"
        setup = "    la a0,memory+64\n"
    else:
        expected = f"""
        unsigned actual=vl<{fault_after}?vl:{fault_after};
        for (unsigned i=0;i<actual;i++) expected_state[64+{int(reg[1:])*128}+i]=0;
        *(uint64_t *)(expected_state+64+0x1020)=actual;
        """
        setup = f"    li a0,{0x88000000-fault_after}\n"
    main = _main(symbol, sew, lmul, lengths, expected)
    candidate = _translate(command, sew, lmul, "forward")
    assert "fallback" not in candidate
    _execute(tmp_path / "native", memory_riscv_tools,
             _native(command, symbol, sew, lmul, setup), main, 1024)
    _execute(tmp_path / "translated", memory_riscv_tools, setup + candidate, main, 256)


@pytest.mark.parametrize("sew,lmul,reg,vl", [
    (sew, lmul, reg, vl)
    for sew, lmul, reg in ((8, 4, "v8"), (8, 8, "v16"), (16, 8, "v24"))
    for vl in (257, 512, 1024) if vl <= 1024 * lmul / sew
])
@pytest.mark.parametrize("base", ["a0", "t6"])
@pytest.mark.parametrize("invalid_address", [False, True])
def test_fof_chunk_path_accepts_large_vl_and_preserves_first_fault(
    tmp_path, memory_riscv_tools, sew, lmul, reg, vl, base, invalid_address,
):
    symbol = RVV1024_TO_RVV256.non_tls_state_symbol
    command = f"vle8ff.v {reg}, ({base})"
    expected = "" if invalid_address else (
        f"for (unsigned i=0;i<vl;i++) expected_state[64+{int(reg[1:])*128}+i]=memory[64+i];"
    )
    main = _main(symbol, sew, lmul, [vl], expected)
    start = _START
    if invalid_address:
        main = main.replace("        probe();", "        probe(); put('F'); return 1;")
        main += r"""
void rejected(void) {
    uint64_t cause;
    __asm__ volatile("csrr %0,mcause" : "=r"(cause));
    put(cause==5 && unchanged() ? 'P' : 'F');
}
"""
        start = _START.replace("    li t0, 0x10000000\n    li t1, 84\n    sb t1, 0(t0)", "    call rejected")
    setup = f"    li {base},0x88000000\n" if invalid_address else f"    la {base},memory+64\n"
    candidate = _translate(command, sew, lmul, "forward")
    assert "fallback" not in candidate
    assert "FOF VL exceeds" not in candidate
    assert "chimera_load_u8_fof_v1" not in candidate
    _execute(tmp_path / "translated", memory_riscv_tools, setup + candidate, main, 256, start)
    _execute(tmp_path / "native", memory_riscv_tools,
             _native(command, symbol, sew, lmul, setup), main, 1024, start)


@pytest.mark.parametrize("vl", [0, 1])
def test_fof_first_element_fault_and_empty_input(tmp_path, memory_riscv_tools, vl):
    symbol = RVV1024_TO_RVV256.non_tls_state_symbol
    command = "vle8ff.v v8, (a0)"
    main = _main(symbol, 8, 1, [vl], "")
    start = _START
    if vl:
        main = main.replace("        probe();", "        probe(); put('F'); return 1;")
        main += r"""
void rejected(void) {
    uint64_t cause;
    __asm__ volatile("csrr %0,mcause" : "=r"(cause));
    put(cause==5 && unchanged() ? 'P' : 'F');
}
"""
        start = _START.replace("    li t0, 0x10000000\n    li t1, 84\n    sb t1, 0(t0)", "    call rejected")
    setup = "    li a0,0x88000000\n"
    candidate = _translate(command, 8, 1, "forward")
    _execute(tmp_path / "translated", memory_riscv_tools, setup + candidate, main, 256, start)
    _execute(tmp_path / "native", memory_riscv_tools,
             _native(command, symbol, 8, 1, setup), main, 1024, start)


@pytest.mark.parametrize("backend", ["scalar", "forward"])
@pytest.mark.parametrize("command,sew,lmul", [
    ("vlseg2e64.v v9,(a0)", 64, 2),
    ("vsseg2e64.v v30,(a0)", 64, 2),
    ("vlseg2e64.v v8,(a0)", 64, 8),
    ("vlseg2e32.v v8,(a0)", 64, 0.125),
])
def test_segment_rejects_invalid_emul_or_field_groups(backend, command, sew, lmul):
    if backend == "scalar":
        with pytest.raises(UnsupportedInstructionError, match="Invalid NF=2/EMUL"):
            _translate(command, sew, lmul, backend)
    else:
        candidate = _translate(command, sew, lmul, backend)
        assert "Invalid NF=2/EMUL" in candidate
        assert "fallback" in candidate and "ebreak" in candidate


@pytest.mark.parametrize("base,number", [("a0", 10), ("a1", 11), ("a2", 12), ("t0", 5), ("t6", 31), ("sp", 2)])
def test_fof_chunk_path_preserves_registers(tmp_path, base, number):
    from test_control_flow_review_fixes import _execute as execute_assembly
    from riscv.registers import CALL_CLOBBERED_FPRS

    candidate = _translate(f"vle8ff.v v8, ({base})", 8, 8, "forward")
    initialize = "\n".join(f"    li x{reg}, {0x100 + reg}" for reg in range(1, 32) if reg != 2)
    save = "\n".join(f"    sd x{reg}, {reg * 8}(sp)" for reg in range(1, 32) if reg != 2)
    fp_initialize = "\n".join(f"    fmv.d.x {reg}, t0" for reg in CALL_CLOBBERED_FPRS)
    fp_check = "\n".join(f"    fmv.x.d t0, {reg}\n    bne t0, t1, fail" for reg in CALL_CLOBBERED_FPRS)
    expected = {reg: str(0x100 + reg) for reg in range(1, 32)}
    expected[2] = "stack_end"
    expected[number] = "source"
    expected_words = "\n".join(f"    .quad {expected[reg]}" for reg in range(1, 32))
    execute_assembly(tmp_path, f"""
.option norelax
.option norvc
.text
.globl _start
_start:
    la t0, trap
    csrw mtvec, t0
    la t0, saved
    csrw mscratch, t0
    li t0, 0x6600
    csrs mstatus, t0
    li t0, 0x65
    fscsr t0
    li t0, 0x1234
{fp_initialize}
    la sp, stack_end
{initialize}
    la {base}, source
{candidate}
completed:
    ebreak
.balign 4
trap:
    csrrw sp, mscratch, sp
{save}
    csrr t0, mscratch
    sd t0, 16(sp)
    csrr t0, mepc
    la t1, completed
    bne t0, t1, fail
    la t0, saved + 8
    la t1, expected
    li t2, 31
check_register:
    ld t3, 0(t0)
    ld t4, 0(t1)
    bne t3, t4, fail
    addi t0, t0, 8
    addi t1, t1, 8
    addi t2, t2, -1
    bnez t2, check_register
    frcsr t0
    li t1, 0x65
    bne t0, t1, fail
    li t1, 0x1234
{fp_check}
    la t0, simulated_cpu_state + 1024
    li t1, 256
    li t2, 0x6b
check_data:
    lbu t3, 0(t0)
    bne t3, t2, fail
    addi t0, t0, 1
    addi t1, t1, -1
    bnez t1, check_data
    li t0, 0x100000
    li t1, 0x5555
    sw t1, 0(t0)
1:  j 1b
fail:
    li t0, 0x100000
    li t1, 0x13333
    sw t1, 0(t0)
2:  j 2b
.data
.balign 128
{RVV1024_TO_RVV256.non_tls_state_symbol}:
simulated_cpu_state:
    .fill 4096, 1, 0xa5
    .quad 0, 0, 0, 0, 256, 3, 128, 0
.balign 16
    .skip 8192
source:
    .fill 256, 1, 0x6b
expected:
{expected_words}
.bss
.balign 16
saved:
    .skip 256
    .skip 8192
stack_end:
""", march="rv64gcv", cpu="rv64,v=true,vlen=256,elen=64")
