"""Execute vmacc.vx restart cases on source and target VLENs in bare-metal QEMU."""

from pathlib import Path
import shutil
import subprocess

import pytest

from riscv.frontend.parser import AsmParser
from riscv.extensions.rvv.backends.rvv256.specs import build_rvv256_registry
from riscv.extensions.rvv.runtime.contract import RVV1024_TO_RVV256
from riscv.extensions.rvv.translation.contracts import VStartPolicy
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
    li t0, 0x100000
    li t1, 0x5555
    sw t1, 0(t0)
1:  j 1b
trap:
    li t0, 0x10000000
    li t1, 84
    sb t1, 0(t0)
    li t0, 0x100000
    li t1, 0x3333
    sw t1, 0(t0)
    j trap
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
#define STATE_SIZE 0x1040
#define CANARY 64
#define SEW @SEW@
#define VLMAX @VLMAX@
#define SOURCE @SOURCE@
#define VTYPE @VTYPE@
typedef uint@SEW@_t element;
uint8_t fixture[STATE_SIZE + 2 * CANARY] __attribute__((aligned(64)));
static uint8_t expected[sizeof(fixture)];
__asm__(".globl @SYMBOL@\n.set @SYMBOL@, fixture + 64\n");
extern void probe(void);
static void put(char c) { *(volatile char *)0x10000000 = c; }
static void number(unsigned n) {
    if (n >= 10) number(n / 10);
    put('0' + n % 10);
}
int main(void) {
    unsigned lengths[] = {0, 1, 256 / SEW - 1, 256 / SEW,
                          256 / SEW + 1, VLMAX - 1, VLMAX};
    unsigned cases = 0;
    for (unsigned l = 0; l < sizeof(lengths) / sizeof(lengths[0]); l++) {
        unsigned vl = lengths[l];
        if (vl > VLMAX) continue;
        unsigned starts[] = {0, 1, 256 / SEW - 1, 256 / SEW,
                             256 / SEW + 1, vl ? vl - 1 : 0, vl, vl + 1};
        for (unsigned s = 0; s < sizeof(starts) / sizeof(starts[0]); s++) {
            unsigned start = starts[s];
            if (start >= 1024) continue; /* Source vstart is a 10-bit CSR. */
            for (unsigned i = 0; i < sizeof(fixture); i++)
                fixture[i] = (i * 37 + 13) & 255;
            uint8_t *state = fixture + CANARY;
            *(uint64_t *)(state + 0x1000) = start;
            *(uint64_t *)(state + 0x1020) = vl;
            *(uint64_t *)(state + 0x1028) = VTYPE;
            *(uint64_t *)(state + 0x1030) = 128;
            for (unsigned i = 0; i < sizeof(fixture); i++) expected[i] = fixture[i];
            element *dst = (element *)(expected + CANARY + 8 * 128);
            const element *src = (const element *)(state + SOURCE * 128);
            for (unsigned i = start; i < vl; i++)
                dst[i] = (element)((uint64_t)dst[i] + (uint64_t)src[i] * (uint64_t)-3);
            *(uint64_t *)(expected + CANARY + 0x1000) = 0;
            probe();
            for (unsigned i = 0; i < sizeof(fixture); i++) {
                if (fixture[i] != expected[i]) {
                    put('F'); put(' '); number(vl); put(' '); number(start);
                    put(' '); number(i); put('\n');
                    return 1;
                }
            }
            cases++;
        }
    }
    put('P'); put(' '); number(cases); put('\n');
    return 0;
}
"""


@pytest.mark.parametrize("wide", [False, True])
def test_vmacc_vx_declares_architectural_vstart(wide):
    registry = build_rvv256_registry(wide_lmul=wide)
    assert registry.require("vmacc.vx").vstart_policy is VStartPolicy.ARCHITECTURAL
    assert registry.require("vmacc.vv").vstart_policy is VStartPolicy.REQUIRE_ZERO


@pytest.fixture(scope="module")
def riscv_tools():
    compiler = shutil.which("riscv64-elf-gcc")
    qemu = shutil.which("qemu-system-riscv64")
    if not compiler or not qemu:
        pytest.skip("requires riscv64-elf-gcc and qemu-system-riscv64")
    return compiler, qemu


@pytest.mark.parametrize("sew,lmul", [(8, 0.5), (8, 8), (16, 1), (16, 8), (32, 2), (64, 8)])
@pytest.mark.parametrize("wide", [False, True])
@pytest.mark.parametrize("alias", [False, True])
@pytest.mark.parametrize("scalar", ["s1", "t6"])
def test_vmacc_vx_restart_matches_source_and_full_state(
    tmp_path: Path, riscv_tools, sew, lmul, wide, alias, scalar
):
    compiler, qemu = riscv_tools
    source = 8 if alias else 16
    token, vlmul = {0.5: ("mf2", 7), 1: ("m1", 0), 2: ("m2", 1), 8: ("m8", 3)}[lmul]
    vtype = ({8: 0, 16: 1, 32: 2, 64: 3}[sew] << 3) | vlmul
    symbol = RVV1024_TO_RVV256.non_tls_state_symbol
    code = _MAIN
    for key, value in {"SEW": sew, "VLMAX": int(1024 * lmul / sew),
                       "SOURCE": source, "VTYPE": vtype, "SYMBOL": symbol}.items():
        code = code.replace(f"@{key}@", str(value))
    (tmp_path / "main.c").write_text(code)
    (tmp_path / "start.S").write_text(_START)
    (tmp_path / "link.ld").write_text(_LINK)
    command = f"vmacc.vx v8, {scalar}, v{source}"
    candidate = translate(
        AsmParser().parse_string(command), init_vtype=f"sew={sew},lmul={lmul},tu,mu",
        raw=True, tls_state=False, wide_lmul=wide,
    )
    assert "ebreak" not in candidate
    assert "fallback" not in candidate
    registers = max(1, int(lmul))
    native = f"""
    la t0, {symbol}
    addi t1, t0, 1024
    vl{registers}re8.v v8, (t1)
    li t1, {source * 128}
    add t1, t0, t1
    vl{registers}re8.v v{source}, (t1)
    li t1, 0x1020
    add t1, t0, t1
    ld t1, 0(t1)
    vsetvli zero, t1, e{sew}, {token}, tu, mu
    li t1, 0x1000
    add t1, t0, t1
    ld t1, 0(t1)
    csrw vstart, t1
    {command}
    csrr t1, vstart
    li t2, 0x1000
    add t2, t0, t2
    sd t1, 0(t2)
    addi t1, t0, 1024
    vs{registers}r.v v8, (t1)
"""
    results = []
    for name, body, vlen in (("native", native, 1024), ("translated", candidate, 256)):
        assembly = f""".text
.globl probe
probe:
    addi sp, sp, -16
    sd s1, 0(sp)
    li {scalar}, -3
{body}
    li t1, -3
    bne {scalar}, t1, trap
    ld s1, 0(sp)
    addi sp, sp, 16
    ret
"""
        (tmp_path / f"{name}.S").write_text(assembly)
        subprocess.run([
            compiler, "-march=rv64gcv", "-mabi=lp64d", "-mcmodel=medany",
            "-msmall-data-limit=0", "-fno-tree-vectorize", "-fno-builtin",
            "-ffreestanding", "-nostdlib", "-O2", "-T", "link.ld", "start.S",
            "main.c", f"{name}.S", "-o", f"{name}.elf",
        ], cwd=tmp_path, check=True, capture_output=True, text=True, timeout=30)
        result = subprocess.run([
            qemu, "-M", "virt", "-cpu", f"rv64,v=true,vlen={vlen},elen=64",
            "-m", "128M", "-nographic", "-bios", "none",
            "-kernel", str(tmp_path / f"{name}.elf"),
        ], check=True, capture_output=True, text=True, timeout=20)
        assert result.stdout.startswith("P "), (name, result.stdout, result.stderr)
        results.append(result.stdout)
    assert results[0] == results[1]


@pytest.mark.parametrize("sew", [8, 16, 32, 64])
@pytest.mark.parametrize("wide", [False, True])
@pytest.mark.parametrize("rd", ["t6", "x31"])
def test_vmv_x_s_state_base_output_matches_source(tmp_path, riscv_tools, sew, wide, rd):
    compiler, qemu = riscv_tools
    symbol = RVV1024_TO_RVV256.non_tls_state_symbol
    vtype = {8: 0, 16: 8, 32: 16, 64: 24}[sew]
    code = r'''
#include <stdint.h>
uint8_t fixture[0x1040 + 128] __attribute__((aligned(64)));
static uint8_t expected[sizeof(fixture)];
__asm__(".globl @SYMBOL@\n.set @SYMBOL@, fixture + 64\n");
extern int64_t probe(void);
int main(void) {
    uint64_t values[] = {0, 1, 127, 128, 0xda2, UINT64_MAX, UINT64_C(0x8000000000000000)};
    for (unsigned vl = 0; vl <= 5; vl++) for (unsigned v = 0; v < 7; v++) {
        for (unsigned i = 0; i < sizeof(fixture); i++) fixture[i] = (i * 37 + 13) & 255;
        uint8_t *state = fixture + 64;
        *(uint@SEW@_t *)(state + 18 * 128) = values[v];
        *(uint64_t *)(state + 0x1000) = 0;
        *(uint64_t *)(state + 0x1020) = vl;
        *(uint64_t *)(state + 0x1028) = @VTYPE@;
        *(uint64_t *)(state + 0x1030) = 128;
        for (unsigned i = 0; i < sizeof(fixture); i++) expected[i] = fixture[i];
        if (probe() != (int64_t)(int@SEW@_t)values[v]) return 1;
        for (unsigned i = 0; i < sizeof(fixture); i++) if (fixture[i] != expected[i]) return 1;
    }
    *(volatile char *)0x10000000 = 'P';
    return 0;
}
'''.replace("@SYMBOL@", symbol).replace("@SEW@", str(sew)).replace("@VTYPE@", str(vtype))
    (tmp_path / "main.c").write_text(code)
    (tmp_path / "start.S").write_text(_START)
    (tmp_path / "link.ld").write_text(_LINK)
    command = f"vmv.x.s {rd}, v18"
    candidate = translate(AsmParser().parse_string(command), init_vtype=f"sew={sew},lmul=1",
                          raw=True, tls_state=False, wide_lmul=wide)
    candidate = "li t0, 123\nli t1, 456\n" + candidate + "\nli t2, 123\nbne t0, t2, trap\nli t2, 456\nbne t1, t2, trap\n"
    native = f"""
    la t0, {symbol}
    li t1, {18 * 128}
    add t1, t0, t1
    vl1re8.v v18, (t1)
    li t1, 0x1020
    add t1, t0, t1
    ld t1, 0(t1)
    vsetvli zero, t1, e{sew}, m1, ta, ma
    {command}
"""
    for name, body, vlen in (("native", native, 1024), ("translated", candidate, 256)):
        (tmp_path / f"{name}.S").write_text(f".text\n.globl probe\nprobe:\n{body}\nmv a0, {rd}\nret\n")
        subprocess.run([compiler, "-march=rv64gcv", "-mabi=lp64d", "-mcmodel=medany",
                        "-msmall-data-limit=0", "-fno-tree-vectorize", "-fno-builtin",
                        "-ffreestanding", "-nostdlib", "-O2", "-T", "link.ld", "start.S",
                        "main.c", f"{name}.S", "-o", f"{name}.elf"],
                       cwd=tmp_path, check=True, capture_output=True, text=True, timeout=30)
        result = subprocess.run([qemu, "-M", "virt", "-cpu", f"rv64,v=true,vlen={vlen},elen=64",
                                 "-m", "128M", "-nographic", "-bios", "none",
                                 "-kernel", str(tmp_path / f"{name}.elf")],
                                check=True, capture_output=True, text=True, timeout=20)
        assert result.stdout == "P", (name, result.stdout, result.stderr)
