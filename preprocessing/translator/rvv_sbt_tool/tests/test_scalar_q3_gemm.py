"""Execute scalar Q3_K lowering against independent full-state references."""

from dataclasses import dataclass
import shutil
import struct
import subprocess

import pytest

from riscv.extensions.rvv.analysis.config import StateTracker
from riscv.extensions.rvv.analysis.model import parse_init_vtype
from riscv.extensions.rvv.backends.scalar.backend import ScalarDispatcher
from riscv.extensions.rvv.runtime.layout import CSR_OFFSETS, STATE_TOTAL_SIZE
from riscv.extensions.rvv.runtime.layout import SimulatedStateLayout
from riscv.extensions.rvv.translation.contracts import UnsupportedInstructionError
from riscv.extensions.rvv.translation.dispatch import VTypeDispatchEmitter
from riscv.extensions.rvv.translation.emitter import ProgramEmitter
from riscv.frontend.parser import AsmParser
from rvv_sbt import translate


CANARY = 64
SIZE = STATE_TOTAL_SIZE + 2 * CANARY
SCALAR = 0xFEDCBA987654321D
MEMORY = bytes((i * 19 + 137) & 255 for i in range(2048))


@dataclass(frozen=True)
class Case:
    source: str
    sew: int
    lmul: float = 1
    masked: bool = False

    @property
    def instruction(self):
        return self.source + (", v0.t" if self.masked else "")

    @property
    def vtype(self):
        return f"sew={self.sew},lmul={self.lmul},tu,mu"


def _lower(case):
    insn = AsmParser().parse_string(case.instruction)[0]
    state = StateTracker(vlenb=128)
    state.apply_vtype_spec(parse_init_vtype(case.vtype))
    return insn, VTypeDispatchEmitter().dispatch(
        insn, state, SimulatedStateLayout(), ScalarDispatcher()
    )


def _cases():
    result = []
    for sew in (8, 16, 32, 64):
        for source in (
            "vand.vi v8, v16, -16", "vor.vv v8, v16, v24",
            "vsll.vi v8, v16, 31", "vsrl.vi v8, v16, 31",
            "vsrl.vx v8, v16, t6", "vsub.vx v8, v16, t6",
            "vmacc.vx v8, t6, v16", "vmseq.vi v8, v16, -1",
        ):
            for masked in (False, True):
                result.append(Case(source, sew, 2, masked))
        for source in ("vsrl.vx v8, v8, a0", "vmacc.vx v8, a0, v8"):
            result.append(Case(source, sew, 8))
        result.append(Case("vmseq.vi v0, v0, -1", sew, 1))
        result.append(Case("vmseq.vi v0, v16, -1", sew, 2, True))
    for sew in (8, 16, 32):
        for masked in (False, True):
            result.append(Case("vwmacc.vv v8, v16, v24", sew, 2, masked))
        result.append(Case("vwmacc.vv v8, v10, v16", sew, 2))
    for sew in (16, 32, 64):
        for masked in (False, True):
            result.append(Case("vzext.vf2 v8, v16", sew, 2, masked))
        result.append(Case("vzext.vf2 v8, v9", sew, 2))
    for sew in (32, 64):
        for masked in (False, True):
            result.append(Case("vfcvt.f.x.v v8, v8", sew, 2, masked))
    for sew in (16, 32):
        for masked in (False, True):
            result.append(Case("vfwcvt.f.f.v v8, v16", sew, 2, masked))
        result.append(Case("vfwcvt.f.f.v v8, v10", sew, 2))
    for op in ("vle8.v", "vle16.v"):
        for sew in (8, 16, 32, 64):
            for masked in (False, True):
                result.append(Case(f"{op} v8, (a1)", sew, 2, masked))
    result.extend((
        Case("vle8.v v8, (t6)", 16),
        Case("vle16.v v8, (t6)", 16),
        Case("vle8.v v27, (a1)", 8, 0.5),
        Case("vzext.vf2 v5, v6", 16),
        Case("vmv1r.v v31, v0", 8),
        Case("vmv2r.v v8, v16", 64),
        Case("vmv2r.v v8, v8", 64),
    ))
    return result


@pytest.mark.parametrize("source,vtype", [
    ("vmv2r.v v9, v16", "sew=16,lmul=1"),
    ("vmv2r.v v8, v31", "sew=16,lmul=1"),
    ("vmv1r.v v8, v16, v0.t", "sew=16,lmul=1"),
    ("vsrl.vi v8, v16, -1", "sew=8,lmul=1"),
    ("vsll.vi v8, v16, 32", "sew=8,lmul=1"),
    ("vand.vi v8, v16, 16", "sew=8,lmul=1"),
    ("vmseq.vi v0, v16, -17", "sew=8,lmul=1"),
    ("vzext.vf2 v8, v16", "sew=8,lmul=1"),
    ("vzext.vf2 v8, v16", "sew=16,lmul=0.125"),
    ("vwmacc.vv v8, v16, v24", "sew=64,lmul=1"),
    ("vwmacc.vv v8, v16, v24", "sew=16,lmul=8"),
    ("vwmacc.vv v8, v8, v16", "sew=16,lmul=1"),
    ("vfwcvt.f.f.v v8, v8", "sew=16,lmul=1"),
    ("vfwcvt.f.f.v v8, v16", "sew=64,lmul=1"),
    ("vfcvt.f.x.v v8, v16", "sew=16,lmul=1"),
    ("vor.vv v9, v16, v24", "sew=16,lmul=2"),
    ("vmseq.vi v17, v16, 0", "sew=16,lmul=2"),
    ("vle16.v v8, (a0)", "sew=8,lmul=8"),
    ("vle8.v v0, (a0), v0.t", "sew=8,lmul=1"),
    ("vmacc.vx v0, a0, v16, v0.t", "sew=16,lmul=1"),
])
def test_invalid_forms_fail_closed(source, vtype):
    with pytest.raises(UnsupportedInstructionError):
        translate(AsmParser().parse_string(source), init_vtype=vtype, raw=True)


def test_q3_gemm_instruction_sequence_uses_only_scalar_isa():
    # The real kernel changes e8,mf2 -> e16,m1 -> e32,m2 around its
    # unpacking, masked sign restoration, integer dot product and rescaling.
    source = """
    vsetvli a0, a0, e32, m2, ta, ma
    vmv.v.i v8, 0
    vsetivli zero, 1, e8, m1, ta, ma
    vmv2r.v v16, v8
.L_unpack:
    vsetvli zero, a0, e8, mf2, ta, ma
    vle8.v v27, (a1)
    vand.vi v31, v27, 15
    vmv1r.v v30, v26
    vsrl.vi v6, v27, 4
    vsrl.vx v5, v27, a5
    vand.vi v5, v5, 1
    vmseq.vi v0, v5, 0
    vsetvli zero, zero, e16, m1, ta, mu
    vzext.vf2 v5, v6
    vadd.vi v5, v5, -4, v0.t
    vmacc.vx v30, a2, v5
    vsetvli zero, zero, e8, mf2, ta, ma
    vsll.vi v7, v27, 4
    vor.vv v31, v31, v7
    vsetvli zero, zero, e16, m1, ta, ma
    vzext.vf2 v7, v31
    vsub.vx v31, v7, a3
    vwmacc.vv v16, v31, v30
    addi a4, a4, -1
    bnez a4, .L_unpack
    vle16.v v27, (a1)
    vfwcvt.f.f.v v28, v27
    vsetvli zero, zero, e32, m2, ta, ma
    vfcvt.f.x.v v16, v16
    vfmul.vf v30, v28, fa5
    vfmacc.vv v8, v30, v16
    vse32.v v8, (a1)
    ret
    """
    output = translate(AsmParser().parse_string(source), raw=True)
    assert "fallback" not in output
    assert all("unsupported nonzero source vstart" in line
               for line in output.splitlines() if "ebreak" in line)
    assert not any(i.opcode.startswith("v") for i in AsmParser().parse_string(output))


def _read(data, register, lane, bits, signed=False):
    offset = CANARY + int(register[1:]) * 128 + lane * (bits // 8)
    return int.from_bytes(data[offset:offset + bits // 8], "little", signed=signed)


def _write(data, register, lane, bits, value):
    offset = CANARY + int(register[1:]) * 128 + lane * (bits // 8)
    data[offset:offset + bits // 8] = (value & ((1 << bits) - 1)).to_bytes(bits // 8, "little")


def _int_float(value, width, rm):
    """Reference IEEE rounding from the exact integer significand."""
    if not value:
        return 0, 0
    negative = value < 0
    value = abs(value)
    precision, bias = (24, 127) if width == 32 else (53, 1023)
    exponent = value.bit_length() - 1
    discarded = max(0, exponent + 1 - precision)
    significand = value >> discarded
    remainder = value - (significand << discarded)
    if remainder:
        half = 1 << (discarded - 1)
        increment = {
            0: remainder > half or (remainder == half and significand & 1),
            1: False, 2: negative, 3: not negative, 4: remainder >= half,
        }[rm]
        significand += bool(increment)
        if significand == 1 << precision:
            significand >>= 1
            exponent += 1
    significand <<= max(0, precision - 1 - exponent)
    bits = ((int(negative) << (width - 1)) | ((exponent + bias) << (precision - 1))
            | (significand & ((1 << (precision - 1)) - 1)))
    return bits, int(bool(remainder))


def _fixture(case, vl, rm=0, half_start=None, mask_off=False):
    initial = bytearray((i * 37 + 13) & 255 for i in range(SIZE))
    insn = AsmParser().parse_string(case.instruction)[0]
    op, args = insn.opcode, insn.operands
    config = parse_init_vtype(case.vtype)
    state = StateTracker(128)
    state.apply_vtype_spec(config)
    for name, value in {"vstart": 0, "vl": vl, "vtype": state.vtype, "vlenb": 128}.items():
        struct.pack_into("<Q", initial, CANARY + CSR_OFFSETS[name], value)
    source = args[2] if op == "vmacc.vx" else args[1]
    source_bits = case.sew // 2 if op == "vzext.vf2" else case.sew
    if source.startswith("v") and not op.startswith("vmv"):
        special = (0, -1, 1, -(1 << (source_bits - 1)), (1 << (source_bits - 1)) - 1,
                   (1 << (source_bits - 2)) + 3, -((1 << (source_bits - 2)) + 3))
        if op == "vfwcvt.f.f.v":
            special = ((0, 0x8000, 1, 0x3FF, 0x400, 0x3C00, 0x7BFF,
                        0x7C00, 0xFC00, 0x7C01, 0x7E00, 0xFE00)
                       if case.sew == 16 else
                       (0, 0x80000000, 1, 0x7FFFFF, 0x800000, 0x3F800000,
                        0x7F7FFFFF, 0x7F800000, 0xFF800000, 0x7F800001, 0x7FC00000))
        for i in range(vl):
            value = half_start + i if half_start is not None else special[i % len(special)]
            _write(initial, source, i, source_bits, value)
    if case.masked:
        initial[CANARY:CANARY + 128] = bytes([0 if mask_off else 0xAA]) * 128
    expected = bytearray(initial)
    flags = 8
    if op.startswith("vmv"):
        count = int(op[3]) * 128
        dst = CANARY + int(args[0][1:]) * 128
        src = CANARY + int(args[1][1:]) * 128
        expected[dst:dst + count] = initial[src:src + count]
        return initial, expected, flags
    for i in range(vl):
        if case.masked and not ((initial[CANARY + i // 8] >> (i % 8)) & 1):
            continue
        dst_bits = case.sew
        if op.startswith("vle"):
            dst_bits = int(op[3:-2])
            value = int.from_bytes(MEMORY[i * dst_bits // 8:(i + 1) * dst_bits // 8], "little")
        else:
            x = _read(initial, source, i, source_bits)
            if op == "vand.vi": value = x & int(args[2])
            elif op == "vor.vv": value = x | _read(initial, args[2], i, source_bits)
            elif op == "vsll.vi": value = x << (int(args[2]) % case.sew)
            elif op == "vsrl.vi": value = x >> (int(args[2]) % case.sew)
            elif op == "vsrl.vx": value = x >> (SCALAR % case.sew)
            elif op == "vsub.vx": value = x - SCALAR
            elif op == "vmacc.vx": value = _read(initial, args[0], i, case.sew) + x * SCALAR
            elif op == "vzext.vf2": value = x
            elif op == "vmseq.vi":
                offset = CANARY + int(args[0][1:]) * 128 + i // 8
                bit = 1 << (i % 8)
                match = x == (int(args[2]) & ((1 << case.sew) - 1))
                expected[offset] = (expected[offset] & ~bit) | (bit if match else 0)
                continue
            elif op == "vwmacc.vv":
                dst_bits *= 2
                value = (_read(initial, args[0], i, dst_bits)
                         + _read(initial, args[1], i, case.sew, True)
                         * _read(initial, args[2], i, case.sew, True))
            elif op == "vfcvt.f.x.v":
                value, exceptions = _int_float(_read(initial, source, i, case.sew, True), case.sew, rm)
                flags |= exceptions
            elif op == "vfwcvt.f.f.v":
                dst_bits *= 2
                frac_bits = 10 if case.sew == 16 else 23
                exponent_mask = 0x7C00 if case.sew == 16 else 0x7F800000
                fraction = x & ((1 << frac_bits) - 1)
                if x & exponent_mask == exponent_mask and fraction:
                    value = 0x7FC00000 if case.sew == 16 else 0x7FF8000000000000
                    if not fraction & (1 << (frac_bits - 1)):
                        flags |= 16
                else:
                    fp = struct.unpack("<e" if case.sew == 16 else "<f", x.to_bytes(case.sew // 8, "little"))[0]
                    value = int.from_bytes(struct.pack("<f" if case.sew == 16 else "<d", fp), "little")
            else:
                raise AssertionError(op)
        _write(expected, args[0], i, dst_bits, value)
    return initial, expected, flags


_START = """
.section .text.init
.globl _start, trap
_start:
    la sp, stack_top
    li t0, 0x6000
    csrs mstatus, t0
    la t0, trap
    csrw mtvec, t0
    call main
    beqz a0, passed
trap:
    li t0, 0x100000
    li t1, 0x3333
    sw t1, 0(t0)
1:  j 1b
passed:
    li t0, 0x100000
    li t1, 0x5555
    sw t1, 0(t0)
2:  j 2b
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
#define SIZE @SIZE@
uint8_t fixture[SIZE] __attribute__((aligned(64)));
__asm__(".globl simulated_cpu_state\n.set simulated_cpu_state, fixture + 64\n");
extern const uint8_t inputs[], outputs[], memory[];
typedef void (*probe)(uint64_t, const uint8_t *);
@DECLARATIONS@
struct test { probe run; unsigned flags; unsigned rm; };
static const struct test cases[] = { @CASES@ };
static void put(char c) { *(volatile char *)0x10000000 = c; }
static void number(unsigned n) { if (n >= 10) number(n / 10); put('0' + n % 10); }
int main(void) {
    for (unsigned c = 0; c < sizeof(cases) / sizeof(cases[0]); c++) {
        for (unsigned i = 0; i < SIZE; i++) fixture[i] = inputs[c * SIZE + i];
        unsigned fcsr = (cases[c].rm << 5) | 8;
        __asm__ volatile("csrw fcsr, %0" :: "r"(fcsr));
        cases[c].run(UINT64_C(0xfedcba987654321d), memory);
        __asm__ volatile("csrr %0, fcsr" : "=r"(fcsr));
        if (fcsr != ((cases[c].rm << 5) | cases[c].flags)) {
            put('R'); number(c); put(' '); number(fcsr); put('\n'); return 1;
        }
        for (unsigned i = 0; i < SIZE; i++) {
            if (fixture[i] != outputs[c * SIZE + i]) {
                put('F'); number(c); put(' '); number(i); put('\n'); return 1;
            }
        }
    }
    put('P'); number(sizeof(cases) / sizeof(cases[0])); put('\n');
    return 0;
}
"""


def test_scalar_q3_instructions_execute_without_vector_or_half_extensions(tmp_path):
    compiler = shutil.which("riscv64-elf-gcc")
    qemu = shutil.which("qemu-system-riscv64")
    if not compiler or not qemu:
        pytest.skip("requires riscv64-elf-gcc and qemu-system-riscv64")
    cases = _cases()
    cases.append(Case("vfwcvt.f.f.v v8, v16", 16, 4))
    functions, declarations, table, descriptions = [], [], [], []
    inputs, outputs = bytearray(), bytearray()
    emitter = ProgramEmitter()
    for n, case in enumerate(cases):
        insn, result = _lower(case)
        assert result.is_lowered
        body = "\n".join(emitter.vector_block.wrap(insn, result, tls_state=False))
        body = body.replace(".L_", f".L_probe_{n}_")
        assert not any(i.opcode.startswith("v") for i in AsmParser().parse_string(body))
        scalar = "a1" if insn.opcode.startswith("vle") else "a0"
        functions.append(f"""
.globl probe_{n}
probe_{n}:
    mv t6, {scalar}
    fmv.d.x ft0, a0
{body}
    bne t6, {scalar}, trap
    fmv.x.d t1, ft0
    bne t1, a0, trap
    ret
""")
        declarations.append(f"extern void probe_{n}(uint64_t, const uint8_t *);")
        maximum = int(1024 * case.lmul / case.sew)
        lengths = sorted({length for length in (0, 1, 7, 8, 9, 63, 64, 65, maximum - 1, maximum)
                          if 0 <= length <= maximum})
        variants = [(vl, rm, None, off)
                    for vl in lengths
                    for rm in (range(5) if insn.opcode == "vfcvt.f.x.v" else (0,))
                    for off in ((False, True) if case.masked else (False,))]
        if n == len(cases) - 1:
            variants = [(256, 0, base, False) for base in range(0, 65536, 256)]
        for vl, rm, half_start, off in variants:
            initial, expected, flags = _fixture(case, vl, rm, half_start, off)
            inputs.extend(initial)
            outputs.extend(expected)
            table.append(f"{{probe_{n}, {flags}, {rm}}}")
            descriptions.append((case, vl, rm, half_start, off))
    (tmp_path / "inputs.bin").write_bytes(inputs)
    (tmp_path / "outputs.bin").write_bytes(outputs)
    (tmp_path / "memory.bin").write_bytes(MEMORY)
    blobs = '\n'.join(f'.globl {name}\n.balign 64\n{name}:\n.incbin "{name}.bin"'
                      for name in ("inputs", "outputs", "memory"))
    (tmp_path / "probes.S").write_text(".text\n" + "\n".join(functions) + "\n.section .rodata\n" + blobs)
    (tmp_path / "start.S").write_text(_START)
    (tmp_path / "link.ld").write_text(_LINK)
    (tmp_path / "main.c").write_text(_MAIN.replace("@SIZE@", str(SIZE))
                                    .replace("@DECLARATIONS@", "\n".join(declarations))
                                    .replace("@CASES@", ",\n".join(table)))
    build = subprocess.run([
        compiler, "-march=rv64gc", "-mabi=lp64d", "-mcmodel=medany",
        "-msmall-data-limit=0", "-fno-tree-vectorize", "-fno-builtin",
        "-ffreestanding", "-nostdlib", "-O2", "-T", "link.ld", "start.S",
        "main.c", "probes.S", "-o", "test.elf",
    ], cwd=tmp_path, capture_output=True, text=True, timeout=30)
    assert build.returncode == 0, build.stderr
    run = subprocess.run([
        qemu, "-M", "virt", "-cpu", "rv64,v=false,zfh=false,zfhmin=false",
        "-m", "128M", "-nographic", "-bios", "none", "-kernel", str(tmp_path / "test.elf"),
    ], capture_output=True, text=True, timeout=30)
    (tmp_path / "cases.txt").write_text("\n".join(f"{n}: {case}" for n, case in enumerate(descriptions)))
    assert run.returncode == 0 and run.stdout == f"P{len(table)}\n", (run.stdout, run.stderr, tmp_path)
