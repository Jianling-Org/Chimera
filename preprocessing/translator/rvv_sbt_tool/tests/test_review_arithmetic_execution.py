"""Execute arithmetic review regressions with distinct source/target VLENs."""

from pathlib import Path
import subprocess

import pytest

from riscv.extensions.rvv.analysis.config import StateTracker
from riscv.extensions.rvv.backends.scalar.backend import ScalarDispatcher, make_scalar_profile
from riscv.extensions.rvv.runtime.contract import RVV1024_TO_RVV256
from riscv.extensions.rvv.runtime.layout import SimulatedStateLayout
from riscv.extensions.rvv.translation.emitter import ProgramEmitter
from riscv.extensions.rvv.translation.pipeline import TranslationPipeline
from riscv.frontend.model import RVFunction, RVProgram
from riscv.frontend.parser import AsmParser
from rvv_sbt_rvv import translate
from test_rvv256_vstart import _LINK, _START, riscv_tools


_MAIN = r'''
#include <stdint.h>
uint8_t storage[0x1040 + 128] __attribute__((aligned(128)));
__asm__(".globl @SYMBOL@\n.set @SYMBOL@, storage + 64\n");
extern void probe(void);
static void put(char c) { *(volatile char *)0x10000000 = c; }
static void dump(const void *p, unsigned n) {
    const uint8_t *b = p;
    for (unsigned i = 0; i < n; i++) {
        put("0123456789abcdef"[b[i] >> 4]);
        put("0123456789abcdef"[b[i] & 15]);
    }
    put('\n');
}
int main(void) {
    const unsigned lengths[] = {@LENGTHS@};
    for (unsigned k = 0; k < sizeof(lengths) / sizeof(*lengths); k++) {
        for (unsigned i = 0; i < sizeof(storage); i++) storage[i] = (i * 37 + 13) & 255;
        uint8_t *state = storage + 64;
        @INITIALIZE@
        for (unsigned i = 0x1000; i < 0x1040; i++) state[i] = 0;
        *(uint64_t *)(state + 0x1018) = @VCSR@;
        *(uint64_t *)(state + 0x1010) = @LEGACY_VCSR@ >> 1;
        *(uint64_t *)(state + 0x1008) = @LEGACY_VCSR@ & 1;
        *(uint64_t *)(state + 0x1020) = lengths[k];
        *(uint64_t *)(state + 0x1028) = @VTYPE@;
        *(uint64_t *)(state + 0x1030) = 128;
        probe();
        dump(storage, 64 + 4096);
        dump(state + 0x1000, 8);
        dump(state + 0x1018, 40);
        dump(state + 0x1040, 64);
    }
}
'''


def _translated(command, sew, lmul, backend):
    instructions = AsmParser().parse_string(command)
    init_vtype = f"sew={sew},lmul={lmul},tu,mu"
    if backend != "scalar":
        return translate(instructions, init_vtype=init_vtype, raw=True,
                         tls_state=False, wide_lmul=backend == "wide")
    pipeline = TranslationPipeline(ProgramEmitter())
    prepared = pipeline.prepare(
        RVProgram(functions=[RVFunction(name="probe", start_addr=0, instructions=instructions)]),
        backend_profile=make_scalar_profile(), init_vtype=init_vtype,
    )
    return pipeline.emit_function(
        prepared, state_factory=lambda: StateTracker(128),
        allocator_factory=SimulatedStateLayout, dispatcher_factory=ScalarDispatcher,
        raw=True, tls_state=False,
    )


def _compare(tmp_path: Path, riscv_tools, command, *, sew=32, lmul=1,
             backend="conservative", initialize="", setup="", vcsr=0,
             lengths=None, native_arch="rv64gcv", native_cpu="", legacy_vcsr=None):
    compiler, qemu = riscv_tools
    symbol = "simulated_cpu_state" if backend == "scalar" else RVV1024_TO_RVV256.non_tls_state_symbol
    token, vlmul = {0.5: ("mf2", 7), 1: ("m1", 0), 2: ("m2", 1),
                    4: ("m4", 2), 8: ("m8", 3)}[lmul]
    vlmax = int(1024 * lmul // sew)
    if lengths is None:
        lengths = sorted({0, 1, 256 // sew - 1, 256 // sew, 256 // sew + 1, vlmax})
    code = _MAIN
    for key, value in {
        "SYMBOL": symbol, "VTYPE": {8: 0, 16: 8, 32: 16, 64: 24}[sew] | vlmul,
        "LENGTHS": ",".join(map(str, lengths)), "INITIALIZE": initialize, "VCSR": vcsr,
        "LEGACY_VCSR": vcsr if legacy_vcsr is None else legacy_vcsr,
    }.items():
        code = code.replace(f"@{key}@", str(value))
    (tmp_path / "main.c").write_text(code)
    (tmp_path / "link.ld").write_text(_LINK)
    (tmp_path / "start.S").write_text(_START.replace("\ntrap:", "\n.balign 4\ntrap:"))
    translated = _translated(command, sew, lmul, backend)
    assert "fallback" not in translated
    assert all("unsupported nonzero source vstart" in line
               for line in translated.splitlines() if "ebreak" in line)
    load = "\n".join(f"    li t1, {i * 128}\n    add t1,t0,t1\n    vl1re8.v v{i},(t1)" for i in range(32))
    store = "\n".join(f"    li t1, {i * 128}\n    add t1,t0,t1\n    vs1r.v v{i},(t1)" for i in range(32))
    native = f"""
    la t0, {symbol}
{load}
    li t1, 0x1020
    add t1, t0, t1
    ld t1, 0(t1)
    vsetvli zero, t1, e{sew}, {token}, tu, mu
    csrwi vcsr, {vcsr}
{setup}
{command}
    la t0, {symbol}
    csrr t2, vcsr
    li t1, 0x1018
    add t1, t0, t1
    sd t2, 0(t1)
{store}
"""
    results = []
    for name, body, vlen, arch, cpu in (
        ("native", native, 1024, native_arch, native_cpu),
        ("translated", setup + "\n" + translated, 256, "rv64gcv", ""),
    ):
        capture_flags = f"""
    la t0, {symbol}
    li t1, 0x1038
    add t0, t0, t1
    csrr t1, fflags
    sd t1, 0(t0)
"""
        (tmp_path / f"{name}.S").write_text(
            f".text\n.globl probe\nprobe:\n    csrwi fflags,0\n{body}\n{capture_flags}\n    ret\n"
        )
        build = subprocess.run([
            compiler, f"-march={arch}", "-mabi=lp64d", "-mcmodel=medany", "-msmall-data-limit=0",
            "-fno-tree-vectorize", "-fno-builtin", "-ffreestanding", "-nostdlib", "-O2",
            "-T", "link.ld", "start.S", "main.c", f"{name}.S", "-o", f"{name}.elf",
        ], cwd=tmp_path, capture_output=True, text=True, timeout=30)
        assert build.returncode == 0, build.stderr
        result = subprocess.run([
            qemu, "-M", "virt", "-cpu", f"rv64,v=true,vlen={vlen},elen=64{cpu}",
            "-m", "128M", "-nographic", "-bios", "none", "-kernel", str(tmp_path / f"{name}.elf"),
        ], capture_output=True, text=True, timeout=20)
        assert result.returncode == 0, (name, result.stdout, result.stderr)
        (tmp_path / f"{name}.stdout").write_text(result.stdout)
        assert len(result.stdout.splitlines()) == len(lengths) * 4, (name, result.stdout)
        results.append(result.stdout)
    assert results[0] == results[1]
    return [bytes.fromhex(line)[64:] for line in results[1].splitlines()[::4]]


@pytest.mark.parametrize("backend", ["scalar", "conservative", "wide"])
@pytest.mark.parametrize("sew", [32, 64])
def test_negative_fused_accumulate_preserves_addend(tmp_path, riscv_tools, backend, sew):
    word, one, three, scalar, answer = (
        ("uint32_t", "0x3f800000", "0x40400000", "li t0,0x40000000\nfmv.w.x fa0,t0", 0xc0a00000)
        if sew == 32 else
        ("uint64_t", "UINT64_C(0x3ff0000000000000)", "UINT64_C(0x4008000000000000)",
         "li t0,0x4000000000000000\nfmv.d.x fa0,t0", 0xc014000000000000)
    )
    initialize = (f"for(unsigned i=0;i<128/{sew // 8};i++) {{"
                  f"(({word} *)(state+8*128))[i]={one};"
                  f"(({word} *)(state+16*128))[i]={three};}}")
    vectors = _compare(tmp_path, riscv_tools, "vfnmsac.vf v8,fa0,v16", sew=sew,
                       backend=backend, initialize=initialize, setup=scalar)
    assert int.from_bytes(vectors[1][8 * 128:8 * 128 + sew // 8], "little") == answer


@pytest.mark.parametrize("form,offset", [("vi", 0), ("vi", 3), ("vi", 31),
                                          ("vx", 3), ("vx", 32), ("vx", 33), ("vx", -1)])
@pytest.mark.parametrize("lmul", [0.5, 1, 2])
def test_slide_reads_through_vl_to_vlmax(tmp_path, riscv_tools, form, offset, lmul):
    operand = str(offset) if form == "vi" else "a2"
    _compare(tmp_path, riscv_tools, f"vslidedown.{form} v8,v16,{operand}",
             lmul=lmul, setup=f"li a2,{offset}")


@pytest.mark.parametrize("backend", ["wide", "conservative"])
@pytest.mark.parametrize("operands", ["v8,v16,v16", "v8,v8,v8", "v8,v16,v24"])
def test_and_not_alias_and_base_v_target(tmp_path, riscv_tools, backend, operands):
    _compare(tmp_path, riscv_tools, f"vandn.vv {operands}", backend=backend,
             native_arch="rv64gcv_zvbb", native_cpu=",zvbb=true")


@pytest.mark.parametrize("backend", ["scalar", "conservative", "wide"])
@pytest.mark.parametrize("sew", [8, 16, 32, 64])
def test_scalar_move_preserves_destination_at_zero_vl(tmp_path, riscv_tools, backend, sew):
    _compare(tmp_path, riscv_tools, "vmv.s.x v8,a2", backend=backend, sew=sew,
             setup="li a2,0x22222222", lengths=[0, 1, 3])


@pytest.mark.parametrize("command,backend,sew", [
    ("vfredusum.vs v8,v16,v24", "scalar", 32),
    ("vfredusum.vs v8,v16,v24,v0.t", "scalar", 32),
    ("vfredusum.vs v8,v16,v24", "conservative", 32),
    ("vfredmin.vs v8,v16,v24", "conservative", 32),
    ("vfredmax.vs v8,v16,v24", "conservative", 64),
    ("vfwredusum.vs v8,v16,v24", "conservative", 32),
    ("vfwredosum.vs v8,v16,v24", "conservative", 32),
])
def test_reduction_zero_vl_preserves_destination(tmp_path, riscv_tools, command, backend, sew):
    initialize = ("for(unsigned i=0;i<4096/4;i++) ((uint32_t*)state)[i]=0x3f800000;"
                  "for(unsigned i=8*128;i<9*128;i++) state[i]=0x11;")
    if "v0.t" in command:
        initialize += "for(unsigned i=0;i<128;i++) state[i]=0;"
    _compare(tmp_path, riscv_tools, command, sew=sew, backend=backend,
             initialize=initialize, lengths=[0, 1, 3, 8, 9])


@pytest.mark.parametrize("command", ["vnsrl.wi v24,v16,3", "vnsra.wi v24,v16,3", "vnclip.wi v24,v16,3"])
@pytest.mark.parametrize("sew", [8, 16, 32])
def test_narrowing_allocates_aligned_source_group(tmp_path, riscv_tools, command, sew):
    _compare(tmp_path, riscv_tools, command, sew=sew)


@pytest.mark.parametrize("vcsr", [0, 2, 4, 6, 1, 7])
def test_vnclip_rounding_and_sticky_vcsr(tmp_path, riscv_tools, vcsr):
    _compare(tmp_path, riscv_tools, "vnclip.wi v8,v16,1", sew=16, vcsr=vcsr,
             legacy_vcsr=vcsr ^ 7)


@pytest.mark.parametrize("wide", [False, True])
@pytest.mark.parametrize("command,sew", [
    ("vadd.vi v8,v16,1,v0.t", 8),
    ("vadd.vi v8,v16,1,v0.t", 32),
    ("vfmacc.vf v8,fa0,v16,v0.t", 32),
    ("vnsrl.wi v24,v16,3,v0.t", 16),
    ("vle32.v v8,(a0),v0.t", 32),
    ("vle8ff.v v8,(a0)", 8),
])
def test_forward_mask_load_is_reported_as_v0_clobber(wide, command, sew):
    from riscv.extensions.rvv.backends.rvv256.backend import RVV256Dispatcher

    insn = AsmParser().parse_string(command)[0]
    state = StateTracker(vlenb=128)
    state.apply_init_vtype(f"sew={sew},lmul=1")
    dispatcher = RVV256Dispatcher(wide_lmul=wide)
    context = dispatcher.make_context(insn, state, SimulatedStateLayout(vlenb=128))
    result = dispatcher.lower(context, dispatcher.plan(context))
    assert result.is_lowered
    assert "v0" in result.clobbered_vregs


@pytest.mark.parametrize("form", ["vi", "vx"])
def test_slide_destination_alias_preserves_unread_source(tmp_path, riscv_tools, form):
    operand = "3" if form == "vi" else "a2"
    _compare(tmp_path, riscv_tools, f"vslidedown.{form} v8,v8,{operand}", setup="li a2,3")
