"""Check source-state recovery and mask metadata on the reverse backend."""

import pytest

from riscv.extensions.rvv.analysis.config import StateTracker
from riscv.extensions.rvv.backends.rvv1024_transition.backend import RVV1024Dispatcher
from riscv.extensions.rvv.runtime.contract import RVV256_TO_RVV1024
from riscv.extensions.rvv.runtime.layout import SimulatedStateLayout
from riscv.frontend.parser import AsmParser
from rvv_sbt_rvv1024 import translate
from test_memory_review_regressions import _execute, _START
from test_rvv256_vstart import riscv_tools


_MAIN = r'''
#include <stdint.h>
uint8_t storage[0x10c0] __attribute__((aligned(128)));
uint8_t expected[sizeof(storage)];
uint64_t observed[2];
__asm__(".globl @SYMBOL@\n.set @SYMBOL@, storage + 64\n");
extern void probe(void);
static void put(char c) { *(volatile char *)0x10000000=c; }
static int same(void) {
    for(unsigned i=0;i<sizeof(storage);i++)
        if(storage[i]!=expected[i]) return 0;
    return 1;
}
void verify_trap(unsigned long cause) {
    put(cause==3 && same() ? 'P':'F');
}
int main(void) {
    const unsigned lengths[]={0,1,3};
    for(unsigned k=0;k<3;k++) {
        for(unsigned i=0;i<sizeof(storage);i++) storage[i]=(i*37+13)&255;
        uint8_t *state=storage+64;
        for(unsigned i=0x1000;i<0x1040;i++) state[i]=0;
        *(uint64_t*)(state+0x1000)=@VSTART@;
        *(uint64_t*)(state+0x1020)=lengths[k];
        *(uint64_t*)(state+0x1028)=@VTYPE@;
        *(uint64_t*)(state+0x1030)=32;
        for(unsigned i=0;i<sizeof(storage);i++) expected[i]=storage[i];
        uint8_t *want=expected+64;
        observed[0]=observed[1]=0;
        @EXPECTED@
        probe();
        if(!same() || !(@OBSERVED@)) { put('F'); return 1; }
    }
    put('P');
    return 0;
}
'''


def _check(tmp_path, tools, command, *, sew=32, vstart=0, expected="",
           observed="1", rejected=False):
    symbol = RVV256_TO_RVV1024.non_tls_state_symbol
    main = _MAIN
    for key, value in {"SYMBOL": symbol, "VSTART": vstart,
                       "VTYPE": {8: 0, 16: 8, 32: 16, 64: 24}[sew],
                       "EXPECTED": expected, "OBSERVED": observed}.items():
        main = main.replace(f"@{key}@", str(value))
    generated = translate(
        AsmParser().parse_string(command), init_vtype=f"sew={sew},lmul=1,tu,mu",
        raw=True, tls_state=False,
    )
    assert "fallback" not in generated
    setup = "li a2,0x22222222\nli a3,16\n"
    setup += f"fmv.{'d' if sew == 64 else 'w'}.x fa0,a2\n"
    capture = "la t0,observed\nsd a0,0(t0)\nsd a1,8(t0)\n"
    start = _START
    if rejected:
        start = start.replace(
            "    li t0, 0x10000000\n    li t1, 84\n    sb t1, 0(t0)",
            "    csrr a0,mcause\n    call verify_trap",
        )
        _execute(tmp_path / "translated", tools, setup + generated, main, 1024, start)
        return
    load = "\n".join(f"li t1,{r*32}\nadd t1,t0,t1\nvl1re8.v v{r},(t1)" for r in range(32))
    save = "\n".join(f"li t1,{r*32}\nadd t1,t0,t1\nvs1r.v v{r},(t1)" for r in range(32))
    native = f"""
    csrwi vstart,0
    la t0,{symbol}
{load}
    li t1,0x1020
    add t1,t0,t1
    ld t1,0(t1)
    vsetvli zero,t1,e{sew},m1,tu,mu
{setup}
    csrwi vstart,{vstart}
{command}
{capture}
    la t0,{symbol}
"""
    for csr, offset in (("vstart", 0x1000), ("vl", 0x1020), ("vtype", 0x1028)):
        native += f"csrr t2,{csr}\nli t1,{offset}\nadd t1,t0,t1\nsd t2,0(t1)\n"
    native += "csrwi vstart,0\n" + save
    _execute(tmp_path / "native", tools, native, main, 256)
    _execute(tmp_path / "translated", tools, setup + generated + "\n" + capture, main, 1024)


@pytest.mark.parametrize("sew", [8, 16, 32, 64])
def test_reverse_integer_insert_observes_source_vl(tmp_path, riscv_tools, sew):
    _check(tmp_path, riscv_tools, "vmv.s.x v8,a2", sew=sew,
           expected=f"if(lengths[k]) *(uint{sew}_t*)(want+8*32)=(uint{sew}_t)0x22222222;")


@pytest.mark.parametrize("sew", [32, 64])
def test_reverse_float_insert_observes_source_vl(tmp_path, riscv_tools, sew):
    _check(tmp_path, riscv_tools, "vfmv.s.f v8,fa0", sew=sew,
           expected=f"if(lengths[k]) *(uint{sew}_t*)(want+8*32)=0x22222222;")


def test_reverse_csr_can_read_and_clear_nonzero_vstart(tmp_path, riscv_tools):
    _check(tmp_path, riscv_tools,
           "csrwi vstart,1\ncsrr a0,vstart\ncsrwi vstart,0\ncsrr a1,vstart",
           observed="observed[0]==1 && observed[1]==0")


def test_reverse_csr_read_preserves_nonzero_vstart(tmp_path, riscv_tools):
    _check(tmp_path, riscv_tools, "csrr a0,vstart", vstart=3,
           observed="observed[0]==3")


@pytest.mark.parametrize("configuration", [
    "vsetivli a0,4,e32,m1,tu,mu",
    "vsetvli a0,a2,e32,m1,tu,mu",
    "vsetvl a0,a2,a3",
    "vsetivli t6,4,e32,m1,tu,mu\nmv a0,t6",
])
def test_reverse_config_recovers_nonzero_vstart(tmp_path, riscv_tools, configuration):
    vl = 4 if "vsetivli" in configuration else 8
    _check(tmp_path, riscv_tools, configuration + "\ncsrr a1,vstart", vstart=1,
           expected=f"*(uint64_t*)(want+0x1000)=0; *(uint64_t*)(want+0x1020)={vl};",
           observed=f"observed[0]=={vl} && observed[1]==0")


def test_reverse_data_still_rejects_nonzero_vstart_before_payload_write(tmp_path, riscv_tools):
    _check(tmp_path, riscv_tools, "vadd.vi v8,v16,1", vstart=1, rejected=True)


@pytest.mark.parametrize("command,sew", [
    ("vadd.vi v8,v16,1,v0.t", 16),
    ("vadd.vi v8,v16,1,v0.t", 32),
    ("vwmacc.vv v8,v16,v24,v0.t", 16),
    ("vfncvt.f.f.w v8,v16,v0.t", 32),
    ("vle32.v v8,(a0),v0.t", 32),
    ("vsse32.v v8,(a0),a1,v0.t", 32),
    ("vslidedown.vi v8,v16,3,v0.t", 32),
    ("vmerge.vvm v8,v16,v24,v0", 32),
])
def test_reverse_explicit_mask_writes_are_in_clobbers(command, sew):
    insn = AsmParser().parse_string(command)[0]
    state = StateTracker(32)
    state.apply_init_vtype(f"sew={sew},lmul=1")
    dispatcher = RVV1024Dispatcher()
    context = dispatcher.make_context(insn, state, SimulatedStateLayout())
    result = dispatcher.lower(context, dispatcher.plan(context))
    assert result.is_lowered
    assert "v0" in result.clobbered_vregs
