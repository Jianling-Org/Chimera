"""Source encoding validation and execution regressions for V01-V05/B03-B04."""

import pytest

from riscv.extensions.rvv.analysis.config import StateTracker
from riscv.extensions.rvv.analysis.model import parse_init_vtype
from riscv.extensions.rvv.backends.scalar.backend import ScalarDispatcher
from riscv.extensions.rvv.backends.rvv256.backend import RVV256Dispatcher
from riscv.extensions.rvv.backends.rvv1024_transition.backend import RVV1024Dispatcher
from riscv.extensions.rvv.runtime.contract import RVV1024_TO_RVV256, RVV256_TO_RVV1024
from riscv.extensions.rvv.runtime.layout import SimulatedStateLayout
from riscv.extensions.rvv.translation.contracts import InstructionValidationError
from riscv.frontend.parser import AsmParser
from rvv_sbt_rvv1024 import translate as translate_reverse
from test_memory_review_regressions import _execute
from test_review_arithmetic_execution import _compare
from test_rvv256_vstart import riscv_tools


def _context(command, backend="scalar", sew=32, lmul=1):
    dispatcher = (ScalarDispatcher() if backend == "scalar" else
                  RVV1024Dispatcher() if backend == "reverse" else
                  RVV256Dispatcher(wide_lmul=backend == "wide"))
    state = StateTracker(32 if backend == "reverse" else 128)
    state.sew, state.lmul = sew, lmul
    insn = AsmParser().parse_string(command)[0]
    return dispatcher, dispatcher.make_context(insn, state, SimulatedStateLayout())


@pytest.mark.parametrize("backend", ["scalar", "conservative", "wide", "reverse"])
@pytest.mark.parametrize("sew,lmul", [(128, 1), (32, 3)])
def test_unsupported_shape_is_structured(backend, sew, lmul):
    dispatcher, context = _context("vadd.vv v8,v16,v24", backend, sew, lmul)
    with pytest.raises(InstructionValidationError):
        dispatcher.plan(context)


@pytest.mark.parametrize("value", ["0x8000000000000000", "0x100", "0x4", "0x20",
                                   "sew=128,lmul=1", "sew=32,lmul=3",
                                   "sew=32,lmul=1,ta,tu", "sew=32,lmul=1,ma,mu",
                                   "sew=32,sew=64,lmul=1", "sew=32,lmul=1,typo"])
def test_init_vtype_rejects_reserved_encodings_and_ambiguous_names(value):
    with pytest.raises(ValueError):
        parse_init_vtype(value)


@pytest.mark.parametrize("raw,named", [("0x10", "sew=32,lmul=1,tu,mu"),
                                      ("0xdf", "sew=64,lmul=f2,ta,ma"),
                                      ("197", "sew=8,lmul=f8,ta,ma")])
def test_init_vtype_forms_agree(raw, named):
    assert parse_init_vtype(raw) == parse_init_vtype(named)


@pytest.mark.parametrize("backend", ["scalar", "conservative", "wide", "reverse"])
@pytest.mark.parametrize("value", [-17, 16, 31, 300, 4096])
def test_vadd_vi_rejects_out_of_range_simm5(backend, value):
    dispatcher, context = _context(f"vadd.vi v8,v16,{value}", backend)
    with pytest.raises(InstructionValidationError):
        dispatcher.plan(context)


@pytest.mark.parametrize("backend", ["scalar", "conservative", "wide", "reverse"])
@pytest.mark.parametrize("command", ["vle32.v v8,8(a0)", "vse32.v v8,-4(a0)",
                                     "vlseg2e32.v v8,0x10(a0)",
                                     "vlse32.v v8,8(t6),a1"])
def test_vector_memory_nonzero_offsets_are_rejected(backend, command):
    dispatcher, context = _context(command, backend)
    with pytest.raises(InstructionValidationError):
        dispatcher.plan(context)


@pytest.mark.parametrize("backend", ["scalar", "conservative", "wide"])
@pytest.mark.parametrize("command,sew,lmul", [
    ("vadd.vv v31,v8,v16", 32, 8), ("vadd.vv v8,v31,v16", 32, 8),
    ("vfmacc.vv v31,v8,v16", 32, 8), ("vfmv.v.f v31,fa0", 32, 8),
    ("vmv.v.i v31,1", 32, 8), ("vid.v v31", 32, 8),
    ("vadd.vv v0,v8,v16,v0.t", 32, 1),
    ("vle32.v v0,(a0),v0.t", 32, 1),
    ("vle64.v v31,(a0)", 32, 1), ("vse64.v v31,(a0)", 32, 1),
    ("vlse32.v v31,(a0),a1", 32, 4), ("vsse32.v v31,(a0),a1", 32, 4),
    ("vlseg2e64.v v28,(a0)", 32, 4), ("vsseg2e32.v v24,(a0)", 32, 8),
    ("vfwmacc.vv v8,v8,v24", 32, 1),
    ("vfncvt.f.xu.w v9,v8", 32, 1),
    ("vwmacc.vv v8,v8,v24", 16, 0.5),
    ("vse32.v v0,(a0),v0.t", 32, 1),
])
def test_invalid_vector_groups_and_overlap_fail_before_emission(backend, command, sew, lmul):
    dispatcher, context = _context(command, backend, sew, lmul)
    with pytest.raises(InstructionValidationError):
        dispatcher.plan(context)


_LEGAL_ALIASES = [
    ("vadd.vv v8,v8,v8", 32, 8),
    ("vfwmacc.vv v8,v9,v24", 32, 1),
    ("vfncvt.f.xu.w v8,v8", 32, 1),
    ("vmv.s.x v31,a0", 32, 8), ("vfmv.f.s fa0,v31", 32, 8),
    ("vfredusum.vs v1,v8,v31", 32, 8),
    ("vfredusum.vs v0,v8,v1,v0.t", 32, 1),
    ("vmseq.vi v0,v8,1,v0.t", 32, 1),
    ("vse32.v v0,(a0)", 32, 1),
    ("vlseg2e32.v v30,(a0)", 32, 0.5),
]


@pytest.mark.parametrize("backend,command,sew,lmul", [
    (backend, command, sew, lmul)
    for command, sew, lmul in _LEGAL_ALIASES
    for backend in ["scalar", "conservative", "wide"]
    if not (backend != "scalar" and command.endswith("v0.t") and
            command.startswith(("vmseq", "vfredusum")))
])
def test_source_encoding_alias_exceptions_remain_legal(backend, command, sew, lmul):
    dispatcher, context = _context(command, backend, sew, lmul)
    dispatcher.plan(context)


@pytest.mark.parametrize("backend", ["conservative", "wide"])
@pytest.mark.parametrize("sew,lmul,sources", [
    (sew, lmul, sources)
    for sew, lmul in [(8, 1), (16, 0.5), (16, 2), (16, 4), (32, 2)]
    for sources in ["v16,v24", "v8,v24", "v16,v10"]
    if sources != "v16,v10" or lmul == 2
])
def test_wide_narrow_add_matches_source(tmp_path, riscv_tools, backend, sew, lmul, sources):
    # A narrow source may overlap only the high part of a wide destination.
    _compare(tmp_path, riscv_tools, f"vwadd.wv v8,{sources}",
             sew=sew, lmul=lmul, backend=backend)


@pytest.mark.parametrize("backend", ["conservative", "wide"])
@pytest.mark.parametrize("index_eew,sew", [(16, 16), (16, 8), (64, 64), (64, 32), (64, 8)])
def test_indexed_load_preserves_legal_destination_index_alias(
    tmp_path, riscv_tools, backend, index_eew, sew,
):
    symbol = RVV1024_TO_RVV256.non_tls_state_symbol
    initialize = (f"for(unsigned i=0;i<{1024 // sew};i++) "
                  f"((uint{index_eew}_t*)(state+8*128))[i]=(i*7%32)*{sew // 8};")
    setup = f"la a0,{symbol}\nli t0,{24 * 128}\nadd a0,a0,t0"
    _compare(tmp_path, riscv_tools, f"vluxei{index_eew}.v v8,(a0),v8",
             sew=sew, lmul=1, backend=backend, initialize=initialize, setup=setup)


@pytest.mark.parametrize("backend", ["conservative", "wide", "reverse"])
@pytest.mark.parametrize("command,sew,legal", [
    ("vluxei16.v v8,(a0),v8", 16, True),
    ("vluxei64.v v8,(a0),v8", 32, True),
    ("vluxei64.v v9,(a0),v8", 32, False),
    ("vluxei16.v v8,(a0),v8", 32, False),
    ("vwadd.wv v8,v16,v16", 16, False),
])
def test_index_and_wide_sources_obey_eew_overlap_rules(backend, command, sew, legal):
    dispatcher, context = _context(command, backend, sew, 1)
    if legal:
        dispatcher.plan(context)
    else:
        with pytest.raises(InstructionValidationError):
            dispatcher.plan(context)


@pytest.mark.parametrize("opcode,ctype", [("vadd.vv", "uint32_t"), ("vfadd.vv", "float")])
def test_reverse_masked_m8_preflight_and_execution(tmp_path, riscv_tools, opcode, ctype):
    command = f"{opcode} v8,v16,v24,v0.t"
    dispatcher, context = _context(command, "reverse", 32, 8)
    result = dispatcher.lower(context, dispatcher.plan(context))
    assert result.is_lowered
    assert result.clobbered_vregs == frozenset({"v0", *(f"v{i}" for i in range(8, 32))})
    symbol = RVV256_TO_RVV1024.non_tls_state_symbol
    main = r'''
#include <stdint.h>
uint8_t storage[0x10c0] __attribute__((aligned(128)));
uint8_t expected[sizeof(storage)];
__asm__(".globl @SYMBOL@\n.set @SYMBOL@, storage + 64\n");
extern void probe(void);
static void put(char c) { *(volatile char *)0x10000000=c; }
int main(void) {
    const unsigned lengths[]={0,1,3,31,32,63,64};
    for(unsigned k=0;k<7;k++) {
        for(unsigned i=0;i<sizeof(storage);i++) storage[i]=(i*37+13)&255;
        uint8_t *state=storage+64;
        for(unsigned i=0x1000;i<0x1040;i++) state[i]=0;
        *(uint64_t*)(state+0x1020)=lengths[k];
        *(uint64_t*)(state+0x1028)=19;
        *(uint64_t*)(state+0x1030)=32;
        for(unsigned i=0;i<64;i++) {
            ((@TYPE@*)(state+16*32))[i]=i+1;
            ((@TYPE@*)(state+24*32))[i]=2*i+1;
        }
        for(unsigned i=0;i<sizeof(storage);i++) expected[i]=storage[i];
        for(unsigned i=0;i<lengths[k];i++)
            if((state[i/8]>>(i%8))&1)
                ((@TYPE@*)(expected+64+8*32))[i]=
                    ((@TYPE@*)(state+16*32))[i]+((@TYPE@*)(state+24*32))[i];
        probe();
        for(unsigned i=0;i<sizeof(storage);i++)
            if(storage[i]!=expected[i]) { put('F'); return 1; }
    }
    put('P'); return 0;
}
'''.replace("@SYMBOL@", symbol).replace("@TYPE@", ctype)
    generated = translate_reverse(AsmParser().parse_string(command),
        init_vtype="sew=32,lmul=8,tu,mu", raw=True, tls_state=False)
    assert "fallback" not in generated
    _execute(tmp_path / "translated", riscv_tools, generated, main, 1024)
    load = "\n".join(f"li t1,{r*32}\nadd t1,t0,t1\nvl1re8.v v{r},(t1)" for r in range(32))
    save = "\n".join(f"li t1,{r*32}\nadd t1,t0,t1\nvs1r.v v{r},(t1)" for r in range(32))
    native = f"""la t0,{symbol}
{load}
li t1,0x1020
add t1,t0,t1
ld t1,0(t1)
vsetvli zero,t1,e32,m8,tu,mu
{command}
la t0,{symbol}
{save}
"""
    _execute(tmp_path / "native", riscv_tools, native, main, 256)
