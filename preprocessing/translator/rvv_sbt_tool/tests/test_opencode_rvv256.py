"""Public-entry and execution regressions for the RVV256 review fixes."""

import pytest

from riscv.extensions.rvv.analysis.config import StateTracker
from riscv.extensions.rvv.backends.rvv256.backend import RVV256Dispatcher, make_rvv256_profile
from riscv.extensions.rvv.backends.rvv256.specs import build_rvv256_registry
from riscv.extensions.rvv.backends.rvv256 import lowering
from riscv.extensions.rvv.runtime.geometry import (
    RVV1024_TO_RVV256_GEOMETRY, RVV256_TO_RVV1024_GEOMETRY,
)
from riscv.extensions.rvv.translation.temps import TempRegisterAllocationError
from riscv.extensions.rvv.runtime.contract import RVV1024_TO_RVV256
from riscv.extensions.rvv.runtime.layout import SimulatedStateLayout
from riscv.frontend.parser import AsmParser
from test_review_arithmetic_execution import _compare
from test_rvv256_vstart import riscv_tools
from rvv_sbt_rvv import translate


@pytest.mark.parametrize("backend", ["wide", "conservative"])
@pytest.mark.parametrize("sew", [32, 64])
def test_masked_division_refreshes_tail_mask(tmp_path, riscv_tools, backend, sew):
    initial, numerator, denominator = (
        ("0x42c60000", "0x40c00000", "0x40000000") if sew == 32 else
        ("0x4058c00000000000ULL", "0x4018000000000000ULL", "0x4000000000000000ULL")
    )
    initialize = (
        "for(unsigned i=0;i<128;i++) state[i]=0; state[0]=1; state[2]=1;"
        f"for(unsigned i=0;i<128/{sew // 8};i++) {{"
        f"((uint{sew}_t *)(state+8*128))[i]={initial};"
        f"((uint{sew}_t *)(state+16*128))[i]={numerator};"
        f"((uint{sew}_t *)(state+24*128))[i]={denominator};}}"
    )
    chunk = 256 // sew
    _compare(tmp_path, riscv_tools, "vfdiv.vv v8,v16,v24,v0.t", sew=sew,
             backend=backend, initialize=initialize,
             lengths=[1, chunk - 1, chunk, chunk + 1, 2 * chunk + 1])


@pytest.mark.parametrize("sew", [8, 16, 32, 64])
@pytest.mark.parametrize("signed_scalar", [False, True])
def test_scalar_mask_equality_uses_low_sew_bits(tmp_path, riscv_tools, sew, signed_scalar):
    scalar = "-1" if signed_scalar else hex((1 << sew) - 1)
    initialize = "for(unsigned i=0;i<128;i++) {state[8*128+i]=0;state[16*128+i]=255;}"
    _compare(tmp_path, riscv_tools, "vmseq.vx v8,v16,a5", sew=sew,
             backend="wide", initialize=initialize, setup=f"li a5,{scalar}",
             lengths=[1, 8, 9])


@pytest.mark.parametrize("sew", [32, 64])
def test_conservative_fmacc_tail_preserves_scalar_fprs(tmp_path, riscv_tools, sew):
    one, two, three, sentinel, move = (
        ("0x3f800000", "0x40000000", "0x40400000", "0x41200000", "fmv.w.x")
        if sew == 32 else
        ("UINT64_C(0x3ff0000000000000)", "UINT64_C(0x4000000000000000)",
         "UINT64_C(0x4008000000000000)", "0x4024000000000000", "fmv.d.x")
    )
    initialize = (
        f"for(unsigned i=0;i<128/{sew // 8};i++) {{"
        f"((uint{sew}_t *)(state+8*128))[i]={one};"
        f"((uint{sew}_t *)(state+16*128))[i]={two};"
        f"((uint{sew}_t *)(state+24*128))[i]={three};}}"
    )
    setup = f"li a2,{sentinel}\n" + "\n".join(
        f"{move} ft{i},a2" for i in range(3)
    )
    command = "vfmacc.vv v8,v16,v24\n" + "\n".join(
        f"vfmv.s.f v{28 + i},ft{i}" for i in range(3)
    )
    chunk = 256 // sew
    _compare(tmp_path, riscv_tools, command, sew=sew, backend="conservative",
             initialize=initialize, setup=setup,
             lengths=[1, chunk - 1, chunk, chunk + 1, 2 * chunk + 1])


def test_conservative_fmacc_declares_fixed_tail_fprs():
    dispatcher = RVV256Dispatcher(wide_lmul=False)
    instruction = AsmParser().parse_string("vfmacc.vv v8,v16,v24")[0]
    state = StateTracker(vlenb=128)
    state.apply_init_vtype("sew=32,lmul=1,tu,mu")
    context = dispatcher.make_context(instruction, state, SimulatedStateLayout(vlenb=128))
    result = dispatcher.lower(context, dispatcher.plan(context))
    assert result.is_lowered
    assert result.clobbered_fprs == frozenset({"ft0", "ft1", "ft2"})


@pytest.mark.parametrize("vtype", [0x10, 0x110, (1 << 62) | 0x10])
def test_dynamic_vsetvl_rejects_reserved_bits(tmp_path, riscv_tools, vtype):
    symbol = RVV1024_TO_RVV256.non_tls_state_symbol
    # Serialize native CSRs into the same state slots used by translated CSRs.
    command = (
        "vsetvl a0,a1,a2\ncsrr t1,vl\n"
        f"la t0,{symbol}\nli t2,0x1020\nadd t0,t0,t2\nsd t1,0(t0)\n"
        "csrr t1,vtype\nsd t1,8(t0)"
    )
    _compare(tmp_path, riscv_tools, command, backend="wide",
             setup=f"li a1,7\nli a2,{vtype}", lengths=[7])


@pytest.mark.parametrize("wide", [False, True])
def test_segment_store_declares_fixed_temporary_groups(wide):
    dispatcher = RVV256Dispatcher(wide_lmul=wide)
    instruction = AsmParser().parse_string("vsseg4e64.v v8,(a0)")[0]
    state = StateTracker(vlenb=128)
    state.apply_init_vtype("sew=64,lmul=2,tu,mu")
    context = dispatcher.make_context(instruction, state, SimulatedStateLayout(vlenb=128))
    result = dispatcher.lower(context, dispatcher.plan(context))
    assert result.is_lowered
    assert result.clobbered_vregs == frozenset(f"v{i}" for i in range(8, 16))


def test_profile_rejects_conflicting_explicit_geometry():
    assert make_rvv256_profile(geometry=RVV1024_TO_RVV256_GEOMETRY).target_vlenb == 32
    for source in (None, 128):
        with pytest.raises(ValueError, match="geometry"):
            make_rvv256_profile(source_vlenb=source, geometry=RVV256_TO_RVV1024_GEOMETRY)


@pytest.mark.parametrize("wide", [False, True])
@pytest.mark.parametrize("opcode", ["vsll.vi", "vsrl.vi"])
@pytest.mark.parametrize("immediate", ["0", "31", "0x1f", "0X1F", "-1", "32", "bad"])
def test_shift_immediate_validation_is_profile_independent(wide, opcode, immediate):
    result = translate(AsmParser().parse_string(f"{opcode} v8,v16,{immediate}"),
                       init_vtype="sew=32,lmul=1", raw=True, wide_lmul=wide)
    assert ("fallback" in result) == (immediate in {"-1", "32", "bad"})


@pytest.mark.parametrize("wide", [False, True])
@pytest.mark.parametrize("command", ["vmacc.vv v8,v16,v24", "vdiv.vx v8,v16,a0"])
def test_fixed_operand_forms_reject_extras(wide, command):
    for suffix in ("", ",extra", ",v0.t"):
        result = translate(AsmParser().parse_string(command + suffix),
                           init_vtype="sew=32,lmul=1", raw=True, wide_lmul=wide)
        assert ("fallback" in result) == bool(suffix)


@pytest.mark.parametrize("immediate", ["31", "0x1f", "0X1f"])
def test_vsetivli_accepts_equivalent_integer_spellings(immediate):
    result = translate(AsmParser().parse_string(f"vsetivli a0,{immediate},e32,m1,tu,mu"), raw=True)
    assert "fallback" not in result


def test_state_writes_use_operand_roles_and_forms_have_one_mask():
    registry = build_rvv256_registry(wide_lmul=True)
    for opcode in ("vsub.vv", "vsll.vi", "vsext.vf2", "vslidedown.vi", "vle32.v"):
        assert "vreg" in registry.require(opcode).state_writes
    for opcode in ("vse32.v", "vsseg4e64.v", "vsm.v", "vmv.x.s"):
        assert "vreg" not in registry.require(opcode).state_writes
    for spec in registry.snapshot().values():
        assert all(form.count("v0.t") <= 1 for form in spec.operand_forms)


@pytest.mark.parametrize("error", [ValueError("internal invariant"), RuntimeError("internal invariant")])
def test_internal_lowering_errors_are_not_input_fallbacks(monkeypatch, error):
    def broken(*args, **kwargs):
        raise error
    monkeypatch.setattr(lowering, "lower_assembly_builder", broken)
    with pytest.raises(type(error), match="internal invariant"):
        translate(AsmParser().parse_string("vadd.vv v8,v16,v24"), init_vtype="sew=32,lmul=1")


def test_resource_exhaustion_keeps_structured_rejection(monkeypatch):
    def exhausted(*args, **kwargs):
        raise TempRegisterAllocationError("register pool exhausted")
    monkeypatch.setattr(lowering, "lower_assembly_builder", exhausted)
    result = translate(AsmParser().parse_string("vadd.vv v8,v16,v24"), init_vtype="sew=32,lmul=1")
    assert "RVV256 fallback" in result and "register pool exhausted" in result
