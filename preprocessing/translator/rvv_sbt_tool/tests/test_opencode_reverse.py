"""Reverse-backend profile and error-boundary regressions from OpenCodeReview."""

from dataclasses import replace

import pytest

from riscv.extensions.rvv.analysis.config import StateTracker
from riscv.extensions.rvv.backends.rvv1024_transition import specs, validation
from riscv.extensions.rvv.backends.rvv1024_transition.backend import (
    RVV1024Dispatcher, make_transition_profile,
)
from riscv.extensions.rvv.backends.rvv1024_transition.handlers import gather
from riscv.extensions.rvv.backends.rvv1024_transition.lowering import TransitionLowerer
from riscv.extensions.rvv.backends.rvv1024_transition.lowering_metadata import (
    TransitionLoweringMetadata,
)
from riscv.extensions.rvv.backends.rvv1024_transition.temp_regs import RegisterAllocationError
from riscv.extensions.rvv.runtime.geometry import (
    RVV1024_TO_RVV256_GEOMETRY, RVV256_TO_RVV1024_GEOMETRY,
)
from riscv.extensions.rvv.runtime.layout import SimulatedStateLayout
from riscv.extensions.rvv.translation.contracts import InstructionValidationError
from riscv.extensions.rvv.translation.temps import TempRegisterAllocationError
from riscv.frontend.parser import AsmParser


def _context(command="vadd.vv v8, v16, v24"):
    instruction, = AsmParser().parse_string(command)
    state = StateTracker(vlenb=32)
    state.apply_init_vtype("sew=32,lmul=1")
    dispatcher = RVV1024Dispatcher()
    context = dispatcher.make_context(instruction, state, SimulatedStateLayout())
    return dispatcher, context


@pytest.mark.parametrize("kwargs", [
    {},
    {"source_vlenb": 32, "target_vlenb": 128},
    {"geometry": RVV256_TO_RVV1024_GEOMETRY},
])
def test_transition_profile_accepts_only_its_source_and_target(kwargs):
    profile = make_transition_profile(**kwargs)
    assert (profile.source_vlenb, profile.target_vlenb) == (32, 128)


@pytest.mark.parametrize("kwargs", [
    {"source_vlenb": 128, "target_vlenb": 32},
    {"geometry": RVV1024_TO_RVV256_GEOMETRY},
    {"geometry": RVV256_TO_RVV1024_GEOMETRY, "source_vlenb": 128},
    {"geometry": RVV256_TO_RVV1024_GEOMETRY, "target_vlenb": 32},
])
def test_transition_profile_rejects_conflicting_direction(kwargs):
    with pytest.raises(ValueError, match="32.*128"):
        make_transition_profile(**kwargs)


@pytest.mark.parametrize("error_type", [TypeError, ValueError])
def test_lowerer_does_not_relabel_internal_builder_errors(error_type):
    dispatcher, context = _context()
    plan = dispatcher.plan(context)
    failure = error_type("broken builder")

    def broken(_context):
        raise failure

    plan = replace(plan, spec=replace(
        plan.spec, lowering_metadata=TransitionLoweringMetadata(broken),
    ))
    with pytest.raises(error_type) as caught:
        TransitionLowerer()(context, plan)
    assert caught.value is failure


def test_lowerer_preserves_builder_result_contract_failure():
    dispatcher, context = _context()
    plan = dispatcher.plan(context)
    plan = replace(plan, spec=replace(
        plan.spec, lowering_metadata=TransitionLoweringMetadata(lambda _context: None),
    ))
    with pytest.raises(TypeError, match="assembly builder"):
        TransitionLowerer()(context, plan)


@pytest.mark.parametrize("error_type", [RegisterAllocationError, TempRegisterAllocationError])
def test_lowerer_keeps_explicit_resource_rejection(error_type):
    dispatcher, context = _context()
    plan = dispatcher.plan(context)
    failure = error_type("no temporary registers")

    def exhausted(_context):
        raise failure

    plan = replace(plan, spec=replace(
        plan.spec, lowering_metadata=TransitionLoweringMetadata(exhausted),
    ))
    with pytest.raises(InstructionValidationError) as caught:
        TransitionLowerer()(context, plan)
    assert caught.value.__cause__ is failure


@pytest.mark.parametrize("error_type", [TypeError, ValueError])
def test_gather_does_not_hide_internal_allocator_errors(monkeypatch, error_type):
    _, context = _context("vrgather.vv v8, v16, v24")
    failure = error_type("broken allocation")

    def broken(_widths):
        raise failure

    monkeypatch.setattr(gather, "_allocate_vector_groups", broken)
    with pytest.raises(error_type) as caught:
        gather._emit_gather(context.instruction, context.state, native_opcode="vrgather.vv")
    assert caught.value is failure


@pytest.mark.parametrize("error_type", [RegisterAllocationError, TempRegisterAllocationError])
def test_gather_preserves_resource_failure_as_rejection(monkeypatch, error_type):
    _, context = _context("vrgather.vv v8, v16, v24")
    failure = error_type("no temporary registers")

    def exhausted(_widths):
        raise failure

    if error_type is RegisterAllocationError:
        monkeypatch.setattr(gather, "_allocate_vector_groups", exhausted)
    else:
        monkeypatch.setattr(gather.TempRegisterAllocator, "alloc_gpr", exhausted)
    with pytest.raises(InstructionValidationError) as caught:
        gather._emit_gather(context.instruction, context.state, native_opcode="vrgather.vv")
    assert "no temporary registers" in caught.value.detail


@pytest.mark.parametrize("error_type", [TypeError, ValueError])
def test_validator_does_not_relabel_internal_dispatch_errors(monkeypatch, error_type):
    dispatcher, context = _context()
    failure = error_type("broken vector token collection")

    def broken(_operands):
        raise failure

    monkeypatch.setattr(validation, "_vector_tokens", broken)
    with pytest.raises(error_type) as caught:
        dispatcher.plan(context)
    assert caught.value is failure


def test_validator_reports_unknown_kind_as_internal_error():
    _, context = _context()
    seed = replace(specs._SEEDS["vadd.vv"], validation_kind="missing-kind")
    validator = validation._validator(seed, {}, {}, {})
    with pytest.raises(RuntimeError, match="missing-kind"):
        validator(context)


def test_validator_does_not_hide_missing_opcode_table_entry():
    _, context = _context("vle32.v v8, (a0)")
    validator = validation._validator(specs._SEEDS["vle32.v"], {}, {}, {})
    with pytest.raises(KeyError, match="vle32.v"):
        validator(context)


@pytest.mark.parametrize("command", [
    "vadd.vi v8, v16, 999",
    "vsll.vi v8, v16, 32",
    "vslideup.vi v8, v8, 1",
])
def test_validator_keeps_input_errors_structured(command):
    dispatcher, context = _context(command)
    with pytest.raises(InstructionValidationError):
        dispatcher.plan(context)
