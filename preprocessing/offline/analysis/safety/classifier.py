"""Combine register and stack liveness into per-instruction safety facts."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ..core.data_model import Program
from ..core.monitor import argument, monitored, returned
from .stack_liveness.model import StackLivenessResult, StackObjectId
from .stack_liveness.scope import (
    CONSERVATIVE,
    CONSERVATIVE_SCOPE_DESCRIPTION,
    assumption_for_policy,
    is_conditional_policy,
)


@dataclass(frozen=True, slots=True)
class SafetyRecord:
    address: int
    safe: bool
    vector_live: frozenset[int]
    stack_live: frozenset[StackObjectId]
    reason_codes: tuple[str, ...] = ()

    @property
    def reasons(self) -> tuple[str, ...]:
        """Return reasons computed by the selected extension and classifiers."""
        return self.reason_codes


@dataclass(frozen=True)
class SafetyAnalysisResult:
    records: dict[int, SafetyRecord]
    vector: Any
    stack: StackLivenessResult
    unknown_stack_size_policy: str = CONSERVATIVE
    assumption: str = CONSERVATIVE_SCOPE_DESCRIPTION
    conditional: bool = False
    scope_exclusions: tuple = ()

    @property
    def safe_addresses(self) -> list[int]:
        return sorted(address for address, record in self.records.items() if record.safe)


@monitored(
    "safety.classify",
    variables=(
        argument("program", label="instructions", path=("instructions",), transform=len),
        returned(
            label="safe",
            path=("records",),
            transform=lambda records: sum(record.safe for record in records.values()),
        ),
        returned(
            label="unsafe",
            path=("records",),
            transform=lambda records: sum(not record.safe for record in records.values()),
        ),
    ),
)
def classify_liveness(
    program: Program,
    vector_result: Any,
    stack_result: StackLivenessResult,
    vector_classifier=None,
) -> SafetyAnalysisResult:
    records: dict[int, SafetyRecord] = {}
    empty_vector: frozenset[int] = frozenset()
    empty_stack: frozenset[StackObjectId] = frozenset()
    for function in program.functions:
        vector_function = vector_result.by_function.get(function.start)
        stack_function = stack_result.by_function.get(function.start)
        vector_live_before = (
            vector_function.live_before if vector_function is not None else {}
        )
        stack_live_before = (
            stack_function.live_before if stack_function is not None else {}
        )
        for instruction in function.insts:
            vector_live = vector_live_before.get(instruction.addr, empty_vector)
            stack_live = stack_live_before.get(instruction.addr, empty_stack)
            vector_reasons = (
                tuple(vector_classifier(vector_live))
                if vector_classifier is not None
                else (("live_vector_registers",) if vector_live else ())
            )
            stack_reasons: list[str] = []
            if any(item.source == "vlen_scalar" for item in stack_live):
                stack_reasons.append("live_vlen_scalar_data")
            if any(item.source == "vlen_stack_frame" for item in stack_live):
                stack_reasons.append("live_vlen_stack_frame")
            if any(item.source == "vlen_stack_setup" for item in stack_live):
                stack_reasons.append("live_vlen_stack_setup")
            if any(
                item.source not in {"vlen_stack_frame", "vlen_stack_setup", "vlen_scalar"}
                for item in stack_live
            ):
                stack_reasons.append("live_stack_vector_data")
            reasons = vector_reasons + tuple(stack_reasons)
            records[instruction.addr] = SafetyRecord(
                address=instruction.addr,
                safe=not reasons,
                vector_live=vector_live,
                stack_live=stack_live,
                reason_codes=reasons,
            )

    for instruction in program.instructions:
        if instruction.addr not in records:
            records[instruction.addr] = SafetyRecord(
                address=instruction.addr,
                safe=True,
                vector_live=empty_vector,
                stack_live=empty_stack,
                reason_codes=(),
            )
    # The liveness inputs are not retained on the result: nothing reads them
    # and they would pin the full per-instruction maps in memory for the
    # rest of the pipeline.
    policy = getattr(stack_result, "unknown_stack_size_policy", CONSERVATIVE)
    exclusions = tuple(
        exclusion
        for local in stack_result.by_function.values()
        for exclusion in getattr(local, "scope_exclusions", ())
    )
    return SafetyAnalysisResult(
        records,
        None,
        None,
        unknown_stack_size_policy=policy,
        assumption=getattr(
            stack_result, "assumption", assumption_for_policy(policy)
        ),
        conditional=bool(
            getattr(stack_result, "conditional", is_conditional_policy(policy))
        ),
        scope_exclusions=exclusions,
    )


__all__ = ["SafetyAnalysisResult", "SafetyRecord", "classify_liveness"]
