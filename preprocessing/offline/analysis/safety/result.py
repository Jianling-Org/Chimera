"""Aggregate result produced by the one-shot safety workflow step."""

from __future__ import annotations

from dataclasses import dataclass, field

from .classifier import SafetyAnalysisResult
from .stack_liveness import AnalysisWarning, StackLivenessResult


@dataclass(frozen=True)
class SafetyPipelineResult:
    """All reusable safety facts for the input ELF's main module.

    The heavy per-instruction intermediates (vector configs, register and
    stack liveness) are deliberately *not* retained: downstream steps only
    consume ``safety.records``, so the step precomputes ``summary`` for
    monitoring and lets the intermediates be garbage-collected on return.
    """

    module_id: str
    vector_configs: object
    vector_liveness: object
    stack_liveness: StackLivenessResult
    safety: SafetyAnalysisResult
    warnings: tuple[AnalysisWarning, ...]
    summary: dict = field(default_factory=dict)


__all__ = ["SafetyPipelineResult"]
