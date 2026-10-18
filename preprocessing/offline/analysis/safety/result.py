"""Aggregate result produced by the one-shot safety workflow step."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from array import array

from .classifier import SafetyAnalysisResult
from .stack_liveness import AnalysisWarning, StackLivenessResult


@dataclass(frozen=True)
class SafetyPipelineResult:
    """All reusable safety facts for the input ELF's main module.

    The heavy per-instruction intermediates (vector configs, register and
    stack liveness) are deliberately *not* retained: downstream steps only
    consume the safe address set. After diagnostic export, ``for_patching``
    packs that set and releases per-instruction records as well. Replay may
    still supply full records; ``iter_safe_addresses`` handles both forms.
    """

    module_id: str
    vector_configs: object
    vector_liveness: object
    stack_liveness: StackLivenessResult
    safety: SafetyAnalysisResult | None
    warnings: tuple[AnalysisWarning, ...]
    summary: dict = field(default_factory=dict)
    patch_addresses: bytes | None = None

    def for_patching(self) -> "SafetyPipelineResult":
        """Retain only exact safe addresses after full diagnostic export."""
        if self.patch_addresses is not None:
            return self
        if self.safety is None:
            raise ValueError("safety facts are missing")
        packed = array("Q", (
            address for address, record in self.safety.records.items() if record.safe
        )).tobytes()
        return replace(
            self, safety=None, vector_configs=None, vector_liveness=None,
            stack_liveness=None, patch_addresses=packed,
        )

    def iter_safe_addresses(self):
        if self.patch_addresses is not None:
            return iter(memoryview(self.patch_addresses).cast("Q"))
        if self.safety is None:
            raise ValueError("safety facts are missing")
        return (
            address for address, record in self.safety.records.items() if record.safe
        )


__all__ = ["SafetyPipelineResult"]
