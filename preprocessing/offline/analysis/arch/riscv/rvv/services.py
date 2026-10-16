"""RVV extension services selected independently from base RISC-V.

Implements the ``VectorExtensionServices`` capability protocol declared in
``core.contracts.services``: a non-vector RISC-V extension would implement
``ArchitectureExtensionServices`` only and skip this file entirely.
"""

from __future__ import annotations

from typing import Any, TYPE_CHECKING

from .config import VTypeAnalyzer, VectorConfigAnalyzer
from .liveness import VectorLivenessAnalyzer
from .liveness import VECTOR_STATE_REGISTER
if TYPE_CHECKING:
    from ..stack_semantics import RiscvStackSemantics


def __getattr__(name: str):
    if name != "RiscvStackSemantics":
        raise AttributeError(name)
    # Preserve the existing services-module export without eagerly loading
    # the adapter while its config imports are still initializing RVV.
    from ..stack_semantics import RiscvStackSemantics

    globals()[name] = RiscvStackSemantics
    return RiscvStackSemantics


class RvvServices:
    # Implements: VectorExtensionServices
    name = "rvv"

    def __init__(self) -> None:
        # stack_semantics reads RVV config helpers while this package loads.
        # Compose the adapter when the service is instantiated, so importing
        # either public module first does not require a half-defined class.
        self._stack_semantics = __getattr__("RiscvStackSemantics")()

    @staticmethod
    def vector_configs(program) -> Any:
        return VectorConfigAnalyzer().analyze_program(program)

    @staticmethod
    def vector_liveness(program) -> Any:
        return VectorLivenessAnalyzer().analyze_program(program)

    @staticmethod
    def vtype_annotations(program, configs) -> Any:
        return VTypeAnalyzer(program, configs).analyze()

    @staticmethod
    def classify_vector_liveness(vector_live) -> tuple[str, ...]:
        reasons: list[str] = []
        if vector_live - {VECTOR_STATE_REGISTER}:
            reasons.append("live_vector_registers")
        if VECTOR_STATE_REGISTER in vector_live:
            reasons.append("live_vector_state")
        return tuple(reasons)

    @property
    def stack_semantics(self) -> RiscvStackSemantics:
        return self._stack_semantics
