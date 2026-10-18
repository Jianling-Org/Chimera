"""Public whole-program stack-liveness analyzer."""

from __future__ import annotations

from dataclasses import replace
from typing import Any

from ...core.algorithm.address_states import retained_entries
from ...core.data_model import Program
from ...core.contracts import VectorStackSemantics
from ...core.monitor import PhaseMemoryMonitor
from .model import ChimeraMetadata, StackFunctionLiveness, StackLivenessResult
from .origins import OriginProver
from .liveness import (
    _CallerStackContextPropagator,
    _FunctionStackLivenessAnalyzer,
    _resolved_scalar_lifetime_transfers,
)
from .scope import (
    assumption_for_policy,
    is_conditional_policy,
    normalize_unknown_stack_size_policy,
)

# region Public pipeline


class StackLivenessAnalyzer:
    """Whole-program stack-data and VLEN-frame liveness analyzer."""

    def __init__(
        self,
        min_vlen_bits: int = 256,
        *,
        semantics: VectorStackSemantics,
        emit_warnings: bool = True,
        unknown_stack_size_policy: str = "conservative",
    ) -> None:
        if isinstance(min_vlen_bits, bool) or min_vlen_bits <= 0:
            raise ValueError("min_vlen_bits must be a positive integer")
        self.unknown_stack_size_policy = normalize_unknown_stack_size_policy(
            unknown_stack_size_policy
        )
        self._function_analyzer = _FunctionStackLivenessAnalyzer(
            min_vlen_bits,
            semantics=semantics,
            emit_warnings=emit_warnings,
            unknown_stack_size_policy=self.unknown_stack_size_policy,
        )
        self._semantics = semantics
        self._propagator = _CallerStackContextPropagator(semantics)

    def analyze_program(
        self,
        program: Program,
        *,
        metadata: ChimeraMetadata | None = None,
        config_results: dict[int, Any] | None = None,
        prover=None,
        external_leaf_bindings=None,
    ) -> StackLivenessResult:
        metadata = metadata or ChimeraMetadata.empty()
        if config_results is None:
            raise ValueError("stack liveness requires precomputed vector configurations")
        # One prover per run: its caches and its shared proof table live for
        # exactly this check and are dropped with it.
        if prover is None:
            prover = OriginProver(program, self._semantics, metadata=metadata)
        resolved_scalar_lifetime_transfers = _resolved_scalar_lifetime_transfers(
            program, metadata, self._semantics)
        # Per-function phase accounting: the local analysis is where the
        # per-instruction state of every function is built, so a slow or
        # suddenly expensive function has to be identifiable here.
        monitor = PhaseMemoryMonitor("safety.stack-local.memory")
        monitor.begin(functions=len(program.functions))
        local_results: dict[int, StackFunctionLiveness] = {}
        retained_total = 0
        for function in program.functions:
            item = monitor.begin_item(
                function.name, function.start, len(function.insts)
            )
            result = self._function_analyzer.analyze(
                function,
                metadata=metadata,
                config_result=config_results[function.start],
                prover=prover,
                resolved_scalar_lifetime_transfers=resolved_scalar_lifetime_transfers,
            )
            retained = retained_entries(result.live_before)
            retained_total += retained
            item.end(retained=retained)
            local_results[function.start] = result
        monitor.end(functions=len(local_results), retained_states=retained_total)
        result = self._propagator.propagate(program, local_results, metadata,
            closed_external_targets=(external_leaf_bindings.closed_targets
                if external_leaf_bindings is not None else frozenset()))
        proofs = {node.id: node for node in prover.proofs()}
        return replace(
            result,
            origin_proofs=proofs,
            origin_gaps=prover.gaps(),
            proof_budget_exhausted=prover.budget_exhausted,
            missing_callees=prover.missing_callees,
            unknown_stack_size_policy=self.unknown_stack_size_policy,
            assumption=assumption_for_policy(self.unknown_stack_size_policy),
            conditional=is_conditional_policy(self.unknown_stack_size_policy),
            external_leaf_proofs=(external_leaf_bindings.proofs if external_leaf_bindings else ()),
            external_leaf_rejections=(external_leaf_bindings.rejections if external_leaf_bindings else ()),
            external_no_callback_interfaces=(external_leaf_bindings.no_callback_interfaces
                                              if external_leaf_bindings else ()),
            external_interface_rejections=(external_leaf_bindings.interface_rejections
                                           if external_leaf_bindings else ()),
        )


# endregion
