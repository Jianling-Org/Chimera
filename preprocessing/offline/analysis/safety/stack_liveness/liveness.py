"""Intra- and interprocedural stack-object liveness solvers."""

from __future__ import annotations

from dataclasses import replace
from typing import Any, Iterable

from ...core.algorithm.address_states import (
    EMPTY_STATES,
    AddressStateMap,
    address_domain,
    retained_entries,
)
from ...core.algorithm.dataflow import solve_backward_liveness
from ...core.data_model.program import Function, Instruction, Program
from ...core.contracts import VectorStackSemantics
from ...core.monitor import PhaseMemoryMonitor, argument, monitored, returned
from .model import (
    AnalysisWarning,
    ACTIVE_EXTERNAL_CALL,
    UNRESOLVED_ACTIVE_CALL,
    CallTargetResolution,
    ActiveOrigin,
    AllocationOrigin,
    ChimeraMetadata,
    FunctionExpressionResult,
    InheritanceEdge,
    InheritanceTrace,
    InheritedLivenessView,
    ORIGIN_CONSERVATIVE,
    ORIGIN_INHERITED,
    ORIGIN_IRREDUCIBLE,
    ORIGIN_LOCAL_FRAME,
    ORIGIN_LOCAL_SETUP,
    ORIGIN_LOCAL_SCALAR,
    ORIGIN_VECTOR_DATA,
    StackAccessKind,
    StackFunctionLiveness,
    StackLivenessResult,
    StackObjectId,
)
from .solver import _FunctionExpressionAnalyzer
from .accesses import (
    _StackAccessFactBuilder,
    _VectorAccessPlanner,
    _VLenSensitiveAccessSelector,
)
from .instruction_facts import _function_exit_addresses, _instruction_predecessors
from .frame_liveness import analyze_vlen_stack_liveness
from .scalar_width import analyze_scalar_width_liveness

#: Which structured origin a live stack object belongs to.  The object
#: *source* string is the analysis's own vocabulary; this table is the only
#: place it is turned into a classification input.
_ORIGIN_BY_SOURCE = {
    "caller": ORIGIN_INHERITED,
    "conservative": ORIGIN_CONSERVATIVE,
    "irreducible": ORIGIN_IRREDUCIBLE,
    "vlen_stack_frame": ORIGIN_LOCAL_FRAME,
    "vlen_stack_setup": ORIGIN_LOCAL_SETUP,
    "vlen_scalar": ORIGIN_LOCAL_SCALAR,
}

#: The prose line of each structured origin.  Classification never reads it.
_ORIGIN_TEXT = {
    ORIGIN_LOCAL_SCALAR: (
        "live hardware-width scalar cache: a value derived from vector width "
        "is still used in a scalar register or private frame slot"
    ),
    ORIGIN_INHERITED: (
        "live caller-inherited stack data: an earlier active call propagated "
        "live vector stack state into this frame"
    ),
    ORIGIN_CONSERVATIVE: (
        "live conservative marker: an unresolved vector memory access forced "
        "the enclosing scope to be treated as stack-active"
    ),
    ORIGIN_IRREDUCIBLE: (
        "live irreducible-loop marker: vector store(s) inside an irreducible "
        "loop were degraded to conservative liveness"
    ),
    ORIGIN_LOCAL_FRAME: (
        "live VLEN-dependent stack frame: the stack pointer still holds an "
        "allocation whose size was not proven independent of the hardware vlenb"
    ),
    ORIGIN_LOCAL_SETUP: (
        "live VLEN-dependent stack setup: a value not proven independent of "
        "the hardware vlenb is still flowing into a stack-pointer adjustment"
    ),
}


def _live_allocation(
    local: StackFunctionLiveness, call_addr: int
) -> AllocationOrigin | None:
    """The allocation whose frame state is live at ``call_addr``.

    Several adjustments can share one marker object, so the record reported at
    a call site is the latest one that starts at or before the call: it is the
    allocation that created the state which is live there.
    """

    candidates = [
        origin
        for origin in getattr(local, "frame_origins", ())
        if origin.source == "vlen_stack_frame" and origin.adjustment <= call_addr
    ]
    if not candidates:
        return None
    return max(candidates, key=lambda origin: origin.adjustment)


def _is_supported_scalar_lifetime_transfer(instruction, function, semantics) -> bool:
    """Whether this is an ABI call or a supported non-linking tail transfer."""
    if semantics.is_call_instruction(instruction):
        facts = semantics.scalar_width_facts(instruction)
        return "ra" in facts.writes
    return semantics.is_tail_call_instruction(instruction, function)


def _resolved_scalar_lifetime_transfers(program, metadata, semantics):
    """Return complete internal ABI transfer sites using the production resolver."""
    functions = {function.start: function for function in program.functions}
    resolver = _CallTargetResolver()
    eligible = set()
    for function in program.functions:
        for instruction in function.insts:
            if not _is_supported_scalar_lifetime_transfer(instruction, function, semantics):
                continue
            resolution = resolver.classify(instruction, functions, metadata)
            if (resolution.unresolved or resolution.empty_metadata
                    or not resolution.internal_targets or resolution.external_targets
                    or any(not functions[target].insts
                           for target in resolution.internal_targets)):
                continue
            eligible.add(instruction.addr)
    return frozenset(eligible)


def _origin_record(
    kind: str,
    obj: StackObjectId,
    line: str,
    *,
    local: StackFunctionLiveness,
    call_addr: int,
) -> ActiveOrigin:
    allocation = (
        _live_allocation(local, call_addr)
        if kind in (ORIGIN_LOCAL_FRAME, ORIGIN_LOCAL_SETUP)
        else None
    )
    # Reuse the local engine's call snapshot; reporting must not request a
    # callee effect proof or turn the snapshot into another unsafe source.
    width_evidence = next((
        origin.width_evidence
        for warning in local.warnings
        if call_addr in warning.addresses
        for origin in warning.origins
        if origin.origin == ORIGIN_LOCAL_SCALAR
        and getattr(origin, "width_evidence", None) is not None
    ), None) if kind == ORIGIN_LOCAL_SCALAR else None
    return ActiveOrigin(
        origin=kind,
        object_source=obj.source,
        object_id=str(obj),
        detail=line,
        allocation=None if allocation is None else allocation.adjustment,
        release=None if allocation is None else allocation.release,
        dependency=(
            "vlen" if kind == ORIGIN_LOCAL_SCALAR else
            None
            if allocation is None
            else allocation.dependency
        ),
        proof=None if allocation is None else allocation.proof,
        gaps=() if allocation is None else allocation.gaps,
        width_evidence=width_evidence,
    )

# region Local and interprocedural liveness


def _marked_states(
    states: AddressStateMap[int, frozenset[StackObjectId]],
    addresses: Iterable[int],
    marker: StackObjectId,
) -> AddressStateMap[int, frozenset[StackObjectId]]:
    """Return ``states`` with ``marker`` added at ``addresses``.

    Only the sparse entries are touched: an address of the function that has no
    entry yet gains exactly the marker set, and an address outside the function
    domain is ignored, matching the dense implementation that only merged into
    keys that were already present.
    """

    marker_set = frozenset({marker})
    entries = dict(states.entry_items())
    changed = False
    for address in addresses:
        current = entries.get(address)
        if current is None:
            if address not in states:
                continue
            entries[address] = marker_set
            changed = True
        elif marker_set.isdisjoint(current):
            entries[address] = current | marker_set
            changed = True
    return states.replace_entries(entries) if changed else states


def _union_states(
    first: AddressStateMap[int, frozenset[StackObjectId]],
    second: Mapping[int, frozenset[StackObjectId]],
) -> AddressStateMap[int, frozenset[StackObjectId]]:
    """Union two set-valued per-address maps without materialising empties.

    ``second`` is normally another compact map over the very same address
    domain (stack-object liveness and VLEN frame liveness are both computed
    from one function).  Then only the sparse entries of either side are
    visited instead of one union per instruction.
    """

    entries = dict(first.entry_items())
    # ``domain`` identity is the common case; comparing it costs one C-level
    # tuple comparison, whereas the fallback pays a membership query per entry.
    same_domain = getattr(second, "domain", None) is first.domain
    for address, value in second.items():
        current = entries.get(address)
        if current is None:
            if value and (same_domain or address in first):
                entries[address] = value
        elif value:
            entries[address] = current | value
    return first.replace_entries(entries)


class _StackLivenessSolver:
    @staticmethod
    @monitored(
        "safety.stack-dataflow",
        variables=(
            argument("function", label="function", path=("name",)),
            argument("function", label="function_start", path=("start",)),
            argument("uses", label="use_addresses", transform=len),
            argument("defs", label="def_addresses", transform=len),
            argument(
                "uses",
                label="stack_objects",
                transform=lambda values: len(
                    {item for objects in values.values() for item in objects}
                ),
            ),
            returned(
                label="nonempty_live_before",
                transform=lambda result: retained_entries(result[0]),
            ),
        ),
    )
    def solve(
        function: Function,
        *,
        uses: dict[int, frozenset[StackObjectId]],
        defs: dict[int, frozenset[StackObjectId]],
        domain: tuple[int, ...] | None = None,
    ) -> tuple[
        AddressStateMap[int, frozenset[StackObjectId]],
        AddressStateMap[int, frozenset[StackObjectId]],
    ]:
        instructions = function.instruction_by_address
        predecessors = _instruction_predecessors(function)
        addresses = (
            domain
            if domain is not None
            else address_domain(
                tuple(instruction.addr for instruction in function.insts)
            )
        )
        live_before, live_after = solve_backward_liveness(
            addresses,
            successors=lambda address: instructions[address].succ,
            predecessors=lambda address: predecessors[address],
            use_def=lambda address: (
                uses.get(address, EMPTY_STATES),
                defs.get(address, EMPTY_STATES),
            ),
        )

        return (
            live_before,
            live_after,
        )

    @staticmethod
    def merge_conservative_activity(
        function: Function,
        live_before: AddressStateMap[int, frozenset[StackObjectId]],
        live_after: AddressStateMap[int, frozenset[StackObjectId]],
        conservative_addresses: Iterable[int],
    ) -> tuple[
        AddressStateMap[int, frozenset[StackObjectId]],
        AddressStateMap[int, frozenset[StackObjectId]],
    ]:
        marker = StackObjectId("conservative", "possible-stack-data")
        exits = _function_exit_addresses(function)
        targets = set(conservative_addresses) - exits
        if not targets:
            return live_before, live_after
        return (
            _marked_states(live_before, targets, marker),
            _marked_states(live_after, targets, marker),
        )


class _FunctionStackLivenessAnalyzer:
    def __init__(
        self,
        min_vlen_bits: int,
        *,
        semantics: VectorStackSemantics,
        emit_warnings: bool,
        unknown_stack_size_policy: str = "conservative",
    ) -> None:
        self._unknown_stack_size_policy = unknown_stack_size_policy
        self._min_vlen_bits = min_vlen_bits
        self._semantics = semantics
        selector = _VLenSensitiveAccessSelector(semantics, min_vlen_bits)
        self._planner = _VectorAccessPlanner(selector)
        self._expression_analyzer = _FunctionExpressionAnalyzer(
            semantics,
            emit_warnings=emit_warnings
        )
        self._fact_builder = _StackAccessFactBuilder(semantics)
        self._solver = _StackLivenessSolver()

    def analyze(
        self,
        function: Function,
        *,
        metadata: ChimeraMetadata,
        config_result: Any,
        prover=None,
        resolved_scalar_lifetime_transfers=frozenset(),
    ) -> StackFunctionLiveness:
        # One address domain per function, shared by the frame markers, both
        # data-flow solutions and the merged result: the per-address state maps
        # of a function then reference a single address tuple.
        domain = address_domain(
            tuple(instruction.addr for instruction in function.insts)
        )
        plan = self._planner.plan(function, metadata, config_result)
        # Scalar expressions are also required for VLEN-dependent stack-frame
        # tracking, including metadata mode and functions without vector
        # memory accesses.
        expressions: FunctionExpressionResult = self._expression_analyzer.analyze(
            function,
            plan.vlen_sensitive_addresses,
        )
        frame_origins: list = []
        scope_exclusions: list = []
        frame_live_before, frame_warnings = analyze_vlen_stack_liveness(
            function,
            expressions,
            self._semantics,
            domain=domain,
            prover=prover,
            origins=frame_origins,
            scope_exclusions=scope_exclusions,
            unknown_stack_size_policy=self._unknown_stack_size_policy,
        )
        # ``plan.metadata_mode`` is the mode actually applied to this function:
        # it is False both when the ELF carries no stack-object section and
        # when this function's metadata coverage was incomplete, in which case
        # the whole of U goes through binary recovery.
        if plan.metadata_mode:
            facts = self._fact_builder.build(
                function=function,
                plan=plan,
                expressions=None,
                config_result=config_result,
            )

        else:
            facts = self._fact_builder.build(
                function=function,
                plan=plan,
                expressions=expressions,
                config_result=config_result,
            )

        # Share the recovered stack-object identities with width provenance.
        # Do not reparse the function or invent a second SOID namespace.
        scalar_live, scalar_sources, scalar_warnings, scalar_fallback = analyze_scalar_width_liveness(
            function, expressions, self._semantics, domain=domain,
            min_vlen_bits=self._min_vlen_bits, config_result=config_result, stack_facts=facts,
            prover=prover,
            resolved_lifetime_transfers=resolved_scalar_lifetime_transfers)

        live_before, live_after = self._solver.solve(
            function,
            uses=facts.uses,
            defs=facts.defs,
            domain=domain,
        )
        live_before, live_after = self._solver.merge_conservative_activity(
            function,
            live_before,
            live_after,
            facts.conservative_addresses,
        )
        # Merge the VLEN frame markers into the stack-object liveness.  Only
        # addresses carrying state on either side are visited, so the common
        # "nothing live anywhere" function allocates nothing at all.
        live_before = _union_states(live_before, frame_live_before)
        live_before = _union_states(live_before, scalar_live)
        loop_info = expressions.loop_info
        return StackFunctionLiveness(
            function_start=function.start,
            live_before=live_before,
            accesses=facts.accesses,
            candidate_addresses=plan.vlen_sensitive_addresses,
            rejected_nonstack_addresses=facts.rejected_nonstack_addresses,
            conservative_addresses=facts.conservative_addresses,
            loop_headers=(
                frozenset(loop_info.header_written_registers)
                if loop_info is not None
                else frozenset()
            ),
            irreducible_loops=(
                tuple(loop.addresses for loop in loop_info.irreducible_loops)
                if loop_info is not None
                else ()
            ),
            warnings=expressions.warnings + frame_warnings + scalar_warnings,
            frame_origins=tuple(frame_origins),
            scope_exclusions=tuple(scope_exclusions),
            has_metadata_section=plan.has_metadata_section,
            sensitive_access_count=len(plan.vlen_sensitive_addresses),
            metadata_covered_count=plan.metadata_covered_count,
            uncovered_sensitive_addresses=plan.uncovered_sensitive_addresses,
            access_mode=plan.access_mode,
            mode_reason=plan.mode_reason,
            scalar_width_sources=scalar_sources,
            scalar_width_fallback=scalar_fallback,
        )


class _CallTargetResolver:
    @staticmethod
    def is_transfer(instruction: Instruction, function: Function,
                    semantics: VectorStackSemantics) -> bool:
        return (semantics.is_call_instruction(instruction)
                or semantics.is_tail_call_instruction(instruction, function))

    def classify(
        self,
        instruction: Instruction,
        functions_by_start: dict[int, Function],
        metadata: ChimeraMetadata,
    ) -> CallTargetResolution:
        if len(instruction.jump_targets) == 1:
            targets = instruction.jump_targets
        else:
            entry = metadata.function_pointer.get(instruction.addr)
            if entry is None:
                return CallTargetResolution(unresolved=True)
            if not entry.usable:
                return CallTargetResolution(empty_metadata=True)
            targets = entry.targets
        internal = frozenset(
            target for target in targets
            if target in functions_by_start
            and not functions_by_start[target].is_external_trampoline
        )
        return CallTargetResolution(
            internal_targets=internal,
            external_targets=frozenset(targets) - internal,
        )

    def resolve(
        self,
        instruction: Instruction,
        functions_by_start: dict[int, Function],
        metadata: ChimeraMetadata,
    ) -> set[int] | None:
        """Compatibility projection, not a certificate of boundary coverage.

        Existing callgraph diagnostics consume internal targets only. Safety
        and source auditing use ``classify`` so external alternatives cannot
        disappear through this projection.
        """
        resolution = self.classify(instruction, functions_by_start, metadata)
        if resolution.unresolved or resolution.empty_metadata:
            return None
        if len(instruction.jump_targets) != 1 and any(
            target not in functions_by_start for target in resolution.external_targets
        ):
            return None
        return set(resolution.internal_targets)


class _CallerStackContextPropagator:
    def __init__(self, semantics: VectorStackSemantics) -> None:
        self._resolver = _CallTargetResolver()
        self._semantics = semantics

    @monitored(
        "safety.call-propagation",
        variables=(
            argument("local_results", label="local_results", transform=len),
            returned(label="result_functions", path=("by_function",), transform=len),
            returned(
                label="inherited_functions",
                path=("inherited_functions",),
                transform=len,
            ),
            returned(
                label="unresolved_active_calls",
                path=("unresolved_live_calls",),
                transform=len,
            ),
            returned(
                label="seed_edges",
                path=("inheritance_trace", "seed_edges"),
                transform=len,
            ),
            returned(
                label="max_inheritance_depth",
                path=("inheritance_trace", "max_depth"),
            ),
            returned(label="warnings", path=("warnings",), transform=len),
        ),
    )
    def propagate(
        self,
        program: Program,
        local_results: dict[int, StackFunctionLiveness],
        metadata: ChimeraMetadata,
        *,
        closed_external_targets: frozenset[int] = frozenset(),
    ) -> StackLivenessResult:
        monitor = PhaseMemoryMonitor("safety.call-propagation.memory")
        monitor.begin(
            functions=len(program.functions),
            local_results=len(local_results),
        )
        functions_by_start = {function.start: function for function in program.functions}
        inherited: set[int] = set()
        unresolved: set[int] = set()
        unresolved_details: dict[int, tuple[str, ...]] = {}
        unresolved_origins: dict[int, tuple[ActiveOrigin, ...]] = {}
        external: dict[int, tuple[int, ...]] = {}
        closed: dict[int, tuple[int, ...]] = {}
        external_details: dict[int, tuple[str, ...]] = {}
        external_origins: dict[int, tuple[ActiveOrigin, ...]] = {}
        hosts: dict[int, int] = {}
        empty_target_errors: set[int] = set()
        # Provenance bookkeeping (observational only; the closure itself is
        # driven solely by ``inherited``/``changed`` exactly as before).
        depth_by_function: dict[int, int] = {}
        first_cause: dict[int, InheritanceEdge] = {}
        seed_edges: dict[tuple[int, int], InheritanceEdge] = {}
        changed = True
        while changed:
            changed = False
            for function in program.functions:
                if function.is_external_trampoline:
                    continue
                local = local_results[function.start]
                item = monitor.begin_item(
                    function.name, function.start, len(function.insts)
                )
                caller_live = function.start in inherited
                for instruction in function.insts:
                    if not self._resolver.is_transfer(instruction, function, self._semantics):
                        continue
                    local_live = bool(local.live_before.get(instruction.addr))
                    if not caller_live and not local_live:
                        continue
                    reason = "inherited" if caller_live else "seed"
                    resolution = self._resolver.classify(
                        instruction,
                        functions_by_start,
                        metadata,
                    )
                    hosts[instruction.addr] = function.start
                    if resolution.unresolved or resolution.empty_metadata:
                        if resolution.empty_metadata:
                            empty_target_errors.add(instruction.addr)
                        # An empty declared set is unusable, not proof that
                        # this active transfer cannot leave the Program.
                        unresolved.add(instruction.addr)
                        details, origins = self._explain_activity(
                            function, local, instruction.addr, caller_live=caller_live,
                        )
                        unresolved_details[instruction.addr] = details
                        unresolved_origins[instruction.addr] = origins
                        continue
                    targets = resolution.internal_targets
                    # Only an ABI call establishes a continuation in the
                    # caller's current body. Tail/custom-link transfers stay open.
                    normal_call = self._semantics.is_call_instruction(instruction) and (
                        instruction.op == "call" or len(instruction.args) == 1
                        or instruction.args[0] in {"ra", "x1"})
                    proved = (resolution.external_targets & closed_external_targets
                              if normal_call else frozenset())
                    if proved:
                        closed[instruction.addr] = tuple(sorted(proved))
                    uncovered = resolution.external_targets - proved
                    if uncovered:
                        external[instruction.addr] = tuple(sorted(uncovered))
                        details, origins = self._explain_activity(
                            function, local, instruction.addr, caller_live=caller_live,
                        )
                        external_details[instruction.addr] = details
                        external_origins[instruction.addr] = origins
                    # Local source activity and inherited reachability are
                    # independent: an inherited function may also contain a
                    # local seed at this call site.
                    if local_live and targets:
                        key = (function.start, instruction.addr)
                        if key not in seed_edges:
                            seed_edges[key] = InheritanceEdge(
                                caller_function_start=function.start,
                                call_site=instruction.addr,
                                reason="seed",
                                depth=1,
                            )
                    for target in targets:
                        if target not in inherited:
                            inherited.add(target)
                            depth = (
                                depth_by_function[function.start] + 1
                                if caller_live
                                else 1
                            )
                            depth_by_function[target] = depth
                            first_cause[target] = InheritanceEdge(
                                caller_function_start=function.start,
                                call_site=instruction.addr,
                                reason=reason,
                                depth=depth,
                            )
                            changed = True
                item.end(retained=retained_entries(local.live_before))

        merged = self._merge_inherited_marker(local_results, inherited)
        diagnostics = tuple(
            warning
            for result in local_results.values()
            for warning in result.warnings
        ) + tuple(
            AnalysisWarning(
                code=UNRESOLVED_ACTIVE_CALL,
                message=(
                    f"active indirect call at {address:#x} has no usable complete "
                    "internal target set; inherited stack state was not propagated"
                ),
                function_start=hosts[address],
                addresses=(address,),
                details=unresolved_details.get(address, ()),
                origins=unresolved_origins.get(address, ()),
            )
            for address in sorted(unresolved)
        ) + tuple(
            AnalysisWarning(
                code=ACTIVE_EXTERNAL_CALL,
                message=(
                    f"stack-active transfer at {address:#x} crosses the analyzed "
                    "Program boundary; callback inheritance is not covered"
                ),
                function_start=hosts[address],
                addresses=(address,),
                details=external_details[address],
                origins=external_origins[address],
                external_targets=external[address],
            )
            for address in sorted(external)
        ) + tuple(
            AnalysisWarning(
                code="empty-call-target-set",
                message=(
                    f"compiler-provided function-pointer entry for call at {address:#x}"
                    " has an empty target set; no inherited stack state was propagated"
                ),
                function_start=hosts[address],
                addresses=(address,),
            )
            for address in sorted(empty_target_errors)
        )
        # Phase boundary: the inherited-marker view and the diagnostics are
        # part of propagation, so the closing sample is taken after both.
        monitor.end(
            inherited_functions=len(inherited),
            unresolved_active_calls=len(unresolved),
            active_external_calls=len(external),
        )
        return StackLivenessResult(
            by_function=merged,
            inherited_functions=frozenset(inherited),
            warnings=diagnostics,
            unresolved_live_calls=tuple(sorted(unresolved)),
            active_external_calls=tuple(sorted(external)),
            closed_external_calls=closed,
            inheritance_trace=InheritanceTrace(
                seed_edges=tuple(seed_edges.values()),
                first_cause=first_cause,
            ),
        )

    @staticmethod
    def _explain_activity(
        function: Function,
        local: StackFunctionLiveness,
        call_addr: int,
        *,
        caller_live: bool,
    ) -> tuple[tuple[str, ...], tuple[ActiveOrigin, ...]]:
        """Explain why a call site is stack-active.

        For each stack object live across the call, list the resolved vector
        stack writes (defs) that may have produced the live data and the
        vector stack reads (uses) that keep it live.  Special marker objects
        (caller-inherited / conservative / irreducible / VLEN frame) get a
        structured reason instead of an access list.

        The structured records and the prose lines are produced together:
        classification reads :class:`ActiveOrigin`, humans read the lines, and
        the two cannot drift apart when either is reworded.
        """

        instructions = function.instruction_by_address
        live = set(local.live_before.get(call_addr, frozenset()))
        if caller_live:
            live.add(StackObjectId("caller", "inherited-stack-data"))

        def describe(access: StackAccessKind, obj: StackObjectId) -> list[str]:
            addresses = sorted(
                address
                for address, item in local.accesses.items()
                if item.stack_id == obj and item.kind is access
            )
            return [
                f"{address:#x} `{instructions[address].text}`"
                for address in addresses
                if address in instructions
            ]

        details: list[str] = []
        origins: list[ActiveOrigin] = []
        for obj in sorted(live, key=str):
            kind = _ORIGIN_BY_SOURCE.get(obj.source)
            line = _ORIGIN_TEXT.get(kind, "")
            if line:
                details.append(line)
                origins.append(
                    _origin_record(
                        kind, obj, line, local=local, call_addr=call_addr
                    )
                )
                continue
            stores = describe(StackAccessKind.STORE, obj)
            loads = describe(StackAccessKind.LOAD, obj)
            if stores:
                detail = f"live stack object {obj}: vector stack write(s) at " + ", ".join(stores)
                if loads:
                    detail += "; read back at " + ", ".join(loads)
            else:
                detail = (
                    f"live stack object {obj}: no resolved vector stack write "
                    "recorded in this function"
                )
            details.append(detail)
            origins.append(
                ActiveOrigin(
                    origin=kind or ORIGIN_VECTOR_DATA,
                    object_source=obj.source,
                    object_id=str(obj),
                    detail=detail,
                )
            )
        if not details:
            line = (
                "no live stack objects recorded; activity was inherited from "
                "an upstream active caller"
            )
            details.append(line)
            origins.append(
                ActiveOrigin(
                    origin=ORIGIN_INHERITED,
                    object_source="caller",
                    object_id=str(StackObjectId("caller", "inherited-stack-data")),
                    detail=line,
                )
            )
        return tuple(details), tuple(origins)

    @staticmethod
    def _merge_inherited_marker(
        local_results: dict[int, StackFunctionLiveness],
        inherited: set[int],
    ) -> dict[int, StackFunctionLiveness]:
        marker = StackObjectId("caller", "inherited-stack-data")
        merged = dict(local_results)
        for function_start in inherited:
            local = local_results[function_start]
            # A read-only "base map + inherited marker" view instead of a
            # per-instruction copy: the inherited closure is typically large,
            # and each copy would retain one dict entry and one frozenset per
            # instruction of every function in it.
            merged[function_start] = replace(
                local,
                live_before=InheritedLivenessView(local.live_before, marker),
            )
        return merged


# endregion
