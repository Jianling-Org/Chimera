"""Track stack-frame state that depends on the hardware VLEN.

Vector-memory liveness answers whether vector data remains in a stack slot.
This module answers the separate question needed by migration: whether the
current scalar stack pointer still holds an allocation whose size could not be
proven independent of the hardware VLEN, or a VLEN-derived value is still being
prepared for such an allocation.

Three rules keep that answer honest:

* a stack adjustment is *proven safe* only when the size it subtracts is proven
  independent of ``vlenb``.  A load, a call result or an operation the scalar
  model cannot interpret is not such a proof, however precise its address
  expression happens to be - and conversely, "the value expression is unknown"
  is not by itself a reason to report a VLEN frame;
* the frame state propagates **along the CFG** from the adjustment, never over
  the whole function: a branch that cannot reach the adjustment is unaffected,
  and no unrelated region's warnings can be changed by shrinking this state.
  The function entry is not an exception - the state it is entered with is "no
  active frame", so a back edge that carries an active frame into the entry is
  merged rather than reset;
* once the frame state is active it is released only by an instruction that
  proves ``sp`` is back at a reliable function-entry base.  The restoring
  instruction itself stays unsafe, because its effect is only visible after it
  executes.
"""

from __future__ import annotations

from collections import deque

from ...core.algorithm.address_states import (
    EMPTY_STATES,
    AddressStateMap,
    address_domain,
)
from ...core.data_model import Function
from ...core.contracts import StackSemantics
from .dependencies import (
    DEPENDENCY_INDEPENDENT,
    DEPENDENCY_UNKNOWN,
    DEPENDENCY_VLEN,
    FunctionDependencyState,
    _read_scalar_registers,
    analyze_register_dependencies,
)
from .expressions import Expr, _affine_terms, vlen_dependency
from .instruction_facts import _instruction_predecessors
from .model import (
    AllocationOrigin,
    AnalysisWarning,
    FunctionExpressionResult,
    ScopeExclusion,
    StackObjectId,
)
from .scope import (
    ASSUME_SCALAR_INDEPENDENT,
    UNKNOWN_SCALAR_INDEPENDENCE_ASSUMPTION,
    normalize_unknown_stack_size_policy,
)


VLEN_STACK_FRAME = StackObjectId("vlen_stack_frame", "dynamic-sp")
VLEN_STACK_SETUP = StackObjectId("vlen_stack_setup", "dynamic-sp")

_FRAME_MARKER = frozenset({VLEN_STACK_FRAME})
_SETUP_MARKER = frozenset({VLEN_STACK_SETUP})

#: Stack-write classifications used while propagating the frame state.
_RELEASE = "release"        # proved back at a reliable stack base
_ADJUSTMENT = "adjustment"  # size not proven independent of VLEN
_INDEPENDENT = "independent"  # independent value that is not a proven base
#: An adjustment whose unproven size an origin proof discharged.  The frame
#: state is not created, and the release is recorded with its certificate.
_PROVEN = "proven-adjustment"
_EXCLUDED = "scope-excluded-adjustment"


def _contains_vlen(value: object) -> bool:
    if not isinstance(value, Expr):
        return False
    return value.kind == "vlenb" or any(
        _contains_vlen(argument) for argument in value.args
    )


def _is_known_stack_base(value: object) -> bool:
    if not isinstance(value, Expr) or _contains_vlen(value):
        return False
    affine = _affine_terms(value)
    if affine is None:
        return False
    coefficients, _constant = affine
    return coefficients == {Expr("input", ("sp",)): 1}


def _add_marker(
    entries: dict[int, frozenset[StackObjectId]],
    address: int,
    marker_set: frozenset[StackObjectId],
) -> None:
    """Add one marker to a sparse entry, allocating only when it is new."""

    current = entries.get(address)
    if current is None:
        entries[address] = marker_set
    elif marker_set.isdisjoint(current):
        entries[address] = current | marker_set


def _merge_marker(
    entries: dict[int, frozenset[StackObjectId]],
    addresses,
    marker_set: frozenset[StackObjectId],
) -> None:
    for address in addresses:
        _add_marker(entries, address, marker_set)


def _adjustment_level(
    address: int,
    dependencies: FunctionDependencyState,
) -> int:
    """Dependency level of the value a stack write leaves in ``sp``.

    The dataflow answer is the authority: it is a may-analysis over every
    reaching path, so it keeps an independence proof only when every path has
    one, and it keeps a VLEN-tainted loop-carried value when the expression
    model had to replace that register with a loop symbol.  "The value
    expression is unknown" is a *different* question, reported separately - it
    must not by itself turn into a VLEN stack frame.
    """

    return dependencies.level_after(address, "sp")


def _frame_live_before(
    address: int,
    live_after: dict[int, bool],
    predecessors: dict[int, set[int]],
) -> bool:
    """Whether the frame state is live when ``address`` starts executing.

    The state is a may-property: one reaching path that still holds an unproven
    allocation is enough, so a branch the adjustment cannot reach is never
    affected.  The function entry has no special case: the state it is entered
    with is "no active frame", which is the identity of this join, so a back
    edge that carries an active frame into the entry is merged rather than
    discarded.
    """

    return any(
        live_after.get(predecessor, False)
        for predecessor in predecessors.get(address, ())
    )


def _classify_stack_writes(
    function: Function,
    expressions: FunctionExpressionResult,
    semantics: StackSemantics,
    dependencies: FunctionDependencyState,
    predecessors: dict[int, set[int]],
    order: list[int],
    prover=None,
    discharge: dict[int, tuple[str, str]] | None = None,
    unknown_stack_size_policy: str = "conservative",
) -> tuple[
    dict[int, bool], dict[int, str], set[int], dict[int, bool], set[int], set[int]
]:
    """Propagate the frame state over the CFG and classify every ``sp`` write.

    Returns the frame state after each instruction, the classification of each
    ``sp`` write, the adjustment addresses, and for every adjustment whether
    its size could not be proven either way - the two answers are separate: an
    unprovable value is still an adjustment, and an adjustment can name a value
    that is perfectly precise.

    ``prover`` performs the follow-up query the frame rule stops at: an
    adjustment whose size is merely unproven is handed to the origin prover,
    and a complete proof turns it into ``_PROVEN`` - no frame state, with the
    certificate recorded in ``discharge``.  Everything the proof did *not*
    establish keeps the adjustment exactly as before.
    """

    instructions = function.instruction_by_address
    after = expressions.after_states
    sp_writes = frozenset(
        address
        for address in order
        if "sp" in semantics.written_scalar_registers(instructions[address])
    )
    classification: dict[int, str] = {}
    diagnosis: dict[int, bool] = {}
    excluded: set[int] = set()
    vlen_evidence: set[int] = set()
    live_after: dict[int, bool] = {}
    entry = order[0]
    worklist: deque[int] = deque([entry])
    queued = {entry}
    while worklist:
        address = worklist.popleft()
        queued.discard(address)
        outgoing = _frame_live_before(address, live_after, predecessors)
        if address in sp_writes:
            if _is_known_stack_base(after.get(address, {}).get("sp")):
                # Proved back at a reliable function-entry base.  The state is
                # released *after* this instruction, which stays unsafe.
                classification[address] = _RELEASE
                outgoing = False
            else:
                level = _adjustment_level(address, dependencies)
                dependency_budget_exhausted = (
                    dependencies.register_dependency_budget_exhausted
                )
                if level == DEPENDENCY_INDEPENDENT and not dependency_budget_exhausted:
                    classification[address] = _INDEPENDENT
                else:
                    # "Cannot be proven either way" is reported when *either*
                    # answer is unprovable: the value expression may be
                    # unreadable while the dataflow knows the value, or the
                    # value may read as an opaque input symbol while the
                    # dataflow knows the caller supplied it.
                    expression_level = vlen_dependency(
                        after.get(address, {}).get("sp")
                    )
                    unproven = (
                        dependency_budget_exhausted
                        or level == DEPENDENCY_UNKNOWN
                        or expression_level == DEPENDENCY_UNKNOWN
                    )
                    verdict = None
                    if unproven and prover is not None and not dependency_budget_exhausted:
                        verdict = prover.prove_adjustment(function, address)
                    proof_has_vlen = _proof_contains_vlen(
                        prover, getattr(verdict, "proof_id", None)
                    )
                    read_registers = getattr(
                        semantics, "read_scalar_registers", None
                    )
                    controlled_vlen = (
                        any(
                            dependencies.vlen_controlled_before(address, register)
                            for register in read_registers(instructions[address])
                        )
                        if callable(read_registers)
                        else False
                    ) or dependencies.vlen_controlled_after(address, "sp")
                    known_vlen = (
                        (level == DEPENDENCY_VLEN and not dependency_budget_exhausted)
                        or expression_level == DEPENDENCY_VLEN
                        or getattr(verdict, "status", None) == "vlen"
                        or proof_has_vlen
                        or controlled_vlen
                    )
                    opt_in_vlen_override = (
                        unknown_stack_size_policy == ASSUME_SCALAR_INDEPENDENT
                        and known_vlen
                    )
                    if opt_in_vlen_override:
                        vlen_evidence.add(address)
                    if (
                        verdict is not None
                        and verdict.proven
                        and not opt_in_vlen_override
                        and not dependency_budget_exhausted
                    ):
                        classification[address] = _PROVEN
                        if discharge is not None:
                            discharge[address] = (verdict.proof_id, verdict.reason)
                    elif (
                        unknown_stack_size_policy == ASSUME_SCALAR_INDEPENDENT
                        and unproven
                        and not opt_in_vlen_override
                        and not dependency_budget_exhausted
                    ):
                        classification[address] = _EXCLUDED
                        excluded.add(address)
                        diagnosis[address] = False
                        if discharge is not None and verdict is not None:
                            discharge[address] = (verdict.proof_id, verdict.reason)
                    else:
                        classification[address] = _ADJUSTMENT
                        diagnosis[address] = unproven and not opt_in_vlen_override
                        if discharge is not None and verdict is not None:
                            discharge[address] = (verdict.proof_id, verdict.reason)
                        outgoing = True
        previous = live_after.get(address)
        if previous is not None and previous == outgoing:
            continue
        live_after[address] = outgoing
        for successor in instructions[address].succ:
            if successor in instructions and successor not in queued:
                worklist.append(successor)
                queued.add(successor)

    adjustments = {
        address
        for address, kind in classification.items()
        if kind is _ADJUSTMENT
    }
    return live_after, classification, adjustments, diagnosis, excluded, vlen_evidence


def _proof_contains_vlen(prover, proof_id: str | None) -> bool:
    """Check the already-built proof DAG for any retained VLEN verdict."""

    if prover is None or proof_id is None:
        return False
    query = getattr(prover, "proof_reaches_status", None)
    return bool(query(proof_id, "vlen")) if callable(query) else False


def _setup_dependencies(
    function: Function,
    semantics: StackSemantics,
    dynamic_sp_writes: set[int],
    dependencies: FunctionDependencyState,
) -> tuple[set[int], set[int]]:
    """Return the VLEN setup region and the adjustments with no local source.

    For every stack adjustment, walk the CFG backwards over the registers that
    still carry a value not proven independent of VLEN.  The walk stops at the
    definition that removes the dependency, so the returned region is exactly
    the set of instructions that can reach the adjustment while that value is
    live - it is never extended by program order over unrelated branches.
    An adjustment whose value no read register carries (a load, a call result,
    an unmodelled operation) is returned in the second set instead.
    """

    predecessors = _instruction_predecessors(function)
    instructions = function.instruction_by_address
    setup: set[int] = set()
    unresolved: set[int] = set()

    for target in dynamic_sp_writes:
        instruction = instructions[target]
        needed = {
            register
            for register in _read_scalar_registers(semantics, instruction)
            if dependencies.level_before(target, register) != DEPENDENCY_INDEPENDENT
        }
        if not needed:
            # The adjustment consumes a value that no read register carries -
            # a load, a call result or an unmodelled operation.  Its source
            # cannot be pinned down, so the adjustment itself is the only
            # region that can be reported.
            unresolved.add(target)
            continue

        worklist: deque[tuple[int, frozenset[str]]] = deque(
            (predecessor, frozenset(needed))
            for predecessor in predecessors.get(target, ())
        )
        visited: set[tuple[int, frozenset[str]]] = set()
        while worklist:
            address, current = worklist.popleft()
            key = (address, current)
            if key in visited:
                continue
            visited.add(key)
            instruction = instructions[address]
            definitions = semantics.written_scalar_registers(instruction)
            relevant = definitions & current
            if not relevant:
                # The value stays live across an instruction that does not
                # touch its register; keep walking predecessors so the setup
                # region covers the instructions it can actually cross.
                if not any(
                    dependencies.level_before(address, register)
                    != DEPENDENCY_INDEPENDENT
                    for register in current
                ):
                    continue
                setup.add(address)
                for predecessor in predecessors.get(address, ()):
                    worklist.append((predecessor, current))
                continue
            setup.add(address)
            remaining = set(current - definitions)
            for register in _read_scalar_registers(semantics, instruction):
                if (
                    dependencies.level_before(address, register)
                    != DEPENDENCY_INDEPENDENT
                ):
                    remaining.add(register)
            if not remaining:
                continue
            for predecessor in predecessors.get(address, ()):
                worklist.append((predecessor, frozenset(remaining)))

    return setup, unresolved


def _size_register(
    semantics: StackSemantics,
    instruction,
    address: int,
    dependencies: FunctionDependencyState,
) -> str | None:
    """The register an adjustment subtracts, when one carries the size."""

    candidates = sorted(
        register
        for register in _read_scalar_registers(semantics, instruction)
        if register != "sp"
        and dependencies.level_before(address, register) != DEPENDENCY_INDEPENDENT
    )
    if candidates:
        return candidates[0]
    return None


def _release_set(
    order: list[int],
    classification: dict[int, str],
    instructions: dict[int, object],
    predecessors: dict[int, set[int]],
) -> set[int]:
    """Addresses that prove ``sp`` is back at the entry base."""

    return {
        address
        for address, kind in classification.items()
        if kind is _RELEASE
    }


def _nearest_release(
    adjustment: int,
    releases: set[int],
    instructions: dict[int, object],
) -> int | None:
    """The closest release an adjustment's frame state can end at.

    Reported for traceability only: the value is the smallest release address
    the adjustment can reach, which names the instruction that clears the
    frame state in the overwhelming majority of compiled functions.
    """

    if not releases:
        return None
    reachable: set[int] = set()
    visited = {adjustment}
    worklist = deque(instructions[adjustment].succ)
    while worklist:
        current = worklist.popleft()
        if current in visited:
            continue
        visited.add(current)
        instruction = instructions.get(current)
        if instruction is None:
            continue
        if current in releases:
            reachable.add(current)
            continue
        worklist.extend(instruction.succ)
    return min(reachable) if reachable else None


def analyze_vlen_stack_liveness(
    function: Function,
    expressions: FunctionExpressionResult,
    semantics: StackSemantics,
    *,
    domain: tuple[int, ...] | None = None,
    prover=None,
    origins: list | None = None,
    scope_exclusions: list | None = None,
    unknown_stack_size_policy: str = "conservative",
) -> tuple[AddressStateMap[int, frozenset[StackObjectId]], tuple[AnalysisWarning, ...]]:
    """Compute VLEN stack-frame markers before every instruction.

    The instruction that restores ``sp`` is still marked because its effect is
    only visible after execution.  The first instruction after a proven
    restore is therefore the first point that can become safe again.

    Only addresses carrying a marker are stored; every other address of the
    function resolves to the shared empty set.  ``domain`` may be supplied by a
    caller that already built the function address domain, so all per-address
    results of one function share one tuple.

    ``prover`` is the on-demand origin prover.  It is asked about every
    adjustment whose size is merely unproven, and a complete proof means the
    adjustment no longer creates frame state.  ``origins``, when given, is
    extended with one structured record per stack adjustment (discharged or
    not) so a report can name the allocation, its dependency verdict, the
    releasing instruction and the proof.
    """

    unknown_stack_size_policy = normalize_unknown_stack_size_policy(
        unknown_stack_size_policy
    )
    if domain is None:
        domain = address_domain(
            tuple(instruction.addr for instruction in function.insts)
        )
    entries: dict[int, frozenset[StackObjectId]] = {}
    warnings: list[AnalysisWarning] = []
    if not function.insts:
        return AddressStateMap(domain, EMPTY_STATES, entries), ()

    order = [instruction.addr for instruction in function.insts]
    dependencies = analyze_register_dependencies(
        function,
        semantics,
        capture_known_vlen_control=(
            unknown_stack_size_policy == ASSUME_SCALAR_INDEPENDENT
        ),
    )
    predecessors = _instruction_predecessors(function)
    discharge: dict[int, tuple[str, str]] = {}
    (
        live_after,
        classification,
        adjustments,
        diagnosis,
        excluded,
        vlen_evidence,
    ) = _classify_stack_writes(
        function,
        expressions,
        semantics,
        dependencies,
        predecessors,
        order,
        prover,
        discharge,
        unknown_stack_size_policy,
    )

    if origins is not None:
        instructions = function.instruction_by_address
        releases = _release_set(order, classification, instructions, predecessors)
        for address in order:
            kind = classification.get(address)
            if kind not in (_ADJUSTMENT, _PROVEN):
                continue
            proof_id, reason = discharge.get(address, (None, ""))
            # Keep the established complete-analysis report shape (including
            # an empty proof-reason string). Budget incompleteness is an
            # additional, explicit gap below.
            gaps = () if kind is _PROVEN else (reason,)
            if dependencies.register_dependency_budget_exhausted:
                gaps = (*gaps, "register-dependency-budget-exhausted")
            origins.append(
                AllocationOrigin(
                    source="vlen_stack_frame",
                    adjustment=address,
                    dependency=(
                        "vlen"
                        if address in vlen_evidence
                        else "unknown"
                        if kind is _ADJUSTMENT and diagnosis.get(address, False)
                        else "proven"
                        if kind is _PROVEN
                        else "vlen"
                    ),
                    size_register=_size_register(
                        semantics, instructions[address], address, dependencies
                    ),
                    release=_nearest_release(address, releases, instructions),
                    proof=proof_id,
                    gaps=gaps,
                )
            )

    if scope_exclusions is not None:
        instructions = function.instruction_by_address
        for address in order:
            if address not in excluded:
                continue
            scope_exclusions.append(
                ScopeExclusion(
                    source="vlen_stack_frame",
                    function_start=function.start,
                    adjustment=address,
                    dependency="unknown",
                    size_register=_size_register(
                        semantics, instructions[address], address, dependencies
                    ),
                    disposition="assumption",
                    assumption=UNKNOWN_SCALAR_INDEPENDENCE_ASSUMPTION,
                    proof=discharge.get(address, (None, ""))[0],
                    gaps=(discharge[address][1],) if address in discharge else (),
                )
            )

    for address in order:
        if address in adjustments or _frame_live_before(
            address, live_after, predecessors
        ):
            _add_marker(entries, address, _FRAME_MARKER)

    # Diagnostics are rendered in program order so one function always exports
    # the same warning sequence, whatever order the work list visited.
    for address in order:
        if address in adjustments:
            if not diagnosis.get(address, False):
                continue
            warnings.append(
                AnalysisWarning(
                    code="unknown-vlen-stack-adjustment",
                    message=(
                        f"stack adjustment at {address:#x} subtracts a value "
                        "whose dependence on the hardware vlenb could not be "
                        "proven either way"
                    ),
                    function_start=function.start,
                    addresses=(address,),
                )
            )
        elif classification.get(address) in (_INDEPENDENT, _PROVEN):
            if _frame_live_before(address, live_after, predecessors):
                warnings.append(
                    AnalysisWarning(
                        code="unproven-vlen-stack-restoration",
                        message=(
                            f"stack restoration at {address:#x} does not prove "
                            "sp equals the function-entry stack base plus a constant"
                        ),
                        function_start=function.start,
                        addresses=(address,),
                    )
                )

    if dependencies.register_dependency_budget_exhausted:
        uncertain_adjustments = tuple(sorted(adjustments))
        if uncertain_adjustments:
            warnings.append(
                AnalysisWarning(
                    code="register-dependency-budget-exhausted",
                    message=(
                        f"register VLEN dependency analysis for function "
                        f"{function.name} ({function.start:#x}) exhausted its "
                        "update budget; affected stack adjustments remain "
                        "active, with their dependency status recorded separately"
                    ),
                    function_start=function.start,
                    addresses=uncertain_adjustments,
                )
            )

    setup, unresolved = _setup_dependencies(
        function, semantics, adjustments, dependencies
    )
    _merge_marker(entries, setup, _SETUP_MARKER)

    if unresolved:
        warnings.append(
            AnalysisWarning(
                code="unresolved-vlen-stack-setup",
                message=(
                    f"function {function.name} ({function.start:#x}) contains a "
                    "VLEN-dependent stack adjustment whose scalar dependency "
                    "could not be resolved"
                ),
                function_start=function.start,
                addresses=tuple(sorted(unresolved)),
            )
        )

    return AddressStateMap(domain, EMPTY_STATES, entries), tuple(warnings)


__all__ = [
    "VLEN_STACK_FRAME",
    "VLEN_STACK_SETUP",
    "analyze_vlen_stack_liveness",
]
