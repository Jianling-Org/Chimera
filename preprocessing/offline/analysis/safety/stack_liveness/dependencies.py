"""Per-function register dependency on the hardware VLEN.

The stack-frame analysis has to answer a question that is *not* the same as
"is this address expression precise": a stack-pointer adjustment may have a
perfectly precise symbolic value that is nevertheless built from a memory load
or from an operation the scalar model does not interpret - and such a value can
still be VLEN-sized.  This module carries that separate answer:

* :data:`DEPENDENCY_INDEPENDENT` - a *proof* that the value was not derived
  from ``vlenb``;
* :data:`DEPENDENCY_VLEN` - the value consumes a ``vlenb`` read;
* :data:`DEPENDENCY_UNKNOWN` - neither can be proven.

The function entry is treated as an *extra in-edge*, not as a reset: a value
that arrives from the caller is controlled by the caller (which may have read
``vlenb`` before the call), so nothing but ``zero`` and the entry ``sp`` - the
reference the frame is measured against - starts out proven.  A back edge that
targets the entry is joined with that external state, so a value carried around
a loop into the entry keeps its taint.

That external state is the *default* of the per-register lattice, not a
property of the entry instruction:

* a register no state entry mentions reads back as
  :data:`DEPENDENCY_UNKNOWN` - "this function never proved anything about it";
* only ``zero`` and ``sp`` read back as :data:`DEPENDENCY_INDEPENDENT`, and a
  register may be *proved* independent at any later point by writing a value
  the function computed from constants.

A state entry therefore records a *deviation from that default*, which is what
keeps the storage sparse (ordinary code stores nothing) while making it
impossible for "the register is simply not in the dictionary" to be mistaken
for an independence proof - the bug that let a caller-supplied stack size look
independent one instruction after the entry.

The analysis is a forward may-dataflow over the instruction CFG with a finite
three-level lattice per register, so it converges with a bounded work list and
never builds a growing expression: a register written inside a loop simply
joins the levels of every path reaching the write, which is what keeps a
VLEN-tainted loop-carried value from being reset to "independent" at the loop
header.

The transfer function delegates to the very same symbolic semantics the
expression analysis uses - through a marker state in which each register stands
for its current level - so a newly modelled instruction cannot silently
disagree with this classification.  The model's answer is then clamped by the
levels of the operands, which both keeps the transfer monotone and makes sure
an unmodellable operation can never end up "independent" by accident.

Results live only for the current function: the caller keeps them in local
variables and they are released with the function's analysis.
"""

from __future__ import annotations

from collections import deque

from ...core.algorithm.address_states import (
    EMPTY_STATES,
    AddressStateMap,
    address_domain,
)
from ...core.contracts import StackSemantics
from ...core.data_model import Function
from ...core.algorithm.graph import immediate_dominators
from .expressions import (
    DEPENDENCY_INDEPENDENT,
    DEPENDENCY_UNKNOWN,
    DEPENDENCY_VLEN,
    Constant,
    Expr,
    Input,
    Unknown,
    vlen_dependency,
)
from .instruction_facts import _instruction_predecessors

__all__ = [
    "DEPENDENCY_INDEPENDENT",
    "DEPENDENCY_UNKNOWN",
    "DEPENDENCY_VLEN",
    "FunctionDependencyState",
    "analyze_register_dependencies",
]


def _read_scalar_registers(semantics: StackSemantics, instruction) -> set[str]:
    """Read optional scalar dependency facts from the architecture adapter."""
    reader = getattr(semantics, "read_scalar_registers", None)
    return set(reader(instruction)) if callable(reader) else set()


def _vlen_marker(register: str):
    """A VLEN-dependent stand-in for one register.

    The marker carries the register name so that two different registers can
    never cancel each other in the abstract transfer: with one shared ``VLENB``
    atom, ``sub sp,sp,a0`` would abstract to ``VLENB - VLENB = 0`` and the
    state could move *down* from VLEN to independent, which would make the
    work list oscillate instead of converging.  Markers only ever exist inside
    one ``_transfer`` call and are never stored in a result.
    """

    return Expr("vlenb", (register,))


#: Upper bound on state updates per function.  The lattice is finite and the
#: transfer is monotone, so this is never reached in practice; it exists so a
#: future transfer that loses monotonicity widens instead of hanging.
_MAX_UPDATES_FACTOR = 4
_MAX_UPDATES_FLOOR = 256

#: Registers whose entry value is proven by the call itself: ``zero`` is a
#: constant and the entry ``sp`` is the reference the stack frame is measured
#: against.  Every other register arrives from the caller, which may have
#: derived it from ``vlenb``.
_ENTRY_PROVEN_REGISTERS = frozenset({"zero", "sp"})


def _baseline(register: str) -> int:
    """Level of a register that no state entry mentions.

    The default is *unproven*, not independent.  A register the analysis never
    saw a proof for is exactly the case the caller controls: assuming
    independence here would let a caller-supplied stack size pass as safe one
    instruction after the entry, which is the failure this module exists to
    avoid.
    """

    if register in _ENTRY_PROVEN_REGISTERS:
        return DEPENDENCY_INDEPENDENT
    return DEPENDENCY_UNKNOWN


def _entry_external(register: str, level: int) -> int:
    """Join the caller's in-edge onto one register level.

    The entry is reached from outside the function *in addition to* its real
    predecessors, and that edge proves nothing about a register it passes in.
    ``level_before`` and the solver both apply this, so the queried state and
    the solved state cannot diverge.
    """

    if register in _ENTRY_PROVEN_REGISTERS:
        return level
    return max(level, DEPENDENCY_UNKNOWN)


class FunctionDependencyState:
    """VLEN dependency level of every scalar register of one function.

    ``after`` holds each register whose level *deviates from the baseline* of
    :func:`_baseline`: a register written with a value proven independent, or
    one that carries a VLEN/unproven value.  A register no entry mentions is
    unproven by default (``zero`` and ``sp`` excepted), so the compact
    representation can never turn "not tracked" into an independence proof.

    The level *before* an instruction is the join over its predecessors - plus,
    at the entry, the unproven external state: that finite-lattice merge is
    exactly what keeps an independence proof only when every reaching path
    proves it, and what keeps a VLEN-tainted value carried back into the
    function entry from being merged away.
    """

    __slots__ = (
        "_after", "_predecessors", "_reached", "_entry", "_control",
        "_vlen_controlled", "_widened_after_vlen_guard",
        "_known_control_fallback",
        "_register_dependency_budget_exhausted",
    )

    def __init__(
        self,
        after: AddressStateMap[int, frozenset[tuple[str, int]]],
        predecessors: dict[int, set[int]],
        reached: frozenset[int],
        entry: int | None,
        control: frozenset[int] = frozenset(),
        vlen_controlled: dict[int, frozenset[str]] | None = None,
        widened_after_vlen_guard: bool = False,
        known_control_fallback: bool = False,
        register_dependency_budget_exhausted: bool = False,
    ) -> None:
        self._after = after
        self._predecessors = predecessors
        self._reached = reached
        self._entry = entry
        self._control = control
        # Sparse per-address value provenance, populated only when a value is
        # written under a branch whose condition is known to depend on vlenb.
        self._vlen_controlled = vlen_controlled or {}
        self._widened_after_vlen_guard = widened_after_vlen_guard
        self._known_control_fallback = known_control_fallback
        self._register_dependency_budget_exhausted = (
            register_dependency_budget_exhausted
        )

    def vlen_controlled_before(self, address: int, register: str) -> bool:
        """Whether a reaching value of ``register`` was selected by known VLEN control.

        This is separate from the historical three-level lattice: it preserves
        evidence through a branch that selects among scalar constants, without
        changing default frame classification or making an unknown guard look
        like a VLEN guard.
        """

        if self._widened_after_vlen_guard:
            return True
        return any(
            register in self._vlen_controlled.get(predecessor, ())
            for predecessor in self._predecessors.get(address, ())
        )

    def vlen_controlled_after(self, address: int, register: str) -> bool:
        """Whether the value after this instruction carries known guard evidence."""

        return self._widened_after_vlen_guard or register in self._vlen_controlled.get(
            address, ()
        )

    def control_dependent(self, address: int) -> bool:
        """Whether ``address`` is reached under a condition not proven independent.

        The program point is control-dependent on a branch whose condition was
        not proven independent of ``vlenb``: a constant selected by such a
        branch is *not* an independence proof, however constant its value
        expression is.
        """

        return address in self._control

    @property
    def known_control_fallback(self) -> bool:
        """Whether structural VLEN-control precision used a conservative fallback.

        This is a non-proof gap: retained values stay conservatively active
        when the CFG has no reliable postdominator or the graph budget is hit.
        It does not establish that a particular allocation is sized by VLEN.
        """

        return self._known_control_fallback

    @property
    def register_dependency_budget_exhausted(self) -> bool:
        """Whether the register dataflow stopped before reaching a fixed point."""

        return self._register_dependency_budget_exhausted

    def level_after(self, address: int, register: str) -> int:
        """Level of ``register`` after ``address``.

        An address the dataflow never reached answers ``DEPENDENCY_UNKNOWN``:
        "no state" must never be read as "proven independent".  A reached
        address answers the stored deviation if there is one, and the baseline
        otherwise.
        """

        if address not in self._reached:
            return DEPENDENCY_UNKNOWN
        for name, level in self._after[address]:
            if name == register:
                return level
        return _baseline(register)

    def level_before(self, address: int, register: str) -> int:
        """Level of ``register`` before ``address`` (join over predecessors)."""

        if address not in self._reached:
            return DEPENDENCY_UNKNOWN
        # The fold starts at the lattice bottom, not at the baseline: a
        # predecessor that has no entry for this register already contributes
        # ``_baseline(register)`` through ``level_after``, so seeding the
        # baseline here would *raise* the join above a proof every predecessor
        # agreed on.
        level = DEPENDENCY_INDEPENDENT
        for predecessor in self._predecessors.get(address, ()):
            if predecessor not in self._reached:
                # Not reachable from the function entry, so the dataflow has
                # no state for it at all.  Contribute "nothing is proven"
                # rather than pretending the register was proven independent.
                candidate = DEPENDENCY_UNKNOWN
            else:
                candidate = self.level_after(predecessor, register)
            if candidate > level:
                level = candidate
        if address == self._entry:
            # The function is also entered from outside, which is an extra
            # in-edge next to these predecessors.
            level = _entry_external(register, level)
        return level

    @property
    def entries(self) -> int:
        """Number of retained register states that deviate from the baseline."""

        return self._after.entry_count


#: Control-dependence policies for the forward dataflow.
#: ``off``   - value dependence only (the historical behaviour).
#: ``vlen``  - a branch whose condition provably consumes ``vlenb`` selects the
#:             code it guards, so constants written there are not a proof.
#: ``unproven`` - any branch whose condition is *not proven independent* does
#:             the same.  This is the policy the frame analysis uses: "the
#:             condition is not proven independent" and "the branch could be
#:             VLEN-selected" are the same statement about the same missing
#:             proof.
CONTROL_DEPENDENCE_OFF = "off"
CONTROL_DEPENDENCE_VLEN = "vlen"
CONTROL_DEPENDENCE_UNPROVEN = "unproven"


def _is_conditional_branch(semantics: StackSemantics, instruction) -> bool:
    """Whether ``instruction`` selects the execution of its successors."""

    if semantics.is_call_instruction(instruction):
        return False
    if len(instruction.succ) >= 2:
        return True
    # A taken branch that happens to have one successor in this CFG (a loop
    # whose fall-through is unreachable) still guards both directions.
    return instruction.op.startswith("b") and len(instruction.succ) == 1


def _is_known_control_branch(semantics: StackSemantics, instruction) -> bool:
    """Recognize real split conditions for the new structural analysis only.

    Preserve the older generic predicate for the legacy three-level lattice.
    When the architecture exposes condition operands, a one-successor
    instruction is a branch only if that adapter identifies its condition;
    this avoids treating bit-manipulation mnemonics such as ``bset`` as
    control flow.
    """

    if semantics.is_call_instruction(instruction):
        return False
    if len(instruction.succ) >= 2:
        return True
    reader = getattr(semantics, "condition_scalar_registers", None)
    if callable(reader):
        return bool(reader(instruction))
    return instruction.op.startswith("b") and len(instruction.succ) == 1


def _known_control_dependence(
    function: Function, semantics: StackSemantics
) -> tuple[dict[int, frozenset[int]], frozenset[int], bool]:
    """Build a bounded direct control-dependence relation for reachable code.

    Postdominators are computed on the reverse instruction CFG rooted at a
    virtual exit connected to explicit returns and conservative divergence
    exits.  These extra exits model unresolved terminal instructions and
    reachable regions with no return, so a branch cannot appear reconverged
    merely because one arm disappears from the postdominator graph.  Direct
    controller edges (rather than one full
    region set per branch) keep storage linear for ordinary CFGs.  A strict
    edge budget protects degenerate graphs; exceeding it falls back to
    function-wide conservatism for known guards.
    """

    instructions = function.instruction_by_address
    if not function.insts or not any(
        _is_known_control_branch(semantics, instruction)
        for instruction in function.insts
    ):
        return {}, frozenset(), False
    entry = function.insts[0].addr
    reachable: set[int] = set()
    pending = [entry]
    while pending:
        address = pending.pop()
        if address in reachable or address not in instructions:
            continue
        reachable.add(address)
        pending.extend(
            successor
            for successor in instructions[address].succ
            if successor in instructions and successor not in reachable
        )

    def successors(address: int) -> tuple[int, ...]:
        return tuple(
            target
            for target in instructions[address].succ
            if target in reachable
        )

    # Avoid repeatedly scanning all instructions for reverse edges. This map
    # also supports the single reverse reachability pass below.
    cfg_predecessors: dict[int, set[int]] = {address: set() for address in reachable}
    for source in reachable:
        for target in successors(source):
            cfg_predecessors[target].add(source)

    returns = {
        address
        for address in reachable
        if instructions[address].is_return or instructions[address].op == "ret"
    }
    can_reach_return = set(returns)
    pending = list(returns)
    while pending:
        address = pending.pop()
        for predecessor in cfg_predecessors[address]:
            if predecessor not in can_reach_return:
                can_reach_return.add(predecessor)
                pending.append(predecessor)
    divergence_exits = {
        address
        for address in reachable
        if address not in can_reach_return
        or any(target not in can_reach_return for target in successors(address))
    }
    if not returns:
        return {}, frozenset(
            address
            for address in reachable
            if _is_known_control_branch(semantics, instructions[address])
        ), True
    # An object sentinel cannot collide with a decoded instruction address.
    virtual_exit = object()
    reverse_nodes = [virtual_exit, *sorted(reachable)]

    def reverse_successors(node):
        if node is virtual_exit:
            return returns | divergence_exits
        return cfg_predecessors[node]

    def reverse_predecessors(node):
        if node is virtual_exit:
            return ()
        result = set(successors(node))
        if node in returns or node in divergence_exits:
            result.add(virtual_exit)
        return result

    post_idom = immediate_dominators(
        reverse_nodes,
        successors=reverse_successors,
        predecessors=reverse_predecessors,
    )

    # Retain unsafe guard identity. Its effect is propagated dynamically by
    # the solver only when that specific guard is known to depend on VLEN.
    unsafe_guards: set[int] = set()
    controlled_by: dict[int, set[int]] = {}
    edge_budget = max(32, 8 * len(reachable) + 4 * sum(len(successors(a)) for a in reachable))
    edges_added = 0
    budget_exhausted = False
    for branch in sorted(reachable):
        instruction = instructions[branch]
        if not _is_known_control_branch(semantics, instruction):
            continue
        branch_successors = successors(branch)
        join = post_idom.get(branch)
        if len(branch_successors) < 2 or join is None:
            unsafe_guards.add(branch)
            continue

        branch_edges: list[int] = []
        valid = True
        for successor in branch_successors:
            current = successor
            seen: set[int] = set()
            while current != join:
                if current is virtual_exit or current in seen:
                    valid = False
                    break
                seen.add(current)
                branch_edges.append(current)
                current = post_idom.get(current)
                if current is None:
                    valid = False
                    break
            if not valid:
                break
        if not valid:
            unsafe_guards.add(branch)
            continue
        if edges_added + len(branch_edges) > edge_budget:
            budget_exhausted = True
            break
        for dependent in branch_edges:
            controlled_by.setdefault(dependent, set()).add(branch)
        edges_added += len(branch_edges)

    if budget_exhausted:
        unsafe_guards.update(
            address
            for address in reachable
            if _is_known_control_branch(semantics, instructions[address])
        )
        return {}, frozenset(unsafe_guards), True

    return (
        {address: frozenset(sources) for address, sources in controlled_by.items()},
        frozenset(unsafe_guards),
        bool(unsafe_guards),
    )


class _DependencySolver:
    """Forward may-dataflow of register dependency levels over one CFG."""

    def __init__(
        self,
        semantics: StackSemantics,
        *,
        control_dependence: str = CONTROL_DEPENDENCE_OFF,
        capture_known_vlen_control: bool = False,
    ) -> None:
        self._semantics = semantics
        self._symbolic = semantics.symbolic
        self._control_dependence = control_dependence
        self._capture_known_vlen_control = capture_known_vlen_control
        # Per-function memo of the write set: ``written_scalar_registers``
        # depends only on the mnemonic and operands, and the same instruction
        # is asked for it once per work-list visit.  ``auipc`` also depends on
        # the address, so it is never memoised.
        self._written_cache: dict[
            tuple[str, tuple[str, ...]], frozenset[str]
        ] = {}

    def _written(self, instruction) -> frozenset[str]:
        if instruction.op == "auipc":
            return frozenset(self._semantics.written_scalar_registers(instruction))
        # Operand lists are lists after hand-built fixtures and tuples after
        # parsing, so the memo key normalises to a tuple.
        key = (instruction.op, tuple(instruction.args))
        cached = self._written_cache.get(key)
        if cached is None:
            written = set(self._semantics.written_scalar_registers(instruction))
            # A call is a definition of every caller-saved register, not just
            # of the link register the encoding names: a value kept across a
            # call is not the value that was there before it.  What the new
            # value is only a callee summary can say, so the transfer leaves
            # those registers at the unproven default.
            clobbered = getattr(
                self._semantics, "call_clobbered_scalar_registers", None
            )
            if callable(clobbered):
                written |= clobbered(instruction)
            cached = frozenset(written)
            self._written_cache[key] = cached
        return cached

    def _transfer(
        self,
        instruction,
        incoming: dict[str, int],
        *,
        control_tainted: bool = False,
    ) -> dict[str, int]:
        writes = self._written(instruction)
        if not writes:
            return incoming

        reads = _read_scalar_registers(self._semantics, instruction)
        marker_state: dict[str, object] = {"zero": Constant(0)}
        strongest_read = DEPENDENCY_INDEPENDENT
        for register in reads:
            level = incoming.get(register, _baseline(register))
            if level > strongest_read:
                strongest_read = level
            if level == DEPENDENCY_VLEN:
                marker_state[register] = _vlen_marker(register)
            elif level == DEPENDENCY_UNKNOWN:
                marker_state[register] = Unknown
            else:
                marker_state[register] = Input(register)

        after = self._symbolic.transfer_instruction(instruction, marker_state)
        outgoing = incoming
        for register in writes:
            # The model's own answer for the written value, clamped by what the
            # operands already carried.  The clamp is what keeps the transfer
            # monotone: a value can only be as independent as every operand it
            # was computed from, even when the abstract marker transfer happens
            # to simplify the result away.
            level = max(vlen_dependency(after.get(register)), strongest_read)
            if level == DEPENDENCY_INDEPENDENT and control_tainted:
                # The value is a constant, but a branch whose condition is not
                # proven independent selected the code that wrote it.  The
                # constant is therefore VLEN-selected data - a frame size
                # chosen by such a branch must not be reported as fixed.
                level = DEPENDENCY_UNKNOWN
            if incoming.get(register, _baseline(register)) == level:
                continue
            if outgoing is incoming:
                outgoing = dict(incoming)
            if level == _baseline(register):
                # Back at the default: the register carries neither a proof nor
                # a taint, so the compact form drops it instead of storing a
                # redundant entry.
                outgoing.pop(register, None)
            else:
                outgoing[register] = level
        return outgoing

    def _control_of_condition(
        self,
        instruction,
        incoming: dict[str, int],
        incoming_control: bool,
        incoming_vlen_controlled: frozenset[str] = frozenset(),
    ) -> bool:
        """Whether this branch's successors become control-dependent on VLEN."""

        if self._control_dependence == CONTROL_DEPENDENCE_OFF:
            return False
        if incoming_control:
            return True
        reader = getattr(self._semantics, "condition_scalar_registers", None)
        reads = set(reader(instruction)) if callable(reader) else set()
        if not reads:
            # Architectures without a branch-condition surface: fall back to
            # the generic read set, which is the conservative choice.
            reads = _read_scalar_registers(self._semantics, instruction)
        if not reads:
            return False
        levels = [incoming.get(register, _baseline(register)) for register in reads]
        if self._control_dependence == CONTROL_DEPENDENCE_VLEN:
            return max(levels) == DEPENDENCY_VLEN
        return max(levels) != DEPENDENCY_INDEPENDENT

    def _known_vlen_condition(
        self, instruction, incoming: dict[str, int], incoming_vlen_controlled: frozenset[str]
    ) -> bool:
        reader = getattr(self._semantics, "condition_scalar_registers", None)
        reads = set(reader(instruction)) if callable(reader) else set()
        if not reads:
            reads = _read_scalar_registers(self._semantics, instruction)
        return bool(reads) and (
            any(incoming.get(register, _baseline(register)) == DEPENDENCY_VLEN for register in reads)
            or bool(reads & incoming_vlen_controlled)
        )

    def solve(self, function: Function) -> FunctionDependencyState:
        instructions = function.instruction_by_address
        predecessors = _instruction_predecessors(function)
        control_sources, conservative_control_nodes, control_fallback = (
            _known_control_dependence(function, self._semantics)
            if self._capture_known_vlen_control
            else ({}, frozenset(), False)
        )
        dependents_by_controller: dict[int, set[int]] = {}
        for dependent, controllers in control_sources.items():
            for controller in controllers:
                dependents_by_controller.setdefault(controller, set()).add(dependent)
        domain = address_domain(
            tuple(instruction.addr for instruction in function.insts)
        )
        outgoing: dict[int, dict[str, int]] = {}
        control: set[int] = set()
        vlen_controlled: dict[int, frozenset[str]] = {}
        known_control_taints: dict[int, bool] = {}
        known_control_activity: dict[int, bool] = {}
        unbounded_control_taints: dict[int, bool] = {}
        # Addresses whose successors are control-dependent on a condition that
        # is not proven independent (including transitive taint).
        taints: dict[int, bool] = {}
        if not function.insts:
            return FunctionDependencyState(
                AddressStateMap(domain, EMPTY_STATES),
                predecessors,
                frozenset(),
                None,
            )

        entry = function.insts[0].addr
        worklist: deque[int] = deque([entry])
        queued = {entry}
        budget = _MAX_UPDATES_FACTOR * len(domain) + _MAX_UPDATES_FLOOR
        while worklist:
            if budget <= 0:
                # The partial worklist is not a fixed point. Discard it instead
                # of turning a previously observed guard into global VLEN
                # provenance. The explicit status lets frame analysis retain
                # UNKNOWN adjustments and report this incomplete proof.
                return FunctionDependencyState(
                    AddressStateMap(domain, EMPTY_STATES),
                    predecessors,
                    frozenset(),
                    None,
                    frozenset(domain),
                    known_control_fallback=(
                        control_fallback or bool(conservative_control_nodes)
                    ),
                    register_dependency_budget_exhausted=True,
                )
            budget -= 1
            address = worklist.popleft()
            queued.discard(address)
            instruction = instructions[address]
            incoming = self._join(address, entry, predecessors, outgoing)
            incoming_control = any(
                taints.get(predecessor, False)
                for predecessor in predecessors.get(address, ())
            )
            incoming_vlen_controlled = frozenset(
                register
                for predecessor in predecessors.get(address, ())
                for register in vlen_controlled.get(predecessor, ())
            ) if self._capture_known_vlen_control else frozenset()
            incoming_unbounded_control = any(
                unbounded_control_taints.get(predecessor, False)
                for predecessor in predecessors.get(address, ())
            ) if self._capture_known_vlen_control else False
            incoming_known_control = (
                any(
                    known_control_taints.get(controller, False)
                    for controller in control_sources.get(address, ())
                )
                or incoming_unbounded_control
            ) if self._capture_known_vlen_control else False
            state = self._transfer(
                instruction, incoming, control_tainted=incoming_control
            )
            reads = _read_scalar_registers(self._semantics, instruction) if self._capture_known_vlen_control else set()
            known_guard_here = self._capture_known_vlen_control and _is_known_control_branch(
                self._semantics, instruction
            ) and self._known_vlen_condition(
                instruction, incoming, incoming_vlen_controlled
            )
            writes = self._written(instruction)
            if self._capture_known_vlen_control:
                next_controlled = set(incoming_vlen_controlled)
                for register in writes:
                    next_controlled.discard(register)
                    if incoming_known_control or bool(reads & incoming_vlen_controlled):
                        next_controlled.add(register)
                controlled_state = frozenset(next_controlled)
            else:
                controlled_state = frozenset()
            # Structural control dependence ends at reliable postdominators.
            # Only an active known guard is carried on the control-dependence
            # graph; selected value provenance below remains in its register
            # and therefore survives a join independently of this region.
            taints_known_here = (
                _is_known_control_branch(self._semantics, instruction)
                and (incoming_known_control or known_guard_here)
                if self._capture_known_vlen_control
                else False
            )
            unbounded_taint_here = (
                incoming_unbounded_control
                or (address in conservative_control_nodes and taints_known_here)
            ) if self._capture_known_vlen_control else False
            taints_here = incoming_control or (
                _is_conditional_branch(self._semantics, instruction)
                and self._control_of_condition(
                    instruction, incoming, incoming_control
                )
            )
            # ``None`` marks "never visited": an empty state is a legitimate
            # result (the instruction leaves every register independent) and
            # must still propagate to the successors.  A late control taint
            # also re-runs the instruction, because it raises the level of the
            # constants written there.
            previous = outgoing.get(address)
            if (
                previous is not None
                and state == previous
                and taints.get(address) == taints_here
                and (
                    not self._capture_known_vlen_control
                    or (
                        vlen_controlled.get(address, frozenset()) == controlled_state
                        and known_control_activity.get(address, False) == incoming_known_control
                        and known_control_taints.get(address, False) == taints_known_here
                        and unbounded_control_taints.get(address, False) == unbounded_taint_here
                    )
                )
            ):
                continue
            outgoing[address] = state
            taints[address] = taints_here
            if self._capture_known_vlen_control and incoming_known_control:
                known_control_activity[address] = True
            else:
                known_control_activity.pop(address, None)
            if self._capture_known_vlen_control and controlled_state:
                vlen_controlled[address] = controlled_state
            else:
                vlen_controlled.pop(address, None)
            guard_was_active = known_control_taints.get(address, False)
            if self._capture_known_vlen_control and taints_known_here:
                known_control_taints[address] = True
            else:
                known_control_taints.pop(address, None)
            if self._capture_known_vlen_control and unbounded_taint_here:
                unbounded_control_taints[address] = True
            else:
                unbounded_control_taints.pop(address, None)
            if incoming_control:
                control.add(address)
            if self._capture_known_vlen_control and guard_was_active != taints_known_here:
                for dependent in sorted(dependents_by_controller.get(address, ())):
                    if dependent not in queued:
                        worklist.append(dependent)
                        queued.add(dependent)
            for successor in sorted(instruction.succ):
                if successor in instructions and successor not in queued:
                    worklist.append(successor)
                    queued.add(successor)

        entries = {
            address: frozenset(state.items())
            for address, state in outgoing.items()
            if state
        }
        return FunctionDependencyState(
            AddressStateMap(domain, EMPTY_STATES, entries),
            predecessors,
            frozenset(outgoing),
            entry,
            frozenset(control),
            vlen_controlled,
            known_control_fallback=(
                control_fallback or bool(conservative_control_nodes)
            ),
        )

    @staticmethod
    def _join(
        address: int,
        entry: int,
        predecessors: dict[int, set[int]],
        outgoing: dict[int, dict[str, int]],
    ) -> dict[str, int]:
        """Join the levels of every register over the predecessors of ``address``.

        Only registers some predecessor *mentions* need an entry: a register no
        predecessor mentions is at :func:`_baseline` on every incoming path, so
        the join is the baseline as well.  A predecessor without state was
        never reached by the dataflow, and contributes "nothing proven" instead
        of an accidental independence proof.

        A back edge may target the entry, so its real predecessors are joined
        rather than replaced; the unproven external state is applied on top by
        :func:`_entry_external`, which is the same rule ``level_before`` uses.
        """

        registers: set[str] = set()
        incoming_predecessors = predecessors.get(address, ())
        for predecessor in incoming_predecessors:
            registers.update(outgoing.get(predecessor, ()))
        if not registers:
            return {}

        incoming: dict[str, int] = {}
        for register in registers:
            level = DEPENDENCY_INDEPENDENT
            for predecessor in incoming_predecessors:
                state = outgoing.get(predecessor)
                candidate = (
                    DEPENDENCY_UNKNOWN
                    if state is None
                    else state.get(register, _baseline(register))
                )
                if candidate > level:
                    level = candidate
            if address == entry:
                level = _entry_external(register, level)
            if level != _baseline(register):
                incoming[register] = level
        return incoming


def analyze_register_dependencies(
    function: Function,
    semantics: StackSemantics,
    *,
    control_dependence: str = CONTROL_DEPENDENCE_UNPROVEN,
    capture_known_vlen_control: bool = False,
) -> FunctionDependencyState:
    """Compute the VLEN dependency level of every register of ``function``.

    Control dependence is on by default: a constant written under a branch
    whose condition is not proven independent is not an independence proof.
    ``control_dependence="off"`` reproduces the purely data-driven levels used
    before that rule existed.
    """

    return _DependencySolver(
        semantics,
        control_dependence=control_dependence,
        capture_known_vlen_control=capture_known_vlen_control,
    ).solve(function)
