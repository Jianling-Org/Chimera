"""On-demand origin proofs for unproven VLEN stack adjustments.

The frame analysis marks a stack adjustment whose size it cannot prove
independent of ``vlenb``.  That mark is honest but coarse: it says "not
proven", which covers two very different situations - a size that really is
VLEN-derived, and a size that comes from a load or a call whose provenance was
never looked at.  This module answers the follow-up question *for those
adjustments only*:

    is the value this adjustment subtracts independent of ``vlenb``?

The answer is a :class:`~...model.OriginProof` node with a closed-vocabulary
``reason``, so a consumer never has to parse prose, and a mark is only cleared
when the proof is complete.  Four rules make the answer trustworthy:

* **the query is demand-driven.**  Nothing is computed for a register or a
  memory range unless an unproven stack adjustment depends on it. The scalar
  cache analysis additionally requests bounded register-only leaf effects
  only where hardware-width state reaches a call;
* **memory is only believed when it is accounted for.**  A load is proven only
  when *every* reaching write to that object and byte range is itself proven,
  with complete coverage.  A partial write, a write through a pointer that
  cannot be traced to a formal parameter, or a call that may write what it
  cannot account for invalidates the proof - and "the stack address is known"
  is never treated as "the value at that address is independent";
* **cross-function claims are summaries, not names.**  A callee's return value
  and its argument-relative writes are summarised with *formal parameters and
  memory inputs as the dependence variables*, and instantiated at each call
  site, so the same callee is judged differently for an independent and for a
  VLEN-derived argument.  External callees, missing bodies and incomplete
  indirect target sets stay unproven: no function is exempt because its name
  looks safe (``strlen`` included), and a call also revokes the proofs of the
  memory it may have written.  Recursion is resolved by a bounded call-graph
  fixpoint, and a summary that still needs its own recursive answer stays
  unproven;
* **control dependence counts.**  A constant selected by a branch whose
  condition is not proven independent is not an independence proof, whatever
  its value expression looks like - inside a callee that rule is carried by the
  summary, so a result "returned as 32 or 16 depending on ``vlenb``" stays a
  VLEN source for its callers;
* **every path, not the walked one.**  A proof is only as good as its worst
  path, so all three sub-analyses report path completeness: the register walk
  also returns the reason the other paths have no definition (a value that
  comes from the entry, or a walk the budget cut short), the summary
  distinguishes a write that runs on every path to a return from one that only
  may run, and a load keeps unproven when any path reaches it unwritten.

Every query is bounded: at most ``node_budget`` proof nodes and
``summary_budget`` callee summaries/effect analyses per check. A register-only
effect also requires one continuous basic block of at most 64 instructions.
A query that runs out of budget
answers unproven with ``analysis-budget-exhausted`` and is reported as such -
the partial result reached before the limit is never used to release a mark.
Caches live in one prover instance, i.e. for one check, and the interned proof
table carries the analysis version so a stale entry can never be reused.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field, replace

from ...core.algorithm.graph import immediate_dominators
from ...core.data_model import Function, Program
from .dependencies import (
    DEPENDENCY_INDEPENDENT,
    DEPENDENCY_UNKNOWN,
    DEPENDENCY_VLEN,
    FunctionDependencyState,
    _is_conditional_branch,
    _read_scalar_registers,
    analyze_register_dependencies,
)
from .expressions import (
    Constant,
    Expr,
    Input,
    Unknown,
    _affine_terms,
    vlen_dependency,
)
from .instruction_facts import _instruction_predecessors
from .model import OriginProof, ScalarLeafCallDiagnostic, ScalarLeafTargetDiagnostic
from .solver import _FunctionExpressionAnalyzer

#: Verdict vocabulary.
PROVEN = "proven"
VLEN = "vlen"
UNPROVEN = "unproven"

#: Certificate reasons (``status=proven`` / ``status=vlen``).
R_ZERO = "zero-constant"
R_CONSTANT = "constant-value"
R_LOCAL_DATAFLOW = "local-dataflow"
R_ARITHMETIC = "independent-operands"
R_FRAME_SLOT = "frame-slot-proven"
R_PARAM_RANGE = "parameter-range-proven"
R_STATIC_OBJECT = "static-object-proven"
R_CALLEE_RETURN = "callee-return-proven"
R_VLENB = "vlenb-read"
R_VLEN_FLOW = "vlen-dependent-value"
R_CALLEE_VLEN = "callee-return-vlen"
R_VECTOR_STORE = "vector-stack-store"

#: Gap reasons (``status=unproven``).
G_ENTRY = "entry-parameter"
G_CLOBBER = "call-clobbered-register"
G_EXTERNAL = "external-callee"
G_NO_BODY = "missing-callee-body"
G_TARGETS = "incomplete-callee-targets"
G_MEMORY = "unresolved-memory-source"
G_NO_WRITER = "no-writer-in-binary"
G_PARTIAL = "partial-write"
G_ALIAS = "memory-alias-unknown"
G_UNMODELLED = "unmodelled-operation"
G_CONTROL = "control-dependent"
G_RECURSION = "recursive-cycle"
G_BUDGET = "analysis-budget-exhausted"
G_LOOP = "loop-carried-value"
#: A reaching path the walk could not follow at all (an edge into an address
#: the disassembly does not cover).  Never a proof, and never silently dropped.
G_PATH = "uncovered-path"

#: Version of the origin/proof semantics.  Part of every cache key: a proof
#: computed under different rules must not be reused.  ``origins-v2`` added
#: path completeness to all three sub-analyses - the register walk, the callee
#: return selection and the write coverage - so v1 proofs must not survive it.
#: ``origins-v3`` completed the *memory* side of a summary: nested calls fold
#: their effects in, store addresses are composed from pointer arithmetic, and
#: vector stores through a pointer are recorded as unmodelled writes instead
#: of being invisible.  A v2 "clean" verdict may be a v3 write.
#: ``origins-v4`` added the missing non-alias and completeness rules: distinct
#: formal parameters may alias (so may a formal pointer and a static object),
#: atomic writes are accounted for, and an indirect call's target set is no
#: longer pruned to its provable subset.  A v3 "clean" or "proven" verdict may
#: be a v4 gap.
#: ``origins-v5`` described the atomic writes instead of merely noticing them:
#: a read-modify-write consumes the old memory content (its stored value
#: depends on it), and a store-conditional may not store at all (it is never
#: guaranteed coverage, and the reaching walk keeps the earlier sources).  A
#: v4 "proven" verdict may describe a write that does not happen or a value
#: that was never established.
#: ``origins-v6`` stopped losing path conditions when summaries compose:
#: must-write is intersected over a call's *complete* target set, a nested
#: write carries the guard of the call that performs it, and the proof side
#: refuses write sources (stores and calls) that run under a branch not
#: proven independent of vlenb.  A v5 "proven" verdict may hold on only some
#: of the paths the caller can take.
#: ``origins-v7`` made the summary solver keep its UNKNOWN: the join stores
#: unknown entries instead of omitting them, and absence is read as the
#: *entry* value wherever it is read (the write change-check and the
#: call-effect substitution included), so a register clobbered by a call can
#: no longer resurface as the caller's argument or as a proven constant.
#: ``origins-v8`` applied the two composition rules on their remaining
#: branches: the *local* reaching-write walk now uses the alias table (a
#: store through a different formal, or through a formal vs a static object,
#: participates instead of being skipped), and a *static* write's value
#: dependence is substituted at the call site like every other write's -
#: against the call site's *incoming* state, never its post-call state.
#: ``origins-v9`` stopped treating "based on the entry ``sp``" as "private":
#: a frame write is ignored only when the callee provably allocated the
#: region it writes (``sp`` proven below entry, write at or above it, whole
#: write ending at or below entry); anything else - including a vector write
#: whose extent is not modelled - keeps the summary from staying silent.
#: The missing-callee list also accumulates for the whole check instead of
#: being rebuilt per summary.
#: ``origins-v10`` extracted the frame-privacy proof into one shared
#: predicate and applied it on its remaining branches: a *rebased* nested
#: write through the frame base, and a *frame-typed escape*, are private
#: only under the same allocation proof - never by address classification.
#: ``origins-v11`` made a rebased write follow the object type it lands on:
#: when the callee's formal held a static address, the write becomes a
#: static object (absolute offset, no base register) instead of crashing on
#: the missing formal key.
#: ``origins-v12`` gave the entry path its due when the *query point* is the
#: entry itself: the register walk records the external-entry gap up front
#: and the memory walk keeps the external source, instead of relying on a
#: back edge to "reach" an address that starts in ``visited``.
#: ``origins-v13`` carried the call-site guard onto the *return value*:
#: a call whose execution is selected by a branch not proven independent of
#: vlenb no longer proves ``a0`` from the callee's constant result - on the
#: branch that skips the call the caller's own value reaches the query
#: point.  The register return now checks control dependence exactly the way
#: the memory-write side has since v6.  Because that check stops a proof
#: before it resolves the call's targets, the missing-callee list is now
#: registered by an up-front scan of every analysed call instead of being
#: assembled along the proof paths - a forensic list may not depend on which
#: proofs ran.  A v12 "proven" verdict may hold on only the branch that
#: executed the call.
#: ``origins-v14`` moved the rule to its single home: every reaching
#: definition - call return, load, arithmetic, ``csrr`` - now passes one
#: exit in ``_prove_definition`` that downgrades a ``PROVEN`` value when the
#: defining instruction itself runs under a branch not proven independent of
#: vlenb.  A load whose *content* is proven in both slots but whose *slot*
#: is vlenb-selected therefore stops certifying the size, and the per-kind
#: guards the rule used to be duplicated in (arithmetic constants since v6,
#: call returns since v13) are gone instead of being patched a third time
#: inside ``_prove_load``.  A v13 "proven" verdict may hold on only the
#: branch that executed the defining load.
#: ``origins-v15`` changed the CFG input the proofs walk: a call target is
#: no longer an in-function CFG edge, so a recursive call no longer makes
#: its own function a loop.  A v14 "unproven" verdict may describe a fixed
#: frame adjustment the false loop had hidden - the entry ``sp`` is the
#: function's own base again - so v14 proofs must not survive it.
#: ``origins-v16`` keeps return dependencies separate from per-write
#: dependencies. A constant write cannot erase a formal/guard dependency of
#: the returned value, and a width-dependent write cannot taint an independent
#: return. A v15 proof may have substituted the last write for the return.
ORIGIN_ANALYSIS_VERSION = "origins-v16"

#: Default budgets for one check.
NODE_BUDGET = 100_000
SUMMARY_BUDGET = 256

#: Upper bound on how often one register may change at one address while a
#: callee summary is built.  The abstract value is a set of formal-parameter
#: names, so the lattice is finite; the bound is a widening guard for loop
#: carried expressions and degrades that register to "unknown".
_SUMMARY_UPDATE_CAP = 6

#: The abstract name used for "the value came from memory".
_MEMORY_INPUT = "memory"

#: Memory object keys.
_OBJECT_FRAME = "frame"
_OBJECT_PARAM = "param"
_OBJECT_STATIC = "static"

#: Sentinel for "this address has no control state yet", distinct from the
#: empty set (reached, and not control dependent) and from ``None`` (reached,
#: and control dependent on an unprovable condition).
_UNVISITED = object()


@dataclass(frozen=True)
class _Location:
    """An abstract memory object plus a byte range inside it."""

    kind: str
    key: object
    start: int
    size: int

    @property
    def object_key(self) -> tuple:
        return (self.kind, self.key)

    @property
    def end(self) -> int:
        return self.start + self.size

    def overlaps(self, other: "_Location") -> bool:
        return (
            self.object_key == other.object_key
            and self.start < other.end
            and other.start < self.end
        )

    def covers(self, other: "_Location") -> bool:
        return (
            self.object_key == other.object_key
            and self.start <= other.start
            and other.end <= self.end
        )

    def describe(self) -> str:
        if self.kind == _OBJECT_STATIC:
            return f"static object at {self.start:#x} (+{self.size} bytes)"
        return (
            f"{self.kind} object {self.key!r} bytes "
            f"[{self.start}, {self.end})"
        )


@dataclass(frozen=True)
class MemoryWrite:
    """One write a callee performs through a formal parameter.

    ``dependencies`` names what the *stored value* was derived from (formal
    parameters, ``memory``, ``vlenb``) - the conditions that selected the
    written branch included.  The write is only a proof once those names are
    discharged against the actual arguments at a call site - the same callee
    must be judged differently for an independent and for a VLEN-derived
    argument.

    ``on_every_path`` separates "the callee may write this" from "every path to
    a return writes this".  Only the latter establishes what the caller reads
    after the call; a write inside one arm of a branch leaves the pre-call
    value in place on the other arm, however complete it is where it runs.
    """

    register: str          # formal holding the base
    offset: int            # byte offset from that base, or the absolute
                           # address when ``object`` is ``static``
    size: int
    dependencies: frozenset[str]
    address: int
    status: str = PROVEN
    reason: str = R_PARAM_RANGE
    #: ``formal`` (the caller named the object through an argument) or
    #: ``static`` (an address the linker fixed).
    object: str = "formal"
    #: Defaults to the conservative answer: a write nobody proved to be
    #: unconditional is *not* treated as covering every path.
    on_every_path: bool = False
    #: True for a write whose byte range is not modelled (a vector store): it
    #: starts at ``offset`` and may reach any byte after it in the object, and
    #: its content is a VLEN source.  Never treated as coverage.
    extent_unknown: bool = False


@dataclass(frozen=True)
class FunctionSummary:
    """What one callee proves about its return value and its memory effects.

    ``return_dependencies`` names the formal parameters (and ``memory``) the
    return value depends on: the summary is applied at a call site by
    discharging those names against the actual arguments, so an unconditional
    "this callee is safe" conclusion cannot be shared between two call
    contexts.
    """

    function_start: int
    return_status: str
    return_reason: str
    return_dependencies: frozenset[str] = frozenset()
    writes: tuple[MemoryWrite, ...] = ()
    #: Formal parameters whose pointee may be written by code whose body is not
    #: available (an external call, an unresolved callee).
    escapes: frozenset[str] = frozenset()
    #: The callee may write memory that cannot be attributed to any formal:
    #: any load after such a call loses its proof.
    unknown_memory: bool = False
    partial: bool = False
    gaps: tuple[str, ...] = ()

    @property
    def usable(self) -> bool:
        return not self.partial


@dataclass(frozen=True, slots=True)
class ScalarLeafCallEffects:
    """Complete register effects of bounded, memory-free internal callees.

    Names denote actual entry registers, including SP. An empty dependency
    set is a proven independent definition; omitted outputs are preserved.
    This is separate from the return/memory summary's ABI assumptions.
    """

    entry_reads: frozenset[str]
    register_dependencies: tuple[tuple[str, frozenset[str]], ...]


@dataclass(frozen=True)
class AdjustmentProof:
    """The prover's answer for one stack adjustment."""

    status: str
    reason: str
    proof_id: str
    size_registers: tuple[str, ...] = ()
    gaps: tuple[str, ...] = ()

    @property
    def proven(self) -> bool:
        return self.status == PROVEN


#: Why a reaching path has no definition, keyed by the gap reason.  The detail
#: is what a report shows the reader; the reason is what it dispatches on.
_UNDEFINED_PATH_DETAIL = {
    G_ENTRY: (
        "another reaching path carries the caller's value: nothing in this "
        "function proves what arrives from outside"
    ),
    G_BUDGET: "the walk over the reaching definitions was cut short by the budget",
    G_PATH: "a reaching path leads to an address this disassembly does not cover",
}


class _FunctionContext:
    """Per-function analysis inputs, computed once and only on demand."""

    __slots__ = (
        "function",
        "instructions",
        "predecessors",
        "dependencies",
        "expressions",
        "_loads",
        "_memory",
        "_stores",
        "_exits",
        "_always_executed",
    )

    def __init__(
        self,
        function: Function,
        semantics,
    ) -> None:
        self.function = function
        self.instructions = function.instruction_by_address
        self.predecessors = _instruction_predecessors(function)
        self.dependencies: FunctionDependencyState = (
            analyze_register_dependencies(function, semantics)
        )
        self.expressions = _FunctionExpressionAnalyzer(
            semantics, emit_warnings=False
        ).analyze(function, frozenset())
        self._loads: dict[int, tuple[str, int, int]] = {}
        self._memory: dict[int, tuple[str, int, int]] = {}
        self._stores: tuple[int, ...] = ()
        self._exits: tuple[int, ...] = ()
        stores: list[int] = []
        scalar_memory = getattr(semantics, "scalar_memory_operand", None)
        vector_operand = getattr(semantics, "vector_memory_operand", None)
        is_store = getattr(semantics, "is_scalar_store", None)
        is_load = getattr(semantics, "is_scalar_load", None)
        for instruction in function.insts:
            address = instruction.addr
            operand = scalar_memory(instruction) if callable(scalar_memory) else None
            if operand is not None:
                self._memory[address] = operand
                if callable(is_load) and is_load(instruction):
                    self._loads[address] = operand
                elif callable(is_store) and is_store(instruction):
                    stores.append(address)
                continue
            if callable(vector_operand) and vector_operand(instruction) is not None:
                stores.append(address)
        self._stores = tuple(stores)
        self._exits = tuple(
            instruction.addr
            for instruction in function.insts
            if not instruction.succ
        )
        self._always_executed: frozenset[int] | None = None

    @property
    def exits(self) -> tuple[int, ...]:
        return self._exits

    @property
    def always_executed(self) -> frozenset[int]:
        """Addresses every path from the entry to a return has to pass through.

        This is what separates "the callee may write this range" from "the
        callee *has* written it before the caller reads it".  Computed from the
        dominator tree, once per function and only when a summary asks: the
        straightforward alternative - a reachability probe per write - is
        quadratic on the large functions this analysis runs on.
        """

        cached = self._always_executed
        if cached is None:
            cached = self._compute_always_executed()
            self._always_executed = cached
        return cached

    def _compute_always_executed(self) -> frozenset[int]:
        nodes = [instruction.addr for instruction in self.function.insts]
        if not nodes:
            return frozenset()
        immediate = immediate_dominators(
            nodes,
            successors=lambda address: self.instructions[address].succ,
            predecessors=lambda address: self.predecessors.get(address, ()),
        )
        # Only nodes reachable from the entry are keys of the dominator map, so
        # an exit missing from it cannot be reached by an execution at all and
        # constrains nothing.  The entry itself is reachable by definition and
        # is simply not a key, which is why it is added back explicitly.
        entry = nodes[0]
        reachable_exits = [
            address
            for address in self._exits
            if address == entry or address in immediate
        ]
        if not reachable_exits:
            return frozenset()
        common: set[int] | None = None
        for exit_address in reachable_exits:
            chain = {exit_address}
            current = immediate.get(exit_address)
            while current is not None:
                chain.add(current)
                current = immediate.get(current)
            common = chain if common is None else common & chain
            if not common:
                return frozenset()
        return frozenset(common or ())

    def load_operands(self, address: int) -> tuple[str, int, int] | None:
        """Operands of a scalar *load* at ``address``."""

        return self._loads.get(address)

    def memory_operands(self, address: int) -> tuple[str, int, int] | None:
        """Operands of any scalar memory access (load or store)."""

        return self._memory.get(address)

    def store_addresses(self) -> tuple[int, ...]:
        return self._stores


class _SummaryDataflow:
    """Forward dependence dataflow used to summarise one callee.

    The abstract value of a register is a set of names: the formal parameters
    it is derived from, plus ``memory`` for a value that came out of memory.
    ``None`` is the top element - "unproven" - and is what every unmodelled
    operation, every external call and every widening fallback produces.

    Alongside the values it carries the *control* dependence: the names of the
    conditions that may have selected the path reaching each instruction.
    Both are needed, because "which value" and "which branch chose it" are
    different questions - a callee that returns 32 or 16 depending on a
    ``vlenb`` comparison returns a VLEN-dependent size, even though each of the
    two constants, taken alone, is perfectly independent.

    Direct internal calls are resolved through ``call_effect``, which maps a
    callee's return-dependence set onto the caller's own dependence variables.
    That is what lets summaries compose: without it a value that merely passed
    through a callee could never be proven, and the call-graph fixpoint this
    module promises would have nothing to iterate.
    """

    def __init__(self, function: Function, semantics, call_effect=None, *, register_facts=None) -> None:
        self._function = function
        self._semantics = semantics
        self._call_effect = call_effect
        self._instructions = function.instruction_by_address
        self._predecessors = _instruction_predecessors(function)
        # Only the bounded register-only proof supplies complete operand facts.
        # Existing return/memory summaries retain their original semantics.
        self._register_facts = register_facts

    def run(
        self,
    ) -> tuple[
        dict[int, dict[str, frozenset[str] | None]],
        dict[int, frozenset[str] | None],
        dict[int, dict[str, frozenset[str] | None]],
    ]:
        """Return per-instruction outgoing values, control and incoming states.

        The outgoing state of a call already reflects the clobber - it says
        what the register holds *after* the call.  A callee summary is
        re-expressed against what the call site *passed in*, which is the
        incoming state; both are returned so the substitution never has to
        read a post-call value for a pre-call question.

        A control state of ``None`` means "selected by a condition that is not
        proven independent, and whose own dependence cannot even be named":
        the top element of that lattice, and never a proof.
        """

        entry = self._function.insts[0].addr
        outgoing: dict[int, dict[str, frozenset[str] | None]] = {}
        control: dict[int, frozenset[str] | None] = {}
        incoming_states: dict[int, dict[str, frozenset[str] | None]] = {}
        updates: dict[tuple[int, str], int] = {}
        worklist: deque[int] = deque([entry])
        queued = {entry}
        while worklist:
            address = worklist.popleft()
            queued.discard(address)
            incoming = self._join(address, entry, outgoing)
            incoming_states[address] = incoming
            instruction = self._instructions[address]
            state, changed_top = self._transfer(
                instruction, incoming, updates, address
            )
            incoming_control = self._join_control(address, control)
            here = (
                self._condition_control(instruction, incoming, incoming_control)
                if _is_conditional_branch(self._semantics, instruction)
                else incoming_control
            )
            previous = outgoing.get(address)
            previous_control = control.get(address, _UNVISITED)
            if (
                not changed_top
                and previous is not None
                and state == previous
                and previous_control == here
            ):
                continue
            outgoing[address] = state
            control[address] = here
            for successor in instruction.succ:
                if successor in self._instructions and successor not in queued:
                    worklist.append(successor)
                    queued.add(successor)
        return outgoing, control, incoming_states

    def _join_control(
        self,
        address: int,
        control: dict[int, frozenset[str] | None],
    ) -> frozenset[str] | None:
        """Union of the control states of every predecessor.

        The entry is not a special case: a back edge may target it, and a
        condition that selected that edge selects what flows into the entry
        with it.  With no predecessor at all the union is the empty set, which
        is the right answer for a function entered from outside.
        """

        joined: frozenset[str] | None = frozenset()
        for predecessor in self._predecessors.get(address, ()):
            if predecessor not in control:
                # A predecessor the analysis never reached: nothing about the
                # path into ``address`` can be claimed through it.
                return None
            value = control[predecessor]
            if value is None:
                return None
            joined = (joined or frozenset()) | value
        return joined

    def _condition_control(
        self,
        instruction,
        incoming: dict[str, frozenset[str] | None],
        incoming_control: frozenset[str] | None,
    ) -> frozenset[str] | None:
        """Control state of a branch's successors.

        A condition whose own dependence is unproven leaves the successors
        control-dependent on an unnamed value - ``None``, never a proof.
        """

        if incoming_control is None:
            return None
        reader = getattr(self._semantics, "condition_scalar_registers", None)
        reads = set(reader(instruction)) if callable(reader) else set()
        if not reads:
            # Architectures without a branch-condition surface: the generic
            # read set is the conservative fallback.
            reads = _read_scalar_registers(self._semantics, instruction)
        names = set(incoming_control)
        for register in reads:
            if register not in incoming:
                return None
            value = incoming[register]
            if value is None:
                return None
            names |= value
        return frozenset(names)

    def _join(
        self,
        address: int,
        entry: int,
        outgoing: dict[int, dict[str, frozenset[str] | None]],
    ) -> dict[str, frozenset[str] | None]:
        registers: set[str] = set()
        predecessors = self._predecessors.get(address, ())
        for predecessor in predecessors:
            registers.update(outgoing.get(predecessor, ()))
        if address == entry:
            # Whatever the callers pass in is exactly the dependence variable
            # this summary is expressed in.
            registers.update(self._mentioned_registers())
        incoming: dict[str, frozenset[str] | None] = {}
        constant_entry = {'zero', 'sp'} if self._register_facts is None else {'zero'}
        for register in registers:
            joined: frozenset[str] | None = frozenset()
            for predecessor in predecessors:
                state = outgoing.get(predecessor)
                if state is None:
                    joined = None
                    break
                if register in state:
                    value = state[register]
                else:
                    # The register was never mentioned along this path: what
                    # flows here is the *entry* value - the register itself
                    # (``zero``/``sp`` are what the call convention proves).
                    # Reading absence as the empty set would claim a constant
                    # that no instruction established.
                    value = (
                        frozenset()
                        if register in constant_entry
                        else frozenset({register})
                    )
                if value is None:
                    joined = None
                    break
                joined = joined | value
            if address == entry:
                # An entry register stands for itself; ``sp``/``zero`` are the
                # only ones the call itself proves.  A join that is unknown
                # stays unknown - a back edge may carry a clobbered value.
                if register in constant_entry:
                    joined = frozenset()
                elif joined is not None:
                    joined = joined | {register}
            if joined is None:
                # An *unknown* entry must be stored as unknown.  Omitting it
                # would make the register look never-mentioned downstream,
                # and "never mentioned" reads as the entry parameter there -
                # a value clobbered by a call on one path would silently turn
                # back into the caller's argument.
                incoming[register] = None
            else:
                # An *empty* set is the strongest answer there is ("this value
                # is a constant"), so it must be kept too: dropping it would
                # be indistinguishable from "the register was never
                # mentioned", which means the opposite - the value is the
                # caller's.
                incoming[register] = joined
        return incoming

    def _mentioned_registers(self) -> frozenset[str]:
        if self._register_facts is not None:
            return frozenset().union(*(f.reads | f.writes for f in self._register_facts.values()))
        registers: set[str] = set()
        stored = getattr(self._semantics, "stored_scalar_register", None)
        conditions = getattr(self._semantics, "condition_scalar_registers", None)
        for instruction in self._function.insts:
            registers |= self._semantics.written_scalar_registers(instruction)
            registers |= _read_scalar_registers(self._semantics, instruction)
            # A store's value operand is read, but the generic read set only
            # looks at ``args[1:]``; without this the value a callee stores
            # through a pointer would have no dependence variable at all.
            if callable(stored):
                value = stored(instruction)
                if value is not None:
                    registers.add(value)
            # Same shape for a branch condition, which sits in ``args[0]``:
            # a condition register that is never mentioned has no dependence
            # variable, so every control join would collapse to "unproven".
            if callable(conditions):
                registers |= conditions(instruction)
        return frozenset(registers)

    def _transfer(
        self,
        instruction,
        incoming: dict[str, frozenset[str] | None],
        updates: dict[tuple[int, str], int],
        address: int,
    ) -> tuple[dict[str, frozenset[str] | None], bool]:
        writes = (self._register_facts[address].writes if self._register_facts is not None
                  else self._semantics.written_scalar_registers(instruction))
        clobbered = getattr(
            self._semantics, "call_clobbered_scalar_registers", None
        )
        if callable(clobbered):
            writes = writes | set(clobbered(instruction))
        if not writes:
            return incoming, False

        if self._register_facts is not None:
            # A dependency set does not identify a value. In particular,
            # two registers derived from a0 need not be equal, so rebuilding
            # them as one symbolic atom would make (2*a0)-a0 cancel falsely.
            # The bounded effect proof only unions actual entry provenance;
            # explicit no-input writes establish independent definitions.
            names: frozenset[str] | None = frozenset()
            for register in self._register_facts[address].reads:
                value = incoming.get(register, frozenset({register}))
                if value is None:
                    names = None
                    break
                names |= value
            outgoing = dict(incoming)
            for register in writes:
                outgoing[register] = names
            return outgoing, outgoing != incoming

        # A call destroys every caller-saved register whatever the encoding
        # says.  ``a0`` is the callee's return value, which a direct internal
        # call can summarise; everything else, and every call whose summary is
        # missing or incomplete, becomes unproven.
        if callable(clobbered) and clobbered(instruction):
            destroyed = clobbered(instruction)
            outgoing = dict(incoming)
            widened = False
            resolved: dict[str, frozenset[str] | None] = {}
            if callable(self._call_effect):
                resolved = self._call_effect(address, incoming) or {}
            for register in destroyed:
                if register not in resolved:
                    resolved[register] = None
            for register, names in resolved.items():
                if outgoing.get(register, frozenset()) != names:
                    outgoing[register] = names
                    widened = True
            return outgoing, widened

        marker_state: dict[str, object] = {"zero": Constant(0)}
        for register in _read_scalar_registers(self._semantics, instruction):
            names = incoming.get(register, frozenset())
            if names is None:
                marker_state[register] = Unknown
            elif not names:
                marker_state[register] = Input(register)
            else:
                marker_state[register] = _marker(names)

        after = self._semantics.symbolic.transfer_instruction(
            instruction, marker_state
        )
        outgoing = dict(incoming)
        widened = False
        for register in writes:
            names = _dependence_names(after.get(register))
            count = updates.get((address, register), 0) + 1
            updates[(address, register)] = count
            if count > _SUMMARY_UPDATE_CAP:
                names = None
            if outgoing.get(register) != names:
                # Absence must not stand in for the empty set here: a constant
                # write to a never-mentioned register really changes it (the
                # entry parameter becomes a constant), and skipping the store
                # would leave the register reading as its entry value.
                outgoing[register] = names
                widened = True
        return outgoing, widened


def _write_span(entry: MemoryWrite) -> int:
    """Bytes a write may cover; unbounded for a modelled-extent-missing write."""

    return entry.size if not entry.extent_unknown else 1 << 62


def _stored_value_register(semantics, instruction, default: str) -> str:
    """The register whose value a store leaves in memory.

    ``args[0]`` is the value operand for ordinary stores, but an atomic write
    keeps the ``rd, rs2, (addr)`` order - there the value is ``rs2``, and the
    architecture adapter says so.  The default only covers adapters without
    the distinction.
    """

    stored = getattr(semantics, "stored_scalar_register", None)
    value = stored(instruction) if callable(stored) else None
    return value if value is not None else default


def _marker(names: frozenset[str]) -> Expr:
    """A stand-in atom carrying the dependence names of a value.

    The atom kind is deliberately not ``vlenb``: a summary must not be able to
    masquerade as a proven VLEN dependency, and two different name sets must
    never collapse into one atom.
    """

    return Expr("summary-input", tuple(sorted(names)))


def _dependence_names(value: object) -> frozenset[str] | None:
    """Names a value depends on; ``None`` when it cannot be proven either way."""

    if not isinstance(value, Expr):
        return None
    kind = value.kind
    if kind == "const":
        return frozenset()
    if kind == "input":
        return frozenset({str(value.args[0])})
    if kind == "loop_input":
        return frozenset({str(value.args[1])})
    if kind == "post_loop_input":
        return None
    if kind == "summary-input":
        return frozenset(str(name) for name in value.args)
    if kind == "load":
        return frozenset({_MEMORY_INPUT})
    if kind == "vlenb":
        # A real VLENB atom: the value is VLEN-derived, which the caller must
        # see as such rather than as a formal dependence.
        return frozenset({_VLEN_NAME})
    if kind not in _DEPENDENCE_PRESERVING:
        return None
    names: set[str] = set()
    for argument in value.args:
        if not isinstance(argument, Expr):
            if isinstance(argument, int):
                continue
            return None
        nested = _dependence_names(argument)
        if nested is None:
            return None
        names |= nested
    return frozenset(names)


#: Name that marks "this is a proven VLEN source" in a summary.
_VLEN_NAME = "vlenb"

#: Expression kinds that only pass their operands through.
_DEPENDENCE_PRESERVING = frozenset(
    {
        "add",
        "scale",
        "mul",
        "and",
        "shl",
        "lshr",
        "ashr",
        "or",
        "xor",
        "sub",
        "sext32",
        "zext32",
        "sext8",
        "zext8",
        "sext16",
        "zext16",
    }
)


class OriginProver:
    """Answers origin queries for the unproven stack adjustments of one run."""

    def __init__(
        self,
        program: Program,
        semantics,
        *,
        metadata=None,
        node_budget: int = NODE_BUDGET,
        summary_budget: int = SUMMARY_BUDGET,
        analysis_version: str = ORIGIN_ANALYSIS_VERSION,
    ) -> None:
        self._semantics = semantics
        self._metadata = metadata
        self._functions = {f.start: f for f in program.functions}
        self._node_budget = node_budget
        self._summary_budget = summary_budget
        self._analysis_version = analysis_version
        self._contexts: dict[int, _FunctionContext] = {}
        self._cache: dict[tuple, str] = {}
        self._inflight: set[tuple] = set()
        self._proofs: dict[str, OriginProof] = {}
        self._order: list[str] = []
        self._proof_status_cache: dict[tuple[str, str], bool] = {}
        self._gaps: list[str] = []
        self._gaps_seen: set[str] = set()
        self._nodes = 0
        self._budget_exhausted = False
        self._summaries: dict[int, FunctionSummary] = {}
        self._summary_inflight: set[int] = set()
        self._summary_requests = 0
        self._scalar_leaf_effects: dict[int, ScalarLeafCallEffects | None] = {}
        self._scalar_leaf_diagnostics: dict[int, ScalarLeafTargetDiagnostic] = {}
        self._scalar_call_diagnostics: dict[int, ScalarLeafCallDiagnostic] = {}
        # Set while a summary consumes a not-yet-complete recursive answer,
        # so the summary can say *why* it stayed unproven.
        self._consumed_recursion = False
        # Addresses a proof asked for and could not read, with the reason.
        self._missing_callees: dict[int, str] = {}
        # The forensic list must not depend on which proofs ran: a proof that
        # stops early (a guarded call, a budget gap) must not take the call
        # targets it never resolved out of the report.  Register the direct
        # targets of every analysed call up front.
        self._register_missing_call_targets()

    # region public surface

    def scalar_leaf_call_diagnostic(self, instruction) -> ScalarLeafCallDiagnostic | None:
        """Read a previous effect attempt; never resolve or prove for reporting."""
        return self._scalar_call_diagnostics.get(instruction.addr)

    def _declared_scalar_targets(self, instruction, prefer_metadata):
        entry = (self._metadata.function_pointer.get(instruction.addr)
                 if self._metadata is not None else None)
        if len(instruction.jump_targets) == 1 and not (prefer_metadata and entry is not None):
            return tuple(sorted(instruction.jump_targets)), 'instruction'
        if entry is not None:
            return tuple(sorted(set(entry.targets))), 'metadata'
        return tuple(sorted(instruction.jump_targets)), ('instruction' if instruction.jump_targets else 'unresolved')

    def _scalar_target_diagnostic(self, target, *, status='not-examined', reason='not-examined',
                                  instruction=None, registers=()):
        function = self._functions.get(target)
        if function is None:
            status, reason = 'unavailable', G_NO_BODY
        elif function.is_external_trampoline:
            status, reason = 'unavailable', G_EXTERNAL
        return ScalarLeafTargetDiagnostic(
            target, function.name if function is not None else None, status, reason,
            len(function.insts) if function is not None else None,
            instruction.addr if instruction is not None else None,
            instruction.op if instruction is not None else None, tuple(sorted(registers)))

    def _record_scalar_call_diagnostic(self, instruction, status, reason, *,
                                       prefer_metadata=False, complete=False, evaluated=()):
        try:
            targets, source = self._declared_scalar_targets(instruction, prefer_metadata)
            attempted = set(evaluated)
            observations = tuple(
                self._scalar_leaf_diagnostics[target] if target in attempted and target in self._scalar_leaf_diagnostics else
                self._scalar_target_diagnostic(target, status='unavailable', reason='effect-diagnostic-unavailable')
                if target in attempted else self._scalar_target_diagnostic(target)
                for target in targets[:64])
            first_refusal = next((self._scalar_leaf_diagnostics[target] for target in evaluated
                if target in self._scalar_leaf_diagnostics
                and self._scalar_leaf_diagnostics[target].status != 'accepted'), None)
            self._scalar_call_diagnostics[instruction.addr] = ScalarLeafCallDiagnostic(
                status, reason, source, complete, observations, len(targets), len(targets) > 64, first_refusal)
        except Exception:
            # Optional reporting cannot alter the original effect verdict.
            self._scalar_call_diagnostics[instruction.addr] = ScalarLeafCallDiagnostic(
                'unavailable', 'diagnostic-recording-failed')

    def _refuse_scalar_leaf(self, start, reason, instruction=None, registers=()):
        self._scalar_leaf_diagnostics[start] = self._scalar_target_diagnostic(
            start, status='refused', reason=reason, instruction=instruction, registers=registers)
        return None

    def scalar_leaf_call_effects(self, instruction) -> ScalarLeafCallEffects | None:
        """Prove the complete target set's register-only effects, or refuse.

        No ABI clobber is treated as an actual definition. The standard RA
        link is the new PC, not the caller's old RA input; the target register
        use is supplied separately by the architecture's call facts.
        """
        reader = getattr(self._semantics, 'scalar_width_facts', None)
        if not callable(reader):
            self._record_scalar_call_diagnostic(instruction, 'refused', 'effect-provider-unavailable')
            return None
        call = reader(instruction)
        # The cache adapter now lists ABI volatile epochs as definitions at a
        # normal call. This optional body-effect API checks the RA link only;
        # its result still comes from the callee's actual instructions.
        if not call.call or call.unmodelled or 'ra' not in call.writes:
            reason = ('not-a-call' if not call.call else 'call-effects-unmodelled' if call.unmodelled
                      else 'unsupported-call-link')
            self._record_scalar_call_diagnostic(instruction, 'refused', reason,
                                               prefer_metadata=bool(call.call_target_reads))
            return None
        targets, target_reason = self._call_targets_of(instruction, prefer_metadata=bool(call.call_target_reads))
        if not targets:
            self._record_scalar_call_diagnostic(instruction, 'refused', target_reason or 'empty-callee-targets',
                                               prefer_metadata=bool(call.call_target_reads))
            return None
        effects = []
        evaluated = []
        for target in sorted(targets):
            effect = self._scalar_leaf_effect(target)
            evaluated.append(target)
            if effect is None:
                self._record_scalar_call_diagnostic(instruction, 'refused', 'callee-effects-refused',
                    prefer_metadata=bool(call.call_target_reads), complete=True, evaluated=evaluated)
                return None
            effects.append(effect)
        outputs = [dict(effect.register_dependencies) for effect in effects]
        written = set().union(*(output.keys() for output in outputs))
        dependencies = tuple((register, frozenset().union(*(
            output.get(register, frozenset({register})) for output in outputs)))
            for register in sorted(written))
        # A target that preserves a register carries the old value through the
        # call. Its dependency is also a use before the merged may-definition.
        reads = frozenset().union(*(effect.entry_reads for effect in effects),
                                  *(names for _, names in dependencies))
        self._record_scalar_call_diagnostic(instruction, 'accepted', 'register-only-effects',
            prefer_metadata=bool(call.call_target_reads), complete=True, evaluated=evaluated)
        return ScalarLeafCallEffects(reads, dependencies)

    def _scalar_leaf_effect(self, start: int) -> ScalarLeafCallEffects | None:
        if start in self._scalar_leaf_effects:
            return self._scalar_leaf_effects[start]
        self._scalar_leaf_effects[start] = None
        function = self._functions[start]
        insts = function.insts
        if function.is_external_trampoline:
            return self._refuse_scalar_leaf(start, G_EXTERNAL)
        if not 0 < len(insts) <= 64:
            return self._refuse_scalar_leaf(start, 'empty-callee-body' if not insts else 'instruction-limit-exceeded')
        if insts[0].addr != start:
            return self._refuse_scalar_leaf(start, 'callee-entry-mismatch')
        if (len(function.blocks) != 1
            or function.blocks[0].instructions != insts
            or function.blocks[0].predecessors or function.blocks[0].successors):
            return self._refuse_scalar_leaf(start, 'nonlinear-callee-cfg')
        facts = {i.addr: self._semantics.scalar_width_facts(i) for i in insts}
        allowed_writes = {f'a{i}' for i in range(8)} | {f't{i}' for i in range(7)}
        for index, instruction in enumerate(insts):
            fact = facts[instruction.addr]
            last = index == len(insts) - 1
            expected = set() if last else {insts[index + 1].addr}
            if (not getattr(fact, 'register_only', False) or fact.unmodelled
                or fact.call or fact.load or fact.store or fact.source_kind
                or fact.vector_reads or fact.vector_writes or fact.memory
                or not fact.writes <= allowed_writes or instruction.jump_targets
                or set(instruction.succ) != expected or fact.returns != last
                or not last and (instruction.ends_block
                    or instruction.addr + instruction.size != insts[index + 1].addr)
                or index > 0 and instruction.jump_sources):
                # Choose a diagnostic witness only after the original predicate
                # refused. This order never supplies extra proof capability.
                if fact.call:
                    reason = 'nested-call'
                elif fact.vector_reads or fact.vector_writes:
                    reason = 'vector-register-effects'
                elif fact.load or fact.store or fact.memory:
                    reason = 'memory-effects'
                elif fact.source_kind or instruction.op.lower().startswith(('csr', 'vset')):
                    reason = 'hardware-width-state-effects'
                elif fact.unmodelled:
                    reason = 'instruction-effects-unmodelled'
                elif fact.returns and (not getattr(fact, 'register_only', False) or fact.returns != last):
                    reason = 'normal-return-unproven'
                elif not fact.returns and any(register.startswith('f') for register in fact.reads | fact.writes):
                    reason = 'floating-point-effects'
                elif not fact.writes <= allowed_writes:
                    reason = 'protected-register-write'
                elif not getattr(fact, 'register_only', False):
                    reason = 'unsupported-register-operation'
                elif fact.returns != last:
                    reason = 'normal-return-unproven'
                else:
                    reason = 'instruction-control-flow-unproven'
                return self._refuse_scalar_leaf(start, reason, instruction, fact.writes - allowed_writes)
        if self._summary_requests >= self._summary_budget:
            self._budget_exhausted = True
            return self._refuse_scalar_leaf(start, G_BUDGET)
        self._summary_requests += 1
        states, controls, incoming = _SummaryDataflow(
            function, self._semantics, register_facts=facts).run()
        written = set().union(*(fact.writes for fact in facts.values()))
        reads = set()
        for instruction in insts:
            address = instruction.addr
            if address not in states or address not in incoming or controls.get(address) != frozenset():
                return self._refuse_scalar_leaf(start, 'scalar-dataflow-unproven', instruction)
            for register in facts[address].reads:
                names = incoming[address].get(register, frozenset({register}))
                if names is None:
                    return self._refuse_scalar_leaf(start, 'input-dependency-unknown', instruction, (register,))
                reads.update(names - {'ra'})
            if any(states[address].get(register) is None for register in facts[address].writes):
                return self._refuse_scalar_leaf(start, 'output-dependency-unknown', instruction,
                    (register for register in facts[address].writes if states[address].get(register) is None))
        dependencies = tuple((register, states[insts[-1].addr][register] - {'ra'})
                             for register in sorted(written))
        result = ScalarLeafCallEffects(frozenset(reads), dependencies)
        self._scalar_leaf_effects[start] = result
        self._scalar_leaf_diagnostics[start] = self._scalar_target_diagnostic(
            start, status='accepted', reason='register-only-effects')
        return result

    def proofs(self) -> tuple[OriginProof, ...]:
        return tuple(self._proofs[proof_id] for proof_id in self._order)

    def proof_reaches_status(self, proof_id: str, status: str) -> bool:
        """Whether an existing proof node or its evidence subtree has status.

        Results are memoized per proof node and verdict, so many stack
        adjustments sharing subproofs do not rebuild or rescan the proof DAG.
        """

        root = (proof_id, status)
        if root in self._proof_status_cache:
            return self._proof_status_cache[root]
        pending: list[tuple[str, bool]] = [(proof_id, False)]
        while pending:
            current, expanded = pending.pop()
            key = (current, status)
            if key in self._proof_status_cache:
                continue
            node = self._proofs.get(current)
            if node is None:
                self._proof_status_cache[key] = False
                continue
            if node.status == status:
                self._proof_status_cache[key] = True
                continue
            dependencies = tuple(node.depends_on)
            if expanded:
                self._proof_status_cache[key] = any(
                    self._proof_status_cache.get((dependency, status), False)
                    for dependency in dependencies
                )
                continue
            pending.append((current, True))
            pending.extend(
                (dependency, False)
                for dependency in dependencies
                if (dependency, status) not in self._proof_status_cache
            )
        return self._proof_status_cache[root]

    def gaps(self) -> tuple[str, ...]:
        return tuple(self._gaps)

    @property
    def budget_exhausted(self) -> bool:
        return self._budget_exhausted

    @property
    def missing_callees(self) -> dict[int, str]:
        """Callees whose bodies the proofs needed but could not read."""

        return dict(self._missing_callees)

    @property
    def summaries_built(self) -> int:
        return len(self._summaries)

    @property
    def proof_nodes(self) -> int:
        return self._nodes

    @property
    def analysis_version(self) -> str:
        return self._analysis_version

    def prove_adjustment(
        self, function: Function, address: int
    ) -> AdjustmentProof:
        """Prove (or fail to prove) the size one stack adjustment subtracts."""

        context = self._context(function)
        instruction = context.instructions[address]
        sizes = tuple(
            sorted(
                register
                for register in _read_scalar_registers(self._semantics, instruction)
                if register != "sp"
                and context.dependencies.level_before(address, register)
                != DEPENDENCY_INDEPENDENT
            )
        )
        if not sizes:
            # The size is not carried by an independent register: either the
            # adjusted value itself came from memory or a call, or the model
            # cannot name it.  Prove the new ``sp`` value instead.
            level = context.dependencies.level_after(address, "sp")
            if level == DEPENDENCY_VLEN:
                return self._adjustment_result(
                    VLEN,
                    R_VLEN_FLOW,
                    self._record(
                        VLEN, R_VLEN_FLOW, function.start, address, "sp",
                        "the adjusted stack pointer itself carries vlenb",
                    ),
                    (),
                )
            if level == DEPENDENCY_INDEPENDENT:
                return self._adjustment_result(
                    PROVEN,
                    R_LOCAL_DATAFLOW,
                    self._record(
                        PROVEN, R_LOCAL_DATAFLOW, function.start, address, "sp",
                        "the local dataflow proves the adjusted value independent",
                    ),
                    (),
                )
            proof_id = self._prove_definition(function, address, "sp")
            node = self._proofs[proof_id]
            return self._adjustment_result(node.status, node.reason, proof_id, ())

        verdicts = [
            self.prove_register_before(function, address, register)
            for register in sizes
        ]
        proof_id = self._join_verdicts(verdicts)
        node = self._proofs[proof_id]
        return self._adjustment_result(node.status, node.reason, proof_id, sizes)

    @staticmethod
    def _adjustment_result(
        status: str,
        reason: str,
        proof_id: str,
        sizes: tuple[str, ...],
    ) -> AdjustmentProof:
        return AdjustmentProof(
            status=status,
            reason=reason,
            proof_id=proof_id,
            size_registers=sizes,
            gaps=() if status == PROVEN else (proof_id,),
        )

    def prove_register_before(
        self, function: Function, address: int, register: str
    ) -> str:
        """Proof id for the value ``register`` holds before ``address``."""

        if register == "zero":
            return self._record(
                PROVEN, R_ZERO, function.start, address, register, "x0 is constant"
            )
        key = ("before", function.start, address, register)
        cached = self._cache.get(key)
        if cached is not None:
            return cached
        if key in self._inflight:
            # A value that needs itself: a loop-carried or recursive question.
            return self._record(
                UNPROVEN, G_LOOP, function.start, address, register,
                "the value depends on itself along a loop or recursive path",
            )
        if self._budget_left() <= 0:
            return self._budget_proof(function.start, address, register)
        self._inflight.add(key)
        try:
            proof_id = self._resolve_before(function, address, register)
        finally:
            self._inflight.discard(key)
        self._cache[key] = proof_id
        return proof_id

    # endregion

    # region register provenance

    def _resolve_before(
        self, function: Function, address: int, register: str
    ) -> str:
        context = self._context(function)
        level = context.dependencies.level_before(address, register)
        if level == DEPENDENCY_INDEPENDENT:
            return self._record(
                PROVEN,
                R_LOCAL_DATAFLOW,
                function.start,
                address,
                register,
                "the local dependency dataflow proves the value independent",
            )
        if level == DEPENDENCY_VLEN:
            return self._record(
                VLEN,
                R_VLEN_FLOW,
                function.start,
                address,
                register,
                "the value is derived from a vlenb read",
            )
        definitions, gap = self._reaching_definitions(context, address, register)
        if not definitions:
            return self._record(
                UNPROVEN,
                gap or G_ENTRY,
                function.start,
                address,
                register,
                _UNDEFINED_PATH_DETAIL.get(
                    gap or G_ENTRY, "no reaching definition was found"
                ),
            )
        verdicts = [
            self._prove_definition(function, definition, register)
            for definition in definitions
        ]
        if gap is not None:
            # The definitions prove nothing about the paths that have none.
            # Dropping this verdict is exactly how "one branch defines the
            # value" used to pass as a proof.
            verdicts.append(
                self._record(
                    UNPROVEN,
                    gap,
                    function.start,
                    address,
                    register,
                    _UNDEFINED_PATH_DETAIL[gap],
                )
            )
        return self._join_verdicts(verdicts)

    def _reaching_definitions(
        self, context: _FunctionContext, address: int, register: str
    ) -> tuple[tuple[int, ...], str | None]:
        """Definitions of ``register`` reaching ``address``, and the gap on the rest.

        Returns the definitions found *and* why the walk could not account for
        every other path: a path that reaches the function entry - so the value
        is whatever the caller left there - a predecessor the disassembly does
        not cover, or a walk the budget cut short.  Reporting only the
        definitions is how "one branch defines the value" used to come back
        ``proven``; the gap makes the other paths part of the verdict.
        """

        clobbered = getattr(
            self._semantics, "call_clobbered_scalar_registers", None
        )
        entry = context.function.insts[0].addr
        definitions: list[int] = []
        # The query point itself may be the entry: the walk starts with it in
        # ``visited``, so a back edge can never "reach" it again and the
        # external-entry path would silently vanish from the verdict.  When
        # the query is the entry, the caller's value participates from the
        # start - the back-edge definitions only cover later iterations.
        gap: str | None = G_ENTRY if address == entry else None
        visited = {address}
        worklist = deque(context.predecessors.get(address, ()))
        budget = self._budget_left()
        while worklist and budget > 0:
            budget -= 1
            current = worklist.popleft()
            if current in visited:
                continue
            visited.add(current)
            instruction = context.instructions.get(current)
            if instruction is None:
                gap = gap or G_PATH
                continue
            if register in self._semantics.written_scalar_registers(instruction) or (
                callable(clobbered) and register in clobbered(instruction)
            ):
                definitions.append(current)
                continue
            if current == entry:
                # The function is entered from outside *in addition to* its
                # real predecessors, so the caller's value may reach this point
                # without ever being defined here.
                gap = gap or G_ENTRY
                continue
            worklist.extend(context.predecessors.get(current, ()))
        if worklist:
            # Stopped with paths left to walk: the definitions in hand are not
            # the whole story.
            self._budget_exhausted = True
            gap = G_BUDGET
        return tuple(definitions), gap

    def _prove_definition(
        self, function: Function, address: int, register: str
    ) -> str:
        context = self._context(function)
        instruction = context.instructions[address]
        clobbered = getattr(
            self._semantics, "call_clobbered_scalar_registers", None
        )
        if callable(clobbered) and clobbered(instruction):
            if register == "a0":
                proof_id = self._prove_callee_return(function, address)
            else:
                proof_id = self._record(
                    UNPROVEN,
                    G_CLOBBER,
                    function.start,
                    address,
                    register,
                    "the register is caller-saved and the call destroys it",
                )
        elif instruction.op == "csrr" and any(
            str(argument).strip() == "vlenb" for argument in instruction.args[1:]
        ):
            proof_id = self._record(
                VLEN, R_VLENB, function.start, address, register, "csrr vlenb"
            )
        else:
            operands = context.load_operands(address)
            if operands is not None and register in self._semantics.written_scalar_registers(
                instruction
            ):
                proof_id = self._prove_load(function, address, register, operands)
            else:
                proof_id = self._prove_arithmetic(function, address, register)
        # This is the single exit every reaching definition passes, so it is
        # where the definition's *own* control dependence belongs: a call
        # return, a load, or an arithmetic result may each prove its value,
        # but when the instruction runs only under a branch that is not
        # proven independent of vlenb, the value holds on that branch alone.
        # Downgrading here covers every definition kind at once instead of
        # patching call, load, and arithmetic proofs separately (the
        # memory-write side keeps its own guard in ``_prove_memory_source``).
        node = self._proofs[proof_id]
        if node.status == PROVEN and context.dependencies.control_dependent(
            address
        ):
            return self._record(
                UNPROVEN,
                G_CONTROL,
                function.start,
                address,
                register,
                "the definition runs under a branch that is not proven "
                "independent of vlenb, so it holds on that branch only",
                (proof_id,),
            )
        return proof_id

    def _prove_arithmetic(
        self, function: Function, address: int, register: str
    ) -> str:
        """Prove a computed value from its operands and the scalar model."""

        context = self._context(function)
        instruction = context.instructions[address]
        reads = sorted(_read_scalar_registers(self._semantics, instruction))
        depends: list[str] = []
        marker_state: dict[str, object] = {"zero": Constant(0)}
        for operand in reads:
            proof_id = self.prove_register_before(function, address, operand)
            depends.append(proof_id)
            status = self._proofs[proof_id].status
            if status == VLEN:
                marker_state[operand] = Expr("vlenb", (operand,))
            elif status == UNPROVEN:
                marker_state[operand] = Unknown
            else:
                marker_state[operand] = Input(operand)
        after = self._semantics.symbolic.transfer_instruction(
            instruction, marker_state
        )
        level = vlen_dependency(after.get(register))
        if level == DEPENDENCY_INDEPENDENT:
            # A value proven independent still only holds where the defining
            # instruction ran; ``_prove_definition`` adds that control
            # dependence on the single exit all definitions share.
            return self._record(
                PROVEN,
                R_ARITHMETIC,
                function.start,
                address,
                register,
                "the scalar model derives the value from independent operands",
                tuple(depends),
            )
        if level == DEPENDENCY_VLEN:
            return self._record(
                VLEN,
                R_VLEN_FLOW,
                function.start,
                address,
                register,
                "the value is derived from a vlenb read",
                tuple(depends),
            )
        worst = self._worst_proof(depends)
        if worst is not None and self._proofs[worst].status == UNPROVEN:
            node = self._proofs[worst]
            return self._record(
                UNPROVEN,
                node.reason,
                function.start,
                address,
                register,
                f"the value inherits the unproven operand: {node.detail}",
                (worst,),
            )
        return self._record(
            UNPROVEN,
            G_UNMODELLED,
            function.start,
            address,
            register,
            "the scalar model cannot interpret this operation",
            tuple(depends),
        )

    def _prove_load(
        self,
        function: Function,
        address: int,
        register: str,
        operands: tuple[str, int, int],
    ) -> str:
        context = self._context(function)
        base, displacement, width = operands
        expression = context.expressions.before_states.get(address, {}).get(base)
        location = self._location(function, expression, displacement, width)
        if location is None:
            return self._record(
                UNPROVEN,
                G_MEMORY,
                function.start,
                address,
                register,
                f"the address in {base} is not a provable object plus a constant",
            )
        sources, complete = self._reaching_memory_sources(context, address, location)
        if not sources:
            return self._record(
                UNPROVEN,
                G_NO_WRITER,
                function.start,
                address,
                register,
                f"no write to {location.describe()} exists in this binary",
            )
        verdicts = [
            self._prove_memory_source(function, source, location, address)
            for source in sources
        ]
        if not complete:
            verdicts.append(
                self._record(
                    UNPROVEN,
                    G_NO_WRITER,
                    function.start,
                    address,
                    register,
                    f"a path reaches this load without writing "
                    f"{location.describe()}",
                )
            )
        return self._join_verdicts(verdicts)

    def _prove_memory_source(
        self,
        function: Function,
        source: tuple[str, int],
        location: _Location,
        load_address: int,
    ) -> str:
        kind, address = source
        if kind == "call":
            return self._prove_call_memory(function, address, location)
        context = self._context(function)
        instruction = context.instructions[address]
        if kind == "alias":
            return self._record(
                UNPROVEN,
                G_ALIAS,
                function.start,
                address,
                None,
                f"a write whose object cannot be resolved may modify "
                f"{location.describe()}",
            )
        operands = context.memory_operands(address)
        if operands is None:
            return self._prove_vector_store(function, address, location)
        base, displacement, width = operands
        store_expression = context.expressions.before_states.get(address, {}).get(base)
        store_location = self._location(
            function, store_expression, displacement, width
        )
        uncovered = store_location is None or not store_location.covers(location)
        value_proof = self.prove_register_before(
            function,
            address,
            _stored_value_register(
                self._semantics, instruction, str(instruction.args[0])
            ),
        )
        status = self._proofs[value_proof].status
        if status != PROVEN:
            return self._record(
                status,
                self._proofs[value_proof].reason,
                function.start,
                address,
                None,
                f"the value stored into {location.describe()} is not proven: "
                f"{self._proofs[value_proof].detail}",
                (value_proof,),
            )
        if uncovered:
            return self._record(
                UNPROVEN,
                G_PARTIAL,
                function.start,
                address,
                None,
                f"the write does not completely cover {location.describe()}",
                (value_proof,),
            )
        if context.dependencies.control_dependent(address):
            # The stored value is proven, but *whether this write happened*
            # was selected by a condition that is not proven independent:
            # on the paths that skip it, the earlier content survives.
            return self._record(
                UNPROVEN,
                G_CONTROL,
                function.start,
                address,
                None,
                "the write to "
                f"{location.describe()} runs under a branch that is not "
                "proven independent of vlenb",
                (value_proof,),
            )
        return self._record(
            PROVEN,
            _object_certificate(location),
            function.start,
            address,
            None,
            f"the write completely covers {location.describe()} with a proven value",
            (value_proof,),
        )

    def _prove_vector_store(
        self, function: Function, address: int, location: _Location
    ) -> str:
        """A vector stack store leaves VLEN-sized bytes behind."""

        context = self._context(function)
        base = getattr(self._semantics, "vector_memory_base", None)
        operands = base(context.instructions[address]) if callable(base) else None
        covers = False
        if operands is not None:
            register, displacement = operands
            expression = (
                context.expressions.before_states.get(address, {}).get(register)
            )
            store_location = self._location(
                function, expression, displacement, 1
            )
            covers = (
                store_location is not None
                and store_location.object_key == location.object_key
                and store_location.start == location.start
                and location.size <= 1
            )
        if covers:
            return self._record(
                VLEN,
                R_VECTOR_STORE,
                function.start,
                address,
                None,
                "a vector stack store covers the loaded bytes",
            )
        return self._record(
            UNPROVEN,
            G_PARTIAL,
            function.start,
            address,
            None,
            "a vector stack store overlaps the loaded range without proving "
            "how many bytes it wrote",
        )

    def _reaching_memory_sources(
        self,
        context: _FunctionContext,
        address: int,
        location: _Location,
    ) -> tuple[tuple[tuple[str, int], ...], bool]:
        """Writes that may have produced the bytes at ``location``.

        Returns the sources and whether *every* path to the load crosses a
        write that completely covers the range.  The walk stops at a covering
        write (nothing before it can matter) and reports an unresolved object
        as an alias, which stops the proof; a path that reaches the function
        entry without crossing one leaves the bytes uninitialised as far as
        this binary can tell, which is just as unusable.
        """

        clobbered = getattr(
            self._semantics, "call_clobbered_scalar_registers", None
        )
        scalar_memory = getattr(self._semantics, "scalar_memory_operand", None)
        vector_operand = getattr(self._semantics, "vector_memory_operand", None)
        sources: list[tuple[str, int]] = []
        entry = context.function.insts[0].addr
        # Same entry rule as the register walk: when the query point *is* the
        # entry, the walk starts with it in ``visited`` and a back edge can
        # never "reach" it again - but the first execution reads whatever the
        # caller left at the location, so the external path participates.
        complete = address != entry
        visited = {address}
        worklist = deque(context.predecessors.get(address, ()))
        budget = self._budget_left()
        while worklist and budget > 0:
            budget -= 1
            current = worklist.popleft()
            if current in visited:
                continue
            visited.add(current)
            instruction = context.instructions.get(current)
            if instruction is None:
                continue
            if callable(clobbered) and clobbered(instruction):
                effect = self._call_memory_effect(context.function, current, location)
                if effect == "clean":
                    # The callee provably leaves these bytes alone, so the
                    # value comes from further back.
                    worklist.extend(context.predecessors.get(current, ()))
                    continue
                sources.append(("call", current))
                if effect == "may-write" or context.dependencies.control_dependent(
                    current
                ):
                    # The call only *may* have written the range - either
                    # because a target may skip the write, or because the call
                    # itself runs under a condition that is not proven
                    # independent.  On the paths that skip it the pre-call
                    # value is still there, so the sources behind the call
                    # stay in the verdict.
                    worklist.extend(context.predecessors.get(current, ()))
                continue
            if callable(vector_operand) and vector_operand(instruction) is not None:
                sources.append(("store", current))
                continue
            operand = scalar_memory(instruction) if callable(scalar_memory) else None
            if operand is None:
                may_write = getattr(self._semantics, "may_write_memory", None)
                if callable(may_write) and may_write(instruction):
                    # An unmodelled memory write: the bytes behind it cannot
                    # be attributed, so the proof stops here.
                    sources.append(("alias", current))
                    continue
                if current == entry:
                    complete = False
                worklist.extend(context.predecessors.get(current, ()))
                continue
            base, displacement, width = operand
            if self._semantics.is_scalar_load(instruction):
                if current == entry:
                    complete = False
                worklist.extend(context.predecessors.get(current, ()))
                continue
            expression = context.expressions.before_states.get(current, {}).get(base)
            store_location = self._location(
                context.function, expression, displacement, width
            )
            if store_location is None:
                sources.append(("alias", current))
                continue
            if store_location.object_key == location.object_key:
                may_touch = store_location.overlaps(location)
                covering = store_location.covers(location)
            else:
                # Different object keys: the same alias table the summary
                # consumer applies.  Only the frame is provably distinct -
                # two different formal names may be the same pointer handed
                # down twice, and a formal may hold any static address.  A
                # may-alias store cannot prove coverage, but it must
                # participate: the loaded bytes may be the value it wrote.
                may_touch = (
                    store_location.kind != _OBJECT_FRAME
                    and location.kind != _OBJECT_FRAME
                )
                covering = False
            if may_touch:
                sources.append(("store", current))
                if covering and not self._unstable_store(instruction):
                    # A stable store completely overwrites these bytes with a
                    # value the walk proves on its own.  A read-modify-write
                    # consumes the old content, and a store-conditional may
                    # not store at all - both keep the earlier sources in the
                    # verdict, because what the location holds afterwards
                    # depends on what was there before.
                    continue
            if current == entry:
                complete = False
            worklist.extend(context.predecessors.get(current, ()))
        if budget <= 0:
            self._budget_exhausted = True
            sources.append(("alias", address))
            complete = False
        return tuple(sources), complete

    def _location(
        self,
        function: Function,
        expression: object,
        displacement: int,
        width: int,
    ) -> _Location | None:
        if not isinstance(expression, Expr):
            return None
        affine = _affine_terms(expression)
        if affine is None:
            return None
        coefficients, constant = affine
        if not coefficients:
            start = constant + displacement
            return _Location(_OBJECT_STATIC, None, start, width)
        if len(coefficients) != 1:
            return None
        atom, coefficient = next(iter(coefficients.items()))
        if coefficient != 1 or atom.kind != "input":
            return None
        register = str(atom.args[0])
        if register == "sp":
            return _Location(
                _OBJECT_FRAME, function.start, constant + displacement, width
            )
        return _Location(
            _OBJECT_PARAM, (function.start, register), constant + displacement, width
        )

    # endregion

    # region cross-function summaries

    def _prove_callee_return(self, function: Function, address: int) -> str:
        context = self._context(function)
        instruction = context.instructions[address]
        # The call's control dependence is applied on the shared definition
        # exit in ``_prove_definition`` - the same rule every definition kind
        # answers to - so this proof only has to establish the callee's value.
        targets, empty_reason = self._call_targets(context, address)
        if targets is None:
            return self._record(
                UNPROVEN,
                G_TARGETS,
                function.start,
                address,
                "a0",
                "the indirect call has no complete internal target set",
            )
        if not targets:
            return self._record(
                UNPROVEN,
                empty_reason or G_EXTERNAL,
                function.start,
                address,
                "a0",
                f"the call to {self._target_note(context, address)} "
                + (
                    "leaves this binary; its result has no contract here"
                    if empty_reason != G_NO_BODY
                    else "has no body in this analysis; its result is unproven"
                ),
            )
        verdicts: list[str] = []
        for target in targets:
            verdicts.append(self._instantiate_return(function, address, target))
        return self._join_verdicts(verdicts)

    def _instantiate_return(
        self, function: Function, address: int, target: int
    ) -> str:
        summary = self._summary(target)
        if summary is None:
            return self._record(
                UNPROVEN,
                G_NO_BODY,
                function.start,
                address,
                "a0",
                f"no body is available for callee {target:#x}",
            )
        if summary.partial:
            return self._record(
                UNPROVEN,
                G_RECURSION,
                function.start,
                address,
                "a0",
                f"the summary of callee {target:#x} did not converge",
            )
        if summary.return_status == VLEN:
            return self._record(
                VLEN,
                R_CALLEE_VLEN,
                function.start,
                address,
                "a0",
                f"callee {target:#x} returns a vlenb-derived value",
            )
        if summary.return_status == UNPROVEN:
            return self._record(
                UNPROVEN,
                summary.return_reason,
                function.start,
                address,
                "a0",
                f"callee {target:#x} does not prove its result: "
                f"{summary.return_reason}",
            )
        depends: list[str] = []
        for name in sorted(summary.return_dependencies):
            if name == _VLEN_NAME:
                return self._record(
                    VLEN,
                    R_CALLEE_VLEN,
                    function.start,
                    address,
                    "a0",
                    f"callee {target:#x} returns a vlenb-derived value",
                )
            if name == _MEMORY_INPUT:
                return self._record(
                    UNPROVEN,
                    G_NO_WRITER,
                    function.start,
                    address,
                    "a0",
                    f"callee {target:#x} returns a value read from memory, "
                    "whose writer is not established",
                )
            proof_id = self.prove_register_before(function, address, name)
            if self._proofs[proof_id].status != PROVEN:
                depends.append(proof_id)
        if depends:
            worst = self._worst_proof(tuple(depends))
            node = self._proofs[worst]
            return self._record(
                node.status,
                node.reason,
                function.start,
                address,
                "a0",
                f"callee {target:#x} returns a value derived from {node.detail}",
                tuple(depends),
            )
        return self._record(
            PROVEN,
            R_CALLEE_RETURN,
            function.start,
            address,
            "a0",
            "the callee returns a value derived only from independent arguments"
            if not summary.return_dependencies
            else "the callee's result depends only on proven arguments",
            tuple(depends),
        )

    def _prove_call_memory(
        self,
        function: Function,
        address: int,
        location: _Location,
    ) -> str:
        context = self._context(function)
        if context.dependencies.control_dependent(address):
            # The write source is the call, and the call runs under a
            # condition that is not proven independent: whether the stored
            # value is in the slot at all was selected by that condition.
            # This is only reached for calls that may or must write, so the
            # guard genuinely matters here.
            return self._record(
                UNPROVEN,
                G_CONTROL,
                function.start,
                address,
                None,
                "the call may write "
                f"{location.describe()} under a branch that is not proven "
                "independent of vlenb",
            )
        targets, empty_reason = self._call_targets(context, address)
        if targets is None or not targets:
            return self._record(
                UNPROVEN,
                G_TARGETS if targets is None else (empty_reason or G_EXTERNAL),
                function.start,
                address,
                None,
                f"the call to {self._target_note(context, address)} cannot be "
                f"accounted for, so {location.describe()} may be modified",
            )
        verdicts: list[str] = []
        for target in targets:
            verdicts.append(
                self._instantiate_call_memory(function, address, target, location)
            )
        return self._join_verdicts(verdicts)

    def _instantiate_call_memory(
        self,
        function: Function,
        address: int,
        target: int,
        location: _Location,
    ) -> str:
        summary = self._summary(target)
        if summary is None:
            return self._record(
                UNPROVEN,
                G_NO_BODY,
                function.start,
                address,
                None,
                f"no body is available for callee {target:#x}, so "
                f"{location.describe()} may be modified",
            )
        if summary.partial:
            return self._record(
                UNPROVEN,
                G_RECURSION,
                function.start,
                address,
                None,
                f"the summary of callee {target:#x} did not converge",
            )
        # A callee that may write what it cannot account for invalidates the
        # proof even when it also has a known write to this range: the unknown
        # write may reach the same bytes.
        if summary.unknown_memory:
            return self._record(
                UNPROVEN,
                G_ALIAS,
                function.start,
                address,
                None,
                f"callee {target:#x} may write memory it cannot account for, "
                f"so {location.describe()} is not protected",
            )
        escaped = [
            name
            for name in summary.escapes
            if self._pointer_may_reach(function, address, name, location)
        ]
        if escaped:
            return self._record(
                UNPROVEN,
                G_ALIAS,
                function.start,
                address,
                None,
                f"callee {target:#x} hands the object behind {escaped[0]} to "
                "code whose body is not available",
            )
        written = [
            entry
            for entry in summary.writes
            if self._write_touches(function, address, entry, location)
        ]
        if not written:
            return self._record(
                PROVEN,
                R_CALLEE_RETURN,
                function.start,
                address,
                None,
                f"callee {target:#x} provably does not write {location.describe()}",
            )
        # Instantiate the callee's write at *this* call site: the value it
        # stores is only proven if the arguments it derived that value from are
        # proven here, and the write must cover the whole range.
        verdicts: list[str] = []
        for entry in written:
            verdicts.append(
                self._instantiate_write(function, address, target, entry, location)
            )
        return self._join_verdicts(verdicts)

    def _instantiate_write(
        self,
        function: Function,
        address: int,
        target: int,
        entry: MemoryWrite,
        location: _Location,
    ) -> str:
        if entry.extent_unknown:
            # A vector store: the bytes it covers and their provenance are
            # not modelled, so what the caller reads afterwards is a VLEN
            # source whether or not the address looks friendly.
            return self._record(
                VLEN,
                R_VECTOR_STORE,
                function.start,
                address,
                None,
                f"callee {target:#x} stores a vector register through a "
                "pointer; the bytes it covers and their provenance are not "
                "modelled",
            )
        if entry.object == "static":
            written_range = _Location(
                _OBJECT_STATIC, None, entry.offset, entry.size
            )
        else:
            argument = self._argument_location(function, address, entry.register)
            if argument is None:
                return self._record(
                    UNPROVEN,
                    G_ALIAS,
                    function.start,
                    address,
                    None,
                    f"callee {target:#x} writes through {entry.register}, whose "
                    "object cannot be identified here",
                )
            written_range = _Location(
                argument.kind,
                argument.key,
                argument.start + entry.offset,
                entry.size,
            )
        if (
            written_range.kind == _OBJECT_PARAM
            and location.kind == _OBJECT_PARAM
            and written_range.key != location.key
        ):
            # Different formal names were enough to select this write as
            # touching - which is exactly why it cannot prove coverage.
            return self._record(
                UNPROVEN,
                G_ALIAS,
                function.start,
                address,
                None,
                f"callee {target:#x} writes through a pointer that may alias "
                f"{location.describe()}: distinct formal names are not a "
                "non-alias proof",
            )
        if not written_range.covers(location):
            return self._record(
                UNPROVEN,
                G_PARTIAL,
                function.start,
                address,
                None,
                f"callee {target:#x} writes {entry.size} byte(s) at "
                f"{entry.offset} through {entry.register}, which does not "
                f"completely cover {location.describe()}",
            )
        if entry.status != PROVEN:
            return self._record(
                entry.status,
                entry.reason,
                function.start,
                entry.address,
                None,
                f"callee {target:#x} cannot prove what it stores at "
                f"{entry.address:#x}",
            )
        depends: list[str] = []
        for name in sorted(entry.dependencies):
            if name == _VLEN_NAME:
                return self._record(
                    VLEN,
                    R_CALLEE_VLEN,
                    function.start,
                    address,
                    None,
                    f"callee {target:#x} stores a vlenb-derived value at "
                    f"{entry.address:#x}",
                )
            if name == _MEMORY_INPUT:
                return self._record(
                    UNPROVEN,
                    G_NO_WRITER,
                    function.start,
                    address,
                    None,
                    f"callee {target:#x} stores a value read from memory at "
                    f"{entry.address:#x}",
                )
            proof_id = self.prove_register_before(function, address, name)
            if self._proofs[proof_id].status != PROVEN:
                depends.append(proof_id)
        if depends:
            worst = self._proofs[self._worst_proof(tuple(depends))]
            return self._record(
                worst.status,
                worst.reason,
                function.start,
                address,
                None,
                f"callee {target:#x} stores a value derived from {worst.detail}",
                tuple(depends),
            )
        return self._record(
            PROVEN,
            _object_certificate(location),
            function.start,
            address,
            None,
            f"callee {target:#x} writes {location.describe()} with a value "
            "proven independent here"
            + (
                " on every path to its return"
                if entry.on_every_path
                else " whenever that write executes"
            ),
        )

    def _sp_offset_at(self, context: _FunctionContext, address: int) -> int | None:
        """The current ``sp`` relative to the function's entry ``sp``.

        ``None`` when the offset is not a proven constant: a frame whose size
        is dynamic has no provable private region at all.
        """

        expression = context.expressions.before_states.get(address, {}).get("sp")
        if not isinstance(expression, Expr):
            return None
        affine = _affine_terms(expression)
        if affine is None:
            return None
        coefficients, constant = affine
        if len(coefficients) != 1:
            return None
        atom, coefficient = next(iter(coefficients.items()))
        if coefficient != 1 or atom.kind != "input" or str(atom.args[0]) != "sp":
            return None
        return constant

    def _frame_region_is_private(
        self,
        sp_offset: int | None,
        start: int,
        width: int,
        *,
        extent_unknown: bool,
    ) -> bool:
        """Whether a write at ``[entry sp + start, +width)`` is the function's
        own newly allocated frame.

        Four conditions, all required: the current ``sp`` sits below the
        entry ``sp`` by a proven constant (the function actually allocated),
        the write is at or above that ``sp``, the whole write ends at or
        below the entry ``sp``, and the write's extent is modelled.  A
        function that never adjusts ``sp`` has its caller's ``sp`` as its
        entry ``sp``, so ``entry sp + 0`` is the caller's frame, not private
        memory - and a write whose extent is not modelled (a vector store)
        can never prove it stays inside the allocation.
        """

        return (
            sp_offset is not None
            and not extent_unknown
            and sp_offset < 0
            and start >= sp_offset
            and start + width <= 0
        )

    def _unstable_store(self, instruction) -> bool:
        """Whether the store's effect depends on the past or on luck.

        A read-modify-write consumes the old memory content; a
        store-conditional may not store at all.  Neither can stop the
        reaching-write walk the way a stable store does.
        """

        rmw = getattr(self._semantics, "is_read_modify_write", None)
        conditional = getattr(self._semantics, "is_conditional_store", None)
        return (callable(rmw) and rmw(instruction)) or (
            callable(conditional) and conditional(instruction)
        )

    def _write_touches(
        self,
        function: Function,
        address: int,
        entry: MemoryWrite,
        location: _Location,
    ) -> bool:
        """Whether the write, instantiated here, may touch ``location``.

        The alias table is deliberately narrow - most pairs have *no* proof:

        * this function's own frame is provably distinct from everything else
          (the frame is allocated after the arguments were fixed, and a frame
          address is never a static address);
        * two distinct formal parameters are **not** a non-alias proof: the
          caller may pass the same pointer twice;
        * a formal pointer and a static object are **not** a non-alias proof:
          the pointer may hold that very address;
        * a pointer that cannot be attributed here may hit anything.
        """

        if entry.object == "static":
            write_kind, write_key = _OBJECT_STATIC, None
            write_start = entry.offset
        else:
            argument = self._argument_location(function, address, entry.register)
            if argument is None:
                return True
            write_kind, write_key = argument.kind, argument.key
            write_start = argument.start + entry.offset
        if write_kind == _OBJECT_FRAME or location.kind == _OBJECT_FRAME:
            # The one provable disjointness.
            return (
                write_kind == location.kind
                and write_key == location.key
                and write_start < location.end
                and location.start < write_start + _write_span(entry)
            )
        if write_kind != location.kind:
            # Static vs param, in either direction.
            return True
        if write_kind == _OBJECT_PARAM and write_key != location.key:
            # Different names are different *sources*, not different objects.
            return True
        if entry.extent_unknown:
            return write_start < location.end
        return (
            write_start < location.end
            and location.start < write_start + entry.size
        )

    def _merge_callee_memory(
        self,
        function: Function,
        context: _FunctionContext,
        call_site_states: dict[int, dict[str, frozenset[str] | None]],
        address: int,
        targets: frozenset[int],
        control: frozenset[str] | None,
        writes: list[MemoryWrite],
        escapes: set[str],
        gaps: list[str],
    ) -> bool:
        """Fold resolved callees' memory effects into this summary.

        Returns True when an effect could not be accounted for.  A callee's
        writes are re-expressed in *this* function's variables: its formal
        base becomes this function's register at the call site (a direct call
        preserves every register but ``ra``), its dependence names are
        substituted the way the return value is, and "runs on every path"
        additionally requires the call itself to run on every path.  A summary
        that stays silent here would let a nested call's write hide behind the
        caller's own proven store.

        Two path conditions survive the merge:

        * *must-write is intersected over the complete target set.*  One
          target writing a range unconditionally is not coverage when another
          target of the same call leaves it alone - the paths that choose the
          other target keep the pre-call value.
        * *the call's own guard rides along.*  A nested write happens only
          when this call executes, so a guard that is not proven independent
          leaves the write unproven, and a proven guard joins the write's
          dependencies: which value the slot holds afterwards was *selected*
          by that guard, however constant the stored value is.
        """

        unknown = False
        on_call_path = address in context.always_executed
        merged_writes: list[tuple[int, MemoryWrite, _Location | None]] = []
        covered: dict[int, list[_Location]] = {}
        for target in sorted(targets):
            summary = self._summary(target)
            if summary is None:
                unknown = True
                gaps.append(G_NO_BODY)
                covered[target] = []
                continue
            if summary.partial:
                unknown = True
                gaps.append(G_RECURSION)
                covered[target] = []
                continue
            gaps.extend(summary.gaps)
            if summary.unknown_memory:
                # The callee writes what it cannot account for; neither can
                # this summary.
                unknown = True
                covered[target] = []
                continue
            covered[target] = []
            for name in sorted(summary.escapes):
                base = self._escape_base(function, context, address, name)
                if base is None:
                    unknown = True
                    gaps.append(G_ALIAS)
                elif base:
                    escapes.add(base)
            for entry in summary.writes:
                outcome, merged, location = self._rebase_write(
                    function,
                    context,
                    call_site_states,
                    address,
                    entry,
                    on_call_path,
                    control,
                )
                if outcome == "unknown":
                    unknown = True
                    gaps.append(G_ALIAS)
                elif outcome == "ok":
                    merged_writes.append((target, merged, location))
                    if merged.on_every_path and location is not None:
                        covered[target].append(location)
        for origin, merged, location in merged_writes:
            if (
                merged.on_every_path
                and len(targets) > 1
                and location is not None
            ):
                for other in sorted(targets):
                    if other == origin:
                        continue
                    if not any(
                        other_location.covers(location)
                        for other_location in covered.get(other, ())
                    ):
                        merged = replace(merged, on_every_path=False)
                        break
            writes.append(merged)
        return unknown

    def _rebase_write(
        self,
        function: Function,
        context: _FunctionContext,
        call_site_states: dict[int, dict[str, frozenset[str] | None]],
        address: int,
        entry: MemoryWrite,
        on_call_path: bool,
        control: frozenset[str] | None,
    ) -> tuple[str, MemoryWrite | None, _Location | None]:
        """Re-express a callee's write against this call site's arguments.

        ``"frame"`` means the write lands in *this* function's own frame and
        cannot reach any caller object; ``"unknown"`` means the address cannot
        be attributed here; ``"ok"`` carries the rebased write together with
        the caller-side location it lands on.

        Dependence names are substituted against the call site's *incoming*
        state - what the call passed in - never against its outgoing state,
        which already reflects the clobber the call performs.  The call's own
        guard rides along: a nested write happens only when this call
        executes, so a guard that is not proven independent (``control is
        None``) leaves the write unproven - the stored value may be a
        constant, but *whether the slot holds it* is selected by that guard -
        and a proven guard joins the write's dependencies, to be discharged by
        whoever consumes this summary.
        """

        status, reason = entry.status, entry.reason
        on_every_path = entry.on_every_path and on_call_path
        if control is None:
            status, reason, on_every_path = UNPROVEN, G_CONTROL, False
        if entry.object == "static":
            # A fixed address needs no rebasing - but the *value* dependence
            # is still expressed in the callee's variables and must be
            # substituted at this call site exactly like a formal write's:
            # the callee stored its formal, and the caller decides what that
            # formal held.  The guard applies on top.
            names = self._callee_side_names(
                call_site_states, address, entry.dependencies
            )
            if names is None:
                status, reason = UNPROVEN, G_UNMODELLED
            if control is None:
                status, reason, on_every_path = UNPROVEN, G_CONTROL, False
            elif control and names is not None:
                names = names | control
            dependencies = (
                frozenset() if control is None or names is None else names
            )
            return (
                "ok",
                replace(
                    entry,
                    status=status,
                    reason=reason,
                    dependencies=dependencies,
                    on_every_path=on_every_path,
                ),
                _Location(_OBJECT_STATIC, None, entry.offset, entry.size),
            )
        expression = context.expressions.before_states.get(address, {}).get(
            entry.register
        )
        location = self._location(function, expression, entry.offset, entry.size)
        if location is None:
            return "unknown", None, None
        if location.kind == _OBJECT_FRAME:
            # A frame-typed address is the callee's own only under the same
            # privacy proof a direct write needs.  A nested callee handed
            # ``sp`` (directly or through arithmetic) writes where *this*
            # function's frame is - or, when this function never allocated,
            # where its caller's frame is.
            if self._frame_region_is_private(
                self._sp_offset_at(context, address),
                location.start,
                entry.size,
                extent_unknown=entry.extent_unknown,
            ):
                return "frame", None, None
            return "unknown", None, None
        names = self._callee_side_names(
            call_site_states, address, entry.dependencies
        )
        if names is None:
            status, reason = UNPROVEN, G_UNMODELLED
        elif control:
            names = names | control
        if location.kind == _OBJECT_STATIC:
            # The callee's formal held a *static* address at this call site:
            # the rebased write is a static object - absolute offset, no base
            # register - with the substituted value dependencies and the
            # guard intact.  Reaching here with a param-style ``key`` would
            # crash; the object type must follow the rebased location.
            return (
                "ok",
                replace(
                    entry,
                    object="static",
                    register="",
                    offset=location.start,
                    status=status,
                    reason=reason,
                    dependencies=frozenset() if names is None else names,
                    on_every_path=on_every_path,
                ),
                _Location(_OBJECT_STATIC, None, location.start, entry.size),
            )
        return (
            "ok",
            replace(
                entry,
                register=str(location.key[1]),
                offset=location.start,
                status=status,
                reason=reason,
                dependencies=frozenset() if names is None else names,
                on_every_path=on_every_path,
            ),
            location,
        )

    @staticmethod
    def _callee_side_names(
        states: dict[int, dict[str, frozenset[str] | None]],
        address: int,
        dependencies: frozenset[str],
    ) -> frozenset[str] | None:
        """Substitute a callee's dependence names with this function's own.

        A name the callee derived from its formal ``r`` becomes whatever this
        function's ``r`` holds at the call site.  A register that was never
        mentioned here still *stands for itself* - its value is this
        function's incoming argument, which is exactly the dependence variable
        a summary is expressed in - while an explicitly unproven value stays
        unproven.  ``vlenb`` and ``memory`` pass through unchanged.
        """

        names: set[str] = set()
        state = states.get(address)
        for name in sorted(dependencies):
            if name in (_VLEN_NAME, _MEMORY_INPUT):
                names.add(name)
                continue
            if state is not None and name in state:
                value = state[name]
                if value is None:
                    return None
                names |= value
            else:
                names.add(name)
        return frozenset(names)

    def _escape_base(
        self,
        function: Function,
        context: _FunctionContext,
        address: int,
        name: str,
    ) -> str | None:
        """This function's formal behind a callee's escaped pointer.

        ``""`` means the escape cannot reach a caller-named object (it points
        into this function's own frame); ``None`` means it cannot be
        attributed at all.
        """

        expression = context.expressions.before_states.get(address, {}).get(name)
        location = self._location(function, expression, 0, 1)
        if location is None:
            return None
        if location.kind == _OBJECT_PARAM:
            return str(location.key[1])
        if location.kind == _OBJECT_FRAME:
            # An escape into the frame is harmless only when the pointed-to
            # region is provably the function's own new allocation; the
            # frame-base name alone says nothing about ownership.
            if self._frame_region_is_private(
                self._sp_offset_at(context, address),
                location.start,
                1,
                extent_unknown=False,
            ):
                return ""
            return None
        return None

    def _call_memory_effect(
        self, function: Function, address: int, location: _Location
    ) -> str:
        """``must-write`` / ``may-write`` / ``clean`` / ``unknown`` for one call.

        Used by the reaching-write walk to decide what a call means for a
        range.  ``must-write`` says every path through the callee writes the
        whole range, so the walk may stop there; ``may-write`` says the range
        is touched but not guaranteed - the pre-call value survives on the
        paths that skip the write, so the caller keeps both the call *and* the
        sources behind it.  Only a call that provably leaves the range alone is
        ``clean``.
        """

        context = self._context(function)
        targets, _reason = self._call_targets(context, address)
        if targets is None or not targets:
            return "unknown"
        effects: set[str] = set()
        for target in targets:
            summary = self._summary(target)
            if summary is None or summary.partial or summary.unknown_memory:
                effects.add("unknown")
                continue
            if any(
                self._pointer_may_reach(function, address, name, location)
                for name in summary.escapes
            ):
                # The callee hands the object to code with no body: it may be
                # written, and it is certainly not proven written.
                effects.add("may-write")
                continue
            if any(
                self._covers_location(function, address, entry, location)
                and entry.on_every_path
                for entry in summary.writes
            ):
                effects.add("must-write")
                continue
            if any(
                self._write_touches(function, address, entry, location)
                for entry in summary.writes
            ):
                effects.add("may-write")
                continue
            effects.add("clean")
        if "unknown" in effects:
            return "unknown"
        if effects == {"must-write"}:
            # Coverage has to hold for the *complete* target set: one target
            # writing the range unconditionally is not coverage when another
            # target of the same call leaves it alone - the paths that choose
            # the other target keep the pre-call value.
            return "must-write"
        if "must-write" in effects or "may-write" in effects:
            return "may-write"
        return "clean"

    def _covers_location(
        self,
        function: Function,
        address: int,
        entry: MemoryWrite,
        location: _Location,
    ) -> bool:
        """Whether the write, instantiated here, covers the whole range."""

        if entry.extent_unknown:
            # The range a vector store covers is not modelled: however well
            # the address is known, this is never provable coverage.
            return False
        if entry.object == "static":
            if location.kind != _OBJECT_STATIC:
                return False
            start = entry.offset
        else:
            argument = self._argument_location(function, address, entry.register)
            if argument is None or argument.object_key != location.object_key:
                return False
            start = argument.start + entry.offset
        return (
            start <= location.start and location.end <= start + entry.size
        )

    def _argument_location(
        self, function: Function, address: int, register: str
    ) -> _Location | None:
        """The abstract object the value in ``register`` points into."""

        context = self._context(function)
        expression = context.expressions.before_states.get(address, {}).get(register)
        return self._location(function, expression, 0, 1)

    def _argument_object(
        self, function: Function, address: int, register: str
    ) -> tuple | None:
        """The object key of the object a formal parameter points at."""

        location = self._argument_location(function, address, register)
        return None if location is None else location.object_key

    def _pointer_may_reach(
        self,
        function: Function,
        address: int,
        register: str,
        location: _Location,
    ) -> bool:
        """Whether the pointer in ``register`` may hit ``location``.

        The same rule :meth:`_write_touches` applies, without a range: two
        distinct formal names are not a non-alias proof, a pointer handed down
        from above may hold any static address, and an unattributable pointer
        may hit anything.  Only this function's own frame is provably distinct.
        """

        argument = self._argument_location(function, address, register)
        if argument is None:
            return True
        if argument.kind == _OBJECT_FRAME or location.kind == _OBJECT_FRAME:
            return argument.kind == location.kind and argument.key == location.key
        return True

    def _register_missing_call_targets(self) -> None:
        """Register direct call targets without a readable body, up front.

        ``_call_targets`` registers a missing body when a proof resolves a
        call - so a proof that stops before resolving one (the guarded-call
        return check, a budget gap) used to remove that body from the
        forensic list.  Walking every analysed call once at construction
        makes the list a property of the program, not of the proof order.
        Only direct targets are covered here; nested registration through a
        callee summary stays lazy.  Without a call detector the scan is
        skipped: keying on ``jump_targets`` alone would read conditional
        branches as calls.
        """

        is_call = getattr(self._semantics, "is_call_instruction", None)
        if not callable(is_call):
            return
        for function in self._functions.values():
            for instruction in function.insts:
                if is_call(instruction):
                    self._call_targets_of(instruction)

    def _call_targets(
        self, context: _FunctionContext, address: int
    ) -> tuple[frozenset[int] | None, str]:
        """Complete internal target set of a call, plus why it is empty.

        A direct call to an address that is not part of the analysed program is
        *not* the same as an external call: it is an internal target whose body
        was not included, and the gap says so.  That distinction is what turns
        "unproven" into an actionable request for one function body instead of
        a shrug.
        """

        return self._call_targets_of(context.instructions[address])

    def _call_targets_of(
        self, instruction, *, prefer_metadata: bool = False
    ) -> tuple[frozenset[int] | None, str]:
        """The same resolution, from the instruction alone."""

        # A disassembler's resolved indirect-call comment can name one member
        # of a larger compiler target set. Register-effect proofs must not
        # prune that set; legacy size/memory queries keep their old selection.
        entry = (self._metadata.function_pointer.get(instruction.addr)
                 if self._metadata is not None else None)
        if len(instruction.jump_targets) == 1 and not (prefer_metadata and entry is not None):
            target = next(iter(instruction.jump_targets))
            function = self._functions.get(target)
            if function is None:
                self._missing_callees.setdefault(target, G_NO_BODY)
                return frozenset(), G_NO_BODY
            if function.is_external_trampoline:
                self._missing_callees.setdefault(
                    target, G_EXTERNAL
                )
                return frozenset(), G_EXTERNAL
            return frozenset({target}), ""
        if self._metadata is None:
            return None, G_TARGETS
        if entry is None or not entry.usable:
            return None, G_TARGETS
        if any(
            target not in self._functions
            or self._functions[target].is_external_trampoline
            for target in entry.targets
        ):
            # A target set containing an address without a provable body is
            # not complete.  Proving the internal subset would say nothing
            # about where the call may really land, so the whole set fails.
            return None, G_TARGETS
        return frozenset(entry.targets), ""

    def _target_note(self, context: _FunctionContext, address: int) -> str:
        """The addresses a call names, for a gap message a human can act on."""

        instruction = context.instructions[address]
        targets = sorted(instruction.jump_targets)
        if targets:
            return ", ".join(f"0x{target:x}" for target in targets)
        return "an unresolved pointer"

    def _summary(self, start: int) -> FunctionSummary | None:
        """Summarise one callee, or ``None`` when its body is not available.

        Recursion is a call-graph fixpoint, entered once: while a function's
        summary is being built, a request for it returns the current
        approximation (or, before there is one, "partial").  A second pass then
        runs when the first one consumed that provisional answer, and the
        result is only usable when both passes agree.  A recursion whose value
        really does feed the result stays unproven - which is the point: no
        summary may approve a value derived from its own unfinished answer.
        """

        function = self._functions.get(start)
        if function is None or function.is_external_trampoline:
            return None
        cached = self._summaries.get(start)
        if cached is not None and not cached.partial:
            return cached
        if start in self._summary_inflight:
            if cached is not None:
                return cached
            # The callee needs its own answer: a recursive edge.  Callers must
            # not treat the provisional conclusion as a proof.
            return FunctionSummary(
                function_start=start,
                return_status=UNPROVEN,
                return_reason=G_RECURSION,
                partial=True,
                gaps=(G_RECURSION,),
            )
        if self._summary_requests >= self._summary_budget:
            self._budget_exhausted = True
            return None
        self._summary_requests += 1
        self._summary_inflight.add(start)
        saved_recursion = self._consumed_recursion
        self._consumed_recursion = False
        # ``_missing_callees`` is created once, in the prover's constructor,
        # and accumulates for the whole check: rebuilding it per summary
        # would make the forensic list depend on the analysis order.
        try:
            summary = self._compute_summary(function)
            if summary.partial:
                self._summaries[start] = summary
                second = self._compute_summary(function)
                summary = (
                    replace(second, partial=False)
                    if second == summary
                    else second
                )
        finally:
            self._summary_inflight.discard(start)
            self._consumed_recursion = saved_recursion
        self._summaries[start] = summary
        return summary

    def _compute_summary(self, function: Function) -> FunctionSummary:
        dataflow = _SummaryDataflow(
            function,
            self._semantics,
            lambda address, incoming: self._summary_call_effect(
                function, address, incoming
            ),
        )
        states, controls, incoming_states = dataflow.run()
        gaps: list[str] = []

        # --- return value: data dependence *and* the branch that selects it --
        return_status = PROVEN
        return_reason = R_CONSTANT
        # Return selection/value and individual stores are separate evidence
        # channels. A later write must never replace the return's formal names.
        return_dependencies: set[str] = set()
        unproven_exit = False
        control_unproven = False
        for exit_address in self._exits(function):
            control = controls.get(exit_address)
            if control is None:
                # Either the exit is unreachable from the entry or its path is
                # selected by a condition whose dependence cannot be named:
                # neither case may be read as "the returned value is free".
                control_unproven = True
            else:
                return_dependencies |= control
            value = states.get(exit_address, {}).get("a0")
            if value is None:
                unproven_exit = True
                continue
            if _VLEN_NAME in value:
                return_status = VLEN
                return_reason = R_VLEN_FLOW
                continue
            return_dependencies |= value
        if unproven_exit:
            return_status = UNPROVEN
            return_reason = (
                G_RECURSION if self._consumed_recursion else G_UNMODELLED
            )
            gaps.append(return_reason)
        if control_unproven and return_status != VLEN:
            # The selection itself is unprovable: a size that switches with
            # VLEN is a VLEN source even when every branch returns a constant.
            return_status = UNPROVEN
            return_reason = G_CONTROL
            gaps.append(G_CONTROL)
        if _VLEN_NAME in return_dependencies:
            return_status = VLEN
            return_reason = R_VLEN_FLOW
        return_dependencies.discard(_VLEN_NAME)

        # --- writes: value provenance, selection, and path coverage ---------
        #
        # Completeness rule: a summary may only stay silent about memory it
        # fully accounted for.  Every store is recorded - scalar with an
        # address composed from pointer arithmetic, vector with an unmodelled
        # extent - and every resolved callee folds its own effects in.  What
        # cannot be attributed becomes ``unknown_memory``, never silence.
        writes: list[MemoryWrite] = []
        escapes: set[str] = set()
        unknown_memory = False
        context = self._context(function)
        scalar_memory = getattr(self._semantics, "scalar_memory_operand", None)
        vector_base = getattr(self._semantics, "vector_memory_base", None)
        clobbered = getattr(
            self._semantics, "call_clobbered_scalar_registers", None
        )
        for instruction in function.insts:
            address = instruction.addr
            if callable(clobbered) and clobbered(instruction):
                targets, _reason = self._call_targets(context, address)
                if targets is None or not targets:
                    # Code without a body may write through any pointer it was
                    # handed, and anything else reachable from here.
                    unknown_memory = True
                    gaps.append(G_EXTERNAL)
                    for register in _read_scalar_registers(
                        self._semantics, instruction
                    ):
                        escapes.add(register)
                else:
                    if self._merge_callee_memory(
                        function,
                        context,
                        incoming_states,
                        address,
                        targets,
                        controls.get(address),
                        writes,
                        escapes,
                        gaps,
                    ):
                        unknown_memory = True
                continue
            # A scalar store, or a vector one whose extent is not modelled.
            operand = scalar_memory(instruction) if callable(scalar_memory) else None
            extent_unknown = False
            if operand is None:
                parsed = vector_base(instruction) if callable(vector_base) else None
                if parsed is None:
                    may_write = getattr(self._semantics, "may_write_memory", None)
                    if callable(may_write) and may_write(instruction):
                        # An unmodelled memory write: "not modelled" is not
                        # "not written", so the summary cannot stay silent.
                        unknown_memory = True
                        gaps.append(G_UNMODELLED)
                    continue
                base, displacement = parsed
                width = 0
                extent_unknown = True
            else:
                base, displacement, width = operand
                if self._semantics.is_scalar_load(instruction):
                    continue
            # The address is *composed*: the base register's value may have
            # been moved by pointer arithmetic, so the store's own displacement
            # is not the write's offset.  Dependence names cannot prove an
            # address; the affine form "one formal plus a constant" can.
            expression = context.expressions.before_states.get(address, {}).get(base)
            location = self._location(function, expression, displacement, width)
            if location is None:
                unknown_memory = True
                gaps.append(G_ALIAS)
                continue
            if location.kind == _OBJECT_FRAME:
                # A write through the entry ``sp`` is the callee's *own* only
                # when the function has actually allocated the region it
                # writes: the current ``sp`` must sit below the entry ``sp``
                # by a proven constant, the write must be at or above that
                # ``sp``, and the whole write must end at or below the entry
                # ``sp``.  A function that never adjusts ``sp`` has its
                # caller's ``sp`` as its entry ``sp`` - writing there may hit
                # the caller's frame - and a write whose extent is not
                # modelled can never prove it stays inside the allocation.
                # Anything unproven keeps the summary from staying silent.
                sp_offset = location.start - displacement
                if self._frame_region_is_private(
                    sp_offset, location.start, width,
                    extent_unknown=extent_unknown,
                ):
                    continue
                unknown_memory = True
                gaps.append(G_ALIAS)
                continue
            value_names = states.get(address, {}).get(
                _stored_value_register(
                    self._semantics, instruction, str(instruction.args[0])
                )
            )
            control = controls.get(address)
            if extent_unknown:
                # A vector store: the bytes it covers and their provenance are
                # not modelled, which is itself the answer - a VLEN source.
                value_names = None
                status, reason = VLEN, R_VECTOR_STORE
                dependencies: frozenset[str] = frozenset({_VLEN_NAME})
            else:
                status = PROVEN if value_names is not None else UNPROVEN
                reason = R_PARAM_RANGE if value_names is not None else G_UNMODELLED
                dependencies = frozenset() if value_names is None else value_names
            if location.kind == _OBJECT_STATIC:
                kind, register, offset = "static", "", location.start
                if not extent_unknown and value_names is not None:
                    reason = R_STATIC_OBJECT
            else:
                kind, register, offset = "formal", str(location.key[1]), location.start
            if control is None:
                # The write runs under a condition that is not proven
                # independent: even a constant store is not a free value, and
                # the write itself is not coverage.
                value_names = None
                if not extent_unknown:
                    status, reason = UNPROVEN, G_CONTROL
                    dependencies = frozenset()
            if control:
                dependencies = dependencies | control
            if self._unstable_store(instruction):
                # What the location holds afterwards is not described by this
                # write alone: an RMW consumes the old memory content, and a
                # store-conditional may not store at all.  The write stays in
                # the summary, but it is never a guaranteed full overwrite.
                if self._semantics.is_read_modify_write(instruction):
                    dependencies = dependencies | {_MEMORY_INPUT}
                on_every_path = False
            else:
                on_every_path = (
                    address in context.always_executed
                    and control is not None
                )
            writes.append(
                MemoryWrite(
                    register=register,
                    offset=offset,
                    size=width,
                    dependencies=dependencies,
                    address=address,
                    status=status,
                    reason=reason,
                    object=kind,
                    on_every_path=on_every_path,
                    extent_unknown=extent_unknown,
                )
            )
        return FunctionSummary(
            function_start=function.start,
            return_status=return_status,
            return_reason=return_reason,
            return_dependencies=frozenset(return_dependencies),
            writes=tuple(writes),
            escapes=frozenset(escapes),
            unknown_memory=unknown_memory,
            partial=False,
            gaps=tuple(dict.fromkeys(gaps)),
        )

    def _exits(self, function: Function) -> tuple[int, ...]:
        return self._context(function).exits

    # endregion

    # region proof table

    def _budget_left(self) -> int:
        return self._node_budget - self._nodes

    def _budget_proof(
        self, function_start: int, address: int, register: str | None
    ) -> str:
        self._budget_exhausted = True
        return self._record(
            UNPROVEN,
            G_BUDGET,
            function_start,
            address,
            register,
            f"the proof budget of {self._node_budget} nodes was exhausted",
        )

    def _record(
        self,
        status: str,
        reason: str,
        function_start: int,
        address: int,
        register: str | None,
        detail: str,
        depends_on: tuple[str, ...] = (),
    ) -> str:
        """Intern one proof node and return its id."""

        key = (status, reason, function_start, address, register, detail)
        existing = self._cache.get(("node",) + key)
        if existing is not None:
            return existing
        if self._budget_left() <= 0:
            # One last node may be created for the budget gap itself, but the
            # partial result computed so far is never turned into a proof.
            self._budget_exhausted = True
            if reason != G_BUDGET:
                key = (UNPROVEN, G_BUDGET, function_start, address, register, "")
                existing = self._cache.get(("node",) + key)
                if existing is not None:
                    return existing
                status, reason, detail, depends_on = (
                    UNPROVEN,
                    G_BUDGET,
                    f"the proof budget of {self._node_budget} nodes was exhausted",
                    (),
                )
        self._nodes += 1
        proof_id = f"p{len(self._order)}"
        node = OriginProof(
            id=proof_id,
            status=status,
            reason=reason,
            function_start=function_start,
            address=address,
            register=register,
            detail=detail,
            depends_on=depends_on,
        )
        self._proofs[proof_id] = node
        self._order.append(proof_id)
        self._cache[("node",) + key] = proof_id
        if status != PROVEN and proof_id not in self._gaps_seen:
            self._gaps_seen.add(proof_id)
            self._gaps.append(proof_id)
        return proof_id

    def _join_verdicts(self, verdicts: list[str]) -> str:
        """Join several proofs: VLEN wins, then unproven, then proven."""

        nodes = [self._proofs[proof_id] for proof_id in verdicts]
        if not nodes:
            return self._record(
                PROVEN, R_CONSTANT, -1, 0, None, "no value to prove"
            )
        worst = max(nodes, key=lambda node: _STATUS_RANK[node.status])
        if len(nodes) == 1:
            return worst.id
        return self._record(
            worst.status,
            worst.reason,
            worst.function_start,
            worst.address,
            worst.register,
            f"joined from {len(nodes)} values; the weakest is: {worst.detail}",
            tuple(verdicts),
        )

    def _worst_proof(self, proof_ids: tuple[str, ...]) -> str | None:
        worst: OriginProof | None = None
        for proof_id in proof_ids:
            node = self._proofs[proof_id]
            if worst is None or _STATUS_RANK[node.status] > _STATUS_RANK[worst.status]:
                worst = node
        return worst.id if worst is not None else None

    # endregion

    def _summary_call_effect(
        self,
        caller_function: Function,
        address: int,
        incoming: dict[str, frozenset[str] | None],
    ) -> dict[str, frozenset[str] | None]:
        """Abstract effect of one call while summarising its caller.

        The callee's return-dependence set is expressed in the callee's formal
        parameters; this maps it back onto the caller's own dependence
        variables by reading the caller's state for the argument registers.
        ``a0`` therefore carries "the caller's dependence names the result is
        built from", which is what makes a chain of direct calls provable - and
        a recursive one *un*provable, because a summary that is still being
        computed answers "partial" and never a proof.
        """

        context = self._context(caller_function)
        targets, _reason = self._call_targets(context, address)
        resolved: dict[str, frozenset[str] | None] = {}
        if targets is None or not targets:
            return resolved
        names: set[str] | None = set()
        for target in targets:
            if target in self._summary_inflight:
                self._consumed_recursion = True
            summary = self._summary(target)
            if summary is None or summary.partial or summary.return_status != PROVEN:
                names = None
                break
            candidate: set[str] = set()
            for name in sorted(summary.return_dependencies):
                if name in (_MEMORY_INPUT, _VLEN_NAME):
                    names = None
                    break
                if name in incoming:
                    argument = incoming[name]
                else:
                    # The caller never mentioned this register: its value at
                    # the call site is the caller's *entry* value - the formal
                    # itself.  Reading absence as the empty set would turn a
                    # passed-through argument into a proven constant.
                    argument = frozenset({name})
                if argument is None:
                    names = None
                    break
                candidate |= argument
            if names is None:
                break
            names |= candidate
        resolved["a0"] = None if names is None else frozenset(names)
        return resolved

    def _context(self, function: Function) -> _FunctionContext:
        context = self._contexts.get(function.start)
        if context is None:
            context = _FunctionContext(function, self._semantics)
            self._contexts[function.start] = context
        return context


_STATUS_RANK = {PROVEN: 0, UNPROVEN: 1, VLEN: 2}


def _object_certificate(location: _Location) -> str:
    if location.kind == _OBJECT_FRAME:
        return R_FRAME_SLOT
    if location.kind == _OBJECT_PARAM:
        return R_PARAM_RANGE
    return R_STATIC_OBJECT


__all__ = [
    "AdjustmentProof",
    "FunctionSummary",
    "MemoryWrite",
    "OriginProver",
    "PROVEN",
    "UNPROVEN",
    "VLEN",
]
