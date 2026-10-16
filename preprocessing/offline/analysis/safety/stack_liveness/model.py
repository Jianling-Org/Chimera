"""Stack and VLEN-frame liveness analysis for RISC-V vector memory accesses.

There are two local-analysis modes, selected **per function** from the coverage
the compiler metadata actually provides for that function:

* compiler-metadata mode -- only reached when ``.chimera.stackobj_map`` exists
  *and* every VLEN-sensitive access of *this* function has a record.  Metadata
  is then authoritative for this function and binary address recovery is
  disabled for it;
* binary mode -- every VLEN-sensitive access in ``U`` is resolved from the
  binary using one CFG worklist with loop-header summary symbols.  It also
  covers the case where the section exists but this function's coverage is
  incomplete: a partially recorded function falls back *as a whole*, and the
  incomplete metadata records are never mixed into its use/def facts.

The section being present therefore no longer means "coverage complete"; the
selected mode, the counts and the uncovered addresses are reported per function
(see :class:`AccessMode`).

The module also performs conservative degradation for irreducible loops and
propagates live caller-stack context through direct calls and compiler-provided
function-pointer target metadata.

Dynamic stack-pointer expressions containing ``vlenb`` are represented by
dedicated marker objects so callers can distinguish frame-layout activity from
vector data activity.
"""

from __future__ import annotations

from .scope import CONSERVATIVE_SCOPE_DESCRIPTION

from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
import struct

from ...core.algorithm.address_states import (
    EMPTY_STATES,
    AddressStateMap,
    address_domain,
    retained_entries,
)
from ...core.data_model import Function


class StackAnalysisError(RuntimeError):
    """Base class for fatal stack-analysis failures."""


class MetadataFormatError(ValueError):
    """Raised when compiler-provided ELF metadata is malformed."""


class IrreducibleLoopWarning(UserWarning):
    """Warning category for conservative irreducible-loop degradation."""


@dataclass(frozen=True)
class CallTargetEntry:
    """Compiler-provided possible targets for one indirect call site."""

    callsite_rva: int
    targets: tuple[int, ...]

    @property
    def usable(self) -> bool:
        return bool(self.targets)


@dataclass(frozen=True)
class CallTargetResolution:
    """Keep external alternatives separate from the internal propagation graph."""

    internal_targets: frozenset[int] = frozenset()
    external_targets: frozenset[int] = frozenset()
    unresolved: bool = False
    empty_metadata: bool = False


UNRESOLVED_ACTIVE_CALL = "unresolved-active-indirect-call"
ACTIVE_EXTERNAL_CALL = "active-external-call"
VLEN_SCALAR_ESCAPE = "escaping-vlen-scalar-value"
# Cache observations (selection, store/return scope, effect diagnostics) are
# informational. Only an active transfer outside the complete Program graph
# constitutes a finding; local cache state still contributes to liveness.
ACTIONABLE_CALL_WARNINGS = frozenset({UNRESOLVED_ACTIVE_CALL, ACTIVE_EXTERNAL_CALL})


# region Structured activity origins
#
# Findings used to be attributed by matching phrases inside the human-readable
# ``details`` lines.  A local VLEN stack frame therefore fell through to the
# "inherited" default branch as soon as its wording changed, which is exactly
# what happened to ``driver::set_up_specs`` (0x17cec) and
# ``destringize_and_run`` (0x6ac3a).  Attribution now reads these records.

#: A VLEN-dependent stack frame of *this* function ("mv sp,<reg>" with an
#: unproven size, or a dynamic adjustment that could not be discharged).
ORIGIN_LOCAL_FRAME = "local-vlen-frame"
#: A value of this function still flowing into an ``sp`` adjustment.
ORIGIN_LOCAL_SETUP = "local-vlen-setup"
#: Live state belonging to an upstream active caller.
ORIGIN_INHERITED = "inherited"
#: An unresolved vector memory access forced stack-active treatment.
ORIGIN_CONSERVATIVE = "conservative"
#: Vector store(s) inside an irreducible loop were degraded.
ORIGIN_IRREDUCIBLE = "irreducible"
#: Resolved vector stack object activity of this function.
ORIGIN_VECTOR_DATA = "local-vector-data"
ORIGIN_LOCAL_SCALAR = "local-vlen-scalar"


@dataclass(frozen=True, slots=True)
class ScalarWidthSource:
    address: int
    register: str
    kind: str

#: Dependency verdict vocabulary used by the origin/proof records.
DEPENDENCY_VLEN_SOURCE = "vlen"
DEPENDENCY_UNPROVEN_SOURCE = "unknown"


@dataclass(frozen=True)
class AllocationOrigin:
    """One stack adjustment that left an unproven VLEN stack frame behind.

    Recorded per adjustment, for the function that owns it, so a report can
    name the allocation address, the register that carried the size, the
    dependency verdict, the releasing instruction and the proof (or the
    gaps that kept the proof from being issued).
    """

    source: str                  # vlen_stack_frame | vlen_stack_setup
    adjustment: int              # address of the sp write
    dependency: str              # vlen | unknown
    size_register: str | None = None
    release: int | None = None   # nearest release address, None = live to exit
    proof: str | None = None     # id in the shared proof table
    gaps: tuple[str, ...] = ()


@dataclass(frozen=True)
class ScopeExclusion:
    """One UNKNOWN allocation omitted under the explicit scope assumption."""

    source: str
    function_start: int
    adjustment: int
    dependency: str
    size_register: str | None
    disposition: str
    assumption: str
    proof: str | None = None
    gaps: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ScalarLeafTargetDiagnostic:
    """An observed proof attempt, not a new callee certificate."""

    target: int
    name: str | None
    status: str
    reason: str
    instruction_count: int | None = None
    instruction: int | None = None
    opcode: str | None = None
    registers: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ScalarLeafCallDiagnostic:
    status: str
    reason: str
    target_source: str = "unresolved"
    targets_complete: bool = False
    targets: tuple[ScalarLeafTargetDiagnostic, ...] = ()
    target_count: int = 0
    truncated: bool = False
    first_refusal: ScalarLeafTargetDiagnostic | None = None


@dataclass(frozen=True, slots=True)
class ScalarWidthSlotDiagnostic:
    start: str | None
    width: str | None
    object_id: str | None
    selected: bool
    live: bool


@dataclass(frozen=True, slots=True)
class ScalarWidthEvidence:
    """Bounded incoming may-state; only consumed by diagnostic reports.

    Selection labels can overlap content dependencies but are informational.
    Liveness describes local may-use, not an actual execution trace.
    """

    kind: str
    schema: str = "chimera-width-obligation-v1"
    provenance_scope: str = "incoming-may-state"
    width_registers: tuple[str, ...] = ()
    selection_registers: tuple[str, ...] = ()
    live_width_registers: tuple[str, ...] = ()
    width_vectors: tuple[int, ...] = ()
    selection_vectors: tuple[int, ...] = ()
    live_width_vectors: tuple[int, ...] = ()
    frame_intervals: tuple[tuple[int, int], ...] = ()
    selection_frame_intervals: tuple[tuple[int, int], ...] = ()
    live_frame_intervals: tuple[tuple[int, int], ...] = ()
    frame_byte_count: int = 0
    frame_interval_count: int = 0
    selection_frame_interval_count: int = 0
    slots: tuple[ScalarWidthSlotDiagnostic, ...] = ()
    slot_count: int = 0
    content_registers: tuple[str, ...] = ()
    content_vectors: tuple[int, ...] = ()
    content_selection_registers: tuple[str, ...] = ()
    content_selection_vectors: tuple[int, ...] = ()
    address_registers: tuple[str, ...] = ()
    address_vectors: tuple[int, ...] = ()
    mask_vectors: tuple[int, ...] = ()
    control_addresses: tuple[int, ...] = ()
    control_count: int = 0
    return_registers: tuple[str, ...] = ()
    memory_start: str | None = None
    memory_width: str | None = None
    memory_private: bool = False
    prior_unclosed_effect: bool = False
    call_effect: ScalarLeafCallDiagnostic | None = None
    truncated: bool = False
    diagnostic_error: str | None = None


@dataclass(frozen=True)
class ActiveOrigin:
    """Structured cause of a live stack activity at one call site."""

    origin: str                  # ORIGIN_* above
    object_source: str           # StackObjectId.source
    object_id: str               # str(StackObjectId)
    detail: str                  # the human-readable line (kept verbatim)
    allocation: int | None = None
    release: int | None = None
    dependency: str | None = None
    proof: str | None = None
    gaps: tuple[str, ...] = ()
    width_evidence: ScalarWidthEvidence | None = None


@dataclass(frozen=True)
class OriginProof:
    """One node of the shared origin-proof table.

    ``status`` is ``proven`` (independence of ``vlenb`` established),
    ``vlen`` (a VLEN source was identified) or ``unproven`` (neither).
    ``reason`` names the certificate or the gap; both are a closed vocabulary
    so no consumer has to parse prose.
    """

    id: str
    status: str
    reason: str
    function_start: int
    address: int
    register: str | None = None
    detail: str = ""
    depends_on: tuple[str, ...] = ()

    @property
    def is_gap(self) -> bool:
        return self.status != "proven"


@dataclass(frozen=True)
class AnalysisWarning:
    code: str
    message: str
    function_start: int
    addresses: tuple[int, ...] = ()
    # Human-readable explanation lines, e.g. why a call site is stack-active
    # (which vector stack writes keep an object live across the call).
    details: tuple[str, ...] = ()
    # The same explanation, structured: classification reads this instead of
    # matching phrases in ``details``.
    origins: tuple[ActiveOrigin, ...] = ()
    # Exact known alternatives outside the auditable internal graph.
    external_targets: tuple[int, ...] = ()


@dataclass(frozen=True)
class ChimeraMetadata:
    """Compiler metadata used by stack analysis.

    ``.chimera.stackobj_map`` is the *candidate* source of the local-analysis
    mode switch, but it is not the switch itself: the compiler-provided
    memory-object mapping is authoritative for one function only when every
    VLEN-sensitive access of that function has a record.  A function whose
    coverage is incomplete falls back to binary address recovery for all of its
    sensitive accesses, so the presence of the section must never be read as
    "coverage complete".  ``.chimera.function_pointer`` is independent and may be
    supplied in either local-analysis mode.
    """

    stack_ids: dict[int, int] = field(default_factory=dict)
    has_stackobj_map_section: bool = False
    function_pointer: dict[int, CallTargetEntry] = field(default_factory=dict)
    has_function_pointer_section: bool = False

    def __post_init__(self) -> None:
        if self.stack_ids and not self.has_stackobj_map_section:
            object.__setattr__(self, "has_stackobj_map_section", True)
        if self.function_pointer and not self.has_function_pointer_section:
            object.__setattr__(self, "has_function_pointer_section", True)

    @classmethod
    def empty(cls) -> "ChimeraMetadata":
        return cls()

    @property
    def capabilities(self) -> frozenset[str]:
        result: set[str] = set()
        if self.has_stackobj_map_section:
            result.add("stack_access_ids")
        if self.has_function_pointer_section:
            result.add("function_pointer")
        return frozenset(result)

    @classmethod
    def from_elf(cls, path: str | Path) -> "ChimeraMetadata":
        try:
            from elftools.elf.elffile import ELFFile
        except ImportError as error:
            raise MetadataFormatError(
                "reading ELF metadata requires pyelftools"
            ) from error

        with Path(path).open("rb") as source:
            elf = ELFFile(source)
            memory_section = elf.get_section_by_name(".chimera.stackobj_map")
            fp_section = elf.get_section_by_name(".chimera.function_pointer")

            load_bases = [
                int(segment.header.p_vaddr)
                for segment in elf.iter_segments()
                if segment.header.p_type == "PT_LOAD"
            ]
            if not load_bases:
                raise MetadataFormatError("input ELF contains no PT_LOAD segment")
            load_base = min(load_bases)

            raw_stack_ids = (
                cls._decode_stackobj_map(memory_section.data())
                if memory_section is not None
                else {}
            )
            raw_function_pointer = (
                cls._decode_function_pointer(fp_section.data())
                if fp_section is not None
                else {}
            )

        # `.chimera.stackobj_map!A` records the linked virtual address of
        # the access (`[u64 LinkedVA][u32 SOID]`) -- exactly the address the
        # disassembler reports and the analysis keys its per-instruction maps
        # on -- so the decoded value is used as-is.  Re-adding `load_base`
        # would shift every record off its instruction and leave the
        # metadata-mode intersection with the VLEN-sensitive access set
        # empty, i.e. stack accesses silently unchecked.  Whether to rebase is
        # never inferred from the ELF type or from an address hit rate: the
        # plugin only emits this absolute, already-linked form.
        stack_ids = dict(raw_stack_ids)
        function_pointer = {
            load_base + address: CallTargetEntry(
                callsite_rva=load_base + entry.callsite_rva,
                targets=tuple(load_base + target for target in entry.targets),
            )
            for address, entry in raw_function_pointer.items()
        }

        return cls(
            stack_ids=stack_ids,
            has_stackobj_map_section=memory_section is not None,
            function_pointer=function_pointer,
            has_function_pointer_section=fp_section is not None,
        )

    @staticmethod
    def _decode_stackobj_map(data: bytes) -> dict[int, int]:
        record = struct.Struct("<QI")
        if len(data) % record.size:
            raise MetadataFormatError(
                f".chimera.stackobj_map size is not a multiple of {record.size} bytes"
            )
        result: dict[int, int] = {}
        for address, object_id in record.iter_unpack(data):
            previous = result.get(address)
            if previous is not None and previous != object_id:
                raise MetadataFormatError(
                    f".chimera.stackobj_map contains conflicting records for {address:#x}"
                )
            result[address] = object_id
        return result

    @staticmethod
    def _decode_function_pointer(data: bytes) -> dict[int, CallTargetEntry]:
        offset = 0
        result: dict[int, CallTargetEntry] = {}
        while offset < len(data):
            if offset + 12 > len(data):
                raise MetadataFormatError(
                    f".chimera.function_pointer record header truncated at offset {offset}"
                )
            call_rva = struct.unpack_from("<Q", data, offset)[0]
            target_count = struct.unpack_from("<I", data, offset + 8)[0]
            offset += 12
            targets_end = offset + target_count * 8
            if targets_end > len(data):
                raise MetadataFormatError(
                    f".chimera.function_pointer targets truncated at call {call_rva:#x}"
                )
            targets = []
            for i in range(target_count):
                target_rva = struct.unpack_from("<Q", data, offset + i * 8)[0]
                targets.append(target_rva)
            offset = targets_end
            if call_rva in result:
                raise MetadataFormatError(
                    f"duplicate function-pointer entry for call site {call_rva:#x}"
                )
            result[call_rva] = CallTargetEntry(
                callsite_rva=call_rva,
                targets=tuple(sorted(set(targets))),
            )
        return result


@dataclass(frozen=True)
class NaturalLoopInfo:
    header: int
    addresses: frozenset[int]
    back_edges: frozenset[tuple[int, int]]
    written_registers: frozenset[str]


@dataclass(frozen=True)
class IrreducibleLoopInfo:
    addresses: frozenset[int]
    entry_blocks: frozenset[int]


@dataclass(frozen=True)
class LoopInfo:
    natural_loops: tuple[NaturalLoopInfo, ...]
    irreducible_loops: tuple[IrreducibleLoopInfo, ...]
    back_edges: frozenset[tuple[int, int]]
    header_written_registers: dict[int, frozenset[str]]
    irreducible_addresses: frozenset[int]

    def innermost_natural_loop(self, address: int) -> NaturalLoopInfo | None:
        candidates = [
            loop for loop in self.natural_loops if address in loop.addresses
        ]
        return min(candidates, key=lambda loop: len(loop.addresses), default=None)


class AccessMode(str, Enum):
    """The local-analysis mode actually applied to one function.

    ``metadata_mode`` is the boolean form of "metadata was used"; this enum also
    distinguishes *why* binary recovery ran, which is what separates "the
    compiler never instrumented this image" from "this function's metadata is
    incomplete and was therefore not trusted".
    """

    #: No ``.chimera.stackobj_map`` section in the ELF at all.
    BINARY_NO_SECTION = "binary-no-section"
    #: Section present and every VLEN-sensitive access of the function has a
    #: record: compiler metadata is authoritative for this function.
    METADATA_COMPLETE = "metadata-complete-coverage"
    #: Section present but at least one VLEN-sensitive access of the function
    #: has no record: the whole function falls back to binary recovery.
    BINARY_INCOMPLETE = "binary-incomplete-coverage"


#: Why a mode was selected; reported alongside :class:`AccessMode`.
MODE_REASON_NO_SECTION = "no-stackobj-section"
MODE_REASON_COMPLETE_COVERAGE = "complete-metadata-coverage"
MODE_REASON_INCOMPLETE_COVERAGE = "incomplete-metadata-coverage"


@dataclass(frozen=True)
class FunctionAccessPlan:
    """VLEN-sensitive set U and the selected local-analysis mode.

    ``metadata_mode`` says metadata was *actually* used for this function.  It
    is no longer the section-presence flag: with incomplete coverage the
    function runs binary recovery and ``metadata_mode`` is False even though
    ``has_metadata_section`` is True.
    """

    vlen_sensitive_addresses: frozenset[int]
    compiler_access_ids: dict[int, int]
    binary_addresses: frozenset[int]
    metadata_mode: bool
    #: Whether the ELF carries ``.chimera.stackobj_map``.  Presence alone never
    #: authorizes ignoring an uncovered access of this function.
    has_metadata_section: bool = False
    #: ``|M|`` -- sensitive accesses of this function with a metadata record.
    metadata_covered_count: int = 0
    #: ``U - M`` -- sensitive accesses the metadata did not cover.  Only
    #: meaningful when ``has_metadata_section``; empty in the no-section case,
    #: where every access is uncovered by construction and the mode says so.
    uncovered_sensitive_addresses: frozenset[int] = frozenset()
    access_mode: AccessMode = AccessMode.BINARY_NO_SECTION
    mode_reason: str = MODE_REASON_NO_SECTION

    @property
    def candidate_addresses(self) -> frozenset[int]:
        return self.vlen_sensitive_addresses

    @property
    def pending_addresses(self) -> frozenset[int]:
        return self.binary_addresses

    @property
    def coverage_incomplete(self) -> bool:
        return self.access_mode is AccessMode.BINARY_INCOMPLETE


ExpressionState = dict[str, "Expr | _Unknown"]


@dataclass(frozen=True)
class FunctionExpressionResult:
    loop_info: LoopInfo
    before_states: dict[int, ExpressionState]
    conservative_addresses: frozenset[int]
    warnings: tuple[AnalysisWarning, ...] = ()
    # Scalar state after each instruction.  This is retained for analyses that
    # need to reason about state transitions (for example, dynamic VLEN-based
    # stack-frame setup and teardown), while address recovery continues to use
    # ``before_states``.
    after_states: dict[int, ExpressionState] = field(default_factory=dict)


@dataclass(frozen=True)
class StackObjectId:
    source: str
    value: int | str

    def __str__(self) -> str:
        return f"{self.source}:{self.value}"


class StackAccessKind(str, Enum):
    LOAD = "load"
    STORE = "store"


class StackAddressStatus(str, Enum):
    STACK = "stack"
    NON_STACK = "non_stack"
    UNRESOLVED = "unresolved"


@dataclass(frozen=True)
class StackAccess:
    instruction_addr: int
    kind: StackAccessKind
    stack_id: StackObjectId
    config: frozenset[object]
    source: str
    address_expression: "Expr | None" = None


@dataclass(frozen=True)
class StackAccessFacts:
    accesses: dict[int, StackAccess]
    uses: dict[int, frozenset[StackObjectId]]
    defs: dict[int, frozenset[StackObjectId]]
    conservative_addresses: frozenset[int]
    rejected_nonstack_addresses: frozenset[int]


class InheritedLivenessView(Mapping[int, frozenset["StackObjectId"]]):
    """Read-only "base live-in map + caller-inherited marker" view.

    Entering a function into the inherited closure only adds one marker object
    to every live-in set.  Materialising that as a fresh dictionary would cost
    one dictionary slot and one ``frozenset`` per instruction of each inherited
    function — the single largest retained-state growth of the propagation
    stage.  The view merges the marker per query instead, so the base map stays
    the only retained structure.
    """

    __slots__ = ("_base", "_marker_set")

    def __init__(
        self,
        base: Mapping[int, frozenset["StackObjectId"]],
        marker: "StackObjectId",
    ) -> None:
        self._base = base
        self._marker_set = frozenset({marker})

    def __getitem__(self, address: int) -> frozenset["StackObjectId"]:
        value = self._base[address]
        return self._marker_set if not value else value | self._marker_set

    def __contains__(self, address: object) -> bool:
        return address in self._base

    def __len__(self) -> int:
        return len(self._base)

    def __iter__(self) -> Iterator[int]:
        return iter(self._base)

    def items(self) -> Iterator[tuple[int, frozenset["StackObjectId"]]]:
        marker_set = self._marker_set
        base = self._base
        for address in base:
            value = base[address]
            yield address, marker_set if not value else value | marker_set

    def values(self) -> Iterator[frozenset["StackObjectId"]]:
        marker_set = self._marker_set
        base = self._base
        for address in base:
            value = base[address]
            yield marker_set if not value else value | marker_set

    @property
    def base(self) -> Mapping[int, frozenset["StackObjectId"]]:
        """The unmarked base mapping this view layers on."""

        return self._base

    @property
    def entry_count(self) -> int:
        """Every address of the base map now carries the marker."""

        return len(self._base)


@dataclass(frozen=True)
class StackFunctionLiveness:
    """Local stack-object liveness of one function.

    ``live_before`` answers every instruction address of the function but only
    retains addresses with a non-empty live set; ``get``/``in``/``len``/
    iteration behave exactly like the dense dictionary it replaces, and plain
    dictionaries remain acceptable as inputs.
    """

    function_start: int
    live_before: Mapping[int, frozenset[StackObjectId]]
    accesses: dict[int, StackAccess]
    candidate_addresses: frozenset[int] = frozenset()
    rejected_nonstack_addresses: frozenset[int] = frozenset()
    conservative_addresses: frozenset[int] = frozenset()
    loop_headers: frozenset[int] = frozenset()
    irreducible_loops: tuple[frozenset[int], ...] = ()
    warnings: tuple[AnalysisWarning, ...] = ()
    # Every stack adjustment of this function that left an unproven VLEN
    # frame behind, with its dependency verdict, proof reference and gaps.
    frame_origins: tuple[AllocationOrigin, ...] = ()
    # --- Explicit metadata-coverage accounting -----------------------------
    # Only counts and the uncovered addresses are retained, never a copy of a
    # per-instruction model.  A consumer that sees these fields absent must not
    # read their absence as "fully covered": the defaults below are the *binary*
    # mode, which is the conservative reading.
    has_metadata_section: bool = False
    sensitive_access_count: int = 0
    metadata_covered_count: int = 0
    uncovered_sensitive_addresses: frozenset[int] = frozenset()
    access_mode: AccessMode = AccessMode.BINARY_NO_SECTION
    mode_reason: str = MODE_REASON_NO_SECTION
    # Unknown scalar-size allocations excluded under an explicit conditional
    # policy. Kept apart from active origins so they cannot relabel retained
    # VLEN frame activity.
    scope_exclusions: tuple[ScopeExclusion, ...] = ()
    scalar_width_sources: tuple[ScalarWidthSource, ...] = ()
    scalar_width_fallback: bool = False

    @classmethod
    def empty(
        cls,
        function: Function,
        *,
        candidate_addresses: frozenset[int] = frozenset(),
    ) -> "StackFunctionLiveness":
        return cls(
            function_start=function.start,
            live_before=AddressStateMap(
                address_domain(
                    tuple(instruction.addr for instruction in function.insts)
                ),
                EMPTY_STATES,
            ),
            accesses={},
            candidate_addresses=candidate_addresses,
        )


@dataclass(frozen=True)
class InheritanceEdge:
    """One call edge observed during inherited-closure propagation.

    ``reason`` is ``"seed"`` when the call site itself was stack-active in a
    function outside the closure, or ``"inherited"`` when the caller was
    already inside the closure.  ``depth`` is 1 for seed-pulled functions
    and grows by one per propagation layer.
    """

    caller_function_start: int
    call_site: int
    reason: str
    depth: int


@dataclass(frozen=True)
class InheritanceTrace:
    """Provenance recorded while building the inherited-function closure.

    Purely observational: it explains *why* each function entered the
    closure, without affecting the closure itself.  ``seed_edges`` lists
    every seed-reason call edge (deduplicated by call site, in discovery
    order); ``first_cause`` maps each inherited function to the first edge
    that pulled it in.
    """

    seed_edges: tuple[InheritanceEdge, ...] = ()
    first_cause: dict[int, InheritanceEdge] = field(default_factory=dict)

    @property
    def max_depth(self) -> int:
        return max((edge.depth for edge in self.first_cause.values()), default=0)


@dataclass(frozen=True)
class StackLivenessResult:
    by_function: dict[int, StackFunctionLiveness]
    inherited_functions: frozenset[int] = frozenset()
    warnings: tuple[AnalysisWarning, ...] = ()
    unresolved_live_calls: tuple[int, ...] = ()
    inheritance_trace: InheritanceTrace = field(default_factory=InheritanceTrace)
    # Shared origin-proof table of this run, keyed by proof id.  Proofs are
    # interned: every consumer (finding, report, allocation record) references
    # the same node instead of copying a path per finding.
    origin_proofs: Mapping[str, OriginProof] = field(default_factory=dict)
    # Ids of the proofs that did not establish independence, in discovery
    # order.  This is the "still to be discharged" list.
    origin_gaps: tuple[str, ...] = ()
    # True when the on-demand prover hit its node/summary budget and had to
    # answer UNKNOWN.  A budgeted answer never becomes a release.
    proof_budget_exhausted: bool = False
    # Callees a proof asked about whose body was not available, keyed by
    # address with the reason ("missing-callee-body" for an internal target
    # that was simply not included, "external-callee" for a trampoline).  This
    # is the *actionable* list: exporting exactly these bodies is what turns
    # the next run's gaps into answers.
    missing_callees: Mapping[int, str] = field(default_factory=dict)
    unknown_stack_size_policy: str = "conservative"
    assumption: str = CONSERVATIVE_SCOPE_DESCRIPTION
    conditional: bool = False
    # Unlike unresolved pointers, these calls have known external targets.
    active_external_calls: tuple[int, ...] = ()
    # Proven closed leaves do not remove caller activity or safe/unsafe facts.
    closed_external_calls: dict[int, tuple[int, ...]] = field(default_factory=dict)
    external_leaf_proofs: tuple[dict, ...] = ()
    external_leaf_rejections: tuple[dict, ...] = ()

    def proof(self, proof_id: str | None) -> OriginProof | None:
        if proof_id is None:
            return None
        return self.origin_proofs.get(proof_id)

    @property
    def live_before(self) -> dict[int, frozenset[StackObjectId]]:
        """Explicit flattened export; the analysis path never expands this."""

        return {
            address: values
            for function in self.by_function.values()
            for address, values in function.live_before.items()
        }

    @property
    def flattened_live_before(
        self,
    ) -> dict[tuple[int, int], frozenset[StackObjectId]]:
        """Explicit flattened export; the analysis path never expands this."""

        return {
            (function_start, address): values
            for function_start, function in self.by_function.items()
            for address, values in function.live_before.items()
        }

    @property
    def nonempty_state_count(self) -> int:
        """Number of retained non-empty live-in sets across all functions."""

        return sum(
            retained_entries(function.live_before)
            for function in self.by_function.values()
        )

    def live_before_at(
        self,
        function_start: int,
        instruction_addr: int,
    ) -> frozenset[StackObjectId]:
        function = self.by_function.get(function_start)
        if function is None:
            return frozenset()
        return function.live_before.get(instruction_addr, frozenset())
