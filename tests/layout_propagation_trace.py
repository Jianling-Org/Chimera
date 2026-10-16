"""Forward propagation trace of one source object to one affected site.

Two grades of answer, never merged:

* ``analysis-trace`` -- the path is seeded by a call where the **original**
  source object is live and then carries a **distinct source id** along
  analyzer-resolved call edges.  Only this grade is evidence that the source
  can reach the site.
* ``callgraph-path-only`` -- a path exists in the call graph but no hop was
  shown to carry the source.  This is reachability, not propagation.

Inherited hops do **not** re-materialise the original object.  The production
``InheritedLivenessView`` puts the shared ``caller:inherited-stack-data``
marker in every live-in set of a callee, and that marker is shared by *every*
inherited source -- so it is never accepted as proof that a hop belongs to
*this* source.  Propagation therefore follows the audit's candidate-id rule:
the first hop must show the original object live, afterwards the distinct
source id travels via the inherited-entry set and the parent edge is kept.

Function identity is by **address**, never by name substring: ``<foo+0x20>``
belongs to ``foo``, ``<foobar>`` does not.  Call/jump classification reuses
``is_call_instruction`` so ``j`` / ``tail`` / ``jal x0`` never become call
edges.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from contextlib import nullcontext
import json
import re
from pathlib import Path
from typing import Callable, ContextManager, Iterable, Mapping

from chimera.preprocess.offline.analysis.arch.riscv.control_flow import (
    is_call_instruction,
)
from chimera.preprocess.offline.analysis.arch.riscv.rvv.services import RvvServices
from chimera.preprocess.offline.analysis.arch.riscv.services import RiscvServices
from chimera.preprocess.offline.analysis.core.data_model import (
    Function,
    Instruction,
    Program,
)
from chimera.preprocess.offline.analysis.program_model.parser import parse_dump
from chimera.preprocess.offline.analysis.safety.stack_liveness.liveness import (
    _CallTargetResolver,
)
from chimera.preprocess.offline.analysis.safety.stack_liveness.model import (
    ChimeraMetadata,
    StackFunctionLiveness,
    StackLivenessResult,
    StackObjectId,
)
from chimera.preprocess.offline.analysis.toolchain.objdump import LinuxObjdump

GRADES = ("analysis-trace", "callgraph-path-only", "insufficient-evidence")

#: The shared marker ``InheritedLivenessView`` layers into every inherited
#: live-in set.  It says "something was inherited", never *which* source.
CALLER_MARKER = StackObjectId("caller", "inherited-stack-data")

#: Formats ``load_inheritance`` accepts.
INHERITANCE_FORMATS = (
    "chimera-inheritance-diagnostics-v1",
    "chimera-inheritance-diagnostics-v2",
)

#: ``<name>``, ``<name+0x20>``, ``<name-0x20>``.  The name is the *full*
#: symbol; nothing may match it by prefix or substring.  The addend is a
#: trailing ``+0x..`` / ``-0x..`` only; a name that itself contains ``-`` is
#: kept intact.
_SYMBOL_ANNOTATION = re.compile(r"<(?P<inner>[^<>]*)>")
_SYMBOL_ADDEND = re.compile(r"(?P<sign>[+-])0x(?P<off>[0-9a-fA-F]+)$")
#: objdump's ``   505e4:  34d000ef    jal 51130 <symbol>``.
_OBJDUMP_LINE = re.compile(
    r"^\s*([0-9a-fA-F]+):\s+\S+\s+(call|jal|jalr|j|tail)\b(.*)$"
)


@dataclass(frozen=True)
class CallEdge:
    """One link-register call with a target set and its resolution grade.

    ``resolved_by`` is ``"analyzer"`` when the production
    ``_CallTargetResolver`` produced the targets and ``"disassembly"`` when
    the targets were inferred from objdump text.  A disassembly edge is a
    *suspected* edge: it may guide the search, but it must never on its own
    authorise ``analysis-trace``.
    """

    call_site: int
    caller_start: int
    targets: tuple[int, ...]
    first_hop_active: bool
    """Whether the **original** source object is live at this call site.

    Only meaningful for edges leaving the source function: inherited hops
    carry ``CALLER_MARKER``, not the original object.
    """
    resolved_by: str = "analyzer"
    """``"analyzer"`` or ``"disassembly"`` -- see the class docstring."""


@dataclass(frozen=True)
class TraceStep:
    caller: int
    call_site: int
    callee: int
    source_id: str
    first_hop: bool
    """True only for the seed edge that proved the original object live."""


@dataclass(frozen=True)
class TraceResult:
    grade: str
    steps: tuple[TraceStep, ...] = ()
    reason: str = ""
    first_edge_carried_object: bool | None = None
    source_id: str = ""
    source_object_id: str = ""
    inheritance_bound: bool | None = None

    @property
    def is_propagation_evidence(self) -> bool:
        return self.grade == "analysis-trace"


def _split_symbol_annotation(annotation: str) -> tuple[str | None, int]:
    """Return ``(full_name, signed_addend)`` for ``<name[+/-0xoff]>``.

    The addend is recognised only as a *trailing* ``+0x..``/``-0x..``, so a
    symbol whose own name contains ``-`` or ``+`` is not truncated.
    """

    match = _SYMBOL_ANNOTATION.fullmatch(annotation.strip())
    if match is None:
        return None, 0
    inner = match.group("inner")
    addend = _SYMBOL_ADDEND.search(inner)
    if addend is None:
        return (inner or None), 0
    name = inner[: addend.start()]
    offset = int(addend.group("off"), 16)
    signed = offset if addend.group("sign") == "+" else -offset
    return (name or None), signed


def parse_symbol_name(annotation: str) -> str | None:
    """Exact symbol name inside ``<...>``; ``<foo+0x20>`` is still ``foo``.

    ``<foobar>`` must not be accepted as ``foo``: the name is matched whole.
    Returns ``None`` when the annotation carries no name (``<.text+0x4>``).
    """

    name, _ = _split_symbol_annotation(annotation)
    return name


def parse_symbol_address(
    annotation: str, functions_by_name: dict[str, int]
) -> int | None:
    """Resolve ``<name[+/-0xoff]>`` to an address using whole-name lookup."""

    name, addend = _split_symbol_annotation(annotation)
    if not name or name not in functions_by_name:
        return None
    return functions_by_name[name] + addend


@dataclass(frozen=True)
class ObjdumpCallCandidate:
    """A disassembly line that *looks* like a transfer; not yet a call edge."""

    address: int
    op: str
    target_address: int | None
    target_name: str | None
    is_call: bool
    """``is_call_instruction`` verdict; ``j`` / ``tail`` / ``jal x0`` are False."""


def parse_objdump_line(
    line: str, functions_by_name: dict[str, int]
) -> ObjdumpCallCandidate | None:
    """Parse one objdump line; classify call vs jump with the CFG rule."""

    match = _OBJDUMP_LINE.match(line)
    if match is None:
        return None
    address = int(match.group(1), 16)
    op = match.group(2)
    rest = match.group(3)

    annotation = _SYMBOL_ANNOTATION.search(rest)
    target_name = parse_symbol_name(annotation.group(0)) if annotation else None
    target_address = (
        parse_symbol_address(annotation.group(0), functions_by_name)
        if annotation
        else None
    )
    if target_address is None:
        # A bare hex target: ``jal 51130`` with no name annotation.
        bare = re.match(r"\s*([0-9a-fA-F]+)", rest)
        if bare:
            target_address = int(bare.group(1), 16)

    # Reuse the CFG's call/jump rule rather than the opcode spelling.  Build
    # the operand list objdump printed: ``jal 51130`` is the one-operand form
    # (implicit link register) and is a call; ``jalr zero, 0(a0)`` is not.
    args = tuple(part for part in re.split(r"[,\s]+", rest.strip()) if part)
    instruction = Instruction(address, 4, op, args, line.strip())
    return ObjdumpCallCandidate(
        address=address,
        op=op,
        target_address=target_address,
        target_name=target_name,
        is_call=is_call_instruction(instruction),
    )


def function_at(
    functions: Iterable[tuple[int, str]],
    address: int,
    *,
    ends: Mapping[int, int] | None = None,
):
    """(start, name) of the function **containing** ``address``.

    Containment is ``start <= address < end``.  ``end`` is ``ends[start]``
    when given, otherwise the next function's start.  The last function has
    no natural end from a start table alone:

    * with ``ends`` its real bound is used;
    * without ``ends`` it is treated as open-ended **for host lookup only**
      (which function body holds this instruction address).

    This function is **never** a call-target resolver.  A call target must be
    an exact function *entry* -- see :func:`resolve_call_target`.  Attributing
    an out-of-range target to the nearest earlier function invents edges that
    do not exist (a call to ``0x9000 <external@plt>`` must not become
    ``-> host`` just because ``host`` starts at ``0x8000``).
    """

    table = tuple(sorted(functions))
    for index, (start, name) in enumerate(table):
        if start > address:
            return None
        if ends is not None and start in ends:
            end = ends[start]
        elif index + 1 < len(table):
            end = table[index + 1][0]
        else:
            end = None  # last function, no natural end
        if end is not None and address >= end:
            continue
        if end is None and address < start:
            continue
        if start <= address and (end is None or address < end):
            return (start, name)
    return None


def resolve_call_target(
    functions_by_start: Mapping[int, object],
    target: int | None,
    *,
    external_trampolines: Iterable[int] = (),
) -> int | None:
    """The production ``_CallTargetResolver`` rule for one direct target.

    Accept only an **exact function entry** that is not an external
    trampoline -- exactly what ``_CallTargetResolver.resolve`` does with
    ``target in functions_by_start`` and
    ``functions_by_start[target].is_external_trampoline``.

    Everything else keeps the gap and returns ``None``:

    * an unknown target (``0x9000 <external@plt>`` is not ``host``'s entry);
    * an external trampoline (propagation stops at the binary boundary);
    * an address inside a function body but not at its entry.

    Never fall back to "the nearest earlier function".
    """

    if target is None:
        return None
    if target not in functions_by_start:
        return None
    if target in frozenset(external_trampolines):
        return None
    entry = functions_by_start[target]
    if getattr(entry, "is_external_trampoline", False):
        return None
    return target


def object_active_call_sites(
    program: Program,
    local: Mapping[int, StackFunctionLiveness],
    object_id: StackObjectId,
    *,
    caller_start: int | None = None,
) -> list[int]:
    """Call sites whose live set carries ``object_id`` -- the *seed* calls.

    This is the set the propagation may start from: only these edges prove
    the original object live at a call.  A seed whose callee is outside the
    analysed program is still a seed, it just cannot be walked further here.
    """

    sites: list[int] = []
    for function in program.functions:
        if caller_start is not None and function.start != caller_start:
            continue
        facts = local.get(function.start)
        if facts is None:
            continue
        for instruction in function.insts:
            if not is_call_instruction(instruction):
                continue
            live = facts.live_before.get(instruction.addr, frozenset())
            if object_id in live:
                sites.append(instruction.addr)
    return sorted(sites)


def resolved_call_edges(
    program: Program,
    *,
    metadata: ChimeraMetadata | None = None,
) -> list[CallEdge]:
    """Every analyzer-resolved call edge, activity-independent.

    Later hops of a source trace walk *this* set (filtered by the source id
    that has already reached the caller), not the seed set: a seed edge list
    is not the complete propagation edge set.
    """

    metadata = metadata or ChimeraMetadata.empty()
    resolver = _CallTargetResolver()
    functions_by_start = {function.start: function for function in program.functions}
    edges: list[CallEdge] = []
    for function in program.functions:
        for instruction in function.insts:
            if not is_call_instruction(instruction):
                continue
            targets = resolver.resolve(instruction, functions_by_start, metadata)
            if not targets:
                continue
            edges.append(
                CallEdge(
                    call_site=instruction.addr,
                    caller_start=function.start,
                    targets=tuple(sorted(targets)),
                    first_hop_active=False,
                    resolved_by="analyzer",
                )
            )
    return edges


def active_call_edges(
    program: Program,
    local: Mapping[int, StackFunctionLiveness],
    object_id: StackObjectId,
    *,
    metadata: ChimeraMetadata | None = None,
) -> list[CallEdge]:
    """Resolved call edges with ``first_hop_active`` filled from the live set.

    ``first_hop_active`` answers "is the **original** object live here".  It
    is the seed criterion; it is deliberately *not* the per-hop criterion,
    because inherited hops carry ``CALLER_MARKER`` instead.
    """

    metadata = metadata or ChimeraMetadata.empty()
    resolver = _CallTargetResolver()
    functions_by_start = {function.start: function for function in program.functions}
    edges: list[CallEdge] = []
    for function in program.functions:
        facts = local.get(function.start)
        if facts is None:
            continue
        for instruction in function.insts:
            if not is_call_instruction(instruction):
                continue
            targets = resolver.resolve(instruction, functions_by_start, metadata)
            if not targets:
                continue
            live = facts.live_before.get(instruction.addr, frozenset())
            edges.append(
                CallEdge(
                    call_site=instruction.addr,
                    caller_start=function.start,
                    targets=tuple(sorted(targets)),
                    first_hop_active=object_id in live,
                )
            )
    return edges


def trace_source_propagation(
    program: Program,
    local: Mapping[int, StackFunctionLiveness],
    source_object_id: StackObjectId,
    source_start: int,
    host_start: int,
    *,
    metadata: ChimeraMetadata | None = None,
    max_depth: int = 8,
) -> TraceResult:
    """Seed on the original object, then propagate a **distinct source id**.

    Rule (the audit's candidate-id rule, one source at a time):

    1. **Seed** -- an edge out of ``source_start`` whose live set carries the
       original ``source_object_id``.  Without such an edge the source cannot
       propagate and the result is ``insufficient-evidence``.
    2. **Propagate** -- the source id (``str(source_object_id)``) travels via
       the *inherited-entry* set along analyzer-resolved call edges.  The
       parent edge of every step is kept.
    3. **Never** require the original object on hops 2+: the production
       ``InheritedLivenessView`` puts ``CALLER_MARKER`` there instead.
    4. **Never** accept ``CALLER_MARKER`` as proof of *this* source -- it is
       shared by every inherited source, so attributing it to
       ``source_object_id`` would cross-contaminate converging sources.
    """

    source_id = str(source_object_id)
    object_id_text = str(source_object_id)
    if source_start == host_start:
        return TraceResult(
            grade="insufficient-evidence",
            reason="source and host are the same function; nothing to trace",
            source_id=source_id,
            source_object_id=object_id_text,
        )

    metadata = metadata or ChimeraMetadata.empty()
    edges = resolved_call_edges(program, metadata=metadata)
    by_caller: dict[int, list[CallEdge]] = {}
    for edge in edges:
        by_caller.setdefault(edge.caller_start, []).append(edge)

    # --- 1. seed: the original object must be live at the first hop --------
    seeds = [
        edge
        for edge in by_caller.get(source_start, [])
        if source_object_id in _live_at(local, edge.caller_start, edge.call_site)
    ]
    if not seeds:
        any_edge = bool(by_caller.get(source_start))
        return TraceResult(
            grade="insufficient-evidence",
            reason=(
                "no call edge out of the source function carries the original "
                "object; the source cannot propagate through its calls"
                if not any_edge
                else "the source's call edges exist but none of them is "
                "seed-active for the original object; a call-graph path "
                "would not be propagation"
            ),
            first_edge_carried_object=False if any_edge else None,
            source_id=source_id,
            source_object_id=object_id_text,
        )

    # --- 2. propagate the source id, keeping the parent edge ---------------
    # entry_state[f] = source ids inherited at f's entry.  Only the source id
    # of *this* trace travels; a converging source keeps its own id and its
    # own parent chain, so the two cannot be swapped.
    entry_state: dict[int, str] = {}
    parent: dict[int, TraceStep] = {}

    def hand_over(caller: int, call_site: int, callee: int, first_hop: bool) -> bool:
        if callee == source_start:
            return False
        if callee in entry_state and entry_state[callee] == source_id:
            return False
        entry_state[callee] = source_id
        parent[callee] = TraceStep(
            caller=caller,
            call_site=call_site,
            callee=callee,
            source_id=source_id,
            first_hop=first_hop,
        )
        return True

    frontier: list[tuple[int, bool]] = []
    for edge in seeds:
        for callee in edge.targets:
            if hand_over(source_start, edge.call_site, callee, True):
                frontier.append((callee, False))

    depth = 1
    while frontier and depth < max_depth:
        nxt: list[tuple[int, bool]] = []
        for caller, _ in frontier:
            for edge in by_caller.get(caller, []):
                # Hops 2+ ride the inherited-entry set.  The caller's live set
                # may hold CALLER_MARKER here; that is NOT proof of this
                # source and is deliberately not consulted.
                for callee in edge.targets:
                    if hand_over(caller, edge.call_site, callee, False):
                        nxt.append((callee, False))
        frontier = nxt
        depth += 1

    if host_start not in entry_state:
        return TraceResult(
            grade="insufficient-evidence",
            reason=(
                "no source-id-carrying call chain from the source reaches the "
                "host; the last hop may be indirect or outside the analyzed "
                "program"
            ),
            first_edge_carried_object=True,
            source_id=source_id,
            source_object_id=object_id_text,
        )

    steps: list[TraceStep] = []
    node = host_start
    while node != source_start and node in parent:
        step = parent[node]
        steps.append(step)
        node = step.caller
    steps.reverse()
    return TraceResult(
        grade="analysis-trace",
        steps=tuple(steps),
        reason=(
            "seeded by the original object live at the first call, then the "
            "distinct source id propagated along analyzer-resolved call edges "
            "(inherited hops carry the shared caller marker, which is not "
            "used as proof)"
        ),
        first_edge_carried_object=True,
        source_id=source_id,
        source_object_id=object_id_text,
    )


def _live_at(
    local: Mapping[int, StackFunctionLiveness], function_start: int, address: int
):
    facts = local.get(function_start)
    if facts is None:
        return frozenset()
    return facts.live_before.get(address, frozenset())


def load_production_program(
    elf_path: str | Path | None = None,
    *,
    objdump_cmd: str = "objdump",
    dump_text: str | None = None,
    metadata: ChimeraMetadata | None = None,
    stage_factory: Callable[[str], ContextManager[object]] | None = None,
) -> tuple[Program, ChimeraMetadata]:
    """Parse + CFG-build through the **production** pipeline.

    Mirrors ``check_elf.collect_diagnostics``: ``LinuxObjdump`` supplies the
    disassembly format and the ``@plt`` trampoline fact, ``parse_dump`` builds
    the instruction model and ``RiscvServices.build_cfg`` connects the CFG.
    ``ChimeraMetadata.from_elf`` supplies the compiler metadata the production
    ``_CallTargetResolver`` reads.

    ``dump_text`` / ``metadata`` are the same test seams ``collect_diagnostics``
    offers; production callers leave both ``None`` and the ELF is disassembled
    and read for real.  The returned ``Program`` is the only kind of input
    that may yield ``resolved_by="analyzer"`` call edges.
    """

    import subprocess
    import tempfile

    adapter = LinuxObjdump(objdump_cmd)

    def _stage(name: str):
        return stage_factory(name) if stage_factory is not None else nullcontext()

    if metadata is None:
        if elf_path is None:
            raise ValueError("load_production_program needs an elf_path or metadata")
        metadata = ChimeraMetadata.from_elf(elf_path)

    dump_file: Path | None = None
    try:
        if dump_text is None:
            if elf_path is None:
                raise ValueError("load_production_program needs an elf_path or dump_text")
            with _stage("disassemble"):
                with tempfile.NamedTemporaryFile(
                    "wb", suffix=".dump", delete=False
                ) as dump_handle:
                    dump_file = Path(dump_handle.name)
                    completed = subprocess.run(
                        list(adapter.command(Path(elf_path))),
                        stdout=dump_handle,
                        stderr=subprocess.DEVNULL,
                        check=False,
                    )
                if completed.returncode != 0:
                    raise RuntimeError(
                        f"disassembly failed ({objdump_cmd}) for {elf_path}"
                    )
        else:
            with tempfile.NamedTemporaryFile(
                "w", suffix=".dump", encoding="utf-8", delete=False
            ) as dump_handle:
                dump_handle.write(dump_text)
                dump_file = Path(dump_handle.name)

        with _stage("parse"):
            parsed = parse_dump(
                dump_file,
                adapter.parse_format,
                is_external_trampoline=adapter.is_external_trampoline,
                retain_dump_lines=False,
            )
        with _stage("cfg"):
            program = RiscvServices(RvvServices()).build_cfg(parsed)
    finally:
        if dump_file is not None:
            dump_file.unlink(missing_ok=True)
    return program, metadata


def function_containing(program: Program, address: int):
    """(start, name) of the function holding ``address``, from real bounds.

    Unlike :func:`function_at` over a bare start table this uses each
    ``Function``'s instruction range (``start`` .. ``end``), so an address past
    the last instruction is not swallowed by the last function.
    """

    for function in program.functions:
        if function.start <= address <= function.end:
            return (function.start, function.name)
    return None


def function_summary(function) -> str:
    """Bounded one-line description of a ``Function``.

    Forensics logging must never expand the object graph: a ``Function``
    owns every ``Instruction`` and ``BasicBlock``, and the default dataclass
    ``__repr__`` would walk all of them.  This is a known overhead; the exact
    allocation responsible for the field OOM remains unconfirmed.
    Only scalars are emitted here.
    """

    return (
        f"{function.name} start={function.start:#x} "
        f"insts={len(function.insts)} blocks={len(function.blocks)}"
    )


def trace_from_elf(
    elf_path: str | Path | None = None,
    *,
    inheritance_path: str | Path | None = None,
    source_start: int,
    host_start: int,
    source_object_id: str | None = None,
    objdump_cmd: str = "objdump",
    max_depth: int = 8,
    dump_text: str | None = None,
    metadata: ChimeraMetadata | None = None,
    expected_sha256: str | None = None,
) -> TraceResult:
    """**Strong** evidence path: production edges + bound inheritance.

    This is the only path that may yield ``analysis-trace``:

    1. the ``Program`` and ``ChimeraMetadata`` come from
       :func:`load_production_program` (the production parse/CFG pipeline);
    2. call edges come from :func:`resolved_call_edges`, i.e. the production
       ``_CallTargetResolver`` -- every edge is ``resolved_by="analyzer"``;
    3. the inheritance report must bind to **this** ELF
       (:func:`load_inheritance`).

    A missing or unbound inheritance report, or any failure to build the
    production program, keeps the low grade.  The disassembly-suspected path
    is never consulted here.

    Steps 3 and the propagation itself are delegated to
    :func:`trace_from_bound_edges` (the shared half with the K3 forensics
    driver); this wrapper only builds the production Program/edges and
    restores the ``inheritance refused: ...`` diagnostic via ``on_refused``.
    """

    import hashlib

    source_label = source_object_id or f"irreducible:{source_start:x}"

    def _digest(path: str | Path) -> str:
        with Path(path).open("rb") as stream:
            return hashlib.file_digest(stream, "sha256").hexdigest()

    audit_sha = expected_sha256
    if audit_sha is None and elf_path is not None:
        audit_sha = _digest(elf_path)

    try:
        program, meta = load_production_program(
            elf_path,
            objdump_cmd=objdump_cmd,
            dump_text=dump_text,
            metadata=metadata,
        )
    except (OSError, RuntimeError, ValueError) as error:
        return TraceResult(
            grade="insufficient-evidence",
            reason=(
                "could not build the production Program/CFG ("
                + str(error)
                + "); the disassembly-suspected path is NOT a substitute"
            ),
            source_id=source_label,
            source_object_id=source_label,
            inheritance_bound=False,
        )

    edges = resolved_call_edges(program, metadata=meta)
    if not edges:
        return TraceResult(
            grade="insufficient-evidence",
            reason=(
                "production _CallTargetResolver produced no internal call "
                "edges; nothing to propagate along"
            ),
            source_id=source_label,
            source_object_id=source_label,
            inheritance_bound=False,
        )

    return trace_from_bound_edges(
        edges,
        inheritance_path=inheritance_path,
        expected_sha256=audit_sha,
        source_object_id=source_label,
        source_start=source_start,
        host_start=host_start,
        max_depth=max_depth,
        on_refused=lambda reason: print("inheritance refused:", reason),
    )


def load_inheritance(
    path: str | Path, expected_sha256: str
) -> tuple[dict | None, str]:
    """Load an inheritance report **bound** to the audited ELF.

    Returns ``(document, "")`` only when the report's format is known and its
    ``elf.content_sha256`` equals ``expected_sha256``.  Anything else returns
    ``(None, reason)`` and the caller must keep the low grade: a report from a
    different binary whose addresses merely coincide must not upgrade the
    trace to ``analysis-trace``.
    """

    source = Path(path)
    if not source.is_file():
        return None, f"insufficient-evidence (no inheritance report at {source})"
    try:
        document = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        return None, f"insufficient-evidence (unreadable inheritance report: {error})"

    fmt = document.get("format")
    if fmt not in INHERITANCE_FORMATS:
        return None, (
            f"insufficient-evidence (unknown inheritance format {fmt!r}; "
            f"accepted: {', '.join(INHERITANCE_FORMATS)})"
        )
    elf = document.get("elf") or {}
    digest = elf.get("content_sha256")
    if not digest:
        return None, (
            "insufficient-evidence (inheritance report carries no "
            "elf.content_sha256; cannot bind it to the audited ELF)"
        )
    if digest.lower() != expected_sha256.lower():
        return None, (
            "insufficient-evidence (inheritance report is bound to a "
            f"different ELF: report={digest} audited={expected_sha256}; "
            "refusing to upgrade the grade)"
        )
    return document, ""


def trace_from_bound_edges(
    call_edges: Iterable[CallEdge],
    *,
    inheritance_path: str | Path | None,
    expected_sha256: str | None,
    source_object_id: str,
    source_start: int,
    host_start: int,
    max_depth: int = 8,
    on_refused: Callable[[str], None] | None = None,
    stage_factory: Callable[[str], ContextManager[object]] | None = None,
) -> TraceResult:
    """Bind the inheritance report and propagate along **pre-resolved** edges.

    Common half of :func:`trace_from_elf` and the K3 forensics driver: both
    already hold a ``Program`` and its call edges and must not reload them.
    Edge-source checks are unchanged -- disassembly-suspected edges still
    cannot authorise ``analysis-trace``.

    A report that was given but refused is announced through ``on_refused``
    and never silently discarded: ``trace_from_elf`` prints
    ``inheritance refused: ...`` and the forensics driver may log it.
    """

    def _stage(name: str):
        return stage_factory(name) if stage_factory is not None else nullcontext()

    document: dict = {"format": "missing", "seed_edges": []}
    bound = False
    with _stage("bind"):
        if inheritance_path is not None and expected_sha256 is not None:
            loaded, reason = load_inheritance(inheritance_path, expected_sha256)
            if loaded is not None:
                document = loaded
                bound = True
            elif on_refused is not None:
                on_refused(reason)

    with _stage("propagate"):
        return trace_from_inheritance(
            document,
            call_edges=call_edges,
            source_object_id=source_object_id,
            source_start=source_start,
            host_start=host_start,
            inheritance_bound=bound,
            max_depth=max_depth,
        )


def seeds_from_inheritance(
    document: dict,
    source_object_id: str,
    source_start: int,
) -> list[tuple[int | None, int]]:
    """``(caller_ref, call_site)`` of seed edges carrying ``source_object_id``.

    Reads the analysis result's ``seed_edges[].local_active_objects``.  The
    generic ``caller:inherited-stack-data`` entry is **not** accepted as proof
    of this source -- it is shared by every inherited source.

    ``call_site`` is normalised to ``int``: the report writes it as a hex
    string (``"0x504d2"``) and the call graph as an address.
    """

    if source_object_id == str(CALLER_MARKER):
        return []
    found: list[tuple[int | None, int]] = []
    for edge in document.get("seed_edges", ()):
        ids = {
            item.get("id", "")
            for item in edge.get("local_active_objects", ())
        }
        if source_object_id in ids:
            site = edge.get("call_site")
            try:
                site_int = int(site, 16) if isinstance(site, str) else int(site)
            except (TypeError, ValueError):
                continue
            found.append((edge.get("caller_function_ref"), site_int))
    return found


def trace_from_inheritance(
    document: dict,
    *,
    call_edges: Iterable[CallEdge],
    source_object_id: str,
    source_start: int,
    host_start: int,
    inheritance_bound: bool,
    max_depth: int = 8,
) -> TraceResult:
    """Unified entry: seed from the analysis result, then propagate.

    ``call_edges`` come from :func:`resolved_call_edges` (analyzer) or
    :func:`call_edges_from_objdump` (disassembly).  Two caps apply and are
    never lifted together:

    * ``inheritance_bound=False`` caps at ``callgraph-path-only``;
    * any hop whose edge is ``resolved_by="disassembly"`` also caps at
      ``callgraph-path-only``.  A disassembly-suspected edge is not a
      production ``_CallTargetResolver`` result and cannot authorise
      ``analysis-trace`` on its own.

    Only bound inheritance **plus** analyzer-resolved edges yield
    ``analysis-trace``.
    """

    source_label = source_object_id
    edges = list(call_edges)
    by_caller: dict[int, list[CallEdge]] = {}
    for edge in edges:
        by_caller.setdefault(edge.caller_start, []).append(edge)

    def _cap_reason(steps: tuple[TraceStep, ...]) -> str | None:
        by_site = {edge.call_site: edge for edge in edges}
        for step in steps:
            edge = by_site.get(step.call_site)
            if edge is not None and edge.resolved_by != "analyzer":
                return (
                    "grade capped: hop "
                    + hex(step.call_site)
                    + " is a disassembly-suspected edge ("
                    + str(edge.resolved_by)
                    + "), not a production _CallTargetResolver result"
                )
        return None

    if not inheritance_bound:
        weak = _reachability(
            by_caller, source_start, host_start, max_depth=max_depth
        )
        return TraceResult(
            grade=weak[0],
            steps=weak[1],
            reason=(
                "inheritance report not bound to the audited ELF (or absent); "
                "grade capped at reachability.  "
                + weak[2]
            ),
            first_edge_carried_object=None,
            source_id=source_label,
            source_object_id=source_label,
            inheritance_bound=False,
        )

    # --- 1. seed from the analysis result's object-active calls ------------
    seed_sites = {
        site
        for _caller, site in seeds_from_inheritance(
            document, source_label, source_start
        )
    }
    seeds = [
        edge
        for edge in by_caller.get(source_start, [])
        if edge.call_site in seed_sites
    ]
    if not seeds:
        return TraceResult(
            grade="insufficient-evidence",
            reason=(
                "inheritance report is bound to this ELF but names no "
                "object-active seed call out of the source function"
            ),
            first_edge_carried_object=False,
            source_id=source_label,
            source_object_id=source_label,
            inheritance_bound=True,
        )

    entry_state: dict[int, str] = {}
    parent: dict[int, TraceStep] = {}

    def hand_over(caller: int, call_site: int, callee: int, first_hop: bool) -> bool:
        if callee == source_start:
            return False
        if entry_state.get(callee) == source_label:
            return False
        entry_state[callee] = source_label
        parent[callee] = TraceStep(
            caller=caller,
            call_site=call_site,
            callee=callee,
            source_id=source_label,
            first_hop=first_hop,
        )
        return True

    frontier: list[int] = []
    for edge in seeds:
        for callee in edge.targets:
            if hand_over(source_start, edge.call_site, callee, True):
                frontier.append(callee)

    depth = 1
    while frontier and depth < max_depth:
        nxt: list[int] = []
        for caller in frontier:
            for edge in by_caller.get(caller, []):
                for callee in edge.targets:
                    if hand_over(caller, edge.call_site, callee, False):
                        nxt.append(callee)
        frontier = nxt
        depth += 1

    if host_start not in entry_state:
        return TraceResult(
            grade="insufficient-evidence",
            reason=(
                "no source-id-carrying call chain from the bound seed reaches "
                "the host within depth "
                + str(max_depth)
            ),
            first_edge_carried_object=True,
            source_id=source_label,
            source_object_id=source_label,
            inheritance_bound=True,
        )

    steps: list[TraceStep] = []
    node = host_start
    while node != source_start and node in parent:
        step = parent[node]
        steps.append(step)
        node = step.caller
    steps.reverse()
    step_tuple = tuple(steps)
    capped = _cap_reason(step_tuple)
    if capped is not None:
        return TraceResult(
            grade="callgraph-path-only",
            steps=step_tuple,
            reason=capped + ".  Reachability only; G2 is NOT filled.",
            first_edge_carried_object=True,
            source_id=source_label,
            source_object_id=source_label,
            inheritance_bound=inheritance_bound,
        )
    return TraceResult(
        grade="analysis-trace",
        steps=step_tuple,
        reason=(
            "seeded by the inheritance report's object-active call and then "
            "carried by a distinct source id along analyzer-resolved call edges"
        ),
        first_edge_carried_object=True,
        source_id=source_label,
        source_object_id=source_label,
        inheritance_bound=True,
    )


def _reachability(
    by_caller: Mapping[int, list[CallEdge]],
    source_start: int,
    host_start: int,
    *,
    max_depth: int,
) -> tuple[str, tuple[TraceStep, ...], str]:
    parent: dict[int, TraceStep] = {}
    seen = {source_start}
    frontier = [source_start]
    depth = 0
    while frontier and depth < max_depth:
        nxt: list[int] = []
        for caller in frontier:
            for edge in by_caller.get(caller, []):
                for callee in edge.targets:
                    if callee in seen:
                        continue
                    seen.add(callee)
                    parent[callee] = TraceStep(
                        caller=caller,
                        call_site=edge.call_site,
                        callee=callee,
                        source_id="",
                        first_hop=False,
                    )
                    if callee == host_start:
                        steps = []
                        node = host_start
                        while node != source_start and node in parent:
                            step = parent[node]
                            steps.append(step)
                            node = step.caller
                        steps.reverse()
                        return (
                            "callgraph-path-only",
                            tuple(steps),
                            "call-graph path exists but no hop was shown to "
                            "carry the source; reachability only",
                        )
                    nxt.append(callee)
        frontier = nxt
        depth += 1
    return (
        "insufficient-evidence",
        (),
        "no call-graph path from source to host",
    )


def callgraph_only_result(
    program: Program,
    source_start: int,
    host_start: int,
    *,
    max_depth: int = 8,
) -> TraceResult:
    """Reachability without the activity filter.  **Never** propagation.

    Present so a caller can see the difference; it must be reported as
    ``callgraph-path-only`` and must not close the propagation-trace gap.
    """

    functions_by_start = {f.start: f for f in program.functions}
    by_caller: dict[int, list[int]] = {}
    for function in program.functions:
        for instruction in function.insts:
            if not is_call_instruction(instruction):
                continue
            for target in instruction.jump_targets:
                if target in functions_by_start:
                    by_caller.setdefault(function.start, []).append(target)

    parent: dict[int, tuple[int, int]] = {}
    seen = {source_start}
    frontier = [source_start]
    depth = 0
    found = False
    while frontier and depth < max_depth and not found:
        nxt: list[int] = []
        for caller in frontier:
            for callee in by_caller.get(caller, []):
                if callee in seen:
                    continue
                seen.add(callee)
                parent[callee] = (caller, caller)
                if callee == host_start:
                    found = True
                nxt.append(callee)
        frontier = nxt
        depth += 1

    if not found:
        return TraceResult(
            grade="insufficient-evidence",
            reason="no call-graph path from source to host",
        )
    return TraceResult(
        grade="callgraph-path-only",
        reason=(
            "call-graph path exists but the edges were not shown to carry the "
            "object; this is reachability, not propagation evidence"
        ),
        first_edge_carried_object=None,
    )


def call_edges_from_objdump(
    functions: Iterable[tuple[int, str]],
    line_by_caller: Mapping[str, Iterable[str]],
    *,
    external_trampolines: Iterable[int] = (),
) -> list[CallEdge]:
    """Build *suspected* call edges from objdump text.

    ``line_by_caller`` maps a function name to its objdump lines.  Targets
    are resolved by :func:`resolve_call_target` -- an exact function entry,
    never "the nearest earlier function" and never an external trampoline.
    Unknown targets and out-of-range addresses **keep the gap**: no edge is
    emitted for them.

    ``j`` / ``tail`` / ``jal x0`` never become edges.  ``first_hop_active``
    is left False here -- only a live set or an analysis result can set it.
    ``resolved_by`` is ``"disassembly"``, so a path built from these edges
    cannot on its own authorise ``analysis-trace``.
    """

    table = tuple(sorted(functions))
    names = {name: start for start, name in table}
    functions_by_start = {start: name for start, name in table}
    trampolines = frozenset(external_trampolines)
    edges: list[CallEdge] = []
    for caller_name, lines in line_by_caller.items():
        caller_start = names.get(caller_name)
        if caller_start is None:
            continue
        for line in lines:
            candidate = parse_objdump_line(line, names)
            if candidate is None or not candidate.is_call:
                continue
            target = resolve_call_target(
                functions_by_start,
                candidate.target_address,
                external_trampolines=trampolines,
            )
            if target is None:
                # Unresolved / external / out of range: keep the gap.
                continue
            edges.append(
                CallEdge(
                    call_site=candidate.address,
                    caller_start=caller_start,
                    targets=(target,),
                    first_hop_active=False,
                    resolved_by="disassembly",
                )
            )
    return edges


def describe(result: TraceResult) -> dict:
    return {
        "grade": result.grade,
        "is_propagation_evidence": result.is_propagation_evidence,
        "first_edge_carried_object": result.first_edge_carried_object,
        "source_id": result.source_id,
        "source_object_id": result.source_object_id,
        "inheritance_bound": result.inheritance_bound,
        "reason": result.reason,
        "steps": [
            {
                "caller": hex(step.caller),
                "call_site": hex(step.call_site),
                "callee": hex(step.callee),
                "source_id": step.source_id,
                "first_hop": step.first_hop,
            }
            for step in result.steps
        ],
    }
