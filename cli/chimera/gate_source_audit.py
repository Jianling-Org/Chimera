"""Independent audit of implicit-vectorization sources against the gate list.

This module is a deliberately *independent* re-check of the gate-2 remediation:
it never imports the check-elf diagnostic module, never touches the
safety-point classification, the pass criteria or the check credentials, and it
recomputes the call closure itself instead of trusting the analyzer's
``seed_edges`` or any single witness path.

Scope assumption of this round (see docs/developer/gate-source-audit.md): the
audit targets stack state introduced by *compiler implicit vectorization* -
vector stack objects and VLEN-dependent stack allocations.  A dynamic
allocation whose size is merely UNKNOWN (an ordinary parameter, a counter, an
external return value) is **excluded under assumption, never proven safe**:
such items are recorded per item with ``excluded_by_assumption=True`` and stay
traceable.  A VLEN dependency that is *tracked* - including one staged through
a register move, a memory spill and a load back - is kept as a VLEN source;
"it went through a load" is never by itself a reason to exclude it.

Per ELF the input is disassembled, parsed and analyzed exactly once; every
enumeration below reads the local facts of that single pass.

Outputs: a machine-readable JSON document (``chimera-gate-source-audit-v1``),
two filterable CSVs (per-candidate and per-gate-list-entry) and a Chinese
conclusion report answering two questions separately:

* which candidate sources are missing from the gate list (哪些源头漏入清单);
* which listed functions still need gate-effect verification
  (哪些清单函数仍需验证 gate 效果).

The two answers are kept apart from the two *evidence* verdicts the report must
never conflate:

* a bound ``blocked`` census record is execution evidence that the gate ran;
* a bound ``formed`` census record is execution evidence that the gate did
  *not* fire;
* a census record that cannot be bound to the build it claims to come from
  proves neither, and is reported as insufficient evidence.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import subprocess
import sys
import tempfile
from collections import deque
from dataclasses import dataclass, replace
from pathlib import Path

from chimera.preprocess.offline.analysis.arch.riscv.rvv.config import VSET_OPS
from chimera.preprocess.offline.analysis.arch.riscv.rvv.services import RvvServices
from chimera.preprocess.offline.analysis.arch.riscv.services import RiscvServices
from chimera.preprocess.offline.analysis.program_model.parser import parse_dump
from chimera.preprocess.offline.analysis.safety.stack_liveness import (
    ChimeraMetadata,
    StackLivenessAnalyzer,
)
from chimera.preprocess.offline.analysis.safety.stack_liveness.frame_liveness import (
    VLEN_STACK_FRAME,
    VLEN_STACK_SETUP,
)
from chimera.preprocess.offline.analysis.safety.stack_liveness.liveness import (
    _CallTargetResolver,
)
from chimera.preprocess.offline.analysis.safety.stack_liveness.model import (
    ACTIVE_EXTERNAL_CALL,
    InheritedLivenessView,
    StackFunctionLiveness,
    StackLivenessResult,
    StackObjectId,
)
from chimera.preprocess.offline.analysis.safety.stack_liveness.origins import VLEN
from chimera.preprocess.offline.analysis.toolchain.objdump import LinuxObjdump

AUDIT_FORMAT = "chimera-gate-source-audit-v1"
COMPARE_FORMAT = "chimera-gate-source-audit-compare-v1"
EVIDENCE_FORMAT = "chimera-gate-source-evidence-v1"

# region Source-kind vocabulary
#
# Five enumerated source kinds plus the honesty fallback.  Only
# SOURCE_UNKNOWN_ALLOCATION is excluded under this round's assumption; the
# fallback kind is *never* auto-excluded, because activity the audit cannot
# attribute is precisely what must not be silently dropped.

#: A stack allocation whose size is a direct or *tracked* VLEN dependency
#: (register dataflow, or a proof that followed the value through a spill and
#: a load back).
SOURCE_VLEN_ALLOCATION = "vlen-allocation"
#: A stack allocation whose size stayed merely UNKNOWN - excluded under this
#: round's assumption, recorded per item, never called proven-safe.
SOURCE_UNKNOWN_ALLOCATION = "unknown-allocation"
#: A resolved vector stack object (compiler metadata id or binary-recovered
#: address expression).
SOURCE_VECTOR_STACK_OBJECT = "vector-stack-object"
#: A vector memory access the address resolution gave up on; the enclosing
#: scope carries the conservative marker.
SOURCE_UNRESOLVED_VECTOR_ACCESS = "unresolved-vector-access"
#: Vector store(s) inside an irreducible loop degraded to a function-scoped
#: conservative object.
SOURCE_IRREDUCIBLE_DEGRADATION = "irreducible-degradation"
#: Live state at an active call site that no enumerated item claims.  Always
#: recorded together with a gap entry; never excluded by assumption.
SOURCE_UNATTRIBUTED_ACTIVITY = "unattributed-activity"
SOURCE_SCALAR_WIDTH_CACHE = "scalar-width-cache"

ASSUMPTION_EXCLUDED_KINDS = frozenset({SOURCE_UNKNOWN_ALLOCATION})

#: The scope statements echoed into every JSON document so the machine-readable
#: output carries the exact assumption it was computed under.
ASSUMPTION_STATEMENTS = (
    "本轮处理编译器隐式向量化引入的向量栈对象、VLEN 相关栈分配及已识别的标量宽度缓存。",
    "普通参数、计数字段、外部返回值驱动的动态分配不因尺寸 UNKNOWN 就被认定为应 gate 的源头；"
    "此类条目按假设排除、未经证明，不得标成已证明安全。",
    "直接或已追踪的 VLEN 依赖（含经寄存器搬运、暂存和加载的依赖）保留；"
    "不按“经过内存加载”直接排除。",
    "显式向量代码及无法判断来源的向量代码单列，不承诺 gate 必然消除。",
    "归属不明的活跃状态按缺口记录，不按地址远近挑一个来源充当唯一归属。",
    "本审计不改变 check-elf、安全点分类、通过判据或检查凭证；原 findings 结论保持不变。",
)

#: Gate-list entry status vocabulary (closed set; the report maps them to
#: Chinese conclusions).
ENTRY_GATE_BYPASSED = "gate-bypassed"
#: A bound ``formed`` record seen in a stage that does not enable the gate
#: (``build-stack``): the code was generated, but there was no gate to bypass.
#: Calling this "bypassed" would manufacture a failure out of the baseline's
#: normal behaviour.
ENTRY_FORMED_BEFORE_GATE = "formed-before-gate"
ENTRY_SOURCE_REMAINS = "source-remains"
ENTRY_VECTOR_REMAINS = "vector-instructions-remain"
ENTRY_BLOCKED_EVIDENCE = "blocked-evidence"
ENTRY_UNBOUND_EVIDENCE = "unbound-evidence"
ENTRY_MISSING_COMPILE_EVIDENCE = "missing-compile-evidence"
ENTRY_NO_SYMBOL = "no-symbol"

#: Statuses meaning "this listed function still needs gate-effect
#: verification" - the second question the report answers.  Only
#: ``ENTRY_BLOCKED_EVIDENCE`` is left out: it is the one status backed by a
#: *bound* blocked record, and even that is not a per-function proof.
PENDING_ENTRY_STATUSES = (
    ENTRY_GATE_BYPASSED,
    ENTRY_FORMED_BEFORE_GATE,
    ENTRY_SOURCE_REMAINS,
    ENTRY_VECTOR_REMAINS,
    ENTRY_UNBOUND_EVIDENCE,
    ENTRY_MISSING_COMPILE_EVIDENCE,
    ENTRY_NO_SYMBOL,
)

#: What the aggregate wrapper log line ("gate list: N function(s)") actually
#: proves: the list was *passed in*.  Nothing else.
AGGREGATE_LOG_NOTE = (
    "聚合日志 “gate list: N function(s)” 只证明名单被传入编译；"
    "找不到符号不能直接算成功，逐函数命中必须有编译期证据。"
)

#: The gate-2 build log reports ``gate list: 1642 function(s)``.  That single
#: line only proves the list *was passed in*; the audit therefore re-derives
#: the deduplicated name set from the original decision file the build
#: actually consumed and checks it against this count on the spot.  A bloated,
#: duplicated or silently truncated decision would otherwise be invisible.
EXPECTED_GATE2_LIST_SIZE = 1642

#: Census record vocabulary.  ``vector_census_report.py`` owns the same four
#: mechanisms; the audit keeps them as a *known* set and reports anything else
#: instead of discarding it, because an unknown mechanism is itself a finding.
CENSUS_TAG = "implicit-vector-census"
CENSUS_ACTIONS = ("formed", "blocked")
CENSUS_MECHANISMS = ("LV", "SLP", "MEMOP", "MERGE")

#: Build stages the evidence manifest can attest.  ``unknown`` never binds.
STAGE_BUILD_STACK = "build-stack"
STAGE_BUILD_GATE2 = "build-gate2"
STAGE_UNKNOWN = "unknown"

#: Bytes of an objdump stderr prefix that are quoted in a failure message.
#: The prefix is *read* bounded - never "read the whole file, then slice".
STDERR_PREFIX_BYTES = 400

# endregion


# region Gap vocabulary
#
# Every hole the audit refuses to paper over is recorded under one of these
# kinds, so a consumer can filter instead of parsing prose.

GAP_AMBIGUOUS_FRAME_ORIGIN = "ambiguous-frame-origin"
GAP_AMBIGUOUS_SETUP_ORIGIN = "ambiguous-setup-origin"
GAP_UNATTRIBUTED_FRAME_MARKER = "unattributed-frame-marker"
GAP_UNATTRIBUTED_SETUP_MARKER = "unattributed-setup-marker"
GAP_UNATTRIBUTED_LIVE_OBJECT = "unattributed-live-object"
GAP_INHERITED_MARKER_IN_BASE = "inherited-marker-in-base-map"
GAP_CLOSURE_MISMATCH = "closure-mismatch"
GAP_AFFECTED_SITE_MISMATCH = "affected-site-mismatch"
GAP_PROPAGATION_ITERATION_CAP = "propagation-iteration-cap"
GAP_GATE_LIST_SIZE_MISMATCH = "gate-list-size-mismatch"
GAP_CHECK_REPORT_HASH_MISMATCH = "check-report-hash-mismatch"
GAP_CENSUS_UNREADABLE = "census-unreadable"
GAP_CENSUS_MALFORMED_LINE = "malformed-census-line"
GAP_CENSUS_WITHOUT_USABLE_LINES = "census-without-usable-lines"
GAP_CENSUS_UNKNOWN_MECHANISM = "census-unknown-mechanism"
GAP_CENSUS_ACTION_CONFLICT = "census-action-conflict"
GAP_CENSUS_UNBOUND = "census-evidence-unbound"
#: Census files were supplied but no *consumed* decision was declared, so
#: nothing could be bound to the build that produced them.  This is a distinct
#: gap from a per-file mismatch: the comparison list is deliberately NOT
#: substituted, because for the baseline build the two are different documents.
GAP_CONSUMED_DECISION_MISSING = "consumed-decision-missing"
GAP_EVIDENCE_UNREADABLE = "evidence-unreadable"

#: Gap kinds that mean "this live state was not claimed by any enumerated
#: source"; the follow-up evidence list keys off this prefix.
UNATTRIBUTED_GAP_PREFIX = "unattributed"

#: Gap kinds that mean "several allocations could own this live state".
AMBIGUOUS_GAP_KINDS = (GAP_AMBIGUOUS_FRAME_ORIGIN, GAP_AMBIGUOUS_SETUP_ORIGIN)

# endregion


# region Compile-evidence verdict vocabulary
#
# Evidence quality is an axis *orthogonal* to the source verdict: a listed
# function can still carry a source and simultaneously have a census record
# nobody can vouch for.  Collapsing the two into one status is what lets an
# unattached "N function(s)" line stand in for a per-function proof, so the two
# are reported side by side.

#: A blocked record whose census file is bound to this build.
EVIDENCE_BOUND_BLOCKED = "bound-blocked"
#: A formed record whose census file is bound to this build.
EVIDENCE_BOUND_FORMED = "bound-formed"
#: Records exist but cannot be bound to this build; they prove neither way.
EVIDENCE_UNBOUND = "unbound"
#: The same function/mechanism is recorded both ways; the conflict is kept.
EVIDENCE_CONFLICT = "conflict"
#: The record names a mechanism this round cannot interpret.  Kept as a
#: record, never promoted to a verdict.
EVIDENCE_UNRECOGNISED = "unrecognised"
#: No census record for this entry at all.
EVIDENCE_NONE = "none"

# endregion


_CONSERVATIVE_MARKER = StackObjectId("conservative", "possible-stack-data")
_CALLER_MARKER = StackObjectId("caller", "inherited-stack-data")

_EMPTY = frozenset()


# region Candidate model


@dataclass(frozen=True)
class SourceCandidate:
    """One enumerated candidate source from the local liveness facts.

    ``addresses`` keeps the typed address roles: ``allocation``/``release``
    for frames, ``stores``/``loads`` for vector objects, ``scopes`` for the
    conservative item, ``stores``/``loops`` for the irreducible item.
    ``objects`` are the liveness object ids this item answers for during
    propagation.
    """

    id: str
    elf_sha256: str
    function: str
    function_start: int
    kind: str
    excluded_by_assumption: bool
    addresses: dict
    evidence: dict
    objects: tuple[str, ...] = ()
    notes: tuple[str, ...] = ()
    affected_sites: tuple[int, ...] = ()


# endregion


# region Local-fact enumeration


def _base_live(local: StackFunctionLiveness):
    """The pre-merge local live-in map of one function.

    The propagation stage layers the inherited marker onto inherited functions
    through :class:`InheritedLivenessView`; the audit enumerates candidates
    from *local* facts only, so the base map is what it reads.
    """

    live = local.live_before
    if isinstance(live, InheritedLivenessView):
        return live.base
    return live


def _allocation_kind(origin, stack: StackLivenessResult):
    """Classify one recorded allocation origin.

    ``dependency == "vlen"`` is a direct VLEN dependency.  ``"unknown"`` needs
    the linked proof node: a ``vlen`` verdict there means the dependency was
    *tracked* through staging (register move / memory spill / load back) and
    the allocation stays a VLEN source; anything else is the plain-UNKNOWN
    case this round excludes under assumption.
    """

    if origin.dependency == "vlen":
        return SOURCE_VLEN_ALLOCATION, {"tracked_via": "register-dependency"}
    if origin.dependency == "unknown":
        proof = stack.proof(origin.proof)
        if proof is not None and proof.status == VLEN:
            return SOURCE_VLEN_ALLOCATION, {
                "tracked_via": "origin-proof",
                "proof_status": proof.status,
                "proof_reason": proof.reason,
            }
        evidence: dict = {}
        if proof is not None:
            evidence["proof_status"] = proof.status
            evidence["proof_reason"] = proof.reason
        return SOURCE_UNKNOWN_ALLOCATION, evidence
    # "proven" origins were discharged and never create frame state; the
    # caller filters them out before they reach here.
    raise ValueError(f"unexpected allocation dependency: {origin.dependency}")


def enumerate_candidates(
    program,
    stack: StackLivenessResult,
    *,
    elf_sha256: str,
) -> list[SourceCandidate]:
    """Enumerate per-item candidate sources from the local liveness facts.

    Mixed origins in one function are kept item by item: an UNKNOWN allocation
    never drags the function's vector objects into the excluded bucket, and
    the excluded allocation never hides the rest of the function.
    """

    candidates: list[SourceCandidate] = []
    for function in program.functions:
        local = stack.by_function.get(function.start)
        if local is None:
            continue
        index = 0

        def next_id(kind: str, _start: int = function.start) -> str:
            nonlocal index
            ident = f"{_start:#x}:{kind}:{index}"
            index += 1
            return ident

        # 1) Stack allocations recorded by the frame analysis.
        for origin in getattr(local, "frame_origins", ()):
            if origin.dependency == "proven":
                continue  # discharged by an origin proof; creates no state
            kind, extra = _allocation_kind(origin, stack)
            excluded = kind in ASSUMPTION_EXCLUDED_KINDS
            notes: list[str] = []
            if excluded:
                notes.append(
                    "尺寸来源未证明（普通 UNKNOWN）：按本轮假设排除，未证明安全"
                )
            elif extra.get("tracked_via") == "origin-proof":
                notes.append(
                    "VLEN 依赖经来源证明追踪（含暂存/加载路径），不按 UNKNOWN 排除"
                )
            candidates.append(
                SourceCandidate(
                    id=next_id(kind),
                    elf_sha256=elf_sha256,
                    function=function.name,
                    function_start=function.start,
                    kind=kind,
                    excluded_by_assumption=excluded,
                    addresses={
                        "allocation": origin.adjustment,
                        "release": origin.release,
                    },
                    evidence={
                        "dependency": origin.dependency,
                        "size_register": origin.size_register,
                        "proof": origin.proof,
                        "gaps": list(origin.gaps),
                        **extra,
                    },
                    objects=(str(VLEN_STACK_FRAME), str(VLEN_STACK_SETUP)),
                    notes=tuple(notes),
                )
            )

        width_sources = getattr(local, "scalar_width_sources", ())
        if width_sources and any(obj.source == "vlen_scalar"
                                 for values in _base_live(local).values() for obj in values):
            candidates.append(SourceCandidate(
                id=next_id(SOURCE_SCALAR_WIDTH_CACHE), elf_sha256=elf_sha256,
                function=function.name, function_start=function.start,
                kind=SOURCE_SCALAR_WIDTH_CACHE, excluded_by_assumption=False,
                addresses={"reads": [item.address for item in width_sources]},
                evidence={"sources": [
                    {"address": item.address, "register": item.register, "kind": item.kind}
                    for item in width_sources],
                    "fallback": bool(getattr(local, "scalar_width_fallback", False))},
                objects=(str(StackObjectId("vlen_scalar", "hardware-width-cache")),),
            ))

        # 2) Resolved vector stack objects, one item per object id.
        by_object: dict[StackObjectId, list] = {}
        for access in local.accesses.values():
            by_object.setdefault(access.stack_id, []).append(access)
        for stack_id in sorted(by_object, key=str):
            entries = by_object[stack_id]
            stores = sorted(
                item.instruction_addr
                for item in entries
                if item.kind.value == "store"
            )
            loads = sorted(
                item.instruction_addr for item in entries if item.kind.value == "load"
            )
            candidates.append(
                SourceCandidate(
                    id=next_id(SOURCE_VECTOR_STACK_OBJECT),
                    elf_sha256=elf_sha256,
                    function=function.name,
                    function_start=function.start,
                    kind=SOURCE_VECTOR_STACK_OBJECT,
                    excluded_by_assumption=False,
                    addresses={"stores": stores, "loads": loads},
                    evidence={
                        "object": str(stack_id),
                        "source": stack_id.source,
                        "accesses": len(entries),
                    },
                    objects=(str(stack_id),),
                )
            )

        # 3) Unresolved vector accesses: the whole conservative scope shares
        # one marker, so one item carries every address; per-address splitting
        # would pretend a precision the liveness state does not have.
        if local.conservative_addresses:
            candidates.append(
                SourceCandidate(
                    id=next_id(SOURCE_UNRESOLVED_VECTOR_ACCESS),
                    elf_sha256=elf_sha256,
                    function=function.name,
                    function_start=function.start,
                    kind=SOURCE_UNRESOLVED_VECTOR_ACCESS,
                    excluded_by_assumption=False,
                    addresses={"scopes": sorted(local.conservative_addresses)},
                    evidence={
                        "detail": "向量访存地址未能解析，所在作用域按保守栈活跃处理"
                    },
                    objects=(str(_CONSERVATIVE_MARKER),),
                    notes=("同一函数的保守作用域共享一个活跃标记，逐项地址不可再分",),
                )
            )

        # 4) Irreducible-loop degradation, one item per function.
        irreducible_warnings = [
            warning
            for warning in local.warnings
            if warning.code == "irreducible-loop-degraded"
        ]
        if irreducible_warnings:
            marker = StackObjectId("irreducible", f"{function.start:x}")
            candidates.append(
                SourceCandidate(
                    id=next_id(SOURCE_IRREDUCIBLE_DEGRADATION),
                    elf_sha256=elf_sha256,
                    function=function.name,
                    function_start=function.start,
                    kind=SOURCE_IRREDUCIBLE_DEGRADATION,
                    excluded_by_assumption=False,
                    addresses={
                        "stores": sorted(
                            {
                                address
                                for warning in irreducible_warnings
                                for address in warning.addresses
                            }
                        ),
                        "loops": [sorted(loop) for loop in local.irreducible_loops],
                    },
                    evidence={
                        "detail": "不可归约循环内的向量存储降级为函数级保守对象"
                    },
                    objects=(str(marker),),
                )
            )

    return candidates


# endregion


# region Call-relation enumeration and fixpoint propagation


def _predecessors(function) -> dict[int, tuple[int, ...]]:
    """Intra-function predecessor lists, derived from the recorded successors.

    Computed here rather than imported from the analysis package: the audit
    reads the *exported* CFG only, so a change to how the analysis stores its
    own edge bookkeeping cannot silently change an attribution.
    """

    table: dict[int, list[int]] = {
        instruction.addr: [] for instruction in function.insts
    }
    for instruction in function.insts:
        for successor in instruction.succ:
            bucket = table.get(successor)
            if bucket is not None:
                bucket.append(instruction.addr)
    return {address: tuple(sorted(values)) for address, values in table.items()}


@dataclass(frozen=True)
class CallRelation:
    """One call boundary or explicit local value-escape site.

    ``local_contributors`` are the host's own candidate items whose watched
    objects are live at the site; the inherited share is added by the
    fixpoint, not stored here.  Whether a site is *active* is therefore a
    post-propagation question - a site with no local contributor can still be
    active because its caller inherited state, and counting the local set
    alone under-reports exactly those cases.
    """

    function_start: int
    call_site: int
    resolution: str  # resolved | unresolved-indirect-call | empty-call-target-set | active-external-call
    targets: tuple[int, ...]
    local_contributors: tuple[str, ...]
    external_targets: tuple[int, ...] = ()
    scalar_width_escape: bool = False


class _MarkerOriginIndex:
    """Which allocations can own a shared marker that is live at an address.

    Both markers are *may* properties, and several adjustments can share one
    marker object, so "the nearest allocation at or before the call" is not an
    attribution - it is a tie-break dressed as a fact.  This index instead
    records **every** adjustment the marker can be traced back to; one
    adjustment means a unique origin, several mean an explicit ambiguity that
    the audit keeps as a candidate set instead of dropping the losers.

    The two markers run in **opposite directions**, and walking both the same
    way silently mis-attributes one of them:

    * the *frame* state is created **at** the adjustment (``_classify_stack_writes``
      propagates it over successors), so the addresses it reaches lie after it
      and are found by walking successors;
    * the *setup* region is a **backward** dependency: ``_setup_dependencies``
      walks predecessors from the adjustment while the VLEN-tainted value is
      live, so the region lies *before* the adjustment and is found by walking
      predecessors.  Walking successors for it finds nothing, which used to
      turn a real setup activity into an ``unattributed-setup-marker`` - and
      from there into an un-excludable fallback source, defeating this round's
      scope narrowing.

    The walk is gated on the marker actually being live at each visited
    address, so it stops exactly where the analysis stopped.  Tables are built
    lazily, once per (function, marker, direction).
    """

    __slots__ = ("_function", "_live", "_tables")

    def __init__(self, function, local: StackFunctionLiveness) -> None:
        self._function = function
        self._live = _base_live(local)
        self._tables: dict[
            tuple[StackObjectId, bool], dict[int, tuple[int, ...]]
        ] = {}

    def origins_at(
        self,
        marker: StackObjectId,
        call_addr: int,
        adjustments,
        *,
        forward: bool,
    ) -> tuple[int, ...]:
        key = (marker, forward)
        table = self._tables.get(key)
        if table is None:
            table = self._build(marker, adjustments, forward=forward)
            self._tables[key] = table
        return table.get(call_addr, ())

    def _build(
        self, marker: StackObjectId, adjustments, *, forward: bool
    ) -> dict[int, tuple[int, ...]]:
        instructions = self._function.instruction_by_address
        live = self._live
        predecessors = None if forward else _predecessors(self._function)
        table: dict[int, list[int]] = {}
        for adjustment in sorted(set(adjustments)):
            seen = {adjustment}
            queue: deque[int] = deque([adjustment])
            while queue:
                address = queue.popleft()
                instruction = instructions.get(address)
                if instruction is None:
                    continue
                if forward:
                    neighbours = instruction.succ
                else:
                    neighbours = predecessors.get(address, ())
                for neighbour in neighbours:
                    if neighbour in seen:
                        continue
                    if marker not in live.get(neighbour, _EMPTY):
                        # The marker is not live here (outside the region, or
                        # past a proven restore); never walk past it.
                        continue
                    seen.add(neighbour)
                    bucket = table.setdefault(neighbour, [])
                    if adjustment not in bucket:
                        bucket.append(adjustment)
                    queue.append(neighbour)
        return {
            address: tuple(sorted(values)) for address, values in table.items()
        }


def _site_contributors(
    function,
    local: StackFunctionLiveness,
    call_addr: int,
    items: list[SourceCandidate],
    gaps: list[dict],
    fallback_items: dict[tuple[int, str], SourceCandidate],
    elf_sha256: str,
    origin_index: _MarkerOriginIndex,
) -> tuple[str, ...]:
    """Candidate items whose watched objects are live at ``call_addr``.

    Shared frame and setup markers are attributed through :class:`_MarkerOriginIndex`:
    a unique allocation is named, several possible allocations are kept as a
    candidate set with an ``ambiguous-*`` gap, and no allocation at all
    becomes an explicit ``unattributed-activity`` fallback item plus a gap -
    the audit records the hole instead of claiming completeness.
    """

    live = _base_live(local).get(call_addr, _EMPTY)
    if not live:
        return ()
    frame_items = [
        item
        for item in items
        if item.kind in (SOURCE_VLEN_ALLOCATION, SOURCE_UNKNOWN_ALLOCATION)
    ]
    frame_by_adjustment = {
        item.addresses["allocation"]: item for item in frame_items
    }
    frame_adjustments = tuple(frame_by_adjustment)
    ids: list[str] = []

    def remember(item: SourceCandidate) -> None:
        if item.id not in ids:
            ids.append(item.id)

    def record_ambiguous(marker, kind: str, origins, attributed) -> None:
        gaps.append(
            {
                "kind": kind,
                "function": function.name,
                "function_start": function.start,
                "call_site": call_addr,
                "marker": str(marker),
                "allocations": [hex(address) for address in origins],
                "candidates": [item.id for item in attributed],
                "detail": (
                    "共享活跃标记在调用点可归属到多个分配；"
                    "保留候选集合，不按地址排序丢弃来源"
                ),
            }
        )

    def fallback_for(obj: StackObjectId, gap_kind: str, detail: str) -> None:
        gaps.append(
            {
                "kind": gap_kind,
                "function": function.name,
                "function_start": function.start,
                "call_site": call_addr,
                "detail": detail,
            }
        )
        key = (function.start, str(obj))
        if key not in fallback_items:
            fallback_items[key] = SourceCandidate(
                id=(
                    f"{function.start:#x}:{SOURCE_UNATTRIBUTED_ACTIVITY}:"
                    f"{len(fallback_items)}"
                ),
                elf_sha256=elf_sha256,
                function=function.name,
                function_start=function.start,
                kind=SOURCE_UNATTRIBUTED_ACTIVITY,
                excluded_by_assumption=False,
                addresses={},
                evidence={"object": str(obj)},
                objects=(str(obj),),
                notes=("活跃对象未被任何已枚举来源认领；按未覆盖缺口记录",),
            )
        remember(fallback_items[key])

    def attribute_marker(
        marker: StackObjectId,
        ambiguous_gap: str,
        missing_gap: str,
        unreachable: str,
        *,
        forward: bool,
    ) -> None:
        origins = origin_index.origins_at(
            marker, call_addr, frame_adjustments, forward=forward
        )
        attributed = [
            frame_by_adjustment[address]
            for address in origins
            if address in frame_by_adjustment
        ]
        if len(attributed) == 1:
            remember(attributed[0])
        elif attributed:
            record_ambiguous(marker, ambiguous_gap, origins, attributed)
            for item in attributed:
                remember(item)
        else:
            fallback_for(
                marker,
                missing_gap,
                unreachable,
            )

    for obj in sorted(live, key=str):
        if obj == _CALLER_MARKER:
            # The inherited marker is layered on by ``InheritedLivenessView``
            # and stripped by ``_base_live``; seeing it here would mean the
            # local facts are already merged, which would silently turn
            # inherited activity into a local attribution.
            gaps.append(
                {
                    "kind": GAP_INHERITED_MARKER_IN_BASE,
                    "function": function.name,
                    "function_start": function.start,
                    "call_site": call_addr,
                    "detail": "局部活跃集合中出现继承标记，局部事实可能已被合并",
                }
            )
            continue
        if obj == VLEN_STACK_FRAME:
            attribute_marker(
                obj,
                GAP_AMBIGUOUS_FRAME_ORIGIN,
                GAP_UNATTRIBUTED_FRAME_MARKER,
                "活跃帧标记在调用点未能归属到任何已记录的分配",
                forward=True,
            )
            continue
        if obj == VLEN_STACK_SETUP:
            attribute_marker(
                obj,
                GAP_AMBIGUOUS_SETUP_ORIGIN,
                GAP_UNATTRIBUTED_SETUP_MARKER,
                "活跃 setup 标记在调用点未能归属到任何已记录的分配",
                forward=False,
            )
            continue
        matched = [item for item in items if str(obj) in item.objects]
        if matched:
            for item in matched:
                remember(item)
            continue
        fallback_for(
            obj,
            GAP_UNATTRIBUTED_LIVE_OBJECT,
            f"活跃对象 {obj} 未被任何已枚举来源认领",
        )
    return tuple(ids)


def propagate_sources(
    program,
    stack: StackLivenessResult,
    candidates: list[SourceCandidate],
    metadata: ChimeraMetadata,
    semantics,
    *,
    elf_sha256: str,
):
    """Attribute sources to unresolved and external boundaries they feed.

    The closure is recomputed from the full re-enumerated call relation set -
    not from the analyzer's ``seed_edges`` or any single witness: a finite
    worklist fixpoint over sets of candidate ids (monotone union on a finite
    universe, so recursion can never make it diverge and no path enumeration
    is involved).  The result is then cross-checked against the analyzer's own
    closure; a mismatch is recorded as a gap, never silently resolved.

    Returns ``(candidates, relations, affected, gaps, stats)`` where
    ``candidates`` may have gained ``unattributed-activity`` fallback items
    and every item carries its ``affected_sites``; ``affected`` maps an
    unresolved call-site address to the contributing candidate ids.
    """

    functions_by_start = {function.start: function for function in program.functions}
    resolver = _CallTargetResolver()
    items_by_function: dict[int, list[SourceCandidate]] = {}
    for item in candidates:
        items_by_function.setdefault(item.function_start, []).append(item)

    gaps: list[dict] = []
    fallback_items: dict[tuple[int, str], SourceCandidate] = {}
    relations: list[CallRelation] = []
    total_calls = 0
    for function in program.functions:
        if function.is_external_trampoline:
            continue
        local = stack.by_function.get(function.start)
        if local is None:
            continue
        items = items_by_function.get(function.start, [])
        origin_index = _MarkerOriginIndex(function, local)
        for instruction in function.insts:
            if not resolver.is_transfer(instruction, function, semantics):
                continue
            total_calls += 1
            targets = resolver.classify(instruction, functions_by_start, metadata)
            # Consume the same proved targets as production. Never infer a
            # closed boundary from a PLT spelling in this independent audit.
            closed = frozenset(stack.closed_external_calls.get(instruction.addr, ()))
            external_targets = targets.external_targets - closed
            local_ids = _site_contributors(
                function,
                local,
                instruction.addr,
                items,
                gaps,
                fallback_items,
                elf_sha256,
                origin_index,
            )
            if targets.unresolved or targets.empty_metadata:
                resolution = (
                    "empty-call-target-set"
                    if targets.empty_metadata
                    else "unresolved-indirect-call"
                )
            elif external_targets:
                resolution = ACTIVE_EXTERNAL_CALL
            else:
                resolution = "resolved"
            relations.append(
                CallRelation(
                    function_start=function.start,
                    call_site=instruction.addr,
                    resolution=resolution,
                    targets=tuple(sorted(targets.internal_targets)),
                    local_contributors=local_ids,
                    external_targets=tuple(sorted(external_targets)),
                )
            )

    # Informational store/return/selection warnings are not call relations.
    # Only actual active transfer boundaries contribute affected sites.

    if fallback_items:
        candidates = list(candidates) + [
            fallback_items[key] for key in sorted(fallback_items)
        ]

    # Finite-set fixpoint: entry_state[f] = candidate ids inherited at f's
    # entry.  A call site feeds its targets the union of the site's local
    # contributors and the caller's inherited set - the same activity rule as
    # the production propagator (local activity or an inherited caller makes
    # the call active).
    entry_state: dict[int, set[str]] = {}
    changed = True
    iterations = 0
    max_iterations = len(program.functions) + 2
    while changed:
        changed = False
        iterations += 1
        if iterations > max_iterations:
            gaps.append(
                {
                    "kind": GAP_PROPAGATION_ITERATION_CAP,
                    "detail": "固定点传播超过函数数+2 轮仍未收敛，按缺口停止",
                }
            )
            break
        for relation in relations:
            contributors = set(relation.local_contributors)
            contributors |= entry_state.get(relation.function_start, set())
            if not contributors:
                continue
            for target in relation.targets:
                slot = entry_state.setdefault(target, set())
                before = len(slot)
                slot |= contributors
                if len(slot) != before:
                    changed = True

    # Activity of a boundary site is decided *after* propagation: a site
    # with an empty local set that inherits a non-empty one is active.
    affected: dict[int, set[str]] = {}
    inactive_sites: set[int] = set()
    inactive_external: set[int] = set()
    active_external: set[int] = set()
    local_only_inactive: set[int] = set()
    for relation in relations:
        if relation.resolution == "resolved":
            continue
        contributors = set(relation.local_contributors)
        contributors |= entry_state.get(relation.function_start, set())
        if contributors:
            affected.setdefault(relation.call_site, set()).update(contributors)
            if relation.resolution == ACTIVE_EXTERNAL_CALL:
                active_external.add(relation.call_site)
        else:
            if relation.resolution == ACTIVE_EXTERNAL_CALL:
                inactive_external.add(relation.call_site)
                continue
            inactive_sites.add(relation.call_site)
            if not relation.local_contributors:
                local_only_inactive.add(relation.call_site)

    # Attach the per-item affected-site lists.
    sites_by_item: dict[str, set[int]] = {}
    for site, ids in affected.items():
        for ident in ids:
            sites_by_item.setdefault(ident, set()).add(site)
    candidates = [
        replace(item, affected_sites=tuple(sorted(sites_by_item.get(item.id, ()))))
        for item in candidates
    ]

    # Cross-check the recomputed closure against the analyzer's own.
    my_inherited = {start for start, ids in entry_state.items() if ids}
    analyzer_inherited = set(stack.inherited_functions)
    my_affected = set(affected)
    analyzer_affected = set(stack.unresolved_live_calls) | set(stack.active_external_calls)
    mismatches: list[str] = []
    if my_inherited != analyzer_inherited:
        mismatches.append("inherited-closure")
        gaps.append(
            {
                "kind": GAP_CLOSURE_MISMATCH,
                "detail": "独立传播的继承闭包与分析器不一致",
                "audit_only": sorted(my_inherited - analyzer_inherited),
                "analyzer_only": sorted(analyzer_inherited - my_inherited),
            }
        )
    if my_affected != analyzer_affected:
        mismatches.append("affected-sites")
        gaps.append(
            {
                "kind": GAP_AFFECTED_SITE_MISMATCH,
                "detail": "独立枚举的未解析／外部活跃边界与分析器不一致",
                "audit_only": sorted(my_affected - analyzer_affected),
                "analyzer_only": sorted(analyzer_affected - my_affected),
            }
        )

    stats = {
        "call_instructions": total_calls,
        "resolved_relations": sum(1 for r in relations if r.resolution == "resolved"),
        "unresolved_sites": sum(
            1 for r in relations if r.resolution == "unresolved-indirect-call"
        ),
        "empty_target_sites": sum(
            1 for r in relations if r.resolution == "empty-call-target-set"
        ),
        "affected_sites": len(affected),
        "active_unresolved_sites": sum(
            r.call_site in affected and r.resolution in {
                "unresolved-indirect-call", "empty-call-target-set"} for r in relations),
        "scalar_width_escape_sites": sum(r.scalar_width_escape for r in relations),
        "active_width_escape_sites": sum(r.scalar_width_escape and r.call_site in affected
                                         for r in relations),
        "external_sites": sum(r.resolution == ACTIVE_EXTERNAL_CALL for r in relations),
        "active_external_sites": len(active_external),
        "inactive_external_sites": len(inactive_external),
        "inactive_unresolved_sites": len(inactive_sites),
        "inactive_unresolved_sites_local_only": len(local_only_inactive),
        "candidate_items": len(candidates),
        "fixpoint_iterations": iterations,
        "fixpoint_converged": not changed,
        "inherited_functions": len(my_inherited),
        "cross_check": {
            "inherited_matches_analyzer": "inherited-closure" not in mismatches,
            "affected_matches_analyzer": "affected-sites" not in mismatches,
            "mismatches": mismatches,
        },
    }
    return (
        candidates,
        relations,
        {site: tuple(sorted(ids)) for site, ids in affected.items()},
        gaps,
        stats,
    )


# endregion


# region Gate-list loading and plugin name matching


def load_gate_names(text: str) -> tuple[list[str], dict[str, int]]:
    """The VectorGate plugin's ``loadNames`` semantics, ported verbatim.

    One mangled name per line; trailing ``\\r`` and spaces are stripped, empty
    lines dropped, and the set container dedupes.  The stats keep the raw
    counts so a bloated or duplicated list is visible instead of silently
    canonicalised away.
    """

    raw_lines = text.splitlines()
    names: set[str] = set()
    nonempty = 0
    for line in raw_lines:
        stripped = line.rstrip("\r ")
        if not stripped:
            continue
        nonempty += 1
        names.add(stripped)
    return sorted(names), {
        "raw_lines": len(raw_lines),
        "nonempty_lines": nonempty,
        "unique_names": len(names),
        "duplicates_dropped": nonempty - len(names),
    }


def load_gate_list_file(path: Path) -> tuple[list[str], dict[str, object]]:
    """Load the decision actually consumed by the gate build.

    Accepts either the derived ``*.gate_names.txt`` (one mangled name per
    line, exactly what the plugin reads) or the decision JSON it was derived
    from (``decision.gate.names``).  The original decision file - not the
    recommendation list of a newer check report - is what the audit compares
    against.
    """

    text = Path(path).read_text(encoding="utf-8")
    sha256 = hashlib.sha256(text.encode("utf-8")).hexdigest()
    stripped = text.lstrip()
    if stripped.startswith("{"):
        document = json.loads(text)
        gate = (document.get("decision") or {}).get("gate") or {}
        names = gate.get("names") or []
        unique, stats = load_gate_names("\n".join(str(name) for name in names))
        stats["source_kind"] = "decision-json"
        return unique, {**stats, "sha256": sha256, "path": str(path)}
    unique, stats = load_gate_names(text)
    stats["source_kind"] = "gate-names-text"
    return unique, {**stats, "sha256": sha256, "path": str(path)}


def expand_special_member_variants(names) -> set[str]:
    """Port of ``expandSpecialMemberVariants`` in VectorGatePlugin.cpp.

    Every C1/C2 and D1/D2 occurrence in a mangled name is swapped (all
    occurrences, one variant per swap direction); the originals stay in the
    set.  This is the *only* name normalisation the plugin performs.
    """

    swaps = (("C1", "C2"), ("C2", "C1"), ("D1", "D2"), ("D2", "D1"))
    expanded = set(names)
    for name in names:
        for from_tag, to_tag in swaps:
            variant = name
            pos = variant.find(from_tag)
            if pos == -1:
                continue
            while pos != -1:
                variant = variant[:pos] + to_tag + variant[pos + len(from_tag):]
                pos = variant.find(from_tag, pos + len(to_tag))
            expanded.add(variant)
    return expanded


def canonical_census_name(name: str) -> str:
    """The census-side normalisation (C1→C2, D1→D2), per vector_census_report."""

    return name.replace("C1", "C2").replace("D1", "D2")


def _evidence_key(path) -> str:
    """The identity a census file is matched under the evidence manifest.

    Resolved, not literal: the CLI and the manifest routinely spell the same
    file differently (``./census.tsv`` against an absolute path), and a
    spelling difference would otherwise be reported as "no evidence at all" -
    a false negative that could hide real evidence.  Every *other* link in the
    chain (content hash, stage, decision hash, compile unit, toolchain) still
    has to hold, so this loosens only the naming, never the verification.
    """

    return str(Path(path).resolve())


def load_census(paths, bound_paths) -> tuple[dict, list[dict]]:
    """Parse ``implicit-vector-census`` TSV files into per-name actions.

    Returns ``{canonical_name: {mechanism: {action: {census paths}}}}`` plus
    gap entries for everything the parser refused to accept.  The record keeps
    the *file* that carried it, so a later stage can ask whether that file is
    bound to a build identity at all.

    A malformed evidence file is itself a finding: it never crashes the audit,
    never counts as evidence, and never merges two conflicting actions into
    one set - a function recorded ``formed`` *and* ``blocked`` for the same
    mechanism keeps both actions and raises an explicit conflict gap.
    """

    census: dict[str, dict[str, dict[str, set[str]]]] = {}
    gaps: list[dict] = []
    for path in paths or ():
        key = _evidence_key(path)
        try:
            text = Path(path).read_text(encoding="utf-8")
        except OSError as exc:
            gaps.append(
                {"kind": GAP_CENSUS_UNREADABLE, "detail": f"{path}: {exc}"}
            )
            continue
        usable = 0
        for line_number, raw in enumerate(text.splitlines(), 1):
            if not raw.strip():
                continue
            fields = raw.split("\t")
            if (
                len(fields) != 4
                or fields[0] != CENSUS_TAG
                or fields[3] not in CENSUS_ACTIONS
            ):
                gaps.append(
                    {
                        "kind": GAP_CENSUS_MALFORMED_LINE,
                        "detail": f"{path}:{line_number}: {raw!r}",
                    }
                )
                continue
            _, mechanism, name, action = fields
            canonical = canonical_census_name(name.strip())
            if not canonical:
                gaps.append(
                    {
                        "kind": GAP_CENSUS_MALFORMED_LINE,
                        "detail": f"{path}:{line_number}: empty function name",
                    }
                )
                continue
            if not mechanism:
                gaps.append(
                    {
                        "kind": GAP_CENSUS_MALFORMED_LINE,
                        "detail": f"{path}:{line_number}: empty mechanism",
                    }
                )
                continue
            if mechanism not in CENSUS_MECHANISMS:
                # Kept, not dropped: an unknown mechanism is a finding, and a
                # dropped record could turn "evidence exists" into "no
                # evidence at all" without saying so.
                gaps.append(
                    {
                        "kind": GAP_CENSUS_UNKNOWN_MECHANISM,
                        "detail": f"{path}:{line_number}: 未知机制 {mechanism!r}（已保留）",
                    }
                )
            by_action = census.setdefault(canonical, {}).setdefault(mechanism, {})
            by_action.setdefault(action, set()).add(key)
            if len(by_action) > 1:
                gaps.append(
                    {
                        "kind": GAP_CENSUS_ACTION_CONFLICT,
                        "detail": (
                            f"{path}:{line_number}: {canonical} 在 {mechanism} "
                            "同时出现 formed/blocked；冲突未被集合合并掩盖"
                        ),
                    }
                )
            usable += 1
        if not usable:
            gaps.append(
                {
                    "kind": GAP_CENSUS_WITHOUT_USABLE_LINES,
                    "detail": f"{path}: 未解析到任何可用的 census 记录",
                }
            )
    del bound_paths  # binding is applied in reconcile_gate_list, not while parsing
    return census, gaps


# endregion


# region Evidence manifest (build identity binding)


@dataclass(frozen=True)
class CensusEvidence:
    """One census file plus the build identity it claims to belong to.

    A census record is only *bound* when every link in this chain holds, and
    each link is checked against something outside the record itself:

    * the manifest names the file and its **content hash** matches the bytes on
      disk (checked, not declared);
    * the manifest belongs to the build **stage** being audited;
    * the manifest's ``decision`` is the decision the audited build **actually
      consumed**, and its hash matches that file.  The *comparison list* is a
      different document and is never substituted here: build-stack consumed a
      stack-only decision, so an honest census record for it can never match
      the gate-2 comparison list;
    * it names the **artifact** (linked product) whose hash equals the audited
      ELF - without this, a record from another build of the same stage and
      decision would attach itself to the wrong product;
    * the **compile unit** exists in ``compile_units`` and carries a compile
      command (a name string that matches nothing is not a unit);
    * the **toolchain identity** is a sha256 digest and is the same one the
      compile unit used.

    Only then is a ``formed`` line evidence that the code was generated anyway,
    or a ``blocked`` line evidence that the gate fired.  Binding closes the
    *accidental* misuse hole; it cannot make a dishonest manifest honest -
    which is why every link is spelled out per file in the report instead of
    collapsed into one boolean.
    """

    path: str
    sha256: str | None = None
    stage: str | None = None
    compile_unit: str | None = None
    unit_declared: bool = False
    compile_command: str | None = None
    unit_census: str | None = None
    toolchain: str | None = None
    #: The hash the manifest declares for the decision the audited build
    #: *consumed* - not for the comparison list.
    consumed_decision_sha256: str | None = None
    artifact_path: str | None = None
    artifact_sha256: str | None = None
    bound: bool = False
    notes: tuple[str, ...] = ()


#: A declared toolchain identity has to be a sha256 digest: a free-text label
#: such as ``"placeholder"`` is indistinguishable from a real one by inspection
#: and would let any record claim any compiler.
_TOOLCHAIN_DIGEST_RE = re.compile(r"\A[0-9a-f]{64}\Z")


def load_evidence_manifest(path) -> dict[str, CensusEvidence]:
    """Read an evidence manifest into ``{declared census path: record}``.

    The manifest is an operator-produced artifact; the audit verifies it
    rather than trusting it.  Whatever the manifest does *not* resolve is left
    empty here so :func:`_bind_evidence` can report the exact missing link.  A
    missing or malformed manifest is an input error (the caller asked for
    evidence that cannot be read), so it raises instead of degrading silently.
    """

    text = Path(path).read_text(encoding="utf-8")
    document = json.loads(text)
    if document.get("format") != EVIDENCE_FORMAT:
        raise ValueError(
            f"证据清单格式不是 {EVIDENCE_FORMAT}：{path}"
        )
    stage = document.get("stage")
    decision = document.get("decision") or {}
    manifest_artifact = document.get("artifact") or {}
    units = {
        str(unit.get("name")): unit
        for unit in (document.get("compile_units") or [])
        if unit.get("name")
    }
    evidence: dict[str, CensusEvidence] = {}
    for record in document.get("census") or []:
        declared = record.get("path")
        if not declared:
            continue
        unit_name = record.get("compile_unit")
        unit = units.get(unit_name)
        artifact = record.get("artifact") or manifest_artifact
        evidence[_evidence_key(declared)] = CensusEvidence(
            path=str(declared),
            sha256=record.get("sha256"),
            stage=stage,
            compile_unit=unit_name,
            unit_declared=unit is not None,
            compile_command=(unit or {}).get("compile_command"),
            unit_census=(unit or {}).get("census"),
            toolchain=record.get("toolchain") or (unit or {}).get("toolchain"),
            consumed_decision_sha256=decision.get("sha256"),
            artifact_path=artifact.get("path"),
            artifact_sha256=artifact.get("sha256"),
        )
    return evidence


def _bind_evidence(
    census_paths,
    evidence: dict[str, CensusEvidence],
    *,
    stage: str,
    consumed_decision_sha256: str | None,
    artifact_sha256: str | None,
    gaps: list[dict],
) -> frozenset[str]:
    """Decide which census files are bound, and record why the others are not.

    Returns the set of *bound* census path keys.  Every rejected file gets an
    explicit reason and a gap; nothing is silently promoted to evidence.  A
    record that merely *exists* under the right stage is not enough - it has to
    belong to this product, this compile unit and this toolchain, and its
    decision has to be the one this build **consumed**.

    ``consumed_decision_sha256`` is deliberately a separate input from the
    comparison list the names were matched against.  Substituting the
    comparison list here would (a) accept a census record captured under a
    different decision that happens to share the stage name, and (b) reject a
    truthful baseline record, because build-stack consumed a stack-only
    decision that could never equal the gate-2 comparison list.  When no
    consumed decision is declared, nothing binds - the comparison list is not
    an acceptable stand-in, and the gap says so.
    """

    bound: set[str] = set()
    if consumed_decision_sha256 is None and (census_paths or ()):
        gaps.append(
            {
                "kind": GAP_CONSUMED_DECISION_MISSING,
                "detail": (
                    "未声明被审构建实际消费的决策（--consumed-decision）："
                    "本次不做证据绑定，也不用对照名单替代；"
                    f"{len(list(census_paths))} 个 census 文件全部降级为未验证旁证"
                ),
            }
        )
    for path in census_paths or ():
        key = _evidence_key(path)
        record = evidence.get(key)
        if record is None:
            gaps.append(
                {
                    "kind": GAP_CENSUS_UNBOUND,
                    "detail": f"{key}: 未出现在证据清单中，仅作未验证旁证",
                }
            )
            continue
        reasons: list[str] = []
        actual = None
        try:
            actual = _sha256(Path(path))
        except OSError as exc:
            reasons.append(f"无法读取 census 文件内容：{exc}")
        if record.sha256 is None:
            reasons.append("证据清单未声明 census 内容哈希")
        elif actual is not None and record.sha256 != actual:
            reasons.append(f"内容哈希不符（清单 {record.sha256} / 实际 {actual}）")
        if stage and stage != STAGE_UNKNOWN:
            if record.stage != stage:
                reasons.append(f"构建阶段不符（清单 {record.stage!r} / 本次 {stage!r}）")
        else:
            reasons.append("本次未声明被审构建阶段")
        # Decision identity: the build's own decision, never the comparison list.
        if consumed_decision_sha256 is None:
            reasons.append(
                "未声明被审构建实际消费的决策；不用对照名单替代，保持未绑定"
            )
        elif record.consumed_decision_sha256 is None:
            reasons.append("证据清单未声明其决策哈希，无法确认属于本次被审构建")
        elif record.consumed_decision_sha256 != consumed_decision_sha256:
            reasons.append(
                "决策哈希与实际消费的决策不符"
                f"（清单 {record.consumed_decision_sha256[:12]}… / "
                f"实际 {consumed_decision_sha256[:12]}…）"
            )
        # Product identity: without it a same-stage, same-decision record from
        # another build of the project would attach to this artifact.
        if record.artifact_sha256 is None:
            reasons.append("证据清单未声明 census 所属产物哈希")
        elif artifact_sha256 is None:
            reasons.append("本次未提供被审产物哈希")
        elif record.artifact_sha256 != artifact_sha256:
            reasons.append(
                f"产物哈希与本次被审 ELF 不符（清单 {record.artifact_sha256}）"
            )
        # Compile unit identity: the name has to be a declared unit with a real
        # command, not an arbitrary string.
        if not record.compile_unit:
            reasons.append("未绑定编译单元")
        elif not record.unit_declared:
            reasons.append(f"编译单元 {record.compile_unit!r} 不在清单的 compile_units 中")
        if not record.compile_command:
            reasons.append("编译单元缺少编译命令")
        if record.unit_census is not None and record.unit_census != key:
            if _evidence_key(record.unit_census) != key:
                reasons.append("编译单元声明的 census 与本次输入不是同一文件")
        # Toolchain identity: a digest, not a label.
        if not record.toolchain:
            reasons.append("未绑定工具链身份")
        elif not _TOOLCHAIN_DIGEST_RE.match(record.toolchain):
            reasons.append(f"工具链身份不是 sha256 摘要：{record.toolchain!r}")
        if reasons:
            gaps.append(
                {
                    "kind": GAP_CENSUS_UNBOUND,
                    "detail": f"{key}: " + "；".join(reasons),
                }
            )
            continue
        bound.add(key)
    return frozenset(bound)


def _evidence_payload(
    census_paths,
    evidence: dict[str, CensusEvidence],
    bound_paths: frozenset[str],
    *,
    consumed_decision_sha256: str | None = None,
) -> list[dict]:
    rows: list[dict] = []
    for path in census_paths or ():
        key = _evidence_key(path)
        record = evidence.get(key)
        declared = None if record is None else record.consumed_decision_sha256
        rows.append(
            {
                "path": key,
                "bound": key in bound_paths,
                "stage": None if record is None else record.stage,
                "compile_unit": None if record is None else record.compile_unit,
                "compile_unit_declared": (
                    False if record is None else record.unit_declared
                ),
                "compile_command": None if record is None else record.compile_command,
                "toolchain": None if record is None else record.toolchain,
                "declared_sha256": None if record is None else record.sha256,
                "declared_consumed_decision_sha256": declared,
                "consumed_decision_sha256": consumed_decision_sha256,
                "consumed_decision_matches": (
                    None
                    if declared is None or consumed_decision_sha256 is None
                    else declared == consumed_decision_sha256
                ),
                "artifact_path": None if record is None else record.artifact_path,
                "artifact_sha256": None if record is None else record.artifact_sha256,
                "notes": (
                    ["未出现在证据清单中，仅作未验证旁证"]
                    if record is None
                    else list(record.notes)
                ),
            }
        )
    return rows


# endregion


# region Reconciliation


def _vector_instruction_count(function) -> int:
    """Vector instructions of one function (same heuristic as the check)."""

    return sum(
        1
        for instruction in function.insts
        if instruction.op.startswith("v") and instruction.op not in VSET_OPS
    )


#: The compiler's clone suffixes.  A trailing index may or may not be present
#: (``.cold`` has none, ``.isra.3`` has one), and the suffixes nest, so
#: ``_clone_stem`` peels them in a loop rather than once.
_CLONE_SUFFIX_RE = re.compile(
    r"\.(?:isra|constprop|cold|part|clone|lto_priv|llvm)(?:\.\d+)?$"
)


def _clone_stem(name: str) -> str | None:
    """The base name a compiler clone suffix hangs off, if any.

    GCC/Clang clones (``.isra.N``, ``.constprop.N``, ``.cold``, ``.part.N``,
    ``.llvm.*`` …) are *separate symbols*: the plugin's exact string match
    never lets a list entry for the base name cover them.  Suffixes nest
    (``foo.part.5.constprop.0``), so every one of them is peeled, not just the
    last - stopping one layer short would report a clone as covered by a stem
    that is itself still a clone.
    """

    stem = name
    while True:
        stripped = _CLONE_SUFFIX_RE.sub("", stem)
        if stripped == stem:
            break
        stem = stripped
    return stem if stem != name else None


def reconcile_gate_list(
    program,
    candidates: list[SourceCandidate],
    names: list[str],
    census: dict,
    bound_paths: frozenset[str],
    stage: str = STAGE_UNKNOWN,
) -> tuple[list[SourceCandidate], list[dict], dict[str, int]]:
    """Match candidates and list entries under the plugin's actual rules.

    Matching is the plugin's exact-name rule on the C1/C2/D1/D2-expanded list;
    same-name functions, clones and inlining ambiguity are kept explicit.  A
    listed name that matches nothing is ``no-symbol`` - never a success - and
    aggregate evidence ("N function(s)") is annotated as list-passed-only.

    Compile evidence is graded, never averaged: a ``formed``/``blocked`` record
    is only reported as evidence when its census file is *bound* to this build
    (see :func:`_bind_evidence`); an unbound record produces
    ``unbound-evidence`` instead of a bypass or an effectiveness claim.

    ``stage`` decides which conclusion a bound ``formed`` record supports.  In
    a stage that does not enable the gate (``build-stack``) the code was always
    going to be generated, so that is ``formed-before-gate`` - baseline
    generation - and calling it a bypass would invent a failure.
    """

    raw = set(names)
    expanded = expand_special_member_variants(raw)
    functions_by_name: dict[str, list] = {}
    for function in program.functions:
        functions_by_name.setdefault(function.name, []).append(function)
    vector_counts = {
        function.start: _vector_instruction_count(function)
        for function in program.functions
    }

    # Per-candidate list status, with same-name and clone ambiguity kept.
    reconciled: list[SourceCandidate] = []
    for item in candidates:
        if item.function in raw:
            status = "exact"
        elif item.function in expanded:
            status = "variant"
        else:
            status = "none"
        same_name = sorted(
            other.start
            for other in functions_by_name.get(item.function, [])
            if other.start != item.function_start
        )
        notes = list(item.notes)
        stem = _clone_stem(item.function)
        if status == "none" and stem is not None and stem in expanded:
            notes.append(
                f"克隆符号 {item.function} 不被名单条目 {stem} 覆盖"
                "（插件为精确字符串匹配）"
            )
        if same_name:
            notes.append(
                "同名函数存在于其他地址：" + ", ".join(hex(s) for s in same_name)
            )
        matched_entries = (
            sorted(
                entry
                for entry in raw
                if item.function in expand_special_member_variants({entry})
            )
            if status != "none"
            else []
        )
        evidence = {
            **item.evidence,
            "list_status": status,
            "matched_entries": matched_entries,
            "same_name_functions": same_name,
        }
        reconciled.append(replace(item, evidence=evidence, notes=tuple(notes)))

    # Per-entry independent status.
    entries: list[dict] = []
    for entry in names:
        variants = expand_special_member_variants({entry})
        matched = sorted(
            (f for f in program.functions if f.name in variants),
            key=lambda f: f.start,
        )
        exact = [f for f in matched if f.name == entry]
        match_kind = "exact" if exact else ("variant" if matched else "none")
        ambiguous = len(matched) > 1
        canonicals = {canonical_census_name(entry)} | {
            canonical_census_name(f.name) for f in matched
        }
        blocked_bound: set[str] = set()
        blocked_unbound: set[str] = set()
        formed_bound: set[str] = set()
        formed_unbound: set[str] = set()
        conflicts: set[str] = set()
        conflicted_mechanisms: set[str] = set()
        unrecognised_mechanisms: set[str] = set()
        for canonical in sorted(canonicals):
            actions = census.get(canonical) or {}
            for mechanism, by_action in sorted(actions.items()):
                if mechanism not in CENSUS_MECHANISMS:
                    # Kept in the census (a dropped record would turn "evidence
                    # exists" into "no evidence at all"), but a mechanism the
                    # audit cannot interpret must never become a verdict.
                    unrecognised_mechanisms.add(mechanism)
                    continue
                if len(by_action) > 1:
                    # The two actions contradict each other for one function and
                    # one mechanism.  Both survive as records, and neither side
                    # is allowed to count as certainty evidence.
                    conflicts.add(f"{mechanism}@{canonical}")
                    conflicted_mechanisms.add(mechanism)
                    continue
                for action, paths in sorted(by_action.items()):
                    is_bound = bool(paths & bound_paths)
                    if action == "formed":
                        (formed_bound if is_bound else formed_unbound).add(mechanism)
                    elif action == "blocked":
                        (blocked_bound if is_bound else blocked_unbound).add(mechanism)
        untrustworthy = bool(conflicted_mechanisms or unrecognised_mechanisms)
        matched_starts = {f.start for f in matched}
        remaining_active = [
            item
            for item in reconciled
            if item.function_start in matched_starts
            and not item.excluded_by_assumption
        ]
        remaining_excluded = [
            item
            for item in reconciled
            if item.function_start in matched_starts and item.excluded_by_assumption
        ]
        vector_total = sum(vector_counts[f.start] for f in matched)
        clone_names = sorted(
            name
            for name in functions_by_name
            if name not in variants
            and _clone_stem(name) is not None
            and (name.startswith(entry + ".") or _clone_stem(name) == entry)
        )

        notes: list[str] = []
        if not matched:
            status = ENTRY_NO_SYMBOL
            if blocked_bound or blocked_unbound:
                notes.append(
                    "census 存在 blocked 记录但符号未进最终 ELF"
                    "（可能被内联/克隆/消除）；仍需 TU/IR 记录确认"
                )
            else:
                notes.append(
                    "符号在 ELF 中不存在且无任何编译期证据；找不到符号不算成功"
                )
        elif formed_bound:
            # A bound formed record means the code was generated in a build
            # whose list named this function.  Whether that is a *failure*
            # depends on the stage: only a stage that enables the gate can be
            # bypassed.  build-stack enables the stack-object plugin only, so
            # its formed records are the baseline's normal output.
            if stage == STAGE_BUILD_STACK:
                status = ENTRY_FORMED_BEFORE_GATE
                notes.append(
                    "已绑定 census 出现 formed 记录：该阶段未启用 gate（仅启用 stack-object），"
                    "此处生成为基线应有的结果，不构成 gate 绕过"
                )
            else:
                status = ENTRY_GATE_BYPASSED
                notes.append(
                    "已绑定 census 出现 formed 记录：函数在名单内却仍生成了隐式向量代码"
                )
        elif remaining_active:
            status = ENTRY_SOURCE_REMAINS
            notes.append("名单内函数在最终 ELF 仍携带候选源头")
        elif vector_total:
            status = ENTRY_VECTOR_REMAINS
            notes.append("源头已消失但最终 ELF 仍含向量指令（显式或来源不明）")
        elif blocked_bound and not untrustworthy:
            status = ENTRY_BLOCKED_EVIDENCE
            notes.append("有已绑定 blocked 证据且无残留：与 gate 生效一致")
        elif formed_unbound or blocked_unbound or untrustworthy:
            status = ENTRY_UNBOUND_EVIDENCE
            notes.append(
                "存在 census 记录但未绑定构建阶段/决策哈希/产物/编译单元/工具链，"
                "或记录本身冲突/机制未识别；既不能判 gate 绕过，也不能证明 gate 生效"
            )
        else:
            status = ENTRY_MISSING_COMPILE_EVIDENCE
            notes.append("缺少编译期证据：无法确认该函数在编译期被命中")
        if formed_unbound:
            notes.append(
                "存在未绑定的 formed 记录（" + ", ".join(sorted(formed_unbound)) + "），"
                "不得据此判定 gate 绕过"
            )
        if blocked_unbound:
            notes.append(
                "存在未绑定的 blocked 记录（" + ", ".join(sorted(blocked_unbound)) + "），"
                "不得据此证明 gate 生效"
            )
        if blocked_bound and status != ENTRY_BLOCKED_EVIDENCE:
            notes.append(
                "同时有已绑定 blocked 证据（" + ", ".join(sorted(blocked_bound)) + "）"
            )
        if conflicts:
            notes.append(
                "census 冲突记录（同一函数同机制 formed+blocked，两者都不计为确定性证据）："
                + ", ".join(sorted(conflicts))
            )
        if unrecognised_mechanisms:
            notes.append(
                "census 机制名未识别（记录保留但不计为证据）："
                + ", ".join(sorted(unrecognised_mechanisms))
            )
        if ambiguous:
            notes.append(
                "同名/变体匹配到多个函数定义，编译期记录尚未区分这些定义；"
                "歧义本身阻止该条目退出待核验清单"
            )
        if clone_names:
            notes.append("存在名单未覆盖的相关克隆符号：" + ", ".join(clone_names))
        # Evidence quality, kept apart from the source verdict so neither can
        # be read as the other.  A conflict or an uninterpretable mechanism
        # outranks the certainty verdicts: those records cannot be trusted, so
        # they must not be averaged away.
        if conflicted_mechanisms:
            evidence_status = EVIDENCE_CONFLICT
        elif unrecognised_mechanisms:
            evidence_status = EVIDENCE_UNRECOGNISED
        elif formed_bound:
            evidence_status = EVIDENCE_BOUND_FORMED
        elif formed_unbound or blocked_unbound:
            evidence_status = EVIDENCE_UNBOUND
        elif blocked_bound:
            evidence_status = EVIDENCE_BOUND_BLOCKED
        else:
            evidence_status = EVIDENCE_NONE
        # Two independent reasons keep an entry on the verification list: the
        # source/evidence verdict, and unresolved same-name ambiguity.  The
        # second one is a *separate* axis on purpose - a bound blocked record
        # for a name that matches two definitions has not verified either of
        # them, however clean the record looks.
        pending = status in PENDING_ENTRY_STATUSES or ambiguous
        entries.append(
            {
                "name": entry,
                "match": match_kind,
                "matched_functions": [
                    {"name": f.name, "function_start": f.start} for f in matched
                ],
                "ambiguous": ambiguous,
                "pending": pending,
                "evidence_status": evidence_status,
                "census_blocked": sorted(blocked_bound | blocked_unbound),
                "census_blocked_bound": sorted(blocked_bound),
                "census_blocked_unbound": sorted(blocked_unbound),
                "census_formed": sorted(formed_bound | formed_unbound),
                "census_formed_bound": sorted(formed_bound),
                "census_formed_unbound": sorted(formed_unbound),
                "census_conflicts": sorted(conflicts),
                "census_conflicted_mechanisms": sorted(conflicted_mechanisms),
                "census_unrecognised_mechanisms": sorted(unrecognised_mechanisms),
                "remaining_active_sources": [item.id for item in remaining_active],
                "remaining_excluded_sources": [
                    item.id for item in remaining_excluded
                ],
                "vector_instructions": vector_total,
                "unmatched_clones": clone_names,
                "status": status,
                "notes": notes,
            }
        )

    summary = {
        "entries_total": len(entries),
        "expanded_match_names": len(expanded),
        "symbols_matched": sum(1 for e in entries if e["match"] != "none"),
        "ambiguous_entries": sum(1 for e in entries if e["ambiguous"]),
        "entries_pending": sum(1 for e in entries if e["pending"]),
        "entries_pending_only_by_ambiguity": sum(
            1
            for e in entries
            if e["pending"] and e["status"] not in PENDING_ENTRY_STATUSES
        ),
        "entries_with_bound_blocked": sum(
            1 for e in entries if e["census_blocked_bound"]
        ),
        "entries_with_unbound_blocked": sum(
            1 for e in entries if e["census_blocked_unbound"]
        ),
        "entries_with_bound_formed": sum(1 for e in entries if e["census_formed_bound"]),
        "entries_with_unbound_formed": sum(
            1 for e in entries if e["census_formed_unbound"]
        ),
        "entries_with_census_conflict": sum(
            1 for e in entries if e["census_conflicted_mechanisms"]
        ),
        "entries_with_unrecognised_mechanism": sum(
            1 for e in entries if e["census_unrecognised_mechanisms"]
        ),
        "evidence_status_counts": {
            status: sum(1 for e in entries if e["evidence_status"] == status)
            for status in (
                EVIDENCE_BOUND_BLOCKED,
                EVIDENCE_BOUND_FORMED,
                EVIDENCE_UNBOUND,
                EVIDENCE_CONFLICT,
                EVIDENCE_UNRECOGNISED,
                EVIDENCE_NONE,
            )
        },
        "status_counts": {
            status: sum(1 for e in entries if e["status"] == status)
            for status in (
                ENTRY_GATE_BYPASSED,
                ENTRY_FORMED_BEFORE_GATE,
                ENTRY_SOURCE_REMAINS,
                ENTRY_VECTOR_REMAINS,
                ENTRY_BLOCKED_EVIDENCE,
                ENTRY_UNBOUND_EVIDENCE,
                ENTRY_MISSING_COMPILE_EVIDENCE,
                ENTRY_NO_SYMBOL,
            )
        },
    }
    return reconciled, entries, summary


# endregion


# region Audit assembly


def _hex_list(values) -> list[str]:
    return [hex(value) for value in values]


def _candidate_payload(item: SourceCandidate) -> dict[str, object]:
    addresses: dict[str, object] = {}
    for key, value in item.addresses.items():
        if value is None or isinstance(value, int):
            addresses[key] = None if value is None else hex(value)
        else:
            addresses[key] = [
                hex(v) if isinstance(v, int) else _hex_list(v) for v in value
            ]
    return {
        "id": item.id,
        "elf_sha256": item.elf_sha256,
        "function": item.function,
        "function_start": hex(item.function_start),
        "kind": item.kind,
        "excluded_by_assumption": item.excluded_by_assumption,
        "addresses": addresses,
        "evidence": item.evidence,
        "objects": list(item.objects),
        "notes": list(item.notes),
        "affected_sites": _hex_list(item.affected_sites),
    }


def _gate_list_size_check(gate_list_info: dict, expected: int | None) -> dict:
    unique = gate_list_info.get("unique_names")
    return {
        "expected": expected,
        "unique_names": unique,
        "nonempty_lines": gate_list_info.get("nonempty_lines"),
        "duplicates_dropped": gate_list_info.get("duplicates_dropped"),
        "matches_expected": (
            None if expected is None or unique is None else unique == expected
        ),
        "note": (
            "原名单位数由原决策文件现场去重得到；聚合日志只证明名单被传入编译"
        ),
    }


def _next_evidence(entries: list[dict], gaps: list[dict]) -> list[str]:
    """The concrete follow-up evidence when logs cannot confirm per-function hits."""

    needed: list[str] = []
    if any(
        entry["status"]
        in (
            ENTRY_MISSING_COMPILE_EVIDENCE,
            ENTRY_NO_SYMBOL,
            ENTRY_UNBOUND_EVIDENCE,
        )
        for entry in entries
    ):
        needed += [
            "逐 TU 的插件命中记录（编译期 IR 函数名匹配结果）",
            "每个 TU 的 CHIMERA_GATE_STATS census TSV（formed/blocked 逐函数）",
            "带 -fpass-plugin 的实际编译命令行与 “applied decision” 日志行",
            "证据清单：census 文件绑定的构建阶段、实际消费决策哈希、编译单元与工具链身份",
            "必要时 -fdump-ipa-optimized 或 IR 清单，以确认内联/克隆后的函数身份",
        ]
    if any(gap["kind"] == GAP_CONSUMED_DECISION_MISSING for gap in gaps):
        needed.append(
            "被审构建实际消费的决策文件路径（--consumed-decision）；"
            "对照名单不能替代它，缺失时全部 census 记录保持未绑定"
        )
    if any(gap["kind"] == GAP_CENSUS_UNBOUND for gap in gaps):
        needed.append("每个 census 记录所属产物（被审 ELF）的哈希关联证明")
    if any(gap["kind"].startswith(UNATTRIBUTED_GAP_PREFIX) for gap in gaps):
        needed.append("未覆盖活跃对象的函数体反汇编（按缺口条目取证）")
    if any(gap["kind"] in AMBIGUOUS_GAP_KINDS for gap in gaps):
        needed.append("归属歧义调用点的 CFG 路径证据（逐条区分共享帧标记的来源）")
    if any(gap["kind"] in (GAP_CLOSURE_MISMATCH, GAP_AFFECTED_SITE_MISMATCH) for gap in gaps):
        needed.append("独立传播与分析器闭包差异的逐点复核（差异不得默认归因于环境）")
    return needed


def audit_program(
    program,
    stack: StackLivenessResult,
    metadata: ChimeraMetadata,
    *,
    elf_path: str,
    elf_sha256: str,
    min_vlen_bits: int,
    gate_names: list[str],
    gate_list_info: dict[str, object],
    census: dict,
    census_gaps: list[dict],
    bound_paths: frozenset[str] = frozenset(),
    census_paths=(),
    evidence: dict | None = None,
    stage: str = STAGE_UNKNOWN,
    expected_gate_count: int | None = EXPECTED_GATE2_LIST_SIZE,
    consumed_decision: dict | None = None,
    check_report: dict | None = None,
) -> dict[str, object]:
    """Assemble the audit document from one parsed, once-analyzed program."""

    semantics = RvvServices().stack_semantics
    candidates = enumerate_candidates(program, stack, elf_sha256=elf_sha256)
    candidates, relations, affected, gaps, stats = propagate_sources(
        program, stack, candidates, metadata, semantics, elf_sha256=elf_sha256
    )
    gaps = list(census_gaps) + gaps
    affected_relations = {
        relation.call_site: relation for relation in relations
        if relation.call_site in affected
    }
    del relations

    candidates, entries, list_summary = reconcile_gate_list(
        program, candidates, gate_names, census, bound_paths, stage
    )

    # Explicit or unattributable vector code: every function with vector
    # instructions, listed separately - the gate is never promised to
    # eliminate these.
    candidate_starts = {item.function_start for item in candidates}
    expanded = expand_special_member_variants(set(gate_names))
    vector_functions = [
        {
            "function": function.name,
            "function_start": hex(function.start),
            "vector_instructions": _vector_instruction_count(function),
            "has_candidate_source": function.start in candidate_starts,
            "in_gate_list": function.name in expanded,
        }
        for function in program.functions
        if _vector_instruction_count(function)
    ]

    check_reference = None
    if check_report is not None:
        reported_hash = (check_report.get("elf") or {}).get("content_sha256")
        recommended = (
            ((check_report.get("decision") or {}).get("gate") or {}).get("names")
            or []
        )
        summaries = [
            ((check.get("diagnostics") or {}).get("summary") or {})
            for check in (check_report.get("checks") or [])
            if check.get("id") == "safety.stack-liveness"
        ]
        check_reference = {
            "content_sha256_matches": reported_hash == elf_sha256,
            "reported_findings_total": (
                summaries[0].get("findings_total") if summaries else None
            ),
            "recommended_gate_names": len(recommended),
            "note": (
                "新版检查报告的推荐名单仅作交叉参照，不是本轮核对所对照的原决策名单"
            ),
        }
        if reported_hash != elf_sha256:
            gaps.append(
                {
                    "kind": GAP_CHECK_REPORT_HASH_MISMATCH,
                    "detail": "交叉参照的检查报告与被审 ELF 的内容哈希不一致",
                }
            )

    size_check = _gate_list_size_check(gate_list_info, expected_gate_count)
    if size_check["matches_expected"] is False:
        gaps.append(
            {
                "kind": GAP_GATE_LIST_SIZE_MISMATCH,
                "detail": (
                    f"原决策名单去重后 {size_check['unique_names']} 项，"
                    f"预期 {expected_gate_count} 项；名单或决策文件不一致"
                ),
            }
        )

    active = [item for item in candidates if not item.excluded_by_assumption]
    excluded = [item for item in candidates if item.excluded_by_assumption]
    missing = [
        item for item in active if item.evidence.get("list_status") == "none"
    ]
    pending = [entry for entry in entries if entry["pending"]]

    by_id = {item.id: item for item in candidates}
    answers = {
        "sources_missing_from_list": [
            {
                "id": item.id,
                "function": item.function,
                "function_start": hex(item.function_start),
                "kind": item.kind,
                "affected_sites": _hex_list(item.affected_sites),
            }
            for item in missing
        ],
        "listed_functions_pending_gate_verification": [
            {
                "name": entry["name"],
                "status": entry["status"],
                "evidence_status": entry["evidence_status"],
                "ambiguous": entry["ambiguous"],
                "pending_reason": (
                    "ambiguous-definitions"
                    if entry["status"] not in PENDING_ENTRY_STATUSES
                    else "source-or-evidence"
                ),
                "notes": entry["notes"],
            }
            for entry in pending
        ],
    }

    return {
        "format": AUDIT_FORMAT,
        "elf": {
            "path": elf_path,
            "sha256": elf_sha256,
            "functions": len(program.functions),
            "instructions": len(program.instructions),
        },
        "parameters": {
            "min_vlen_bits": min_vlen_bits,
            "stage": stage,
            "expected_gate_count": expected_gate_count,
            "consumed_decision": consumed_decision,
        },
        "assumptions": {
            "scope": "implicit-vectorization",
            "statements": list(ASSUMPTION_STATEMENTS),
            "excluded_kinds": sorted(ASSUMPTION_EXCLUDED_KINDS),
        },
        "evidence": {
            "census_files": _evidence_payload(
                census_paths,
                evidence or {},
                bound_paths,
                consumed_decision_sha256=(
                    None
                    if consumed_decision is None
                    else consumed_decision.get("sha256")
                ),
            ),
            "bound_census_files": sorted(bound_paths),
            "bound_census_count": len(bound_paths),
            "unbound_census_count": len(
                [
                    path
                    for path in (census_paths or ())
                    if _evidence_key(path) not in bound_paths
                ]
            ),
            "consumed_decision": consumed_decision,
            "comparison_list_sha256": gate_list_info.get("sha256"),
            "note": (
                "只有绑定到构建阶段、**被审构建实际消费的决策**、编译单元、"
                "产物哈希和工具链身份的 census 才计为证据；"
                "未绑定记录仅作未验证旁证。对照名单只用于名称覆盖核对，"
                "不参与证据绑定。"
            ),
        },
        "candidates": [_candidate_payload(item) for item in candidates],
        "candidate_summary": {
            "total": len(candidates),
            "active": len(active),
            "excluded_by_assumption": len(excluded),
            "by_kind": {
                kind: sum(1 for item in candidates if item.kind == kind)
                for kind in sorted({item.kind for item in candidates})
            },
        },
        "affected_sites": [
            {
                "call_site": hex(site),
                "resolution": affected_relations[site].resolution,
                "internal_targets": _hex_list(affected_relations[site].targets),
                "external_targets": _hex_list(affected_relations[site].external_targets),
                "scalar_width_escape": affected_relations[site].scalar_width_escape,
                "contributors": list(ids),
                "contributors_excluded": [
                    ident
                    for ident in ids
                    if by_id[ident].excluded_by_assumption
                ],
            }
            for site, ids in sorted(affected.items())
        ],
        "propagation": stats,
        "vector_code_functions": vector_functions,
        "gate_list": {
            **gate_list_info,
            **list_summary,
            "role": "comparison-target-list",
            "role_note": (
                "本名单是**对照名单**（gate2 的原决策），只用于名称覆盖核对，"
                "不参与证据绑定，也不一定是被审构建实际消费的决策："
                "build-stack 只启用 stack-object，build-gate2 才使用 gate 名单。"
                "两者对照同一份目标名单是为了让分组差分可比，不代表 baseline 消费了它；"
                "被审构建实际消费的决策见参数中的 consumed_decision。"
            ),
            "expected_count": size_check["expected"],
            "size_check": size_check,
            "aggregate_log_note": AGGREGATE_LOG_NOTE,
            "entries": entries,
        },
        "gaps": gaps,
        "answers": answers,
        "check_report_reference": check_reference,
        "next_evidence_needed": _next_evidence(entries, gaps),
    }


# endregion


# region Disassembly / analysis of one ELF


def _sha256(path: Path) -> str:
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def _stderr_prefix(path: Path | None, limit: int = STDERR_PREFIX_BYTES) -> str:
    """A *bounded* prefix of a captured stream.

    Reading the whole file and slicing afterwards would materialise an
    unbounded artifact on disk and in memory; a failing objdump is exactly the
    case that produces one, so the prefix is read, never sliced.
    """

    if path is None or not path.exists():
        return ""
    with path.open("rb") as stream:
        raw = stream.read(limit)
    return raw.decode("utf-8", errors="replace").strip()


def _consumed_decision_payload(path) -> dict | None:
    """Describe the decision the audited build *consumed*, or ``None``.

    This is an operator declaration: the audit cannot read a build's mind.  It
    is a distinct role from the comparison list - build-stack enables only the
    stack-object plugin and consumes a stack-only decision - so it is recorded
    verbatim and used *only* for evidence binding, never for name matching.
    An unreadable declaration is kept with a ``null`` hash instead of being
    silently dropped, because a declared-but-missing file is itself a finding.
    """

    if path is None:
        return None
    declared = Path(path)
    return {
        "path": str(declared),
        "sha256": _sha256(declared) if declared.is_file() else None,
        "role": "consumed-decision",
        "note": (
            "被审构建实际消费的决策（人工声明，仅用于证据绑定与记录）；"
            "名称覆盖核对另见 gate_list（对照名单），两者角色不同"
        ),
    }


def analyze_elf_once(
    elf_path: Path,
    *,
    objdump_cmd: str = "objdump",
    min_vlen_bits: int = 256,
    dump_text: str | None = None,
    metadata: ChimeraMetadata | None = None,
    elf_sha256: str | None = None,
):
    """Disassemble, parse and analyze one ELF exactly once.

    ``dump_text``/``metadata`` are test seams (same contract as the check
    pipeline): they replace the objdump invocation and the ELF metadata
    extraction with captured inputs.  Production callers leave both as None.

    ``elf_sha256`` may be supplied by a caller that already hashed the file -
    the evidence binding needs the artifact hash *before* the analysis runs, so
    passing it here keeps a large ELF from being read twice.

    Every temporary file created here is removed in a ``finally`` block, so an
    objdump failure, an interrupt or a parse error leaves nothing behind.
    """

    elf_path = Path(elf_path).resolve()
    if not elf_path.is_file():
        raise FileNotFoundError(f"input ELF does not exist: {elf_path}")
    if elf_sha256 is None:
        elf_sha256 = _sha256(elf_path)

    adapter = LinuxObjdump(objdump_cmd)
    dump_file: Path | None = None
    stderr_file: Path | None = None
    try:
        if dump_text is None:
            with tempfile.NamedTemporaryFile(
                "wb", suffix=".dump", delete=False
            ) as dump_handle:
                dump_file = Path(dump_handle.name)
                with tempfile.NamedTemporaryFile(
                    "wb", suffix=".stderr", delete=False
                ) as stderr_handle:
                    stderr_file = Path(stderr_handle.name)
                    completed = subprocess.run(
                        list(adapter.command(elf_path)),
                        stdout=dump_handle,
                        stderr=stderr_handle,
                        check=False,
                    )
            if completed.returncode != 0:
                raise RuntimeError(
                    f"disassembly failed ({objdump_cmd}): "
                    f"{_stderr_prefix(stderr_file)}"
                )
        else:
            with tempfile.NamedTemporaryFile(
                "w", suffix=".dump", encoding="utf-8", delete=False
            ) as dump_handle:
                dump_handle.write(dump_text)
                dump_file = Path(dump_handle.name)

        extension = RvvServices()
        architecture = RiscvServices(extension)
        parsed = parse_dump(
            dump_file,
            adapter.parse_format,
            is_external_trampoline=adapter.is_external_trampoline,
            retain_dump_lines=False,
        )
        program = architecture.build_cfg(parsed)

        configs = extension.vector_configs(program)
        if metadata is None:
            metadata = ChimeraMetadata.from_elf(elf_path)
        analyzer = StackLivenessAnalyzer(
            min_vlen_bits=min_vlen_bits,
            semantics=extension.stack_semantics,
        )
        stack = analyzer.analyze_program(
            program, metadata=metadata, config_results=configs
        )
    finally:
        if dump_file is not None:
            dump_file.unlink(missing_ok=True)
        if stderr_file is not None:
            stderr_file.unlink(missing_ok=True)

    return program, stack, metadata, elf_sha256


def audit_elf(
    elf_path,
    *,
    gate_names: list[str],
    gate_list_info: dict[str, object] | None = None,
    census_paths=(),
    evidence_path=None,
    stage: str = STAGE_UNKNOWN,
    expected_gate_count: int | None = EXPECTED_GATE2_LIST_SIZE,
    consumed_decision_path=None,
    check_report_path=None,
    objdump_cmd: str = "objdump",
    min_vlen_bits: int = 256,
    dump_text: str | None = None,
    metadata: ChimeraMetadata | None = None,
) -> dict[str, object]:
    """Full audit of one ELF against the comparison gate list.

    ``gate_names`` is the *comparison* list (the gate-2 target list); what the
    audited build itself consumed is a separate, declared fact
    (``consumed_decision_path``) recorded verbatim and never used for matching.
    The two are distinct for the baseline build, which only enables the
    stack-object plugin.
    """

    info = dict(gate_list_info or {})
    info.setdefault("entries_input", len(gate_names))
    # The artifact hash is needed *before* the analysis, because the evidence
    # binding refuses a census file that cannot be tied to this product.
    resolved_elf = Path(elf_path).resolve()
    if not resolved_elf.is_file():
        raise FileNotFoundError(f"input ELF does not exist: {resolved_elf}")
    elf_sha256 = _sha256(resolved_elf)
    census, census_gaps = load_census(census_paths, frozenset())
    evidence: dict[str, CensusEvidence] = {}
    if evidence_path is not None:
        evidence = load_evidence_manifest(evidence_path)
    # The *consumed* decision is resolved before binding, and it is the only
    # decision hash the binding ever sees.  ``info["sha256"]`` is the
    # comparison list - a different document - and must not stand in for it.
    consumed_decision = _consumed_decision_payload(consumed_decision_path)
    bound_paths = _bind_evidence(
        census_paths,
        evidence,
        stage=stage,
        consumed_decision_sha256=(
            None if consumed_decision is None else consumed_decision["sha256"]
        ),
        artifact_sha256=elf_sha256,
        gaps=census_gaps,
    )
    check_report = None
    if check_report_path is not None:
        check_report = json.loads(
            Path(check_report_path).read_text(encoding="utf-8")
        )
    program, stack, metadata, elf_sha256 = analyze_elf_once(
        resolved_elf,
        objdump_cmd=objdump_cmd,
        min_vlen_bits=min_vlen_bits,
        dump_text=dump_text,
        metadata=metadata,
        elf_sha256=elf_sha256,
    )
    return audit_program(
        program,
        stack,
        metadata,
        elf_path=str(resolved_elf),
        elf_sha256=elf_sha256,
        min_vlen_bits=min_vlen_bits,
        gate_names=gate_names,
        gate_list_info=info,
        census=census,
        census_gaps=census_gaps,
        bound_paths=bound_paths,
        census_paths=census_paths,
        evidence=evidence,
        stage=stage,
        expected_gate_count=expected_gate_count,
        consumed_decision=consumed_decision,
        check_report=check_report,
    )


# endregion


# region CSV and Chinese conclusion outputs


_CANDIDATE_COLUMNS = (
    "id",
    "elf_sha256",
    "function",
    "function_start",
    "kind",
    "excluded_by_assumption",
    "allocation",
    "release",
    "dependency",
    "proof_status",
    "tracked_via",
    "access_addresses",
    "affected_sites",
    "list_status",
    "matched_entries",
    "notes",
)

_ENTRY_COLUMNS = (
    "name",
    "match",
    "matched_functions",
    "ambiguous",
    "pending",
    "status",
    "evidence_status",
    "census_blocked",
    "census_blocked_bound",
    "census_blocked_unbound",
    "census_formed",
    "census_formed_bound",
    "census_formed_unbound",
    "census_conflicts",
    "census_unrecognised_mechanisms",
    "remaining_active_sources",
    "remaining_excluded_sources",
    "vector_instructions",
    "unmatched_clones",
    "notes",
)


def _cell(value) -> str:
    if value is None:
        return ""
    if isinstance(value, (list, tuple)):
        return ";".join(str(item) for item in value)
    return str(value)


def write_candidates_csv(document: dict, path) -> None:
    """One row per candidate source - filterable by kind/excluded/list_status."""

    with Path(path).open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(_CANDIDATE_COLUMNS)
        for item in document["candidates"]:
            addresses = item["addresses"]
            access_addresses = (
                addresses.get("stores", [])
                + addresses.get("loads", [])
                + addresses.get("scopes", [])
            )
            evidence = item["evidence"]
            writer.writerow(
                [
                    item["id"],
                    item["elf_sha256"],
                    item["function"],
                    item["function_start"],
                    item["kind"],
                    item["excluded_by_assumption"],
                    _cell(addresses.get("allocation")),
                    _cell(addresses.get("release")),
                    _cell(evidence.get("dependency")),
                    _cell(evidence.get("proof_status")),
                    _cell(evidence.get("tracked_via")),
                    _cell(access_addresses),
                    _cell(item["affected_sites"]),
                    _cell(evidence.get("list_status")),
                    _cell(evidence.get("matched_entries")),
                    _cell(item["notes"]),
                ]
            )


def write_gate_list_csv(document: dict, path) -> None:
    """One row per original gate-list entry - filterable by status."""

    with Path(path).open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(_ENTRY_COLUMNS)
        for entry in document["gate_list"]["entries"]:
            writer.writerow(
                [
                    entry["name"],
                    entry["match"],
                    _cell(
                        [
                            f"{f['name']}@{hex(f['function_start'])}"
                            for f in entry["matched_functions"]
                        ]
                    ),
                    entry["ambiguous"],
                    entry["pending"],
                    entry["status"],
                    entry["evidence_status"],
                    _cell(entry["census_blocked"]),
                    _cell(entry["census_blocked_bound"]),
                    _cell(entry["census_blocked_unbound"]),
                    _cell(entry["census_formed"]),
                    _cell(entry["census_formed_bound"]),
                    _cell(entry["census_formed_unbound"]),
                    _cell(entry["census_conflicts"]),
                    _cell(entry["census_unrecognised_mechanisms"]),
                    _cell(entry["remaining_active_sources"]),
                    _cell(entry["remaining_excluded_sources"]),
                    entry["vector_instructions"],
                    _cell(entry["unmatched_clones"]),
                    _cell(entry["notes"]),
                ]
            )


_KIND_LABELS = {
    SOURCE_VLEN_ALLOCATION: "明确/已追踪 VLEN 分配",
    SOURCE_UNKNOWN_ALLOCATION: "仅普通尺寸 UNKNOWN（假设下排除）",
    SOURCE_VECTOR_STACK_OBJECT: "向量栈对象",
    SOURCE_UNRESOLVED_VECTOR_ACCESS: "未解析向量访问",
    SOURCE_IRREDUCIBLE_DEGRADATION: "不可归约降级",
    SOURCE_UNATTRIBUTED_ACTIVITY: "未归属活跃（缺口）",
    SOURCE_SCALAR_WIDTH_CACHE: "标量硬件宽度缓存",
}

_STATUS_LABELS = {
    ENTRY_GATE_BYPASSED: "疑似 gate 失效（已绑定 census formed）",
    ENTRY_FORMED_BEFORE_GATE: "基线阶段已生成（该阶段未启用 gate，不构成绕过）",
    ENTRY_SOURCE_REMAINS: "已 gate 但源头残留",
    ENTRY_VECTOR_REMAINS: "源头已消失但仍有向量指令",
    ENTRY_BLOCKED_EVIDENCE: "有已绑定 blocked 证据且无残留",
    ENTRY_UNBOUND_EVIDENCE: "证据存在但未绑定构建身份",
    ENTRY_MISSING_COMPILE_EVIDENCE: "缺少编译期证据",
    ENTRY_NO_SYMBOL: "符号未出现在最终 ELF",
}

#: Rendered beside (never merged into) ``_STATUS_LABELS``: a source verdict and
#: an evidence verdict answer different questions about the same entry.  The
#: evidence labels stay stage-neutral on purpose - whether a formed record is a
#: bypass depends on the stage, which the source verdict carries.
_EVIDENCE_LABELS = {
    EVIDENCE_BOUND_BLOCKED: "已绑定 blocked（gate 有执行证据）",
    EVIDENCE_BOUND_FORMED: "已绑定 formed（名单内仍生成隐式向量代码）",
    EVIDENCE_UNBOUND: "记录存在但未绑定构建身份（证据不足）",
    EVIDENCE_CONFLICT: "同一函数同机制 formed+blocked 冲突（两者都不计为证据）",
    EVIDENCE_UNRECOGNISED: "机制名未识别（记录保留但不可作为证据）",
    EVIDENCE_NONE: "无 census 记录",
}

_GAP_LABELS = {
    GAP_AMBIGUOUS_FRAME_ORIGIN: "共享帧标记归属歧义",
    GAP_AMBIGUOUS_SETUP_ORIGIN: "准备区标记归属歧义",
    GAP_UNATTRIBUTED_FRAME_MARKER: "帧标记未能归属",
    GAP_UNATTRIBUTED_SETUP_MARKER: "准备区标记未能归属",
    GAP_UNATTRIBUTED_LIVE_OBJECT: "活跃对象未被认领",
    GAP_INHERITED_MARKER_IN_BASE: "局部活跃集合混入继承标记",
    GAP_CLOSURE_MISMATCH: "传播闭包与分析器不一致",
    GAP_AFFECTED_SITE_MISMATCH: "影响站点与分析器不一致",
    GAP_PROPAGATION_ITERATION_CAP: "传播未收敛",
    GAP_GATE_LIST_SIZE_MISMATCH: "原名单规模不符",
    GAP_CHECK_REPORT_HASH_MISMATCH: "交叉参照报告哈希不符",
    GAP_CENSUS_UNREADABLE: "census 无法读取",
    GAP_CENSUS_MALFORMED_LINE: "census 行非法",
    GAP_CENSUS_WITHOUT_USABLE_LINES: "census 无可用记录",
    GAP_CENSUS_UNKNOWN_MECHANISM: "census 机制名未知",
    GAP_CENSUS_ACTION_CONFLICT: "census 动作冲突",
    GAP_CENSUS_UNBOUND: "census 证据未绑定",
    GAP_CONSUMED_DECISION_MISSING: "未声明被审构建实际消费的决策（不绑定）",
    GAP_EVIDENCE_UNREADABLE: "证据清单无法读取",
}


def render_report(document: dict) -> str:
    """Render the Chinese conclusion report."""

    lines: list[str] = []
    add = lines.append
    elf = document["elf"]
    summary = document["candidate_summary"]
    gate = document["gate_list"]

    add("# 隐式向量化源头独立核对结论")
    add("")
    add("## 范围与工程假设")
    for statement in document["assumptions"]["statements"]:
        add(f"- {statement}")
    add("")
    add("## 输入身份")
    add(f"- ELF：`{elf['path']}`")
    add(f"- SHA256：`{elf['sha256']}`")
    add(f"- 函数 {elf['functions']} 个 / 指令 {elf['instructions']} 条；"
        f"min_vlen_bits={document['parameters']['min_vlen_bits']}")
    add(f"- 被审构建阶段：`{document['parameters']['stage']}`")
    consumed = document["parameters"].get("consumed_decision")
    if consumed is not None:
        add(
            f"- 该构建实际消费的决策（人工声明，用于证据绑定）：{consumed.get('path')}"
            f"（SHA256 `{consumed.get('sha256') or '未提供'}`）"
        )
    else:
        add(
            "- 该构建实际消费的决策：**未声明** —— census 记录因此全部保持未绑定"
            "（不用对照名单替代）"
        )
    add(
        f"- 对照名单（仅用于名称覆盖核对）：{gate.get('path', '<未提供>')}，"
        f"{gate.get('unique_names', 0)} 项（SHA256 `{gate.get('sha256', '-')}`）"
    )
    add(f"- {gate.get('role_note', '')}")
    size_check = gate.get("size_check") or {}
    if size_check.get("expected") is not None:
        verdict = {
            True: "一致",
            False: "不一致",
            None: "无法判定",
        }.get(size_check.get("matches_expected"), "无法判定")
        add(
            f"- 原名单位数核对：去重后 {size_check.get('unique_names')} 项，"
            f"预期 {size_check['expected']} 项，判定 {verdict}"
            f"（重复丢弃 {size_check.get('duplicates_dropped')} 行）"
        )
    add(f"- {document['gate_list']['aggregate_log_note']}")
    reference = document.get("check_report_reference")
    if reference is not None:
        add(
            f"- 新版检查报告交叉参照：findings={reference['reported_findings_total']}，"
            f"推荐名单 {reference['recommended_gate_names']} 项（仅参照，不作对照名单）；"
            f"哈希一致={reference['content_sha256_matches']}"
        )
    add("")

    evidence = document["evidence"]
    add("## 证据绑定状态")
    add(
        f"- 已绑定 census 文件 {evidence['bound_census_count']} 个；"
        f"未绑定 {evidence['unbound_census_count']} 个"
    )
    if evidence["census_files"]:
        add(
            "| census 文件 | 绑定 | 阶段 | 决策哈希（记录 vs 实际消费） "
            "| 编译单元（已在清单） | 编译命令 | 工具链 | 产物哈希 |"
        )
        add("|---|---|---|---|---|---|---|---|")
        for row in evidence["census_files"]:
            declared = row["declared_consumed_decision_sha256"]
            consumed_hash = row["consumed_decision_sha256"]
            if declared is None:
                decision_cell = "记录未声明"
            elif consumed_hash is None:
                decision_cell = f"{declared[:12]}… vs 未声明"
            elif row["consumed_decision_matches"]:
                decision_cell = f"{declared[:12]}… =✔"
            else:
                decision_cell = f"{declared[:12]}… ≠ {consumed_hash[:12]}…"
            add(
                f"| `{row['path']}` | {'是' if row['bound'] else '否'} "
                f"| {row['stage'] or '—'} "
                f"| {decision_cell} "
                f"| {row['compile_unit'] or '—'}"
                f"{'' if row['compile_unit_declared'] else '（未声明）'} "
                f"| {'有' if row['compile_command'] else '无'} "
                f"| {row['toolchain'] or '—'} "
                f"| {(row['artifact_sha256'] or '—')[:12]} |"
            )
    else:
        add("- 未提供 census 文件：逐函数 gate 执行证据缺失。")
    add(f"- {evidence['note']}")
    add("")

    add("## 候选源头总览（逐项；排除项逐条可追溯）")
    add("| 来源类型 | 数量 |")
    add("|---|---:|")
    for kind, count in sorted(summary["by_kind"].items()):
        add(f"| {_KIND_LABELS.get(kind, kind)} | {count} |")
    add(
        f"| 合计（活跃 {summary['active']} / 假设下排除 "
        f"{summary['excluded_by_assumption']}） | {summary['total']} |"
    )
    add("")

    propagation = document["propagation"]
    cross = propagation["cross_check"]
    add("## 传播与影响站点")
    add(
        f"- 调用／跨函数转移 {propagation['call_instructions']} 条；"
        f"已解析 {propagation['resolved_relations']}，"
        f"未解析 {propagation['unresolved_sites']}，"
        f"空目标集 {propagation['empty_target_sites']}，"
        f"外部边界 {propagation.get('external_sites', 0)}；"
        f"固定点 {propagation['fixpoint_iterations']} 轮收敛"
        f"（收敛={propagation['fixpoint_converged']}）"
    )
    add(
        f"- 继承闭包 {propagation['inherited_functions']} 个函数，"
        f"来源相关活跃站点 {propagation['affected_sites']} 个"
        f"（外部 {propagation.get('active_external_sites', 0)}，"
        f"值逃逸 {propagation.get('active_width_escape_sites', 0)}），"
        f"传播后仍不活跃 {propagation['inactive_unresolved_sites']} 个"
        f"（其中局部为空、仅继承非空者 "
        f"{propagation['inactive_unresolved_sites_local_only']} 个）"
    )
    add(
        f"- 与分析器闭包交叉核对：闭包一致={cross['inherited_matches_analyzer']}，"
        f"站点一致={cross['affected_matches_analyzer']}"
    )
    if cross["mismatches"]:
        add(f"- ⚠️ 交叉核对不一致项：{', '.join(cross['mismatches'])}（详见 JSON gaps）")
    add("")

    missing = document["answers"]["sources_missing_from_list"]
    add("## 问题一：哪些源头漏入清单")
    if missing:
        add("| 源头 | 函数 | 类型 | 影响站点 |")
        add("|---|---|---|---|")
        for item in missing:
            add(
                f"| `{item['id']}` | `{item['function']}` "
                f"({item['function_start']}) | {_KIND_LABELS.get(item['kind'], item['kind'])} "
                f"| {', '.join(item['affected_sites']) or '—'} |"
            )
    else:
        add("范围内活跃候选源头全部在名单内，或已按假设逐条排除。")
    excluded_items = [
        item for item in document["candidates"] if item["excluded_by_assumption"]
    ]
    add("")
    add(f"按假设排除（未经证明，不是已证明安全）共 {len(excluded_items)} 项：")
    for item in excluded_items:
        add(
            f"- `{item['id']}` `{item['function']}`："
            f"{'；'.join(item['notes']) or '按假设排除'}"
        )
    add("")

    add("## 问题二：哪些清单函数仍需验证 gate 效果")
    counts = gate.get("status_counts") or {}
    if counts:
        add("| 状态 | 条目数 |")
        add("|---|---:|")
        for status, label in _STATUS_LABELS.items():
            add(f"| {label} | {counts.get(status, 0)} |")
        add("")
    evidence_counts = gate.get("evidence_status_counts") or {}
    if evidence_counts:
        add("编译证据质量（与上表相互独立）：")
        add("")
        add("| 证据状态 | 条目数 |")
        add("|---|---:|")
        for status, label in _EVIDENCE_LABELS.items():
            add(f"| {label} | {evidence_counts.get(status, 0)} |")
        add("")
    pending = document["answers"]["listed_functions_pending_gate_verification"]
    if pending:
        add("| 名单条目 | 状态 | 证据 | 歧义 | 待核验原因 | 说明 |")
        add("|---|---|---|---|---|---|")
        for entry in pending:
            reason = (
                "同名定义未区分"
                if entry["pending_reason"] == "ambiguous-definitions"
                else "源头或证据未决"
            )
            add(
                f"| `{entry['name']}` | {_STATUS_LABELS.get(entry['status'], entry['status'])} "
                f"| {_EVIDENCE_LABELS.get(entry['evidence_status'], entry['evidence_status'])} "
                f"| {'是' if entry['ambiguous'] else '否'} "
                f"| {reason} "
                f"| {'；'.join(entry['notes'])} |"
            )
    else:
        add("所有名单条目均有已绑定 blocked 证据、无残留且无歧义（仍不等于逐函数证明）。")
    add(
        f"- 待核验条目合计：{gate.get('entries_pending', 0)}"
        f"（其中仅因同名歧义而未决：{gate.get('entries_pending_only_by_ambiguity', 0)}）"
    )
    add(
        f"- 已绑定 blocked 证据的条目：{gate.get('entries_with_bound_blocked', 0)}；"
        f"未绑定 blocked：{gate.get('entries_with_unbound_blocked', 0)}；"
        f"已绑定 formed：{gate.get('entries_with_bound_formed', 0)}；"
        f"未绑定 formed：{gate.get('entries_with_unbound_formed', 0)}；"
        f"census 冲突条目：{gate.get('entries_with_census_conflict', 0)}；"
        f"机制未识别条目：{gate.get('entries_with_unrecognised_mechanism', 0)}"
    )
    add("")

    gaps = document["gaps"]
    ambiguous = [gap for gap in gaps if gap["kind"] in AMBIGUOUS_GAP_KINDS]
    unattributed = [
        gap for gap in gaps if gap["kind"].startswith(UNATTRIBUTED_GAP_PREFIX)
    ]
    add("## 归属歧义与未覆盖")
    if ambiguous:
        add(f"归属歧义（共享标记可归属到多个分配，保留候选集合）共 {len(ambiguous)} 处：")
        for gap in ambiguous:
            add(
                f"- [{_GAP_LABELS.get(gap['kind'], gap['kind'])}] "
                f"`{gap.get('function', '?')}` @ {hex(gap.get('call_site', 0))}："
                f"候选分配 {', '.join(gap.get('allocations', []))}"
            )
    else:
        add("无共享标记归属歧义。")
    if unattributed:
        add(f"未被认领的活跃状态共 {len(unattributed)} 处：")
        for gap in unattributed:
            add(
                f"- [{_GAP_LABELS.get(gap['kind'], gap['kind'])}] "
                f"{gap['detail']}"
            )
    else:
        add("无未认领的活跃状态。")
    add("")

    add("## 缺口与未覆盖")
    if gaps:
        for gap in gaps:
            add(f"- [{_GAP_LABELS.get(gap['kind'], gap['kind'])}] {gap['detail']}")
    else:
        add("无。")
    add("")

    needed = document["next_evidence_needed"]
    add("## 下一步需要的证据")
    if needed:
        for item in needed:
            add(f"- {item}")
    else:
        add("无新增证据需求。")
    add("")
    add(
        "说明：本审计不改变 check-elf 的任何结论；排除项是“假设下排除、未经证明”，"
        "不是已证明安全；跨构建对比只按符号与证据关联，不按地址配对；"
        "“脚本正常完成”不等于“安全检查通过”。"
    )
    return "\n".join(lines) + "\n"


# endregion


# region Cross-build comparison


def compare_documents(baseline: dict, audited: dict) -> dict[str, object]:
    """Align two audit documents by symbol and evidence, never by address.

    ``baseline`` is typically the build-stack audit and ``audited`` the
    build-gate2 one.  Candidates pair up by ``(function, kind)``; addresses
    are reported per document and are only meaningful inside their own ELF.
    A group that exists on one side only says that *this class of source in
    this function* is not on the other side - without a per-allocation
    identity link it never claims that one particular allocation was
    eliminated.
    """

    def index(document: dict) -> dict[tuple[str, str], list[dict]]:
        grouped: dict[tuple[str, str], list[dict]] = {}
        for item in document["candidates"]:
            if item["excluded_by_assumption"]:
                continue  # excluded items are compared separately, in full
            grouped.setdefault((item["function"], item["kind"]), []).append(item)
        return grouped

    def excluded_index(document: dict) -> dict[tuple[str, str], int]:
        counts: dict[tuple[str, str], int] = {}
        for item in document["candidates"]:
            if item["excluded_by_assumption"]:
                key = (item["function"], item["kind"])
                counts[key] = counts.get(key, 0) + 1
        return counts

    base_active = index(baseline)
    gate_active = index(audited)
    only_in_baseline = []
    only_in_audited = []
    in_both = []
    for key in sorted(set(base_active) | set(gate_active)):
        left = base_active.get(key, [])
        right = gate_active.get(key, [])
        entry = {
            "function": key[0],
            "kind": key[1],
            "baseline_count": len(left),
            "audited_count": len(right),
            "baseline_items": [item["id"] for item in left],
            "audited_items": [item["id"] for item in right],
            "baseline_addresses": [item["addresses"] for item in left],
            "audited_addresses": [item["addresses"] for item in right],
        }
        if left and right:
            in_both.append(entry)
        elif left:
            only_in_baseline.append(entry)
        else:
            only_in_audited.append(entry)

    base_excluded = excluded_index(baseline)
    gate_excluded = excluded_index(audited)
    excluded_rows = [
        {
            "function": key[0],
            "kind": key[1],
            "baseline_items": base_excluded.get(key, 0),
            "audited_items": gate_excluded.get(key, 0),
        }
        for key in sorted(set(base_excluded) | set(gate_excluded))
    ]

    return {
        "format": COMPARE_FORMAT,
        "baseline_elf": baseline["elf"],
        "audited_elf": audited["elf"],
        "linkage": {
            "same_elf_content": (
                baseline["elf"]["sha256"] == audited["elf"]["sha256"]
            ),
            "baseline_stage": baseline.get("parameters", {}).get("stage"),
            "audited_stage": audited.get("parameters", {}).get("stage"),
            "per_allocation_identity": False,
            "note": (
                "两份审计只按 (函数, 来源类型) 分组关联，没有逐分配身份证据；"
                "“baseline 有、被审没有”只能说该类来源在该函数下消失，"
                "不能宣称某一处分配被精确消除。"
            ),
        },
        "note": (
            "跨构建按符号与来源类型关联；地址仅在各自 ELF 内有效，不能直接配对。"
            "baseline 中消失不等于已证明安全，仍需 gate 执行证据。"
        ),
        "sources_only_in_baseline": only_in_baseline,
        "sources_only_in_audited": only_in_audited,
        "sources_in_both": in_both,
        "excluded_items": excluded_rows,
        "summary": {
            "only_in_baseline": len(only_in_baseline),
            "only_in_audited": len(only_in_audited),
            "in_both": len(in_both),
        },
    }


def render_compare_report(document: dict) -> str:
    """Chinese conclusions for the cross-build comparison."""

    lines = ["# 跨构建源头对比结论（按符号关联，不按地址配对）", ""]
    lines.append(
        f"- baseline：`{document['baseline_elf']['path']}` "
        f"（SHA256 `{document['baseline_elf']['sha256']}`）"
    )
    lines.append(
        f"- 被审构建：`{document['audited_elf']['path']}` "
        f"（SHA256 `{document['audited_elf']['sha256']}`）"
    )
    linkage = document.get("linkage") or {}
    if linkage:
        lines.append(
            f"- 关联前提：同一 ELF 内容={linkage['same_elf_content']}，"
            f"baseline 阶段={linkage.get('baseline_stage') or '—'}，"
            f"被审阶段={linkage.get('audited_stage') or '—'}；"
            f"逐分配身份={linkage['per_allocation_identity']}"
        )
        lines.append(f"- {linkage['note']}")
    lines.append("")
    note = document.get("note")
    if note:
        lines.append(note)
        lines.append("")
    summary = document["summary"]
    lines.append(
        f"活跃源头：仅 baseline {summary['only_in_baseline']} 项，"
        f"仅被审构建 {summary['only_in_audited']} 项，"
        f"两边都在 {summary['in_both']} 项。"
    )
    lines.append("")
    if document["sources_only_in_audited"]:
        lines.append("## 被审构建新出现的源头（gate 后新增，需优先核对）")
        for entry in document["sources_only_in_audited"]:
            lines.append(
                f"- `{entry['function']}`（{entry['kind']}）："
                f"{entry['audited_count']} 项"
            )
        lines.append("")
    if document["sources_in_both"]:
        lines.append("## 两边都在的源头（gate 后残留，需 gate 执行证据）")
        for entry in document["sources_in_both"]:
            lines.append(
                f"- `{entry['function']}`（{entry['kind']}）："
                f"baseline {entry['baseline_count']} 项 / 被审 {entry['audited_count']} 项"
            )
        lines.append("")
    if document["sources_only_in_baseline"]:
        lines.append(
            "## 仅在 baseline 的源头（与该类来源被 gate 消除一致，但需 census 证据确认）"
        )
        for entry in document["sources_only_in_baseline"]:
            lines.append(
                f"- `{entry['function']}`（{entry['kind']}）："
                f"baseline {entry['baseline_count']} 项；"
                f"baseline 地址 {_cell(entry['baseline_addresses'])}"
            )
        lines.append("")
    if document["excluded_items"]:
        lines.append("## 假设下排除项对照（未经证明，不是已证明安全）")
        for row in document["excluded_items"]:
            lines.append(
                f"- `{row['function']}`（{row['kind']}）："
                f"baseline {row['baseline_items']} 项 / 被审 {row['audited_items']} 项"
            )
        lines.append("")
    lines.append(
        "说明：地址只在各自 ELF 内有效；“仅 baseline 有”只说明该类来源在该函数下消失，"
        "不能据此宣称某一处分配被精确消除。"
    )
    return "\n".join(lines) + "\n"


# endregion


# region CLI


def _write_text(path, text: str) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text, encoding="utf-8")


def _write_json(path, document: dict) -> None:
    _write_text(path, json.dumps(document, ensure_ascii=False, indent=2) + "\n")


def _run_audit(arguments: argparse.Namespace) -> int:
    names, info = load_gate_list_file(Path(arguments.gate_list))
    document = audit_elf(
        Path(arguments.input),
        gate_names=names,
        gate_list_info=info,
        census_paths=arguments.census or (),
        evidence_path=arguments.evidence,
        stage=arguments.stage,
        expected_gate_count=arguments.expected_gate_count,
        consumed_decision_path=arguments.consumed_decision,
        check_report_path=arguments.check_report,
        objdump_cmd=arguments.objdump,
        min_vlen_bits=arguments.min_vlen_bits,
    )
    if arguments.json:
        _write_json(arguments.json, document)
    if arguments.candidates_csv:
        write_candidates_csv(document, arguments.candidates_csv)
    if arguments.gate_csv:
        write_gate_list_csv(document, arguments.gate_csv)
    report = render_report(document)
    if arguments.report:
        _write_text(arguments.report, report)
    summary = document["candidate_summary"]
    answers = document["answers"]
    print("隐式向量化源头独立核对完成：")
    print(f"  ELF: {document['elf']['path']}")
    print(f"  候选源头 {summary['total']} 项（活跃 {summary['active']} / "
          f"假设下排除 {summary['excluded_by_assumption']}）")
    print(f"  漏入清单的源头：{len(answers['sources_missing_from_list'])} 项")
    print(
        "  仍需验证 gate 效果的清单函数："
        f"{len(answers['listed_functions_pending_gate_verification'])} 项"
    )
    print(
        f"  已绑定 census {document['evidence']['bound_census_count']} / "
        f"未绑定 {document['evidence']['unbound_census_count']}"
    )
    print(f"  缺口：{len(document['gaps'])} 项")
    print("  注意：本脚本正常完成只表示审计执行成功，不代表安全检查通过。")
    if not (arguments.json and arguments.report):
        print("提示：未同时给出 --json 与 --report，以下为中文结论全文：\n")
        print(report)
    return 0


def _run_compare(arguments: argparse.Namespace) -> int:
    baseline = json.loads(Path(arguments.baseline).read_text(encoding="utf-8"))
    audited = json.loads(Path(arguments.audited).read_text(encoding="utf-8"))
    if baseline.get("format") != AUDIT_FORMAT or audited.get("format") != AUDIT_FORMAT:
        raise SystemExit(f"compare 只接受 {AUDIT_FORMAT} 文档")
    document = compare_documents(baseline, audited)
    if arguments.json:
        _write_json(arguments.json, document)
    report = render_compare_report(document)
    if arguments.report:
        _write_text(arguments.report, report)
    summary = document["summary"]
    print("跨构建对比完成：")
    print(f"  仅 baseline：{summary['only_in_baseline']} 项；"
          f"仅被审构建：{summary['only_in_audited']} 项；"
          f"两边都在：{summary['in_both']} 项")
    if not arguments.report:
        print()
        print(report)
    return 0


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m chimera.gate_source_audit",
        description=(
            "隐式向量化源头独立核对：不改变 check-elf/安全点分类/通过判据/检查凭证；"
            "对照 gate 构建实际使用的原决策文件，而非新版报告的推荐名单。"
        ),
    )
    sub = parser.add_subparsers(dest="command", required=True)

    audit = sub.add_parser("audit", help="审计一份 ELF")
    audit.add_argument("--input", required=True, help="被审 ELF 路径")
    audit.add_argument(
        "--gate-list",
        required=True,
        help="gate 构建实际使用的原决策文件（decision JSON 或 .gate_names.txt）",
    )
    audit.add_argument(
        "--census",
        action="append",
        help="implicit-vector-census TSV（可多次给出，逐函数 gate 执行证据）",
    )
    audit.add_argument(
        "--evidence",
        help=f"{EVIDENCE_FORMAT} 证据清单 JSON（把 census 绑定到构建身份）",
    )
    audit.add_argument(
        "--stage",
        choices=(STAGE_BUILD_STACK, STAGE_BUILD_GATE2, STAGE_UNKNOWN),
        default=STAGE_UNKNOWN,
        help="被审构建阶段；只有与证据清单一致的阶段才能绑定 census 证据",
    )
    audit.add_argument(
        "--expected-gate-count",
        type=int,
        default=EXPECTED_GATE2_LIST_SIZE,
        help=(
            "原决策名单去重后的预期项数；默认 "
            f"{EXPECTED_GATE2_LIST_SIZE}（gate-2 聚合日志所报）"
        ),
    )
    audit.add_argument(
        "--check-report",
        help="同一 ELF 的新版检查报告 JSON（仅交叉参照，不作对照名单）",
    )
    audit.add_argument(
        "--consumed-decision",
        help=(
            "被审构建实际消费的决策文件（用于证据绑定与记录；不参与名称匹配）；"
            "对照名单由 --gate-list 给出。未提供时 census 记录一律保持未绑定"
        ),
    )
    audit.add_argument("--json", help="机器可读 JSON 输出路径")
    audit.add_argument("--candidates-csv", help="候选源头 CSV 输出路径")
    audit.add_argument("--gate-csv", help="名单逐项核对 CSV 输出路径")
    audit.add_argument("--report", help="中文结论 Markdown 输出路径")
    audit.add_argument("--objdump", default="objdump")
    audit.add_argument("--min-vlen-bits", type=int, default=256)
    audit.set_defaults(handler=_run_audit)

    compare = sub.add_parser("compare", help="跨构建按符号对比两份审计 JSON")
    compare.add_argument("--baseline", required=True, help="baseline 审计 JSON")
    compare.add_argument("--audited", required=True, help="被审构建审计 JSON")
    compare.add_argument("--json", help="对比 JSON 输出路径")
    compare.add_argument("--report", help="中文对比结论输出路径")
    compare.set_defaults(handler=_run_compare)

    return parser


def main(argv=None) -> int:
    """Entry point.

    The exit code reports whether the *audit* ran, never whether the
    application is safe: a completed audit with insufficient evidence still
    exits 0 and says so in the report, while invalid input, a mismatched
    identity or an execution failure exits non-zero.
    """

    parser = _build_parser()
    arguments = parser.parse_args(argv)
    try:
        return arguments.handler(arguments)
    except (OSError, ValueError, KeyError, RuntimeError) as error:
        sys.stderr.write(f"错误：{error}\n")
        return 2


if __name__ == "__main__":
    sys.exit(main())


# endregion
