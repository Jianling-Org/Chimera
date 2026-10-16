"""check-elf: workflow-driven ELF checks and compile-decision export.

The command collects only the binary checks declared by the selected Profile
workflow.  The current Safety declaration runs the same analysis kernel as
prepare's safety step (disassemble → program model → vector configs → stack
liveness) on an arbitrary ELF without creating a workspace; an empty check
plan validates the input and succeeds without invoking objdump, then:

* attributes active unresolved and external call boundaries to their first cause
  (local vector-stack object / caller-inherited / conservative / irreducible);
  every such finding is actionable: unknown targets or a known external body
  prevent complete caller-stack propagation, including callbacks into the
  Program. This is a safety gap even when the host has no vector code. The
  ``residual`` report field is retained for consumer compatibility but is
  always false for this finding class;
* composes the remediation decision from the nature of the findings, with
  orthogonal switches: irreducible-loop degradation selects the StackObject
  metadata route; the remaining pointer-analysis need is routed by code size —
  small programs take the SVF metadata route (cheap and precise), large ones
  take the de-vectorization gate (full-program pointer analysis does not
  scale); known active external boundaries select source elimination via
  gate, since pointer metadata cannot close the callback graph. Metadata and
  gate remain orthogonal, and rebuilding must be followed by a strict check;
* exports ``<elf>.check.json`` (report + compile decision block), writes the
  decision file consumed by ``chimera-pkg llvm``, and registers the ELF state.
"""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path

from chimera.preprocess.offline.analysis.arch.riscv.rvv.config import VSET_OPS
from chimera.preprocess.offline.analysis.arch.riscv.rvv.services import RvvServices
from chimera.preprocess.offline.analysis.arch.riscv.services import RiscvServices
from chimera.preprocess.offline.analysis.core.contracts import DisassemblyFormat
from chimera.preprocess.offline.analysis.program_model.parser import parse_dump
from chimera.preprocess.offline.analysis.toolchain.objdump import LinuxObjdump
from chimera.preprocess.offline.analysis.safety.stack_liveness import (
    AccessMode,
    ChimeraMetadata,
    StackLivenessAnalyzer,
)
from chimera.preprocess.offline.analysis.safety.stack_liveness.model import (
    ACTIONABLE_CALL_WARNINGS,
    ACTIVE_EXTERNAL_CALL,
    UNRESOLVED_ACTIVE_CALL,
    ORIGIN_CONSERVATIVE,
    ORIGIN_INHERITED,
    ORIGIN_IRREDUCIBLE,
    ORIGIN_LOCAL_FRAME,
    ORIGIN_LOCAL_SETUP,
    ORIGIN_LOCAL_SCALAR,
    VLEN_SCALAR_ESCAPE,
    ORIGIN_VECTOR_DATA,
)
from chimera.preprocess.offline.analysis.safety.stack_liveness.scope import (
    CONSERVATIVE,
    CONSERVATIVE_SCOPE_DESCRIPTION,
    assumption_for_policy,
    is_conditional_policy,
    normalize_unknown_stack_size_policy,
)
from chimera.preprocess.offline.analysis.safety.external_leaf import (
    bind_external_scalar_leaves, normalize_leaf_contracts, selected_check_modules,
)
from chimera.preprocess.offline.analysis.core.monitor import current_session
from chimera.preprocess.offline.analysis.core.monitor.render import render_line
from chimera.preprocess.offline.analysis.program_model.parser import _memory_fields
from chimera.preprocess.offline.analysis_profile.checks import (
    BinaryCheckContext,
    BinaryCheckOutcome,
    BinaryCheckRequest,
)

DEFAULT_TEXT_THRESHOLD = 1_048_576

CAUSE_LOCAL = "local-root"
CAUSE_INHERITED = "inherited"
CAUSE_CONSERVATIVE = "conservative"
CAUSE_IRREDUCIBLE = "irreducible"

#: Origin status vocabulary of a finding: what the *local* evidence is.
ORIGIN_STATUS_VLEN_SOURCE = "vlen-source"
ORIGIN_STATUS_UNPROVEN = "unproven"
ORIGIN_STATUS_INHERITED = "inherited"
ORIGIN_STATUS_MIXED = "mixed"

STRATEGY_GATE = "gate"
STRATEGY_SVF = "svf"
STRATEGY_NONE = "none"          # 无指针分析需求（仅不可规约发现或零发现）

ACTION_DISABLE_AUTOVEC = "disable-autovec-file"
ACTION_SVF_METADATA = "svf-metadata"
ACTION_STACK_OBJECT = "stack-object-metadata"
# Removed from generated findings: inheriting live state while calling an
# unresolved target is never an acceptable outcome — the live state belongs
# to upstream frames and only proves that propagation stopped at this call.
ACTION_TRACE_SOURCE = "trace-inheritance-source"
#: An unproven stack adjustment: the finding is real (the mark is kept) but the
#: next step is to establish where the size comes from, not to de-vectorize a
#: function that may hold no VLEN-sensitive data at all.
ACTION_TRACE_SIZE_SOURCE = "trace-size-source"
ACTION_ACCEPT_RESIDUAL = "accept-residual"  # legacy constant; no longer emitted

IRREDUCIBLE_DEGRADED = "irreducible-loop-degraded"


def _debug_event(event: str, values: dict) -> None:
    """Emit a bounded single-line debug event under --debug.

    Monitoring failures never affect the check itself.
    """

    session = current_session()
    if not session.enabled or session.stream is None:
        return
    try:
        print(render_line(event, values), file=session.stream, flush=True)
    except BaseException:
        return


def _read_limited(path: Path, limit: int) -> str:
    """Read at most ``limit`` characters; never raises on I/O errors."""

    try:
        with Path(path).open(encoding="utf-8", errors="ignore") as handle:
            return handle.read(limit)
    except OSError:
        return ""


@dataclass(frozen=True)
class Finding:
    kind: str                    # local-root | inherited | conservative | irreducible
    function: str                # mangled name of the enclosing function
    call_site: str               # hex address of the active boundary transfer
    recommended_action: str      # disable-autovec-file | svf-metadata |
                                 # stack-object-metadata | trace-inheritance-source |
                                 # trace-size-source
    support: tuple[str, ...]     # verbatim cause details
    residual: bool = False       # retained for report-schema compatibility;
                                 # active boundary findings are always
                                 # actionable, so this is always False
    #: Whether the host of this finding is on the gate list this run produced.
    #: This is a remediation candidate, not proof of discharge. An unchanged
    #: active boundary must still fail the next check after gate recompilation.
    gate_listed: bool = False
    #: Structured origins behind the finding (``model.ActiveOrigin``).  The
    #: report exposes them as ``activity_origins``; classification never reads
    #: ``support``.
    origins: tuple = ()
    #: ``vlen-source`` | ``unproven`` | ``inherited`` | ``mixed``.
    origin_status: str = ""
    diagnostic_code: str = UNRESOLVED_ACTIVE_CALL
    external_targets: tuple[int, ...] = ()


@dataclass(frozen=True)
class _InheritanceAnalysis:
    """Analysis handles needed to render --inheritance-report.

    The report reuses the already-computed program model, liveness result
    and metadata — it never re-disassembles the ELF.
    """

    program: object   # Program
    stack: object     # StackLivenessResult
    metadata: object  # ChimeraMetadata
    # Per-warning traceability, keyed by the call-site address.
    warning_starts_by_site: dict[int, int] = field(default_factory=dict)
    warning_details_by_site: dict[int, tuple[str, ...]] = field(default_factory=dict)


@dataclass(frozen=True)
class DiagnosticsResult:
    elf_path: Path
    strategy: str                # gate | svf | none（指针分析路线）
    strategy_reason: str
    text_bytes: int | None   # forced 策略下不读取 ELF，为 None
    findings: tuple[Finding, ...]
    gate_names: tuple[str, ...]  # mangled host functions to de-vectorize
    seed_host_starts: tuple[int, ...] = ()
    counts: dict[str, int] = field(default_factory=dict)
    stack_object: bool = False   # 不可规约降级存在 → StackObject 元数据路线
    # Inherited hosts without local vector code (trace targets, never gated).
    pure_inherited_starts: tuple[int, ...] = ()
    # Hosts whose only local activity is an unproven stack adjustment: listed
    # as pending proofs, deliberately absent from the gate list.
    pending_proof_starts: tuple[int, ...] = ()
    # Analysis handles retained for the optional --inheritance-report export;
    # never serialised into the report and never part of the decision.
    analysis: _InheritanceAnalysis | None = None
    unknown_stack_size_policy: str = CONSERVATIVE
    assumption: str = CONSERVATIVE_SCOPE_DESCRIPTION
    conditional: bool = False
    scope_exclusion_count: int = 0


def _seed_has_known_source(stack, function_start: int, site: int) -> bool:
    """Whether the activity that seeds a call site is something we can name.

    A seed edge exists because a call is made while the caller's stack is
    active.  When the only live object is a VLEN stack frame whose size is
    *unproven*, gating the caller is a guess: the size may well come from an
    ordinary scalar.  Such a host is reported as a pending proof instead.
    """

    local = stack.by_function.get(function_start)
    if local is None:
        return True
    live = local.live_before.get(site, frozenset())
    if not live:
        return True
    live_sources = {obj.source for obj in live}
    for obj in live:
        if obj.source in {"caller", "vlen_stack_frame", "vlen_stack_setup"}:
            continue
        # Conservative / irreducible / a resolved stack object.
        return True
    origins = getattr(local, "frame_origins", ())
    if "vlen_stack_setup" in live_sources:
        # Setup can be live before the stack adjustment that consumes it, so
        # its known VLEN dependency may be recorded at a later instruction.
        return any(
            origin.dependency == "vlen"
            and origin.source == "vlen_stack_frame"
            for origin in origins
        )
    return any(
        origin.dependency == "vlen"
        and origin.source == "vlen_stack_frame"
        and origin.adjustment <= site
        for origin in origins
        if origin.source in live_sources
    )


def _width_evidence_payload(evidence) -> dict:
    payload = asdict(evidence)
    payload['control_addresses'] = [hex(address) for address in evidence.control_addresses]
    call = payload['call_effect']
    if call is not None:
        def target_payload(target):
            return {**target, 'target': hex(target['target']),
                    'instruction': hex(target['instruction']) if target['instruction'] is not None else None}
        call['targets'] = [target_payload(target) for target in call['targets']]
        if call['first_refusal'] is not None:
            call['first_refusal'] = target_payload(call['first_refusal'])
    return payload


def _origins_payload(origins) -> list[dict]:
    """Serialise structured origins for the report."""

    return [
        {
            "origin": origin.origin,
            "object": origin.object_id,
            "allocation": (
                f"0x{origin.allocation:x}" if origin.allocation is not None else None
            ),
            "release": (
                f"0x{origin.release:x}" if origin.release is not None else None
            ),
            "dependency": origin.dependency,
            "proof": origin.proof,
            "gaps": list(origin.gaps),
            "detail": origin.detail,
            **({'width_evidence': _width_evidence_payload(origin.width_evidence)}
               if getattr(origin, 'width_evidence', None) is not None else {}),
        }
        for origin in origins
    ]


def _diagnostics_payload(result: DiagnosticsResult) -> dict[str, object]:
    return {
        "unknown_stack_size_policy": result.unknown_stack_size_policy,
        "assumption": result.assumption,
        "conditional": result.conditional,
        "scope_exclusion_count": result.scope_exclusion_count,
        "external_scalar_leaves": _external_leaf_payload(result),
        "warnings": _cache_warnings_payload(result),
        "strategy": result.strategy,
        "strategy_reason": result.strategy_reason,
        "text_bytes": result.text_bytes,
        "summary": {
            "findings_total": len(result.findings),
            "actionable": len(result.findings),
            "stack_object_plugin": bool(result.stack_object),
            **result.counts,
        },
        "gate_names": list(result.gate_names),
        "pending_proof_names": [
            _function_name(result, start) for start in result.pending_proof_starts
        ],
        "missing_internal_targets": _missing_targets(result),
        "findings": [
            {
                "kind": item.kind,
                "diagnostic_code": item.diagnostic_code,
                "external_targets": [hex(target) for target in item.external_targets],
                "function": item.function,
                "call_site": item.call_site,
                "recommended_action": item.recommended_action,
                "support": list(item.support),
                "activity_origins": _origins_payload(item.origins),
                "origin_status": item.origin_status,
                "residual": item.residual,
                "gate_listed": item.gate_listed,
            }
            for item in result.findings
        ],
    }


def _cache_warnings_payload(result: DiagnosticsResult) -> list[dict]:
    """Keep local cache scope observations visible without creating findings."""
    if result.analysis is None:
        return []
    functions = {f.start: f.name for f in result.analysis.program.functions}
    return [
        {
            "severity": "warning",
            "actionable": False,
            "diagnostic_code": warning.code,
            "function": functions.get(warning.function_start, hex(warning.function_start)),
            "function_start": hex(warning.function_start),
            "addresses": [hex(address) for address in warning.addresses],
            "message": warning.message,
            "support": list(warning.details),
            "activity_origins": _origins_payload(warning.origins),
        }
        for warning in result.analysis.stack.warnings
        if warning.code == VLEN_SCALAR_ESCAPE
    ]


def _external_leaf_payload(result) -> dict:
    stack = result.analysis.stack if result.analysis is not None else None
    return {
        "proofs": list(getattr(stack, "external_leaf_proofs", ())),
        "rejections": list(getattr(stack, "external_leaf_rejections", ())),
        "closed_calls": [
            {"call_site": hex(site), "targets": [hex(target) for target in targets]}
            for site, targets in sorted(getattr(stack, "closed_external_calls", {}).items())],
    }


def _missing_targets(result: DiagnosticsResult) -> list[dict]:
    """Callees whose bodies the origin proofs needed and could not read."""

    if result.analysis is None:
        return []
    stack = result.analysis.stack
    missing = getattr(stack, "missing_callees", {}) or {}
    return [
        {
            "address": f"0x{address:x}",
            "reason": reason,
            "name": _function_name(result, address),
        }
        for address, reason in sorted(missing.items())
    ]


def _function_name(result: DiagnosticsResult, start: int) -> str:
    """Best-effort function name for an address of the analysed program."""

    if result.analysis is None:
        return hex(start)
    for function in result.analysis.program.functions:
        if function.start == start:
            return function.name
    return hex(start)


def safety_binary_check_request(parameters) -> BinaryCheckRequest:
    """Declare the Safety stack diagnostic required by a workflow step."""
    normalized = {
        "min_vlen_bits": parameters["min_vlen_bits"],
        "compiler_metadata": tuple(parameters["compiler_metadata"]),
        "unknown_stack_size_policy": normalize_unknown_stack_size_policy(
            parameters.get("unknown_stack_size_policy", CONSERVATIVE)
        ),
        "external_scalar_leaf_contracts": normalize_leaf_contracts(
            parameters.get("external_scalar_leaf_contracts", ())),
    }

    def run(input_elf: Path, context: BinaryCheckContext) -> BinaryCheckOutcome:
        configuration = context.configuration
        tools = getattr(getattr(configuration, "base", None), "tools", None)
        objdump = context.objdump_cmd or getattr(tools, "objdump", None)
        if not objdump:
            raise ValueError(
                "Safety binary check requires an objdump; pass --objdump or "
                "set config.tools.objdump in the profile"
            )
        metadata = ChimeraMetadata.from_elf(input_elf)
        result = collect_diagnostics(
            input_elf,
            objdump_cmd=objdump,
            min_vlen_bits=normalized["min_vlen_bits"],
            unknown_stack_size_policy=normalized["unknown_stack_size_policy"],
            strategy=context.overrides.get("strategy", "auto"),
            text_threshold=context.overrides.get("text_threshold", DEFAULT_TEXT_THRESHOLD),
            metadata=metadata,
            external_scalar_leaf_contracts=normalized["external_scalar_leaf_contracts"],
            external_modules=(selected_check_modules(input_elf, configuration)
                if normalized["external_scalar_leaf_contracts"] else ()),
        )
        inheritance_report = context.overrides.get("inheritance_report")
        if inheritance_report is not None:
            from chimera.elf_state import sha256_of

            export_inheritance_diagnostics(
                result,
                Path(inheritance_report),
                content_hash=sha256_of(Path(input_elf).resolve()),
            )
        diagnostics = _diagnostics_payload(result)
        missing_metadata = sorted(
            set(normalized["compiler_metadata"]) - metadata.capabilities
        )
        if missing_metadata:
            diagnostics["missing_compiler_metadata"] = missing_metadata
        decision = build_decision_block(result)
        if missing_metadata:
            if "stack_access_ids" in missing_metadata:
                decision["stack_object_plugin"] = True
            if "function_pointer" in missing_metadata:
                decision["function_pointer_plugin"] = True
        actionable = has_actionable_findings(result) or bool(missing_metadata)
        message = (
            "missing compiler metadata: " + ", ".join(missing_metadata)
            if missing_metadata else ""
        )
        return BinaryCheckOutcome(
            passed=not actionable,
            diagnostics=diagnostics,
            decision=decision,
            message=message,
            actionable=actionable,
        )

    return BinaryCheckRequest(
        check_id="safety.stack-liveness",
        # Version 4: the *attribution* and the *proof* changed together.
        # Findings are attributed from structured origin records instead of
        # phrases in their human-readable details, so a local VLEN stack frame
        # is no longer reported as caller-inherited; "a VLEN source exists" and
        # "the source is not proven" are separate answers with separate
        # recommendations; and an unproven stack adjustment is discharged by an
        # on-demand origin proof (memory ranges, callee summaries, control
        # dependence) instead of staying unproven forever.
        # Version 5 closed three ways a proof could cover only the path that
        # was walked: a register definition that misses the entry-keeping
        # path, a callee result selected by a branch, and a callee write that
        # does not run on every path to a return (origins-v2).
        # Version 6 completed the *memory* side of a callee summary
        # (origins-v3): a nested call's writes are folded in, a store address
        # is composed from pointer arithmetic instead of a dependence name,
        # and a vector store through a pointer is recorded as an unmodelled
        # write.
        # Version 7 closes the remaining alias/completeness holes
        # (origins-v4): distinct formal parameters may alias and a formal
        # pointer may hold any static address (no non-alias proof exists),
        # atomic writes are accounted for, and an indirect call's target set
        # is no longer pruned to its provable subset.
        # Version 8 described the atomic writes instead of merely noticing
        # them (origins-v5): a read-modify-write consumes the old memory
        # content, and a store-conditional may not store at all - v7 could
        # call such a write a proven full overwrite.
        # Version 9 stopped losing path conditions when summaries compose
        # (origins-v6): must-write is intersected over a call's complete
        # target set, a nested write carries the guard of the call that
        # performs it, and write sources under a branch not proven
        # independent of vlenb are refused - v8 could return "proven" for a
        # value that holds on only some of the caller's paths.
        # Version 10 made the summary solver keep its UNKNOWN (origins-v7):
        # the join stores unknown entries instead of omitting them and
        # absence reads as the entry value everywhere, so a register a call
        # had clobbered could resurface as the caller's argument or as a
        # proven constant - v9 could return "proven" through such a value.
        # Version 11 applied the alias and substitution rules on their
        # remaining branches (origins-v8): the local reaching-write walk now
        # uses the alias table, and a static write's value dependence is
        # substituted at the call site against the incoming state - v10 could
        # return "proven" from a local may-alias store or a static write
        # whose value a nested call had clobbered.
        # Version 12 stopped treating "based on the entry sp" as "private"
        # (origins-v9): a frame write is ignored only when the callee
        # provably allocated the region it writes, and the missing-callee
        # forensic list accumulates for the whole check - v11 could return
        # "proven" past a write into the caller's frame and could drop
        # bodies that needed fetching.
        # Version 13 extracted the frame-privacy proof into one shared
        # predicate (origins-v10) and applied it on the remaining branches -
        # a rebased nested write through the frame base, and a frame-typed
        # escape - so v12 could return "proven" past a nested callee's write
        # into the caller's frame.
        # Version 14 made a rebased write follow the object type it lands on
        # (origins-v11): a formal that held a static address becomes a static
        # write - v13 crashed on such summaries.
        # Version 15 gave the entry path its due when the query point is the
        # entry itself (origins-v12): a back-edge definition covers later
        # iterations only, and the first execution uses the caller's value -
        # v14 could return "proven" for such an entry adjustment, so
        # credentials recorded under it attest answers this version refuses.
        # Version 16 carried the call-site guard onto the register-return
        # side (origins-v13): a call whose execution is selected by a branch
        # not proven independent of vlenb no longer proves a0 from the
        # callee's constant result - on the branch that skips the call the
        # caller's value reaches the query point.  v15 could return "proven"
        # for such a guarded return, so credentials recorded under it attest
        # answers this version refuses.
        # Version 17 moved that rule to the single exit every reaching
        # definition passes (origins-v14): a load whose content is proven in
        # every candidate slot but whose slot is vlenb-selected no longer
        # proves the size either, and the per-kind guards (arithmetic since
        # v6, call returns since v16) are replaced by one downgrade at the
        # definition exit.  v16 could return "proven" for a branch-selected
        # load, so credentials recorded under it attest answers this version
        # refuses.
        # Version 19 changed what compiler stack-object metadata may silence
        # (per-function coverage): the section being present is no longer read
        # as "this function is covered".  A VLEN-sensitive access without a
        # record now sends the whole function back to binary recovery instead
        # of being dropped, so a half-instrumented product no longer looks
        # clean - sources that v18 discarded reappear as local marks, as
        # propagated seeds and as gate candidates.  v18 could accept such an
        # ELF, so a credential recorded under it attests a decision this
        # version no longer makes; every previously accepted ELF must be
        # re-checked under the corrected rule.
        # Version 20 records locally active calls even when their caller has
        # inherited state, and keeps unknown-only VLEN setup/frame evidence
        # pending instead of treating inherited markers as a named source.
        # Version 18 changed the CFG the proofs walk (the CFG input
        # semantics, origins-v15): a call target is no longer an in-function
        # control-flow edge, so a recursive call - or any call whose target
        # lies inside the function - no longer turns that function into a
        # loop.  v17 could keep a proven fixed frame adjustment unproven (and
        # its fixed restore unreleased) behind such a false loop, so a
        # credential recorded under it attests a decision this version no
        # longer makes; every previously accepted ELF must be re-checked
        # under the corrected rule.
        # Earlier versions: 17 moved that rule to the single exit every
        # reaching definition passes (origins-v14): a load whose content is
        # proven in every candidate slot but whose slot is vlenb-selected no
        # longer proves the size either, and the per-kind guards (arithmetic
        # since v6, call returns since v16) are replaced by one downgrade at
        # the definition exit.  v16 could return "proven" for a
        # branch-selected load, so credentials recorded under it attest
        # answers this version refuses.  16 carried the call-site guard onto
        # register returns, 15 gave the entry path its due, 14 made a rebased
        # write follow the object type it lands on, 13 extracted the
        # frame-privacy predicate, 12 proved frame privacy by allocation,
        # 11 applied the alias/substitution rules on the remaining branches,
        # 10 kept the solver's UNKNOWN, 9 closed the alias rules, 8 the
        # atomic-write semantics, 7 completed the summary's memory side,
        # 6 closed path completeness, 5 fixed attribution, 4 changed the
        # local VLEN stack-frame analysis, 3 removed the residual
        # pass-through.  The check fingerprint covers
        # elf hash + check id + version + parameters, so a CHECKED credential
        # recorded under an earlier version never satisfies admission again;
        # every previously accepted ELF must be re-checked under the
        # corrected rule.
        # Version 23 separates incomplete register analysis from established
        # VLEN provenance and prevents budget fallback from using the scalar
        # assumption. Version 22 credentials therefore require a fresh check.
        # Version 24 rejects active external boundaries (including tail
        # transfers and mixed target sets). v23 silently stopped at these
        # boundaries, so its successful credentials require a fresh check.
        # Version 25 admits only content-bound, machine-code-verified scalar
        # leaves; contract parameters are part of the admission fingerprint.
        # Version 26 keeps live scalar hardware-width caches unsafe and
        # propagates their sources; v25 could resume native with stale VLEN.
        # Version 27 separates vector operands and closes only proven local
        # cross-domain lifetimes. Cached v26 proofs require revalidation.
        # Version 28 separates a callee's return dependencies from its memory
        # writes (origins-v16); v27 could incorrectly prove a width-dependent
        # return after an unrelated constant write. Recheck v27 credentials.
        # Version 29 models complete bounded scalar leaf register effects,
        # including actual inputs outside the assumed argument set and live
        # return/temporary copies. Version 28 could miss those width sources.
        # v30 separates warning-only selection/scope observations from
        # active call boundaries and narrows cache value transfer to local
        # copies/conversions. v29 credentials require an actual fresh check.
        # v31 limits synthetic exit uses to open/unsupported transfers.
        # Complete internal ABI exits retain actual target/SP/continuation
        # uses; v30 credentials require a fresh check under that lifetime.
        version=31,
        parameters=normalized,
        runner=run,
    )


def write_check_report(plan, result, output_path: Path, *, elf_identity: dict) -> Path:
    """Write the generic workflow check report consumed by build wrappers."""
    output_path = Path(output_path)
    identity = dict(elf_identity)
    identity["path"] = str(Path(identity.get("path", output_path)).resolve())
    checks = []
    for request, outcome in result.outcomes:
        checks.append({
            "id": request.check_id,
            "version": request.version,
            "parameters": dict(request.parameters),
            "requested_by": list(request.requested_by),
            "passed": outcome.passed,
            "actionable": outcome.actionable,
            "message": outcome.message,
            "diagnostics": dict(outcome.diagnostics),
        })
    document = {
        "schema": "chimera.check.v1",
        "elf": identity,
        "target": {
            "os": plan.target_key[0],
            "arch": plan.target_key[1],
            "extension": plan.target_key[2],
            "runtime_scene": plan.target_key[3],
        },
        "runtime_abi": plan.runtime_abi,
        "check_scope": plan.scope,
        "check_fingerprint": plan.fingerprint(identity["content_sha256"]),
        "checks": checks,
        "passed": result.passed,
        "message": result.message,
        "decision": dict(result.decision),
    }
    if len(checks) == 1 and checks[0]["diagnostics"]:
        diagnostics = checks[0]["diagnostics"]
        for key in (
            "strategy", "strategy_reason", "text_bytes", "summary", "gate_names",
            "findings", "warnings", "unknown_stack_size_policy", "assumption", "conditional",
            "scope_exclusion_count", "external_scalar_leaves",
        ):
            if key in diagnostics:
                document[key] = diagnostics[key]
    output_path.parent.mkdir(parents=True, exist_ok=True)
    temporary = output_path.with_suffix(output_path.suffix + ".tmp")
    temporary.write_text(json.dumps(document, indent=2, ensure_ascii=False), encoding="utf-8")
    os.replace(temporary, output_path)
    return output_path


def has_actionable_findings(result: DiagnosticsResult) -> bool:
    """Return whether any finding still requires a remediation action.

    Every recorded finding is actionable under the corrected rule, including
    pure caller-inherited hosts without vector code of their own: an active
    call whose targets stayed unresolved is a propagation gap whose source
    must be traced (see --inheritance-report), not an acceptable outcome.
    """

    return bool(result.findings)


def _text_size(elf_path: Path) -> int:
    """Sum the size of every executable section (pyelftools)."""

    from elftools.elf.elffile import ELFFile

    total = 0
    with Path(elf_path).open("rb") as handle:
        elf = ELFFile(handle)
        for section in elf.iter_sections():
            if section["sh_flags"] & 0x4:  # SHF_EXECINSTR
                total += int(section["sh_size"])
    return total


def _parse_call_site(call_site: str) -> int:
    """Parse a finding call_site back to an address; -1 when not parseable."""

    try:
        return int(call_site, 16)
    except (TypeError, ValueError):
        return -1


@dataclass(frozen=True)
class Attribution:
    """Structured attribution of one unresolved-call finding.

    ``primary`` is the cause a remediation should start from; ``is_root`` says
    the host carries local activity of its own (so a witness path to a seed is
    not required); ``has_vlen_source`` and ``has_unproven`` separate "a VLEN
    source was identified" from "the source could not be established", which
    the recommendation treats differently.
    """

    primary: str
    is_root: bool
    has_vlen_source: bool
    has_unproven: bool
    has_inherited: bool
    origin_status: str


def _attribute(origins) -> Attribution:
    """Attribute a warning from its structured origins.

    Classification reads :class:`~...model.ActiveOrigin` records only.  The
    previous implementation matched phrases inside the human-readable
    ``details`` lines, and a local VLEN stack frame - whose wording starts
    with "live VLEN-dependent stack frame" - fell through to the inherited
    default branch as soon as its wording changed.  That is exactly how
    ``driver::set_up_specs`` (0x17cec) and ``destringize_and_run`` (0x6ac3a)
    came to be reported as inherited.
    """

    kinds = {origin.origin for origin in origins}
    if not origins:
        # No structured evidence at all.  This is not a classification input -
        # the analysis attaches origins to every warning it emits - but if one
        # ever arrives without them, the honest answer is "we cannot tell what
        # this is", which is the inherited branch: trace it, do not gate it.
        return Attribution(
            primary=CAUSE_INHERITED,
            is_root=False,
            has_vlen_source=False,
            has_unproven=False,
            has_inherited=True,
            origin_status=ORIGIN_STATUS_INHERITED,
        )
    local_frames = [
        origin
        for origin in origins
        if origin.origin in (ORIGIN_LOCAL_FRAME, ORIGIN_LOCAL_SETUP)
    ]
    has_local_frame = bool(local_frames)
    has_scalar = ORIGIN_LOCAL_SCALAR in kinds
    has_inherited = ORIGIN_INHERITED in kinds
    has_vlen_source = has_scalar or any(
        origin.dependency == "vlen" for origin in local_frames
    )
    has_unproven = any(
        origin.dependency == "unknown" for origin in local_frames
    )

    if has_local_frame or has_scalar:
        primary = CAUSE_LOCAL
    elif ORIGIN_CONSERVATIVE in kinds:
        primary = CAUSE_CONSERVATIVE
    elif ORIGIN_IRREDUCIBLE in kinds:
        primary = CAUSE_IRREDUCIBLE
    elif ORIGIN_VECTOR_DATA in kinds:
        primary = CAUSE_LOCAL
    else:
        primary = CAUSE_INHERITED

    is_root = primary != CAUSE_INHERITED
    if has_local_frame or has_scalar:
        if has_vlen_source and has_unproven:
            status = ORIGIN_STATUS_MIXED
        elif has_vlen_source:
            status = ORIGIN_STATUS_VLEN_SOURCE
        else:
            status = ORIGIN_STATUS_UNPROVEN
    elif has_inherited:
        status = ORIGIN_STATUS_INHERITED
    else:
        status = ORIGIN_STATUS_VLEN_SOURCE
    return Attribution(
        primary=primary,
        is_root=is_root,
        has_vlen_source=has_vlen_source,
        has_unproven=has_unproven,
        has_inherited=has_inherited,
        origin_status=status,
    )


def collect_diagnostics(
    elf_path: Path,
    *,
    objdump_cmd: str,
    min_vlen_bits: int = 256,
    unknown_stack_size_policy: str = CONSERVATIVE,
    strategy: str = "auto",
    text_threshold: int = DEFAULT_TEXT_THRESHOLD,
    dump_text: str | None = None,
    metadata: ChimeraMetadata | None = None,
    external_scalar_leaf_contracts=(),
    external_modules=(),
    external_leaf_bindings=None,
) -> DiagnosticsResult:
    """Run the standalone diagnostics pipeline on ``elf_path``.

    ``dump_text`` and ``metadata`` are test seams: they override the objdump
    invocation with pre-captured disassembly text and skip ELF metadata
    extraction respectively.  Production callers leave both as None.
    """

    elf_path = Path(elf_path).resolve()
    unknown_stack_size_policy = normalize_unknown_stack_size_policy(
        unknown_stack_size_policy
    )
    if not elf_path.is_file():
        raise FileNotFoundError(f"input ELF does not exist: {elf_path}")

    adapter = LinuxObjdump(objdump_cmd)
    # objdump output goes straight to a temp file instead of a pipe: for
    # cc1-scale binaries the captured text used to sit in memory several
    # times over (pipe capture, str, parser copy) before parsing started.
    # stderr also lands on disk; only a bounded prefix feeds error text.
    dump_file: Path | None = None
    stderr_file: Path | None = None
    try:
        if dump_text is None:
            _debug_event(
                "offline.check-elf.disassemble.start", {"elf": str(elf_path)}
            )
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
            # Both write handles are closed before parsing starts.
            if completed.returncode != 0:
                raise RuntimeError(
                    f"disassembly failed ({objdump_cmd}): "
                    f"{_read_limited(stderr_file, 400).strip()}"
                )
            _debug_event(
                "offline.check-elf.disassemble.finish",
                {
                    "elf": str(elf_path),
                    "dump_bytes": dump_file.stat().st_size,
                    **_memory_fields(),
                },
            )
        else:
            with tempfile.NamedTemporaryFile(
                "w", suffix=".dump", encoding="utf-8", delete=False
            ) as dump_handle:
                dump_handle.write(dump_text)
                dump_file = Path(dump_handle.name)

        extension = RvvServices()
        architecture = RiscvServices(extension)
        fmt: DisassemblyFormat = adapter.parse_format
        _debug_event(
            "offline.check-elf.parse.start", {"dump": str(dump_file)}
        )
        parsed = parse_dump(
            dump_file,
            fmt,
            is_external_trampoline=adapter.is_external_trampoline,
            # dump_lines has no consumer past the parser; keeping it would
            # duplicate the whole disassembly text in memory.
            retain_dump_lines=False,
        )
        _debug_event(
            "offline.check-elf.parse.finish",
            {
                "functions": len(parsed.functions),
                "instructions": len(parsed.instructions),
                **_memory_fields(),
            },
        )
        _debug_event("offline.check-elf.cfg-build.start", {})
        program = architecture.build_cfg(parsed)
        _debug_event(
            "offline.check-elf.cfg-build.finish",
            {
                "functions": len(program.functions),
                **_memory_fields(),
            },
        )
    finally:
        # Clean up on success, failure, and interruption alike.
        if dump_file is not None:
            dump_file.unlink(missing_ok=True)
        if stderr_file is not None:
            stderr_file.unlink(missing_ok=True)
    functions_by_start = {
        function.start: function for function in program.functions
    }
    # Active unknown or unproved external boundaries are actionable: caller
    # state cannot be tracked through all callees/callbacks, regardless of
    # whether this host contains vector code.
    # Gating such a host is only a no-op; the actionable remediation is to
    # trace and eliminate the upstream source (see --inheritance-report), so
    # every warning of this class becomes a Finding with residual=False.
    # Functions containing at least one vector instruction of their own (same
    # mnemonic heuristic as VTypeAnalyzer: op starts with "v", excluding
    # vset* configuration instructions).  Only used to decide gate-list
    # membership for inherited hosts — never to waive a finding.
    vector_functions = {
        function.start
        for function in program.functions
        if any(
            instruction.op.startswith("v") and instruction.op not in VSET_OPS
            for instruction in function.insts
        )
    }

    configs = extension.vector_configs(program)
    if metadata is None:
        metadata = ChimeraMetadata.from_elf(elf_path)
    if external_leaf_bindings is None and external_scalar_leaf_contracts:
        external_leaf_bindings = bind_external_scalar_leaves(
            elf_path, program, external_modules, external_scalar_leaf_contracts,
            objdump=objdump_cmd)
    analyzer = StackLivenessAnalyzer(
        min_vlen_bits=min_vlen_bits,
        semantics=extension.stack_semantics,
        unknown_stack_size_policy=unknown_stack_size_policy,
    )
    stack = analyzer.analyze_program(
        program, metadata=metadata, config_results=configs,
        external_leaf_bindings=external_leaf_bindings,
    )

    inherited_functions = set(stack.inherited_functions)
    findings: list[Finding] = []
    root_hosts: set[int] = set()
    inherited_hosts: set[int] = set()
    # Hosts whose local activity is an unproven stack adjustment: the size
    # source must be established before de-vectorizing them can mean anything.
    pending_proof_starts: set[int] = set()
    # Inherited hosts without local vector code: never gate-listed (gating
    # them is a no-op) but their findings are actionable trace targets.
    pure_inherited_starts: set[int] = set()
    for warning in stack.warnings:
        if warning.code not in ACTIONABLE_CALL_WARNINGS:
            continue
        function_name = functions_by_start.get(warning.function_start)
        if function_name is not None and function_name.is_external_trampoline:
            # The disassembler has already classified this linkage entry as
            # an external boundary; it is not an actionable function body.
            continue
        attribution = _attribute(warning.origins)
        name = function_name.name if function_name else hex(warning.function_start)
        if attribution.is_root:
            if attribution.origin_status != ORIGIN_STATUS_UNPROVEN:
                # A *named* local source - a proven VLEN stack frame, an
                # unresolved vector access, an irreducible loop, or resolved
                # vector stack objects. Gate the host as a candidate remedy,
                # then verify that the rebuilt ELF actually removes it.
                root_hosts.add(warning.function_start)
            elif attribution.has_inherited and warning.function_start in vector_functions:
                # Only an unproven local size, but the host also carries
                # inherited state over vector code of its own: it stays a
                # propagation carrier, not a source.
                inherited_hosts.add(warning.function_start)
            else:
                # Unproven local size only: recommend establishing the source,
                # never gating the function on the strength of "not proven".
                pending_proof_starts.add(warning.function_start)
        elif attribution.has_inherited:
            # Inherited hosts stay on the gate list whenever they contain
            # vector code of their own (the caller-inherited attribution
            # cannot distinguish inherited state from locally produced
            # state).  Hosts without vector code are NOT exempt either: the
            # active state belongs to upstream frames, and "gating this
            # function would be a no-op" only proves the finding must be
            # traced back to its source — it is still actionable.
            if warning.function_start in vector_functions:
                inherited_hosts.add(warning.function_start)
            else:
                pure_inherited_starts.add(warning.function_start)
        findings.append(Finding(
            kind=attribution.primary,
            function=name,
            call_site=(hex(warning.addresses[0]) if warning.addresses else "?"),
            recommended_action="",   # filled after strategy selection
            support=tuple(warning.details),
            residual=False,
            origins=tuple(warning.origins),
            origin_status=attribution.origin_status,
            diagnostic_code=warning.code,
            external_targets=warning.external_targets,
        ))

    # Seed-edge callers are locally-active direct-call hosts: they must be
    # gated even when they never warn themselves (their callees inherit).  A
    # seed created only by an unproven dynamic frame does not make its host a
    # gate target - the source of that size is a proof question first.
    for edge in stack.inheritance_trace.seed_edges:
        start = edge.caller_function_start
        if _seed_has_known_source(stack, start, edge.call_site):
            root_hosts.add(start)
        else:
            pending_proof_starts.add(start)

    # Traceability data for --inheritance-report and the recommended-action
    # selection: per-warning function start and full details, keyed by the
    # call-site address (findings only carry the mangled name, which is
    # ambiguous when one symbol hosts several unresolved call sites).
    warning_starts_by_site: dict[int, int] = {}
    warning_details_by_site: dict[int, tuple[str, ...]] = {}
    for warning in stack.warnings:
        if warning.code not in ACTIONABLE_CALL_WARNINGS:
            continue
        if not warning.addresses:
            continue
        warning_starts_by_site[warning.addresses[0]] = warning.function_start
        warning_details_by_site[warning.addresses[0]] = tuple(warning.details)

    counts = {
        "active_external_calls": sum(
            item.diagnostic_code == ACTIVE_EXTERNAL_CALL for item in findings
        ),
        "closed_external_calls": len(getattr(stack, "closed_external_calls", {})),
        "local_root": sum(1 for f in findings if f.kind == CAUSE_LOCAL),
        "inherited": sum(1 for f in findings if f.kind == CAUSE_INHERITED),
        "conservative": sum(1 for f in findings if f.kind == CAUSE_CONSERVATIVE),
        "irreducible": sum(1 for f in findings if f.kind == CAUSE_IRREDUCIBLE),
        # "A VLEN source exists" and "the source is not proven" are different
        # answers: both keep the finding, only the first justifies gating.
        "local_vlen_source": sum(
            1
            for f in findings
            if f.origin_status
            in (ORIGIN_STATUS_VLEN_SOURCE, ORIGIN_STATUS_MIXED)
        ),
        "local_unproven": sum(
            1 for f in findings if f.origin_status == ORIGIN_STATUS_UNPROVEN
        ),
        "pending_proof": len(pending_proof_starts),
        # Always zero under the corrected rule; kept so existing consumers
        # parsing the summary do not break on a missing key.
        "residual": sum(1 for f in findings if f.residual),
        # Every finding of this class is actionable — including pure
        # inherited ones, whose remediation is tracing the source.
        "actionable": len(findings),
        "proof_nodes": len(getattr(stack, "origin_proofs", ())),
        "proof_gaps": len(getattr(stack, "origin_gaps", ())),
        "proof_budget_exhausted": bool(
            getattr(stack, "proof_budget_exhausted", False)
        ),
    }

    # 不可规约循环降级 → StackObject 元数据路线：保守的函数级不可规约对象
    # 正是 stackobj_map 元数据能精确化的部分，只要分析器降级过就开启该开关。
    # 迭代修复下该开关必须"粘滞"：当前产物已携带 stackobj_map 时同样保持
    # 开启——否则下一轮按本决策重编会丢掉元数据，分析退化回
    # conservative/irreducible，决策在开/关之间振荡（元数据在场 ⇒ 无降级
    # 警告 ⇒ 决策关插件 ⇒ 元数据消失 ⇒ 降级回归 ⇒ 再开插件）。
    stack_object_needed = any(
        warning.code == IRREDUCIBLE_DEGRADED for warning in stack.warnings
    ) or metadata.has_stackobj_map_section

    # Known external boundaries need source elimination. The remaining
    # unresolved targets keep the existing code-size routing for SVF/gate.
    external_need = any(finding.diagnostic_code == ACTIVE_EXTERNAL_CALL for finding in findings)
    pointer_need = any(
        finding.kind != CAUSE_IRREDUCIBLE
        and finding.diagnostic_code != ACTIVE_EXTERNAL_CALL
        for finding in findings
    )

    if external_need and strategy == STRATEGY_SVF:
        raise ValueError(
            "active external boundaries cannot be closed by function-pointer "
            "metadata alone; use --strategy gate and recheck the rebuilt ELF"
        )
    if strategy == "auto":
        if external_need:
            text_bytes = None
            strategy = STRATEGY_GATE
            reason = "active external boundaries require source elimination via gate"
        elif pointer_need:
            text_bytes = _text_size(elf_path)
            strategy = (
                STRATEGY_SVF if text_bytes <= text_threshold else STRATEGY_GATE
            )
            reason = (
                f".text={text_bytes} bytes <= threshold {text_threshold}"
                if strategy == STRATEGY_SVF
                else f".text={text_bytes} bytes > threshold {text_threshold}"
            )
        else:
            text_bytes = None   # 无指针分析需求，不读取 ELF
            strategy = STRATEGY_NONE
            reason = (
                "no pointer-analysis need: irreducible-only findings"
                if findings
                else "no findings"
            )
    else:
        text_bytes = None   # forced strategies do not need the ELF read
        reason = "forced via --strategy"

    route_action = (
        ACTION_DISABLE_AUTOVEC if strategy == STRATEGY_GATE else ACTION_SVF_METADATA
    )
    # Hosts this run actually put on the gate list.  Under the gate strategy an
    # irreducible source in such a host gets the gate action; discharge still
    # requires rechecking the rebuilt ELF. "Re-add the stack-object plugin"
    # would hide the intended source-elimination step. Hosts that
    # are *not* gated, and any strategy other than the gate, keep the
    # stack-object recommendation: for them the metadata route is the remaining
    # way to make the degradation precise.
    gate_starts = root_hosts | inherited_hosts
    findings = [
        Finding(
            kind=item.kind,
            function=item.function,
            call_site=item.call_site,
            recommended_action=(
                ACTION_DISABLE_AUTOVEC
                if item.kind == CAUSE_IRREDUCIBLE
                and strategy == STRATEGY_GATE
                and warning_starts_by_site.get(_parse_call_site(item.call_site), -1)
                in gate_starts
                else ACTION_STACK_OBJECT
                if item.kind == CAUSE_IRREDUCIBLE
                # Pure-inherited host without vector code: gating it is a
                # no-op.  The finding is still actionable — follow the
                # inheritance chain to the source (see --inheritance-report)
                # and eliminate it there.
                else ACTION_TRACE_SOURCE
                if item.kind == CAUSE_INHERITED
                and warning_starts_by_site.get(_parse_call_site(item.call_site), -1)
                in pure_inherited_starts
                # A local stack frame whose size is *unproven*: the next step
                # is to establish where that size comes from.  Recommending
                # de-vectorization here would be a guess dressed as a remedy.
                else ACTION_TRACE_SIZE_SOURCE
                if item.origin_status == ORIGIN_STATUS_UNPROVEN
                else route_action
            ),
            support=item.support,
            residual=item.residual,
            origins=item.origins,
            origin_status=item.origin_status,
            diagnostic_code=item.diagnostic_code,
            external_targets=item.external_targets,
            gate_listed=(
                warning_starts_by_site.get(_parse_call_site(item.call_site), -1)
                in gate_starts
            ),
        )
        for item in findings
    ]

    # Gate set = root hosts (own VLEN-sensitive data) + inherited hosts
    # (propagation carriers), excluding external trampolines: they have no
    # compilable definition, so naming them would
    # only spam "listed function(s) not found" warnings in every TU.
    gate_names = sorted(
        function.name if function is not None else hex(start)
        for start in root_hosts | inherited_hosts
        if (function := functions_by_start.get(start)) is None
        or not function.is_external_trampoline
    )

    return DiagnosticsResult(
        elf_path=elf_path,
        strategy=strategy,
        strategy_reason=reason,
        text_bytes=text_bytes,
        findings=tuple(findings),
        gate_names=tuple(gate_names),
        seed_host_starts=tuple(sorted(root_hosts)),
        counts=counts,
        stack_object=stack_object_needed,
        pure_inherited_starts=tuple(sorted(pure_inherited_starts)),
        pending_proof_starts=tuple(sorted(pending_proof_starts)),
        analysis=_InheritanceAnalysis(
            program=program,
            stack=stack,
            metadata=metadata,
            warning_starts_by_site=warning_starts_by_site,
            warning_details_by_site=warning_details_by_site,
        ),
        unknown_stack_size_policy=getattr(
            stack, "unknown_stack_size_policy", unknown_stack_size_policy
        ),
        assumption=getattr(
            stack, "assumption", assumption_for_policy(unknown_stack_size_policy)
        ),
        conditional=bool(
            getattr(stack, "conditional", is_conditional_policy(unknown_stack_size_policy))
        ),
        scope_exclusion_count=sum(
            len(getattr(local, "scope_exclusions", ()))
            for local in getattr(stack, "by_function", {}).values()
        ),
    )



INHERITANCE_DIAGNOSTICS_FORMAT = "chimera-inheritance-diagnostics-v2"

#: What changed between the diagnostic formats, spelled out so a consumer can
#: decide what it has to handle instead of guessing from a version string.
INHERITANCE_DIAGNOSTICS_COMPATIBILITY = {
    "from": "chimera-inheritance-diagnostics-v1",
    "changed": [
        "findings[].activity_origins: structured origins (origin, object, "
        "allocation, release, dependency, proof, gaps)",
        "findings[].origin_status: vlen-source | unproven | inherited | mixed",
        "findings[].diagnostics_incomplete: only reported for findings whose "
        "primary cause is inherited; a local source needs no seed witness",
        "functions[].frame_origins: per-adjustment allocation records",
        "proof_table / proof_gaps: shared origin-proof nodes and the "
        "undischarged ones, referenced by id",
        "pending_proof_refs: hosts listed for size-origin tracing, never gated",
        # Added for check version 19 (per-function metadata coverage).
        "functions[].has_metadata_section / sensitive_access_count / "
        "metadata_covered_count / uncovered_sensitive_addresses / "
        "access_mode / mode_reason: the coverage accounting behind the mode "
        "that actually ran.  Absent fields must never be read as 'fully "
        "covered'; binary-incomplete-coverage is the fallback state in which "
        "the section existed but did not cover this function",
    ],
    "unchanged": [
        "elf, closure_size, max_depth, seed_edges, functions (existing keys)",
        "findings[].function / function_ref / function_start / call_site / kind",
        "findings[].witness_path / witness_reached_seed / witness_note",
        "findings[].activity_explanation (the human-readable prose)",
    ],
}


def _build_inheritance_diagnostics(result: DiagnosticsResult, content_hash: str) -> dict:
    """Render the --inheritance-report document from the collected analysis.

    The report reuses the program model, liveness result and metadata of this
    run (no re-disassembly).  It shares one seed-edge table and one function
    table across all findings; witness paths reference edge indices instead
    of copying edges.  For every inherited finding a single witness path to a
    seed caller is exported -- explicitly *not* the full path set.  When no
    witness exists the finding is marked diagnostics_incomplete; the check
    result itself already failed and this report never changes it.
    """

    if result.analysis is None:
        raise ValueError("diagnostics result carries no analysis handles")
    program = result.analysis.program
    stack = result.analysis.stack
    starts_by_site = result.analysis.warning_starts_by_site
    details_by_site = result.analysis.warning_details_by_site

    functions_by_start = {f.start: f for f in program.functions}
    function_ids: dict[int, int] = {}
    seed_ids: dict[tuple[int, int], int] = {}

    def function_index(start: int) -> int:
        return function_ids.setdefault(start, len(function_ids))

    def seed_index(edge) -> int:
        key = (edge.caller_function_start, edge.call_site)
        return seed_ids.setdefault(key, len(seed_ids))

    # The edge table always carries the complete seed_edges list; witness
    # paths may append first-cause edges with reason=inherited.
    for edge in stack.inheritance_trace.seed_edges:
        seed_index(edge)

    # Every function that carries an allocation record belongs in the table,
    # even when it has no finding and no seed edge: a report about a pending
    # size-origin proof has to name the allocations and the callee bodies it is
    # missing (``cplus_demangle_print_callback`` is the worked example).
    for start, liveness in stack.by_function.items():
        if (
            getattr(liveness, "frame_origins", ())
            or getattr(liveness, "scope_exclusions", ())
            or getattr(liveness, "scalar_width_sources", ())
        ):
            function_index(start)
    for start in result.pending_proof_starts:
        function_index(start)

    # Witness paths: walk first_cause upwards, bounded by a visited set so
    # recursion and multi-source cycles always terminate.  Reaching a seed
    # edge is tracked explicitly: a non-empty path that never arrives at a
    # seed (missing first-cause hop or cycle abort) is NOT a source witness
    # and must be reported as incomplete.
    witness_refs: dict[int, tuple[tuple[int, ...], bool]] = {}
    for warning in stack.warnings:
        if warning.code not in ACTIONABLE_CALL_WARNINGS:
            continue
        if not warning.addresses:
            continue
        site = warning.addresses[0]
        start = warning.function_start
        path: list[int] = []
        reached_seed = False
        current = start
        visited = {start}
        while True:
            edge = stack.inheritance_trace.first_cause.get(current)
            if edge is None:
                break  # broken chain: no recorded cause for this hop
            path.append(seed_index(edge))
            if edge.reason == "seed":
                reached_seed = True
                break
            caller = edge.caller_function_start
            if caller in visited:
                break  # recursive cycle; the last edge still terminates it
            visited.add(caller)
            current = caller
        witness_refs[site] = (tuple(path), reached_seed)


    # Shared seed-edge table with the local active objects at each call site.
    ordered_seeds = sorted(seed_ids, key=seed_ids.__getitem__)
    seed_reason_depth = {
        (edge.caller_function_start, edge.call_site): (edge.reason, edge.depth)
        for edge in stack.inheritance_trace.seed_edges
    }
    # first_cause edges may not appear in seed_edges when reason=inherited.
    trace_all = {
        (edge.caller_function_start, edge.call_site): (edge.reason, edge.depth)
        for edge in stack.inheritance_trace.first_cause.values()
    }
    seed_entries = []
    for caller_start, site in ordered_seeds:
        reason, depth = seed_reason_depth.get(
            (caller_start, site), trace_all.get((caller_start, site), (None, None))
        )
        live = stack.by_function[caller_start].live_before.get(site, frozenset())
        accesses = stack.by_function[caller_start].accesses
        objects = []
        for obj in sorted(live, key=str):
            access_entries = [
                {
                    "address": f"0x{address:x}",
                    "kind": access.kind.value,
                    "source": access.source,
                }
                for address, access in sorted(accesses.items())
                if access.stack_id == obj
            ]
            objects.append(
                {
                    "id": str(obj),
                    "metadata_source": obj.source,
                    "accesses": access_entries,
                }
            )
        seed_entries.append(
            {
                "caller_function_ref": function_index(caller_start),
                "call_site": f"0x{site:x}",
                "reason": reason,
                "depth": depth,
                "local_active_objects": objects,
            }
        )

    # Findings with witness-path references and the full activity details.
    findings = []
    for item in result.findings:
        site = _parse_call_site(item.call_site)
        start = starts_by_site.get(site)
        witness, reached_seed = witness_refs.get(site, ((), False))
        if item.kind == CAUSE_INHERITED:
            # Only a genuinely inherited finding has to show a path to a seed:
            # it is the statement "this state belongs to an upstream frame".
            # A local source *is* the source and needs no inheritance chain.
            complete = reached_seed
        else:
            complete = True
        findings.append(
            {
                "function": item.function,
                "function_ref": function_index(start) if start is not None else None,
                "function_start": f"0x{start:x}" if start is not None else None,
                "call_site": item.call_site,
                "kind": item.kind,
                "diagnostic_code": item.diagnostic_code,
                "external_targets": [hex(target) for target in item.external_targets],
                "origin_status": item.origin_status,
                "activity_origins": _origins_payload(item.origins),
                "witness_path": list(witness),
                "witness_reached_seed": reached_seed,
                "witness_note": (
                    "one witness path to a seed caller; not the full path set"
                    if item.kind == CAUSE_INHERITED
                    else "not applicable: the origin of this finding is local"
                ),
                "diagnostics_incomplete": not complete,
                "activity_explanation": list(
                    details_by_site.get(site, item.support)
                ),
            }
        )

    ordered_functions = sorted(function_ids, key=function_ids.__getitem__)

    def _coverage(start: int) -> dict:
        """The metadata-coverage accounting of one function.

        Only counts and the uncovered addresses are exported, never a copy of
        a per-instruction model.  A reader must not take an absent field as
        "fully covered": the fallback (``binary-incomplete-coverage``) is the
        state in which the section existed but did not cover this function.
        """

        local = stack.by_function.get(start)
        if local is None:
            return {}
        # ``AccessMode`` is a ``str`` enum: ``str()`` of it would write
        # "AccessMode.BINARY_INCOMPLETE" into the report, which no consumer
        # matches on.  The report always carries the documented value.
        access_mode = getattr(local, "access_mode", AccessMode.BINARY_NO_SECTION)
        access_mode = getattr(access_mode, "value", access_mode)
        return {
            "has_metadata_section": bool(
                getattr(local, "has_metadata_section", False)
            ),
            "sensitive_access_count": int(
                getattr(local, "sensitive_access_count", 0)
            ),
            "metadata_covered_count": int(
                getattr(local, "metadata_covered_count", 0)
            ),
            "uncovered_sensitive_addresses": [
                f"0x{address:x}"
                for address in sorted(
                    getattr(local, "uncovered_sensitive_addresses", ())
                )
            ],
            "access_mode": str(access_mode),
            "mode_reason": str(getattr(local, "mode_reason", "")),
        }

    function_table = [
        {
            "name": (
                functions_by_start[start].name
                if start in functions_by_start
                else f"0x{start:x}"
            ),
            "function_start": f"0x{start:x}",
            "in_inherited_closure": start in stack.inherited_functions,
            **_coverage(start),
            "scalar_width_sources": [
                {"address": hex(source.address), "register": source.register, "kind": source.kind}
                for source in getattr(stack.by_function.get(start), "scalar_width_sources", ())
            ],
            "scalar_width_fallback": bool(getattr(
                stack.by_function.get(start), "scalar_width_fallback", False)),
            "frame_origins": [
                {
                    "source": origin.source,
                    "adjustment": f"0x{origin.adjustment:x}",
                    "dependency": origin.dependency,
                    "size_register": origin.size_register,
                    "release": (
                        f"0x{origin.release:x}"
                        if origin.release is not None
                        else None
                    ),
                    "proof": origin.proof,
                    "gaps": list(origin.gaps),
                }
                for origin in getattr(
                    stack.by_function.get(start), "frame_origins", ()
                )
            ],
            "scope_exclusions": [
                {
                    "source": item.source,
                    "function_start": f"0x{item.function_start:x}",
                    "adjustment": f"0x{item.adjustment:x}",
                    "dependency": item.dependency,
                    "size_register": item.size_register,
                    "disposition": item.disposition,
                    "assumption": item.assumption,
                    "proof": item.proof,
                    "gaps": list(item.gaps),
                }
                for item in getattr(
                    stack.by_function.get(start), "scope_exclusions", ()
                )
            ],
        }
        for start in ordered_functions
    ]

    # Shared proof table: every finding and every allocation references these
    # nodes by id instead of carrying its own copy of the reasoning.
    proof_table = [
        {
            "id": node.id,
            "status": node.status,
            "reason": node.reason,
            "function_ref": function_index(node.function_start),
            "function_start": f"0x{node.function_start:x}",
            "address": f"0x{node.address:x}",
            "register": node.register,
            "detail": node.detail,
            "depends_on": list(node.depends_on),
        }
        for node in getattr(stack, "origin_proofs", {}).values()
    ]
    proof_gaps = [
        node_id for node_id in getattr(stack, "origin_gaps", ())
    ]

    return {
        "format": INHERITANCE_DIAGNOSTICS_FORMAT,
        "format_compatibility": INHERITANCE_DIAGNOSTICS_COMPATIBILITY,
        "unknown_stack_size_policy": getattr(
            stack, "unknown_stack_size_policy", CONSERVATIVE
        ),
        "assumption": getattr(
            stack, "assumption", assumption_for_policy(CONSERVATIVE)
        ),
        "conditional": bool(
            getattr(stack, "conditional", is_conditional_policy(CONSERVATIVE))
        ),
        "scope_exclusion_count": sum(
            len(getattr(local, "scope_exclusions", ()))
            for local in getattr(stack, "by_function", {}).values()
        ),
        "elf": {"path": str(result.elf_path), "content_sha256": content_hash},
        "closure_size": len(stack.inherited_functions),
        "max_depth": stack.inheritance_trace.max_depth,
        "active_external_calls": [hex(site) for site in getattr(stack, "active_external_calls", ())],
        "external_scalar_leaves": _external_leaf_payload(result),
        "seed_edges": seed_entries,
        "functions": function_table,
        "findings": findings,
        "warnings": _cache_warnings_payload(result),
        "proof_table": proof_table,
        "proof_gaps": proof_gaps,
        "proof_budget_exhausted": bool(
            getattr(stack, "proof_budget_exhausted", False)
        ),
        # Exactly the callees the proofs asked for and could not read: the
        # forensic command exports these bodies and nothing else.
        "missing_internal_targets": _missing_targets(result),
        "pending_proof_refs": [
            {
                "function_ref": function_index(start) if start in function_ids else None,
                "function_start": f"0x{start:x}",
                "name": (
                    functions_by_start[start].name
                    if start in functions_by_start
                    else f"0x{start:x}"
                ),
                "reason": "unproven stack adjustment: the size origin is not "
                          "established, so this host is not a gate target",
            }
            for start in result.pending_proof_starts
        ],
    }


def export_inheritance_diagnostics(
    result: DiagnosticsResult,
    output_path: Path,
    *,
    content_hash: str,
) -> Path:
    """Write the --inheritance-report JSON document atomically."""

    output_path = Path(output_path)
    document = _build_inheritance_diagnostics(result, content_hash)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    temporary = output_path.with_suffix(output_path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(document, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    os.replace(temporary, output_path)
    return output_path

def build_decision_block(result: DiagnosticsResult) -> dict:
    """Compile-decision block embedded in the report JSON.

    Gate and function_pointer select source elimination or pointer metadata
    respectively. Active known external boundaries require the former;
    unresolved-only targets retain code-size routing. StackObject is added
    independently for degradation or to retain existing metadata.
    """

    return {
        "strategy": result.strategy,
        "vector_gate": {
            "enabled": result.strategy == STRATEGY_GATE,
            "names_source": "report:findings(root-hosts+inherited-hosts)",
        },
        "function_pointer_plugin": result.strategy == STRATEGY_SVF,
        "stack_object_plugin": bool(result.stack_object),
        "gate": {
            "enabled": result.strategy == STRATEGY_GATE,
            "names": list(result.gate_names),
        },
    }


def write_report(
    result: DiagnosticsResult,
    output_path: Path,
    *,
    elf_identity: dict,
) -> Path:
    output_path = Path(output_path)
    document = {
        "schema": "chimera.check.v1",
        "elf": {"path": str(result.elf_path), **elf_identity},
        "strategy": result.strategy,
        "strategy_reason": result.strategy_reason,
        "text_bytes": result.text_bytes,
        "summary": {
            "findings_total": len(result.findings),
            "actionable": len(result.findings),
            "stack_object_plugin": bool(result.stack_object),
            **result.counts,
        },
        "gate_names": list(result.gate_names),
        "decision": build_decision_block(result),
        "findings": [
            {
                "kind": item.kind,
                "diagnostic_code": item.diagnostic_code,
                "external_targets": [hex(target) for target in item.external_targets],
                "function": item.function,
                "call_site": item.call_site,
                "recommended_action": item.recommended_action,
                "support": list(item.support),
                "activity_origins": _origins_payload(item.origins),
                "origin_status": item.origin_status,
                "residual": item.residual,
            }
            for item in result.findings
        ],
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    temporary = output_path.with_suffix(output_path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(document, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    os.replace(temporary, output_path)
    return output_path


def load_latest_pointer() -> dict | None:
    path = Path.home() / ".chimera" / "check_elf" / "latest.json"
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None


def write_latest_pointer(entry: dict) -> None:
    path = Path.home() / ".chimera" / "check_elf" / "latest.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(entry, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    os.replace(temporary, path)


def now_stamp() -> str:
    return datetime.now().isoformat(timespec="seconds")

