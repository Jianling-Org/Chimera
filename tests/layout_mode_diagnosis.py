"""Mode-switch diagnosis for the real gate-2 ``layout`` disassembly.

Read-only: this module never writes an ELF, a check credential, a decision or a
safety criterion.  Forcing a metadata state on is a *diagnostic* act and its
result is not a safety pass.

The same program is analysed under three metadata states:

* **binary mode** -- ``ChimeraMetadata.empty()``; no ``.chimera.stackobj_map``
  section, so every VLEN-sensitive access is recovered from the binary and
  unresolved ones degrade conservatively;
* **metadata-empty** -- ``ChimeraMetadata(has_stackobj_map_section=True)`` with an
  empty mapping, the "capability present, zero records" state.  Forcing this
  state is how the mode contribution is isolated; it is never evidence that the
  ELF really carried the section.  Since coverage is decided per function, this
  state is *incomplete coverage* for ``layout`` and falls back to binary
  recovery -- it must therefore agree with the binary run;
* **metadata-complete** -- every VLEN-sensitive access of the function carries a
  record.  Producing that mapping is a diagnostic act
  (``complete_coverage_metadata``); it is what isolates the pure metadata
  contribution, and it is never a claim that any ELF recorded those addresses.

For each run the diagnosis records the access plan (``metadata_mode``,
``access_mode``, ``mode_reason``, coverage counts and the uncovered addresses),
the irreducible-loop warnings, the objects that were actually created, the local
active call sites and the propagation entries.  A degradation *warning* and a
*propagatable degradation object* are reported as two separate facts and never
merged.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# ``chimera/__init__`` registers the source-tree ``preprocessing`` namespace as
# ``chimera.preprocess``; import the package first so the alias is in place.
import chimera  # noqa: F401

from chimera.preprocess.offline.analysis.arch.riscv.control_flow import (
    is_call_instruction,
)
from chimera.preprocess.offline.analysis.arch.riscv.rvv.services import RvvServices
from chimera.preprocess.offline.analysis.safety.stack_liveness.accesses import (
    _VectorAccessPlanner,
    _VLenSensitiveAccessSelector,
)
from chimera.preprocess.offline.analysis.safety.stack_liveness.analyzer import (
    StackLivenessAnalyzer,
)
from chimera.preprocess.offline.analysis.safety.stack_liveness.model import (
    AccessMode,
    ChimeraMetadata,
    StackFunctionLiveness,
    StackObjectId,
)

#: Marker created only by the binary-mode fact builder when a vector store sits
#: inside an irreducible loop.  Absent from metadata mode by construction.
IRREDUCIBLE_SOURCE = "irreducible"
#: Shared conservative marker created only for unresolved binary-mode accesses.
CONSERVATIVE_SOURCE = "conservative"
IRREDUCIBLE_WARNING = "irreducible-loop-degraded"


@dataclass(frozen=True)
class FunctionPlanView:
    """The access-plan facts of one function, as the planner produced them."""

    function_start: int
    function_name: str
    metadata_mode: bool
    vlen_sensitive_addresses: tuple[int, ...]
    compiler_access_ids: dict[int, int]
    binary_addresses: tuple[int, ...]
    has_metadata_section: bool = False
    metadata_covered_count: int = 0
    uncovered_sensitive_addresses: tuple[int, ...] = ()
    access_mode: str = AccessMode.BINARY_NO_SECTION.value
    mode_reason: str = ""

    @property
    def coverage_incomplete(self) -> bool:
        return self.access_mode == AccessMode.BINARY_INCOMPLETE.value


@dataclass(frozen=True)
class ModeRun:
    """Everything one forced mode produced for one function."""

    label: str
    metadata: ChimeraMetadata
    plan: FunctionPlanView
    irreducible_warnings: tuple[int, ...]
    """Addresses named by ``irreducible-loop-degraded`` warnings (mode-independent)."""

    irreducible_object_live_at: tuple[int, ...]
    """Addresses whose live set holds the function-scoped irreducible object."""

    conservative_object_live_at: tuple[int, ...]
    conservative_addresses: tuple[int, ...]
    object_sources: tuple[str, ...]
    """Distinct ``StackObjectId.source`` values seen in the function's live sets."""

    local_active_call_sites: tuple[int, ...]
    """Call sites with a non-empty local live set."""

    irreducible_call_sites: tuple[int, ...]
    """Call sites whose live set holds the irreducible object."""

    conservative_call_sites: tuple[int, ...]
    created_stack_object_ids: tuple[str, ...]
    warnings: tuple[str, ...]
    irreducible_loops: tuple[tuple[int, ...], ...]

    @property
    def access_mode(self) -> str:
        return self.plan.access_mode

    @property
    def coverage_incomplete(self) -> bool:
        """The section was present but this function's coverage was not."""

        return self.plan.coverage_incomplete

    @property
    def has_irreducible_warning(self) -> bool:
        return bool(self.irreducible_warnings)

    @property
    def has_propagatable_irreducible_object(self) -> bool:
        """True only when the degradation object was really created and live.

        A warning alone does not qualify: ``_build_from_metadata`` never builds
        the irreducible object, so the warning can be present while nothing
        propagates.  Callers must read this flag instead of the warning.
        """

        return bool(self.irreducible_object_live_at) or bool(
            self.irreducible_call_sites
        )


@dataclass(frozen=True)
class ModeComparison:
    """Side-by-side result for one function under both forced modes."""

    function_name: str
    function_start: int
    binary: ModeRun
    metadata: ModeRun
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def warning_parity(self) -> bool:
        """Irreducible warnings must not depend on the mode switch."""

        return (
            self.binary.irreducible_warnings == self.metadata.irreducible_warnings
        )

    @property
    def object_divergence(self) -> bool:
        """Binary versus the forced empty-metadata state.

        Coverage is decided per function, so an empty mapping is *incomplete*
        coverage and falls back to binary recovery: the two runs must agree,
        and this property must be False.  The divergence that the mode switch
        really produces only shows up against a fully covered run
        (:attr:`complete_coverage_divergence`).
        """

        return (
            self.binary.has_propagatable_irreducible_object
            != self.metadata.has_propagatable_irreducible_object
        )

    @property
    def complete_coverage_divergence(self) -> bool:
        """Binary versus a run whose coverage of this function is complete."""

        complete = self.extra.get("metadata-complete")
        if complete is None:
            return False
        return (
            self.binary.has_propagatable_irreducible_object
            != complete.has_propagatable_irreducible_object
        )

    @property
    def binary_fallback_parity(self) -> bool:
        """No section and incomplete coverage must analyse identically."""

        return (
            self.binary.irreducible_object_live_at
            == self.metadata.irreducible_object_live_at
            and self.binary.conservative_addresses
            == self.metadata.conservative_addresses
            and self.binary.irreducible_call_sites
            == self.metadata.irreducible_call_sites
            and self.binary.created_stack_object_ids
            == self.metadata.created_stack_object_ids
        )

    @property
    def call_site_delta(self) -> tuple[tuple[int, ...], tuple[int, ...]]:
        """``(only_binary, only_metadata)`` irreducible-marked call sites."""

        binary = set(self.binary.irreducible_call_sites)
        metadata = set(self.metadata.irreducible_call_sites)
        return tuple(sorted(binary - metadata)), tuple(sorted(metadata - binary))


def forced_metadata_mode() -> ChimeraMetadata:
    """The diagnostic-only "capability present, zero records" state.

    This is *not* a claim about any real ELF.  An empty payload with the
    section present is a legitimate third state of ``ChimeraMetadata.from_elf``
    (see ``test_stackobject_metadata_addresses``), and reproducing it here is
    how the mode contribution is isolated from the code shape.

    With per-function coverage it is also *incomplete* coverage for a function
    that has any VLEN-sensitive access, so ``layout`` falls back to binary
    recovery and this run must agree with :func:`binary_mode_metadata`.
    """

    return ChimeraMetadata(has_stackobj_map_section=True)


def complete_coverage_metadata(
    program, function, *, base_object_id: int = 1
) -> ChimeraMetadata:
    """A diagnostic mapping that covers every sensitive access of ``function``.

    The object ids are synthetic: this exists to exercise the branch in which
    metadata really is authoritative, never to claim an ELF recorded them.
    """

    extension = RvvServices()
    configs = extension.vector_configs(program)
    planner = _VectorAccessPlanner(
        _VLenSensitiveAccessSelector(extension.stack_semantics, 256)
    )
    sensitive = planner.plan(
        function, ChimeraMetadata.empty(), configs[function.start]
    ).vlen_sensitive_addresses
    stack_ids = {
        address: base_object_id + index
        for index, address in enumerate(sorted(sensitive))
    }
    return ChimeraMetadata(stack_ids=stack_ids, has_stackobj_map_section=True)


def binary_mode_metadata() -> ChimeraMetadata:
    return ChimeraMetadata.empty()


def plan_view(function, metadata: ChimeraMetadata, config_result) -> FunctionPlanView:
    """Re-run the production access planner and expose its split."""

    semantics = RvvServices().stack_semantics
    planner = _VectorAccessPlanner(_VLenSensitiveAccessSelector(semantics, 256))
    plan = planner.plan(function, metadata, config_result)
    return FunctionPlanView(
        function_start=function.start,
        function_name=function.name,
        metadata_mode=plan.metadata_mode,
        vlen_sensitive_addresses=tuple(sorted(plan.vlen_sensitive_addresses)),
        compiler_access_ids=dict(plan.compiler_access_ids),
        binary_addresses=tuple(sorted(plan.binary_addresses)),
        has_metadata_section=plan.has_metadata_section,
        metadata_covered_count=plan.metadata_covered_count,
        uncovered_sensitive_addresses=tuple(
            sorted(plan.uncovered_sensitive_addresses)
        ),
        access_mode=str(plan.access_mode.value),
        mode_reason=plan.mode_reason,
    )


def _live_addresses(local: StackFunctionLiveness, marker) -> tuple[int, ...]:
    hits = [
        address
        for address, objects in local.live_before.items()
        if marker in objects
    ]
    return tuple(sorted(hits))


def _call_sites(function) -> list[int]:
    return sorted(
        instruction.addr
        for instruction in function.insts
        if is_call_instruction(instruction)
    )


def _stack_object_ids(local: StackFunctionLiveness) -> tuple[str, ...]:
    seen: set[str] = set()
    for access in local.accesses.values():
        seen.add(str(access.stack_id))
    for objects in local.live_before.values():
        for item in objects:
            seen.add(str(item))
    return tuple(sorted(seen))


def run_mode(program, function, *, label: str, metadata: ChimeraMetadata) -> ModeRun:
    """Analyse ``program`` under ``metadata`` and extract the function's facts."""

    extension = RvvServices()
    config_results = extension.vector_configs(program)
    analyzer = StackLivenessAnalyzer(
        min_vlen_bits=256,
        semantics=extension.stack_semantics,
        emit_warnings=False,
    )
    result = analyzer.analyze_program(
        program,
        metadata=metadata,
        config_results=config_results,
    )
    local = result.by_function[function.start]
    plan = plan_view(function, metadata, config_results[function.start])

    irreducible = StackObjectId(IRREDUCIBLE_SOURCE, f"{function.start:x}")
    conservative = StackObjectId(CONSERVATIVE_SOURCE, "possible-stack-data")

    call_sites = _call_sites(function)
    live_at_calls = {
        site: local.live_before.get(site, frozenset()) for site in call_sites
    }

    sources = sorted(
        {
            item.source
            for objects in local.live_before.values()
            for item in objects
        }
    )

    return ModeRun(
        label=label,
        metadata=metadata,
        plan=plan,
        irreducible_warnings=tuple(
            warning.addresses
            for warning in local.warnings
            if warning.code == IRREDUCIBLE_WARNING
        ),
        irreducible_object_live_at=_live_addresses(local, irreducible),
        conservative_object_live_at=_live_addresses(local, conservative),
        conservative_addresses=tuple(sorted(local.conservative_addresses)),
        object_sources=tuple(sources),
        local_active_call_sites=tuple(
            site for site, objects in live_at_calls.items() if objects
        ),
        irreducible_call_sites=tuple(
            site for site, objects in live_at_calls.items() if irreducible in objects
        ),
        conservative_call_sites=tuple(
            site for site, objects in live_at_calls.items() if conservative in objects
        ),
        created_stack_object_ids=_stack_object_ids(local),
        warnings=tuple(sorted({warning.code for warning in local.warnings})),
        irreducible_loops=tuple(
            tuple(sorted(loop)) for loop in local.irreducible_loops
        ),
    )


def diagnose_function(
    program,
    function,
    *,
    stack_ids: dict[int, int] | None = None,
    include_complete_coverage: bool = True,
) -> ModeComparison:
    """Compare binary mode against the forced metadata states.

    ``stack_ids`` optionally supplies real compiler mapping (from a live ELF)
    for a further, non-forced observation; it is never invented here.  The
    ``metadata-complete`` observation *is* synthetic (see
    :func:`complete_coverage_metadata`) and says nothing about any ELF.
    """

    binary = run_mode(
        program, function, label="binary", metadata=binary_mode_metadata()
    )
    metadata_run = run_mode(
        program,
        function,
        label="metadata-empty",
        metadata=forced_metadata_mode(),
    )
    extra: dict[str, Any] = {}
    if stack_ids is not None:
        real = ChimeraMetadata(
            stack_ids=dict(stack_ids), has_stackobj_map_section=True
        )
        extra["metadata-with-records"] = run_mode(
            program, function, label="metadata-with-records", metadata=real
        )
    if include_complete_coverage:
        extra["metadata-complete"] = run_mode(
            program,
            function,
            label="metadata-complete",
            metadata=complete_coverage_metadata(program, function),
        )
    return ModeComparison(
        function_name=function.name,
        function_start=function.start,
        binary=binary,
        metadata=metadata_run,
        extra=extra,
    )


def format_comparison(comparison: ModeComparison) -> str:
    """Human-readable dump; the JSON export is the machine-readable form."""

    lines = [
        f"function: {comparison.function_name} ({comparison.function_start:#x})",
        "",
    ]
    for run in (comparison.binary, comparison.metadata):
        lines.extend(
            [
                f"[{run.label}]",
                f"  metadata_mode={run.plan.metadata_mode}",
                f"  access_mode={run.plan.access_mode} ({run.plan.mode_reason})",
                f"  has_metadata_section={run.plan.has_metadata_section}",
                f"  metadata_covered={run.plan.metadata_covered_count}"
                f"/{len(run.plan.vlen_sensitive_addresses)}",
                f"  uncovered_sensitive={len(run.plan.uncovered_sensitive_addresses)}",
                f"  compiler_access_ids={len(run.plan.compiler_access_ids)}",
                f"  binary_addresses={len(run.plan.binary_addresses)}",
                f"  irreducible_warnings={len(run.irreducible_warnings)}",
                f"  propagatable_irreducible_object={run.has_propagatable_irreducible_object}",
                f"  irreducible_object_live_at={len(run.irreducible_object_live_at)}",
                f"  conservative_addresses={len(run.conservative_addresses)}",
                f"  conservative_object_live_at={len(run.conservative_object_live_at)}",
                f"  local_active_call_sites={len(run.local_active_call_sites)}",
                f"  irreducible_call_sites={len(run.irreducible_call_sites)}",
                f"  conservative_call_sites={len(run.conservative_call_sites)}",
                f"  object_sources={list(run.object_sources)}",
                f"  warnings={list(run.warnings)}",
                "",
            ]
        )
    only_binary, only_metadata = comparison.call_site_delta
    lines.extend(
        [
            f"warning_parity={comparison.warning_parity}",
            f"object_divergence={comparison.object_divergence}",
            f"irreducible_call_sites_only_in_binary={len(only_binary)}",
            f"irreducible_call_sites_only_in_metadata={len(only_metadata)}",
        ]
    )
    return "\n".join(lines)


def comparison_to_json(comparison: ModeComparison) -> dict[str, Any]:
    def run_json(run: ModeRun) -> dict[str, Any]:
        return {
            "label": run.label,
            "metadata_mode": run.plan.metadata_mode,
            "access_mode": run.plan.access_mode,
            "mode_reason": run.plan.mode_reason,
            "has_metadata_section": run.plan.has_metadata_section,
            "metadata_covered_count": run.plan.metadata_covered_count,
            "uncovered_sensitive_addresses": [
                hex(a) for a in run.plan.uncovered_sensitive_addresses
            ],
            "coverage_incomplete": run.plan.coverage_incomplete,
            "compiler_access_ids": {
                hex(k): v for k, v in sorted(run.plan.compiler_access_ids.items())
            },
            "binary_addresses": [hex(a) for a in run.plan.binary_addresses],
            "vlen_sensitive_addresses": [
                hex(a) for a in run.plan.vlen_sensitive_addresses
            ],
            "irreducible_warnings": [
                [hex(a) for a in group] for group in run.irreducible_warnings
            ],
            "has_irreducible_warning": run.has_irreducible_warning,
            "has_propagatable_irreducible_object": (
                run.has_propagatable_irreducible_object
            ),
            "irreducible_object_live_at": [
                hex(a) for a in run.irreducible_object_live_at
            ],
            "conservative_addresses": [hex(a) for a in run.conservative_addresses],
            "conservative_object_live_at": [
                hex(a) for a in run.conservative_object_live_at
            ],
            "object_sources": list(run.object_sources),
            "local_active_call_sites": [hex(a) for a in run.local_active_call_sites],
            "irreducible_call_sites": [hex(a) for a in run.irreducible_call_sites],
            "conservative_call_sites": [
                hex(a) for a in run.conservative_call_sites
            ],
            "created_stack_object_ids": list(run.created_stack_object_ids),
            "warnings": list(run.warnings),
            "irreducible_loops": [
                [hex(a) for a in loop] for loop in run.irreducible_loops
            ],
        }

    only_binary, only_metadata = comparison.call_site_delta
    payload = {
        "format": "chimera-layout-mode-diagnosis-v2",
        "compatibility": {
            "from": "chimera-layout-mode-diagnosis-v1",
            "changed": [
                "runs[].access_mode / mode_reason: the mode actually applied",
                "runs[].has_metadata_section / metadata_covered_count / "
                "uncovered_sensitive_addresses / coverage_incomplete",
                "metadata-complete: a synthetic fully-covered observation; "
                "metadata-empty now falls back to binary recovery and must "
                "agree with the binary run",
            ],
            "unchanged": [
                "format-independent keys: read_only, function_name, "
                "function_start, warning_parity, binary, metadata_empty",
                "runs[].metadata_mode / binary_addresses / "
                "vlen_sensitive_addresses / warnings",
            ],
        },
        "read_only": True,
        "forced_metadata_mode_is_not_a_safety_pass": True,
        "function_name": comparison.function_name,
        "function_start": hex(comparison.function_start),
        "binary": run_json(comparison.binary),
        "metadata_empty": run_json(comparison.metadata),
        "warning_parity": comparison.warning_parity,
        "object_divergence": comparison.object_divergence,
        "binary_fallback_parity": comparison.binary_fallback_parity,
        "complete_coverage_divergence": comparison.complete_coverage_divergence,
        "irreducible_call_sites_only_in_binary": [hex(a) for a in only_binary],
        "irreducible_call_sites_only_in_metadata": [hex(a) for a in only_metadata],
    }
    for label, run in comparison.extra.items():
        payload[label] = run_json(run)
    return payload
