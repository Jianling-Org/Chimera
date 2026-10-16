"""Incremental rebuild of selected offline steps on a published workspace.

`chimera-dev rebuild` opens an already-published workspace as a throwaway
staging copy. Only the Manifest-declared `local/<runtime_name>` module inputs
are hard-linked so their inode remains stable; generated and artifact files
are copied before rebuild steps run, then
re-runs the named steps and any later consumers invalidated by their outputs.
Skipped steps are *replayed*: their prior in-memory analysis results are
reconstructed from the staged workspace so downstream steps satisfy their data
contracts without redoing unrelated work.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from chimera.preprocess.offline.analysis.core.contracts import AnalysisContext
from chimera.preprocess.offline.analysis.core.data_model import (
    DELIVERY_PACKAGE,
    AnalysisModule,
)
from chimera.preprocess.offline.analysis.core.monitor import current_session
from chimera.preprocess.offline.analysis.core.workspace import (
    WorkspaceSession,
    anchor_modules,
)
from chimera.preprocess.offline.analysis.prepare_workspace.selection import (
    select_modules,
)
from chimera.runtime.manifest import PACKAGE_MODULE_DIR

from .pipeline import PreparePipeline, _last_use_positions, _release_dead_globals
from .errors import BuildReplayPropertyError, RebuildMissingUpstream


@dataclass(frozen=True)
class RebuildInspection:
    """Read-only view exposed to a step's rebuild preflight hook."""

    stage: Path
    manifest: object
    steps: tuple[object, ...]
    target_bundle: object


@dataclass(frozen=True)
class RebuildExecutionPlan:
    """A one-shot, pipeline-issued rebuild execution plan.

    The token is intentionally bound to the materialized workflow, the
    reopened session, and its staging directory.  ``RebuildPipeline`` keeps
    the identity registry and marks a token consumed before executing any
    step, so callers cannot alter or replay an arbitrary list of identifiers.
    """

    request: frozenset[str]
    preflight: frozenset[str]
    execution: tuple[str, ...]
    workflow: object
    session: WorkspaceSession
    staging: Path


class RebuildPipeline(PreparePipeline):
    _SCHEDULING_OUTPUTS = frozenset({
        "workspace_session", "workspace_contributions", "capabilities",
    })

    def __init__(self, plan):
        super().__init__(plan)
        self._issued_execution_plans: dict[int, RebuildExecutionPlan] = {}
        self._execution_plan_snapshots: dict[
            int, tuple[object, frozenset[str], frozenset[str], tuple[str, ...], object, object, Path]
        ] = {}
        self._consumed_execution_plans: set[int] = set()

    @staticmethod
    def _normalize_request(steps) -> frozenset[str]:
        try:
            values = frozenset(steps)
        except TypeError as error:
            raise TypeError("rebuild steps must be an iterable of strings") from error
        invalid = sorted(repr(value) for value in values if not isinstance(value, str))
        if invalid:
            raise TypeError(
                "rebuild steps must contain only strings: " + ", ".join(invalid)
            )
        if any(not value for value in values):
            raise ValueError("rebuild step identifier cannot be empty")
        return values

    def _validate_request(self, request: frozenset[str]) -> None:
        known_names = {item.name for item in self.plan.steps}
        known_ids = {item.identifier for item in self.plan.steps}
        unknown = sorted(request - known_names - known_ids)
        if unknown:
            raise ValueError("unknown rebuild step(s): " + ", ".join(unknown))
        prepare_ids = {
            item.identifier for item in self.plan.steps
            if item.name == "prepare-workspace"
        }
        if "prepare-workspace" in request or request & prepare_ids:
            raise ValueError(
                "prepare-workspace cannot be re-run: it copies the input ELF into "
                "the workspace local copy and establishes its content identity"
            )

    def _preflight(self, session: WorkspaceSession) -> frozenset[str]:
        known_ids = {item.identifier for item in self.plan.steps}
        prepare_ids = {
            item.identifier for item in self.plan.steps
            if item.name == "prepare-workspace"
        }
        inspection = RebuildInspection(
            stage=session.stage,
            manifest=getattr(session, "published_manifest", None),
            steps=self.plan.steps,
            target_bundle=self.plan.target_bundle,
        )
        additions: set[str] = set()
        for planned in self.plan.steps:
            hook = getattr(planned.definition, "rebuild_preflight", None)
            if hook is None:
                continue
            result = hook(planned.parameters, inspection)
            if not isinstance(result, frozenset):
                raise TypeError(
                    f"{planned.identifier} rebuild preflight must return "
                    "frozenset[str]"
                )
            invalid_types = sorted(
                repr(value) for value in result if not isinstance(value, str)
            )
            if invalid_types:
                raise TypeError(
                    f"{planned.identifier} rebuild preflight returned non-string "
                    "step identifier(s): " + ", ".join(invalid_types)
                )
            unknown = sorted(result - known_ids)
            if unknown:
                raise ValueError(
                    f"{planned.identifier} rebuild preflight returned unknown or "
                    "non-exact step identifier(s): " + ", ".join(unknown)
                )
            forbidden = sorted(result & prepare_ids)
            if forbidden:
                raise ValueError(
                    f"{planned.identifier} rebuild preflight cannot request "
                    "prepare-workspace: " + ", ".join(forbidden)
                )
            additions.update(result)
        return frozenset(additions)

    def _execution_for(
        self, request: frozenset[str], preflight: frozenset[str]
    ) -> tuple[str, ...]:
        invalidated: set[str] = set()
        execution: list[str] = []
        for planned in self.plan.steps:
            if planned.name == "prepare-workspace":
                continue
            definition = planned.definition
            inputs = (
                frozenset()
                if definition is None
                else frozenset(
                    getattr(
                        definition,
                        "rebuild_inputs",
                        set(getattr(definition, "requires", ()))
                        - set(self._SCHEDULING_OUTPUTS),
                    )
                )
            )
            direct = (
                planned.name in request
                or planned.identifier in request
                or planned.identifier in preflight
            )
            impacted = bool(inputs & invalidated)
            required_execution = bool(
                definition is not None and definition.rebuild_execute
            )
            if direct or impacted or required_execution:
                execution.append(planned.identifier)
                if definition is not None:
                    invalidated.update(
                        set(getattr(definition, "provides", ()))
                        - self._SCHEDULING_OUTPUTS
                    )
        return tuple(execution)

    def _compute_execution(
        self, request: frozenset[str], session: WorkspaceSession | None
    ) -> tuple[frozenset[str], tuple[str, ...]]:
        self._validate_request(request)
        preflight = frozenset() if session is None else self._preflight(session)
        return preflight, self._execution_for(request, preflight)

    def make_rebuild_plan(
        self, steps, *, session: WorkspaceSession
    ) -> RebuildExecutionPlan:
        try:
            session.require_open()
            request = self._normalize_request(steps)
            preflight, execution = self._compute_execution(request, session)
            token = RebuildExecutionPlan(
                request=request,
                preflight=preflight,
                execution=execution,
                workflow=self.plan,
                session=session,
                staging=session.stage.resolve(),
            )
            self._issued_execution_plans[id(token)] = token
            self._execution_plan_snapshots[id(token)] = (
                token,
                token.request,
                token.preflight,
                token.execution,
                token.workflow,
                token.session,
                token.staging,
            )
            return token
        except BaseException:
            # A preflight or plan materialization error is discovered before
            # any step executes, but the staging tree belongs to this call.
            session.abort()
            raise

    def rebuild_execution_list(
        self, steps: set[str], *, session: WorkspaceSession | None = None
    ) -> tuple[str, ...]:
        """Compute direct and dependency-propagated rebuild executions."""
        if session is not None:
            return self.make_rebuild_plan(steps, session=session).execution
        request = self._normalize_request(steps)
        return self._compute_execution(request, None)[1]

    def _validate_execution_plan(
        self,
        execution_plan: RebuildExecutionPlan,
        steps,
        session: WorkspaceSession,
    ) -> None:
        session.require_open()
        if not isinstance(execution_plan, RebuildExecutionPlan):
            raise TypeError("prepare requires a RebuildExecutionPlan token")
        issued = self._issued_execution_plans.get(id(execution_plan))
        if issued is not execution_plan:
            raise ValueError("rebuild execution plan was not issued by this pipeline")
        snapshot = self._execution_plan_snapshots.get(id(execution_plan))
        if snapshot is None or snapshot[0] is not execution_plan:
            raise ValueError("rebuild execution plan snapshot is missing")
        if (
            execution_plan.request != snapshot[1]
            or execution_plan.preflight != snapshot[2]
            or execution_plan.execution != snapshot[3]
            or execution_plan.workflow is not snapshot[4]
            or execution_plan.session is not snapshot[5]
            or execution_plan.staging != snapshot[6]
        ):
            raise ValueError("rebuild execution plan contents were modified")
        if id(execution_plan) in self._consumed_execution_plans:
            raise ValueError("rebuild execution plan has already been consumed")
        if execution_plan.workflow is not self.plan:
            raise ValueError("rebuild execution plan belongs to another workflow")
        if execution_plan.session is not session:
            raise ValueError("rebuild execution plan belongs to another session")
        if execution_plan.staging != session.stage.resolve():
            raise ValueError("rebuild execution plan staging directory does not match session")
        request = self._normalize_request(steps)
        if request != execution_plan.request:
            raise ValueError("rebuild execution plan request does not match steps")
        self._validate_request(execution_plan.request)
        known_ids = {item.identifier for item in self.plan.steps}
        if not isinstance(execution_plan.preflight, frozenset):
            raise ValueError("rebuild execution plan preflight set is invalid")
        if any(
            not isinstance(identifier, str) or identifier not in known_ids
            for identifier in execution_plan.preflight
        ):
            raise ValueError("rebuild execution plan contains invalid preflight identifier")
        if any(
            planned.name == "prepare-workspace"
            and planned.identifier in execution_plan.preflight
            for planned in self.plan.steps
        ):
            raise ValueError("rebuild execution plan preflight cannot include prepare-workspace")
        if not isinstance(execution_plan.execution, tuple):
            raise ValueError("rebuild execution plan execution list is invalid")
        expected = self._execution_for(
            execution_plan.request, execution_plan.preflight
        )
        if execution_plan.execution != expected:
            raise ValueError("rebuild execution plan contents were modified")
        self._consumed_execution_plans.add(id(execution_plan))

    def prepare(
        self,
        input_elf: Path,
        *,
        session: WorkspaceSession,
        steps: set[str],
        workspace: str | None = None,
        execution_plan: RebuildExecutionPlan | None = None,
    ) -> Path:
        try:
            source = input_elf.resolve()
            if not source.is_file():
                raise FileNotFoundError(f"input ELF does not exist: {source}")
            if execution_plan is None:
                execution_plan = self.make_rebuild_plan(steps, session=session)
            self._validate_execution_plan(execution_plan, steps, session)
        except BaseException:
            session.abort()
            raise
        try:
            profile = self.plan.profile
            context = AnalysisContext(
                input_elf=source,
                stage=session.stage,
                config=self.plan.base,
                target_os=profile.target_os,
                target_arch=profile.target_arch,
                target_arch_extension=profile.target_arch_extension,
                runtime_scene=profile.runtime_scene,
                runtime_abi=profile.runtime_abi,
                services=self.plan.services,
                target_bundle=self.plan.target_bundle,
                debug_enabled=current_session().enabled,
            )
            # The reopened session owns a staging tree from this point on;
            # failures while reconstructing state or checking capabilities
            # must be cleaned up by the rebuild pipeline as well.
            context = context.put_global("workspace_session", session)
            context = context.put_global("publication_path", session.destination)
            context = context.put_global("modules", self._reconstruct_modules(session, context))
            context = context.put_global("workspace_contributions", ())
            context = context.put_global(
                "capabilities", context.platform.validate_capabilities(context.config)
            )
            execution_set = set(execution_plan.execution)
            # prepare-workspace is intentionally skipped during rebuild, so
            # its target-level publication validators must be re-attached to
            # the new staging session before finalize runs.
            for identifier, validator in self.plan.target_bundle.publication_validators:
                session.register_validator(identifier, validator)
            total = len(self.plan.steps)
            last_use = _last_use_positions(self.plan)
            index = 0
            for planned in self.plan.steps:
                index += 1
                name = planned.name
                if name == "prepare-workspace":
                    context = self._record_contribution(context, planned)
                    continue
                # Steps that must execute during rebuild declare that policy
                # on their definition.  User-requested steps execute too;
                # all remaining steps require an explicit replay callback.
                definition = planned.definition
                if planned.identifier in execution_set:
                    context = self._execute_step(planned, context, index, total)
                else:
                    context = self._replay_step(planned, context)
                context = _release_dead_globals(context, last_use, index)
            return context.require_global("published_workspace")
        except BaseException:
            session.abort()
            raise

    def _reconstruct_modules(self, session: WorkspaceSession, context: AnalysisContext):
        """Rebuild the module list from the Manifest plus a fresh selection.

        The Manifest stays authoritative about *which* modules exist; the
        machine supplies *where* the ones without a payload live.  Both halves
        are required to agree: a module that can no longer be resolved, or one
        whose delivery changed since the Workspace was prepared, means the
        published artifacts describe inputs this machine no longer has, and
        rebuilding from them would bake in the mismatch.
        """

        chosen = select_modules(
            context.input_elf,
            context.platform.dependencies(
                context.input_elf,
                context.config.target_files.library_roots,
            ),
            context.config.scalar_root,
        )
        by_name = {item.selected_path.name: item for item in chosen}
        scalar_root_dir = context.stage / PACKAGE_MODULE_DIR
        modules = []
        for record in session.registry.modules.values():
            item = by_name.get(record.runtime_name)
            if item is None:
                raise ValueError(
                    "module recorded in the Workspace Manifest cannot be "
                    f"resolved from this machine: {record.runtime_name}; "
                    "re-run prepare on the machine that has it"
                )
            packaged = item.delivery == DELIVERY_PACKAGE
            if packaged != (record.selected_kind == "scalar"):
                raise ValueError(
                    "module delivery changed since this Workspace was prepared: "
                    f"{record.runtime_name} is recorded as "
                    f"{record.selected_kind} but now selects {item.delivery}; "
                    "re-run prepare"
                )
            if packaged:
                selected_path = scalar_root_dir / record.runtime_name
                if not selected_path.is_file():
                    raise ValueError(
                        "Workspace is missing a packaged module payload: "
                        f"{record.runtime_name}"
                    )
            else:
                selected_path = item.selected_path
            modules.append(AnalysisModule(
                module_id=record.module_id,
                source=item.source,
                selected_path=selected_path,
                is_scalar=record.selected_kind == "scalar",
                is_main=record.role == "main",
                delivery=item.delivery,
            ))
        session.anchors = tuple(anchor_modules(modules).values())
        return tuple(modules)

    def _record_contribution(self, context: AnalysisContext, planned) -> AnalysisContext:
        contributions = tuple(context.global_results.get("workspace_contributions", ()))
        return context.put_global(
            "workspace_contributions", (*contributions, planned.identifier)
        )

    def _replay_step(self, planned, context: AnalysisContext) -> AnalysisContext:
        definition = planned.definition
        replay = None if definition is None else definition.replay
        if replay is None:
            raise RebuildMissingUpstream(
                f"workflow step {planned.identifier} has no replay callback; "
                "request it for rebuild or provide StepDefinition.replay"
            )
        missing = sorted(
            name for name in definition.requires
            if name not in context.global_results
        )
        if missing:
            raise RebuildMissingUpstream(
                f"{planned.identifier} replay requires missing output(s): "
                + ", ".join(missing)
            )
        updated = replay(planned.parameters, context)
        if not isinstance(updated, AnalysisContext):
            raise TypeError(
                f"workflow step {planned.identifier} replay did not return "
                "AnalysisContext"
            )
        if "workspace_contributions" in definition.provides:
            updated = self._record_contribution(updated, planned)
        missing = sorted(
            name for name in definition.provides
            if name not in updated.global_results
        )
        if missing:
            raise RebuildMissingUpstream(
                f"{planned.identifier} replay did not provide output(s): "
                + ", ".join(missing)
            )
        session = updated.global_results.get("workspace_session")
        if session is not None:
            for identifier, validator in definition.publication_validators:
                session.register_validator(identifier, validator)
        return updated

# Keep the historical exception import path working while the implementation
# lives beside the replay callbacks rather than in the generic engine.
__all__ = [
    "BuildReplayPropertyError", "RebuildMissingUpstream", "RebuildExecutionPlan",
    "RebuildPipeline",
]
