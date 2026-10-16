"""Execute a materialized plan without reading TOML or resolving catalogs."""

from __future__ import annotations

from pathlib import Path

from chimera.preprocess.offline.analysis import AnalysisContext
from chimera.preprocess.offline.analysis.core.monitor import (
    argument,
    current_session,
    local,
    monitored,
    returned,
)
from .plan import ExecutionPlan, PlannedStep


class StepContractError(RuntimeError):
    """A workflow step did not satisfy its declared data contract."""


def _result_keys(context: AnalysisContext) -> list[str]:
    return sorted(context.global_results)


def _last_use_positions(plan: ExecutionPlan) -> dict[str, int]:
    """Map each global result to the last plan position (1-based) requiring it.

    Steps declare their inputs via ``StepDefinition.requires``; once the last
    requirer has executed, the value is dead weight and can be dropped so its
    memory is reclaimed while later steps still run.
    """

    last_use: dict[str, int] = {}
    for position, planned in enumerate(plan.steps, start=1):
        if planned.definition is None:
            continue
        for name in planned.definition.requires:
            last_use[name] = position
    return last_use


def _release_dead_globals(
    context: AnalysisContext,
    last_use: dict[str, int],
    position: int,
) -> AnalysisContext:
    for name, last_position in last_use.items():
        if last_position == position:
            context = context.drop_global(name)
    return context


class PreparePipeline:
    def __init__(self, plan: ExecutionPlan):
        self.plan = plan

    @monitored(
        "pipeline",
        variables=(
            argument("input_elf"),
            argument("workspace"),
            local("source", label="input_elf"),
            returned(label="published_workspace"),
        ),
    )
    def prepare(self, input_elf: Path, *, workspace: str | None = None) -> Path:
        source = input_elf.resolve()
        if not source.is_file():
            raise FileNotFoundError(f"input ELF does not exist: {source}")
        profile = self.plan.profile
        context = AnalysisContext(
            input_elf=source,
            stage=None,
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
        if workspace is not None:
            context = context.put_parameter("requested_workspace", workspace)
        session = None
        try:
            total = len(self.plan.steps)
            last_use = _last_use_positions(self.plan)
            for index, planned in enumerate(self.plan.steps, start=1):
                # Capture a caller-supplied session before invoking the step.
                # If the step fails before it can return a context (for
                # example during capability validation), the pipeline still
                # owns cleanup of that external session.  A session created
                # by the step remains owned by the step's exception path.
                session = context.global_results.get("workspace_session", session)
                context = self._execute_step(planned, context, index, total)
                # Keep a local owner for cleanup even if liveness-based global
                # release drops ``workspace_session`` before a later step
                # fails (for example in an invalid post-finalizer workflow).
                session = context.global_results.get("workspace_session", session)
                context = _release_dead_globals(context, last_use, index)
            return context.require_global("published_workspace")
        except BaseException:
            if session is not None:
                session.abort()
            raise

    @monitored(
        "step",
        variables=(
            argument("planned", label="id", path=("identifier",)),
            argument("planned", label="name", path=("name",)),
            argument("planned", label="parameters", path=("parameters",)),
            argument("index"),
            argument("total"),
            argument("context", label="results_before", transform=_result_keys),
            returned(label="results_after", transform=_result_keys),
        ),
    )
    def _execute_step(
        self,
        planned: PlannedStep,
        context: AnalysisContext,
        index: int,
        total: int,
    ) -> AnalysisContext:
        definition = planned.definition
        before = dict(context.global_results)
        # A step may create a session and then return a context which fails a
        # postcondition or publication-validator registration below.  Keep the
        # returned context long enough to abort that newly-created session; the
        # outer pipeline remains responsible for sessions supplied by callers.
        supplied_session = before.get("workspace_session")
        updated = None
        try:
            if definition is not None:
                missing = sorted(
                    name for name in definition.requires
                    if name not in before
                )
                if missing:
                    raise StepContractError(
                        f"{planned.identifier} requires missing output(s): "
                        + ", ".join(missing)
                    )
            updated = planned.implementation.run(context)
            if not isinstance(updated, AnalysisContext):
                raise TypeError(
                    f"workflow step {planned.identifier} did not return AnalysisContext"
                )
            if definition is not None:
                if "workspace_contributions" in definition.provides:
                    contributions = tuple(
                        updated.global_results.get("workspace_contributions", ())
                    )
                    updated = updated.put_global(
                        "workspace_contributions",
                        (*contributions, planned.identifier),
                    )
                missing = sorted(
                    name for name in definition.provides
                    if name not in updated.global_results
                )
                if missing:
                    raise StepContractError(
                        f"{planned.identifier} did not provide output(s): "
                        + ", ".join(missing)
                    )
                if definition.postcondition is not None:
                    try:
                        definition.postcondition(before, updated.global_results)
                    except (TypeError, ValueError) as error:
                        raise StepContractError(
                            f"{planned.identifier} postcondition failed: {error}"
                        ) from error
                session = updated.global_results.get("workspace_session")
                if session is not None:
                    if "workspace_session" in definition.provides:
                        # target_bundle is always supplied by build_execution_plan,
                        # so publication validators are unconditionally available.
                        for identifier, validator in (
                            self.plan.target_bundle.publication_validators
                        ):
                            session.register_validator(identifier, validator)
                    for identifier, validator in definition.publication_validators:
                        session.register_validator(identifier, validator)
            return updated
        except BaseException:
            if supplied_session is None and isinstance(updated, AnalysisContext):
                created_session = updated.global_results.get("workspace_session")
                if created_session is not None:
                    created_session.abort()
            raise
