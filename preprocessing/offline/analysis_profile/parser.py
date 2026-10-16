"""Build an executable plan from already parsed configuration models."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from chimera.preprocess.offline.analysis.core.workspace import WorkspaceRepository
from chimera.preprocess.offline.analysis.core.monitor import argument, monitored, returned
from chimera.preprocess.offline.config import ChimeraConfiguration
from .plan import ExecutionPlan, PlannedStep, immutable_parameters
from .registry import registered_step_catalog
from .target import TargetKey, registered_target_catalog


@dataclass(frozen=True)
class ResolvedWorkflowStep:
    """A normalized workflow declaration without an instantiated producer."""

    identifier: str
    name: str
    parameters: Mapping[str, Any]
    definition: object


def _configuration_summary(configuration: ChimeraConfiguration) -> dict[str, object]:
    base = configuration.base
    profile = configuration.profile
    return {
        "profile": {"name": profile.name, "source": configuration.source},
        "target": {
            "os": profile.target_os,
            "arch": profile.target_arch,
            "extension": profile.target_arch_extension,
            "runtime_scene": profile.runtime_scene,
        },
        "abi": {"runtime": profile.runtime_abi},
        "roots": {
            "workspace": base.workspace_root,
            "scalar": base.scalar_root,
            "data": base.data_root,
        },
        "translator_routes": [
            {
                "source": binding.source.canonical,
                "target": binding.target.canonical,
            }
            for binding in base.translators
        ],
        "tools": base.tools,
    }


def _plan_summary(plan: ExecutionPlan) -> list[dict[str, object]]:
    return [
        {"id": item.identifier, "name": item.name, "parameters": item.parameters}
        for item in plan.steps
    ]


def resolve_workflow_steps(
    configuration: ChimeraConfiguration,
) -> tuple[object, tuple[ResolvedWorkflowStep, ...]]:
    """Resolve and validate workflow declarations without creating services."""
    declarations = configuration.profile.workflow.steps
    if not declarations:
        raise ValueError(
            "the selected Profile has no prepare workflow; provide a complete --profile"
        )
    target_bundle = registered_target_catalog().select(
        TargetKey.from_profile(configuration.profile)
    )
    if configuration.profile.runtime_abi != target_bundle.runtime.abi:
        raise ValueError(
            "runtime ABI mismatch: "
            f"profile={configuration.profile.runtime_abi}, "
            f"bundle={target_bundle.runtime.abi}"
        )
    catalog = registered_step_catalog(target_bundle)
    seen: set[str] = set()
    resolved: list[ResolvedWorkflowStep] = []
    declarations_by_step: dict[str, list[Mapping[str, Any]]] = {}
    for declaration in declarations:
        try:
            definition = catalog[declaration.step]
        except KeyError as error:
            raise ValueError(
                f"unknown workflow step {declaration.step!r}; legacy direction "
                "pseudo-steps and public safety substeps are unsupported, and "
                "translate must carry source/target endpoints"
            ) from error
        parameters = definition.normalize_parameters(declaration.parameters)
        if definition.name in seen and not definition.repeatable:
            raise ValueError(f"workflow step may not repeat: {definition.name}")
        identifier = f"{len(resolved) + 1:03d}:{definition.name}"
        resolved.append(ResolvedWorkflowStep(identifier, definition.name, parameters, definition))
        declarations_by_step.setdefault(definition.name, []).append(parameters)
        seen.add(definition.name)

    for name, parameters in declarations_by_step.items():
        validator = catalog[name].declaration_validator
        if validator is not None:
            validator(tuple(parameters))

    producer_positions: dict[str, list[int]] = {}
    for position, step in enumerate(resolved):
        for output in step.definition.provides:
            producer_positions.setdefault(output, []).append(position)
    for position, step in enumerate(resolved):
        for required in sorted(step.definition.requires):
            producers = producer_positions.get(required, [])
            if not producers:
                raise ValueError(
                    f"unsatisfied input for {step.name}: {required!r} has no producer"
                )
            later = [index + 1 for index in producers if index >= position]
            if later:
                raise ValueError(
                    f"unsatisfied input for {step.name}: {required!r} "
                    f"has later producer(s) at workflow position(s) {later}"
                )
    if not producer_positions.get("published_workspace"):
        raise ValueError("workflow does not provide published_workspace")
    return target_bundle, tuple(resolved)


@monitored(
    "plan",
    variables=(
        argument("configuration", label="configuration", transform=_configuration_summary),
        returned(label="steps", transform=_plan_summary),
    ),
)
def build_execution_plan(configuration: ChimeraConfiguration) -> ExecutionPlan:
    target_bundle, resolved = resolve_workflow_steps(configuration)
    services = target_bundle.create_services(configuration.base)
    repository = WorkspaceRepository(configuration.base.workspace_root)

    planned: list[PlannedStep] = []
    for step in resolved:
        implementation = step.definition.factory(step.parameters, configuration, repository)
        planned.append(
            PlannedStep(
                step.identifier,
                step.name,
                implementation,
                immutable_parameters(step.parameters),
                step.definition,
            )
        )
    return ExecutionPlan(configuration, services, tuple(planned), target_bundle)
