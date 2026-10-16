"""Composable workflow-step catalog and current target composition root."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Callable

from chimera.preprocess.offline.analysis.build_runtime import BuildRuntimeStep
from chimera.preprocess.offline.analysis.disassemble import DisassembleStep
from chimera.preprocess.offline.analysis.finalize_workspace import FinalizeWorkspaceStep
from chimera.preprocess.offline.analysis.offsetmap import OffsetMapStep
from chimera.preprocess.offline.analysis.prepare_workspace import PrepareWorkspaceStep
from chimera.preprocess.offline.analysis.program_model import BuildProgramModelStep
from chimera.preprocess.offline.analysis.safety import SafetyStep
from chimera.preprocess.offline.analysis.safety.external_leaf import normalize_leaf_contracts
from chimera.preprocess.offline.analysis.safety.stack_liveness.scope import (
    CONSERVATIVE as CONSERVATIVE_UNKNOWN_STACK_SIZE_POLICY,
    normalize_unknown_stack_size_policy,
)
from chimera.preprocess.offline.analysis.safepoint_patch import (
    PatchSafepointsStep, check_unpatched_productions,
)
from chimera.preprocess.offline.analysis.translation import TranslationStep
from chimera.preprocess.offline.config import TranslationEndpoint
from .replay import (
    replay_build_runtime,
    replay_disassemble,
    replay_offset_map,
    replay_program_model,
    replay_safety,
    replay_translate,
)


StepFactory = Callable[[Mapping[str, Any], Any, Any], Any]
ParameterNormalizer = Callable[[Any], Any]
DeclarationValidator = Callable[[tuple[Mapping[str, Any], ...]], None]
Postcondition = Callable[[Mapping[str, Any], Mapping[str, Any]], None]
PublicationValidator = Callable[[Any], None]
ParameterValidator = Callable[[Mapping[str, Any]], None]
ReplayCallback = Callable[[Mapping[str, Any], Any], Any]
RebuildPreflight = Callable[[Mapping[str, Any], Any], frozenset[str]]
BinaryCheckFactory = Callable[[Mapping[str, Any]], Any]


_MISSING = object()


def _safety_binary_check_factory(parameters):
    """Build the Safety preflight request without importing it at module load."""
    from chimera.check_elf import safety_binary_check_request

    return safety_binary_check_request(parameters)


def _rvv_unpatched_productions(inspection):
    """Enumerate built-in RVV translation declarations for patch preflight.

    This adapter is composition-root code: it understands how the current
    workflow names and parameterizes translation declarations, while the
    generic checker remains independent of those details.
    """
    bundle = inspection.target_bundle
    semantics = getattr(bundle, "translation_semantics", None)
    if semantics is None or not callable(getattr(semantics, "production_spec", None)):
        return
    if getattr(bundle, "trap_patch_services", None) is None:
        return
    modules = tuple(getattr(getattr(inspection, "manifest", None), "modules", ()))
    for planned in inspection.steps:
        if planned.name != "translate":
            continue
        source = planned.parameters.get("source")
        target = planned.parameters.get("target")
        if source is None or target is None:
            continue
        for module in modules:
            yield (
                planned.identifier,
                semantics.production_spec(
                    module.module_id, source, target, inspection.stage
                ),
            )


def _rvv_unpatched_copy_preflight(_parameters, inspection) -> frozenset[str]:
    return check_unpatched_productions(inspection, _rvv_unpatched_productions)


@dataclass(frozen=True)
class ParameterSpec:
    expected_type: type
    default: Any = _MISSING
    normalize: ParameterNormalizer | None = None

    @property
    def required(self) -> bool:
        return self.default is _MISSING

    def resolve(self, name: str, values: Mapping[str, Any]) -> Any:
        supplied = name in values
        if not supplied:
            if self.required:
                raise ValueError(f"missing parameter: {name}")
            value = self.default
        else:
            value = values[name]
        if not isinstance(value, self.expected_type) or (
            self.expected_type is int and isinstance(value, bool)
        ):
            raise TypeError(f"{name} must be {self.expected_type.__name__}")
        return self.normalize(value) if self.normalize is not None else value


@dataclass(frozen=True)
class StepDefinition:
    name: str
    parameters: Mapping[str, ParameterSpec]
    requires: frozenset[str]
    provides: frozenset[str]
    repeatable: bool
    factory: StepFactory
    declaration_validator: DeclarationValidator | None = None
    postcondition: Postcondition | None = None
    publication_validators: tuple[tuple[str, PublicationValidator], ...] = ()
    parameter_validator: ParameterValidator | None = None
    replay: ReplayCallback | None = None
    rebuild_execute: bool = False
    rebuild_preflight: RebuildPreflight | None = None
    # Optional binary preflight declaration.  The factory receives normalized
    # step parameters and returns a workflow-level check request; it is used by
    # check-elf without instantiating or running the production step.
    binary_check_factory: BinaryCheckFactory | None = None
    # Inputs whose contents can change this step's products.  Scheduling-only
    # globals are excluded from the default so rebuild invalidation follows
    # data dependencies rather than session bookkeeping.
    rebuild_inputs: frozenset[str] | None = None

    def __post_init__(self) -> None:
        if self.rebuild_inputs is None:
            excluded = frozenset({
                "workspace_session", "workspace_contributions",
                "capabilities",
            })
            value = frozenset(self.requires) - excluded
        else:
            value = frozenset(self.rebuild_inputs)
        object.__setattr__(self, "rebuild_inputs", value)

    def normalize_parameters(
        self, values: Mapping[str, Any]
    ) -> Mapping[str, Any]:
        if self.parameter_validator is not None:
            self.parameter_validator(values)
        unknown = sorted(set(values) - set(self.parameters))
        if unknown:
            raise ValueError(
                f"invalid parameters for {self.name}: unknown="
                + ",".join(unknown)
            )
        normalized: dict[str, Any] = {}
        for name, spec in self.parameters.items():
            try:
                normalized[name] = spec.resolve(name, values)
            except (TypeError, ValueError) as error:
                raise type(error)(f"{self.name}.{error}") from error
        return MappingProxyType(normalized)


class StepCatalog:
    def __init__(self, definitions=()) -> None:
        self._definitions: dict[str, StepDefinition] = {}
        for definition in definitions:
            self.register(definition)

    def register(self, definition: StepDefinition) -> None:
        if definition.name in self._definitions:
            raise ValueError(f"duplicate workflow step: {definition.name}")
        self._definitions[definition.name] = definition

    def extend(self, definitions) -> None:
        for definition in definitions:
            self.register(definition)

    def __getitem__(self, name: str) -> StepDefinition:
        return self._definitions[name]

    def definitions(self) -> Mapping[str, StepDefinition]:
        return MappingProxyType(dict(self._definitions))


def _simple(step_type):
    return lambda _parameters, _configuration, _repository: step_type()


def _translation_declarations(
    declarations: tuple[Mapping[str, Any], ...],
    semantics=None,
) -> None:
    sources: dict[TranslationEndpoint, TranslationEndpoint] = {}
    for parameters in declarations:
        source = parameters["source"]
        target = parameters["target"]
        if source in sources:
            raise ValueError(
                f"source endpoint {source.canonical} is declared more than once "
                f"({sources[source].canonical} and {target.canonical})"
            )
        if semantics is not None:
            semantics.validate_route(source, target)
        sources[source] = target


def _normalize_endpoint(value: object) -> TranslationEndpoint:
    endpoint = TranslationEndpoint.parse(value, field="translation endpoint")
    return endpoint


def _reject_legacy_translation_parameters(values: Mapping[str, Any]) -> None:
    legacy = sorted(set(values) & {"source_vlen_bits", "target_vlen_bits"})
    if legacy:
        raise ValueError(
            "legacy translate parameter(s) " + ", ".join(legacy)
            + " are unsupported; declare a matching source/target endpoint "
            "route instead"
        )


def _translation_step(parameters, configuration, _repository, semantics=None):
    source = parameters["source"]
    target = parameters["target"]
    return TranslationStep(
        source_endpoint=source,
        target_endpoint=target,
        translator_path=configuration.base.translator_for(source, target),
        semantics=semantics,
    )


def _translations_grew(before, after) -> None:
    old = before.get("translations", {})
    new = after.get("translations", {})
    if len(new) <= len(old):
        raise ValueError("translate did not add a translation result")


def _safety_publication(manifest) -> None:
    owners = {
        artifact.owner_id
        for artifact in manifest.artifacts
        if artifact.owner_kind == "module" and artifact.capability == "safety"
    }
    if not owners:
        raise ValueError("safety step requires at least one published artifact")
    for module_id in owners:
        count = sum(
            artifact.owner_kind == "module"
            and artifact.owner_id == module_id
            and artifact.capability == "safety"
            and artifact.representation == "elf"
            and artifact.abi == 1
            for artifact in manifest.artifacts
        )
        if count != 1:
            raise ValueError(
                f"module {module_id} requires exactly one safety v1 ELF artifact"
            )


def common_step_definitions(
    completion_requirements: frozenset[str],
) -> tuple[StepDefinition, ...]:
    empty = frozenset()
    contribution = frozenset({"workspace_contributions"})
    return (
        StepDefinition(
            "prepare-workspace", {}, empty,
            frozenset({"workspace_session", "modules"}) | contribution, False,
            lambda _p, _c, repository: PrepareWorkspaceStep(repository),
        ),
        StepDefinition(
            "build-runtime", {}, frozenset({"workspace_session"}),
            frozenset({"runtime_artifact"}) | contribution, False, _simple(BuildRuntimeStep),
            replay=replay_build_runtime,
        ),
        StepDefinition(
            "disassemble", {}, frozenset({"modules"}),
            frozenset({"native_dumps"}) | contribution, False, _simple(DisassembleStep),
            replay=replay_disassemble,
        ),
        StepDefinition(
            "build-program-model", {}, frozenset({"native_dumps"}),
            frozenset({"programs"}) | contribution, False, _simple(BuildProgramModelStep),
            replay=replay_program_model,
        ),
        StepDefinition(
            "finalize-workspace", {},
            frozenset({"workspace_session", "workspace_contributions"})
            | completion_requirements,
            frozenset({"published_workspace"}), False,
            _simple(FinalizeWorkspaceStep),
            rebuild_execute=True,
        ),
    )


def rvv_step_definitions(*, translation_semantics=None) -> tuple[StepDefinition, ...]:
    """The RVV target bundle's step definitions.

    Public so callers can read the RVV bundle's facts directly (e.g. tests
    inspecting a specific step's parameter spec). Not a default fallback:
    ``registered_step_catalog`` always consumes whatever the supplied
    bundle exposes.
    """
    if translation_semantics is None:
        # Lazy import keeps this catalog module target-neutral.  The default
        # exists only for compatibility callers that explicitly request the
        # RVV catalog; a target bundle should inject its own semantics.
        from .target import RvvTranslationSemantics
        translation_semantics = RvvTranslationSemantics()
    contribution = frozenset({"workspace_contributions"})
    return (
        StepDefinition(
            "safety",
            {
                "min_vlen_bits": ParameterSpec(int),
                "compiler_metadata": ParameterSpec(
                    Sequence,
                    default=(),
                    normalize=lambda values: tuple(values),
                ),
                "unknown_stack_size_policy": ParameterSpec(
                    str,
                    default=CONSERVATIVE_UNKNOWN_STACK_SIZE_POLICY,
                    normalize=normalize_unknown_stack_size_policy,
                ),
                "external_scalar_leaf_contracts": ParameterSpec(
                    Sequence, default=(), normalize=normalize_leaf_contracts),
            },
            frozenset({"modules", "programs"}),
            frozenset({"safety_analysis"}) | contribution,
            False,
            lambda p, _configuration, _repository: SafetyStep(
                min_vlen_bits=p["min_vlen_bits"],
                compiler_metadata=p["compiler_metadata"],
                unknown_stack_size_policy=p["unknown_stack_size_policy"],
                external_scalar_leaf_contracts=p["external_scalar_leaf_contracts"],
            ),
            publication_validators=(("step.safety.v1", _safety_publication),),
            replay=replay_safety,
            binary_check_factory=lambda parameters: _safety_binary_check_factory(parameters),
        ),
        StepDefinition(
            "translate",
            {
                "source": ParameterSpec(str, normalize=_normalize_endpoint),
                "target": ParameterSpec(str, normalize=_normalize_endpoint),
            },
            frozenset({"modules", "native_dumps"}),
            frozenset({"translations"}) | contribution,
            True,
            lambda p, c, r: _translation_step(
                p, c, r, translation_semantics
            ),
            declaration_validator=lambda declarations: _translation_declarations(
                declarations, translation_semantics
            ),
            postcondition=_translations_grew,
            parameter_validator=_reject_legacy_translation_parameters,
            replay=replay_translate,
        ),
        StepDefinition(
            "offset-map", {}, frozenset({"modules", "translations"}),
            frozenset({"offset_maps"}) | contribution, False, _simple(OffsetMapStep),
            replay=replay_offset_map,
        ),
        StepDefinition(
            "patch-safepoints", {},
            frozenset({
                "modules", "workspace_session",
                "safety_analysis", "translations", "offset_maps",
            }),
            frozenset({"patched_safepoints"}) | contribution,
            False, _simple(PatchSafepointsStep),
            rebuild_execute=True,
            rebuild_preflight=_rvv_unpatched_copy_preflight,
        ),
    )


def registered_step_catalog(target_bundle) -> StepCatalog:
    if target_bundle is None:
        raise ValueError(
            "registered_step_catalog requires an explicit target_bundle; "
            "the legacy RVV-only default has been removed"
        )
    catalog = StepCatalog(
        common_step_definitions(target_bundle.plan_completion_requirements)
    )
    catalog.extend(target_bundle.step_definitions)
    return catalog


def registered_step_definitions(*, target_bundle) -> Mapping[str, StepDefinition]:
    if target_bundle is None:
        raise ValueError(
            "registered_step_definitions requires an explicit target_bundle; "
            "the legacy RVV-only default has been removed"
        )
    return registered_step_catalog(target_bundle).definitions()


__all__ = [
    "BinaryCheckFactory", "ParameterSpec", "StepCatalog", "StepDefinition",
    "common_step_definitions", "registered_step_catalog",
    "registered_step_definitions", "rvv_step_definitions",
]
