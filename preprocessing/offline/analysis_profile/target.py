"""Repository-internal target bundle composition."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re
from types import MappingProxyType
from typing import Any, Callable, Mapping

from chimera.preprocess.offline.analysis import AnalysisServices
from chimera.preprocess.offline.analysis.arch.riscv import RiscvServices
from chimera.preprocess.offline.analysis.arch.riscv.rvv import (
    RvvArtifactEmitter,
    RvvServices,
)
from chimera.preprocess.offline.analysis.platform.linux import LinuxServices
from chimera.preprocess.offline.analysis.toolchain import build_toolchain_services
from chimera.preprocess.offline.config import TranslationEndpoint
from chimera.runtime.manifest import parse_property_value
from chimera.preprocess.offline.analysis.translation.model import TranslationProductionSpec
from chimera.runtime.scene_contracts import (
    RuntimeArtifactContract,
)
from chimera.runtime.scene_contracts.linux_riscv64_rvv_v1 import (
    RVV_RUNTIME_ARTIFACT_CONTRACT,
)


SUPPORTED_VLEN_ROUTES = frozenset({
    (1024, 256),
    (256, 1024),
})
_RVV_SPECIFICATION = re.compile(r"^vlen=([1-9][0-9]*)$")


def rvv_vlen(endpoint: TranslationEndpoint) -> int:
    if endpoint.architecture != "riscv64" or endpoint.extension != "rvv":
        raise ValueError(
            "current RVV target accepts only riscv64;rvv translation endpoints: "
            f"{endpoint.canonical}"
        )
    match = _RVV_SPECIFICATION.fullmatch(endpoint.specification)
    if match is None:
        raise ValueError(
            "current RVV target requires canonical specification vlen=<positive-u64>: "
            f"{endpoint.canonical}"
        )
    value = int(match.group(1))
    if value > (1 << 64) - 1:
        raise ValueError(f"translation endpoint VLEN exceeds u64: {endpoint.canonical}")
    return value


def validate_rvv_route(
    source: TranslationEndpoint,
    target: TranslationEndpoint,
) -> tuple[int, int]:
    source_vlen = rvv_vlen(source)
    target_vlen = rvv_vlen(target)
    if (source_vlen, target_vlen) not in SUPPORTED_VLEN_ROUTES:
        detail = " (endpoints must be distinct)" if source == target else ""
        raise ValueError(
            "unsupported RVV translation route"
            f"{detail}: {source.canonical} -> {target.canonical}"
        )
    return source_vlen, target_vlen


class RvvTranslationSemantics:
    """RVV scene adapter for endpoint, manifest and file naming semantics."""

    def validate_route(self, source: TranslationEndpoint, target: TranslationEndpoint):
        return validate_rvv_route(source, target)

    def production_spec(
        self,
        module_id: str,
        source: TranslationEndpoint,
        target: TranslationEndpoint,
        _stage,
    ) -> TranslationProductionSpec:
        source_vlen, target_vlen = validate_rvv_route(source, target)
        suffix = f"vlen{source_vlen}_to_vlen{target_vlen}"
        artifact_suffix = f"vlen{source_vlen}-to-vlen{target_vlen}"
        identifier = f"{module_id}_{suffix}"
        return TranslationProductionSpec(
            variant_id=identifier,
            artifact_id=f"translated-code-{module_id}-{artifact_suffix}",
            symbol_namespace=identifier,
            input_properties={
                "architecture": source.architecture,
                "architecture_extension": source.extension,
                "vector_vlen_bits": source_vlen,
            },
            output_properties={
                "architecture": target.architecture,
                "architecture_extension": target.extension,
                "vector_vlen_bits": target_vlen,
            },
            assembly_path=Path(f"generated/{module_id}.{suffix}.translated.S"),
            translated_dump_path=Path(f"dump/{module_id}.{suffix}.translated.dump"),
            provenance_path=Path(f"generated/{identifier}.provenance.S"),
            library_path=Path(f"artifacts/libtranslated_{module_id}_{suffix}.so"),
            unpatched_library_path=Path(
                f"generated/unpatched/libtranslated_{module_id}_{suffix}.so"
            ),
            unpatched_library_sha256_path=Path(
                f"generated/unpatched/libtranslated_{module_id}_{suffix}.so.sha256"
            ),
            offset_map_assembly_path=Path(f"generated/{module_id}.{suffix}.maps.S"),
            offset_map_document_path=Path(f"generated/{module_id}.{suffix}.maps.json"),
            offset_map_library_path=Path(f"artifacts/liboffsetmap_{module_id}_{suffix}.so"),
            offset_map_artifact_id=f"offset-map-{module_id}-{artifact_suffix}-elf",
            suffix=suffix,
            input_property_kinds={
                "architecture": "token",
                "architecture_extension": "token",
                "vector_vlen_bits": "u64",
            },
            output_property_kinds={
                "architecture": "token",
                "architecture_extension": "token",
                "vector_vlen_bits": "u64",
            },
        )

    def endpoint_from_properties(self, registry, variant_id: str, side: str):
        values = {}
        for name in ("architecture", "architecture_extension", "vector_vlen_bits"):
            record = registry.variant_properties.get((variant_id, side, name))
            if record is None:
                raise ValueError(
                    f"variant {variant_id} lacks {side}.{name} property"
                )
            values[name] = parse_property_value(record.value_kind, record.value)
        return TranslationEndpoint(
            values["architecture"],
            values["architecture_extension"],
            f"vlen={values['vector_vlen_bits']}",
        )


class RvvTrapPatchServices:
    """RVV scene's size-preserving trap encoding."""

    max_instruction_bytes = 4

    def trap_for_instruction(self, instruction_bytes: bytes) -> tuple[int, bytes]:
        if len(instruction_bytes) < 2:
            raise ValueError("cannot classify a truncated instruction slot")
        halfword = int.from_bytes(instruction_bytes[:2], "little")
        if halfword & 0x3 != 0x3:
            return 2, (0x9002).to_bytes(2, "little")
        # RISC-V encodings with bits[4:0] all set are 48-bit or longer.  The
        # RVV scene only supports 16/32-bit slots and must fail explicitly
        # instead of silently overwriting the first four bytes.
        if halfword & 0x1F == 0x1F:
            raise ValueError("RVV trap patch does not support long instructions")
        if len(instruction_bytes) < 4:
            raise ValueError("cannot classify a truncated 32-bit instruction")
        return 4, (0x00100073).to_bytes(4, "little")


@dataclass(frozen=True, order=True)
class TargetKey:
    target_os: str
    target_arch: str
    target_arch_extension: str
    runtime_scene: str

    @classmethod
    def from_profile(cls, profile) -> "TargetKey":
        return cls(
            profile.target_os,
            profile.target_arch,
            profile.target_arch_extension,
            profile.runtime_scene,
        )


@dataclass(frozen=True)
class RuntimeBuildSpecification:
    system_name: str
    system_processor: str
    elf_machine: int
    abi: int
    artifact_contract: RuntimeArtifactContract | None = None


@dataclass(frozen=True)
class VariantPropertySpec:
    name: str
    value_kind: str
    required_sides: frozenset[str]


@dataclass(frozen=True)
class PrepareTargetBundle:
    key: TargetKey
    architecture_factory: Callable[[Any], Any]
    extension_factory: Callable[[], Any]
    platform_factory: Callable[[], Any]
    toolchain_factory: Callable[[Any], Any]
    step_definitions: tuple[Any, ...]
    variant_property_schema: Mapping[str, VariantPropertySpec]
    runtime: RuntimeBuildSpecification
    plan_completion_requirements: frozenset[str]
    publication_validators: tuple[tuple[str, Callable[..., None]], ...] = ()
    translation_semantics: Any | None = None
    trap_patch_services: Any | None = None

    def create_services(self, config) -> AnalysisServices:
        extension = self.extension_factory()
        return AnalysisServices(
            architecture=self.architecture_factory(extension),
            platform=self.platform_factory(),
            toolchain=self.toolchain_factory(config),
        )


class TargetCatalog:
    def __init__(self, bundles=()) -> None:
        self._bundles: dict[TargetKey, PrepareTargetBundle] = {}
        for bundle in bundles:
            self.register(bundle)

    def register(self, bundle: PrepareTargetBundle) -> None:
        if bundle.key in self._bundles:
            raise ValueError(f"duplicate target bundle: {bundle.key}")
        self._bundles[bundle.key] = bundle

    def select(self, key: TargetKey) -> PrepareTargetBundle:
        try:
            return self._bundles[key]
        except KeyError as error:
            raise ValueError(
                "unsupported target bundle: "
                f"{key.target_os}/{key.target_arch}/"
                f"{key.target_arch_extension}/{key.runtime_scene}"
            ) from error

    def __getitem__(self, key: TargetKey) -> PrepareTargetBundle:
        return self.select(key)

    def bundles(self) -> Mapping[TargetKey, PrepareTargetBundle]:
        return MappingProxyType(dict(self._bundles))


def validate_linux_riscv64_rvv_publication(manifest) -> None:
    expected = TargetKey("linux", "riscv64", "rvv", "linux_riscv64_rvv_v1")
    actual = TargetKey(
        manifest.target_os,
        manifest.target_arch,
        manifest.target_arch_extension,
        manifest.runtime_scene,
    )
    if actual != expected:
        raise ValueError(f"scene/target mismatch: expected {expected}, got {actual}")

    def artifacts(owner_kind, owner_id, capability, representation):
        return [
            item for item in manifest.artifacts
            if (
                item.owner_kind, item.owner_id,
                item.capability, item.representation,
            ) == (owner_kind, owner_id, capability, representation)
        ]

    runtime = artifacts("workspace", "root", "runtime", "elf")
    if len(runtime) != 1 or runtime[0].abi != 1:
        raise ValueError("workspace requires exactly one runtime v1 ELF artifact")
    variant_modules = {variant.module_id for variant in manifest.variants}
    for module in manifest.modules:
        if module.module_id not in variant_modules:
            raise ValueError(
                f"module {module.module_id} requires at least one translation variant"
            )
        safety_elf = artifacts("module", module.module_id, "safety", "elf")
        if safety_elf and (len(safety_elf) != 1 or safety_elf[0].abi != 1):
            raise ValueError(
                f"module {module.module_id} has invalid safety v1 artifacts"
            )
    selectors: set[tuple[str, int]] = set()
    for variant in manifest.variants:
        expected_kinds = {
            "architecture": "token",
            "architecture_extension": "token",
            "vector_vlen_bits": "u64",
        }
        records = {
            (side, name): manifest.property_record(
                variant.variant_id, side, name
            )
            for side in ("input", "output")
            for name in expected_kinds
        }
        for (side, name), record in records.items():
            if record.value_kind != expected_kinds[name]:
                raise ValueError(
                    f"variant {variant.variant_id} property {side}.{name} "
                    f"must have kind {expected_kinds[name]}"
                )
        values = {
            key: parse_property_value(record.value_kind, record.value)
            for key, record in records.items()
        }
        source_arch = values[("input", "architecture")]
        source_extension = values[("input", "architecture_extension")]
        source = values[("input", "vector_vlen_bits")]
        target_arch = values[("output", "architecture")]
        target_extension = values[("output", "architecture_extension")]
        target = values[("output", "vector_vlen_bits")]
        if (
            source_arch != "riscv64" or target_arch != "riscv64"
            or source_extension != "rvv" or target_extension != "rvv"
            or not isinstance(source, int) or isinstance(source, bool) or source <= 0
            or not isinstance(target, int) or isinstance(target, bool) or target <= 0
        ):
            raise ValueError(
                f"variant {variant.variant_id} requires complete riscv64/rvv "
                "endpoint properties with positive VLEN values"
            )
        validate_rvv_route(
            TranslationEndpoint(source_arch, source_extension, f"vlen={source}"),
            TranslationEndpoint(target_arch, target_extension, f"vlen={target}"),
        )
        selector = (variant.module_id, source)
        if selector in selectors:
            raise ValueError(f"duplicate module input selector: {selector}")
        selectors.add(selector)
        translated = artifacts(
            "variant", variant.variant_id, "translated-code", "elf"
        )
        offset_map = artifacts(
            "variant", variant.variant_id, "offset-map", "elf"
        )
        if len(translated) != 1 or translated[0].abi != 1:
            raise ValueError(
                f"variant {variant.variant_id} requires one translated-code v1 ELF"
            )
        if len(offset_map) != 1 or offset_map[0].abi != 1:
            raise ValueError(
                f"variant {variant.variant_id} requires one offset-map v1 ELF"
            )


def current_target_bundle() -> PrepareTargetBundle:
    from .registry import rvv_step_definitions

    property_specs = (
        VariantPropertySpec(
            name="architecture", value_kind="token",
            required_sides=frozenset({"input", "output"}),
        ),
        VariantPropertySpec(
            name="architecture_extension", value_kind="token",
            required_sides=frozenset({"input", "output"}),
        ),
        VariantPropertySpec(
            name="vector_vlen_bits", value_kind="u64",
            required_sides=frozenset({"input", "output"}),
        ),
    )
    key = TargetKey("linux", "riscv64", "rvv", "linux_riscv64_rvv_v1")
    translation_semantics = RvvTranslationSemantics()
    trap_patch_services = RvvTrapPatchServices()
    artifact_emitter = RvvArtifactEmitter()
    return PrepareTargetBundle(
        key=key,
        architecture_factory=RiscvServices,
        extension_factory=RvvServices,
        platform_factory=LinuxServices,
        toolchain_factory=lambda config: build_toolchain_services(
            config,
            artifact_emitter=artifact_emitter,
            linker_flags=("-Wl,--relax",),
        ),
        step_definitions=rvv_step_definitions(
            translation_semantics=translation_semantics
        ),
        variant_property_schema=MappingProxyType({
            specification.name: specification for specification in property_specs
        }),
        runtime=RuntimeBuildSpecification(
            "Linux", "riscv64", 243, 1,
            artifact_contract=RVV_RUNTIME_ARTIFACT_CONTRACT,
        ),
        plan_completion_requirements=frozenset({
            "modules", "runtime_artifact", "translations", "offset_maps"
        }),
        translation_semantics=translation_semantics,
        trap_patch_services=trap_patch_services,
        publication_validators=((
            "scene.linux_riscv64_rvv_v1.topology",
            validate_linux_riscv64_rvv_publication,
        ),),
    )


def registered_target_catalog() -> TargetCatalog:
    return TargetCatalog((current_target_bundle(),))


__all__ = [
    "PrepareTargetBundle",
    "RuntimeBuildSpecification",
    "TargetCatalog",
    "TargetKey",
    "RvvTranslationSemantics",
    "RvvTrapPatchServices",
    "VariantPropertySpec",
    "SUPPORTED_VLEN_ROUTES",
    "current_target_bundle",
    "registered_target_catalog",
    "rvv_vlen",
    "validate_rvv_route",
    "validate_linux_riscv64_rvv_publication",
]
