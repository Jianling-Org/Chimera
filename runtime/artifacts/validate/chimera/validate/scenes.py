"""Scene-selected verification policy over the generic v1 codec."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from chimera.runtime.env_verify import verify_host
from chimera.runtime.manifest import WorkspaceManifest, parse_property_value
from chimera.runtime.scene_contracts import (
    registered_runtime_artifact_contracts,
)

from .capabilities import VERIFIERS


SceneKey = tuple[str, str, str, str]
_SUPPORTED_RVV_ROUTES = frozenset({
    (1024, 256),
    (256, 1024),
})


def manifest_scene_key(manifest: WorkspaceManifest) -> SceneKey:
    return (
        manifest.target_os, manifest.target_arch,
        manifest.target_arch_extension, manifest.runtime_scene,
    )


def validate_linux_riscv64_rvv_topology(
    root: Path, manifest: WorkspaceManifest, _settings
) -> None:
    def records(owner_kind, owner_id, capability, representation):
        return [
            item for item in manifest.artifacts
            if (item.owner_kind, item.owner_id, item.capability, item.representation)
            == (owner_kind, owner_id, capability, representation)
        ]

    contract = registered_runtime_artifact_contracts().select(
        manifest_scene_key(manifest)
    )
    runtime = records(
        "workspace", "root", "runtime", contract.representation
    )
    if len(runtime) != 1 or runtime[0].abi != contract.runtime_abi:
        raise ValueError("workspace requires exactly one runtime/elf ABI v1 artifact")
    try:
        contract.validate_elf(root / runtime[0].path)
    except (OSError, ValueError) as error:
        raise ValueError(f"runtime artifact is invalid: {error}") from error
    modules_with_variants = {item.module_id for item in manifest.variants}
    selectors: set[tuple[str, int]] = set()
    for module in manifest.modules:
        if module.module_id not in modules_with_variants:
            raise ValueError(
                f"module {module.module_id} requires at least one translation variant"
            )
        safety_elf = records("module", module.module_id, "safety", "elf")
        if safety_elf and len(safety_elf) != 1:
            raise ValueError(
                f"module {module.module_id} has invalid safety artifacts"
            )
    for variant in manifest.variants:
        endpoint_records = {
            (side, name): manifest.property_record(
                variant.variant_id, side, name
            )
            for side in ("input", "output")
            for name in (
                "architecture", "architecture_extension", "vector_vlen_bits"
            )
        }
        expected_kinds = {
            "architecture": "token",
            "architecture_extension": "token",
            "vector_vlen_bits": "u64",
        }
        for (_side, name), record in endpoint_records.items():
            if record.value_kind != expected_kinds[name]:
                raise ValueError(
                    f"variant {variant.variant_id} property {_side}.{name} "
                    f"must have kind {expected_kinds[name]}"
                )
        values = {
            key: parse_property_value(record.value_kind, record.value)
            for key, record in endpoint_records.items()
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
            or not isinstance(source, int) or source <= 0
            or not isinstance(target, int) or target <= 0
        ):
            raise ValueError(
                f"variant {variant.variant_id} has invalid RVV endpoint properties"
            )
        if (source, target) not in _SUPPORTED_RVV_ROUTES:
            raise ValueError(
                f"unsupported RVV translation route: {source} -> {target}"
            )
        selector = (variant.module_id, source)
        if selector in selectors:
            raise ValueError(f"duplicate module input selector: {selector}")
        selectors.add(selector)
        translated = records("variant", variant.variant_id, "translated-code", "elf")
        offset_map = records("variant", variant.variant_id, "offset-map", "elf")
        if len(translated) != 1 or translated[0].abi != 1:
            raise ValueError(f"variant {variant.variant_id} lacks translated-code v1")
        if len(offset_map) != 1 or offset_map[0].abi != 1:
            raise ValueError(f"variant {variant.variant_id} lacks offset-map v1")


@dataclass(frozen=True)
class SceneVerifier:
    key: SceneKey
    topology_validators: tuple[object, ...]
    capability_handlers: dict[tuple[str, str], object]
    host_verifier: object


class SceneVerifierCatalog:
    def __init__(self, verifiers=()) -> None:
        self._verifiers: dict[SceneKey, SceneVerifier] = {}
        for verifier in verifiers:
            if verifier.key in self._verifiers:
                raise ValueError(f"duplicate scene verifier: {verifier.key}")
            self._verifiers[verifier.key] = verifier

    def select(self, key: SceneKey) -> SceneVerifier:
        try:
            return self._verifiers[key]
        except KeyError as error:
            raise ValueError("unsupported runtime scene/target: " + "/".join(key)) from error


def registered_scene_verifiers() -> SceneVerifierCatalog:
    key = ("linux", "riscv64", "rvv", "linux_riscv64_rvv_v1")
    return SceneVerifierCatalog((SceneVerifier(
        key=key,
        topology_validators=(validate_linux_riscv64_rvv_topology,),
        capability_handlers=VERIFIERS,
        host_verifier=verify_host,
    ),))
