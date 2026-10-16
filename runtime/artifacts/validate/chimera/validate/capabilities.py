"""Capability-specific validation for generic Manifest v1 artifacts."""

from __future__ import annotations

from collections.abc import Callable
import json
from pathlib import Path
import re
import struct

try:
    from elftools.elf.elffile import ELFFile
except ImportError:  # pragma: no cover - dependency is declared by the package
    ELFFile = None

from chimera.runtime.manifest import (
    ArtifactRecord, WorkspaceManifest, variant_fingerprint,
)
from chimera.runtime.scene_contracts import (
    registered_runtime_artifact_contracts,
)


SAFETY_ABI_VERSION = 1
OFFSET_MAP_ABI_VERSION = 1
TRANSLATED_CODE_ABI_VERSION = 1


class CapabilityVerificationError(RuntimeError):
    pass


def _exported_symbols(path: Path, settings) -> set[str]:
    """Read dynamic exports directly from ELF, without spawning ``nm``."""
    try:
        if ELFFile is None:
            raise RuntimeError("pyelftools is unavailable")
        with path.open("rb") as stream:
            elf = ELFFile(stream)
            section = elf.get_section_by_name(".dynsym")
            if section is None:
                return set()
            return {
                symbol.name
                for symbol in section.iter_symbols()
                if symbol.name and symbol.entry.st_shndx != "SHN_UNDEF"
            }
    except (OSError, ValueError, RuntimeError) as error:
        raise CapabilityVerificationError(
            f"cannot inspect exported symbols in {path}: {error}"
        ) from error


def _require_symbols(path: Path, settings, required: set[str], label: str) -> None:
    missing = sorted(required - _exported_symbols(path, settings))
    if missing:
        raise CapabilityVerificationError(
            f"{label} symbols missing: " + ", ".join(missing)
        )


def _safe_symbol(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9]", "_", value)


def _runtime_contract(manifest: WorkspaceManifest):
    key = tuple(
        getattr(manifest, field, "")
        for field in (
            "target_os", "target_arch",
            "target_arch_extension", "runtime_scene",
        )
    )
    catalog = registered_runtime_artifact_contracts()
    if all(key):
        try:
            return catalog.select(key)
        except ValueError as error:
            raise CapabilityVerificationError(str(error)) from error
    matches = [
        contract for contract in catalog.contracts().values()
        if contract.runtime_scene == getattr(manifest, "runtime_scene", "")
    ]
    if len(matches) != 1:
        raise CapabilityVerificationError(
            f"unsupported runtime scene: {getattr(manifest, 'runtime_scene', '')}"
        )
    return matches[0]


def verify_runtime_elf(
    path: Path, artifact: ArtifactRecord, manifest: WorkspaceManifest, settings
) -> None:
    contract = _runtime_contract(manifest)
    if (
        artifact.owner_kind != "workspace"
        or artifact.owner_id != "root"
        or artifact.capability != "runtime"
        or artifact.representation != contract.representation
        or artifact.abi != contract.runtime_abi
    ):
        raise CapabilityVerificationError("invalid runtime ELF owner or ABI")
    if manifest.runtime_abi != contract.runtime_abi:
        raise CapabilityVerificationError(
            f"unsupported runtime ABI: manifest={manifest.runtime_abi}, artifact={artifact.abi}"
        )
    try:
        contract.validate_elf(path)
    except (OSError, ValueError) as error:
        raise CapabilityVerificationError(str(error)) from error
    _require_symbols(path, settings, set(contract.required_symbols), "runtime")


def verify_translated_elf(
    path: Path, artifact: ArtifactRecord, manifest: WorkspaceManifest, settings
) -> None:
    if artifact.owner_kind != "variant":
        raise CapabilityVerificationError("translated-code must be variant-owned")
    if artifact.abi != TRANSLATED_CODE_ABI_VERSION:
        raise CapabilityVerificationError("unsupported translated-code ABI")
    prefix = f"chimera_{_safe_symbol(artifact.owner_id)}"
    fingerprint = variant_fingerprint(manifest, artifact.owner_id)
    _require_symbols(
        path,
        settings,
        {
            f"{artifact.owner_id}_original_base_addr",
            f"{prefix}_translated_code_abi_v1",
            f"{prefix}_translation_fingerprint_{fingerprint}",
        },
        f"variant {artifact.owner_id} translated-code",
    )


def verify_offset_map_elf(
    path: Path, artifact: ArtifactRecord, manifest: WorkspaceManifest, settings
) -> None:
    if artifact.owner_kind != "variant" or artifact.abi != OFFSET_MAP_ABI_VERSION:
        raise CapabilityVerificationError("invalid offset-map ELF owner or ABI")
    prefix = f"chimera_{_safe_symbol(artifact.owner_id)}"
    _require_symbols(path, settings, {
        f"{prefix}_offset_map_abi",
        f"{prefix}_forward_entries",
        f"{prefix}_forward_count",
        f"{prefix}_reverse_entries",
        f"{prefix}_reverse_count",
    }, f"variant {artifact.owner_id} offset-map")


def verify_safety_elf(
    path: Path, artifact: ArtifactRecord, manifest: WorkspaceManifest, settings
) -> None:
    if artifact.owner_kind != "module" or artifact.abi != SAFETY_ABI_VERSION:
        raise CapabilityVerificationError("invalid safety ELF owner or ABI")
    prefix = f"chimera_{_safe_symbol(artifact.owner_id)}"
    _require_symbols(path, settings, {
        f"{prefix}_safety_abi",
        f"{prefix}_safety_entries",
        f"{prefix}_safety_count",
    }, f"module {artifact.owner_id} safety")


def _json_document(path: Path) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise CapabilityVerificationError(f"invalid JSON artifact {path}: {error}") from error
    if not isinstance(value, dict):
        raise CapabilityVerificationError(f"JSON artifact root must be an object: {path}")
    return value


def verify_offset_map_json(
    path: Path, artifact: ArtifactRecord, manifest: WorkspaceManifest, settings
) -> None:
    if artifact.owner_kind != "variant" or artifact.abi != OFFSET_MAP_ABI_VERSION:
        raise CapabilityVerificationError("invalid offset-map JSON owner or ABI")
    document = _json_document(path)
    if document.get("format") != "chimera-offset-map-v1":
        raise CapabilityVerificationError("unsupported offset-map JSON format")


def verify_safety_json(
    path: Path, artifact: ArtifactRecord, manifest: WorkspaceManifest, settings
) -> None:
    if artifact.owner_kind != "module" or artifact.abi != SAFETY_ABI_VERSION:
        raise CapabilityVerificationError("invalid safety JSON owner or ABI")
    document = _json_document(path)
    if document.get("format") != "chimera-safety-v1":
        raise CapabilityVerificationError("unsupported safety JSON format")


def verify_external_leaf_json(path, artifact, manifest, settings) -> None:
    if artifact.owner_kind != "module" or artifact.abi != 1:
        raise CapabilityVerificationError("invalid external scalar leaf owner or ABI")
    document = _json_document(path)
    if (document.get("format") != "chimera-external-scalar-leaf-v1"
            or not document.get("proofs") or not document.get("closed_calls")
            or document.get("rejections")):
        raise CapabilityVerificationError("incomplete external scalar leaf proof artifact")


Verifier = Callable[[Path, ArtifactRecord, WorkspaceManifest, object], None]
class CapabilityHandlerCatalog:
    def __init__(self, handlers=()) -> None:
        self._handlers: dict[tuple[str, str], Verifier] = {}
        for key, handler in handlers:
            self.register(key, handler)

    def register(self, key: tuple[str, str], handler: Verifier) -> None:
        if key in self._handlers:
            raise ValueError(f"duplicate capability handler: {key}")
        self._handlers[key] = handler

    def handlers(self) -> dict[tuple[str, str], Verifier]:
        return dict(self._handlers)


def registered_capability_handlers() -> CapabilityHandlerCatalog:
    return CapabilityHandlerCatalog((
        (("runtime", "elf"), verify_runtime_elf),
        (("translated-code", "elf"), verify_translated_elf),
        (("offset-map", "elf"), verify_offset_map_elf),
        (("offset-map", "json"), verify_offset_map_json),
        (("safety", "elf"), verify_safety_elf),
        (("safety", "json"), verify_safety_json),
        (("external-scalar-leaf-contracts", "json"), verify_external_leaf_json),
    ))


VERIFIERS = registered_capability_handlers().handlers()


__all__ = [
    "CapabilityHandlerCatalog", "CapabilityVerificationError", "VERIFIERS",
    "Verifier", "registered_capability_handlers",
]
