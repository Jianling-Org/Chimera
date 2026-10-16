"""Translation-variant boundary and its products."""

from __future__ import annotations

from dataclasses import dataclass
from functools import total_ordering
from pathlib import Path
from types import MappingProxyType
from typing import Any, Mapping
from chimera.preprocess.offline.config import TranslationEndpoint
from ..core.data_model import AnalysisModule


@total_ordering
@dataclass(frozen=True)
class TranslationKey:
    """Identity of one translation route, based on canonical endpoints."""

    module_id: str
    source_endpoint: TranslationEndpoint
    target_endpoint: TranslationEndpoint

    @property
    def canonical_route(self) -> tuple[str, str]:
        return self.source_endpoint.canonical, self.target_endpoint.canonical

    @property
    def _sort_key(self) -> tuple[str, str, str]:
        return (self.module_id, *self.canonical_route)

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, TranslationKey):
            return NotImplemented
        return self._sort_key < other._sort_key


def variant_id(
    module_id: str,
    source: TranslationEndpoint,
    target: TranslationEndpoint,
) -> str:
    """Return a route identifier for simple adapters."""
    return f"{module_id}_{source.canonical}_to_{target.canonical}"


@dataclass(frozen=True)
class TranslationProductionSpec:
    """Scene-owned names, properties and paths for one translation variant."""

    variant_id: str
    artifact_id: str
    symbol_namespace: str
    input_properties: Mapping[str, Any]
    output_properties: Mapping[str, Any]
    assembly_path: Path
    translated_dump_path: Path
    provenance_path: Path
    library_path: Path
    offset_map_assembly_path: Path
    offset_map_document_path: Path
    offset_map_library_path: Path
    offset_map_artifact_id: str
    suffix: str = ""
    input_property_kinds: Mapping[str, str] | None = None
    output_property_kinds: Mapping[str, str] | None = None
    # A private, unpatched copy is retained so safety changes can rebuild the
    # published library from the original translation each time.  The paths
    # are optional for compatibility with specifications produced before this
    # intermediate was introduced.
    unpatched_library_path: Path | None = None
    unpatched_library_sha256_path: Path | None = None

    @property
    def owner_id(self) -> str:
        """Manifest owner for products produced by this variant."""
        return self.variant_id

    def __post_init__(self) -> None:
        for name in (
            "assembly_path", "translated_dump_path", "provenance_path",
            "library_path",
            "offset_map_assembly_path", "offset_map_document_path",
            "offset_map_library_path",
        ):
            path = Path(getattr(self, name))
            if path.is_absolute() or ".." in path.parts:
                raise ValueError(
                    f"translation production path must stay inside staging: {name}"
                )
            object.__setattr__(self, name, path)
        if self.unpatched_library_path is not None:
            path = Path(self.unpatched_library_path)
            if path.is_absolute() or ".." in path.parts:
                raise ValueError(
                    "translation production path must stay inside staging: "
                    "unpatched_library_path"
                )
            object.__setattr__(self, "unpatched_library_path", path)
            if path == self.library_path:
                raise ValueError(
                    "unpatched_library_path must be independent from library_path"
                )
            checksum = self.unpatched_library_sha256_path
            if checksum is None:
                checksum = Path(f"{path}.sha256")
            else:
                checksum = Path(checksum)
                if checksum.is_absolute() or ".." in checksum.parts:
                    raise ValueError(
                        "translation production path must stay inside staging: "
                        "unpatched_library_sha256_path"
                    )
            object.__setattr__(self, "unpatched_library_sha256_path", checksum)
        elif self.unpatched_library_sha256_path is not None:
            raise ValueError(
                "unpatched_library_sha256_path requires unpatched_library_path"
            )
        object.__setattr__(self, "input_properties", MappingProxyType(dict(self.input_properties)))
        object.__setattr__(self, "output_properties", MappingProxyType(dict(self.output_properties)))
        if self.input_property_kinds is not None:
            object.__setattr__(self, "input_property_kinds", MappingProxyType(dict(self.input_property_kinds)))
        if self.output_property_kinds is not None:
            object.__setattr__(self, "output_property_kinds", MappingProxyType(dict(self.output_property_kinds)))

    @property
    def unpatched_sha256_path(self) -> Path | None:
        """Compatibility alias for the sidecar checksum path."""
        return self.unpatched_library_sha256_path


def ensure_production_outputs_are_writable(
    spec: TranslationProductionSpec,
    stage: Path,
    module_paths: set[Path] | frozenset[Path],
) -> None:
    """Reject scene paths that would overwrite a hard-linked module input.

    Rebuild stages intentionally preserve ``local/<runtime_name>`` by inode.
    A malformed scene production specification must therefore not be able to
    route an intermediate or generated output to one of those files.
    """
    stage_root = Path(stage).resolve()
    protected = {
        (stage_root / Path(path)).resolve()
        if not Path(path).is_absolute()
        else Path(path).resolve()
        for path in module_paths
    }
    fields = (
        "assembly_path", "translated_dump_path", "provenance_path",
        "library_path", "offset_map_assembly_path",
        "offset_map_document_path", "offset_map_library_path",
        "unpatched_library_path", "unpatched_library_sha256_path",
    )
    for field in fields:
        relative = getattr(spec, field)
        if relative is None:
            continue
        candidate = (stage_root / Path(relative)).resolve()
        if not candidate.is_relative_to(stage_root):
            raise ValueError(
                "translation production output escapes staging: "
                f"{field}={Path(relative).as_posix()}"
            )
        if candidate in protected:
            raise ValueError(
                "translation production output cannot overwrite a module input: "
                f"{field}={Path(relative).as_posix()}"
            )


@dataclass(frozen=True)
class TranslationRequest:
    module: AnalysisModule
    source_endpoint: TranslationEndpoint
    target_endpoint: TranslationEndpoint
    translator_path: Path
    native_dump: Path
    assembly_output: Path
    library_output: Path
    translated_dump_output: Path
    symbol_namespace: str
    input_properties: Mapping[str, Any]
    output_properties: Mapping[str, Any]


@dataclass(frozen=True)
class TranslatedModule:
    key: TranslationKey
    assembly: Path
    library: Path
    native_dump: Path
    translated_dump: Path
    symbol_namespace: str
    fingerprint: str
    spec: TranslationProductionSpec | None = None
