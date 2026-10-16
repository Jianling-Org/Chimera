"""Transactional registry for artifacts produced in a staging Workspace."""

from __future__ import annotations

from collections.abc import Callable
from hashlib import sha256
from pathlib import Path, PurePosixPath

from chimera.runtime.manifest import (
    ArtifactRecord,
    ModuleRecord,
    VariantRecord,
    VariantPropertyRecord,
    WorkspaceManifest,
)


class WorkspaceRegistry:
    def __init__(self, stage: Path, *, is_open: Callable[[], bool]):
        self.stage = stage.resolve()
        self._is_open = is_open
        self.modules: dict[str, ModuleRecord] = {}
        self.variants: dict[str, VariantRecord] = {}
        self.variant_properties: dict[tuple[str, str, str], VariantPropertyRecord] = {}
        self.artifacts: dict[str, ArtifactRecord] = {}
        self._artifact_paths: dict[str, str] = {}

    def _require_open(self) -> None:
        if not self._is_open():
            raise RuntimeError("workspace staging session is already finished")

    def register_module(self, record: ModuleRecord) -> None:
        self._require_open()
        record.validate()
        if record.module_id in self.modules:
            raise ValueError(f"duplicate module ID: {record.module_id}")
        if any(item.runtime_name == record.runtime_name for item in self.modules.values()):
            raise ValueError(f"duplicate module runtime_name: {record.runtime_name}")
        self.modules[record.module_id] = record

    def register_variant(self, record: VariantRecord) -> None:
        self._require_open()
        record.validate()
        if record.module_id not in self.modules:
            raise ValueError(f"variant has unknown module owner: {record.module_id}")
        # Override on duplicate: a rebuild re-registers an existing variant.
        self.variants[record.variant_id] = record

    def register_variant_property(self, record: VariantPropertyRecord) -> None:
        self._require_open()
        record.validate()
        if record.variant_id not in self.variants:
            raise ValueError(f"property has unknown variant owner: {record.variant_id}")
        key = (record.variant_id, record.side, record.name)
        # Override on duplicate: a rebuild re-registers existing properties.
        self.variant_properties[key] = record

    def register_artifact(self, record: ArtifactRecord) -> None:
        self._require_open()
        record.validate()
        relative = PurePosixPath(record.path)
        candidate = (self.stage / Path(*relative.parts)).resolve()
        if not candidate.is_relative_to(self.stage) or not candidate.is_file():
            raise ValueError(f"artifact is missing or escapes workspace: {record.path}")
        actual = sha256(candidate.read_bytes()).hexdigest()
        if actual != record.sha256:
            raise ValueError(f"artifact SHA-256 mismatch: {record.path}")
        # A path may be re-registered only by its owning artifact id (rebuild
        # override); a different id claiming the same path is a producer bug.
        existing_id = self._artifact_paths.get(record.path)
        if existing_id is not None and existing_id != record.artifact_id:
            raise ValueError(
                f"artifact path already registered: {record.path} "
                f"(by artifact {existing_id}, not {record.artifact_id})"
            )
        # Override on duplicate id: rebuild re-registers an updated artifact.
        existing = self.artifacts.get(record.artifact_id)
        if existing is not None and existing.path != record.path:
            self._artifact_paths.pop(existing.path, None)
        self.artifacts[record.artifact_id] = record
        self._artifact_paths[record.path] = record.artifact_id

    def load_manifest(self, manifest: WorkspaceManifest) -> None:
        self._require_open()
        for record in manifest.modules:
            self.modules[record.module_id] = record
        for record in manifest.variants:
            self.variants[record.variant_id] = record
        for record in manifest.variant_properties:
            key = (record.variant_id, record.side, record.name)
            self.variant_properties[key] = record
        for record in manifest.artifacts:
            self.artifacts[record.artifact_id] = record
            self._artifact_paths[record.path] = record.artifact_id

    def freeze(
        self,
        *,
        runtime_abi: int,
        target_os: str,
        target_arch: str,
        target_arch_extension: str,
        runtime_scene: str,
    ) -> WorkspaceManifest:
        self._require_open()
        manifest = WorkspaceManifest(
            runtime_abi=runtime_abi,
            target_os=target_os,
            target_arch=target_arch,
            target_arch_extension=target_arch_extension,
            runtime_scene=runtime_scene,
            modules=tuple(sorted(self.modules.values())),
            variants=tuple(sorted(self.variants.values())),
            variant_properties=tuple(sorted(self.variant_properties.values())),
            artifacts=tuple(sorted(self.artifacts.values(), key=lambda item: item.artifact_id)),
        )
        manifest.validate(workspace_root=self.stage)
        return manifest
