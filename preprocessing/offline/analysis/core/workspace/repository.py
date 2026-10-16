"""Create, write, and atomically publish immutable workspaces."""

from __future__ import annotations

import os
from pathlib import Path
import shutil
from uuid import uuid4

from chimera.runtime.manifest import PACKAGE_MODULE_DIR, read_manifest

from .layout import WorkspaceLayout
from .metadata import write_workspace_metadata
from .paths import WorkspaceError, safe_name, workspace_name
from .session import WorkspaceSession


class WorkspaceRepository:
    def __init__(self, workspace_root: str | Path):
        self.workspace_root = Path(workspace_root).resolve()

    def start(self, input_elf: Path, *, workspace: str | None = None) -> WorkspaceSession:
        source = input_elf.resolve()
        name = workspace_name(source) if workspace is None else safe_name(workspace)
        if not name or (workspace is not None and name != workspace):
            raise WorkspaceError(f"unsafe workspace name: {workspace!r}")
        self.workspace_root.mkdir(parents=True, exist_ok=True)
        destination = self.workspace_root / name
        if destination.exists():
            raise FileExistsError(f"workspace already exists: {destination}")
        stage = self.workspace_root / f".{name}.staging-{uuid4().hex}"
        try:
            stage.mkdir()
            WorkspaceLayout(stage).create()
            write_workspace_metadata(stage, workspace_id=name, input_elf=source)
        except BaseException:
            if stage.exists():
                shutil.rmtree(stage)
            raise
        return WorkspaceSession(
            root=self.workspace_root,
            stage=stage,
            destination=destination,
        )

    def reopen(self, workspace_path: str | Path) -> WorkspaceSession:
        source = Path(workspace_path).resolve()
        if source == self.workspace_root or self.workspace_root not in source.parents:
            raise WorkspaceError(
                "workspace to reopen must be a child of the configured workspace root: "
                f"{source}"
            )
        if not source.is_dir():
            raise FileNotFoundError(f"workspace does not exist: {source}")
        manifest_path = source / "artifacts" / "modules.tsv"
        if not manifest_path.is_file():
            raise FileNotFoundError(f"workspace has no manifest: {manifest_path}")
        # Validate the published tree before creating a staging copy.  Apart
        # from avoiding work for an invalid workspace, this gives us the
        # exact module paths whose inode identity is part of the BPF contract.
        prior = read_manifest(manifest_path, workspace_root=source)
        # Only package-delivered modules keep a payload inside the workspace.
        # Target-resolved modules (the application and its own libraries) live
        # on the machine and are resolved from ``--input`` during rebuild, so
        # their absence here is the expected shape rather than a defect.  Which
        # of the two a module is, is *not* guessed from file presence: rebuild
        # re-resolves the selection and cross-checks it against the Manifest.
        hardlinked: list[Path] = []
        for module in prior.modules:
            relative = Path(PACKAGE_MODULE_DIR) / module.runtime_name
            candidate = source / relative
            if candidate.is_symlink():
                raise ValueError(
                    f"workspace module payload is a symlink: {relative.as_posix()}"
                )
            if candidate.is_file():
                hardlinked.append(relative)
        if not hardlinked:
            raise ValueError(
                "workspace publishes no module payloads; refusing to reopen it: "
                f"{source}"
            )
        hardlink_paths = frozenset(hardlinked)
        artifact_paths = {
            Path(*artifact.path.split("/")) for artifact in prior.artifacts
        }
        if hardlink_paths & artifact_paths:
            raise ValueError(
                "workspace manifest cannot publish an artifact over a module input"
            )
        name = source.name
        stage = self.workspace_root / f".{name}.staging-{uuid4().hex}"
        try:
            stage.mkdir()
            _materialize_tree(source, stage, hardlink_paths=hardlink_paths)
            WorkspaceLayout(stage).create()
            session = WorkspaceSession(
                root=self.workspace_root,
                stage=stage,
                destination=source,
                published_manifest=prior,
            )
            session.registry.load_manifest(prior)
            return session
        except BaseException:
            if stage.exists():
                shutil.rmtree(stage)
            raise


def _materialize_tree(
    source: Path,
    stage: Path,
    *,
    hardlink_paths: frozenset[Path] = frozenset(),
) -> None:
    for current, dirs, files in os.walk(source):
        dirs[:] = [name for name in dirs if not name.startswith(".staging-")]
        relative = Path(current).relative_to(source)
        target_dir = stage / relative
        target_dir.mkdir(parents=True, exist_ok=True)
        for name in files:
            if name.startswith(".staging-"):
                continue
            source_file = Path(current) / name
            target_file = target_dir / name
            if target_file.exists():
                continue
            if source_file.is_symlink():
                raise WorkspaceError(
                    "workspace staging refuses symlinked file: "
                    f"{source_file.relative_to(source).as_posix()}"
                )
            if relative / name in hardlink_paths:
                os.link(source_file, target_file)
            else:
                # Rebuild steps are allowed to rewrite generated files.  A
                # copy prevents a failed rebuild from modifying the
                # published workspace through a shared inode.
                shutil.copy2(source_file, target_file)


def _hardlink_tree(source: Path, stage: Path) -> None:
    """Compatibility helper for callers that explicitly request hardlinks."""
    _materialize_tree(source, stage, hardlink_paths=frozenset({
        Path(current).relative_to(source) / name
        for current, _dirs, files in os.walk(source)
        for name in files
    }))
