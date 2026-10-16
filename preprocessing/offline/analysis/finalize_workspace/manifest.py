"""Manifest v1 publication adapter for the final workspace step."""

from __future__ import annotations

from pathlib import Path

from chimera.runtime.manifest import WorkspaceManifest, write_manifest


def write_workspace_manifest(manifest: WorkspaceManifest, artifact_dir: Path) -> Path:
    destination = artifact_dir / "modules.tsv"
    write_manifest(manifest, destination)
    return destination
