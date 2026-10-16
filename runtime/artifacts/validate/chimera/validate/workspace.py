"""Validate immutable Workspace artifacts through Manifest v1 registries."""

from __future__ import annotations

from pathlib import Path
import os

from chimera.preprocess.offline.config import BaseConfig
from chimera.preprocess.offline.analysis.core.monitor import argument, local, monitored, returned
from chimera.runtime.manifest import (
    PACKAGE_MODULE_DIR, WorkspaceManifest, read_manifest,
)

from .capabilities import CapabilityVerificationError, VERIFIERS
from .scenes import manifest_scene_key, registered_scene_verifiers


class VerificationError(RuntimeError):
    """A Workspace or target environment violates a runtime contract."""


@monitored(
    "runtime.verify",
    variables=(
        argument("workspace"), argument("check_host"), local("manifest_path"),
        returned(label="artifacts", path=("artifacts",), transform=len),
        returned(label="target", transform=lambda manifest: [
            manifest.target_os, manifest.target_arch,
            manifest.target_arch_extension, manifest.runtime_scene,
        ]),
        returned(label="runtime_abi", path=("runtime_abi",)),
    ),
)
def verify_workspace(
    workspace: str | Path, settings: BaseConfig, *, check_host: bool = True,
) -> WorkspaceManifest:
    root = Path(workspace).resolve()
    if not root.is_dir():
        raise VerificationError(f"workspace does not exist: {root}")
    manifest_path = root / "artifacts" / "modules.tsv"
    try:
        manifest = read_manifest(manifest_path, workspace_root=root)
        _validate_runtime_payload(root, manifest)
        scene = registered_scene_verifiers().select(manifest_scene_key(manifest))
        for validator in scene.topology_validators:
            validator(root, manifest, settings)
        for artifact in manifest.artifacts:
            verifier = scene.capability_handlers.get(
                (artifact.capability, artifact.representation)
            )
            if verifier is None:
                if "runtime" in artifact.required_by:
                    raise VerificationError(
                        "unsupported required capability for runtime: "
                        f"{artifact.capability}/{artifact.representation}"
                    )
                continue
            verifier(root / artifact.path, artifact, manifest, settings)
    except VerificationError:
        raise
    except (OSError, ValueError, CapabilityVerificationError) as error:
        raise VerificationError(f"invalid workspace artifact: {error}") from error
    if check_host:
        try:
            scene.host_verifier(settings)
        except Exception as error:
            raise VerificationError(f"host environment validation failed: {error}") from error
    return manifest


def _validate_runtime_payload(root: Path, manifest: WorkspaceManifest) -> None:
    """Check module and explicitly shipped resource trees before execution.

    Manifest validation covers declared artifact paths.  Package-delivered
    module files and Workspack resources live outside that index, so validate
    their filesystem shape here as part of every runtime verification as well.
    Target-resolved modules have no file here at all -- that is the point of
    the split, not a defect.
    """
    scalar = root / PACKAGE_MODULE_DIR
    # A scene topology validator may construct a synthetic manifest before it
    # materializes module inputs (for example while validating publication
    # metadata).  In that case leave packaged-file checks to the launch path;
    # published Workspaces always contain the directory.
    scalar_available = scalar.is_dir()
    for module in manifest.modules:
        runtime_name = getattr(module, "runtime_name", None)
        # Lightweight verifier tests and third-party scene adapters may expose
        # only module IDs; their scene-specific topology validator remains the
        # authority for module materialization in that case.
        if runtime_name is None:
            continue
        if getattr(module, "delivery", "package") != "package":
            continue
        if not scalar_available:
            continue
        path = scalar / runtime_name
        if (
            path.is_symlink()
            or not path.is_file()
            or path.resolve().parent != scalar.resolve()
        ):
            raise VerificationError(
                f"workspace module is missing or escapes {PACKAGE_MODULE_DIR}/: "
                f"{runtime_name}"
            )
    resources = root / "resources"
    if not resources.exists():
        return
    if resources.is_symlink() or not resources.is_dir():
        raise VerificationError("workspace resources path is not a directory")
    for current, dirs, files in os.walk(resources):
        current_path = Path(current)
        for name in dirs:
            path = current_path / name
            if path.is_symlink():
                raise VerificationError(
                    f"workspace resource directory is a symlink: {path.relative_to(root)}"
                )
        for name in files:
            path = current_path / name
            if path.is_symlink() or not path.is_file():
                raise VerificationError(
                    f"workspace resource is not a regular file: {path.relative_to(root)}"
                )


__all__ = ["VERIFIERS", "VerificationError", "verify_workspace"]
