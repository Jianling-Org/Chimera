"""Freeze contributions, round-trip Manifest v1, and atomically publish."""

from __future__ import annotations

from chimera.runtime.manifest import read_manifest

from ..core.contracts import AnalysisContext
from ..core.monitor import local, monitored, returned
from .manifest import write_workspace_manifest


def _finalize_summary(context: AnalysisContext) -> dict[str, object]:
    manifest = context.require_global("manifest")
    return {
        "modules": len(manifest.modules),
        "variants": len(manifest.variants),
        "artifacts": len(manifest.artifacts),
        "published_workspace": context.require_global("published_workspace"),
    }


class FinalizeWorkspaceStep:
    name = "finalize-workspace"

    @monitored(
        "offline.finalize-workspace",
        variables=(
            local("manifest", label="manifest"),
            local("published"),
            returned(label="publication", transform=_finalize_summary),
        ),
    )
    def run(self, context: AnalysisContext) -> AnalysisContext:
        if context.stage is None:
            raise RuntimeError("finalize-workspace requires a staging workspace")
        session = context.require_global("workspace_session")
        manifest = session.freeze(
            runtime_abi=context.runtime_abi,
            target_os=context.target_os,
            target_arch=context.target_arch,
            target_arch_extension=context.target_arch_extension,
            runtime_scene=context.runtime_scene,
        )
        path = write_workspace_manifest(manifest, context.stage / "artifacts")
        reread = read_manifest(path, workspace_root=context.stage)
        if reread != manifest:
            raise ValueError("written Workspace Manifest does not round-trip")
        # Publication is the last moment at which the inputs can still be
        # checked.  Committing first would publish artifacts that describe
        # bytes which are no longer on disk.
        session.verify_inputs_unchanged()
        published = session.commit()
        return (
            context.put_global("manifest", manifest)
            .put_global("published_workspace", published)
        )


__all__ = ["FinalizeWorkspaceStep"]
