"""Build the preload environment from one verified Workspace manifest."""

from __future__ import annotations

import os
from pathlib import Path

from chimera.runtime.manifest import WorkspaceManifest


def runtime_environment(
    workspace: Path,
    manifest: WorkspaceManifest,
) -> dict[str, str]:
    root = workspace.resolve()
    runtime = next(
        artifact
        for artifact in manifest.artifacts
        if artifact.owner_kind == "workspace"
        and artifact.owner_id == "root"
        and artifact.capability == "runtime"
        and artifact.representation == "elf"
    )
    inject = root / runtime.path
    environment = dict(os.environ)
    environment["CHIMERA_WORKSPACE"] = str(root)
    # Runtime announces this process after initialization. Children inherit
    # the marker but must not replace the launch parent's notification.
    environment["CHIMERA_LAUNCH_PID"] = str(os.getpid())
    resources = root / "resources"
    if resources.is_dir():
        environment["CHIMERA_RESOURCES"] = str(resources)
    # The search path is no longer an environment variable: the launcher passes
    # it to the loader explicitly with ``--library-path``.  Anything inherited
    # from the caller would sit at the same priority and make the launch depend
    # on the shell it happened to be started from, so it is dropped.
    environment.pop("LD_LIBRARY_PATH", None)
    prior_preload = environment.get("LD_PRELOAD")
    environment["LD_PRELOAD"] = (
        os.pathsep.join((str(inject), prior_preload))
        if prior_preload
        else str(inject)
    )
    return environment
