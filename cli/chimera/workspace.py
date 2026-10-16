"""Public Workspace package API.

The implementation remains in :mod:`chimera.workspack` for on-disk protocol
compatibility; this module exposes the role-neutral names used by the CLI.
"""

from .workspack import (
    WORKSPACE_EXTENSION,
    WorkspackError,
    install_workspace,
    pack_workspace,
    verify_workspace_installation,
    verify_workspack_installation,
)

__all__ = [
    "WORKSPACE_EXTENSION",
    "WorkspackError",
    "install_workspace",
    "pack_workspace",
    "verify_workspace_installation",
    "verify_workspack_installation",
]
