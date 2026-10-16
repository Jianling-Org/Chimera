"""Safe workspace naming and cleanup helpers."""

from __future__ import annotations

from pathlib import Path
import re

from .identity import identity_digest


class WorkspaceError(ValueError):
    """A workspace target is unsafe or escapes the configured root."""


def safe_name(value: str) -> str:
    sanitized = re.sub(r"[^A-Za-z0-9._-]", "_", value)
    return sanitized.strip(".-")


def workspace_name(input_path: Path) -> str:
    """Return the Workspace directory name for *input_path*.

    The name **is** the identity digest: one ELF, one digest, one Workspace,
    with no second source of truth and no lookup index to keep in step.  A
    self-describing prepended basename was given up on purpose -- it forced a
    "name already taken by different content" branch that cannot exist when the
    name is the identity, and reading it is ``chimera-user list``'s job.
    """

    return identity_digest(input_path)


def resolve_clean_target(workspace_root: Path, target: Path) -> Path:
    root = workspace_root.resolve()
    if target.is_symlink():
        raise WorkspaceError(f"cleanup target must not be a symlink: {target}")
    resolved = target.resolve()
    if resolved == root or root not in resolved.parents:
        raise WorkspaceError(
            f"cleanup target must be a child of workspace root {root}: {resolved}"
        )
    return resolved


def resolve_workspace_id(workspace_root: Path, workspace_id: str) -> Path:
    if not isinstance(workspace_id, str) or not workspace_id or safe_name(workspace_id) != workspace_id:
        raise WorkspaceError(f"unsafe workspace ID: {workspace_id!r}")
    if Path(workspace_id).name != workspace_id:
        raise WorkspaceError(f"workspace ID must not contain a path: {workspace_id!r}")
    return resolve_clean_target(workspace_root, workspace_root.resolve() / workspace_id)


def resolve_workspace_reference(workspace_root: Path, reference: str | Path) -> Path:
    """Resolve either a Workspace ID under *workspace_root* or an explicit path.

    User-facing runtime commands may consume a Workspack installed under a
    configured root, while deployment tools often need to inspect a staging
    location explicitly.  IDs stay constrained to the configured root; an
    explicit path is accepted only when it names a real directory containing a
    Manifest, preventing accidental resolution of an arbitrary file.
    """

    value = str(reference)
    candidate = Path(value).expanduser()
    if not candidate.is_absolute() and len(candidate.parts) == 1:
        return resolve_workspace_id(workspace_root, value)
    resolved = candidate.resolve()
    if not resolved.is_dir():
        raise WorkspaceError(f"workspace path does not exist: {resolved}")
    if not (resolved / "artifacts" / "modules.tsv").is_file():
        raise WorkspaceError(f"workspace path has no Manifest: {resolved}")
    return resolved


def resolve_workspace_by_elf(workspace_root: Path, elf_path: Path) -> Path:
    """Resolve the unique workspace for *elf_path* by content identity.

    One ELF has one identity digest and one digest names one workspace, so the
    lookup is a single directory probe.  Local binding state -- path, inode,
    kernel registration -- plays no part: it is recomputed for this machine on
    every run and must never become a cross-machine identity.

    A directory whose name matches the digest but whose recorded digest does
    not is a conflict rather than a hit, and is reported instead of used.
    """

    from .metadata import read_workspace_metadata

    source = Path(elf_path).resolve()
    root = workspace_root.resolve()
    digest = identity_digest(source)
    candidate = root / digest
    if not candidate.is_dir():
        raise WorkspaceError(
            "no workspace prepared for this ELF "
            f"(identity {digest}); run 'chimera-pkg prepare --input {elf_path}' first"
        )
    try:
        metadata = read_workspace_metadata(candidate)
    except ValueError as error:
        raise WorkspaceError(f"workspace {candidate} is unusable: {error}") from error
    if metadata.workspace_id != candidate.name:
        raise WorkspaceError(
            f"workspace {candidate} records ID {metadata.workspace_id!r}, which "
            "does not match its directory name"
        )
    if metadata.input_elf_digest != digest:
        raise WorkspaceError(
            f"workspace {candidate} is installed under identity {digest} but "
            f"records {metadata.input_elf_digest!r}; refusing to reuse it"
        )
    return candidate
