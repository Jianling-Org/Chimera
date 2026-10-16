"""Small immutable metadata used to identify published workspaces.

Module records are deliberately absent: the Manifest
(``artifacts/modules.tsv``) is their single authority, so a Workspace can never
disagree with itself about which modules it carries.

There is no format version number.  An older Workspace is recognised by the
shape of this document -- unknown or missing required fields -- and reported as
such, instead of a version counter claiming a format that has moved on.
"""

from __future__ import annotations

from dataclasses import MISSING, dataclass, fields
from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any

from .identity import identity_digest


WORKSPACE_METADATA = "workspace.json"


@dataclass(frozen=True)
class WorkspaceMetadata:
    workspace_id: str
    created_at: str
    input_elf_name: str
    #: Cross-machine identity of the input ELF (see :mod:`.identity`).
    input_elf_digest: str
    #: Digest of every input the prepare run selected, used only to decide
    #: whether an existing Workspace may be reused.  Empty means the
    #: publication never completed: a Workspace is allocated before its modules
    #: are selected, so the prepare step fills this in afterwards.
    input_fingerprint: str = ""


def write_workspace_metadata(stage: Path, *, workspace_id: str, input_elf: Path) -> Path:
    """Allocate the metadata document for a freshly staged Workspace."""

    return _write(
        Path(stage),
        WorkspaceMetadata(
            workspace_id=workspace_id,
            created_at=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            input_elf_name=Path(input_elf).name,
            input_elf_digest=identity_digest(input_elf),
        ),
    )


def update_workspace_metadata(stage: Path, **changes: Any) -> Path:
    """Apply *changes* to the staged metadata document.

    Fields become known at different points -- the input fingerprint only after
    modules have been selected -- so every write goes through this function and
    the document always satisfies the same shape.
    """

    document = read_workspace_metadata(stage, require_fingerprint=False)
    unknown = sorted(set(changes) - _field_names())
    if unknown:
        raise ValueError(f"unknown workspace metadata fields: {unknown}")
    values = {name: getattr(document, name) for name in _field_names()}
    values.update(changes)
    return _write(Path(stage), WorkspaceMetadata(**values))


def parse_workspace_metadata(
    document: object, *, require_fingerprint: bool = True
) -> WorkspaceMetadata:
    """Validate an already-decoded metadata document.

    Shared with the packaging code, which validates the copy travelling inside
    a ``.workspace`` archive rather than a directory on disk.
    """

    if not isinstance(document, dict):
        raise ValueError("workspace metadata must be a JSON object")

    unknown = sorted(set(document) - _field_names())
    missing = sorted(name for name in _required_names() if name not in document)
    if unknown or missing:
        raise ValueError(
            "workspace metadata does not match the current format "
            f"(unknown={unknown}, missing={missing}); re-run "
            "'chimera-pkg prepare' for this ELF"
        )

    values = WorkspaceMetadata(**document)
    if require_fingerprint and not values.input_fingerprint:
        raise ValueError(
            "workspace metadata has no input fingerprint; the publication is "
            "incomplete"
        )
    return values


def read_workspace_metadata(
    root: Path, *, require_fingerprint: bool = True
) -> WorkspaceMetadata:
    """Read and validate the metadata document under *root*.

    ``workspace_id`` is **not** compared with the directory name here: staging
    directories are named ``.<id>.staging-<uuid>`` on purpose, so that check
    only belongs where a directory name is used as an address.
    """

    path = Path(root) / WORKSPACE_METADATA
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as error:
        raise ValueError(f"workspace has no metadata: {path}") from error
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError(f"cannot read workspace metadata: {path}") from error
    try:
        return parse_workspace_metadata(
            document, require_fingerprint=require_fingerprint
        )
    except ValueError as error:
        raise ValueError(f"{error}: {path}") from error


def _field_names() -> frozenset[str]:
    return frozenset(item.name for item in fields(WorkspaceMetadata))


def _required_names() -> frozenset[str]:
    return frozenset(
        item.name for item in fields(WorkspaceMetadata) if item.default is MISSING
    )


def _write(stage: Path, document: WorkspaceMetadata) -> Path:
    destination = stage / WORKSPACE_METADATA
    destination.write_text(
        json.dumps(document.__dict__, sort_keys=True) + "\n", encoding="utf-8"
    )
    return destination


__all__ = [
    "WORKSPACE_METADATA",
    "WorkspaceMetadata",
    "parse_workspace_metadata",
    "read_workspace_metadata",
    "update_workspace_metadata",
    "write_workspace_metadata",
]
