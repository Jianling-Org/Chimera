"""Workspace allocation, layout, metadata, and publication primitives."""

from .anchor import (
    FileAnchor,
    anchor_file,
    anchor_modules,
    verify_anchor,
    verify_anchors,
)
from .artifacts import sha256_file
from .fingerprint import input_fingerprint
from .identity import (
    ANALYSIS_SECTIONS,
    HeaderIdentity,
    IdentityInputs,
    LoadRegion,
    SectionRegion,
    compute_identity_digest,
    identity_digest,
    scan_identity_inputs,
)
from .layout import WorkspaceLayout
from .metadata import (
    WORKSPACE_METADATA,
    WorkspaceMetadata,
    parse_workspace_metadata,
    read_workspace_metadata,
    update_workspace_metadata,
    write_workspace_metadata,
)
from .paths import (
    WorkspaceError,
    resolve_clean_target,
    resolve_workspace_by_elf,
    resolve_workspace_id,
    resolve_workspace_reference,
    safe_name,
    workspace_name,
)
from .repository import WorkspaceRepository
from .registry import WorkspaceRegistry
from .session import WorkspaceSession

__all__ = [
    "ANALYSIS_SECTIONS",
    "FileAnchor",
    "HeaderIdentity",
    "IdentityInputs",
    "LoadRegion",
    "SectionRegion",
    "WORKSPACE_METADATA",
    "WorkspaceError",
    "WorkspaceLayout",
    "WorkspaceMetadata",
    "WorkspaceRepository",
    "WorkspaceRegistry",
    "WorkspaceSession",
    "anchor_file",
    "anchor_modules",
    "compute_identity_digest",
    "identity_digest",
    "input_fingerprint",
    "read_workspace_metadata",
    "resolve_clean_target",
    "resolve_workspace_id",
    "resolve_workspace_reference",
    "resolve_workspace_by_elf",
    "safe_name",
    "scan_identity_inputs",
    "sha256_file",
    "update_workspace_metadata",
    "verify_anchor",
    "verify_anchors",
    "workspace_name",
    "write_workspace_metadata",
]
