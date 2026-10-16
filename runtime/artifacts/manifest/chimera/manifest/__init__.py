"""Public Chimera Workspace Manifest v2 contract."""

from .codec import MANIFEST_MAGIC, read_manifest, write_manifest
from .model import (
    PACKAGE_MODULE_DIR,
    VALID_DELIVERIES,
    ArtifactRecord,
    ModuleRecord,
    VariantPropertyRecord,
    VariantRecord,
    WorkspaceManifest,
    canonical_property_value,
    parse_property_value,
    variant_fingerprint,
    variant_records_fingerprint,
)

RUNTIME_ABI_VERSION = 1

__all__ = [
    "ArtifactRecord",
    "MANIFEST_MAGIC",
    "ModuleRecord",
    "PACKAGE_MODULE_DIR",
    "RUNTIME_ABI_VERSION",
    "VALID_DELIVERIES",
    "VariantRecord",
    "VariantPropertyRecord",
    "WorkspaceManifest",
    "read_manifest",
    "write_manifest",
    "canonical_property_value",
    "parse_property_value",
    "variant_fingerprint",
    "variant_records_fingerprint",
]
