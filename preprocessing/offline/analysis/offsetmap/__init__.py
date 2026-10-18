"""Variant-scoped Offset-map analysis and artifact generation."""

from .model import OffsetMapArtifact
from .codegen import OFFSET_MAP_ABI_VERSION
from .step import OffsetMapStep

__all__ = ["OFFSET_MAP_ABI_VERSION", "OffsetMapArtifact", "OffsetMapStep"]
