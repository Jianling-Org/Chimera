"""Products of one translation-variant Offset-map analysis."""

from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

from ..translation import TranslationKey


@dataclass(frozen=True)
class OffsetMapArtifact:
    key: TranslationKey
    mapping: Mapping[int, int]
    assembly: Path
    document: Path
    library: Path
    original_base: int


__all__ = ["OffsetMapArtifact"]
