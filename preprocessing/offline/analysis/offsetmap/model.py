"""Products of one translation-variant Offset-map analysis."""

from dataclasses import dataclass
from pathlib import Path
from typing import Mapping
from array import array
from bisect import bisect_left
from collections.abc import Mapping as MappingABC

from ..translation import TranslationKey


class PackedOffsetMapping(MappingABC):
    """Immutable sorted u64 pairs with normal Mapping lookup semantics."""

    def __init__(self, mapping):
        self._keys = array('Q', sorted(mapping))
        self._values = array('Q', (mapping[key] for key in self._keys))

    def __len__(self):
        return len(self._keys)

    def __iter__(self):
        return iter(self._keys)

    def __getitem__(self, key):
        index = bisect_left(self._keys, key)
        if index == len(self._keys) or self._keys[index] != key:
            raise KeyError(key)
        return self._values[index]

    def items(self):
        return zip(self._keys, self._values)


@dataclass(frozen=True)
class OffsetMapArtifact:
    key: TranslationKey
    mapping: Mapping[int, int]
    assembly: Path
    document: Path
    library: Path
    original_base: int


__all__ = ["OffsetMapArtifact"]
