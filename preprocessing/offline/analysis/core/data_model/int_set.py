"""Compact mutable integer set used for per-instruction CFG edge sets.

A typical program model holds hundreds of thousands of instructions, each
with three small integer sets (``succ``, ``jump_targets``,
``jump_sources``) that are empty or hold a single element most of the
time.  A plain ``set`` costs ~232 bytes even when empty, so three of them
per instruction dominate the parse-phase footprint.  This container keeps
the same set semantics while tiering the backing store:

* empty     → no container at all;
* 1 element → the integer itself;
* 2-4       → a sorted tuple;
* 5+        → a builtin ``set`` (grows back down below the same threshold).

Only the operations consumed by the CFG builders and dataflow analyses
are supported: ``add``, ``update``, ``clear``, ``discard``, membership,
iteration, length, truthiness, and equality against any set-like
container (iteration order is NOT part of the contract).
"""

from __future__ import annotations

from typing import Iterator

__slots__ = ()

_TUPLE_LIMIT = 4


class CompactIntSet:
    __slots__ = ("_data",)

    def __init__(self, values=()) -> None:
        self._data = None
        for value in values:
            self.add(value)

    # -- mutators ------------------------------------------------------

    def add(self, value: int) -> None:
        data = self._data
        if data is None:
            self._data = value
            return
        if isinstance(data, int):
            if data != value:
                self._data = (
                    (data, value) if data < value else (value, data)
                )
            return
        if isinstance(data, tuple):
            if value in data:
                return
            merged = tuple(sorted((*data, value)))
            self._data = merged if len(merged) <= _TUPLE_LIMIT else set(merged)
            return
        data.add(value)

    def update(self, values) -> None:
        for value in values:
            self.add(value)

    def discard(self, value: int) -> None:
        data = self._data
        if data is None:
            return
        if isinstance(data, int):
            if data == value:
                self._data = None
            return
        if isinstance(data, tuple):
            if value not in data:
                return
            remaining = tuple(item for item in data if item != value)
            if len(remaining) > 1:
                self._data = remaining
            elif remaining:
                self._data = remaining[0]
            else:
                self._data = None
            return
        data.discard(value)
        if len(data) <= _TUPLE_LIMIT:
            if not data:
                self._data = None
            elif len(data) == 1:
                self._data = next(iter(data))
            else:
                self._data = tuple(sorted(data))

    def clear(self) -> None:
        self._data = None

    # -- read-only set protocol ----------------------------------------

    def __contains__(self, value: object) -> bool:
        data = self._data
        if data is None:
            return False
        if isinstance(data, int):
            return data == value
        return value in data

    def __iter__(self) -> Iterator[int]:
        data = self._data
        if data is None:
            return iter(())
        if isinstance(data, int):
            return iter((data,))
        return iter(data)

    def __len__(self) -> int:
        data = self._data
        if data is None:
            return 0
        if isinstance(data, int):
            return 1
        return len(data)

    def __bool__(self) -> bool:
        return self._data is not None

    def __eq__(self, other: object) -> bool:
        if isinstance(other, CompactIntSet):
            return self._frozen() == other._frozen()
        if isinstance(other, (set, frozenset)):
            return self._frozen() == other
        return NotImplemented

    def __ne__(self, other: object) -> bool:
        result = self.__eq__(other)
        if result is NotImplemented:
            return result
        return not result

    def __repr__(self) -> str:
        return f"CompactIntSet({sorted(self._frozen())!r})"

    def _frozen(self) -> frozenset[int]:
        data = self._data
        if data is None:
            return frozenset()
        if isinstance(data, int):
            return frozenset((data,))
        return frozenset(data)


__all__ = ["CompactIntSet"]
