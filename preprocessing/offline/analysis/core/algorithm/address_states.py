"""Compact read-only per-address analysis state.

Long-running whole-program analyses keep one state value per instruction for
every function they have already visited.  A plain ``dict`` costs a hash slot
per address *plus* a distinct value object per address, even when the vast
majority of those values are the same empty set.  :class:`AddressStateMap`
stores the same logical mapping as:

* an **address domain** (a deduplicated address tuple, first-seen order) that
  answers ``len``/iteration and doubles as the membership reference;
* one **shared default** value reused by every address without an exception;
* a small **exception dictionary** holding only entries that differ from the
  default.

The observable behaviour matches the dense dictionary it replaces:

* ``mapping[address]`` returns the exception value, else the shared default for
  a known address, else raises ``KeyError``;
* an address whose value equals the default is still *in* the mapping, while an
  address outside the domain behaves like a missing key for ``in``/``get``;
* ``items``/``values`` follow the domain order and ``len`` is the domain size;
* equality follows normal mapping rules against any ``Mapping`` (plain
  dictionaries keep working as inputs and comparison operands).

Addresses are stored once, so a single domain tuple can be shared by every
result computed for the same function.  Membership uses a binary search over
the sorted addresses; no auxiliary per-address dictionary is built.
"""

from __future__ import annotations

from bisect import bisect_left
from collections.abc import Iterable, ItemsView, Iterator, Mapping
from typing import Any, Hashable, TypeVar

Address = TypeVar("Address", bound=Hashable)
Value = TypeVar("Value")

#: Shared immutable empty state.  Every empty analysis state is this one
#: object, so "empty" costs no per-address allocation at all.
EMPTY_STATES: frozenset[Any] = frozenset()


def _strictly_increasing(values: tuple[Any, ...]) -> bool:
    """True when ``values`` is already sorted and duplicate-free."""

    for previous, current in zip(values, values[1:]):
        if not previous < current:
            return False
    return True


def address_domain(addresses: Iterable[Address]) -> tuple[Address, ...]:
    """Return the deduplicated address domain, preserving first-seen order.

    A tuple that is already strictly increasing is reused as-is: it is its own
    deduplicated and sorted form, and sharing it keeps one tuple per function
    instead of one per analysis result.
    """

    sequence = addresses if isinstance(addresses, tuple) else tuple(addresses)
    if _strictly_increasing(sequence):
        return sequence
    seen: set[Address] = set()
    unique: list[Address] = []
    for address in sequence:
        if address not in seen:
            seen.add(address)
            unique.append(address)
    return tuple(unique)


def compact_states(
    domain: tuple[Address, ...],
    values: Mapping[Address, Value],
    default: Value,
) -> "AddressStateMap[Address, Value]":
    """Build a compact map over ``domain`` keeping only non-default values."""

    entries: dict[Address, Value] = {}
    get = values.get
    for address in domain:
        value = get(address, default)
        if value != default:
            entries[address] = value
    return AddressStateMap(domain, default, entries)


def retained_entries(states: Mapping[Address, Value]) -> int:
    """Number of non-default entries a per-address mapping actually retains.

    Works for both :class:`AddressStateMap` and a plain dictionary, so
    monitoring can report the sparse state behind either representation
    without expanding it.
    """

    counter = getattr(states, "entry_count", None)
    if counter is not None:
        return int(counter)
    return sum(1 for value in states.values() if value)


class AddressStateMap(Mapping[Address, Value]):
    """Per-address state stored as address domain + default + exceptions."""

    __slots__ = ("_domain", "_ordered", "_default", "_entries")

    def __init__(
        self,
        domain: tuple[Address, ...],
        default: Value,
        entries: dict[Address, Value] | None = None,
    ) -> None:
        increasing = _strictly_increasing(domain)
        if not increasing:
            # Deduplicate while preserving first-seen order.  A domain that is
            # already strictly increasing is reused as-is, so sibling results
            # of one function share a single address tuple.
            domain = address_domain(domain)
            increasing = _strictly_increasing(domain)
        self._domain = domain
        self._default = default
        self._entries: dict[Address, Value] = {} if entries is None else entries
        # Sorted addresses for the binary-search membership test; a strictly
        # increasing domain is its own sorted form.
        self._ordered = domain if increasing else tuple(sorted(domain))

    # region Mapping protocol

    def __getitem__(self, address: Address) -> Value:
        try:
            return self._entries[address]
        except KeyError:
            pass
        ordered = self._ordered
        index = bisect_left(ordered, address)
        if index < len(ordered) and ordered[index] == address:
            return self._default
        raise KeyError(address)

    def __contains__(self, address: object) -> bool:
        if address in self._entries:
            return True
        ordered = self._ordered
        try:
            index = bisect_left(ordered, address)
        except TypeError:
            return False
        return index < len(ordered) and ordered[index] == address

    def __len__(self) -> int:
        return len(self._domain)

    def __iter__(self) -> Iterator[Address]:
        return iter(self._domain)

    def items(self) -> Iterator[tuple[Address, Value]]:
        entries = self._entries
        default = self._default
        for address in self._domain:
            yield address, entries.get(address, default)

    def values(self) -> Iterator[Value]:
        entries = self._entries
        default = self._default
        for address in self._domain:
            yield entries.get(address, default)

    def __eq__(self, other: object) -> bool:
        # Mapping equality, not representation equality: the domain order is
        # observable through iteration but does not change which addresses map
        # to which values.
        if self is other:
            return True
        if isinstance(other, AddressStateMap):
            if (
                self._default == other._default
                and self._domain == other._domain
                and self._entries == other._entries
            ):
                return True
            if len(other._domain) != len(self._domain):
                return False
        if not isinstance(other, Mapping):
            return NotImplemented
        if len(other) != len(self._domain):
            return False
        entries = self._entries
        default = self._default
        for address in self._domain:
            try:
                value = other[address]
            except KeyError:
                return False
            if entries.get(address, default) != value:
                return False
        return True

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}(domain={len(self._domain)}, "
            f"entries={len(self._entries)}, default={self._default!r})"
        )

    # endregion

    # region Compact storage introspection

    @property
    def domain(self) -> tuple[Address, ...]:
        """The address domain, in first-seen order."""

        return self._domain

    @property
    def default(self) -> Value:
        """The value shared by every address without an exception entry."""

        return self._default

    @property
    def entry_count(self) -> int:
        """Number of exception entries actually retained.

        This is the sparse state a long analysis really keeps alive, as
        opposed to ``len(self)`` (the logical mapping size, i.e. the whole
        address domain).
        """

        return len(self._entries)

    def entry_items(self) -> ItemsView[Address, Value]:
        """Read-only view of the exception entries, without expanding them."""

        return self._entries.items()

    def replace_entries(
        self, entries: dict[Address, Value]
    ) -> "AddressStateMap[Address, Value]":
        """A new map over the same domain and default with new exceptions."""

        return AddressStateMap(self._domain, self._default, entries)

    # endregion


__all__ = [
    "AddressStateMap",
    "EMPTY_STATES",
    "address_domain",
    "compact_states",
    "retained_entries",
]
