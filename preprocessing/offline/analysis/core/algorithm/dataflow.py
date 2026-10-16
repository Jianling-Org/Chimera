"""Reusable architecture-neutral fixed-point data-flow solvers."""

from __future__ import annotations

from collections import deque
from collections.abc import Callable, Hashable, Iterable, Sequence
from typing import TypeVar

from .address_states import EMPTY_STATES, AddressStateMap, address_domain


Address = TypeVar("Address", bound=Hashable)
Fact = TypeVar("Fact", bound=Hashable)


def solve_backward_liveness(
    addresses: Sequence[Address],
    *,
    successors: Callable[[Address], Iterable[Address]],
    predecessors: Callable[[Address], Iterable[Address]],
    use_def: Callable[[Address], tuple[Iterable[Fact], Iterable[Fact]]],
) -> tuple[
    AddressStateMap[Address, frozenset[Fact]],
    AddressStateMap[Address, frozenset[Fact]],
]:
    """Solve ``before = use union (after - def)`` to a fixed point.

    Only non-empty states are ever retained: an address whose ``live_before``
    or ``live_after`` is empty keeps no entry at all and resolves to the shared
    :data:`~..address_states.EMPTY_STATES` value, and an entry is dropped again
    once the state converges back to empty.  The returned maps still answer
    ``[]``/``get``/``in``/``len``/iteration for every address of the input
    domain, so consumers observe the same mapping as before.
    """

    domain = address_domain(addresses)
    known = set(domain)
    empty = EMPTY_STATES
    live_before: dict[Address, frozenset[Fact]] = {}
    live_after: dict[Address, frozenset[Fact]] = {}
    worklist: deque[Address] = deque(reversed(domain))
    queued = set(worklist)
    while worklist:
        address = worklist.popleft()
        queued.discard(address)
        # Union of the successor live-in sets.  The accumulator is allocated
        # only when a successor actually contributes something.
        accumulated: set[Fact] | None = None
        for successor in successors(address):
            if successor not in known:
                continue
            value = live_before.get(successor)
            if value:
                if accumulated is None:
                    accumulated = set(value)
                else:
                    accumulated |= value
        after: frozenset[Fact] = empty if accumulated is None else frozenset(accumulated)

        uses, definitions = use_def(address)
        if not after and not uses:
            before: frozenset[Fact] = empty
        else:
            # ``uses | (after - def)``: the subtraction must happen before the
            # uses are added, so an instruction that both reads and writes the
            # same fact (a keep-vl ``vsetvli`` reads and writes the vector
            # state register) keeps it live-in.
            combined = set(after)
            if combined:
                combined.difference_update(definitions)
            combined.update(uses)
            before = frozenset(combined) if combined else empty

        if (
            before == live_before.get(address, empty)
            and after == live_after.get(address, empty)
        ):
            continue
        if before:
            live_before[address] = before
        else:
            live_before.pop(address, None)
        if after:
            live_after[address] = after
        else:
            live_after.pop(address, None)
        for predecessor in predecessors(address):
            if predecessor not in queued:
                worklist.append(predecessor)
                queued.add(predecessor)
    return (
        AddressStateMap(domain, empty, live_before),
        AddressStateMap(domain, empty, live_after),
    )
