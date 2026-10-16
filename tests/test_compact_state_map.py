"""Compact per-address state map: behaviour and dense-dictionary compatibility."""

from __future__ import annotations

from collections.abc import Mapping
import unittest

from chimera.preprocess.offline.analysis.core.algorithm.address_states import (
    EMPTY_STATES,
    AddressStateMap,
    address_domain,
    compact_states,
    retained_entries,
)


class AddressDomainTests(unittest.TestCase):
    def test_domain_is_deduplicated_and_ordered(self) -> None:
        self.assertEqual(address_domain([5, 3, 5, 1, 3]), (5, 3, 1))

    def test_sorted_tuple_is_reused(self) -> None:
        values = (1, 2, 3, 4)
        self.assertIs(address_domain(values), values)

    def test_unsorted_tuple_is_not_reused(self) -> None:
        values = (4, 1, 2, 3)
        self.assertEqual(address_domain(values), (4, 1, 2, 3))
        self.assertIsNot(address_domain(values), values)

    def test_duplicate_tuple_is_deduplicated(self) -> None:
        self.assertEqual(address_domain((1, 1, 2)), (1, 2))

    def test_empty_domain(self) -> None:
        self.assertEqual(address_domain([]), ())


class AddressStateMapBehaviourTests(unittest.TestCase):
    """The map must behave exactly like the dense dictionary it replaces."""

    def _map(self, *values: int) -> AddressStateMap:
        return AddressStateMap(
            (0x10, 0x14, 0x18),
            EMPTY_STATES,
            {address: frozenset({value}) for address, value in zip((0x10, 0x14, 0x18), values) if value},
        )

    def test_is_a_mapping(self) -> None:
        self.assertIsInstance(self._map(1), Mapping)

    def test_known_address_with_default_value_is_still_present(self) -> None:
        states = self._map(0, 7, 0)
        self.assertIn(0x10, states)
        self.assertIn(0x18, states)
        self.assertEqual(states[0x10], EMPTY_STATES)
        self.assertEqual(len(states), 3)

    def test_unknown_address_raises_key_error(self) -> None:
        states = self._map(1)
        with self.assertRaises(KeyError):
            states[0x999]

    def test_unknown_address_get_returns_the_caller_default(self) -> None:
        states = self._map(1)
        self.assertIsNone(states.get(0x999))
        self.assertIs(states.get(0x999, EMPTY_STATES), EMPTY_STATES)
        self.assertNotIn(0x999, states)

    def test_len_counts_the_whole_domain_not_the_exceptions(self) -> None:
        states = self._map(0, 0, 0)
        self.assertEqual(len(states), 3)
        self.assertEqual(states.entry_count, 0)

    def test_iteration_and_items_follow_domain_order(self) -> None:
        states = self._map(1, 0, 2)
        self.assertEqual(list(states), [0x10, 0x14, 0x18])
        self.assertEqual(
            list(states.items()),
            [
                (0x10, frozenset({1})),
                (0x14, EMPTY_STATES),
                (0x18, frozenset({2})),
            ],
        )
        self.assertEqual(
            list(states.values()),
            [frozenset({1}), EMPTY_STATES, frozenset({2})],
        )

    def test_iteration_covers_every_domain_address_once(self) -> None:
        # A non-monotonic domain must not lose or repeat addresses.
        states = AddressStateMap((0x20, 0x10, 0x18, 0x10), EMPTY_STATES)
        self.assertEqual(len(list(states)), 3)
        self.assertEqual(sorted(states), [0x10, 0x18, 0x20])
        self.assertIn(0x20, states)
        self.assertIn(0x10, states)

    def test_dict_round_trip(self) -> None:
        states = self._map(3, 0, 4)
        dense = dict(states)
        self.assertEqual(dense, {0x10: frozenset({3}), 0x14: frozenset(), 0x18: frozenset({4})})
        self.assertEqual(dict(states.items()), dense)

    def test_equality_with_plain_dict_in_both_directions(self) -> None:
        states = self._map(3, 0, 4)
        dense = {0x10: frozenset({3}), 0x14: frozenset(), 0x18: frozenset({4})}
        self.assertEqual(states, dense)
        self.assertEqual(dense, states)
        self.assertNotEqual(states, {0x10: frozenset({3})})
        self.assertNotEqual(
            states, {0x10: frozenset({3}), 0x14: frozenset(), 0x18: frozenset({9})}
        )
        # Same size, different keys: must not compare equal.
        self.assertNotEqual(
            states, {0x10: frozenset({3}), 0x14: frozenset(), 0x99: frozenset({4})}
        )

    def test_equality_between_compact_maps(self) -> None:
        self.assertEqual(self._map(1, 0, 2), self._map(1, 0, 2))
        self.assertNotEqual(self._map(1, 0, 2), self._map(1, 0, 3))

    def test_equality_ignores_domain_order_like_a_dict(self) -> None:
        first = AddressStateMap((0x10, 0x14), EMPTY_STATES, {0x10: frozenset({1})})
        second = AddressStateMap((0x14, 0x10), EMPTY_STATES, {0x10: frozenset({1})})
        self.assertEqual(first, second)
        self.assertEqual(dict(first), dict(second))
        # Only iteration order differs, which equality must not observe.
        self.assertEqual(list(first), [0x10, 0x14])
        self.assertEqual(list(second), [0x14, 0x10])

    def test_not_equal_to_unrelated_types(self) -> None:
        self.assertNotEqual(self._map(1), "0x10")
        self.assertNotEqual(self._map(1), None)

    def test_entries_only_hold_non_default_values(self) -> None:
        states = compact_states(
            (0x10, 0x14, 0x18),
            {0x10: frozenset(), 0x14: frozenset({5}), 0x18: frozenset()},
            EMPTY_STATES,
        )
        self.assertEqual(states.entry_count, 1)
        self.assertEqual(list(states.entry_items()), [(0x14, frozenset({5}))])
        self.assertEqual(retained_entries(states), 1)

    def test_replace_entries_keeps_the_shared_domain(self) -> None:
        states = compact_states((0x10, 0x14), {0x10: frozenset({1})}, EMPTY_STATES)
        updated = states.replace_entries({0x14: frozenset({2})})
        self.assertIs(updated.domain, states.domain)
        self.assertEqual(updated[0x10], frozenset())
        self.assertEqual(updated[0x14], frozenset({2}))
        self.assertEqual(len(updated), 2)

    def test_unhashable_like_a_dict(self) -> None:
        with self.assertRaises(TypeError):
            hash(self._map(1))

    def test_retained_entries_accepts_plain_dicts(self) -> None:
        self.assertEqual(
            retained_entries({0x10: frozenset(), 0x14: frozenset({1})}), 1
        )
        self.assertEqual(retained_entries({}), 0)

    def test_default_is_shared_not_copied(self) -> None:
        states = AddressStateMap((0x10, 0x14), EMPTY_STATES)
        # Both addresses resolve to the very same object: an empty state is
        # never materialised per address.
        self.assertIs(states[0x10], states[0x14])
        self.assertIs(states[0x10], EMPTY_STATES)
        self.assertIs(states.default, EMPTY_STATES)


if __name__ == "__main__":
    unittest.main()
