"""CompactIntSet behaviour and compatibility with plain sets."""

from __future__ import annotations

import unittest

from chimera.preprocess.offline.analysis.core.data_model import (
    CompactIntSet,
    Instruction,
)


class CompactIntSetTests(unittest.TestCase):
    def test_empty_set(self):
        values = CompactIntSet()
        self.assertEqual(len(values), 0)
        self.assertFalse(values)
        self.assertEqual(list(values), [])
        self.assertNotIn(1, values)
        self.assertEqual(values, set())

    def test_add_and_deduplicate(self):
        values = CompactIntSet()
        values.add(7)
        values.add(7)
        values.add(3)
        self.assertEqual(len(values), 2)
        self.assertEqual(set(values), {3, 7})
        self.assertTrue(values)

    def test_upgrade_to_tuple_then_builtin_set(self):
        values = CompactIntSet()
        for item in (4, 1, 3, 2):
            values.add(item)
        self.assertEqual(len(values), 4)
        self.assertEqual(set(values), {1, 2, 3, 4})
        values.add(5)  # crosses the tuple threshold -> builtin set
        self.assertEqual(len(values), 5)
        self.assertEqual(set(values), {1, 2, 3, 4, 5})

    def test_downgrade_on_discard(self):
        values = CompactIntSet(range(10))
        self.assertEqual(len(values), 10)
        for item in range(10, 4, -1):  # discard down to {0..4}
            values.discard(item)
        self.assertEqual(set(values), {0, 1, 2, 3, 4})
        for item in (4, 3, 2):
            values.discard(item)
        self.assertEqual(set(values), {0, 1})
        values.discard(1)
        self.assertEqual(set(values), {0})
        values.discard(0)
        self.assertEqual(len(values), 0)
        self.assertFalse(values)
        values.discard(99)  # discarding from empty is a no-op
        self.assertEqual(len(values), 0)

    def test_clear_restores_empty_representation(self):
        values = CompactIntSet(range(9))
        values.clear()
        self.assertEqual(len(values), 0)
        self.assertFalse(values)
        self.assertEqual(values, set())
        values.add(1)
        self.assertEqual(set(values), {1})

    def test_update_accepts_iterables(self):
        values = CompactIntSet()
        values.update(iter([1, 2, 2, 3]))
        self.assertEqual(set(values), {1, 2, 3})

    def test_equality_with_plain_sets(self):
        compact = CompactIntSet([5, 6, 7])
        self.assertEqual(compact, {5, 6, 7})
        self.assertEqual(compact, frozenset({5, 6, 7}))
        self.assertNotEqual(compact, {5, 6})
        self.assertNotEqual(compact, "567")
        self.assertEqual(CompactIntSet([1]), CompactIntSet([1]))
        self.assertNotEqual(CompactIntSet([1]), CompactIntSet([2]))

    def test_membership_and_iteration(self):
        values = CompactIntSet([10, 20, 30, 40, 50])
        self.assertIn(30, values)
        self.assertNotIn(31, values)
        self.assertEqual(sorted(values), [10, 20, 30, 40, 50])
        # No ordering guarantee: iteration must only cover each element once.
        self.assertEqual(set(values), {10, 20, 30, 40, 50})

    def test_repr_roundtrip_shape(self):
        self.assertEqual(repr(CompactIntSet([2, 1])), "CompactIntSet([1, 2])")
        self.assertEqual(repr(CompactIntSet()), "CompactIntSet([])")

    def test_instance_isolation(self):
        first = CompactIntSet()
        second = CompactIntSet()
        first.add(1)
        self.assertEqual(len(second), 0)

        one = Instruction(addr=0x10, size=4, op="nop", args=[], text="x")
        two = Instruction(addr=0x14, size=4, op="nop", args=[], text="y")
        one.succ.add(0x14)
        self.assertEqual(len(two.succ), 0)  # no shared mutable default
        self.assertEqual(two.succ, set())

    def test_instruction_accepts_plain_sets(self):
        provided = {0x20}
        instruction = Instruction(
            addr=0x10, size=4, op="j", args=["20"], text="x",
            succ=provided, jump_targets=set(), jump_sources={0x8},
        )
        self.assertIs(instruction.succ, provided)
        self.assertEqual(instruction.succ, {0x20})
        self.assertEqual(instruction.jump_sources, {0x8})


if __name__ == "__main__":
    unittest.main()
