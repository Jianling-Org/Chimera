from __future__ import annotations

from random import Random
import unittest

from chimera.preprocess.offline.analysis.core.algorithm.graph import (
    dominators,
    immediate_dominators,
    strongly_connected_components,
)
from chimera.preprocess.offline.analysis.core.data_model import (
    BasicBlock,
    Function,
    Instruction,
)
from chimera.preprocess.offline.analysis.safety.stack_liveness.loops import (
    _LoopAnalyzer,
)


def _reachable(nodes: list[int], successors: dict[int, set[int]]) -> set[int]:
    if not nodes:
        return set()
    visited = {nodes[0]}
    pending = [nodes[0]]
    while pending:
        node = pending.pop()
        for successor in successors[node]:
            if successor not in visited:
                visited.add(successor)
                pending.append(successor)
    return visited


def _idom_dominates(header: int, tail: int, idoms: dict[int, int]) -> bool:
    current = tail
    while True:
        if current == header:
            return True
        parent = idoms.get(current)
        if parent is None:
            return False
        current = parent


def _instruction(address: int) -> Instruction:
    return Instruction(address, 4, "addi", ["a0", "a0", "1"], "addi a0, a0, 1")


def _block(address: int) -> BasicBlock:
    return BasicBlock([_instruction(address)])


def _connect(source: BasicBlock, destination: BasicBlock) -> None:
    source.successors.append(destination)
    destination.predecessors.append(source)


class _NoRegistersWritten:
    def written_scalar_registers(self, instruction: Instruction) -> set[str]:
        return set()


class ImmediateDominatorsTests(unittest.TestCase):
    def test_empty_and_single_node_graphs_have_no_immediate_dominators(self) -> None:
        self.assertEqual(
            immediate_dominators([], successors=lambda _: (), predecessors=lambda _: ()),
            {},
        )
        self.assertEqual(
            immediate_dominators([0], successors=lambda _: (), predecessors=lambda _: ()),
            {},
        )

    def test_chain_and_diamond_immediate_dominators(self) -> None:
        chain_successors = {0: {1}, 1: {2}, 2: set()}
        chain_predecessors = {0: set(), 1: {0}, 2: {1}}
        self.assertEqual(
            immediate_dominators(
                [0, 1, 2],
                successors=lambda node: chain_successors[node],
                predecessors=lambda node: chain_predecessors[node],
            ),
            {1: 0, 2: 1},
        )

        diamond_successors = {0: {1, 2}, 1: {3}, 2: {3}, 3: set()}
        diamond_predecessors = {0: set(), 1: {0}, 2: {0}, 3: {1, 2}}
        self.assertEqual(
            immediate_dominators(
                [0, 1, 2, 3],
                successors=lambda node: diamond_successors[node],
                predecessors=lambda node: diamond_predecessors[node],
            ),
            {1: 0, 2: 0, 3: 0},
        )

    def test_ignores_unreachable_nodes_and_successors_outside_the_graph(self) -> None:
        successors = {
            0: {1, 99},
            1: set(),
            2: {2},
        }
        predecessors = {
            0: set(),
            1: {0},
            2: {2},
        }

        result = immediate_dominators(
            [0, 1, 2],
            successors=lambda node: successors[node],
            predecessors=lambda node: predecessors[node],
        )

        self.assertEqual(result, {1: 0})
        self.assertNotIn(0, result)
        self.assertNotIn(2, result)
        self.assertNotIn(99, result)

    def test_random_reachable_dominance_matches_legacy_algorithm(self) -> None:
        random = Random(0xD01A)
        for case in range(40):
            nodes = list(range(2 + random.randrange(29)))
            successors = {node: set() for node in nodes}
            for source in nodes:
                for destination in nodes:
                    if random.random() < 0.14:
                        successors[source].add(destination)
            predecessors = {node: set() for node in nodes}
            for source, destinations in successors.items():
                for destination in destinations:
                    predecessors[destination].add(source)

            idoms = immediate_dominators(
                nodes,
                successors=lambda node: successors[node],
                predecessors=lambda node: predecessors[node],
            )
            reachable = _reachable(nodes, successors)
            reachable_nodes = [node for node in nodes if node in reachable]
            # The legacy solver has no reachability phase: an unreachable
            # predecessor can incorrectly constrain a reachable node.  Compare
            # against its result on the same entry-reachable induced subgraph.
            legacy = dominators(
                reachable_nodes,
                lambda node: (value for value in predecessors[node] if value in reachable),
            )

            self.assertIn(nodes[0], legacy[nodes[0]], msg=f"case {case}")
            self.assertEqual(set(idoms), reachable - {nodes[0]}, msg=f"case {case}")
            for tail in reachable:
                for header in reachable:
                    self.assertEqual(
                        _idom_dominates(header, tail, idoms),
                        header in legacy[tail],
                        msg=f"case {case}: expected {header} dominates {tail}",
                    )

    def test_loop_analyzer_keeps_regular_and_self_back_edges(self) -> None:
        entry = _block(0x10)
        header = _block(0x20)
        tail = _block(0x30)
        self_loop = _block(0x40)
        _connect(entry, header)
        _connect(header, tail)
        _connect(tail, header)
        _connect(header, self_loop)
        _connect(self_loop, self_loop)
        function = Function(
            "loops",
            entry.start,
            blocks=[entry, header, tail, self_loop],
        )

        result = _LoopAnalyzer(_NoRegistersWritten()).analyze(function)

        self.assertEqual(
            result.back_edges,
            frozenset(
                {
                    (tail.instructions[-1].addr, header.start),
                    (self_loop.instructions[-1].addr, self_loop.start),
                }
            ),
        )
        self.assertEqual(
            {loop.header for loop in result.natural_loops},
            {header.start, self_loop.start},
        )

    def test_self_loop_never_pulls_its_external_predecessors(self) -> None:
        # entry -> prologue -> header -> self_loop (self edge) -> exit
        # A single self edge is a loop of exactly one block.  Walking the
        # header's predecessors would pull the whole prologue into the loop
        # and report every function-entry register (``sp`` included) as
        # loop-written.
        entry = _block(0x10)
        prologue = _block(0x20)
        header = _block(0x30)
        exit_block = _block(0x40)
        _connect(entry, prologue)
        _connect(prologue, header)
        _connect(header, header)          # self edge
        _connect(header, exit_block)
        function = Function(
            "self_loop",
            entry.start,
            blocks=[entry, prologue, header, exit_block],
        )

        result = _LoopAnalyzer(_NoRegistersWritten()).analyze(function)

        loops = {loop.header: loop for loop in result.natural_loops}
        self.assertEqual(set(loops), {header.start})
        self.assertEqual(
            loops[header.start].addresses,
            frozenset({header.instructions[0].addr}),
        )
        self.assertEqual(
            loops[header.start].back_edges,
            frozenset({(header.instructions[-1].addr, header.start)}),
        )
        self.assertNotIn(prologue.instructions[0].addr, loops[header.start].addresses)

    def test_self_loop_does_not_collect_entry_registers(self) -> None:
        # The prologue writes ``sp``; a self-loop header must not report it.
        class _SpAndT0Written:
            def written_scalar_registers(self, instruction: Instruction) -> set[str]:
                return {"sp"} if instruction is entry.instructions[0] else {"t0"}

        entry = _block(0x10)
        header = _block(0x30)
        _connect(entry, header)
        _connect(header, header)
        function = Function("self_loop", entry.start, blocks=[entry, header])

        result = _LoopAnalyzer(_SpAndT0Written()).analyze(function)

        self.assertEqual(
            result.header_written_registers[header.start], frozenset({"t0"})
        )

    def test_regular_back_edge_stops_at_the_header(self) -> None:
        # entry -> prologue -> header -> body -> latch -> header, and the
        # latch also reaches the header through the prologue path... the loop
        # must still contain only the blocks between header and latch.
        entry = _block(0x10)
        header = _block(0x20)
        body = _block(0x30)
        latch = _block(0x40)
        exit_block = _block(0x50)
        _connect(entry, header)
        _connect(header, body)
        _connect(body, latch)
        _connect(latch, header)          # back edge
        _connect(header, exit_block)
        function = Function(
            "regular", entry.start, blocks=[entry, header, body, latch, exit_block]
        )

        result = _LoopAnalyzer(_NoRegistersWritten()).analyze(function)

        loops = {loop.header: loop for loop in result.natural_loops}
        self.assertEqual(set(loops), {header.start})
        self.assertEqual(
            loops[header.start].addresses,
            frozenset(
                block.instructions[0].addr for block in (header, body, latch)
            ),
        )
        self.assertNotIn(entry.instructions[0].addr, loops[header.start].addresses)

    def test_nested_loops_and_multiple_back_edges_still_merge(self) -> None:
        entry = _block(0x10)
        outer = _block(0x20)
        inner = _block(0x30)
        inner_latch = _block(0x40)
        outer_latch_a = _block(0x50)
        outer_latch_b = _block(0x60)
        exit_block = _block(0x70)
        _connect(entry, outer)
        _connect(outer, inner)
        _connect(inner, inner_latch)
        _connect(inner_latch, inner)         # inner back edge
        _connect(inner_latch, outer_latch_a)  # inner exit
        _connect(outer_latch_a, outer)        # outer back edge #1
        _connect(outer_latch_a, outer_latch_b)
        _connect(outer_latch_b, outer)        # outer back edge #2
        _connect(outer, exit_block)
        function = Function(
            "nested",
            entry.start,
            blocks=[
                entry, outer, inner, inner_latch,
                outer_latch_a, outer_latch_b, exit_block,
            ],
        )

        result = _LoopAnalyzer(_NoRegistersWritten()).analyze(function)

        loops = {loop.header: loop for loop in result.natural_loops}
        inner_addresses = frozenset(
            block.instructions[0].addr for block in (inner, inner_latch)
        )
        self.assertEqual(loops[inner.start].addresses, inner_addresses)
        # Both outer back edges merge into one natural loop, and no loop
        # contains the entry block.
        self.assertEqual(len(loops[outer.start].back_edges), 2)
        self.assertTrue(
            all(
                entry.instructions[0].addr not in loop.addresses
                for loop in result.natural_loops
            )
        )


class StronglyConnectedComponentsTests(unittest.TestCase):
    def test_deep_chain_does_not_use_python_recursion(self) -> None:
        count = 5_000
        components = strongly_connected_components(
            list(range(count)),
            successors=lambda node: (node + 1,) if node + 1 < count else (),
        )

        self.assertEqual(len(components), count)
        self.assertTrue(all(len(component) == 1 for component in components))

    def test_empty_and_self_loop_graphs(self) -> None:
        self.assertEqual(strongly_connected_components([], lambda _: ()), [])
        self.assertEqual(
            strongly_connected_components([0], lambda _: (0,)),
            [{0}],
        )


if __name__ == "__main__":
    unittest.main()
