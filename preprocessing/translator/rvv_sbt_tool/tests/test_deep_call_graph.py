"""Deep DFS and independent SCC partition/order regressions."""

import random

import pytest

from riscv.frontend.call_graph import bottom_up_sccs, strongly_connected_components
from riscv.frontend.model import CallEdge, CallEdgeKind, CallGraph
from riscv.frontend.parser import AsmParser
from riscv.extensions.rvv.translation.pipeline import analyze_program


def _graph(adjacency):
    return CallGraph({
        caller: tuple(CallEdge(caller, caller * 16 + i, callee, None,
                              CallEdgeKind.DIRECT_CALL, callee, True, True)
                      for i, callee in enumerate(callees))
        for caller, callees in adjacency.items()
    }, {})


@pytest.mark.parametrize("count", [1000, 2000, 5000])
@pytest.mark.parametrize("cycle", [False, True])
def test_deep_call_graph_has_no_python_recursion_limit(count, cycle):
    adjacency = {i: (i + 1,) for i in range(count - 1)}
    adjacency[count - 1] = (0,) if cycle else ()
    expected = ((frozenset(range(count)),) if cycle else
                tuple(frozenset({i}) for i in reversed(range(count))))
    graph = _graph(adjacency)
    assert strongly_connected_components(graph, range(count)) == expected
    assert bottom_up_sccs(graph, range(count)) == expected


def test_scc_partition_matches_mutual_reachability_and_dependency_order():
    rng = random.Random(763)
    for _ in range(80):
        count = rng.randrange(1, 25)
        adjacency = {i: {j for j in range(count) if rng.random() < 0.13}
                     for i in range(count)}
        reachable = {}
        for vertex in adjacency:
            reached, pending = set(), [vertex]
            while pending:
                item = pending.pop()
                if item in reached:
                    continue
                reached.add(item)
                pending.extend(adjacency[item] - reached)
            reachable[vertex] = reached
        expected = {frozenset(j for j in range(count)
                              if j in reachable[i] and i in reachable[j])
                    for i in range(count)}
        components = bottom_up_sccs(_graph(adjacency), reversed(range(count)))
        assert set(components) == expected
        component_of = {vertex: i for i, component in enumerate(components)
                        for vertex in component}
        for caller, callees in adjacency.items():
            assert all(component_of[callee] <= component_of[caller] for callee in callees)


def test_scc_order_is_stable_for_disconnected_branches_and_cycles():
    graph = _graph({0: (3, 1), 1: (2,), 2: (1,), 3: (4,), 4: (),
                    5: (6,), 6: (5,), 7: ()})
    expected = tuple(map(frozenset, ({1, 2}, {4}, {3}, {0}, {5, 6}, {7})))
    assert strongly_connected_components(graph, reversed(range(8))) == expected
    assert bottom_up_sccs(graph, reversed(range(8))) == expected


@pytest.mark.parametrize("count", [1000, 2000])
def test_deep_program_vtype_summaries_keep_leaf_first_order(count):
    source = []
    for i in range(count):
        address = 0x1000 + 16 * i
        source.append(f"{address:08x} <function_{i}>:")
        if i < count - 1:
            source.append(f" {address:x}: 000000ef call {address + 16:x} <function_{i + 1}>")
        else:
            source.append(f" {address:x}: 01007057 vsetivli zero,4,e32,m1,tu,mu")
        source.append(f" {address + 4:x}: 00008067 ret")
    analysis = analyze_program(AsmParser().parse_string_program("\n".join(source)))
    starts = [0x1000 + 16 * i for i in reversed(range(count))]
    assert list(analysis.function_summaries) == starts
    leaf = analysis.function_summaries[starts[0]]
    assert leaf.normal_return and not leaf.has_unknown_effect
    assert all(summary.effects == leaf.effects and summary.normal_return
               for summary in analysis.function_summaries.values())
