"""Architecture-neutral graph algorithms used by offline analyses."""

from __future__ import annotations

from collections.abc import Callable, Hashable, Iterable, Iterator, Sequence
from typing import TypeVar


Node = TypeVar("Node", bound=Hashable)


def dominators(
    nodes: Sequence[Node],
    predecessors: Callable[[Node], Iterable[Node]],
) -> dict[Node, set[Node]]:
    if not nodes:
        return {}
    entry = nodes[0]
    all_nodes = set(nodes)
    result = {node: ({node} if node == entry else set(all_nodes)) for node in nodes}
    changed = True
    while changed:
        changed = False
        for node in nodes[1:]:
            incoming = list(predecessors(node))
            shared = set.intersection(*(result[value] for value in incoming)) if incoming else set()
            value = {node} | shared
            if value != result[node]:
                result[node] = value
                changed = True
    return result


def immediate_dominators(
    nodes: Sequence[Node],
    *,
    successors: Callable[[Node], Iterable[Node]],
    predecessors: Callable[[Node], Iterable[Node]],
) -> dict[Node, Node]:
    """Return immediate dominators reachable from ``nodes[0]``.

    This is the Lengauer-Tarjan algorithm with an iterative DFS and
    path-compressed link/eval forest.  It uses O(V + E) space and runs in
    O(E log V) time for the reachable subgraph.  The entry node and nodes
    unreachable from it are intentionally omitted from the result.
    """
    if not nodes:
        return {}

    entry = nodes[0]
    node_set = set(nodes)
    dfs_number = {entry: 0}
    vertex = [entry]
    parent = [-1]

    # Number nodes in DFS preorder without risking Python's recursion limit
    # on large functions.  Successors outside ``nodes`` are ignored so a
    # malformed edge cannot become part of the dominator tree.
    pending: list[tuple[Node, Iterator[Node]]] = [(entry, iter(successors(entry)))]
    while pending:
        node, iterator = pending[-1]
        try:
            successor = next(iterator)
        except StopIteration:
            pending.pop()
            continue
        if successor not in node_set or successor in dfs_number:
            continue
        successor_number = len(vertex)
        dfs_number[successor] = successor_number
        vertex.append(successor)
        parent.append(dfs_number[node])
        pending.append((successor, iter(successors(successor))))

    count = len(vertex)
    semidominator = list(range(count))
    label = list(range(count))
    ancestor = [-1] * count
    immediate = [-1] * count
    buckets: list[list[int]] = [[] for _ in range(count)]

    def evaluate(value: int) -> int:
        """Return the best label while iteratively applying path compression."""
        if ancestor[value] == -1:
            return label[value]

        path: list[int] = []
        current = value
        while (
            ancestor[current] != -1
            and ancestor[ancestor[current]] != -1
        ):
            path.append(current)
            current = ancestor[current]
        for node in reversed(path):
            parent_node = ancestor[node]
            if semidominator[label[parent_node]] < semidominator[label[node]]:
                label[node] = label[parent_node]
            ancestor[node] = ancestor[parent_node]
        return label[value]

    for node_number in range(count - 1, 0, -1):
        node = vertex[node_number]
        for predecessor in predecessors(node):
            predecessor_number = dfs_number.get(predecessor)
            if predecessor_number is None:
                continue
            candidate = evaluate(predecessor_number)
            if semidominator[candidate] < semidominator[node_number]:
                semidominator[node_number] = semidominator[candidate]

        buckets[semidominator[node_number]].append(node_number)
        ancestor[node_number] = parent[node_number]
        parent_bucket = buckets[parent[node_number]]
        for bucketed_node in parent_bucket:
            candidate = evaluate(bucketed_node)
            immediate[bucketed_node] = (
                candidate
                if semidominator[candidate] < semidominator[bucketed_node]
                else parent[node_number]
            )
        parent_bucket.clear()

    for node_number in range(1, count):
        if immediate[node_number] != semidominator[node_number]:
            immediate[node_number] = immediate[immediate[node_number]]

    return {
        vertex[node_number]: vertex[immediate[node_number]]
        for node_number in range(1, count)
    }


def strongly_connected_components(
    nodes: Sequence[Node],
    successors: Callable[[Node], Iterable[Node]],
) -> list[set[Node]]:
    """Tarjan SCC with an explicit call stack (no recursion-depth limit)."""
    index = 0
    stack: list[Node] = []
    on_stack: set[Node] = set()
    indices: dict[Node, int] = {}
    lowlink: dict[Node, int] = {}
    components: list[set[Node]] = []
    call_stack: list[tuple[Node, Iterable[Node]]] = []

    for start in nodes:
        if start in indices:
            continue
        call_stack.append((start, iter(successors(start))))
        while call_stack:
            node, iterator = call_stack[-1]
            if node not in indices:
                indices[node] = lowlink[node] = index
                index += 1
                stack.append(node)
                on_stack.add(node)
            progressed = False
            for successor in iterator:
                if successor not in indices:
                    call_stack.append((successor, iter(successors(successor))))
                    progressed = True
                    break
                if successor in on_stack:
                    lowlink[node] = min(lowlink[node], indices[successor])
            if progressed:
                continue
            call_stack.pop()
            if call_stack:
                parent = call_stack[-1][0]
                lowlink[parent] = min(lowlink[parent], lowlink[node])
            if lowlink[node] == indices[node]:
                component: set[Node] = set()
                while True:
                    member = stack.pop()
                    on_stack.remove(member)
                    component.add(member)
                    if member == node:
                        break
                components.append(component)
    return components
