"""从反汇编文本构造直接调用图。"""

from __future__ import annotations

from collections import defaultdict
from heapq import heapify, heappop, heappush
from typing import Iterable, Iterator

from riscv.frontend.text_index import TextProgramIndex
from riscv.frontend.model import CallEdge, CallEdgeKind, CallGraph
from riscv.frontend.model import RVFunction, RVProgram


class CallGraphBuilder:
    """只使用 dump.S 中显式目标构造调用关系。

    未解析的 ``jalr``、外部符号和缺少目标文本的调用都会生成边记录，
    但不会生成可供 vtype 摘要使用的内部函数目标。这样调用图可以完整
    报告未知来源，同时不会把启发式猜测引入翻译语义。
    """

    def build(
        self,
        program: RVProgram | Iterable[RVFunction],
        *,
        text_index: TextProgramIndex | None = None,
    ) -> CallGraph:
        functions = tuple(
            program.functions if isinstance(program, RVProgram) else list(program)
        )
        index = text_index or TextProgramIndex.build(
            program if isinstance(program, RVProgram) else functions
        )

        by_caller: dict[int, list[CallEdge]] = defaultdict(list)
        by_address: dict[int, CallEdge] = {}
        for function in functions:
            if not function.instructions:
                continue
            local_labels = {
                instruction.label: instruction.address
                for instruction in function.instructions
                if instruction.label
            }
            for instruction in function.instructions:
                kind = self._call_kind(instruction, index, function, local_labels)
                if kind is None:
                    continue
                target = index.resolve_target(instruction, local_labels=local_labels)
                # jalr/jr 即使被反汇编器附带打印了数值地址，架构上仍是
                # 寄存器间接转移；该地址只能作为审计信息，不能直接把
                # 它提升为可用于 vtype 摘要的函数目标。
                target_function = (
                    index.function_containing(target)
                    if kind is not CallEdgeKind.INDIRECT_CALL
                    else None
                )
                # 目标地址在当前函数内时，j/jal x0 是普通 CFG 跳转，不能
                # 被误报为 tail call；跨函数时才进入调用图。
                if (
                    kind is CallEdgeKind.TAIL_CALL
                    and target_function is function
                ):
                    continue
                is_external_stub = index.is_external_stub(target_function)
                target_is_function_entry = (
                    target_function is not None
                    and not is_external_stub
                    and target == target_function.start_addr
                )
                if kind is CallEdgeKind.INDIRECT_CALL:
                    provenance = "text:unresolved-indirect"
                elif target is None:
                    provenance = "text:unresolved-target"
                elif is_external_stub:
                    provenance = "text:external-stub"
                elif target_function is not None and not target_is_function_entry:
                    provenance = "text:direct-target-interior"
                else:
                    provenance = "text:direct-target"
                edge = CallEdge(
                    caller_function_start=function.start_addr,
                    call_address=instruction.address,
                    target_address=target,
                    target_symbol=instruction.target_symbol,
                    kind=kind,
                    target_function_start=(
                        target_function.start_addr
                        if target_function is not None and not is_external_stub
                        else None
                    ),
                    target_is_function_entry=target_is_function_entry,
                    resolved=(
                        target is not None
                        and target_function is not None
                        and not is_external_stub
                    ),
                    provenance=provenance,
                )
                by_caller[function.start_addr].append(edge)
                by_address[instruction.address] = edge

        return CallGraph(
            edges_by_caller={
                caller: tuple(edges)
                for caller, edges in by_caller.items()
            },
            edge_by_call_address=by_address,
        )

    @staticmethod
    def _call_kind(
        instruction,
        index: TextProgramIndex,
        function: RVFunction,
        local_labels: dict[str, int],
    ) -> CallEdgeKind | None:
        opcode = instruction.opcode.lower()
        if opcode == "call":
            return CallEdgeKind.DIRECT_CALL
        if opcode == "jalr":
            # 即使文本打印了一个绝对地址，jalr 的架构语义仍是寄存器
            # 间接调用；只有后续分析确认目标函数时才允许使用摘要。
            return CallEdgeKind.INDIRECT_CALL if index.is_call(instruction) else None
        if opcode == "jal":
            if index.is_call(instruction):
                return CallEdgeKind.DIRECT_CALL
            target = index.resolve_target(instruction, local_labels=local_labels)
            target_function = index.function_containing(target)
            if target_function is not None and target_function is function:
                return None
            return CallEdgeKind.TAIL_CALL
        if opcode == "tail":
            return CallEdgeKind.TAIL_CALL
        if opcode == "j":
            # ``j`` 是无条件跳转；只有文本明确表明目标属于另一个函数
            # 时，才将它视为 tail jump，避免污染函数内 CFG。
            target = index.resolve_target(instruction, local_labels=local_labels)
            target_function = index.function_containing(target)
            if target_function is not None and target_function is not function:
                return CallEdgeKind.TAIL_CALL
        return None


def strongly_connected_components(
    call_graph: CallGraph,
    function_starts: Iterable[int],
) -> tuple[frozenset[int], ...]:
    """使用 Tarjan 算法返回调用图 SCC。"""

    vertices = set(function_starts)
    adjacency = {
        vertex: {
            edge.target_function_start
            for edge in call_graph.edges_for(vertex)
            if (
                edge.resolved
                and edge.target_is_function_entry
                and edge.target_function_start in vertices
            )
        }
        for vertex in vertices
    }
    index_counter = 0
    indices: dict[int, int] = {}
    lowlinks: dict[int, int] = {}
    stack: list[int] = []
    on_stack: set[int] = set()
    components: list[frozenset[int]] = []

    # Explicit DFS frames preserve Tarjan's visit order without using Python's
    # call stack for deep chains or recursive components.
    for root in sorted(vertices):
        if root in indices:
            continue
        indices[root] = lowlinks[root] = index_counter
        index_counter += 1
        stack.append(root)
        on_stack.add(root)
        frames: list[tuple[int, Iterator[int]]] = [
            (root, iter(sorted(adjacency[root])))
        ]
        while frames:
            vertex, successors = frames[-1]
            successor = next(successors, None)
            if successor is not None:
                if successor not in indices:
                    indices[successor] = lowlinks[successor] = index_counter
                    index_counter += 1
                    stack.append(successor)
                    on_stack.add(successor)
                    frames.append((successor, iter(sorted(adjacency[successor]))))
                elif successor in on_stack:
                    lowlinks[vertex] = min(lowlinks[vertex], indices[successor])
                continue

            frames.pop()
            if frames:
                parent = frames[-1][0]
                lowlinks[parent] = min(lowlinks[parent], lowlinks[vertex])
            if lowlinks[vertex] == indices[vertex]:
                members: set[int] = set()
                while True:
                    member = stack.pop()
                    on_stack.remove(member)
                    members.add(member)
                    if member == vertex:
                        break
                components.append(frozenset(members))
    return tuple(components)


def bottom_up_sccs(
    call_graph: CallGraph,
    function_starts: Iterable[int],
) -> tuple[frozenset[int], ...]:
    """返回先叶函数、后调用者的 SCC 顺序。"""

    components = strongly_connected_components(call_graph, function_starts)
    component_of = {
        function_start: component_index
        for component_index, component in enumerate(components)
        for function_start in component
    }
    dependencies: dict[int, set[int]] = {
        index: set() for index in range(len(components))
    }
    reverse: dict[int, set[int]] = {
        index: set() for index in range(len(components))
    }
    for caller, edges in call_graph.edges_by_caller.items():
        caller_component = component_of.get(caller)
        if caller_component is None:
            continue
        for edge in edges:
            if (
                not edge.resolved
                or not edge.target_is_function_entry
                or edge.target_function_start is None
            ):
                continue
            callee_component = component_of.get(edge.target_function_start)
            if callee_component is None or callee_component == caller_component:
                continue
            dependencies[caller_component].add(callee_component)
            reverse[callee_component].add(caller_component)

    ready = [index for index, deps in dependencies.items() if not deps]
    heapify(ready)
    result: list[frozenset[int]] = []
    while ready:
        current = heappop(ready)
        result.append(components[current])
        for caller_component in sorted(reverse[current]):
            dependencies[caller_component].discard(current)
            # Each component becomes ready once, when its last dependency is
            # removed. Keep deterministic order without sorting a growing list
            # or rebuilding the emitted set for every call-graph edge.
            if not dependencies[caller_component]:
                heappush(ready, caller_component)

    # 理论上 SCC 缩点图无环；保留排序回退以防手工构造的异常调用图
    # 破坏输入不变量时仍能返回保守且确定的结果。
    if len(result) != len(components):
        emitted = {component for component in result}
        result.extend(
            components[index]
            for index in range(len(components))
            if components[index] not in emitted
        )
    return tuple(result)


__all__ = [
    "CallGraphBuilder",
    "bottom_up_sccs",
    "strongly_connected_components",
]
