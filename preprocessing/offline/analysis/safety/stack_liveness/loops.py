"""Natural and irreducible loop discovery."""

from collections import defaultdict
from typing import Iterable

from ...core.algorithm.graph import immediate_dominators, strongly_connected_components
from ...core.data_model.program import BasicBlock, Function
from ...core.contracts import StackSemantics
from ...core.monitor import argument, monitored, returned
from .model import IrreducibleLoopInfo, LoopInfo, NaturalLoopInfo

# region CFG loop analysis


class _LoopAnalyzer:
    """Identify natural-loop summaries and irreducible SCCs on an existing CFG."""

    def __init__(self, semantics: StackSemantics) -> None:
        self._semantics = semantics

    @monitored(
        "safety.loop-analysis",
        variables=(
            argument("function", label="function", path=("name",)),
            argument("function", label="function_start", path=("start",)),
            returned(label="natural_loops", path=("natural_loops",), transform=len),
            returned(label="back_edges", path=("back_edges",), transform=len),
            returned(label="irreducible_scc", path=("irreducible_loops",), transform=len),
            returned(
                label="irreducible_addresses",
                path=("irreducible_addresses",),
                transform=len,
            ),
        ),
    )
    def analyze(self, function: Function) -> LoopInfo:
        if not function.blocks:
            return LoopInfo((), (), frozenset(), {}, frozenset())

        block_idominators = immediate_dominators(
            function.blocks,
            successors=lambda block: block.successors,
            predecessors=lambda block: block.predecessors,
        )
        tin, tout = self._dominance_intervals(function.blocks, block_idominators)
        blocks_by_header: dict[int, set[BasicBlock]] = defaultdict(set)
        tails_by_header: dict[int, set[BasicBlock]] = defaultdict(set)
        all_back_edges: set[tuple[int, int]] = set()

        for tail in function.blocks:
            for header in tail.successors:
                if header != tail:
                    header_tin = tin.get(header)
                    if header_tin is None or not header_tin <= tin[tail] < tout[header]:
                        continue
                blocks_by_header[header.start].update(
                    self._collect_natural_loop(tail, header)
                )
                tails_by_header[header.start].add(tail)
                all_back_edges.add((tail.instructions[-1].addr, header.start))

        natural_loops: list[NaturalLoopInfo] = []
        header_written: dict[int, frozenset[str]] = {}
        for header in sorted(blocks_by_header):
            blocks = blocks_by_header[header]
            addresses = self._block_addresses(blocks)
            written = frozenset(
                register
                for block in blocks
                for instruction in block.instructions
                for register in self._semantics.written_scalar_registers(instruction)
            )
            back_edges = frozenset(
                (tail.instructions[-1].addr, header)
                for tail in tails_by_header[header]
            )
            loop = NaturalLoopInfo(
                header=header,
                addresses=frozenset(addresses),
                back_edges=back_edges,
                written_registers=written,
            )
            natural_loops.append(loop)
            header_written[header] = written

        irreducible_loops: list[IrreducibleLoopInfo] = []
        irreducible_addresses: set[int] = set()
        for component in strongly_connected_components(
            function.blocks,
            lambda block: block.successors,
        ):
            if len(component) == 1:
                block = next(iter(component))
                if block not in block.successors:
                    continue
            entries = {
                block
                for block in component
                if any(pred not in component for pred in block.predecessors)
            }
            if len(entries) <= 1:
                continue
            addresses = frozenset(self._block_addresses(component))
            irreducible_addresses.update(addresses)
            irreducible_loops.append(
                IrreducibleLoopInfo(
                    addresses=addresses,
                    entry_blocks=frozenset(block.start for block in entries),
                )
            )

        return LoopInfo(
            natural_loops=tuple(
                sorted(natural_loops, key=lambda loop: (len(loop.addresses), loop.header))
            ),
            irreducible_loops=tuple(
                sorted(
                    irreducible_loops,
                    key=lambda loop: (min(loop.addresses), len(loop.addresses)),
                )
            ),
            back_edges=frozenset(all_back_edges),
            header_written_registers=header_written,
            irreducible_addresses=frozenset(irreducible_addresses),
        )

    @staticmethod
    def _collect_natural_loop(
        tail: BasicBlock,
        header: BasicBlock,
    ) -> set[BasicBlock]:
        """Blocks that reach ``tail`` from the region entry without leaving it.

        A *self edge* (``tail is header``) is a loop of exactly one block: the
        edge is the whole loop, and the header is its own loop entry.  Walking
        the header's predecessors there would instead collect every block that
        can reach the header — that is the enclosing region, not the loop — and
        would report the function prologue as loop-written (turning the entry
        ``sp`` into a ``loop_input`` symbol).

        Every other back edge is collected backwards from its tail; the walk
        stops at the header and never continues past the header's own
        predecessors, so the loop stays inside the region entered at the
        header while still merging every tail that targets the same header.
        """

        if tail is header:
            return {header}

        loop = {header, tail}
        pending = [tail]
        while pending:
            block = pending.pop()
            for predecessor in block.predecessors:
                if predecessor not in loop:
                    loop.add(predecessor)
                    pending.append(predecessor)
        return loop

    @staticmethod
    def _dominance_intervals(
        blocks: Iterable[BasicBlock],
        idominators: dict[BasicBlock, BasicBlock],
    ) -> tuple[dict[BasicBlock, int], dict[BasicBlock, int]]:
        """Index the dominator tree so dominance checks are constant-time."""
        children: dict[BasicBlock, list[BasicBlock]] = defaultdict(list)
        for child, parent in idominators.items():
            children[parent].append(child)

        tin: dict[BasicBlock, int] = {}
        tout: dict[BasicBlock, int] = {}
        time = 0
        for root in blocks:
            if root in tin:
                continue
            pending = [(root, False)]
            while pending:
                block, exiting = pending.pop()
                if exiting:
                    tout[block] = time
                    continue
                if block in tin:
                    continue
                tin[block] = time
                time += 1
                pending.append((block, True))
                pending.extend(
                    (child, False) for child in reversed(children.get(block, ()))
                )
        return tin, tout

    @staticmethod
    def _block_addresses(blocks: Iterable[BasicBlock]) -> set[int]:
        return {
            instruction.addr
            for block in blocks
            for instruction in block.instructions
        }


# endregion


__all__ = ["_LoopAnalyzer"]
