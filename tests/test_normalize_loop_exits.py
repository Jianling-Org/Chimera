"""Regression: reverse-indexed _normalize_loop_exits matches the legacy BFS version.

The optimized implementation replaces the per-loop forward-reachability BFS with a
symbol -> address reverse index. These tests pin the optimized output against an
inline copy of the legacy implementation so any semantic drift is caught.
"""
from __future__ import annotations

import random
import unittest

from chimera.preprocess.offline.analysis.arch.riscv.rvv.services import RiscvStackSemantics
from chimera.preprocess.offline.analysis.core.data_model import (
    BasicBlock,
    Function,
    Instruction,
)
from chimera.preprocess.offline.analysis.safety.stack_liveness.expressions import (
    Expr,
    LoopInput,
    PostLoopInput,
    Unknown,
    substitute,
)
from chimera.preprocess.offline.analysis.safety.stack_liveness.loops import _LoopAnalyzer
from chimera.preprocess.offline.analysis.safety.stack_liveness.solver import (
    _ScalarExpressionSolver,
)


def _legacy_normalize(
    self,
    function: Function,
    loop_info,
    before_states,
    outgoing_states,
    header_inputs,
) -> None:
    """Inline copy of the legacy per-loop BFS implementation (reference)."""
    instructions = function.instruction_by_address
    for loop in loop_info.natural_loops:
        exit_edges = [
            (address, successor)
            for address in loop.addresses
            for successor in instructions[address].succ
            if successor in instructions and successor not in loop.addresses
        ]
        if not exit_edges:
            continue
        replacements = {}
        for register in loop.written_registers:
            symbol = LoopInput(loop.header, register)
            exit_values = [outgoing_states.get(tail, {}).get(register, Unknown) for tail, _ in exit_edges]
            if exit_values and all(value == symbol for value in exit_values):
                replacement = header_inputs.get(loop.header, {}).get(register, Unknown)
                if isinstance(replacement, Expr):
                    replacements[symbol] = replacement
            else:
                replacements[symbol] = PostLoopInput(loop.header, register)
        if not replacements:
            continue
        reachable = set()
        worklist = list({successor for _, successor in exit_edges})
        reachable.update(worklist)
        while worklist:
            address = worklist.pop()
            for successor in instructions[address].succ:
                if successor in instructions and successor not in loop.addresses and successor not in reachable:
                    reachable.add(successor)
                    worklist.append(successor)
        for address in reachable:
            state = before_states.get(address)
            if state is None:
                continue
            before_states[address] = {
                register: substitute(value, replacements) if isinstance(value, Expr) else value
                for register, value in state.items()
            }


def _connect(source: BasicBlock, destination: BasicBlock) -> None:
    source.successors.append(destination)
    destination.predecessors.append(source)


def _instruction(address: int) -> Instruction:
    # Every instruction writes a0 so loop headers get a summary symbol.
    return Instruction(address, 4, "addi", ["a0", "a0", "1"], "addi a0, a0, 1")


def _block(start: int, count: int) -> BasicBlock:
    return BasicBlock([_instruction(start + i * 4) for i in range(count)])


def _link_instruction_succ(blocks: list[BasicBlock]) -> None:
    for block in blocks:
        body = block.instructions
        for i in range(len(body) - 1):
            body[i].succ.add(body[i + 1].addr)
        for successor in block.successors:
            body[-1].succ.add(successor.instructions[0].addr)


def _nested_loop_function() -> Function:
    # entry -> outer_header -> inner_header <-> inner_body -> outer_latch -> outer_header
    # outer_header -> exit  (loop exit uses a0)
    entry = _block(0x1000, 2)
    outer_header = _block(0x2000, 2)
    inner_header = _block(0x3000, 2)
    inner_body = _block(0x4000, 2)
    outer_latch = _block(0x5000, 2)
    exit_block = _block(0x6000, 2)
    _connect(entry, outer_header)
    _connect(outer_header, inner_header)
    _connect(inner_header, inner_body)
    _connect(inner_body, inner_header)   # inner back edge
    _connect(inner_body, outer_latch)    # inner exit
    _connect(outer_latch, outer_header)  # outer back edge
    _connect(outer_header, exit_block)   # outer exit
    blocks = [entry, outer_header, inner_header, inner_body, outer_latch, exit_block]
    _link_instruction_succ(blocks)
    insts = [inst for block in blocks for inst in block.instructions]
    return Function("nested", entry.start, insts=insts, blocks=blocks)


def _random_function(n_insns: int, rng: random.Random) -> Function:
    insts = [_instruction(0x10000 + i * 4) for i in range(n_insns)]
    blk = 8
    nb = max(1, n_insns // blk)
    blocks = [BasicBlock(insts[b * blk:(b + 1) * blk]) for b in range(nb)]
    for b in range(nb):
        nxt = (b + 1) % nb
        _connect(blocks[b], blocks[nxt])
        if rng.random() < 0.2 and b > 4:
            _connect(blocks[b], blocks[rng.randrange(max(0, b - 8), b)])  # back edge
        if rng.random() < 0.3 and b + 2 < nb:
            _connect(blocks[b], blocks[b + 2])  # forward branch
    _link_instruction_succ(blocks)
    return Function("synth", 0x10000, insts=insts, blocks=blocks)


def _analyze(function: Function, normalize) -> dict:
    semantics = RiscvStackSemantics()
    solver = _ScalarExpressionSolver(semantics)
    loop_info = _LoopAnalyzer(semantics).analyze(function)
    if normalize is not None:
        solver._normalize_loop_exits = normalize.__get__(solver, _ScalarExpressionSolver)
    return solver.analyze(function, loop_info)


def _states_equal(left: dict, right: dict) -> bool:
    if set(left) != set(right):
        return False
    return all(left[address] == right[address] for address in left)


class NormalizeLoopExitsTests(unittest.TestCase):
    def test_matches_legacy_on_nested_loops(self) -> None:
        function = _nested_loop_function()
        optimized = _analyze(function, None)
        legacy = _analyze(function, _legacy_normalize)
        self.assertTrue(_states_equal(optimized, legacy))

    def test_matches_legacy_on_random_cfgs(self) -> None:
        for seed in (1, 7, 42, 99):
            function = _random_function(600, random.Random(seed))
            optimized = _analyze(function, None)
            legacy = _analyze(function, _legacy_normalize)
            self.assertTrue(_states_equal(optimized, legacy), f"seed {seed}")


if __name__ == "__main__":
    unittest.main()
