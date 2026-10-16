"""Instruction facts shared by the stack-analysis stages.

Target-specific spelling is deliberately kept in one adapter-facing module so
the data-flow solvers do not scatter RISC-V mnemonic checks throughout their
implementations.
"""

from __future__ import annotations

from ...core.data_model import Function
def function_exit_addresses(function: Function) -> set[int]:
    return {
        instruction.addr
        for instruction in function.insts
        if instruction.is_return or not instruction.succ
    }


def instruction_predecessors(function: Function) -> dict[int, set[int]]:
    # Pre-size with empty sets so branch fan-in lands directly; most
    # instructions have exactly one predecessor, but the dict-of-sets
    # layout keeps the dataflow solver API unchanged.
    predecessors: dict[int, set[int]] = {
        instruction.addr: set() for instruction in function.insts
    }
    for instruction in function.insts:
        # succ is a CompactIntSet; iteration order is unspecified, and the
        # set-union semantics here do not depend on it.
        for successor in instruction.succ:
            if successor in predecessors:
                predecessors[successor].add(instruction.addr)
    return predecessors


# Private aliases keep the existing solver names stable while making this file
# the single ownership point for the instruction facts.
_function_exit_addresses = function_exit_addresses
_instruction_predecessors = instruction_predecessors
