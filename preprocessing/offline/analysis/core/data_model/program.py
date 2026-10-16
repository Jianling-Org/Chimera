"""Shared program structures used by Chimera's offline analyses."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from .int_set import CompactIntSet


@dataclass(slots=True)
class Instruction:
    addr: int
    size: int
    op: str
    # Read-only operand sequence; tuples keep the per-instruction
    # overhead minimal (callers never mutate it).
    args: list[str] | tuple[str, ...]
    text: str
    machine_code: str = ""
    operand: str = ""
    line_index: int = 0

    # CFG facts filled by cfg.py.  The compact tiered container keeps the
    # empty/singleton cases allocation-light; callers may still pass a
    # plain ``set`` and it is stored as-is.  Iteration order is not part
    # of the contract — consumers must derive set semantics only.
    succ: set[int] = field(default_factory=CompactIntSet)
    jump_targets: set[int] = field(default_factory=CompactIntSet)
    jump_sources: set[int] = field(default_factory=CompactIntSet)
    ends_block: bool = False
    is_return: bool = False


@dataclass(eq=False)
class BasicBlock:
    instructions: list[Instruction]
    predecessors: list["BasicBlock"] = field(default_factory=list)
    successors: list["BasicBlock"] = field(default_factory=list)

    @property
    def start(self) -> int:
        return self.instructions[0].addr

    @property
    def end(self) -> int:
        return self.instructions[-1].addr


@dataclass
class Function:
    name: str
    start: int
    insts: list[Instruction] = field(default_factory=list)
    blocks: list[BasicBlock] = field(default_factory=list)
    # Toolchain disassemblers may classify external linkage trampolines.
    # Analysis consumes this fact without knowing the spelling or object
    # format convention used by the disassembler.
    is_external_trampoline: bool = False

    @property
    def end(self) -> int:
        return self.insts[-1].addr if self.insts else self.start

    @property
    def instruction_by_address(self) -> dict[int, Instruction]:
        return {instruction.addr: instruction for instruction in self.insts}


@dataclass
class Program:
    dump_lines: list[str]
    functions: list[Function]
    instructions: list[Instruction]
    instruction_by_address: dict[int, Instruction]
    source_path: Path | None = None
