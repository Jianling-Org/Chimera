"""Control-flow classification and CFG construction for offline analysis."""

from __future__ import annotations

import re

from ...core.data_model import BasicBlock, Function, Instruction, Program


CONDITIONAL_BRANCHES = {
    "beq",
    "bne",
    "blt",
    "bge",
    "bltu",
    "bgeu",
    "beqz",
    "bnez",
    "bltz",
    "bgez",
    "blez",
    "bgtz",
}
BLOCK_TERMINATORS = CONDITIONAL_BRANCHES | {
    "j",
    "jal",
    "jalr",
    "call",
    "jr",
    "ret",
    "tail",
    "ebreak",
}
NO_FALLTHROUGH = {"j", "jr", "ret", "tail", "ebreak"}
OBJDUMP_RESOLVED_TARGET_RE = re.compile(
    r"#\s*(?:0x)?([0-9a-f]+)\b",
    re.IGNORECASE,
)
#: Operands that name the zero register, i.e. "this instruction links no
#: return address".
_ZERO_LINK_OPERANDS = {"zero", "x0"}


def is_call_instruction(instruction: Instruction) -> bool:
    """Return true for link-register calls, but not ``jal/jalr x0`` jumps.

    This is the single call/jump classification of the RISC-V CFG builder:
    block connection, the fallthrough rule and instruction successors all
    read it, so a call is never connected as an in-function control-flow
    edge while every consumer that reads the recorded target information
    still recognises it as a call.

    ``jal``/``jalr`` with one operand carry the return address implicitly
    (``jal target``; ``jalr rs`` is the compressed ``c.jalr``), and the
    explicit forms name the link register first: a non-zero register is a
    call, ``zero``/``x0`` is the unconditional jump ``j``/``jr`` spelled
    out.
    """

    if instruction.op == "call":
        return True
    if instruction.op not in {"jal", "jalr"}:
        return False
    if len(instruction.args) < 2:
        return True
    return instruction.args[0].lower() not in _ZERO_LINK_OPERANDS


def is_tail_call_instruction(instruction: Instruction, function: Function) -> bool:
    """Recognise non-linking transfers out of a function, excluding returns.

    An unresolved non-return indirect jump is also a graph boundary. Local
    jumps stay in the CFG; treating them as calls would manufacture recursion.
    A conditional branch to an out-of-line function body also carries the
    ancestor context, even though it is not an ABI call instruction.
    """
    if instruction.op == "tail":
        return True
    if (instruction.op not in CONDITIONAL_BRANCHES | {"j", "jr", "jal", "jalr"}
            or is_call_instruction(instruction)):
        return False
    args = tuple(arg.lower() for arg in instruction.args)
    if instruction.op == "jr" and args in {("ra",), ("x1",)}:
        return False
    if instruction.op == "jalr" and args and args[0] in _ZERO_LINK_OPERANDS:
        if len(args) == 2 and re.fullmatch(r"(?:0|0x0)?\((?:ra|x1)\)", args[1]):
            return False
        if len(args) == 3 and args[1] in {"ra", "x1"} and args[2] in {"0", "0x0"}:
            return False
    targets = instruction.jump_targets
    if targets:
        return any(not (function.start <= target <= function.end) for target in targets)
    return instruction.op in {"jr", "jalr"}


def build_cfg(program: Program) -> Program:
    _clear_existing_cfg(program)
    _classify_control_flow(program)
    for function in program.functions:
        function.blocks = _build_blocks(function)
        _connect_blocks(function)
        _connect_instruction_successors(function)
    return program


def _clear_existing_cfg(program: Program) -> None:
    for instruction in program.instructions:
        instruction.succ.clear()
        instruction.jump_targets.clear()
        instruction.jump_sources.clear()
        instruction.ends_block = False
        instruction.is_return = False
    for function in program.functions:
        function.blocks.clear()


def _classify_control_flow(program: Program) -> None:
    for instruction in program.instructions:
        instruction.ends_block = instruction.op in BLOCK_TERMINATORS
        instruction.is_return = instruction.op == "ret"
        target = direct_target(instruction)
        if target is None:
            continue
        instruction.jump_targets.add(target)
        target_instruction = program.instruction_by_address.get(target)
        if target_instruction is not None:
            target_instruction.jump_sources.add(instruction.addr)


def direct_target(instruction: Instruction) -> int | None:
    """Return a statically known control-flow target.

    Direct branches and ``jal`` carry the target as an operand.  A ``jalr``
    normally computes its target from a register, but GNU objdump annotates
    common ``auipc`` + ``jalr`` call sequences with the resolved absolute
    address, for example::

        jalr 1124(ra) # 192330 <callee>

    The comment address is hexadecimal even when it has no ``0x`` prefix.
    """

    if instruction.op in CONDITIONAL_BRANCHES | {"j", "jal", "call", "tail"}:
        if not instruction.args:
            return None
        token = instruction.args[-1].split()[0]
        try:
            return int(token, 16)
        except ValueError:
            return None

    if instruction.op == "jalr":
        match = OBJDUMP_RESOLVED_TARGET_RE.search(instruction.operand)
        if match is not None:
            return int(match.group(1), 16)

    return None


def _build_blocks(function: Function) -> list[BasicBlock]:
    blocks: list[BasicBlock] = []
    current: list[Instruction] = []
    branch_targets = {
        target for instruction in function.insts for target in instruction.jump_targets
    }

    for instruction in function.insts:
        if current and instruction.addr in branch_targets:
            blocks.append(BasicBlock(current))
            current = []
        current.append(instruction)
        if instruction.ends_block:
            blocks.append(BasicBlock(current))
            current = []

    if current:
        blocks.append(BasicBlock(current))
    return blocks


def _connect_blocks(function: Function) -> None:
    by_start = {block.start: block for block in function.blocks}
    for index, block in enumerate(function.blocks):
        last = block.instructions[-1]
        # A call links the return address: the target is a *callee*, reached
        # through the call graph (``jump_targets``), never through this
        # function's CFG.  Connecting it would turn every call whose target
        # lies inside the function - recursion above all - into a back edge
        # and the whole function into a loop.  The sequential successor is
        # the return address and is kept below.
        if not is_call_instruction(last):
            for target in last.jump_targets:
                if target in by_start:
                    _add_edge(block, by_start[target])

        if _has_no_fallthrough(last):
            continue
        if index + 1 < len(function.blocks):
            _add_edge(block, function.blocks[index + 1])


def _has_no_fallthrough(instruction: Instruction) -> bool:
    if instruction.op in NO_FALLTHROUGH:
        return True
    if instruction.op in {"jal", "jalr", "call"}:
        # A call resumes at the next instruction; the same mnemonics with an
        # explicit zero link register are jumps and do not.
        return not is_call_instruction(instruction)
    return False


def _add_edge(source: BasicBlock, destination: BasicBlock) -> None:
    if destination not in source.successors:
        source.successors.append(destination)
    if source not in destination.predecessors:
        destination.predecessors.append(source)


def _connect_instruction_successors(function: Function) -> None:
    for block in function.blocks:
        for current, following in zip(block.instructions, block.instructions[1:]):
            current.succ.add(following.addr)
        last = block.instructions[-1]
        last.succ.update(successor.start for successor in block.successors)
