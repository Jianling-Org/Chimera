"""从当前 ``RVInstruction`` 模型构造函数级 CFG。"""

from __future__ import annotations

from typing import Iterable

from riscv.frontend.model import (
    BasicBlock,
    CFGEdgeKind,
    CFGEntryKind,
    ControlFlowEdge,
    ControlFlowGraph,
    InstructionBlockMap,
    ProgramCFG,
)
from riscv.frontend.model import RVFunction, RVInstruction, RVProgram
from riscv.frontend.text_index import TextProgramIndex


CONDITIONAL_BRANCH_OPS = {
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

UNCONDITIONAL_JUMP_OPS = {"j", "tail"}
RETURN_OPS = {"ret", "jr", "jalr", "ecall", "ebreak"}
KNOWN_TERMINAL_OPS = {"ret", "ecall", "ebreak"}
CALL_OPS = {"call"}


class CFGBuilder:
    """为每个函数构造保守的地址级 CFG。

    直接目标优先使用 objdump 解析器保存的 ``target_address``；普通汇编
    则使用函数内标签或数字地址。无法静态解析的间接跳转不会被猜测，
    而是标记为 ``unknown_exit``，供 vtype 分析保守处理。
    """

    def build_program_cfg(
        self,
        program: RVProgram | Iterable[RVFunction],
        *,
        text_index: TextProgramIndex | None = None,
    ) -> ProgramCFG:
        """构造完整程序的函数 CFG 集合。"""

        functions = program.functions if isinstance(program, RVProgram) else list(program)
        index = (
            text_index
            if text_index is not None
            else TextProgramIndex.build(
                program if isinstance(program, RVProgram) else functions
            )
        )
        return ProgramCFG(
            functions={
                function.start_addr: self.build_function_cfg(function, text_index=index)
                for function in functions
                if function.instructions
            }
        )

    def build_function_cfg(
        self,
        function: RVFunction,
        *,
        text_index: TextProgramIndex | None = None,
    ) -> ControlFlowGraph:
        """构造单个函数 CFG，并把后继地址写回指令对象。"""

        instructions = list(function.instructions)
        if not instructions:
            cfg = ControlFlowGraph(entry_address=None, entry_addresses=())
            function.cfg = cfg
            return cfg

        text_index = text_index or TextProgramIndex.build([function])
        by_address = {instruction.address: instruction for instruction in instructions}
        ordered_addresses = [instruction.address for instruction in instructions]
        label_to_address = {
            instruction.label: instruction.address
            for instruction in instructions
            if instruction.label
        }
        label_to_address[function.name] = function.start_addr

        successors: dict[int, tuple[int, ...]] = {}
        unknown_exits: set[int] = set()
        edges: list[ControlFlowEdge] = []
        for index, instruction in enumerate(instructions):
            next_address = (
                ordered_addresses[index + 1]
                if index + 1 < len(ordered_addresses)
                else None
            )
            target = text_index.resolve_target(
                instruction,
                local_labels=label_to_address,
            )
            target_known_globally = target in text_index.function_by_instruction
            next_addresses, unknown_exit = self._instruction_successors(
                instruction,
                next_address=next_address,
                by_address=by_address,
                target=target,
                target_known_globally=target_known_globally,
            )
            successors[instruction.address] = tuple(next_addresses)
            instruction.successors = tuple(next_addresses)
            if unknown_exit:
                unknown_exits.add(instruction.address)
            if self._is_control_transfer(instruction):
                edges.extend(self._instruction_edges(
                    instruction,
                    next_address=next_address,
                    target=target,
                    target_known_globally=target_known_globally,
                ))

        leaders = {ordered_addresses[0]}
        leaders.update(edge.target_address for edge in edges if edge.target_address in by_address)
        for index, instruction in enumerate(instructions):
            # Sequential successors stay inside a block. Only transfers split
            # blocks; treating every fallthrough as a leader creates N blocks.
            if not self._is_control_transfer(instruction):
                continue
            instruction_successors = successors[instruction.address]
            for successor in instruction_successors:
                if successor in by_address:
                    leaders.add(successor)

            if index + 1 < len(ordered_addresses):
                leaders.add(ordered_addresses[index + 1])

        blocks: dict[int, BasicBlock] = {}
        instruction_to_block: dict[int, int] = {}
        current_addresses: list[int] = []

        def flush_block() -> None:
            if not current_addresses:
                return
            start_address = current_addresses[0]
            block = BasicBlock(
                start_address=start_address,
                instruction_addresses=tuple(current_addresses),
            )
            blocks[start_address] = block
            for address in current_addresses:
                instruction_to_block[address] = start_address
            current_addresses.clear()

        for index, address in enumerate(ordered_addresses):
            if current_addresses and address in leaders:
                flush_block()
            current_addresses.append(address)
            instruction = by_address[address]
            next_address = (
                ordered_addresses[index + 1]
                if index + 1 < len(ordered_addresses)
                else None
            )
            if self._is_control_transfer(instruction) and next_address is not None:
                flush_block()
        flush_block()

        predecessors: dict[int, list[int]] = {address: [] for address in blocks}
        for block in blocks.values():
            last_address = block.end_address
            if not self._is_control_transfer(by_address[last_address]):
                edges.extend(
                    ControlFlowEdge(last_address, successor, CFGEdgeKind.FALLTHROUGH, True)
                    for successor in successors[last_address]
                )
            block_successors: list[int] = []
            for successor in successors[last_address]:
                successor_block = instruction_to_block.get(successor)
                if successor_block is None:
                    block.unknown_exit = True
                    continue
                if successor_block not in block_successors:
                    block_successors.append(successor_block)
                    predecessors[successor_block].append(block.start_address)
            block.successors = tuple(block_successors)
            if last_address in unknown_exits:
                block.unknown_exit = True
        for block in blocks.values():
            block.predecessors = tuple(predecessors[block.start_address])

        primary_entry = ordered_addresses[0]
        # 函数范围内没有前驱的块不一定是死代码：objdump 可能把冷代码、
        # 异常落点或次级入口仍放在同一个函数符号范围中。把它们作为候选
        # 入口交给数据流分析，入口状态仍然是 unknown；只有该块内执行
        # vset 后才恢复为完整 vtype。这样既避免误判为不可达，也不会
        # 凭空继承主入口的 vtype。
        secondary_entries = [
            block.start_address
            for block in blocks.values()
            if block.start_address != primary_entry and not block.predecessors
        ]
        entry_addresses = tuple([primary_entry, *secondary_entries])
        entry_kinds = {primary_entry: CFGEntryKind.PRIMARY}
        entry_kinds.update({address: CFGEntryKind.SECONDARY_CANDIDATE for address in secondary_entries})

        edges_by_source: dict[int, list[ControlFlowEdge]] = {}
        for edge in edges:
            edges_by_source.setdefault(edge.source_address, []).append(edge)

        cfg = ControlFlowGraph(
            entry_address=primary_entry,
            blocks=blocks,
            instruction_to_block=InstructionBlockMap(instruction_to_block),
            unknown_exit=bool(unknown_exits),
            entry_addresses=entry_addresses,
            edges=tuple(edges),
            edges_by_source={
                address: tuple(source_edges)
                for address, source_edges in edges_by_source.items()
            },
            entry_kinds=entry_kinds,
            unknown_exit_addresses=frozenset(unknown_exits),
        )
        function.cfg = cfg
        return cfg

    def _instruction_successors(
        self,
        instruction: RVInstruction,
        *,
        next_address: int | None,
        by_address: dict[int, RVInstruction],
        target: int | None = None,
        target_known_globally: bool = False,
    ) -> tuple[list[int], bool]:
        opcode = instruction.opcode.lower()
        if opcode in KNOWN_TERMINAL_OPS:
            # 正常返回/陷阱是已知终止点，不应被误记成未知出口。
            return [], False

        if opcode == "jr":
            # 间接跳转的运行时目标不能在这里猜测；jr 的伪指令形式
            # 相当于 jalr x0，因此没有可确认的 fall-through。
            return [], True

        if opcode == "jalr":
            # ``jalr ra, ...`` 或单操作数 ``jalr rs1`` 是间接调用，
            # 调用者应保留 fall-through；``jalr x0, ...`` 是间接跳转，
            # 没有可确认的顺序后继。两者都保留 unknown_exit，因为目标
            # 函数和异常/返回路径仍可能改变 vtype。
            rd = (
                instruction.operands[0].strip().lower()
                if len(instruction.operands) > 1
                else "ra"
            )
            if rd in {"x0", "zero"}:
                return [], True
            fallthrough = [next_address] if next_address is not None else []
            return fallthrough, True

        if opcode in CONDITIONAL_BRANCH_OPS:
            result: list[int] = []
            if target in by_address:
                result.append(target)  # type: ignore[arg-type]
            unknown = target is None or (target not in by_address and not target_known_globally)
            if next_address is not None:
                result.append(next_address)
            return self._unique(result), unknown

        if opcode in UNCONDITIONAL_JUMP_OPS:
            if target in by_address:
                return [target], False  # type: ignore[list-item]
            if target is not None and target_known_globally:
                # 文本明确给出了跨函数 tail/jump 目标。当前函数没有本地
                # 后继，但这不是未知控制流出口，调用图会单独记录该边。
                return [], False
            return [], True

        if opcode == "jal":
            # ``jal target`` 和 ``jal ra,target`` 是调用，调用者继续执行
            # fall-through；只有 rd=x0 才是无条件跳转。
            rd = instruction.operands[0].strip().lower() if len(instruction.operands) > 1 else "ra"
            if rd in {"x0", "zero"}:
                if target in by_address:
                    return [target], False  # type: ignore[list-item]
                if target is not None and target_known_globally:
                    return [], False
                return [], True
            return ([next_address] if next_address is not None else []), False

        if opcode in CALL_OPS:
            return ([next_address] if next_address is not None else []), False

        if next_address is None:
            return [], False
        return [next_address], False

    def _instruction_edges(
        self,
        instruction: RVInstruction,
        *,
        next_address: int | None,
        target: int | None,
        target_known_globally: bool,
    ) -> list[ControlFlowEdge]:
        """把一条指令的控制流事实记录为可审计的文本边。"""

        opcode = instruction.opcode.lower()
        edges: list[ControlFlowEdge] = []

        def add(
            kind: CFGEdgeKind,
            address: int | None,
            *,
            resolved: bool,
            provenance: str = "text",
        ) -> None:
            edges.append(
                ControlFlowEdge(
                    source_address=instruction.address,
                    target_address=address,
                    kind=kind,
                    resolved=resolved,
                    provenance=provenance,
                )
            )

        if opcode == "ret":
            add(CFGEdgeKind.RETURN, None, resolved=True)
            return edges
        if opcode in {"ecall", "ebreak"}:
            add(CFGEdgeKind.TERMINAL, None, resolved=True)
            return edges
        if opcode == "jr":
            add(CFGEdgeKind.INDIRECT_JUMP, None, resolved=False)
            return edges
        if opcode == "jalr":
            is_call = TextProgramIndex.is_call(instruction)
            kind = CFGEdgeKind.INDIRECT_CALL if is_call else CFGEdgeKind.INDIRECT_JUMP
            # jalr 的目标由寄存器运行时决定。即使 objdump 同行出现数值
            # 地址，也不把它当成已经证明的 CFG 边；target_address 仍保留
            # 在 RVInstruction 中，供人工审计和后续更强分析使用。
            add(kind, None, resolved=False, provenance="text:unresolved-indirect")
            if is_call and next_address is not None:
                add(CFGEdgeKind.FALLTHROUGH, next_address, resolved=True)
            return edges
        if opcode in CONDITIONAL_BRANCH_OPS:
            add(
                CFGEdgeKind.CONDITIONAL_BRANCH,
                target,
                resolved=target is not None,
            )
            if next_address is not None:
                add(CFGEdgeKind.FALLTHROUGH, next_address, resolved=True)
            return edges
        if opcode in UNCONDITIONAL_JUMP_OPS:
            add(
                CFGEdgeKind.TAIL_CALL if opcode == "tail" else CFGEdgeKind.UNCONDITIONAL_JUMP,
                target,
                resolved=target is not None,
            )
            return edges
        if opcode == "jal":
            is_call = TextProgramIndex.is_call(instruction)
            if is_call:
                add(CFGEdgeKind.DIRECT_CALL, target, resolved=target is not None)
                if next_address is not None:
                    add(CFGEdgeKind.FALLTHROUGH, next_address, resolved=True)
            else:
                add(CFGEdgeKind.UNCONDITIONAL_JUMP, target, resolved=target is not None)
            return edges
        if opcode == "call":
            add(CFGEdgeKind.DIRECT_CALL, target, resolved=target is not None)
            if next_address is not None:
                add(CFGEdgeKind.FALLTHROUGH, next_address, resolved=True)
            return edges

        # 普通指令只在存在顺序后继时记录 fall-through；函数末尾没有目标
        # 并不构造一个虚假的地址，也不会影响旧的 CFG block 逻辑。
        if next_address is not None:
            add(CFGEdgeKind.FALLTHROUGH, next_address, resolved=True)
        return edges

    @staticmethod
    def _target_operand_index(instruction: RVInstruction) -> int | None:
        opcode = instruction.opcode.lower()
        if opcode in {"j", "call", "tail"}:
            return 0 if instruction.operands else None
        if opcode == "jal":
            return len(instruction.operands) - 1 if instruction.operands else None
        if opcode in {"beqz", "bnez", "bltz", "bgez", "blez", "bgtz"}:
            return 1 if len(instruction.operands) > 1 else None
        if opcode in {"beq", "bne", "blt", "bge", "bltu", "bgeu"}:
            return 2 if len(instruction.operands) > 2 else None
        return None

    @staticmethod
    def _is_control_transfer(instruction: RVInstruction) -> bool:
        opcode = instruction.opcode.lower()
        return (
            opcode in CONDITIONAL_BRANCH_OPS
            or opcode in UNCONDITIONAL_JUMP_OPS
            or opcode in RETURN_OPS
            or opcode in CALL_OPS
            or opcode == "jal"
        )

    @staticmethod
    def _unique(addresses: Iterable[int]) -> list[int]:
        result: list[int] = []
        seen: set[int] = set()
        for address in addresses:
            if address in seen:
                continue
            result.append(address)
            seen.add(address)
        return result


__all__ = ["CFGBuilder"]
