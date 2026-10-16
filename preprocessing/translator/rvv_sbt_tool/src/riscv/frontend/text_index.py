"""反汇编文本的程序级地址、符号和目标索引。

本模块只消费 ``RVProgram`` 已经从 dump.S 解析出的文本信息，不读取 ELF
或重定位表。索引的目的不是推测间接跳转，而是把 objdump 明确打印出的
``target_address``、``target_symbol``、函数头和局部标签统一提供给 CFG
构造器与直接调用图。
"""

from __future__ import annotations

from dataclasses import dataclass
from bisect import bisect_right
import re
from typing import Iterable, Optional

from riscv.frontend.literals import parse_integer_literal
from riscv.frontend.model import PLTTarget, RVFunction, RVInstruction, RVProgram
from riscv.registers import normalize_gpr_name


_CONDITIONAL_BRANCH_OPS = {
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


@dataclass(frozen=True)
class TextProgramIndex:
    """从反汇编文本建立的只读程序索引。"""

    functions: tuple[RVFunction, ...]
    function_by_start: dict[int, RVFunction]
    function_by_name: dict[str, RVFunction]
    function_by_instruction: dict[int, RVFunction]
    label_to_address: dict[str, int]
    numeric_label_addresses: dict[str, tuple[int, ...]]
    symbol_to_address: dict[str, int]

    @classmethod
    def build(cls, program: RVProgram | Iterable[RVFunction]) -> "TextProgramIndex":
        """为完整反汇编程序建立全局索引。"""

        functions = tuple(
            program.functions if isinstance(program, RVProgram) else list(program)
        )
        function_by_start = {
            function.start_addr: function
            for function in functions
            if function.instructions
        }
        function_by_name = {
            function.name: function
            for function in functions
            if function.instructions
        }
        function_by_instruction: dict[int, RVFunction] = {}
        label_to_address: dict[str, int] = {}
        numeric_label_addresses: dict[str, list[int]] = {}
        symbol_to_address = {
            function.name: function.start_addr
            for function in functions
            if function.instructions
        }

        if isinstance(program, RVProgram):
            # 解析器已经生成的程序符号/全局标签优先保留；下面再用函数
            # 内指令补齐，以兼容手工构造的 RVProgram 测试对象。
            symbol_to_address.update(program.symbols)
            label_to_address.update(program.global_labels)

        for function in functions:
            for instruction in function.instructions:
                function_by_instruction[instruction.address] = function
                if instruction.label:
                    label_to_address.setdefault(instruction.label, instruction.address)
                    if instruction.label.isdigit():
                        numeric_label_addresses.setdefault(instruction.label, []).append(
                            instruction.address
                        )

        return cls(
            functions=functions,
            function_by_start=function_by_start,
            function_by_name=function_by_name,
            function_by_instruction=function_by_instruction,
            label_to_address=label_to_address,
            numeric_label_addresses={
                label: tuple(sorted(addresses))
                for label, addresses in numeric_label_addresses.items()
            },
            symbol_to_address=symbol_to_address,
        )

    def function_containing(self, address: int | None) -> RVFunction | None:
        """返回包含给定指令地址的函数；文本没有该地址时返回 ``None``。"""

        if address is None:
            return None
        function = self.function_by_instruction.get(address)
        if function is not None:
            return function
        if address in self.function_by_start:
            return self.function_by_start[address]
        return None

    def plt_call_candidates(self) -> dict[int, PLTTarget]:
        """Index direct PLT targets and adjacent AUIPC/JALR candidates.

        These are guarded at emission time, since control flow or migration may
        enter the JALR without executing the immediately preceding AUIPC.
        """
        targets = {
            function.start_addr: PLTTarget(
                function.start_addr, function.name, self._plt_got_address(function)
            )
            for function in self.functions if self.is_external_stub(function)
        }
        candidates = {}
        for function in self.functions:
            for index, insn in enumerate(function.instructions):
                if insn.opcode in {"call", "tail", "j", "jal"}:
                    target = targets.get(self.resolve_target(insn))
                    if target is not None:
                        candidates[insn.address] = target
                    continue
                if index == 0:
                    continue
                previous = function.instructions[index - 1]
                if (previous.opcode != "auipc" or len(previous.operands) != 2
                        or previous.address + 4 != insn.address
                        or insn.opcode not in {"jalr", "jr"}):
                    continue
                operands = [str(value).strip() for value in insn.operands]
                if not operands:
                    continue
                if len(operands) == 3 and insn.opcode == "jalr":
                    base, offset_text = operands[1:]
                elif len(operands) <= 2:
                    target = operands[-1]
                    match = re.fullmatch(r"([+-]?(?:0[xX][0-9a-fA-F]+|0[bB][01]+|[0-9]+))?\((\w+)\)", target)
                    base = match.group(2) if match else target
                    offset_text = (match.group(1) or "0") if match else "0"
                else:
                    continue
                base_reg = normalize_gpr_name(base)
                if (base_reg in {None, "zero", "sp"}
                        or base_reg != normalize_gpr_name(previous.operands[0])):
                    continue
                try:
                    upper = self.auipc_displacement(previous)
                    offset = parse_integer_literal(offset_text)
                except ValueError:
                    continue
                if not -2048 <= offset <= 2047:
                    continue
                address = ((previous.address + upper + offset) & ((1 << 64) - 1)) & ~1
                if address in targets:
                    candidates[insn.address] = targets[address]
        return candidates

    @staticmethod
    def auipc_displacement(instruction: RVInstruction) -> int:
        """Decode the source-specific immediate and sign-extend the U-immediate."""
        token = str(instruction.operands[1])
        immediate = int(token, 16) if instruction.raw_bytes_hex else parse_integer_literal(token)
        value = (immediate & 0xfffff) << 12
        return value - 0x100000000 if value & 0x80000000 else value

    @staticmethod
    def _plt_got_address(stub: RVFunction) -> int | None:
        """Decode the RV64 AUIPC/LD/JALR PLT entry, without trusting comments."""
        if len(stub.instructions) < 3:
            return None
        upper, load, jump = stub.instructions[:3]
        if (upper.address != stub.start_addr
                or load.address != upper.address + 4
                or jump.address != load.address + 4
                or (upper.opcode, load.opcode, jump.opcode) != ("auipc", "ld", "jalr")
                or any(len(insn.operands) != 2 for insn in (upper, load, jump))):
            return None
        base = normalize_gpr_name(upper.operands[0])
        loaded = normalize_gpr_name(load.operands[0])
        memory = re.fullmatch(
            r"([+-]?(?:0[xX][0-9a-fA-F]+|0[bB][01]+|[0-9]+))?\((\w+)\)", str(load.operands[1])
        )
        jump_memory = re.fullmatch(r"(?:0|0x0)?\((\w+)\)", str(jump.operands[1]))
        jump_base = jump_memory.group(1) if jump_memory else str(jump.operands[1])
        if (base in {None, "zero", "sp"} or loaded in {None, "zero", "sp"}
                or memory is None or normalize_gpr_name(memory.group(2)) != base
                or normalize_gpr_name(jump.operands[0]) != "t1"
                or normalize_gpr_name(jump_base) != loaded):
            return None
        try:
            displacement = TextProgramIndex.auipc_displacement(upper)
            offset = parse_integer_literal(memory.group(1) or "0")
        except ValueError:
            return None
        if not -2048 <= offset <= 2047:
            return None
        address = (upper.address + displacement + offset) & ((1 << 64) - 1)
        return address if address % 8 == 0 else None

    @staticmethod
    def is_external_stub(function: RVFunction | None) -> bool:
        """判断函数是否是反汇编中的外部链接桩。

        程序级 emitter 会过滤 ``@plt`` 函数，不为它们生成翻译函数；CFG
        分析也必须保持同样的边界。即使 dump 同时包含了桩函数的几条机器
        指令，也不能把它们的局部行为当成真实外部函数的 vtype 摘要。
        """

        return function is not None and "@plt" in function.name

    def resolve_target(
        self,
        instruction: RVInstruction,
        *,
        local_labels: Optional[dict[str, int]] = None,
    ) -> int | None:
        """解析文本中明确出现的控制流目标。

        解析顺序固定为：objdump 保存的绝对地址、目标符号、函数内标签、
        全局标签、操作数中的整数。寄存器间接地址不在这里猜测。
        """

        if instruction.target_address is not None:
            return instruction.target_address

        target_symbol = instruction.target_symbol
        if target_symbol:
            resolved = self._resolve_name(target_symbol, local_labels)
            if resolved is not None:
                return resolved

        target_index = self.target_operand_index(instruction)
        if target_index is None or target_index >= len(instruction.operands):
            return None
        operand = str(instruction.operands[target_index]).strip()

        numeric_reference = re.fullmatch(r"([0-9]+)([bf])", operand)
        if numeric_reference and not instruction.raw_bytes_hex:
            addresses = self.numeric_label_addresses.get(numeric_reference[1], ())
            index = bisect_right(addresses, instruction.address)
            if numeric_reference[2] == "b":
                return addresses[index - 1] if index else None
            return addresses[index] if index < len(addresses) else None

        resolved = self._resolve_name(operand, local_labels)
        if resolved is not None:
            return resolved

        # objdump 的直接目标通常以裸十六进制地址打印，例如 ``j 1014``。
        # 普通手写汇编中的同样文本更可能是十进制立即数；有原始机器码
        # 字段时才采用 objdump 语义，避免改变片段模式的操作数解释。
        if instruction.raw_bytes_hex and re.fullmatch(r"[0-9a-fA-F]+", operand):
            return int(operand, 16)
        try:
            return parse_integer_literal(operand)
        except ValueError:
            return None

    def _resolve_name(
        self,
        name: str,
        local_labels: Optional[dict[str, int]],
    ) -> int | None:
        """解析标签/符号名，不把带寄存器的表达式当成目标地址。"""

        clean = name.strip().strip("<>")
        if local_labels and clean in local_labels:
            return local_labels[clean]
        if clean in self.label_to_address:
            return self.label_to_address[clean]
        if clean in self.symbol_to_address:
            return self.symbol_to_address[clean]

        # objdump 可能打印 ``foo+0xe`` 或 ``foo@plt``；只有符号基址已在
        # 文本索引中时才解析偏移，避免把普通寄存器表达式误当成符号。
        match = re.fullmatch(r"(.+?)(?:\+([+-]?(?:0x)?[0-9a-fA-F]+))?", clean)
        if match:
            base = match.group(1)
            offset_text = match.group(2)
            base_address = (
                (local_labels or {}).get(base)
                if local_labels and base in local_labels
                else self.label_to_address.get(base, self.symbol_to_address.get(base))
            )
            if base_address is not None:
                offset = self.parse_integer(offset_text) if offset_text else 0
                if offset is not None:
                    return base_address + offset
        return None

    @staticmethod
    def target_operand_index(instruction: RVInstruction) -> int | None:
        """返回直接控制流指令的目标操作数位置。"""

        opcode = instruction.opcode.lower()
        if opcode in {"j", "call", "tail"}:
            return 0 if instruction.operands else None
        if opcode == "jal":
            return len(instruction.operands) - 1 if instruction.operands else None
        if opcode in {"beqz", "bnez", "bltz", "bgez", "blez", "bgtz"}:
            return 1 if len(instruction.operands) > 1 else None
        if opcode in _CONDITIONAL_BRANCH_OPS:
            return 2 if len(instruction.operands) > 2 else None
        return None

    @staticmethod
    def parse_integer(value: str | None) -> int | None:
        """解析十进制、带 ``0x`` 或 objdump 常见裸十六进制数字。"""

        if value is None:
            return None
        text = value.strip()
        if not text:
            return None
        try:
            return int(text, 0)
        except ValueError:
            try:
                return int(text, 16)
            except ValueError:
                return None

    @staticmethod
    def is_call(instruction: RVInstruction) -> bool:
        """判断指令是否写回返回地址，因而具有调用语义。"""

        opcode = instruction.opcode.lower()
        if opcode in {"call"}:
            return True
        if opcode == "jal":
            if len(instruction.operands) <= 1:
                return True
            return str(instruction.operands[0]).strip().lower() not in {"x0", "zero"}
        if opcode == "jalr":
            if len(instruction.operands) <= 1:
                return True
            return str(instruction.operands[0]).strip().lower() not in {"x0", "zero"}
        return False



__all__ = ["TextProgramIndex"]
