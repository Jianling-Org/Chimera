# src/riscv/frontend/parser.py
"""
汇编解析器：将 .s 文件解析为 RVInstruction 列表

仅用于本地测试/验证。生产环境中，List[RVInstruction] 由其他工具直接提供。

支持解析：
- 标签 (.Lxxx, func_name:)
- 向量指令 (vsetvli, vfmacc.vf, vle64.v, ...)
- 标量指令 (add, mv, ld, ...)
- 空白行和注释
"""

import re
import sys
from functools import lru_cache
from typing import Iterable, List, Tuple

from riscv.frontend.model import RVFunction, RVInstruction, RVProgram


class AsmParser:
    """RISC-V 汇编解析器"""

    # 标签匹配:
    # - 普通标签: .L6:, daxpy_k:, .Lloop:
    # - GNU 数字局部标签: 1:, 2:
    #
    # 数字局部标签在 GNU 汇编和部分反汇编/手写汇编里都很常见，
    # 分支操作数中的 `1f` / `1b` 也依赖这些标签存在。
    LABEL_PATTERN = re.compile(r'^([a-zA-Z_.][a-zA-Z0-9_.$]*|[0-9]+):\s*$')

    # 指令匹配:     addi    sp, sp, -32
    #           vsetvli a4, a0, e64, m8, ta, ma
    #           ret
    INSN_PATTERN = re.compile(
        r'^\s*([a-zA-Z_][a-zA-Z0-9_.]*)(?:\s+(.*))?\s*$'
    )

    # llvm-objdump 格式匹配: "       0: f20007d3     	fmv.d.x	fa5, zero"
    # 支持反汇编输出格式
    OBJDUMP_PATTERN = re.compile(
        r'^\s*([0-9a-f]+):\s+([0-9a-f]+)\s+([a-zA-Z_][a-zA-Z0-9_.]*)\s*(.*)$'
    )

    # llvm-objdump 标签行: "000000000000001a <.L6>:"
    OBJDUMP_LABEL_PATTERN = re.compile(
        r'^\s*([0-9a-f]+)\s+<([^>]+)>:\s*$'
    )

    # 操作数中的注释移除
    COMMENT_PATTERN = re.compile(r'#.*$')

    # llvm-objdump 格式中的地址+标签: "0x3c <.L33>" -> ".L33"
    ADDRESS_LABEL_PATTERN = re.compile(r'^(.*?)\s+<([^>]+)>$')

    def __init__(self, *, retain_raw_lines: bool = True):
        self.instructions: List[RVInstruction] = []
        self.labels: dict = {}  # label_name -> address(index)
        self.retain_raw_lines = retain_raw_lines

    def parse_file(self, filepath: str) -> List[RVInstruction]:
        """
        解析 .s 文件

        :param filepath: .s 文件路径
        :return: RVInstruction 列表
        """
        with open(filepath, 'r') as f:
            return self.parse_lines(f)

    def parse_file_functions(self, filepath: str) -> List[RVFunction]:
        """
        解析完整 objdump 文件，按函数边界返回函数列表。

        旧的 parse_file() 仍返回扁平指令列表；此入口服务离线优化流程。
        """
        with open(filepath, 'r') as f:
            return self.parse_lines_functions(f)

    def parse_string(self, asm_code: str) -> List[RVInstruction]:
        """
        解析汇编代码字符串

        :param asm_code: 汇编代码
        :return: RVInstruction 列表
        """
        lines = asm_code.split('\n')
        return self.parse_lines(lines)

    def parse_string_functions(self, asm_code: str) -> List[RVFunction]:
        """解析完整 objdump 字符串，按函数边界返回函数列表。"""
        lines = asm_code.split('\n')
        return self.parse_lines_functions(lines)

    def parse_file_program(self, filepath: str) -> RVProgram:
        """解析完整 objdump 并返回统一的 ``RVProgram`` 容器。"""

        functions = self.parse_file_functions(filepath)
        return self._build_program(functions)

    def parse_string_program(self, asm_code: str) -> RVProgram:
        """解析完整 objdump 字符串并返回统一程序模型。"""

        return self._build_program(self.parse_string_functions(asm_code))

    @staticmethod
    def _build_program(functions: List[RVFunction]) -> RVProgram:
        symbols: dict[str, int] = {}
        global_labels: dict[str, int] = {}
        for function in functions:
            symbols[function.name] = function.start_addr
            for instruction in function.instructions:
                if instruction.label:
                    global_labels[instruction.label] = instruction.address
        return RVProgram(
            functions=functions,
            symbols=symbols,
            global_labels=global_labels,
        )

    def parse_lines_functions(self, lines: Iterable[str]) -> List[RVFunction]:
        """
        解析完整 objdump，形成函数级 IR。

        仅 objdump 函数头 (`0000 <func>:`) 会开启新函数；函数内部标签
        继续绑定到下一条指令，供 emitter 做局部标签去冲突。
        """
        functions: List[RVFunction] = []
        current_function: RVFunction | None = None
        current_label = None
        in_text_section = True
        in_plt_section = False

        for line in lines:
            stripped = line.strip()

            if not stripped:
                continue

            if stripped.startswith('Disassembly of section'):
                in_text_section = ('.text' in stripped)
                section = stripped.removeprefix('Disassembly of section').strip().removesuffix(':')
                in_plt_section = section == '.plt' or section.startswith('.plt.')
                # PLT entries supply address/symbol facts for call routing, but
                # section boundaries must never extend the preceding function.
                current_function = None
                current_label = None
                continue

            if stripped.startswith('file format'):
                continue

            if not (in_text_section or in_plt_section):
                continue

            if stripped.startswith('#'):
                continue

            objdump_label_match = self.OBJDUMP_LABEL_PATTERN.match(stripped)
            if objdump_label_match:
                addr_hex = objdump_label_match.group(1)
                label_name = objdump_label_match.group(2)
                addr = int(addr_hex, 16)

                if in_plt_section and not label_name.endswith('@plt'):
                    # In particular, do not create a translatable function for
                    # the unnamed dynamic resolver at the start of .plt.
                    current_function = None
                    current_label = None
                    continue

                if current_function is None or not self._is_local_label(label_name):
                    current_function = RVFunction(
                        name=label_name,
                        start_addr=addr,
                    )
                    functions.append(current_function)
                    current_label = label_name
                else:
                    current_label = label_name
                continue

            label_match = self.LABEL_PATTERN.match(stripped)
            if label_match:
                current_label = label_match.group(1)
                continue

            objdump_insn_match = self.OBJDUMP_PATTERN.match(stripped)
            if objdump_insn_match and current_function is not None:
                insn = self._build_objdump_instruction(
                    addr_hex=objdump_insn_match.group(1),
                    raw_bytes_hex=objdump_insn_match.group(2),
                    opcode=objdump_insn_match.group(3),
                    op_str_raw=objdump_insn_match.group(4),
                    label=current_label,
                    raw_line=line.rstrip('\n') if self.retain_raw_lines else '',
                )
                current_function.instructions.append(insn)
                current_label = None
                continue

        return functions

    def parse_lines(self, lines: Iterable[str]) -> List[RVInstruction]:
        """
        解析行列表

        :param lines: 代码行列表
        :return: RVInstruction 列表
        """
        self.instructions = []
        self.labels = {}

        current_label = None
        address = 0
        in_text_section = True

        for line in lines:
            # 去除首尾空白
            stripped = line.strip()

            # 跳过空行
            if not stripped:
                continue

            if stripped.startswith('Disassembly of section'):
                in_text_section = ('.text' in stripped)
                continue

            # 跳过文件头等非指令行
            if stripped.startswith('file format'):
                continue

            if not in_text_section:
                continue

            # 跳过纯注释行
            if stripped.startswith('#'):
                continue

            # 优先检查 llvm-objdump 标签行: "000000000000001a <.L6>:"
            objdump_label_match = self.OBJDUMP_LABEL_PATTERN.match(stripped)
            if objdump_label_match:
                addr_hex = objdump_label_match.group(1)
                label_name = objdump_label_match.group(2)
                current_label = label_name
                address = int(addr_hex, 16)
                self.labels[current_label] = address
                continue

            # 检查标准标签行: ".L6:"
            label_match = self.LABEL_PATTERN.match(stripped)
            if label_match:
                current_label = label_match.group(1)
                self.labels[current_label] = address
                continue

            # 优先检查 llvm-objdump 指令行: "       0: f20007d3     	fmv.d.x	fa5, zero"
            objdump_insn_match = self.OBJDUMP_PATTERN.match(stripped)
            if objdump_insn_match:
                addr_hex = objdump_insn_match.group(1)
                raw_bytes_hex = objdump_insn_match.group(2)
                opcode = objdump_insn_match.group(3)
                op_str_raw = objdump_insn_match.group(4)

                insn = self._build_objdump_instruction(
                    addr_hex=addr_hex,
                    raw_bytes_hex=raw_bytes_hex,
                    opcode=opcode,
                    op_str_raw=op_str_raw,
                    label=current_label,
                    raw_line=line.rstrip('\n') if self.retain_raw_lines else '',
                )

                self.instructions.append(insn)
                current_label = None  # 标签已绑定到指令
                address += 4  # 假设每条指令 4 字节
                continue

            # 检查标准指令行
            insn_match = self.INSN_PATTERN.match(stripped)
            if insn_match:
                opcode = insn_match.group(1)
                op_str_raw = insn_match.group(2) or ""

                # 移除操作数中的注释
                op_str = self.COMMENT_PATTERN.sub('', op_str_raw).strip()

                # 解析操作数列表
                operands = self._parse_operands(op_str)

                # 创建指令对象
                insn = RVInstruction(
                    address=address,
                    opcode=opcode,
                    op_str=op_str,
                    operands=operands,
                    label=current_label,
                    raw_line=line.rstrip('\n') if self.retain_raw_lines else '',
                )

                self.instructions.append(insn)
                current_label = None  # 标签已绑定到指令
                address += 4  # 假设每条指令 4 字节

        return self.instructions

    def _is_local_label(self, label_name: str) -> bool:
        """判断 objdump 标签是否应视为当前函数内部标签。"""
        return label_name.startswith('.') or label_name.isdigit()

    def _build_objdump_instruction(
        self,
        addr_hex: str,
        raw_bytes_hex: str,
        opcode: str,
        op_str_raw: str,
        label: str | None,
        raw_line: str,
    ) -> RVInstruction:
        """从 objdump 指令匹配结果构造 RVInstruction。"""
        op_str = self.COMMENT_PATTERN.sub('', op_str_raw).strip()
        op_str, operands, target_address, target_symbol = self._objdump_operands(op_str)
        raw_bytes_hex, raw_bytes = self._objdump_encoding(raw_bytes_hex)
        return RVInstruction(
            address=int(addr_hex, 16),
            opcode=sys.intern(opcode),
            op_str=op_str,
            operands=list(operands),
            label=label,
            raw_bytes=raw_bytes,
            raw_line=raw_line,
            raw_bytes_hex=raw_bytes_hex,
            target_address=target_address,
            target_symbol=target_symbol,
        )

    @staticmethod
    @lru_cache(maxsize=4096)
    def _objdump_encoding(raw_bytes_hex: str) -> tuple[str, bytes]:
        """Share recurring encodings without a cache that grows with the input."""
        return raw_bytes_hex, bytes.fromhex(raw_bytes_hex) if len(raw_bytes_hex) % 2 == 0 else b''

    @classmethod
    @lru_cache(maxsize=4096)
    def _objdump_operands(cls, op_str: str) -> tuple[str, tuple[str, ...], int | None, str | None]:
        # Cache immutable fields only; each instruction owns its operands list.
        operands = tuple(cls._parse_operands(op_str))
        target_address, target_symbol = cls._parse_objdump_target(op_str)
        target_symbol = next((op for op in operands if op == target_symbol), target_symbol)
        return op_str, operands, target_address, target_symbol

    @classmethod
    def _clean_operand(cls, operand: str) -> str:
        """
        清洗单个操作数：移除地址+标签格式中的地址部分

        llvm-objdump 输出: "0x3c <.L33>" -> ".L33"
        标准格式: "0x3c" -> "0x3c" (保留)

        :param operand: 原始操作数
        :return: 清洗后的操作数
        """
        # 检查是否是 "地址 <标签>" 格式
        match = cls.ADDRESS_LABEL_PATTERN.match(operand.strip())
        if match:
            # 返回标签部分（带点号）
            label = match.group(2)
            return label
        return operand.strip()

    @staticmethod
    def _parse_objdump_target(op_str: str) -> Tuple[int | None, str | None]:
        """提取 objdump 操作数中的 `地址 <符号>` 目标信息。"""
        match = re.search(r'(?:^|[\s,])((?:0x)?[0-9a-fA-F]+)\s+<([^>]+)>', op_str.strip())
        if not match:
            return None, None

        address_text = match.group(1)
        return int(address_text, 0 if address_text.startswith("0x") else 16), match.group(2)

    @classmethod
    def _parse_operands(cls, op_str: str) -> List[str]:
        """
        解析操作数字符串

        :param op_str: 操作数字符串 (如 'a4, a0, e64, m8, ta, ma')
        :return: 操作数列表
        """
        if not op_str:
            return []

        # 按逗号分割，保留括号内的内容
        operands = []
        depth = 0
        current = ''

        for char in op_str:
            if char in '([':
                depth += 1
                current += char
            elif char in ')]':
                depth -= 1
                current += char
            elif char == ',' and depth == 0:
                operands.append(current.strip())
                current = ''
            else:
                current += char

        # 添加最后一个操作数
        if current.strip():
            operands.append(current.strip())

        # 清洗每个操作数（移除地址+标签格式中的地址部分）
        # Share common register names and small immediates without retaining
        # arbitrary symbol names in a program-sized interning table.
        cleaned = [cls._clean_operand(op) for op in operands]
        cleaned = [sys.intern(op) if len(op) <= 4 else op for op in cleaned]

        return cleaned


def parse_file(filepath: str) -> List[RVInstruction]:
    """
    便捷函数：解析 .s 文件

    :param filepath: .s 文件路径
    :return: RVInstruction 列表
    """
    parser = AsmParser()
    return parser.parse_file(filepath)


def parse_string(asm_code: str) -> List[RVInstruction]:
    """
    便捷函数：解析汇编代码字符串

    :param asm_code: 汇编代码
    :return: RVInstruction 列表
    """
    parser = AsmParser()
    return parser.parse_string(asm_code)
