# src/riscv/extensions/rvv/backends/rvv256/temp_regs.py
"""
256-bit RVV 模式临时向量寄存器分配器 (v24-v31 池)

说明:
- 可按单寄存器分配临时 vreg，也可按连续寄存器组宽度分配，用于 narrowing/
  widening 这类对寄存器组重叠敏感的指令。
- 目前池仍局限于 v24-v31；若将来需要感知更复杂的 LMUL/EMUL 约束，可在此基础上扩展。
"""

import re
from typing import Iterable
from riscv.extensions.rvv.translation.temps import record_vreg_group
from riscv.frontend.model import RVInstruction

VREG_TEMP_POOL = tuple(f"v{i}" for i in range(24, 32))
_VREG_RE = re.compile(r"^v(?:[0-9]|[12][0-9]|3[01])$")


def _collect_vreg_uses(insn: RVInstruction) -> set[int]:
    used: set[int] = set()
    operands = list(insn.operands) if insn.operands else []
    tokens = [insn.op_str]
    tokens.extend(str(op) for op in operands)
    for text in tokens:
        for token in re.split(r"[^A-Za-z0-9_.]+", text):
            m = _VREG_RE.match(token.strip().lower())
            if m:
                used.add(int(token.strip().lower()[1:]))
    return used


class VRegTempAllocator:
    def __init__(self, insn: RVInstruction, reserved_vregs: Iterable[int] = ()):
        used = _collect_vreg_uses(insn) | set(reserved_vregs)
        self._free = [r for r in VREG_TEMP_POOL if int(r[1:]) not in used]

    def alloc_vreg(self) -> str:
        if not self._free:
            raise ValueError("可用临时向量寄存器不足")
        register = self._free.pop(0)
        record_vreg_group(register, 1)
        return register

    def alloc_vreg_group(self, width: int) -> str:
        if width <= 0:
            raise ValueError("寄存器组宽度必须为正整数")

        for reg in list(self._free):
            start = int(reg[1:])
            # RVV 寄存器组需要按组宽对齐: EMUL=2 只能从偶数号起，EMUL=4 只能从 4 的倍数起。
            if start % width != 0:
                continue
            group = [f"v{i}" for i in range(start, start + width)]
            if any(member not in VREG_TEMP_POOL for member in group):
                continue
            if all(member in self._free for member in group):
                for member in group:
                    self._free.remove(member)
                record_vreg_group(reg, width)
                return reg

        raise ValueError(f"无法分配宽度为 {width} 的连续临时向量寄存器组")
