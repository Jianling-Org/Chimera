"""RVV1024 过渡执行使用的临时向量寄存器分配器。

源 RVV256 的 ``vN`` 名称只是紧凑状态块中的物理寄存器编号，并不占用
RVV1024 硬件同名寄存器。为了让 m8 的三操作数指令仍有确定的空间，本路径
固定把 v8--v31 作为数据临时池，并永久保留 v0 给 RVV mask。
"""

from __future__ import annotations

from typing import Iterable

from riscv.extensions.rvv.translation.temps import record_vreg_group


VREG_TEMP_POOL = tuple(range(8, 32))


class RegisterAllocationError(ValueError):
    """目标临时寄存器资源不足或请求的组宽非法。"""


class VRegTempAllocator:
    """按 RVV EMUL 对齐规则从 v8--v31 分配临时寄存器组。"""

    def __init__(self, reserved_vregs: Iterable[int] = ()):
        # 客体 vN 只是紧凑状态槽位编号，不能用于排除目标硬件同名寄存器。
        reserved = set(reserved_vregs) | {0}
        self._free = [reg for reg in VREG_TEMP_POOL if reg not in reserved]

    def alloc_vreg_group(self, width: int) -> str:
        """分配一个按 ``width`` 对齐、连续且完全位于临时池的寄存器组。"""
        if width not in (1, 2, 4, 8):
            raise RegisterAllocationError(
                f"RVV1024 临时组宽度必须是 1/2/4/8，得到 {width}"
            )
        for start in tuple(self._free):
            if start % width:
                continue
            group = list(range(start, start + width))
            if all(reg in self._free for reg in group):
                for reg in group:
                    self._free.remove(reg)
                result = f"v{start}"
                record_vreg_group(result, width)
                return result
        raise RegisterAllocationError(
            f"RVV1024 临时向量寄存器不足，无法分配 m{width} 组"
        )

    def alloc_group_for_lmul(self, lmul: float) -> str:
        """按普通数据 LMUL 分配组；分数 LMUL 使用一个物理寄存器。"""
        width = int(lmul) if lmul >= 1 else 1
        return self.alloc_vreg_group(width)

    def alloc_groups(self, widths: Iterable[int]) -> list[str]:
        """按给定顺序分配多组，失败时不返回部分结果给调用方。"""
        snapshot = list(self._free)
        try:
            return [self.alloc_vreg_group(width) for width in widths]
        except RegisterAllocationError:
            self._free = snapshot
            raise
