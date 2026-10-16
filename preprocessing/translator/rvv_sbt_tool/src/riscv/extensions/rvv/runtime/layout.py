"""模拟 RVV 状态缓冲区布局。

这里集中保存 ABI 偏移，而不承担临时寄存器分配。向量寄存器槽位仍固定
为 128 字节，不能因为某个目标后端的实际 VLEN 改变就擅自缩放布局。
"""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType


# 这些值是翻译器与在线运行时共享的 ABI（应用二进制接口）事实。
# 任何后端都只能引用，不能根据目标硬件 VLEN 重新计算。
DEFAULT_VLENB = 128
VREG_SIZE = 128
STATE_TOTAL_SIZE = 0x1040
CSR_OFFSETS = MappingProxyType({
    "vstart": 0x1000,
    "vxsat": 0x1008,
    "vxrm": 0x1010,
    "vcsr": 0x1018,
    "vl": 0x1020,
    "vtype": 0x1028,
    "vlenb": 0x1030,
})


@dataclass(frozen=True, slots=True)
class SimulatedStateLayout:
    """``simulated_cpu_state`` 的只读布局描述。"""

    # vlenb 是源模型参数；槽位大小仍由当前 ABI 固定为 128 字节。
    vlenb: int = DEFAULT_VLENB
    vreg_size: int = VREG_SIZE

    def __post_init__(self) -> None:
        if self.vlenb <= 0:
            raise ValueError("源模型 VLENB 必须为正整数")
        if self.vreg_size != VREG_SIZE:
            raise ValueError(
                f"模拟 vreg 槽位是固定 ABI，必须为 {VREG_SIZE} B"
            )

    def get_vreg_offset(self, reg_name: str) -> int:
        register = reg_name.lower().strip()
        if not register.startswith("v") or not register[1:].isdigit():
            raise ValueError(f"未知向量寄存器: {reg_name}")
        number = int(register[1:])
        if not 0 <= number <= 31:
            raise ValueError(f"无效向量寄存器编号: {reg_name}")
        return number * self.vreg_size

    def get_csr_offset(self, csr_name: str) -> int:
        try:
            return CSR_OFFSETS[csr_name.lower().strip()]
        except KeyError as exc:
            raise ValueError(f"未知向量 CSR: {csr_name}") from exc

    def get_offset(self, name: str) -> int:
        normalized = name.lower().strip()
        if normalized.startswith("v") and normalized[1:].isdigit():
            return self.get_vreg_offset(normalized)
        return self.get_csr_offset(normalized)

    def get_vreg_range(self, reg_name: str) -> tuple[int, int]:
        start = self.get_vreg_offset(reg_name)
        return start, start + self.vreg_size

    def get_total_size(self) -> int:
        return STATE_TOTAL_SIZE


__all__ = [
    "CSR_OFFSETS",
    "DEFAULT_VLENB",
    "STATE_TOTAL_SIZE",
    "SimulatedStateLayout",
    "VREG_SIZE",
]
