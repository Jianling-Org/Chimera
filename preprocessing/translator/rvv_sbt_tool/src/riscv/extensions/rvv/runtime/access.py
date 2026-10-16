"""模拟 CPU 状态基址取址器。

本组件是 TLS（线程局部存储）符号、helper 回退和翻译方向
profile 的唯一所有者。它只负责把当前后端的状态块地址装入
``t6``；寄存器保护由 :class:`VectorBlockEmitter` 依据结构化
``LoweringResult`` 完成。
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from riscv.extensions.rvv.runtime.contract import LEGACY_OUTPUT_CONTRACT
from riscv.extensions.rvv.runtime.layout import CSR_OFFSETS, SimulatedStateLayout


from riscv.registers import CALL_CLOBBERED_GPRS, CALL_CLOBBERED_FPRS


# 状态地址发射者（chunk.py / state_view.py / 旧模板）与 VectorBlockEmitter
# 之间的内部合同标记。出现在汇编注释中：当源指令把 t6 当作语义输入时，
# wrapper 会改写语义 t6，但带此标记的行必须继续引用真实状态基址。
# 该字符串只有一个定义点；任何模块不得自行复制字面量。
STATE_BASE_MARKER = "CHIMERA_STATE_BASE"


def emit_clear_vstart(lines: list[str], address_reg: str) -> None:
    """Clear the source CSR before a configuration result can overwrite t6."""
    lines.extend((
        f"    li      {address_reg}, {CSR_OFFSETS['vstart']:#x}",
        f"    add     {address_reg}, t6, {address_reg}  # {STATE_BASE_MARKER}",
        f"    sd      zero, 0({address_reg})              # CSR.vstart = 0 after vset",
    ))


@dataclass(frozen=True, slots=True)
class StateAccessEmitter:
    """发射当前翻译方向的状态基址装载序列。"""

    state_base_mode: str = "initial-exec"
    state_symbol: str = LEGACY_OUTPUT_CONTRACT.state_symbol
    lookup_profile: int = LEGACY_OUTPUT_CONTRACT.lookup_profile
    non_tls_state_symbol: str = LEGACY_OUTPUT_CONTRACT.non_tls_state_symbol
    layout: SimulatedStateLayout = SimulatedStateLayout()

    STATE_BASE_MODES = ("initial-exec", "helper")
    call_clobbered_gprs = CALL_CLOBBERED_GPRS
    call_clobbered_fprs = CALL_CLOBBERED_FPRS

    def __post_init__(self) -> None:
        if self.state_base_mode not in self.STATE_BASE_MODES:
            valid_modes = ", ".join(self.STATE_BASE_MODES)
            raise ValueError(
                f"unsupported state_base_mode {self.state_base_mode!r}; "
                f"expected one of: {valid_modes}"
            )
        symbol_pattern = r"^[A-Za-z_][A-Za-z0-9_]*$"
        if not self.state_symbol or not re.match(symbol_pattern, self.state_symbol):
            raise ValueError(f"invalid state_symbol {self.state_symbol!r}")
        if not re.match(symbol_pattern, self.non_tls_state_symbol):
            raise ValueError(
                f"invalid non_tls_state_symbol {self.non_tls_state_symbol!r}"
            )
        if self.lookup_profile < 0:
            raise ValueError(
                f"lookup_profile must be non-negative, got {self.lookup_profile}"
            )

    def calls_helper(self, *, tls_state: bool = True) -> bool:
        """返回基址装载是否具有普通函数调用的破坏语义。"""

        return tls_state and self.state_base_mode == "helper"

    def emit_base_load(self, *, tls_state: bool = True) -> list[str]:
        """把当前线程的模拟状态基址装入 ``t6``。

        Initial-Exec 模式只覆盖 ``t6`` 并只读 ``tp``。helper 模式
        是显式兼容路径，必须按普通调用 ABI 保护 caller-saved
        寄存器。非 TLS fixture 直接引用后端约定的本地对象。
        """

        if not tls_state:
            return [f"    la      t6, {self.non_tls_state_symbol}"]
        if self.state_base_mode == "helper":
            lines: list[str] = []
            if self.lookup_profile:
                lines.append(f"    li      a0, {self.lookup_profile}")
            lines.extend((
                "    call    get_simulated_cpu_state_addr@plt",
                "    mv      t6, a0",
            ))
            return lines
        return [
            f"    la.tls.ie t6, {self.state_symbol}",
            "    add     t6, t6, tp",
        ]

    @staticmethod
    def emit_address(destination: str, base: str, offset: int) -> str:
        """生成状态字段地址，正确处理超出 I 型立即数范围的偏移。"""

        if -2048 <= offset <= 2047:
            return f"    addi    {destination}, {base}, {offset}  # {STATE_BASE_MARKER}"
        return "\n".join((
            f"    li      {destination}, {offset}",
            f"    add     {destination}, {base}, {destination}  # {STATE_BASE_MARKER}",
        ))

    def emit_load_csr(
        self, destination: str, csr_name: str, base: str = "t6"
    ) -> list[str]:
        """从统一布局读取一个模拟 CSR。"""

        offset = self.layout.get_csr_offset(csr_name)
        return [
            self.emit_address(destination, base, offset),
            f"    ld      {destination}, 0({destination})",
        ]

    def emit_store_csr(
        self,
        source: str,
        csr_name: str,
        base: str = "t6",
        address_reg: str = "t0",
    ) -> list[str]:
        """按统一布局写回一个模拟 CSR。"""

        offset = self.layout.get_csr_offset(csr_name)
        return [
            self.emit_address(address_reg, base, offset),
            f"    sd      {source}, 0({address_reg})",
        ]


__all__ = [
    "CALL_CLOBBERED_FPRS",
    "CALL_CLOBBERED_GPRS",
    "STATE_BASE_MARKER",
    "StateAccessEmitter",
    "emit_clear_vstart",
]
