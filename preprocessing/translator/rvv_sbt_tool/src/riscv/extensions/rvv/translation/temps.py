"""一次 lowering 的临时寄存器分配与破坏集合捕获。"""

from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from typing import Iterator
from typing import Iterable
from riscv.frontend.model import RVInstruction
from riscv.registers import (
    collect_scalar_register_uses,
    normalize_gpr_name,
    normalize_fpr_name,
)


@dataclass(slots=True)
class ClobberCapture:
    """一次 lowerer 调用中实际分配的临时寄存器集合。"""

    gprs: set[str] = field(default_factory=set)
    fprs: set[str] = field(default_factory=set)
    vregs: set[str] = field(default_factory=set)


_ACTIVE_CAPTURE: ContextVar[ClobberCapture | None] = ContextVar(
    "chimera_lowering_clobber_capture", default=None
)


@contextmanager
def capture_clobbers() -> Iterator[ClobberCapture]:
    """建立可嵌套的单次采集作用域。"""

    capture = ClobberCapture()
    token = _ACTIVE_CAPTURE.set(capture)
    try:
        yield capture
    finally:
        _ACTIVE_CAPTURE.reset(token)


def record_gpr(register: str) -> None:
    capture = _ACTIVE_CAPTURE.get()
    if capture is not None:
        capture.gprs.add(str(register).strip().lower())


def record_fpr(register: str) -> None:
    capture = _ACTIVE_CAPTURE.get()
    if capture is not None:
        capture.fprs.add(str(register).strip().lower())


def record_vreg_group(start_register: str, width: int) -> None:
    """记录一个连续目标向量临时组的全部物理寄存器。"""

    capture = _ACTIVE_CAPTURE.get()
    if capture is None:
        return
    text = str(start_register).strip().lower()
    if not text.startswith("v") or not text[1:].isdigit():
        raise ValueError(f"临时向量寄存器名称非法: {start_register!r}")
    start = int(text[1:])
    for number in range(start, start + int(width)):
        capture.vregs.add(f"v{number}")


GPR_TEMP_POOL = ("t0", "t1", "t2", "t3", "t4", "t5", "a0", "a1", "a2", "a3")


FPR_TEMP_POOL = (
    "ft0", "ft1", "ft2", "ft3", "ft4", "ft5",
    "ft6", "ft7", "ft8", "ft9", "ft10", "ft11",
)


class TempRegisterAllocator:
    """
    轻量级临时寄存器分配器。

    用法示例：
        temps = TempRegisterAllocator(insn, reserved_gprs=("t6",))
        loop_counter = temps.alloc_gpr()
        value_reg = temps.alloc_fpr()

    设计原则：
    - 分配结果稳定：始终按固定 temp 池顺序选择；
    - 避免语义冲突：自动排除当前指令已使用的标量寄存器；
    - 避免基址冲突：调用方可额外传入保留寄存器集合；
    - 不做释放复用：每个 handler 生命周期很短，直接单向分配最清晰。
    """

    def __init__(
        self,
        insn: RVInstruction | None = None,
        reserved_gprs: Iterable[str] = (),
        reserved_fprs: Iterable[str] = (),
        extra_avoid_gprs: Iterable[str] = (),
        extra_avoid_fprs: Iterable[str] = (),
    ) -> None:
        inferred_gprs: set[str] = set()
        inferred_fprs: set[str] = set()

        # ``extra_avoid_*`` 不是普通保留寄存器：调用方用它声明模板中仍由
        # 固定标量尾部显式写入的 scratch（例如 RVV256 尾部的 ft0-ft2）。
        # 因而除了阻止动态分配器再次选中它们，还必须把它们写入本轮
        # LoweringResult 的结构化 clobber 集。``reserved_*`` 则包括只读输入
        # 或 t6 状态基址，不能在这里一概视为破坏。
        explicit_gprs = {
            register
            for token in extra_avoid_gprs
            if (register := normalize_gpr_name(str(token))) is not None
        }
        explicit_fprs = {
            register
            for token in extra_avoid_fprs
            if (register := normalize_fpr_name(str(token))) is not None
        }
        for register in explicit_gprs:
            record_gpr(register)
        for register in explicit_fprs:
            record_fpr(register)

        if insn is not None:
            inferred_gprs, inferred_fprs = collect_scalar_register_uses(insn)

        self._blocked_gprs = (
            set(reserved_gprs) |
            explicit_gprs |
            inferred_gprs
        )
        self._blocked_fprs = (
            set(reserved_fprs) |
            explicit_fprs |
            inferred_fprs
        )

        self._free_gprs = [reg for reg in GPR_TEMP_POOL if reg not in self._blocked_gprs]
        self._free_fprs = [reg for reg in FPR_TEMP_POOL if reg not in self._blocked_fprs]

    def alloc_gpr(self) -> str:
        """
        分配一个不与当前语义冲突的 GPR temp。
        """
        if not self._free_gprs:
            raise ValueError("可用的 GPR 临时寄存器不足，无法继续翻译当前指令")
        register = self._free_gprs.pop(0)
        record_gpr(register)
        return register

    def alloc_fpr(self) -> str:
        """
        分配一个不与当前语义冲突的 FPR temp。
        """
        if not self._free_fprs:
            raise ValueError("可用的 FPR 临时寄存器不足，无法继续翻译当前指令")
        register = self._free_fprs.pop(0)
        record_fpr(register)
        return register
