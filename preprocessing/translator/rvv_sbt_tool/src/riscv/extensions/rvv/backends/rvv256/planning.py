"""planning：后端内部职责。"""

from __future__ import annotations

from dataclasses import dataclass
from fractions import Fraction
import re
from typing import Iterable
from riscv.extensions.rvv.translation.temps import record_vreg_group
from riscv.extensions.rvv.runtime.geometry import RVV1024_TO_RVV256_GEOMETRY


_LEGAL_LMULS = (
    Fraction(8), Fraction(4), Fraction(2), Fraction(1),
    Fraction(1, 2), Fraction(1, 4), Fraction(1, 8),
)


_LMUL_TEXT = {
    Fraction(8): "m8",
    Fraction(4): "m4",
    Fraction(2): "m2",
    Fraction(1): "m1",
    Fraction(1, 2): "mf2",
    Fraction(1, 4): "mf4",
    Fraction(1, 8): "mf8",
}


_VREG_RE = re.compile(r"^v([0-9]|[12][0-9]|3[01])$")


@dataclass(frozen=True)
class WideChunkPlan:
    """一次宽块翻译所需的静态布局和目标 vtype 决策。"""

    source_operand_emuls: tuple[Fraction, ...]
    target_lmul: Fraction
    target_operand_emuls: tuple[Fraction, ...]
    target_vtype_sew: int
    elements_per_chunk: int
    bytes_per_chunk: int
    group_bases: tuple[str, ...]
    one_shot: bool

    @property
    def target_lmul_text(self) -> str:
        return _LMUL_TEXT[self.target_lmul]


class WideVRegGroupAllocator:
    """
    在 v8-v31 中分配对齐且互不重叠的目标物理向量寄存器组。

    v0 永远留给 mask；v1-v7 暂不使用，为后续专用指令和部署门禁保留空间。
    分数 LMUL 仍占用一个物理寄存器，但其有效位数由目标 vtype 约束。
    """

    def __init__(self, first: int = 8, last: int = 31):
        self.first = first
        self.last = last

    @staticmethod
    def _width(emul: Fraction) -> int:
        return int(emul) if emul >= 1 else 1

    def allocate(self, emuls: Iterable[Fraction]) -> tuple[str, ...] | None:
        emuls = tuple(emuls)
        widths = tuple(self._width(emul) for emul in emuls)
        occupied: set[int] = set()
        result: list[int] = []

        def search(index: int) -> bool:
            if index == len(widths):
                return True
            width = widths[index]
            for base in range(self.first, self.last - width + 2):
                if width > 1 and base % width:
                    continue
                members = set(range(base, base + width))
                if members & occupied:
                    continue
                occupied.update(members)
                result.append(base)
                if search(index + 1):
                    return True
                result.pop()
                occupied.difference_update(members)
            return False

        if not search(0):
            return None
        groups = tuple(f"v{base}" for base in result)
        # 与保守路径的 VRegTempAllocator 相同，每个成功分配的组必须进入
        # clobber 采集；否则宽 profile 的 LoweringResult.clobbered_vregs
        # 会静默为空，未来任何依赖该合同的 wrapper/验证器都会拿到错误数据。
        for base, width in zip(result, widths):
            record_vreg_group(f"v{base}", width)
        return groups


def _as_fraction(value: float | int | Fraction) -> Fraction:
    """把 StateTracker 的历史 float LMUL 无损映射回 RVV 合法分数。"""
    fraction = Fraction(str(value))
    if fraction not in _LEGAL_LMULS:
        raise ValueError(f"非法源 LMUL: {value}")
    return fraction


def _validate_source_group(reg: str, emul: Fraction) -> None:
    """校验源模拟寄存器组的 RVV 对齐和 v31 边界约束。"""
    match = _VREG_RE.match(str(reg).strip().lower())
    if not match:
        raise ValueError(f"非法向量寄存器: {reg}")
    base = int(match.group(1))
    if emul < Fraction(1, 8) or emul > 8:
        raise ValueError(f"{reg} 的源 EMUL={emul} 超出 mf8..m8")
    if emul >= 1:
        if emul.denominator != 1:
            raise ValueError(f"{reg} 的整数寄存器组 EMUL 非整数: {emul}")
        width = int(emul)
        if base % width or base + width > 32:
            raise ValueError(f"{reg} 不满足 EMUL={emul} 的组对齐/边界约束")


def plan_wide_chunk(
    *,
    source_lmul: float | int | Fraction,
    source_sew: int,
    data_sew: int,
    source_regs: Iterable[str],
    target_group_count: int,
    max_target_lmul: float | int | Fraction = Fraction(8),
) -> WideChunkPlan | None:
    """
    规划饱和宽块。

    访存指令的寄存器 EMUL 为 ``LMUL * EEW / SEW``；同宽算术传入
    ``data_sew == source_sew``。目标 vtype 直接使用 data_sew，因此目标
    operand EMUL 与目标 LMUL 相同。
    """
    source_regs = tuple(str(reg) for reg in source_regs)
    return plan_wide_operands(
        source_lmul=source_lmul,
        source_sew=source_sew,
        source_operands=tuple((reg, data_sew) for reg in source_regs),
        target_vtype_sew=data_sew,
        target_operand_eews=tuple(data_sew for _ in range(target_group_count)),
        max_target_lmul=max_target_lmul,
    )


def plan_wide_operands(
    *,
    source_lmul: float | int | Fraction,
    source_sew: int,
    source_operands: Iterable[tuple[str, int]],
    target_vtype_sew: int,
    target_operand_eews: Iterable[int],
    max_target_lmul: float | int | Fraction = Fraction(8),
) -> WideChunkPlan | None:
    """
    为 widening（加宽）等异构 EEW 指令规划目标寄存器组。

    ``source_operands`` 描述模拟状态中的 ``(vreg, EEW)``；
    ``target_operand_eews`` 描述每个目标临时组承载的 EEW。EMUL 始终按
    ``LMUL * EEW / SEW`` 推导，因而不会把宽目标误分配成窄 m1 组。
    """
    if source_sew not in (8, 16, 32, 64) or target_vtype_sew not in (8, 16, 32, 64):
        return None
    source_lmul_fraction = _as_fraction(source_lmul)
    max_lmul = _as_fraction(max_target_lmul)
    source_operands = tuple((str(reg), int(eew)) for reg, eew in source_operands)
    target_eews = tuple(int(eew) for eew in target_operand_eews)
    if any(eew not in (8, 16, 32, 64) for _, eew in source_operands):
        return None
    if any(eew not in (8, 16, 32, 64) for eew in target_eews):
        return None

    source_emuls = tuple(
        source_lmul_fraction * Fraction(eew, source_sew)
        for _, eew in source_operands
    )
    for (reg, _), emul in zip(source_operands, source_emuls):
        _validate_source_group(reg, emul)

    # 目标 vtype 的 SEW 与源 SEW 不同（例如 EEW 型访存）时，需要先换算
    # 到目标 vtype 的 LMUL 标度。放大倍数来自方向几何（128B→32B 即 4），
    # 不再内联魔法数字。
    geometry = RVV1024_TO_RVV256_GEOMETRY
    desired = min(
        source_lmul_fraction
        * Fraction(target_vtype_sew, source_sew)
        * geometry.ratio,
        max_lmul,
        Fraction(8),
    )
    candidates = [item for item in _LEGAL_LMULS if item <= desired]
    group_allocator = WideVRegGroupAllocator()
    for target_lmul in candidates:
        target_emuls = tuple(
            target_lmul * Fraction(eew, target_vtype_sew) for eew in target_eews
        )
        if any(emul < Fraction(1, 8) or emul > 8 for emul in target_emuls):
            continue
        groups = group_allocator.allocate(target_emuls)
        if groups is None:
            continue
        elements = (
            Fraction(geometry.target_vlen_bits)
            * target_lmul
            / target_vtype_sew
        )
        source_vlmax = (
            Fraction(geometry.source_vlen_bits)
            * source_lmul_fraction
            / source_sew
        )
        if elements.denominator != 1 or source_vlmax.denominator != 1:
            continue
        elements_int = int(elements)
        if elements_int <= 0 or elements_int & (elements_int - 1):
            continue
        return WideChunkPlan(
            source_operand_emuls=source_emuls,
            target_lmul=target_lmul,
            target_operand_emuls=target_emuls,
            target_vtype_sew=target_vtype_sew,
            elements_per_chunk=elements_int,
            bytes_per_chunk=elements_int * (target_vtype_sew // 8),
            group_bases=groups,
            one_shot=elements_int >= int(source_vlmax),
        )
    return None
