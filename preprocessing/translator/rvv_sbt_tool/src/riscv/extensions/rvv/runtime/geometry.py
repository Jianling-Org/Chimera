"""翻译方向 VLEN 几何的唯一权威定义。

一个翻译方向的根本事实只有三个：源 VLENB、目标 VLENB 和二者比值。
此前这些值以字面量形式散落在 chunk/wide_chunk/profile/handler 中
（``256 // sew``、``* 4``、``Fraction(1024)`` 等），没有任何单一模块
拥有它们，导致：

- 支持新方向（例如 512→256）需要修改多处且无一致性保证；
- ``BackendProfile`` 的 source/target_vlenb 字段从未被消费，属于
  与真实推导漂移的声明。

本模块把几何收敛为 :class:`TranslationGeometry`：构造时校验方向合法、
槽位尺寸与 ``SimulatedStateLayout`` ABI 一致，并提供所有派生量（块元素
数、块字节数、寄存器槽覆盖的目标物理寄存器数）。任何后端代码不得再
内联这些推导。
"""

from __future__ import annotations

from dataclasses import dataclass

from riscv.extensions.rvv.runtime.layout import (
    STATE_TOTAL_SIZE,
    VREG_SIZE,
    SimulatedStateLayout,
)


@dataclass(frozen=True, slots=True)
class TranslationGeometry:
    """一个翻译方向的 VLEN 几何及其全部派生量。

    ``source_vlenb`` 是客体语义参数（决定 guest 可见 VLMAX）；
    ``target_vlenb`` 是目标硬件能力。状态槽大小固定为 ABI 的
    ``VREG_SIZE``，不随后者缩放。
    """

    source_vlenb: int
    target_vlenb: int

    def __post_init__(self) -> None:
        if self.source_vlenb <= 0 or self.target_vlenb <= 0:
            raise ValueError("源/目标 VLENB 必须为正整数")
        # 源 VLENB 必须能被状态槽整除覆盖（源 vreg 组物理上落在
        # simulated_cpu_state 的固定槽内），且不超过 ABI 总 payload。
        if VREG_SIZE % self.source_vlenb:
            raise ValueError(
                f"源 VLENB={self.source_vlenb} 不能整除固定状态槽 "
                f"{VREG_SIZE}B，无法解释源寄存器组布局"
            )
        # 目标 VLENB 必须是 2 的幂字节（RVV 硬件约束）。
        if self.target_vlenb & (self.target_vlenb - 1):
            raise ValueError(f"目标 VLENB={self.target_vlenb} 必须是 2 的幂")
        if 32 * self.source_vlenb > STATE_TOTAL_SIZE:
            raise ValueError(
                f"32 个源 vreg 槽 ({self.source_vlenb}B) 超出状态块 "
                f"{STATE_TOTAL_SIZE:#x}B"
            )

    @property
    def ratio(self) -> int:
        """源/目标 VLENB 比值；strip-mining 的方向常数。"""
        if self.source_vlenb < self.target_vlenb:
            raise ValueError("该方向源窄于目标，块拆分常数未定义")
        return self.source_vlenb // self.target_vlenb

    @property
    def source_vlen_bits(self) -> int:
        return self.source_vlenb * 8

    @property
    def target_vlen_bits(self) -> int:
        return self.target_vlenb * 8

    def elements_per_chunk(self, sew: int) -> int:
        """一个目标块在给定 SEW 下承载的元素数。"""
        if sew <= 0 or self.target_vlen_bits % sew:
            raise ValueError(f"SEW={sew} 不能整除目标 VLEN={self.target_vlen_bits}")
        return self.target_vlen_bits // sew

    def chunk_bytes(self) -> int:
        """一个目标块的搬运字节数（恒等于目标 VLENB）。"""
        return self.target_vlenb

    def source_vlmax(self, sew: int, lmul: float) -> int:
        """guest 可见 VLMAX = 源 VLEN * LMUL / SEW。"""
        if sew <= 0:
            raise ValueError("SEW 必须为正")
        value = self.source_vlen_bits * lmul / sew
        if value != int(value):
            raise ValueError(f"VLMAX 非整数: VLEN={self.source_vlen_bits}, e{sew}, {lmul:g}")
        return int(value)

    def whole_register_transfer_lmul(self, byte_count: int) -> int:
        """为整寄存器搬运选择恰好覆盖 ``byte_count`` 的目标寄存器数。

        返回值即 ``vl{N}r/vs{N}r`` 的 N（1/2/4/8）。
        """
        if byte_count <= 0 or byte_count % self.target_vlenb:
            raise ValueError(
                f"整寄存器搬运字节数 {byte_count} 必须是目标 VLENB="
                f"{self.target_vlenb} 的整数倍"
            )
        registers = byte_count // self.target_vlenb
        if registers not in (1, 2, 4, 8):
            raise ValueError(f"整寄存器搬运需要 1/2/4/8 个目标寄存器，得到 {registers}")
        return registers


# ---------------------------------------------------------------------------
# 当前支持的翻译方向。新增方向必须在此登记并同步 profile/layout 合同，
# 不允许在 handler 中内联几何常量。
# ---------------------------------------------------------------------------

#: RVV1024 源语义 → RVV256 目标执行（rvv_sbt_rvv.py 主路径）。
RVV1024_TO_RVV256_GEOMETRY = TranslationGeometry(
    source_vlenb=128,
    target_vlenb=32,
)

#: RVV256 紧凑源状态 → RVV1024 目标执行（rvv_sbt_rvv1024.py 过渡路径）。
RVV256_TO_RVV1024_GEOMETRY = TranslationGeometry(
    source_vlenb=32,
    target_vlenb=128,
)


def geometry_for_direction(source_vlenb: int, target_vlenb: int) -> TranslationGeometry:
    """按方向参数返回已登记的几何对象，拒绝未支持方向。

    这是对外的唯一构造入口：调用方不能凭空 new 一个几何来绕过方向
    白名单（例如 64→32），除非它同时在本模块登记并通过测试。
    """

    for geometry in (RVV1024_TO_RVV256_GEOMETRY, RVV256_TO_RVV1024_GEOMETRY):
        if (
            geometry.source_vlenb == source_vlenb
            and geometry.target_vlenb == target_vlenb
        ):
            return geometry
    raise ValueError(
        "未支持的翻译方向: "
        f"source_vlenb={source_vlenb}, target_vlenb={target_vlenb}; "
        "当前已登记 128→32 (RVV1024→RVV256) 与 32→128 (RVV256→RVV1024)"
    )


def validate_state_layout_compatibility(geometry: TranslationGeometry) -> SimulatedStateLayout:
    """校验几何与状态 ABI 布局一致，返回布局对象。

    源 VLENB 描述的是 payload 解释方式；CSR 页和总大小始终来自固定
    ABI。两路径的 payload 语义不同（128B 槽 vs 32B 紧凑），但 CSR 页
    共享，因此这里只验证几何的算术自洽性。
    """

    layout = SimulatedStateLayout(vlenb=geometry.source_vlenb)
    if 32 * geometry.source_vlenb > layout.get_total_size():
        raise ValueError(
            f"几何 {geometry} 的源 payload 超出状态 ABI 总大小"
        )
    return layout


__all__ = [
    "RVV1024_TO_RVV256_GEOMETRY",
    "RVV256_TO_RVV1024_GEOMETRY",
    "TranslationGeometry",
    "geometry_for_direction",
    "validate_state_layout_compatibility",
]
