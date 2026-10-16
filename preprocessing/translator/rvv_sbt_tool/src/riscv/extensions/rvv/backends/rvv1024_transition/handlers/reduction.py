"""RVV256→RVV1024 过渡路径的浮点归约安全子集。

这组 handler 不复用 RVV1024→RVV256 后端的 strip-mining（分块向量化）策略。
迁移后的目标硬件已经是 VLEN=1024，只要把源端保存的运行时 ``vl`` 作为 AVL
（活动向量长度），一条原生 RVV1024 reduction 就恰好观察源 RVV256 指令会
观察的活动元素。

归约的寄存器组规则与普通逐元素指令不同，必须单独写清楚：

* ``vs2`` 是被归约的向量，按当前源 ``LMUL`` 从紧凑状态 Pack；
* ``vd`` 和 ``vs1`` 分别是结果与初始 seed（种子），都只按一个源物理
  寄存器 Pack/Unpack，即使当前源 ``LMUL`` 是 m2/m4/m8；
* 对 widening reduction，``vd``/``vs1`` 的 element 0 的元素宽度会翻倍，
  但它们仍是单寄存器 seed/result，不得错误按 ``2 * LMUL`` 解释 raw
  payload。

每条指令始终遵循 ``Pack 全部输入 → 以源 VL/SEW/LMUL 在 RVV1024 执行
→ Unpack 单寄存器结果``。这保证 ``vd == vs1``、``vd == vs2`` 或三者部分
别名时，不会在写回前破坏尚未读取的源状态。当前刻意只支持无掩码 form；
masked reduction 的关闭 lane、NaN 传播和 v0 位布局需要独立的目标机差分验证。
"""

from __future__ import annotations

from typing import List

from riscv.extensions.rvv.analysis.config import StateTracker
from riscv.extensions.rvv.backends.rvv1024_transition.execution import (
    _emit_packed_vector_write,
)
from riscv.extensions.rvv.backends.rvv1024_transition.operands import (
    _error,
    _float_shape,
    _unmasked_operands,
)
from riscv.frontend.model import RVInstruction


def _emit_float_reduction_vs(
    insn: RVInstruction,
    state: StateTracker,

    *,
    native_opcode: str,
) -> List[str]:
    """发射同宽 ``vfred*.vs vd, vs2, vs1`` 的完整迁移闭环。

``_emit_packed_vector_write`` 会先 Pack ``vd``，再 Pack 所有 vector source；
这里显式把 result/seed 的 LMUL 均指定为 ``1.0``，而不是把当前 ``lmul``
传给它。如此既符合归约指令只读取/定义 element 0 的寄存器组规则，也避免
在源 m2/m4/m8 时不必要地要求 ``vd`` 或 ``vs1`` 满足整组起点对齐。
    """
    operands = _unmasked_operands(insn, 3)
    if operands is None:
        return _error(insn, "浮点归约仅支持无掩码 vd, vs2, vs1 form")
    vd, vs2, vs1 = operands
    try:
        sew, source_lmul, source_lmul_token = _float_shape(state)
    except ValueError as exc:
        return _error(insn, str(exc))

    return _emit_packed_vector_write(
        insn,
        state,

        native_opcode=native_opcode,
        # reduction 只把 vd[0] 写为结果；先 Pack 整个单物理寄存器可使 tu,mu
        # 下其余 byte 保持原值，Unpack 时不破坏源 RVV256 的紧凑 payload。
        vd=vd,
        result_lmul=1.0,
        vector_sources=((vs2, source_lmul), (vs1, 1.0)),
        execution_sew=sew,
        execution_lmul_token=source_lmul_token,
        operand_order=("vd", "vs0", "vs1"),
    )


def _emit_widening_float_reduction_vs(
    insn: RVInstruction,
    state: StateTracker,

    *,
    native_opcode: str,
) -> List[str]:
    """发射 ``vfwredusum.vs`` 的完整迁移闭环。

当前 vtype 描述的是窄 ``vs2``；目标指令自身据此把 ``vd``/``vs1`` 的
element 0 解释为 ``2 * SEW``。一期只支持 e16→e32 与 e32→e64：e8 没有
此路径承诺的浮点格式，e64→e128 则超出现有目标汇编/profile 的可验证范围。
    """
    operands = _unmasked_operands(insn, 3)
    if operands is None:
        return _error(insn, "宽化浮点归约仅支持无掩码 vd, vs2, vs1 form")
    vd, vs2, vs1 = operands
    try:
        sew, source_lmul, source_lmul_token = _float_shape(state)
        if sew not in (16, 32):
            raise ValueError(
                f"{native_opcode} 仅支持 e16->e32 或 e32->e64，当前为 e{sew}"
            )
    except ValueError as exc:
        return _error(insn, str(exc))

    return _emit_packed_vector_write(
        insn,
        state,

        native_opcode=native_opcode,
        # 重要：宽化 reduction 不等同于逐元素 widening。vd/vs1 都是宽元素
        # 的单寄存器 seed/result；只有被归约的 vs2 使用当前源 LMUL。
        vd=vd,
        result_lmul=1.0,
        vector_sources=((vs2, source_lmul), (vs1, 1.0)),
        execution_sew=sew,
        execution_lmul_token=source_lmul_token,
        operand_order=("vd", "vs0", "vs1"),
    )


def _build_vfredusum_vs_lines(context) -> list[str]:
    """翻译无掩码、非确定归约求和 ``vfredusum.vs``。"""
    insn = context.instruction
    state = context.state

    return _emit_float_reduction_vs(
        insn, state,  native_opcode="vfredusum.vs"
    )


def _build_vfredmax_vs_lines(context) -> list[str]:
    """翻译无掩码浮点最大值归约 ``vfredmax.vs``。"""
    insn = context.instruction
    state = context.state

    return _emit_float_reduction_vs(
        insn, state,  native_opcode="vfredmax.vs"
    )


def _build_vfredmin_vs_lines(context) -> list[str]:
    """翻译无掩码浮点最小值归约 ``vfredmin.vs``。"""
    insn = context.instruction
    state = context.state

    return _emit_float_reduction_vs(
        insn, state,  native_opcode="vfredmin.vs"
    )


def _build_vfwredusum_vs_lines(context) -> list[str]:
    """翻译无掩码宽化、非确定归约求和 ``vfwredusum.vs``。"""
    insn = context.instruction
    state = context.state

    return _emit_widening_float_reduction_vs(
        insn, state,  native_opcode="vfwredusum.vs"
    )


def _build_vfwredosum_vs_lines(context) -> list[str]:
    """翻译无掩码宽化、有序归约求和 ``vfwredosum.vs``。

    和 ``vfwredusum.vs`` 相比，差别只在目标硬件执行的归约顺序；两者的
    raw state 物理组规则完全相同：宽 seed/result 都是单个源寄存器，而
    ``vs2`` 仍按当前 source LMUL。不能把有序语义错误地降为 unordered
    opcode，也不能把 seed/result 扩大成 ``2 * LMUL`` 组。
    """
    insn = context.instruction
    state = context.state

    return _emit_widening_float_reduction_vs(
        insn, state,  native_opcode="vfwredosum.vs"
    )
