"""RVV256→RVV1024 过渡区的安全 ``vrgather`` 指令。

``vrgather`` 不能像普通逐元素算术那样，简单地以相同的 SEW/LMUL 在更宽的
RVV1024 硬件上执行。原因是它的索引边界由 *源端* VLMAX 决定：

``vd[i] = vs2[vs1[i]] if vs1[i] < source_VLMAX else 0``。

在 VLENB=32 的源端和 VLENB=128 的目标端之间，同一 vtype 的目标 VLMAX
恰好扩大四倍。若直接执行目标 ``vrgather``，位于
``[source_VLMAX, target_VLMAX)`` 的索引会读到目标临时寄存器的残留字节，
而不是源架构规定的零。

本模块采用不改变客体 VL 的零扩展办法：

1. 先以目标同形 vtype 和 AVL=-1 覆盖 ``temp_vs2`` 的整个目标 VLMAX 为零；
2. 再把紧凑 RVV256 ``vs2`` raw 字节 Pack 到该临时组的低位；
3. 最后以保存的源 VL 执行原生 gather。

因此，目标 VLMAX 以内、但超过 source VLMAX 的访问只能读到步骤 1 写入的
零；超过 target VLMAX 的访问则仍由 RVV 原生 gather 定义为零。这样无需用
标量循环，也不会把目标机更宽的寄存器视图泄漏给源客体。

所有操作数（旧 ``vd``、数据 ``vs2``、索引 ``vs1``）都在任何 Unpack 前完成
Pack，故 ``vd == vs2``、``vd == vs1`` 及部分 LMUL 组重叠不会破坏读取顺序。
本阶段刻意只支持无掩码 form；new_label 会让 ``v0.t`` 进入结构化拒绝，
再由反向 profile 输出带诊断的 ``ebreak``，而不是悄悄当作无掩码执行。
"""

from __future__ import annotations

from typing import List

from riscv.extensions.rvv.backends.rvv1024_transition import state_view
from riscv.extensions.rvv.analysis.model import LEGAL_LMULS
from riscv.extensions.rvv.analysis.config import StateTracker
from riscv.extensions.rvv.translation.temps import TempRegisterAllocator
from riscv.extensions.rvv.backends.rvv1024_transition.execution import (
    _allocate_vector_groups,
    _emit_execution_vsetvl,
    _emit_load_source_vl,
    _emit_pack_group,
    _emit_unpack_group,
)
from riscv.extensions.rvv.backends.rvv1024_transition.operands import (
    _error,
    _source_shape,
    _unmasked_operands,
)
from riscv.extensions.rvv.backends.rvv1024_transition.state_view import SOURCE_VLENB

from riscv.extensions.rvv.backends.rvv1024_transition.operands import _index_e16_shape


_LEGAL_LMULS = LEGAL_LMULS




def _emit_zero_extended_vs2(
    lines: List[str],
    *,
    temp_vs2: str,
    target_vlmax_avl_reg: str,
    sew: int,
    lmul_token: str,
    source_vlmax: int,
) -> None:
    """清零目标 ``vs2`` 的完整目标 VLMAX，构造 source-VLMAX 边界。

    这里 **不能** 把当前 source VL 传给 ``vsetvli``：那只会清零 active lane，
    仍会让 ``VL`` 内的 out-of-source-range index 读取未初始化的目标 lane。向
    ``vsetvli`` 传入全一 AVL 会让硬件选择该目标 vtype 的 VLMAX；在本路径固定
    32B→128B profile 下，它是 source VLMAX 的四倍。

    后续 Pack 只覆盖低 ``source_VLMAX`` 所在的 raw 字节区，因此原始源数据
    保留在低位，而扩展区始终为零。该临时组只用于读取，既不触及
    ``simulated_cpu_state``，也不会改变客体可见的 source ``vl``。
    """
    lines.append(
        "    # gather 边界：先把目标 vs2 的扩展 lane 清零，"
        f"source VLMAX={source_vlmax}。"
    )
    lines.append(
        f"    li      {target_vlmax_avl_reg}, -1             "
        "# 请求 RVV1024 同形 vtype 的完整 VLMAX"
    )
    lines.append(
        f"    vsetvli zero, {target_vlmax_avl_reg}, e{sew}, {lmul_token}, tu, mu"
        "  # 目标 VLMAX=4*source VLMAX"
    )
    lines.append(
        f"    vmv.v.i {temp_vs2}, 0                     "
        "# index>=source VLMAX 时读取零扩展区"
    )


def _emit_gather(
    insn,
    state: StateTracker,

    *,
    native_opcode: str,
    index_lmul: float | None = None,
) -> List[str]:
    """发射一个无掩码 gather 的 Pack→执行→Unpack 闭环。

    ``index_lmul=None`` 代表 ``vrgather.vv``：index 与 data 共用当前 LMUL。
    其余情况用于 ``vrgatherei16.vv``，由调用方传入已经验证的 e16-index EMUL。
    """
    operands = _unmasked_operands(insn, 3)
    if operands is None:
        return _error(insn, f"{native_opcode} 当前只支持无掩码 vd, vs2, vs1 form")
    vd, vs2, vs1 = operands

    try:
        sew, data_lmul, lmul_token, data_group_width = _source_shape(state)
        # state_view 的 raw 地址定义固定为 N*32B。即使日后有人直接调用
        # handler，也不能让一个非 32B 的 StateTracker 静默复用这套布局。
        if state.vlenb != SOURCE_VLENB:
            raise ValueError(
                f"{native_opcode} 只支持 source vlenb={SOURCE_VLENB}，"
                f"当前为 {state.vlenb}"
            )
        # ``StateTracker`` 用 source_vlenb=32 构造。该数字只用于翻译期
        # 合法性诊断和注释；生成代码仍通过 state CSR.vl 取得动态活动长度。
        source_vlmax = state.get_vlmax()
        if source_vlmax <= 0:
            raise ValueError(
                f"{native_opcode} 需要正的 source VLMAX，当前为 {source_vlmax}"
            )
        if index_lmul is None:
            index_lmul = data_lmul
            index_group_width = data_group_width
        else:
            if index_lmul not in _LEGAL_LMULS:
                raise ValueError(f"内部错误：非法 index LMUL={index_lmul:g}")
            index_group_width = int(index_lmul) if index_lmul >= 1 else 1

        state_view
        # 独立临时组保证所有 raw state 读取均早于任意目的 Unpack，即使
        # 客体寄存器编号相同或 LMUL 组部分重叠也不受影响。
        temp_vd, temp_vs2, temp_vs1 = _allocate_vector_groups(
            [data_group_width, data_group_width, index_group_width]
        )
        temps = TempRegisterAllocator(insn, reserved_gprs=("t6",))
        source_vl_reg = temps.alloc_gpr()
        address_reg = temps.alloc_gpr()
        transfer_avl_reg = temps.alloc_gpr()
        target_vlmax_avl_reg = temps.alloc_gpr()
    except (ValueError, TypeError) as exc:
        return _error(insn, str(exc))

    index_description = (
        f"index EMUL={index_lmul:g}" if native_opcode == "vrgatherei16.vv"
        else f"index EMUL={data_lmul:g}"
    )
    lines: List[str] = [
        f"# {insn.opcode} {insn.op_str} (RVV256 -> RVV1024 安全 gather)",
        f"# source SEW=e{sew}, data LMUL={data_lmul:g}, {index_description}; 仅无掩码。",
        "# 关键：target VLMAX 更大，必须零扩展 vs2 后再使用目标原生 gather。",
        "# Pack 顺序覆盖旧 vd、vs2、vs1；任何 raw state 写回都发生在它们之后。",
    ]
    _emit_load_source_vl(lines,  source_vl_reg, address_reg)

    # 对 source data 输入执行完整目标 VLMAX 的零初始化。后续 Pack 只会覆盖
    # 低位的 source raw payload，故 target gather 的扩大索引范围不会泄漏残值。
    _emit_zero_extended_vs2(
        lines,
        temp_vs2=temp_vs2,
        target_vlmax_avl_reg=target_vlmax_avl_reg,
        sew=sew,
        lmul_token=lmul_token,
        source_vlmax=source_vlmax,
    )

    # ``tu`` 下 vd 的 source tail 必须先被带入临时组；对于别名，三个 Pack
    # 都在同一 state 快照上进行，不能在中途 Unpack。
    _emit_pack_group(
        lines,  temp_vd, address_reg, vd, data_lmul,
        transfer_avl_reg,
    )
    _emit_pack_group(
        lines,  temp_vs2, address_reg, vs2, data_lmul,
        transfer_avl_reg,
    )
    _emit_pack_group(
        lines,  temp_vs1, address_reg, vs1, index_lmul,
        transfer_avl_reg,
    )

    # 只恢复 source VL，而不是 target VLMAX。这样 active lane 集合与源客体
    # 一致；越界索引的零结果由上方零扩展 + 原生 target-gather 边界共同给出。
    _emit_execution_vsetvl(lines, source_vl_reg, sew, lmul_token)
    lines.append(f"    {native_opcode:<18} {temp_vd}, {temp_vs2}, {temp_vs1}")
    _emit_unpack_group(
        lines,  temp_vd, address_reg, vd, data_lmul,
        transfer_avl_reg,
    )
    lines.append(
        "    # gather 完成：仅源 data 组的 raw 字节被立即写回，"
        "source VLMAX 之外不进入 state。"
    )
    return lines


def _build_vrgather_vv_lines(context) -> list[str]:
    """翻译无掩码 ``vrgather.vv vd, vs2, vs1``。"""
    insn = context.instruction
    state = context.state

    return _emit_gather(insn, state,  native_opcode="vrgather.vv")


def _build_vrgatherei16_vv_lines(context) -> list[str]:
    """翻译无掩码 e16-index ``vrgatherei16.vv vd, vs2, vs1``。"""
    insn = context.instruction
    state = context.state

    try:
        sew, lmul, _, _ = _source_shape(state)
        index_lmul, _ = _index_e16_shape(lmul, sew)
    except (ValueError, TypeError) as exc:
        return _error(insn, str(exc))
    return _emit_gather(
        insn,
        state,

        native_opcode="vrgatherei16.vv",
        index_lmul=index_lmul,
    )
