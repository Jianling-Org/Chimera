"""RVV256→RVV1024 过渡区的整数 slide 指令。

这组指令不能全部套用普通逐元素 Pack→执行→Unpack 模板。尤其是
``vslidedown`` 的读取边界是**源端 VLMAX**，而不是当前 ``vl``：

``vd[i] = vs2[i + OFFSET]``（当 ``i + OFFSET < source VLMAX``），否则为零。

在本迁移 profile 中，相同 SEW/LMUL 的 RVV1024 临时组有四倍 VLMAX。若直接
执行目标 ``vslidedown``，落在 ``[source VLMAX, target VLMAX)`` 的访问会读到
临时组残留内容，错误地泄漏目标核心更宽的寄存器视图。本模块因此在 Pack 前先
清零 ``vs2`` 临时组的完整目标 VLMAX，再只 Pack RVV256 raw payload 的低位字节。

``vslideup`` 与 ``vslide1up`` 不会读取超过 source ``vl`` 的元素，所以只需以
source ``vl`` 执行；但 RVV 规范规定它们的目的组不得与 source 组重叠，重叠编码
是保留的。本路径显式拒绝这种 form，而非利用临时组“碰巧”赋予保留编码含义。

``vslidedown.vi`` 已接通显式 ``v0.t``：old ``vd`` 和源 v0 都会在执行前
Pack，固定 ``tu,mu`` 保留关闭 lane。其他 slide handler 仍只接受无掩码 form；
调用方 new_label 会把未接通的 ``v0.t`` 标为结构化拒绝，从而不把
mask-undisturbed 语义悄悄降成无掩码执行。
"""

from __future__ import annotations

from typing import List

from riscv.extensions.rvv.analysis.config import StateTracker
from riscv.extensions.rvv.translation.temps import TempRegisterAllocator, record_vreg_group
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
    _data_operands_with_optional_v0_mask,
    _unmasked_operands,
)
from riscv.extensions.rvv.backends.rvv1024_transition.state_view import SOURCE_VLENB

from riscv.extensions.rvv.backends.rvv1024_transition.operands import (
    _source_group_span,
    _require_non_overlapping_groups,
    _parse_slide_uimm5,
)








def _emit_zero_extended_source(
    lines: List[str],
    *,
    temp_vs2: str,
    target_vlmax_avl_reg: str,
    sew: int,
    lmul_token: str,
    source_vlmax: int,
) -> None:
    """为 ``vslidedown`` 构造精确的 source-VLMAX 读取边界。

    这里必须以 AVL=-1 获得完整 target VLMAX；如果只清零 source ``vl`` 之外
    的一小段，``vslidedown`` 仍可能从未初始化的 target 扩展 lane 读取。随后
    的 Pack 只覆盖源 RVV256 raw payload（恰为 source VLMAX 个元素），所以
    ``[source VLMAX, target VLMAX)`` 始终为零。
    """
    lines.extend([
        "    # vslidedown 读取边界：target VLMAX 扩展区必须全为零，",
        f"    # 因而 i+OFFSET >= source VLMAX={source_vlmax} 时严格得到零。",
        f"    li      {target_vlmax_avl_reg}, -1             # 请求完整 RVV1024 VLMAX",
        f"    vsetvli zero, {target_vlmax_avl_reg}, e{sew}, {lmul_token}, tu, mu"
        "  # target VLMAX = 4 * source VLMAX",
        f"    vmv.v.i {temp_vs2}, 0                     # 清零 target 扩展 source lane",
    ])


def _emit_slide(
    insn,
    state: StateTracker,

    *,
    native_opcode: str,
    offset_operand: str,
    zero_extend_source: bool,
    require_non_overlap: bool,
) -> List[str]:
    """发射一条 slide 的 Pack→原生执行→Unpack 闭环及可选 ``v0.t``。

    ``offset_operand`` 已由外层按 .vi 或 .vx 规则规范化。无论客户 ``vd`` 与
    ``vs2`` 是否相同，两个临时组都独立分配，并且两次 Pack 都在任何 Unpack
    之前完成；这对合法 ``vslidedown``/``vslide1down`` 的 in-place 用法尤其重要。
    """
    parsed = _data_operands_with_optional_v0_mask(insn, 3)
    if parsed is None:
        return _error(insn, f"{native_opcode} 当前只支持 vd, vs2, offset 及可选 v0.t form")
    operands, mask_source = parsed
    vd, vs2, _ = operands

    try:
        sew, lmul, lmul_token, group_width = _source_shape(state)
        if state.vlenb != SOURCE_VLENB:
            raise ValueError(
                f"{native_opcode} 只支持 source vlenb={SOURCE_VLENB}，当前为 {state.vlenb}"
            )
        # 两个 span 检查也把非法 LMUL 组尽早变成整文件预检诊断。
        _source_group_span(vd, lmul)
        _source_group_span(vs2, lmul)
        if require_non_overlap:
            _require_non_overlapping_groups(vd, vs2, lmul, native_opcode)
        source_vlmax = state.get_vlmax()
        if source_vlmax <= 0:
            raise ValueError(f"{native_opcode} 需要正的 source VLMAX，当前为 {source_vlmax}")
        requested_widths = [group_width, group_width]
        if mask_source is not None:
            requested_widths.append(1)
        allocated = _allocate_vector_groups(requested_widths)
        temp_vd, temp_vs2 = allocated[:2]
        temp_mask = allocated[2] if mask_source is not None else None
        temps = TempRegisterAllocator(insn, reserved_gprs=("t6",))
        source_vl_reg = temps.alloc_gpr()
        address_reg = temps.alloc_gpr()
        transfer_avl_reg = temps.alloc_gpr()
        # 只有 slidedown 的 target 扩展区需要完整 VLMAX 的显式清零。
        target_vlmax_avl_reg = temps.alloc_gpr() if zero_extend_source else None
    except (ValueError, TypeError) as exc:
        return _error(insn, str(exc))

    lines: List[str] = [
        f"# {insn.opcode} {insn.op_str} (RVV256 -> RVV1024 安全 slide)",
        "# 先 Pack 旧 vd 与全部 vector source；任何紧凑 state 写回都在其后。",
    ]
    _emit_load_source_vl(lines,  source_vl_reg, address_reg)

    if zero_extend_source:
        _emit_zero_extended_source(
            lines,
            temp_vs2=temp_vs2,
            target_vlmax_avl_reg=target_vlmax_avl_reg,
            sew=sew,
            lmul_token=lmul_token,
            source_vlmax=source_vlmax,
        )

    # 先 Pack old vd 让 source tail 与 slide-up prefix 在 ``tu`` 下保持原值；
    # 再 Pack vs2。二者均不写 state，故 alias / partial-group overlap 不受影响。
    _emit_pack_group(
        lines,  temp_vd, address_reg, vd, lmul,
        transfer_avl_reg,
    )
    _emit_pack_group(
        lines,  temp_vs2, address_reg, vs2, lmul,
        transfer_avl_reg,
    )
    if mask_source is not None:
        _emit_pack_group(
            lines,  temp_mask, address_reg, mask_source, 1.0,
            transfer_avl_reg,
        )
        record_vreg_group("v0", 1)
        lines.append(
            f"    vmv1r.v v0, {temp_mask}                 # 载入源 v0.t 执行掩码"
        )
    _emit_execution_vsetvl(lines, source_vl_reg, sew, lmul_token)
    mask_suffix = ", v0.t" if mask_source is not None else ""
    lines.append(
        f"    {native_opcode:<18} {temp_vd}, {temp_vs2}, {offset_operand}{mask_suffix}"
    )
    _emit_unpack_group(
        lines,  temp_vd, address_reg, vd, lmul,
        transfer_avl_reg,
    )
    lines.append("    # 仅将源 RVV256 逻辑组的 raw bytes 立即 Unpack 回 state")
    return lines


def _build_vslidedown_vi_lines(context) -> list[str]:
    """翻译 ``vslidedown.vi vd, vs2, uimm`` 及可选 ``v0.t``。"""
    insn = context.instruction
    state = context.state

    parsed = _data_operands_with_optional_v0_mask(insn, 3)
    if parsed is None:
        return _error(insn, "vslidedown.vi 当前只支持 vd, vs2, uimm 及可选 v0.t form")
    operands, _mask_source = parsed
    try:
        offset = _parse_slide_uimm5(operands[2], "vslidedown.vi")
    except ValueError as exc:
        return _error(insn, str(exc))
    return _emit_slide(
        insn, state,
        native_opcode="vslidedown.vi",
        offset_operand=str(offset),
        zero_extend_source=True,
        require_non_overlap=False,
    )


def _build_vslidedown_vx_lines(context) -> list[str]:
    """翻译无掩码 ``vslidedown.vx vd, vs2, rs1``。"""
    insn = context.instruction
    state = context.state

    operands = _unmasked_operands(insn, 3)
    if operands is None:
        return _error(insn, "vslidedown.vx 当前只支持无掩码 vd, vs2, rs1 form")
    return _emit_slide(
        insn, state,
        native_opcode="vslidedown.vx",
        offset_operand=operands[2],
        zero_extend_source=True,
        require_non_overlap=False,
    )


def _build_vslideup_vi_lines(context) -> list[str]:
    """翻译无掩码 ``vslideup.vi``，并拒绝规范保留的组重叠编码。"""
    insn = context.instruction
    state = context.state

    operands = _unmasked_operands(insn, 3)
    if operands is None:
        return _error(insn, "vslideup.vi 当前只支持无掩码 vd, vs2, uimm form")
    try:
        offset = _parse_slide_uimm5(operands[2], "vslideup.vi")
    except ValueError as exc:
        return _error(insn, str(exc))
    return _emit_slide(
        insn, state,
        native_opcode="vslideup.vi",
        offset_operand=str(offset),
        zero_extend_source=False,
        require_non_overlap=True,
    )


def _build_vslide1up_vx_lines(context) -> list[str]:
    """翻译无掩码 ``vslide1up.vx``，并拒绝规范保留的组重叠编码。"""
    insn = context.instruction
    state = context.state

    operands = _unmasked_operands(insn, 3)
    if operands is None:
        return _error(insn, "vslide1up.vx 当前只支持无掩码 vd, vs2, rs1 form")
    return _emit_slide(
        insn, state,
        native_opcode="vslide1up.vx",
        offset_operand=operands[2],
        zero_extend_source=False,
        require_non_overlap=True,
    )


def _build_vslide1down_vx_lines(context) -> list[str]:
    """翻译无掩码 ``vslide1down.vx``；该 form 允许 ``vd == vs2``。"""
    insn = context.instruction
    state = context.state

    operands = _unmasked_operands(insn, 3)
    if operands is None:
        return _error(insn, "vslide1down.vx 当前只支持无掩码 vd, vs2, rs1 form")
    return _emit_slide(
        insn, state,
        native_opcode="vslide1down.vx",
        offset_operand=operands[2],
        zero_extend_source=False,
        require_non_overlap=False,
    )
