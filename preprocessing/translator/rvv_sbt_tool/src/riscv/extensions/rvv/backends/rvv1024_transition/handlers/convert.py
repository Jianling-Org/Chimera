"""RVV256→RVV1024 过渡路径的宽窄转换与扩展指令。

这类指令不能交给等宽模板：当前 source vtype 所描述的一侧有时是窄输入，
有时是窄输出。例如 ``vzext.vf2`` 的 ``vs2`` 使用 ``LMUL/2``，而
``vnsrl.wi`` 的 ``vs2`` 使用 ``2*LMUL``。本模块把每个 raw state 组的
字节数显式作为 Pack/Unpack 参数，避免 32B 源物理布局被错误解释为目标
RVV1024 的完整寄存器。

当前只接通无掩码 form；``vfncvt.f.f.w`` 额外支持显式 ``v0.t``。其余带掩码
的转换、窄化和饱和路径仍需要单独覆盖 rounding/mask-undisturbed/vxsat 的
目标机差分后才能开放。
"""

from __future__ import annotations

from typing import List, Sequence

from riscv.extensions.rvv.backends.rvv1024_transition import state_view
from riscv.extensions.rvv.analysis.model import LMUL_TOKENS
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
    _data_operands_with_optional_v0_mask,
    _error,
    _parse_uimm5,
    _source_shape,
    _unmasked_operands,
)

from riscv.extensions.rvv.backends.rvv1024_transition.operands import _validate_lmul






def _emit_mixed_width_write(
    insn,
    state: StateTracker,

    *,
    native_opcode: str,
    vd: str,
    result_lmul: float,
    vector_sources: Sequence[tuple[str, float]],
    description: str,
    immediate: int | None = None,
    mask_source: str | None = None,
) -> List[str]:
    """发射一个显式声明目的/源 LMUL 的转换闭环及可选 ``v0.t``。"""
    try:
        sew, _, lmul_token, _ = _source_shape(state)
        _, result_width = _validate_lmul(result_lmul, "目的")
        source_widths = [
            _validate_lmul(source_lmul, f"源 {source_vreg}")[1]
            for source_vreg, source_lmul in vector_sources
        ]
        requested_widths = [result_width, *source_widths]
        if mask_source is not None:
            requested_widths.append(1)
        allocated = _allocate_vector_groups(requested_widths)
        temp_vd = allocated[0]
        temp_sources = allocated[1:1 + len(vector_sources)]
        temp_mask = allocated[-1] if mask_source is not None else None
        temps = TempRegisterAllocator(insn, reserved_gprs=("t6",))
        vl_reg = temps.alloc_gpr()
        address_reg = temps.alloc_gpr()
        transfer_avl_reg = (
            vl_reg if native_opcode == "vzext.vf2" and mask_source is None
            and sew == 16 and state.lmul == 1 else temps.alloc_gpr()
        )
    except (ValueError, TypeError) as exc:
        return _error(insn, str(exc))

    lines: List[str] = [
        f"# {insn.opcode} {insn.op_str} (RVV256 -> RVV1024 宽窄转换)",
        f"# {description}; 每个 source/destination 组按各自 EMUL 精确 Pack。",
        "# 所有向量源先从 raw state 读取，随后以源 VL 执行并立即写回 vd。",
    ]
    _emit_load_source_vl(lines,  vl_reg, address_reg)
    if native_opcode == "vzext.vf2" and mask_source is None and sew == 16 and state.lmul == 1:
        # Commit only active results so raw tail bytes need no old-vd preload.
        target_lmul = state.lmul * state_view.SOURCE_VLENB / state_view.TARGET_VLENB
        _emit_execution_vsetvl(lines, vl_reg, sew, LMUL_TOKENS[target_lmul])
        for (source_vreg, _), temp_source in zip(vector_sources, temp_sources):
            state_view.emit_source_vreg_address(lines, address_reg, source_vreg)
            lines.append(f"    vle8.v {temp_source}, ({address_reg})")
        lines.append(f"    {native_opcode} {temp_vd}, {', '.join(temp_sources)}")
        state_view.emit_source_vreg_address(lines, address_reg, vd)
        lines.append(f"    vse{sew}.v {temp_vd}, ({address_reg})")
        return lines

    _emit_pack_group(
        lines,

        temp_vd,
        address_reg,
        vd,
        result_lmul,
        transfer_avl_reg,
    )
    for (source_vreg, source_lmul), temp_source in zip(vector_sources, temp_sources):
        _emit_pack_group(
            lines,

            temp_source,
            address_reg,
            source_vreg,
            source_lmul,
            transfer_avl_reg,
        )

    if mask_source is not None:
        _emit_pack_group(
            lines,

            temp_mask,
            address_reg,
            mask_source,
            1.0,
            transfer_avl_reg,
        )
        record_vreg_group("v0", 1)
        lines.append(
            f"    vmv1r.v v0, {temp_mask}                 # 载入源 v0.t 执行掩码"
        )

    # 执行 vtype 始终保持 source state 的 SEW/LMUL；转换指令自己的编码
    # 决定宽/窄操作数 EMUL，不能为迁移而篡改客体可见的 VL 解释。
    _emit_execution_vsetvl(lines, vl_reg, sew, lmul_token)
    operands = [temp_vd, *temp_sources]
    if immediate is not None:
        operands.append(str(immediate))
    mask_suffix = ", v0.t" if mask_source is not None else ""
    lines.append(f"    {native_opcode:<14} {', '.join(operands)}{mask_suffix}")
    _emit_unpack_group(
        lines,

        temp_vd,
        address_reg,
        vd,
        result_lmul,
        transfer_avl_reg,
    )
    return lines


def _emit_extend(insn, state, allocator,  opcode: str, factor: int) -> List[str]:
    """翻译零/符号扩展：当前 vtype 是宽目的，vs2 为较窄 EMUL。"""
    operands = _unmasked_operands(insn, 2)
    if operands is None:
        return _error(insn, f"{opcode} 仅支持无掩码 vd, vs2 form")
    vd, vs2 = operands
    try:
        sew, lmul, _, _ = _source_shape(state)
        if sew // factor < 8:
            raise ValueError(f"{opcode} 在 e{sew} 下的源 EEW 小于 e8")
        source_lmul = lmul / factor
        _validate_lmul(source_lmul, "窄源")
    except ValueError as exc:
        return _error(insn, str(exc))
    return _emit_mixed_width_write(
        insn,
        state,

        native_opcode=opcode,
        vd=vd,
        result_lmul=lmul,
        vector_sources=((vs2, source_lmul),),
        description=f"e{sew // factor}->e{sew} 扩展，vs2 EMUL={source_lmul:g}",
    )


def _emit_narrow(insn, state, allocator,  opcode: str, *, immediate: int | None = None) -> List[str]:
    """翻译窄化：当前 vtype 是窄目的，vs2 为两倍 EMUL 的宽源。"""
    expected_operands = 3
    operands = _unmasked_operands(insn, expected_operands)
    if operands is None:
        return _error(insn, f"{opcode} 仅支持无掩码固定操作数 form")
    vd, vs2 = operands[:2]
    try:
        sew, lmul, _, _ = _source_shape(state)
        if sew not in (8, 16, 32):
            raise ValueError(f"{opcode} 只支持目的 SEW=e8/e16/e32，当前 e{sew}")
        source_lmul = lmul * 2.0
        _validate_lmul(source_lmul, "宽源")
    except ValueError as exc:
        return _error(insn, str(exc))
    return _emit_mixed_width_write(
        insn,
        state,

        native_opcode=opcode,
        vd=vd,
        result_lmul=lmul,
        vector_sources=((vs2, source_lmul),),
        description=f"e{sew * 2}->e{sew} 窄化，vs2 EMUL={source_lmul:g}",
        immediate=immediate,
    )


def _emit_narrow_no_immediate(insn, state, allocator,  opcode: str, *, floating: bool = False) -> List[str]:
    """翻译 ``vd, vs2`` 形式的整数/浮点窄化转换。"""
    parsed = _data_operands_with_optional_v0_mask(insn, 2)
    if parsed is None:
        return _error(insn, f"{opcode} 仅支持 vd, vs2 及可选 v0.t form")
    operands, mask_source = parsed
    vd, vs2 = operands
    try:
        sew, lmul, _, _ = _source_shape(state)
        if sew not in (8, 16, 32):
            raise ValueError(f"{opcode} 只支持目的 SEW=e8/e16/e32，当前 e{sew}")
        if floating and sew not in (16, 32):
            raise ValueError(f"{opcode} 浮点目的只支持 e16/e32，当前 e{sew}")
        source_lmul = lmul * 2.0
        _validate_lmul(source_lmul, "宽源")
    except ValueError as exc:
        return _error(insn, str(exc))
    return _emit_mixed_width_write(
        insn,
        state,

        native_opcode=opcode,
        vd=vd,
        result_lmul=lmul,
        vector_sources=((vs2, source_lmul),),
        description=f"e{sew * 2}->e{sew} 窄化，vs2 EMUL={source_lmul:g}",
        mask_source=mask_source,
    )


def _emit_widen_int_convert(insn, state, allocator,  opcode: str) -> List[str]:
    """翻译整数扩宽转换：当前 vtype 是窄输入，vd 为两倍 EMUL。"""
    operands = _unmasked_operands(insn, 2)
    if operands is None:
        return _error(insn, f"{opcode} 仅支持无掩码 vd, vs2 form")
    vd, vs2 = operands
    try:
        sew, lmul, _, _ = _source_shape(state)
        if sew not in (8, 16, 32):
            raise ValueError(f"{opcode} 只支持源 SEW=e8/e16/e32，当前 e{sew}")
        result_lmul = lmul * 2.0
        _validate_lmul(result_lmul, "宽目的")
    except ValueError as exc:
        return _error(insn, str(exc))
    return _emit_mixed_width_write(
        insn,
        state,

        native_opcode=opcode,
        vd=vd,
        result_lmul=result_lmul,
        vector_sources=((vs2, lmul),),
        description=f"e{sew}->e{sew * 2} 整数扩宽转换，vd EMUL={result_lmul:g}",
    )


def _emit_widening_shift_left_vi(
    insn,
    state,
    allocator,

) -> List[str]:
    """翻译 ``vwsll.vi``：窄 source 左移后写入两倍宽目的组。

    ``vwsll.vi`` 不是普通 ``vsll.vi``：当前 source vtype 描述 ``vs2``，
    而 ``vd`` 的 EMUL 是其两倍。指令本身属于 Zvbb 扩展；新路径不能因为
    某个 RVV1024 核心恰好更宽就偷偷要求它具备 Zvbb。因此以基础 RVV 的
    两步 lowering 实现等价语义：

    1. ``vwcvtu.x.x.v`` 将窄 source 零扩展到宽目的；
    2. 在宽元素 vtype 下执行 ``vsll.vi``。

    两步之间不再读取 raw state，且旧 vd 在开始时已完整 Pack，因而 ``tu``
    下的 tail bytes 保持不变。m8→m16 或 e64→e128 仍在生成前 fail-closed；
    立即数是无符号 5-bit shift amount，不能当成 simm5。
    """

    operands = _unmasked_operands(insn, 3)
    if operands is None:
        return _error(insn, "vwsll.vi 仅支持无掩码 vd, vs2, uimm form")
    vd, vs2, raw_imm = operands
    try:
        immediate = _parse_uimm5(raw_imm)
        sew, lmul, source_lmul_token, source_width = _source_shape(state)
        if sew not in (8, 16, 32):
            raise ValueError(f"vwsll.vi 只支持源 SEW=e8/e16/e32，当前 e{sew}")
        result_lmul = lmul * 2.0
        result_lmul_token, result_width = _validate_lmul(result_lmul, "宽目的")
        temp_vd, temp_vs2 = _allocate_vector_groups([result_width, source_width])
        temps = TempRegisterAllocator(insn, reserved_gprs=("t6",))
        vl_reg = temps.alloc_gpr()
        address_reg = temps.alloc_gpr()
        transfer_avl_reg = temps.alloc_gpr()
    except ValueError as exc:
        return _error(insn, str(exc))
    except TypeError as exc:
        return _error(insn, str(exc))

    lines: List[str] = [
        f"# {insn.opcode} {insn.op_str} (RVV256 -> RVV1024 基础 RVV lowering)",
        f"# e{sew}->e{sew * 2} 宽化左移，vd EMUL={result_lmul:g}，uimm={immediate}",
        "# 以 vwcvtu + vsll 替代需要 Zvbb 的原生 vwsll，避免扩大目标 ISA 假设。",
        "# 先 Pack 宽目的旧值与窄 source；两步执行期间不再读取紧凑 state。",
    ]
    _emit_load_source_vl(lines,  vl_reg, address_reg)
    _emit_pack_group(
        lines,  temp_vd, address_reg, vd, result_lmul,
        transfer_avl_reg,
    )
    _emit_pack_group(
        lines,  temp_vs2, address_reg, vs2, lmul,
        transfer_avl_reg,
    )

    # 第一步以窄 source vtype 建立 widening conversion 的输入解释；该指令
    # 的宽目的 EMUL 由自身编码决定。
    _emit_execution_vsetvl(lines, vl_reg, sew, source_lmul_token)
    lines.append(f"    vwcvtu.x.x.v  {temp_vd}, {temp_vs2}       # 零扩展到宽元素")
    # 第二步把同一物理宽目的组解释成 e(2*SEW), 2*LMUL，才可用基础 vsll
    # 对宽元素逐 lane 左移。AVL 仍严格取 source VL，不能扩大至目标 VLMAX。
    _emit_execution_vsetvl(lines, vl_reg, sew * 2, result_lmul_token)
    lines.append(f"    vsll.vi       {temp_vd}, {temp_vd}, {immediate}       # 宽元素逻辑左移")
    _emit_unpack_group(
        lines,  temp_vd, address_reg, vd, result_lmul,
        transfer_avl_reg,
    )
    lines.append("    # 宽化左移结果已按 RVV256 紧凑 raw layout 立即写回")
    return lines


# ---------------------------------------------------------------------------
# 对外 handler
# ---------------------------------------------------------------------------


def _build_vzext_vf2_lines(context) -> list[str]:
    insn = context.instruction
    state = context.state
    allocator = context.layout
    return _emit_extend(insn, state, allocator,  "vzext.vf2", 2)


def _build_vzext_vf4_lines(context) -> list[str]:
    insn = context.instruction
    state = context.state
    allocator = context.layout
    return _emit_extend(insn, state, allocator,  "vzext.vf4", 4)


def _build_vzext_vf8_lines(context) -> list[str]:
    insn = context.instruction
    state = context.state
    allocator = context.layout
    return _emit_extend(insn, state, allocator,  "vzext.vf8", 8)


def _build_vsext_vf2_lines(context) -> list[str]:
    insn = context.instruction
    state = context.state
    allocator = context.layout
    return _emit_extend(insn, state, allocator,  "vsext.vf2", 2)


def _build_vsext_vf4_lines(context) -> list[str]:
    insn = context.instruction
    state = context.state
    allocator = context.layout
    return _emit_extend(insn, state, allocator,  "vsext.vf4", 4)


def _build_vsext_vf8_lines(context) -> list[str]:
    insn = context.instruction
    state = context.state
    allocator = context.layout
    return _emit_extend(insn, state, allocator,  "vsext.vf8", 8)


def _emit_narrow_shift_or_clip(insn, state, allocator,  opcode: str) -> List[str]:
    """解析 narrowing shift/clip 的 5-bit 立即数并发射混合宽度模板。"""
    operands = _unmasked_operands(insn, 3)
    if operands is None:
        return _error(insn, f"{opcode} 仅支持无掩码 vd, vs2, uimm form")
    try:
        immediate = _parse_uimm5(operands[2])
    except ValueError as exc:
        return _error(insn, str(exc))
    # _emit_narrow 需要原始三操作数以保留 `vd,vs2`，显式传入已验证 immediate。
    return _emit_narrow(insn, state, allocator,  opcode, immediate=immediate)


def _build_vnsrl_wi_lines(context) -> list[str]:
    insn = context.instruction
    state = context.state
    allocator = context.layout
    return _emit_narrow_shift_or_clip(insn, state, allocator,  "vnsrl.wi")


def _build_vnsra_wi_lines(context) -> list[str]:
    insn = context.instruction
    state = context.state
    allocator = context.layout
    return _emit_narrow_shift_or_clip(insn, state, allocator,  "vnsra.wi")


def _build_vnclip_wi_lines(context) -> list[str]:
    insn = context.instruction
    state = context.state
    allocator = context.layout
    return _emit_narrow_shift_or_clip(insn, state, allocator,  "vnclip.wi")


def _build_vwcvtu_x_x_v_lines(context) -> list[str]:
    insn = context.instruction
    state = context.state
    allocator = context.layout
    return _emit_widen_int_convert(insn, state, allocator,  "vwcvtu.x.x.v")


def _build_vwcvt_x_x_v_lines(context) -> list[str]:
    insn = context.instruction
    state = context.state
    allocator = context.layout
    return _emit_widen_int_convert(insn, state, allocator,  "vwcvt.x.x.v")


def _build_vwsll_vi_lines(context) -> list[str]:
    """对外 handler：无掩码宽化左移立即数 form。"""
    insn = context.instruction
    state = context.state
    allocator = context.layout
    return _emit_widening_shift_left_vi(insn, state, allocator)


def _build_vncvt_x_x_w_lines(context) -> list[str]:
    insn = context.instruction
    state = context.state
    allocator = context.layout
    return _emit_narrow_no_immediate(insn, state, allocator,  "vncvt.x.x.w")


def _build_vfncvt_f_xu_w_lines(context) -> list[str]:
    insn = context.instruction
    state = context.state
    allocator = context.layout
    return _emit_narrow_no_immediate(
        insn, state, allocator,  "vfncvt.f.xu.w", floating=True
    )


def _build_vfncvt_f_f_w_lines(context) -> list[str]:
    insn = context.instruction
    state = context.state
    allocator = context.layout
    return _emit_narrow_no_immediate(
        insn, state, allocator,  "vfncvt.f.f.w", floating=True
    )


def _build_vfncvt_x_f_w_lines(context) -> list[str]:
    insn = context.instruction
    state = context.state
    allocator = context.layout
    return _emit_narrow_no_immediate(
        insn, state, allocator,  "vfncvt.x.f.w"
    )
