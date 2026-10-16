"""
RVV256 → RVV1024 迁移过渡区的一期算术与移动指令。

这里的 ``v0`` 到 ``v31`` **不是**目标 RVV1024 硬件寄存器的名称。迁移入口
保存的是原生 RVV256 的物理寄存器文件：每个源寄存器连续占 32 字节，``vN`` 的
起点为 ``simulated_cpu_state + N * 32``。本文件中的每条 handler 都遵守同一条
不可变约束：

1. 先从紧凑 RVV256 状态读取本条指令所需的全部向量输入；
2. 以源 ``VL/SEW`` 和适用的目标 LMUL，在固定 ``tu, mu`` 下执行原生指令；
3. 在本条源指令结束前提交结果，保持紧凑 state 的未执行字节。

无掩码源 e32/m2 热点只搬运活动元素，旧目的是否是输入由规格的 ``reads_old_vd``
决定。其他 form 保留旧目的和完整输入组 Pack，以及精确源字节数的 Unpack。

因此，源寄存器别名（例如 ``LMUL=m2`` 后续又以 ``m1`` 读取同一物理寄存器）
始终由 state 中的 RVV256 物理布局决定，而不会被 128B 的目标临时寄存器布局
污染。所有向量输入均在写回前读完；即使 ``vd`` 与 ``vs1/vs2`` 重叠，也不会
因提前写回破坏尚未读取的操作数。

一期的移动指令仍只接受无掩码 form；普通整数二元运算以及已接通的部分浮点、
访存、slide form 可用严格的 ``v0.t`` 复用这里的 Pack/执行/Unpack 框架。其他
掩码寄存器或未知后缀必须由 后端的预检识别；反向 profile 会把该结构化
拒绝转换为带诊断的 ``ebreak``，不能在这里静默忽略。
"""

from __future__ import annotations

from typing import Callable, List, Sequence

from riscv.extensions.rvv.analysis.config import StateTracker
from riscv.frontend.model import RVInstruction

from riscv.extensions.rvv.backends.rvv1024_transition.operands import (
    _error,
    _unmasked_operands,
    _data_operands_with_optional_v0_mask,
    _source_shape,
    _require_float_sew,
    _parse_simm5,
    _parse_uimm5,
    _lmul_token_and_group_width,
    _float_shape,
)

from riscv.extensions.rvv.backends.rvv1024_transition.execution import (
    _ACTIVE_SAME_WIDTH_ARITHMETIC,
    _emit_vector_write,
    _emit_packed_vector_write,
    _emit_scalar_insert,
    _emit_scalar_extract,
)


def _emit_vv(
    insn: RVInstruction,
    state: StateTracker,
    *,
    native_opcode: str,
    reads_old_vd: bool = True,
) -> List[str]:
    """通用 ``vd, vs2, vs1`` 整数二元向量指令。"""
    parsed = _data_operands_with_optional_v0_mask(insn, 3)
    if parsed is None:
        return _error(insn, "只支持无掩码或显式 v0.t 的三操作数 form")
    operands, mask_source = parsed
    vd, vs2, vs1 = operands
    return _emit_vector_write(
        insn, state,  native_opcode=native_opcode, vd=vd,
        reads_old_vd=reads_old_vd,
        vector_sources=(vs2, vs1), mask_source=mask_source,
    )


def _emit_vx(
    insn: RVInstruction,
    state: StateTracker,
    *,
    native_opcode: str,
    reads_old_vd: bool = True,
) -> List[str]:
    """通用 ``vd, vs2, rs1`` 整数向量-标量指令。"""
    parsed = _data_operands_with_optional_v0_mask(insn, 3)
    if parsed is None:
        return _error(insn, "只支持无掩码或显式 v0.t 的三操作数 form")
    operands, mask_source = parsed
    vd, vs2, rs1 = operands
    return _emit_vector_write(
        insn, state,  native_opcode=native_opcode, vd=vd,
        reads_old_vd=reads_old_vd,
        vector_sources=(vs2,), scalar_operand=rs1, mask_source=mask_source,
    )


def _emit_vi(
    insn: RVInstruction,
    state: StateTracker,
    *,
    native_opcode: str,
    reads_old_vd: bool = True,
    shift: bool = False,
) -> List[str]:
    """通用 ``vd, vs2, imm`` 整数向量-立即数指令。"""
    parsed = _data_operands_with_optional_v0_mask(insn, 3)
    if parsed is None:
        return _error(insn, "只支持无掩码或显式 v0.t 的三操作数 form")
    operands, mask_source = parsed
    vd, vs2, raw_imm = operands
    try:
        immediate = _parse_uimm5(raw_imm) if shift else _parse_simm5(raw_imm)
    except ValueError as exc:
        return _error(insn, str(exc))
    return _emit_vector_write(
        insn, state,  native_opcode=native_opcode, vd=vd,
        reads_old_vd=reads_old_vd,
        vector_sources=(vs2,), immediate=immediate, mask_source=mask_source,
    )


def build_with_opcode(
    context,
    *,
    emitter: Callable[..., List[str]],
    **emitter_options,
) -> list[str]:
    """把统一上下文绑定到以 ``native_opcode`` 命名参数接收目标指令的模板。"""

    if (context.spec.target_mnemonic in _ACTIVE_SAME_WIDTH_ARITHMETIC
        or context.spec.target_mnemonic == "vmacc.vx"
        or (context.spec.target_mnemonic == "vsrl.vx"
            and context.state.sew == 8 and context.state.lmul == 0.5)):
        emitter_options["reads_old_vd"] = context.spec.reads_old_vd
    return emitter(
        context.instruction,
        context.state,

        native_opcode=context.spec.target_mnemonic,
        **emitter_options,
    )


# ---------------------------------------------------------------------------
# 一期无掩码移动
# ---------------------------------------------------------------------------

def _build_vmv_v_i_lines(context) -> list[str]:
    """翻译 ``vmv.v.i vd, simm5``。"""
    insn = context.instruction
    state = context.state
    operands = _unmasked_operands(insn, 2)
    if operands is None:
        return _error(insn, "一期仅支持无掩码 vmv.v.i")
    vd, raw_imm = operands
    try:
        immediate = _parse_simm5(raw_imm)
    except ValueError as exc:
        return _error(insn, str(exc))
    return _emit_vector_write(
        insn, state,  native_opcode="vmv.v.i", vd=vd,
        vector_sources=(), immediate=immediate,
    )


def _build_vmv_v_x_lines(context) -> list[str]:
    """翻译 ``vmv.v.x vd, rs1``，保留 vd 的 tail 字节。"""
    insn = context.instruction
    state = context.state
    operands = _unmasked_operands(insn, 2)
    if operands is None:
        return _error(insn, "一期仅支持无掩码 vmv.v.x")
    vd, rs1 = operands
    return _emit_vector_write(
        insn, state,  native_opcode="vmv.v.x", vd=vd,
        vector_sources=(), scalar_operand=rs1,
    )


def _build_vmv_v_v_lines(context) -> list[str]:
    """翻译 ``vmv.v.v vd, vs1``；vd 与 vs1 可相同或位于重叠组中。"""
    insn = context.instruction
    state = context.state
    operands = _unmasked_operands(insn, 2)
    if operands is None:
        return _error(insn, "一期仅支持无掩码 vmv.v.v")
    vd, vs1 = operands
    return _emit_vector_write(
        insn, state,  native_opcode="vmv.v.v", vd=vd,
        vector_sources=(vs1,),
    )


def _build_vmv_s_x_lines(context) -> list[str]:
    """翻译 VL 非零时写元素 0 的 ``vmv.s.x vd, rs1``。"""
    insn = context.instruction
    state = context.state
    operands = _unmasked_operands(insn, 2)
    if operands is None:
        return _error(insn, "一期仅支持无掩码 vmv.s.x")
    vd, rs1 = operands
    return _emit_scalar_insert(
        insn, state,  native_opcode="vmv.s.x", vd=vd, scalar=rs1,
        new_label=context.new_label,
    )


def _build_vmv_x_s_lines(context) -> list[str]:
    """翻译不依赖 VL 的 ``vmv.x.s rd, vs2``。"""
    insn = context.instruction
    state = context.state
    operands = _unmasked_operands(insn, 2)
    if operands is None:
        return _error(insn, "一期仅支持无掩码 vmv.x.s")
    rd, vs2 = operands
    return _emit_scalar_extract(
        insn, state,  native_opcode="vmv.x.s", rd=rd, vs2=vs2,
    )


def _build_vfmv_v_f_lines(context) -> list[str]:
    """翻译 ``vfmv.v.f vd, fs1``。"""
    insn = context.instruction
    state = context.state
    operands = _unmasked_operands(insn, 2)
    if operands is None:
        return _error(insn, "一期仅支持无掩码 vfmv.v.f")
    try:
        _require_float_sew(state)
    except ValueError as exc:
        return _error(insn, str(exc))
    vd, fs1 = operands
    return _emit_vector_write(
        insn, state,  native_opcode="vfmv.v.f", vd=vd,
        vector_sources=(), scalar_operand=fs1,
    )


def _build_vfmv_s_f_lines(context) -> list[str]:
    """翻译 VL 非零时写元素 0 的 ``vfmv.s.f vd, fs1``。"""
    insn = context.instruction
    state = context.state
    operands = _unmasked_operands(insn, 2)
    if operands is None:
        return _error(insn, "一期仅支持无掩码 vfmv.s.f")
    try:
        _require_float_sew(state)
    except ValueError as exc:
        return _error(insn, str(exc))
    vd, fs1 = operands
    return _emit_scalar_insert(
        insn, state,  native_opcode="vfmv.s.f", vd=vd, scalar=fs1,
        new_label=context.new_label,
    )


def _build_vfmv_f_s_lines(context) -> list[str]:
    """翻译不依赖 VL 的 ``vfmv.f.s fd, vs2``。"""
    insn = context.instruction
    state = context.state
    operands = _unmasked_operands(insn, 2)
    if operands is None:
        return _error(insn, "一期仅支持无掩码 vfmv.f.s")
    try:
        _require_float_sew(state)
    except ValueError as exc:
        return _error(insn, str(exc))
    fd, vs2 = operands
    return _emit_scalar_extract(
        insn, state,  native_opcode="vfmv.f.s", rd=fd, vs2=vs2,
    )


# ---------------------------------------------------------------------------
# 一期无掩码整数基础运算
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# 批次 3：无掩码浮点热点
# ---------------------------------------------------------------------------


def _emit_float_binary_vv(
    insn: RVInstruction,
    state: StateTracker,

    *,
    native_opcode: str,
    reads_old_vd: bool = True,
) -> List[str]:
    """发射 ``vd, vs2, vs1`` 格式的等宽浮点二元向量运算。"""
    parsed = _data_operands_with_optional_v0_mask(insn, 3)
    if parsed is None:
        return _error(insn, "仅支持三个数据操作数及可选 v0.t 的浮点 .vv form")
    operands, mask_source = parsed
    vd, vs2, vs1 = operands
    try:
        sew, lmul, lmul_token = _float_shape(state)
    except ValueError as exc:
        return _error(insn, str(exc))
    return _emit_packed_vector_write(
        insn,
        state,

        native_opcode=native_opcode,
        reads_old_vd=reads_old_vd,
        vd=vd,
        result_lmul=lmul,
        vector_sources=((vs2, lmul), (vs1, lmul)),
        execution_sew=sew,
        execution_lmul_token=lmul_token,
        operand_order=("vd", "vs0", "vs1"),
        mask_source=mask_source,
    )

def _emit_float_binary_vf(
    insn: RVInstruction,
    state: StateTracker,

    *,
    native_opcode: str,
) -> List[str]:
    """发射 ``vd, vs2, rs1`` 格式的等宽浮点向量-标量运算。"""
    parsed = _data_operands_with_optional_v0_mask(insn, 3)
    if parsed is None:
        return _error(insn, "仅支持三个数据操作数及可选 v0.t 的浮点 .vf form")
    operands, mask_source = parsed
    vd, vs2, rs1 = operands
    try:
        sew, lmul, lmul_token = _float_shape(state)
    except ValueError as exc:
        return _error(insn, str(exc))
    return _emit_packed_vector_write(
        insn,
        state,

        native_opcode=native_opcode,
        vd=vd,
        result_lmul=lmul,
        vector_sources=((vs2, lmul),),
        execution_sew=sew,
        execution_lmul_token=lmul_token,
        operand_order=("vd", "vs0", "scalar"),
        scalar_operand=rs1,
        mask_source=mask_source,
    )


def _emit_float_accumulate_vv(
    insn: RVInstruction,
    state: StateTracker,

    *,
    native_opcode: str,
    reads_old_vd: bool = True,
) -> List[str]:
    """发射 FMA ``vd, vs1, vs2``，并把旧 vd 作为真正的累加器 Pack。

    FMA 与普通二元写指令的本质差别是 ``vd`` 既是输出又是输入。通用闭环
    helper 总是先 Pack 旧 vd，因此同名或重叠源组不会在 Unpack 前丢失。
    """
    operands = _unmasked_operands(insn, 3)
    if operands is None:
        return _error(insn, "仅支持恰好三个操作数的无掩码 FMA .vv form")
    vd, vs1, vs2 = operands
    try:
        sew, lmul, lmul_token = _float_shape(state)
    except ValueError as exc:
        return _error(insn, str(exc))
    return _emit_packed_vector_write(
        insn,
        state,

        native_opcode=native_opcode,
        reads_old_vd=reads_old_vd,
        vd=vd,
        result_lmul=lmul,
        vector_sources=((vs1, lmul), (vs2, lmul)),
        execution_sew=sew,
        execution_lmul_token=lmul_token,
        operand_order=("vd", "vs0", "vs1"),
    )


def _emit_float_accumulate_vf(
    insn: RVInstruction,
    state: StateTracker,

    *,
    native_opcode: str,
) -> List[str]:
    """发射 FMA ``vd, rs1, vs2``，保留其与普通 ``.vf`` 不同的操作数顺序。"""
    operands = _unmasked_operands(insn, 3)
    if operands is None:
        return _error(insn, "仅支持恰好三个操作数的无掩码 FMA .vf form")
    vd, rs1, vs2 = operands
    try:
        sew, lmul, lmul_token = _float_shape(state)
    except ValueError as exc:
        return _error(insn, str(exc))
    return _emit_packed_vector_write(
        insn,
        state,

        native_opcode=native_opcode,
        vd=vd,
        result_lmul=lmul,
        vector_sources=((vs2, lmul),),
        execution_sew=sew,
        execution_lmul_token=lmul_token,
        # RVV FMA .vf 的汇编格式为 ``vd, rs1, vs2``，不能误用普通 .vf
        # 的 ``vd, vs2, rs1`` 顺序。
        operand_order=("vd", "scalar", "vs0"),
        scalar_operand=rs1,
    )


# ---------------------------------------------------------------------------
# 批次 3：等宽与扩宽浮点转换
# ---------------------------------------------------------------------------

def _emit_equal_width_vfcvt(
    insn: RVInstruction,
    state: StateTracker,

    *,
    native_opcode: str,
) -> List[str]:
    """发射等宽 ``vfcvt``：源/目的组均按当前 SEW、LMUL 解释。

    整数/浮点之间的位解释虽然不同，但它们的 EEW 相同，因而 raw state 中
    ``vd`` 与 ``vs2`` 的物理字节数同为 ``32 * LMUL``。目标硬件使用同一
    源 vtype 执行，旧 vd 先被 Pack 以满足固定 ``tu,mu`` 策略。
    """
    parsed = _data_operands_with_optional_v0_mask(insn, 2)
    if parsed is None:
        return _error(insn, "等宽 vfcvt 仅支持 vd, vs2 及可选 v0.t form")
    operands, mask_source = parsed
    vd, vs2 = operands
    try:
        sew, lmul, lmul_token = _float_shape(state)
    except ValueError as exc:
        return _error(insn, str(exc))
    return _emit_packed_vector_write(
        insn,
        state,

        native_opcode=native_opcode,
        vd=vd,
        result_lmul=lmul,
        vector_sources=((vs2, lmul),),
        execution_sew=sew,
        execution_lmul_token=lmul_token,
        operand_order=("vd", "vs0"),
        mask_source=mask_source,
    )


def _emit_widening_vfwcvt(
    insn: RVInstruction,
    state: StateTracker,

    *,
    native_opcode: str,
) -> List[str]:
    """发射一个可验证组宽的 ``vfwcvt`` widening conversion。

    RVV 把当前 vtype 解释为窄输入的 ``SEW/LMUL``；目的向量的 EMUL 是
    ``2 * LMUL``。因此同一个源物理状态里，目的组的 raw 字节数是输入组
    的两倍。这里显式按两种 LMUL Pack/Unpack，禁止把目的组错误地按输入
    LMUL 回写。

    本阶段只选择 e16→e32 和 e32→e64：它们不引入 e8/e16 浮点扩展依赖，
    也不要求尚未定义的 e128 浮点格式。输入 m8 会导致目的 EMUL=m16，
    不属于 RVV 合法编码，必须在预检阶段拒绝。
    """
    operands = _unmasked_operands(insn, 2)
    if operands is None:
        return _error(insn, "vfwcvt 仅支持无掩码 vd, vs2 form")
    vd, vs2 = operands
    try:
        input_sew, input_lmul, input_lmul_token, _ = _source_shape(state)
        if input_sew not in (16, 32):
            raise ValueError(
                f"{native_opcode} 仅支持 e16->e32 或 e32->e64，当前为 e{input_sew}"
            )
        output_lmul = input_lmul * 2.0
        _lmul_token_and_group_width(output_lmul)
    except ValueError as exc:
        return _error(insn, str(exc))
    return _emit_packed_vector_write(
        insn,
        state,

        native_opcode=native_opcode,
        vd=vd,
        result_lmul=output_lmul,
        vector_sources=((vs2, input_lmul),),
        execution_sew=input_sew,
        execution_lmul_token=input_lmul_token,
        operand_order=("vd", "vs0"),
    )


def _build_vfwcvt_f_f_v_lines(context) -> list[str]:
    """翻译 e16/e32 浮点扩宽 ``vfwcvt.f.f.v``。"""
    insn = context.instruction
    state = context.state

    return _emit_widening_vfwcvt(insn, state,  native_opcode="vfwcvt.f.f.v")


def _build_vfwcvt_f_x_v_lines(context) -> list[str]:
    """翻译 e16/e32 有符号整数到扩宽浮点 ``vfwcvt.f.x.v``。"""
    insn = context.instruction
    state = context.state

    return _emit_widening_vfwcvt(insn, state,  native_opcode="vfwcvt.f.x.v")


def _build_vfwcvt_f_xu_v_lines(context) -> list[str]:
    """翻译 e16/e32 无符号整数到扩宽浮点 ``vfwcvt.f.xu.v``。"""
    insn = context.instruction
    state = context.state

    return _emit_widening_vfwcvt(insn, state,  native_opcode="vfwcvt.f.xu.v")


def _build_vfwcvt_x_f_v_lines(context) -> list[str]:
    """翻译 e16/e32 浮点到扩宽有符号整数 ``vfwcvt.x.f.v``。"""
    insn = context.instruction
    state = context.state

    return _emit_widening_vfwcvt(insn, state,  native_opcode="vfwcvt.x.f.v")


def _build_vfwcvt_xu_f_v_lines(context) -> list[str]:
    """翻译 e16/e32 浮点到扩宽无符号整数 ``vfwcvt.xu.f.v``。"""
    insn = context.instruction
    state = context.state

    return _emit_widening_vfwcvt(insn, state,  native_opcode="vfwcvt.xu.f.v")


# ---------------------------------------------------------------------------
# 批次 4：逐元素整数/浮点补齐与整数归约
# ---------------------------------------------------------------------------

def _emit_plain_integer_vv(
    insn: RVInstruction,
    state: StateTracker,

    *,
    native_opcode: str,
) -> List[str]:
    """发射无掩码 ``vd, vs2, vs1`` 的等宽整数二元指令。"""
    operands = _unmasked_operands(insn, 3)
    if operands is None:
        return _error(insn, "仅支持恰好三个操作数的无掩码整数 .vv form")
    vd, vs2, vs1 = operands
    try:
        sew, lmul, lmul_token, _ = _source_shape(state)
    except ValueError as exc:
        return _error(insn, str(exc))
    return _emit_packed_vector_write(
        insn,
        state,

        native_opcode=native_opcode,
        vd=vd,
        result_lmul=lmul,
        vector_sources=((vs2, lmul), (vs1, lmul)),
        execution_sew=sew,
        execution_lmul_token=lmul_token,
        operand_order=("vd", "vs0", "vs1"),
    )


def _emit_plain_integer_vx(
    insn: RVInstruction,
    state: StateTracker,

    *,
    native_opcode: str,
) -> List[str]:
    """发射无掩码 ``vd, vs2, rs1`` 的等宽整数向量-标量指令。"""
    operands = _unmasked_operands(insn, 3)
    if operands is None:
        return _error(insn, "仅支持恰好三个操作数的无掩码整数 .vx form")
    vd, vs2, rs1 = operands
    try:
        sew, lmul, lmul_token, _ = _source_shape(state)
    except ValueError as exc:
        return _error(insn, str(exc))
    return _emit_packed_vector_write(
        insn,
        state,

        native_opcode=native_opcode,
        vd=vd,
        result_lmul=lmul,
        vector_sources=((vs2, lmul),),
        execution_sew=sew,
        execution_lmul_token=lmul_token,
        operand_order=("vd", "vs0", "scalar"),
        scalar_operand=rs1,
    )


def _emit_integer_accumulate_vv(
    insn: RVInstruction,
    state: StateTracker,

    *,
    native_opcode: str,
    reads_old_vd: bool = True,
) -> List[str]:
    """发射 ``vd, vs1, vs2`` 形式的整数乘累加/乘加。

    ``vmacc`` 和 ``vmadd`` 都将旧 ``vd`` 读作运算输入；闭环 helper 已经先
    Pack 旧值和两个向量源，故 ``vd == vs1/vs2`` 时也不会出现提前 Unpack
    覆盖尚未读取 source 的问题。
    """
    operands = _unmasked_operands(insn, 3)
    if operands is None:
        return _error(insn, "仅支持恰好三个操作数的无掩码整数乘累加 .vv form")
    vd, vs1, vs2 = operands
    try:
        sew, lmul, lmul_token, _ = _source_shape(state)
    except ValueError as exc:
        return _error(insn, str(exc))
    return _emit_packed_vector_write(
        insn,
        state,

        native_opcode=native_opcode,
        reads_old_vd=reads_old_vd,
        vd=vd,
        result_lmul=lmul,
        vector_sources=((vs1, lmul), (vs2, lmul)),
        execution_sew=sew,
        execution_lmul_token=lmul_token,
        operand_order=("vd", "vs0", "vs1"),
    )


def _emit_integer_accumulate_vx(
    insn: RVInstruction,
    state: StateTracker,

    *,
    native_opcode: str,
    reads_old_vd: bool = True,
) -> List[str]:
    """发射 ``vd, rs1, vs2`` 形式的整数向量-标量乘累加。"""
    operands = _unmasked_operands(insn, 3)
    if operands is None:
        return _error(insn, "仅支持恰好三个操作数的无掩码整数乘累加 .vx form")
    vd, rs1, vs2 = operands
    try:
        sew, lmul, lmul_token, _ = _source_shape(state)
    except ValueError as exc:
        return _error(insn, str(exc))
    return _emit_packed_vector_write(
        insn,
        state,

        native_opcode=native_opcode,
        reads_old_vd=reads_old_vd,
        vd=vd,
        result_lmul=lmul,
        vector_sources=((vs2, lmul),),
        execution_sew=sew,
        execution_lmul_token=lmul_token,
        # ``vmacc.vx`` 的汇编顺序为 vd, rs1, vs2，和常规 .vx 相反。
        operand_order=("vd", "scalar", "vs0"),
        scalar_operand=rs1,
    )


def _build_vandn_vv_lines(context) -> list[str]:
    """翻译 ``vandn.vv vd, vs2, vs1``，但不假定目标核心支持 Zvkb。

    ``vandn.vv`` 在 LLVM 中属于可选 Zvkb（向量密码位操作）扩展；本迁移
    后端的基础目标合同只有 RV64GCV。所有输入已经 Pack 后，把 ``vs1`` 的
    临时组原地按位取反，再用基础 ``vand.vv`` 计算 ``vs2 & ~vs1``，无需
    额外临时组，也能覆盖 m8 的三组空间上限。
    """
    insn = context.instruction
    state = context.state

    operands = _unmasked_operands(insn, 3)
    if operands is None:
        return _error(insn, "vandn.vv 仅支持无掩码 vd, vs2, vs1 form")
    vd, vs2, vs1 = operands
    try:
        sew, lmul, lmul_token, _ = _source_shape(state)
    except ValueError as exc:
        return _error(insn, str(exc))

    def _lower(values: dict[str, str]) -> Sequence[str]:
        return (
            f"    vxor.vi       {values['vs1']}, {values['vs1']}, -1  # ~vs1，基础 V lowering",
            f"    vand.vv       {values['vd']}, {values['vs0']}, {values['vs1']}  # vs2 & ~vs1",
        )

    return _emit_packed_vector_write(
        insn,
        state,

        native_opcode="vandn.vv",
        vd=vd,
        result_lmul=lmul,
        vector_sources=((vs2, lmul), (vs1, lmul)),
        execution_sew=sew,
        execution_lmul_token=lmul_token,
        operand_order=("vd", "vs0", "vs1"),
        native_lines_builder=_lower,
    )


def _build_vnot_v_lines(context) -> list[str]:
    """翻译 ``vnot.v vd, vs2`` 为基础 ``vxor.vi vd, vs2, -1``。"""
    insn = context.instruction
    state = context.state

    operands = _unmasked_operands(insn, 2)
    if operands is None:
        return _error(insn, "vnot.v 仅支持无掩码 vd, vs2 form")
    vd, vs2 = operands
    try:
        sew, lmul, lmul_token, _ = _source_shape(state)
    except ValueError as exc:
        return _error(insn, str(exc))

    def _lower(values: dict[str, str]) -> Sequence[str]:
        return (
            f"    vxor.vi       {values['vd']}, {values['vs0']}, -1  # vnot.v 的基础 V lowering",
        )

    return _emit_packed_vector_write(
        insn,
        state,

        native_opcode="vnot.v",
        vd=vd,
        result_lmul=lmul,
        vector_sources=((vs2, lmul),),
        execution_sew=sew,
        execution_lmul_token=lmul_token,
        operand_order=("vd", "vs0"),
        native_lines_builder=_lower,
    )


def _build_vid_v_lines(context) -> list[str]:
    """翻译 ``vid.v vd``；目标和源都以相同 lane index 与源 VL 执行。"""
    insn = context.instruction
    state = context.state

    operands = _unmasked_operands(insn, 1)
    if operands is None:
        return _error(insn, "vid.v 仅支持无掩码单目的操作数 form")
    (vd,) = operands
    try:
        sew, lmul, lmul_token, _ = _source_shape(state)
    except ValueError as exc:
        return _error(insn, str(exc))
    return _emit_packed_vector_write(
        insn,
        state,

        native_opcode="vid.v",
        vd=vd,
        result_lmul=lmul,
        vector_sources=(),
        execution_sew=sew,
        execution_lmul_token=lmul_token,
        operand_order=("vd",),
    )


def _emit_float_unary(
    insn: RVInstruction,
    state: StateTracker,

    *,
    native_opcode: str,
) -> List[str]:
    """发射 ``vd, vs2`` 及可选 ``v0.t`` 的浮点一元指令。"""
    parsed = _data_operands_with_optional_v0_mask(insn, 2)
    if parsed is None:
        return _error(insn, "仅支持 vd, vs2 及可选 v0.t 的浮点一元 form")
    operands, mask_source = parsed
    vd, vs2 = operands
    try:
        sew, lmul, lmul_token = _float_shape(state)
    except ValueError as exc:
        return _error(insn, str(exc))
    return _emit_packed_vector_write(
        insn,
        state,

        native_opcode=native_opcode,
        vd=vd,
        result_lmul=lmul,
        vector_sources=((vs2, lmul),),
        execution_sew=sew,
        execution_lmul_token=lmul_token,
        operand_order=("vd", "vs0"),
        mask_source=mask_source,
    )


def _emit_integer_reduction_vs(
    insn: RVInstruction,
    state: StateTracker,

    *,
    native_opcode: str,
) -> List[str]:
    """发射 ``vred*.vs vd, vs2, vs1`` 的单条目标归约闭环。

    reduction 的 ``vs2`` 是当前 LMUL 的向量源；但初始标量 ``vs1`` 与
    结果 ``vd`` 按 RVV 规范始终是 EMUL=m1 的单寄存器组。不能把它们按
    当前 LMUL Pack，否则在 m2/m4/m8 下会错读额外 raw 物理寄存器，并拒绝
    合法的非组对齐 ``vd``/``vs1``。目标仍使用源 VL，因此不会因为 VLEN
    从 256 扩到 1024 而额外归约 source VLMAX 之外的 lane。
    """
    operands = _unmasked_operands(insn, 3)
    if operands is None:
        return _error(insn, "整数归约仅支持无掩码 vd, vs2, vs1 form")
    vd, vs2, vs1 = operands
    try:
        sew, lmul, lmul_token, _ = _source_shape(state)
    except ValueError as exc:
        return _error(insn, str(exc))
    return _emit_packed_vector_write(
        insn,
        state,

        native_opcode=native_opcode,
        vd=vd,
        result_lmul=1.0,
        vector_sources=((vs2, lmul), (vs1, 1.0)),
        execution_sew=sew,
        execution_lmul_token=lmul_token,
        operand_order=("vd", "vs0", "vs1"),
    )
