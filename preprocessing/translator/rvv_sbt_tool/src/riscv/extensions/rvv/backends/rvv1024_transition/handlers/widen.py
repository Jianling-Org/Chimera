"""过渡后端的整数及浮点加宽实现。"""

from __future__ import annotations

from typing import List, Sequence
from riscv.extensions.rvv.backends.rvv1024_transition import state_view
from riscv.extensions.rvv.analysis.config import StateTracker
from riscv.extensions.rvv.analysis.model import LMUL_TOKENS
from riscv.extensions.rvv.translation.temps import TempRegisterAllocator, record_vreg_group
from riscv.extensions.rvv.backends.rvv1024_transition.execution import (
    _allocate_vector_groups,
    _emit_execution_vsetvl,
    _emit_load_source_vl,
    _emit_pack_group,
    _emit_unpack_group,
    _emit_packed_vector_write,
)
from riscv.extensions.rvv.backends.rvv1024_transition.operands import (
    _data_operands_with_optional_v0_mask,
    _source_shape,
    _error,
    _unmasked_operands,
    _widened_lmul,
    _wide_result_shape,
)


def _emit_widening_write(
    insn,
    state: StateTracker,

    *,
    native_opcode: str,
    vd: str,
    operand_specs: Sequence[tuple[str, str, float | None]],
    description: str,
    mask_source: str | None = None,
) -> List[str]:
    """发射一个有宽化目的组的 RVV 指令。

``operand_specs`` 保持原生指令的操作数顺序；每一项为
``("vector", 源寄存器, LMUL)`` 或 ``("scalar", 标量寄存器, None)``。
这让 ``vwmacc.vx vd, rs1, vs2`` 这种标量在向量之前的语法无需靠交换操作数
来“凑模板”，避免在未来加入非交换操作时埋下语义错误。
    """
    try:
        sew, source_lmul, lmul_token, _ = _source_shape(state)
        widened_lmul, widened_width = _widened_lmul(source_lmul, sew)
        if mask_source is None and native_opcode == "vwmacc.vv" and sew == 16 and source_lmul == 1:
            lmul_token = LMUL_TOKENS[
                source_lmul * state_view.SOURCE_VLENB / state_view.TARGET_VLENB
            ]

        vector_specs = [spec for spec in operand_specs if spec[0] == "vector"]
        vector_widths = [
            int(float(spec[2])) if float(spec[2]) >= 1 else 1
            for spec in vector_specs
        ]
        requested_widths = [widened_width, *vector_widths]
        if mask_source is not None:
            # source v0 的低 32B 保存 RVV256 全部可能活动 mask bit；它必须
            # 作为普通临时数据先 Pack，不能直接把 state 中的 v0 当作硬件 v0。
            requested_widths.append(1)
        allocated = _allocate_vector_groups(requested_widths)
        temp_vd, *remaining_temps = allocated
        temp_vectors = remaining_temps[:len(vector_specs)]
        temp_mask = remaining_temps[-1] if mask_source is not None else None
        vector_temp_iter = iter(temp_vectors)

        temps = TempRegisterAllocator(insn, reserved_gprs=("t6",))
        vl_reg = temps.alloc_gpr()
        address_reg = temps.alloc_gpr()
        transfer_avl_reg = temps.alloc_gpr()
    except (ValueError, TypeError) as exc:
        return _error(insn, str(exc))

    lines: List[str] = [
        f"# {insn.opcode} {insn.op_str} (RVV256 -> RVV1024 宽化过渡)",
        f"# {description}; 源 LMUL={source_lmul:g}，目的 EMUL={widened_lmul:g}",
        "# 先 Pack 宽目的旧值及全部向量源，随后才允许写回目的组。",
    ]
    _emit_load_source_vl(lines,  vl_reg, address_reg)
    _emit_pack_group(
        lines,

        temp_vd,
        address_reg,
        vd,
        widened_lmul,
        transfer_avl_reg,
    )

    native_operands: list[str] = [temp_vd]
    for kind, operand, group_lmul in operand_specs:
        if kind == "scalar":
            native_operands.append(operand)
            continue
        assert kind == "vector" and group_lmul is not None
        temp_source = next(vector_temp_iter)
        _emit_pack_group(
            lines,

            temp_source,
            address_reg,
            operand,
            group_lmul,
            transfer_avl_reg,
        )
        native_operands.append(temp_source)

    if mask_source is not None:
        assert temp_mask is not None
        _emit_pack_group(
            lines,

            temp_mask,
            address_reg,
            mask_source,
            1.0,
            transfer_avl_reg,
        )
        # 直到所有 source 都从 raw state 读出后，才覆盖目标硬件的 v0。
        # 这也覆盖源 vd/vs 恰好是 v0 的别名情形。
        record_vreg_group("v0", 1)
        lines.append(f"    vmv1r.v v0, {temp_mask}                 # 载入源 v0.t 执行掩码")

    _emit_execution_vsetvl(lines, vl_reg, sew, lmul_token)
    mask_suffix = ", v0.t" if mask_source is not None else ""
    lines.append(f"    {native_opcode:<12} {', '.join(native_operands)}{mask_suffix}")
    _emit_unpack_group(
        lines,

        temp_vd,
        address_reg,
        vd,
        widened_lmul,
        transfer_avl_reg,
    )
    lines.append("    # 宽化目的组已按源 RVV256 紧凑布局立即写回")
    return lines


def _emit_widening_vv(
    insn,
    state,
    allocator,

    opcode: str,
    *,
    description: str,
) -> List[str]:
    """翻译 ``vd, vs2, vs1`` 都为窄元素的宽化二元 form。"""
    parsed = _data_operands_with_optional_v0_mask(insn, 3)
    if parsed is None:
        return _error(insn, "仅支持无掩码或显式 v0.t 的宽化 vv form")
    operands, mask_source = parsed
    vd, vs2, vs1 = operands
    try:
        _, source_lmul, _, _ = _source_shape(state)
    except ValueError as exc:
        return _error(insn, str(exc))
    return _emit_widening_write(
        insn,
        state,

        native_opcode=opcode,
        vd=vd,
        operand_specs=(("vector", vs2, source_lmul), ("vector", vs1, source_lmul)),
        description=description,
        mask_source=mask_source,
    )


def _emit_widening_vx(
    insn,
    state,
    allocator,

    opcode: str,
    *,
    scalar_first: bool = False,
    description: str,
) -> List[str]:
    """翻译 ``vd, vs2, rs1`` 或 ``vd, rs1, vs2`` 的宽化 vx form。"""
    parsed = _data_operands_with_optional_v0_mask(insn, 3)
    if parsed is None:
        return _error(insn, "仅支持无掩码或显式 v0.t 的宽化 vx form")
    operands, mask_source = parsed
    vd, second, third = operands
    try:
        _, source_lmul, _, _ = _source_shape(state)
    except ValueError as exc:
        return _error(insn, str(exc))
    if scalar_first:
        specs = (("scalar", second, None), ("vector", third, source_lmul))
    else:
        specs = (("vector", second, source_lmul), ("scalar", third, None))
    return _emit_widening_write(
        insn,
        state,

        native_opcode=opcode,
        vd=vd,
        operand_specs=specs,
        description=description,
        mask_source=mask_source,
    )


def _emit_wide_narrow_wv(
    insn,
    state,
    allocator,

    opcode: str,
    *,
    description: str,
) -> List[str]:
    """翻译 ``vd, vs2(wide), vs1(narrow)``，目的和 vs2 都是宽组。"""
    parsed = _data_operands_with_optional_v0_mask(insn, 3)
    if parsed is None:
        return _error(insn, "仅支持无掩码或显式 v0.t 的 wide+narrow form")
    operands, mask_source = parsed
    vd, vs2, vs1 = operands
    try:
        sew, source_lmul, _, _ = _source_shape(state)
        widened_lmul, _ = _widened_lmul(source_lmul, sew)
    except ValueError as exc:
        return _error(insn, str(exc))
    return _emit_widening_write(
        insn,
        state,

        native_opcode=opcode,
        vd=vd,
        operand_specs=(
            ("vector", vs2, widened_lmul),
            ("vector", vs1, source_lmul),
        ),
        description=description,
        mask_source=mask_source,
    )


def _emit_widening_reduction(
    insn,
    state,
    allocator,

    opcode: str,
) -> List[str]:
    """翻译 ``vwredsum.vs vd, vs2, vs1`` 的宽化归约布局。

    这里不能复用一般宽化算术的 ``2 * LMUL`` 目的组规则。RVV 的 widening
    reduction 把 ``vd`` 与 ``vs1`` 都解释成 *单寄存器的宽标量*：只观察
    ``vs1[0]``，并只定义 ``vd[0]``。只有待归约的 ``vs2`` 才按当前源
    LMUL 成组。因此，例如 ``e8,m1`` 下合法的
    ``vwredsum.vs v4, v4, v5`` 绝不能要求 ``v5`` 是 m2 起点；那会把实际
    workload 中的合法指令错误挡在预检之外。

    Pack 仍搬运两个完整的 32B 源物理寄存器，而不是只搬 element 0。这样
    ``tu,mu`` 下非结果字节保持原样，随后 Unpack 回紧凑状态时不会破坏
    未定义/未活动 lane 的既有载荷。
    """
    parsed = _data_operands_with_optional_v0_mask(insn, 3)
    if parsed is None:
        return _error(insn, "仅支持无掩码或显式 v0.t 的宽化归约 form")
    operands, mask_source = parsed
    vd, vs2, vs1 = operands
    try:
        sew, source_lmul, lmul_token, source_width = _source_shape(state)
        # e64 的结果会是 e128；一期的目标执行 profile 没有该元素宽度。
        if sew not in (8, 16, 32):
            raise ValueError(f"宽化归约只支持源 SEW=e8/e16/e32，当前 e{sew}")

        requested_widths = [1, source_width, 1]
        if mask_source is not None:
            requested_widths.append(1)
        allocated = _allocate_vector_groups(requested_widths)
        temp_vd, temp_vs2, temp_vs1, *mask_temps = allocated
        temp_mask = mask_temps[0] if mask_temps else None

        temps = TempRegisterAllocator(insn, reserved_gprs=("t6",))
        vl_reg = temps.alloc_gpr()
        address_reg = temps.alloc_gpr()
        transfer_avl_reg = temps.alloc_gpr()
    except (ValueError, TypeError) as exc:
        return _error(insn, str(exc))

    lines: List[str] = [
        f"# {insn.opcode} {insn.op_str} (RVV256 -> RVV1024 宽化归约过渡)",
        f"# vs2 使用源 LMUL={source_lmul:g}；宽 seed/result 均为单物理寄存器",
        "# 先 Pack result、vs2、seed 和可选 v0，最后才在目标临时组执行。",
    ]
    _emit_load_source_vl(lines,  vl_reg, address_reg)
    _emit_pack_group(
        lines,  temp_vd, address_reg, vd, 1.0,
        transfer_avl_reg,
    )
    _emit_pack_group(
        lines,  temp_vs2, address_reg, vs2, source_lmul,
        transfer_avl_reg,
    )
    _emit_pack_group(
        lines,  temp_vs1, address_reg, vs1, 1.0,
        transfer_avl_reg,
    )
    if mask_source is not None:
        assert temp_mask is not None
        _emit_pack_group(
            lines,  temp_mask, address_reg, mask_source, 1.0,
            transfer_avl_reg,
        )
        record_vreg_group("v0", 1)
        lines.append(f"    vmv1r.v v0, {temp_mask}                 # 载入源 v0.t 执行掩码")

    _emit_execution_vsetvl(lines, vl_reg, sew, lmul_token)
    mask_suffix = ", v0.t" if mask_source is not None else ""
    lines.append(
        f"    {opcode:<12} {temp_vd}, {temp_vs2}, {temp_vs1}{mask_suffix}"
    )
    _emit_unpack_group(
        lines,  temp_vd, address_reg, vd, 1.0,
        transfer_avl_reg,
    )
    lines.append("    # 宽化归约单寄存器结果已立即写回紧凑 RVV256 状态")
    return lines


def _build_vwmul_vv_lines(context) -> list[str]:
    insn = context.instruction
    state = context.state
    allocator = context.layout
    return _emit_widening_vv(
        insn, state, allocator,  "vwmul.vv", description="有符号宽化乘法"
    )


def _build_vwmul_vx_lines(context) -> list[str]:
    insn = context.instruction
    state = context.state
    allocator = context.layout
    return _emit_widening_vx(
        insn, state, allocator,  "vwmul.vx", description="有符号向量-标量宽化乘法"
    )


def _build_vwmulu_vv_lines(context) -> list[str]:
    insn = context.instruction
    state = context.state
    allocator = context.layout
    return _emit_widening_vv(
        insn, state, allocator,  "vwmulu.vv", description="无符号宽化乘法"
    )


def _build_vwmulu_vx_lines(context) -> list[str]:
    insn = context.instruction
    state = context.state
    allocator = context.layout
    return _emit_widening_vx(
        insn, state, allocator,  "vwmulu.vx", description="无符号向量-标量宽化乘法"
    )


def _build_vwmulsu_vv_lines(context) -> list[str]:
    insn = context.instruction
    state = context.state
    allocator = context.layout
    return _emit_widening_vv(
        insn, state, allocator,  "vwmulsu.vv", description="有符号×无符号宽化乘法"
    )


def _build_vwmacc_vv_lines(context) -> list[str]:
    insn = context.instruction
    state = context.state
    allocator = context.layout
    return _emit_widening_vv(
        insn, state, allocator,  "vwmacc.vv", description="有符号宽化乘加，vd 是宽累加器"
    )


def _build_vwmacc_vx_lines(context) -> list[str]:
    insn = context.instruction
    state = context.state
    allocator = context.layout
    return _emit_widening_vx(
        insn,
        state,
        allocator,

        "vwmacc.vx",
        scalar_first=True,
        description="有符号标量-向量宽化乘加，vd 是宽累加器",
    )


def _build_vwadd_vv_lines(context) -> list[str]:
    insn = context.instruction
    state = context.state
    allocator = context.layout
    return _emit_widening_vv(
        insn, state, allocator,  "vwadd.vv", description="有符号宽化加法"
    )


def _build_vwadd_wv_lines(context) -> list[str]:
    insn = context.instruction
    state = context.state
    allocator = context.layout
    return _emit_wide_narrow_wv(
        insn, state, allocator,  "vwadd.wv", description="有符号宽元素加窄元素"
    )


def _build_vwaddu_wv_lines(context) -> list[str]:
    insn = context.instruction
    state = context.state
    allocator = context.layout
    return _emit_wide_narrow_wv(
        insn, state, allocator,  "vwaddu.wv", description="无符号宽元素加窄元素"
    )


def _build_vwaddu_vx_lines(context) -> list[str]:
    """翻译无掩码 ``vwaddu.vx vd, vs2, rs1``。

    ``vwaddu.vx`` 的向量输入是窄元素，标量也按窄 SEW 解释，目的组则是
    二倍宽；专用 widening helper 会据此分别计算目的 EMUL 与源 EMUL，不能
    复用等宽 ``.vx`` Pack 布局。当前 new_label 只放开无掩码形态。
    """
    insn = context.instruction
    state = context.state
    allocator = context.layout
    return _emit_widening_vx(
        insn,
        state,
        allocator,

        "vwaddu.vx",
        scalar_first=False,
        description="无符号向量-标量宽化加法",
    )


def _build_vwredsum_vs_lines(context) -> list[str]:
    insn = context.instruction
    state = context.state
    allocator = context.layout
    return _emit_widening_reduction(insn, state, allocator,  "vwredsum.vs")


def _build_vfwmacc_vv_lines(context) -> list[str]:
    """翻译无掩码宽化 FMA ``vfwmacc.vv vd, vs1, vs2``。

汇编 operand 顺序与普通 ``vfmacc.vv`` 相同：第二、第三操作数都是窄浮点
向量，宽 ``vd`` 是隐含累加器。不可将它误写成 ``vd, vs2, vs1``；虽然乘法
数值交换，浮点 NaN/异常行为以及未来非交换 form 的通用模板都不应依赖该巧合。
    """
    insn = context.instruction
    state = context.state

    operands = _unmasked_operands(insn, 3)
    if operands is None:
        return _error(insn, "vfwmacc.vv 仅支持无掩码 vd, vs1, vs2 form")
    vd, vs1, vs2 = operands
    try:
        sew, source_lmul, source_lmul_token, result_lmul = _wide_result_shape(
            state, "vfwmacc.vv"
        )
    except ValueError as exc:
        return _error(insn, str(exc))

    return _emit_packed_vector_write(
        insn,
        state,

        native_opcode="vfwmacc.vv",
        # 宽 vd 是旧累加器，也是结果；先 Pack 它让 tu,mu 的 tail 具有稳定
        # 初值，并在同名/重叠 source 尚未读取前避免提前覆盖 raw state。
        vd=vd,
        result_lmul=result_lmul,
        vector_sources=((vs1, source_lmul), (vs2, source_lmul)),
        execution_sew=sew,
        execution_lmul_token=source_lmul_token,
        operand_order=("vd", "vs0", "vs1"),
    )


def _build_vfwmul_vf_lines(context) -> list[str]:
    """翻译无掩码宽化向量-标量乘法 ``vfwmul.vf vd, vs2, rs1``。"""
    insn = context.instruction
    state = context.state

    operands = _unmasked_operands(insn, 3)
    if operands is None:
        return _error(insn, "vfwmul.vf 仅支持无掩码 vd, vs2, rs1 form")
    vd, vs2, rs1 = operands
    try:
        sew, source_lmul, source_lmul_token, result_lmul = _wide_result_shape(
            state, "vfwmul.vf"
        )
    except ValueError as exc:
        return _error(insn, str(exc))

    return _emit_packed_vector_write(
        insn,
        state,

        native_opcode="vfwmul.vf",
        vd=vd,
        result_lmul=result_lmul,
        vector_sources=((vs2, source_lmul),),
        execution_sew=sew,
        execution_lmul_token=source_lmul_token,
        # 普通 .vf 的编码是 ``vd, vs2, rs1``；与 FMA .vf 的 scalar-first
        # 形式不同，必须显式保留此顺序。
        operand_order=("vd", "vs0", "scalar"),
        scalar_operand=rs1,
    )
