"""RVV256→RVV1024 过渡路径的一期访存和整寄存器 move。

unit-stride 指令的 EEW 可以和当前 SEW 不同；因此目的/源操作数的物理
寄存器组宽度必须按 EMUL = LMUL * EEW / SEW 计算，而不能偷用普通算术的
LMUL。这是从紧凑 RVV256 state Pack 到 RVV1024 临时组时最容易出错的边界。
"""

from __future__ import annotations

from typing import List

from riscv.extensions.rvv.backends.rvv1024_transition import state_view
from riscv.extensions.rvv.analysis.model import LEGAL_LMULS
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
    _source_shape,
    _unmasked_operands,
)

from riscv.extensions.rvv.backends.rvv1024_transition.operands import (
    _effective_lmul,
    _segment_field_registers,
)


_LEGAL_LMULS = LEGAL_LMULS




def _emit_unit_load(
    insn,
    state: StateTracker,

    *,
    eew: int,
) -> List[str]:
    """发射 unit-stride load，无掩码形式只写回活动元素。

    masked load 仍先 Pack 旧目的和源 mask，以固定 ``tu,mu`` 保留关闭 lane。
    无掩码 load 不读取旧目的；活动元素直接写回后，state 中的 tail 保持原值。
    """
    parsed = _data_operands_with_optional_v0_mask(insn, 2)
    if parsed is None:
        return _error(insn, "unit-stride load 只支持无掩码或显式 v0.t form")
    operands, mask_source = parsed
    vd, address = operands
    try:
        sew, lmul, lmul_token, _ = _source_shape(state)
        emul, group_width = _effective_lmul(lmul, sew, eew)
        execution_lmul_token = lmul_token
        if mask_source is None and sew == 32 and lmul == 8:
            # Source e32/m8 has 64 lanes, which fit target e32/m2.
            execution_lmul_token = "m2"
            _, group_width = _effective_lmul(2, sew, eew)
        state_view
        requested_widths = [group_width]
        if mask_source is not None:
            requested_widths.append(1)
        temp_vd, *mask_temps = _allocate_vector_groups(requested_widths)
        temp_mask = mask_temps[0] if mask_temps else None
        temps = TempRegisterAllocator(insn, reserved_gprs=("t6",))
        vl_reg = temps.alloc_gpr()
        address_reg = temps.alloc_gpr()
        transfer_avl_reg = temps.alloc_gpr() if mask_source is not None else None
    except (ValueError, TypeError) as exc:
        return _error(insn, str(exc))

    lines: List[str] = [
        f"# {insn.opcode} {insn.op_str} (RVV256 raw state -> RVV1024 load)",
        f"# EEW=e{eew}, 源 SEW=e{sew}, 源 LMUL={lmul_token}, EMUL={emul:g}",
    ]
    # 运行时 VL 属于源 RVV256 状态；helper 通过 new_label 的 state_view
    # 读取固定 CSR 槽位，不能误从当前目标硬件 CSR 读取。
    _emit_load_source_vl(lines,  vl_reg, address_reg)
    if mask_source is not None:
        _emit_pack_group(
            lines, temp_vd, address_reg, vd, emul,
            transfer_avl_reg,
        )
        _emit_pack_group(
            lines,  temp_mask, address_reg, mask_source, 1.0,
            transfer_avl_reg,
        )
        record_vreg_group("v0", 1)
        lines.append(f"    vmv1r.v v0, {temp_mask}                 # 载入源 v0.t 执行掩码")
    _emit_execution_vsetvl(lines, vl_reg, sew, execution_lmul_token)
    mask_suffix = ", v0.t" if mask_source is not None else ""
    lines.append(f"    vle{eew}.v   {temp_vd}, {address}{mask_suffix}")
    if mask_source is None:
        # Same VL/vtype makes the store cover only the load's active elements.
        state_view.emit_source_vreg_address(lines, address_reg, vd)
        lines.append(f"    vse{eew}.v   {temp_vd}, ({address_reg})")
    else:
        _emit_unpack_group(
            lines, temp_vd, address_reg, vd, emul,
            transfer_avl_reg,
        )
    return lines


def _emit_unit_store(
    insn,
    state: StateTracker,

    *,
    eew: int,
) -> List[str]:
    """发射 unit-stride store：只 Pack 源组，绝不向 state 回写伪结果。

    masked store 同样只接受 ``v0.t``；目标硬件 v0 在真正的 store 前才写入，
    保证所有读取的源 state 都已经 Pack 完成。
    """
    parsed = _data_operands_with_optional_v0_mask(insn, 2)
    if parsed is None:
        return _error(insn, "unit-stride store 只支持无掩码或显式 v0.t form")
    operands, mask_source = parsed
    vs3, address = operands
    try:
        sew, lmul, lmul_token, _ = _source_shape(state)
        emul, group_width = _effective_lmul(lmul, sew, eew)
        state_view
        requested_widths = [group_width]
        if mask_source is not None:
            requested_widths.append(1)
        temp_vs3, *mask_temps = _allocate_vector_groups(requested_widths)
        temp_mask = mask_temps[0] if mask_temps else None
        temps = TempRegisterAllocator(insn, reserved_gprs=("t6",))
        vl_reg = temps.alloc_gpr()
        address_reg = temps.alloc_gpr()
        transfer_avl_reg = temps.alloc_gpr()
    except (ValueError, TypeError) as exc:
        return _error(insn, str(exc))

    lines: List[str] = [
        f"# {insn.opcode} {insn.op_str} (RVV256 raw state -> RVV1024 store)",
        f"# EEW=e{eew}, 源 SEW=e{sew}, 源 LMUL={lmul_token}, EMUL={emul:g}",
    ]
    # store 同样必须以迁移入口保存的源 VL 为准。
    _emit_load_source_vl(lines,  vl_reg, address_reg)
    _emit_pack_group(
        lines,  temp_vs3, address_reg, vs3, emul,
        transfer_avl_reg,
    )
    if mask_source is not None:
        _emit_pack_group(
            lines,  temp_mask, address_reg, mask_source, 1.0,
            transfer_avl_reg,
        )
        record_vreg_group("v0", 1)
        lines.append(f"    vmv1r.v v0, {temp_mask}                 # 载入源 v0.t 执行掩码")
    _emit_execution_vsetvl(lines, vl_reg, sew, lmul_token)
    mask_suffix = ", v0.t" if mask_source is not None else ""
    lines.append(f"    vse{eew}.v   {temp_vs3}, {address}{mask_suffix}")
    return lines


def _emit_strided_load(
    insn,
    state: StateTracker,

    *,
    eew: int,
) -> List[str]:
    """发射无掩码 ``vlse*.v``，保持源 RVV256 的 byte-stride 语义。

    RVV1024 的 VLMAX 大于源 RVV256；只要把源 ``vl`` 作为 AVL 重新建立，
    单条原生 ``vlse`` 就会访问与源机相同的元素集合和相同的地址序列。目的
    组仍按 ``EMUL = LMUL * EEW / SEW`` Pack/Unpack，不能因为这是 strided
    form 就退回普通 LMUL：例如 source e32,m1 的 ``vlse64.v`` 实际写 m2。

    这里的已接通 form 也可带显式 ``v0.t``：先 Pack 旧 vd 和源 v0，再以
    ``tu,mu`` 发射 masked load，关闭 lane 不访存且保留旧值。其他掩码形式仍由
    new_label 预检拒绝，不能静默降级为无掩码语义。
    """
    parsed = _data_operands_with_optional_v0_mask(insn, 3)
    if parsed is None:
        return _error(insn, "vlse 只支持 vd, (rs1), rs2 及可选 v0.t form")
    operands, mask_source = parsed
    vd, address, stride = operands
    try:
        sew, lmul, lmul_token, _ = _source_shape(state)
        emul, group_width = _effective_lmul(lmul, sew, eew)
        state_view
        requested_widths = [group_width]
        if mask_source is not None:
            requested_widths.append(1)
        allocated = _allocate_vector_groups(requested_widths)
        temp_vd = allocated[0]
        temp_mask = allocated[1] if mask_source is not None else None
        temps = TempRegisterAllocator(insn, reserved_gprs=("t6",))
        vl_reg = temps.alloc_gpr()
        address_reg = temps.alloc_gpr()
        transfer_avl_reg = temps.alloc_gpr()
    except (ValueError, TypeError) as exc:
        return _error(insn, str(exc))

    lines: List[str] = [
        f"# {insn.opcode} {insn.op_str} (RVV256 raw state -> RVV1024 strided load)",
        f"# EEW=e{eew}, 源 SEW=e{sew}, 源 LMUL={lmul_token}, EMUL={emul:g}",
    ]
    _emit_load_source_vl(lines,  vl_reg, address_reg)
    # ``tu`` 需要旧 vd 作为 tail 的具体结果；先读完整源组后才允许写回。
    _emit_pack_group(
        lines,  temp_vd, address_reg, vd, emul,
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
    _emit_execution_vsetvl(lines, vl_reg, sew, lmul_token)
    mask_suffix = ", v0.t" if mask_source is not None else ""
    lines.append(f"    vlse{eew}.v  {temp_vd}, {address}, {stride}{mask_suffix}")
    _emit_unpack_group(
        lines,  temp_vd, address_reg, vd, emul,
        transfer_avl_reg,
    )
    return lines


def _emit_strided_store(
    insn,
    state: StateTracker,

    *,
    eew: int,
) -> List[str]:
    """发射 ``vsse*.v``，只读取 state 而不伪造向量写回。

    store 的源组 EMUL 与同 EEW 的 load 目的组相同。先把该源组全部 Pack，
    然后以源 VL/SEW/LMUL 发射原生 ``vsse``；因为它不会修改向量目的，不能
    对 ``vs3`` 调用 Unpack，更不能改变紧凑 state 中的任意 payload 字节。已接通
    的 masked form 会在 store 前把源 v0 Pack 到硬件 v0，关闭 lane 不产生访存。
    """
    parsed = _data_operands_with_optional_v0_mask(insn, 3)
    if parsed is None:
        return _error(insn, "vsse 只支持 vs3, (rs1), rs2 及可选 v0.t form")
    operands, mask_source = parsed
    vs3, address, stride = operands
    try:
        sew, lmul, lmul_token, _ = _source_shape(state)
        emul, group_width = _effective_lmul(lmul, sew, eew)
        state_view
        requested_widths = [group_width]
        if mask_source is not None:
            requested_widths.append(1)
        allocated = _allocate_vector_groups(requested_widths)
        temp_vs3 = allocated[0]
        temp_mask = allocated[1] if mask_source is not None else None
        temps = TempRegisterAllocator(insn, reserved_gprs=("t6",))
        vl_reg = temps.alloc_gpr()
        address_reg = temps.alloc_gpr()
        transfer_avl_reg = temps.alloc_gpr()
    except (ValueError, TypeError) as exc:
        return _error(insn, str(exc))

    lines: List[str] = [
        f"# {insn.opcode} {insn.op_str} (RVV256 raw state -> RVV1024 strided store)",
        f"# EEW=e{eew}, 源 SEW=e{sew}, 源 LMUL={lmul_token}, EMUL={emul:g}",
    ]
    _emit_load_source_vl(lines,  vl_reg, address_reg)
    _emit_pack_group(
        lines,  temp_vs3, address_reg, vs3, emul,
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
    _emit_execution_vsetvl(lines, vl_reg, sew, lmul_token)
    mask_suffix = ", v0.t" if mask_source is not None else ""
    lines.append(f"    vsse{eew}.v  {temp_vs3}, {address}, {stride}{mask_suffix}")
    lines.append("    # store 不写回紧凑 RVV256 state；仅产生源语义的内存副作用")
    return lines


def _emit_unordered_indexed_load(
    insn,
    state: StateTracker,

    *,
    index_eew: int,
) -> List[str]:
    """发射无掩码 ``vluxei*.v``，保留 source index EMUL 与地址语义。

    indexed load 的数据 EEW 是当前 source SEW，因此目的 ``vd`` 仍按 source
    LMUL 解释；只有 offsets ``vs2`` 的 EMUL 受 index EEW 影响：
    ``index_emul = LMUL * index_EEW / SEW``。把 ``vs2`` 错按 data LMUL
    Pack 会在 e32/m1 + ei16（实际 mf2）等常见组合中读取错误的 raw bytes。

    源 ``vl`` 作为 AVL，使 RVV1024 临时执行只观察源端的活动元素集合。该
    指令的 unordered 性只影响不同 active lane 的访存顺序，不改变每个 lane
    使用的 unsigned byte offset；目标硬件原生 ``vluxei`` 保留该语义。
    """
    operands = _unmasked_operands(insn, 3)
    if operands is None:
        return _error(insn, "vluxei 只支持无掩码 vd, (rs1), vs2 form")
    vd, address, vs2 = operands
    try:
        sew, source_lmul, lmul_token, group_width = _source_shape(state)
        index_emul, index_width = _effective_lmul(source_lmul, sew, index_eew)
        state_view
        temp_vd, temp_index = _allocate_vector_groups([group_width, index_width])
        temps = TempRegisterAllocator(insn, reserved_gprs=("t6",))
        vl_reg = temps.alloc_gpr()
        address_reg = temps.alloc_gpr()
        transfer_avl_reg = temps.alloc_gpr()
    except (ValueError, TypeError) as exc:
        return _error(insn, str(exc))

    lines: List[str] = [
        f"# {insn.opcode} {insn.op_str} (RVV256 raw state -> RVV1024 indexed load)",
        f"# data EMUL={source_lmul:g}; index EEW=e{index_eew}, index EMUL={index_emul:g}; 仅无掩码",
        "# 先 Pack 旧 vd 和完整 index group，避免 vd==vs2 时提前写回覆盖 offset。",
    ]
    _emit_load_source_vl(lines,  vl_reg, address_reg)
    _emit_pack_group(
        lines,  temp_vd, address_reg, vd, source_lmul,
        transfer_avl_reg,
    )
    _emit_pack_group(
        lines,  temp_index, address_reg, vs2, index_emul,
        transfer_avl_reg,
    )
    _emit_execution_vsetvl(lines, vl_reg, sew, lmul_token)
    lines.append(f"    vluxei{index_eew}.v  {temp_vd}, {address}, {temp_index}")
    _emit_unpack_group(
        lines,  temp_vd, address_reg, vd, source_lmul,
        transfer_avl_reg,
    )
    return lines




def _emit_segment_memory(
    insn,
    state: StateTracker,

    *,
    eew: int,
    field_count: int,
    is_load: bool,
    is_strided: bool,
) -> List[str]:
    """发射无掩码 unit/strided segment load/store 的紧凑状态闭环。

    segment 的每个 field 的 EMUL 都是 ``LMUL * EEW / SEW``。load 必须先
    Pack *全部* field 的旧值，随后一次原生 segment load，再把每个 field
    Unpack；store 则先 Pack 全部 field，再一次原生 segment store。这样既
    保持 source ``vl`` 和交错内存布局，也避免 ``vs3`` group 重叠时在读取
    尚未完成前写回 raw state。

    此 helper 刻意只接受无掩码 form。masked segment 的 lane 访存、mu 旧值
    和 field group 别名需要独立目标机差分，不能因本 helper 已可汇编而放开。
    """
    operand_count = 3 if is_strided else 2
    operands = _unmasked_operands(insn, operand_count)
    if operands is None:
        shape = "vreg, (rs1), rs2" if is_strided else "vreg, (rs1)"
        return _error(insn, f"segment memory 只支持无掩码 {shape} form")
    first_vreg, address = operands[:2]
    stride = operands[2] if is_strided else None
    try:
        sew, source_lmul, lmul_token, _ = _source_shape(state)
        emul, field_width = _effective_lmul(source_lmul, sew, eew)
        # RVV segment group 总体不能跨越 8 个物理 vreg。对 fractional EMUL，
        # 每个 field 仍消耗一个物理寄存器，故使用 field_width 作此检查。
        if field_count * field_width > 8:
            raise ValueError(
                f"NF={field_count} 与 EMUL={emul:g} 需要 {field_count * field_width} 个物理寄存器，超出 RVV segment 上限"
            )
        source_fields = _segment_field_registers(first_vreg, field_width, field_count)
        state_view
        temp_fields = _allocate_vector_groups([field_width] * field_count)
        temp_numbers = [int(temp[1:]) for temp in temp_fields]
        expected_numbers = [temp_numbers[0] + index * field_width for index in range(field_count)]
        if temp_numbers != expected_numbers:
            raise ValueError("RVV1024 临时 field groups 未连续排列，不能发射 segment 指令")

        temps = TempRegisterAllocator(insn, reserved_gprs=("t6",))
        vl_reg = temps.alloc_gpr()
        address_reg = temps.alloc_gpr()
        transfer_avl_reg = temps.alloc_gpr()
    except (ValueError, TypeError) as exc:
        return _error(insn, str(exc))

    prefix = "vl" if is_load else "vs"
    native_opcode = f"{prefix}{'s' if is_strided else ''}seg{field_count}e{eew}.v"
    role = "load" if is_load else "store"
    lines: List[str] = [
        f"# {insn.opcode} {insn.op_str} (RVV256 -> RVV1024 {role} segment)",
        f"# NF={field_count}, EEW=e{eew}, source LMUL={source_lmul:g}, field EMUL={emul:g}; 仅无掩码",
        "# 每个 field 先独立 Pack；原生 segment 指令后才允许对 load field Unpack。",
    ]
    _emit_load_source_vl(lines,  vl_reg, address_reg)
    for source_field, temp_field in zip(source_fields, temp_fields):
        _emit_pack_group(
            lines,  temp_field, address_reg, source_field, emul,
            transfer_avl_reg,
        )
    _emit_execution_vsetvl(lines, vl_reg, sew, lmul_token)
    native_suffix = f", {stride}" if is_strided else ""
    lines.append(f"    {native_opcode:<15} {temp_fields[0]}, {address}{native_suffix}")
    if is_load:
        for source_field, temp_field in zip(source_fields, temp_fields):
            _emit_unpack_group(
                lines,  temp_field, address_reg, source_field, emul,
                transfer_avl_reg,
            )
    else:
        lines.append("    # segment store 不写回紧凑 RVV256 state；仅产生交错内存副作用")
    return lines


def _emit_vsm(
    insn,

) -> List[str]:
    """发射无掩码 ``vsm.v``，由硬件按 ``ceil(VL/8)`` 存储 mask bytes。

    ``vsm.v`` 仅观察 source ``vl`` 和一个 bit-packed mask register，不依赖
    source SEW/LMUL 对数据寄存器组的解释。RVV256 在任何合法 vtype 下的
    ``VL`` 最大值均为 256；因此在 RVV1024 上固定 ``e8,m2``（VLMAX=256）
    即可精确建立同一 VL，且不会把未知/动态 source vtype 猜成某一静态值。

    目标 ``vsm.v`` 自己定义写入 ``ceil(VL/8)`` 字节的行为。不能改用标量
    循环，否则最后一个不完整 byte 的架构性 bit 表示容易被手写逻辑改变。
    """
    operands = _unmasked_operands(insn, 2)
    if operands is None:
        return _error(insn, "vsm.v 只支持无掩码 vs3, (rs1) form")
    vs3, address = operands
    try:
        state_view
        (temp_vs3,) = _allocate_vector_groups([1])
        temps = TempRegisterAllocator(insn, reserved_gprs=("t6",))
        vl_reg = temps.alloc_gpr()
        address_reg = temps.alloc_gpr()
        transfer_avl_reg = temps.alloc_gpr()
    except (ValueError, TypeError) as exc:
        return _error(insn, str(exc))

    lines: List[str] = [
        f"# {insn.opcode} {insn.op_str} (RVV256 bit-packed mask -> RVV1024)",
        "# vsm.v 原生写 ceil(VL/8) 个 mask byte；不写回紧凑 state。",
    ]
    _emit_load_source_vl(lines,  vl_reg, address_reg)
    # 所有源机 mask register 都是单个 32B 物理寄存器；Pack m1 即覆盖其
    # 前 256 个 mask bit，正好覆盖任意合法 RVV256 的最大 VL。
    _emit_pack_group(
        lines,  temp_vs3, address_reg, vs3, 1.0,
        transfer_avl_reg,
    )
    lines.append(
        f"    vsetvli zero, {vl_reg}, e8, m2, tu, mu"
        "  # VLMAX=256，精确保留源 mask-store VL"
    )
    lines.append(f"    vsm.v     {temp_vs3}, {address}")
    return lines


def _emit_whole_move(insn,  factor: int) -> List[str]:
    """以精确 Pack/Unpack 实现 ``vmvNr.v``，不误搬目标机的 128B 整寄存器。"""
    operands = _unmasked_operands(insn, 2)
    if operands is None:
        return _error(insn, "整寄存器 move 只接受无掩码 vd, vs2")
    vd, vs2 = operands
    try:
        state_view
        # N 个源物理寄存器是 N*32B；目标 e8 transfer 至多用 m2。
        transfer_width = 1 if factor <= 4 else 2
        (temp,) = _allocate_vector_groups([transfer_width])
        temps = TempRegisterAllocator(insn, reserved_gprs=("t6",))
        address_reg = temps.alloc_gpr()
        avl_reg = temps.alloc_gpr()
    except (ValueError, TypeError) as exc:
        return _error(insn, str(exc))

    lines: List[str] = [
        f"# {insn.opcode} {insn.op_str}: 复制 {factor} 个 RVV256 物理寄存器",
        "# 不使用目标 vlNr/vsNr：它们会错误搬运 128B/寄存器。",
    ]
    _emit_pack_group(lines,  temp, address_reg, vs2, float(factor), avl_reg)
    _emit_unpack_group(lines,  temp, address_reg, vd, float(factor), avl_reg)
    return lines


def _emit_whole_register_memory(
    insn,

    *,
    factor: int,
    is_load: bool,
) -> List[str]:
    """按源 RVV256 的固定 raw 字节数实现 whole-register load/store。

    ``vlNr`` / ``vsNr`` 在源端每个物理寄存器只占 32B。若直接在目标
    RVV1024 上发射同名 whole-register 指令，它会错误读取或写入 128B/寄存器。
    因此这里使用一个 e8 transfer 临时组：N=1/2/4 时 m1 足够容纳
    ``N*32B``，N=8 时使用 m2。该 transfer 与当前 ``vl``、SEW 和 LMUL
    无关；``vl*re*`` 的 EEW 后缀也只影响源指令编码，不改变 whole-register
    所定义的总字节数。

    load 会把内存字节 Unpack 到目标 raw group；store 只 Pack source group 并
    写内存。两者都不会借用旧 ``SimulatedStateLayout`` 的 128B 向量槽位。
    """
    operands = _unmasked_operands(insn, 2)
    role = "load" if is_load else "store"
    if operands is None:
        return _error(insn, f"whole-register {role} 只支持无掩码 vreg, (rs1) form")
    vreg, address = operands
    try:
        state_view
        transfer_width = 1 if factor <= 4 else 2
        (temp,) = _allocate_vector_groups([transfer_width])
        temps = TempRegisterAllocator(insn, reserved_gprs=("t6",))
        address_reg = temps.alloc_gpr()
        avl_reg = temps.alloc_gpr()
    except (ValueError, TypeError) as exc:
        return _error(insn, str(exc))

    total_bytes = factor * 32
    direction = "内存 -> 紧凑 raw state" if is_load else "紧凑 raw state -> 内存"
    lines: List[str] = [
        f"# {insn.opcode} {insn.op_str} (RVV256 whole-register {role})",
        f"# 固定搬运 {factor} * 32B = {total_bytes}B；{direction}。",
        "# 不发射同名目标 whole-register 指令，避免误搬 128B/目标物理寄存器。",
    ]
    if is_load:
        # 先加载全部 raw 字节，再一次性 Unpack；没有 source vector operand，
        # 因而不会与 destination group 的即将写回发生读取次序冲突。
        lines.append(f"    li      {avl_reg}, {total_bytes}             # whole-register 源字节数")
        transfer_lmul = "m1" if factor <= 4 else "m2"
        lines.append(f"    vsetvli zero, {avl_reg}, e8, {transfer_lmul}, tu, mu")
        lines.append(f"    vle8.v  {temp}, {address}       # 读取 RVV256 whole-register bytes")
        _emit_unpack_group(
            lines,  temp, address_reg, vreg, float(factor), avl_reg,
        )
    else:
        _emit_pack_group(
            lines,  temp, address_reg, vreg, float(factor), avl_reg,
        )
        lines.append(f"    vse8.v  {temp}, {address}       # 写出 RVV256 whole-register bytes")
    return lines


def _emit_vle8ff(
    insn,
    state: StateTracker,

) -> List[str]:
    """发射一次 RVV1024 ``vle8ff.v`` 并同步 fault-only-first 后的源 VL。

    源 RVV256 的任意合法 ``VL`` 至多为 256。将其作为 AVL 配置到
    RVV1024 的同一源 SEW/LMUL 后，目标 VLMAX 恰好至少为源端的四倍，故不需
    256-bit strip-mining。硬件在非首元素 fault 时会把目标 ``vl`` 缩短；在
    改变 vtype 以 Unpack 前先读回它，随后写入既有 state CSR.vl 槽位。

    首元素 fault 会由原生 ``vle8ff.v`` 同步触发异常，后续 Unpack/CSR 写回
    不会执行，符合 FOF 的异常边界。当前阶段刻意不支持 masked FOF form。
    """
    operands = _unmasked_operands(insn, 2)
    if operands is None:
        return _error(insn, "vle8ff.v 当前只支持无掩码 vd, (rs1) form")
    vd, address = operands
    try:
        sew, lmul, lmul_token, _ = _source_shape(state)
        emul, group_width = _effective_lmul(lmul, sew, 8)
        view = state_view
        (temp_vd,) = _allocate_vector_groups([group_width])
        temps = TempRegisterAllocator(insn, reserved_gprs=("t6",))
        source_vl_reg = temps.alloc_gpr()
        actual_vl_reg = temps.alloc_gpr()
        address_reg = temps.alloc_gpr()
        transfer_avl_reg = temps.alloc_gpr()
    except (ValueError, TypeError) as exc:
        return _error(insn, str(exc))

    lines: List[str] = [
        f"# {insn.opcode} {insn.op_str} (RVV256 FOF -> RVV1024)",
        f"# e8 FOF 的目的 EMUL={emul:g}；执行 vtype 仍是源 e{sew},{lmul_token}。",
    ]
    _emit_load_source_vl(lines,  source_vl_reg, address_reg)
    # ``tu`` 保留 FOF 缩短后的未加载元素及 tail，随后完整 raw 组安全 Unpack。
    _emit_pack_group(
        lines,  temp_vd, address_reg, vd, emul,
        transfer_avl_reg,
    )
    # RVV memory 指令的 EEW 只决定目的 EMUL，不能改写 CSR vtype：VL 的
    # 语义仍由源端 SEW/LMUL 决定。这与普通 vle8.v 路径保持一致。
    _emit_execution_vsetvl(lines, source_vl_reg, sew, lmul_token)
    lines.append(f"    vle8ff.v  {temp_vd}, {address}")
    lines.append(f"    csrr      {actual_vl_reg}, vl             # FOF 实际加载元素数")
    _emit_unpack_group(
        lines,  temp_vd, address_reg, vd, emul,
        transfer_avl_reg,
    )
    view.emit_store_csr(lines, actual_vl_reg, address_reg, "vl")
    lines.append("    # FOF 已把缩短后的 VL 同步到 RVV256 紧凑状态")
    return lines


# 以下公共 builder 由 specs.py 通过显式 EEW/NF/factor 数据绑定。它们不从
# opcode 字符串推导语义，因此同一模板只保留一份，也不会把不同访存形态
# 错误合并。
def build_unit_load_lines(context, *, eew: int) -> list[str]:
    return _emit_unit_load(
        context.instruction, context.state,  eew=eew
    )


def build_unit_store_lines(context, *, eew: int) -> list[str]:
    return _emit_unit_store(
        context.instruction, context.state,  eew=eew
    )


def build_strided_load_lines(context, *, eew: int) -> list[str]:
    return _emit_strided_load(
        context.instruction, context.state,  eew=eew
    )


def build_strided_store_lines(context, *, eew: int) -> list[str]:
    return _emit_strided_store(
        context.instruction, context.state,  eew=eew
    )


def build_indexed_load_lines(context, *, index_eew: int) -> list[str]:
    return _emit_unordered_indexed_load(
        context.instruction,
        context.state,

        index_eew=index_eew,
    )


def build_segment_memory_lines(
    context,
    *,
    eew: int,
    field_count: int,
    is_load: bool,
    is_strided: bool,
) -> list[str]:
    return _emit_segment_memory(
        context.instruction,
        context.state,

        eew=eew,
        field_count=field_count,
        is_load=is_load,
        is_strided=is_strided,
    )


def build_whole_memory_lines(
    context, *, factor: int, is_load: bool
) -> list[str]:
    return _emit_whole_register_memory(
        context.instruction,

        factor=factor,
        is_load=is_load,
    )


def build_whole_move_lines(context, *, factor: int) -> list[str]:
    return _emit_whole_move(context.instruction,  factor)


def _build_vle8ff_v_lines(context) -> list[str]:
    """翻译 unmasked ``vle8ff.v``，并写回硬件实际 VL。"""
    insn = context.instruction
    state = context.state

    return _emit_vle8ff(insn, state)


def _build_vsm_v_lines(context) -> list[str]:
    """翻译无掩码 mask store；source vtype 未知时仍可由 ``vl`` 精确执行。"""
    insn = context.instruction
    return _emit_vsm(insn)
