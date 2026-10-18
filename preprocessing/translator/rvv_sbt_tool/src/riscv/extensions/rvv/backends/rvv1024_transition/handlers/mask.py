"""RVV256→RVV1024 过渡路径的批次 2 掩码指令。

源端掩码仍是 RVV 1.0 的 bit-packed 物理表示：元素 ``i`` 的掩码位位于
raw ``vN`` 的 ``byte(i // 8)`` 的 bit ``i % 8``。由于本阶段固定源
VLEN=256 bit，任意合法源 ``VL`` 最多为 256；所以一个源物理寄存器的低
32B 足以承载所有可能被指令观察的 mask bit。

本模块不直接用 ``SimulatedStateLayout.get_offset('vN')``。所有 mask 与数据向量
都经由 ``state_view`` 以 ``simulated_cpu_state + N * 32`` Pack/Unpack，
避免把旧 128B 逻辑槽位误用到 RVV256 原生迁移状态。
"""

from __future__ import annotations

from typing import List, Sequence

from riscv.extensions.rvv.backends.rvv1024_transition import state_view
from riscv.extensions.rvv.translation.lowering import AssemblyFragments
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
    _parse_simm5,
    _source_shape,
)


def _plain_operands(insn, expected: int) -> list[str] | None:
    """取得无 ``*.t`` 后缀的固定数量操作数。

    mask-producing 指令的 mask destination 与普通 ``v0.t`` 执行掩码是两种
    完全不同的语义。本批只支持无掩码 compare/mask logic；若带 ``*.t``，
    必须由预检标为结构化拒绝，不能悄悄将它解释为普通 mask 输入；反向 profile
    会进一步生成带诊断的 ``ebreak``。
    """
    operands = [str(operand).strip() for operand in insn.operands]
    if len(operands) != expected or any(operand.endswith(".t") for operand in operands):
        return None
    return operands


def _emit_mask_result(
    insn,
    state: StateTracker,

    *,
    native_opcode: str,
    vd: str,
    vector_sources: Sequence[str],
    scalar_operand: str | None = None,
    immediate: int | None = None,
) -> List[str]:
    """发射比较类 mask 结果：``vd.mask = predicate(...)``。

    目标 mask temporary 始终以一个完整物理寄存器承载；数据源则按当前源
    LMUL 分配。先 Pack 旧 ``vd`` 是为了与统一的 ``tu,mu`` 策略保持一致：
    即使目标机对 mask tail 给出具体保留值，Unpack 后也不会损坏源状态中未被
    当前 ``VL`` 定义的 bit。
    """
    try:
        sew, lmul, lmul_token, group_width = _source_shape(state)
        state_view
        temp_vd, *temp_sources = _allocate_vector_groups(
            [1, *([group_width] * len(vector_sources))]
        )
        temps = TempRegisterAllocator(insn, reserved_gprs=("t6",))
        vl_reg = temps.alloc_gpr()
        address_reg = temps.alloc_gpr()
        transfer_avl_reg = temps.alloc_gpr()
    except (ValueError, TypeError) as exc:
        return _error(insn, str(exc))

    lines: List[str] = [
        f"# {insn.opcode} {insn.op_str} (RVV256 bit-packed mask -> RVV1024)",
        "# 先 Pack 旧 mask 结果与全部数据源，再执行并写回低 32B mask payload。",
    ]
    _emit_load_source_vl(lines,  vl_reg, address_reg)
    _emit_pack_group(
        lines,  temp_vd, address_reg, vd, 1.0,
        transfer_avl_reg,
    )
    for source_vreg, temp_source in zip(vector_sources, temp_sources):
        _emit_pack_group(
            lines,  temp_source, address_reg, source_vreg, lmul,
            transfer_avl_reg,
        )
    _emit_execution_vsetvl(lines, vl_reg, sew, lmul_token)

    native_operands = [temp_vd, *temp_sources]
    if scalar_operand is not None:
        native_operands.append(scalar_operand)
    elif immediate is not None:
        native_operands.append(str(immediate))
    lines.append(f"    {native_opcode:<10} {', '.join(native_operands)}")
    _emit_unpack_group(
        lines,  temp_vd, address_reg, vd, 1.0,
        transfer_avl_reg,
    )
    return lines


def _emit_mask_logic(
    insn,
    state: StateTracker,

    *,
    native_opcode: str,
    source_count: int,
) -> List[str]:
    """发射 ``vmor.mm``、``vmand.mm`` 与 ``vmnot.m`` 的 raw mask 闭环。"""
    operands = _plain_operands(insn, 1 + source_count)
    if operands is None:
        return _error(insn, f"{native_opcode} 只支持无掩码固定操作数 form")
    vd, *sources = operands
    try:
        sew, _, lmul_token, _ = _source_shape(state)
        state_view
        temp_vd, *temp_sources = _allocate_vector_groups([1] * (1 + source_count))
        temps = TempRegisterAllocator(insn, reserved_gprs=("t6",))
        vl_reg = temps.alloc_gpr()
        address_reg = temps.alloc_gpr()
        transfer_avl_reg = temps.alloc_gpr()
    except (ValueError, TypeError) as exc:
        return _error(insn, str(exc))

    lines: List[str] = [
        f"# {insn.opcode} {insn.op_str} (RVV256 raw mask -> RVV1024)",
        "# mask 采用一 bit/element 布局；所有源先 Pack，避免 vd 别名覆盖。",
    ]
    _emit_load_source_vl(lines,  vl_reg, address_reg)
    _emit_pack_group(
        lines,  temp_vd, address_reg, vd, 1.0,
        transfer_avl_reg,
    )
    for source_vreg, temp_source in zip(sources, temp_sources):
        _emit_pack_group(
            lines,  temp_source, address_reg, source_vreg, 1.0,
            transfer_avl_reg,
        )
    _emit_execution_vsetvl(lines, vl_reg, sew, lmul_token)
    lines.append(f"    {native_opcode:<10} {', '.join([temp_vd, *temp_sources])}")
    _emit_unpack_group(
        lines,  temp_vd, address_reg, vd, 1.0,
        transfer_avl_reg,
    )
    return lines


def _emit_mask_clear(insn, state) -> List[str]:
    """发射 ``vmclr.m vd`` 的目标机 lowering。

    ``vmclr.m`` 是伪指令，目标汇编器未必提供同名编码；这里先 Pack 旧 mask
    到一个普通临时组，再用 ``vmxor.mm temp, temp, temp`` 清零活动 mask 位，
    最后 Unpack 回紧凑 RVV256 state。这样既保留了迁移状态 ABI，也不会把
    源状态中的 ``vN`` 误当成目标硬件 ``vN``。
    """
    operands = _plain_operands(insn, 1)
    if operands is None:
        return _error(insn, "vmclr.m 只支持无掩码 vd form")
    (vd,) = operands
    try:
        sew, _, lmul_token, _ = _source_shape(state)
        state_view
        (temp_vd,) = _allocate_vector_groups([1])
        temps = TempRegisterAllocator(insn, reserved_gprs=("t6",))
        vl_reg = temps.alloc_gpr()
        address_reg = temps.alloc_gpr()
        transfer_avl_reg = temps.alloc_gpr()
    except (ValueError, TypeError) as exc:
        return _error(insn, str(exc))

    lines: List[str] = [
        f"# {insn.opcode} {insn.op_str} (RVV256 bit-packed mask clear -> RVV1024)",
        "# 先 Pack 旧 vd；vmxor.mm 的结果再按源 VL Unpack，避免写坏紧凑 state 的其它字节。",
    ]
    _emit_load_source_vl(lines,  vl_reg, address_reg)
    _emit_pack_group(
        lines,  temp_vd, address_reg, vd, 1.0,
        transfer_avl_reg,
    )
    _emit_execution_vsetvl(lines, vl_reg, sew, lmul_token)
    lines.append(f"    vmxor.mm   {temp_vd}, {temp_vd}, {temp_vd}   # vmclr.m lowering")
    _emit_unpack_group(
        lines,  temp_vd, address_reg, vd, 1.0,
        transfer_avl_reg,
    )
    return lines


def _emit_mask_scan(
    insn,
    state: StateTracker,

    *,
    native_opcode: str,
) -> List[str] | AssemblyFragments:
    """发射 ``vfirst.m`` / ``vcpop.m``，只读 source mask 并写标量结果。"""
    operands = _plain_operands(insn, 2)
    if operands is None:
        return _error(insn, f"{native_opcode} 只支持无掩码 rd, vs2 form")
    rd, vs2 = operands
    try:
        sew, _, lmul_token, _ = _source_shape(state)
        state_view
        (temp_vs2,) = _allocate_vector_groups([1])
        temps = TempRegisterAllocator(insn, reserved_gprs=("t6",))
        vl_reg = temps.alloc_gpr()
        address_reg = temps.alloc_gpr()
        transfer_avl_reg = temps.alloc_gpr()
    except (ValueError, TypeError) as exc:
        return _error(insn, str(exc))

    lines: List[str] = [
        f"# {insn.opcode} {insn.op_str} (RVV256 mask scan -> RVV1024)",
        "# 只读取紧凑状态中的 source mask；本指令不写向量 payload。",
    ]
    _emit_load_source_vl(lines,  vl_reg, address_reg)
    _emit_pack_group(
        lines,  temp_vs2, address_reg, vs2, 1.0,
        transfer_avl_reg,
    )
    _emit_execution_vsetvl(lines, vl_reg, sew, lmul_token)
    # vfirst/vcpop 的 rd 可合法是 t6/x31。此时不能在 postamble 仍需访问
    # state base 时立即写 rd；结构化 post-state 片段会把本行移动到
    # vcsr/vstart 写回之后，wrapper 随后也不会恢复旧 t6 覆盖语义结果。
    result_line = f"    {native_opcode:<10} {rd}, {temp_vs2}"
    if str(rd).strip().lower() in {"t6", "x31"}:
        return AssemblyFragments(tuple(lines), (result_line,))
    lines.append(result_line)
    return lines


def _emit_vmerge(
    insn,
    state: StateTracker,

    *,
    native_opcode: str,
    kind: str,
) -> List[str]:
    """发射以 source ``v0`` 为 selector 的三种 ``vmerge``。

    ``vmerge`` 的末尾 ``v0`` 不是 ``v0.t`` 后缀，而是明确的 mask 操作数。
    它依然必须从 raw state Pack 到临时组后复制进目标硬件 v0。复制发生在
    所有 data source Pack 之后，故 ``vd/vs*`` 与 source v0 的任何别名都不
    会让写回提前覆盖尚未读取的状态。
    """
    operands = [str(operand).strip() for operand in insn.operands]
    if len(operands) not in (3, 4) or any(operand.endswith(".t") for operand in operands):
        return _error(insn, f"{native_opcode} 只支持 vd, vs2, operand[, v0] form")
    vd, vs2, third = operands[:3]
    selector = operands[3].lower() if len(operands) == 4 else "v0"
    if selector != "v0":
        return _error(insn, f"{native_opcode} 的 selector 必须是 v0，得到 {selector}")
    if kind == "imm":
        try:
            third = str(_parse_simm5(third))
        except ValueError as exc:
            return _error(insn, str(exc))

    try:
        sew, lmul, lmul_token, group_width = _source_shape(state)
        state_view
        requested_widths = [group_width, group_width]
        if kind == "vv":
            requested_widths.append(group_width)
        requested_widths.append(1)  # source v0 selector 的 Pack temporary
        temp_vd, temp_vs2, *rest = _allocate_vector_groups(requested_widths)
        if kind == "vv":
            temp_vs1, temp_mask = rest
        else:
            temp_vs1 = None
            temp_mask = rest[-1]
        temps = TempRegisterAllocator(insn, reserved_gprs=("t6",))
        vl_reg = temps.alloc_gpr()
        address_reg = temps.alloc_gpr()
        transfer_avl_reg = temps.alloc_gpr()
    except (ValueError, TypeError) as exc:
        return _error(insn, str(exc))

    lines: List[str] = [
        f"# {insn.opcode} {insn.op_str} (RVV256 v0 selector -> RVV1024)",
        "# 先 Pack 旧 vd、全部数据源及 source v0；随后才写目标硬件 v0。",
    ]
    _emit_load_source_vl(lines,  vl_reg, address_reg)
    _emit_pack_group(
        lines,  temp_vd, address_reg, vd, lmul,
        transfer_avl_reg,
    )
    _emit_pack_group(
        lines,  temp_vs2, address_reg, vs2, lmul,
        transfer_avl_reg,
    )
    if kind == "vv":
        _emit_pack_group(
            lines,  temp_vs1, address_reg, third, lmul,
            transfer_avl_reg,
        )
    _emit_pack_group(
        lines,  temp_mask, address_reg, "v0", 1.0,
        transfer_avl_reg,
    )
    record_vreg_group("v0", 1)
    lines.append(f"    vmv1r.v v0, {temp_mask}                 # 载入 vmerge selector")
    _emit_execution_vsetvl(lines, vl_reg, sew, lmul_token)
    if kind == "vv":
        native_operands = [temp_vd, temp_vs2, temp_vs1, "v0"]
    else:
        native_operands = [temp_vd, temp_vs2, third, "v0"]
    lines.append(f"    {native_opcode:<10} {', '.join(native_operands)}")
    _emit_unpack_group(
        lines,  temp_vd, address_reg, vd, lmul,
        transfer_avl_reg,
    )
    return lines


def _build_vlm_v_lines(context) -> list[str]:
    """迁移 ``vlm.v``：以目标 mask load 读取相同的 ``ceil(VL/8)`` 字节。"""
    insn = context.instruction
    state = context.state

    operands = _plain_operands(insn, 2)
    if operands is None:
        return _error(insn, "vlm.v 只支持无掩码 vd, (rs1) form")
    vd, address = operands
    try:
        sew, _, lmul_token, _ = _source_shape(state)
        state_view
        (temp_vd,) = _allocate_vector_groups([1])
        temps = context.temp_register_allocator
        vl_reg = temps.alloc_gpr()
        address_reg = temps.alloc_gpr()
        transfer_avl_reg = temps.alloc_gpr()
    except (ValueError, TypeError) as exc:
        return _error(insn, str(exc))

    lines: List[str] = [
        f"# {insn.opcode} {insn.op_str} (RVV256 mask load -> RVV1024)",
        "# 先保留目的 mask 的旧 32B；tu 使 VL 外 bit 不会污染紧凑状态。",
    ]
    _emit_load_source_vl(lines,  vl_reg, address_reg)
    _emit_pack_group(
        lines,  temp_vd, address_reg, vd, 1.0,
        transfer_avl_reg,
    )
    _emit_execution_vsetvl(lines, vl_reg, sew, lmul_token)
    lines.append(f"    vlm.v     {temp_vd}, {address}")
    _emit_unpack_group(
        lines,  temp_vd, address_reg, vd, 1.0,
        transfer_avl_reg,
    )
    return lines


def _build_vmseq_vi_lines(context) -> list[str]:
    insn = context.instruction
    state = context.state

    operands = _plain_operands(insn, 3)
    if operands is None:
        return _error(insn, "vmseq.vi 只支持无掩码 vd, vs2, simm5")
    vd, vs2, raw_imm = operands
    try:
        immediate = _parse_simm5(raw_imm)
    except ValueError as exc:
        return _error(insn, str(exc))
    return _emit_mask_result(
        insn, state,  native_opcode="vmseq.vi", vd=vd,
        vector_sources=(vs2,), immediate=immediate,
    )


def _build_vmseq_vx_lines(context) -> list[str]:
    insn = context.instruction
    state = context.state

    operands = _plain_operands(insn, 3)
    if operands is None:
        return _error(insn, "vmseq.vx 只支持无掩码 vd, vs2, rs1")
    vd, vs2, rs1 = operands
    return _emit_mask_result(
        insn, state,  native_opcode="vmseq.vx", vd=vd,
        vector_sources=(vs2,), scalar_operand=rs1,
    )


def _build_vmsne_vv_lines(context) -> list[str]:
    insn = context.instruction
    state = context.state

    operands = _plain_operands(insn, 3)
    if operands is None:
        return _error(insn, "vmsne.vv 只支持无掩码 vd, vs2, vs1")
    vd, vs2, vs1 = operands
    return _emit_mask_result(
        insn, state,  native_opcode="vmsne.vv", vd=vd,
        vector_sources=(vs2, vs1),
    )


def _build_vmsne_vi_lines(context) -> list[str]:
    insn = context.instruction
    state = context.state

    operands = _plain_operands(insn, 3)
    if operands is None:
        return _error(insn, "vmsne.vi 只支持无掩码 vd, vs2, simm5")
    vd, vs2, raw_imm = operands
    try:
        immediate = _parse_simm5(raw_imm)
    except ValueError as exc:
        return _error(insn, str(exc))
    return _emit_mask_result(
        insn, state,  native_opcode="vmsne.vi", vd=vd,
        vector_sources=(vs2,), immediate=immediate,
    )


def _build_vmsne_vx_lines(context) -> list[str]:
    insn = context.instruction
    state = context.state

    operands = _plain_operands(insn, 3)
    if operands is None:
        return _error(insn, "vmsne.vx 只支持无掩码 vd, vs2, rs1")
    vd, vs2, rs1 = operands
    return _emit_mask_result(
        insn, state,  native_opcode="vmsne.vx", vd=vd,
        vector_sources=(vs2,), scalar_operand=rs1,
    )


def _build_vmsle_vi_lines(context) -> list[str]:
    """翻译无掩码有符号 ``vmsle.vi`` 并写回 bit-packed source mask。

    ``.vi`` 的立即数仍是 sign-extended 5-bit 值；不能沿用 unsigned compare
    的注释/命名而模糊其有符号比较语义。结果 mask 的 raw 布局与其它 compare
    一致，故复用统一 Pack→执行→Unpack helper。
    """
    insn = context.instruction
    state = context.state

    operands = _plain_operands(insn, 3)
    if operands is None:
        return _error(insn, "vmsle.vi 只支持无掩码 vd, vs2, simm5")
    vd, vs2, raw_imm = operands
    try:
        immediate = _parse_simm5(raw_imm)
    except ValueError as exc:
        return _error(insn, str(exc))
    return _emit_mask_result(
        insn, state,  native_opcode="vmsle.vi", vd=vd,
        vector_sources=(vs2,), immediate=immediate,
    )


def _emit_unsigned_mask_vi(insn, state,  *, native_opcode: str) -> List[str]:
    """发射无掩码 unsigned mask compare 的 ``vd, vs2, simm5`` form。

    RVV 的 .vi 编码携带的是 5-bit sign-extended immediate；比较指令随后按
    unsigned 元素语义解释该扩展后的位模式。因此必须复用 `_parse_simm5`，
    不能把 ``-1`` 偷换为一个 host 整数范围不同的常量。
    """
    operands = _plain_operands(insn, 3)
    if operands is None:
        return _error(insn, f"{native_opcode} 只支持无掩码 vd, vs2, simm5")
    vd, vs2, raw_imm = operands
    try:
        immediate = _parse_simm5(raw_imm)
    except ValueError as exc:
        return _error(insn, str(exc))
    return _emit_mask_result(
        insn, state,  native_opcode=native_opcode, vd=vd,
        vector_sources=(vs2,), immediate=immediate,
    )


def _emit_mask_vx(insn, state,  *, native_opcode: str) -> List[str]:
    """发射无掩码 ``vd, vs2, rs1`` 比较，保持 scalar operand 原始位置。"""
    operands = _plain_operands(insn, 3)
    if operands is None:
        return _error(insn, f"{native_opcode} 只支持无掩码 vd, vs2, rs1")
    vd, vs2, rs1 = operands
    return _emit_mask_result(
        insn, state,  native_opcode=native_opcode, vd=vd,
        vector_sources=(vs2,), scalar_operand=rs1,
    )


def _emit_mask_vv(insn, state,  *, native_opcode: str) -> List[str]:
    """发射无掩码 ``vd, vs2, vs1`` 比较并把 bit-packed 结果写回 raw state。"""
    operands = _plain_operands(insn, 3)
    if operands is None:
        return _error(insn, f"{native_opcode} 只支持无掩码 vd, vs2, vs1")
    vd, vs2, vs1 = operands
    return _emit_mask_result(
        insn, state,  native_opcode=native_opcode, vd=vd,
        vector_sources=(vs2, vs1),
    )


def _build_vmsgtu_vi_lines(context) -> list[str]:
    """翻译无掩码 unsigned ``vmsgtu.vi``。"""
    insn = context.instruction
    state = context.state

    return _emit_unsigned_mask_vi(insn, state,  native_opcode="vmsgtu.vi")


def _build_vmsgtu_vx_lines(context) -> list[str]:
    """翻译无掩码 unsigned ``vmsgtu.vx``。"""
    insn = context.instruction
    state = context.state

    return _emit_mask_vx(insn, state,  native_opcode="vmsgtu.vx")


def _build_vmsleu_vi_lines(context) -> list[str]:
    """翻译无掩码 unsigned ``vmsleu.vi``。"""
    insn = context.instruction
    state = context.state

    return _emit_unsigned_mask_vi(insn, state,  native_opcode="vmsleu.vi")


def _build_vmsleu_vv_lines(context) -> list[str]:
    """翻译无掩码 unsigned ``vmsleu.vv``。"""
    insn = context.instruction
    state = context.state

    return _emit_mask_vv(insn, state,  native_opcode="vmsleu.vv")


def _build_vmsltu_vv_lines(context) -> list[str]:
    """翻译无掩码 unsigned ``vmsltu.vv``。"""
    insn = context.instruction
    state = context.state

    return _emit_mask_vv(insn, state,  native_opcode="vmsltu.vv")


def _build_vmsltu_vx_lines(context) -> list[str]:
    """翻译无掩码 unsigned ``vmsltu.vx``。"""
    insn = context.instruction
    state = context.state

    return _emit_mask_vx(insn, state,  native_opcode="vmsltu.vx")


def _build_vmfgt_vf_lines(context) -> list[str]:
    """翻译无掩码浮点 ``vmfgt.vf``；标量浮点寄存器位于原生 operand 末尾。"""
    insn = context.instruction
    state = context.state

    return _emit_mask_vx(insn, state,  native_opcode="vmfgt.vf")


def _build_vmfle_vf_lines(context) -> list[str]:
    """翻译无掩码浮点 ``vmfle.vf``。"""
    insn = context.instruction
    state = context.state

    return _emit_mask_vx(insn, state,  native_opcode="vmfle.vf")


def _build_vmfne_vf_lines(context) -> list[str]:
    """翻译无掩码浮点 ``vmfne.vf``，结果按 bit-packed mask 写回。"""
    insn = context.instruction
    state = context.state

    return _emit_mask_vx(insn, state,  native_opcode="vmfne.vf")


def _build_vmclr_m_lines(context) -> list[str]:
    """翻译无掩码 ``vmclr.m vd``，使用 ``vmxor.mm`` 作为目标机实现。"""
    insn = context.instruction
    state = context.state

    return _emit_mask_clear(insn, state)


def _build_vmor_mm_lines(context) -> list[str]:
    insn = context.instruction
    state = context.state

    return _emit_mask_logic(
        insn, state,  native_opcode="vmor.mm", source_count=2,
    )


def _build_vmand_mm_lines(context) -> list[str]:
    insn = context.instruction
    state = context.state

    return _emit_mask_logic(
        insn, state,  native_opcode="vmand.mm", source_count=2,
    )


def _build_vmnot_m_lines(context) -> list[str]:
    insn = context.instruction
    state = context.state

    return _emit_mask_logic(
        insn, state,  native_opcode="vmnot.m", source_count=1,
    )


def _build_vfirst_m_lines(context) -> list[str]:
    insn = context.instruction
    state = context.state

    return _emit_mask_scan(insn, state,  native_opcode="vfirst.m")


def _build_vcpop_m_lines(context) -> list[str]:
    insn = context.instruction
    state = context.state

    return _emit_mask_scan(insn, state,  native_opcode="vcpop.m")


def _build_vmerge_vvm_lines(context) -> list[str]:
    insn = context.instruction
    state = context.state

    return _emit_vmerge(
        insn, state,  native_opcode="vmerge.vvm", kind="vv",
    )


def _build_vmerge_vxm_lines(context) -> list[str]:
    insn = context.instruction
    state = context.state

    return _emit_vmerge(
        insn, state,  native_opcode="vmerge.vxm", kind="vx",
    )


def _build_vmerge_vim_lines(context) -> list[str]:
    insn = context.instruction
    state = context.state

    return _emit_vmerge(
        insn, state,  native_opcode="vmerge.vim", kind="imm",
    )
