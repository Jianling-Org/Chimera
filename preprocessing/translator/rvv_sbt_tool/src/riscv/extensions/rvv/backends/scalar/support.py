"""标量逐元素执行的地址和掩码支撑。"""

from __future__ import annotations

from typing import List
from riscv.frontend.model import RVInstruction
from riscv.extensions.rvv.instruction import uses_explicit_v0_mask
from riscv.extensions.rvv.analysis.model import LEGAL_LMULS


def _vector_group_bounds(context, register: str, eew: int) -> tuple[int, int]:
    """Return one non-segment operand group's simulated byte range."""
    state = context.state
    number = _parse_vector_register_number(register)
    emul = 1 if eew == 1 else state.lmul * eew / state.sew
    if emul not in LEGAL_LMULS:
        raise ValueError(f"{register}: unsupported EMUL={emul:g}")
    registers = max(1, int(emul))
    if number % registers or number + registers > 32:
        raise ValueError(f"{register}: misaligned or out-of-range EMUL={emul:g} group")
    start = context.layout.get_offset(register)
    return start, start + int(emul * context.layout.vreg_size)


def _validate_vector_groups(context, destination_eew: int, sources) -> None:
    """Enforce overlap for plain groups; segment/slide/gather use source validation."""
    state = context.state
    if state.sew not in (8, 16, 32, 64) or state.lmul not in LEGAL_LMULS:
        raise ValueError(f"Invalid vector configuration: e{state.sew}, LMUL={state.lmul}")
    destination = context.instruction.operands[0]
    dst_start, dst_end = _vector_group_bounds(context, destination, destination_eew)
    if destination_eew != 1 and dst_start == 0 and uses_explicit_v0_mask(context.instruction):
        raise ValueError("Masked data destination must not overlap v0")
    for register, eew in sources:
        src_start, src_end = _vector_group_bounds(context, register, eew)
        if max(dst_start, src_start) >= min(dst_end, src_end) or eew == destination_eew:
            continue
        if destination_eew < eew and dst_start == src_start:
            continue
        if (
            destination_eew > eew
            and src_end == dst_end
            and src_end - src_start >= context.layout.vreg_size
        ):
            continue
        raise ValueError(f"Illegal overlapping vector groups: {destination}, {register}")


def emit_mask_skip_guard(
    lines: List[str],
    element_index_reg: str,
    mask_chunk_reg: str,
    shift_reg: str,
    skip_label: str,
) -> None:
    """
    生成统一的“若 v0[i] == 0 则跳过当前元素”模板。

    Mask 位布局 (标量模式):
    - 以 64-bit 为单位 (ld) 读取 simulated_cpu_state 中 v0 的 mask 字节
    - 元素 i 的 mask bit 位于 offset(i/64) 的第 (i%64) bit
    - 这在 little-endian RISC-V 上与 RVV 1.0 bit-packed 布局 (bit i
      位于 byte i/8 的 i%8 位) 兼容: ld 将 byte 0 读入 bit 0-7
    - 与 256-bit 模式 (backends/rvv256/support.py 的 _emit_mask_extraction_chunk) 的逐字节 lbu 访问在位级
      结果上一致, 均遵循 RVV 1.0 spec

    参考了 QEMU `vext_elem_mask()` 的位读取思路。

    参数约束：
    - `element_index_reg` 中保存“元素索引 i”，而不是字节偏移；
    - `mask_chunk_reg` / `shift_reg` 会被本模板覆盖；
    - `t6` 依旧被视为 `simulated_cpu_state` 基址。
    """

    lines.append("    # masked form: 读取 v0[i]，若当前 mask bit 为 0 则跳过本元素")
    lines.append(
        f"    srli    {mask_chunk_reg}, {element_index_reg}, 6    # chunk = i / 64"
    )
    lines.append(
        f"    slli    {mask_chunk_reg}, {mask_chunk_reg}, 3    # byte offset = chunk * 8"
    )
    lines.append(
        f"    add     {mask_chunk_reg}, t6, {mask_chunk_reg}    # v0 chunk address"
    )
    lines.append(
        f"    ld      {mask_chunk_reg}, 0({mask_chunk_reg})    # load 64-bit mask chunk"
    )
    lines.append(
        f"    andi    {shift_reg}, {element_index_reg}, 63    # shift = i % 64"
    )
    lines.append(
        f"    srl     {mask_chunk_reg}, {mask_chunk_reg}, {shift_reg}"
    )
    lines.append(f"    andi    {mask_chunk_reg}, {mask_chunk_reg}, 1")
    lines.append(f"    beqz    {mask_chunk_reg}, {skip_label}")


def _emit_element_shift(
    lines: List[str],
    element_size: int,
    shift_reg: str = "t2"
) -> None:
    """
    根据元素大小对指定寄存器生成移位指令。

    :param lines: 输出行列表
    :param element_size: 元素大小 (字节)
    :param shift_reg: 需要原地左移的寄存器
    """
    if element_size == 8:
        lines.append(f"    slli    {shift_reg}, {shift_reg}, 3           # {shift_reg} = i * 8 (64-bit)")
    elif element_size == 4:
        lines.append(f"    slli    {shift_reg}, {shift_reg}, 2           # {shift_reg} = i * 4 (32-bit)")
    elif element_size == 2:
        lines.append(f"    slli    {shift_reg}, {shift_reg}, 1           # {shift_reg} = i * 2 (16-bit)")
    elif element_size == 1:
        # 8-bit 元素不需要移位，寄存器本身已经是字节偏移。
        pass
    else:
        raise ValueError(f"不支持的元素大小: {element_size} bytes")


def _parse_vector_register_number(reg_name: str) -> int:
    """
    解析形如 `v8` 的向量寄存器名，并返回寄存器编号。

    这个辅助函数主要服务于 `vmv4r.v` 这类“整组寄存器搬运"指令，
    因为这类指令需要按物理向量寄存器编号推导复制范围。
    """
    reg_name = reg_name.strip().lower()
    if not reg_name.startswith('v') or not reg_name[1:].isdigit():
        raise ValueError(f"无效向量寄存器名: {reg_name}")

    reg_num = int(reg_name[1:])
    if not 0 <= reg_num <= 31:
        raise ValueError(f"向量寄存器编号超出范围: {reg_name}")
    return reg_num


def _maybe_emit_mask_skip_guard(
    lines: List[str],
    insn: RVInstruction,
    new_label,
    element_index_reg: str,
    mask_chunk_reg: str,
    shift_reg: str,
    label_prefix: str,
) -> str | None:
    """
    若当前指令带 `v0.t`，则生成统一的 masked-off 跳过逻辑。

    第一阶段的策略非常保守：
    - active 元素：照常执行当前 handler 的标量语义；
    - masked-off 元素：直接跳到本轮循环的收尾，既不计算也不写回。

    这样天然满足“保留旧值"的目标，因为目标位置根本没有被覆盖。
    """
    if not uses_explicit_v0_mask(insn):
        return None

    skip_label = new_label(label_prefix)
    emit_mask_skip_guard(
        lines=lines,
        element_index_reg=element_index_reg,
        mask_chunk_reg=mask_chunk_reg,
        shift_reg=shift_reg,
        skip_label=skip_label,
    )
    return skip_label
