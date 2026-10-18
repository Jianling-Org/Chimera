"""RVV256 浮点算术与浮点转换。

本文件由原算术模块按语义族机械拆分；函数体保持原样，公共状态与 ABI 访问统一复用 common。
"""

from typing import List

from riscv.frontend.model import RVInstruction
from riscv.extensions.rvv.analysis.config import StateTracker
from riscv.extensions.rvv.runtime.layout import SimulatedStateLayout
from riscv.extensions.rvv.translation.contracts import InstructionValidationError
from riscv.extensions.rvv.backends.rvv256.temp_regs import VRegTempAllocator
from riscv.extensions.rvv.translation.temps import TempRegisterAllocator
from riscv.extensions.rvv.backends.rvv256.support import (
    _chunk_size,
    _chunk_bytes,
    _emit_vsetvl_for_chunk,
    _load_vl_from_csr,
    _get_vle_instr,
    _get_vse_instr,
    _emit_mask_setup,
    _emit_mask_extraction_chunk,
)

from riscv.extensions.rvv.backends.rvv256.support import (
    _emit_scalar_tail_vf,
    _emit_scalar_tail_vv,
    _get_float_instr,
)


def _build_vfadd_vv_lines(context) -> list[str]:
    """
    翻译 vfadd.vv 指令 (256-bit 模式)

    格式: vfadd.vv vd, vs2, vs1
    语义: vd[i] = vs2[i] + vs1[i] 对于 i in [0, vl)
    :return: 生成的汇编代码行列表
    """
    insn = context.instruction
    state = context.state
    allocator = context.layout
    new_label = context.new_label
    lines = []
    mask_suffix = ""
    operands = list(insn.operands)
    is_masked = False
    if len(operands) > 0 and str(operands[-1]).strip().endswith(".t"):
        is_masked = True
        operands = operands[:-1]
    if len(operands) < 3:
        raise InstructionValidationError(insn, f"Invalid operands for {insn.opcode}: {insn.op_str}")

    vd = operands[0]
    vs2 = operands[1]
    vs1 = operands[2]

    sew = state.sew
    chunk_n = _chunk_size(sew)
    c_bytes = _chunk_bytes()
    elem_bytes = sew // 8
    shift_amt = {8: 5, 16: 4, 32: 3, 64: 2}[sew]
    mask = chunk_n - 1

    vd_off = allocator.get_offset(vd)
    vs2_off = allocator.get_offset(vs2)
    vs1_off = allocator.get_offset(vs1)

    vtemps = VRegTempAllocator(insn)
    vs2_vreg = vtemps.alloc_vreg()
    vs1_vreg = vtemps.alloc_vreg()
    vd_vreg = vtemps.alloc_vreg()

    temps = TempRegisterAllocator(insn, reserved_gprs=("t6",), extra_avoid_fprs=("ft0", "ft1", "ft2"))
    vl_reg = temps.alloc_gpr()
    chunk_count = temps.alloc_gpr()
    tail_count = temps.alloc_gpr()
    vs2_ptr = temps.alloc_gpr()
    vs1_ptr = temps.alloc_gpr()
    vd_ptr = temps.alloc_gpr()
    temp = temps.alloc_gpr()
    if is_masked:
        mask_bit_idx = temps.alloc_gpr()
        v0_base = temps.alloc_gpr()


    vle_instr = _get_vle_instr(sew)
    vse_instr = _get_vse_instr(sew)

    lines.append(f"# vfadd.vv {vd}, {vs2}, {vs1} (256-bit mode, SEW={sew})")
    lines.append(f"# Semantic: {vd}[i] = {vs2}[i] + {vs1}[i]")
    lines.append("")

    if is_masked:
        _emit_mask_setup(lines, mask_bit_idx, v0_base, temp)

    _load_vl_from_csr(lines, vl_reg=vl_reg, addr_reg=chunk_count)
    lines.append(f"    srli    {chunk_count}, {vl_reg}, {shift_amt}       # {chunk_count} = vl / {chunk_n}")
    lines.append(f"    andi    {tail_count}, {vl_reg}, {mask}              # {tail_count} = vl % {chunk_n}")
    lines.append("")

    # 之后 vl_reg 不再使用，可复用为临时寄存器做 li（不破坏 tail_count）
    lines.append(f"    li      {vl_reg}, {vs2_off:#x}")
    lines.append(f"    add     {vs2_ptr}, t6, {vl_reg}             # {vs2_ptr} = &{vs2}")
    lines.append(f"    li      {vl_reg}, {vs1_off:#x}")
    lines.append(f"    add     {vs1_ptr}, t6, {vl_reg}             # {vs1_ptr} = &{vs1}")
    lines.append(f"    li      {vl_reg}, {vd_off:#x}")
    lines.append(f"    add     {vd_ptr}, t6, {vl_reg}              # {vd_ptr} = &{vd}")
    lines.append("")

    # ========== 主循环 (256-bit 块) ==========
    main_loop = new_label("vfadd_vv_main")
    after_main = new_label("vfadd_vv_after")

    lines.append(f"    # --- 主循环: 每块处理 {chunk_n} 个元素 ({c_bytes} 字节) ---")
    lines.append(f"    beqz    {chunk_count}, {after_main}")
    lines.append(f"{main_loop}:")
    mask_suffix = ", v0.t" if is_masked else ""
    if is_masked:
        _emit_mask_extraction_chunk(lines, sew, mask_bit_idx, v0_base, vl_reg, temp)

    _emit_vsetvl_for_chunk(lines, chunk_n, sew, "m1", vl_reg, scratch_reg=temp)
    lines.append("")
    lines.append(f"    {vle_instr} {vs2_vreg}, ({vs2_ptr})         # 加载 {vs2} 块")
    lines.append(f"    {vle_instr} {vs1_vreg}, ({vs1_ptr})         # 加载 {vs1} 块")
    lines.append(f"    vfadd.vv {vd_vreg}, {vs2_vreg}, {vs1_vreg}{mask_suffix}    # {vd}[i] = {vs2}[i] + {vs1}[i]")
    lines.append(f"    {vse_instr} {vd_vreg}, ({vd_ptr}){mask_suffix}          # 写回 {vd} 块")
    lines.append("")
    lines.append(f"    addi    {vs2_ptr}, {vs2_ptr}, {c_bytes}")
    lines.append(f"    addi    {vs1_ptr}, {vs1_ptr}, {c_bytes}")
    lines.append(f"    addi    {vd_ptr}, {vd_ptr}, {c_bytes}")
    if is_masked:
        lines.append(f"    addi    {mask_bit_idx}, {mask_bit_idx}, {chunk_n}")
    lines.append(f"    addi    {chunk_count}, {chunk_count}, -1")
    lines.append(f"    bnez    {chunk_count}, {main_loop}")
    lines.append(f"{after_main}:")
    lines.append("")

    # ========== 尾部标量回退 ==========
    lines.append(f"    # --- 尾部标量回退: 剩余 {tail_count} 个元素 ---")
    tail_loop = new_label("vfadd_vv_tail")
    end_label = new_label("vfadd_vv_end")
    _emit_scalar_tail_vv(lines, sew, tail_count, vs2_ptr, vs1_ptr, vd_ptr,
                         tail_label=tail_loop, end_label=end_label,
                         op_type='add',
        is_masked=is_masked,
        mask_bit_idx=mask_bit_idx if is_masked else '',
        v0_base=v0_base if is_masked else '',
        mask_tmp1=vl_reg,
        mask_tmp2=temp,
    )

    return lines



def _emit_vfaddsub_vf(
    insn: RVInstruction,
    state: StateTracker,
    allocator: SimulatedStateLayout,
    new_label,
    *,
    opcode: str,
    op_symbol: str,
) -> List[str]:
    """翻译 vfadd.vf / vfsub.vf 指令 (256-bit 模式)。"""
    lines = []
    mask_suffix = ""
    operands = list(insn.operands)
    is_masked = False
    if len(operands) > 0 and str(operands[-1]).strip().endswith(".t"):
        is_masked = True
        operands = operands[:-1]
    if len(operands) < 3:
        raise InstructionValidationError(insn, f"Invalid operands for {insn.opcode}: {insn.op_str}")

    vd = operands[0]
    vs2 = operands[1]
    rs1 = operands[2]

    sew = state.sew
    if sew not in (32, 64):
        raise InstructionValidationError(insn, f"{opcode} supports floating SEW=32/64 only, got SEW={sew}")

    chunk_n = _chunk_size(sew)
    c_bytes = _chunk_bytes()
    shift_amt = {32: 3, 64: 2}[sew]
    mask = chunk_n - 1

    vd_off = allocator.get_offset(vd)
    vs2_off = allocator.get_offset(vs2)

    vtemps = VRegTempAllocator(insn)
    vs2_vreg = vtemps.alloc_vreg()
    vd_vreg = vtemps.alloc_vreg()

    temps = TempRegisterAllocator(insn, reserved_gprs=("t6",))
    vl_reg = temps.alloc_gpr()
    chunk_count = temps.alloc_gpr()
    tail_count = temps.alloc_gpr()
    vs2_ptr = temps.alloc_gpr()
    vd_ptr = temps.alloc_gpr()
    temp = temps.alloc_gpr()
    if is_masked:
        mask_bit_idx = temps.alloc_gpr()
        v0_base = temps.alloc_gpr()

    vle_instr = _get_vle_instr(sew)
    vse_instr = _get_vse_instr(sew)

    lines.append(f"# {opcode} {vd}, {vs2}, {rs1} (256-bit mode, SEW={sew})")
    lines.append(f"# Semantic: {vd}[i] = {vs2}[i] {op_symbol} {rs1}")
    lines.append("")

    if is_masked:
        _emit_mask_setup(lines, mask_bit_idx, v0_base, temp)

    _load_vl_from_csr(lines, vl_reg=vl_reg, addr_reg=chunk_count)
    lines.append(f"    srli    {chunk_count}, {vl_reg}, {shift_amt}       # {chunk_count} = vl / {chunk_n}")
    lines.append(f"    andi    {tail_count}, {vl_reg}, {mask}              # {tail_count} = vl % {chunk_n}")
    lines.append("")

    lines.append(f"    li      {vl_reg}, {vs2_off:#x}")
    lines.append(f"    add     {vs2_ptr}, t6, {vl_reg}             # {vs2_ptr} = &{vs2}")
    lines.append(f"    li      {vl_reg}, {vd_off:#x}")
    lines.append(f"    add     {vd_ptr}, t6, {vl_reg}              # {vd_ptr} = &{vd}")
    lines.append("")

    label_base = opcode.replace(".", "_")
    main_loop = new_label(f"{label_base}_main")
    after_main = new_label(f"{label_base}_after")

    lines.append(f"    # --- 主循环: 每块处理 {chunk_n} 个元素 ({c_bytes} 字节) ---")
    lines.append(f"    beqz    {chunk_count}, {after_main}")
    lines.append(f"{main_loop}:")
    mask_suffix = ", v0.t" if is_masked else ""
    if is_masked:
        _emit_mask_extraction_chunk(lines, sew, mask_bit_idx, v0_base, vl_reg, temp)

    _emit_vsetvl_for_chunk(lines, chunk_n, sew, "m1", vl_reg, scratch_reg=temp)
    lines.append("")
    lines.append(f"    {vle_instr} {vs2_vreg}, ({vs2_ptr})         # 加载 {vs2} 块")
    lines.append(f"    {opcode} {vd_vreg}, {vs2_vreg}, {rs1}{mask_suffix}        # {vd}[i] = {vs2}[i] {op_symbol} {rs1}")
    lines.append(f"    {vse_instr} {vd_vreg}, ({vd_ptr}){mask_suffix}          # 写回 {vd} 块")
    lines.append("")
    lines.append(f"    addi    {vs2_ptr}, {vs2_ptr}, {c_bytes}")
    lines.append(f"    addi    {vd_ptr}, {vd_ptr}, {c_bytes}")
    if is_masked:
        lines.append(f"    addi    {mask_bit_idx}, {mask_bit_idx}, {chunk_n}")
    lines.append(f"    addi    {chunk_count}, {chunk_count}, -1")
    lines.append(f"    bnez    {chunk_count}, {main_loop}")
    lines.append(f"{after_main}:")
    lines.append("")

    lines.append(f"    # --- 尾部 RVV chunk: 剩余 {tail_count} 个元素 ---")
    end_label = new_label(f"{label_base}_end")
    lines.append(f"    beqz    {tail_count}, {end_label}")
    lines.append(f"    vsetvli zero, {tail_count}, e{sew}, m1, ta, ma")
    lines.append(f"    {vle_instr} {vs2_vreg}, ({vs2_ptr})         # 加载 {vs2} tail")
    lines.append(f"    {opcode} {vd_vreg}, {vs2_vreg}, {rs1}        # tail: {vd}[i] = {vs2}[i] {op_symbol} {rs1}")
    lines.append(f"    {vse_instr} {vd_vreg}, ({vd_ptr}){mask_suffix}          # 写回 {vd} tail")
    lines.append(f"{end_label}:")

    return lines



def _build_vfadd_vf_lines(context) -> list[str]:
    """
    翻译 vfadd.vf 指令 (256-bit 模式)

    格式: vfadd.vf vd, vs2, rs1
    语义: vd[i] = vs2[i] + rs1 对于 i in [0, vl)
    """
    insn = context.instruction
    state = context.state
    allocator = context.layout
    new_label = context.new_label
    return _emit_vfaddsub_vf(
        insn, state, allocator, new_label, opcode="vfadd.vf", op_symbol="+"
    )



def _build_vfsub_vf_lines(context) -> list[str]:
    """
    翻译 vfsub.vf 指令 (256-bit 模式)

    格式: vfsub.vf vd, vs2, rs1
    语义: vd[i] = vs2[i] - rs1 对于 i in [0, vl)
    """
    insn = context.instruction
    state = context.state
    allocator = context.layout
    new_label = context.new_label
    return _emit_vfaddsub_vf(
        insn, state, allocator, new_label, opcode="vfsub.vf", op_symbol="-"
    )



def _build_vfrsub_vf_lines(context) -> list[str]:
    """
    翻译 vfrsub.vf 指令 (256-bit 模式)

    格式: vfrsub.vf vd, vs2, rs1
    语义: vd[i] = rs1 - vs2[i] 对于 i in [0, vl)
    """
    insn = context.instruction
    state = context.state
    allocator = context.layout
    new_label = context.new_label
    lines = []
    operands = list(insn.operands)
    is_masked = False
    if len(operands) > 0 and str(operands[-1]).strip().endswith(".t"):
        is_masked = True
        operands = operands[:-1]
    if len(operands) < 3:
        raise InstructionValidationError(insn, f"Invalid operands for {insn.opcode}: {insn.op_str}")

    vd = operands[0]
    vs2 = operands[1]
    rs1 = operands[2]

    sew = state.sew
    if sew not in (32, 64):
        raise InstructionValidationError(insn, f"vfrsub.vf supports floating SEW=32/64 only, got SEW={sew}")

    chunk_n = _chunk_size(sew)
    c_bytes = _chunk_bytes()
    shift_amt = {32: 3, 64: 2}[sew]
    mask = chunk_n - 1

    vd_off = allocator.get_offset(vd)
    vs2_off = allocator.get_offset(vs2)

    vtemps = VRegTempAllocator(insn)
    vs2_vreg = vtemps.alloc_vreg()
    vd_vreg = vtemps.alloc_vreg()

    temps = context.temp_register_allocator
    vl_reg = temps.alloc_gpr()
    chunk_count = temps.alloc_gpr()
    tail_count = temps.alloc_gpr()
    vs2_ptr = temps.alloc_gpr()
    vd_ptr = temps.alloc_gpr()
    temp = temps.alloc_gpr()
    if is_masked:
        mask_bit_idx = temps.alloc_gpr()
        v0_base = temps.alloc_gpr()

    vle_instr = _get_vle_instr(sew)
    vse_instr = _get_vse_instr(sew)

    lines.append(f"# vfrsub.vf {vd}, {vs2}, {rs1} (256-bit mode, SEW={sew})")
    lines.append(f"# Semantic: {vd}[i] = {rs1} - {vs2}[i]")
    lines.append("")

    if is_masked:
        _emit_mask_setup(lines, mask_bit_idx, v0_base, temp)

    _load_vl_from_csr(lines, vl_reg=vl_reg, addr_reg=chunk_count)
    lines.append(f"    srli    {chunk_count}, {vl_reg}, {shift_amt}       # {chunk_count} = vl / {chunk_n}")
    lines.append(f"    andi    {tail_count}, {vl_reg}, {mask}              # {tail_count} = vl % {chunk_n}")
    lines.append("")

    lines.append(f"    li      {temp}, {vs2_off:#x}")
    lines.append(f"    add     {vs2_ptr}, t6, {temp}             # {vs2_ptr} = &{vs2}")
    lines.append(f"    li      {temp}, {vd_off:#x}")
    lines.append(f"    add     {vd_ptr}, t6, {temp}              # {vd_ptr} = &{vd}")
    lines.append("")

    main_loop = new_label("vfrsub_vf_main")
    after_main = new_label("vfrsub_vf_after")

    lines.append(f"    # --- 主循环: 每块处理 {chunk_n} 个元素 ({c_bytes} 字节) ---")
    lines.append(f"    beqz    {chunk_count}, {after_main}")
    lines.append(f"{main_loop}:")
    mask_suffix = ", v0.t" if is_masked else ""
    if is_masked:
        _emit_mask_extraction_chunk(lines, sew, mask_bit_idx, v0_base, vl_reg, temp)

    _emit_vsetvl_for_chunk(lines, chunk_n, sew, "m1", vl_reg, scratch_reg=temp)
    lines.append("")
    lines.append(f"    {vle_instr} {vs2_vreg}, ({vs2_ptr})         # 加载 {vs2} 块")
    lines.append(f"    vfrsub.vf {vd_vreg}, {vs2_vreg}, {rs1}{mask_suffix}       # {vd}[i] = {rs1} - {vs2}[i]")
    lines.append(f"    {vse_instr} {vd_vreg}, ({vd_ptr}){mask_suffix}          # 写回 {vd} 块")
    lines.append("")
    lines.append(f"    addi    {vs2_ptr}, {vs2_ptr}, {c_bytes}")
    lines.append(f"    addi    {vd_ptr}, {vd_ptr}, {c_bytes}")
    if is_masked:
        lines.append(f"    addi    {mask_bit_idx}, {mask_bit_idx}, {chunk_n}")
    lines.append(f"    addi    {chunk_count}, {chunk_count}, -1")
    lines.append(f"    bnez    {chunk_count}, {main_loop}")
    lines.append(f"{after_main}:")
    lines.append("")

    end_label = new_label("vfrsub_vf_end")
    lines.append(f"    # --- 尾部 RVV chunk: 剩余 {tail_count} 个元素 ---")
    lines.append(f"    beqz    {tail_count}, {end_label}")
    if is_masked:
        _emit_mask_extraction_chunk(lines, sew, mask_bit_idx, v0_base, vl_reg, temp)
    lines.append(f"    vsetvli zero, {tail_count}, e{sew}, m1, ta, ma")
    lines.append(f"    {vle_instr} {vs2_vreg}, ({vs2_ptr})         # 加载 {vs2} tail")
    lines.append(f"    vfrsub.vf {vd_vreg}, {vs2_vreg}, {rs1}{mask_suffix}       # tail: {vd}[i] = {rs1} - {vs2}[i]")
    lines.append(f"    {vse_instr} {vd_vreg}, ({vd_ptr}){mask_suffix}          # 写回 {vd} tail")
    lines.append(f"{end_label}:")

    return lines



def _emit_vfmaddsub_vv(
    insn: RVInstruction,
    state: StateTracker,
    allocator: SimulatedStateLayout,
    new_label,
    *,
    opcode: str,
    op_symbol: str,
) -> List[str]:
    """翻译 vfmadd.vv / vfmsub.vv 指令 (旧 vd 参与乘法)。"""
    lines = []
    mask_suffix = ""
    operands = insn.operands
    if len(operands) < 3:
        raise InstructionValidationError(insn, f"Invalid operands for {insn.opcode}: {insn.op_str}")

    vd = operands[0]
    vs1 = operands[1]
    vs2 = operands[2]

    sew = state.sew
    if sew not in (32, 64):
        raise InstructionValidationError(insn, f"{opcode} supports floating SEW=32/64 only, got SEW={sew}")

    chunk_n = _chunk_size(sew)
    c_bytes = _chunk_bytes()
    shift_amt = {32: 3, 64: 2}[sew]
    mask = chunk_n - 1

    vd_off = allocator.get_offset(vd)
    vs1_off = allocator.get_offset(vs1)
    vs2_off = allocator.get_offset(vs2)

    vtemps = VRegTempAllocator(insn)
    vd_vreg = vtemps.alloc_vreg()
    vs1_vreg = vtemps.alloc_vreg()
    vs2_vreg = vtemps.alloc_vreg()

    temps = TempRegisterAllocator(insn, reserved_gprs=("t6",))
    vl_reg = temps.alloc_gpr()
    chunk_count = temps.alloc_gpr()
    tail_count = temps.alloc_gpr()
    vd_ptr = temps.alloc_gpr()
    vs1_ptr = temps.alloc_gpr()
    vs2_ptr = temps.alloc_gpr()

    vle_instr = _get_vle_instr(sew)
    vse_instr = _get_vse_instr(sew)

    lines.append(f"# {opcode} {vd}, {vs1}, {vs2} (256-bit mode, SEW={sew})")
    lines.append(f"# Semantic: {vd}[i] = {vd}[i] * {vs1}[i] {op_symbol} {vs2}[i]")
    lines.append("")

    _load_vl_from_csr(lines, vl_reg=vl_reg, addr_reg=chunk_count)
    lines.append(f"    srli    {chunk_count}, {vl_reg}, {shift_amt}       # {chunk_count} = vl / {chunk_n}")
    lines.append(f"    andi    {tail_count}, {vl_reg}, {mask}              # {tail_count} = vl % {chunk_n}")
    lines.append("")

    lines.append(f"    li      {vl_reg}, {vd_off:#x}")
    lines.append(f"    add     {vd_ptr}, t6, {vl_reg}              # {vd_ptr} = &{vd}")
    lines.append(f"    li      {vl_reg}, {vs1_off:#x}")
    lines.append(f"    add     {vs1_ptr}, t6, {vl_reg}             # {vs1_ptr} = &{vs1}")
    lines.append(f"    li      {vl_reg}, {vs2_off:#x}")
    lines.append(f"    add     {vs2_ptr}, t6, {vl_reg}             # {vs2_ptr} = &{vs2}")
    lines.append("")

    label_base = opcode.replace(".", "_")
    main_loop = new_label(f"{label_base}_main")
    after_main = new_label(f"{label_base}_after")

    lines.append(f"    # --- 主循环: 每块处理 {chunk_n} 个元素 ({c_bytes} 字节) ---")
    lines.append(f"    beqz    {chunk_count}, {after_main}")
    lines.append(f"{main_loop}:")
    _emit_vsetvl_for_chunk(lines, chunk_n, sew, "m1", vl_reg, scratch_reg=vl_reg)
    lines.append("")
    lines.append(f"    {vle_instr} {vd_vreg}, ({vd_ptr})          # 加载旧 {vd} 块 (multiplicand)")
    lines.append(f"    {vle_instr} {vs1_vreg}, ({vs1_ptr})         # 加载 {vs1} 块")
    lines.append(f"    {vle_instr} {vs2_vreg}, ({vs2_ptr})         # 加载 {vs2} 块")
    lines.append(f"    {opcode} {vd_vreg}, {vs1_vreg}, {vs2_vreg}  # {vd}[i] = old {vd}[i] * {vs1}[i] {op_symbol} {vs2}[i]")
    lines.append(f"    {vse_instr} {vd_vreg}, ({vd_ptr}){mask_suffix}          # 写回 {vd} 块")
    lines.append("")
    lines.append(f"    addi    {vd_ptr}, {vd_ptr}, {c_bytes}")
    lines.append(f"    addi    {vs1_ptr}, {vs1_ptr}, {c_bytes}")
    lines.append(f"    addi    {vs2_ptr}, {vs2_ptr}, {c_bytes}")
    lines.append(f"    addi    {chunk_count}, {chunk_count}, -1")
    lines.append(f"    bnez    {chunk_count}, {main_loop}")
    lines.append(f"{after_main}:")
    lines.append("")

    lines.append(f"    # --- 尾部 RVV chunk: 剩余 {tail_count} 个元素 ---")
    end_label = new_label(f"{label_base}_end")
    lines.append(f"    beqz    {tail_count}, {end_label}")
    lines.append(f"    vsetvli zero, {tail_count}, e{sew}, m1, ta, ma")
    lines.append(f"    {vle_instr} {vd_vreg}, ({vd_ptr})          # 加载旧 {vd} tail")
    lines.append(f"    {vle_instr} {vs1_vreg}, ({vs1_ptr})         # 加载 {vs1} tail")
    lines.append(f"    {vle_instr} {vs2_vreg}, ({vs2_ptr})         # 加载 {vs2} tail")
    lines.append(f"    {opcode} {vd_vreg}, {vs1_vreg}, {vs2_vreg}  # tail: {vd}[i] = old {vd}[i] * {vs1}[i] {op_symbol} {vs2}[i]")
    lines.append(f"    {vse_instr} {vd_vreg}, ({vd_ptr}){mask_suffix}          # 写回 {vd} tail")
    lines.append(f"{end_label}:")

    return lines



def _build_vfmadd_vv_lines(context) -> list[str]:
    """
    翻译 vfmadd.vv 指令 (256-bit 模式)

    格式: vfmadd.vv vd, vs1, vs2
    语义: vd[i] = vd[i] * vs1[i] + vs2[i]
    """
    insn = context.instruction
    state = context.state
    allocator = context.layout
    new_label = context.new_label
    return _emit_vfmaddsub_vv(
        insn, state, allocator, new_label, opcode="vfmadd.vv", op_symbol="+"
    )



def _build_vfmadd_vf_lines(context) -> list[str]:
    """
    翻译 vfmadd.vf 指令 (256-bit 模式)

    格式: vfmadd.vf vd, rs1, vs2
    语义: vd[i] = vd[i] * rs1 + vs2[i]
    """
    insn = context.instruction
    state = context.state
    allocator = context.layout
    new_label = context.new_label
    lines = []
    operands = insn.operands
    if len(operands) < 3:
        raise InstructionValidationError(insn, f"Invalid operands for {insn.opcode}: {insn.op_str}")

    vd = operands[0]
    rs1 = operands[1]
    vs2 = operands[2]

    sew = state.sew
    if sew not in (32, 64):
        raise InstructionValidationError(insn, f"vfmadd.vf supports floating SEW=32/64 only, got SEW={sew}")

    chunk_n = _chunk_size(sew)
    c_bytes = _chunk_bytes()
    shift_amt = {32: 3, 64: 2}[sew]
    mask = chunk_n - 1

    vd_off = allocator.get_offset(vd)
    vs2_off = allocator.get_offset(vs2)

    vtemps = VRegTempAllocator(insn)
    vd_vreg = vtemps.alloc_vreg()
    vs2_vreg = vtemps.alloc_vreg()

    temps = context.temp_register_allocator
    vl_reg = temps.alloc_gpr()
    chunk_count = temps.alloc_gpr()
    tail_count = temps.alloc_gpr()
    vd_ptr = temps.alloc_gpr()
    vs2_ptr = temps.alloc_gpr()

    vle_instr = _get_vle_instr(sew)
    vse_instr = _get_vse_instr(sew)

    lines.append(f"# vfmadd.vf {vd}, {rs1}, {vs2} (256-bit mode, SEW={sew})")
    lines.append(f"# Semantic: {vd}[i] = {vd}[i] * {rs1} + {vs2}[i]")
    lines.append("")

    _load_vl_from_csr(lines, vl_reg=vl_reg, addr_reg=chunk_count)
    lines.append(f"    srli    {chunk_count}, {vl_reg}, {shift_amt}       # {chunk_count} = vl / {chunk_n}")
    lines.append(f"    andi    {tail_count}, {vl_reg}, {mask}              # {tail_count} = vl % {chunk_n}")
    lines.append("")

    lines.append(f"    li      {vl_reg}, {vd_off:#x}")
    lines.append(f"    add     {vd_ptr}, t6, {vl_reg}              # {vd_ptr} = &{vd}")
    lines.append(f"    li      {vl_reg}, {vs2_off:#x}")
    lines.append(f"    add     {vs2_ptr}, t6, {vl_reg}             # {vs2_ptr} = &{vs2}")
    lines.append("")

    main_loop = new_label("vfmadd_vf_main")
    after_main = new_label("vfmadd_vf_after")

    lines.append(f"    # --- 主循环: 每块处理 {chunk_n} 个元素 ({c_bytes} 字节) ---")
    lines.append(f"    beqz    {chunk_count}, {after_main}")
    lines.append(f"{main_loop}:")
    _emit_vsetvl_for_chunk(lines, chunk_n, sew, "m1", vl_reg, scratch_reg=vl_reg)
    lines.append("")
    lines.append(f"    {vle_instr} {vd_vreg}, ({vd_ptr})          # 加载旧 {vd} 块 (multiplicand)")
    lines.append(f"    {vle_instr} {vs2_vreg}, ({vs2_ptr})         # 加载 {vs2} 块 (addend)")
    lines.append(f"    vfmadd.vf {vd_vreg}, {rs1}, {vs2_vreg}     # {vd}[i] = old {vd}[i] * {rs1} + {vs2}[i]")
    lines.append(f"    {vse_instr} {vd_vreg}, ({vd_ptr})          # 写回 {vd} 块")
    lines.append("")
    lines.append(f"    addi    {vd_ptr}, {vd_ptr}, {c_bytes}")
    lines.append(f"    addi    {vs2_ptr}, {vs2_ptr}, {c_bytes}")
    lines.append(f"    addi    {chunk_count}, {chunk_count}, -1")
    lines.append(f"    bnez    {chunk_count}, {main_loop}")
    lines.append(f"{after_main}:")
    lines.append("")

    end_label = new_label("vfmadd_vf_end")
    lines.append(f"    # --- 尾部 RVV chunk: 剩余 {tail_count} 个元素 ---")
    lines.append(f"    beqz    {tail_count}, {end_label}")
    lines.append(f"    vsetvli zero, {tail_count}, e{sew}, m1, ta, ma")
    lines.append(f"    {vle_instr} {vd_vreg}, ({vd_ptr})          # 加载旧 {vd} tail")
    lines.append(f"    {vle_instr} {vs2_vreg}, ({vs2_ptr})         # 加载 {vs2} tail")
    lines.append(f"    vfmadd.vf {vd_vreg}, {rs1}, {vs2_vreg}     # tail: old {vd} * {rs1} + {vs2}")
    lines.append(f"    {vse_instr} {vd_vreg}, ({vd_ptr})          # 写回 {vd} tail")
    lines.append(f"{end_label}:")

    return lines



def _build_vfmsub_vv_lines(context) -> list[str]:
    """
    翻译 vfmsub.vv 指令 (256-bit 模式)

    格式: vfmsub.vv vd, vs1, vs2
    语义: vd[i] = vd[i] * vs1[i] - vs2[i]
    """
    insn = context.instruction
    state = context.state
    allocator = context.layout
    new_label = context.new_label
    return _emit_vfmaddsub_vv(
        insn, state, allocator, new_label, opcode="vfmsub.vv", op_symbol="-"
    )



def _emit_vfminmax_vv(
    insn: RVInstruction,
    state: StateTracker,
    allocator: SimulatedStateLayout,
    new_label,
    *,
    opcode: str,
    op_name: str,
) -> List[str]:
    """翻译 vfmax.vv / vfmin.vv 指令 (256-bit 模式)。"""
    lines = []
    mask_suffix = ""
    operands = insn.operands
    if len(operands) < 3:
        raise InstructionValidationError(insn, f"Invalid operands for {insn.opcode}: {insn.op_str}")

    vd = operands[0]
    vs2 = operands[1]
    vs1 = operands[2]

    sew = state.sew
    if sew not in (32, 64):
        raise InstructionValidationError(insn, f"{opcode} supports floating SEW=32/64 only, got SEW={sew}")

    chunk_n = _chunk_size(sew)
    c_bytes = _chunk_bytes()
    shift_amt = {32: 3, 64: 2}[sew]
    mask = chunk_n - 1

    vd_off = allocator.get_offset(vd)
    vs2_off = allocator.get_offset(vs2)
    vs1_off = allocator.get_offset(vs1)

    vtemps = VRegTempAllocator(insn)
    vs2_vreg = vtemps.alloc_vreg()
    vs1_vreg = vtemps.alloc_vreg()
    vd_vreg = vtemps.alloc_vreg()

    temps = TempRegisterAllocator(insn, reserved_gprs=("t6",))
    vl_reg = temps.alloc_gpr()
    chunk_count = temps.alloc_gpr()
    tail_count = temps.alloc_gpr()
    vs2_ptr = temps.alloc_gpr()
    vs1_ptr = temps.alloc_gpr()
    vd_ptr = temps.alloc_gpr()

    vle_instr = _get_vle_instr(sew)
    vse_instr = _get_vse_instr(sew)

    lines.append(f"# {opcode} {vd}, {vs2}, {vs1} (256-bit mode, SEW={sew})")
    lines.append(f"# Semantic: {vd}[i] = {op_name}({vs2}[i], {vs1}[i])")
    lines.append("")

    _load_vl_from_csr(lines, vl_reg=vl_reg, addr_reg=chunk_count)
    lines.append(f"    srli    {chunk_count}, {vl_reg}, {shift_amt}       # {chunk_count} = vl / {chunk_n}")
    lines.append(f"    andi    {tail_count}, {vl_reg}, {mask}              # {tail_count} = vl % {chunk_n}")
    lines.append("")

    lines.append(f"    li      {vl_reg}, {vs2_off:#x}")
    lines.append(f"    add     {vs2_ptr}, t6, {vl_reg}             # {vs2_ptr} = &{vs2}")
    lines.append(f"    li      {vl_reg}, {vs1_off:#x}")
    lines.append(f"    add     {vs1_ptr}, t6, {vl_reg}             # {vs1_ptr} = &{vs1}")
    lines.append(f"    li      {vl_reg}, {vd_off:#x}")
    lines.append(f"    add     {vd_ptr}, t6, {vl_reg}              # {vd_ptr} = &{vd}")
    lines.append("")

    label_base = opcode.replace(".", "_")
    main_loop = new_label(f"{label_base}_main")
    after_main = new_label(f"{label_base}_after")

    lines.append(f"    # --- 主循环: 每块处理 {chunk_n} 个元素 ({c_bytes} 字节) ---")
    lines.append(f"    beqz    {chunk_count}, {after_main}")
    lines.append(f"{main_loop}:")
    _emit_vsetvl_for_chunk(lines, chunk_n, sew, "m1", vl_reg, scratch_reg=vl_reg)
    lines.append("")
    lines.append(f"    {vle_instr} {vs2_vreg}, ({vs2_ptr})         # 加载 {vs2} 块")
    lines.append(f"    {vle_instr} {vs1_vreg}, ({vs1_ptr})         # 加载 {vs1} 块")
    lines.append(f"    {opcode} {vd_vreg}, {vs2_vreg}, {vs1_vreg}     # {vd}[i] = {op_name}({vs2}[i], {vs1}[i])")
    lines.append(f"    {vse_instr} {vd_vreg}, ({vd_ptr}){mask_suffix}          # 写回 {vd} 块")
    lines.append("")
    lines.append(f"    addi    {vs2_ptr}, {vs2_ptr}, {c_bytes}")
    lines.append(f"    addi    {vs1_ptr}, {vs1_ptr}, {c_bytes}")
    lines.append(f"    addi    {vd_ptr}, {vd_ptr}, {c_bytes}")
    lines.append(f"    addi    {chunk_count}, {chunk_count}, -1")
    lines.append(f"    bnez    {chunk_count}, {main_loop}")
    lines.append(f"{after_main}:")
    lines.append("")

    lines.append(f"    # --- 尾部 RVV chunk: 剩余 {tail_count} 个元素 ---")
    end_label = new_label(f"{label_base}_end")
    lines.append(f"    beqz    {tail_count}, {end_label}")
    lines.append(f"    vsetvli zero, {tail_count}, e{sew}, m1, ta, ma")
    lines.append(f"    {vle_instr} {vs2_vreg}, ({vs2_ptr})         # 加载 {vs2} tail")
    lines.append(f"    {vle_instr} {vs1_vreg}, ({vs1_ptr})         # 加载 {vs1} tail")
    lines.append(f"    {opcode} {vd_vreg}, {vs2_vreg}, {vs1_vreg}     # tail: {vd}[i] = {op_name}({vs2}[i], {vs1}[i])")
    lines.append(f"    {vse_instr} {vd_vreg}, ({vd_ptr}){mask_suffix}          # 写回 {vd} tail")
    lines.append(f"{end_label}:")

    return lines



def _build_vfmax_vv_lines(context) -> list[str]:
    """翻译 vfmax.vv 指令。"""
    insn = context.instruction
    state = context.state
    allocator = context.layout
    new_label = context.new_label
    return _emit_vfminmax_vv(
        insn, state, allocator, new_label, opcode="vfmax.vv", op_name="maxNum"
    )



def _build_vfmin_vv_lines(context) -> list[str]:
    """翻译 vfmin.vv 指令。"""
    insn = context.instruction
    state = context.state
    allocator = context.layout
    new_label = context.new_label
    return _emit_vfminmax_vv(
        insn, state, allocator, new_label, opcode="vfmin.vv", op_name="minNum"
    )



def _build_vfmsac_vv_lines(context) -> list[str]:
    """
    翻译 vfmsac.vv 指令 (256-bit 模式)

    格式: vfmsac.vv vd, vs1, vs2
    语义: vd[i] = vs1[i] * vs2[i] - vd[i]

    注意它不同于 vfmadd.vv：vfmsac.vv 覆盖的是 subtrahend vd。
    新增指令采用 RVV tail chunk，而不是手写标量尾部。
    """
    insn = context.instruction
    state = context.state
    allocator = context.layout
    new_label = context.new_label
    lines = []
    mask_suffix = ""
    operands = insn.operands
    if len(operands) < 3:
        raise InstructionValidationError(insn, f"Invalid operands for {insn.opcode}: {insn.op_str}")

    vd = operands[0]
    vs1 = operands[1]
    vs2 = operands[2]

    sew = state.sew
    if sew not in (32, 64):
        raise InstructionValidationError(insn, f"vfmsac.vv supports floating SEW=32/64 only, got SEW={sew}")

    chunk_n = _chunk_size(sew)
    c_bytes = _chunk_bytes()
    shift_amt = {32: 3, 64: 2}[sew]
    mask = chunk_n - 1

    vd_off = allocator.get_offset(vd)
    vs1_off = allocator.get_offset(vs1)
    vs2_off = allocator.get_offset(vs2)

    vtemps = VRegTempAllocator(insn)
    vd_vreg = vtemps.alloc_vreg()
    vs1_vreg = vtemps.alloc_vreg()
    vs2_vreg = vtemps.alloc_vreg()

    temps = context.temp_register_allocator
    vl_reg = temps.alloc_gpr()
    chunk_count = temps.alloc_gpr()
    tail_count = temps.alloc_gpr()
    vd_ptr = temps.alloc_gpr()
    vs1_ptr = temps.alloc_gpr()
    vs2_ptr = temps.alloc_gpr()

    vle_instr = _get_vle_instr(sew)
    vse_instr = _get_vse_instr(sew)

    lines.append(f"# vfmsac.vv {vd}, {vs1}, {vs2} (256-bit mode, SEW={sew})")
    lines.append(f"# Semantic: {vd}[i] = {vs1}[i] * {vs2}[i] - old {vd}[i]")
    lines.append("")

    _load_vl_from_csr(lines, vl_reg=vl_reg, addr_reg=chunk_count)
    lines.append(f"    srli    {chunk_count}, {vl_reg}, {shift_amt}       # {chunk_count} = vl / {chunk_n}")
    lines.append(f"    andi    {tail_count}, {vl_reg}, {mask}              # {tail_count} = vl % {chunk_n}")
    lines.append("")

    lines.append(f"    li      {vl_reg}, {vd_off:#x}")
    lines.append(f"    add     {vd_ptr}, t6, {vl_reg}              # {vd_ptr} = &{vd}")
    lines.append(f"    li      {vl_reg}, {vs1_off:#x}")
    lines.append(f"    add     {vs1_ptr}, t6, {vl_reg}             # {vs1_ptr} = &{vs1}")
    lines.append(f"    li      {vl_reg}, {vs2_off:#x}")
    lines.append(f"    add     {vs2_ptr}, t6, {vl_reg}             # {vs2_ptr} = &{vs2}")
    lines.append("")

    main_loop = new_label("vfmsac_vv_main")
    after_main = new_label("vfmsac_vv_after")

    lines.append(f"    # --- 主循环: 每块处理 {chunk_n} 个元素 ({c_bytes} 字节) ---")
    lines.append(f"    beqz    {chunk_count}, {after_main}")
    lines.append(f"{main_loop}:")
    _emit_vsetvl_for_chunk(lines, chunk_n, sew, "m1", vl_reg, scratch_reg=vl_reg)
    lines.append("")
    lines.append(f"    {vle_instr} {vd_vreg}, ({vd_ptr})          # 加载旧 {vd} 块 (subtrahend)")
    lines.append(f"    {vle_instr} {vs1_vreg}, ({vs1_ptr})         # 加载 {vs1} 块")
    lines.append(f"    {vle_instr} {vs2_vreg}, ({vs2_ptr})         # 加载 {vs2} 块")
    lines.append(f"    vfmsac.vv {vd_vreg}, {vs1_vreg}, {vs2_vreg}  # {vd}[i] = {vs1}[i] * {vs2}[i] - old {vd}[i]")
    lines.append(f"    {vse_instr} {vd_vreg}, ({vd_ptr}){mask_suffix}          # 写回 {vd} 块")
    lines.append("")
    lines.append(f"    addi    {vd_ptr}, {vd_ptr}, {c_bytes}")
    lines.append(f"    addi    {vs1_ptr}, {vs1_ptr}, {c_bytes}")
    lines.append(f"    addi    {vs2_ptr}, {vs2_ptr}, {c_bytes}")
    lines.append(f"    addi    {chunk_count}, {chunk_count}, -1")
    lines.append(f"    bnez    {chunk_count}, {main_loop}")
    lines.append(f"{after_main}:")
    lines.append("")

    lines.append(f"    # --- 尾部 RVV chunk: 剩余 {tail_count} 个元素 ---")
    end_label = new_label("vfmsac_vv_end")
    lines.append(f"    beqz    {tail_count}, {end_label}")
    lines.append(f"    vsetvli zero, {tail_count}, e{sew}, m1, ta, ma")
    lines.append(f"    {vle_instr} {vd_vreg}, ({vd_ptr})          # 加载旧 {vd} tail")
    lines.append(f"    {vle_instr} {vs1_vreg}, ({vs1_ptr})         # 加载 {vs1} tail")
    lines.append(f"    {vle_instr} {vs2_vreg}, ({vs2_ptr})         # 加载 {vs2} tail")
    lines.append(f"    vfmsac.vv {vd_vreg}, {vs1_vreg}, {vs2_vreg}  # tail: {vd}[i] = {vs1}[i] * {vs2}[i] - old {vd}[i]")
    lines.append(f"    {vse_instr} {vd_vreg}, ({vd_ptr}){mask_suffix}          # 写回 {vd} tail")
    lines.append(f"{end_label}:")

    return lines



def _build_vfsub_vv_lines(context) -> list[str]:
    """
    翻译 vfsub.vv 指令 (256-bit 模式)

    格式: vfsub.vv vd, vs2, vs1
    语义: vd[i] = vs2[i] - vs1[i] 对于 i in [0, vl)
    :return: 生成的汇编代码行列表
    """
    insn = context.instruction
    state = context.state
    allocator = context.layout
    new_label = context.new_label
    lines = []
    mask_suffix = ""
    operands = list(insn.operands)
    is_masked = False
    if len(operands) > 0 and str(operands[-1]).strip().endswith(".t"):
        is_masked = True
        operands = operands[:-1]
    if len(operands) < 3:
        raise InstructionValidationError(insn, f"Invalid operands for {insn.opcode}: {insn.op_str}")

    vd = operands[0]
    vs2 = operands[1]
    vs1 = operands[2]

    sew = state.sew
    chunk_n = _chunk_size(sew)
    c_bytes = _chunk_bytes()
    elem_bytes = sew // 8
    shift_amt = {8: 5, 16: 4, 32: 3, 64: 2}[sew]
    mask = chunk_n - 1

    vd_off = allocator.get_offset(vd)
    vs2_off = allocator.get_offset(vs2)
    vs1_off = allocator.get_offset(vs1)

    vtemps = VRegTempAllocator(insn)
    vs2_vreg = vtemps.alloc_vreg()
    vs1_vreg = vtemps.alloc_vreg()
    vd_vreg = vtemps.alloc_vreg()

    temps = TempRegisterAllocator(insn, reserved_gprs=("t6",), extra_avoid_fprs=("ft0", "ft1", "ft2"))
    vl_reg = temps.alloc_gpr()
    chunk_count = temps.alloc_gpr()
    tail_count = temps.alloc_gpr()
    vs2_ptr = temps.alloc_gpr()
    vs1_ptr = temps.alloc_gpr()
    vd_ptr = temps.alloc_gpr()
    temp = temps.alloc_gpr()
    if is_masked:
        mask_bit_idx = temps.alloc_gpr()
        v0_base = temps.alloc_gpr()


    vle_instr = _get_vle_instr(sew)
    vse_instr = _get_vse_instr(sew)

    lines.append(f"# vfsub.vv {vd}, {vs2}, {vs1} (256-bit mode, SEW={sew})")
    lines.append(f"# Semantic: {vd}[i] = {vs2}[i] - {vs1}[i]")
    lines.append("")

    if is_masked:
        _emit_mask_setup(lines, mask_bit_idx, v0_base, temp)

    _load_vl_from_csr(lines, vl_reg=vl_reg, addr_reg=chunk_count)
    lines.append(f"    srli    {chunk_count}, {vl_reg}, {shift_amt}       # {chunk_count} = vl / {chunk_n}")
    lines.append(f"    andi    {tail_count}, {vl_reg}, {mask}              # {tail_count} = vl % {chunk_n}")
    lines.append("")

    lines.append(f"    li      {vl_reg}, {vs2_off:#x}")
    lines.append(f"    add     {vs2_ptr}, t6, {vl_reg}            # {vs2_ptr} = &{vs2}")
    lines.append(f"    li      {vl_reg}, {vs1_off:#x}")
    lines.append(f"    add     {vs1_ptr}, t6, {vl_reg}            # {vs1_ptr} = &{vs1}")
    lines.append(f"    li      {vl_reg}, {vd_off:#x}")
    lines.append(f"    add     {vd_ptr}, t6, {vl_reg}             # {vd_ptr} = &{vd}")
    lines.append("")

    # ========== 主循环 (256-bit 块) ==========
    main_loop = new_label("vfsub_vv_main")
    after_main = new_label("vfsub_vv_after")

    lines.append(f"    # --- 主循环: 每块处理 {chunk_n} 个元素 ({c_bytes} 字节) ---")
    lines.append(f"    beqz    {chunk_count}, {after_main}")
    lines.append(f"{main_loop}:")
    mask_suffix = ", v0.t" if is_masked else ""
    if is_masked:
        _emit_mask_extraction_chunk(lines, sew, mask_bit_idx, v0_base, vl_reg, temp)

    _emit_vsetvl_for_chunk(lines, chunk_n, sew, "m1", vl_reg, scratch_reg=temp)
    lines.append("")
    lines.append(f"    {vle_instr} {vs2_vreg}, ({vs2_ptr})         # 加载 {vs2} 块")
    lines.append(f"    {vle_instr} {vs1_vreg}, ({vs1_ptr})         # 加载 {vs1} 块")
    lines.append(f"    vfsub.vv {vd_vreg}, {vs2_vreg}, {vs1_vreg}{mask_suffix}    # {vd}[i] = {vs2}[i] - {vs1}[i]")
    lines.append(f"    {vse_instr} {vd_vreg}, ({vd_ptr}){mask_suffix}          # 写回 {vd} 块")
    lines.append("")
    lines.append(f"    addi    {vs2_ptr}, {vs2_ptr}, {c_bytes}")
    lines.append(f"    addi    {vs1_ptr}, {vs1_ptr}, {c_bytes}")
    lines.append(f"    addi    {vd_ptr}, {vd_ptr}, {c_bytes}")
    if is_masked:
        lines.append(f"    addi    {mask_bit_idx}, {mask_bit_idx}, {chunk_n}")
    lines.append(f"    addi    {chunk_count}, {chunk_count}, -1")
    lines.append(f"    bnez    {chunk_count}, {main_loop}")
    lines.append(f"{after_main}:")
    lines.append("")

    # ========== 尾部标量回退 ==========
    lines.append(f"    # --- 尾部标量回退: 剩余 {tail_count} 个元素 ---")
    tail_loop = new_label("vfsub_vv_tail")
    end_label = new_label("vfsub_vv_end")
    _emit_scalar_tail_vv(lines, sew, tail_count, vs2_ptr, vs1_ptr, vd_ptr,
                         tail_label=tail_loop, end_label=end_label,
                         op_type='sub',
        is_masked=is_masked,
        mask_bit_idx=mask_bit_idx if is_masked else '',
        v0_base=v0_base if is_masked else '',
        mask_tmp1=vl_reg,
        mask_tmp2=temp,
    )

    return lines



def _build_vfmul_vv_lines(context) -> list[str]:
    """
    翻译 vfmul.vv 指令 (256-bit 模式)

    格式: vfmul.vv vd, vs2, vs1
    语义: vd[i] = vs2[i] * vs1[i] 对于 i in [0, vl)
    :return: 生成的汇编代码行列表
    """
    insn = context.instruction
    state = context.state
    allocator = context.layout
    new_label = context.new_label
    lines = []
    mask_suffix = ""
    operands = list(insn.operands)
    is_masked = False
    if len(operands) > 0 and str(operands[-1]).strip().endswith(".t"):
        is_masked = True
        operands = operands[:-1]
    if len(operands) < 3:
        raise InstructionValidationError(insn, f"Invalid operands for {insn.opcode}: {insn.op_str}")

    vd = operands[0]
    vs2 = operands[1]
    vs1 = operands[2]

    sew = state.sew
    chunk_n = _chunk_size(sew)
    c_bytes = _chunk_bytes()
    elem_bytes = sew // 8
    shift_amt = {8: 5, 16: 4, 32: 3, 64: 2}[sew]
    mask = chunk_n - 1

    vd_off = allocator.get_offset(vd)
    vs2_off = allocator.get_offset(vs2)
    vs1_off = allocator.get_offset(vs1)

    vtemps = VRegTempAllocator(insn)
    vs2_vreg = vtemps.alloc_vreg()
    vs1_vreg = vtemps.alloc_vreg()
    vd_vreg = vtemps.alloc_vreg()

    temps = TempRegisterAllocator(insn, reserved_gprs=("t6",), extra_avoid_fprs=("ft0", "ft1", "ft2"))
    vl_reg = temps.alloc_gpr()
    chunk_count = temps.alloc_gpr()
    tail_count = temps.alloc_gpr()
    vs2_ptr = temps.alloc_gpr()
    vs1_ptr = temps.alloc_gpr()
    vd_ptr = temps.alloc_gpr()
    temp = temps.alloc_gpr()
    if is_masked:
        mask_bit_idx = temps.alloc_gpr()
        v0_base = temps.alloc_gpr()


    vle_instr = _get_vle_instr(sew)
    vse_instr = _get_vse_instr(sew)

    lines.append(f"# vfmul.vv {vd}, {vs2}, {vs1} (256-bit mode, SEW={sew})")
    lines.append(f"# Semantic: {vd}[i] = {vs2}[i] * {vs1}[i]")
    lines.append("")

    if is_masked:
        _emit_mask_setup(lines, mask_bit_idx, v0_base, temp)

    _load_vl_from_csr(lines, vl_reg=vl_reg, addr_reg=chunk_count)
    lines.append(f"    srli    {chunk_count}, {vl_reg}, {shift_amt}       # {chunk_count} = vl / {chunk_n}")
    lines.append(f"    andi    {tail_count}, {vl_reg}, {mask}              # {tail_count} = vl % {chunk_n}")
    lines.append("")

    # 之后 vl_reg 不再使用，可复用为临时寄存器做 li（不破坏 tail_count）
    lines.append(f"    li      {vl_reg}, {vs2_off:#x}")
    lines.append(f"    add     {vs2_ptr}, t6, {vl_reg}             # {vs2_ptr} = &{vs2}")
    lines.append(f"    li      {vl_reg}, {vs1_off:#x}")
    lines.append(f"    add     {vs1_ptr}, t6, {vl_reg}             # {vs1_ptr} = &{vs1}")
    lines.append(f"    li      {vl_reg}, {vd_off:#x}")
    lines.append(f"    add     {vd_ptr}, t6, {vl_reg}              # {vd_ptr} = &{vd}")
    lines.append("")

    # ========== 主循环 (256-bit 块) ==========
    main_loop = new_label("vfmul_vv_main")
    after_main = new_label("vfmul_vv_after")

    lines.append(f"    # --- 主循环: 每块处理 {chunk_n} 个元素 ({c_bytes} 字节) ---")
    lines.append(f"    beqz    {chunk_count}, {after_main}")
    lines.append(f"{main_loop}:")
    mask_suffix = ", v0.t" if is_masked else ""
    if is_masked:
        _emit_mask_extraction_chunk(lines, sew, mask_bit_idx, v0_base, vl_reg, temp)

    _emit_vsetvl_for_chunk(lines, chunk_n, sew, "m1", vl_reg, scratch_reg=temp)
    lines.append("")
    lines.append(f"    {vle_instr} {vs2_vreg}, ({vs2_ptr})         # 加载 {vs2} 块")
    lines.append(f"    {vle_instr} {vs1_vreg}, ({vs1_ptr})         # 加载 {vs1} 块")
    lines.append(f"    vfmul.vv {vd_vreg}, {vs2_vreg}, {vs1_vreg}{mask_suffix}    # {vd}[i] = {vs2}[i] * {vs1}[i]")
    lines.append(f"    {vse_instr} {vd_vreg}, ({vd_ptr}){mask_suffix}          # 写回 {vd} 块")
    lines.append("")
    lines.append(f"    addi    {vs2_ptr}, {vs2_ptr}, {c_bytes}")
    lines.append(f"    addi    {vs1_ptr}, {vs1_ptr}, {c_bytes}")
    lines.append(f"    addi    {vd_ptr}, {vd_ptr}, {c_bytes}")
    if is_masked:
        lines.append(f"    addi    {mask_bit_idx}, {mask_bit_idx}, {chunk_n}")
    lines.append(f"    addi    {chunk_count}, {chunk_count}, -1")
    lines.append(f"    bnez    {chunk_count}, {main_loop}")
    lines.append(f"{after_main}:")
    lines.append("")

    # ========== 尾部标量回退 ==========
    lines.append(f"    # --- 尾部标量回退: 剩余 {tail_count} 个元素 ---")
    tail_loop = new_label("vfmul_vv_tail")
    end_label = new_label("vfmul_vv_end")
    _emit_scalar_tail_vv(lines, sew, tail_count, vs2_ptr, vs1_ptr, vd_ptr,
                         tail_label=tail_loop, end_label=end_label,
                         op_type='mul',
        is_masked=is_masked,
        mask_bit_idx=mask_bit_idx if is_masked else '',
        v0_base=v0_base if is_masked else '',
        mask_tmp1=vl_reg,
        mask_tmp2=temp,
    )

    return lines



def _build_vfdiv_vv_lines(context) -> list[str]:
    """
    翻译 vfdiv.vv 指令 (256-bit 模式)

    格式: vfdiv.vv vd, vs2, vs1
    语义: vd[i] = vs2[i] / vs1[i] 对于 i in [0, vl)

    新增指令采用 RVV tail chunk，而不是手写标量尾部。
    """
    insn = context.instruction
    state = context.state
    allocator = context.layout
    new_label = context.new_label
    lines = []
    mask_suffix = ""
    operands = list(insn.operands)
    is_masked = False
    if len(operands) > 0 and str(operands[-1]).strip().endswith(".t"):
        is_masked = True
        operands = operands[:-1]
    if len(operands) < 3:
        raise InstructionValidationError(insn, f"Invalid operands for {insn.opcode}: {insn.op_str}")

    vd = operands[0]
    vs2 = operands[1]
    vs1 = operands[2]

    sew = state.sew
    if sew not in (32, 64):
        raise InstructionValidationError(insn, f"vfdiv.vv supports floating SEW=32/64 only, got SEW={sew}")

    chunk_n = _chunk_size(sew)
    c_bytes = _chunk_bytes()
    shift_amt = {32: 3, 64: 2}[sew]
    mask = chunk_n - 1

    vd_off = allocator.get_offset(vd)
    vs2_off = allocator.get_offset(vs2)
    vs1_off = allocator.get_offset(vs1)

    vtemps = VRegTempAllocator(insn)
    vs2_vreg = vtemps.alloc_vreg()
    vs1_vreg = vtemps.alloc_vreg()
    vd_vreg = vtemps.alloc_vreg()

    temps = context.temp_register_allocator
    vl_reg = temps.alloc_gpr()
    chunk_count = temps.alloc_gpr()
    tail_count = temps.alloc_gpr()
    vs2_ptr = temps.alloc_gpr()
    vs1_ptr = temps.alloc_gpr()
    vd_ptr = temps.alloc_gpr()
    temp = temps.alloc_gpr()
    if is_masked:
        mask_bit_idx = temps.alloc_gpr()
        v0_base = temps.alloc_gpr()


    vle_instr = _get_vle_instr(sew)
    vse_instr = _get_vse_instr(sew)

    lines.append(f"# vfdiv.vv {vd}, {vs2}, {vs1} (256-bit mode, SEW={sew})")
    lines.append(f"# Semantic: {vd}[i] = {vs2}[i] / {vs1}[i]")
    lines.append("")

    if is_masked:
        _emit_mask_setup(lines, mask_bit_idx, v0_base, temp)

    _load_vl_from_csr(lines, vl_reg=vl_reg, addr_reg=chunk_count)
    lines.append(f"    srli    {chunk_count}, {vl_reg}, {shift_amt}       # {chunk_count} = vl / {chunk_n}")
    lines.append(f"    andi    {tail_count}, {vl_reg}, {mask}              # {tail_count} = vl % {chunk_n}")
    lines.append("")

    lines.append(f"    li      {vl_reg}, {vs2_off:#x}")
    lines.append(f"    add     {vs2_ptr}, t6, {vl_reg}             # {vs2_ptr} = &{vs2}")
    lines.append(f"    li      {vl_reg}, {vs1_off:#x}")
    lines.append(f"    add     {vs1_ptr}, t6, {vl_reg}             # {vs1_ptr} = &{vs1}")
    lines.append(f"    li      {vl_reg}, {vd_off:#x}")
    lines.append(f"    add     {vd_ptr}, t6, {vl_reg}              # {vd_ptr} = &{vd}")
    lines.append("")

    main_loop = new_label("vfdiv_vv_main")
    after_main = new_label("vfdiv_vv_after")

    lines.append(f"    # --- 主循环: 每块处理 {chunk_n} 个元素 ({c_bytes} 字节) ---")
    lines.append(f"    beqz    {chunk_count}, {after_main}")
    lines.append(f"{main_loop}:")
    mask_suffix = ", v0.t" if is_masked else ""
    if is_masked:
        _emit_mask_extraction_chunk(lines, sew, mask_bit_idx, v0_base, vl_reg, temp)

    _emit_vsetvl_for_chunk(lines, chunk_n, sew, "m1", vl_reg, scratch_reg=temp)
    lines.append("")
    lines.append(f"    {vle_instr} {vs2_vreg}, ({vs2_ptr})         # 加载 {vs2} 块")
    lines.append(f"    {vle_instr} {vs1_vreg}, ({vs1_ptr})         # 加载 {vs1} 块")
    lines.append(f"    vfdiv.vv {vd_vreg}, {vs2_vreg}, {vs1_vreg}{mask_suffix}    # {vd}[i] = {vs2}[i] / {vs1}[i]")
    lines.append(f"    {vse_instr} {vd_vreg}, ({vd_ptr}){mask_suffix}          # 写回 {vd} 块")
    lines.append("")
    lines.append(f"    addi    {vs2_ptr}, {vs2_ptr}, {c_bytes}")
    lines.append(f"    addi    {vs1_ptr}, {vs1_ptr}, {c_bytes}")
    lines.append(f"    addi    {vd_ptr}, {vd_ptr}, {c_bytes}")
    if is_masked:
        lines.append(f"    addi    {mask_bit_idx}, {mask_bit_idx}, {chunk_n}")
    lines.append(f"    addi    {chunk_count}, {chunk_count}, -1")
    lines.append(f"    bnez    {chunk_count}, {main_loop}")
    lines.append(f"{after_main}:")
    lines.append("")

    lines.append(f"    # --- 尾部 RVV chunk: 剩余 {tail_count} 个元素 ---")
    end_label = new_label("vfdiv_vv_end")
    lines.append(f"    beqz    {tail_count}, {end_label}")
    lines.append(f"    vsetvli zero, {tail_count}, e{sew}, m1, ta, ma")
    lines.append(f"    {vle_instr} {vs2_vreg}, ({vs2_ptr})         # 加载 {vs2} tail")
    lines.append(f"    {vle_instr} {vs1_vreg}, ({vs1_ptr})         # 加载 {vs1} tail")
    lines.append(f"    vfdiv.vv {vd_vreg}, {vs2_vreg}, {vs1_vreg}{mask_suffix}    # tail: {vd}[i] = {vs2}[i] / {vs1}[i]")
    lines.append(f"    {vse_instr} {vd_vreg}, ({vd_ptr}){mask_suffix}          # 写回 {vd} tail")
    lines.append(f"{end_label}:")

    return lines



def _build_vfabs_v_lines(context) -> list[str]:
    """
    翻译 vfabs.v 指令 (256-bit 模式)

    格式: vfabs.v vd, vs2
    语义: vd[i] = abs(vs2[i]) 对于 i in [0, vl)
    :return: 生成的汇编代码行列表
    """
    insn = context.instruction
    state = context.state
    allocator = context.layout
    new_label = context.new_label
    lines = []
    mask_suffix = ""
    operands = insn.operands
    if len(operands) < 2:
        raise InstructionValidationError(insn, f"Invalid operands for {insn.opcode}: {insn.op_str}")

    vd = operands[0]
    vs2 = operands[1]

    sew = state.sew
    chunk_n = _chunk_size(sew)
    c_bytes = _chunk_bytes()
    elem_bytes = sew // 8
    shift_amt = {8: 5, 16: 4, 32: 3, 64: 2}[sew]
    mask = chunk_n - 1

    vd_off = allocator.get_offset(vd)
    vs2_off = allocator.get_offset(vs2)

    vtemps = VRegTempAllocator(insn)
    vs2_vreg = vtemps.alloc_vreg()
    vd_vreg = vtemps.alloc_vreg()

    temps = TempRegisterAllocator(insn, reserved_gprs=("t6",), extra_avoid_fprs=("ft0",))
    vl_reg = temps.alloc_gpr()
    chunk_count = temps.alloc_gpr()
    tail_count = temps.alloc_gpr()
    vs2_ptr = temps.alloc_gpr()
    vd_ptr = temps.alloc_gpr()
    temp = temps.alloc_gpr()

    vle_instr = _get_vle_instr(sew)
    vse_instr = _get_vse_instr(sew)

    lines.append(f"# vfabs.v {vd}, {vs2} (256-bit mode, SEW={sew})")
    lines.append(f"# Semantic: {vd}[i] = abs({vs2}[i])")
    lines.append("")

    _load_vl_from_csr(lines, vl_reg=vl_reg, addr_reg=chunk_count)
    lines.append(f"    srli    {chunk_count}, {vl_reg}, {shift_amt}       # {chunk_count} = vl / {chunk_n}")
    lines.append(f"    andi    {tail_count}, {vl_reg}, {mask}              # {tail_count} = vl % {chunk_n}")
    lines.append("")

    lines.append(f"    li      {temp}, {vs2_off:#x}")
    lines.append(f"    add     {vs2_ptr}, t6, {temp}            # {vs2_ptr} = &{vs2}")
    lines.append(f"    li      {temp}, {vd_off:#x}")
    lines.append(f"    add     {vd_ptr}, t6, {temp}             # {vd_ptr} = &{vd}")
    lines.append("")

    # ========== 主循环 (256-bit 块) ==========
    main_loop = new_label("vfabs_v_main")
    after_main = new_label("vfabs_v_after")

    lines.append(f"    # --- 主循环: 每块处理 {chunk_n} 个元素 ({c_bytes} 字节) ---")
    lines.append(f"    beqz    {chunk_count}, {after_main}")
    _emit_vsetvl_for_chunk(lines, chunk_n, sew, "m1", vl_reg, scratch_reg=temp)
    lines.append(f"{main_loop}:")
    lines.append("")
    lines.append(f"    {vle_instr} {vs2_vreg}, ({vs2_ptr})         # 加载 {vs2} 块")
    lines.append(f"    vfabs.v {vd_vreg}, {vs2_vreg}                  # {vd}[i] = abs({vs2}[i])")
    lines.append(f"    {vse_instr} {vd_vreg}, ({vd_ptr}){mask_suffix}          # 写回 {vd} 块")
    lines.append("")
    lines.append(f"    addi    {vs2_ptr}, {vs2_ptr}, {c_bytes}")
    lines.append(f"    addi    {vd_ptr}, {vd_ptr}, {c_bytes}")
    lines.append(f"    addi    {chunk_count}, {chunk_count}, -1")
    lines.append(f"    bnez    {chunk_count}, {main_loop}")
    lines.append(f"{after_main}:")
    lines.append("")

    # ========== 尾部标量回退 ==========
    tail_loop = new_label("vfabs_v_tail")
    end_label = new_label("vfabs_v_end")

    load_instr = _get_float_instr('load', sew)
    store_instr = _get_float_instr('store', sew)
    abs_instr = _get_float_instr('abs', sew)

    lines.append(f"    # --- 尾部标量回退: 剩余 {tail_count} 个元素 ---")
    lines.append(f"{tail_loop}:")
    lines.append(f"    beqz    {tail_count}, {end_label}")
    lines.append(f"    {load_instr:<8} ft0, 0({vs2_ptr})           # ft0 = {vs2}[i]")
    lines.append(f"    {abs_instr:<8} ft0, ft0                      # ft0 = abs(ft0)")
    lines.append(f"    {store_instr:<8} ft0, 0({vd_ptr})           # {vd}[i] = ft0")
    lines.append(f"    addi    {vs2_ptr}, {vs2_ptr}, {elem_bytes}")
    lines.append(f"    addi    {vd_ptr}, {vd_ptr}, {elem_bytes}")
    lines.append(f"    addi    {tail_count}, {tail_count}, -1")
    lines.append(f"    j       {tail_loop}")
    lines.append(f"{end_label}:")

    return lines



def _build_vfneg_v_lines(context) -> list[str]:
    """
    翻译 vfneg.v 指令 (256-bit 模式)

    格式: vfneg.v vd, vs2
    语义: vd[i] = -vs2[i] 对于 i in [0, vl)
    :return: 生成的汇编代码行列表
    """
    insn = context.instruction
    state = context.state
    allocator = context.layout
    new_label = context.new_label
    lines = []
    mask_suffix = ""
    operands = list(insn.operands)
    is_masked = False
    if len(operands) > 0 and str(operands[-1]).strip().endswith(".t"):
        is_masked = True
        operands = operands[:-1]
    if len(operands) < 2:
        raise InstructionValidationError(insn, f"Invalid operands for {insn.opcode}: {insn.op_str}")

    vd = operands[0]
    vs2 = operands[1]

    sew = state.sew
    chunk_n = _chunk_size(sew)
    c_bytes = _chunk_bytes()
    elem_bytes = sew // 8
    shift_amt = {8: 5, 16: 4, 32: 3, 64: 2}[sew]
    mask = chunk_n - 1

    vd_off = allocator.get_offset(vd)
    vs2_off = allocator.get_offset(vs2)

    vtemps = VRegTempAllocator(insn)
    vs2_vreg = vtemps.alloc_vreg()
    vd_vreg = vtemps.alloc_vreg()

    temps = TempRegisterAllocator(insn, reserved_gprs=("t6",), extra_avoid_fprs=("ft0",))
    vl_reg = temps.alloc_gpr()
    chunk_count = temps.alloc_gpr()
    tail_count = temps.alloc_gpr()
    vs2_ptr = temps.alloc_gpr()
    vd_ptr = temps.alloc_gpr()
    temp = temps.alloc_gpr()

    if is_masked:
        mask_bit_idx = temps.alloc_gpr()
        v0_base = temps.alloc_gpr()

    vle_instr = _get_vle_instr(sew)
    vse_instr = _get_vse_instr(sew)

    lines.append(f"# vfneg.v {vd}, {vs2} (256-bit mode, SEW={sew})")
    lines.append(f"# Semantic: {vd}[i] = -{vs2}[i]")
    lines.append("")

    if is_masked:
        _emit_mask_setup(lines, mask_bit_idx, v0_base, temp)

    _load_vl_from_csr(lines, vl_reg=vl_reg, addr_reg=chunk_count)
    lines.append(f"    srli    {chunk_count}, {vl_reg}, {shift_amt}       # {chunk_count} = vl / {chunk_n}")
    lines.append(f"    andi    {tail_count}, {vl_reg}, {mask}              # {tail_count} = vl % {chunk_n}")
    lines.append("")

    lines.append(f"    li      {temp}, {vs2_off:#x}")
    lines.append(f"    add     {vs2_ptr}, t6, {temp}            # {vs2_ptr} = &{vs2}")
    lines.append(f"    li      {temp}, {vd_off:#x}")
    lines.append(f"    add     {vd_ptr}, t6, {temp}             # {vd_ptr} = &{vd}")
    lines.append("")

    # ========== 主循环 (256-bit 块) ==========
    main_loop = new_label("vfneg_v_main")
    after_main = new_label("vfneg_v_after")

    lines.append(f"    # --- 主循环: 每块处理 {chunk_n} 个元素 ({c_bytes} 字节) ---")
    lines.append(f"    beqz    {chunk_count}, {after_main}")
    lines.append(f"{main_loop}:")
    mask_suffix = ", v0.t" if is_masked else ""
    if is_masked:
        _emit_mask_extraction_chunk(lines, sew, mask_bit_idx, v0_base, vl_reg, temp)

    _emit_vsetvl_for_chunk(lines, chunk_n, sew, "m1", vl_reg, scratch_reg=temp)
    lines.append("")
    lines.append(f"    {vle_instr} {vs2_vreg}, ({vs2_ptr})         # 加载 {vs2} 块")
    lines.append(f"    vfneg.v {vd_vreg}, {vs2_vreg}{mask_suffix}                  # {vd}[i] = -{vs2}[i]")
    lines.append(f"    {vse_instr} {vd_vreg}, ({vd_ptr}){mask_suffix}          # 写回 {vd} 块")
    lines.append("")
    lines.append(f"    addi    {vs2_ptr}, {vs2_ptr}, {c_bytes}")
    lines.append(f"    addi    {vd_ptr}, {vd_ptr}, {c_bytes}")
    if is_masked:
        lines.append(f"    addi    {mask_bit_idx}, {mask_bit_idx}, {chunk_n}")
    lines.append(f"    addi    {chunk_count}, {chunk_count}, -1")
    lines.append(f"    bnez    {chunk_count}, {main_loop}")
    lines.append(f"{after_main}:")
    lines.append("")

    # ========== 尾部标量回退 ==========
    tail_loop = new_label("vfneg_v_tail")
    end_label = new_label("vfneg_v_end")

    load_instr = _get_float_instr('load', sew)
    store_instr = _get_float_instr('store', sew)
    neg_instr = _get_float_instr('neg', sew)

    lines.append(f"    # --- 尾部标量回退: 剩余 {tail_count} 个元素 ---")
    lines.append(f"{tail_loop}:")
    lines.append(f"    beqz    {tail_count}, {end_label}")
    lines.append(f"    {load_instr:<8} ft0, 0({vs2_ptr})           # ft0 = {vs2}[i]")
    lines.append(f"    {neg_instr:<8} ft0, ft0                      # ft0 = -ft0")
    lines.append(f"    {store_instr:<8} ft0, 0({vd_ptr})           # {vd}[i] = ft0")
    lines.append(f"    addi    {vs2_ptr}, {vs2_ptr}, {elem_bytes}")
    lines.append(f"    addi    {vd_ptr}, {vd_ptr}, {elem_bytes}")
    lines.append(f"    addi    {tail_count}, {tail_count}, -1")
    lines.append(f"    j       {tail_loop}")
    lines.append(f"{end_label}:")

    return lines



def _build_vfnmsac_vf_lines(context) -> list[str]:
    """
    翻译 vfnmsac.vf 指令 (256-bit 模式)

    格式: vfnmsac.vf vd, rs1, vs2
    语义: vd[i] = vd[i] - rs1 * vs2[i] 对于 i in [0, vl)
    :return: 生成的汇编代码行列表
    """
    insn = context.instruction
    state = context.state
    allocator = context.layout
    new_label = context.new_label
    lines = []
    mask_suffix = ""
    operands = list(insn.operands)
    if len(operands) > 0 and str(operands[-1]).strip().endswith(".t"):
        raise InstructionValidationError(insn, "conservative vfnmsac.vf does not support masked form")
    if len(operands) < 3:
        raise InstructionValidationError(insn, f"Invalid operands for {insn.opcode}: {insn.op_str}")

    vd = operands[0]
    rs1 = str(operands[1])
    vs2 = operands[2]

    sew = state.sew
    chunk_n = _chunk_size(sew)
    c_bytes = _chunk_bytes()
    elem_bytes = sew // 8
    shift_amt = {8: 5, 16: 4, 32: 3, 64: 2}[sew]
    mask = chunk_n - 1

    vd_off = allocator.get_offset(vd)
    vs2_off = allocator.get_offset(vs2)

    vtemps = VRegTempAllocator(insn)
    vs2_vreg = vtemps.alloc_vreg()
    vd_vreg = vtemps.alloc_vreg()

    temps = context.temp_register_allocator
    vl_reg = temps.alloc_gpr()
    chunk_count = temps.alloc_gpr()
    tail_count = temps.alloc_gpr()
    vs2_ptr = temps.alloc_gpr()
    vd_ptr = temps.alloc_gpr()
    temp = temps.alloc_gpr()
    tail_vs2_fpr = temps.alloc_fpr()
    tail_vd_fpr = temps.alloc_fpr()

    vle_instr = _get_vle_instr(sew)
    vse_instr = _get_vse_instr(sew)

    lines.append(f"# vfnmsac.vf {vd}, {rs1}, {vs2} (256-bit mode, SEW={sew})")
    lines.append(f"# Semantic: {vd}[i] = {vd}[i] - {rs1} * {vs2}[i]")
    lines.append("")

    _load_vl_from_csr(lines, vl_reg=vl_reg, addr_reg=chunk_count)
    lines.append(f"    srli    {chunk_count}, {vl_reg}, {shift_amt}       # {chunk_count} = vl / {chunk_n}")
    lines.append(f"    andi    {tail_count}, {vl_reg}, {mask}              # {tail_count} = vl % {chunk_n}")
    lines.append("")

    lines.append(f"    li      {temp}, {vs2_off:#x}")
    lines.append(f"    add     {vs2_ptr}, t6, {temp}            # {vs2_ptr} = &{vs2}")
    lines.append(f"    li      {temp}, {vd_off:#x}")
    lines.append(f"    add     {vd_ptr}, t6, {temp}             # {vd_ptr} = &{vd}")
    lines.append("")

    # ========== 主循环 (256-bit 块) ==========
    main_loop = new_label("vfnmsac_vf_main")
    after_main = new_label("vfnmsac_vf_after")

    lines.append(f"    # --- 主循环: 每块处理 {chunk_n} 个元素 ({c_bytes} 字节) ---")
    lines.append(f"    beqz    {chunk_count}, {after_main}")
    _emit_vsetvl_for_chunk(lines, chunk_n, sew, "m1", vl_reg, scratch_reg=temp)
    lines.append(f"{main_loop}:")
    lines.append("")
    lines.append(f"    {vle_instr} {vs2_vreg}, ({vs2_ptr})         # 加载 {vs2} 块")
    lines.append(f"    {vle_instr} {vd_vreg}, ({vd_ptr})          # 加载 {vd} 块 (累加器)")
    lines.append(f"    vfnmsac.vf {vd_vreg}, {rs1}, {vs2_vreg}       # {vd}[i] -= {rs1} * {vs2}[i]")
    lines.append(f"    {vse_instr} {vd_vreg}, ({vd_ptr}){mask_suffix}          # 写回 {vd} 块")
    lines.append("")
    lines.append(f"    addi    {vs2_ptr}, {vs2_ptr}, {c_bytes}")
    lines.append(f"    addi    {vd_ptr}, {vd_ptr}, {c_bytes}")
    lines.append(f"    addi    {chunk_count}, {chunk_count}, -1")
    lines.append(f"    bnez    {chunk_count}, {main_loop}")
    lines.append(f"{after_main}:")
    lines.append("")

    # ========== 尾部标量回退 ==========
    tail_loop = new_label("vfnmsac_vf_tail")
    end_label = new_label("vfnmsac_vf_end")
    _emit_scalar_tail_vf(lines, sew, tail_count, vs2_ptr, vd_ptr, rs1,
                         tail_vs2_fpr, tail_vd_fpr,
                         tail_label=tail_loop, end_label=end_label,
                         op_type='nmsub',
        mask_tmp1=vl_reg,
        mask_tmp2=temp)

    return lines



def _build_vfcvt_f_x_v_lines(context) -> list[str]:
    """
    翻译 vfcvt.f.x.v 指令 (256-bit 模式)

    格式: vfcvt.f.x.v vd, vs2
    语义: vd[i] = float(vs2[i]) (signed integer to float, 相同 SEW)
    :return: 生成的汇编代码行列表
    """
    insn = context.instruction
    state = context.state
    allocator = context.layout
    new_label = context.new_label
    lines = []
    mask_suffix = ""
    operands = insn.operands
    if len(operands) < 2:
        raise InstructionValidationError(insn, f"Invalid operands for {insn.opcode}: {insn.op_str}")

    vd = operands[0]
    vs2 = operands[1]

    sew = state.sew
    chunk_n = _chunk_size(sew)
    c_bytes = _chunk_bytes()
    elem_bytes = sew // 8
    shift_amt = {8: 5, 16: 4, 32: 3, 64: 2}[sew]
    mask = chunk_n - 1

    vd_off = allocator.get_offset(vd)
    vs2_off = allocator.get_offset(vs2)

    vtemps = VRegTempAllocator(insn)
    vs2_vreg = vtemps.alloc_vreg()
    vd_vreg = vtemps.alloc_vreg()

    temps = TempRegisterAllocator(insn, reserved_gprs=("t6",), extra_avoid_fprs=("ft0",))
    vl_reg = temps.alloc_gpr()
    chunk_count = temps.alloc_gpr()
    tail_count = temps.alloc_gpr()
    vs2_ptr = temps.alloc_gpr()
    vd_ptr = temps.alloc_gpr()
    temp = temps.alloc_gpr()

    vle_instr = _get_vle_instr(sew)
    vse_instr = _get_vse_instr(sew)
    int_load_instr = {8: 'lb', 16: 'lh', 32: 'lw', 64: 'ld'}[sew]
    float_store_instr = _get_float_instr('store', sew)

    if sew == 32:
        fcvt_instr = "fcvt.s.l"
    elif sew == 64:
        fcvt_instr = "fcvt.d.l"
    else:
        raise InstructionValidationError(insn, f"vfcvt.f.x.v 不支持 SEW={sew}")

    lines.append(f"# vfcvt.f.x.v {vd}, {vs2} (256-bit mode, SEW={sew})")
    lines.append(f"# Semantic: {vd}[i] = float({vs2}[i]) (signed)")
    lines.append("")

    _load_vl_from_csr(lines, vl_reg=vl_reg, addr_reg=chunk_count)
    lines.append(f"    srli    {chunk_count}, {vl_reg}, {shift_amt}       # {chunk_count} = vl / {chunk_n}")
    lines.append(f"    andi    {tail_count}, {vl_reg}, {mask}              # {tail_count} = vl % {chunk_n}")
    lines.append("")

    lines.append(f"    li      {temp}, {vs2_off:#x}")
    lines.append(f"    add     {vs2_ptr}, t6, {temp}            # {vs2_ptr} = &{vs2}")
    lines.append(f"    li      {temp}, {vd_off:#x}")
    lines.append(f"    add     {vd_ptr}, t6, {temp}             # {vd_ptr} = &{vd}")
    lines.append("")

    # ========== 主循环 (256-bit 块) ==========
    main_loop = new_label("vfcvt_f_x_v_main")
    after_main = new_label("vfcvt_f_x_v_after")

    lines.append(f"    # --- 主循环: 每块处理 {chunk_n} 个元素 ({c_bytes} 字节) ---")
    lines.append(f"    beqz    {chunk_count}, {after_main}")
    lines.append(f"{main_loop}:")
    _emit_vsetvl_for_chunk(lines, chunk_n, sew, "m1", vl_reg, scratch_reg=temp)
    lines.append("")
    lines.append(f"    {vle_instr} {vs2_vreg}, ({vs2_ptr})         # 加载 {vs2} 块 (int{sew})")
    lines.append(f"    vfcvt.f.x.v {vd_vreg}, {vs2_vreg}              # {vd}[i] = float({vs2}[i])")
    lines.append(f"    {vse_instr} {vd_vreg}, ({vd_ptr}){mask_suffix}          # 写回 {vd} 块 (float)")
    lines.append("")
    lines.append(f"    addi    {vs2_ptr}, {vs2_ptr}, {c_bytes}")
    lines.append(f"    addi    {vd_ptr}, {vd_ptr}, {c_bytes}")
    lines.append(f"    addi    {chunk_count}, {chunk_count}, -1")
    lines.append(f"    bnez    {chunk_count}, {main_loop}")
    lines.append(f"{after_main}:")
    lines.append("")

    # ========== 尾部标量回退 ==========
    tail_loop = new_label("vfcvt_f_x_v_tail")
    end_label = new_label("vfcvt_f_x_v_end")

    lines.append(f"    # --- 尾部标量回退: 剩余 {tail_count} 个元素 (int -> float) ---")
    lines.append(f"{tail_loop}:")
    lines.append(f"    beqz    {tail_count}, {end_label}")
    lines.append(f"    {int_load_instr:<8} {temp}, 0({vs2_ptr})            # {temp} = {vs2}[i] (int{sew})")
    lines.append(f"    {fcvt_instr:<12} ft0, {temp}              # ft0 = float({temp})")
    lines.append(f"    {float_store_instr:<8} ft0, 0({vd_ptr})            # {vd}[i] = ft0")
    lines.append(f"    addi    {vs2_ptr}, {vs2_ptr}, {elem_bytes}")
    lines.append(f"    addi    {vd_ptr}, {vd_ptr}, {elem_bytes}")
    lines.append(f"    addi    {tail_count}, {tail_count}, -1")
    lines.append(f"    j       {tail_loop}")
    lines.append(f"{end_label}:")

    return lines



def _emit_vfcvt_equal_width_v(
    insn: RVInstruction,
    state: StateTracker,
    allocator: SimulatedStateLayout,
    new_label,
    *,
    opcode: str,
    semantic: str,
    src_kind: str,
    dst_kind: str,
) -> List[str]:
    """翻译等宽 vfcvt.*.*.v 单源转换指令。"""
    lines = []
    mask_suffix = ""
    operands = insn.operands
    if len(operands) < 2:
        raise InstructionValidationError(insn, f"Invalid operands for {insn.opcode}: {insn.op_str}")

    vd = operands[0]
    vs2 = operands[1]

    sew = state.sew
    if sew not in (32, 64):
        raise InstructionValidationError(
            insn, f"{opcode} 当前仅支持 SEW=32/64，实际为 SEW={sew}"
        )

    chunk_n = _chunk_size(sew)
    c_bytes = _chunk_bytes()
    shift_amt = {32: 3, 64: 2}[sew]
    mask = chunk_n - 1

    vd_off = allocator.get_offset(vd)
    vs2_off = allocator.get_offset(vs2)

    vtemps = VRegTempAllocator(insn)
    vs2_vreg = vtemps.alloc_vreg()
    vd_vreg = vtemps.alloc_vreg()

    temps = TempRegisterAllocator(insn, reserved_gprs=("t6",))
    vl_reg = temps.alloc_gpr()
    chunk_count = temps.alloc_gpr()
    tail_count = temps.alloc_gpr()
    vs2_ptr = temps.alloc_gpr()
    vd_ptr = temps.alloc_gpr()

    vle_instr = _get_vle_instr(sew)
    vse_instr = _get_vse_instr(sew)

    lines.append(f"# {opcode} {vd}, {vs2} (256-bit mode, SEW={sew})")
    lines.append(f"# Semantic: {vd}[i] = {semantic}({vs2}[i])")
    lines.append("")

    _load_vl_from_csr(lines, vl_reg=vl_reg, addr_reg=chunk_count)
    lines.append(f"    srli    {chunk_count}, {vl_reg}, {shift_amt}       # {chunk_count} = vl / {chunk_n}")
    lines.append(f"    andi    {tail_count}, {vl_reg}, {mask}              # {tail_count} = vl % {chunk_n}")
    lines.append("")

    lines.append(f"    li      {vl_reg}, {vs2_off:#x}")
    lines.append(f"    add     {vs2_ptr}, t6, {vl_reg}             # {vs2_ptr} = &{vs2}")
    lines.append(f"    li      {vl_reg}, {vd_off:#x}")
    lines.append(f"    add     {vd_ptr}, t6, {vl_reg}              # {vd_ptr} = &{vd}")
    lines.append("")

    label_base = opcode.replace(".", "_")
    main_loop = new_label(f"{label_base}_main")
    after_main = new_label(f"{label_base}_after")

    lines.append(f"    # --- 主循环: 每块处理 {chunk_n} 个元素 ({c_bytes} 字节) ---")
    lines.append(f"    beqz    {chunk_count}, {after_main}")
    lines.append(f"{main_loop}:")
    _emit_vsetvl_for_chunk(lines, chunk_n, sew, "m1", vl_reg, scratch_reg=vl_reg)
    lines.append("")
    lines.append(f"    {vle_instr} {vs2_vreg}, ({vs2_ptr})         # 加载 {vs2} 块 ({src_kind})")
    lines.append(f"    {opcode} {vd_vreg}, {vs2_vreg}              # {vd}[i] = {semantic}({vs2}[i])")
    lines.append(f"    {vse_instr} {vd_vreg}, ({vd_ptr}){mask_suffix}          # 写回 {vd} 块 ({dst_kind})")
    lines.append("")
    lines.append(f"    addi    {vs2_ptr}, {vs2_ptr}, {c_bytes}")
    lines.append(f"    addi    {vd_ptr}, {vd_ptr}, {c_bytes}")
    lines.append(f"    addi    {chunk_count}, {chunk_count}, -1")
    lines.append(f"    bnez    {chunk_count}, {main_loop}")
    lines.append(f"{after_main}:")
    lines.append("")

    lines.append(f"    # --- 尾部 RVV chunk: 剩余 {tail_count} 个元素 ---")
    end_label = new_label(f"{label_base}_end")
    lines.append(f"    beqz    {tail_count}, {end_label}")
    lines.append(f"    vsetvli zero, {tail_count}, e{sew}, m1, ta, ma")
    lines.append(f"    {vle_instr} {vs2_vreg}, ({vs2_ptr})         # 加载 {vs2} tail")
    lines.append(f"    {opcode} {vd_vreg}, {vs2_vreg}              # tail: {vd}[i] = {semantic}({vs2}[i])")
    lines.append(f"    {vse_instr} {vd_vreg}, ({vd_ptr}){mask_suffix}          # 写回 {vd} tail")
    lines.append(f"{end_label}:")

    return lines



def _build_vfcvt_x_f_v_lines(context) -> list[str]:
    """翻译 vfcvt.x.f.v 指令 (float -> signed integer, 等宽)。"""
    insn = context.instruction
    state = context.state
    allocator = context.layout
    new_label = context.new_label
    return _emit_vfcvt_equal_width_v(
        insn,
        state,
        allocator,
        new_label,
        opcode="vfcvt.x.f.v",
        semantic="int",
        src_kind="float",
        dst_kind="signed int",
    )



def _build_vfcvt_f_xu_v_lines(context) -> list[str]:
    """翻译 vfcvt.f.xu.v 指令 (unsigned integer -> float, 等宽)。"""
    insn = context.instruction
    state = context.state
    allocator = context.layout
    new_label = context.new_label
    return _emit_vfcvt_equal_width_v(
        insn,
        state,
        allocator,
        new_label,
        opcode="vfcvt.f.xu.v",
        semantic="float_unsigned",
        src_kind="unsigned int",
        dst_kind="float",
    )



def _build_vfncvt_f_f_w_lines(context) -> list[str]:
    """
    翻译 vfncvt.f.f.w 指令 (256-bit 模式, narrowing)

    格式: vfncvt.f.f.w vd, vs2
    语义: vd[i] = float(vs2[i]) (narrowing: e{sew*2} -> e{sew})
    :return: 生成的汇编代码行列表
    """
    insn = context.instruction
    state = context.state
    allocator = context.layout
    new_label = context.new_label
    lines = []
    mask_suffix = ""
    operands = insn.operands
    if len(operands) < 2:
        raise InstructionValidationError(insn, f"Invalid operands for {insn.opcode}: {insn.op_str}")

    vd = operands[0]
    vs2 = operands[1]

    output_sew = state.sew
    input_sew = output_sew * 2

    if output_sew not in (16, 32):
        raise ValueError(
            f"vfncvt.f.f.w 当前仅支持输出 SEW=16/32 (e32->e16, e64->e32), "
            f"实际为 SEW={state.sew}"
        )

    # 每块元素数基于输入宽度
    chunk_n = 256 // input_sew  # 对于 sew=32, input_sew=64: chunk_n=4
    chunk_bytes_in = chunk_n * (input_sew // 8)
    chunk_bytes_out = chunk_n * (output_sew // 8)
    shift_amt = 0
    t = chunk_n
    while t > 1:
        t >>= 1
        shift_amt += 1
    mask = chunk_n - 1

    elem_bytes_in = input_sew // 8
    elem_bytes_out = output_sew // 8

    vd_off = allocator.get_offset(vd)
    vs2_off = allocator.get_offset(vs2)

    vtemps = VRegTempAllocator(insn)
    vs2_vreg = vtemps.alloc_vreg_group(2)
    vd_vreg = vtemps.alloc_vreg()

    temps = TempRegisterAllocator(insn, reserved_gprs=("t6",), extra_avoid_fprs=("ft0",))
    vl_reg = temps.alloc_gpr()
    chunk_count = temps.alloc_gpr()
    tail_count = temps.alloc_gpr()
    vs2_ptr = temps.alloc_gpr()
    vd_ptr = temps.alloc_gpr()
    temp = temps.alloc_gpr()

    lines.append(f"# vfncvt.f.f.w {vd}, {vs2} (256-bit mode)")
    lines.append(f"# Semantic: {vd}[i] = float({vs2}[i]), e{input_sew} -> e{output_sew}")
    lines.append("")

    _load_vl_from_csr(lines, vl_reg=vl_reg, addr_reg=chunk_count)
    lines.append(f"    srli    {chunk_count}, {vl_reg}, {shift_amt}       # {chunk_count} = vl / {chunk_n}")
    lines.append(f"    andi    {tail_count}, {vl_reg}, {mask}              # {tail_count} = vl % {chunk_n}")
    lines.append("")

    lines.append(f"    li      {temp}, {vs2_off:#x}")
    lines.append(f"    add     {vs2_ptr}, t6, {temp}            # {vs2_ptr} = &{vs2}")
    lines.append(f"    li      {temp}, {vd_off:#x}")
    lines.append(f"    add     {vd_ptr}, t6, {temp}             # {vd_ptr} = &{vd}")
    lines.append("")

    # ========== 主循环 (256-bit 块) ==========
    main_loop = new_label("vfncvt_ff_main")
    after_main = new_label("vfncvt_ff_after")

    lines.append(f"    # --- 主循环: 每块处理 {chunk_n} 个元素 ---")
    lines.append(f"    # 输入: {chunk_bytes_in}B (e{input_sew}), 输出: {chunk_bytes_out}B (e{output_sew})")
    lines.append(f"    beqz    {chunk_count}, {after_main}")
    lines.append(f"{main_loop}:")
    _emit_vsetvl_for_chunk(lines, chunk_n, input_sew, "m1", vl_reg, scratch_reg=temp)
    lines.append(f"    vle{input_sew}.v {vs2_vreg}, ({vs2_ptr})       # 加载 {vs2} 块 (e{input_sew})")
    _emit_vsetvl_for_chunk(lines, chunk_n, output_sew, "m1", vl_reg, scratch_reg=temp)
    lines.append(f"    vfncvt.f.f.w {vd_vreg}, {vs2_vreg}                # {vd}[i] = float({vs2}[i])")
    lines.append(f"    vse{output_sew}.v {vd_vreg}, ({vd_ptr})       # 写回 {vd} 块 (e{output_sew})")
    lines.append("")
    lines.append(f"    addi    {vs2_ptr}, {vs2_ptr}, {chunk_bytes_in}")
    lines.append(f"    addi    {vd_ptr}, {vd_ptr}, {chunk_bytes_out}")
    lines.append(f"    addi    {chunk_count}, {chunk_count}, -1")
    lines.append(f"    bnez    {chunk_count}, {main_loop}")
    lines.append(f"{after_main}:")
    lines.append("")

    # ========== 尾部标量回退 ==========
    lines.append(f"    # --- 尾部标量回退: 剩余 {tail_count} 个元素 (e{input_sew} -> e{output_sew}) ---")
    tail_loop = new_label("vfncvt_ff_tail")
    end_label = new_label("vfncvt_ff_end")

    load_instr = _get_float_instr('load', input_sew)
    store_instr = _get_float_instr('store', output_sew)

    lines.append(f"{tail_loop}:")
    lines.append(f"    beqz    {tail_count}, {end_label}")
    lines.append(f"    {load_instr:<8} ft0, 0({vs2_ptr})            # ft0 = {vs2}[i] (e{input_sew})")
    if input_sew == 64 and output_sew == 32:
        lines.append(f"    fcvt.s.d ft0, ft0                      # ft0 = float(ft0) (e64 -> e32)")
    elif input_sew == 32 and output_sew == 16:
        lines.append(f"    fcvt.h.s ft0, ft0                      # ft0 = float(ft0) (e32 -> e16)")
    lines.append(f"    {store_instr:<8} ft0, 0({vd_ptr})            # {vd}[i] = ft0")
    lines.append(f"    addi    {vs2_ptr}, {vs2_ptr}, {elem_bytes_in}")
    lines.append(f"    addi    {vd_ptr}, {vd_ptr}, {elem_bytes_out}")
    lines.append(f"    addi    {tail_count}, {tail_count}, -1")
    lines.append(f"    j       {tail_loop}")
    lines.append(f"{end_label}:")

    return lines



def _build_vfncvt_x_f_w_lines(context) -> list[str]:
    """
    翻译 vfncvt.x.f.w 指令 (256-bit 模式, narrowing)

    格式: vfncvt.x.f.w vd, vs2
    语义: vd[i] = (int)vs2[i] (narrowing: e{sew*2} float -> e{sew} int)
    :return: 生成的汇编代码行列表
    """
    insn = context.instruction
    state = context.state
    allocator = context.layout
    new_label = context.new_label
    lines = []
    mask_suffix = ""
    operands = insn.operands
    if len(operands) < 2:
        raise InstructionValidationError(insn, f"Invalid operands for {insn.opcode}: {insn.op_str}")

    vd = operands[0]
    vs2 = operands[1]

    output_sew = state.sew
    input_sew = output_sew * 2

    if output_sew not in (16, 32):
        raise ValueError(
            f"vfncvt.x.f.w 当前仅支持输出 SEW=16/32, "
            f"实际为 SEW={state.sew}"
        )

    chunk_n = 256 // input_sew  # 4
    chunk_bytes_in = chunk_n * (input_sew // 8)
    chunk_bytes_out = chunk_n * (output_sew // 8)
    shift_amt = 0
    t = chunk_n
    while t > 1:
        t >>= 1
        shift_amt += 1
    mask = chunk_n - 1

    elem_bytes_in = input_sew // 8
    elem_bytes_out = output_sew // 8

    vd_off = allocator.get_offset(vd)
    vs2_off = allocator.get_offset(vs2)

    vtemps = VRegTempAllocator(insn)
    vs2_vreg = vtemps.alloc_vreg_group(2)
    vd_vreg = vtemps.alloc_vreg()

    temps = TempRegisterAllocator(insn, reserved_gprs=("t6",), extra_avoid_fprs=("ft0",))
    vl_reg = temps.alloc_gpr()
    chunk_count = temps.alloc_gpr()
    tail_count = temps.alloc_gpr()
    vs2_ptr = temps.alloc_gpr()
    vd_ptr = temps.alloc_gpr()
    temp = temps.alloc_gpr()

    lines.append(f"# vfncvt.x.f.w {vd}, {vs2} (256-bit mode)")
    lines.append(f"# Semantic: {vd}[i] = (int){vs2}[i], e{input_sew} float -> e{output_sew} int")
    lines.append("")

    _load_vl_from_csr(lines, vl_reg=vl_reg, addr_reg=chunk_count)
    lines.append(f"    srli    {chunk_count}, {vl_reg}, {shift_amt}       # {chunk_count} = vl / {chunk_n}")
    lines.append(f"    andi    {tail_count}, {vl_reg}, {mask}              # {tail_count} = vl % {chunk_n}")
    lines.append("")

    lines.append(f"    li      {temp}, {vs2_off:#x}")
    lines.append(f"    add     {vs2_ptr}, t6, {temp}            # {vs2_ptr} = &{vs2}")
    lines.append(f"    li      {temp}, {vd_off:#x}")
    lines.append(f"    add     {vd_ptr}, t6, {temp}             # {vd_ptr} = &{vd}")
    lines.append("")

    # ========== 主循环 (256-bit 块) ==========
    main_loop = new_label("vfncvt_xf_main")
    after_main = new_label("vfncvt_xf_after")

    lines.append(f"    # --- 主循环: 每块处理 {chunk_n} 个元素 ---")
    lines.append(f"    # 输入: {chunk_bytes_in}B (e{input_sew}), 输出: {chunk_bytes_out}B (e{output_sew})")
    lines.append(f"    beqz    {chunk_count}, {after_main}")
    lines.append(f"{main_loop}:")
    _emit_vsetvl_for_chunk(lines, chunk_n, input_sew, "m1", vl_reg, scratch_reg=temp)
    lines.append(f"    vle{input_sew}.v {vs2_vreg}, ({vs2_ptr})       # 加载 {vs2} 块 (e{input_sew})")
    _emit_vsetvl_for_chunk(lines, chunk_n, output_sew, "m1", vl_reg, scratch_reg=temp)
    lines.append(f"    vfncvt.x.f.w {vd_vreg}, {vs2_vreg}                # {vd}[i] = (int){vs2}[i]")
    lines.append(f"    vse{output_sew}.v {vd_vreg}, ({vd_ptr})       # 写回 {vd} 块 (e{output_sew})")
    lines.append("")
    lines.append(f"    addi    {vs2_ptr}, {vs2_ptr}, {chunk_bytes_in}")
    lines.append(f"    addi    {vd_ptr}, {vd_ptr}, {chunk_bytes_out}")
    lines.append(f"    addi    {chunk_count}, {chunk_count}, -1")
    lines.append(f"    bnez    {chunk_count}, {main_loop}")
    lines.append(f"{after_main}:")
    lines.append("")

    # ========== 尾部标量回退 ==========
    lines.append(f"    # --- 尾部标量回退: 剩余 {tail_count} 个元素 ---")
    tail_loop = new_label("vfncvt_xf_tail")
    end_label = new_label("vfncvt_xf_end")

    float_load_instr = _get_float_instr('load', input_sew)
    int_store_instr = {8: 'sb', 16: 'sh', 32: 'sw', 64: 'sd'}[output_sew]

    if output_sew == 32 and input_sew == 64:
        fcvt_instr = "fcvt.w.d"
    elif output_sew == 16 and input_sew == 32:
        fcvt_instr = "fcvt.w.s"
    else:
        raise InstructionValidationError(
            insn,
            f"vfncvt.x.f.w 不支持 input e{input_sew} -> output e{output_sew}",
        )

    lines.append(f"{tail_loop}:")
    lines.append(f"    beqz    {tail_count}, {end_label}")
    lines.append(f"    {float_load_instr:<8} ft0, 0({vs2_ptr})            # ft0 = {vs2}[i] (e{input_sew})")
    lines.append(f"    {fcvt_instr:<12} {temp}, ft0              # {temp} = (int)ft0")
    lines.append(f"    {int_store_instr:<8} {temp}, 0({vd_ptr})            # {vd}[i] = {temp}")
    lines.append(f"    addi    {vs2_ptr}, {vs2_ptr}, {elem_bytes_in}")
    lines.append(f"    addi    {vd_ptr}, {vd_ptr}, {elem_bytes_out}")
    lines.append(f"    addi    {tail_count}, {tail_count}, -1")
    lines.append(f"    j       {tail_loop}")
    lines.append(f"{end_label}:")

    return lines



def _build_vfwcvt_f_f_v_lines(context) -> list[str]:
    """
    翻译 vfwcvt.f.f.v 指令 (256-bit 模式, widening)

    格式: vfwcvt.f.f.v vd, vs2
    语义: vd[i] = widen(vs2[i]) (widening: e{sew} -> e{sew*2} float)
    :return: 生成的汇编代码行列表
    """
    insn = context.instruction
    state = context.state
    allocator = context.layout
    new_label = context.new_label
    lines = []
    mask_suffix = ""
    operands = insn.operands
    if len(operands) < 2:
        raise InstructionValidationError(insn, f"Invalid operands for {insn.opcode}: {insn.op_str}")

    vd = operands[0]
    vs2 = operands[1]

    input_sew = state.sew
    output_sew = input_sew * 2

    if input_sew not in (16, 32):
        raise InstructionValidationError(
            insn,
            "vfwcvt.f.f.v 当前仅支持输入 SEW=16/32 "
            f"(e16 -> e32 或 e32 -> e64), 实际为 SEW={state.sew}",
        )

    # Widening: input uses LMUL=mf2, output uses LMUL=m1.
    chunk_n = 256 // output_sew
    chunk_bytes_in = chunk_n * (input_sew // 8)
    chunk_bytes_out = chunk_n * (output_sew // 8)
    shift_amt = 0
    t = chunk_n
    while t > 1:
        t >>= 1
        shift_amt += 1
    mask = chunk_n - 1

    vd_off = allocator.get_offset(vd)
    vs2_off = allocator.get_offset(vs2)

    vtemps = VRegTempAllocator(insn)
    vs2_vreg = vtemps.alloc_vreg()
    vd_vreg = vtemps.alloc_vreg()

    temps = TempRegisterAllocator(insn, reserved_gprs=("t6",), extra_avoid_fprs=("ft0",))
    vl_reg = temps.alloc_gpr()
    chunk_count = temps.alloc_gpr()
    tail_count = temps.alloc_gpr()
    vs2_ptr = temps.alloc_gpr()
    vd_ptr = temps.alloc_gpr()
    temp = temps.alloc_gpr()

    lines.append(f"# vfwcvt.f.f.v {vd}, {vs2} (256-bit mode)")
    lines.append(f"# Semantic: {vd}[i] = widen({vs2}[i]), e{input_sew} -> e{output_sew}")
    lines.append("")

    _load_vl_from_csr(lines, vl_reg=vl_reg, addr_reg=chunk_count)
    lines.append(f"    srli    {chunk_count}, {vl_reg}, {shift_amt}       # {chunk_count} = vl / {chunk_n}")
    lines.append(f"    andi    {tail_count}, {vl_reg}, {mask}              # {tail_count} = vl % {chunk_n}")
    lines.append("")

    lines.append(f"    li      {temp}, {vs2_off:#x}")
    lines.append(f"    add     {vs2_ptr}, t6, {temp}            # {vs2_ptr} = &{vs2}")
    lines.append(f"    li      {temp}, {vd_off:#x}")
    lines.append(f"    add     {vd_ptr}, t6, {temp}             # {vd_ptr} = &{vd}")
    lines.append("")

    # ========== 主循环 (256-bit 块, LMUL=mf2 用于输入) ==========
    main_loop = new_label("vfwcvt_ff_main")
    after_main = new_label("vfwcvt_ff_after")

    lines.append(f"    # --- 主循环: 每块处理 {chunk_n} 个元素 ---")
    lines.append(f"    # 输入: {chunk_bytes_in}B (LMUL=mf2), 输出: {chunk_bytes_out}B (LMUL=m1)")
    lines.append(f"    beqz    {chunk_count}, {after_main}")
    lines.append(f"{main_loop}:")
    _emit_vsetvl_for_chunk(lines, chunk_n, input_sew, "mf2", vl_reg, scratch_reg=temp)
    lines.append("")
    lines.append(f"    vle{input_sew}.v {vs2_vreg}, ({vs2_ptr})       # 加载 {vs2} 块 (e{input_sew}, mf2)")
    lines.append(f"    vfwcvt.f.f.v {vd_vreg}, {vs2_vreg}                 # {vd}[i] = widen({vs2}[i])")
    lines.append(f"    vse{output_sew}.v {vd_vreg}, ({vd_ptr})       # 写回 {vd} 块 (e{output_sew})")
    lines.append("")
    lines.append(f"    addi    {vs2_ptr}, {vs2_ptr}, {chunk_bytes_in}")
    lines.append(f"    addi    {vd_ptr}, {vd_ptr}, {chunk_bytes_out}")
    lines.append(f"    addi    {chunk_count}, {chunk_count}, -1")
    lines.append(f"    bnez    {chunk_count}, {main_loop}")
    lines.append(f"{after_main}:")
    lines.append("")

    # ========== 尾部 RVV chunk ==========
    lines.append(f"    # --- 尾部 RVV widening chunk: 剩余 {tail_count} 个元素 ---")
    tail_loop = new_label("vfwcvt_ff_tail")
    end_label = new_label("vfwcvt_ff_end")

    lines.append(f"{tail_loop}:")
    lines.append(f"    beqz    {tail_count}, {end_label}")
    lines.append(f"    vsetvli zero, {tail_count}, e{input_sew}, mf2, ta, ma")
    lines.append(f"    vle{input_sew}.v {vs2_vreg}, ({vs2_ptr})")
    lines.append(f"    vfwcvt.f.f.v {vd_vreg}, {vs2_vreg}")
    lines.append(f"    vse{output_sew}.v {vd_vreg}, ({vd_ptr})")
    lines.append(f"{end_label}:")

    return lines



def _build_vfwcvt_f_x_v_lines(context) -> list[str]:
    """
    翻译 vfwcvt.f.x.v 指令 (256-bit 模式, widening)

    格式: vfwcvt.f.x.v vd, vs2
    语义: vd[i] = float_signed_widen(vs2[i]) (e16/e32 int -> e32/e64 float)
    """
    insn = context.instruction
    state = context.state
    allocator = context.layout
    new_label = context.new_label
    lines = []
    mask_suffix = ""
    operands = insn.operands
    if len(operands) < 2:
        raise InstructionValidationError(insn, f"Invalid operands for {insn.opcode}: {insn.op_str}")

    vd = operands[0]
    vs2 = operands[1]

    input_sew = state.sew
    output_sew = input_sew * 2

    if input_sew not in (16, 32):
        raise InstructionValidationError(
            insn,
            "vfwcvt.f.x.v 当前仅支持输入 SEW=16/32 "
            f"(e16 -> e32 或 e32 -> e64), 实际为 SEW={state.sew}",
        )

    chunk_n = 256 // output_sew
    chunk_bytes_in = chunk_n * (input_sew // 8)
    chunk_bytes_out = chunk_n * (output_sew // 8)
    shift_amt = 0
    t = chunk_n
    while t > 1:
        t >>= 1
        shift_amt += 1
    mask = chunk_n - 1

    vd_off = allocator.get_offset(vd)
    vs2_off = allocator.get_offset(vs2)

    vtemps = VRegTempAllocator(insn)
    vs2_vreg = vtemps.alloc_vreg()
    vd_vreg = vtemps.alloc_vreg()

    temps = context.temp_register_allocator
    vl_reg = temps.alloc_gpr()
    chunk_count = temps.alloc_gpr()
    tail_count = temps.alloc_gpr()
    vs2_ptr = temps.alloc_gpr()
    vd_ptr = temps.alloc_gpr()
    temp = temps.alloc_gpr()

    lines.append(f"# vfwcvt.f.x.v {vd}, {vs2} (256-bit mode)")
    lines.append(f"# Semantic: {vd}[i] = float_signed({vs2}[i]), e{input_sew} -> e{output_sew}")
    lines.append("")

    _load_vl_from_csr(lines, vl_reg=vl_reg, addr_reg=chunk_count)
    lines.append(f"    srli    {chunk_count}, {vl_reg}, {shift_amt}       # {chunk_count} = vl / {chunk_n}")
    lines.append(f"    andi    {tail_count}, {vl_reg}, {mask}              # {tail_count} = vl % {chunk_n}")
    lines.append("")

    lines.append(f"    li      {temp}, {vs2_off:#x}")
    lines.append(f"    add     {vs2_ptr}, t6, {temp}            # {vs2_ptr} = &{vs2}")
    lines.append(f"    li      {temp}, {vd_off:#x}")
    lines.append(f"    add     {vd_ptr}, t6, {temp}             # {vd_ptr} = &{vd}")
    lines.append("")

    main_loop = new_label("vfwcvt_f_x_main")
    after_main = new_label("vfwcvt_f_x_after")

    lines.append(f"    # --- 主循环: 每块处理 {chunk_n} 个元素 ---")
    lines.append(f"    # 输入: {chunk_bytes_in}B (e{input_sew}, LMUL=mf2), 输出: {chunk_bytes_out}B (e{output_sew}, LMUL=m1)")
    lines.append(f"    beqz    {chunk_count}, {after_main}")
    lines.append(f"{main_loop}:")
    _emit_vsetvl_for_chunk(lines, chunk_n, input_sew, "mf2", vl_reg, scratch_reg=temp)
    lines.append("")
    lines.append(f"    vle{input_sew}.v {vs2_vreg}, ({vs2_ptr})       # 加载 {vs2} 块 (signed int e{input_sew}, mf2)")
    lines.append(f"    vfwcvt.f.x.v {vd_vreg}, {vs2_vreg}                 # signed int -> widened float")
    lines.append(f"    vse{output_sew}.v {vd_vreg}, ({vd_ptr})       # 写回 {vd} 块 (float e{output_sew})")
    lines.append("")
    lines.append(f"    addi    {vs2_ptr}, {vs2_ptr}, {chunk_bytes_in}")
    lines.append(f"    addi    {vd_ptr}, {vd_ptr}, {chunk_bytes_out}")
    lines.append(f"    addi    {chunk_count}, {chunk_count}, -1")
    lines.append(f"    bnez    {chunk_count}, {main_loop}")
    lines.append(f"{after_main}:")
    lines.append("")

    lines.append(f"    # --- 尾部 RVV widening convert chunk: 剩余 {tail_count} 个元素 ---")
    end_label = new_label("vfwcvt_f_x_end")
    lines.append(f"    beqz    {tail_count}, {end_label}")
    lines.append(f"    vsetvli zero, {tail_count}, e{input_sew}, mf2, ta, ma")
    lines.append(f"    vle{input_sew}.v {vs2_vreg}, ({vs2_ptr})")
    lines.append(f"    vfwcvt.f.x.v {vd_vreg}, {vs2_vreg}")
    lines.append(f"    vse{output_sew}.v {vd_vreg}, ({vd_ptr}){mask_suffix}")
    lines.append(f"{end_label}:")

    return lines
