"""RVV256 整数逻辑、移位、极值与整寄存器搬移。

本文件由原算术模块按语义族机械拆分；函数体保持原样，公共状态与 ABI 访问统一复用 common。
"""

from typing import List

from riscv.frontend.model import RVInstruction
from riscv.extensions.rvv.analysis.config import StateTracker
from riscv.extensions.rvv.runtime.layout import SimulatedStateLayout
from riscv.extensions.rvv.translation.contracts import InstructionValidationError
from riscv.extensions.rvv.backends.rvv256.temp_regs import VRegTempAllocator
from riscv.extensions.rvv.translation.temps import TempRegisterAllocator
from riscv.extensions.rvv.translation.lowering import AssemblyBuilderOutput, AssemblyFragments
from riscv.extensions.rvv.backends.rvv256.support import (
    _chunk_size,
    _chunk_bytes,
    _emit_vsetvl_for_chunk,
    _load_vl_from_csr,
    _get_vle_instr,
    _get_vse_instr,
    _emit_mask_setup,
    _emit_mask_extraction_chunk,
    _emit_mask_load_byte_aligned_chunk,
)

from riscv.extensions.rvv.backends.rvv256.support import (
    _get_int_load_signed,
    _get_int_store,
    _parse_int_operand,
)


def _build_vxor_vv_lines(context) -> list[str]:
    """
    翻译 vxor.vv 指令 (256-bit 模式)

    格式: vxor.vv vd, vs2, vs1
    语义: vd[i] = vs2[i] ^ vs1[i] 对于 i in [0, vl)
    :return: 生成的汇编代码行列表
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

    temps = context.temp_register_allocator
    vl_reg = temps.alloc_gpr()
    chunk_count = temps.alloc_gpr()
    tail_count = temps.alloc_gpr()
    vs2_ptr = temps.alloc_gpr()
    vs1_ptr = temps.alloc_gpr()
    vd_ptr = temps.alloc_gpr()
    data_reg = temps.alloc_gpr()

    vle_instr = _get_vle_instr(sew)
    vse_instr = _get_vse_instr(sew)
    int_load = {8: 'lbu', 16: 'lhu', 32: 'lwu', 64: 'ld'}[sew]
    int_store = {8: 'sb', 16: 'sh', 32: 'sw', 64: 'sd'}[sew]

    lines.append(f"# vxor.vv {vd}, {vs2}, {vs1} (256-bit mode, SEW={sew})")
    lines.append(f"# Semantic: {vd}[i] = {vs2}[i] ^ {vs1}[i]")
    lines.append("")

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
    main_loop = new_label("vxor_vv_main")
    after_main = new_label("vxor_vv_after")

    lines.append(f"    # --- 主循环: 每块处理 {chunk_n} 个元素 ({c_bytes} 字节) ---")
    lines.append(f"    beqz    {chunk_count}, {after_main}")
    lines.append(f"{main_loop}:")
    _emit_vsetvl_for_chunk(lines, chunk_n, sew, "m1", vl_reg, scratch_reg=vl_reg)
    lines.append("")
    lines.append(f"    {vle_instr} {vs2_vreg}, ({vs2_ptr})         # 加载 {vs2} 块")
    lines.append(f"    {vle_instr} {vs1_vreg}, ({vs1_ptr})         # 加载 {vs1} 块")
    lines.append(f"    vxor.vv {vd_vreg}, {vs2_vreg}, {vs1_vreg}     # {vd}[i] = {vs2}[i] ^ {vs1}[i]")
    lines.append(f"    {vse_instr} {vd_vreg}, ({vd_ptr}){mask_suffix}          # 写回 {vd} 块")
    lines.append("")
    lines.append(f"    addi    {vs2_ptr}, {vs2_ptr}, {c_bytes}")
    lines.append(f"    addi    {vs1_ptr}, {vs1_ptr}, {c_bytes}")
    lines.append(f"    addi    {vd_ptr}, {vd_ptr}, {c_bytes}")
    lines.append(f"    addi    {chunk_count}, {chunk_count}, -1")
    lines.append(f"    bnez    {chunk_count}, {main_loop}")
    lines.append(f"{after_main}:")
    lines.append("")

    # ========== 尾部标量回退 ==========
    lines.append(f"    # --- 尾部标量回退: 剩余 {tail_count} 个元素 ---")
    tail_loop = new_label("vxor_vv_tail")
    end_label = new_label("vxor_vv_end")

    lines.append(f"{tail_loop}:")
    lines.append(f"    beqz    {tail_count}, {end_label}")
    lines.append(f"    {int_load:<8} {chunk_count}, 0({vs2_ptr})           # {chunk_count} = {vs2}[i]")
    lines.append(f"    {int_load:<8} {data_reg}, 0({vs1_ptr})                 # {data_reg} = {vs1}[i]")
    lines.append(f"    xor     {chunk_count}, {chunk_count}, {data_reg}                 # {chunk_count} = {vs2}[i] ^ {vs1}[i]")
    lines.append(f"    {int_store:<8} {chunk_count}, 0({vd_ptr})            # {vd}[i] = {chunk_count}")
    lines.append(f"    addi    {vs2_ptr}, {vs2_ptr}, {elem_bytes}")
    lines.append(f"    addi    {vs1_ptr}, {vs1_ptr}, {elem_bytes}")
    lines.append(f"    addi    {vd_ptr}, {vd_ptr}, {elem_bytes}")
    lines.append(f"    addi    {tail_count}, {tail_count}, -1")
    lines.append(f"    j       {tail_loop}")
    lines.append(f"{end_label}:")

    return lines



def _build_vand_vv_lines(context) -> list[str]:
    """
    翻译 vand.vv 指令 (256-bit 模式)

    格式: vand.vv vd, vs2, vs1
    语义: vd[i] = vs2[i] & vs1[i] 对于 i in [0, vl)
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
    vs2 = operands[1]
    vs1 = operands[2]

    sew = state.sew
    chunk_n = _chunk_size(sew)
    c_bytes = _chunk_bytes()
    shift_amt = {8: 5, 16: 4, 32: 3, 64: 2}[sew]
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

    vle_instr = _get_vle_instr(sew)
    vse_instr = _get_vse_instr(sew)

    lines.append(f"# vand.vv {vd}, {vs2}, {vs1} (256-bit mode, SEW={sew})")
    lines.append(f"# Semantic: {vd}[i] = {vs2}[i] & {vs1}[i]")
    lines.append("")

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

    main_loop = new_label("vand_vv_main")
    after_main = new_label("vand_vv_after")

    lines.append(f"    # --- 主循环: 每块处理 {chunk_n} 个元素 ({c_bytes} 字节) ---")
    lines.append(f"    beqz    {chunk_count}, {after_main}")
    lines.append(f"{main_loop}:")
    _emit_vsetvl_for_chunk(lines, chunk_n, sew, "m1", vl_reg, scratch_reg=vl_reg)
    lines.append("")
    lines.append(f"    {vle_instr} {vs2_vreg}, ({vs2_ptr})         # 加载 {vs2} 块")
    lines.append(f"    {vle_instr} {vs1_vreg}, ({vs1_ptr})         # 加载 {vs1} 块")
    lines.append(f"    vand.vv {vd_vreg}, {vs2_vreg}, {vs1_vreg}     # {vd}[i] = {vs2}[i] & {vs1}[i]")
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
    end_label = new_label("vand_vv_end")
    lines.append(f"    beqz    {tail_count}, {end_label}")
    lines.append(f"    vsetvli zero, {tail_count}, e{sew}, m1, ta, ma")
    lines.append(f"    {vle_instr} {vs2_vreg}, ({vs2_ptr})         # 加载 {vs2} tail")
    lines.append(f"    {vle_instr} {vs1_vreg}, ({vs1_ptr})         # 加载 {vs1} tail")
    lines.append(f"    vand.vv {vd_vreg}, {vs2_vreg}, {vs1_vreg}     # tail: {vd}[i] = {vs2}[i] & {vs1}[i]")
    lines.append(f"    {vse_instr} {vd_vreg}, ({vd_ptr}){mask_suffix}          # 写回 {vd} tail")
    lines.append(f"{end_label}:")

    return lines



def _build_vand_vi_lines(context) -> list[str]:
    """
    翻译 vand.vi 指令 (256-bit 模式)

    格式: vand.vi vd, vs2, imm
    语义: vd[i] = vs2[i] & sign_extend(imm)
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
    vs2 = operands[1]
    try:
        imm = _parse_int_operand(operands[2])
    except ValueError:
        raise InstructionValidationError(insn, f"vand.vi immediate must be an integer: {insn.op_str}")

    if imm < -16 or imm > 15:
        raise InstructionValidationError(insn, f"vand.vi immediate must be signed 5-bit (-16..15), got {imm}")

    sew = state.sew
    chunk_n = _chunk_size(sew)
    c_bytes = _chunk_bytes()
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

    vle_instr = _get_vle_instr(sew)
    vse_instr = _get_vse_instr(sew)

    lines.append(f"# vand.vi {vd}, {vs2}, {imm} (256-bit mode, SEW={sew})")
    lines.append(f"# Semantic: {vd}[i] = {vs2}[i] & sign_extend({imm})")
    lines.append("")

    _load_vl_from_csr(lines, vl_reg=vl_reg, addr_reg=chunk_count)
    lines.append(f"    srli    {chunk_count}, {vl_reg}, {shift_amt}       # {chunk_count} = vl / {chunk_n}")
    lines.append(f"    andi    {tail_count}, {vl_reg}, {mask}              # {tail_count} = vl % {chunk_n}")
    lines.append("")

    # 之后 vl_reg 不再使用，可复用为临时寄存器做 li（不破坏 tail_count）
    lines.append(f"    li      {vl_reg}, {vs2_off:#x}")
    lines.append(f"    add     {vs2_ptr}, t6, {vl_reg}             # {vs2_ptr} = &{vs2}")
    lines.append(f"    li      {vl_reg}, {vd_off:#x}")
    lines.append(f"    add     {vd_ptr}, t6, {vl_reg}              # {vd_ptr} = &{vd}")
    lines.append("")

    main_loop = new_label("vand_vi_main")
    after_main = new_label("vand_vi_after")

    lines.append(f"    # --- 主循环: 每块处理 {chunk_n} 个元素 ({c_bytes} 字节) ---")
    lines.append(f"    beqz    {chunk_count}, {after_main}")
    lines.append(f"{main_loop}:")
    _emit_vsetvl_for_chunk(lines, chunk_n, sew, "m1", vl_reg, scratch_reg=vl_reg)
    lines.append("")
    lines.append(f"    {vle_instr} {vs2_vreg}, ({vs2_ptr})         # 加载 {vs2} 块")
    lines.append(f"    vand.vi {vd_vreg}, {vs2_vreg}, {imm}          # {vd}[i] = {vs2}[i] & sign_extend({imm})")
    lines.append(f"    {vse_instr} {vd_vreg}, ({vd_ptr}){mask_suffix}          # 写回 {vd} 块")
    lines.append("")
    lines.append(f"    addi    {vs2_ptr}, {vs2_ptr}, {c_bytes}")
    lines.append(f"    addi    {vd_ptr}, {vd_ptr}, {c_bytes}")
    lines.append(f"    addi    {chunk_count}, {chunk_count}, -1")
    lines.append(f"    bnez    {chunk_count}, {main_loop}")
    lines.append(f"{after_main}:")
    lines.append("")

    lines.append(f"    # --- 尾部 RVV chunk: 剩余 {tail_count} 个元素 ---")
    end_label = new_label("vand_vi_end")
    lines.append(f"    beqz    {tail_count}, {end_label}")
    lines.append(f"    vsetvli zero, {tail_count}, e{sew}, m1, ta, ma")
    lines.append(f"    {vle_instr} {vs2_vreg}, ({vs2_ptr})         # 加载 {vs2} tail")
    lines.append(f"    vand.vi {vd_vreg}, {vs2_vreg}, {imm}          # tail: {vd}[i] = {vs2}[i] & sign_extend({imm})")
    lines.append(f"    {vse_instr} {vd_vreg}, ({vd_ptr}){mask_suffix}          # 写回 {vd} tail")
    lines.append(f"{end_label}:")

    return lines



def _build_vand_vx_lines(context) -> list[str]:
    """
    翻译 vand.vx 指令 (256-bit 模式)

    格式: vand.vx vd, vs2, rs1
    语义: vd[i] = vs2[i] & rs1 对于 i in [0, vl)
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
    chunk_n = _chunk_size(sew)
    c_bytes = _chunk_bytes()
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
    if is_masked:
        mask_bit_idx = temps.alloc_gpr()
        v0_base = temps.alloc_gpr()

    vle_instr = _get_vle_instr(sew)
    vse_instr = _get_vse_instr(sew)

    lines.append(f"# vand.vx {vd}, {vs2}, {rs1} (256-bit mode, SEW={sew})")
    lines.append(f"# Semantic: {vd}[i] = {vs2}[i] & {rs1}")
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

    main_loop = new_label("vand_vx_main")
    after_main = new_label("vand_vx_after")

    lines.append(f"    # --- 主循环: 每块处理 {chunk_n} 个元素 ({c_bytes} 字节) ---")
    lines.append(f"    beqz    {chunk_count}, {after_main}")
    lines.append(f"{main_loop}:")
    mask_suffix = ", v0.t" if is_masked else ""
    if is_masked:
        _emit_mask_extraction_chunk(lines, sew, mask_bit_idx, v0_base, vl_reg, temp)

    _emit_vsetvl_for_chunk(lines, chunk_n, sew, "m1", vl_reg, scratch_reg=temp)
    lines.append("")
    lines.append(f"    {vle_instr} {vs2_vreg}, ({vs2_ptr})         # 加载 {vs2} 块")
    lines.append(f"    vand.vx {vd_vreg}, {vs2_vreg}, {rs1}{mask_suffix}          # {vd}[i] = {vs2}[i] & {rs1}")
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

    end_label = new_label("vand_vx_end")
    lines.append(f"    # --- 尾部 RVV chunk: 剩余 {tail_count} 个元素 ---")
    lines.append(f"    beqz    {tail_count}, {end_label}")
    if is_masked:
        _emit_mask_extraction_chunk(lines, sew, mask_bit_idx, v0_base, vl_reg, temp)
    lines.append(f"    vsetvli zero, {tail_count}, e{sew}, m1, ta, ma")
    lines.append(f"    {vle_instr} {vs2_vreg}, ({vs2_ptr})         # 加载 {vs2} tail")
    lines.append(f"    vand.vx {vd_vreg}, {vs2_vreg}, {rs1}{mask_suffix}          # tail: {vd}[i] = {vs2}[i] & {rs1}")
    lines.append(f"    {vse_instr} {vd_vreg}, ({vd_ptr}){mask_suffix}          # 写回 {vd} tail")
    lines.append(f"{end_label}:")

    return lines



def _build_vandn_vv_lines(context) -> list[str]:
    """
    翻译 vandn.vv 指令 (256-bit 模式)

    格式: vandn.vv vd, vs2, vs1
    语义: vd[i] = vs2[i] & ~vs1[i] 对于 i in [0, vl)
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
    vs2 = operands[1]
    vs1 = operands[2]

    sew = state.sew
    chunk_n = _chunk_size(sew)
    c_bytes = _chunk_bytes()
    shift_amt = {8: 5, 16: 4, 32: 3, 64: 2}[sew]
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

    vle_instr = _get_vle_instr(sew)
    vse_instr = _get_vse_instr(sew)

    lines.append(f"# vandn.vv {vd}, {vs2}, {vs1} (256-bit mode, SEW={sew})")
    lines.append(f"# Semantic: {vd}[i] = {vs2}[i] & ~{vs1}[i]")
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

    main_loop = new_label("vandn_vv_main")
    after_main = new_label("vandn_vv_after")

    lines.append(f"    # --- 主循环: 每块处理 {chunk_n} 个元素 ({c_bytes} 字节) ---")
    lines.append(f"    beqz    {chunk_count}, {after_main}")
    lines.append(f"{main_loop}:")
    _emit_vsetvl_for_chunk(lines, chunk_n, sew, "m1", vl_reg, scratch_reg=vl_reg)
    lines.append("")
    lines.append(f"    {vle_instr} {vs2_vreg}, ({vs2_ptr})         # 加载 {vs2} 块")
    lines.append(f"    {vle_instr} {vs1_vreg}, ({vs1_ptr})         # 加载 {vs1} 块")
    lines.append(f"    vxor.vi {vs1_vreg}, {vs1_vreg}, -1")
    lines.append(f"    vand.vv {vd_vreg}, {vs2_vreg}, {vs1_vreg}")
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
    end_label = new_label("vandn_vv_end")
    lines.append(f"    beqz    {tail_count}, {end_label}")
    lines.append(f"    vsetvli zero, {tail_count}, e{sew}, m1, ta, ma")
    lines.append(f"    {vle_instr} {vs2_vreg}, ({vs2_ptr})         # 加载 {vs2} tail")
    lines.append(f"    {vle_instr} {vs1_vreg}, ({vs1_ptr})         # 加载 {vs1} tail")
    lines.append(f"    vxor.vi {vs1_vreg}, {vs1_vreg}, -1")
    lines.append(f"    vand.vv {vd_vreg}, {vs2_vreg}, {vs1_vreg}")
    lines.append(f"    {vse_instr} {vd_vreg}, ({vd_ptr}){mask_suffix}          # 写回 {vd} tail")
    lines.append(f"{end_label}:")

    return lines



def _build_vor_vv_lines(context) -> list[str]:
    """
    翻译 vor.vv 指令 (256-bit 模式)

    格式: vor.vv vd, vs2, vs1
    语义: vd[i] = vs2[i] | vs1[i] 对于 i in [0, vl)
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
    shift_amt = {8: 5, 16: 4, 32: 3, 64: 2}[sew]
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

    lines.append(f"# vor.vv {vd}, {vs2}, {vs1} (256-bit mode, SEW={sew})")
    lines.append(f"# Semantic: {vd}[i] = {vs2}[i] | {vs1}[i]")
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

    main_loop = new_label("vor_vv_main")
    after_main = new_label("vor_vv_after")

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
    lines.append(f"    vor.vv  {vd_vreg}, {vs2_vreg}, {vs1_vreg}{mask_suffix}     # {vd}[i] = {vs2}[i] | {vs1}[i]")
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
    end_label = new_label("vor_vv_end")
    lines.append(f"    beqz    {tail_count}, {end_label}")
    lines.append(f"    vsetvli zero, {tail_count}, e{sew}, m1, ta, ma")
    lines.append(f"    {vle_instr} {vs2_vreg}, ({vs2_ptr})         # 加载 {vs2} tail")
    lines.append(f"    {vle_instr} {vs1_vreg}, ({vs1_ptr})         # 加载 {vs1} tail")
    lines.append(f"    vor.vv  {vd_vreg}, {vs2_vreg}, {vs1_vreg}{mask_suffix}     # tail: {vd}[i] = {vs2}[i] | {vs1}[i]")
    lines.append(f"    {vse_instr} {vd_vreg}, ({vd_ptr}){mask_suffix}          # 写回 {vd} tail")
    lines.append(f"{end_label}:")

    return lines



def _build_vor_vi_lines(context) -> list[str]:
    """
    翻译 vor.vi 指令 (256-bit 模式)

    格式: vor.vi vd, vs2, imm
    语义: vd[i] = vs2[i] | sign_extend(imm) 对于 i in [0, vl)
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
    try:
        imm = _parse_int_operand(operands[2])
    except ValueError:
        raise InstructionValidationError(insn, f"vor.vi immediate must be an integer: {insn.op_str}")
    if imm < -16 or imm > 15:
        raise InstructionValidationError(insn, f"vor.vi immediate must be signed 5-bit (-16..15), got {imm}")

    sew = state.sew
    chunk_n = _chunk_size(sew)
    c_bytes = _chunk_bytes()
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
    if is_masked:
        mask_bit_idx = temps.alloc_gpr()
        v0_base = temps.alloc_gpr()

    vle_instr = _get_vle_instr(sew)
    vse_instr = _get_vse_instr(sew)

    lines.append(f"# vor.vi {vd}, {vs2}, {imm} (256-bit mode, SEW={sew})")
    lines.append(f"# Semantic: {vd}[i] = {vs2}[i] | sign_extend({imm})")
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

    main_loop = new_label("vor_vi_main")
    after_main = new_label("vor_vi_after")

    lines.append(f"    # --- 主循环: 每块处理 {chunk_n} 个元素 ({c_bytes} 字节) ---")
    lines.append(f"    beqz    {chunk_count}, {after_main}")
    lines.append(f"{main_loop}:")
    mask_suffix = ", v0.t" if is_masked else ""
    if is_masked:
        _emit_mask_extraction_chunk(lines, sew, mask_bit_idx, v0_base, vl_reg, temp)

    _emit_vsetvl_for_chunk(lines, chunk_n, sew, "m1", vl_reg, scratch_reg=temp)
    lines.append("")
    lines.append(f"    {vle_instr} {vs2_vreg}, ({vs2_ptr})         # 加载 {vs2} 块")
    lines.append(f"    vor.vi {vd_vreg}, {vs2_vreg}, {imm}{mask_suffix}          # {vd}[i] = {vs2}[i] | sign_extend({imm})")
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

    end_label = new_label("vor_vi_end")
    lines.append(f"    # --- 尾部 RVV chunk: 剩余 {tail_count} 个元素 ---")
    lines.append(f"    beqz    {tail_count}, {end_label}")
    if is_masked:
        _emit_mask_extraction_chunk(lines, sew, mask_bit_idx, v0_base, vl_reg, temp)
    lines.append(f"    vsetvli zero, {tail_count}, e{sew}, m1, ta, ma")
    lines.append(f"    {vle_instr} {vs2_vreg}, ({vs2_ptr})         # 加载 {vs2} tail")
    lines.append(f"    vor.vi {vd_vreg}, {vs2_vreg}, {imm}{mask_suffix}          # tail: {vd}[i] = {vs2}[i] | sign_extend({imm})")
    lines.append(f"    {vse_instr} {vd_vreg}, ({vd_ptr}){mask_suffix}          # 写回 {vd} tail")
    lines.append(f"{end_label}:")

    return lines



def _build_vor_vx_lines(context) -> list[str]:
    """
    翻译 vor.vx 指令 (256-bit 模式)

    格式: vor.vx vd, vs2, rs1
    语义: vd[i] = vs2[i] | rs1 对于 i in [0, vl)
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
    chunk_n = _chunk_size(sew)
    c_bytes = _chunk_bytes()
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
    if is_masked:
        mask_bit_idx = temps.alloc_gpr()
        v0_base = temps.alloc_gpr()
        mask_tmp = temps.alloc_gpr()

    vle_instr = _get_vle_instr(sew)
    vse_instr = _get_vse_instr(sew)

    lines.append(f"# vor.vx {vd}, {vs2}, {rs1} (256-bit mode, SEW={sew})")
    lines.append(f"# Semantic: {vd}[i] = {vs2}[i] | {rs1}")
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

    main_loop = new_label("vor_vx_main")
    after_main = new_label("vor_vx_after")

    lines.append(f"    # --- 主循环: 每块处理 {chunk_n} 个元素 ({c_bytes} 字节) ---")
    lines.append(f"    beqz    {chunk_count}, {after_main}")
    lines.append(f"{main_loop}:")
    mask_suffix = ", v0.t" if is_masked else ""
    if is_masked:
        if sew in (8, 16, 32):
            _emit_vsetvl_for_chunk(lines, chunk_n, sew, "m1", vl_reg, scratch_reg=temp)
            _emit_mask_load_byte_aligned_chunk(lines, sew, mask_bit_idx, v0_base, vl_reg)
        else:
            _emit_mask_extraction_chunk(lines, sew, mask_bit_idx, v0_base, vl_reg, mask_tmp)
            _emit_vsetvl_for_chunk(lines, chunk_n, sew, "m1", vl_reg, scratch_reg=temp)
    else:
        _emit_vsetvl_for_chunk(lines, chunk_n, sew, "m1", vl_reg, scratch_reg=temp)
    lines.append("")
    lines.append(f"    {vle_instr} {vs2_vreg}, ({vs2_ptr})         # 加载 {vs2} 块")
    lines.append(f"    vor.vx {vd_vreg}, {vs2_vreg}, {rs1}{mask_suffix}          # {vd}[i] = {vs2}[i] | {rs1}")
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

    end_label = new_label("vor_vx_end")
    lines.append(f"    # --- 尾部 RVV chunk: 剩余 {tail_count} 个元素 ---")
    lines.append(f"    beqz    {tail_count}, {end_label}")
    if is_masked:
        if sew in (8, 16, 32):
            lines.append(f"    vsetvli zero, {tail_count}, e{sew}, m1, ta, ma")
            _emit_mask_load_byte_aligned_chunk(lines, sew, mask_bit_idx, v0_base, vl_reg)
        else:
            _emit_mask_extraction_chunk(lines, sew, mask_bit_idx, v0_base, vl_reg, mask_tmp)
            lines.append(f"    vsetvli zero, {tail_count}, e{sew}, m1, ta, ma")
    else:
        lines.append(f"    vsetvli zero, {tail_count}, e{sew}, m1, ta, ma")
    lines.append(f"    {vle_instr} {vs2_vreg}, ({vs2_ptr})         # 加载 {vs2} tail")
    lines.append(f"    vor.vx {vd_vreg}, {vs2_vreg}, {rs1}{mask_suffix}          # tail: {vd}[i] = {vs2}[i] | {rs1}")
    lines.append(f"    {vse_instr} {vd_vreg}, ({vd_ptr}){mask_suffix}          # 写回 {vd} tail")
    lines.append(f"{end_label}:")

    return lines



def _build_vnot_v_lines(context) -> list[str]:
    """
    翻译 vnot.v 指令 (256-bit 模式)

    格式: vnot.v vd, vs2
    语义: vd[i] = ~vs2[i] 对于 i in [0, vl)
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

    vle_instr = _get_vle_instr(sew)
    vse_instr = _get_vse_instr(sew)

    lines.append(f"# vnot.v {vd}, {vs2} (256-bit mode, SEW={sew})")
    lines.append(f"# Semantic: {vd}[i] = ~{vs2}[i] (lowered to vxor.vi -1)")
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

    main_loop = new_label("vnot_v_main")
    after_main = new_label("vnot_v_after")

    lines.append(f"    # --- 主循环: 每块处理 {chunk_n} 个元素 ({c_bytes} 字节) ---")
    lines.append(f"    beqz    {chunk_count}, {after_main}")
    lines.append(f"{main_loop}:")
    _emit_vsetvl_for_chunk(lines, chunk_n, sew, "m1", vl_reg, scratch_reg=vl_reg)
    lines.append("")
    lines.append(f"    {vle_instr} {vs2_vreg}, ({vs2_ptr})         # 加载 {vs2} 块")
    lines.append(f"    vxor.vi {vd_vreg}, {vs2_vreg}, -1             # {vd}[i] = ~{vs2}[i]")
    lines.append(f"    {vse_instr} {vd_vreg}, ({vd_ptr}){mask_suffix}          # 写回 {vd} 块")
    lines.append("")
    lines.append(f"    addi    {vs2_ptr}, {vs2_ptr}, {c_bytes}")
    lines.append(f"    addi    {vd_ptr}, {vd_ptr}, {c_bytes}")
    lines.append(f"    addi    {chunk_count}, {chunk_count}, -1")
    lines.append(f"    bnez    {chunk_count}, {main_loop}")
    lines.append(f"{after_main}:")
    lines.append("")

    lines.append(f"    # --- 尾部 RVV chunk: 剩余 {tail_count} 个元素 ---")
    end_label = new_label("vnot_v_end")
    lines.append(f"    beqz    {tail_count}, {end_label}")
    lines.append(f"    vsetvli zero, {tail_count}, e{sew}, m1, ta, ma")
    lines.append(f"    {vle_instr} {vs2_vreg}, ({vs2_ptr})         # 加载 {vs2} tail")
    lines.append(f"    vxor.vi {vd_vreg}, {vs2_vreg}, -1             # tail: {vd}[i] = ~{vs2}[i]")
    lines.append(f"    {vse_instr} {vd_vreg}, ({vd_ptr}){mask_suffix}          # 写回 {vd} tail")
    lines.append(f"{end_label}:")

    return lines



def _build_vmax_vv_lines(context) -> list[str]:
    """
    翻译 vmax.vv 指令 (256-bit 模式)

    格式: vmax.vv vd, vs2, vs1
    语义: vd[i] = max_signed(vs2[i], vs1[i]) 对于 i in [0, vl)
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
    vs2 = operands[1]
    vs1 = operands[2]

    sew = state.sew
    chunk_n = _chunk_size(sew)
    c_bytes = _chunk_bytes()
    shift_amt = {8: 5, 16: 4, 32: 3, 64: 2}[sew]
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

    vle_instr = _get_vle_instr(sew)
    vse_instr = _get_vse_instr(sew)

    lines.append(f"# vmax.vv {vd}, {vs2}, {vs1} (256-bit mode, SEW={sew})")
    lines.append(f"# Semantic: {vd}[i] = max_signed({vs2}[i], {vs1}[i])")
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

    main_loop = new_label("vmax_vv_main")
    after_main = new_label("vmax_vv_after")

    lines.append(f"    # --- 主循环: 每块处理 {chunk_n} 个元素 ({c_bytes} 字节) ---")
    lines.append(f"    beqz    {chunk_count}, {after_main}")
    lines.append(f"{main_loop}:")
    _emit_vsetvl_for_chunk(lines, chunk_n, sew, "m1", vl_reg, scratch_reg=vl_reg)
    lines.append("")
    lines.append(f"    {vle_instr} {vs2_vreg}, ({vs2_ptr})         # 加载 {vs2} 块")
    lines.append(f"    {vle_instr} {vs1_vreg}, ({vs1_ptr})         # 加载 {vs1} 块")
    lines.append(f"    vmax.vv {vd_vreg}, {vs2_vreg}, {vs1_vreg}     # {vd}[i] = signed max({vs2}[i], {vs1}[i])")
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
    end_label = new_label("vmax_vv_end")
    lines.append(f"    beqz    {tail_count}, {end_label}")
    lines.append(f"    vsetvli zero, {tail_count}, e{sew}, m1, ta, ma")
    lines.append(f"    {vle_instr} {vs2_vreg}, ({vs2_ptr})         # 加载 {vs2} tail")
    lines.append(f"    {vle_instr} {vs1_vreg}, ({vs1_ptr})         # 加载 {vs1} tail")
    lines.append(f"    vmax.vv {vd_vreg}, {vs2_vreg}, {vs1_vreg}     # tail: signed max")
    lines.append(f"    {vse_instr} {vd_vreg}, ({vd_ptr}){mask_suffix}          # 写回 {vd} tail")
    lines.append(f"{end_label}:")

    return lines



def _build_vmaxu_vv_lines(context) -> list[str]:
    """
    翻译 vmaxu.vv 指令 (256-bit 模式)

    格式: vmaxu.vv vd, vs2, vs1
    语义: vd[i] = max_unsigned(vs2[i], vs1[i]) 对于 i in [0, vl)
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
    vs2 = operands[1]
    vs1 = operands[2]

    sew = state.sew
    chunk_n = _chunk_size(sew)
    c_bytes = _chunk_bytes()
    shift_amt = {8: 5, 16: 4, 32: 3, 64: 2}[sew]
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

    vle_instr = _get_vle_instr(sew)
    vse_instr = _get_vse_instr(sew)

    lines.append(f"# vmaxu.vv {vd}, {vs2}, {vs1} (256-bit mode, SEW={sew})")
    lines.append(f"# Semantic: {vd}[i] = max_unsigned({vs2}[i], {vs1}[i])")
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

    main_loop = new_label("vmaxu_vv_main")
    after_main = new_label("vmaxu_vv_after")

    lines.append(f"    # --- 主循环: 每块处理 {chunk_n} 个元素 ({c_bytes} 字节) ---")
    lines.append(f"    beqz    {chunk_count}, {after_main}")
    lines.append(f"{main_loop}:")
    _emit_vsetvl_for_chunk(lines, chunk_n, sew, "m1", vl_reg, scratch_reg=vl_reg)
    lines.append("")
    lines.append(f"    {vle_instr} {vs2_vreg}, ({vs2_ptr})         # 加载 {vs2} 块")
    lines.append(f"    {vle_instr} {vs1_vreg}, ({vs1_ptr})         # 加载 {vs1} 块")
    lines.append(f"    vmaxu.vv {vd_vreg}, {vs2_vreg}, {vs1_vreg}     # {vd}[i] = unsigned max({vs2}[i], {vs1}[i])")
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
    end_label = new_label("vmaxu_vv_end")
    lines.append(f"    beqz    {tail_count}, {end_label}")
    lines.append(f"    vsetvli zero, {tail_count}, e{sew}, m1, ta, ma")
    lines.append(f"    {vle_instr} {vs2_vreg}, ({vs2_ptr})         # 加载 {vs2} tail")
    lines.append(f"    {vle_instr} {vs1_vreg}, ({vs1_ptr})         # 加载 {vs1} tail")
    lines.append(f"    vmaxu.vv {vd_vreg}, {vs2_vreg}, {vs1_vreg}     # tail: unsigned max")
    lines.append(f"    {vse_instr} {vd_vreg}, ({vd_ptr}){mask_suffix}          # 写回 {vd} tail")
    lines.append(f"{end_label}:")

    return lines



def _emit_shift_vv(
    insn: RVInstruction,
    state: StateTracker,
    allocator: SimulatedStateLayout,
    new_label,
    *,
    opcode: str,
    symbol: str,
) -> List[str]:
    """翻译 vsll.vv / vsrl.vv 这类向量移位量指令。"""
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
    shift_amt = {8: 5, 16: 4, 32: 3, 64: 2}[sew]
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

    temp = temps.alloc_gpr()
    if is_masked:
        mask_bit_idx = temps.alloc_gpr()
        v0_base = temps.alloc_gpr()
    vle_instr = _get_vle_instr(sew)
    vse_instr = _get_vse_instr(sew)

    lines.append(f"# {opcode} {vd}, {vs2}, {vs1} (256-bit mode, SEW={sew})")
    lines.append(
        f"# Semantic: {vd}[i] = {vs2}[i] {symbol} "
        f"({vs1}[i] & (SEW - 1))"
    )
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
    lines.append(f"    {vle_instr} {vs1_vreg}, ({vs1_ptr})         # 加载 {vs1} 块")
    lines.append(f"    {opcode} {vd_vreg}, {vs2_vreg}, {vs1_vreg}     # {vd}[i] = {vs2}[i] {symbol} {vs1}[i]")
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
    end_label = new_label(f"{label_base}_end")
    lines.append(f"    beqz    {tail_count}, {end_label}")
    if is_masked:
        _emit_mask_extraction_chunk(lines, sew, mask_bit_idx, v0_base, vl_reg, temp)
    lines.append(f"    vsetvli zero, {tail_count}, e{sew}, m1, ta, ma")
    lines.append(f"    {vle_instr} {vs2_vreg}, ({vs2_ptr})         # 加载 {vs2} tail")
    lines.append(f"    {vle_instr} {vs1_vreg}, ({vs1_ptr})         # 加载 {vs1} tail")
    lines.append(f"    {opcode} {vd_vreg}, {vs2_vreg}, {vs1_vreg}     # tail: {vd}[i] = {vs2}[i] {symbol} {vs1}[i]")
    lines.append(f"    {vse_instr} {vd_vreg}, ({vd_ptr}){mask_suffix}          # 写回 {vd} tail")
    lines.append(f"{end_label}:")

    return lines



def _emit_shift_vx(
    insn: RVInstruction,
    state: StateTracker,
    allocator: SimulatedStateLayout,
    new_label,
    *,
    opcode: str,
    symbol: str,
) -> List[str]:
    """翻译 vsll.vx / vsrl.vx 这类标量移位量指令。"""
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
    chunk_n = _chunk_size(sew)
    c_bytes = _chunk_bytes()
    shift_amt = {8: 5, 16: 4, 32: 3, 64: 2}[sew]
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
    scalar_reg = temps.alloc_gpr()

    temp = temps.alloc_gpr()
    if is_masked:
        mask_bit_idx = temps.alloc_gpr()
        v0_base = temps.alloc_gpr()
    vle_instr = _get_vle_instr(sew)
    vse_instr = _get_vse_instr(sew)

    lines.append(f"# {opcode} {vd}, {vs2}, {rs1} (256-bit mode, SEW={sew})")
    lines.append(
        f"# Semantic: {vd}[i] = {vs2}[i] {symbol} "
        f"({rs1} & (SEW - 1))"
    )
    lines.append("")

    if is_masked:
        _emit_mask_setup(lines, mask_bit_idx, v0_base, temp)

    _load_vl_from_csr(lines, vl_reg=vl_reg, addr_reg=chunk_count)
    lines.append(f"    srli    {chunk_count}, {vl_reg}, {shift_amt}       # {chunk_count} = vl / {chunk_n}")
    lines.append(f"    andi    {tail_count}, {vl_reg}, {mask}              # {tail_count} = vl % {chunk_n}")
    lines.append(f"    mv      {scalar_reg}, {rs1}              # 保存标量移位量，RVV 指令按 SEW 自动取低位")
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
    lines.append(f"    {opcode} {vd_vreg}, {vs2_vreg}, {scalar_reg}      # {vd}[i] = {vs2}[i] {symbol} {rs1}")
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
    if is_masked:
        _emit_mask_extraction_chunk(lines, sew, mask_bit_idx, v0_base, vl_reg, temp)
    lines.append(f"    vsetvli zero, {tail_count}, e{sew}, m1, ta, ma")
    lines.append(f"    {vle_instr} {vs2_vreg}, ({vs2_ptr})         # 加载 {vs2} tail")
    lines.append(f"    {opcode} {vd_vreg}, {vs2_vreg}, {scalar_reg}      # tail: {vd}[i] = {vs2}[i] {symbol} {rs1}")
    lines.append(f"    {vse_instr} {vd_vreg}, ({vd_ptr}){mask_suffix}          # 写回 {vd} tail")
    lines.append(f"{end_label}:")

    return lines



def _build_vsll_vv_lines(context) -> list[str]:
    """翻译 vsll.vv 指令 (256-bit 模式)。"""
    insn = context.instruction
    state = context.state
    allocator = context.layout
    new_label = context.new_label
    return _emit_shift_vv(insn, state, allocator, new_label, opcode="vsll.vv", symbol="<<")



def _build_vsrl_vv_lines(context) -> list[str]:
    """翻译 vsrl.vv 指令 (256-bit 模式)。"""
    insn = context.instruction
    state = context.state
    allocator = context.layout
    new_label = context.new_label
    return _emit_shift_vv(insn, state, allocator, new_label, opcode="vsrl.vv", symbol=">>")



def _build_vsll_vx_lines(context) -> list[str]:
    """翻译 vsll.vx 指令 (256-bit 模式)。"""
    insn = context.instruction
    state = context.state
    allocator = context.layout
    new_label = context.new_label
    return _emit_shift_vx(insn, state, allocator, new_label, opcode="vsll.vx", symbol="<<")



def _build_vsrl_vx_lines(context) -> list[str]:
    """翻译 vsrl.vx 指令 (256-bit 模式)。"""
    insn = context.instruction
    state = context.state
    allocator = context.layout
    new_label = context.new_label
    return _emit_shift_vx(insn, state, allocator, new_label, opcode="vsrl.vx", symbol=">>")



def _build_vsll_vi_lines(context) -> list[str]:
    """
    翻译 vsll.vi 指令 (256-bit 模式)

    格式: vsll.vi vd, vs2, uimm
    语义: vd[i] = vs2[i] << uimm 对于 i in [0, vl)
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
    uimm = int(operands[2])

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
    data_reg = temps.alloc_gpr()

    temp = temps.alloc_gpr()
    if is_masked:
        mask_bit_idx = temps.alloc_gpr()
        v0_base = temps.alloc_gpr()
    vle_instr = _get_vle_instr(sew)
    vse_instr = _get_vse_instr(sew)
    int_load = {8: 'lbu', 16: 'lhu', 32: 'lwu', 64: 'ld'}[sew]
    int_store = {8: 'sb', 16: 'sh', 32: 'sw', 64: 'sd'}[sew]

    lines.append(f"# vsll.vi {vd}, {vs2}, {uimm} (256-bit mode, SEW={sew})")
    lines.append(f"# Semantic: {vd}[i] = {vs2}[i] << {uimm}")
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
    lines.append(f"    li      {vl_reg}, {vd_off:#x}")
    lines.append(f"    add     {vd_ptr}, t6, {vl_reg}              # {vd_ptr} = &{vd}")
    lines.append("")

    # ========== 主循环 (256-bit 块) ==========
    main_loop = new_label("vsll_vi_main")
    after_main = new_label("vsll_vi_after")

    lines.append(f"    # --- 主循环: 每块处理 {chunk_n} 个元素 ({c_bytes} 字节) ---")
    lines.append(f"    beqz    {chunk_count}, {after_main}")
    lines.append(f"{main_loop}:")
    mask_suffix = ", v0.t" if is_masked else ""
    if is_masked:
        _emit_mask_extraction_chunk(lines, sew, mask_bit_idx, v0_base, vl_reg, temp)

    _emit_vsetvl_for_chunk(lines, chunk_n, sew, "m1", vl_reg, scratch_reg=temp)
    lines.append("")
    lines.append(f"    {vle_instr} {vs2_vreg}, ({vs2_ptr})         # 加载 {vs2} 块")
    lines.append(f"    vsll.vi {vd_vreg}, {vs2_vreg}, {uimm}          # {vd}[i] = {vs2}[i] << {uimm}")
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

    # ========== 尾部 RVV 回退 ==========
    lines.append(f"    # --- 尾部 RVV chunk: 剩余 {tail_count} 个元素 ---")
    end_label = new_label("vsll_vi_end")

    lines.append(f"    beqz    {tail_count}, {end_label}")
    if is_masked:
        _emit_mask_extraction_chunk(lines, sew, mask_bit_idx, v0_base, vl_reg, temp)
    lines.append(f"    vsetvli zero, {tail_count}, e{sew}, m1, ta, ma")
    lines.append(f"    {vle_instr} {vs2_vreg}, ({vs2_ptr})         # 加载 {vs2} tail")
    lines.append(f"    vsll.vi {vd_vreg}, {vs2_vreg}, {uimm}{mask_suffix}          # tail: shift")
    lines.append(f"    {vse_instr} {vd_vreg}, ({vd_ptr}){mask_suffix}          # 写回 {vd} tail")
    lines.append(f"{end_label}:")
    return lines



def _build_vsrl_vi_lines(context) -> list[str]:
    """
    翻译 vsrl.vi 指令 (256-bit 模式)

    格式: vsrl.vi vd, vs2, uimm
    语义: vd[i] = vs2[i] >> uimm (logical) 对于 i in [0, vl)
    :return: 生成的汇编代码行列表
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
    vs2 = operands[1]
    uimm = int(operands[2])

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
    data_reg = temps.alloc_gpr()

    vle_instr = _get_vle_instr(sew)
    vse_instr = _get_vse_instr(sew)
    int_load = {8: 'lbu', 16: 'lhu', 32: 'lwu', 64: 'ld'}[sew]
    int_store = {8: 'sb', 16: 'sh', 32: 'sw', 64: 'sd'}[sew]

    lines.append(f"# vsrl.vi {vd}, {vs2}, {uimm} (256-bit mode, SEW={sew})")
    lines.append(f"# Semantic: {vd}[i] = {vs2}[i] >> {uimm} (logical)")
    lines.append("")

    _load_vl_from_csr(lines, vl_reg=vl_reg, addr_reg=chunk_count)
    lines.append(f"    srli    {chunk_count}, {vl_reg}, {shift_amt}       # {chunk_count} = vl / {chunk_n}")
    lines.append(f"    andi    {tail_count}, {vl_reg}, {mask}              # {tail_count} = vl % {chunk_n}")
    lines.append("")

    # 之后 vl_reg 不再使用，可复用为临时寄存器做 li（不破坏 tail_count）
    lines.append(f"    li      {vl_reg}, {vs2_off:#x}")
    lines.append(f"    add     {vs2_ptr}, t6, {vl_reg}             # {vs2_ptr} = &{vs2}")
    lines.append(f"    li      {vl_reg}, {vd_off:#x}")
    lines.append(f"    add     {vd_ptr}, t6, {vl_reg}              # {vd_ptr} = &{vd}")
    lines.append("")

    # ========== 主循环 (256-bit 块) ==========
    main_loop = new_label("vsrl_vi_main")
    after_main = new_label("vsrl_vi_after")

    lines.append(f"    # --- 主循环: 每块处理 {chunk_n} 个元素 ({c_bytes} 字节) ---")
    lines.append(f"    beqz    {chunk_count}, {after_main}")
    lines.append(f"{main_loop}:")
    _emit_vsetvl_for_chunk(lines, chunk_n, sew, "m1", vl_reg, scratch_reg=vl_reg)
    lines.append("")
    lines.append(f"    {vle_instr} {vs2_vreg}, ({vs2_ptr})         # 加载 {vs2} 块")
    lines.append(f"    vsrl.vi {vd_vreg}, {vs2_vreg}, {uimm}          # {vd}[i] = {vs2}[i] >> {uimm}")
    lines.append(f"    {vse_instr} {vd_vreg}, ({vd_ptr}){mask_suffix}          # 写回 {vd} 块")
    lines.append("")
    lines.append(f"    addi    {vs2_ptr}, {vs2_ptr}, {c_bytes}")
    lines.append(f"    addi    {vd_ptr}, {vd_ptr}, {c_bytes}")
    lines.append(f"    addi    {chunk_count}, {chunk_count}, -1")
    lines.append(f"    bnez    {chunk_count}, {main_loop}")
    lines.append(f"{after_main}:")
    lines.append("")

    # ========== 尾部标量回退 ==========
    lines.append(f"    # --- 尾部标量回退: 剩余 {tail_count} 个元素 ---")
    tail_loop = new_label("vsrl_vi_tail")
    end_label = new_label("vsrl_vi_end")

    lines.append(f"{tail_loop}:")
    lines.append(f"    beqz    {tail_count}, {end_label}")
    lines.append(f"    {int_load:<8} {data_reg}, 0({vs2_ptr})           # {data_reg} = {vs2}[i]")
    lines.append(f"    srli    {data_reg}, {data_reg}, {uimm}              # {data_reg} = {data_reg} >> {uimm}")
    lines.append(f"    {int_store:<8} {data_reg}, 0({vd_ptr})            # {vd}[i] = {data_reg}")
    lines.append(f"    addi    {vs2_ptr}, {vs2_ptr}, {elem_bytes}")
    lines.append(f"    addi    {vd_ptr}, {vd_ptr}, {elem_bytes}")
    lines.append(f"    addi    {tail_count}, {tail_count}, -1")
    lines.append(f"    j       {tail_loop}")
    lines.append(f"{end_label}:")

    return lines



def _build_vsra_vi_lines(context) -> list[str]:
    """
    翻译 vsra.vi 指令 (256-bit 模式)

    格式: vsra.vi vd, vs2, uimm
    语义: vd[i] = signed(vs2[i]) >> uimm 对于 i in [0, vl)
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
    vs2 = operands[1]
    try:
        uimm = _parse_int_operand(operands[2])
    except ValueError:
        raise InstructionValidationError(insn, f"vsra.vi immediate must be an integer: {insn.op_str}")

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
    data_reg = temps.alloc_gpr()

    vle_instr = _get_vle_instr(sew)
    vse_instr = _get_vse_instr(sew)
    int_load = _get_int_load_signed(sew)
    int_store = _get_int_store(sew)

    lines.append(f"# vsra.vi {vd}, {vs2}, {uimm} (256-bit mode, SEW={sew})")
    lines.append(f"# Semantic: {vd}[i] = signed({vs2}[i]) >> {uimm} (arithmetic)")
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

    main_loop = new_label("vsra_vi_main")
    after_main = new_label("vsra_vi_after")

    lines.append(f"    # --- 主循环: 每块处理 {chunk_n} 个元素 ({c_bytes} 字节) ---")
    lines.append(f"    beqz    {chunk_count}, {after_main}")
    lines.append(f"{main_loop}:")
    _emit_vsetvl_for_chunk(lines, chunk_n, sew, "m1", vl_reg, scratch_reg=vl_reg)
    lines.append("")
    lines.append(f"    {vle_instr} {vs2_vreg}, ({vs2_ptr})         # 加载 {vs2} 块")
    lines.append(f"    vsra.vi {vd_vreg}, {vs2_vreg}, {uimm}          # arithmetic shift right")
    lines.append(f"    {vse_instr} {vd_vreg}, ({vd_ptr}){mask_suffix}          # 写回 {vd} 块")
    lines.append("")
    lines.append(f"    addi    {vs2_ptr}, {vs2_ptr}, {c_bytes}")
    lines.append(f"    addi    {vd_ptr}, {vd_ptr}, {c_bytes}")
    lines.append(f"    addi    {chunk_count}, {chunk_count}, -1")
    lines.append(f"    bnez    {chunk_count}, {main_loop}")
    lines.append(f"{after_main}:")
    lines.append("")

    tail_loop = new_label("vsra_vi_tail")
    end_label = new_label("vsra_vi_end")
    lines.append(f"    # --- 尾部标量回退: 剩余 {tail_count} 个元素 ---")
    lines.append(f"{tail_loop}:")
    lines.append(f"    beqz    {tail_count}, {end_label}")
    lines.append(f"    {int_load:<8} {data_reg}, 0({vs2_ptr})           # {data_reg} = signed {vs2}[i]")
    lines.append(f"    srai    {data_reg}, {data_reg}, {uimm}              # arithmetic shift")
    lines.append(f"    {int_store:<8} {data_reg}, 0({vd_ptr})            # {vd}[i] = {data_reg}")
    lines.append(f"    addi    {vs2_ptr}, {vs2_ptr}, {elem_bytes}")
    lines.append(f"    addi    {vd_ptr}, {vd_ptr}, {elem_bytes}")
    lines.append(f"    addi    {tail_count}, {tail_count}, -1")
    lines.append(f"    j       {tail_loop}")
    lines.append(f"{end_label}:")

    return lines



def _build_vmv_x_s_lines(context) -> AssemblyBuilderOutput:
    """
    翻译 vmv.x.s 指令 (256-bit 模式)

    格式: vmv.x.s rd, vs2
    语义: rd = vs2[0] (提取第一个元素到标量整数寄存器)
    :return: 生成的汇编代码行列表
    """
    insn = context.instruction
    state = context.state
    allocator = context.layout
    lines = []
    mask_suffix = ""
    operands = insn.operands
    if len(operands) < 2:
        raise InstructionValidationError(insn, f"Invalid operands for {insn.opcode}: {insn.op_str}")

    rd = operands[0]
    vs2 = operands[1]

    sew = state.sew
    elem_bytes = sew // 8
    vs2_off = allocator.get_offset(vs2)

    temps = context.temp_register_allocator
    vs2_ptr = temps.alloc_gpr()

    # t6 must remain the state base through vstart cleanup. Its scratch address
    # register is reused by cleanup, so keep the pending result in a second GPR.
    writes_state_base = rd.strip().lower() in {"t6", "x31"}
    result_reg = temps.alloc_gpr() if writes_state_base else rd

    load_instr = {8: 'lb', 16: 'lh', 32: 'lw', 64: 'ld'}[sew]

    lines.append(f"# vmv.x.s {rd}, {vs2} (256-bit mode)")
    lines.append(f"# Semantic: {rd} = {vs2}[0]")
    lines.append("")

    lines.append(f"    li      {vs2_ptr}, {vs2_off:#x}")
    lines.append(f"    add     {vs2_ptr}, t6, {vs2_ptr}            # {vs2_ptr} = &{vs2}")
    lines.append(f"    {load_instr:<8} {result_reg}, 0({vs2_ptr})                   # {rd} = {vs2}[0]")

    if writes_state_base:
        return AssemblyFragments(tuple(lines), (f"    mv      {rd}, {result_reg}",))
    return lines



def _emit_vmv_whole_register(
    insn: RVInstruction,
    state: StateTracker,
    allocator: SimulatedStateLayout,
    new_label,
    nf: int,
) -> List[str]:
    """复制 nf 个连续 simulated vector register, 不依赖 vl/vtype。"""
    lines = []
    mask_suffix = ""
    operands = insn.operands
    if len(operands) < 2:
        raise InstructionValidationError(insn, f"Invalid operands for {insn.opcode}: {insn.op_str}")

    vd = operands[0]
    vs2 = operands[1]

    total_bytes = nf * allocator.vreg_size
    chunk_bytes = 32
    num_chunks = total_bytes // chunk_bytes

    vd_base_off = allocator.get_offset(vd)
    vs2_base_off = allocator.get_offset(vs2)

    vtemps = VRegTempAllocator(insn)
    temp_vreg = vtemps.alloc_vreg()

    temps = TempRegisterAllocator(insn, reserved_gprs=("t6",))
    vs2_ptr = temps.alloc_gpr()
    vd_ptr = temps.alloc_gpr()
    chunk_count = temps.alloc_gpr()

    lines.append(f"# vmv{nf}r.v {vd}, {vs2} (256-bit mode)")
    lines.append(f"# Semantic: copy {total_bytes} bytes from {vs2} to {vd} ({nf} whole vreg)")
    lines.append("")

    lines.append(f"    li      {vs2_ptr}, {vs2_base_off:#x}")
    lines.append(f"    add     {vs2_ptr}, t6, {vs2_ptr}            # {vs2_ptr} = &{vs2}")
    lines.append(f"    li      {vd_ptr}, {vd_base_off:#x}")
    lines.append(f"    add     {vd_ptr}, t6, {vd_ptr}             # {vd_ptr} = &{vd}")
    lines.append("")

    lines.append(f"    li      {chunk_count}, {num_chunks}")
    main_loop = new_label(f"vmv{nf}r_main")
    after_main = new_label(f"vmv{nf}r_after")

    lines.append(f"    # --- 主循环: 每块 {chunk_bytes} 字节, 共 {num_chunks} 块 ---")
    lines.append(f"{main_loop}:")
    lines.append(f"    vsetivli zero, 8, e32, m1, ta, ma")
    lines.append("")
    lines.append(f"    vle32.v {temp_vreg}, ({vs2_ptr})               # 从 {vs2} 加载 32 字节")
    lines.append(f"    vse32.v {temp_vreg}, ({vd_ptr})                # 写回 {vd}")
    lines.append("")
    lines.append(f"    addi    {vs2_ptr}, {vs2_ptr}, {chunk_bytes}")
    lines.append(f"    addi    {vd_ptr}, {vd_ptr}, {chunk_bytes}")
    lines.append(f"    addi    {chunk_count}, {chunk_count}, -1")
    lines.append(f"    bnez    {chunk_count}, {main_loop}")
    lines.append(f"{after_main}:")

    return lines



def _build_vmv1r_v_lines(context) -> list[str]:
    """翻译 vmv1r.v 指令 (1 个整向量寄存器移动, 256-bit 模式)。"""
    insn = context.instruction
    state = context.state
    allocator = context.layout
    new_label = context.new_label
    return _emit_vmv_whole_register(insn, state, allocator, new_label, nf=1)



def _build_vmv2r_v_lines(context) -> list[str]:
    """
    翻译 vmv2r.v 指令 (256-bit 模式)

    格式: vmv2r.v vd, vs2
    语义: 复制 2 个连续向量寄存器 (256 字节) 从 vs2..vs2+1 到 vd..vd+1
    :return: 生成的汇编代码行列表
    """
    insn = context.instruction
    state = context.state
    allocator = context.layout
    new_label = context.new_label
    return _emit_vmv_whole_register(insn, state, allocator, new_label, nf=2)



def _build_vmv4r_v_lines(context) -> list[str]:
    """翻译 vmv4r.v 指令 (4 个整向量寄存器移动, 256-bit 模式)。"""
    insn = context.instruction
    state = context.state
    allocator = context.layout
    new_label = context.new_label
    return _emit_vmv_whole_register(insn, state, allocator, new_label, nf=4)



def _build_vmv8r_v_lines(context) -> list[str]:
    """翻译 vmv8r.v 指令 (8 个整向量寄存器移动, 256-bit 模式)。"""
    insn = context.instruction
    state = context.state
    allocator = context.layout
    new_label = context.new_label
    return _emit_vmv_whole_register(insn, state, allocator, new_label, nf=8)
