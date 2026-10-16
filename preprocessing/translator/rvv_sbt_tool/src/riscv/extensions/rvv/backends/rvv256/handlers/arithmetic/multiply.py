"""RVV256 整数乘除、乘加与反向减法。

本文件由原算术模块按语义族机械拆分；函数体保持原样，公共状态与 ABI 访问统一复用 common。
"""


from riscv.extensions.rvv.translation.contracts import InstructionValidationError
from riscv.extensions.rvv.runtime.layout import CSR_OFFSETS
from riscv.extensions.rvv.backends.rvv256.temp_regs import VRegTempAllocator
from riscv.extensions.rvv.backends.rvv256.support import (
    _chunk_size,
    _chunk_bytes,
    _emit_vsetvl_for_chunk,
    _load_vl_from_csr,
    _get_vle_instr,
    _get_vse_instr,
    _emit_mask_setup,
    _emit_mask_extraction_chunk,
    _emit_mask_extraction_tail,
    _emit_mask_load_byte_aligned_chunk,
)

from riscv.extensions.rvv.backends.rvv256.support import _parse_int_operand


def _build_vmul_vv_lines(context) -> list[str]:
    """
    翻译 vmul.vv 指令 (256-bit 模式)

    RVV 1.0 语义: signed SEW x SEW multiply, write the low SEW bits.
    """
    insn = context.instruction
    state = context.state
    allocator = context.layout
    new_label = context.new_label
    lines = []
    mask_suffix = ""
    operands = insn.operands
    if len(operands) != 3:
        raise InstructionValidationError(insn, f"Invalid operands for {insn.opcode}: {insn.op_str}")

    vd, vs2, vs1 = operands
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

    lines.append(f"# vmul.vv {vd}, {vs2}, {vs1} (256-bit mode, RVV1.0)")
    lines.append(f"# Semantic: {vd}[i] = low_SEW_bits({vs2}[i] * {vs1}[i])")
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

    main_loop = new_label("vmul_vv_main")
    after_main = new_label("vmul_vv_after")
    lines.append(f"    # --- 主循环: 每块处理 {chunk_n} 个元素 ({c_bytes} 字节) ---")
    lines.append(f"    beqz    {chunk_count}, {after_main}")
    lines.append(f"{main_loop}:")
    _emit_vsetvl_for_chunk(lines, chunk_n, sew, "m1", vl_reg, scratch_reg=vl_reg)
    lines.append(f"    {vle_instr} {vs2_vreg}, ({vs2_ptr})")
    lines.append(f"    {vle_instr} {vs1_vreg}, ({vs1_ptr})")
    lines.append(f"    vmul.vv {vd_vreg}, {vs2_vreg}, {vs1_vreg}")
    lines.append(f"    {vse_instr} {vd_vreg}, ({vd_ptr}){mask_suffix}")
    lines.append(f"    addi    {vs2_ptr}, {vs2_ptr}, {c_bytes}")
    lines.append(f"    addi    {vs1_ptr}, {vs1_ptr}, {c_bytes}")
    lines.append(f"    addi    {vd_ptr}, {vd_ptr}, {c_bytes}")
    lines.append(f"    addi    {chunk_count}, {chunk_count}, -1")
    lines.append(f"    bnez    {chunk_count}, {main_loop}")
    lines.append(f"{after_main}:")
    lines.append("")

    end_label = new_label("vmul_vv_end")
    lines.append(f"    # --- 尾部 RVV chunk: 剩余 {tail_count} 个元素 ---")
    lines.append(f"    beqz    {tail_count}, {end_label}")
    lines.append(f"    vsetvli zero, {tail_count}, e{sew}, m1, ta, ma")
    lines.append(f"    {vle_instr} {vs2_vreg}, ({vs2_ptr})")
    lines.append(f"    {vle_instr} {vs1_vreg}, ({vs1_ptr})")
    lines.append(f"    vmul.vv {vd_vreg}, {vs2_vreg}, {vs1_vreg}")
    lines.append(f"    {vse_instr} {vd_vreg}, ({vd_ptr}){mask_suffix}")
    lines.append(f"{end_label}:")

    return lines



def _build_vmadd_vv_lines(context) -> list[str]:
    """
    翻译 vmadd.vv 指令 (256-bit 模式)

    RVV 1.0 语义: vd[i] = low_SEW_bits(old_vd[i] * vs1[i] + vs2[i]).
    """
    insn = context.instruction
    state = context.state
    allocator = context.layout
    new_label = context.new_label
    lines = []
    mask_suffix = ""
    operands = insn.operands
    if len(operands) != 3:
        raise InstructionValidationError(insn, f"Invalid operands for {insn.opcode}: {insn.op_str}")

    vd, vs1, vs2 = operands
    sew = state.sew
    chunk_n = _chunk_size(sew)
    c_bytes = _chunk_bytes()
    shift_amt = {8: 5, 16: 4, 32: 3, 64: 2}[sew]
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

    lines.append(f"# vmadd.vv {vd}, {vs1}, {vs2} (256-bit mode, RVV1.0)")
    lines.append(f"# Semantic: {vd}[i] = low_SEW_bits(old {vd}[i] * {vs1}[i] + {vs2}[i])")
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

    main_loop = new_label("vmadd_vv_main")
    after_main = new_label("vmadd_vv_after")
    lines.append(f"    # --- 主循环: 每块处理 {chunk_n} 个元素 ({c_bytes} 字节) ---")
    lines.append(f"    beqz    {chunk_count}, {after_main}")
    lines.append(f"{main_loop}:")
    _emit_vsetvl_for_chunk(lines, chunk_n, sew, "m1", vl_reg, scratch_reg=vl_reg)
    lines.append(f"    {vle_instr} {vd_vreg}, ({vd_ptr})")
    lines.append(f"    {vle_instr} {vs1_vreg}, ({vs1_ptr})")
    lines.append(f"    {vle_instr} {vs2_vreg}, ({vs2_ptr})")
    lines.append(f"    vmadd.vv {vd_vreg}, {vs1_vreg}, {vs2_vreg}")
    lines.append(f"    {vse_instr} {vd_vreg}, ({vd_ptr}){mask_suffix}")
    lines.append(f"    addi    {vd_ptr}, {vd_ptr}, {c_bytes}")
    lines.append(f"    addi    {vs1_ptr}, {vs1_ptr}, {c_bytes}")
    lines.append(f"    addi    {vs2_ptr}, {vs2_ptr}, {c_bytes}")
    lines.append(f"    addi    {chunk_count}, {chunk_count}, -1")
    lines.append(f"    bnez    {chunk_count}, {main_loop}")
    lines.append(f"{after_main}:")
    lines.append("")

    end_label = new_label("vmadd_vv_end")
    lines.append(f"    # --- 尾部 RVV chunk: 剩余 {tail_count} 个元素 ---")
    lines.append(f"    beqz    {tail_count}, {end_label}")
    lines.append(f"    vsetvli zero, {tail_count}, e{sew}, m1, ta, ma")
    lines.append(f"    {vle_instr} {vd_vreg}, ({vd_ptr})")
    lines.append(f"    {vle_instr} {vs1_vreg}, ({vs1_ptr})")
    lines.append(f"    {vle_instr} {vs2_vreg}, ({vs2_ptr})")
    lines.append(f"    vmadd.vv {vd_vreg}, {vs1_vreg}, {vs2_vreg}")
    lines.append(f"    {vse_instr} {vd_vreg}, ({vd_ptr}){mask_suffix}")
    lines.append(f"{end_label}:")

    return lines



def _build_vmadd_vx_lines(context) -> list[str]:
    """翻译无掩码 ``vmadd.vx vd, rs1, vs2``。

    RVV 的原生 operand 顺序是 ``vd, rs1, vs2``，语义为
    ``low_SEW_bits(old_vd * rs1 + vs2)``。旧目的值必须先从模拟状态加载，
    而标量寄存器直接作为原生 RVV 标量输入；new_label 不放开 ``v0.t``，
    因而这里不会误把执行掩码当作普通第三操作数。
    """
    insn = context.instruction
    state = context.state
    allocator = context.layout
    new_label = context.new_label
    lines = []
    operands = insn.operands
    if len(operands) != 3:
        raise InstructionValidationError(insn, f"Invalid operands for {insn.opcode}: {insn.op_str}")

    vd, rs1, vs2 = operands
    sew = state.sew
    if sew not in (8, 16, 32, 64):
        raise InstructionValidationError(insn, f"vmadd.vx only supports SEW=8/16/32/64, got SEW={sew}")

    chunk_n = _chunk_size(sew)
    c_bytes = _chunk_bytes()
    shift_amt = {8: 5, 16: 4, 32: 3, 64: 2}[sew]
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
    temp = temps.alloc_gpr()

    vle_instr = _get_vle_instr(sew)
    vse_instr = _get_vse_instr(sew)

    lines.append(f"# vmadd.vx {vd}, {rs1}, {vs2} (256-bit mode, RVV1.0)")
    lines.append(
        f"# Semantic: {vd}[i] = low_SEW_bits(old {vd}[i] * {rs1} + {vs2}[i])"
    )
    lines.append("")

    _load_vl_from_csr(lines, vl_reg=vl_reg, addr_reg=chunk_count)
    lines.append(
        f"    srli    {chunk_count}, {vl_reg}, {shift_amt}"
        f"       # {chunk_count} = vl / {chunk_n}"
    )
    lines.append(
        f"    andi    {tail_count}, {vl_reg}, {mask}"
        f"              # {tail_count} = vl % {chunk_n}"
    )
    lines.append("")

    lines.append(f"    li      {temp}, {vd_off:#x}")
    lines.append(f"    add     {vd_ptr}, t6, {temp}              # {vd_ptr} = &{vd}")
    lines.append(f"    li      {temp}, {vs2_off:#x}")
    lines.append(f"    add     {vs2_ptr}, t6, {temp}             # {vs2_ptr} = &{vs2}")
    lines.append("")

    main_loop = new_label("vmadd_vx_main")
    after_main = new_label("vmadd_vx_after")
    lines.append(f"    # --- 主循环: 每块处理 {chunk_n} 个元素 ({c_bytes} 字节) ---")
    lines.append(f"    beqz    {chunk_count}, {after_main}")
    lines.append(f"{main_loop}:")
    _emit_vsetvl_for_chunk(lines, chunk_n, sew, "m1", vl_reg, scratch_reg=temp)
    lines.append(f"    {vle_instr} {vd_vreg}, ({vd_ptr})")
    lines.append(f"    {vle_instr} {vs2_vreg}, ({vs2_ptr})")
    lines.append(f"    vmadd.vx {vd_vreg}, {rs1}, {vs2_vreg}")
    lines.append(f"    {vse_instr} {vd_vreg}, ({vd_ptr})")
    lines.append(f"    addi    {vd_ptr}, {vd_ptr}, {c_bytes}")
    lines.append(f"    addi    {vs2_ptr}, {vs2_ptr}, {c_bytes}")
    lines.append(f"    addi    {chunk_count}, {chunk_count}, -1")
    lines.append(f"    bnez    {chunk_count}, {main_loop}")
    lines.append(f"{after_main}:")
    lines.append("")

    end_label = new_label("vmadd_vx_end")
    lines.append(f"    # --- 尾部 RVV chunk: 剩余 {tail_count} 个元素 ---")
    lines.append(f"    beqz    {tail_count}, {end_label}")
    lines.append(f"    vsetvli zero, {tail_count}, e{sew}, m1, ta, ma")
    lines.append(f"    {vle_instr} {vd_vreg}, ({vd_ptr})")
    lines.append(f"    {vle_instr} {vs2_vreg}, ({vs2_ptr})")
    lines.append(f"    vmadd.vx {vd_vreg}, {rs1}, {vs2_vreg}")
    lines.append(f"    {vse_instr} {vd_vreg}, ({vd_ptr})")
    lines.append(f"{end_label}:")

    return lines



def _build_vmacc_vx_lines(context) -> list[str]:
    """
    翻译 vmacc.vx 指令 (256-bit 模式)

    RVV 1.0 语义: vd[i] = low_SEW_bits(rs1 * vs2[i] + old_vd[i]).
    """
    insn = context.instruction
    state = context.state
    allocator = context.layout
    new_label = context.new_label
    lines = []
    mask_suffix = ""
    operands = insn.operands
    if len(operands) != 3:
        raise InstructionValidationError(insn, f"Invalid operands for {insn.opcode}: {insn.op_str}")

    vd, rs1, vs2 = operands
    sew = state.sew
    chunk_n = _chunk_size(sew)
    c_bytes = _chunk_bytes()
    shift_amt = {8: 5, 16: 4, 32: 3, 64: 2}[sew]
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
    temp = temps.alloc_gpr()

    vle_instr = _get_vle_instr(sew)
    vse_instr = _get_vse_instr(sew)

    lines.append(f"# vmacc.vx {vd}, {rs1}, {vs2} (256-bit mode, RVV1.0)")
    lines.append(f"# Semantic: {vd}[i] = low_SEW_bits({rs1} * {vs2}[i] + old {vd}[i])")
    lines.append("")

    main_loop = new_label("vmacc_vx_main")
    after_main = new_label("vmacc_vx_after")
    end_label = new_label("vmacc_vx_end")
    _load_vl_from_csr(lines, vl_reg=vl_reg, addr_reg=chunk_count)
    # Resume only the unfinished suffix; prestart accumulator elements must
    # not be multiplied and added a second time after migration.
    lines.append(f"    li      {temp}, {CSR_OFFSETS['vstart']:#x}")
    lines.append(f"    add     {temp}, t6, {temp}")
    lines.append(f"    ld      {temp}, 0({temp})")
    lines.append(f"    bgeu    {temp}, {vl_reg}, {end_label}")
    lines.append(f"    sub     {vl_reg}, {vl_reg}, {temp}")
    lines.append(f"    srli    {chunk_count}, {vl_reg}, {shift_amt}       # {chunk_count} = vl / {chunk_n}")
    lines.append(f"    andi    {tail_count}, {vl_reg}, {mask}              # {tail_count} = vl % {chunk_n}")
    lines.append("")

    lines.append(f"    slli    {temp}, {temp}, {(sew // 8).bit_length() - 1}")
    lines.append(f"    li      {vd_ptr}, {vd_off:#x}")
    lines.append(f"    add     {vd_ptr}, t6, {vd_ptr}")
    lines.append(f"    add     {vd_ptr}, {vd_ptr}, {temp}")
    lines.append(f"    li      {vs2_ptr}, {vs2_off:#x}")
    lines.append(f"    add     {vs2_ptr}, t6, {vs2_ptr}")
    lines.append(f"    add     {vs2_ptr}, {vs2_ptr}, {temp}")
    lines.append("")

    lines.append(f"    # --- 主循环: 每块处理 {chunk_n} 个元素 ({c_bytes} 字节) ---")
    lines.append(f"    beqz    {chunk_count}, {after_main}")
    lines.append(f"{main_loop}:")
    _emit_vsetvl_for_chunk(lines, chunk_n, sew, "m1", vl_reg, scratch_reg=temp)
    lines.append(f"    {vle_instr} {vd_vreg}, ({vd_ptr})")
    lines.append(f"    {vle_instr} {vs2_vreg}, ({vs2_ptr})")
    lines.append(f"    vmacc.vx {vd_vreg}, {rs1}, {vs2_vreg}{mask_suffix}")
    lines.append(f"    {vse_instr} {vd_vreg}, ({vd_ptr}){mask_suffix}")
    lines.append(f"    addi    {vd_ptr}, {vd_ptr}, {c_bytes}")
    lines.append(f"    addi    {vs2_ptr}, {vs2_ptr}, {c_bytes}")
    lines.append(f"    addi    {chunk_count}, {chunk_count}, -1")
    lines.append(f"    bnez    {chunk_count}, {main_loop}")
    lines.append(f"{after_main}:")
    lines.append("")

    lines.append(f"    # --- 尾部 RVV chunk: 剩余 {tail_count} 个元素 ---")
    lines.append(f"    beqz    {tail_count}, {end_label}")
    lines.append(f"    vsetvli zero, {tail_count}, e{sew}, m1, ta, ma")
    lines.append(f"    {vle_instr} {vd_vreg}, ({vd_ptr})")
    lines.append(f"    {vle_instr} {vs2_vreg}, ({vs2_ptr})")
    lines.append(f"    vmacc.vx {vd_vreg}, {rs1}, {vs2_vreg}{mask_suffix}")
    lines.append(f"    {vse_instr} {vd_vreg}, ({vd_ptr}){mask_suffix}")
    lines.append(f"{end_label}:")

    return lines



def _build_vmacc_vv_lines(context) -> list[str]:
    """
    翻译 vmacc.vv 指令 (256-bit 模式)

    格式: vmacc.vv vd, vs1, vs2
    语义: vd[i] += vs1[i] * vs2[i]
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
    vs1 = operands[1]
    vs2 = operands[2]

    sew = state.sew
    chunk_n = _chunk_size(sew)
    c_bytes = _chunk_bytes()
    shift_amt = {8: 5, 16: 4, 32: 3, 64: 2}[sew]
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
    temp = temps.alloc_gpr()

    vle_instr = _get_vle_instr(sew)
    vse_instr = _get_vse_instr(sew)

    lines.append(f"# vmacc.vv {vd}, {vs1}, {vs2} (256-bit mode, SEW={sew})")
    lines.append(f"# Semantic: {vd}[i] += {vs1}[i] * {vs2}[i]")
    lines.append("")

    _load_vl_from_csr(lines, vl_reg=vl_reg, addr_reg=chunk_count)
    lines.append(f"    srli    {chunk_count}, {vl_reg}, {shift_amt}       # {chunk_count} = vl / {chunk_n}")
    lines.append(f"    andi    {tail_count}, {vl_reg}, {mask}              # {tail_count} = vl % {chunk_n}")
    lines.append("")

    lines.append(f"    li      {temp}, {vd_off:#x}")
    lines.append(f"    add     {vd_ptr}, t6, {temp}             # {vd_ptr} = &{vd}")
    lines.append(f"    li      {temp}, {vs1_off:#x}")
    lines.append(f"    add     {vs1_ptr}, t6, {temp}            # {vs1_ptr} = &{vs1}")
    lines.append(f"    li      {temp}, {vs2_off:#x}")
    lines.append(f"    add     {vs2_ptr}, t6, {temp}            # {vs2_ptr} = &{vs2}")
    lines.append("")

    main_loop = new_label("vmacc_vv_main")
    after_main = new_label("vmacc_vv_after")
    end_label = new_label("vmacc_vv_end")

    lines.append(f"    # --- 主循环: 每块处理 {chunk_n} 个元素 ({c_bytes} 字节) ---")
    lines.append(f"    beqz    {chunk_count}, {after_main}")
    lines.append(f"{main_loop}:")
    _emit_vsetvl_for_chunk(lines, chunk_n, sew, "m1", vl_reg, scratch_reg=temp)
    lines.append(f"    {vle_instr} {vd_vreg}, ({vd_ptr})")
    lines.append(f"    {vle_instr} {vs1_vreg}, ({vs1_ptr})")
    lines.append(f"    {vle_instr} {vs2_vreg}, ({vs2_ptr})")
    lines.append(f"    vmacc.vv {vd_vreg}, {vs1_vreg}, {vs2_vreg}")
    lines.append(f"    {vse_instr} {vd_vreg}, ({vd_ptr})")
    lines.append(f"    addi    {vd_ptr}, {vd_ptr}, {c_bytes}")
    lines.append(f"    addi    {vs1_ptr}, {vs1_ptr}, {c_bytes}")
    lines.append(f"    addi    {vs2_ptr}, {vs2_ptr}, {c_bytes}")
    lines.append(f"    addi    {chunk_count}, {chunk_count}, -1")
    lines.append(f"    bnez    {chunk_count}, {main_loop}")
    lines.append(f"{after_main}:")
    lines.append(f"    beqz    {tail_count}, {end_label}")
    lines.append(f"    vsetvli zero, {tail_count}, e{sew}, m1, ta, ma")
    lines.append(f"    {vle_instr} {vd_vreg}, ({vd_ptr})")
    lines.append(f"    {vle_instr} {vs1_vreg}, ({vs1_ptr})")
    lines.append(f"    {vle_instr} {vs2_vreg}, ({vs2_ptr})")
    lines.append(f"    vmacc.vv {vd_vreg}, {vs1_vreg}, {vs2_vreg}")
    lines.append(f"    {vse_instr} {vd_vreg}, ({vd_ptr})")
    lines.append(f"{end_label}:")

    return lines



def _build_vmul_vx_lines(context) -> list[str]:
    """
    翻译 vmul.vx 指令 (256-bit 模式)

    RVV 1.0 语义: signed SEW x SEW multiply, write the low SEW bits.
    """
    insn = context.instruction
    state = context.state
    allocator = context.layout
    new_label = context.new_label
    lines = []
    mask_suffix = ""
    operands = insn.operands
    if len(operands) != 3:
        raise InstructionValidationError(insn, f"Invalid operands for {insn.opcode}: {insn.op_str}")

    vd, vs2, rs1 = operands
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

    vle_instr = _get_vle_instr(sew)
    vse_instr = _get_vse_instr(sew)
    int_load = {8: 'lbu', 16: 'lhu', 32: 'lwu', 64: 'ld'}[sew]
    int_store = {8: 'sb', 16: 'sh', 32: 'sw', 64: 'sd'}[sew]

    lines.append(f"# vmul.vx {vd}, {vs2}, {rs1} (256-bit mode, RVV1.0)")
    lines.append(f"# Semantic: {vd}[i] = low_SEW_bits({vs2}[i] * {rs1})")
    _load_vl_from_csr(lines, vl_reg=vl_reg, addr_reg=chunk_count)
    lines.append(f"    srli    {chunk_count}, {vl_reg}, {shift_amt}       # {chunk_count} = vl / {chunk_n}")
    lines.append(f"    andi    {tail_count}, {vl_reg}, {mask}              # {tail_count} = vl % {chunk_n}")
    lines.append(f"    li      {temp}, {vs2_off:#x}")
    lines.append(f"    add     {vs2_ptr}, t6, {temp}            # {vs2_ptr} = &{vs2}")
    lines.append(f"    li      {temp}, {vd_off:#x}")
    lines.append(f"    add     {vd_ptr}, t6, {temp}             # {vd_ptr} = &{vd}")

    main_loop = new_label("vmul_vx_main")
    after_main = new_label("vmul_vx_after")
    lines.append(f"    beqz    {chunk_count}, {after_main}")
    lines.append(f"{main_loop}:")
    _emit_vsetvl_for_chunk(lines, chunk_n, sew, "m1", vl_reg, scratch_reg=temp)
    lines.append(f"    {vle_instr} {vs2_vreg}, ({vs2_ptr})")
    lines.append(f"    vmul.vx {vd_vreg}, {vs2_vreg}, {rs1}")
    lines.append(f"    {vse_instr} {vd_vreg}, ({vd_ptr}){mask_suffix}")
    lines.append(f"    addi    {vs2_ptr}, {vs2_ptr}, {c_bytes}")
    lines.append(f"    addi    {vd_ptr}, {vd_ptr}, {c_bytes}")
    lines.append(f"    addi    {chunk_count}, {chunk_count}, -1")
    lines.append(f"    bnez    {chunk_count}, {main_loop}")
    lines.append(f"{after_main}:")

    tail_loop = new_label("vmul_vx_tail")
    end_label = new_label("vmul_vx_end")
    lines.append(f"{tail_loop}:")
    lines.append(f"    beqz    {tail_count}, {end_label}")
    lines.append(f"    {int_load:<8} {data_reg}, 0({vs2_ptr})")
    lines.append(f"    mul     {data_reg}, {data_reg}, {rs1}")
    lines.append(f"    {int_store:<8} {data_reg}, 0({vd_ptr})")
    lines.append(f"    addi    {vs2_ptr}, {vs2_ptr}, {elem_bytes}")
    lines.append(f"    addi    {vd_ptr}, {vd_ptr}, {elem_bytes}")
    lines.append(f"    addi    {tail_count}, {tail_count}, -1")
    lines.append(f"    j       {tail_loop}")
    lines.append(f"{end_label}:")

    return lines



def _build_vdiv_vx_lines(context) -> list[str]:
    """
    翻译 vdiv.vx 指令 (256-bit 模式, signed integer divide)

    格式: vdiv.vx vd, vs2, rs1
    语义: vd[i] = signed(vs2[i]) / signed(rs1)
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
    scalar = temps.alloc_gpr()
    temp = temps.alloc_gpr()

    vle_instr = _get_vle_instr(sew)
    vse_instr = _get_vse_instr(sew)

    lines.append(f"# vdiv.vx {vd}, {vs2}, {rs1} (256-bit mode, SEW={sew})")
    lines.append(f"# Semantic: {vd}[i] = signed({vs2}[i]) / signed({rs1})")
    lines.append("")

    lines.append(f"    slli    {scalar}, {rs1}, {64 - sew}              # scalar low e{sew} bits")
    lines.append(f"    srai    {scalar}, {scalar}, {64 - sew}              # sign-extend scalar to XLEN")
    _load_vl_from_csr(lines, vl_reg=vl_reg, addr_reg=chunk_count)
    lines.append(f"    srli    {chunk_count}, {vl_reg}, {shift_amt}       # {chunk_count} = vl / {chunk_n}")
    lines.append(f"    andi    {tail_count}, {vl_reg}, {mask}              # {tail_count} = vl % {chunk_n}")
    lines.append("")

    lines.append(f"    li      {temp}, {vs2_off:#x}")
    lines.append(f"    add     {vs2_ptr}, t6, {temp}            # {vs2_ptr} = &{vs2}")
    lines.append(f"    li      {temp}, {vd_off:#x}")
    lines.append(f"    add     {vd_ptr}, t6, {temp}             # {vd_ptr} = &{vd}")
    lines.append("")

    main_loop = new_label("vdiv_vx_main")
    after_main = new_label("vdiv_vx_after")
    end_label = new_label("vdiv_vx_end")

    lines.append(f"    # --- 主循环: 每块处理 {chunk_n} 个元素 ({c_bytes} 字节) ---")
    lines.append(f"    beqz    {chunk_count}, {after_main}")
    lines.append(f"{main_loop}:")
    _emit_vsetvl_for_chunk(lines, chunk_n, sew, "m1", vl_reg, scratch_reg=temp)
    lines.append(f"    {vle_instr} {vs2_vreg}, ({vs2_ptr})")
    lines.append(f"    vdiv.vx {vd_vreg}, {vs2_vreg}, {scalar}")
    lines.append(f"    {vse_instr} {vd_vreg}, ({vd_ptr})")
    lines.append(f"    addi    {vs2_ptr}, {vs2_ptr}, {c_bytes}")
    lines.append(f"    addi    {vd_ptr}, {vd_ptr}, {c_bytes}")
    lines.append(f"    addi    {chunk_count}, {chunk_count}, -1")
    lines.append(f"    bnez    {chunk_count}, {main_loop}")
    lines.append(f"{after_main}:")
    lines.append(f"    beqz    {tail_count}, {end_label}")
    lines.append(f"    vsetvli zero, {tail_count}, e{sew}, m1, ta, ma")
    lines.append(f"    {vle_instr} {vs2_vreg}, ({vs2_ptr})")
    lines.append(f"    vdiv.vx {vd_vreg}, {vs2_vreg}, {scalar}")
    lines.append(f"    {vse_instr} {vd_vreg}, ({vd_ptr})")
    lines.append(f"{end_label}:")

    return lines



def _build_vrsub_vi_lines(context) -> list[str]:
    """
    翻译 vrsub.vi 指令 (256-bit 模式)

    RVV 1.0 语义: vd[i] = imm - vs2[i].
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
    if len(operands) != 3:
        raise InstructionValidationError(insn, f"Invalid operands for {insn.opcode}: {insn.op_str}")

    vd, vs2, imm_s = operands
    imm = _parse_int_operand(imm_s)
    if imm < -16 or imm > 15:
        raise InstructionValidationError(insn, f"vrsub.vi immediate must be signed 5-bit (-16..15), got {imm}")

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
        # e64,m1 的 4-bit chunk 和标量尾部均需要保留独立的 raw mask byte；
        # data_reg / temp 仍分别承担元素值与立即数，不能与其混用。
        mask_tmp = temps.alloc_gpr()

    vle_instr = _get_vle_instr(sew)
    vse_instr = _get_vse_instr(sew)
    int_load = {8: 'lbu', 16: 'lhu', 32: 'lwu', 64: 'ld'}[sew]
    int_store = {8: 'sb', 16: 'sh', 32: 'sw', 64: 'sd'}[sew]

    lines.append(f"# vrsub.vi {vd}, {vs2}, {imm} (256-bit mode, RVV1.0)")
    lines.append(f"# Semantic: {vd}[i] = {imm} - {vs2}[i]")
    if is_masked:
        _emit_mask_setup(lines, mask_bit_idx, v0_base, temp)

    _load_vl_from_csr(lines, vl_reg=vl_reg, addr_reg=chunk_count)
    lines.append(f"    srli    {chunk_count}, {vl_reg}, {shift_amt}       # {chunk_count} = vl / {chunk_n}")
    lines.append(f"    andi    {tail_count}, {vl_reg}, {mask}              # {tail_count} = vl % {chunk_n}")
    lines.append(f"    li      {temp}, {vs2_off:#x}")
    lines.append(f"    add     {vs2_ptr}, t6, {temp}            # {vs2_ptr} = &{vs2}")
    lines.append(f"    li      {temp}, {vd_off:#x}")
    lines.append(f"    add     {vd_ptr}, t6, {temp}             # {vd_ptr} = &{vd}")

    main_loop = new_label("vrsub_vi_main")
    after_main = new_label("vrsub_vi_after")
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
    lines.append(f"    {vle_instr} {vs2_vreg}, ({vs2_ptr})")
    lines.append(f"    vrsub.vi {vd_vreg}, {vs2_vreg}, {imm}{mask_suffix}")
    lines.append(f"    {vse_instr} {vd_vreg}, ({vd_ptr}){mask_suffix}")
    lines.append(f"    addi    {vs2_ptr}, {vs2_ptr}, {c_bytes}")
    lines.append(f"    addi    {vd_ptr}, {vd_ptr}, {c_bytes}")
    if is_masked:
        lines.append(f"    addi    {mask_bit_idx}, {mask_bit_idx}, {chunk_n}")
    lines.append(f"    addi    {chunk_count}, {chunk_count}, -1")
    lines.append(f"    bnez    {chunk_count}, {main_loop}")
    lines.append(f"{after_main}:")

    tail_loop = new_label("vrsub_vi_tail")
    end_label = new_label("vrsub_vi_end")
    skip_label = f"{tail_loop}_skip"
    lines.append(f"{tail_loop}:")
    lines.append(f"    beqz    {tail_count}, {end_label}")
    if is_masked:
        _emit_mask_extraction_tail(lines, mask_bit_idx, v0_base, temp, mask_tmp, skip_label)
    lines.append(f"    {int_load:<8} {data_reg}, 0({vs2_ptr})")
    lines.append(f"    li      {temp}, {imm}")
    lines.append(f"    sub     {data_reg}, {temp}, {data_reg}       # {data_reg} = imm - vs2[i]")
    lines.append(f"    {int_store:<8} {data_reg}, 0({vd_ptr})")
    if is_masked:
        lines.append(f"{skip_label}:")
        lines.append(f"    addi    {mask_bit_idx}, {mask_bit_idx}, 1")
    lines.append(f"    addi    {vs2_ptr}, {vs2_ptr}, {elem_bytes}")
    lines.append(f"    addi    {vd_ptr}, {vd_ptr}, {elem_bytes}")
    lines.append(f"    addi    {tail_count}, {tail_count}, -1")
    lines.append(f"    j       {tail_loop}")
    lines.append(f"{end_label}:")

    return lines
