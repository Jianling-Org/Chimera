"""RVV256 rearrange 指令实现。"""

from __future__ import annotations

from riscv.extensions.rvv.translation.contracts import InstructionValidationError
from riscv.extensions.rvv.backends.rvv256.temp_regs import VRegTempAllocator
from riscv.extensions.rvv.backends.rvv256.support import (
    _chunk_size,
    _chunk_bytes,
    _emit_vsetvl_for_chunk,
    _load_vl_from_csr,
    _get_vle_instr,
    _get_vse_instr,
    _get_int_load_unsigned,
    _get_float_instr,
    _get_int_store,
)


def _build_vslidedown_vi_lines(context) -> list[str]:
    """
    翻译 vslidedown.vi 指令 (256-bit 模式)

    格式: vslidedown.vi vd, vs2, uimm
    语义: vd[i] = vs2[i + uimm] 对于 i+uimm < VLMAX, 否则 0
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
    temp_vreg = vtemps.alloc_vreg()

    temps = context.temp_register_allocator
    vl_reg = temps.alloc_gpr()
    clipped_vl = temps.alloc_gpr()
    chunk_count = temps.alloc_gpr()
    tail_count = temps.alloc_gpr()
    vs2_ptr = temps.alloc_gpr()
    vd_ptr = temps.alloc_gpr()
    data_reg = temps.alloc_gpr()

    vle_instr = _get_vle_instr(sew)
    vse_instr = _get_vse_instr(sew)

    lines.append(f"# vslidedown.vi {vd}, {vs2}, {uimm} (256-bit mode, SEW={sew})")
    lines.append(f"# Semantic: {vd}[i] = {vs2}[i+{uimm}] for i+{uimm} < VLMAX, else 0")
    lines.append("")

    # 加载 vl
    _load_vl_from_csr(lines, vl_reg=vl_reg, addr_reg=tail_count)
    lines.append("")

    # 源读取受 VLMAX 限制，目的写入受 VL 限制。
    zero_all_label = new_label("vslidedown_zero_all")
    lines.append(f"    li      {tail_count}, {uimm}")
    lines.append(f"    li      {clipped_vl}, {state.get_vlmax()}")
    lines.append(f"    bgeu    {tail_count}, {clipped_vl}, {zero_all_label}")
    lines.append("")

    lines.append(f"    sub     {clipped_vl}, {clipped_vl}, {tail_count}")
    lines.append("")

    copy_limit_label = new_label("vslidedown_copy_limit")
    lines.append(f"    bleu    {clipped_vl}, {vl_reg}, {copy_limit_label}")
    lines.append(f"    mv      {clipped_vl}, {vl_reg}")
    lines.append(f"{copy_limit_label}:")

    # 对 clipped_vl 计算块数和尾数
    lines.append(f"    srli    {chunk_count}, {clipped_vl}, {shift_amt}  # {chunk_count} = {clipped_vl} / {chunk_n}")
    lines.append(f"    andi    {tail_count}, {clipped_vl}, {mask}         # {tail_count} = {clipped_vl} % {chunk_n}")
    lines.append("")

    # 设置指针: vs2 从偏移 uimm * elem_bytes 开始
    lines.append(f"    li      {vs2_ptr}, {vs2_off:#x}")
    lines.append(f"    add     {vs2_ptr}, t6, {vs2_ptr}              # {vs2_ptr} = &{vs2}")
    lines.append(f"    li      {vd_ptr}, {vd_off:#x}")
    lines.append(f"    add     {vd_ptr}, t6, {vd_ptr}               # {vd_ptr} = &{vd}")
    lines.append("")

    slide_bytes = uimm * elem_bytes
    lines.append(f"    addi    {vs2_ptr}, {vs2_ptr}, {slide_bytes}     # 前移 {vs2_ptr} 跳过 {uimm} 个元素")
    lines.append("")

    # ========== 主循环: chunked copy (指针已调整) ==========
    main_loop = new_label("vslidedown_main")
    after_main = new_label("vslidedown_after")

    lines.append(f"    # --- 主循环: 每块复制 {chunk_n} 个元素 ({c_bytes} 字节) ---")
    lines.append(f"    beqz    {chunk_count}, {after_main}")
    lines.append(f"{main_loop}:")
    _emit_vsetvl_for_chunk(lines, chunk_n, sew, "m1", vl_reg, scratch_reg=vl_reg)
    lines.append("")
    lines.append(f"    {vle_instr} {temp_vreg}, ({vs2_ptr})           # 从 {vs2}+offset 加载")
    lines.append(f"    {vse_instr} {temp_vreg}, ({vd_ptr})            # 写回 {vd}")
    lines.append("")
    lines.append(f"    addi    {vs2_ptr}, {vs2_ptr}, {c_bytes}")
    lines.append(f"    addi    {vd_ptr}, {vd_ptr}, {c_bytes}")
    lines.append(f"    addi    {chunk_count}, {chunk_count}, -1")
    lines.append(f"    bnez    {chunk_count}, {main_loop}")
    lines.append(f"{after_main}:")
    lines.append("")

    # ========== 尾部标量回退 ==========
    tail_loop = new_label("vslidedown_tail")
    end_label = new_label("vslidedown_end")

    int_load = _get_int_load_unsigned(sew)
    int_store = _get_int_store(sew)

    lines.append(f"    # --- 尾部标量回退: 剩余 {tail_count} 个元素 ---")
    lines.append(f"{tail_loop}:")
    lines.append(f"    beqz    {tail_count}, {end_label}")
    lines.append(f"    {int_load:<8} {data_reg}, 0({vs2_ptr})                  # {data_reg} = {vs2}[pos+offset]")
    lines.append(f"    {int_store:<8} {data_reg}, 0({vd_ptr})                  # {vd}[i] = {data_reg}")
    lines.append(f"    addi    {vs2_ptr}, {vs2_ptr}, {elem_bytes}")
    lines.append(f"    addi    {vd_ptr}, {vd_ptr}, {elem_bytes}")
    lines.append(f"    addi    {tail_count}, {tail_count}, -1")
    lines.append(f"    j       {tail_loop}")
    lines.append(f"{end_label}:")
    lines.append("")

    # Only indices beyond the source VLMAX require zero fill.
    zero_suffix_loop = new_label("vslidedown_zero_suffix")
    done_label = new_label("vslidedown_done")
    _load_vl_from_csr(lines, vl_reg=vl_reg, addr_reg=tail_count)
    lines.append(f"    sub     {tail_count}, {vl_reg}, {clipped_vl}")
    lines.append(f"{zero_suffix_loop}:")
    lines.append(f"    beqz    {tail_count}, {done_label}")
    lines.append(f"    {int_store:<8} zero, 0({vd_ptr})")
    lines.append(f"    addi    {vd_ptr}, {vd_ptr}, {elem_bytes}")
    lines.append(f"    addi    {tail_count}, {tail_count}, -1")
    lines.append(f"    j       {zero_suffix_loop}")
    lines.append("")

    lines.append(f"{zero_all_label}:                         # uimm >= VLMAX: zero-fill all active elements")
    # Set up vd_ptr (not yet initialized on this path)
    lines.append(f"    li      {vd_ptr}, {vd_off:#x}")
    lines.append(f"    add     {vd_ptr}, t6, {vd_ptr}            # {vd_ptr} = &{vd}")
    zero_loop = new_label("vslidedown_zero")
    lines.append(f"    mv      {tail_count}, {vl_reg}            # tail_count = vl (use as counter)")
    lines.append(f"{zero_loop}:")
    lines.append(f"    beqz    {tail_count}, {done_label}")
    lines.append(f"    {int_store:<8} zero, 0({vd_ptr})")
    lines.append(f"    addi    {vd_ptr}, {vd_ptr}, {elem_bytes}")
    lines.append(f"    addi    {tail_count}, {tail_count}, -1")
    lines.append(f"    j       {zero_loop}")
    lines.append(f"{done_label}:")

    return lines


def _build_vslidedown_vx_lines(context) -> list[str]:
    """
    翻译 vslidedown.vx 指令 (256-bit 模式)

    格式: vslidedown.vx vd, vs2, rs1
    语义: vd[i] = vs2[i + x[rs1]] 对于 i+x[rs1] < VLMAX, 否则 0
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
    if sew not in (8, 16, 32, 64):
        raise InstructionValidationError(insn, f"vslidedown.vx supports SEW=8/16/32/64, got SEW={sew}")

    chunk_n = _chunk_size(sew)
    c_bytes = _chunk_bytes()
    elem_bytes = sew // 8
    shift_amt = {8: 5, 16: 4, 32: 3, 64: 2}[sew]
    mask = chunk_n - 1
    elem_shift = {8: 0, 16: 1, 32: 2, 64: 3}[sew]

    vd_off = allocator.get_offset(vd)
    vs2_off = allocator.get_offset(vs2)

    vtemps = VRegTempAllocator(insn)
    temp_vreg = vtemps.alloc_vreg()

    temps = context.temp_register_allocator
    vl_reg = temps.alloc_gpr()
    slide_elems = temps.alloc_gpr()
    clipped_vl = temps.alloc_gpr()
    chunk_count = temps.alloc_gpr()
    tail_count = temps.alloc_gpr()
    vs2_ptr = temps.alloc_gpr()
    vd_ptr = temps.alloc_gpr()
    byte_offset = temps.alloc_gpr()
    data_reg = temps.alloc_gpr()

    vle_instr = _get_vle_instr(sew)
    vse_instr = _get_vse_instr(sew)
    int_load = _get_int_load_unsigned(sew)
    int_store = _get_int_store(sew)

    lines.append(f"# vslidedown.vx {vd}, {vs2}, {rs1} (256-bit mode, SEW={sew})")
    lines.append(f"# Semantic: {vd}[i] = {vs2}[i+{rs1}] for i+{rs1} < VLMAX, else 0")
    lines.append("")

    _load_vl_from_csr(lines, vl_reg=vl_reg, addr_reg=tail_count)
    lines.append(f"    mv      {slide_elems}, {rs1}              # runtime slide offset in elements")
    lines.append("")

    zero_all_label = new_label("vslidedown_vx_zero_all")
    lines.append(f"    li      {clipped_vl}, {state.get_vlmax()}")
    lines.append(f"    bgeu    {slide_elems}, {clipped_vl}, {zero_all_label}")
    lines.append("")

    lines.append(f"    sub     {clipped_vl}, {clipped_vl}, {slide_elems}")
    copy_limit_label = new_label("vslidedown_vx_copy_limit")
    lines.append(f"    bleu    {clipped_vl}, {vl_reg}, {copy_limit_label}")
    lines.append(f"    mv      {clipped_vl}, {vl_reg}")
    lines.append(f"{copy_limit_label}:")
    lines.append(f"    srli    {chunk_count}, {clipped_vl}, {shift_amt}  # {chunk_count} = {clipped_vl} / {chunk_n}")
    lines.append(f"    andi    {tail_count}, {clipped_vl}, {mask}         # {tail_count} = {clipped_vl} % {chunk_n}")
    lines.append("")

    lines.append(f"    li      {vs2_ptr}, {vs2_off:#x}")
    lines.append(f"    add     {vs2_ptr}, t6, {vs2_ptr}              # {vs2_ptr} = &{vs2}")
    lines.append(f"    li      {vd_ptr}, {vd_off:#x}")
    lines.append(f"    add     {vd_ptr}, t6, {vd_ptr}               # {vd_ptr} = &{vd}")
    if elem_shift:
        lines.append(f"    slli    {byte_offset}, {slide_elems}, {elem_shift}       # byte offset = offset * {elem_bytes}")
    else:
        lines.append(f"    mv      {byte_offset}, {slide_elems}          # byte offset = offset")
    lines.append(f"    add     {vs2_ptr}, {vs2_ptr}, {byte_offset}   # start at {vs2}[offset]")
    lines.append("")

    main_loop = new_label("vslidedown_vx_main")
    after_main = new_label("vslidedown_vx_after")

    lines.append(f"    # --- 主循环: 每块复制 {chunk_n} 个元素 ({c_bytes} 字节) ---")
    lines.append(f"    beqz    {chunk_count}, {after_main}")
    lines.append(f"{main_loop}:")
    _emit_vsetvl_for_chunk(lines, chunk_n, sew, "m1", vl_reg, scratch_reg=vl_reg)
    lines.append("")
    lines.append(f"    {vle_instr} {temp_vreg}, ({vs2_ptr})           # 从 {vs2}+runtime offset 加载")
    lines.append(f"    {vse_instr} {temp_vreg}, ({vd_ptr})            # 写回 {vd}")
    lines.append("")
    lines.append(f"    addi    {vs2_ptr}, {vs2_ptr}, {c_bytes}")
    lines.append(f"    addi    {vd_ptr}, {vd_ptr}, {c_bytes}")
    lines.append(f"    addi    {chunk_count}, {chunk_count}, -1")
    lines.append(f"    bnez    {chunk_count}, {main_loop}")
    lines.append(f"{after_main}:")
    lines.append("")

    tail_loop = new_label("vslidedown_vx_tail")
    copied_end_label = new_label("vslidedown_vx_copied")

    lines.append(f"    # --- 尾部标量回退: 剩余 {tail_count} 个元素 ---")
    lines.append(f"{tail_loop}:")
    lines.append(f"    beqz    {tail_count}, {copied_end_label}")
    lines.append(f"    {int_load:<8} {data_reg}, 0({vs2_ptr})                  # {data_reg} = {vs2}[pos+offset]")
    lines.append(f"    {int_store:<8} {data_reg}, 0({vd_ptr})                  # {vd}[i] = {data_reg}")
    lines.append(f"    addi    {vs2_ptr}, {vs2_ptr}, {elem_bytes}")
    lines.append(f"    addi    {vd_ptr}, {vd_ptr}, {elem_bytes}")
    lines.append(f"    addi    {tail_count}, {tail_count}, -1")
    lines.append(f"    j       {tail_loop}")
    lines.append(f"{copied_end_label}:")
    lines.append("")

    zero_suffix_loop = new_label("vslidedown_vx_zero_suffix")
    done_label = new_label("vslidedown_vx_done")
    _load_vl_from_csr(lines, vl_reg=vl_reg, addr_reg=tail_count)
    lines.append(f"    sub     {tail_count}, {vl_reg}, {clipped_vl}")
    lines.append(f"{zero_suffix_loop}:")
    lines.append(f"    beqz    {tail_count}, {done_label}")
    lines.append(f"    {int_store:<8} zero, 0({vd_ptr})")
    lines.append(f"    addi    {vd_ptr}, {vd_ptr}, {elem_bytes}")
    lines.append(f"    addi    {tail_count}, {tail_count}, -1")
    lines.append(f"    j       {zero_suffix_loop}")
    lines.append("")

    lines.append(f"{zero_all_label}:                         # offset >= VLMAX: zero-fill all active elements")
    lines.append(f"    li      {vd_ptr}, {vd_off:#x}")
    lines.append(f"    add     {vd_ptr}, t6, {vd_ptr}            # {vd_ptr} = &{vd}")
    zero_loop = new_label("vslidedown_vx_zero")
    lines.append(f"    mv      {tail_count}, {vl_reg}            # tail_count = vl")
    lines.append(f"{zero_loop}:")
    lines.append(f"    beqz    {tail_count}, {done_label}")
    lines.append(f"    {int_store:<8} zero, 0({vd_ptr})")
    lines.append(f"    addi    {vd_ptr}, {vd_ptr}, {elem_bytes}")
    lines.append(f"    addi    {tail_count}, {tail_count}, -1")
    lines.append(f"    j       {zero_loop}")
    lines.append(f"{done_label}:")

    return lines


def _build_vslideup_vi_lines(context) -> list[str]:
    """
    翻译 vslideup.vi 指令 (256-bit 模式)

    格式: vslideup.vi vd, vs2, uimm
    语义: vd[i+uimm] = vs2[i] for i+uimm < vl; prefix elements are undisturbed.
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
    try:
        uimm = int(str(operands[2]), 0)
    except ValueError:
        raise InstructionValidationError(insn, f"vslideup.vi immediate must be an integer: {insn.op_str}")

    sew = state.sew
    elem_bytes = sew // 8
    elem_shift = {8: 0, 16: 1, 32: 2, 64: 3}[sew]

    vd_off = allocator.get_offset(vd)
    vs2_off = allocator.get_offset(vs2)

    temps = context.temp_register_allocator
    vl_reg = temps.alloc_gpr()
    copy_count = temps.alloc_gpr()
    vs2_ptr = temps.alloc_gpr()
    vd_ptr = temps.alloc_gpr()
    data = temps.alloc_gpr()
    temp = temps.alloc_gpr()

    int_load = _get_int_load_unsigned(sew)
    int_store = _get_int_store(sew)

    lines.append(f"# vslideup.vi {vd}, {vs2}, {uimm} (256-bit mode, SEW={sew})")
    lines.append(f"# Semantic: {vd}[i+{uimm}] = {vs2}[i], prefix undisturbed")
    lines.append("")

    _load_vl_from_csr(lines, vl_reg=vl_reg, addr_reg=temp)
    end_label = new_label("vslideup_vi_end")
    lines.append(f"    li      {temp}, {uimm}")
    lines.append(f"    bgeu    {temp}, {vl_reg}, {end_label}       # offset >= vl: no active destination writes")
    lines.append(f"    sub     {copy_count}, {vl_reg}, {temp}      # copy_count = vl - offset")
    lines.append("")

    lines.append(f"    li      {vs2_ptr}, {vs2_off:#x}")
    lines.append(f"    add     {vs2_ptr}, t6, {vs2_ptr}            # {vs2_ptr} = &{vs2}")
    lines.append(f"    li      {vd_ptr}, {vd_off:#x}")
    lines.append(f"    add     {vd_ptr}, t6, {vd_ptr}              # {vd_ptr} = &{vd}")
    lines.append(f"    addi    {temp}, {copy_count}, -1")
    if elem_shift:
        lines.append(f"    slli    {temp}, {temp}, {elem_shift}")
    lines.append(f"    add     {vs2_ptr}, {vs2_ptr}, {temp}        # start at {vs2}[copy_count-1]")
    lines.append(f"    li      {temp}, {uimm}")
    lines.append(f"    add     {temp}, {temp}, {copy_count}")
    lines.append(f"    addi    {temp}, {temp}, -1")
    if elem_shift:
        lines.append(f"    slli    {temp}, {temp}, {elem_shift}")
    lines.append(f"    add     {vd_ptr}, {vd_ptr}, {temp}          # start at {vd}[vl-1]")
    lines.append("")

    loop_label = new_label("vslideup_vi_loop")
    lines.append(f"    # --- 反向标量搬运: 允许 {vd} 和 {vs2} 重叠 ---")
    lines.append(f"{loop_label}:")
    lines.append(f"    beqz    {copy_count}, {end_label}")
    lines.append(f"    {int_load:<8} {data}, 0({vs2_ptr})")
    lines.append(f"    {int_store:<8} {data}, 0({vd_ptr})")
    lines.append(f"    addi    {vs2_ptr}, {vs2_ptr}, -{elem_bytes}")
    lines.append(f"    addi    {vd_ptr}, {vd_ptr}, -{elem_bytes}")
    lines.append(f"    addi    {copy_count}, {copy_count}, -1")
    lines.append(f"    j       {loop_label}")
    lines.append(f"{end_label}:")

    return lines


def _build_vslide1up_vx_lines(context) -> list[str]:
    """
    翻译 vslide1up.vx 指令 (256-bit 模式)

    格式: vslide1up.vx vd, vs2, rs1
    语义: vd[0] = rs1; vd[i] = vs2[i-1] for 1 <= i < vl.
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
    elem_bytes = sew // 8
    elem_shift = {8: 0, 16: 1, 32: 2, 64: 3}[sew]

    vd_off = allocator.get_offset(vd)
    vs2_off = allocator.get_offset(vs2)
    int_load = _get_int_load_unsigned(sew)
    int_store = _get_int_store(sew)

    temps = context.temp_register_allocator
    vl_reg = temps.alloc_gpr()
    count = temps.alloc_gpr()
    vs2_ptr = temps.alloc_gpr()
    vd_ptr = temps.alloc_gpr()
    data = temps.alloc_gpr()
    scalar = temps.alloc_gpr()
    tmp = temps.alloc_gpr()

    lines.append(f"# vslide1up.vx {vd}, {vs2}, {rs1} (256-bit mode, SEW={sew})")
    lines.append(f"# Semantic: {vd}[0] = {rs1}; {vd}[i] = {vs2}[i-1]")
    _load_vl_from_csr(lines, vl_reg=vl_reg, addr_reg=tmp)
    end_label = new_label("vslide1up_vx_end")
    lines.append(f"    beqz    {vl_reg}, {end_label}")
    lines.append(f"    addi    {count}, {vl_reg}, -1             # elements to shift upward")
    lines.append(f"    li      {vs2_ptr}, {vs2_off:#x}")
    lines.append(f"    add     {vs2_ptr}, t6, {vs2_ptr}")
    lines.append(f"    li      {vd_ptr}, {vd_off:#x}")
    lines.append(f"    add     {vd_ptr}, t6, {vd_ptr}")
    lines.append(f"    addi    {tmp}, {count}, -1")
    if elem_shift:
        lines.append(f"    slli    {tmp}, {tmp}, {elem_shift}")
    lines.append(f"    add     {vs2_ptr}, {vs2_ptr}, {tmp}       # start at {vs2}[vl-2]")
    lines.append(f"    mv      {tmp}, {count}")
    if elem_shift:
        lines.append(f"    slli    {tmp}, {tmp}, {elem_shift}")
    lines.append(f"    add     {vd_ptr}, {vd_ptr}, {tmp}       # start at {vd}[vl-1]")
    loop_label = new_label("vslide1up_vx_loop")
    scalar_label = new_label("vslide1up_vx_scalar")
    lines.append(f"{loop_label}:")
    lines.append(f"    beqz    {count}, {scalar_label}")
    lines.append(f"    {int_load:<8} {data}, 0({vs2_ptr})")
    lines.append(f"    {int_store:<8} {data}, 0({vd_ptr})")
    lines.append(f"    addi    {vs2_ptr}, {vs2_ptr}, -{elem_bytes}")
    lines.append(f"    addi    {vd_ptr}, {vd_ptr}, -{elem_bytes}")
    lines.append(f"    addi    {count}, {count}, -1")
    lines.append(f"    j       {loop_label}")
    lines.append(f"{scalar_label}:")
    lines.append(f"    li      {vd_ptr}, {vd_off:#x}")
    lines.append(f"    add     {vd_ptr}, t6, {vd_ptr}")
    lines.append(f"    slli    {scalar}, {rs1}, {64 - sew}")
    lines.append(f"    srli    {scalar}, {scalar}, {64 - sew}")
    lines.append(f"    {int_store:<8} {scalar}, 0({vd_ptr})       # {vd}[0] = scalar")
    lines.append(f"{end_label}:")

    return lines


def _build_vslide1down_vx_lines(context) -> list[str]:
    """
    翻译 vslide1down.vx 指令 (256-bit 模式)

    格式: vslide1down.vx vd, vs2, rs1
    语义: vd[i] = vs2[i+1] for i+1 < vl; vd[vl-1] = rs1.
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
    elem_bytes = sew // 8
    elem_shift = {8: 0, 16: 1, 32: 2, 64: 3}[sew]

    vd_off = allocator.get_offset(vd)
    vs2_off = allocator.get_offset(vs2)
    int_load = _get_int_load_unsigned(sew)
    int_store = _get_int_store(sew)

    temps = context.temp_register_allocator
    vl_reg = temps.alloc_gpr()
    count = temps.alloc_gpr()
    vs2_ptr = temps.alloc_gpr()
    vd_ptr = temps.alloc_gpr()
    data = temps.alloc_gpr()
    scalar = temps.alloc_gpr()
    tmp = temps.alloc_gpr()

    lines.append(f"# vslide1down.vx {vd}, {vs2}, {rs1} (256-bit mode, SEW={sew})")
    lines.append(f"# Semantic: {vd}[i] = {vs2}[i+1]; {vd}[vl-1] = {rs1}")
    _load_vl_from_csr(lines, vl_reg=vl_reg, addr_reg=tmp)
    end_label = new_label("vslide1down_vx_end")
    lines.append(f"    beqz    {vl_reg}, {end_label}")
    lines.append(f"    addi    {count}, {vl_reg}, -1             # elements copied from source suffix")
    lines.append(f"    li      {vs2_ptr}, {vs2_off + elem_bytes:#x}")
    lines.append(f"    add     {vs2_ptr}, t6, {vs2_ptr}          # start at {vs2}[1]")
    lines.append(f"    li      {vd_ptr}, {vd_off:#x}")
    lines.append(f"    add     {vd_ptr}, t6, {vd_ptr}")
    loop_label = new_label("vslide1down_vx_loop")
    scalar_label = new_label("vslide1down_vx_scalar")
    lines.append(f"{loop_label}:")
    lines.append(f"    beqz    {count}, {scalar_label}")
    lines.append(f"    {int_load:<8} {data}, 0({vs2_ptr})")
    lines.append(f"    {int_store:<8} {data}, 0({vd_ptr})")
    lines.append(f"    addi    {vs2_ptr}, {vs2_ptr}, {elem_bytes}")
    lines.append(f"    addi    {vd_ptr}, {vd_ptr}, {elem_bytes}")
    lines.append(f"    addi    {count}, {count}, -1")
    lines.append(f"    j       {loop_label}")
    lines.append(f"{scalar_label}:")
    lines.append(f"    li      {vd_ptr}, {vd_off:#x}")
    lines.append(f"    add     {vd_ptr}, t6, {vd_ptr}")
    lines.append(f"    mv      {tmp}, {vl_reg}")
    lines.append(f"    addi    {tmp}, {tmp}, -1")
    if elem_shift:
        lines.append(f"    slli    {tmp}, {tmp}, {elem_shift}")
    lines.append(f"    add     {vd_ptr}, {vd_ptr}, {tmp}          # &{vd}[vl-1]")
    lines.append(f"    slli    {scalar}, {rs1}, {64 - sew}")
    lines.append(f"    srli    {scalar}, {scalar}, {64 - sew}")
    lines.append(f"    {int_store:<8} {scalar}, 0({vd_ptr})       # final element = scalar")
    lines.append(f"{end_label}:")

    return lines


def _build_vrgather_vv_lines(context) -> list[str]:
    """
    翻译 vrgather.vv 指令 (256-bit 模式)

    格式: vrgather.vv vd, vs2, vs1
    语义: vd[i] = (vs1[i] < VLMAX) ? vs2[vs1[i]] : 0

    这里使用标量逐元素路径。原因是硬件 256-bit vrgather.vv 只能在当前
    物理 chunk 内 gather，而源 RVV 寄存器在模拟状态中是完整 VLEN=1024-bit
    逻辑向量；索引可能跨越 256-bit chunk。
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
    if sew not in (8, 16, 32, 64):
        raise InstructionValidationError(insn, f"vrgather.vv supports SEW=8/16/32/64, got SEW={sew}")

    vlmax = state.get_vlmax()
    if vlmax <= 0:
        raise InstructionValidationError(insn, f"vrgather.vv requires a valid VLMAX, got {vlmax}")

    elem_bytes = sew // 8
    elem_shift = {8: 0, 16: 1, 32: 2, 64: 3}[sew]

    vd_off = allocator.get_offset(vd)
    vs2_off = allocator.get_offset(vs2)
    vs1_off = allocator.get_offset(vs1)

    index_load = _get_int_load_unsigned(sew)
    data_load = _get_int_load_unsigned(sew)
    data_store = _get_int_store(sew)

    temps = context.temp_register_allocator
    vl_reg = temps.alloc_gpr()
    vlmax_reg = temps.alloc_gpr()
    index_reg = temps.alloc_gpr()
    vs2_base = temps.alloc_gpr()
    vs1_ptr = temps.alloc_gpr()
    vd_ptr = temps.alloc_gpr()
    gather_ptr = temps.alloc_gpr()
    data_reg = temps.alloc_gpr()

    loop_label = new_label("vrgather_vv_loop")
    zero_label = new_label("vrgather_vv_zero")
    store_label = new_label("vrgather_vv_store")
    end_label = new_label("vrgather_vv_end")

    lines.append(f"# vrgather.vv {vd}, {vs2}, {vs1} (256-bit mode, scalar cross-chunk gather)")
    lines.append(f"# Semantic: {vd}[i] = ({vs1}[i] < VLMAX={vlmax}) ? {vs2}[{vs1}[i]] : 0")
    lines.append("# Active element count comes from vl; gather index bounds are checked against VLMAX")
    lines.append("")

    _load_vl_from_csr(lines, vl_reg=vl_reg, addr_reg=vlmax_reg)
    lines.append(f"    li      {vlmax_reg}, {vlmax}              # VLMAX for current vtype")
    lines.append("")

    lines.append(f"    li      {gather_ptr}, {vs2_off:#x}")
    lines.append(f"    add     {vs2_base}, t6, {gather_ptr}      # {vs2_base} = &{vs2}")
    lines.append(f"    li      {gather_ptr}, {vs1_off:#x}")
    lines.append(f"    add     {vs1_ptr}, t6, {gather_ptr}       # {vs1_ptr} = &{vs1}")
    lines.append(f"    li      {gather_ptr}, {vd_off:#x}")
    lines.append(f"    add     {vd_ptr}, t6, {gather_ptr}        # {vd_ptr} = &{vd}")
    lines.append("")

    lines.append("    # --- 标量 gather: 保持跨 256-bit chunk 的索引语义 ---")
    lines.append(f"{loop_label}:")
    lines.append(f"    beqz    {vl_reg}, {end_label}")
    lines.append(f"    {index_load:<8} {index_reg}, 0({vs1_ptr})        # index = {vs1}[i] (unsigned e{sew})")
    lines.append(f"    bgeu    {index_reg}, {vlmax_reg}, {zero_label}   # index >= VLMAX => 0")
    if elem_shift:
        lines.append(f"    slli    {gather_ptr}, {index_reg}, {elem_shift}      # byte offset = index * {elem_bytes}")
    else:
        lines.append(f"    mv      {gather_ptr}, {index_reg}             # byte offset = index")
    lines.append(f"    add     {gather_ptr}, {vs2_base}, {gather_ptr}")
    lines.append(f"    {data_load:<8} {data_reg}, 0({gather_ptr})      # data = {vs2}[index]")
    lines.append(f"    j       {store_label}")
    lines.append(f"{zero_label}:")
    lines.append(f"    mv      {data_reg}, zero                  # out-of-range index")
    lines.append(f"{store_label}:")
    lines.append(f"    {data_store:<8} {data_reg}, 0({vd_ptr})        # {vd}[i] = data")
    lines.append(f"    addi    {vs1_ptr}, {vs1_ptr}, {elem_bytes}")
    lines.append(f"    addi    {vd_ptr}, {vd_ptr}, {elem_bytes}")
    lines.append(f"    addi    {vl_reg}, {vl_reg}, -1")
    lines.append(f"    j       {loop_label}")
    lines.append(f"{end_label}:")

    return lines


def _build_vrgatherei16_vv_lines(context) -> list[str]:
    """
    翻译 vrgatherei16.vv 指令 (256-bit 模式)

    格式: vrgatherei16.vv vd, vs2, vs1
    语义: vd[i] = (u16(vs1[i]) < VLMAX) ? vs2[u16(vs1[i])] : 0
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
    if sew not in (8, 16, 32, 64):
        raise InstructionValidationError(insn, f"vrgatherei16.vv supports SEW=8/16/32/64, got SEW={sew}")

    vlmax = state.get_vlmax()
    if vlmax <= 0:
        raise InstructionValidationError(insn, f"vrgatherei16.vv requires a valid VLMAX, got {vlmax}")

    elem_bytes = sew // 8
    elem_shift = {8: 0, 16: 1, 32: 2, 64: 3}[sew]

    vd_off = allocator.get_offset(vd)
    vs2_off = allocator.get_offset(vs2)
    vs1_off = allocator.get_offset(vs1)

    data_load = _get_int_load_unsigned(sew)
    data_store = _get_int_store(sew)

    temps = context.temp_register_allocator
    vl_reg = temps.alloc_gpr()
    vlmax_reg = temps.alloc_gpr()
    index_reg = temps.alloc_gpr()
    vs2_base = temps.alloc_gpr()
    vs1_ptr = temps.alloc_gpr()
    vd_ptr = temps.alloc_gpr()
    gather_ptr = temps.alloc_gpr()
    data_reg = temps.alloc_gpr()

    loop_label = new_label("vrgatherei16_vv_loop")
    zero_label = new_label("vrgatherei16_vv_zero")
    store_label = new_label("vrgatherei16_vv_store")
    end_label = new_label("vrgatherei16_vv_end")

    lines.append(f"# vrgatherei16.vv {vd}, {vs2}, {vs1} (256-bit mode, scalar e16-index gather)")
    lines.append(f"# Semantic: {vd}[i] = (u16({vs1}[i]) < VLMAX={vlmax}) ? {vs2}[u16({vs1}[i])] : 0")
    lines.append("# Active element count comes from vl; gather index bounds are checked against VLMAX")
    lines.append("")

    _load_vl_from_csr(lines, vl_reg=vl_reg, addr_reg=vlmax_reg)
    lines.append(f"    li      {vlmax_reg}, {vlmax}              # VLMAX for current vtype")
    lines.append("")

    lines.append(f"    li      {gather_ptr}, {vs2_off:#x}")
    lines.append(f"    add     {vs2_base}, t6, {gather_ptr}      # {vs2_base} = &{vs2}")
    lines.append(f"    li      {gather_ptr}, {vs1_off:#x}")
    lines.append(f"    add     {vs1_ptr}, t6, {gather_ptr}       # {vs1_ptr} = &{vs1} (e16 indices)")
    lines.append(f"    li      {gather_ptr}, {vd_off:#x}")
    lines.append(f"    add     {vd_ptr}, t6, {gather_ptr}        # {vd_ptr} = &{vd}")
    lines.append("")

    lines.append("    # --- 标量 gather: 索引固定按 e16 读取 ---")
    lines.append(f"{loop_label}:")
    lines.append(f"    beqz    {vl_reg}, {end_label}")
    lines.append(f"    lhu     {index_reg}, 0({vs1_ptr})        # index = u16({vs1}[i])")
    lines.append(f"    bgeu    {index_reg}, {vlmax_reg}, {zero_label}   # index >= VLMAX => 0")
    if elem_shift:
        lines.append(f"    slli    {gather_ptr}, {index_reg}, {elem_shift}      # byte offset = index * {elem_bytes}")
    else:
        lines.append(f"    mv      {gather_ptr}, {index_reg}             # byte offset = index")
    lines.append(f"    add     {gather_ptr}, {vs2_base}, {gather_ptr}")
    lines.append(f"    {data_load:<8} {data_reg}, 0({gather_ptr})      # data = {vs2}[index]")
    lines.append(f"    j       {store_label}")
    lines.append(f"{zero_label}:")
    lines.append(f"    mv      {data_reg}, zero                  # out-of-range index")
    lines.append(f"{store_label}:")
    lines.append(f"    {data_store:<8} {data_reg}, 0({vd_ptr})        # {vd}[i] = data")
    lines.append(f"    addi    {vs1_ptr}, {vs1_ptr}, 2")
    lines.append(f"    addi    {vd_ptr}, {vd_ptr}, {elem_bytes}")
    lines.append(f"    addi    {vl_reg}, {vl_reg}, -1")
    lines.append(f"    j       {loop_label}")
    lines.append(f"{end_label}:")

    return lines


def _build_vfmv_v_f_lines(context) -> list[str]:
    """
    翻译 vfmv.v.f 指令 (256-bit 模式)

    格式: vfmv.v.f vd, rs1
    语义: vd[i] = rs1 对所有 i in [0, vl)

    策略:
    - 每个块使用 vfmv.v.f 填充 temp vreg, 然后 vse 写回 sim_state
    - 尾部使用标量逐元素写回
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
    rs1 = operands[1]

    sew = state.sew
    chunk_n = _chunk_size(sew)
    c_bytes = _chunk_bytes()
    elem_bytes = sew // 8
    shift_amt = {8: 5, 16: 4, 32: 3, 64: 2}[sew]
    mask = chunk_n - 1

    vd_off = allocator.get_offset(vd)

    vtemps = VRegTempAllocator(insn)
    vd_vreg = vtemps.alloc_vreg()

    temps = context.temp_register_allocator
    vl_reg = temps.alloc_gpr()
    chunk_count = temps.alloc_gpr()
    tail_count = temps.alloc_gpr()
    vd_ptr = temps.alloc_gpr()
    temp = temps.alloc_gpr()

    vse_instr = _get_vse_instr(sew)

    lines.append(f"# vfmv.v.f {vd}, {rs1} (256-bit mode)")
    lines.append(f"# Semantic: {vd}[i] = {rs1} for all i, SEW={sew}")
    lines.append("")

    # ========== 加载 vl 并计算块数/尾数 ==========
    _load_vl_from_csr(lines, vl_reg=vl_reg, addr_reg=chunk_count)
    lines.append(f"    srli    {chunk_count}, {vl_reg}, {shift_amt}       # {chunk_count} = vl / {chunk_n}")
    lines.append(f"    andi    {tail_count}, {vl_reg}, {mask}              # {tail_count} = vl % {chunk_n}")
    lines.append("")

    # ========== 设置 vd 指针 ==========
    lines.append(f"    li      {temp}, {vd_off:#x}")
    lines.append(f"    add     {vd_ptr}, t6, {temp}             # {vd_ptr} = &{vd}")
    lines.append("")

    # ========== 主循环 ==========
    main_loop = new_label("vfmv_v_f_main")
    after_main = new_label("vfmv_v_f_after")

    lines.append(f"    beqz    {chunk_count}, {after_main}")
    lines.append(f"{main_loop}:")
    _emit_vsetvl_for_chunk(lines, chunk_n, sew, "m1", vl_reg, scratch_reg=temp)
    lines.append(f"    vfmv.v.f {vd_vreg}, {rs1}                    # 广播 {rs1} -> {vd_vreg}")
    lines.append(f"    {vse_instr} {vd_vreg}, ({vd_ptr}){mask_suffix}          # 写回 {vd} 块")
    lines.append(f"    addi    {vd_ptr}, {vd_ptr}, {c_bytes}")
    lines.append(f"    addi    {chunk_count}, {chunk_count}, -1")
    lines.append(f"    bnez    {chunk_count}, {main_loop}")
    lines.append(f"{after_main}:")
    lines.append("")

    # ========== 尾部标量回退 ==========
    lines.append(f"    # --- 尾部标量回退: 剩余 {tail_count} 个元素 ---")
    tail_loop = new_label("vfmv_v_f_tail")
    end_label = new_label("vfmv_v_f_end")

    store_instr = _get_float_instr('store', sew)

    lines.append(f"{tail_loop}:")
    lines.append(f"    beqz    {tail_count}, {end_label}")
    lines.append(f"    {store_instr:<8} {rs1}, 0({vd_ptr})               # {vd}[i] = {rs1}")
    lines.append(f"    addi    {vd_ptr}, {vd_ptr}, {elem_bytes}")
    lines.append(f"    addi    {tail_count}, {tail_count}, -1")
    lines.append(f"    j       {tail_loop}")
    lines.append(f"{end_label}:")

    return lines


def _build_vfmv_s_f_lines(context) -> list[str]:
    """
    翻译 vfmv.s.f 指令 (256-bit 模式)

    格式: vfmv.s.f vd, rs1
    语义: 若 vl > 0，则 vd[0] = rs1；vl=0 时不更新目标。

    RVV 1.0 中该指令只写 element 0，忽略 LMUL/寄存器组；这里用真实
    vfmv.s.f 生成 element 0，再只把一个 active 元素写回 simulated state。
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
    rs1 = operands[1]

    sew = state.sew
    if sew not in (32, 64):
        raise InstructionValidationError(insn, f"vfmv.s.f supports floating SEW=32/64 only, got SEW={sew}")

    vd_off = allocator.get_offset(vd)

    vtemps = VRegTempAllocator(insn)
    vd_vreg = vtemps.alloc_vreg()

    temps = context.temp_register_allocator
    vl_reg = temps.alloc_gpr()
    addr_reg = temps.alloc_gpr()

    vse_instr = _get_vse_instr(sew)
    end_label = new_label("vfmv_s_f_end")

    lines.append(f"# vfmv.s.f {vd}, {rs1} (256-bit mode)")
    lines.append(f"# Semantic: if vl > 0, {vd}[0] = {rs1}; otherwise no update")
    lines.append("")

    _load_vl_from_csr(lines, vl_reg=vl_reg, addr_reg=addr_reg)
    lines.append(f"    beqz    {vl_reg}, {end_label}              # vl=0: vfmv.s.f 不更新目标")
    lines.append(f"    li      {addr_reg}, {vd_off:#x}")
    lines.append(f"    add     {addr_reg}, t6, {addr_reg}         # {addr_reg} = &{vd}")
    lines.append(f"    vsetivli zero, 1, e{sew}, m1, ta, ma")
    lines.append(f"    vfmv.s.f {vd_vreg}, {rs1}                         # {vd}[0] = {rs1}")
    lines.append(f"    {vse_instr} {vd_vreg}, ({addr_reg})              # 只写回 element 0")
    lines.append(f"{end_label}:")

    return lines


def _build_vfmv_f_s_lines(context) -> list[str]:
    """
    翻译 vfmv.f.s 指令 (256-bit 模式)

    格式: vfmv.f.s rd, vs2
    语义: rd = vs2[0]

    vfmv.f.s 只读取元素 0, 不依赖 vl。
    使用 vle 加载一个块到 temp vreg, 再通过 vfmv.f.s 提取元素 0。
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
    vs2_off = allocator.get_offset(vs2)

    vtemps = VRegTempAllocator(insn)
    vs2_vreg = vtemps.alloc_vreg()

    temps = context.temp_register_allocator
    addr_reg = temps.alloc_gpr()

    vle_instr = _get_vle_instr(sew)

    lines.append(f"# vfmv.f.s {rd}, {vs2} (256-bit mode)")
    lines.append(f"# Semantic: {rd} = {vs2}[0] (不依赖 vl)")
    lines.append("")
    lines.append(f"    li      {addr_reg}, {vs2_off:#x}")
    lines.append(f"    add     {addr_reg}, t6, {addr_reg}")
    lines.append(f"    vsetivli zero, 1, e{sew}, m1, ta, ma")
    lines.append(f"    {vle_instr} {vs2_vreg}, ({addr_reg})              # 加载 {vs2} 到 vreg")
    lines.append(f"    vfmv.f.s {rd}, {vs2_vreg}                         # {rd} = {vs2}[0]")

    return lines


def _build_vmv_v_i_lines(context) -> list[str]:
    """
    翻译 vmv.v.i 指令 (256-bit 模式)

    格式: vmv.v.i vd, imm
    语义: vd[i] = sext(imm[4:0]) 对所有 i in [0, vl)

    策略:
    - 每个块使用 vmv.v.i 填充 temp vreg, 然后 vse 写回 sim_state
    - 尾部使用标量逐元素写回
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
    imm_str = operands[1]

    # 解析立即数
    try:
        raw_imm = int(str(imm_str), 0)
    except ValueError:
        raise InstructionValidationError(insn, f"Invalid immediate for {insn.opcode}: {insn.op_str}")
    signed_imm = raw_imm & 0x1F
    if signed_imm & 0x10:
        signed_imm -= 0x20

    sew = state.sew
    chunk_n = _chunk_size(sew)
    c_bytes = _chunk_bytes()
    elem_bytes = sew // 8
    shift_amt = {8: 5, 16: 4, 32: 3, 64: 2}[sew]
    mask = chunk_n - 1

    vd_off = allocator.get_offset(vd)

    vtemps = VRegTempAllocator(insn)
    vd_vreg = vtemps.alloc_vreg()

    temps = context.temp_register_allocator
    vl_reg = temps.alloc_gpr()
    chunk_count = temps.alloc_gpr()
    tail_count = temps.alloc_gpr()
    vd_ptr = temps.alloc_gpr()
    temp = temps.alloc_gpr()
    imm_reg = temps.alloc_gpr()

    store_instr = {8: 'sb', 16: 'sh', 32: 'sw', 64: 'sd'}[sew]
    vse_instr = _get_vse_instr(sew)

    lines.append(f"# vmv.v.i {vd}, {imm_str} (signed={signed_imm}) (256-bit mode)")
    lines.append(f"# Semantic: {vd}[i] = {signed_imm} for all i, SEW={sew}")
    lines.append("")

    # ========== 加载 vl 并计算块数/尾数 ==========
    _load_vl_from_csr(lines, vl_reg=vl_reg, addr_reg=chunk_count)
    lines.append(f"    srli    {chunk_count}, {vl_reg}, {shift_amt}       # {chunk_count} = vl / {chunk_n}")
    lines.append(f"    andi    {tail_count}, {vl_reg}, {mask}              # {tail_count} = vl % {chunk_n}")
    lines.append("")

    # ========== 设置 vd 指针 ==========
    lines.append(f"    li      {temp}, {vd_off:#x}")
    lines.append(f"    add     {vd_ptr}, t6, {temp}             # {vd_ptr} = &{vd}")
    lines.append("")

    # ========== 主循环 ==========
    main_loop = new_label("vmv_v_i_main")
    after_main = new_label("vmv_v_i_after")

    lines.append(f"    beqz    {chunk_count}, {after_main}")
    lines.append(f"{main_loop}:")
    _emit_vsetvl_for_chunk(lines, chunk_n, sew, "m1", vl_reg, scratch_reg=temp)
    lines.append(f"    vmv.v.i {vd_vreg}, {signed_imm}                 # 广播 {signed_imm} -> {vd_vreg}")
    lines.append(f"    {vse_instr} {vd_vreg}, ({vd_ptr}){mask_suffix}          # 写回 {vd} 块")
    lines.append(f"    addi    {vd_ptr}, {vd_ptr}, {c_bytes}")
    lines.append(f"    addi    {chunk_count}, {chunk_count}, -1")
    lines.append(f"    bnez    {chunk_count}, {main_loop}")
    lines.append(f"{after_main}:")
    lines.append("")

    # ========== 尾部标量回退 ==========
    lines.append(f"    # --- 尾部标量回退: 剩余 {tail_count} 个元素 ---")
    tail_loop = new_label("vmv_v_i_tail")
    end_label = new_label("vmv_v_i_end")

    lines.append(f"    li      {imm_reg}, {signed_imm}")
    lines.append(f"{tail_loop}:")
    lines.append(f"    beqz    {tail_count}, {end_label}")
    lines.append(f"    {store_instr:<8} {imm_reg}, 0({vd_ptr})               # {vd}[i] = {signed_imm}")
    lines.append(f"    addi    {vd_ptr}, {vd_ptr}, {elem_bytes}")
    lines.append(f"    addi    {tail_count}, {tail_count}, -1")
    lines.append(f"    j       {tail_loop}")
    lines.append(f"{end_label}:")

    return lines


def _build_vmv_v_x_lines(context) -> list[str]:
    """
    翻译 vmv.v.x 指令 (256-bit 模式)

    格式: vmv.v.x vd, rs1
    语义: vd[i] = (SEW)rs1 对所有 i in [0, vl)

    策略:
    - 每个块使用 vmv.v.x 填充 temp vreg, 然后 vse 写回 sim_state
    - 尾部使用标量逐元素写回
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
    rs1 = operands[1]

    sew = state.sew
    chunk_n = _chunk_size(sew)
    c_bytes = _chunk_bytes()
    elem_bytes = sew // 8
    shift_amt = {8: 5, 16: 4, 32: 3, 64: 2}[sew]
    mask = chunk_n - 1

    vd_off = allocator.get_offset(vd)

    vtemps = VRegTempAllocator(insn)
    vd_vreg = vtemps.alloc_vreg()

    temps = context.temp_register_allocator
    vl_reg = temps.alloc_gpr()
    chunk_count = temps.alloc_gpr()
    tail_count = temps.alloc_gpr()
    vd_ptr = temps.alloc_gpr()
    temp = temps.alloc_gpr()
    val_reg = temps.alloc_gpr()

    store_instr = {8: 'sb', 16: 'sh', 32: 'sw', 64: 'sd'}[sew]
    vse_instr = _get_vse_instr(sew)

    lines.append(f"# vmv.v.x {vd}, {rs1} (256-bit mode)")
    lines.append(f"# Semantic: {vd}[i] = {rs1} for all i, SEW={sew}")
    lines.append("")

    # 将 GPR 源值复制到 temp (避免 rs1 与分配器冲突)
    lines.append(f"    mv      {val_reg}, {rs1}")
    lines.append("")

    # ========== 加载 vl 并计算块数/尾数 ==========
    _load_vl_from_csr(lines, vl_reg=vl_reg, addr_reg=chunk_count)
    lines.append(f"    srli    {chunk_count}, {vl_reg}, {shift_amt}       # {chunk_count} = vl / {chunk_n}")
    lines.append(f"    andi    {tail_count}, {vl_reg}, {mask}              # {tail_count} = vl % {chunk_n}")
    lines.append("")

    # ========== 设置 vd 指针 ==========
    lines.append(f"    li      {temp}, {vd_off:#x}")
    lines.append(f"    add     {vd_ptr}, t6, {temp}             # {vd_ptr} = &{vd}")
    lines.append("")

    # ========== 主循环 ==========
    main_loop = new_label("vmv_v_x_main")
    after_main = new_label("vmv_v_x_after")

    lines.append(f"    beqz    {chunk_count}, {after_main}")
    lines.append(f"{main_loop}:")
    _emit_vsetvl_for_chunk(lines, chunk_n, sew, "m1", vl_reg, scratch_reg=temp)
    lines.append(f"    vmv.v.x {vd_vreg}, {val_reg}                   # 广播 {rs1} -> {vd_vreg}")
    lines.append(f"    {vse_instr} {vd_vreg}, ({vd_ptr}){mask_suffix}          # 写回 {vd} 块")
    lines.append(f"    addi    {vd_ptr}, {vd_ptr}, {c_bytes}")
    lines.append(f"    addi    {chunk_count}, {chunk_count}, -1")
    lines.append(f"    bnez    {chunk_count}, {main_loop}")
    lines.append(f"{after_main}:")
    lines.append("")

    # ========== 尾部标量回退 ==========
    lines.append(f"    # --- 尾部标量回退: 剩余 {tail_count} 个元素 ---")
    tail_loop = new_label("vmv_v_x_tail")
    end_label = new_label("vmv_v_x_end")

    lines.append(f"{tail_loop}:")
    lines.append(f"    beqz    {tail_count}, {end_label}")
    lines.append(f"    {store_instr:<8} {val_reg}, 0({vd_ptr})               # {vd}[i] = {rs1}")
    lines.append(f"    addi    {vd_ptr}, {vd_ptr}, {elem_bytes}")
    lines.append(f"    addi    {tail_count}, {tail_count}, -1")
    lines.append(f"    j       {tail_loop}")
    lines.append(f"{end_label}:")

    return lines


def _build_vmv_v_v_lines(context) -> list[str]:
    """
    翻译 vmv.v.v 指令 (256-bit 模式)

    格式: vmv.v.v vd, vs1
    语义: vd[i] = vs1[i] 对所有 active 元素 i in [0, vl)
    """
    insn = context.instruction
    state = context.state
    allocator = context.layout
    new_label = context.new_label
    lines = []
    operands = insn.operands
    if len(operands) < 2:
        raise InstructionValidationError(insn, f"Invalid operands for {insn.opcode}: {insn.op_str}")

    vd = operands[0]
    vs1 = operands[1]

    sew = state.sew
    chunk_n = _chunk_size(sew)
    c_bytes = _chunk_bytes()
    shift_amt = {8: 5, 16: 4, 32: 3, 64: 2}[sew]
    mask = chunk_n - 1

    vd_off = allocator.get_offset(vd)
    vs1_off = allocator.get_offset(vs1)

    vtemps = VRegTempAllocator(insn)
    temp_vreg = vtemps.alloc_vreg()

    temps = context.temp_register_allocator
    vl_reg = temps.alloc_gpr()
    chunk_count = temps.alloc_gpr()
    tail_count = temps.alloc_gpr()
    vs1_ptr = temps.alloc_gpr()
    vd_ptr = temps.alloc_gpr()
    temp = temps.alloc_gpr()

    vle_instr = _get_vle_instr(sew)
    vse_instr = _get_vse_instr(sew)

    lines.append(f"# vmv.v.v {vd}, {vs1} (256-bit mode, SEW={sew})")
    lines.append(f"# Semantic: {vd}[i] = {vs1}[i] for active elements")
    lines.append("")

    _load_vl_from_csr(lines, vl_reg=vl_reg, addr_reg=chunk_count)
    lines.append(f"    srli    {chunk_count}, {vl_reg}, {shift_amt}       # {chunk_count} = vl / {chunk_n}")
    lines.append(f"    andi    {tail_count}, {vl_reg}, {mask}              # {tail_count} = vl % {chunk_n}")
    lines.append("")

    lines.append(f"    li      {temp}, {vs1_off:#x}")
    lines.append(f"    add     {vs1_ptr}, t6, {temp}            # {vs1_ptr} = &{vs1}")
    lines.append(f"    li      {temp}, {vd_off:#x}")
    lines.append(f"    add     {vd_ptr}, t6, {temp}             # {vd_ptr} = &{vd}")
    lines.append("")

    main_loop = new_label("vmv_v_v_main")
    after_main = new_label("vmv_v_v_after")
    end_label = new_label("vmv_v_v_end")

    lines.append(f"    # --- 主循环: 每块复制 {chunk_n} 个元素 ({c_bytes} 字节) ---")
    lines.append(f"    beqz    {chunk_count}, {after_main}")
    lines.append(f"{main_loop}:")
    _emit_vsetvl_for_chunk(lines, chunk_n, sew, "m1", vl_reg, scratch_reg=temp)
    lines.append(f"    {vle_instr} {temp_vreg}, ({vs1_ptr})")
    lines.append(f"    {vse_instr} {temp_vreg}, ({vd_ptr})")
    lines.append(f"    addi    {vs1_ptr}, {vs1_ptr}, {c_bytes}")
    lines.append(f"    addi    {vd_ptr}, {vd_ptr}, {c_bytes}")
    lines.append(f"    addi    {chunk_count}, {chunk_count}, -1")
    lines.append(f"    bnez    {chunk_count}, {main_loop}")
    lines.append(f"{after_main}:")
    lines.append(f"    beqz    {tail_count}, {end_label}")
    lines.append(f"    vsetvli zero, {tail_count}, e{sew}, m1, ta, ma")
    lines.append(f"    {vle_instr} {temp_vreg}, ({vs1_ptr})")
    lines.append(f"    {vse_instr} {temp_vreg}, ({vd_ptr})")
    lines.append(f"{end_label}:")

    return lines


def _build_vmv_s_x_lines(context) -> list[str]:
    """
    翻译 vmv.s.x 指令 (256-bit 模式)

    格式: vmv.s.x vd, rs1
    语义: vl > 0 时 vd[0] = rs1 (仅元素 0)
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

    vd = operands[0]
    rs1 = operands[1]

    sew = state.sew
    elem_bytes = sew // 8
    vd_off = allocator.get_offset(vd)

    temps = context.temp_register_allocator
    addr_reg = temps.alloc_gpr()
    vl_reg = temps.alloc_gpr()
    end_label = context.new_label("vmv_s_x_end")

    store_instr = {8: 'sb', 16: 'sh', 32: 'sw', 64: 'sd'}[sew]

    lines.append(f"# vmv.s.x {vd}, {rs1} (256-bit mode)")
    lines.append(f"# Semantic: {vd}[0] = {rs1}")
    lines.append("")
    _load_vl_from_csr(lines, vl_reg=vl_reg, addr_reg=addr_reg)
    lines.append(f"    beqz    {vl_reg}, {end_label}")
    lines.append(f"    li      {addr_reg}, {vd_off:#x}")
    lines.append(f"    add     {addr_reg}, t6, {addr_reg}")
    lines.append(f"    {store_instr:<8} {rs1}, 0({addr_reg})            # {vd}[0] = {rs1}")

    lines.append(f"{end_label}:")
    return lines
