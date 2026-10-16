"""RVV256 conversion 指令实现。"""

from __future__ import annotations

from typing import List
from riscv.frontend.model import RVInstruction
from riscv.extensions.rvv.analysis.config import StateTracker
from riscv.extensions.rvv.runtime.layout import SimulatedStateLayout, CSR_OFFSETS
from riscv.extensions.rvv.translation.contracts import InstructionValidationError
from riscv.extensions.rvv.backends.rvv256.temp_regs import VRegTempAllocator
from riscv.extensions.rvv.translation.temps import TempRegisterAllocator
from riscv.extensions.rvv.backends.rvv256.support import (
    _emit_mask_setup,
    _emit_mask_extraction_chunk,
    _get_int_load_signed,
    _get_int_load_unsigned,
    _emit_vsetvl_for_chunk,
    _load_vl_from_csr,
    _get_float_instr,
    _get_int_store,
)


def _emit_vext_vf(
    insn: RVInstruction,
    state: StateTracker,
    allocator: SimulatedStateLayout,
    new_label,
    *,
    signed: bool,
    factor: int,
) -> List[str]:
    """共享实现 vzext.vf{factor} / vsext.vf{factor}。"""
    opcode = f"vsext.vf{factor}" if signed else f"vzext.vf{factor}"
    kind = "sign" if signed else "zero"
    source_lmul = {2: "mf2", 4: "mf4", 8: "mf8"}[factor]
    loop_prefix = f"{'vsext' if signed else 'vzext'}_vf{factor}"

    lines = []
    operands = insn.operands
    if len(operands) < 2:
        raise InstructionValidationError(insn, f"Invalid operands for {insn.opcode}: {insn.op_str}")

    vd = operands[0]
    vs2 = operands[1]
    output_sew = state.sew
    if output_sew % factor != 0:
        raise InstructionValidationError(insn, f"{opcode} requires destination SEW divisible by {factor}, got SEW={output_sew}")

    input_sew = output_sew // factor
    if input_sew not in (8, 16, 32):
        raise InstructionValidationError(
            insn,
            f"{opcode} requires source EEW=8/16/32 "
            f"(destination e{output_sew} / {factor}), got e{input_sew}",
        )

    if output_sew not in (16, 32, 64):
        raise InstructionValidationError(insn, f"{opcode} supports destination SEW=16/32/64, got SEW={output_sew}")

    chunk_n = 256 // output_sew
    chunk_bytes_in = chunk_n * (input_sew // 8)
    chunk_bytes_out = chunk_n * (output_sew // 8)
    shift_amt = {16: 4, 32: 3, 64: 2}[output_sew]
    mask = chunk_n - 1

    vd_off = allocator.get_offset(vd)
    vs2_off = allocator.get_offset(vs2)

    vtemps = VRegTempAllocator(insn)
    vs2_vreg = vtemps.alloc_vreg()
    vd_vreg = vtemps.alloc_vreg()
    if vd_vreg == "v25":
        vd_vreg = vtemps.alloc_vreg()

    temps = TempRegisterAllocator(insn, reserved_gprs=("t6",))
    vl_reg = temps.alloc_gpr()
    chunk_count = temps.alloc_gpr()
    tail_count = temps.alloc_gpr()
    vs2_ptr = temps.alloc_gpr()
    vd_ptr = temps.alloc_gpr()
    temp = temps.alloc_gpr()

    lines.append(f"# {opcode} {vd}, {vs2} (256-bit mode)")
    lines.append(f"# Semantic: {vd}[i] = {kind}_extend({vs2}[i]), e{input_sew} -> e{output_sew}")
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

    main_loop = new_label(f"{loop_prefix}_main")
    after_main = new_label(f"{loop_prefix}_after")

    lines.append(f"    # --- 主循环: 每块处理 {chunk_n} 个元素 ---")
    lines.append(f"    # 输入: {chunk_bytes_in}B (e{input_sew}, LMUL={source_lmul}), 输出: {chunk_bytes_out}B (e{output_sew}, LMUL=m1)")
    lines.append(f"    beqz    {chunk_count}, {after_main}")
    lines.append(f"{main_loop}:")
    _emit_vsetvl_for_chunk(lines, chunk_n, input_sew, source_lmul, vl_reg, scratch_reg=temp)
    lines.append(f"    vle{input_sew}.v {vs2_vreg}, ({vs2_ptr})       # 加载 {vs2} 源块 (e{input_sew}, {source_lmul})")
    _emit_vsetvl_for_chunk(lines, chunk_n, output_sew, "m1", vl_reg, scratch_reg=temp)
    lines.append(f"    {opcode} {vd_vreg}, {vs2_vreg}                  # {kind}-extend to e{output_sew}")
    lines.append(f"    vse{output_sew}.v {vd_vreg}, ({vd_ptr})       # 写回 {vd} 块 (e{output_sew})")
    lines.append("")
    lines.append(f"    addi    {vs2_ptr}, {vs2_ptr}, {chunk_bytes_in}")
    lines.append(f"    addi    {vd_ptr}, {vd_ptr}, {chunk_bytes_out}")
    lines.append(f"    addi    {chunk_count}, {chunk_count}, -1")
    lines.append(f"    bnez    {chunk_count}, {main_loop}")
    lines.append(f"{after_main}:")
    lines.append("")

    end_label = new_label(f"{loop_prefix}_end")
    lines.append(f"    # --- 尾部 RVV extension chunk: 剩余 {tail_count} 个元素 ---")
    lines.append(f"    beqz    {tail_count}, {end_label}")
    lines.append(f"    vsetvli zero, {tail_count}, e{input_sew}, {source_lmul}, ta, ma")
    lines.append(f"    vle{input_sew}.v {vs2_vreg}, ({vs2_ptr})")
    lines.append(f"    vsetvli zero, {tail_count}, e{output_sew}, m1, ta, ma")
    lines.append(f"    {opcode} {vd_vreg}, {vs2_vreg}")
    lines.append(f"    vse{output_sew}.v {vd_vreg}, ({vd_ptr})")
    lines.append(f"{end_label}:")

    return lines


def _build_vzext_vf2_lines(context) -> list[str]:
    """翻译 vzext.vf2 指令 (zero extension, EEW=SEW/2 -> SEW)。"""
    insn = context.instruction
    state = context.state
    allocator = context.layout
    new_label = context.new_label
    return _emit_vext_vf(insn, state, allocator, new_label, signed=False, factor=2)


def _build_vzext_vf4_lines(context) -> list[str]:
    """翻译 vzext.vf4 指令 (zero extension, EEW=SEW/4 -> SEW)。"""
    insn = context.instruction
    state = context.state
    allocator = context.layout
    new_label = context.new_label
    return _emit_vext_vf(insn, state, allocator, new_label, signed=False, factor=4)


def _build_vzext_vf8_lines(context) -> list[str]:
    """翻译 vzext.vf8 指令 (zero extension, EEW=SEW/8 -> SEW)。"""
    insn = context.instruction
    state = context.state
    allocator = context.layout
    new_label = context.new_label
    return _emit_vext_vf(insn, state, allocator, new_label, signed=False, factor=8)


def _build_vsext_vf2_lines(context) -> list[str]:
    """翻译 vsext.vf2 指令 (sign extension, EEW=SEW/2 -> SEW)。"""
    insn = context.instruction
    state = context.state
    allocator = context.layout
    new_label = context.new_label
    return _emit_vext_vf(insn, state, allocator, new_label, signed=True, factor=2)


def _build_vsext_vf4_lines(context) -> list[str]:
    """翻译 vsext.vf4 指令 (sign extension, EEW=SEW/4 -> SEW)。"""
    insn = context.instruction
    state = context.state
    allocator = context.layout
    new_label = context.new_label
    return _emit_vext_vf(insn, state, allocator, new_label, signed=True, factor=4)


def _build_vwcvtu_x_x_v_lines(context) -> list[str]:
    """
    翻译 vwcvtu.x.x.v 指令 (256-bit 模式, widening)

    格式: vwcvtu.x.x.v vd, vs2
    语义: vd[i] = zero_extend(vs2[i]) (e{sew} -> e{sew*2} unsigned)
    :return: 生成的汇编代码行列表
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
    vs2 = operands[1]

    input_sew = state.sew
    output_sew = input_sew * 2

    if input_sew not in (8, 16, 32):
        raise InstructionValidationError(
            insn, f"vwcvtu.x.x.v 不支持输入 SEW={input_sew}"
        )

    chunk_n = 256 // output_sew
    chunk_bytes_in = chunk_n * (input_sew // 8)
    chunk_bytes_out = chunk_n * (output_sew // 8)
    shift_amt = {8: 4, 16: 3, 32: 2}[input_sew]
    mask = chunk_n - 1

    elem_bytes_in = input_sew // 8
    elem_bytes_out = output_sew // 8

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

    lines.append(f"# vwcvtu.x.x.v {vd}, {vs2} (256-bit mode)")
    lines.append(f"# Semantic: {vd}[i] = zero_extend({vs2}[i]), e{input_sew} -> e{output_sew}")
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
    main_loop = new_label("vwcvtu_main")
    after_main = new_label("vwcvtu_after")

    lines.append(f"    # --- 主循环: 每块处理 {chunk_n} 个元素 ---")
    lines.append(f"    # 输入: {chunk_bytes_in}B (LMUL=mf2), 输出: {chunk_bytes_out}B (LMUL=m1)")
    lines.append(f"    beqz    {chunk_count}, {after_main}")
    lines.append(f"{main_loop}:")
    _emit_vsetvl_for_chunk(lines, chunk_n, input_sew, "mf2", vl_reg, scratch_reg=temp)
    lines.append("")
    lines.append(f"    vle{input_sew}.v {vs2_vreg}, ({vs2_ptr})       # 加载 {vs2} 块 (e{input_sew}, mf2)")
    lines.append(f"    vwcvtu.x.x.v {vd_vreg}, {vs2_vreg}                 # {vd}[i] = zero_extend({vs2}[i])")
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
    tail_loop = new_label("vwcvtu_tail")
    end_label = new_label("vwcvtu_end")

    int_load_instr = {8: 'lbu', 16: 'lhu', 32: 'lwu', 64: 'ld'}[input_sew]
    int_store_instr = {8: 'sb', 16: 'sh', 32: 'sw', 64: 'sd'}[output_sew]

    lines.append(f"{tail_loop}:")
    lines.append(f"    beqz    {tail_count}, {end_label}")
    lines.append(f"    {int_load_instr:<8} {temp}, 0({vs2_ptr})            # {temp} = {vs2}[i] (u{input_sew})")
    lines.append(f"    {int_store_instr:<8} {temp}, 0({vd_ptr})            # {vd}[i] = {temp} (zero_extended)")
    lines.append(f"    addi    {vs2_ptr}, {vs2_ptr}, {elem_bytes_in}")
    lines.append(f"    addi    {vd_ptr}, {vd_ptr}, {elem_bytes_out}")
    lines.append(f"    addi    {tail_count}, {tail_count}, -1")
    lines.append(f"    j       {tail_loop}")
    lines.append(f"{end_label}:")

    return lines


def _build_vwcvt_x_x_v_lines(context) -> list[str]:
    """
    翻译 vwcvt.x.x.v 指令 (256-bit 模式, signed widening)

    格式: vwcvt.x.x.v vd, vs2
    语义: vd[i] = sign_extend(vs2[i]) (e{sew} -> e{sew*2})
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
    vs2 = operands[1]

    input_sew = state.sew
    output_sew = input_sew * 2

    if input_sew not in (8, 16, 32):
        raise InstructionValidationError(insn, f"vwcvt.x.x.v supports input SEW=8/16/32, got SEW={input_sew}")

    chunk_n = 256 // output_sew
    chunk_bytes_in = chunk_n * (input_sew // 8)
    chunk_bytes_out = chunk_n * (output_sew // 8)
    shift_amt = {8: 4, 16: 3, 32: 2}[input_sew]
    mask = chunk_n - 1

    elem_bytes_in = input_sew // 8
    elem_bytes_out = output_sew // 8

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

    lines.append(f"# vwcvt.x.x.v {vd}, {vs2} (256-bit mode)")
    lines.append(f"# Semantic: {vd}[i] = sign_extend({vs2}[i]), e{input_sew} -> e{output_sew}")
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

    main_loop = new_label("vwcvt_main")
    after_main = new_label("vwcvt_after")

    lines.append(f"    # --- 主循环: 每块处理 {chunk_n} 个元素 ---")
    lines.append(f"    # 输入: {chunk_bytes_in}B (LMUL=mf2), 输出: {chunk_bytes_out}B (LMUL=m1)")
    lines.append(f"    beqz    {chunk_count}, {after_main}")
    lines.append(f"{main_loop}:")
    _emit_vsetvl_for_chunk(lines, chunk_n, input_sew, "mf2", vl_reg, scratch_reg=temp)
    lines.append("")
    lines.append(f"    vle{input_sew}.v {vs2_vreg}, ({vs2_ptr})       # 加载 {vs2} 块 (e{input_sew}, mf2)")
    lines.append(f"    vwcvt.x.x.v {vd_vreg}, {vs2_vreg}                  # {vd}[i] = sign_extend({vs2}[i])")
    lines.append(f"    vse{output_sew}.v {vd_vreg}, ({vd_ptr})       # 写回 {vd} 块 (e{output_sew})")
    lines.append("")
    lines.append(f"    addi    {vs2_ptr}, {vs2_ptr}, {chunk_bytes_in}")
    lines.append(f"    addi    {vd_ptr}, {vd_ptr}, {chunk_bytes_out}")
    lines.append(f"    addi    {chunk_count}, {chunk_count}, -1")
    lines.append(f"    bnez    {chunk_count}, {main_loop}")
    lines.append(f"{after_main}:")
    lines.append("")

    tail_loop = new_label("vwcvt_tail")
    end_label = new_label("vwcvt_end")
    int_load_instr = _get_int_load_signed(input_sew)
    int_store_instr = _get_int_store(output_sew)

    lines.append(f"    # --- 尾部标量回退: 剩余 {tail_count} 个元素 ---")
    lines.append(f"{tail_loop}:")
    lines.append(f"    beqz    {tail_count}, {end_label}")
    lines.append(f"    {int_load_instr:<8} {temp}, 0({vs2_ptr})            # {temp} = sext({vs2}[i]) (e{input_sew})")
    lines.append(f"    {int_store_instr:<8} {temp}, 0({vd_ptr})            # {vd}[i] = {temp} (sign_extended)")
    lines.append(f"    addi    {vs2_ptr}, {vs2_ptr}, {elem_bytes_in}")
    lines.append(f"    addi    {vd_ptr}, {vd_ptr}, {elem_bytes_out}")
    lines.append(f"    addi    {tail_count}, {tail_count}, -1")
    lines.append(f"    j       {tail_loop}")
    lines.append(f"{end_label}:")

    return lines


def _build_vncvt_x_x_w_lines(context) -> list[str]:
    """
    翻译 vncvt.x.x.w 指令 (256-bit 模式, narrowing)

    格式: vncvt.x.x.w vd, vs2
    语义: vd[i] = truncate(vs2[i]) (narrowing: e{sew*2} -> e{sew} int)
    :return: 生成的汇编代码行列表
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
    vs2 = operands[1]

    output_sew = state.sew
    input_sew = output_sew * 2

    if output_sew not in (8, 16, 32):
        raise InstructionValidationError(
            insn, f"vncvt.x.x.w 不支持输出 SEW={output_sew}"
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
    vs2_vreg = vtemps.alloc_vreg()
    vd_vreg = vtemps.alloc_vreg()

    temps = context.temp_register_allocator
    vl_reg = temps.alloc_gpr()
    chunk_count = temps.alloc_gpr()
    tail_count = temps.alloc_gpr()
    vs2_ptr = temps.alloc_gpr()
    vd_ptr = temps.alloc_gpr()
    temp = temps.alloc_gpr()

    lines.append(f"# vncvt.x.x.w {vd}, {vs2} (256-bit mode)")
    lines.append(f"# Semantic: {vd}[i] = truncate({vs2}[i]), e{input_sew} -> e{output_sew}")
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
    main_loop = new_label("vncvt_xx_main")
    after_main = new_label("vncvt_xx_after")

    lines.append(f"    # --- 主循环: 每块处理 {chunk_n} 个元素 ---")
    lines.append(f"    # 输入: {chunk_bytes_in}B (e{input_sew}), 输出: {chunk_bytes_out}B (e{output_sew})")
    lines.append(f"    beqz    {chunk_count}, {after_main}")
    lines.append(f"{main_loop}:")
    _emit_vsetvl_for_chunk(lines, chunk_n, input_sew, "m1", vl_reg, scratch_reg=temp)
    lines.append(f"    vle{input_sew}.v {vs2_vreg}, ({vs2_ptr})       # 加载 {vs2} 块 (e{input_sew})")
    _emit_vsetvl_for_chunk(lines, chunk_n, output_sew, "m1", vl_reg, scratch_reg=temp)
    lines.append(f"    vncvt.x.x.w {vd_vreg}, {vs2_vreg}                  # {vd}[i] = truncate({vs2}[i])")
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
    tail_loop = new_label("vncvt_xx_tail")
    end_label = new_label("vncvt_xx_end")

    int_load_instr = {8: 'lb', 16: 'lh', 32: 'lw', 64: 'ld'}[input_sew]
    int_store_instr = {8: 'sb', 16: 'sh', 32: 'sw', 64: 'sd'}[output_sew]

    lines.append(f"{tail_loop}:")
    lines.append(f"    beqz    {tail_count}, {end_label}")
    lines.append(f"    {int_load_instr:<8} {temp}, 0({vs2_ptr})            # {temp} = {vs2}[i] (e{input_sew})")
    lines.append(f"    {int_store_instr:<8} {temp}, 0({vd_ptr})            # {vd}[i] = truncate({temp})")
    lines.append(f"    addi    {vs2_ptr}, {vs2_ptr}, {elem_bytes_in}")
    lines.append(f"    addi    {vd_ptr}, {vd_ptr}, {elem_bytes_out}")
    lines.append(f"    addi    {tail_count}, {tail_count}, -1")
    lines.append(f"    j       {tail_loop}")
    lines.append(f"{end_label}:")

    return lines


def _emit_vnsr_wi(
    insn: RVInstruction,
    state: StateTracker,
    allocator: SimulatedStateLayout,
    new_label,
    *,
    signed: bool,
) -> List[str]:
    """翻译 vnsrl.wi / vnsra.wi 的共享实现。"""
    opcode = "vnsra.wi" if signed else "vnsrl.wi"
    scalar_shift = "srai" if signed else "srli"
    load_kind = "signed" if signed else "unsigned"
    type_prefix = "s" if signed else "u"
    loop_prefix = "vnsra_wi" if signed else "vnsrl_wi"

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
        uimm = int(operands[2], 0)
    except ValueError:
        raise InstructionValidationError(insn, f"{opcode} immediate must be an integer: {insn.op_str}")

    if not 0 <= uimm <= 31:
        raise InstructionValidationError(insn, f"{opcode} immediate must be 5-bit unsigned (0..31), got {uimm}")

    output_sew = state.sew
    input_sew = output_sew * 2

    if output_sew not in (8, 16, 32):
        raise InstructionValidationError(
            insn,
            f"{opcode} supports destination SEW=8/16/32 "
            f"(source e16/e32/e64), got SEW={output_sew}",
        )

    chunk_n = 256 // input_sew
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
    vs2_vreg = vtemps.alloc_vreg_group(2)
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

    lines.append(f"# {opcode} {vd}, {vs2}, {uimm} (256-bit mode)")
    lines.append(
        f"# Semantic: {vd}[i] = truncate(({type_prefix}{input_sew}){vs2}[i] >> {uimm}), "
        f"e{input_sew} -> e{output_sew}"
    )
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
    main_loop = new_label(f"{loop_prefix}_main")
    after_main = new_label(f"{loop_prefix}_after")

    lines.append(f"    # --- 主循环: 每块处理 {chunk_n} 个元素 ---")
    lines.append(f"    # 输入: {chunk_bytes_in}B (e{input_sew}), 输出: {chunk_bytes_out}B (e{output_sew})")
    lines.append(f"    beqz    {chunk_count}, {after_main}")
    lines.append(f"{main_loop}:")
    mask_suffix = ", v0.t" if is_masked else ""
    if is_masked:
        _emit_mask_extraction_chunk(lines, input_sew, mask_bit_idx, v0_base, vl_reg, temp)

    _emit_vsetvl_for_chunk(lines, chunk_n, input_sew, "m1", vl_reg, scratch_reg=temp)
    lines.append(f"    vle{input_sew}.v {vs2_vreg}, ({vs2_ptr})       # 加载 {vs2} 块 (e{input_sew})")
    _emit_vsetvl_for_chunk(lines, chunk_n, output_sew, "m1", vl_reg, scratch_reg=temp)
    lines.append(f"    {opcode} {vd_vreg}, {vs2_vreg}, {uimm}{mask_suffix}              # {vd}[i] = ({vs2}[i] >> {uimm}) narrow")
    lines.append(f"    vse{output_sew}.v {vd_vreg}, ({vd_ptr}){mask_suffix}       # 写回 {vd} 块 (e{output_sew})")
    lines.append("")
    lines.append(f"    addi    {vs2_ptr}, {vs2_ptr}, {chunk_bytes_in}")
    lines.append(f"    addi    {vd_ptr}, {vd_ptr}, {chunk_bytes_out}")
    if is_masked:
        lines.append(f"    addi    {mask_bit_idx}, {mask_bit_idx}, {chunk_n}")
    lines.append(f"    addi    {chunk_count}, {chunk_count}, -1")
    lines.append(f"    bnez    {chunk_count}, {main_loop}")
    lines.append(f"{after_main}:")
    lines.append("")

    # ========== 尾部 RVV 回退 ==========
    lines.append(f"    # --- 尾部 RVV chunk: 剩余 {tail_count} 个元素 ---")
    end_label = new_label(f"{loop_prefix}_end")

    lines.append(f"    beqz    {tail_count}, {end_label}")
    if is_masked:
        _emit_mask_extraction_chunk(lines, input_sew, mask_bit_idx, v0_base, vl_reg, temp)
    lines.append(f"    vsetvli zero, {tail_count}, e{input_sew}, m1, ta, ma")
    lines.append(f"    vle{input_sew}.v {vs2_vreg}, ({vs2_ptr})       # 加载 {vs2} tail (e{input_sew})")
    lines.append(f"    vsetvli zero, {tail_count}, e{output_sew}, m1, ta, ma")
    lines.append(f"    {opcode} {vd_vreg}, {vs2_vreg}, {uimm}{mask_suffix}              # tail: narrow shift")
    lines.append(f"    vse{output_sew}.v {vd_vreg}, ({vd_ptr}){mask_suffix}       # 写回 {vd} tail (e{output_sew})")
    lines.append(f"{end_label}:")
    return lines


def _build_vnsrl_wi_lines(context) -> list[str]:
    """
    翻译 vnsrl.wi 指令 (256-bit 模式, narrowing logical shift right)

    格式: vnsrl.wi vd, vs2, uimm
    语义: vd[i] = truncate(unsigned(vs2[i]) >> uimm)
          narrowing: e{sew*2} -> e{sew}
    """
    insn = context.instruction
    state = context.state
    allocator = context.layout
    new_label = context.new_label
    return _emit_vnsr_wi(insn, state, allocator, new_label, signed=False)


def _build_vnsra_wi_lines(context) -> list[str]:
    """
    翻译 vnsra.wi 指令 (256-bit 模式, narrowing arithmetic shift right)

    格式: vnsra.wi vd, vs2, uimm
    语义: vd[i] = truncate(signed(vs2[i]) >> uimm)
          narrowing: e{sew*2} -> e{sew}
    """
    insn = context.instruction
    state = context.state
    allocator = context.layout
    new_label = context.new_label
    return _emit_vnsr_wi(insn, state, allocator, new_label, signed=True)


def _build_vnclip_wi_lines(context) -> list[str]:
    """
    翻译 vnclip.wi 指令 (256-bit 模式, signed narrowing clip with rounding)

    格式: vnclip.wi vd, vs2, uimm
    语义: vd[i] = signed_saturate(roundoff_signed(vs2[i], uimm), SEW)
          narrowing: e{sew*2} -> e{sew}
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
        uimm = int(operands[2], 0)
    except ValueError:
        raise InstructionValidationError(insn, f"vnclip.wi immediate must be an integer: {insn.op_str}")

    if not 0 <= uimm <= 31:
        raise InstructionValidationError(insn, f"vnclip.wi immediate must be 5-bit unsigned (0..31), got {uimm}")

    output_sew = state.sew
    input_sew = output_sew * 2
    if output_sew not in (8, 16, 32):
        raise InstructionValidationError(
            insn,
            "vnclip.wi supports destination SEW=8/16/32 "
            f"(source e16/e32/e64), got SEW={output_sew}",
        )

    chunk_n = 256 // input_sew
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
    vcsr_off = CSR_OFFSETS['vcsr']

    vtemps = VRegTempAllocator(insn)
    vs2_vreg = vtemps.alloc_vreg_group(2)
    vd_vreg = vtemps.alloc_vreg()

    temps = context.temp_register_allocator
    vl_reg = temps.alloc_gpr()
    chunk_count = temps.alloc_gpr()
    tail_count = temps.alloc_gpr()
    vs2_ptr = temps.alloc_gpr()
    vd_ptr = temps.alloc_gpr()
    temp = temps.alloc_gpr()
    csr_addr = temps.alloc_gpr()
    csr_val = temps.alloc_gpr()

    lines.append(f"# vnclip.wi {vd}, {vs2}, {uimm} (256-bit mode)")
    lines.append(
        f"# Semantic: {vd}[i] = sat_signed(round_signed({vs2}[i] >> {uimm})), "
        f"e{input_sew} -> e{output_sew}"
    )
    lines.append("# Uses native RVV vnclip.wi so vxrm rounding and vxsat saturation match hardware semantics")
    lines.append("")

    lines.append(f"    li      {csr_addr}, {vcsr_off:#x}")
    lines.append(f"    add     {csr_addr}, t6, {csr_addr}")
    lines.append(f"    ld      {csr_val}, 0({csr_addr})          # CSR.vcsr")
    lines.append(f"    srli    {csr_val}, {csr_val}, 1")
    lines.append(f"    andi    {csr_val}, {csr_val}, 3")
    lines.append(f"    csrw    vxrm, {csr_val}                  # sync simulated vxrm to hardware")
    lines.append("    csrwi   vxsat, 0                         # collect vxsat for this instruction")
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

    main_loop = new_label("vnclip_wi_main")
    after_main = new_label("vnclip_wi_after")
    tail_label = new_label("vnclip_wi_tail")
    end_label = new_label("vnclip_wi_end")

    lines.append(f"    # --- 主循环: 每块处理 {chunk_n} 个元素 ---")
    lines.append(f"    # 输入: {chunk_bytes_in}B (e{input_sew}), 输出: {chunk_bytes_out}B (e{output_sew})")
    lines.append(f"    beqz    {chunk_count}, {after_main}")
    lines.append(f"{main_loop}:")
    _emit_vsetvl_for_chunk(lines, chunk_n, input_sew, "m1", vl_reg, scratch_reg=temp)
    lines.append(f"    vle{input_sew}.v {vs2_vreg}, ({vs2_ptr})       # 加载 {vs2} 块 (e{input_sew})")
    _emit_vsetvl_for_chunk(lines, chunk_n, output_sew, "m1", vl_reg, scratch_reg=temp)
    lines.append(f"    vnclip.wi {vd_vreg}, {vs2_vreg}, {uimm}             # round + signed saturating narrow")
    lines.append(f"    vse{output_sew}.v {vd_vreg}, ({vd_ptr})       # 写回 {vd} 块 (e{output_sew})")
    lines.append("")
    lines.append(f"    addi    {vs2_ptr}, {vs2_ptr}, {chunk_bytes_in}")
    lines.append(f"    addi    {vd_ptr}, {vd_ptr}, {chunk_bytes_out}")
    lines.append(f"    addi    {chunk_count}, {chunk_count}, -1")
    lines.append(f"    bnez    {chunk_count}, {main_loop}")
    lines.append(f"{after_main}:")
    lines.append("")

    lines.append("    # --- 尾部 RVV chunk: 使用真实 vl 处理剩余元素 ---")
    lines.append(f"    beqz    {tail_count}, {tail_label}")
    lines.append(f"    vsetvli zero, {tail_count}, e{input_sew}, m1, ta, ma")
    lines.append(f"    vle{input_sew}.v {vs2_vreg}, ({vs2_ptr})")
    lines.append(f"    vsetvli zero, {tail_count}, e{output_sew}, m1, ta, ma")
    lines.append(f"    vnclip.wi {vd_vreg}, {vs2_vreg}, {uimm}")
    lines.append(f"    vse{output_sew}.v {vd_vreg}, ({vd_ptr})")
    lines.append(f"{tail_label}:")
    lines.append("")

    lines.append("    # --- Merge sticky vxsat into authoritative simulated vcsr ---")
    lines.append(f"    csrr    {csr_val}, vxsat")
    lines.append(f"    li      {csr_addr}, {vcsr_off:#x}")
    lines.append(f"    add     {csr_addr}, t6, {csr_addr}")
    lines.append(f"    ld      {temp}, 0({csr_addr})            # old CSR.vcsr")
    lines.append(f"    or      {csr_val}, {csr_val}, {temp}")
    lines.append(f"    sd      {csr_val}, 0({csr_addr})          # CSR.vcsr |= hardware vxsat")
    lines.append(f"    andi    {temp}, {csr_val}, 1")
    lines.append(f"    sd      {temp}, {CSR_OFFSETS['vxsat'] - vcsr_off}({csr_addr})")
    lines.append(f"    srli    {temp}, {csr_val}, 1")
    lines.append(f"    andi    {temp}, {temp}, 3")
    lines.append(f"    sd      {temp}, {CSR_OFFSETS['vxrm'] - vcsr_off}({csr_addr})")
    lines.append(f"{end_label}:")

    return lines


def _build_vfncvt_f_xu_w_lines(context) -> list[str]:
    """
    翻译 vfncvt.f.xu.w 指令 (256-bit 模式, narrowing)

    格式: vfncvt.f.xu.w vd, vs2
    语义: vd[i] = float(vs2[i]) (narrowing: SEW*2 unsigned int -> SEW float)

    策略:
    - 输入 SEW = output_sew * 2, 每块处理 256 // input_sew 个元素
    - 主循环: vsetivli(input_sew) + vle + vsetivli(output_sew) + vfncvt + vse
    - 尾部: 标量 unsigned int -> float 回退
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
        raise InstructionValidationError(
            insn, f"vfncvt.f.xu.w 不支持输出 SEW={output_sew}"
        )

    # 每块元素数基于输入宽度 (更宽的输入意味着更少的元素/块)
    chunk_n = 256 // input_sew  # 对于 sew=32, input_sew=64: chunk_n=4
    chunk_bytes_in = chunk_n * (input_sew // 8)
    chunk_bytes_out = chunk_n * (output_sew // 8)
    # 计算 shift_amt (log2(chunk_n))
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
    # narrowing 指令读取更宽的源元素；为避免 vd 落到源寄存器组的高半部分，
    # 这里需要按组为 vs2 预留连续寄存器。
    vs2_vreg = vtemps.alloc_vreg_group(2)
    vd_vreg = vtemps.alloc_vreg()

    temps = TempRegisterAllocator(insn, reserved_gprs=("t6",), extra_avoid_fprs=("ft0",))
    vl_reg = temps.alloc_gpr()
    chunk_count = temps.alloc_gpr()
    tail_count = temps.alloc_gpr()
    vs2_ptr = temps.alloc_gpr()
    vd_ptr = temps.alloc_gpr()
    temp = temps.alloc_gpr()

    lines.append(f"# vfncvt.f.xu.w {vd}, {vs2} (256-bit mode)")
    lines.append(f"# Semantic: {vd}[i] = float({vs2}[i]), e{input_sew} -> e{output_sew}")
    lines.append("")

    # ========== 加载 vl 并计算块数/尾数 ==========
    _load_vl_from_csr(lines, vl_reg=vl_reg, addr_reg=chunk_count)
    lines.append(f"    srli    {chunk_count}, {vl_reg}, {shift_amt}       # {chunk_count} = vl / {chunk_n}")
    lines.append(f"    andi    {tail_count}, {vl_reg}, {mask}              # {tail_count} = vl % {chunk_n}")
    lines.append("")

    # ========== 设置基址指针 ==========
    lines.append(f"    li      {temp}, {vs2_off:#x}")
    lines.append(f"    add     {vs2_ptr}, t6, {temp}            # {vs2_ptr} = &{vs2}")
    lines.append(f"    li      {temp}, {vd_off:#x}")
    lines.append(f"    add     {vd_ptr}, t6, {temp}             # {vd_ptr} = &{vd}")
    lines.append("")

    # ========== 主循环 (256-bit 块) ==========
    main_loop = new_label("vfncvt_main")
    after_main = new_label("vfncvt_after")

    lines.append(f"    # --- 主循环: 每块处理 {chunk_n} 个元素 ---")
    lines.append(f"    # 输入: {chunk_bytes_in}B (e{input_sew}), 输出: {chunk_bytes_out}B (e{output_sew})")
    lines.append(f"    beqz    {chunk_count}, {after_main}")
    lines.append(f"{main_loop}:")
    # 设置输入 SEW 用于加载
    _emit_vsetvl_for_chunk(lines, chunk_n, input_sew, "m1", vl_reg, scratch_reg=temp)
    lines.append(f"    vle{input_sew}.v {vs2_vreg}, ({vs2_ptr})       # 加载 {vs2} 块 (e{input_sew})")
    # 切换为输出 SEW 用于 narrowing 转换和存储
    _emit_vsetvl_for_chunk(lines, chunk_n, output_sew, "m1", vl_reg, scratch_reg=temp)
    lines.append(f"    vfncvt.f.xu.w {vd_vreg}, {vs2_vreg}              # {vd_vreg}[i] = float({vs2_vreg}[i])")
    lines.append(f"    vse{output_sew}.v {vd_vreg}, ({vd_ptr})       # 写回 {vd} 块 (e{output_sew})")
    lines.append("")
    lines.append(f"    addi    {vs2_ptr}, {vs2_ptr}, {chunk_bytes_in}")
    lines.append(f"    addi    {vd_ptr}, {vd_ptr}, {chunk_bytes_out}")
    lines.append(f"    addi    {chunk_count}, {chunk_count}, -1")
    lines.append(f"    bnez    {chunk_count}, {main_loop}")
    lines.append(f"{after_main}:")
    lines.append("")

    # ========== 尾部标量回退 ==========
    lines.append(f"    # --- 尾部标量回退: 剩余 {tail_count} 个元素 (scalar uint -> float) ---")
    tail_loop = new_label("vfncvt_tail")
    end_label = new_label("vfncvt_end")

    int_load_instr = {8: 'lbu', 16: 'lhu', 32: 'lwu', 64: 'ld'}[input_sew]
    float_store_instr = _get_float_instr('store', output_sew)

    if output_sew == 32:
        fcvt_instr = "fcvt.s.lu"
    elif output_sew == 16:
        fcvt_instr = "fcvt.h.wu"
    else:
        raise InstructionValidationError(
            insn, f"vfncvt.f.xu.w 不支持输出 SEW={output_sew}"
        )

    lines.append(f"{tail_loop}:")
    lines.append(f"    beqz    {tail_count}, {end_label}")
    lines.append(f"    {int_load_instr:<8} {temp}, 0({vs2_ptr})            # {temp} = {vs2}[i] (uint{input_sew})")
    lines.append(f"    {fcvt_instr:<12} ft0, {temp}              # ft0 = float({temp})")
    lines.append(f"    {float_store_instr:<8} ft0, 0({vd_ptr})            # {vd}[i] = ft0")
    lines.append(f"    addi    {vs2_ptr}, {vs2_ptr}, {elem_bytes_in}")
    lines.append(f"    addi    {vd_ptr}, {vd_ptr}, {elem_bytes_out}")
    lines.append(f"    addi    {tail_count}, {tail_count}, -1")
    lines.append(f"    j       {tail_loop}")
    lines.append(f"{end_label}:")

    return lines
