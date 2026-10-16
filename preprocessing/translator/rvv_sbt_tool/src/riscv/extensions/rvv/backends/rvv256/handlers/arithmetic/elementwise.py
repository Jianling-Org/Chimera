"""RVV256 基础算术与数据搬移。

本文件由原算术模块按语义族机械拆分；函数体保持原样，公共状态与 ABI 访问统一复用 common。
"""

from riscv.extensions.rvv.translation.contracts import InstructionValidationError
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
    _emit_state_ptr,
)

from riscv.extensions.rvv.backends.rvv256.support import (
    _emit_scalar_tail_int_vv,
    _get_int_store,
)















def _build_vadd_vv_lines(context) -> list[str]:
    """
    翻译 vadd.vv 指令 (256-bit 模式)

    格式: vadd.vv vd, vs1, vs2
    语义: vd[i] = vs1[i] + vs2[i]
    尾部: 使用整数标量加法回退，按 SEW 截断写回
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
    vs1_vreg = vtemps.alloc_vreg()
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
    # e8/m1 的 AVL=32 不能由 vsetivli 编码，helper 会写 scratch_reg。
    # 因此不能再把 vl_reg 同时作为 vs1 状态指针，否则会生成从地址 32
    # 加载的错误代码。
    vs1_ptr = temps.alloc_gpr()

    vle_instr = _get_vle_instr(sew)
    vse_instr = _get_vse_instr(sew)

    lines.append(f"# vadd.vv {vd}, {vs1}, {vs2} (256-bit mode)")
    lines.append(f"# Semantic: {vd}[i] = {vs1}[i] + {vs2}[i], SEW={sew}")
    lines.append("")

    # ========== 加载 vl 并计算块数/尾数 ==========
    if is_masked:
        _emit_mask_setup(lines, mask_bit_idx, v0_base, temp)

    _load_vl_from_csr(lines, vl_reg=vl_reg, addr_reg=chunk_count)
    lines.append(f"    srli    {chunk_count}, {vl_reg}, {shift_amt}       # {chunk_count} = vl / {chunk_n}")
    lines.append(f"    andi    {tail_count}, {vl_reg}, {mask}              # {tail_count} = vl % {chunk_n}")
    lines.append("")

    # ========== 设置基址指针 ==========
    _emit_state_ptr(lines, vs2_ptr, vs2_off)
    _emit_state_ptr(lines, vd_ptr, vd_off)
    _emit_state_ptr(lines, vs1_ptr, vs1_off)
    lines.append("")

    # ========== 主循环 ==========
    main_loop = new_label("vadd_vv_main")
    after_main = new_label("vadd_vv_after")

    lines.append(f"    # --- 主循环: 每块处理 {chunk_n} 个元素 ({c_bytes} 字节) ---")
    lines.append(f"    beqz    {chunk_count}, {after_main}")
    if not is_masked:
        _emit_vsetvl_for_chunk(lines, chunk_n, sew, "m1", vl_reg, scratch_reg=vl_reg)
    lines.append(f"{main_loop}:")
    mask_suffix = ", v0.t" if is_masked else ""
    if is_masked:
        _emit_mask_extraction_chunk(lines, sew, mask_bit_idx, v0_base, vl_reg, temp)

    if is_masked:
        _emit_vsetvl_for_chunk(lines, chunk_n, sew, "m1", vl_reg, scratch_reg=vl_reg)
    lines.append("")
    lines.append(f"    {vle_instr} {vs2_vreg}, ({vs2_ptr})         # 加载 {vs2} 块")
    lines.append(f"    {vle_instr} {vs1_vreg}, ({vs1_ptr})         # 加载 {vs1} 块")
    lines.append(f"    vadd.vv {vd_vreg}, {vs1_vreg}, {vs2_vreg}{mask_suffix}     # {vd_vreg}{mask_suffix} = {vs1_vreg}{mask_suffix} + {vs2_vreg}{mask_suffix}")
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
    tail_loop = new_label("vadd_vv_tail")
    end_label = new_label("vadd_vv_end")
    _emit_scalar_tail_int_vv(
        lines=lines,
        sew=sew,
        tail_reg=tail_count,
        vs2_ptr=vs2_ptr,
        vs1_ptr=vs1_ptr,
        vd_ptr=vd_ptr,
        tmp0=chunk_count,
        tmp1=temp,
        tail_label=tail_loop,
        end_label=end_label,
        op_type='add',
        is_masked=is_masked,
        mask_bit_idx=mask_bit_idx if is_masked else '',
        v0_base=v0_base if is_masked else '',
        mask_tmp1=vl_reg,
        mask_tmp2=temp,
    )

    return lines
def _build_vsub_vv_lines(context) -> list[str]:
    """
    翻译 vsub.vv 指令 (256-bit 模式)

    格式: vsub.vv vd, vs2, vs1
    语义: vd[i] = vs2[i] - vs1[i] 对于 i in [0, vl)
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

    lines.append(f"# vsub.vv {vd}, {vs2}, {vs1} (256-bit mode, SEW={sew})")
    lines.append(f"# Semantic: {vd}[i] = {vs2}[i] - {vs1}[i]")
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

    main_loop = new_label("vsub_vv_main")
    after_main = new_label("vsub_vv_after")

    lines.append(f"    # --- 主循环: 每块处理 {chunk_n} 个元素 ({c_bytes} 字节) ---")
    lines.append(f"    beqz    {chunk_count}, {after_main}")
    _emit_vsetvl_for_chunk(lines, chunk_n, sew, "m1", vl_reg, scratch_reg=vl_reg)
    lines.append(f"{main_loop}:")
    lines.append("")
    lines.append(f"    {vle_instr} {vs2_vreg}, ({vs2_ptr})         # 加载 {vs2} 块")
    lines.append(f"    {vle_instr} {vs1_vreg}, ({vs1_ptr})         # 加载 {vs1} 块")
    lines.append(f"    vsub.vv {vd_vreg}, {vs2_vreg}, {vs1_vreg}     # {vd}[i] = {vs2}[i] - {vs1}[i]")
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
    end_label = new_label("vsub_vv_end")
    lines.append(f"    beqz    {tail_count}, {end_label}")
    lines.append(f"    vsetvli zero, {tail_count}, e{sew}, m1, ta, ma")
    lines.append(f"    {vle_instr} {vs2_vreg}, ({vs2_ptr})         # 加载 {vs2} tail")
    lines.append(f"    {vle_instr} {vs1_vreg}, ({vs1_ptr})         # 加载 {vs1} tail")
    lines.append(f"    vsub.vv {vd_vreg}, {vs2_vreg}, {vs1_vreg}     # tail: {vd}[i] = {vs2}[i] - {vs1}[i]")
    lines.append(f"    {vse_instr} {vd_vreg}, ({vd_ptr}){mask_suffix}          # 写回 {vd} tail")
    lines.append(f"{end_label}:")

    return lines






















def _build_vadd_vi_lines(context) -> list[str]:
    """
    翻译 vadd.vi 指令 (256-bit 模式)

    格式: vadd.vi vd, vs2, imm
    语义: vd[i] = vs2[i] + imm

    策略:
    - 主循环: vle + vadd.vi + vse 处理 256-bit 块
    - 尾部: 标量整数加法回退
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
    imm_str = operands[2]

    # 解析立即数
    try:
        imm_val = int(str(imm_str), 0)
    except ValueError:
        raise InstructionValidationError(insn, f"Invalid immediate for {insn.opcode}: {insn.op_str}")

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

    if is_masked:
        mask_bit_idx = temps.alloc_gpr()
        v0_base = temps.alloc_gpr()
        mask_tmp = temps.alloc_gpr()

    vle_instr = _get_vle_instr(sew)
    vse_instr = _get_vse_instr(sew)
    store_instr = {8: 'sb', 16: 'sh', 32: 'sw', 64: 'sd'}[sew]
    load_instr = {8: 'lb', 16: 'lh', 32: 'lw', 64: 'ld'}[sew]
    # 尾部标量加法: sew=32 使用 addiw, 其它使用 addi (imm 仅 5-bit, 安全)
    addi_instr = {8: 'addi', 16: 'addi', 32: 'addiw', 64: 'addi'}[sew]

    lines.append(f"# vadd.vi {vd}, {vs2}, {imm_str} (256-bit mode)")
    lines.append(f"# Semantic: {vd}[i] = {vs2}[i] + {imm_val}, SEW={sew}")
    lines.append("")

    # ========== 加载 vl 并计算块数/尾数 ==========
    if is_masked:
        _emit_mask_setup(lines, mask_bit_idx, v0_base, temp)

    _load_vl_from_csr(lines, vl_reg=vl_reg, addr_reg=chunk_count)
    lines.append(f"    srli    {chunk_count}, {vl_reg}, {shift_amt}       # {chunk_count} = vl / {chunk_n}")
    lines.append(f"    andi    {tail_count}, {vl_reg}, {mask}              # {tail_count} = vl % {chunk_n}")
    lines.append("")

    # ========== 设置基址指针 ==========
    _emit_state_ptr(lines, vs2_ptr, vs2_off)
    _emit_state_ptr(lines, vd_ptr, vd_off)
    lines.append("")

    # ========== 主循环 (256-bit 块) ==========
    main_loop = new_label("vadd_vi_main")
    after_main = new_label("vadd_vi_after")

    lines.append(f"    # --- 主循环: 每块处理 {chunk_n} 个元素 ({c_bytes} 字节) ---")
    lines.append(f"    beqz    {chunk_count}, {after_main}")
    if not is_masked:
        _emit_vsetvl_for_chunk(lines, chunk_n, sew, "m1", vl_reg, scratch_reg=temp)
    lines.append(f"{main_loop}:")
    mask_suffix = ", v0.t" if is_masked else ""
    if is_masked:
        if sew in (8, 16, 32):
            _emit_vsetvl_for_chunk(lines, chunk_n, sew, "m1", vl_reg, scratch_reg=temp)
            _emit_mask_load_byte_aligned_chunk(lines, sew, mask_bit_idx, v0_base, vl_reg)
        else:
            _emit_mask_extraction_chunk(lines, sew, mask_bit_idx, v0_base, vl_reg, temp)
            _emit_vsetvl_for_chunk(lines, chunk_n, sew, "m1", vl_reg, scratch_reg=temp)
    lines.append("")
    lines.append(f"    {vle_instr} {vs2_vreg}, ({vs2_ptr})         # 加载 {vs2} 块")
    lines.append(f"    vadd.vi {vd_vreg}, {vs2_vreg}, {imm_val}{mask_suffix}      # {vd_vreg}{mask_suffix} = {vs2_vreg}{mask_suffix} + {imm_val}")
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
    lines.append(f"    # --- 尾部标量回退: 剩余 {tail_count} 个元素 ---")
    tail_loop = new_label("vadd_vi_tail")
    end_label = new_label("vadd_vi_end")
    skip_label = f"{tail_loop}_skip"

    lines.append(f"{tail_loop}:")
    lines.append(f"    beqz    {tail_count}, {end_label}")
    if is_masked:
        _emit_mask_extraction_tail(lines, mask_bit_idx, v0_base, temp, mask_tmp, skip_label)
    lines.append(f"    {load_instr:<8} {temp}, 0({vs2_ptr})               # {temp} = {vs2}[i]")
    lines.append(f"    {addi_instr:<8} {temp}, {temp}, {imm_val}            # {temp} = {temp} + {imm_val}")
    lines.append(f"    {store_instr:<8} {temp}, 0({vd_ptr})               # {vd}[i] = {temp}")
    if is_masked:
        lines.append(f"{skip_label}:")
        lines.append(f"    addi    {mask_bit_idx}, {mask_bit_idx}, 1")
    lines.append(f"    addi    {vs2_ptr}, {vs2_ptr}, {elem_bytes}")
    lines.append(f"    addi    {vd_ptr}, {vd_ptr}, {elem_bytes}")
    lines.append(f"    addi    {tail_count}, {tail_count}, -1")
    lines.append(f"    j       {tail_loop}")
    lines.append(f"{end_label}:")

    return lines



def _build_vadd_vx_lines(context) -> list[str]:
    """
    翻译 vadd.vx 指令 (256-bit 模式)

    格式: vadd.vx vd, vs2, rs1
    语义: vd[i] = vs2[i] + rs1

    策略:
    - 主循环: vle + vadd.vx + vse 处理 256-bit 块
    - 尾部: 标量整数加法回退
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
    rs1 = operands[2]

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
    scalar_reg = temps.alloc_gpr()

    if is_masked:
        mask_bit_idx = temps.alloc_gpr()
        v0_base = temps.alloc_gpr()

    vle_instr = _get_vle_instr(sew)
    vse_instr = _get_vse_instr(sew)
    store_instr = {8: 'sb', 16: 'sh', 32: 'sw', 64: 'sd'}[sew]
    load_instr = {8: 'lb', 16: 'lh', 32: 'lw', 64: 'ld'}[sew]
    add_instr = {8: 'add', 16: 'add', 32: 'addw', 64: 'add'}[sew]

    lines.append(f"# vadd.vx {vd}, {vs2}, {rs1} (256-bit mode)")
    lines.append(f"# Semantic: {vd}[i] = {vs2}[i] + {rs1}, SEW={sew}")
    lines.append("")

    # ========== 加载 vl 并计算块数/尾数 ==========
    if is_masked:
        _emit_mask_setup(lines, mask_bit_idx, v0_base, temp)

    _load_vl_from_csr(lines, vl_reg=vl_reg, addr_reg=chunk_count)
    lines.append(f"    srli    {chunk_count}, {vl_reg}, {shift_amt}       # {chunk_count} = vl / {chunk_n}")
    lines.append(f"    andi    {tail_count}, {vl_reg}, {mask}              # {tail_count} = vl % {chunk_n}")
    lines.append("")

    # ========== 保存 rs1 值 ==========
    lines.append(f"    mv      {scalar_reg}, {rs1}                        # {scalar_reg} = {rs1}")
    lines.append("")

    # ========== 设置基址指针 ==========
    lines.append(f"    li      {temp}, {vs2_off:#x}")
    lines.append(f"    add     {vs2_ptr}, t6, {temp}            # {vs2_ptr} = &{vs2}")
    lines.append(f"    li      {temp}, {vd_off:#x}")
    lines.append(f"    add     {vd_ptr}, t6, {temp}             # {vd_ptr} = &{vd}")
    lines.append("")

    # ========== 主循环 (256-bit 块) ==========
    main_loop = new_label("vadd_vx_main")
    after_main = new_label("vadd_vx_after")

    lines.append(f"    # --- 主循环: 每块处理 {chunk_n} 个元素 ({c_bytes} 字节) ---")
    lines.append(f"    beqz    {chunk_count}, {after_main}")
    if not is_masked:
        _emit_vsetvl_for_chunk(lines, chunk_n, sew, "m1", vl_reg, scratch_reg=temp)
    lines.append(f"{main_loop}:")
    mask_suffix = ", v0.t" if is_masked else ""
    if is_masked:
        if sew in (8, 16, 32):
            _emit_vsetvl_for_chunk(lines, chunk_n, sew, "m1", vl_reg, scratch_reg=temp)
            _emit_mask_load_byte_aligned_chunk(lines, sew, mask_bit_idx, v0_base, vl_reg)
        else:
            _emit_mask_extraction_chunk(lines, sew, mask_bit_idx, v0_base, vl_reg, temp)
            _emit_vsetvl_for_chunk(lines, chunk_n, sew, "m1", vl_reg, scratch_reg=temp)
    lines.append("")
    lines.append(f"    {vle_instr} {vs2_vreg}, ({vs2_ptr})         # 加载 {vs2} 块")
    lines.append(f"    vadd.vx {vd_vreg}, {vs2_vreg}, {scalar_reg}{mask_suffix}      # {vd_vreg}{mask_suffix} = {vs2_vreg}{mask_suffix} + {rs1}")
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
    lines.append(f"    # --- 尾部标量回退: 剩余 {tail_count} 个元素 ---")
    tail_loop = new_label("vadd_vx_tail")
    end_label = new_label("vadd_vx_end")
    skip_label = f"{tail_loop}_skip"

    lines.append(f"{tail_loop}:")
    lines.append(f"    beqz    {tail_count}, {end_label}")
    if is_masked:
        _emit_mask_extraction_tail(lines, mask_bit_idx, v0_base, vl_reg, temp, skip_label)
    lines.append(f"    {load_instr:<8} {temp}, 0({vs2_ptr})               # {temp} = {vs2}[i]")
    lines.append(f"    {add_instr:<8} {temp}, {temp}, {scalar_reg}         # {temp} = {temp} + {rs1}")
    lines.append(f"    {store_instr:<8} {temp}, 0({vd_ptr})               # {vd}[i] = {temp}")
    if is_masked:
        lines.append(f"{skip_label}:")
        lines.append(f"    addi    {mask_bit_idx}, {mask_bit_idx}, 1")
    lines.append(f"    addi    {vs2_ptr}, {vs2_ptr}, {elem_bytes}")
    lines.append(f"    addi    {vd_ptr}, {vd_ptr}, {elem_bytes}")
    lines.append(f"    addi    {tail_count}, {tail_count}, -1")
    lines.append(f"    j       {tail_loop}")
    lines.append(f"{end_label}:")

    return lines



def _build_vsub_vx_lines(context) -> list[str]:
    """
    翻译 vsub.vx 指令 (256-bit 模式)

    格式: vsub.vx vd, vs2, rs1
    语义: vd[i] = vs2[i] - rs1
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
    scalar_reg = temps.alloc_gpr()

    if is_masked:
        mask_bit_idx = temps.alloc_gpr()
        v0_base = temps.alloc_gpr()

    vle_instr = _get_vle_instr(sew)
    vse_instr = _get_vse_instr(sew)
    load_instr = {8: 'lb', 16: 'lh', 32: 'lw', 64: 'ld'}[sew]
    store_instr = _get_int_store(sew)
    sub_instr = {8: 'sub', 16: 'sub', 32: 'subw', 64: 'sub'}[sew]

    lines.append(f"# vsub.vx {vd}, {vs2}, {rs1} (256-bit mode)")
    lines.append(f"# Semantic: {vd}[i] = {vs2}[i] - {rs1}, SEW={sew}")
    lines.append("")

    if is_masked:
        _emit_mask_setup(lines, mask_bit_idx, v0_base, temp)

    _load_vl_from_csr(lines, vl_reg=vl_reg, addr_reg=chunk_count)
    lines.append(f"    srli    {chunk_count}, {vl_reg}, {shift_amt}       # {chunk_count} = vl / {chunk_n}")
    lines.append(f"    andi    {tail_count}, {vl_reg}, {mask}              # {tail_count} = vl % {chunk_n}")
    lines.append("")

    lines.append(f"    mv      {scalar_reg}, {rs1}                        # {scalar_reg} = {rs1}")
    lines.append("")

    lines.append(f"    li      {temp}, {vs2_off:#x}")
    lines.append(f"    add     {vs2_ptr}, t6, {temp}            # {vs2_ptr} = &{vs2}")
    lines.append(f"    li      {temp}, {vd_off:#x}")
    lines.append(f"    add     {vd_ptr}, t6, {temp}             # {vd_ptr} = &{vd}")
    lines.append("")

    main_loop = new_label("vsub_vx_main")
    after_main = new_label("vsub_vx_after")

    lines.append(f"    # --- 主循环: 每块处理 {chunk_n} 个元素 ({c_bytes} 字节) ---")
    lines.append(f"    beqz    {chunk_count}, {after_main}")
    if not is_masked:
        _emit_vsetvl_for_chunk(lines, chunk_n, sew, "m1", vl_reg, scratch_reg=temp)
    lines.append(f"{main_loop}:")
    mask_suffix = ", v0.t" if is_masked else ""
    if is_masked:
        _emit_mask_extraction_chunk(lines, sew, mask_bit_idx, v0_base, vl_reg, temp)
        _emit_vsetvl_for_chunk(lines, chunk_n, sew, "m1", vl_reg, scratch_reg=temp)
    lines.append("")
    lines.append(f"    {vle_instr} {vs2_vreg}, ({vs2_ptr})         # 加载 {vs2} 块")
    lines.append(f"    vsub.vx {vd_vreg}, {vs2_vreg}, {scalar_reg}{mask_suffix}      # {vd_vreg}{mask_suffix} = {vs2_vreg}{mask_suffix} - {rs1}")
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

    tail_loop = new_label("vsub_vx_tail")
    end_label = new_label("vsub_vx_end")
    skip_label = f"{tail_loop}_skip"
    lines.append(f"    # --- 尾部标量回退: 剩余 {tail_count} 个元素 ---")
    lines.append(f"{tail_loop}:")
    lines.append(f"    beqz    {tail_count}, {end_label}")
    if is_masked:
        _emit_mask_extraction_tail(lines, mask_bit_idx, v0_base, vl_reg, temp, skip_label)
    lines.append(f"    {load_instr:<8} {temp}, 0({vs2_ptr})               # {temp} = {vs2}[i]")
    lines.append(f"    {sub_instr:<8} {temp}, {temp}, {scalar_reg}         # {temp} = {temp} - {rs1}")
    lines.append(f"    {store_instr:<8} {temp}, 0({vd_ptr})               # {vd}[i] = {temp}")
    if is_masked:
        lines.append(f"{skip_label}:")
        lines.append(f"    addi    {mask_bit_idx}, {mask_bit_idx}, 1")
    lines.append(f"    addi    {vs2_ptr}, {vs2_ptr}, {elem_bytes}")
    lines.append(f"    addi    {vd_ptr}, {vd_ptr}, {elem_bytes}")
    lines.append(f"    addi    {tail_count}, {tail_count}, -1")
    lines.append(f"    j       {tail_loop}")
    lines.append(f"{end_label}:")

    return lines






def _build_vid_v_lines(context) -> list[str]:
    """
    翻译 vid.v 指令 (256-bit 模式)

    格式: vid.v vd
    语义: vd[i] = i (元素索引)

    策略:
    - 主循环: vid.v 生成 0..chunk_n-1, vadd.vx 加上块起始偏移
    - 尾部: 标量写回索引值
    :return: 生成的汇编代码行列表
    """
    insn = context.instruction
    state = context.state
    allocator = context.layout
    new_label = context.new_label
    lines = []
    mask_suffix = ""
    operands = insn.operands
    if len(operands) < 1:
        raise InstructionValidationError(insn, f"Invalid operand for {insn.opcode}: {insn.op_str}")

    vd = operands[0]

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
    chunk_offset = temps.alloc_gpr()

    vse_instr = _get_vse_instr(sew)
    store_instr = {8: 'sb', 16: 'sh', 32: 'sw', 64: 'sd'}[sew]

    lines.append(f"# vid.v {vd} (256-bit mode)")
    lines.append(f"# Semantic: {vd}[i] = i, SEW={sew}")
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

    # ========== 初始化块偏移 ==========
    lines.append(f"    li      {chunk_offset}, 0                # 当前块起始索引")
    lines.append("")

    # ========== 主循环 (256-bit 块) ==========
    main_loop = new_label("vid_v_main")
    after_main = new_label("vid_v_after")

    lines.append(f"    # --- 主循环: 每块处理 {chunk_n} 个元素 ({c_bytes} 字节) ---")
    lines.append(f"    beqz    {chunk_count}, {after_main}")
    _emit_vsetvl_for_chunk(lines, chunk_n, sew, "m1", vl_reg, scratch_reg=temp)
    lines.append(f"{main_loop}:")
    lines.append("")
    lines.append(f"    vid.v {vd_vreg}                               # {vd_vreg}[j] = j (0..{chunk_n - 1})")
    lines.append(f"    vadd.vx {vd_vreg}, {vd_vreg}, {chunk_offset}    # {vd_vreg}[j] = j + chunk_offset")
    lines.append(f"    {vse_instr} {vd_vreg}, ({vd_ptr}){mask_suffix}          # 写回 {vd} 块")
    lines.append("")
    lines.append(f"    addi    {vd_ptr}, {vd_ptr}, {c_bytes}")
    lines.append(f"    addi    {chunk_offset}, {chunk_offset}, {chunk_n}")
    lines.append(f"    addi    {chunk_count}, {chunk_count}, -1")
    lines.append(f"    bnez    {chunk_count}, {main_loop}")
    lines.append(f"{after_main}:")
    lines.append("")

    # ========== 尾部标量回退 ==========
    lines.append(f"    # --- 尾部标量回退: 剩余 {tail_count} 个元素 ---")
    tail_loop = new_label("vid_v_tail")
    end_label = new_label("vid_v_end")

    lines.append(f"{tail_loop}:")
    lines.append(f"    beqz    {tail_count}, {end_label}")
    lines.append(f"    {store_instr:<8} {chunk_offset}, 0({vd_ptr})          # {vd}[i] = {chunk_offset}")
    lines.append(f"    addi    {vd_ptr}, {vd_ptr}, {elem_bytes}")
    lines.append(f"    addi    {chunk_offset}, {chunk_offset}, 1")
    lines.append(f"    addi    {tail_count}, {tail_count}, -1")
    lines.append(f"    j       {tail_loop}")
    lines.append(f"{end_label}:")

    return lines
