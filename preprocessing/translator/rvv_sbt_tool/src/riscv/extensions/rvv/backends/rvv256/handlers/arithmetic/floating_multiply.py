"""floating_multiply：后端内部职责。"""

from __future__ import annotations

from riscv.extensions.rvv.translation.contracts import InstructionValidationError
from riscv.extensions.rvv.translation.temps import record_fpr
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
    _emit_state_ptr,
)
from riscv.extensions.rvv.backends.rvv256.support import (
    _emit_scalar_tail_vf,
    _emit_scalar_tail_vv,
)


def _build_vfmacc_vf_lines(context) -> list[str]:
    """
    翻译 vfmacc.vf 指令 (256-bit 模式)

    格式: vfmacc.vf vd, rs1, vs2
    语义: vd[i] += rs1 * vs2[i]

    策略:
    - 主循环: 使用 vsetivli + vle{sew}.v / vse{sew}.v + vfmacc.vf 处理 256-bit 块
    - 尾部: 标量 fmadd 回退
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
    rs1 = operands[1]
    vs2 = operands[2]

    sew = state.sew
    chunk_n = _chunk_size(sew)       # 每块元素数
    c_bytes = _chunk_bytes()         # 每块字节数 (32)
    shift_amt = chunk_n.bit_length() - 1  # log2(chunk_n)
    mask = chunk_n - 1               # chunk_n-1 掩码

    vd_off = allocator.get_offset(vd)
    vs2_off = allocator.get_offset(vs2)

    # 分配临时向量寄存器
    vtemps = VRegTempAllocator(insn)
    vs2_vreg = vtemps.alloc_vreg()
    vd_vreg = vtemps.alloc_vreg()

    # 分配 GPR 临时寄存器
    temps = context.temp_register_allocator
    vl_reg = temps.alloc_gpr()
    chunk_count = temps.alloc_gpr()
    tail_count = temps.alloc_gpr()
    vs2_ptr = temps.alloc_gpr()
    vd_ptr = temps.alloc_gpr()
    temp = temps.alloc_gpr()
    tail_vs2_fpr = temps.alloc_fpr()
    tail_vd_fpr = temps.alloc_fpr()

    if is_masked:
        mask_bit_idx = temps.alloc_gpr()
        v0_base = temps.alloc_gpr()


    # ========== 注释头部 ==========
    lines.append(f"# vfmacc.vf {vd}, {rs1}, {vs2} (256-bit mode)")
    lines.append(f"# Semantic: {vd}[i] += {rs1} * {vs2}[i], SEW={sew}")
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
    main_loop = new_label("vfmacc_vf_main")
    after_main = new_label("vfmacc_vf_after")

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
    lines.append(f"    vle{sew}.v {vs2_vreg}, ({vs2_ptr})         # 加载 {vs2} 块")
    lines.append(f"    vle{sew}.v {vd_vreg}, ({vd_ptr})          # 加载 {vd} 块")
    lines.append(f"    vfmacc.vf {vd_vreg}, {rs1}, {vs2_vreg}{mask_suffix}     # {vd_vreg}{mask_suffix} = {rs1}{mask_suffix} * {vs2_vreg}{mask_suffix} + {vd_vreg}")
    lines.append(f"    vse{sew}.v {vd_vreg}, ({vd_ptr}){mask_suffix}          # 写回 {vd} 块")
    lines.append("")
    lines.append(f"    addi    {vs2_ptr}, {vs2_ptr}, {c_bytes}    # 前进 vs2 指针")
    lines.append(f"    addi    {vd_ptr}, {vd_ptr}, {c_bytes}      # 前进 vd 指针")
    if is_masked:
        lines.append(f"    addi    {mask_bit_idx}, {mask_bit_idx}, {chunk_n}")
    lines.append(f"    addi    {chunk_count}, {chunk_count}, -1")
    lines.append(f"    bnez    {chunk_count}, {main_loop}")
    lines.append(f"{after_main}:")
    lines.append("")

    # ========== 尾部标量回退 ==========
    lines.append(f"    # --- 尾部标量回退: 剩余 {tail_count} 个元素 ---")
    tail_loop = new_label("vfmacc_vf_tail")
    end_label = new_label("vfmacc_vf_end")
    _emit_scalar_tail_vf(
        lines=lines,
        sew=sew,
        tail_reg=tail_count,
        vs2_ptr=vs2_ptr,
        vd_ptr=vd_ptr,
        rs1=rs1,
        vs2_fpr=tail_vs2_fpr,
        vd_fpr=tail_vd_fpr,
        tail_label=tail_loop,
        end_label=end_label,
        op_type='madd',
        is_masked=is_masked,
        mask_bit_idx=mask_bit_idx if is_masked else '',
        v0_base=v0_base if is_masked else '',
        mask_tmp1=vl_reg,
        mask_tmp2=temp,
    )

    return lines


def _build_vfmacc_vv_lines(context) -> list[str]:
    """
    翻译 vfmacc.vv 指令 (256-bit 模式)

    格式: vfmacc.vv vd, vs1, vs2
    语义: vd[i] += vs1[i] * vs2[i]
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
    vs1 = operands[1]
    vs2 = operands[2]

    sew = state.sew
    chunk_n = _chunk_size(sew)
    c_bytes = _chunk_bytes()
    shift_amt = chunk_n.bit_length() - 1
    mask = chunk_n - 1

    vd_off = allocator.get_offset(vd)
    vs1_off = allocator.get_offset(vs1)
    vs2_off = allocator.get_offset(vs2)

    # 分配临时向量寄存器 (vv 变体需要 3 个 vreg: vs1, vs2, vd)
    vtemps = VRegTempAllocator(insn)
    vs1_vreg = vtemps.alloc_vreg()
    vs2_vreg = vtemps.alloc_vreg()
    vd_vreg = vtemps.alloc_vreg()

    # 分配 GPR 临时寄存器
    # vs1_ptr 必须独立分配。旧实现把它与 vl_reg 复用；当 e8 chunk 需要
    # register-form AVL 时，_emit_vsetvl_for_chunk 会再次写 vl_reg，从而把
    # 状态指针覆盖成 32。即使当前浮点白名单通常只到 e32/e64，也在这里
    # 保持统一的 live-range（活跃区间）约束，避免后续扩展重新引入该问题。
    temps = context.temp_register_allocator
    vl_reg = temps.alloc_gpr()
    chunk_count = temps.alloc_gpr()
    tail_count = temps.alloc_gpr()
    vs2_ptr = temps.alloc_gpr()
    vd_ptr = temps.alloc_gpr()
    temp = temps.alloc_gpr()
    vs1_ptr = temps.alloc_gpr()

    vle_instr = _get_vle_instr(sew)
    vse_instr = _get_vse_instr(sew)

    lines.append(f"# vfmacc.vv {vd}, {vs1}, {vs2} (256-bit mode)")
    lines.append(f"# Semantic: {vd}[i] += {vs1}[i] * {vs2}[i], SEW={sew}")
    lines.append("")

    # ========== 加载 vl 并计算块数/尾数 ==========
    _load_vl_from_csr(lines, vl_reg=vl_reg, addr_reg=chunk_count)
    lines.append(f"    srli    {chunk_count}, {vl_reg}, {shift_amt}       # {chunk_count} = vl / {chunk_n}")
    lines.append(f"    andi    {tail_count}, {vl_reg}, {mask}              # {tail_count} = vl % {chunk_n}")
    lines.append("")

    # ========== 设置基址指针 ==========
    _emit_state_ptr(lines, vs2_ptr, vs2_off)
    _emit_state_ptr(lines, vd_ptr, vd_off)
    _emit_state_ptr(lines, vs1_ptr, vs1_off)
    lines.append("")

    # ========== 主循环 (256-bit 块) ==========
    main_loop = new_label("vfmacc_vv_main")
    after_main = new_label("vfmacc_vv_after")

    lines.append(f"    # --- 主循环: 每块处理 {chunk_n} 个元素 ({c_bytes} 字节) ---")
    lines.append(f"    beqz    {chunk_count}, {after_main}")
    lines.append(f"{main_loop}:")
    _emit_vsetvl_for_chunk(lines, chunk_n, sew, "m1", vl_reg, scratch_reg=vl_reg)
    lines.append("")
    lines.append(f"    {vle_instr} {vs2_vreg}, ({vs2_ptr})         # 加载 {vs2} 块")
    lines.append(f"    {vle_instr} {vs1_vreg}, ({vs1_ptr})         # 加载 {vs1} 块")
    lines.append(f"    {vle_instr} {vd_vreg}, ({vd_ptr})          # 加载 {vd} 块")
    lines.append(f"    vfmacc.vv {vd_vreg}, {vs1_vreg}, {vs2_vreg}  # {vd_vreg} = {vs1_vreg}*{vs2_vreg} + {vd_vreg}")
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
    tail_loop = new_label("vfmacc_vv_tail")
    end_label = new_label("vfmacc_vv_end")
    for register in ("ft0", "ft1", "ft2"):
        record_fpr(register)
    _emit_scalar_tail_vv(
        lines=lines,
        sew=sew,
        tail_reg=tail_count,
        vs2_ptr=vs2_ptr,
        vs1_ptr=vs1_ptr,
        vd_ptr=vd_ptr,
        tail_label=tail_loop,
        end_label=end_label,
        op_type='madd',
    )

    return lines


def _build_vfmul_vf_lines(context) -> list[str]:
    """
    翻译 vfmul.vf 指令 (256-bit 模式)

    格式: vfmul.vf vd, vs2, rs1
    语义: vd[i] = vs2[i] * rs1
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

    # vfmul.vf 的标准 GNU 汇编格式: vfmul.vf vd, vs2, rs1
    vd = operands[0]
    vs2 = operands[1]
    rs1 = operands[2]

    sew = state.sew
    chunk_n = _chunk_size(sew)
    c_bytes = _chunk_bytes()
    shift_amt = chunk_n.bit_length() - 1
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

    if is_masked:
        mask_bit_idx = temps.alloc_gpr()
        v0_base = temps.alloc_gpr()

    vle_instr = _get_vle_instr(sew)
    vse_instr = _get_vse_instr(sew)

    lines.append(f"# vfmul.vf {vd}, {vs2}, {rs1} (256-bit mode)")
    lines.append(f"# Semantic: {vd}[i] = {vs2}[i] * {rs1}, SEW={sew}")
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

    # ========== 主循环 ==========
    main_loop = new_label("vfmul_vf_main")
    after_main = new_label("vfmul_vf_after")

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
    lines.append(f"    vfmul.vf {vd_vreg}, {vs2_vreg}, {rs1}{mask_suffix}        # {vd_vreg}{mask_suffix} = {vs2_vreg}{mask_suffix} * {rs1}")
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
    tail_loop = new_label("vfmul_vf_tail")
    end_label = new_label("vfmul_vf_end")
    _emit_scalar_tail_vf(
        lines=lines,
        sew=sew,
        tail_reg=tail_count,
        vs2_ptr=vs2_ptr,
        vd_ptr=vd_ptr,
        rs1=rs1,
        vs2_fpr=tail_vs2_fpr,
        vd_fpr=tail_vd_fpr,
        tail_label=tail_loop,
        end_label=end_label,
        op_type='mul',
        is_masked=is_masked,
        mask_bit_idx=mask_bit_idx if is_masked else '',
        v0_base=v0_base if is_masked else '',
        mask_tmp1=vl_reg,
        mask_tmp2=temp,
    )

    return lines
