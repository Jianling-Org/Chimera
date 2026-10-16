"""RVV256 浮点、整数与宽化归约实现。

归约的目的/初始寄存器组、累加精度和尾部处理与普通逐元素算术不同，
因此保留显式 builder，不与 same-width 数据驱动模板合并。
"""

from typing import List

from riscv.frontend.model import RVInstruction
from riscv.extensions.rvv.analysis.config import StateTracker
from riscv.extensions.rvv.runtime.layout import SimulatedStateLayout
from riscv.extensions.rvv.translation.contracts import InstructionValidationError
from riscv.extensions.rvv.runtime.layout import CSR_OFFSETS
from riscv.extensions.rvv.backends.rvv256.temp_regs import VRegTempAllocator
from riscv.extensions.rvv.translation.temps import TempRegisterAllocator
from riscv.extensions.rvv.backends.rvv256.support import (
    _chunk_size,
    _chunk_bytes,
    _emit_vsetvl_for_chunk,
    _load_vl_from_csr,
    _get_vle_instr,
)

from riscv.extensions.rvv.backends.rvv256.support import (
    _get_float_instr,
    _get_int_load_unsigned,
    _get_int_store,
)

def _build_vfredusum_vs_lines(context) -> list[str]:
    """
    翻译 vfredusum.vs 指令 (256-bit 模式)

    格式: vfredusum.vs vd, src_vec, seed_vec
    语义: vd[0] = Σ src_vec[i] + seed_vec[0] (i = 0 to vl-1)

    策略:
    - 加载 seed_vec[0] 作为初始累加器
    - 主循环: 对每个 src_vec 块执行 vfredusum.vs, 跨块传递累加值
    - 尾部: 标量 fadd 回退
    - 最终写回 vd[0]
    :return: 生成的汇编代码行列表
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
    src_vec = operands[1]
    seed_vec = operands[2]

    sew = state.sew
    chunk_n = _chunk_size(sew)
    c_bytes = _chunk_bytes()
    elem_bytes = sew // 8
    shift_amt = {8: 5, 16: 4, 32: 3, 64: 2}[sew]
    mask = chunk_n - 1

    vd_off = allocator.get_offset(vd)
    src_vec_off = allocator.get_offset(src_vec)
    seed_vec_off = allocator.get_offset(seed_vec)

    vtemps = VRegTempAllocator(insn)
    src_vec_vreg = vtemps.alloc_vreg()
    acc_vreg = vtemps.alloc_vreg()

    # 保留 ft0: 尾部回退循环硬编码 ft0 作为源加载目标, 不能与 acc_fpr 冲突
    temps = TempRegisterAllocator(insn, reserved_gprs=("t6",), extra_avoid_fprs=("ft0",))
    vl_reg = temps.alloc_gpr()
    chunk_count = temps.alloc_gpr()
    tail_count = temps.alloc_gpr()
    src_vec_ptr = temps.alloc_gpr()
    temp = temps.alloc_gpr()
    acc_fpr = temps.alloc_fpr()  # 标量累加器 (不会是 ft0)

    load_instr = _get_float_instr('load', sew)
    store_instr = _get_float_instr('store', sew)
    add_instr = _get_float_instr('add', sew)

    lines.append(f"# vfredusum.vs {vd}, {src_vec}, {seed_vec} (256-bit mode)")
    lines.append(f"# Semantic: {vd}[0] = Σ{src_vec}[i] + {seed_vec}[0], SEW={sew}")
    lines.append("")

    done_label = new_label("reduction_done")
    _load_vl_from_csr(lines, vl_reg=vl_reg, addr_reg=chunk_count)
    lines.append(f"    beqz    {vl_reg}, {done_label}")

    # ========== 1. 加载初始值 seed_vec[0] ==========
    lines.append(f"    # 加载初始值 {seed_vec}[0] -> {acc_fpr}")
    lines.append(f"    li      {temp}, {seed_vec_off:#x}")
    lines.append(f"    add     {temp}, t6, {temp}")
    lines.append(f"    {load_instr:<8} {acc_fpr}, 0({temp})            # {acc_fpr} = {seed_vec}[0]")
    lines.append("")

    # ========== 2. 加载 vl 并计算块数/尾数 ==========
    lines.append(f"    srli    {chunk_count}, {vl_reg}, {shift_amt}       # {chunk_count} = vl / {chunk_n}")
    lines.append(f"    andi    {tail_count}, {vl_reg}, {mask}              # {tail_count} = vl % {chunk_n}")
    lines.append("")

    # ========== 设置 src_vec 指针 ==========
    lines.append(f"    li      {temp}, {src_vec_off:#x}")
    lines.append(f"    add     {src_vec_ptr}, t6, {temp}            # {src_vec_ptr} = &{src_vec}")
    lines.append("")

    # ========== 3. 主循环: 256-bit 块级归约 ==========
    main_loop = new_label("vfredusum_main")
    after_main = new_label("vfredusum_after")

    lines.append(f"    # --- 主循环: 逐块归约 {src_vec} ---")
    lines.append(f"    beqz    {chunk_count}, {after_main}")
    lines.append(f"{main_loop}:")
    _emit_vsetvl_for_chunk(lines, chunk_n, sew, "m1", vl_reg, scratch_reg=vl_reg)
    lines.append("")
    lines.append(f"    vfmv.v.f {acc_vreg}, {acc_fpr}                  # 广播累加器 -> {acc_vreg}")
    lines.append(f"    vle{sew}.v {src_vec_vreg}, ({src_vec_ptr})               # 加载 {src_vec} 块")
    lines.append(f"    vfredusum.vs {acc_vreg}, {src_vec_vreg}, {acc_vreg}  # {acc_vreg}[0] += Σ{src_vec_vreg}[i]")
    lines.append(f"    vfmv.f.s {acc_fpr}, {acc_vreg}                   # 提取累加结果 -> {acc_fpr}")
    lines.append("")
    lines.append(f"    addi    {src_vec_ptr}, {src_vec_ptr}, {c_bytes}")
    lines.append(f"    addi    {chunk_count}, {chunk_count}, -1")
    lines.append(f"    bnez    {chunk_count}, {main_loop}")
    lines.append(f"{after_main}:")
    lines.append("")

    # ========== 4. 尾部标量回退 ==========
    lines.append(f"    # --- 尾部标量回退: 剩余 {tail_count} 个元素 ---")
    tail_loop = new_label("vfredusum_tail")
    tail_end = new_label("vfredusum_tail_end")

    lines.append(f"{tail_loop}:")
    lines.append(f"    beqz    {tail_count}, {tail_end}")
    lines.append(f"    {load_instr:<8} ft0, 0({src_vec_ptr})               # ft0 = {src_vec}[i]")
    lines.append(f"    {add_instr:<8} {acc_fpr}, {acc_fpr}, ft0           # {acc_fpr} += ft0")
    lines.append(f"    addi    {src_vec_ptr}, {src_vec_ptr}, {elem_bytes}")
    lines.append(f"    addi    {tail_count}, {tail_count}, -1")
    lines.append(f"    j       {tail_loop}")
    lines.append(f"{tail_end}:")
    lines.append("")

    # ========== 5. 写回结果 vd[0] ==========
    lines.append("")
    lines.append(f"    # 写回结果到 {vd}[0]")
    lines.append(f"    li      {temp}, {vd_off:#x}")
    lines.append(f"    add     {temp}, t6, {temp}")
    lines.append(f"    {store_instr:<8} {acc_fpr}, 0({temp})            # {vd}[0] = {acc_fpr}")

    lines.append(f"{done_label}:")
    return lines



def _emit_vfred_minmax_vs(
    insn: RVInstruction,
    state: StateTracker,
    allocator: SimulatedStateLayout,
    new_label,
    op: str,
) -> List[str]:
    """Emit vfredmax.vs/vfredmin.vs using chunked RVV reductions."""
    lines = []
    operands = insn.operands
    if len(operands) < 3:
        raise InstructionValidationError(insn, f"Invalid operands for {insn.opcode}: {insn.op_str}")

    vd = operands[0]
    src_vec = operands[1]
    scalar_vec = operands[2]

    sew = state.sew
    if sew not in (32, 64):
        raise InstructionValidationError(insn, f"{insn.opcode} supports floating SEW=32/64 only, got SEW={sew}")

    opcode = f"vfred{op}.vs"
    chunk_n = _chunk_size(sew)
    c_bytes = _chunk_bytes()
    shift_amt = {32: 3, 64: 2}[sew]
    mask = chunk_n - 1

    vd_off = allocator.get_offset(vd)
    src_off = allocator.get_offset(src_vec)
    scalar_off = allocator.get_offset(scalar_vec)

    vtemps = VRegTempAllocator(insn)
    src_vreg = vtemps.alloc_vreg()
    acc_vreg = vtemps.alloc_vreg()

    temps = TempRegisterAllocator(insn, reserved_gprs=("t6",))
    vl_reg = temps.alloc_gpr()
    chunk_count = temps.alloc_gpr()
    tail_count = temps.alloc_gpr()
    src_ptr = temps.alloc_gpr()
    temp = temps.alloc_gpr()
    acc_fpr = temps.alloc_fpr()

    load_instr = _get_float_instr('load', sew)
    store_instr = _get_float_instr('store', sew)
    vle_instr = _get_vle_instr(sew)

    symbol = "max" if op == "max" else "min"
    lines.append(f"# {opcode} {vd}, {src_vec}, {scalar_vec} (256-bit mode)")
    lines.append(f"# Semantic: {vd}[0] = fred{symbol}({src_vec}[0:vl], {scalar_vec}[0]), SEW={sew}")
    lines.append("")

    done_label = new_label("reduction_done")
    _load_vl_from_csr(lines, vl_reg=vl_reg, addr_reg=chunk_count)
    lines.append(f"    beqz    {vl_reg}, {done_label}")

    lines.append(f"    # 加载初始值 {scalar_vec}[0] -> {acc_fpr}")
    lines.append(f"    li      {temp}, {scalar_off:#x}")
    lines.append(f"    add     {temp}, t6, {temp}")
    lines.append(f"    {load_instr:<8} {acc_fpr}, 0({temp})            # {acc_fpr} = {scalar_vec}[0]")
    lines.append("")

    lines.append(f"    srli    {chunk_count}, {vl_reg}, {shift_amt}       # {chunk_count} = vl / {chunk_n}")
    lines.append(f"    andi    {tail_count}, {vl_reg}, {mask}              # {tail_count} = vl % {chunk_n}")
    lines.append("")

    lines.append(f"    li      {temp}, {src_off:#x}")
    lines.append(f"    add     {src_ptr}, t6, {temp}            # {src_ptr} = &{src_vec}")
    lines.append("")

    main_loop = new_label(f"vfred{op}_main")
    after_main = new_label(f"vfred{op}_after")

    lines.append(f"    # --- 主循环: 逐块归约 {src_vec} ---")
    lines.append(f"    beqz    {chunk_count}, {after_main}")
    lines.append(f"{main_loop}:")
    _emit_vsetvl_for_chunk(lines, chunk_n, sew, "m1", vl_reg, scratch_reg=temp)
    lines.append(f"    vle{sew}.v {src_vreg}, ({src_ptr})               # 加载 {src_vec} 块")
    lines.append(f"    vsetivli zero, 1, e{sew}, m1, ta, ma")
    lines.append(f"    vfmv.s.f {acc_vreg}, {acc_fpr}                   # accumulator -> {acc_vreg}[0]")
    _emit_vsetvl_for_chunk(lines, chunk_n, sew, "m1", vl_reg, scratch_reg=temp)
    lines.append(f"    {opcode} {acc_vreg}, {src_vreg}, {acc_vreg}  # {acc_vreg}[0] = fred{symbol}(chunk, acc)")
    lines.append(f"    vfmv.f.s {acc_fpr}, {acc_vreg}                   # 提取归约结果 -> {acc_fpr}")
    lines.append(f"    addi    {src_ptr}, {src_ptr}, {c_bytes}")
    lines.append(f"    addi    {chunk_count}, {chunk_count}, -1")
    lines.append(f"    bnez    {chunk_count}, {main_loop}")
    lines.append(f"{after_main}:")
    lines.append("")

    lines.append(f"    # --- 尾部 RVV reduction chunk: 剩余 {tail_count} 个元素 ---")
    tail_end = new_label(f"vfred{op}_tail_end")
    lines.append(f"    beqz    {tail_count}, {tail_end}")
    lines.append(f"    vsetvli zero, {tail_count}, e{sew}, m1, ta, ma")
    lines.append(f"    {vle_instr} {src_vreg}, ({src_ptr})               # 加载 {src_vec} tail")
    lines.append(f"    vsetivli zero, 1, e{sew}, m1, ta, ma")
    lines.append(f"    vfmv.s.f {acc_vreg}, {acc_fpr}                   # accumulator -> {acc_vreg}[0]")
    lines.append(f"    vsetvli zero, {tail_count}, e{sew}, m1, ta, ma")
    lines.append(f"    {opcode} {acc_vreg}, {src_vreg}, {acc_vreg}  # tail: fred{symbol}(tail, acc)")
    lines.append(f"    vfmv.f.s {acc_fpr}, {acc_vreg}                   # 提取 tail 归约结果")
    lines.append(f"{tail_end}:")
    lines.append("")

    lines.append(f"    # 写回结果到 {vd}[0]")
    lines.append(f"    li      {temp}, {vd_off:#x}")
    lines.append(f"    add     {temp}, t6, {temp}")
    lines.append(f"    {store_instr:<8} {acc_fpr}, 0({temp})            # {vd}[0] = {acc_fpr}")

    lines.append(f"{done_label}:")
    return lines



def _build_vfredmax_vs_lines(context) -> list[str]:
    """翻译 vfredmax.vs 指令 (256-bit 模式)。"""
    insn = context.instruction
    state = context.state
    allocator = context.layout
    new_label = context.new_label
    return _emit_vfred_minmax_vs(insn, state, allocator, new_label, "max")



def _build_vfredmin_vs_lines(context) -> list[str]:
    """翻译 vfredmin.vs 指令 (256-bit 模式)。"""
    insn = context.instruction
    state = context.state
    allocator = context.layout
    new_label = context.new_label
    return _emit_vfred_minmax_vs(insn, state, allocator, new_label, "min")



def _emit_vred_int_vs(
    insn: RVInstruction,
    state: StateTracker,
    allocator: SimulatedStateLayout,
    new_label,
    op: str,
) -> List[str]:
    """Emit single-width integer vredsum.vs/vredor.vs/vredmaxu.vs using chunked RVV reductions."""
    lines = []
    operands = insn.operands
    if len(operands) < 3:
        raise InstructionValidationError(insn, f"Invalid operands for {insn.opcode}: {insn.op_str}")

    vd = operands[0]
    src_vec = operands[1]
    scalar_vec = operands[2]

    sew = state.sew
    if sew not in (8, 16, 32, 64):
        raise InstructionValidationError(insn, f"{insn.opcode} supports integer SEW=8/16/32/64 only, got SEW={sew}")

    opcode = f"vred{op}.vs"
    chunk_n = _chunk_size(sew)
    c_bytes = _chunk_bytes()
    shift_amt = {8: 5, 16: 4, 32: 3, 64: 2}[sew]
    mask = chunk_n - 1

    vd_off = allocator.get_offset(vd)
    src_off = allocator.get_offset(src_vec)
    scalar_off = allocator.get_offset(scalar_vec)

    vtemps = VRegTempAllocator(insn)
    src_vreg = vtemps.alloc_vreg()
    acc_vreg = vtemps.alloc_vreg()

    temps = TempRegisterAllocator(insn, reserved_gprs=("t6",))
    vl_reg = temps.alloc_gpr()
    chunk_count = temps.alloc_gpr()
    tail_count = temps.alloc_gpr()
    src_ptr = temps.alloc_gpr()
    temp = temps.alloc_gpr()
    acc_gpr = temps.alloc_gpr()

    load_instr = _get_int_load_unsigned(sew)
    store_instr = _get_int_store(sew)
    vle_instr = _get_vle_instr(sew)

    symbol_map = {
        "sum": "sum",
        "or": "or",
        "maxu": "max_unsigned",
    }
    symbol = symbol_map.get(op, op)
    lines.append(f"# {opcode} {vd}, {src_vec}, {scalar_vec} (256-bit mode)")
    lines.append(f"# Semantic: {vd}[0] = red{symbol}({src_vec}[0:vl], {scalar_vec}[0]), SEW={sew}")
    lines.append("")

    lines.append(f"    # 加载初始值 {scalar_vec}[0] -> {acc_gpr}")
    lines.append(f"    li      {temp}, {scalar_off:#x}")
    lines.append(f"    add     {temp}, t6, {temp}")
    lines.append(f"    {load_instr:<8} {acc_gpr}, 0({temp})            # {acc_gpr} = low e{sew} {scalar_vec}[0]")
    lines.append("")

    _load_vl_from_csr(lines, vl_reg=vl_reg, addr_reg=chunk_count)
    lines.append(f"    srli    {chunk_count}, {vl_reg}, {shift_amt}       # {chunk_count} = vl / {chunk_n}")
    lines.append(f"    andi    {tail_count}, {vl_reg}, {mask}              # {tail_count} = vl % {chunk_n}")
    lines.append("")

    lines.append(f"    li      {temp}, {src_off:#x}")
    lines.append(f"    add     {src_ptr}, t6, {temp}            # {src_ptr} = &{src_vec}")
    lines.append("")

    main_loop = new_label(f"vred{op}_main")
    after_main = new_label(f"vred{op}_after")

    lines.append(f"    # --- 主循环: 逐块归约 {src_vec} ---")
    lines.append(f"    beqz    {chunk_count}, {after_main}")
    lines.append(f"{main_loop}:")
    _emit_vsetvl_for_chunk(lines, chunk_n, sew, "m1", vl_reg, scratch_reg=temp)
    lines.append(f"    {vle_instr} {src_vreg}, ({src_ptr})               # 加载 {src_vec} 块")
    lines.append(f"    vsetivli zero, 1, e{sew}, m1, ta, ma")
    lines.append(f"    vmv.s.x {acc_vreg}, {acc_gpr}                    # accumulator -> {acc_vreg}[0]")
    _emit_vsetvl_for_chunk(lines, chunk_n, sew, "m1", vl_reg, scratch_reg=temp)
    lines.append(f"    {opcode} {acc_vreg}, {src_vreg}, {acc_vreg}  # {acc_vreg}[0] = red{symbol}(chunk, acc)")
    lines.append(f"    vmv.x.s {acc_gpr}, {acc_vreg}                    # 提取归约结果 -> {acc_gpr}")
    lines.append(f"    addi    {src_ptr}, {src_ptr}, {c_bytes}")
    lines.append(f"    addi    {chunk_count}, {chunk_count}, -1")
    lines.append(f"    bnez    {chunk_count}, {main_loop}")
    lines.append(f"{after_main}:")
    lines.append("")

    lines.append(f"    # --- 尾部 RVV integer reduction chunk: 剩余 {tail_count} 个元素 ---")
    tail_end = new_label(f"vred{op}_tail_end")
    lines.append(f"    beqz    {tail_count}, {tail_end}")
    lines.append(f"    vsetvli zero, {tail_count}, e{sew}, m1, ta, ma")
    lines.append(f"    {vle_instr} {src_vreg}, ({src_ptr})               # 加载 {src_vec} tail")
    lines.append(f"    vsetivli zero, 1, e{sew}, m1, ta, ma")
    lines.append(f"    vmv.s.x {acc_vreg}, {acc_gpr}                    # accumulator -> {acc_vreg}[0]")
    lines.append(f"    vsetvli zero, {tail_count}, e{sew}, m1, ta, ma")
    lines.append(f"    {opcode} {acc_vreg}, {src_vreg}, {acc_vreg}  # tail: red{symbol}(tail, acc)")
    lines.append(f"    vmv.x.s {acc_gpr}, {acc_vreg}                    # 提取 tail 归约结果")
    lines.append(f"{tail_end}:")
    lines.append("")

    lines.append(f"    # 写回结果到 {vd}[0]")
    lines.append(f"    li      {temp}, {vd_off:#x}")
    lines.append(f"    add     {temp}, t6, {temp}")
    lines.append(f"    {store_instr:<8} {acc_gpr}, 0({temp})            # {vd}[0] = low e{sew} {acc_gpr}")

    return lines



def _build_vredsum_vs_lines(context) -> list[str]:
    """翻译 vredsum.vs 指令 (256-bit 模式)。"""
    insn = context.instruction
    state = context.state
    allocator = context.layout
    new_label = context.new_label
    return _emit_vred_int_vs(insn, state, allocator, new_label, "sum")



def _build_vredor_vs_lines(context) -> list[str]:
    """翻译 vredor.vs 指令 (256-bit 模式)。"""
    insn = context.instruction
    state = context.state
    allocator = context.layout
    new_label = context.new_label
    return _emit_vred_int_vs(insn, state, allocator, new_label, "or")



def _build_vredmaxu_vs_lines(context) -> list[str]:
    """翻译 vredmaxu.vs 指令 (256-bit 模式)。"""
    insn = context.instruction
    state = context.state
    allocator = context.layout
    new_label = context.new_label
    return _emit_vred_int_vs(insn, state, allocator, new_label, "maxu")



def _emit_vfwred_sum_vs(
    insn: RVInstruction,
    state: StateTracker,
    allocator: SimulatedStateLayout,
    new_label,
    op: str,
) -> List[str]:
    """Emit vfwred[o/u]sum.vs for e16/e32 inputs and e32/e64 accumulator/results."""
    input_sew = state.sew
    if input_sew in (16, 32):
        return _emit_vfwred_sum_vs_for_sew(insn, state, allocator, new_label, op, input_sew)
    return _emit_vfwred_sum_vs_dynamic_vtype(insn, state, allocator, new_label, op)



def _emit_vfwred_sum_vs_dynamic_vtype(
    insn: RVInstruction,
    state: StateTracker,
    allocator: SimulatedStateLayout,
    new_label,
    op: str,
) -> List[str]:
    """Emit runtime vtype dispatch for vfwred[o/u]sum.vs when static CFG state is ambiguous."""
    operands = list(insn.operands)
    if len(operands) > 0 and str(operands[-1]).strip().endswith(".t"):
        operands = operands[:-1]
    if len(operands) < 3:
        raise InstructionValidationError(insn, f"Invalid operands for {insn.opcode}: {insn.op_str}")

    temps = TempRegisterAllocator(insn, reserved_gprs=("t6",))
    addr_reg = temps.alloc_gpr()
    vsew_reg = temps.alloc_gpr()
    cmp_reg = temps.alloc_gpr()

    e16_label = new_label(f"vfwred{op}_dyn_e16")
    e32_label = new_label(f"vfwred{op}_dyn_e32")
    bad_label = new_label(f"vfwred{op}_dyn_bad")
    done_label = new_label(f"vfwred{op}_dyn_done")
    vtype_offset = CSR_OFFSETS["vtype"]

    lines = [
        f"# {insn.opcode} {', '.join(str(opnd) for opnd in operands)} (256-bit mode, runtime vtype dispatch)",
        "# Static vtype is ambiguous at this CFG point; dispatch on simulated CSR.vtype.",
        f"    li      {addr_reg}, {vtype_offset:#x}",
        f"    add     {addr_reg}, t6, {addr_reg}",
        f"    ld      {vsew_reg}, 0({addr_reg})            # runtime CSR.vtype",
        f"    srli    {vsew_reg}, {vsew_reg}, 3",
        f"    andi    {vsew_reg}, {vsew_reg}, 7            # vsew encoding",
        f"    li      {cmp_reg}, 1",
        f"    beq     {vsew_reg}, {cmp_reg}, {e16_label}   # e16 -> e32",
        f"    li      {cmp_reg}, 2",
        f"    beq     {vsew_reg}, {cmp_reg}, {e32_label}   # e32 -> e64",
        f"    j       {bad_label}",
        "",
        f"{e16_label}:",
    ]
    lines.extend(_emit_vfwred_sum_vs_for_sew(insn, state, allocator, new_label, op, 16))
    lines.extend([
        f"    j       {done_label}",
        "",
        f"{e32_label}:",
    ])
    lines.extend(_emit_vfwred_sum_vs_for_sew(insn, state, allocator, new_label, op, 32))
    lines.extend([
        f"    j       {done_label}",
        "",
        f"{bad_label}:",
        f"# Runtime unsupported vtype for {insn.opcode}: only SEW=16/32 is implemented",
        "    ebreak",
        f"{done_label}:",
    ])
    return lines



def _emit_vfwred_sum_vs_for_sew(
    insn: RVInstruction,
    state: StateTracker,
    allocator: SimulatedStateLayout,
    new_label,
    op: str,
    input_sew: int,
) -> List[str]:
    """Emit vfwred[o/u]sum.vs for a known e16/e32 input SEW."""
    lines = []
    operands = list(insn.operands)
    if len(operands) > 0 and str(operands[-1]).strip().endswith(".t"):
        operands = operands[:-1]
    if len(operands) < 3:
        raise InstructionValidationError(insn, f"Invalid operands for {insn.opcode}: {insn.op_str}")

    vd = operands[0]
    src_vec = operands[1]
    scalar_vec = operands[2]

    output_sew = input_sew * 2
    if input_sew not in (16, 32):
        raise InstructionValidationError(
            insn,
            f"{insn.opcode} currently supports SEW=16/32 only "
            f"(got SEW={input_sew})",
        )

    opcode = f"vfwred{op}.vs"
    kind = "ordered" if op == "osum" else "unordered"
    chunk_n = _chunk_size(input_sew)
    c_bytes = _chunk_bytes()
    shift_amt = {16: 4, 32: 3}[input_sew]
    mask = chunk_n - 1

    vd_off = allocator.get_offset(vd)
    src_off = allocator.get_offset(src_vec)
    scalar_off = allocator.get_offset(scalar_vec)

    vtemps = VRegTempAllocator(insn)
    src_vreg = vtemps.alloc_vreg()
    acc_vreg = vtemps.alloc_vreg()

    temps = TempRegisterAllocator(insn, reserved_gprs=("t6",))
    vl_reg = temps.alloc_gpr()
    chunk_count = temps.alloc_gpr()
    tail_count = temps.alloc_gpr()
    src_ptr = temps.alloc_gpr()
    temp = temps.alloc_gpr()
    acc_fpr = temps.alloc_fpr()

    src_vle_instr = _get_vle_instr(input_sew)
    acc_load_instr = _get_float_instr('load', output_sew)
    acc_store_instr = _get_float_instr('store', output_sew)

    lines.append(f"# {opcode} {vd}, {src_vec}, {scalar_vec} (256-bit mode, {kind})")
    lines.append(
        f"# Semantic: {vd}[0] = widen-reduce-{kind}-sum({src_vec}[0:vl], "
        f"{scalar_vec}[0]), e{input_sew}->e{output_sew}"
    )
    lines.append("")

    done_label = new_label("reduction_done")
    _load_vl_from_csr(lines, vl_reg=vl_reg, addr_reg=chunk_count)
    lines.append(f"    beqz    {vl_reg}, {done_label}")

    lines.append(f"    # 加载 e{output_sew} 初始累加器 {scalar_vec}[0] -> {acc_fpr}")
    lines.append(f"    li      {temp}, {scalar_off:#x}")
    lines.append(f"    add     {temp}, t6, {temp}")
    lines.append(f"    {acc_load_instr:<8} {acc_fpr}, 0({temp})            # {acc_fpr} = {scalar_vec}[0] (e{output_sew})")
    lines.append("")

    lines.append(f"    srli    {chunk_count}, {vl_reg}, {shift_amt}       # {chunk_count} = vl / {chunk_n}")
    lines.append(f"    andi    {tail_count}, {vl_reg}, {mask}              # {tail_count} = vl % {chunk_n}")
    lines.append("")

    lines.append(f"    li      {temp}, {src_off:#x}")
    lines.append(f"    add     {src_ptr}, t6, {temp}            # {src_ptr} = &{src_vec}")
    lines.append("")

    main_loop = new_label(f"vfwred{op}_main")
    after_main = new_label(f"vfwred{op}_after")

    lines.append(f"    # --- 主循环: 逐块 widening 归约 {src_vec} ---")
    lines.append(f"    beqz    {chunk_count}, {after_main}")
    lines.append(f"{main_loop}:")
    _emit_vsetvl_for_chunk(lines, chunk_n, input_sew, "m1", vl_reg, scratch_reg=temp)
    lines.append(f"    {src_vle_instr} {src_vreg}, ({src_ptr})               # 加载 {src_vec} 块 (e{input_sew})")
    lines.append(f"    vsetivli zero, 1, e{output_sew}, m1, ta, ma")
    lines.append(f"    vfmv.s.f {acc_vreg}, {acc_fpr}                   # e{output_sew} accumulator -> {acc_vreg}[0]")
    _emit_vsetvl_for_chunk(lines, chunk_n, input_sew, "m1", vl_reg, scratch_reg=temp)
    lines.append(f"    {opcode} {acc_vreg}, {src_vreg}, {acc_vreg}  # {acc_vreg}[0] = widening {kind} sum(chunk, acc)")
    lines.append(f"    vsetivli zero, 1, e{output_sew}, m1, ta, ma")
    lines.append(f"    vfmv.f.s {acc_fpr}, {acc_vreg}                   # 提取 e{output_sew} 累加结果 -> {acc_fpr}")
    lines.append(f"    addi    {src_ptr}, {src_ptr}, {c_bytes}")
    lines.append(f"    addi    {chunk_count}, {chunk_count}, -1")
    lines.append(f"    bnez    {chunk_count}, {main_loop}")
    lines.append(f"{after_main}:")
    lines.append("")

    lines.append(f"    # --- 尾部 RVV widening reduction chunk: 剩余 {tail_count} 个元素 ---")
    tail_end = new_label(f"vfwred{op}_tail_end")
    lines.append(f"    beqz    {tail_count}, {tail_end}")
    lines.append(f"    vsetvli zero, {tail_count}, e{input_sew}, m1, ta, ma")
    lines.append(f"    {src_vle_instr} {src_vreg}, ({src_ptr})               # 加载 {src_vec} tail (e{input_sew})")
    lines.append(f"    vsetivli zero, 1, e{output_sew}, m1, ta, ma")
    lines.append(f"    vfmv.s.f {acc_vreg}, {acc_fpr}                   # e{output_sew} accumulator -> {acc_vreg}[0]")
    lines.append(f"    vsetvli zero, {tail_count}, e{input_sew}, m1, ta, ma")
    lines.append(f"    {opcode} {acc_vreg}, {src_vreg}, {acc_vreg}  # tail: widening {kind} sum(tail, acc)")
    lines.append(f"    vsetivli zero, 1, e{output_sew}, m1, ta, ma")
    lines.append(f"    vfmv.f.s {acc_fpr}, {acc_vreg}                   # 提取 tail e{output_sew} 累加结果")
    lines.append(f"{tail_end}:")
    lines.append("")

    lines.append(f"    # 写回 e{output_sew} 结果到 {vd}[0]")
    lines.append(f"    li      {temp}, {vd_off:#x}")
    lines.append(f"    add     {temp}, t6, {temp}")
    lines.append(f"    {acc_store_instr:<8} {acc_fpr}, 0({temp})            # {vd}[0] = {acc_fpr} (e{output_sew})")

    lines.append(f"{done_label}:")
    return lines



def _build_vfwredosum_vs_lines(context) -> list[str]:
    """翻译 vfwredosum.vs 指令 (256-bit 模式)。"""
    insn = context.instruction
    state = context.state
    allocator = context.layout
    new_label = context.new_label
    return _emit_vfwred_sum_vs(insn, state, allocator, new_label, "osum")



def _build_vfwredusum_vs_lines(context) -> list[str]:
    """翻译 vfwredusum.vs 指令 (256-bit 模式)。"""
    insn = context.instruction
    state = context.state
    allocator = context.layout
    new_label = context.new_label
    return _emit_vfwred_sum_vs(insn, state, allocator, new_label, "usum")
