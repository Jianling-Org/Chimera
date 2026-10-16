# src/riscv/extensions/rvv/backends/scalar/handlers/arithmetic.py
"""
RVV 算术指令翻译模块

将 RVV 向量算术指令翻译为标量 RISC-V 汇编代码

翻译策略:
- 使用 CSR 中存储的 vl 进行循环控制 (动态读取)
- 通过 `TempRegisterAllocator` 为高风险 handler 动态选择临时寄存器
- 内存操作通过 allocator 获取偏移量
- 配合 emitter 的块级 save/restore，避免污染原程序上下文
"""

from typing import List
from riscv.extensions.rvv.translation.contracts import InstructionValidationError
from riscv.extensions.rvv.runtime.layout import CSR_OFFSETS

from riscv.extensions.rvv.backends.scalar.support import (
    _emit_element_shift,
    _parse_vector_register_number,
    _maybe_emit_mask_skip_guard,
    _validate_vector_groups,
)


# ============================================================================
# 辅助函数
# ============================================================================

# 支持的 SEW 值 (仅浮点操作)
SUPPORTED_FLOAT_SEW = {32, 64}


def _validate_sew(sew: int) -> None:
    """验证 SEW 值是否有效"""
    if sew not in SUPPORTED_FLOAT_SEW:
        raise ValueError(
            f"浮点操作不支持 SEW={sew} (支持: {SUPPORTED_FLOAT_SEW})"
        )


def _get_float_instr(suffix: str, sew: int) -> str:
    """
    根据 SEW 返回正确的浮点指令

    :param suffix: 指令后缀 (load/store/madd)
    :param sew: Standard Element Width (32 or 64)
    :return: 指令助记符
    :raises ValueError: 不支持的 SEW
    """
    _validate_sew(sew)

    if sew == 32:
        instr_map = {
            'load': 'flw',
            'store': 'fsw',
            'madd': 'fmadd.s',
            'nmsub': 'fnmsub.s',
            'add': 'fadd.s',
            'mul': 'fmul.s',
            'sub': 'fsub.s',
            'div': 'fdiv.s',
            'sqrt': 'fsqrt.s',
        }
    else:  # sew == 64
        instr_map = {
            'load': 'fld',
            'store': 'fsd',
            'madd': 'fmadd.d',
            'nmsub': 'fnmsub.d',
            'add': 'fadd.d',
            'mul': 'fmul.d',
            'sub': 'fsub.d',
            'div': 'fdiv.d',
            'sqrt': 'fsqrt.d',
        }
    return instr_map[suffix]




def _emit_load_vl_from_csr(
    lines: List[str],
    vl_reg: str,
    addr_reg: str,
) -> None:
    """从 CSR 加载 ``vl``；调用方必须显式传入已分配寄存器。"""
    vl_offset = CSR_OFFSETS['vl']
    lines.append(f"    li      {addr_reg}, {vl_offset}")
    lines.append(f"    add     {addr_reg}, t6, {addr_reg}")
    lines.append(f"    ld      {vl_reg}, 0({addr_reg})  # {vl_reg} = vl (from CSR)")






# ============================================================================
# 整数操作辅助函数
# ============================================================================

# 支持的 SEW 值 (整数操作)
SUPPORTED_INT_SEW = {8, 16, 32, 64}


def _get_int_instr(sew: int, kind: str) -> str:
    """
    根据 SEW 返回整数指令

    :param sew: 元素宽度 (8/16/32/64)
    :param kind: 'load', 'store', 'add', 'sub', 'mul'
    :return: 指令助记符
    """
    SUPPORTED_INT_SEW = {8, 16, 32, 64}
    if sew not in SUPPORTED_INT_SEW:
        raise ValueError(f"不支持的 SEW 值: {sew}")

    if kind == 'load':
        return {8: 'lb', 16: 'lh', 32: 'lw', 64: 'ld'}[sew]
    elif kind == 'store':
        return {8: 'sb', 16: 'sh', 32: 'sw', 64: 'sd'}[sew]
    elif kind == 'add':
        # 对于 32 位操作，使用 addw (32位加法，结果符号扩展到 64 位)
        return {8: 'add', 16: 'add', 32: 'addw', 64: 'add'}[sew]
    else:
        raise ValueError(f"不支持的指令类型: {kind}")


# ============================================================================
# vfmacc.vf 指令翻译
# ============================================================================

def _build_vfmacc_vf_lines(context) -> list[str]:
    """
    翻译 vfmacc.vf 指令 (向量-浮点乘加)

    格式: vfmacc.vf vd, rs1, vs2, vm
    语义: vd[i] = +(rs1 * vs2[i]) + vd[i]

    翻译为标量循环:
        for i in range(vl):  # vl 从 CSR 动态读取
            ft0 = load(vs2[i])
            ft1 = load(vd[i])
            ft1 = fmadd.d(ft0, rs1, ft1)
            store(vd[i], ft1)
    :return: 生成的汇编代码行列表
    """
    insn = context.instruction
    state = context.state
    allocator = context.layout
    new_label = context.new_label
    lines = []

    # 解析操作数: vd, rs1, vs2
    operands = insn.operands
    if len(operands) < 3:
        raise InstructionValidationError(insn, f"Invalid operands for {insn.opcode}: {insn.op_str}")

    vd = operands[0]   # 目标向量寄存器 (如 v8)
    rs1 = operands[1]  # 标量浮点寄存器 (如 fa0)
    vs2 = operands[2]  # 源向量寄存器 (如 v16)

    # 使用 TempRegisterAllocator 动态分配所有临时寄存器，
    # 避免与指令操作数中的标量寄存器冲突。
    temps = context.temp_register_allocator
    vl_reg = temps.alloc_gpr()
    csr_addr_reg = temps.alloc_gpr()
    element_offset_reg = temps.alloc_gpr()
    addr_reg = temps.alloc_gpr()
    source_value_fpr = temps.alloc_fpr()
    accum_value_fpr = temps.alloc_fpr()

    # 获取内存偏移量
    vd_offset = allocator.get_offset(vd)
    vs2_offset = allocator.get_offset(vs2)

    # 获取元素大小
    element_size = state.sew // 8

    # 获取浮点指令 (根据 SEW)
    load_instr = _get_float_instr('load', state.sew)
    store_instr = _get_float_instr('store', state.sew)
    madd_instr = _get_float_instr('madd', state.sew)

    # 生成注释头
    lines.append(f"# vfmacc.vf {vd}, {rs1}, {vs2}")
    lines.append(f"# Semantic: {vd}[i] += {rs1} * {vs2}[i]")
    lines.append(f"# SEW = {state.sew}-bit, vl 从 CSR 动态读取")
    lines.append("")

    # ========== 从 CSR 加载 vl ==========
    _emit_load_vl_from_csr(lines, vl_reg=vl_reg, addr_reg=csr_addr_reg)
    lines.append("")

    # ========== 循环体 ==========
    loop_label = new_label("vfmacc")
    lines.append(f"{loop_label}:                         # 循环入口")
    lines.append(f"    beqz    {vl_reg}, {loop_label}_end    # 如果 vl == 0，退出循环")
    lines.append("")

    # 计算当前元素偏移: (vl_reg - 1) * element_size
    lines.append("    # 计算元素索引和偏移")
    lines.append(f"    addi    {element_offset_reg}, {vl_reg}, -1          # {element_offset_reg} = i = vl - 1")
    skip_label = _maybe_emit_mask_skip_guard(
        lines=lines,
        insn=insn,
        new_label=new_label,
        element_index_reg=element_offset_reg,
        mask_chunk_reg=addr_reg,
        shift_reg=csr_addr_reg,
        label_prefix="vfmacc_vf_mask_skip",
    )
    _emit_element_shift(lines, element_size, shift_reg=element_offset_reg)

    # 加载 vs2[i] 到临时浮点寄存器
    lines.append("")
    lines.append(f"    # 加载 {vs2}[i] 到 {source_value_fpr}")
    lines.append(f"    li      {csr_addr_reg}, {vs2_offset}")
    lines.append(f"    add     {addr_reg}, t6, {csr_addr_reg}")
    lines.append(f"    add     {addr_reg}, {addr_reg}, {element_offset_reg}")
    lines.append(f"    {load_instr:<7} {source_value_fpr}, 0({addr_reg})")

    # 加载 vd[i] 到累加寄存器
    lines.append("")
    lines.append(f"    # 加载 {vd}[i] 到 {accum_value_fpr}")
    lines.append(f"    li      {csr_addr_reg}, {vd_offset}")
    lines.append(f"    add     {addr_reg}, t6, {csr_addr_reg}")
    lines.append(f"    add     {addr_reg}, {addr_reg}, {element_offset_reg}")
    lines.append(f"    {load_instr:<7} {accum_value_fpr}, 0({addr_reg})")

    # 执行 fmadd：目标寄存器继续复用累加值寄存器。
    lines.append("")
    lines.append(f"    # {madd_instr}: {accum_value_fpr} = {source_value_fpr} * {rs1} + {accum_value_fpr}")
    lines.append(
        f"    {madd_instr:<7} {accum_value_fpr}, {source_value_fpr}, {rs1}, {accum_value_fpr}"
        f"  # {accum_value_fpr} = {source_value_fpr} * {rs1} + {accum_value_fpr}"
    )

    # 存储结果回 vd[i]
    lines.append("")
    lines.append(f"    # 存储 {vd}[i]")
    lines.append(f"    li      {csr_addr_reg}, {vd_offset}")
    lines.append(f"    add     {addr_reg}, t6, {csr_addr_reg}")
    lines.append(f"    add     {addr_reg}, {addr_reg}, {element_offset_reg}")
    lines.append(f"    {store_instr:<7} {accum_value_fpr}, 0({addr_reg})")

    # 更新循环计数器
    lines.append("")
    lines.append("    # 更新循环计数器")
    if skip_label is not None:
        lines.append(f"{skip_label}:")
    lines.append(f"    addi    {vl_reg}, {vl_reg}, -1          # {vl_reg}--")
    lines.append(f"    j       {loop_label}        # 继续循环")
    lines.append("")

    # ========== 循环结束 ==========
    lines.append(f"{loop_label}_end:")

    return lines


def _build_vfnmsac_vf_lines(context) -> list[str]:
    """
    翻译 `vfnmsac.vf` 指令 (向量-标量浮点 negative multiply-subtract-accumulate)。

    格式: `vfnmsac.vf vd, rs1, vs2, vm`
    语义: `vd[i] = -(rs1 * vs2[i]) + vd[i]`

    这里参考 QEMU `fnmsac32/fnmsac64` 的语义：
    - 负号只作用在乘积上；
    - 再与原先的 `vd[i]` 做加法；
    - 因此与标量 FPU 的 `fnmsub.s/d` 精确对应。
    :return: 生成的标量汇编代码
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

    # `vfnmsac.vf` 与 `vfmacc.vf` 一样，风险点在于 `rs1` 可能本身就是 `ft*`。
    # 因此这里统一动态分配 GPR/FPR temp：对当前常见
    # form 仍稳定选中 t0-t4，但寄存器破坏集会由分配器直接
    # 写入 LoweringResult，不再需要 emitter 反解析汇编文本。
    temps = context.temp_register_allocator
    vl_reg = temps.alloc_gpr()
    csr_addr_reg = temps.alloc_gpr()
    element_offset_reg = temps.alloc_gpr()
    addr_reg = temps.alloc_gpr()
    mask_shift_reg = temps.alloc_gpr()
    source_value_fpr = temps.alloc_fpr()
    accum_value_fpr = temps.alloc_fpr()

    vd_offset = allocator.get_offset(vd)
    vs2_offset = allocator.get_offset(vs2)

    element_size = state.sew // 8
    load_instr = _get_float_instr('load', state.sew)
    store_instr = _get_float_instr('store', state.sew)
    nmsub_instr = _get_float_instr('nmsub', state.sew)

    lines.append(f"# vfnmsac.vf {vd}, {rs1}, {vs2}")
    lines.append(f"# Semantic: {vd}[i] = -({rs1} * {vs2}[i]) + {vd}[i]")
    lines.append(f"# SEW = {state.sew}-bit, vl 从 CSR 动态读取")
    lines.append("")

    _emit_load_vl_from_csr(lines, vl_reg=vl_reg, addr_reg=csr_addr_reg)
    lines.append("")

    loop_label = new_label("vfnmsac_vf")
    lines.append(f"{loop_label}:                         # 循环入口")
    lines.append(f"    beqz    {vl_reg}, {loop_label}_end    # 如果 vl == 0，退出循环")
    lines.append("")

    lines.append("    # 计算元素索引和偏移")
    lines.append(
        f"    addi    {element_offset_reg}, {vl_reg}, -1          "
        f"# {element_offset_reg} = i = {vl_reg} - 1"
    )
    skip_label = _maybe_emit_mask_skip_guard(
        lines=lines,
        insn=insn,
        new_label=new_label,
        element_index_reg=element_offset_reg,
        mask_chunk_reg=addr_reg,
        shift_reg=mask_shift_reg,
        label_prefix="vfnmsac_vf_mask_skip",
    )
    _emit_element_shift(lines, element_size, shift_reg=element_offset_reg)

    lines.append("")
    lines.append(f"    # 加载 {vs2}[i] 到 {source_value_fpr}")
    lines.append(f"    li      {mask_shift_reg}, {vs2_offset}")
    lines.append(f"    add     {addr_reg}, t6, {mask_shift_reg}")
    lines.append(f"    add     {addr_reg}, {addr_reg}, {element_offset_reg}")
    lines.append(f"    {load_instr:<7} {source_value_fpr}, 0({addr_reg})")

    lines.append("")
    lines.append(f"    # 加载 {vd}[i] 到 {accum_value_fpr}")
    lines.append(f"    li      {mask_shift_reg}, {vd_offset}")
    lines.append(f"    add     {addr_reg}, t6, {mask_shift_reg}")
    lines.append(f"    add     {addr_reg}, {addr_reg}, {element_offset_reg}")
    lines.append(f"    {load_instr:<7} {accum_value_fpr}, 0({addr_reg})")

    lines.append("")
    lines.append(
        f"    # {nmsub_instr}: {accum_value_fpr} = -({rs1} * {source_value_fpr}) + {accum_value_fpr}"
    )
    lines.append(
        f"    {nmsub_instr:<7} {accum_value_fpr}, {source_value_fpr}, {rs1}, {accum_value_fpr}"
    )

    lines.append("")
    lines.append(f"    # 写回 {vd}[i]")
    lines.append(f"    li      {mask_shift_reg}, {vd_offset}")
    lines.append(f"    add     {addr_reg}, t6, {mask_shift_reg}")
    lines.append(f"    add     {addr_reg}, {addr_reg}, {element_offset_reg}")
    lines.append(f"    {store_instr:<7} {accum_value_fpr}, 0({addr_reg})")

    lines.append("")
    lines.append("    # 更新循环计数器")
    if skip_label is not None:
        lines.append(f"{skip_label}:")
    lines.append(f"    addi    {vl_reg}, {vl_reg}, -1")
    lines.append(f"    j       {loop_label}")
    lines.append("")
    lines.append(f"{loop_label}_end:")

    return lines


# ============================================================================
# vadd.vv 指令翻译 (整数向量加法)
# ============================================================================

def _build_vadd_vv_lines(context) -> list[str]:
    """
    翻译 vadd.vv 指令 (整数向量-向量加法)

    格式: vadd.vv vd, vs1, vs2, vm
    语义: vd[i] = vs1[i] + vs2[i]

    翻译为标量循环:
        for i in range(vl):  # vl 从 CSR 动态读取
            t4 = load vs1[i]
            t5 = load vs2[i]
            t4 = add t4, t5
            store vd[i] = t4
    :return: 生成的汇编代码行列表
    """
    insn = context.instruction
    state = context.state
    allocator = context.layout
    new_label = context.new_label
    lines = []

    # 解析操作数: vd, vs1, vs2
    operands = insn.operands
    if len(operands) < 3:
        raise InstructionValidationError(insn, f"Invalid operands for {insn.opcode}: {insn.op_str}")

    vd = operands[0]    # 目标向量寄存器
    vs1 = operands[1]  # 源向量寄存器 1
    vs2 = operands[2]  # 源向量寄存器 2

    # 获取偏移量
    vd_offset = allocator.get_offset(vd)
    vs1_offset = allocator.get_offset(vs1)
    vs2_offset = allocator.get_offset(vs2)

    # 获取元素大小和指令
    sew = state.sew
    element_size = sew // 8
    load_instr = _get_int_instr(sew, 'load')
    store_instr = _get_int_instr(sew, 'store')
    add_instr = _get_int_instr(sew, 'add')

    # `vadd.vv` 虽然只有向量操作数，不会直接与标量语义寄存器冲突，
    # 但这里仍统一迁到 temp allocator，保持所有已支持 handler 的风格一致。
    temps = context.temp_register_allocator
    vl_reg = temps.alloc_gpr()
    csr_addr_reg = temps.alloc_gpr()
    element_offset_reg = temps.alloc_gpr()
    addr_reg = temps.alloc_gpr()
    lhs_value_reg = temps.alloc_gpr()
    rhs_value_reg = temps.alloc_gpr()

    # 生成注释头 (简洁风格)
    lines.append(f"    # {insn.opcode}: {vd} = {vs1} + {vs2}翻译开始")

    # 从 CSR 加载 vl
    _emit_load_vl_from_csr(lines, vl_reg=vl_reg, addr_reg=csr_addr_reg)

    # 循环体
    loop_label = new_label("vadd_vv")
    lines.append(f"{loop_label}:")
    lines.append(f"    beqz    {vl_reg}, {loop_label}_end")

    # 计算元素偏移
    lines.append(f"    addi    {element_offset_reg}, {vl_reg}, -1")
    skip_label = _maybe_emit_mask_skip_guard(
        lines=lines,
        insn=insn,
        new_label=new_label,
        element_index_reg=element_offset_reg,
        mask_chunk_reg=addr_reg,
        shift_reg=csr_addr_reg,
        label_prefix="vadd_vv_mask_skip",
    )
    _emit_element_shift(lines, element_size, shift_reg=element_offset_reg)

    # 加载 vs2[i]
    lines.append(f"    li      {csr_addr_reg}, {vs2_offset}")
    lines.append(f"    add     {addr_reg}, t6, {csr_addr_reg}")
    lines.append(f"    add     {addr_reg}, {addr_reg}, {element_offset_reg}")
    lines.append(f"    {load_instr:<7} {rhs_value_reg}, 0({addr_reg})")

    # 加载 vs1[i]
    lines.append(f"    li      {csr_addr_reg}, {vs1_offset}")
    lines.append(f"    add     {addr_reg}, t6, {csr_addr_reg}")
    lines.append(f"    add     {addr_reg}, {addr_reg}, {element_offset_reg}")
    lines.append(f"    {load_instr:<7} {lhs_value_reg}, 0({addr_reg})")

    # 执行加法
    lines.append(f"    {add_instr:<7} {lhs_value_reg}, {lhs_value_reg}, {rhs_value_reg}")

    # 存储结果
    lines.append(f"    li      {csr_addr_reg}, {vd_offset}")
    lines.append(f"    add     {addr_reg}, t6, {csr_addr_reg}")
    lines.append(f"    add     {addr_reg}, {addr_reg}, {element_offset_reg}")
    lines.append(f"    {store_instr:<7} {lhs_value_reg}, 0({addr_reg})")

    # 更新循环计数器
    if skip_label is not None:
        lines.append(f"{skip_label}:")
    lines.append(f"    addi    {vl_reg}, {vl_reg}, -1")
    lines.append(f"    j       {loop_label}")

    # 循环结束
    lines.append(f"{loop_label}_end:")

    return lines


# ============================================================================
# vfmacc.vv 指令翻译
# ============================================================================

def _build_vfmacc_vv_lines(context) -> list[str]:
    """
    翻译 vfmacc.vv 指令 (向量-向量乘加)

    格式: vfmacc.vv vd, vs1, vs2, vm
    语义: vd[i] = +(vs1[i] * vs2[i]) + vd[i]
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

    vd = operands[0]   # 目标向量寄存器
    vs1 = operands[1]  # 源向量寄存器 1
    vs2 = operands[2]  # 源向量寄存器 2

    vd_offset = allocator.get_offset(vd)
    vs1_offset = allocator.get_offset(vs1)
    vs2_offset = allocator.get_offset(vs2)

    element_size = state.sew // 8

    load_instr = _get_float_instr('load', state.sew)
    store_instr = _get_float_instr('store', state.sew)
    madd_instr = _get_float_instr('madd', state.sew)

    # 这里虽然只有向量操作数，但统一迁到 allocator 后，
    # 后续维护时就不再需要人工记忆哪些 handler “理论上不会冲突"。
    temps = context.temp_register_allocator
    vl_reg = temps.alloc_gpr()
    csr_addr_reg = temps.alloc_gpr()
    element_offset_reg = temps.alloc_gpr()
    addr_reg = temps.alloc_gpr()
    source_rhs_fpr = temps.alloc_fpr()
    source_lhs_fpr = temps.alloc_fpr()
    accum_value_fpr = temps.alloc_fpr()

    lines.append(f"# vfmacc.vv {vd}, {vs1}, {vs2}")
    lines.append(f"# Semantic: {vd}[i] += {vs1}[i] * {vs2}[i]")
    lines.append(f"# SEW = {state.sew}-bit, vl 从 CSR 动态读取")
    lines.append("")

    _emit_load_vl_from_csr(lines, vl_reg=vl_reg, addr_reg=csr_addr_reg)
    lines.append("")

    loop_label = new_label("vfmacc_vv")
    lines.append(f"{loop_label}:")
    lines.append(f"    beqz    {vl_reg}, {loop_label}_end")
    lines.append("")

    lines.append("    # 计算元素索引和偏移")
    lines.append(f"    addi    {element_offset_reg}, {vl_reg}, -1")
    skip_label = _maybe_emit_mask_skip_guard(
        lines=lines,
        insn=insn,
        new_label=new_label,
        element_index_reg=element_offset_reg,
        mask_chunk_reg=addr_reg,
        shift_reg=csr_addr_reg,
        label_prefix="vfmacc_vv_mask_skip",
    )
    _emit_element_shift(lines, element_size, shift_reg=element_offset_reg)

    # 加载 vs2[i]
    lines.append("")
    lines.append(f"    # 加载 {vs2}[i] 到 {source_rhs_fpr}")
    lines.append(f"    li      {csr_addr_reg}, {vs2_offset}")
    lines.append(f"    add     {addr_reg}, t6, {csr_addr_reg}")
    lines.append(f"    add     {addr_reg}, {addr_reg}, {element_offset_reg}")
    lines.append(f"    {load_instr:<7} {source_rhs_fpr}, 0({addr_reg})")

    # 加载 vs1[i]
    lines.append("")
    lines.append(f"    # 加载 {vs1}[i] 到 {source_lhs_fpr}")
    lines.append(f"    li      {csr_addr_reg}, {vs1_offset}")
    lines.append(f"    add     {addr_reg}, t6, {csr_addr_reg}")
    lines.append(f"    add     {addr_reg}, {addr_reg}, {element_offset_reg}")
    lines.append(f"    {load_instr:<7} {source_lhs_fpr}, 0({addr_reg})")

    # 加载 vd[i]
    lines.append("")
    lines.append(f"    # 加载 {vd}[i] 到 {accum_value_fpr}")
    lines.append(f"    li      {csr_addr_reg}, {vd_offset}")
    lines.append(f"    add     {addr_reg}, t6, {csr_addr_reg}")
    lines.append(f"    add     {addr_reg}, {addr_reg}, {element_offset_reg}")
    lines.append(f"    {load_instr:<7} {accum_value_fpr}, 0({addr_reg})")

    # fmadd
    lines.append("")
    lines.append(
        f"    {madd_instr:<7} {accum_value_fpr}, {source_rhs_fpr}, {source_lhs_fpr}, {accum_value_fpr}"
        f"  # {accum_value_fpr} = {source_rhs_fpr} * {source_lhs_fpr} + {accum_value_fpr}"
    )

    # 存储
    lines.append("")
    lines.append(f"    li      {csr_addr_reg}, {vd_offset}")
    lines.append(f"    add     {addr_reg}, t6, {csr_addr_reg}")
    lines.append(f"    add     {addr_reg}, {addr_reg}, {element_offset_reg}")
    lines.append(f"    {store_instr:<7} {accum_value_fpr}, 0({addr_reg})")

    lines.append("")
    if skip_label is not None:
        lines.append(f"{skip_label}:")
    lines.append(f"    addi    {vl_reg}, {vl_reg}, -1")
    lines.append(f"    j       {loop_label}")
    lines.append("")

    lines.append(f"{loop_label}_end:")

    return lines


# ============================================================================
# vfwmacc.vv 指令翻译
# ============================================================================

def _build_vfwmacc_vv_lines(context) -> list[str]:
    """
    翻译 vfwmacc.vv 指令 (widening 向量-向量浮点乘加)

    格式: vfwmacc.vv vd, vs1, vs2, vm
    语义: vd[i] = vd[i] + widen(vs1[i]) * widen(vs2[i])

    参考 QEMU `fwmacc32()` / `trans_vfwmacc_vv()` 的核心语义：
        vd[i] = float64_muladd(float32_to_float64(vs1[i]),
                               float32_to_float64(vs2[i]),
                               vd[i])

    当前项目中的实现范围：
    - 支持 OpenBLAS `sdot_k` 所需的 `e32 -> e64` widening 路径；
    - 即：源元素宽度为 32-bit，目标累加寄存器元素宽度为 64-bit；
    - 这与当前 `sdot_k` 中的 `vsetvli ..., e32, m4` + `vfwmacc.vv v16, v8, v4`
      使用方式一致。

    翻译策略：
    1. 从 CSR 读取 `vl`，逐元素循环；
    2. 使用 `flw` 读取 32-bit 源元素；
    3. 使用 `fcvt.d.s` 将两个源元素都提升为 double；
    4. 使用 `fld` 读取 64-bit 累加目的元素；
    5. 使用 `fmadd.d` 完成 widening 乘加；
    6. 使用 `fsd` 写回 widened 目标元素。

    说明：
    - 源向量元素步长是 4 字节；
    - 目标向量元素步长是 8 字节；
    - 尽管 widened 目标在 RVV 语义上会占用更大的寄存器组，
      但在本项目的 `simulated_cpu_state` 线性布局中，
      使用 `vd_offset + i * 8` 自然就会跨越到后续物理向量寄存器区域，
      因此无需额外处理寄存器组边界。
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

    # 当前实现只覆盖 OpenBLAS `sdot_k` 的核心需求：float32 源 -> float64 累加。
    if state.sew != 32:
        raise ValueError(
            f"vfwmacc.vv 当前仅支持源 SEW=32 的 widening 路径，实际为 SEW={state.sew}"
        )

    vd = operands[0]   # widened 目标向量寄存器（按 64-bit 元素读写）
    vs1 = operands[1]  # 32-bit 源向量寄存器 1
    vs2 = operands[2]  # 32-bit 源向量寄存器 2

    vd_offset = allocator.get_offset(vd)
    vs1_offset = allocator.get_offset(vs1)
    vs2_offset = allocator.get_offset(vs2)

    src_element_size = state.sew // 8          # 4 bytes
    dst_sew = state.sew * 2                    # 64 bits
    dst_element_size = dst_sew // 8            # 8 bytes

    src_load_instr = _get_float_instr('load', state.sew)
    dst_load_instr = _get_float_instr('load', dst_sew)
    dst_store_instr = _get_float_instr('store', dst_sew)

    # widening 版本同时需要两套索引偏移，但因为这里只有向量操作数，
    # 所有 GPR/FPR temp 都可以安全地从 allocator 统一分配。
    temps = context.temp_register_allocator
    vl_reg = temps.alloc_gpr()
    csr_addr_reg = temps.alloc_gpr()
    src_offset_reg = temps.alloc_gpr()
    dst_offset_reg = temps.alloc_gpr()
    addr_reg = temps.alloc_gpr()
    source_rhs_fpr = temps.alloc_fpr()
    source_lhs_fpr = temps.alloc_fpr()
    accum_value_fpr = temps.alloc_fpr()

    lines.append(f"# vfwmacc.vv {vd}, {vs1}, {vs2}")
    lines.append(f"# Semantic: {vd}[i] += widen({vs1}[i]) * widen({vs2}[i])")
    lines.append("# 源元素使用 float32 读取并提升到 float64，目标元素按 float64 累加")
    lines.append("")

    # 从 CSR 中读取运行时 vl，保持与其他向量翻译路径一致。
    _emit_load_vl_from_csr(lines, vl_reg=vl_reg, addr_reg=csr_addr_reg)
    lines.append("")

    loop_label = new_label("vfwmacc_vv")
    lines.append(f"{loop_label}:")
    lines.append(f"    beqz    {vl_reg}, {loop_label}_end")
    lines.append("")

    # 同一个逻辑元素索引 i，会对应两种不同的字节步长：
    # - 源向量：4 字节
    # - 目的向量：8 字节
    lines.append("    # 分别计算源向量和 widened 目标向量的元素偏移")
    lines.append(f"    addi    {src_offset_reg}, {vl_reg}, -1")
    skip_label = _maybe_emit_mask_skip_guard(
        lines=lines,
        insn=insn,
        new_label=new_label,
        element_index_reg=src_offset_reg,
        mask_chunk_reg=addr_reg,
        shift_reg=csr_addr_reg,
        label_prefix="vfwmacc_vv_mask_skip",
    )
    _emit_element_shift(lines, src_element_size, shift_reg=src_offset_reg)
    lines.append(f"    addi    {dst_offset_reg}, {vl_reg}, -1")
    lines.append(f"    slli    {dst_offset_reg}, {dst_offset_reg}, 3           # {dst_offset_reg} = i * {dst_element_size} (widened 64-bit)")

    # 读取 vs2[i]，并从单精度提升到双精度。
    lines.append("")
    lines.append(f"    # 读取 {vs2}[i] (float32) -> {source_rhs_fpr}，再提升到 float64")
    lines.append(f"    li      {csr_addr_reg}, {vs2_offset}")
    lines.append(f"    add     {addr_reg}, t6, {csr_addr_reg}")
    lines.append(f"    add     {addr_reg}, {addr_reg}, {src_offset_reg}")
    lines.append(f"    {src_load_instr:<7} {source_rhs_fpr}, 0({addr_reg})")
    lines.append(f"    fcvt.d.s {source_rhs_fpr}, {source_rhs_fpr}")

    # 读取 vs1[i]，并从单精度提升到双精度。
    lines.append("")
    lines.append(f"    # 读取 {vs1}[i] (float32) -> {source_lhs_fpr}，再提升到 float64")
    lines.append(f"    li      {csr_addr_reg}, {vs1_offset}")
    lines.append(f"    add     {addr_reg}, t6, {csr_addr_reg}")
    lines.append(f"    add     {addr_reg}, {addr_reg}, {src_offset_reg}")
    lines.append(f"    {src_load_instr:<7} {source_lhs_fpr}, 0({addr_reg})")
    lines.append(f"    fcvt.d.s {source_lhs_fpr}, {source_lhs_fpr}")

    # widened 目的寄存器元素按 64-bit 读写。
    lines.append("")
    lines.append(f"    # 读取 widened {vd}[i] (float64) -> {accum_value_fpr}")
    lines.append(f"    li      {csr_addr_reg}, {vd_offset}")
    lines.append(f"    add     {addr_reg}, t6, {csr_addr_reg}")
    lines.append(f"    add     {addr_reg}, {addr_reg}, {dst_offset_reg}")
    lines.append(f"    {dst_load_instr:<7} {accum_value_fpr}, 0({addr_reg})")

    # 执行 widening 浮点乘加：ft1 = ft0 * ft2 + ft1
    lines.append("")
    lines.append("    # widening fused multiply-add")
    lines.append(
        f"    fmadd.d {accum_value_fpr}, {source_rhs_fpr}, {source_lhs_fpr}, {accum_value_fpr}"
        f"  # {accum_value_fpr} = widen({vs2}[i]) * widen({vs1}[i]) + {vd}[i]"
    )

    # 写回 widened 目标元素。
    lines.append("")
    lines.append(f"    # 写回 widened {vd}[i]")
    lines.append(f"    li      {csr_addr_reg}, {vd_offset}")
    lines.append(f"    add     {addr_reg}, t6, {csr_addr_reg}")
    lines.append(f"    add     {addr_reg}, {addr_reg}, {dst_offset_reg}")
    lines.append(f"    {dst_store_instr:<7} {accum_value_fpr}, 0({addr_reg})")

    lines.append("")
    if skip_label is not None:
        lines.append(f"{skip_label}:")
    lines.append(f"    addi    {vl_reg}, {vl_reg}, -1")
    lines.append(f"    j       {loop_label}")
    lines.append("")
    lines.append(f"{loop_label}_end:")

    return lines


# ============================================================================
# vmv4r.v 指令翻译 (whole register move)
# ============================================================================

def _build_whole_register_move_lines(context) -> list[str]:
    """Copy aligned whole register groups, independently of vl and vtype."""
    insn = context.instruction
    allocator = context.layout
    new_label = context.new_label
    lines = []

    operands = insn.operands
    if len(operands) < 2:
        raise InstructionValidationError(insn, f"Invalid operands for {insn.opcode}: {insn.op_str}")

    vd = operands[0]
    vs2 = operands[1]

    vd_num = _parse_vector_register_number(vd)
    vs2_num = _parse_vector_register_number(vs2)

    registers = {"vmv1r.v": 1, "vmv2r.v": 2, "vmv4r.v": 4}[insn.opcode]
    if (
        vd_num % registers or vs2_num % registers
        or vd_num + registers > 32 or vs2_num + registers > 32
    ):
        raise ValueError(
            f"{insn.opcode} requires aligned groups of {registers} registers: {vd}, {vs2}"
        )

    dst_offset = allocator.get_offset(vd)
    src_offset = allocator.get_offset(vs2)
    total_bytes = registers * allocator.vreg_size

    # whole-register move 只有向量输入输出，但这里同样迁到 allocator，
    # 这样整份文件就不再混用“有的 handler 动态分配、有的手写 t0-t3"两套风格。
    temps = context.temp_register_allocator
    remaining_bytes_reg = temps.alloc_gpr()
    src_addr_reg = temps.alloc_gpr()
    value_reg = temps.alloc_gpr()
    dst_addr_reg = temps.alloc_gpr()

    lines.append(f"    # {insn.opcode}: copy {vs2}-v{vs2_num + registers - 1} -> {vd}-v{vd_num + registers - 1}")
    lines.append("    # 这是 whole-register move，不依赖 vl，按完整物理寄存器字节块复制")
    lines.append(f"    li      {remaining_bytes_reg}, {total_bytes}    # 需要复制的总字节数")

    loop_label = new_label(insn.opcode.replace('.', '_'))
    lines.append(f"{loop_label}:")
    lines.append(f"    beqz    {remaining_bytes_reg}, {loop_label}_end")
    lines.append(f"    addi    {remaining_bytes_reg}, {remaining_bytes_reg}, -8          # 以 8 字节为单位倒序复制，避免额外比较")

    lines.append(f"    li      {src_addr_reg}, {src_offset}")
    lines.append(f"    add     {src_addr_reg}, t6, {src_addr_reg}")
    lines.append(f"    add     {src_addr_reg}, {src_addr_reg}, {remaining_bytes_reg}")
    lines.append(f"    ld      {value_reg}, 0({src_addr_reg})")

    lines.append(f"    li      {dst_addr_reg}, {dst_offset}")
    lines.append(f"    add     {dst_addr_reg}, t6, {dst_addr_reg}")
    lines.append(f"    add     {dst_addr_reg}, {dst_addr_reg}, {remaining_bytes_reg}")
    lines.append(f"    sd      {value_reg}, 0({dst_addr_reg})")

    lines.append(f"    j       {loop_label}")
    lines.append(f"{loop_label}_end:")

    return lines


# ============================================================================
# vfmv.v.f 指令翻译 (vector-scalar float move, fill)
# ============================================================================

def _build_vfmv_v_f_lines(context) -> list[str]:
    """
    翻译 vfmv.v.f 指令 (将标量浮点复制到所有向量元素)

    格式: vfmv.v.f vd, rs1
    语义: for i in range(vl): vd[i] = rs1

    QEMU vector_helper.c 语义 (使用 vmv_v_x helper):
        for (i = env->vstart; i < vl; i++) {
            vd[i] = rs1;  // 所有元素设置为 rs1
        }
    :return: 生成的汇编代码行列表
    """
    insn = context.instruction
    state = context.state
    allocator = context.layout
    new_label = context.new_label
    lines = []

    # 解析操作数: vd, rs1
    operands = insn.operands
    if len(operands) < 2:
        raise InstructionValidationError(insn, f"Invalid operands for {insn.opcode}: {insn.op_str}")

    vd = operands[0]
    rs1 = operands[1]

    # 获取偏移量
    vd_offset = allocator.get_offset(vd)
    element_size = state.sew // 8

    # 标量源 `rs1` 是浮点寄存器，因此这里只需动态分配地址/循环类 GPR temp 即可。
    temps = context.temp_register_allocator
    vl_reg = temps.alloc_gpr()
    csr_addr_reg = temps.alloc_gpr()
    element_offset_reg = temps.alloc_gpr()
    addr_reg = temps.alloc_gpr()

    # 生成注释
    lines.append(f"    # {insn.opcode}: {vd}[i] = {rs1} for all i")

    # 从 CSR 加载 vl
    _emit_load_vl_from_csr(lines, vl_reg=vl_reg, addr_reg=csr_addr_reg)

    # 循环体
    loop_label = new_label("vfmv_v_f")
    lines.append(f"{loop_label}:")
    lines.append(f"    beqz    {vl_reg}, {loop_label}_end")

    # 计算元素偏移
    lines.append(f"    addi    {element_offset_reg}, {vl_reg}, -1")
    _emit_element_shift(lines, element_size, shift_reg=element_offset_reg)

    # 加载标量 rs1
    # rs1 是浮点寄存器如 fa5
    # 使用同一个浮点值

    # 计算目标地址
    lines.append(f"    li      {addr_reg}, {vd_offset}")
    lines.append(f"    add     {addr_reg}, t6, {addr_reg}")
    lines.append(f"    add     {addr_reg}, {addr_reg}, {element_offset_reg}")

    # 存储标量值到所有元素
    # 对于双精度: 复制 fa5 到每个元素
    if state.sew == 64:
        lines.append(f"    fsd     {rs1}, 0({addr_reg})")
    else:
        lines.append(f"    fsw     {rs1}, 0({addr_reg})")

    # 更新循环计数器
    lines.append(f"    addi    {vl_reg}, {vl_reg}, -1")
    lines.append(f"    j       {loop_label}")

    lines.append(f"{loop_label}_end:")

    return lines


# ============================================================================
# vfmv.f.s 指令翻译 (vector-to-scalar float move, element 0 only)
# ============================================================================

def _build_vfmv_f_s_lines(context) -> list[str]:
    """
    翻译 vfmv.f.s 指令 (将向量第 0 个浮点元素移动到标量浮点寄存器)

    格式: vfmv.f.s rd, vs2
    语义: rd = vs2[0]

    参考 QEMU `trans_vfmv_f_s()`：
        vec_element_loadi(..., rs2, 0, false)
        # 必要时对更窄的浮点值执行 NaN-box

    在本项目中的落地策略：
    - 向量寄存器内容保存在 `simulated_cpu_state` 中；
    - 第 0 个元素正好位于对应向量寄存器的起始偏移处；
    - 该指令不依赖 `vl`，直接读取元素 0；
    - 根据 SEW 选择加载指令: SEW=32 → flw, SEW=64 → fld；
    :return: 生成的汇编代码行列表
    """
    insn = context.instruction
    state = context.state
    allocator = context.layout
    lines = []

    # 解析操作数: rd, vs2
    operands = insn.operands
    if len(operands) < 2:
        raise InstructionValidationError(insn, f"Invalid operands for {insn.opcode}: {insn.op_str}")

    rd = operands[0]
    vs2 = operands[1]

    # 向量寄存器第 0 个元素位于该寄存器在模拟状态块中的基址处。
    vs2_offset = allocator.get_offset(vs2)

    temps = context.temp_register_allocator
    addr_reg = temps.alloc_gpr()

    lines.append(f"    # {insn.opcode}: {rd} = {vs2}[0] (SEW={state.sew})")
    lines.append(f"    li      {addr_reg}, {vs2_offset}")
    lines.append(f"    add     {addr_reg}, t6, {addr_reg}")

    # 根据 SEW 选择加载指令: SEW=32 → flw, SEW=64 → fld
    load_instr = _get_float_instr('load', state.sew)
    lines.append(f"    {load_instr:<8} {rd}, 0({addr_reg})")

    return lines


# ============================================================================
# vfmul.vf 指令翻译
# ============================================================================

def _build_vfmul_vf_lines(context) -> list[str]:
    """
    翻译 vfmul.vf 指令 (向量-标量浮点乘法)

    格式: vfmul.vf vd, vs2, rs1, vm
    语义: vd[i] = vs2[i] * rs1
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

    temps = context.temp_register_allocator
    vl_reg = temps.alloc_gpr()
    csr_addr_reg = temps.alloc_gpr()
    element_offset_reg = temps.alloc_gpr()
    addr_reg = temps.alloc_gpr()
    source_value_fpr = temps.alloc_fpr()
    result_value_fpr = temps.alloc_fpr()

    vd_offset = allocator.get_offset(vd)
    vs2_offset = allocator.get_offset(vs2)

    element_size = state.sew // 8
    load_instr = _get_float_instr('load', state.sew)
    store_instr = _get_float_instr('store', state.sew)
    mul_instr = _get_float_instr('mul', state.sew)

    lines.append(f"# vfmul.vf {vd}, {vs2}, {rs1}")
    lines.append(f"# Semantic: {vd}[i] = {vs2}[i] * {rs1}")
    lines.append(f"# SEW = {state.sew}-bit, vl 从 CSR 动态读取")
    lines.append("")

    _emit_load_vl_from_csr(lines, vl_reg=vl_reg, addr_reg=csr_addr_reg)
    lines.append("")

    loop_label = new_label("vfmul_vf")
    lines.append(f"{loop_label}:")
    lines.append(f"    beqz    {vl_reg}, {loop_label}_end")
    lines.append("")

    lines.append("    # 计算元素索引和偏移")
    lines.append(f"    addi    {element_offset_reg}, {vl_reg}, -1")
    skip_label = _maybe_emit_mask_skip_guard(
        lines=lines,
        insn=insn,
        new_label=new_label,
        element_index_reg=element_offset_reg,
        mask_chunk_reg=addr_reg,
        shift_reg=csr_addr_reg,
        label_prefix="vfmul_vf_mask_skip",
    )
    _emit_element_shift(lines, element_size, shift_reg=element_offset_reg)

    lines.append("")
    lines.append(f"    # 加载 {vs2}[i] 到 {source_value_fpr}")
    lines.append(f"    li      {csr_addr_reg}, {vs2_offset}")
    lines.append(f"    add     {addr_reg}, t6, {csr_addr_reg}")
    lines.append(f"    add     {addr_reg}, {addr_reg}, {element_offset_reg}")
    lines.append(f"    {load_instr:<7} {source_value_fpr}, 0({addr_reg})")

    lines.append("")
    lines.append(f"    # 执行 {mul_instr}: {result_value_fpr} = {source_value_fpr} * {rs1}")
    lines.append(f"    {mul_instr:<7} {result_value_fpr}, {source_value_fpr}, {rs1}")

    lines.append("")
    lines.append(f"    # 存储 {vd}[i]")
    lines.append(f"    li      {csr_addr_reg}, {vd_offset}")
    lines.append(f"    add     {addr_reg}, t6, {csr_addr_reg}")
    lines.append(f"    add     {addr_reg}, {addr_reg}, {element_offset_reg}")
    lines.append(f"    {store_instr:<7} {result_value_fpr}, 0({addr_reg})")

    lines.append("")
    lines.append("    # 更新循环计数器")
    if skip_label is not None:
        lines.append(f"{skip_label}:")
    lines.append(f"    addi    {vl_reg}, {vl_reg}, -1")
    lines.append(f"    j       {loop_label}")
    lines.append("")
    lines.append(f"{loop_label}_end:")

    return lines


# vmv.v.i 指令翻译 (vector immediate move, fill)
# ============================================================================

def _build_vmv_v_i_lines(context) -> list[str]:
    """
    翻译 vmv.v.i 指令 (将 5-bit 有符号立即数复制到所有向量元素)

    格式: vmv.v.i vd, imm
    语义: for i in range(vl): vd[i] = sext(imm[4:0])

    参考 QEMU `trans_vmv_v_i()` / `GEN_VEXT_VMV_VX()`：
        simm = sextract64(imm, 0, 5)
        for each active element:
            vd[i] = (ETYPE)simm
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
    imm = operands[1]

    vd_offset = allocator.get_offset(vd)
    element_size = state.sew // 8
    store_instr = _get_int_instr(state.sew, 'store')

    try:
        raw_imm = int(str(imm), 0)
    except ValueError:
        raise InstructionValidationError(insn, f"Invalid immediate for {insn.opcode}: {insn.op_str}")

    signed_imm = raw_imm & 0x1F
    if signed_imm & 0x10:
        signed_imm -= 0x20

    # `vmv.v.i` 没有标量寄存器输入，但仍然会用到多个 GPR temp，
    # 统一迁移后可以避免后续同类 handler 继续复制旧写法。
    temps = context.temp_register_allocator
    vl_reg = temps.alloc_gpr()
    csr_addr_reg = temps.alloc_gpr()
    element_offset_reg = temps.alloc_gpr()
    addr_reg = temps.alloc_gpr()
    imm_reg = temps.alloc_gpr()

    lines.append(f"    # {insn.opcode}: {vd}[i] = {signed_imm} for all i")

    _emit_load_vl_from_csr(lines, vl_reg=vl_reg, addr_reg=csr_addr_reg)

    loop_label = new_label("vmv_v_i")
    lines.append(f"{loop_label}:")
    lines.append(f"    beqz    {vl_reg}, {loop_label}_end")

    lines.append(f"    addi    {element_offset_reg}, {vl_reg}, -1")
    _emit_element_shift(lines, element_size, shift_reg=element_offset_reg)

    lines.append(f"    li      {imm_reg}, {signed_imm}")
    lines.append(f"    li      {addr_reg}, {vd_offset}")
    lines.append(f"    add     {addr_reg}, t6, {addr_reg}")
    lines.append(f"    add     {addr_reg}, {addr_reg}, {element_offset_reg}")
    lines.append(f"    {store_instr:<7} {imm_reg}, 0({addr_reg})")

    lines.append(f"    addi    {vl_reg}, {vl_reg}, -1")
    lines.append(f"    j       {loop_label}")
    lines.append(f"{loop_label}_end:")

    return lines


# ============================================================================
# vmv.s.x 指令翻译 (vector scalar move, element 0 only)
# ============================================================================

def _build_vmv_s_x_lines(context) -> list[str]:
    """
    翻译 vmv.s.x 指令 (将标量整数写入向量元素 0)

    格式: vmv.s.x vd, rs1
    语义: vd[0] = rs1 (仅元素 0)

    QEMU trans_rvv.c.inc 语义:
        vd[0] = rs1  // 只写入第一个元素
    :return: 生成的汇编代码行列表
    """
    insn = context.instruction
    state = context.state
    allocator = context.layout
    lines = []

    # 解析操作数: vd, rs1
    operands = insn.operands
    if len(operands) < 2:
        raise InstructionValidationError(insn, f"Invalid operands for {insn.opcode}: {insn.op_str}")

    vd = operands[0]
    rs1 = operands[1]

    # 获取偏移量
    vd_offset = allocator.get_offset(vd)
    element_size = state.sew // 8

    # 生成注释
    lines.append(f"    # {insn.opcode}: {vd}[0] = {rs1}")

    # `rs1` 如果本身就是 `t3/t4/...`，继续硬编码地址 temp 会直接覆盖语义值。
    # 因此这里把地址寄存器也改为动态分配。
    temps = context.temp_register_allocator
    addr_reg = temps.alloc_gpr()
    vl_reg = temps.alloc_gpr()
    end_label = context.new_label("vmv_s_x_end")
    _emit_load_vl_from_csr(lines, vl_reg=vl_reg, addr_reg=addr_reg)
    lines.append(f"    beqz    {vl_reg}, {end_label}")

    # 计算目标地址 (元素 0)
    lines.append(f"    li      {addr_reg}, {vd_offset}")
    lines.append(f"    add     {addr_reg}, t6, {addr_reg}")

    # 存储 rs1 到 vd[0]
    if element_size == 8:
        lines.append(f"    sd      {rs1}, 0({addr_reg})")
    elif element_size == 4:
        lines.append(f"    sw      {rs1}, 0({addr_reg})")
    elif element_size == 2:
        lines.append(f"    sh      {rs1}, 0({addr_reg})")
    else:
        lines.append(f"    sb      {rs1}, 0({addr_reg})")

    lines.append(f"{end_label}:")
    return lines


# ============================================================================
# vmv.v.x 指令翻译 (vector scalar splat, all active elements)
# ============================================================================

def _build_vmv_v_x_lines(context) -> list[str]:
    """
    翻译 vmv.v.x 指令（将标量 GPR 广播到向量的前 vl 个元素）

    格式: vmv.v.x vd, rs1
    语义: for i in range(vl): vd[i] = (SEW)rs1

    与 QEMU `trans_vmv_v_x` / splat 行为一致：按当前 SEW 使用 sb/sh/sw/sd 写入模拟内存。
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
    rs1 = operands[1]

    vd_offset = allocator.get_offset(vd)
    element_size = state.sew // 8
    store_instr = _get_int_instr(state.sew, "store")

    # 分配所有临时寄存器，避免与 rs1 冲突
    temps = context.temp_register_allocator
    val_reg = temps.alloc_gpr()
    vl_reg = temps.alloc_gpr()
    csr_addr_reg = temps.alloc_gpr()
    element_offset_reg = temps.alloc_gpr()
    addr_reg = temps.alloc_gpr()

    lines.append(f"    # {insn.opcode}: {vd}[i] = {rs1} for i in 0..vl-1 (SEW={state.sew})")
    lines.append(f"    mv      {val_reg}, {rs1}")

    # 显式传入寄存器，避免覆盖 val_reg
    _emit_load_vl_from_csr(lines, vl_reg=vl_reg, addr_reg=csr_addr_reg)

    loop_label = new_label("vmv_v_x")
    lines.append(f"{loop_label}:")
    lines.append(f"    beqz    {vl_reg}, {loop_label}_end")

    lines.append(f"    addi    {element_offset_reg}, {vl_reg}, -1")
    _emit_element_shift(lines, element_size, shift_reg=element_offset_reg)

    lines.append(f"    li      {addr_reg}, {vd_offset}")
    lines.append(f"    add     {addr_reg}, t6, {addr_reg}")
    lines.append(f"    add     {addr_reg}, {addr_reg}, {element_offset_reg}")
    lines.append(f"    {store_instr:<7} {val_reg}, 0({addr_reg})")

    lines.append(f"    addi    {vl_reg}, {vl_reg}, -1")
    lines.append(f"    j       {loop_label}")
    lines.append(f"{loop_label}_end:")

    return lines


# ============================================================================
# vfredusum.vs 指令翻译 (浮点归约求和)
# ============================================================================

def _build_vfredusum_vs_lines(context) -> list[str]:
    """
    翻译 vfredusum.vs 指令 (浮点归约求和)

    格式: vfredusum.vs vd, vs1, vs2, vm
    语义: vd[0] = Σ vs1[i] + vs2[0] (i = 0 to vl-1)

    RISC-V V 规范语义:
        accum = 0
        for (i = 0; i < vl; i++) {
            accum += vs1[i];  // vs1 是被归约的向量
        }
        vd[0] = accum + vs2[0];  // vs2[0] 是初始值
    :return: 生成的汇编代码行列表
    """
    insn = context.instruction
    state = context.state
    allocator = context.layout
    new_label = context.new_label
    lines = []

    # 解析操作数: vd, vs1, vs2
    operands = insn.operands
    if len(operands) < 3:
        raise InstructionValidationError(insn, f"Invalid operands for {insn.opcode}: {insn.op_str}")

    vd = operands[0]
    vs1 = operands[1]  # 被归约的源向量
    vs2 = operands[2]  # 提供初始值 (vs2[0])

    # 获取偏移量
    vd_offset = allocator.get_offset(vd)
    vs1_offset = allocator.get_offset(vs1)
    vs2_offset = allocator.get_offset(vs2)

    element_size = state.sew // 8

    # `vfredusum.vs` 使用了两组 FPR temp 和多组地址计算寄存器。
    # 尽管它的操作数都是向量寄存器，但统一迁移后可以保证：
    # - helper 与 handler 的寄存器使用方式一致；
    # - 后续如果引入更复杂 form，也不需要再回头重构旧模板。
    temps = context.temp_register_allocator
    vl_reg = temps.alloc_gpr()
    csr_addr_reg = temps.alloc_gpr()
    element_offset_reg = temps.alloc_gpr()
    addr_reg = temps.alloc_gpr()
    accum_value_fpr = temps.alloc_fpr()
    source_value_fpr = temps.alloc_fpr()

    # 生成注释
    lines.append(f"    # {insn.opcode}: {vd}[0] = Σ{vs1}[i] + {vs2}[0]")

    end_label = new_label("vfredusum_done")
    _emit_load_vl_from_csr(lines, vl_reg=vl_reg, addr_reg=csr_addr_reg)
    lines.append(f"    beqz    {vl_reg}, {end_label}")

    # ========== 1. 加载初始值 vs2[0] ==========
    load_instr = _get_float_instr('load', state.sew)
    lines.append(f"    # 加载初始值 {vs2}[0]")
    lines.append(f"    li      {addr_reg}, {vs2_offset}")
    lines.append(f"    add     {addr_reg}, t6, {addr_reg}")
    lines.append(f"    {load_instr:<7} {accum_value_fpr}, 0({addr_reg})    # {accum_value_fpr} = {vs2}[0]")

    # ========== 2. 循环累加 ==========

    loop_label = new_label("vfredusum")
    lines.append(f"{loop_label}:")
    lines.append(f"    beqz    {vl_reg}, {loop_label}_end")

    # 计算元素偏移
    lines.append(f"    addi    {element_offset_reg}, {vl_reg}, -1")
    skip_label = _maybe_emit_mask_skip_guard(
        lines=lines,
        insn=insn,
        new_label=new_label,
        element_index_reg=element_offset_reg,
        mask_chunk_reg=addr_reg,
        shift_reg=csr_addr_reg,
        label_prefix="vfredusum_mask_skip",
    )
    _emit_element_shift(lines, element_size, shift_reg=element_offset_reg)

    # 加载 vs1[i]
    lines.append(f"    li      {addr_reg}, {vs1_offset}")
    lines.append(f"    add     {addr_reg}, t6, {addr_reg}")
    lines.append(f"    add     {addr_reg}, {addr_reg}, {element_offset_reg}")
    lines.append(f"    {load_instr:<7} {source_value_fpr}, 0({addr_reg})    # {source_value_fpr} = {vs1}[i]")

    # 累加
    add_instr = _get_float_instr('add', state.sew)
    lines.append(f"    {add_instr:<7} {accum_value_fpr}, {accum_value_fpr}, {source_value_fpr}    # {accum_value_fpr} += {source_value_fpr}")

    # 更新循环计数器
    if skip_label is not None:
        lines.append(f"{skip_label}:")
    lines.append(f"    addi    {vl_reg}, {vl_reg}, -1")
    lines.append(f"    j       {loop_label}")

    lines.append(f"{loop_label}_end:")

    # ========== 3. 写回结果 vd[0] ==========
    store_instr = _get_float_instr('store', state.sew)
    lines.append(f"    # 写回结果到 {vd}[0]")
    lines.append(f"    li      {addr_reg}, {vd_offset}")
    lines.append(f"    add     {addr_reg}, t6, {addr_reg}")
    lines.append(f"    {store_instr:<7} {accum_value_fpr}, 0({addr_reg})    # {vd}[0] = {accum_value_fpr}")

    lines.append(f"{end_label}:")
    return lines


# ============================================================================
# vadd.vi 指令翻译 (整数向量-立即数加法)
# ============================================================================

def _build_vadd_vi_lines(context) -> list[str]:
    """
    翻译 vadd.vi 指令 (整数向量-立即数加法)

    格式: vadd.vi vd, vs2, imm
    语义: vd[i] = vs2[i] + imm

    翻译为标量循环:
        for i in range(vl):  # vl 从 CSR 动态读取
            temp = load vs2[i]
            temp = temp + imm
            store vd[i] = temp
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
    vs2 = operands[1]
    imm_str = operands[2]

    # 解析立即数
    try:
        imm_val = int(str(imm_str), 0)
    except ValueError:
        raise InstructionValidationError(insn, f"Invalid immediate for {insn.opcode}: {insn.op_str}")

    vd_offset = allocator.get_offset(vd)
    vs2_offset = allocator.get_offset(vs2)

    sew = state.sew
    element_size = sew // 8
    load_instr = _get_int_instr(sew, 'load')
    store_instr = _get_int_instr(sew, 'store')
    # 标量立即数加法: sew=32 使用 addiw, 其它使用 addi (vadd.vi imm 仅 5-bit, 安全)
    addi_instr = {8: 'addi', 16: 'addi', 32: 'addiw', 64: 'addi'}[sew]

    temps = context.temp_register_allocator
    vl_reg = temps.alloc_gpr()
    csr_addr_reg = temps.alloc_gpr()
    element_offset_reg = temps.alloc_gpr()
    addr_reg = temps.alloc_gpr()
    rhs_value_reg = temps.alloc_gpr()

    lines.append(f"    # {insn.opcode}: {vd}[i] = {vs2}[i] + {imm_val}")

    _emit_load_vl_from_csr(lines, vl_reg=vl_reg, addr_reg=csr_addr_reg)

    loop_label = new_label("vadd_vi")
    lines.append(f"{loop_label}:")
    lines.append(f"    beqz    {vl_reg}, {loop_label}_end")

    # 计算元素偏移
    lines.append(f"    addi    {element_offset_reg}, {vl_reg}, -1")
    skip_label = _maybe_emit_mask_skip_guard(
        lines=lines, insn=insn, new_label=new_label,
        element_index_reg=element_offset_reg,
        mask_chunk_reg=addr_reg, shift_reg=csr_addr_reg,
        label_prefix="vadd_vi_mask_skip",
    )
    _emit_element_shift(lines, element_size, shift_reg=element_offset_reg)

    # 加载 vs2[i]
    lines.append(f"    li      {csr_addr_reg}, {vs2_offset}")
    lines.append(f"    add     {addr_reg}, t6, {csr_addr_reg}")
    lines.append(f"    add     {addr_reg}, {addr_reg}, {element_offset_reg}")
    lines.append(f"    {load_instr:<7} {rhs_value_reg}, 0({addr_reg})")

    # 加立即数 (使用 addi/addiw 直接编码, 无需 imm_reg)
    lines.append(f"    {addi_instr:<7} {rhs_value_reg}, {rhs_value_reg}, {imm_val}")

    # 存储结果
    lines.append(f"    li      {csr_addr_reg}, {vd_offset}")
    lines.append(f"    add     {addr_reg}, t6, {csr_addr_reg}")
    lines.append(f"    add     {addr_reg}, {addr_reg}, {element_offset_reg}")
    lines.append(f"    {store_instr:<7} {rhs_value_reg}, 0({addr_reg})")

    if skip_label is not None:
        lines.append(f"{skip_label}:")
    lines.append(f"    addi    {vl_reg}, {vl_reg}, -1")
    lines.append(f"    j       {loop_label}")

    lines.append(f"{loop_label}_end:")

    return lines


# ============================================================================
# vadd.vx 指令翻译 (整数向量-标量加法)
# ============================================================================

def _build_vadd_vx_lines(context) -> list[str]:
    """
    翻译 vadd.vx 指令 (整数向量-标量加法)

    格式: vadd.vx vd, vs2, rs1
    语义: vd[i] = vs2[i] + rs1

    翻译为标量循环:
        for i in range(vl):
            temp = load vs2[i]
            temp = temp + rs1
            store vd[i] = temp
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
    vs2 = operands[1]
    rs1 = operands[2]

    vd_offset = allocator.get_offset(vd)
    vs2_offset = allocator.get_offset(vs2)

    sew = state.sew
    element_size = sew // 8
    load_instr = _get_int_instr(sew, 'load')
    store_instr = _get_int_instr(sew, 'store')
    add_instr = _get_int_instr(sew, 'add')

    temps = context.temp_register_allocator
    vl_reg = temps.alloc_gpr()
    csr_addr_reg = temps.alloc_gpr()
    element_offset_reg = temps.alloc_gpr()
    addr_reg = temps.alloc_gpr()
    rhs_value_reg = temps.alloc_gpr()
    val_reg = temps.alloc_gpr()

    lines.append(f"    # {insn.opcode}: {vd}[i] = {vs2}[i] + {rs1}")

    # 保存 rs1 到临时寄存器以避免冲突
    lines.append(f"    mv      {val_reg}, {rs1}")

    _emit_load_vl_from_csr(lines, vl_reg=vl_reg, addr_reg=csr_addr_reg)

    loop_label = new_label("vadd_vx")
    lines.append(f"{loop_label}:")
    lines.append(f"    beqz    {vl_reg}, {loop_label}_end")

    # 计算元素偏移
    lines.append(f"    addi    {element_offset_reg}, {vl_reg}, -1")
    skip_label = _maybe_emit_mask_skip_guard(
        lines=lines, insn=insn, new_label=new_label,
        element_index_reg=element_offset_reg,
        mask_chunk_reg=addr_reg, shift_reg=csr_addr_reg,
        label_prefix="vadd_vx_mask_skip",
    )
    _emit_element_shift(lines, element_size, shift_reg=element_offset_reg)

    # 加载 vs2[i]
    lines.append(f"    li      {csr_addr_reg}, {vs2_offset}")
    lines.append(f"    add     {addr_reg}, t6, {csr_addr_reg}")
    lines.append(f"    add     {addr_reg}, {addr_reg}, {element_offset_reg}")
    lines.append(f"    {load_instr:<7} {rhs_value_reg}, 0({addr_reg})")

    # 加 rs1
    lines.append(f"    {add_instr:<7} {rhs_value_reg}, {rhs_value_reg}, {val_reg}")

    # 存储结果
    lines.append(f"    li      {csr_addr_reg}, {vd_offset}")
    lines.append(f"    add     {addr_reg}, t6, {csr_addr_reg}")
    lines.append(f"    add     {addr_reg}, {addr_reg}, {element_offset_reg}")
    lines.append(f"    {store_instr:<7} {rhs_value_reg}, 0({addr_reg})")

    if skip_label is not None:
        lines.append(f"{skip_label}:")
    lines.append(f"    addi    {vl_reg}, {vl_reg}, -1")
    lines.append(f"    j       {loop_label}")

    lines.append(f"{loop_label}_end:")

    return lines


# ============================================================================
# vid.v 指令翻译 (向量索引生成)
# ============================================================================

def _build_vid_v_lines(context) -> list[str]:
    """
    翻译 vid.v 指令 (向量索引生成)

    格式: vid.v vd
    语义: vd[i] = i

    翻译为标量循环:
        for i in range(vl):  # vl 从 CSR 动态读取
            store vd[i] = i
    :return: 生成的汇编代码行列表
    """
    insn = context.instruction
    state = context.state
    allocator = context.layout
    new_label = context.new_label
    lines = []

    operands = insn.operands
    if len(operands) < 1:
        raise InstructionValidationError(insn, f"Invalid operands for {insn.opcode}: {insn.op_str}")

    vd = operands[0]

    vd_offset = allocator.get_offset(vd)
    sew = state.sew
    element_size = sew // 8
    store_instr = _get_int_instr(sew, 'store')

    temps = context.temp_register_allocator
    vl_reg = temps.alloc_gpr()
    csr_addr_reg = temps.alloc_gpr()
    element_offset_reg = temps.alloc_gpr()
    addr_reg = temps.alloc_gpr()
    idx_reg = temps.alloc_gpr()

    lines.append(f"    # {insn.opcode}: {vd}[i] = i")

    _emit_load_vl_from_csr(lines, vl_reg=vl_reg, addr_reg=csr_addr_reg)

    loop_label = new_label("vid_v")
    lines.append(f"{loop_label}:")
    lines.append(f"    beqz    {vl_reg}, {loop_label}_end")

    # 保存索引值 i = vl_reg - 1
    lines.append(f"    addi    {idx_reg}, {vl_reg}, -1           # {idx_reg} = i = vl - 1")
    # 计算字节偏移: i * element_size
    lines.append(f"    addi    {element_offset_reg}, {vl_reg}, -1")
    _emit_element_shift(lines, element_size, shift_reg=element_offset_reg)

    # 存储 vd[i] = i
    lines.append(f"    li      {addr_reg}, {vd_offset}")
    lines.append(f"    add     {addr_reg}, t6, {addr_reg}")
    lines.append(f"    add     {addr_reg}, {addr_reg}, {element_offset_reg}")
    lines.append(f"    {store_instr:<7} {idx_reg}, 0({addr_reg})          # {vd}[i] = i")

    lines.append(f"    addi    {vl_reg}, {vl_reg}, -1")
    lines.append(f"    j       {loop_label}")

    lines.append(f"{loop_label}_end:")

    return lines


# ============================================================================
# vfncvt.f.xu.w 指令翻译 (narrowing unsigned int -> float)
# ============================================================================

def _build_vfncvt_f_xu_w_lines(context) -> list[str]:
    """
    翻译 vfncvt.f.xu.w 指令 (narrowing 无符号整数 -> 浮点)

    格式: vfncvt.f.xu.w vd, vs2
    语义: vd[i] = float(vs2[i]) (输入 SEW*2 无符号整数, 输出 SEW 浮点)

    翻译为标量循环:
        for i in range(vl):
            temp = load uint64(vs2[i])    # ld
            fpr = fcvt.s.lu(temp)         # 64-bit uint -> 32-bit float
            store float32(vd[i]) = fpr    # fsw

    当前支持范围: e64 -> e32 (SEW=32)
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

    if output_sew != 32:
        raise ValueError(
            f"vfncvt.f.xu.w 当前仅支持输出 SEW=32 (e64 -> e32), "
            f"实际为 SEW={state.sew}"
        )

    vd_offset = allocator.get_offset(vd)
    vs2_offset = allocator.get_offset(vs2)

    src_element_size = input_sew // 8     # 8 bytes (ld)
    dst_element_size = output_sew // 8    # 4 bytes (fsw)

    temps = context.temp_register_allocator
    vl_reg = temps.alloc_gpr()
    csr_addr_reg = temps.alloc_gpr()
    src_offset_reg = temps.alloc_gpr()
    dst_offset_reg = temps.alloc_gpr()
    addr_reg = temps.alloc_gpr()
    int_val_reg = temps.alloc_gpr()
    float_val_fpr = temps.alloc_fpr()

    lines.append(f"# vfncvt.f.xu.w {vd}, {vs2} (scalar mode)")
    lines.append(f"# Semantic: {vd}[i] = float({vs2}[i]), e{input_sew} -> e{output_sew}")
    lines.append("")

    _emit_load_vl_from_csr(lines, vl_reg=vl_reg, addr_reg=csr_addr_reg)
    lines.append("")

    loop_label = new_label("vfncvt")
    lines.append(f"{loop_label}:")
    lines.append(f"    beqz    {vl_reg}, {loop_label}_end")
    lines.append("")

    # 计算源偏移 (unsigned int 宽度)
    lines.append("    # 计算源偏移 (uint64)")
    lines.append(f"    addi    {src_offset_reg}, {vl_reg}, -1")
    skip_label = _maybe_emit_mask_skip_guard(
        lines=lines, insn=insn, new_label=new_label,
        element_index_reg=src_offset_reg,
        mask_chunk_reg=addr_reg, shift_reg=csr_addr_reg,
        label_prefix="vfncvt_mask_skip",
    )
    _emit_element_shift(lines, src_element_size, shift_reg=src_offset_reg)

    # 计算目标偏移 (float 宽度)
    lines.append("    # 计算目标偏移 (float32)")
    lines.append(f"    addi    {dst_offset_reg}, {vl_reg}, -1")
    _emit_element_shift(lines, dst_element_size, shift_reg=dst_offset_reg)

    # 加载 unsigned int 源
    lines.append("")
    lines.append(f"    # 加载 {vs2}[i] (uint64)")
    lines.append(f"    li      {csr_addr_reg}, {vs2_offset}")
    lines.append(f"    add     {addr_reg}, t6, {csr_addr_reg}")
    lines.append(f"    add     {addr_reg}, {addr_reg}, {src_offset_reg}")
    lines.append(f"    ld      {int_val_reg}, 0({addr_reg})")

    # 转换为 float (32-bit)
    lines.append("")
    lines.append(f"    # 转换为 float32 (fcvt.s.lu)")
    lines.append(f"    fcvt.s.lu {float_val_fpr}, {int_val_reg}")

    # 存储 float 结果
    lines.append("")
    lines.append(f"    # 写回 {vd}[i] (float32)")
    lines.append(f"    li      {csr_addr_reg}, {vd_offset}")
    lines.append(f"    add     {addr_reg}, t6, {csr_addr_reg}")
    lines.append(f"    add     {addr_reg}, {addr_reg}, {dst_offset_reg}")
    lines.append(f"    fsw     {float_val_fpr}, 0({addr_reg})")

    lines.append("")
    if skip_label is not None:
        lines.append(f"{skip_label}:")
    lines.append(f"    addi    {vl_reg}, {vl_reg}, -1")
    lines.append(f"    j       {loop_label}")
    lines.append("")
    lines.append(f"{loop_label}_end:")

    return lines


def _emit_element_address(
    lines: List[str], offset: int, index: str, size: int, address: str, scratch: str
) -> None:
    lines.append(f"    mv      {scratch}, {index}")
    _emit_element_shift(lines, size, shift_reg=scratch)
    lines.extend((
        f"    li      {address}, {offset}",
        f"    add     {address}, t6, {address}",
        f"    add     {address}, {address}, {scratch}",
    ))


def _integer_immediate(operand: str, *, unsigned: bool = False) -> int:
    value = int(operand, 0)
    low, high = (0, 31) if unsigned else (-16, 15)
    if not low <= value <= high:
        raise ValueError(f"Immediate must be in [{low}, {high}]: {operand}")
    return value


def _build_integer_lines(context) -> list[str]:
    """Lower bit operations, extension and integer multiply-accumulate."""
    insn, state, layout = context.instruction, context.state, context.layout
    op = insn.opcode
    operands = insn.operands
    sew = state.sew
    source_sew = sew // 2 if op == "vzext.vf2" else sew
    destination_sew = sew * 2 if op == "vwmacc.vv" else sew
    if source_sew not in SUPPORTED_INT_SEW or destination_sew not in SUPPORTED_INT_SEW:
        raise ValueError(f"{op} does not support SEW={sew}")
    source = operands[2] if op == "vmacc.vx" else operands[1]
    vector_rhs = op in ("vor.vv", "vwmacc.vv")
    sources = [(source, source_sew)]
    if vector_rhs:
        sources.append((operands[2], source_sew))
    _validate_vector_groups(context, destination_sew, sources)

    immediate = None
    if op.endswith(".vi"):
        immediate = _integer_immediate(operands[2], unsigned=op != "vand.vi")
    scalar = operands[1] if op == "vmacc.vx" else operands[2] if op.endswith(".vx") else None
    unsigned_load = op in ("vsrl.vi", "vsrl.vx", "vzext.vf2")
    load = ({8: "lbu", 16: "lhu", 32: "lwu", 64: "ld"}[source_sew]
            if unsigned_load else _get_int_instr(source_sew, "load"))
    store = _get_int_instr(destination_sew, "store")
    temps = context.temp_register_allocator
    vl, index, scratch, address, value, rhs = (temps.alloc_gpr() for _ in range(6))
    lines = [f"    # {op} {insn.op_str}"]
    _emit_load_vl_from_csr(lines, vl, address)
    loop = context.new_label(op.replace('.', '_'))
    # Forward traversal preserves narrow sources in the high part of a legal
    # overlapping widening destination. Read both sources before writing vd.
    lines.extend((f"    li      {index}, 0", f"{loop}:", f"    bgeu    {index}, {vl}, {loop}_end"))
    skip = _maybe_emit_mask_skip_guard(
        lines, insn, context.new_label, index, address, scratch, "integer_mask_skip"
    )
    _emit_element_address(lines, layout.get_offset(source), index, source_sew // 8, address, scratch)
    lines.append(f"    {load:<7} {value}, 0({address})")
    if vector_rhs:
        _emit_element_address(lines, layout.get_offset(operands[2]), index, source_sew // 8, address, scratch)
        lines.append(f"    {load:<7} {rhs}, 0({address})")

    if op == "vand.vi":
        lines.append(f"    andi    {value}, {value}, {immediate}")
    elif op == "vor.vv":
        lines.append(f"    or      {value}, {value}, {rhs}")
    elif op in ("vsll.vi", "vsrl.vi"):
        shift = "slli" if op == "vsll.vi" else "srli"
        lines.append(f"    {shift:<7} {value}, {value}, {immediate & (sew - 1)}")
    elif op == "vsrl.vx":
        lines.extend((f"    andi    {rhs}, {scalar}, {sew - 1}", f"    srl     {value}, {value}, {rhs}"))
    elif op == "vsub.vx":
        lines.append(f"    sub     {value}, {value}, {scalar}")
    elif op in ("vmacc.vx", "vwmacc.vv"):
        lines.append(f"    mul     {value}, {value}, {scalar if scalar else rhs}")

    _emit_element_address(lines, layout.get_offset(operands[0]), index, destination_sew // 8, address, scratch)
    if op in ("vmacc.vx", "vwmacc.vv"):
        lines.extend((
            f"    {_get_int_instr(destination_sew, 'load'):<7} {rhs}, 0({address})",
            f"    add     {value}, {value}, {rhs}",
        ))
    lines.append(f"    {store:<7} {value}, 0({address})")
    if skip:
        lines.append(f"{skip}:")
    lines.extend((f"    addi    {index}, {index}, 1", f"    j       {loop}", f"{loop}_end:"))
    return lines


def _build_vmseq_vi_lines(context) -> list[str]:
    """Write individual mask bits without disturbing adjacent or tail bits."""
    insn, state, layout = context.instruction, context.state, context.layout
    vd, vs2, immediate = insn.operands[:3]
    immediate = _integer_immediate(immediate)
    _validate_vector_groups(context, 1, ((vs2, state.sew),))
    temps = context.temp_register_allocator
    vl, index, scratch, address, value, bit, old = (temps.alloc_gpr() for _ in range(7))
    lines = [f"    # {insn.opcode} {insn.op_str}"]
    _emit_load_vl_from_csr(lines, vl, address)
    loop = context.new_label("vmseq_vi")
    # Forward traversal also permits the mask destination to overlap the low
    # part of vs2: an updated mask byte can only cover source elements read.
    lines.extend((f"    li      {index}, 0", f"{loop}:", f"    bgeu    {index}, {vl}, {loop}_end"))
    skip = _maybe_emit_mask_skip_guard(
        lines, insn, context.new_label, index, address, scratch, "compare_mask_skip"
    )
    _emit_element_address(lines, layout.get_offset(vs2), index, state.sew // 8, address, scratch)
    lines.extend((
        f"    {_get_int_instr(state.sew, 'load'):<7} {value}, 0({address})",
        f"    addi    {value}, {value}, {-immediate}",
        f"    seqz    {value}, {value}",
        f"    andi    {scratch}, {index}, 7",
        f"    li      {bit}, 1",
        f"    sll     {bit}, {bit}, {scratch}",
        f"    sll     {value}, {value}, {scratch}",
        f"    srli    {scratch}, {index}, 3",
        f"    li      {address}, {layout.get_offset(vd)}",
        f"    add     {address}, t6, {address}",
        f"    add     {address}, {address}, {scratch}",
        f"    lbu     {old}, 0({address})",
        f"    not     {bit}, {bit}",
        f"    and     {old}, {old}, {bit}",
        f"    or      {old}, {old}, {value}",
        f"    sb      {old}, 0({address})",
    ))
    if skip:
        lines.append(f"{skip}:")
    lines.extend((f"    addi    {index}, {index}, 1", f"    j       {loop}", f"{loop}_end:"))
    return lines


def _emit_fp16_to_fp32(
    lines: List[str], new_label, value: str, sign: str, exponent: str, fraction: str
) -> None:
    """Exact binary16 widening using RV64GC, including canonical NaN and NV."""
    label = new_label("fp16_widen")
    lines.extend((
        f"    srli    {sign}, {value}, 15",
        f"    slli    {sign}, {sign}, 31",
        f"    srli    {exponent}, {value}, 10",
        f"    andi    {exponent}, {exponent}, 31",
        f"    andi    {fraction}, {value}, 1023",
        f"    beqz    {exponent}, {label}_subnormal",
        f"    li      {value}, 31",
        f"    beq     {exponent}, {value}, {label}_special",
        f"    addi    {exponent}, {exponent}, 112",
        f"    j       {label}_pack",
        f"{label}_subnormal:",
        f"    li      {value}, 0",
        f"    beqz    {fraction}, {label}_signed",
        f"    li      {exponent}, 113",
        f"{label}_normalize:",
        f"    andi    {value}, {fraction}, 1024",
        f"    bnez    {value}, {label}_normalized",
        f"    slli    {fraction}, {fraction}, 1",
        f"    addi    {exponent}, {exponent}, -1",
        f"    j       {label}_normalize",
        f"{label}_normalized:",
        f"    andi    {fraction}, {fraction}, 1023",
        f"{label}_pack:",
        f"    slli    {exponent}, {exponent}, 23",
        f"    slli    {fraction}, {fraction}, 13",
        f"    or      {value}, {sign}, {exponent}",
        f"    or      {value}, {value}, {fraction}",
        f"    j       {label}_end",
        f"{label}_special:",
        f"    li      {value}, 0x7f800000",
        f"    beqz    {fraction}, {label}_signed",
        f"    andi    {exponent}, {fraction}, 512",
        f"    bnez    {exponent}, {label}_nan",
        "    csrsi   fflags, 16",
        f"{label}_nan:",
        f"    li      {value}, 0x7fc00000",
        f"    j       {label}_end",
        f"{label}_signed:",
        f"    or      {value}, {value}, {sign}",
        f"{label}_end:",
    ))


def _build_float_conversion_lines(context) -> list[str]:
    insn, state, layout = context.instruction, context.state, context.layout
    widening = insn.opcode == "vfwcvt.f.f.v"
    if state.sew not in ((16, 32) if widening else (32, 64)):
        raise ValueError(f"{insn.opcode} does not support SEW={state.sew}")
    destination_sew = state.sew * 2 if widening else state.sew
    vd, vs2 = insn.operands[:2]
    _validate_vector_groups(context, destination_sew, ((vs2, state.sew),))
    temps = context.temp_register_allocator
    vl, index, scratch, address, value = (temps.alloc_gpr() for _ in range(5))
    half = widening and state.sew == 16
    if half:
        sign, exponent, fraction = (temps.alloc_gpr() for _ in range(3))
    else:
        fp = temps.alloc_fpr()
    lines = [f"    # {insn.opcode} {insn.op_str}"]
    _emit_load_vl_from_csr(lines, vl, address)
    loop = context.new_label("float_convert")
    lines.extend((f"    li      {index}, 0", f"{loop}:", f"    bgeu    {index}, {vl}, {loop}_end"))
    skip = _maybe_emit_mask_skip_guard(
        lines, insn, context.new_label, index, address, scratch, "convert_mask_skip"
    )
    _emit_element_address(lines, layout.get_offset(vs2), index, state.sew // 8, address, scratch)
    if half:
        lines.append(f"    lhu     {value}, 0({address})")
        _emit_fp16_to_fp32(lines, context.new_label, value, sign, exponent, fraction)
    elif widening:
        lines.extend((f"    flw     {fp}, 0({address})", f"    fcvt.d.s {fp}, {fp}"))
    else:
        conversion = "fcvt.s.w" if state.sew == 32 else "fcvt.d.l"
        lines.extend((
            f"    {_get_int_instr(state.sew, 'load'):<7} {value}, 0({address})",
            f"    {conversion} {fp}, {value}",
        ))
    _emit_element_address(lines, layout.get_offset(vd), index, destination_sew // 8, address, scratch)
    if half:
        lines.append(f"    sw      {value}, 0({address})")
    else:
        lines.append(f"    {_get_float_instr('store', destination_sew):<7} {fp}, 0({address})")
    if skip:
        lines.append(f"{skip}:")
    lines.extend((f"    addi    {index}, {index}, 1", f"    j       {loop}", f"{loop}_end:"))
    return lines
