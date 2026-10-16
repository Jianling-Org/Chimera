# src/riscv/extensions/rvv/backends/scalar/handlers/memory.py
"""
RVV 内存指令翻译模块

将 RVV 向量内存指令翻译为标量 RISC-V 汇编代码

支持的指令:
- vle64.v: 向量加载 (Vector Load Element, 64-bit)
- vse64.v: 向量存储 (Vector Store Element, 64-bit)
- vle32.v: 向量加载 (32-bit)
- vse32.v: 向量存储 (32-bit)
- vlse64.v / vsse64.v: 带步长加载/存储 (64-bit)
- vlse32.v / vsse32.v: 带步长加载/存储 (32-bit)

翻译策略:
- 从 CSR 动态读取 vl
- 使用标量循环逐元素搬运
- 内存地址由通用寄存器提供
- 向量数据存储在 simulated_cpu_state 内存块中
"""

from typing import List
from riscv.extensions.rvv.backends.scalar.support import (
    _emit_element_shift,
    _parse_vector_register_number,
    _maybe_emit_mask_skip_guard,
    _validate_vector_groups,
)
from riscv.frontend.model import RVInstruction
from riscv.extensions.rvv.analysis.config import StateTracker
from riscv.extensions.rvv.runtime.layout import SimulatedStateLayout
from riscv.extensions.rvv.translation.contracts import InstructionValidationError
from riscv.extensions.rvv.runtime.layout import CSR_OFFSETS
from riscv.extensions.rvv.translation.temps import TempRegisterAllocator


# ============================================================================
# 辅助函数 (复用 rvv_arithmetic.py 的模式)
# ============================================================================

# 支持的 SEW 值
SUPPORTED_SEW = {8, 16, 32, 64}


def _validate_sew(sew: int) -> None:
    """验证 SEW 值是否有效"""
    if sew not in SUPPORTED_SEW:
        raise ValueError(f"不支持的 SEW 值: {sew} (支持: {SUPPORTED_SEW})")


def _get_float_load_instr(sew: int) -> str:
    return {32: "flw", 64: "fld"}[sew]


def _get_float_store_instr(sew: int) -> str:
    return {32: "fsw", 64: "fsd"}[sew]


def _get_int_load_instr(sew: int) -> str:
    """
    根据 SEW 返回整数加载指令

    用于整数向量指令 (vle8/16/32.v)
    - 64-bit: ld (64位)
    - 32-bit: lw (32位，符号扩展)
    - 16-bit: lh (16位，符号扩展)
    - 8-bit:  lb (8位，符号扩展)
    """
    _validate_sew(sew)
    if sew == 64:
        return 'ld'
    elif sew == 32:
        return 'lw'
    elif sew == 16:
        return 'lh'
    else:  # sew == 8
        return 'lb'


def _get_int_store_instr(sew: int) -> str:
    """
    根据 SEW 返回整数存储指令

    用于整数向量指令 (vse8/16/32.v)
    - 64-bit: sd (64位)
    - 32-bit: sw (32位)
    - 16-bit: sh (16位)
    - 8-bit:  sb (8位)
    """
    _validate_sew(sew)
    if sew == 64:
        return 'sd'
    elif sew == 32:
        return 'sw'
    elif sew == 16:
        return 'sh'
    else:  # sew == 8
        return 'sb'




def _emit_load_vl_from_csr(
    lines: List[str],
    vl_reg: str = "t0",
    addr_reg: str = "t1"
) -> None:
    """
    从 CSR 加载 `vl` 到指定寄存器。

    之所以把目标寄存器和地址寄存器都参数化，是因为内存类 handler
    需要避免与指令语义中已经出现的 `t*` 寄存器发生硬冲突。
    """
    vl_offset = CSR_OFFSETS['vl']
    lines.append("    # 从 CSR 加载 vl")
    lines.append(f"    li      {addr_reg}, {vl_offset}")
    lines.append(f"    add     {addr_reg}, t6, {addr_reg}")
    lines.append(f"    ld      {vl_reg}, 0({addr_reg})  # {vl_reg} = vl (from CSR)")






def _get_segment_group_offsets(
    base_reg: str,
    state: StateTracker,
    allocator: SimulatedStateLayout,
    segment_count: int,
    eew: int,
) -> List[int]:
    """Locate fields by source EMUL; fractional fields still start in separate registers."""
    emul = state.lmul * eew / state.sew
    group_regs = max(1, int(emul))
    base_num = _parse_vector_register_number(base_reg)
    if (emul < 0.125 or emul * segment_count > 8 or base_num % group_regs
            or base_num + segment_count * group_regs > 32):
        raise ValueError(f"Invalid NF={segment_count}/EMUL={emul:g} register group: {base_reg}")
    return [
        allocator.get_offset(f"v{base_num + index * group_regs}")
        for index in range(segment_count)
    ]


def _parse_memory_operands(
    insn: RVInstruction,
    expect_stride: bool
) -> tuple[str, str | None]:
    """
    解析内存类指令中的 base / stride 操作数。

    支持格式：
    - `vd, (rs1)` 或 `vs3, (rs1)`
    - `vd, (rs1), rs2` 或 `vs3, (rs1), rs2`
    """
    operands = [str(operand).strip() for operand in insn.operands]
    op_str = insn.op_str

    rs1 = None
    rs2 = None

    if '(' in op_str:
        start = op_str.rfind('(') + 1
        end = op_str.rfind(')')
        rs1 = op_str[start:end].strip()

        if expect_stride:
            # 这里必须优先相信结构化 `operands`，不能再从 `op_str` 的最后一段去取。
            #
            # 原因是 masked form 会把 `v0.t` 放到最后一个逗号字段：
            # - `vlse32.v v8, (a0), a1, v0.t`
            # - 如果继续用 `parts[-1]`，就会把 `v0.t` 错认成 stride；
            # - 而 parser 已经把 stride 稳定地放在 `operands[2]`。
            if len(operands) >= 3:
                rs2 = operands[2].strip()
    else:
        if len(operands) >= 2:
            rs1 = operands[1].strip()
        if expect_stride and len(operands) >= 3:
            rs2 = operands[2].strip()

    if not rs1:
        raise ValueError(f"无法解析 base address: {insn.opcode} {insn.op_str}")
    if expect_stride and not rs2:
        raise ValueError(f"无法解析 stride operand: {insn.opcode} {insn.op_str}")

    return rs1, rs2




# ============================================================================
# vle64.v 指令翻译 (向量加载)
# ============================================================================

def _emit_vle_v(
    insn: RVInstruction,
    state: StateTracker,
    allocator: SimulatedStateLayout,
    new_label,
    is_float: bool = False,
    sew: int = 64
) -> List[str]:
    """
    通用的向量加载翻译函数

    :param insn: 指令
    :param state: 当前向量状态
    :param allocator: 寄存器分配器
    :param new_label: 本轮标签分配函数
    :param is_float: 是否使用浮点指令
    :param sew: 元素宽度 (8/16/32/64)
    :return: 生成的汇编代码行列表
    """
    lines = []

    # 解析操作数
    operands = insn.operands
    if len(operands) < 2:
        raise InstructionValidationError(insn, f"Invalid operands for {insn.opcode}: {insn.op_str}")

    vd = operands[0]
    try:
        rs1, _ = _parse_memory_operands(insn, expect_stride=False)
    except ValueError:
        raise InstructionValidationError(insn, f"Cannot parse memory operand for {insn.opcode}: {insn.op_str}")

    # 获取偏移量
    vd_offset = allocator.get_offset(vd)
    element_size = sew // 8

    # 这里不能再直接写死 `t0/t2/t3/t4/t5`：
    # - `rs1` 本身就可能是 `t3/t4/t5`；
    # - 如果继续硬编码这些寄存器为地址或数据 temp，
    #   会在块内部先把真实的 base address 覆盖掉。
    temps = TempRegisterAllocator(insn, reserved_gprs=("t6",))
    vl_reg = temps.alloc_gpr()
    csr_addr_reg = temps.alloc_gpr()
    element_offset_reg = temps.alloc_gpr()
    addr_reg = temps.alloc_gpr()

    # 根据 is_float 选择加载/存储指令
    if is_float:
        load_instr = _get_float_load_instr(sew)
        store_instr = _get_float_store_instr(sew)
        data_reg = temps.alloc_fpr()
    else:
        load_instr = _get_int_load_instr(sew)
        store_instr = _get_int_store_instr(sew)
        data_reg = temps.alloc_gpr()

    lines.append(f"    # {insn.opcode}: {vd} = mem[{rs1}]")

    # 从 CSR 加载 vl
    _emit_load_vl_from_csr(lines, vl_reg=vl_reg, addr_reg=csr_addr_reg)

    # 循环体
    loop_label = new_label(insn.opcode.replace('.', '_'))
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
        label_prefix=f"{insn.opcode.replace('.', '_')}_mask_skip",
    )
    _emit_element_shift(lines, element_size=element_size, shift_reg=element_offset_reg)

    # Keep a guest t6 base in the second source position so VectorBlockEmitter
    # can distinguish it from the internal `add address, t6, offset` form.
    lines.append(f"    add     {addr_reg}, {element_offset_reg}, {rs1}")
    lines.append(f"    {load_instr:<7} {data_reg}, 0({addr_reg})")

    # 这里复用 `csr_addr_reg` 和 `addr_reg` 计算向量寄存器写回地址，
    # 避免引入更多无谓的 scratch 寄存器。
    lines.append(f"    li      {csr_addr_reg}, {vd_offset}")
    lines.append(f"    add     {addr_reg}, t6, {csr_addr_reg}")
    lines.append(f"    add     {addr_reg}, {addr_reg}, {element_offset_reg}")
    lines.append(f"    {store_instr:<7} {data_reg}, 0({addr_reg})")

    # 更新循环计数器
    if skip_label is not None:
        lines.append(f"{skip_label}:")
    lines.append(f"    addi    {vl_reg}, {vl_reg}, -1")
    lines.append(f"    j       {loop_label}")

    # 循环结束
    lines.append(f"{loop_label}_end:")

    return lines


def _build_vle64_v_lines(context) -> list[str]:
    """
    翻译 vle64.v 指令 (向量加载, 64-bit)

    格式: vle64.v vd, (rs1), vm
    语义: for i in range(vl): vd[i] = mem[rs1 + i*8]

    :return: 生成的汇编代码行列表
    """
    # 汇编 builder 只从结构化上下文读取本轮对象；plan 保留已经验证的
    # 操作数和规格，禁止重新接受旧四参数 handler 调用。vle64 在本后端
    # 历史合同中固定使用浮点搬运 (fld/fsd，见 daxpy/ddot 集成断言)，
    # 因此显式传入参数，不继承 _emit_vle_v 的整数默认值。
    insn = context.instruction
    state = context.state
    allocator = context.layout
    new_label = context.new_label
    return _emit_vle_v(
        insn, state, allocator, new_label, is_float=True, sew=64
    )


# ============================================================================
# vse64.v 指令翻译 (向量存储)
# ============================================================================

def _emit_vse_v(
    insn: RVInstruction,
    state: StateTracker,
    allocator: SimulatedStateLayout,
    new_label,
    is_float: bool = False,
    sew: int = 64
) -> List[str]:
    """
    通用的向量存储翻译函数

    :param insn: 指令
    :param state: 当前向量状态
    :param allocator: 寄存器分配器
    :param new_label: 本轮标签分配函数
    :param is_float: 是否使用浮点指令
    :param sew: 元素宽度 (8/16/32/64)
    :return: 生成的汇编代码行列表
    """
    lines = []

    # 解析操作数
    operands = insn.operands
    if len(operands) < 2:
        raise InstructionValidationError(insn, f"Invalid operands for {insn.opcode}: {insn.op_str}")

    vs3 = operands[0]
    try:
        rs1, _ = _parse_memory_operands(insn, expect_stride=False)
    except ValueError:
        raise InstructionValidationError(insn, f"Cannot parse memory operand for {insn.opcode}: {insn.op_str}")

    # 获取偏移量
    vs3_offset = allocator.get_offset(vs3)
    element_size = sew // 8

    # `vse*` 也存在同样的问题：`rs1` 完全可能是某个 `t*`，
    # 因此地址寄存器和数据寄存器都必须动态选择。
    temps = TempRegisterAllocator(insn, reserved_gprs=("t6",))
    vl_reg = temps.alloc_gpr()
    csr_addr_reg = temps.alloc_gpr()
    element_offset_reg = temps.alloc_gpr()
    addr_reg = temps.alloc_gpr()

    # 根据 is_float 选择加载/存储指令
    if is_float:
        load_instr = _get_float_load_instr(sew)
        store_instr = _get_float_store_instr(sew)
        data_reg = temps.alloc_fpr()
    else:
        load_instr = _get_int_load_instr(sew)
        store_instr = _get_int_store_instr(sew)
        data_reg = temps.alloc_gpr()

    lines.append(f"    # {insn.opcode}: mem[{rs1}] = {vs3}")

    # 从 CSR 加载 vl
    _emit_load_vl_from_csr(lines, vl_reg=vl_reg, addr_reg=csr_addr_reg)

    # 循环体
    loop_label = new_label(insn.opcode.replace('.', '_'))
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
        label_prefix=f"{insn.opcode.replace('.', '_')}_mask_skip",
    )
    _emit_element_shift(lines, element_size=element_size, shift_reg=element_offset_reg)

    # 从向量寄存器加载
    lines.append(f"    li      {csr_addr_reg}, {vs3_offset}")
    lines.append(f"    add     {addr_reg}, t6, {csr_addr_reg}")
    lines.append(f"    add     {addr_reg}, {addr_reg}, {element_offset_reg}")
    lines.append(f"    {load_instr:<7} {data_reg}, 0({addr_reg})")

    # 存储到内存
    lines.append(f"    add     {addr_reg}, {element_offset_reg}, {rs1}")
    lines.append(f"    {store_instr:<7} {data_reg}, 0({addr_reg})")

    # 更新循环计数器
    if skip_label is not None:
        lines.append(f"{skip_label}:")
    lines.append(f"    addi    {vl_reg}, {vl_reg}, -1")
    lines.append(f"    j       {loop_label}")

    # 循环结束
    lines.append(f"{loop_label}_end:")

    return lines




def _build_vse64_v_lines(context) -> list[str]:
    """
    翻译 vse64.v 指令 (向量存储, 64-bit)

    :return: 生成的汇编代码行列表
    """
    # 同 vle64：SEW=64 固定使用 fsd 写回，显式传参避免依赖默认值。
    insn = context.instruction
    state = context.state
    allocator = context.layout
    new_label = context.new_label
    return _emit_vse_v(
        insn, state, allocator, new_label, is_float=True, sew=64
    )


# ============================================================================
# 32-bit 变体 (vle32.v / vse32.v)
# ============================================================================

def _build_narrow_load_lines(context) -> list[str]:
    """EEW is encoded by the load, independently of the current SEW."""
    eew = {"vle8.v": 8, "vle16.v": 16}[context.instruction.opcode]
    _validate_vector_groups(context, eew, ())
    return _emit_vle_v(
        context.instruction, context.state, context.layout, context.new_label, sew=eew
    )


def _build_vle32_v_lines(context) -> list[str]:
    """
    翻译 vle32.v 指令 (32-bit 整数向量加载)

    使用整数寄存器和 lw 指令（而非浮点寄存器）
    :return: 生成的汇编代码行列表
    """
    insn = context.instruction
    state = context.state
    allocator = context.layout
    new_label = context.new_label
    return _emit_vle_v(insn, state, allocator, new_label, is_float=False, sew=32)


def _build_vse32_v_lines(context) -> list[str]:
    """
    翻译 vse32.v 指令 (32-bit 整数向量存储)

    使用整数寄存器和 sw 指令（而非浮点寄存器）
    :return: 生成的汇编代码行列表
    """
    insn = context.instruction
    state = context.state
    allocator = context.layout
    new_label = context.new_label
    return _emit_vse_v(insn, state, allocator, new_label, is_float=False, sew=32)


# ============================================================================
# Stride 加载/存储 (vlse64.v / vsse64.v)
# ============================================================================

def _emit_vlse_v(
    insn: RVInstruction,
    state: StateTracker,
    allocator: SimulatedStateLayout,
    new_label,
    sew: int = 64
) -> List[str]:
    """
    通用的 stride 向量加载翻译函数

    格式: vlse64.v vd, (rs1), rs2
    语义: for i in range(vl): vd[i] = mem[rs1 + rs2 * i]

    QEMU vector_helper.c 语义:
        for (i = env->vstart; i < env->vl; i++) {
            addr = base + stride * i;
            vd[i] = mem[addr];
        }

    :param insn: 指令
    :param state: 当前向量状态
    :param allocator: 寄存器分配器
    :param new_label: 本轮标签分配函数
    :param sew: 元素宽度 (默认 64)
    :return: 生成的汇编代码行列表
    """
    lines = []

    # 解析操作数: vd, (rs1), rs2
    operands = insn.operands
    if len(operands) < 3:
        raise InstructionValidationError(insn, f"Invalid operands for {insn.opcode}: {insn.op_str}")

    vd = operands[0]
    try:
        rs1, rs2 = _parse_memory_operands(insn, expect_stride=True)
    except ValueError:
        raise InstructionValidationError(insn, f"Cannot parse operands for {insn.opcode}: {insn.op_str}")

    # 获取偏移量
    vd_offset = allocator.get_offset(vd)
    element_size = sew // 8
    load_instr = _get_int_load_instr(sew)

    # `vlse*` 需要额外处理 stride，因此比 unit-stride 多一个寄存器压力点。
    # 这里的关键是：
    # - 避免把 `rs1` / `rs2` 自己拿来当中间值；
    # - 同时尽量复用地址寄存器，压低 scratch 数量。
    temps = TempRegisterAllocator(insn, reserved_gprs=("t6",))
    vl_reg = temps.alloc_gpr()
    data_reg = temps.alloc_gpr()
    index_reg = temps.alloc_gpr()
    addr_reg = temps.alloc_gpr()

    # 生成注释
    lines.append(f"    # {insn.opcode}: {vd} = mem[{rs1} + {rs2} * i]")

    # 从 CSR 加载 vl
    _emit_load_vl_from_csr(lines, vl_reg=vl_reg, addr_reg=data_reg)

    # 循环体
    loop_label = new_label(insn.opcode.replace('.', '_'))
    lines.append(f"{loop_label}:")
    lines.append(f"    beqz    {vl_reg}, {loop_label}_end")

    # 计算元素索引 i = t0 - 1
    lines.append(f"    addi    {index_reg}, {vl_reg}, -1")
    skip_label = _maybe_emit_mask_skip_guard(
        lines=lines,
        insn=insn,
        new_label=new_label,
        element_index_reg=index_reg,
        mask_chunk_reg=addr_reg,
        shift_reg=data_reg,
        label_prefix=f"{insn.opcode.replace('.', '_')}_mask_skip",
    )

    # 计算地址: rs1 + stride * i
    # 注意: stride * i，不是元素大小 * i
    lines.append(f"    mul     {addr_reg}, {index_reg}, {rs2}    # {addr_reg} = i * stride")

    # 加载 from memory
    lines.append(f"    add     {addr_reg}, {addr_reg}, {rs1}")
    lines.append(f"    {load_instr:<7} {data_reg}, 0({addr_reg})")

    # 存储到向量寄存器 vd[i]
    lines.append(f"    li      {addr_reg}, {vd_offset}")
    lines.append(f"    add     {addr_reg}, t6, {addr_reg}")
    # 计算向量内的字节偏移: i * element_size
    lines.append(f"    addi    {index_reg}, {vl_reg}, -1")
    _emit_element_shift(lines, element_size=element_size, shift_reg=index_reg)
    lines.append(f"    add     {addr_reg}, {addr_reg}, {index_reg}")
    lines.append(f"    {_get_int_store_instr(sew):<7} {data_reg}, 0({addr_reg})")

    # 更新循环计数器
    if skip_label is not None:
        lines.append(f"{skip_label}:")
    lines.append(f"    addi    {vl_reg}, {vl_reg}, -1")
    lines.append(f"    j       {loop_label}")

    lines.append(f"{loop_label}_end:")

    return lines


def _emit_vsse_v(
    insn: RVInstruction,
    state: StateTracker,
    allocator: SimulatedStateLayout,
    new_label,
    sew: int = 64
) -> List[str]:
    """
    通用的 stride 向量存储翻译函数

    格式: vsse64.v vs3, (rs1), rs2
    语义: for i in range(vl): mem[rs1 + rs2 * i] = vs3[i]

    QEMU vector_helper.c 语义:
        for (i = env->vstart; i < env->vl; i++) {
            addr = base + stride * i;
            mem[addr] = vs3[i];
        }

    :param insn: 指令
    :param state: 当前向量状态
    :param allocator: 寄存器分配器
    :param new_label: 本轮标签分配函数
    :param sew: 元素宽度 (默认 64)
    :return: 生成的汇编代码行列表
    """
    lines = []

    # 解析操作数: vs3, (rs1), rs2
    operands = insn.operands
    if len(operands) < 3:
        raise InstructionValidationError(insn, f"Invalid operands for {insn.opcode}: {insn.op_str}")

    vs3 = operands[0]
    try:
        rs1, rs2 = _parse_memory_operands(insn, expect_stride=True)
    except ValueError:
        raise InstructionValidationError(insn, f"Cannot parse operands for {insn.opcode}: {insn.op_str}")

    # 获取偏移量
    vs3_offset = allocator.get_offset(vs3)
    element_size = sew // 8
    load_instr = _get_int_load_instr(sew)
    store_instr = _get_int_store_instr(sew)

    # `vsse*` 的风险点与 `vlse*` 相同：
    # - base / stride 很可能落在 `t*`；
    # - 如果内部继续硬编码 `t3/t4/t5`，就会破坏原始语义寄存器。
    temps = TempRegisterAllocator(insn, reserved_gprs=("t6",))
    vl_reg = temps.alloc_gpr()
    data_reg = temps.alloc_gpr()
    index_reg = temps.alloc_gpr()
    addr_reg = temps.alloc_gpr()

    # 生成注释
    lines.append(f"    # {insn.opcode}: mem[{rs1} + {rs2} * i] = {vs3}")

    # 从 CSR 加载 vl
    _emit_load_vl_from_csr(lines, vl_reg=vl_reg, addr_reg=data_reg)

    # 循环体
    loop_label = new_label(insn.opcode.replace('.', '_'))
    lines.append(f"{loop_label}:")
    lines.append(f"    beqz    {vl_reg}, {loop_label}_end")

    # 计算元素索引
    lines.append(f"    addi    {index_reg}, {vl_reg}, -1")
    skip_label = _maybe_emit_mask_skip_guard(
        lines=lines,
        insn=insn,
        new_label=new_label,
        element_index_reg=index_reg,
        mask_chunk_reg=addr_reg,
        shift_reg=data_reg,
        label_prefix=f"{insn.opcode.replace('.', '_')}_mask_skip",
    )

    # 从向量寄存器 vs3[i] 加载
    lines.append(f"    li      {addr_reg}, {vs3_offset}")
    lines.append(f"    add     {addr_reg}, t6, {addr_reg}")
    # 计算向量内的字节偏移
    lines.append(f"    mv      {data_reg}, {index_reg}")
    _emit_element_shift(lines, element_size=element_size, shift_reg=data_reg)
    lines.append(f"    add     {addr_reg}, {addr_reg}, {data_reg}")
    lines.append(f"    {load_instr:<7} {data_reg}, 0({addr_reg})    # {data_reg} = vs3[i]")

    # 计算内存地址: rs1 + stride * i
    lines.append(f"    mul     {addr_reg}, {index_reg}, {rs2}    # {addr_reg} = i * stride")
    lines.append(f"    add     {addr_reg}, {addr_reg}, {rs1}")

    # 存储到内存
    lines.append(f"    {store_instr:<7} {data_reg}, 0({addr_reg})")

    # 更新循环计数器
    if skip_label is not None:
        lines.append(f"{skip_label}:")
    lines.append(f"    addi    {vl_reg}, {vl_reg}, -1")
    lines.append(f"    j       {loop_label}")

    lines.append(f"{loop_label}_end:")

    return lines


def _build_vlse64_v_lines(context) -> list[str]:
    """
    翻译 vlse64.v 指令 (带步长的向量加载, 64-bit)

    格式: vlse64.v vd, (rs1), rs2
    语义: for i in range(vl): vd[i] = mem[rs1 + rs2 * i]
    :return: 生成的汇编代码行列表
    """
    insn = context.instruction
    state = context.state
    allocator = context.layout
    new_label = context.new_label
    return _emit_vlse_v(insn, state, allocator, new_label, sew=64)


def _build_vsse64_v_lines(context) -> list[str]:
    """
    翻译 vsse64.v 指令 (带步长的向量存储, 64-bit)

    格式: vsse64.v vs3, (rs1), rs2
    语义: for i in range(vl): mem[rs1 + rs2 * i] = vs3[i]
    :return: 生成的汇编代码行列表
    """
    insn = context.instruction
    state = context.state
    allocator = context.layout
    new_label = context.new_label
    return _emit_vsse_v(insn, state, allocator, new_label, sew=64)


def _build_vlse32_v_lines(context) -> list[str]:
    """
    翻译 vlse32.v 指令 (带步长的向量加载, 32-bit)

    格式: vlse32.v vd, (rs1), rs2
    语义: for i in range(vl): vd[i] = mem[rs1 + rs2 * i]
    :return: 生成的汇编代码行列表
    """
    insn = context.instruction
    state = context.state
    allocator = context.layout
    new_label = context.new_label
    return _emit_vlse_v(insn, state, allocator, new_label, sew=32)


def _build_vsse32_v_lines(context) -> list[str]:
    """
    翻译 vsse32.v 指令 (带步长的向量存储, 32-bit)

    格式: vsse32.v vs3, (rs1), rs2
    语义: for i in range(vl): mem[rs1 + rs2 * i] = vs3[i]
    :return: 生成的汇编代码行列表
    """
    insn = context.instruction
    state = context.state
    allocator = context.layout
    new_label = context.new_label
    return _emit_vsse_v(insn, state, allocator, new_label, sew=32)


# ============================================================================
# Segmented load/store (vlseg2e*.v / vsseg2e*.v / vlsseg2e*.v / vssseg2e*.v)
# ============================================================================

def _emit_vlseg2_v(
    insn: RVInstruction,
    state: StateTracker,
    allocator: SimulatedStateLayout,
    new_label,
    sew: int,
    is_strided: bool
) -> List[str]:
    """
    通用的 `segment count = 2` 向量加载翻译函数。

    支持两类语义：
    - unit-stride: `vlseg2e*.v`
    - strided: `vlsseg2e*.v`

    对于每个逻辑元素 `i`：
    - segment 0 读取到第一个寄存器组
    - segment 1 读取到第二个寄存器组

    地址计算规则：
    - unit-stride: `base + i * (2 * element_size) + k * element_size`
    - strided: `base + i * stride + k * element_size`
    其中 `k ∈ {0, 1}`。
    """
    lines = []
    operands = insn.operands

    if len(operands) < 2:
        raise InstructionValidationError(insn, f"Invalid operands for {insn.opcode}: {insn.op_str}")

    vd = operands[0]

    rs1, rs2 = _parse_memory_operands(insn, expect_stride=is_strided)
    segment_offsets = _get_segment_group_offsets(vd, state, allocator, segment_count=2, eew=sew)

    element_size = sew // 8
    tuple_size = element_size * 2
    load_instr = _get_int_load_instr(sew)
    store_instr = _get_int_store_instr(sew)

    # segmented load 需要同时管理：
    # - `vl` 循环计数；
    # - 逻辑元素索引 `i`；
    # - 向量寄存器内的字节偏移；
    # - tuple 地址；
    # - 当前 segment 的向量地址。
    # 这里同样采用动态 temp 分配，避免与 base/stride 的 `t*` 输入冲突。
    temps = TempRegisterAllocator(insn, reserved_gprs=("t6",))
    vl_reg = temps.alloc_gpr()
    index_reg = temps.alloc_gpr()
    temp_reg = temps.alloc_gpr()
    addr_reg = temps.alloc_gpr()

    lines.append(f"    # {insn.opcode}: segmented load -> {vd} (NF=2)")
    if is_strided:
        lines.append(f"    # 地址语义: mem[{rs1} + i * {rs2} + k * {element_size}]")
    else:
        lines.append(f"    # 地址语义: mem[{rs1} + i * {tuple_size} + k * {element_size}]")
    lines.append("    # segment 0 / segment 1 会分别写入相邻的两个向量寄存器组")

    _emit_load_vl_from_csr(lines, vl_reg=vl_reg, addr_reg=temp_reg)

    loop_label = new_label(insn.opcode.replace('.', '_'))
    lines.append(f"{loop_label}:")
    lines.append(f"    beqz    {vl_reg}, {loop_label}_end")

    lines.append(f"    addi    {index_reg}, {vl_reg}, -1          # {index_reg} = i")
    skip_label = _maybe_emit_mask_skip_guard(
        lines=lines,
        insn=insn,
        new_label=new_label,
        element_index_reg=index_reg,
        mask_chunk_reg=addr_reg,
        shift_reg=temp_reg,
        label_prefix=f"{insn.opcode.replace('.', '_')}_mask_skip",
    )

    if is_strided:
        lines.append(f"    mul     {temp_reg}, {index_reg}, {rs2}       # {temp_reg} = i * stride")
    else:
        lines.append(f"    li      {temp_reg}, {tuple_size}")
        lines.append(f"    mul     {temp_reg}, {index_reg}, {temp_reg}          # {temp_reg} = i * tuple_size")
    lines.append(f"    add     {addr_reg}, {temp_reg}, {rs1}       # {addr_reg} = 当前 tuple 的基地址")

    lines.append(f"    {load_instr:<7} {index_reg}, 0({addr_reg})   # 读取 segment 0")
    lines.append(f"    addi    {temp_reg}, {vl_reg}, -1")
    _emit_element_shift(lines, element_size=element_size, shift_reg=temp_reg)
    lines.append(f"    li      {addr_reg}, {segment_offsets[0]}")
    lines.append(f"    add     {addr_reg}, t6, {addr_reg}")
    lines.append(f"    add     {addr_reg}, {addr_reg}, {temp_reg}")
    lines.append(f"    {store_instr:<7} {index_reg}, 0({addr_reg})")

    lines.append(f"    addi    {index_reg}, {vl_reg}, -1")
    if is_strided:
        lines.append(f"    mul     {temp_reg}, {index_reg}, {rs2}       # {temp_reg} = i * stride")
    else:
        lines.append(f"    li      {temp_reg}, {tuple_size}")
        lines.append(f"    mul     {temp_reg}, {index_reg}, {temp_reg}          # {temp_reg} = i * tuple_size")
    lines.append(f"    add     {addr_reg}, {temp_reg}, {rs1}       # {addr_reg} = 当前 tuple 的基地址")
    lines.append(f"    {load_instr:<7} {index_reg}, {element_size}({addr_reg})   # 读取 segment 1")
    lines.append(f"    addi    {temp_reg}, {vl_reg}, -1")
    _emit_element_shift(lines, element_size=element_size, shift_reg=temp_reg)
    lines.append(f"    li      {addr_reg}, {segment_offsets[1]}")
    lines.append(f"    add     {addr_reg}, t6, {addr_reg}")
    lines.append(f"    add     {addr_reg}, {addr_reg}, {temp_reg}")
    lines.append(f"    {store_instr:<7} {index_reg}, 0({addr_reg})")

    if skip_label is not None:
        lines.append(f"{skip_label}:")
    lines.append(f"    addi    {vl_reg}, {vl_reg}, -1")
    lines.append(f"    j       {loop_label}")
    lines.append(f"{loop_label}_end:")

    return lines


def _emit_vsseg2_v(
    insn: RVInstruction,
    state: StateTracker,
    allocator: SimulatedStateLayout,
    new_label,
    sew: int,
    is_strided: bool
) -> List[str]:
    """
    通用的 `segment count = 2` 向量存储翻译函数。

    这里与 `_emit_vlseg2_v()` 相反：
    - 从两个相邻向量寄存器组中分别取出 element `i`
    - 再写回到目标 memory tuple 的 `k=0/1` 位置。
    """
    lines = []
    operands = insn.operands

    if len(operands) < 2:
        raise InstructionValidationError(insn, f"Invalid operands for {insn.opcode}: {insn.op_str}")

    vs3 = operands[0]

    rs1, rs2 = _parse_memory_operands(insn, expect_stride=is_strided)
    segment_offsets = _get_segment_group_offsets(vs3, state, allocator, segment_count=2, eew=sew)

    element_size = sew // 8
    tuple_size = element_size * 2
    load_instr = _get_int_load_instr(sew)
    store_instr = _get_int_store_instr(sew)

    # segmented store 的寄存器压力略高，但仍然可以通过复用 temp 保持在一个较小集合内。
    temps = TempRegisterAllocator(insn, reserved_gprs=("t6",))
    vl_reg = temps.alloc_gpr()
    index_reg = temps.alloc_gpr()
    temp_reg = temps.alloc_gpr()
    addr_reg = temps.alloc_gpr()

    lines.append(f"    # {insn.opcode}: segmented store <- {vs3} (NF=2)")
    if is_strided:
        lines.append(f"    # 地址语义: mem[{rs1} + i * {rs2} + k * {element_size}]")
    else:
        lines.append(f"    # 地址语义: mem[{rs1} + i * {tuple_size} + k * {element_size}]")
    lines.append("    # segment 0 / segment 1 分别从相邻的两个向量寄存器组取值")

    _emit_load_vl_from_csr(lines, vl_reg=vl_reg, addr_reg=temp_reg)

    loop_label = new_label(insn.opcode.replace('.', '_'))
    lines.append(f"{loop_label}:")
    lines.append(f"    beqz    {vl_reg}, {loop_label}_end")

    lines.append(f"    addi    {index_reg}, {vl_reg}, -1          # {index_reg} = i")
    skip_label = _maybe_emit_mask_skip_guard(
        lines=lines,
        insn=insn,
        new_label=new_label,
        element_index_reg=index_reg,
        mask_chunk_reg=addr_reg,
        shift_reg=temp_reg,
        label_prefix=f"{insn.opcode.replace('.', '_')}_mask_skip",
    )

    if is_strided:
        lines.append(f"    mul     {temp_reg}, {index_reg}, {rs2}       # {temp_reg} = i * stride")
    else:
        lines.append(f"    li      {temp_reg}, {tuple_size}")
        lines.append(f"    mul     {temp_reg}, {index_reg}, {temp_reg}          # {temp_reg} = i * tuple_size")
    lines.append(f"    add     {addr_reg}, {temp_reg}, {rs1}       # {addr_reg} = 当前 tuple 的基地址")

    lines.append(f"    addi    {index_reg}, {vl_reg}, -1")
    _emit_element_shift(lines, element_size=element_size, shift_reg=index_reg)
    lines.append(f"    li      {temp_reg}, {segment_offsets[0]}")
    lines.append(f"    add     {temp_reg}, t6, {temp_reg}")
    lines.append(f"    add     {temp_reg}, {temp_reg}, {index_reg}")
    lines.append(f"    {load_instr:<7} {temp_reg}, 0({temp_reg})   # 读取 segment 0")
    lines.append(f"    {store_instr:<7} {temp_reg}, 0({addr_reg})")

    lines.append(f"    addi    {index_reg}, {vl_reg}, -1")
    _emit_element_shift(lines, element_size=element_size, shift_reg=index_reg)
    lines.append(f"    li      {temp_reg}, {segment_offsets[1]}")
    lines.append(f"    add     {temp_reg}, t6, {temp_reg}")
    lines.append(f"    add     {temp_reg}, {temp_reg}, {index_reg}")
    lines.append(f"    {load_instr:<7} {temp_reg}, 0({temp_reg})   # 读取 segment 1")
    lines.append(f"    {store_instr:<7} {temp_reg}, {element_size}({addr_reg})")

    if skip_label is not None:
        lines.append(f"{skip_label}:")
    lines.append(f"    addi    {vl_reg}, {vl_reg}, -1")
    lines.append(f"    j       {loop_label}")
    lines.append(f"{loop_label}_end:")

    return lines


def _build_vlseg2e32_v_lines(context) -> list[str]:
    """翻译 `vlseg2e32.v` 指令。"""
    insn = context.instruction
    state = context.state
    allocator = context.layout
    new_label = context.new_label
    return _emit_vlseg2_v(insn, state, allocator, new_label, sew=32, is_strided=False)


def _build_vsseg2e32_v_lines(context) -> list[str]:
    """翻译 `vsseg2e32.v` 指令。"""
    insn = context.instruction
    state = context.state
    allocator = context.layout
    new_label = context.new_label
    return _emit_vsseg2_v(insn, state, allocator, new_label, sew=32, is_strided=False)


def _build_vlsseg2e32_v_lines(context) -> list[str]:
    """翻译 `vlsseg2e32.v` 指令。"""
    insn = context.instruction
    state = context.state
    allocator = context.layout
    new_label = context.new_label
    return _emit_vlseg2_v(insn, state, allocator, new_label, sew=32, is_strided=True)


def _build_vssseg2e32_v_lines(context) -> list[str]:
    """翻译 `vssseg2e32.v` 指令。"""
    insn = context.instruction
    state = context.state
    allocator = context.layout
    new_label = context.new_label
    return _emit_vsseg2_v(insn, state, allocator, new_label, sew=32, is_strided=True)


def _build_vlseg2e64_v_lines(context) -> list[str]:
    """翻译 `vlseg2e64.v` 指令。"""
    insn = context.instruction
    state = context.state
    allocator = context.layout
    new_label = context.new_label
    return _emit_vlseg2_v(insn, state, allocator, new_label, sew=64, is_strided=False)


def _build_vsseg2e64_v_lines(context) -> list[str]:
    """翻译 `vsseg2e64.v` 指令。"""
    insn = context.instruction
    state = context.state
    allocator = context.layout
    new_label = context.new_label
    return _emit_vsseg2_v(insn, state, allocator, new_label, sew=64, is_strided=False)


def _build_vlsseg2e64_v_lines(context) -> list[str]:
    """翻译 `vlsseg2e64.v` 指令。"""
    insn = context.instruction
    state = context.state
    allocator = context.layout
    new_label = context.new_label
    return _emit_vlseg2_v(insn, state, allocator, new_label, sew=64, is_strided=True)


def _build_vssseg2e64_v_lines(context) -> list[str]:
    """翻译 `vssseg2e64.v` 指令。"""
    insn = context.instruction
    state = context.state
    allocator = context.layout
    new_label = context.new_label
    return _emit_vsseg2_v(insn, state, allocator, new_label, sew=64, is_strided=True)
