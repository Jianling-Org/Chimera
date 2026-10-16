"""
256-bit RVV 模式内存指令翻译模块

将 VLEN=1024 的 RVV 向量内存指令翻译为 256-bit 实际 RVV 指令 + 标量回退

翻译策略:
- 从 simulated_cpu_state 的 CSR 区域动态读取原始 vl
- 计算完整 256-bit 块数 (chunk_count = vl // chunk_size) 和尾数 (tail = vl % chunk_size)
- vle: 主循环使用 vsetivli + vle{sew}.v 从真实内存加载到临时向量寄存器,
       然后 vse{sew}.v 写回 simulated_cpu_state
- vse: 主循环使用 vle{sew}.v 从 simulated_cpu_state 加载到临时向量寄存器,
       然后 vse{sew}.v 写回真实内存
- 尾部使用标量浮点加载/存储指令逐元素回退
- 所有 GPR/FPR 临时寄存器通过 TempRegisterAllocator 动态分配
"""

from typing import List
from riscv.frontend.model import RVInstruction
from riscv.extensions.rvv.analysis.config import StateTracker
from riscv.extensions.rvv.runtime.layout import SimulatedStateLayout
from riscv.extensions.rvv.translation.contracts import InstructionValidationError
from riscv.extensions.rvv.runtime.layout import CSR_OFFSETS
from riscv.extensions.rvv.backends.rvv256.temp_regs import VRegTempAllocator
from riscv.extensions.rvv.translation.temps import TempRegisterAllocator, record_vreg_group
from riscv.extensions.rvv.backends.rvv256.support import (
    _chunk_size,
    _emit_mask_setup,
    _emit_mask_extraction_chunk,
    _emit_mask_extraction_tail,
    _emit_mask_load_byte_aligned_chunk,
    _chunk_bytes,
    _emit_vsetvl_for_chunk,
    _load_vl_from_csr,
    _get_vle_instr,
    _get_vse_instr,
    _emit_state_ptr,
)


# ============================================================================
# 辅助函数
# ============================================================================

def _get_tail_instrs(sew: int):
    """
    返回尾部标量加载/存储指令对

    对于 sew=64 使用 fld/fsd, sew=32 使用 flw/fsw
    对于 sew=16 使用 lh/sh, sew=8 使用 lb/sb (整数指令)
    """
    if sew == 64:
        return 'fld', 'fsd'
    elif sew == 32:
        return 'flw', 'fsw'
    elif sew == 16:
        return 'lh', 'sh'
    elif sew == 8:
        return 'lb', 'sb'
    else:
        raise ValueError(f"不支持 SEW={sew}")


# ============================================================================
# vle64.v / vle32.v 指令翻译 (向量加载)
# ============================================================================

def _emit_vle_v(
    insn: RVInstruction,
    state: StateTracker,
    allocator: SimulatedStateLayout,
    new_label,
    sew: int,
) -> List[str]:
    """
    通用的 256-bit 向量加载翻译函数

    格式: vle{sew}.v vd, (rs1)
    语义: vd[i] = mem[rs1 + i * element_size] 对于 i in [0, vl)

    策略:
    - 从 CSR 动态读取 vl
    - 计算完整 256-bit 块数 (vl // chunk_n) 和尾数 (vl % chunk_n)
    - 主循环: vsetivli + vle{sew}.v 从真实内存加载 -> vse{sew}.v 写回 sim_state
    - 尾部: 标量浮点加载/存储逐元素回退

    :param insn: vle*.v 指令
    :param state: 当前向量状态
    :param allocator: 寄存器分配器
    :param new_label: 本轮标签分配函数
    :param sew: 元素宽度 (32 或 64)
    :return: 生成的汇编代码行列表
    """
    lines = []
    operands = list(insn.operands)
    is_masked = False
    if len(operands) > 0 and str(operands[-1]).strip().endswith(".t"):
        is_masked = True
        operands = operands[:-1]
    if len(operands) < 2:
        raise InstructionValidationError(insn, f"Invalid operands for {insn.opcode}: {insn.op_str}")

    vd = str(operands[0])
    # 提取内存基址寄存器, 格式如 (a0)
    rs1 = str(operands[1]).strip('()')

    chunk_n = _chunk_size(sew)
    c_bytes = _chunk_bytes()
    elem_bytes = sew // 8
    shift_amt = {8: 5, 16: 4, 32: 3, 64: 2}[sew]   # log2(chunk_n)
    mask = chunk_n - 1

    vd_off = allocator.get_offset(vd)

    # 分配临时向量寄存器 (从 v24-v31 池)
    vtemps = VRegTempAllocator(insn)
    temp_vreg = vtemps.alloc_vreg()

    # 分配 GPR 临时寄存器: 共 5 个 GPR + 可选 FPR 用于尾部
    temps = TempRegisterAllocator(insn, reserved_gprs=("t6",))
    vl_reg = temps.alloc_gpr()       # 保存从 CSR 读取的 vl
    chunk_count = temps.alloc_gpr()  # 剩余完整块计数 (也用作 CSR 地址暂存)
    tail_count = temps.alloc_gpr()   # 尾部元素计数
    mem_ptr = temps.alloc_gpr()      # 真实内存指针 (rs1 的副本)
    vd_ptr = temps.alloc_gpr()       # sim_state 中 vd 的指针
    # 尾部数据寄存器: 整数元素 (sew=8,16) 用 GPR, 浮点元素 (sew=32,64) 用 FPR
    if sew in (8, 16):
        data_reg = temps.alloc_gpr()     # 整数数据寄存器
    else:
        data_reg = temps.alloc_fpr()     # 浮点数据寄存器

    if is_masked:
        mask_bit_idx = temps.alloc_gpr()
        v0_base = temps.alloc_gpr()
        # e64,m1 保留旧 bit-shift 提取时需要独立保存原始 mask byte；不能
        # 再借用 chunk_count，否则会破坏主循环计数器。
        mask_value = temps.alloc_gpr()

    vle_instr = _get_vle_instr(sew)
    vse_instr = _get_vse_instr(sew)
    tail_load, tail_store = _get_tail_instrs(sew)

    # ========== 注释和初始化 ==========
    lines.append(f"# {insn.opcode}: {vd} = mem[{rs1}] (256-bit mode, SEW={sew})")
    lines.append("")

    # 复制内存基址到临时指针, 避免修改原始 rs1
    lines.append(f"    mv      {mem_ptr}, {rs1}              # 复制基址到临时指针")
    lines.append("")

    if is_masked:
        _emit_mask_setup(lines, mask_bit_idx, v0_base, chunk_count)

    # 从 CSR 加载 vl, 并计算块数和尾数
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

    # 计算 vd 在 sim_state 中的起始地址
    _emit_state_ptr(lines, vd_ptr, vd_off)
    lines.append("")

    # ========== 主循环: 256-bit 块加载 ==========
    main_loop = new_label("vle_main")
    after_main = new_label("vle_after")

    lines.append(f"    # --- 主循环: 每块加载 {chunk_n} 个元素 ({c_bytes} 字节) ---")
    lines.append(f"    beqz    {chunk_count}, {after_main}")
    if not is_masked:
        _emit_vsetvl_for_chunk(lines, chunk_n, sew, "m1", vl_reg, scratch_reg=vl_reg)
    lines.append(f"{main_loop}:")
    mask_suffix = ", v0.t" if is_masked else ""
    if is_masked:
        if sew in (8, 16, 32):
            # vlm.v 必须在实际 chunk vtype 建立后执行，才能按当前 VL 装入
            # 32/16/8 个连续 mask bit。
            _emit_vsetvl_for_chunk(lines, chunk_n, sew, "m1", vl_reg, scratch_reg=vl_reg)
            _emit_mask_load_byte_aligned_chunk(lines, sew, mask_bit_idx, v0_base, vl_reg)
        else:
            _emit_mask_extraction_chunk(lines, sew, mask_bit_idx, v0_base, vl_reg, mask_value)
            _emit_vsetvl_for_chunk(lines, chunk_n, sew, "m1", vl_reg, scratch_reg=vl_reg)
    lines.append("")
    lines.append(
        f"    {vle_instr} {temp_vreg}, ({mem_ptr}){mask_suffix}"
        f"           # 从内存加载块到临时向量寄存器"
    )
    lines.append(
        f"    {vse_instr} {temp_vreg}, ({vd_ptr}){mask_suffix}"
        f"            # 写回 sim_state"
    )
    lines.append("")
    lines.append(f"    addi    {mem_ptr}, {mem_ptr}, {c_bytes}        # 前进内存指针")
    lines.append(f"    addi    {vd_ptr}, {vd_ptr}, {c_bytes}          # 前进 sim_state 指针")
    if is_masked:
        lines.append(f"    addi    {mask_bit_idx}, {mask_bit_idx}, {chunk_n}")
    lines.append(f"    addi    {chunk_count}, {chunk_count}, -1")
    lines.append(f"    bnez    {chunk_count}, {main_loop}")
    lines.append(f"{after_main}:")
    lines.append("")

    # ========== 尾部标量回退 ==========
    lines.append(f"    # --- 尾部标量回退: 剩余 {tail_count} 个元素 ---")
    tail_loop = new_label("vle_tail")
    end_label = new_label("vle_end")
    skip_label = f"{tail_loop}_skip"

    lines.append(f"{tail_loop}:")
    lines.append(f"    beqz    {tail_count}, {end_label}")

    if is_masked:
        _emit_mask_extraction_tail(lines, mask_bit_idx, v0_base, vl_reg, mask_value, skip_label)

    lines.append(
        f"    {tail_load:<8} {data_reg}, 0({mem_ptr})"
        f"          # {data_reg} = mem[{mem_ptr}]"
    )
    lines.append(
        f"    {tail_store:<8} {data_reg}, 0({vd_ptr})"
        f"          # 写回 sim_state"
    )

    if is_masked:
        lines.append(f"{skip_label}:")
        lines.append(f"    addi    {mask_bit_idx}, {mask_bit_idx}, 1")

    lines.append(f"    addi    {mem_ptr}, {mem_ptr}, {elem_bytes}")
    lines.append(f"    addi    {vd_ptr}, {vd_ptr}, {elem_bytes}")
    lines.append(f"    addi    {tail_count}, {tail_count}, -1")
    lines.append(f"    j       {tail_loop}")
    lines.append(f"{end_label}:")

    return lines


def _build_vle64_v_lines(context) -> list[str]:
    """
    翻译 vle64.v 指令 (64-bit 元素, 256-bit 模式)

    格式: vle64.v vd, (rs1)
    语义: vd[i] = mem[rs1 + i * 8] 对于 i in [0, vl)
    :return: 生成的汇编代码行列表
    """
    insn = context.instruction
    state = context.state
    allocator = context.layout
    new_label = context.new_label
    return _emit_vle_v(insn, state, allocator, new_label, sew=64)


def _build_vle32_v_lines(context) -> list[str]:
    """
    翻译 vle32.v 指令 (32-bit 元素, 256-bit 模式)

    格式: vle32.v vd, (rs1)
    语义: vd[i] = mem[rs1 + i * 4] 对于 i in [0, vl)
    :return: 生成的汇编代码行列表
    """
    insn = context.instruction
    state = context.state
    allocator = context.layout
    new_label = context.new_label
    return _emit_vle_v(insn, state, allocator, new_label, sew=32)


# ============================================================================
# vse64.v / vse32.v 指令翻译 (向量存储)
# ============================================================================

def _emit_vse_v(
    insn: RVInstruction,
    state: StateTracker,
    allocator: SimulatedStateLayout,
    new_label,
    sew: int,
) -> List[str]:
    """
    通用的 256-bit 向量存储翻译函数

    格式: vse{sew}.v vs3, (rs1)
    语义: mem[rs1 + i * element_size] = vs3[i] 对于 i in [0, vl)

    策略:
    - 从 CSR 动态读取 vl
    - 计算完整 256-bit 块数 (vl // chunk_n) 和尾数 (vl % chunk_n)
    - 主循环: vle{sew}.v 从 sim_state 加载 -> vse{sew}.v 写回真实内存
    - 尾部: 标量浮点加载/存储逐元素回退

    :param insn: vse*.v 指令
    :param state: 当前向量状态
    :param allocator: 寄存器分配器
    :param new_label: 本轮标签分配函数
    :param sew: 元素宽度 (32 或 64)
    :return: 生成的汇编代码行列表
    """
    lines = []
    operands = list(insn.operands)
    is_masked = False
    if len(operands) > 0 and str(operands[-1]).strip().endswith(".t"):
        is_masked = True
        operands = operands[:-1]
    if len(operands) < 2:
        raise InstructionValidationError(insn, f"Invalid operands for {insn.opcode}: {insn.op_str}")

    vs3 = str(operands[0]).strip()
    rs1 = str(operands[1]).strip('()')

    chunk_n = _chunk_size(sew)
    c_bytes = _chunk_bytes()
    elem_bytes = sew // 8
    shift_amt = {8: 5, 16: 4, 32: 3, 64: 2}[sew]
    mask = chunk_n - 1

    vs3_off = allocator.get_offset(vs3)

    vtemps = VRegTempAllocator(insn)
    temp_vreg = vtemps.alloc_vreg()

    temps = TempRegisterAllocator(insn, reserved_gprs=("t6",))
    vl_reg = temps.alloc_gpr()
    chunk_count = temps.alloc_gpr()
    tail_count = temps.alloc_gpr()
    mem_ptr = temps.alloc_gpr()
    vs3_ptr = temps.alloc_gpr()
    if sew in (8, 16):
        data_reg = temps.alloc_gpr()
    else:
        data_reg = temps.alloc_fpr()

    if is_masked:
        mask_bit_idx = temps.alloc_gpr()
        v0_base = temps.alloc_gpr()
        mask_value = temps.alloc_gpr()

    vle_instr = _get_vle_instr(sew)
    vse_instr = _get_vse_instr(sew)
    tail_load, tail_store = _get_tail_instrs(sew)

    # ========== 注释和初始化 ==========
    lines.append(f"# {insn.opcode}: mem[{rs1}] = {vs3} (256-bit mode, SEW={sew})")
    lines.append("")

    lines.append(f"    mv      {mem_ptr}, {rs1}              # 复制基址到临时指针")
    lines.append("")

    if is_masked:
        _emit_mask_setup(lines, mask_bit_idx, v0_base, chunk_count)

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

    # 计算 vs3 在 sim_state 中的起始地址
    _emit_state_ptr(lines, vs3_ptr, vs3_off)
    lines.append("")

    # ========== 主循环: 256-bit 块存储 ==========
    main_loop = new_label("vse_main")
    after_main = new_label("vse_after")

    lines.append(f"    # --- 主循环: 每块存储 {chunk_n} 个元素 ({c_bytes} 字节) ---")
    lines.append(f"    beqz    {chunk_count}, {after_main}")
    if not is_masked:
        _emit_vsetvl_for_chunk(lines, chunk_n, sew, "m1", vl_reg, scratch_reg=vl_reg)
    lines.append(f"{main_loop}:")
    mask_suffix = ", v0.t" if is_masked else ""
    if is_masked:
        if sew in (8, 16, 32):
            _emit_vsetvl_for_chunk(lines, chunk_n, sew, "m1", vl_reg, scratch_reg=vl_reg)
            _emit_mask_load_byte_aligned_chunk(lines, sew, mask_bit_idx, v0_base, vl_reg)
        else:
            _emit_mask_extraction_chunk(lines, sew, mask_bit_idx, v0_base, vl_reg, mask_value)
            _emit_vsetvl_for_chunk(lines, chunk_n, sew, "m1", vl_reg, scratch_reg=vl_reg)
    lines.append("")
    lines.append(
        f"    {vle_instr} {temp_vreg}, ({vs3_ptr}){mask_suffix}"
        f"           # 从 sim_state 加载块到临时向量寄存器"
    )
    lines.append(
        f"    {vse_instr} {temp_vreg}, ({mem_ptr}){mask_suffix}"
        f"           # 写回真实内存"
    )
    lines.append("")
    lines.append(f"    addi    {vs3_ptr}, {vs3_ptr}, {c_bytes}")
    lines.append(f"    addi    {mem_ptr}, {mem_ptr}, {c_bytes}")
    if is_masked:
        lines.append(f"    addi    {mask_bit_idx}, {mask_bit_idx}, {chunk_n}")
    lines.append(f"    addi    {chunk_count}, {chunk_count}, -1")
    lines.append(f"    bnez    {chunk_count}, {main_loop}")
    lines.append(f"{after_main}:")
    lines.append("")

    # ========== 尾部标量回退 ==========
    tail_loop = new_label("vse_tail")
    end_label = new_label("vse_end")
    skip_label = f"{tail_loop}_skip"

    lines.append(f"    # --- 尾部标量回退: 剩余 {tail_count} 个元素 ---")
    lines.append(f"{tail_loop}:")
    lines.append(f"    beqz    {tail_count}, {end_label}")

    if is_masked:
        _emit_mask_extraction_tail(lines, mask_bit_idx, v0_base, vl_reg, mask_value, skip_label)

    lines.append(
        f"    {tail_load:<8} {data_reg}, 0({vs3_ptr})"
        f"          # {data_reg} = {vs3}[i] (sim_state)"
    )
    lines.append(
        f"    {tail_store:<8} {data_reg}, 0({mem_ptr})"
        f"         # 写回真实内存"
    )

    if is_masked:
        lines.append(f"{skip_label}:")
        lines.append(f"    addi    {mask_bit_idx}, {mask_bit_idx}, 1")

    lines.append(f"    addi    {vs3_ptr}, {vs3_ptr}, {elem_bytes}")
    lines.append(f"    addi    {mem_ptr}, {mem_ptr}, {elem_bytes}")
    lines.append(f"    addi    {tail_count}, {tail_count}, -1")
    lines.append(f"    j       {tail_loop}")
    lines.append(f"{end_label}:")

    return lines


def _build_vse64_v_lines(context) -> list[str]:
    """
    翻译 vse64.v 指令 (64-bit 元素, 256-bit 模式)

    格式: vse64.v vs3, (rs1)
    语义: mem[rs1 + i * 8] = vs3[i] 对于 i in [0, vl)
    :return: 生成的汇编代码行列表
    """
    insn = context.instruction
    state = context.state
    allocator = context.layout
    new_label = context.new_label
    return _emit_vse_v(insn, state, allocator, new_label, sew=64)


def _build_vse32_v_lines(context) -> list[str]:
    """
    翻译 vse32.v 指令 (32-bit 元素, 256-bit 模式)

    格式: vse32.v vs3, (rs1)
    语义: mem[rs1 + i * 4] = vs3[i] 对于 i in [0, vl)
    :return: 生成的汇编代码行列表
    """
    insn = context.instruction
    state = context.state
    allocator = context.layout
    new_label = context.new_label
    return _emit_vse_v(insn, state, allocator, new_label, sew=32)


# ============================================================================
# vle8.v 指令翻译 (8-bit 元素加载)
# ============================================================================

def _build_vle8_v_lines(context) -> list[str]:
    """
    翻译 vle8.v 指令 (8-bit 元素, 256-bit 模式)

    格式: vle8.v vd, (rs1)
    语义: vd[i] = mem[rs1 + i] 对于 i in [0, vl)
    :return: 生成的汇编代码行列表
    """
    insn = context.instruction
    state = context.state
    allocator = context.layout
    new_label = context.new_label
    return _emit_vle_v(insn, state, allocator, new_label, sew=8)


# ============================================================================
# vle16.v 指令翻译 (16-bit 元素加载)
# ============================================================================

def _build_vle16_v_lines(context) -> list[str]:
    """
    翻译 vle16.v 指令 (16-bit 元素, 256-bit 模式)

    格式: vle16.v vd, (rs1)
    语义: vd[i] = mem[rs1 + i * 2] 对于 i in [0, vl)
    :return: 生成的汇编代码行列表
    """
    insn = context.instruction
    state = context.state
    allocator = context.layout
    new_label = context.new_label
    return _emit_vle_v(insn, state, allocator, new_label, sew=16)


# ============================================================================
# vse8.v 指令翻译 (8-bit 元素存储)
# ============================================================================

def _build_vse8_v_lines(context) -> list[str]:
    """
    翻译 vse8.v 指令 (8-bit 元素, 256-bit 模式)

    格式: vse8.v vs3, (rs1)
    语义: mem[rs1 + i] = vs3[i] 对于 i in [0, vl)
    :return: 生成的汇编代码行列表
    """
    insn = context.instruction
    state = context.state
    allocator = context.layout
    new_label = context.new_label
    return _emit_vse_v(insn, state, allocator, new_label, sew=8)


# ============================================================================
# vse16.v 指令翻译 (16-bit 元素存储)
# ============================================================================

def _build_vse16_v_lines(context) -> list[str]:
    """
    翻译 vse16.v 指令 (16-bit 元素, 256-bit 模式)

    格式: vse16.v vs3, (rs1)
    语义: mem[rs1 + i * 2] = vs3[i] 对于 i in [0, vl)
    :return: 生成的汇编代码行列表
    """
    insn = context.instruction
    state = context.state
    allocator = context.layout
    new_label = context.new_label
    return _emit_vse_v(insn, state, allocator, new_label, sew=16)


# ============================================================================
# vlse*.v 指令翻译 (带步长向量加载)
# ============================================================================

def _emit_vlse_v(
    insn: RVInstruction,
    state: StateTracker,
    allocator: SimulatedStateLayout,
    new_label,
    sew: int,
) -> List[str]:
    """
    通用的 256-bit strided load 翻译函数

    格式: vlse{sew}.v vd, (rs1), rs2
    语义: vd[i] = mem[rs1 + rs2 * i] 对于 i in [0, vl)

    策略:
    - 从 CSR 动态读取 vl
    - 主循环用实际 vlse{sew}.v 每次加载一个 256-bit chunk
    - 尾部同样用动态 AVL 的 RVV chunk, 避免手写标量尾部
    """
    lines = []
    operands = list(insn.operands)
    is_masked = False
    if len(operands) > 0 and str(operands[-1]).strip().endswith(".t"):
        is_masked = True
        operands = operands[:-1]
    if len(operands) < 3:
        raise InstructionValidationError(insn, f"Invalid operands for {insn.opcode}: {insn.op_str}")

    vd = str(operands[0])
    rs1 = str(operands[1]).strip('()')
    rs2 = str(operands[2])

    chunk_n = _chunk_size(sew)
    c_bytes = _chunk_bytes()
    shift_amt = {8: 5, 16: 4, 32: 3, 64: 2}[sew]
    mask = chunk_n - 1

    vd_off = allocator.get_offset(vd)

    vtemps = VRegTempAllocator(insn)
    temp_vreg = vtemps.alloc_vreg()

    temps = TempRegisterAllocator(insn, reserved_gprs=("t6",))
    vl_reg = temps.alloc_gpr()
    chunk_count = temps.alloc_gpr()
    tail_count = temps.alloc_gpr()
    mem_ptr = temps.alloc_gpr()
    vd_ptr = temps.alloc_gpr()
    step_bytes = temps.alloc_gpr()

    if is_masked:
        mask_bit_idx = temps.alloc_gpr()
        v0_base = temps.alloc_gpr()

    vlse_instr = f"vlse{sew}.v"
    vse_instr = _get_vse_instr(sew)

    lines.append(f"# {insn.opcode}: {vd}[i] = mem[{rs1} + {rs2} * i] (256-bit mode, SEW={sew})")
    lines.append("")

    lines.append(f"    mv      {mem_ptr}, {rs1}              # 当前 strided load 基址")
    lines.append("")

    if is_masked:
        _emit_mask_setup(lines, mask_bit_idx, v0_base, chunk_count)

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

    _emit_state_ptr(lines, vd_ptr, vd_off)
    lines.append("")

    main_loop = new_label("vlse_main")
    after_main = new_label("vlse_after")

    # e8/e16/e32 的直接 vlm.v 不再覆盖 step_bytes，故 masked/unmasked 都可
    # 将 chunk_n * stride 移到循环外。e64 的旧半字节提取仍会覆盖它，随后只
    # 在 e64 masked 路径重算即可。
    lines.append(f"    li      {step_bytes}, {chunk_n}")
    lines.append(f"    mul     {step_bytes}, {step_bytes}, {rs2}       # 循环外预计算 chunk_n * stride")
    lines.append(f"    # --- 主循环: 每块加载 {chunk_n} 个 strided 元素 ({c_bytes} 字节写回) ---")
    lines.append(f"    beqz    {chunk_count}, {after_main}")
    if not is_masked:
        _emit_vsetvl_for_chunk(lines, chunk_n, sew, "m1", vl_reg, scratch_reg=vl_reg)
    lines.append(f"{main_loop}:")
    mask_suffix = ", v0.t" if is_masked else ""
    if is_masked:
        if sew in (8, 16, 32):
            _emit_vsetvl_for_chunk(lines, chunk_n, sew, "m1", vl_reg, scratch_reg=vl_reg)
            _emit_mask_load_byte_aligned_chunk(lines, sew, mask_bit_idx, v0_base, vl_reg)
        else:
            _emit_mask_extraction_chunk(lines, sew, mask_bit_idx, v0_base, vl_reg, step_bytes)
            _emit_vsetvl_for_chunk(lines, chunk_n, sew, "m1", vl_reg, scratch_reg=vl_reg)
    lines.append("")
    lines.append(
        f"    {vlse_instr} {temp_vreg}, ({mem_ptr}), {rs2}{mask_suffix}"
        f"       # 从真实内存按 byte stride 加载"
    )
    lines.append(
        f"    {vse_instr} {temp_vreg}, ({vd_ptr}){mask_suffix}"
        f"            # 紧凑写回 sim_state"
    )
    lines.append("")
    if is_masked and sew == 64:
        lines.append(f"    li      {step_bytes}, {chunk_n}")
        lines.append(f"    mul     {step_bytes}, {step_bytes}, {rs2}       # e64 mask scratch 被覆盖后重算")
    lines.append(f"    add     {mem_ptr}, {mem_ptr}, {step_bytes}      # 前进真实内存基址")
    lines.append(f"    addi    {vd_ptr}, {vd_ptr}, {c_bytes}          # 前进 sim_state 指针")
    if is_masked:
        lines.append(f"    addi    {mask_bit_idx}, {mask_bit_idx}, {chunk_n}")
    lines.append(f"    addi    {chunk_count}, {chunk_count}, -1")
    lines.append(f"    bnez    {chunk_count}, {main_loop}")
    lines.append(f"{after_main}:")
    lines.append("")

    tail_end = new_label("vlse_tail_end")
    lines.append(f"    # --- 尾部 RVV strided load chunk: 剩余 {tail_count} 个元素 ---")
    lines.append(f"    beqz    {tail_count}, {tail_end}")

    if is_masked:
        if sew in (8, 16, 32):
            lines.append(f"    vsetvli zero, {tail_count}, e{sew}, m1, ta, ma")
            _emit_mask_load_byte_aligned_chunk(lines, sew, mask_bit_idx, v0_base, vl_reg)
        else:
            _emit_mask_extraction_chunk(lines, sew, mask_bit_idx, v0_base, vl_reg, step_bytes)
            lines.append(f"    vsetvli zero, {tail_count}, e{sew}, m1, ta, ma")
    else:
        lines.append(f"    vsetvli zero, {tail_count}, e{sew}, m1, ta, ma")
    lines.append("")
    lines.append(f"    {vlse_instr} {temp_vreg}, ({mem_ptr}), {rs2}{mask_suffix}")
    lines.append(f"    {vse_instr} {temp_vreg}, ({vd_ptr}){mask_suffix}")
    lines.append(f"{tail_end}:")

    return lines


def _build_vlse8_v_lines(context) -> list[str]:
    """翻译 vlse8.v 指令 (带 byte stride 的 8-bit 向量加载)"""
    insn = context.instruction
    state = context.state
    allocator = context.layout
    new_label = context.new_label
    return _emit_vlse_v(insn, state, allocator, new_label, sew=8)


def _build_vlse32_v_lines(context) -> list[str]:
    """翻译 vlse32.v 指令 (带 byte stride 的 32-bit 向量加载)"""
    insn = context.instruction
    state = context.state
    allocator = context.layout
    new_label = context.new_label
    return _emit_vlse_v(insn, state, allocator, new_label, sew=32)


def _build_vlse16_v_lines(context) -> list[str]:
    """翻译 vlse16.v 指令 (带 byte stride 的 16-bit 向量加载)"""
    insn = context.instruction
    state = context.state
    allocator = context.layout
    new_label = context.new_label
    return _emit_vlse_v(insn, state, allocator, new_label, sew=16)


def _build_vlse64_v_lines(context) -> list[str]:
    """翻译 vlse64.v 指令 (带 byte stride 的 64-bit 向量加载)"""
    insn = context.instruction
    state = context.state
    allocator = context.layout
    new_label = context.new_label
    return _emit_vlse_v(insn, state, allocator, new_label, sew=64)


# ============================================================================
# vsse*.v 指令翻译 (带步长向量存储)
# ============================================================================

def _emit_vsse_v(
    insn: RVInstruction,
    state: StateTracker,
    allocator: SimulatedStateLayout,
    new_label,
    sew: int,
) -> List[str]:
    """
    通用的 256-bit strided store 翻译函数

    格式: vsse{sew}.v vs3, (rs1), rs2
    语义: mem[rs1 + rs2 * i] = vs3[i] 对于 i in [0, vl)

    策略:
    - 从 CSR 动态读取 vl
    - 主循环从 simulated_cpu_state 紧凑加载 256-bit chunk
    - 使用实际 vsse{sew}.v 按 byte stride 写回真实内存
    - 尾部同样用动态 AVL 的 RVV chunk
    """
    lines = []
    operands = list(insn.operands)
    is_masked = False
    if len(operands) > 0 and str(operands[-1]).strip().endswith(".t"):
        is_masked = True
        operands = operands[:-1]
    if len(operands) < 3:
        raise InstructionValidationError(insn, f"Invalid operands for {insn.opcode}: {insn.op_str}")

    vs3 = str(operands[0])
    rs1 = str(operands[1]).strip('()')
    rs2 = str(operands[2])

    chunk_n = _chunk_size(sew)
    c_bytes = _chunk_bytes()
    shift_amt = {8: 5, 16: 4, 32: 3, 64: 2}[sew]
    mask = chunk_n - 1

    vs3_off = allocator.get_offset(vs3)

    vtemps = VRegTempAllocator(insn)
    temp_vreg = vtemps.alloc_vreg()

    temps = TempRegisterAllocator(insn, reserved_gprs=("t6",))
    vl_reg = temps.alloc_gpr()
    chunk_count = temps.alloc_gpr()
    tail_count = temps.alloc_gpr()
    mem_ptr = temps.alloc_gpr()
    vs3_ptr = temps.alloc_gpr()
    step_bytes = temps.alloc_gpr()

    if is_masked:
        mask_bit_idx = temps.alloc_gpr()
        v0_base = temps.alloc_gpr()

    vle_instr = _get_vle_instr(sew)
    vsse_instr = f"vsse{sew}.v"

    lines.append(f"# {insn.opcode}: mem[{rs1} + {rs2} * i] = {vs3}[i] (256-bit mode, SEW={sew})")
    lines.append("")

    lines.append(f"    mv      {mem_ptr}, {rs1}              # 当前 strided store 基址")
    lines.append("")

    if is_masked:
        _emit_mask_setup(lines, mask_bit_idx, v0_base, chunk_count)

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

    _emit_state_ptr(lines, vs3_ptr, vs3_off)
    lines.append("")

    main_loop = new_label("vsse_main")
    after_main = new_label("vsse_after")

    lines.append(f"    li      {step_bytes}, {chunk_n}")
    lines.append(f"    mul     {step_bytes}, {step_bytes}, {rs2}       # 循环外预计算 chunk_n * stride")
    lines.append(f"    # --- 主循环: 每块存储 {chunk_n} 个 strided 元素 ({c_bytes} 字节读入) ---")
    lines.append(f"    beqz    {chunk_count}, {after_main}")
    if not is_masked:
        _emit_vsetvl_for_chunk(lines, chunk_n, sew, "m1", vl_reg, scratch_reg=vl_reg)
    lines.append(f"{main_loop}:")
    mask_suffix = ", v0.t" if is_masked else ""
    if is_masked:
        if sew in (8, 16, 32):
            _emit_vsetvl_for_chunk(lines, chunk_n, sew, "m1", vl_reg, scratch_reg=vl_reg)
            _emit_mask_load_byte_aligned_chunk(lines, sew, mask_bit_idx, v0_base, vl_reg)
        else:
            _emit_mask_extraction_chunk(lines, sew, mask_bit_idx, v0_base, vl_reg, step_bytes)
            _emit_vsetvl_for_chunk(lines, chunk_n, sew, "m1", vl_reg, scratch_reg=vl_reg)
    lines.append("")
    lines.append(
        f"    {vle_instr} {temp_vreg}, ({vs3_ptr}){mask_suffix}"
        f"            # 从 sim_state 紧凑加载 {vs3} 块"
    )
    lines.append(
        f"    {vsse_instr} {temp_vreg}, ({mem_ptr}), {rs2}{mask_suffix}"
        f"       # 按 byte stride 写回真实内存"
    )
    lines.append("")
    if is_masked and sew == 64:
        lines.append(f"    li      {step_bytes}, {chunk_n}")
        lines.append(f"    mul     {step_bytes}, {step_bytes}, {rs2}       # e64 mask scratch 被覆盖后重算")
    lines.append(f"    add     {mem_ptr}, {mem_ptr}, {step_bytes}      # 前进真实内存基址")
    lines.append(f"    addi    {vs3_ptr}, {vs3_ptr}, {c_bytes}         # 前进 sim_state 指针")
    if is_masked:
        lines.append(f"    addi    {mask_bit_idx}, {mask_bit_idx}, {chunk_n}")
    lines.append(f"    addi    {chunk_count}, {chunk_count}, -1")
    lines.append(f"    bnez    {chunk_count}, {main_loop}")
    lines.append(f"{after_main}:")
    lines.append("")

    tail_end = new_label("vsse_tail_end")
    lines.append(f"    # --- 尾部 RVV strided store chunk: 剩余 {tail_count} 个元素 ---")
    lines.append(f"    beqz    {tail_count}, {tail_end}")

    if is_masked:
        if sew in (8, 16, 32):
            lines.append(f"    vsetvli zero, {tail_count}, e{sew}, m1, ta, ma")
            _emit_mask_load_byte_aligned_chunk(lines, sew, mask_bit_idx, v0_base, vl_reg)
        else:
            _emit_mask_extraction_chunk(lines, sew, mask_bit_idx, v0_base, vl_reg, step_bytes)
            lines.append(f"    vsetvli zero, {tail_count}, e{sew}, m1, ta, ma")
    else:
        lines.append(f"    vsetvli zero, {tail_count}, e{sew}, m1, ta, ma")
    lines.append("")
    lines.append(f"    {vle_instr} {temp_vreg}, ({vs3_ptr}){mask_suffix}")
    lines.append(f"    {vsse_instr} {temp_vreg}, ({mem_ptr}), {rs2}{mask_suffix}")
    lines.append(f"{tail_end}:")

    return lines


def _build_vsse32_v_lines(context) -> list[str]:
    """翻译 vsse32.v 指令 (带 byte stride 的 32-bit 向量存储)"""
    insn = context.instruction
    state = context.state
    allocator = context.layout
    new_label = context.new_label
    return _emit_vsse_v(insn, state, allocator, new_label, sew=32)


def _build_vsse64_v_lines(context) -> list[str]:
    """
    翻译 ``vsse64.v`` 指令（带 byte stride 的 64-bit 向量存储）。

    ``vs3`` 仍然表示 ``simulated_cpu_state`` 中的源向量槽，而 ``rs2``
    是每个元素之间的字节步长；不能把步长误当成 64-bit 元素个数。通用
    helper 会在每个 256-bit 块中使用 ``vle64.v`` 紧凑读取状态，再用原生
    ``vsse64.v`` 写入真实内存，并在尾部使用动态 AVL，保持源 ``vl`` 语义。
    """
    insn = context.instruction
    state = context.state
    allocator = context.layout
    new_label = context.new_label
    return _emit_vsse_v(insn, state, allocator, new_label, sew=64)


# ============================================================================
# vle8ff.v 指令翻译 (8-bit fault-only-first load)
# ============================================================================

def _build_vle8ff_v_lines(context) -> list[str]:
    """
    翻译 vle8ff.v 指令 (256-bit 模式)

    首块最多加载32字节；后续块屏蔽元素0，最多加载31个新字节。
    后续块的源/目的基址退一字节，但屏蔽位置不访问内存，避免重复读取。
    因此只有源元素0能触发首元素异常；其他 fault 缩短硬件 vl，扣除
    屏蔽前缀后同步模拟 CSR.vl，无需 Runtime 异常恢复。
    """
    insn = context.instruction
    allocator = context.layout
    new_label = context.new_label
    lines = []
    operands = insn.operands
    if len(operands) < 2:
        raise InstructionValidationError(insn, f"Invalid operands for {insn.opcode}: {insn.op_str}")

    vd = str(operands[0])
    rs1 = str(operands[1]).strip('()')
    vd_off = allocator.get_offset(vd)
    vl_offset = CSR_OFFSETS['vl']

    vtemps = VRegTempAllocator(insn)
    temp_vreg = vtemps.alloc_vreg()
    record_vreg_group("v0", 1)

    temps = context.temp_register_allocator
    remaining = temps.alloc_gpr()
    avl = temps.alloc_gpr()
    actual_vl = temps.alloc_gpr()
    loaded_total = temps.alloc_gpr()
    mem_ptr = temps.alloc_gpr()
    vd_ptr = temps.alloc_gpr()
    tmp = temps.alloc_gpr()

    loop_label = new_label("vle8ff_loop")
    avl_ready = new_label("vle8ff_avl_ready")
    full_chunk = new_label("vle8ff_full_chunk")
    trim_label = new_label("vle8ff_trim")
    end_label = new_label("vle8ff_end")

    lines.append(f"# vle8ff.v {vd}, ({rs1}) (256-bit mode, RVV1.0 fault-only-first)")
    lines.append("# Non-first fault trimming is reflected into simulated CSR.vl")
    lines.append(f"    mv      {mem_ptr}, {rs1}                  # source byte pointer")
    _load_vl_from_csr(lines, vl_reg=remaining, addr_reg=tmp)
    lines.append(f"    li      {tmp}, {vd_off:#x}")
    lines.append(f"    add     {vd_ptr}, t6, {tmp}               # {vd_ptr} = &{vd}")
    lines.append(f"    li      {loaded_total}, 0")
    lines.append(f"{loop_label}:")
    lines.append(f"    beqz    {remaining}, {end_label}")
    lines.append(f"    snez    {tmp}, {loaded_total}            # masked prefix after the first chunk")
    lines.append(f"    add     {avl}, {remaining}, {tmp}")
    lines.append(f"    li      {actual_vl}, 32")
    lines.append(f"    bleu    {avl}, {actual_vl}, {avl_ready}")
    lines.append(f"    mv      {avl}, {actual_vl}")
    lines.append(f"{avl_ready}:")
    lines.append(f"    vsetvli zero, {avl}, e8, m1, ta, ma")
    lines.append(f"    vid.v   {temp_vreg}")
    lines.append(f"    vmsgeu.vx v0, {temp_vreg}, {tmp}")
    lines.append(f"    sub     {mem_ptr}, {mem_ptr}, {tmp}")
    lines.append(f"    sub     {vd_ptr}, {vd_ptr}, {tmp}")
    lines.append(f"    vle8ff.v {temp_vreg}, ({mem_ptr}), v0.t")
    lines.append(f"    csrr    {actual_vl}, vl                   # hardware vl includes the masked prefix")
    lines.append(f"    vse8.v  {temp_vreg}, ({vd_ptr}), v0.t")
    lines.append(f"    add     {mem_ptr}, {mem_ptr}, {actual_vl}")
    lines.append(f"    add     {vd_ptr}, {vd_ptr}, {actual_vl}")
    lines.append(f"    sub     {actual_vl}, {actual_vl}, {tmp}   # exclude the masked prefix")
    lines.append(f"    sub     {avl}, {avl}, {tmp}")
    lines.append(f"    add     {loaded_total}, {loaded_total}, {actual_vl}")
    lines.append(f"    beq     {actual_vl}, {avl}, {full_chunk}")
    lines.append(f"    j       {trim_label}                      # non-first fault trimmed vl")
    lines.append(f"{full_chunk}:")
    lines.append(f"    sub     {remaining}, {remaining}, {actual_vl}")
    lines.append(f"    j       {loop_label}")
    lines.append(f"{trim_label}:")
    lines.append(f"    li      {tmp}, {vl_offset:#x}")
    lines.append(f"    add     {tmp}, t6, {tmp}")
    lines.append(f"    sd      {loaded_total}, 0({tmp})           # CSR.vl = loaded count after FOF trim")
    lines.append(f"{end_label}:")
    return lines


def _emit_vluxei_v(
    insn: RVInstruction,
    state: StateTracker,
    allocator: SimulatedStateLayout,
    new_label,
    index_eew: int,
) -> List[str]:
    """
    翻译 vluxei*.v 指令 (256-bit 模式)

    格式: vluxei{index_eew}.v vd, (rs1), vs2
    语义: vd[i] = mem[rs1 + unsigned(vs2[i])] for i in [0, vl)

    这里采用标量逐元素 load。这样可以直接使用模拟状态中完整的
    index vector, 不受 256-bit chunk 边界影响。
    """
    lines = []
    operands = insn.operands
    if len(operands) < 3:
        raise InstructionValidationError(insn, f"Invalid operands for {insn.opcode}: {insn.op_str}")

    vd = str(operands[0])
    rs1 = str(operands[1]).strip('()')
    vs2 = str(operands[2])

    sew = state.sew
    if sew not in (8, 16, 32, 64):
        raise InstructionValidationError(insn, f"{insn.opcode} supports SEW=8/16/32/64, got SEW={sew}")
    if index_eew not in (16, 64):
        raise InstructionValidationError(insn, f"{insn.opcode} unsupported index EEW={index_eew}")

    elem_bytes = sew // 8
    index_bytes = index_eew // 8
    vd_off = allocator.get_offset(vd)
    vs2_off = allocator.get_offset(vs2)

    data_load = {8: 'lbu', 16: 'lhu', 32: 'lwu', 64: 'ld'}[sew]
    data_store = {8: 'sb', 16: 'sh', 32: 'sw', 64: 'sd'}[sew]
    index_load = {16: 'lhu', 64: 'ld'}[index_eew]

    temps = TempRegisterAllocator(insn, reserved_gprs=("t6",))
    vl_reg = temps.alloc_gpr()
    index_ptr = temps.alloc_gpr()
    vd_ptr = temps.alloc_gpr()
    mem_ptr = temps.alloc_gpr()
    index_reg = temps.alloc_gpr()
    temp = temps.alloc_gpr()
    data_reg = temps.alloc_gpr()

    label_base = f"vluxei{index_eew}"
    loop_label = new_label(f"{label_base}_loop")
    end_label = new_label(f"{label_base}_end")

    lines.append(f"# vluxei{index_eew}.v {vd}, ({rs1}), {vs2} (256-bit mode, scalar indexed load)")
    lines.append(f"# Semantic: {vd}[i] = mem[{rs1} + u{index_eew}({vs2}[i])] (data SEW={sew}, index EEW={index_eew})")
    lines.append("")

    _load_vl_from_csr(lines, vl_reg=vl_reg, addr_reg=temp)
    lines.append(f"    li      {temp}, {vs2_off:#x}")
    lines.append(f"    add     {index_ptr}, t6, {temp}           # {index_ptr} = &{vs2} (e{index_eew} byte offsets)")
    lines.append(f"    li      {temp}, {vd_off:#x}")
    lines.append(f"    add     {vd_ptr}, t6, {temp}              # {vd_ptr} = &{vd}")
    lines.append("")

    lines.append(f"    # --- 标量 unordered indexed load: index EEW 固定为 {index_eew}-bit ---")
    lines.append(f"{loop_label}:")
    lines.append(f"    beqz    {vl_reg}, {end_label}")
    lines.append(f"    {index_load:<8} {index_reg}, 0({index_ptr})       # byte offset = u{index_eew}({vs2}[i])")
    lines.append(f"    add     {mem_ptr}, {rs1}, {index_reg}     # effective address")
    lines.append(f"    {data_load:<8} {data_reg}, 0({mem_ptr})        # load data element e{sew}")
    lines.append(f"    {data_store:<8} {data_reg}, 0({vd_ptr})         # store into simulated {vd}")
    lines.append(f"    addi    {index_ptr}, {index_ptr}, {index_bytes}")
    lines.append(f"    addi    {vd_ptr}, {vd_ptr}, {elem_bytes}")
    lines.append(f"    addi    {vl_reg}, {vl_reg}, -1")
    lines.append(f"    j       {loop_label}")
    lines.append(f"{end_label}:")

    return lines


# ============================================================================
# vluxei16.v / vluxei64.v 指令翻译 (unordered indexed load)
# ============================================================================

def _build_vluxei16_v_lines(context) -> list[str]:
    """翻译 vluxei16.v 指令 (256-bit 模式, scalar indexed load)。"""
    insn = context.instruction
    state = context.state
    allocator = context.layout
    new_label = context.new_label
    return _emit_vluxei_v(insn, state, allocator, new_label, index_eew=16)


def _build_vluxei64_v_lines(context) -> list[str]:
    """翻译 vluxei64.v 指令 (256-bit 模式, scalar indexed load)。"""
    insn = context.instruction
    state = context.state
    allocator = context.layout
    new_label = context.new_label
    return _emit_vluxei_v(insn, state, allocator, new_label, index_eew=64)


# ============================================================================
# vl1r.v / vl1re*.v / vl4r.v 指令翻译 (整寄存器加载)
# ============================================================================

def _emit_vlr_like(
    insn: RVInstruction,
    state: StateTracker,
    allocator: SimulatedStateLayout,
    new_label,
    mnemonic: str,
    eew: int,
    nf: int,
) -> List[str]:
    """
    翻译 whole-register load 指令 (256-bit 模式)

    格式: vl{nf}r.v/vl{nf}re*.v vd, (rs1)
    语义: 从内存加载 nf 个完整向量寄存器到 vd..vd+nf-1.
    不依赖 vl, 总是加载完整的 nf 个 vreg.

    当前 simulated_cpu_state 中每个 vreg 固定为 128 字节. 这里按指令
    编码 EEW 选择实际搬运指令, 每个 chunk 仍固定为 32 字节.
    """
    lines = []
    operands = insn.operands
    if len(operands) < 2:
        raise InstructionValidationError(insn, f"Invalid operands for {insn.opcode}: {insn.op_str}")

    vd = str(operands[0])
    rs1 = str(operands[1]).strip('()')
    vd_num = int(vd[1:]) if vd.startswith('v') and vd[1:].isdigit() else -1
    if vd_num < 0 or vd_num + nf > 32 or vd_num % nf != 0:
        raise InstructionValidationError(
            insn,
            f"Invalid vector register group for {insn.opcode}: {insn.op_str}",
        )

    total_bytes = nf * allocator.vreg_size
    chunk_bytes = 32
    num_chunks = total_bytes // chunk_bytes
    chunk_elems = chunk_bytes // (eew // 8)

    vd_base_off = allocator.get_offset(vd)

    vtemps = VRegTempAllocator(insn)
    temp_vreg = vtemps.alloc_vreg()

    temps = TempRegisterAllocator(insn, reserved_gprs=("t6",))
    mem_ptr = temps.alloc_gpr()
    vd_ptr = temps.alloc_gpr()
    chunk_count = temps.alloc_gpr()
    temp = temps.alloc_gpr()
    vle_instr = _get_vle_instr(eew)
    vse_instr = _get_vse_instr(eew)

    dest_desc = vd if nf == 1 else f"{vd}..v{vd_num + nf - 1}"
    lines.append(f"# {mnemonic} {vd}, ({rs1}) (256-bit mode)")
    lines.append(f"# Semantic: load {total_bytes}B into {dest_desc} from mem[{rs1}] (whole-register, EEW={eew})")
    lines.append("")

    lines.append(f"    mv      {mem_ptr}, {rs1}")
    lines.append("")

    lines.append(f"    li      {vd_ptr}, {vd_base_off:#x}")
    lines.append(f"    add     {vd_ptr}, t6, {vd_ptr}            # {vd_ptr} = &{vd}")
    lines.append("")

    lines.append(f"    li      {chunk_count}, {num_chunks}")
    main_loop = new_label("vlr_main")
    after_main = new_label("vlr_after")

    lines.append(f"    # --- 主循环: 每块 {chunk_bytes} 字节, 共 {num_chunks} 块 ---")
    lines.append(f"{main_loop}:")
    _emit_vsetvl_for_chunk(lines, chunk_elems, eew, "m1", chunk_count, scratch_reg=temp)
    lines.append("")
    lines.append(f"    {vle_instr} {temp_vreg}, ({mem_ptr})              # 从内存加载 32 字节")
    lines.append(f"    {vse_instr} {temp_vreg}, ({vd_ptr})               # 写回 sim_state")
    lines.append("")
    lines.append(f"    addi    {mem_ptr}, {mem_ptr}, {chunk_bytes}")
    lines.append(f"    addi    {vd_ptr}, {vd_ptr}, {chunk_bytes}")
    lines.append(f"    addi    {chunk_count}, {chunk_count}, -1")
    lines.append(f"    bnez    {chunk_count}, {main_loop}")
    lines.append(f"{after_main}:")

    return lines


def _build_vl1r_v_lines(context) -> list[str]:
    """翻译 vl1r.v 指令 (整寄存器加载, 256-bit 模式)"""
    insn = context.instruction
    state = context.state
    allocator = context.layout
    new_label = context.new_label
    return _emit_vlr_like(insn, state, allocator, new_label, "vl1r.v", eew=8, nf=1)


def _build_vl1re16_v_lines(context) -> list[str]:
    """翻译 vl1re16.v 指令 (EEW=16 的整寄存器加载, 256-bit 模式)"""
    insn = context.instruction
    state = context.state
    allocator = context.layout
    new_label = context.new_label
    return _emit_vlr_like(insn, state, allocator, new_label, "vl1re16.v", eew=16, nf=1)


def _build_vl1re32_v_lines(context) -> list[str]:
    """翻译 vl1re32.v 指令 (EEW=32 的整寄存器加载, 256-bit 模式)"""
    insn = context.instruction
    state = context.state
    allocator = context.layout
    new_label = context.new_label
    return _emit_vlr_like(insn, state, allocator, new_label, "vl1re32.v", eew=32, nf=1)


def _build_vl2r_v_lines(context) -> list[str]:
    """翻译 vl2r.v 指令 (2-register whole-register load, 256-bit 模式)"""
    insn = context.instruction
    state = context.state
    allocator = context.layout
    new_label = context.new_label
    return _emit_vlr_like(insn, state, allocator, new_label, "vl2r.v", eew=8, nf=2)


def _build_vl2re16_v_lines(context) -> list[str]:
    """翻译 vl2re16.v 指令 (EEW=16 的 2-register whole-register load, 256-bit 模式)"""
    insn = context.instruction
    state = context.state
    allocator = context.layout
    new_label = context.new_label
    return _emit_vlr_like(insn, state, allocator, new_label, "vl2re16.v", eew=16, nf=2)


def _build_vl2re32_v_lines(context) -> list[str]:
    """翻译 vl2re32.v 指令 (EEW=32 的 2-register whole-register load, 256-bit 模式)"""
    insn = context.instruction
    state = context.state
    allocator = context.layout
    new_label = context.new_label
    return _emit_vlr_like(insn, state, allocator, new_label, "vl2re32.v", eew=32, nf=2)


def _build_vl4re16_v_lines(context) -> list[str]:
    """翻译 vl4re16.v 指令 (EEW=16 的 4-register whole-register load, 256-bit 模式)"""
    insn = context.instruction
    state = context.state
    allocator = context.layout
    new_label = context.new_label
    return _emit_vlr_like(insn, state, allocator, new_label, "vl4re16.v", eew=16, nf=4)


def _build_vl4re32_v_lines(context) -> list[str]:
    """翻译 vl4re32.v 指令 (EEW=32 的 4-register whole-register load, 256-bit 模式)"""
    insn = context.instruction
    state = context.state
    allocator = context.layout
    new_label = context.new_label
    return _emit_vlr_like(insn, state, allocator, new_label, "vl4re32.v", eew=32, nf=4)


def _build_vl4re64_v_lines(context) -> list[str]:
    """翻译 vl4re64.v 指令 (EEW=64 的 4-register whole-register load, 256-bit 模式)"""
    insn = context.instruction
    state = context.state
    allocator = context.layout
    new_label = context.new_label
    return _emit_vlr_like(insn, state, allocator, new_label, "vl4re64.v", eew=64, nf=4)


def _build_vl8re32_v_lines(context) -> list[str]:
    """翻译 vl8re32.v 指令 (EEW=32 的 8-register whole-register load, 256-bit 模式)"""
    insn = context.instruction
    state = context.state
    allocator = context.layout
    new_label = context.new_label
    return _emit_vlr_like(insn, state, allocator, new_label, "vl8re32.v", eew=32, nf=8)


def _build_vl8re64_v_lines(context) -> list[str]:
    """翻译 vl8re64.v 指令 (EEW=64 的 8-register whole-register load, 256-bit 模式)"""
    insn = context.instruction
    state = context.state
    allocator = context.layout
    new_label = context.new_label
    return _emit_vlr_like(insn, state, allocator, new_label, "vl8re64.v", eew=64, nf=8)


def _build_vl1re64_v_lines(context) -> list[str]:
    """翻译 vl1re64.v 指令 (EEW=64 的整寄存器加载, 256-bit 模式)"""
    insn = context.instruction
    state = context.state
    allocator = context.layout
    new_label = context.new_label
    return _emit_vlr_like(insn, state, allocator, new_label, "vl1re64.v", eew=64, nf=1)


def _build_vsm_v_lines(context) -> list[str]:
    """
    翻译 vsm.v 指令 (mask store, 256-bit 模式)

    格式: vsm.v vs3, (rs1)
    语义: 将 mask register 的 ceil(vl / 8) 个 bit-packed bytes 写到真实内存.
    """
    insn = context.instruction
    allocator = context.layout
    new_label = context.new_label
    lines = []
    operands = insn.operands
    if len(operands) < 2:
        raise InstructionValidationError(insn, f"Invalid operands for {insn.opcode}: {insn.op_str}")

    vs3 = str(operands[0])
    rs1 = str(operands[1]).strip('()')
    vs3_off = allocator.get_offset(vs3)

    temps = context.temp_register_allocator
    vl_reg = temps.alloc_gpr()
    byte_count = temps.alloc_gpr()
    src_ptr = temps.alloc_gpr()
    mem_ptr = temps.alloc_gpr()
    byte_reg = temps.alloc_gpr()
    tmp = temps.alloc_gpr()

    loop_label = new_label("vsm_loop")
    end_label = new_label("vsm_end")

    lines.append(f"# vsm.v {vs3}, ({rs1}) (256-bit mode, RVV1.0 bit-packed mask)")
    lines.append(f"# Semantic: store ceil(vl / 8) mask bytes from {vs3} to mem[{rs1}]")
    lines.append("")
    _load_vl_from_csr(lines, vl_reg=vl_reg, addr_reg=tmp)
    lines.append(f"    addi    {byte_count}, {vl_reg}, 7")
    lines.append(f"    srli    {byte_count}, {byte_count}, 3        # {byte_count} = ceil(vl / 8)")
    lines.append(f"    li      {tmp}, {vs3_off:#x}")
    lines.append(f"    add     {src_ptr}, t6, {tmp}            # {src_ptr} = &{vs3} mask bytes")
    lines.append(f"    mv      {mem_ptr}, {rs1}")
    lines.append(f"{loop_label}:")
    lines.append(f"    beqz    {byte_count}, {end_label}")
    lines.append(f"    lbu     {byte_reg}, 0({src_ptr})")
    lines.append(f"    sb      {byte_reg}, 0({mem_ptr})")
    lines.append(f"    addi    {src_ptr}, {src_ptr}, 1")
    lines.append(f"    addi    {mem_ptr}, {mem_ptr}, 1")
    lines.append(f"    addi    {byte_count}, {byte_count}, -1")
    lines.append(f"    j       {loop_label}")
    lines.append(f"{end_label}:")

    return lines


def _emit_vsr_v(
    insn: RVInstruction,
    state: StateTracker,
    allocator: SimulatedStateLayout,
    new_label,
    nf: int,
) -> List[str]:
    """
    翻译 whole-register store 指令 (256-bit 模式)

    格式: vs{nf}r.v vs3, (rs1)
    语义: 将 nf 个连续完整向量寄存器从 simulated_cpu_state 存到内存.
    不依赖 vl/vtype.
    """
    lines = []
    operands = insn.operands
    if len(operands) < 2:
        raise InstructionValidationError(insn, f"Invalid operands for {insn.opcode}: {insn.op_str}")

    vs3 = str(operands[0])
    rs1 = str(operands[1]).strip('()')
    vs3_num = int(vs3[1:]) if vs3.startswith('v') and vs3[1:].isdigit() else -1
    if vs3_num < 0 or vs3_num + nf > 32 or vs3_num % nf != 0:
        raise InstructionValidationError(
            insn,
            f"Invalid vector register group for {insn.opcode}: {insn.op_str}",
        )

    total_bytes = nf * allocator.vreg_size
    chunk_bytes = 32
    num_chunks = total_bytes // chunk_bytes

    vs3_base_off = allocator.get_offset(vs3)

    vtemps = VRegTempAllocator(insn)
    temp_vreg = vtemps.alloc_vreg()

    temps = TempRegisterAllocator(insn, reserved_gprs=("t6",))
    mem_ptr = temps.alloc_gpr()
    vs3_ptr = temps.alloc_gpr()
    chunk_count = temps.alloc_gpr()

    source_desc = vs3 if nf == 1 else f"{vs3}..v{vs3_num + nf - 1}"
    lines.append(f"# vs{nf}r.v {vs3}, ({rs1}) (256-bit mode)")
    lines.append(f"# Semantic: store {total_bytes}B from {source_desc} to mem[{rs1}] (whole-register)")
    lines.append("")

    lines.append(f"    mv      {mem_ptr}, {rs1}")
    lines.append("")

    lines.append(f"    li      {vs3_ptr}, {vs3_base_off:#x}")
    lines.append(f"    add     {vs3_ptr}, t6, {vs3_ptr}           # {vs3_ptr} = &{vs3}")
    lines.append("")

    lines.append(f"    li      {chunk_count}, {num_chunks}")
    main_loop = new_label(f"vs{nf}r_main")
    after_main = new_label(f"vs{nf}r_after")

    lines.append(f"    # --- 主循环: 每块 {chunk_bytes} 字节, 共 {num_chunks} 块 ---")
    lines.append(f"{main_loop}:")
    lines.append(f"    vsetivli zero, 8, e32, m1, ta, ma")
    lines.append("")
    lines.append(f"    vle32.v {temp_vreg}, ({vs3_ptr})              # 从 sim_state 加载 32 字节")
    lines.append(f"    vse32.v {temp_vreg}, ({mem_ptr})              # 写回真实内存")
    lines.append("")
    lines.append(f"    addi    {vs3_ptr}, {vs3_ptr}, {chunk_bytes}")
    lines.append(f"    addi    {mem_ptr}, {mem_ptr}, {chunk_bytes}")
    lines.append(f"    addi    {chunk_count}, {chunk_count}, -1")
    lines.append(f"    bnez    {chunk_count}, {main_loop}")
    lines.append(f"{after_main}:")

    return lines


def _build_vs1r_v_lines(context) -> list[str]:
    """翻译 vs1r.v 指令 (1 个整向量寄存器 store, 256-bit 模式)。"""
    insn = context.instruction
    state = context.state
    allocator = context.layout
    new_label = context.new_label
    return _emit_vsr_v(insn, state, allocator, new_label, nf=1)


def _build_vs2r_v_lines(context) -> list[str]:
    """翻译 vs2r.v 指令 (2 个整向量寄存器 store, 256-bit 模式)。"""
    insn = context.instruction
    state = context.state
    allocator = context.layout
    new_label = context.new_label
    return _emit_vsr_v(insn, state, allocator, new_label, nf=2)


def _build_vs4r_v_lines(context) -> list[str]:
    """翻译 vs4r.v 指令 (4 个整向量寄存器 store, 256-bit 模式)。"""
    insn = context.instruction
    state = context.state
    allocator = context.layout
    new_label = context.new_label
    return _emit_vsr_v(insn, state, allocator, new_label, nf=4)


def _build_vs8r_v_lines(context) -> list[str]:
    """翻译 vs8r.v 指令 (8 个整向量寄存器 store, 256-bit 模式)。"""
    insn = context.instruction
    state = context.state
    allocator = context.layout
    new_label = context.new_label
    return _emit_vsr_v(insn, state, allocator, new_label, nf=8)


def _build_vl4r_v_lines(context) -> list[str]:
    return _emit_vlr_like(
        context.instruction, context.state, context.layout, context.new_label,
        "vl4r.v", eew=8, nf=4,
    )


# ============================================================================
# Segmented load/store (vlseg2e*.v / vsseg2e*.v / vlsseg2e*.v / vssseg2e*.v)
# ============================================================================


def _segment_field_registers(insn: RVInstruction, state: StateTracker, eew: int) -> tuple[str, str]:
    base = int(str(insn.operands[0])[1:])
    emul = state.lmul * eew / state.sew
    group_regs = max(1, int(emul))
    if emul < 0.125 or emul > 4 or base % group_regs or base + 2 * group_regs > 32:
        raise InstructionValidationError(insn, f"Invalid NF=2/EMUL={emul:g} register group: {insn.op_str}")
    return f"v{base}", f"v{base + group_regs}"


def _emit_vlseg2_chunked(
    insn: RVInstruction,
    state: StateTracker,
    allocator: SimulatedStateLayout,
    new_label,
    sew: int,
    is_strided: bool,
) -> List[str]:
    """
    分块翻译 vlseg2e{sew}.v / vlsseg2e{sew}.v (NF=2 segment load).

    主循环使用实际硬件 vlseg2e{sew}.v 加载段对到临时 vreg，再分别写回
    simulated_cpu_state 中按源 EMUL 定位的两个字段组。尾部用标量回退。
    """
    lines = []
    operands = insn.operands
    if len(operands) < 2:
        raise InstructionValidationError(insn, f"Invalid operands for {insn.opcode}: {insn.op_str}")

    vd = str(operands[0])
    rs1 = str(operands[1]).strip("()")
    stride_reg = None
    if is_strided:
        if len(operands) < 3:
            raise InstructionValidationError(insn, f"strided segload requires stride operand: {insn.op_str}")
        stride_reg = str(operands[2])

    vd, vd_next = _segment_field_registers(insn, state, sew)
    vd_off = allocator.get_offset(vd)
    vd_next_off = allocator.get_offset(vd_next)

    # 块几何统一来自方向几何（chunk.py helper），不再内联 256//sew 与 32。
    chunk_n = _chunk_size(sew)
    c_bytes = _chunk_bytes()
    elem_bytes = sew // 8
    shift_amt = {8: 5, 16: 4, 32: 3, 64: 2}[sew]
    mask = chunk_n - 1

    vtemps = VRegTempAllocator(insn)
    seg0_vreg = vtemps.alloc_vreg_group(2)
    seg1_vreg = f"v{int(seg0_vreg[1:]) + 1}"

    temps = TempRegisterAllocator(insn, reserved_gprs=("t6",))
    vl_reg = temps.alloc_gpr()
    chunk_count = temps.alloc_gpr()
    tail_count = temps.alloc_gpr()
    mem_ptr = temps.alloc_gpr()
    vd_ptr = temps.alloc_gpr()
    vd_next_ptr = temps.alloc_gpr()
    temp = temps.alloc_gpr()
    elem_idx = temps.alloc_gpr()

    segload_instr = f"vlsseg2e{sew}.v" if is_strided else f"vlseg2e{sew}.v"

    mode_label = "strided" if is_strided else "unit-stride"
    lines.append(f"# {insn.opcode} {vd}, ({rs1}){' ,' + stride_reg if stride_reg else ''} (256-bit, {mode_label})")
    lines.append(f"# NF=2: segment 0 -> {vd}, segment 1 -> {vd_next}")
    lines.append("")

    # 加载 vl 并计算块数/尾数
    _load_vl_from_csr(lines, vl_reg=vl_reg, addr_reg=chunk_count)
    lines.append(f"    srli    {chunk_count}, {vl_reg}, {shift_amt}       # {chunk_count} = vl / {chunk_n}")
    lines.append(f"    andi    {tail_count}, {vl_reg}, {mask}              # {tail_count} = vl % {chunk_n}")
    lines.append("")

    # 设置指针
    lines.append(f"    mv      {mem_ptr}, {rs1}                  # mem_ptr = base address")
    lines.append(f"    li      {temp}, {vd_off:#x}")
    lines.append(f"    add     {vd_ptr}, t6, {temp}             # {vd_ptr} = &{vd}")
    lines.append(f"    li      {temp}, {vd_next_off:#x}")
    lines.append(f"    add     {vd_next_ptr}, t6, {temp}        # {vd_next_ptr} = &{vd_next}")
    lines.append("")

    # 主循环: 使用硬件段加载
    main_loop = new_label(f"vlseg2e{sew}_main")
    after_main = new_label(f"vlseg2e{sew}_after")

    lines.append(f"    # --- 主循环: 每块 {chunk_n} 个元素对 ---")
    lines.append(f"    beqz    {chunk_count}, {after_main}")
    lines.append(f"{main_loop}:")
    _emit_vsetvl_for_chunk(lines, chunk_n, sew, "m1", vl_reg, scratch_reg=temp)
    lines.append("")

    if is_strided:
        lines.append(f"    {segload_instr} {seg0_vreg}, ({mem_ptr}), {stride_reg}")
    else:
        lines.append(f"    {segload_instr} {seg0_vreg}, ({mem_ptr})")
    lines.append(f"    vse{sew}.v {seg0_vreg}, ({vd_ptr})         # 写 segment 0 到 sim_state")
    lines.append(f"    vse{sew}.v {seg1_vreg}, ({vd_next_ptr})    # 写 segment 1 到 sim_state")
    lines.append("")

    # 前进指针 (segment load 后 mem_ptr 按 element 对前进)
    pair_bytes = elem_bytes * 2
    if is_strided:
        lines.append(f"    mv      {temp}, {stride_reg}")
        lines.append(f"    li      {elem_idx}, {chunk_n}")
        lines.append(f"    mul     {temp}, {temp}, {elem_idx}")
        lines.append(f"    add     {mem_ptr}, {mem_ptr}, {temp}       # mem_ptr += chunk_n * stride")
    else:
        lines.append(f"    addi    {mem_ptr}, {mem_ptr}, {c_bytes * 2}  # mem_ptr += chunk_n * 2 * elem_bytes")
    lines.append(f"    addi    {vd_ptr}, {vd_ptr}, {c_bytes}")
    lines.append(f"    addi    {vd_next_ptr}, {vd_next_ptr}, {c_bytes}")
    lines.append(f"    addi    {chunk_count}, {chunk_count}, -1")
    lines.append(f"    bnez    {chunk_count}, {main_loop}")
    lines.append(f"{after_main}:")
    lines.append("")

    # 尾部标量回退
    lines.append(f"    # --- 尾部标量回退: 剩余 {tail_count} 个元素对 ---")
    tail_loop = new_label(f"vlseg2e{sew}_tail")
    tail_end = new_label(f"vlseg2e{sew}_tail_end")

    load_instr = {8: "lbu", 16: "lhu", 32: "lwu", 64: "ld"}[sew]
    store_instr = {8: "sb", 16: "sh", 32: "sw", 64: "sd"}[sew]

    lines.append(f"{tail_loop}:")
    lines.append(f"    beqz    {tail_count}, {tail_end}")
    # 加载 segment 0
    lines.append(f"    {load_instr:<8} {temp}, 0({mem_ptr})              # segment 0: mem[0]")
    lines.append(f"    {store_instr:<8} {temp}, 0({vd_ptr})")
    # 加载 segment 1
    lines.append(f"    {load_instr:<8} {temp}, {elem_bytes}({mem_ptr})   # segment 1: mem[{elem_bytes}]")
    lines.append(f"    {store_instr:<8} {temp}, 0({vd_next_ptr})")
    if is_strided:
        lines.append(f"    add     {mem_ptr}, {mem_ptr}, {stride_reg}    # mem_ptr += stride")
    else:
        lines.append(f"    addi    {mem_ptr}, {mem_ptr}, {elem_bytes * 2}")
    lines.append(f"    addi    {vd_ptr}, {vd_ptr}, {elem_bytes}")
    lines.append(f"    addi    {vd_next_ptr}, {vd_next_ptr}, {elem_bytes}")
    lines.append(f"    addi    {tail_count}, {tail_count}, -1")
    lines.append(f"    j       {tail_loop}")
    lines.append(f"{tail_end}:")

    return lines


def _emit_vsseg2_chunked(
    insn: RVInstruction,
    state: StateTracker,
    allocator: SimulatedStateLayout,
    new_label,
    sew: int,
    is_strided: bool,
) -> List[str]:
    """
    分块翻译 vsseg2e{sew}.v / vssseg2e{sew}.v (NF=2 segment store)。

    主循环从 simulated_cpu_state 中按源 EMUL 定位的两个字段组加载段对到临时 vreg，
    再用实际硬件 vsseg2e{sew}.v 写入内存。尾部用标量回退。
    """
    lines = []
    operands = insn.operands
    if len(operands) < 2:
        raise InstructionValidationError(insn, f"Invalid operands for {insn.opcode}: {insn.op_str}")

    vs3 = str(operands[0])
    rs1 = str(operands[1]).strip("()")
    stride_reg = None
    if is_strided:
        if len(operands) < 3:
            raise InstructionValidationError(insn, f"strided segstore requires stride operand: {insn.op_str}")
        stride_reg = str(operands[2])

    vs3, vs3_next = _segment_field_registers(insn, state, sew)
    vs3_off = allocator.get_offset(vs3)
    vs3_next_off = allocator.get_offset(vs3_next)

    chunk_n = _chunk_size(sew)
    c_bytes = _chunk_bytes()
    elem_bytes = sew // 8
    shift_amt = {8: 5, 16: 4, 32: 3, 64: 2}[sew]
    mask = chunk_n - 1

    vtemps = VRegTempAllocator(insn)
    seg0_vreg = vtemps.alloc_vreg_group(2)
    seg1_vreg = f"v{int(seg0_vreg[1:]) + 1}"

    temps = TempRegisterAllocator(insn, reserved_gprs=("t6",))
    vl_reg = temps.alloc_gpr()
    chunk_count = temps.alloc_gpr()
    tail_count = temps.alloc_gpr()
    mem_ptr = temps.alloc_gpr()
    vs3_ptr = temps.alloc_gpr()
    vs3_next_ptr = temps.alloc_gpr()
    temp = temps.alloc_gpr()
    elem_idx = temps.alloc_gpr()

    segstore_instr = f"vssseg2e{sew}.v" if is_strided else f"vsseg2e{sew}.v"

    mode_label = "strided" if is_strided else "unit-stride"
    lines.append(f"# {insn.opcode} {vs3}, ({rs1}){' ,' + stride_reg if stride_reg else ''} (256-bit, {mode_label})")
    lines.append(f"# NF=2: segment 0 <- {vs3}, segment 1 <- {vs3_next}")
    lines.append("")

    _load_vl_from_csr(lines, vl_reg=vl_reg, addr_reg=chunk_count)
    lines.append(f"    srli    {chunk_count}, {vl_reg}, {shift_amt}       # {chunk_count} = vl / {chunk_n}")
    lines.append(f"    andi    {tail_count}, {vl_reg}, {mask}              # {tail_count} = vl % {chunk_n}")
    lines.append("")

    lines.append(f"    mv      {mem_ptr}, {rs1}                  # mem_ptr = base address")
    lines.append(f"    li      {temp}, {vs3_off:#x}")
    lines.append(f"    add     {vs3_ptr}, t6, {temp}            # {vs3_ptr} = &{vs3}")
    lines.append(f"    li      {temp}, {vs3_next_off:#x}")
    lines.append(f"    add     {vs3_next_ptr}, t6, {temp}       # {vs3_next_ptr} = &{vs3_next}")
    lines.append("")

    main_loop = new_label(f"vsseg2e{sew}_main")
    after_main = new_label(f"vsseg2e{sew}_after")

    lines.append(f"    # --- 主循环: 每块 {chunk_n} 个元素对 ---")
    lines.append(f"    beqz    {chunk_count}, {after_main}")
    lines.append(f"{main_loop}:")
    _emit_vsetvl_for_chunk(lines, chunk_n, sew, "m1", vl_reg, scratch_reg=temp)
    lines.append("")

    lines.append(f"    vle{sew}.v {seg0_vreg}, ({vs3_ptr})        # 从 sim_state 加载 segment 0")
    lines.append(f"    vle{sew}.v {seg1_vreg}, ({vs3_next_ptr})   # 从 sim_state 加载 segment 1")

    if is_strided:
        lines.append(f"    {segstore_instr} {seg0_vreg}, ({mem_ptr}), {stride_reg}")
    else:
        lines.append(f"    {segstore_instr} {seg0_vreg}, ({mem_ptr})")
    lines.append("")

    if is_strided:
        lines.append(f"    mv      {temp}, {stride_reg}")
        lines.append(f"    li      {elem_idx}, {chunk_n}")
        lines.append(f"    mul     {temp}, {temp}, {elem_idx}")
        lines.append(f"    add     {mem_ptr}, {mem_ptr}, {temp}       # mem_ptr += chunk_n * stride")
    else:
        lines.append(f"    addi    {mem_ptr}, {mem_ptr}, {c_bytes * 2}")
    lines.append(f"    addi    {vs3_ptr}, {vs3_ptr}, {c_bytes}")
    lines.append(f"    addi    {vs3_next_ptr}, {vs3_next_ptr}, {c_bytes}")
    lines.append(f"    addi    {chunk_count}, {chunk_count}, -1")
    lines.append(f"    bnez    {chunk_count}, {main_loop}")
    lines.append(f"{after_main}:")
    lines.append("")

    # 尾部标量回退
    lines.append(f"    # --- 尾部标量回退: 剩余 {tail_count} 个元素对 ---")
    tail_loop = new_label(f"vsseg2e{sew}_tail")
    tail_end = new_label(f"vsseg2e{sew}_tail_end")

    load_instr = {8: "lbu", 16: "lhu", 32: "lwu", 64: "ld"}[sew]
    store_instr = {8: "sb", 16: "sh", 32: "sw", 64: "sd"}[sew]

    lines.append(f"{tail_loop}:")
    lines.append(f"    beqz    {tail_count}, {tail_end}")
    # 存储 segment 0
    lines.append(f"    {load_instr:<8} {temp}, 0({vs3_ptr})              # segment 0 <- {vs3}[i]")
    lines.append(f"    {store_instr:<8} {temp}, 0({mem_ptr})")
    # 存储 segment 1
    lines.append(f"    {load_instr:<8} {temp}, 0({vs3_next_ptr})         # segment 1 <- {vs3_next}[i]")
    lines.append(f"    {store_instr:<8} {temp}, {elem_bytes}({mem_ptr})")
    if is_strided:
        lines.append(f"    add     {mem_ptr}, {mem_ptr}, {stride_reg}")
    else:
        lines.append(f"    addi    {mem_ptr}, {mem_ptr}, {elem_bytes * 2}")
    lines.append(f"    addi    {vs3_ptr}, {vs3_ptr}, {elem_bytes}")
    lines.append(f"    addi    {vs3_next_ptr}, {vs3_next_ptr}, {elem_bytes}")
    lines.append(f"    addi    {tail_count}, {tail_count}, -1")
    lines.append(f"    j       {tail_loop}")
    lines.append(f"{tail_end}:")

    return lines


# Individual handlers


def _build_vlseg2e32_v_lines(context) -> list[str]:
    insn = context.instruction
    state = context.state
    allocator = context.layout
    new_label = context.new_label
    return _emit_vlseg2_chunked(insn, state, allocator, new_label, sew=32, is_strided=False)


def _build_vlseg2e64_v_lines(context) -> list[str]:
    insn = context.instruction
    state = context.state
    allocator = context.layout
    new_label = context.new_label
    return _emit_vlseg2_chunked(insn, state, allocator, new_label, sew=64, is_strided=False)


def _build_vsseg2e32_v_lines(context) -> list[str]:
    insn = context.instruction
    state = context.state
    allocator = context.layout
    new_label = context.new_label
    return _emit_vsseg2_chunked(insn, state, allocator, new_label, sew=32, is_strided=False)


def _build_vsseg2e64_v_lines(context) -> list[str]:
    insn = context.instruction
    state = context.state
    allocator = context.layout
    new_label = context.new_label
    return _emit_vsseg2_chunked(insn, state, allocator, new_label, sew=64, is_strided=False)


def _build_vsseg4e64_v_lines(context) -> list[str]:
    """
    翻译真实 llama 输入中的 ``vsseg4e64.v``（SEW=64、LMUL=m2）。

    源指令的四个 field 分别从四个 m2 模拟寄存器组读取；目标 VLEN=256
    也使用 e64,m2，因此每块处理 8 个元素，四个 field 合计占用 m8。
    尾数通过最后一个缩短 VL 的 RVV 块处理，不使用标量 store 循环。
    """
    insn = context.instruction
    state = context.state
    allocator = context.layout
    new_label = context.new_label
    operands = list(insn.operands)
    if len(operands) != 2 or str(operands[-1]).endswith(".t"):
        raise InstructionValidationError(insn, f"vsseg4e64.v 当前只支持 unmasked 形式: {insn.op_str}")
    if state.sew != 64 or float(state.lmul) != 2.0:
        raise InstructionValidationError(
            insn,
            "vsseg4e64.v 当前只支持 e64,m2，实际为 "
            f"e{state.sew},m{state.lmul:g}: {insn.op_str}",
        )

    vs3 = str(operands[0])
    rs1 = str(operands[1]).strip("()")
    if not vs3.startswith("v") or not vs3[1:].isdigit():
        raise InstructionValidationError(insn, f"非法 vsseg4e64.v 源寄存器: {insn.op_str}")
    base = int(vs3[1:])
    # NF=4、EMUL=2 要求首寄存器按 m2 对齐，且最后一个 field 组不能越过 v31。
    if base % 2 or base + 8 > 32:
        raise InstructionValidationError(insn, f"vsseg4e64.v 源寄存器组未按 NF=4/EMUL=2 对齐: {insn.op_str}")

    field_regs = tuple(f"v{base + index * 2}" for index in range(4))
    temps = context.temp_register_allocator
    vl_reg = temps.alloc_gpr()
    full_reg = temps.alloc_gpr()
    tail_reg = temps.alloc_gpr()
    mem_ptr = temps.alloc_gpr()
    field_ptrs = tuple(temps.alloc_gpr() for _ in range(4))
    scratch = temps.alloc_gpr()

    # v8/v10/v12/v14 是一个合法的 NF=4、LMUL=m2 临时 tuple。源 v24 等
    # 名字只描述模拟状态槽，并不是翻译块入口处的 live 物理 vreg。
    target_fields = ("v8", "v10", "v12", "v14")
    record_vreg_group("v8", 8)
    chunk_n = 8
    field_step = 64
    memory_step = chunk_n * 4 * 8
    lines = [
        f"# vsseg4e64.v {vs3}, ({rs1}) (RVV256, NF=4, source e64,m2)",
        "# 四个 field 均从 simulated_cpu_state 读取；每条源指令结束前内存已完成写入",
    ]
    _load_vl_from_csr(lines, vl_reg=vl_reg, addr_reg=full_reg)
    lines.append(f"    srli    {full_reg}, {vl_reg}, 3")
    lines.append(f"    andi    {tail_reg}, {vl_reg}, 7")
    lines.append(f"    mv      {mem_ptr}, {rs1}")
    for pointer, source_reg in zip(field_ptrs, field_regs):
        _emit_state_ptr(lines, pointer, allocator.get_offset(source_reg))

    loop = new_label("vsseg4e64_main")
    after = new_label("vsseg4e64_after")
    end = new_label("vsseg4e64_end")
    lines.append(f"    beqz    {full_reg}, {after}")
    _emit_vsetvl_for_chunk(lines, chunk_n, 64, "m2", vl_reg, scratch_reg=scratch)
    lines.append(f"{loop}:")

    def emit_body() -> None:
        for target, pointer, source_reg in zip(target_fields, field_ptrs, field_regs):
            lines.append(f"    vle64.v {target}, ({pointer})        # field <- {source_reg}")
        lines.append(f"    vsseg4e64.v v8, ({mem_ptr})")

    emit_body()
    for pointer in field_ptrs:
        lines.append(f"    addi    {pointer}, {pointer}, {field_step}")
    lines.append(f"    addi    {mem_ptr}, {mem_ptr}, {memory_step}")
    lines.append(f"    addi    {full_reg}, {full_reg}, -1")
    lines.append(f"    bnez    {full_reg}, {loop}")
    lines.append(f"{after}:")
    lines.append(f"    beqz    {tail_reg}, {end}")
    lines.append(f"    vsetvli zero, {tail_reg}, e64, m2, ta, ma")
    emit_body()
    lines.append(f"{end}:")
    return lines


def _build_vlsseg2e32_v_lines(context) -> list[str]:
    insn = context.instruction
    state = context.state
    allocator = context.layout
    new_label = context.new_label
    return _emit_vlseg2_chunked(insn, state, allocator, new_label, sew=32, is_strided=True)


def _build_vlsseg2e64_v_lines(context) -> list[str]:
    insn = context.instruction
    state = context.state
    allocator = context.layout
    new_label = context.new_label
    return _emit_vlseg2_chunked(insn, state, allocator, new_label, sew=64, is_strided=True)


def _build_vssseg2e32_v_lines(context) -> list[str]:
    insn = context.instruction
    state = context.state
    allocator = context.layout
    new_label = context.new_label
    return _emit_vsseg2_chunked(insn, state, allocator, new_label, sew=32, is_strided=True)


def _build_vssseg2e64_v_lines(context) -> list[str]:
    insn = context.instruction
    state = context.state
    allocator = context.layout
    new_label = context.new_label
    return _emit_vsseg2_chunked(insn, state, allocator, new_label, sew=64, is_strided=True)
