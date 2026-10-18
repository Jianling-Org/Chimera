# src/riscv/extensions/rvv/backends/rvv256/handlers/mask.py
"""
256-bit RVV 模式向量掩码指令翻译模块

将 VLEN=1024 的 RVV 向量掩码指令翻译为 256-bit 实际 RVV 指令 + 标量回退

Mask 位布局 (256-bit 模式):
- 严格遵循 RVV 1.0 bit-packed mask layout
- 元素 i 的 mask bit 位于 byte (i/8) 的 (i%8) 位 (LSB 方向)
- 使用 lbu/sb 逐字节访问 simulated_cpu_state 中的 mask vreg
- 与标量模式 mask 工具的 64-bit ``ld`` 访问在位级结果上
  兼容 (little-endian RISC-V 下 ld 将 byte 0 读入 bit 0-7)

包含:
- vmfgt.vf / vmfle.vf / vmfne.vf: 浮点比较
- vcpop.m: 掩码population count (RVV 1.0 bit-packed)
- vlm.v: mask load
- vmsne.vv / vmseq.vi / vmsleu.vi: integer compare to mask
- vmor.mm / vmclr.m: mask 逻辑
- vfirst.m: find first set mask bit
- vmerge.vvm: merge by v0 mask
"""

from typing import List
from riscv.frontend.model import RVInstruction
from riscv.extensions.rvv.analysis.config import StateTracker
from riscv.extensions.rvv.runtime.layout import SimulatedStateLayout
from riscv.extensions.rvv.translation.contracts import InstructionValidationError
from riscv.extensions.rvv.translation.temps import TempRegisterAllocator
from riscv.extensions.rvv.backends.rvv256.support import _emit_state_ptr, _load_vl_from_csr


# ============================================================================
# 辅助函数
# ============================================================================

def _get_int_load(sew: int) -> str:
    """返回对应 SEW 的标量整数加载指令"""
    return {8: 'lbu', 16: 'lhu', 32: 'lwu', 64: 'ld'}[sew]


def _get_int_load_signed(sew: int) -> str:
    """返回对应 SEW 的有符号标量整数加载指令"""
    return {8: 'lb', 16: 'lh', 32: 'lw', 64: 'ld'}[sew]


def _get_int_store(sew: int) -> str:
    """返回对应 SEW 的标量整数存储指令"""
    return {8: 'sb', 16: 'sh', 32: 'sw', 64: 'sd'}[sew]


def _parse_int(value: str) -> int:
    """Parse decimal/hex integer operands."""
    return int(str(value), 0)


def _emit_byte_count_from_vl(lines: List[str], byte_count: str, vl_reg: str) -> None:
    """byte_count = ceil(vl / 8), used by RVV mask memory layout."""
    lines.append(f"    addi    {byte_count}, {vl_reg}, 7")
    lines.append(f"    srli    {byte_count}, {byte_count}, 3        # {byte_count} = ceil(vl / 8)")


def _emit_mask_result_loop_header(
    insn: RVInstruction,
    state: StateTracker,
    allocator: SimulatedStateLayout,
    new_label,
    lines: List[str],
    vd: str,
    vs2: str,
    need_vs1: bool = False,
    vs1: str | None = None,
):
    """
    Shared setup for scalar bit-packed mask producing loops.

    RVV 1.0 mask registers use one bit per element.  In simulated_cpu_state the
    mask vreg is therefore treated as raw bytes, where bit i stores mask[i].
    """
    sew = state.sew
    elem_bytes = sew // 8
    vd_off = allocator.get_offset(vd)
    vs2_off = allocator.get_offset(vs2)
    vs1_off = allocator.get_offset(vs1) if need_vs1 and vs1 else None

    temps = TempRegisterAllocator(insn, reserved_gprs=("t6",))
    vl_reg = temps.alloc_gpr()
    vs2_ptr = temps.alloc_gpr()
    vs1_ptr = temps.alloc_gpr() if need_vs1 else None
    vd_ptr = temps.alloc_gpr()
    bit_pos = temps.alloc_gpr()
    byte_acc = temps.alloc_gpr()
    val2 = temps.alloc_gpr()
    val1 = temps.alloc_gpr()
    tmp = temps.alloc_gpr()
    addr = temps.alloc_gpr()

    _load_vl_from_csr(lines, vl_reg=vl_reg, addr_reg=addr)
    lines.append(f"    li      {tmp}, {vs2_off:#x}")
    lines.append(f"    add     {vs2_ptr}, t6, {tmp}            # {vs2_ptr} = &{vs2}")
    if need_vs1:
        lines.append(f"    li      {tmp}, {vs1_off:#x}")
        lines.append(f"    add     {vs1_ptr}, t6, {tmp}            # {vs1_ptr} = &{vs1}")
    lines.append(f"    li      {tmp}, {vd_off:#x}")
    lines.append(f"    add     {vd_ptr}, t6, {tmp}             # {vd_ptr} = &{vd} mask bytes")
    lines.append(f"    li      {bit_pos}, 0")
    lines.append(f"    li      {byte_acc}, 0")
    return {
        "sew": sew,
        "elem_bytes": elem_bytes,
        "vl_reg": vl_reg,
        "vs2_ptr": vs2_ptr,
        "vs1_ptr": vs1_ptr,
        "vd_ptr": vd_ptr,
        "bit_pos": bit_pos,
        "byte_acc": byte_acc,
        "val2": val2,
        "val1": val1,
        "tmp": tmp,
    }


# ============================================================================
# vmfgt.vf 指令翻译 (浮点大于比较)
# ============================================================================

def _build_vmfgt_vf_lines(context) -> list[str]:
    """
    翻译 vmfgt.vf 指令 (256-bit 模式)

    格式: vmfgt.vf vd, vs2, rs1
    语义: vd.mask[i] = (vs2[i] > f[rs1])

    策略:
    - 标量逐元素比较并写入 RVV 1.0 bit-packed mask layout
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

    # vmfgt.vf vd, vs2, rs1
    vd = operands[0]
    vs2 = operands[1]
    rs1 = operands[2]

    sew = state.sew
    elem_bytes = sew // 8
    if sew not in (32, 64):
        raise InstructionValidationError(insn, f"vmfgt.vf only supports floating SEW=32/64, got SEW={sew}")

    vd_off = allocator.get_offset(vd)
    vs2_off = allocator.get_offset(vs2)

    # 分配 GPR 临时寄存器
    temps = context.temp_register_allocator
    vl_reg = temps.alloc_gpr()
    remaining = temps.alloc_gpr()
    vs2_ptr = temps.alloc_gpr()
    vd_ptr = temps.alloc_gpr()
    bit_pos = temps.alloc_gpr()
    byte_acc = temps.alloc_gpr()
    bit_mask = temps.alloc_gpr()
    addr = temps.alloc_gpr()
    tmp = temps.alloc_gpr()
    value_fpr = temps.alloc_fpr()

    load_instr = {64: 'fld', 32: 'flw'}[sew]

    lines.append(f"# vmfgt.vf {vd}, {vs2}, {rs1} (256-bit mode, RVV1.0 bit-packed mask)")
    lines.append(f"# Semantic: {vd}.mask[i] = ({vs2}[i] > {rs1}), SEW={sew}")
    lines.append("")

    _load_vl_from_csr(lines, vl_reg=vl_reg, addr_reg=addr)
    lines.append(f"    mv      {remaining}, {vl_reg}              # remaining elements")
    lines.append(f"    li      {tmp}, {vs2_off:#x}")
    lines.append(f"    add     {vs2_ptr}, t6, {tmp}              # {vs2_ptr} = &{vs2}")
    lines.append(f"    li      {tmp}, {vd_off:#x}")
    lines.append(f"    add     {vd_ptr}, t6, {tmp}               # {vd_ptr} = &{vd} mask bytes")
    lines.append(f"    li      {bit_pos}, 0")
    lines.append(f"    li      {byte_acc}, 0")
    lines.append("")

    loop_label = new_label("vmfgt_vf_mask_loop")
    bit_done = new_label("vmfgt_vf_mask_bit_done")
    flush_label = new_label("vmfgt_vf_mask_flush")
    end_label = new_label("vmfgt_vf_mask_end")

    # 比较: vs2[i] > rs1 -> set mask bit
    # flt.d tmp, rs1, vs2[i]  => tmp = (rs1 < vs2[i]) = (vs2[i] > rs1)
    fcvt_cmp = {64: 'flt.d', 32: 'flt.s'}[sew]

    lines.append(f"{loop_label}:")
    lines.append(f"    beqz    {remaining}, {flush_label}")
    lines.append(f"    {load_instr:<8} {value_fpr}, 0({vs2_ptr})           # {value_fpr} = {vs2}[i]")
    lines.append(f"    {fcvt_cmp:<8} {tmp}, {rs1}, {value_fpr}           # {tmp} = ({value_fpr} > {rs1})")
    lines.append(f"    beqz    {tmp}, {bit_done}")
    lines.append(f"    li      {bit_mask}, 1")
    lines.append(f"    sll     {bit_mask}, {bit_mask}, {bit_pos}")
    lines.append(f"    or      {byte_acc}, {byte_acc}, {bit_mask}")
    lines.append(f"{bit_done}:")
    lines.append(f"    addi    {vs2_ptr}, {vs2_ptr}, {elem_bytes}")
    lines.append(f"    addi    {bit_pos}, {bit_pos}, 1")
    lines.append(f"    addi    {remaining}, {remaining}, -1")
    lines.append(f"    li      {tmp}, 8")
    lines.append(f"    bltu    {bit_pos}, {tmp}, {loop_label}")
    lines.append(f"    sb      {byte_acc}, 0({vd_ptr})")
    lines.append(f"    addi    {vd_ptr}, {vd_ptr}, 1")
    lines.append(f"    li      {bit_pos}, 0")
    lines.append(f"    li      {byte_acc}, 0")
    lines.append(f"    j       {loop_label}")
    lines.append(f"{flush_label}:")
    lines.append(f"    beqz    {bit_pos}, {end_label}")
    lines.append(f"    sb      {byte_acc}, 0({vd_ptr})")
    lines.append(f"{end_label}:")

    return lines


def _build_vmfle_vf_lines(context) -> list[str]:
    """
    翻译 vmfle.vf 指令 (256-bit 模式)

    格式: vmfle.vf vd, vs2, rs1
    语义: vd.mask[i] = (vs2[i] <= f[rs1])

    策略:
    - 标量逐元素比较并写入 RVV 1.0 bit-packed mask layout
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
    if sew not in (32, 64):
        raise InstructionValidationError(insn, f"vmfle.vf only supports floating SEW=32/64, got SEW={sew}")

    vd_off = allocator.get_offset(vd)
    vs2_off = allocator.get_offset(vs2)

    temps = context.temp_register_allocator
    vl_reg = temps.alloc_gpr()
    remaining = temps.alloc_gpr()
    vs2_ptr = temps.alloc_gpr()
    vd_ptr = temps.alloc_gpr()
    bit_pos = temps.alloc_gpr()
    byte_acc = temps.alloc_gpr()
    bit_mask = temps.alloc_gpr()
    addr = temps.alloc_gpr()
    tmp = temps.alloc_gpr()
    value_fpr = temps.alloc_fpr()

    load_instr = {64: 'fld', 32: 'flw'}[sew]
    cmp_instr = {64: 'fle.d', 32: 'fle.s'}[sew]

    lines.append(f"# vmfle.vf {vd}, {vs2}, {rs1} (256-bit mode, RVV1.0 bit-packed mask)")
    lines.append(f"# Semantic: {vd}.mask[i] = ({vs2}[i] <= {rs1}), SEW={sew}")
    lines.append("")

    _load_vl_from_csr(lines, vl_reg=vl_reg, addr_reg=addr)
    lines.append(f"    mv      {remaining}, {vl_reg}              # remaining elements")
    lines.append(f"    li      {tmp}, {vs2_off:#x}")
    lines.append(f"    add     {vs2_ptr}, t6, {tmp}              # {vs2_ptr} = &{vs2}")
    lines.append(f"    li      {tmp}, {vd_off:#x}")
    lines.append(f"    add     {vd_ptr}, t6, {tmp}               # {vd_ptr} = &{vd} mask bytes")
    lines.append(f"    li      {bit_pos}, 0")
    lines.append(f"    li      {byte_acc}, 0")
    lines.append("")

    loop_label = new_label("vmfle_vf_mask_loop")
    bit_done = new_label("vmfle_vf_mask_bit_done")
    flush_label = new_label("vmfle_vf_mask_flush")
    end_label = new_label("vmfle_vf_mask_end")

    lines.append(f"{loop_label}:")
    lines.append(f"    beqz    {remaining}, {flush_label}")
    lines.append(f"    {load_instr:<8} {value_fpr}, 0({vs2_ptr})           # {value_fpr} = {vs2}[i]")
    lines.append(f"    {cmp_instr:<8} {tmp}, {value_fpr}, {rs1}           # {tmp} = ({value_fpr} <= {rs1})")
    lines.append(f"    beqz    {tmp}, {bit_done}")
    lines.append(f"    li      {bit_mask}, 1")
    lines.append(f"    sll     {bit_mask}, {bit_mask}, {bit_pos}")
    lines.append(f"    or      {byte_acc}, {byte_acc}, {bit_mask}")
    lines.append(f"{bit_done}:")
    lines.append(f"    addi    {vs2_ptr}, {vs2_ptr}, {elem_bytes}")
    lines.append(f"    addi    {bit_pos}, {bit_pos}, 1")
    lines.append(f"    addi    {remaining}, {remaining}, -1")
    lines.append(f"    li      {tmp}, 8")
    lines.append(f"    bltu    {bit_pos}, {tmp}, {loop_label}")
    lines.append(f"    sb      {byte_acc}, 0({vd_ptr})")
    lines.append(f"    addi    {vd_ptr}, {vd_ptr}, 1")
    lines.append(f"    li      {bit_pos}, 0")
    lines.append(f"    li      {byte_acc}, 0")
    lines.append(f"    j       {loop_label}")
    lines.append(f"{flush_label}:")
    lines.append(f"    beqz    {bit_pos}, {end_label}")
    lines.append(f"    sb      {byte_acc}, 0({vd_ptr})")
    lines.append(f"{end_label}:")

    return lines


def _build_vmfne_vf_lines(context) -> list[str]:
    """翻译无掩码 ``vmfne.vf vd, vs2, rs1``。

    RVV 的 ``!=`` 对 NaN 也应产生 true。标量 RV64 路径使用 ``feq`` 后取反：
    RISC-V ``feq.s/d`` 对 NaN 返回 0，``xori 1`` 正好得到无序不等比较结果。
    结果仍写入 RVV 1.0 bit-packed mask，而不是把每个元素误写成一个字节。
    """
    insn = context.instruction
    state = context.state
    allocator = context.layout
    new_label = context.new_label
    operands = insn.operands
    if len(operands) != 3:
        raise InstructionValidationError(insn, f"Invalid operands for {insn.opcode}: {insn.op_str}")

    vd, vs2, rs1 = operands
    sew = state.sew
    elem_bytes = sew // 8
    if sew not in (32, 64):
        raise InstructionValidationError(insn, f"vmfne.vf only supports floating SEW=32/64, got SEW={sew}")

    vd_off = allocator.get_offset(vd)
    vs2_off = allocator.get_offset(vs2)

    temps = context.temp_register_allocator
    vl_reg = temps.alloc_gpr()
    remaining = temps.alloc_gpr()
    vs2_ptr = temps.alloc_gpr()
    vd_ptr = temps.alloc_gpr()
    bit_pos = temps.alloc_gpr()
    byte_acc = temps.alloc_gpr()
    bit_mask = temps.alloc_gpr()
    addr = temps.alloc_gpr()
    tmp = temps.alloc_gpr()
    value_fpr = temps.alloc_fpr()

    load_instr = {64: "fld", 32: "flw"}[sew]
    equal_instr = {64: "feq.d", 32: "feq.s"}[sew]

    lines = [
        f"# vmfne.vf {vd}, {vs2}, {rs1} (256-bit mode, RVV1.0 bit-packed mask)",
        f"# Semantic: {vd}.mask[i] = ({vs2}[i] != {rs1}), SEW={sew}; NaN => true",
        "",
    ]
    _load_vl_from_csr(lines, vl_reg=vl_reg, addr_reg=addr)
    lines.append(f"    mv      {remaining}, {vl_reg}              # remaining elements")
    lines.append(f"    li      {tmp}, {vs2_off:#x}")
    lines.append(f"    add     {vs2_ptr}, t6, {tmp}              # {vs2_ptr} = &{vs2}")
    lines.append(f"    li      {tmp}, {vd_off:#x}")
    lines.append(f"    add     {vd_ptr}, t6, {tmp}               # {vd_ptr} = &{vd} mask bytes")
    lines.append(f"    li      {bit_pos}, 0")
    lines.append(f"    li      {byte_acc}, 0")
    lines.append("")

    loop_label = new_label("vmfne_vf_mask_loop")
    bit_done = new_label("vmfne_vf_mask_bit_done")
    flush_label = new_label("vmfne_vf_mask_flush")
    end_label = new_label("vmfne_vf_mask_end")

    lines.append(f"{loop_label}:")
    lines.append(f"    beqz    {remaining}, {flush_label}")
    lines.append(f"    {load_instr:<8} {value_fpr}, 0({vs2_ptr})           # {value_fpr} = {vs2}[i]")
    lines.append(f"    {equal_instr:<8} {tmp}, {value_fpr}, {rs1}           # {tmp} = ({value_fpr} == {rs1})")
    lines.append(f"    xori    {tmp}, {tmp}, 1                    # !=；NaN 的 feq 结果为 0，因此这里为 1")
    lines.append(f"    beqz    {tmp}, {bit_done}")
    lines.append(f"    li      {bit_mask}, 1")
    lines.append(f"    sll     {bit_mask}, {bit_mask}, {bit_pos}")
    lines.append(f"    or      {byte_acc}, {byte_acc}, {bit_mask}")
    lines.append(f"{bit_done}:")
    lines.append(f"    addi    {vs2_ptr}, {vs2_ptr}, {elem_bytes}")
    lines.append(f"    addi    {bit_pos}, {bit_pos}, 1")
    lines.append(f"    addi    {remaining}, {remaining}, -1")
    lines.append(f"    li      {tmp}, 8")
    lines.append(f"    bltu    {bit_pos}, {tmp}, {loop_label}")
    lines.append(f"    sb      {byte_acc}, 0({vd_ptr})")
    lines.append(f"    addi    {vd_ptr}, {vd_ptr}, 1")
    lines.append(f"    li      {bit_pos}, 0")
    lines.append(f"    li      {byte_acc}, 0")
    lines.append(f"    j       {loop_label}")
    lines.append(f"{flush_label}:")
    lines.append(f"    beqz    {bit_pos}, {end_label}")
    lines.append(f"    sb      {byte_acc}, 0({vd_ptr})")
    lines.append(f"{end_label}:")
    return lines


# ============================================================================
# RVV 1.0 bit-packed mask handlers
# ============================================================================

def _build_vcpop_m_lines(context) -> list[str]:
    """
    翻译 vcpop.m 指令 (256-bit 模式)

    格式: vcpop.m rd, vs2
    RVV 1.0 语义: rd = sum_i vs2.mask[i], i in [0, vl)

    mask register 按 RVV 1.0 的 bit-packed layout 存放在
    simulated_cpu_state 中：第 i 个 mask 元素是第 i bit。
    """
    insn = context.instruction
    allocator = context.layout
    new_label = context.new_label
    lines = []
    operands = insn.operands
    if len(operands) < 2:
        raise InstructionValidationError(insn, f"Invalid operands for {insn.opcode}: {insn.op_str}")

    rd = operands[0]
    vs2 = operands[1]
    vs2_off = allocator.get_offset(vs2)

    temps = context.temp_register_allocator
    vl_reg = temps.alloc_gpr()
    count_reg = temps.alloc_gpr()
    ptr_reg = temps.alloc_gpr()
    byte_reg = temps.alloc_gpr()
    bit_pos = temps.alloc_gpr()
    bit_reg = temps.alloc_gpr()
    addr_reg = temps.alloc_gpr()

    lines.append(f"# vcpop.m {rd}, {vs2} (256-bit mode, RVV1.0 bit-packed mask)")
    lines.append(f"# Semantic: {rd} = count of 1 bits in {vs2}.mask[0:vl]")
    _load_vl_from_csr(lines, vl_reg=vl_reg, addr_reg=addr_reg)
    lines.append(f"    li      {count_reg}, 0")
    lines.append(f"    li      {bit_pos}, 0")
    lines.append(f"    li      {ptr_reg}, {vs2_off:#x}")
    lines.append(f"    add     {ptr_reg}, t6, {ptr_reg}            # {ptr_reg} = &{vs2} mask bytes")

    loop_label = new_label("vcpop_loop")
    have_byte = new_label("vcpop_have_byte")
    next_label = new_label("vcpop_next")
    end_label = new_label("vcpop_end")

    lines.append(f"{loop_label}:")
    lines.append(f"    beqz    {vl_reg}, {end_label}")
    lines.append(f"    bnez    {bit_pos}, {have_byte}")
    lines.append(f"    lbu     {byte_reg}, 0({ptr_reg})           # load next mask byte")
    lines.append(f"{have_byte}:")
    lines.append(f"    srl     {bit_reg}, {byte_reg}, {bit_pos}")
    lines.append(f"    andi    {bit_reg}, {bit_reg}, 1")
    lines.append(f"    add     {count_reg}, {count_reg}, {bit_reg}")
    lines.append(f"    addi    {bit_pos}, {bit_pos}, 1")
    lines.append(f"    li      {bit_reg}, 8")
    lines.append(f"    bne     {bit_pos}, {bit_reg}, {next_label}")
    lines.append(f"    li      {bit_pos}, 0")
    lines.append(f"    addi    {ptr_reg}, {ptr_reg}, 1")
    lines.append(f"{next_label}:")
    lines.append(f"    addi    {vl_reg}, {vl_reg}, -1")
    lines.append(f"    j       {loop_label}")
    lines.append(f"{end_label}:")
    lines.append(f"    mv      {rd}, {count_reg}                  # {rd} = popcount({vs2}.mask)")

    return lines


def _build_vlm_v_lines(context) -> list[str]:
    """RVV 1.0: vlm.v vd, (rs1) loads ceil(vl/8) bytes of mask data."""
    insn = context.instruction
    allocator = context.layout
    new_label = context.new_label
    lines = []
    operands = insn.operands
    if len(operands) < 2:
        raise InstructionValidationError(insn, f"Invalid operands for {insn.opcode}: {insn.op_str}")

    vd = operands[0]
    rs1 = str(operands[1]).strip("()")
    vd_off = allocator.get_offset(vd)

    temps = context.temp_register_allocator
    vl_reg = temps.alloc_gpr()
    byte_count = temps.alloc_gpr()
    mem_ptr = temps.alloc_gpr()
    vd_ptr = temps.alloc_gpr()
    data = temps.alloc_gpr()

    lines.append(f"# vlm.v {vd}, ({rs1}) (256-bit mode, RVV1.0)")
    lines.append("# Semantic: load ceil(vl / 8) bytes of bit-packed mask data")
    lines.append(f"    mv      {mem_ptr}, {rs1}                  # source mask byte pointer")
    _load_vl_from_csr(lines, vl_reg=vl_reg, addr_reg=byte_count)
    _emit_byte_count_from_vl(lines, byte_count=byte_count, vl_reg=vl_reg)
    lines.append(f"    li      {vd_ptr}, {vd_off:#x}")
    lines.append(f"    add     {vd_ptr}, t6, {vd_ptr}            # {vd_ptr} = &{vd} mask bytes")

    loop_label = new_label("vlm_loop")
    end_label = new_label("vlm_end")
    lines.append(f"{loop_label}:")
    lines.append(f"    beqz    {byte_count}, {end_label}")
    lines.append(f"    lbu     {data}, 0({mem_ptr})")
    lines.append(f"    sb      {data}, 0({vd_ptr})")
    lines.append(f"    addi    {mem_ptr}, {mem_ptr}, 1")
    lines.append(f"    addi    {vd_ptr}, {vd_ptr}, 1")
    lines.append(f"    addi    {byte_count}, {byte_count}, -1")
    lines.append(f"    j       {loop_label}")
    lines.append(f"{end_label}:")

    return lines


def _emit_mask_compare_finish(
    lines: List[str],
    regs: dict,
    new_label,
    compare_lines: List[str],
    label_prefix: str,
) -> None:
    """Emit loop body trailer for bit-packed mask-producing compares."""
    vl_reg = regs["vl_reg"]
    vs2_ptr = regs["vs2_ptr"]
    vs1_ptr = regs["vs1_ptr"]
    vd_ptr = regs["vd_ptr"]
    bit_pos = regs["bit_pos"]
    byte_acc = regs["byte_acc"]
    val1 = regs["val1"]
    tmp = regs["tmp"]
    elem_bytes = regs["elem_bytes"]

    loop_label = new_label(f"{label_prefix}_loop")
    flush_label = new_label(f"{label_prefix}_flush")
    next_label = new_label(f"{label_prefix}_next")
    done_label = new_label(f"{label_prefix}_done")
    end_label = new_label(f"{label_prefix}_end")

    lines.append(f"{loop_label}:")
    lines.append(f"    beqz    {vl_reg}, {end_label}")
    lines.extend(compare_lines)
    lines.append(f"    sll     {tmp}, {tmp}, {bit_pos}")
    lines.append(f"    or      {byte_acc}, {byte_acc}, {tmp}")
    lines.append(f"    addi    {vs2_ptr}, {vs2_ptr}, {elem_bytes}")
    if vs1_ptr:
        lines.append(f"    addi    {vs1_ptr}, {vs1_ptr}, {elem_bytes}")
    lines.append(f"    addi    {bit_pos}, {bit_pos}, 1")
    lines.append(f"    li      {val1}, 8")
    lines.append(f"    beq     {bit_pos}, {val1}, {flush_label}")
    lines.append(f"    j       {next_label}")
    lines.append(f"{flush_label}:")
    lines.append(f"    sb      {byte_acc}, 0({vd_ptr})")
    lines.append(f"    addi    {vd_ptr}, {vd_ptr}, 1")
    lines.append(f"    li      {byte_acc}, 0")
    lines.append(f"    li      {bit_pos}, 0")
    lines.append(f"{next_label}:")
    lines.append(f"    addi    {vl_reg}, {vl_reg}, -1")
    lines.append(f"    j       {loop_label}")
    lines.append(f"{end_label}:")
    lines.append(f"    beqz    {bit_pos}, {done_label}")
    lines.append(f"    sb      {byte_acc}, 0({vd_ptr})             # store final partial mask byte")
    lines.append(f"{done_label}:")


def _build_vmsne_vv_lines(context) -> list[str]:
    """RVV 1.0: vmsne.vv vd, vs2, vs1 => vd.mask[i] = vs2[i] != vs1[i]."""
    insn = context.instruction
    state = context.state
    allocator = context.layout
    new_label = context.new_label
    lines = []
    operands = insn.operands
    if len(operands) != 3:
        raise InstructionValidationError(insn, f"vmsne.vv currently supports unmasked RVV1.0 form only: {insn.op_str}")
    vd, vs2, vs1 = operands
    regs = _emit_mask_result_loop_header(insn, state, allocator, new_label, lines, vd, vs2, True, vs1)
    load = _get_int_load(regs["sew"])
    lines.insert(0, f"# vmsne.vv {vd}, {vs2}, {vs1} (256-bit mode, RVV1.0 bit-packed mask)")
    compare = [
        f"    {load:<8} {regs['val2']}, 0({regs['vs2_ptr']})",
        f"    {load:<8} {regs['val1']}, 0({regs['vs1_ptr']})",
        f"    xor     {regs['tmp']}, {regs['val2']}, {regs['val1']}",
        f"    snez    {regs['tmp']}, {regs['tmp']}              # mask bit = ({vs2}[i] != {vs1}[i])",
    ]
    _emit_mask_compare_finish(lines, regs, new_label, compare, "vmsne_vv")
    return lines


def _build_vmsne_vi_lines(context) -> list[str]:
    """RVV 1.0: vmsne.vi vd, vs2, imm => vd.mask[i] = vs2[i] != imm."""
    insn = context.instruction
    state = context.state
    allocator = context.layout
    new_label = context.new_label
    lines = []
    operands = insn.operands
    if len(operands) != 3:
        raise InstructionValidationError(insn, f"vmsne.vi currently supports unmasked RVV1.0 form only: {insn.op_str}")
    vd, vs2, imm_s = operands
    imm = _parse_int(imm_s)
    if imm < -16 or imm > 15:
        raise InstructionValidationError(insn, f"vmsne.vi immediate must be signed 5-bit (-16..15), got {imm}")
    regs = _emit_mask_result_loop_header(insn, state, allocator, new_label, lines, vd, vs2)
    load = _get_int_load(regs["sew"])
    imm_bits = imm if regs["sew"] == 64 else imm & ((1 << regs["sew"]) - 1)
    lines.insert(0, f"# vmsne.vi {vd}, {vs2}, {imm} (256-bit mode, RVV1.0 bit-packed mask)")
    compare = [
        f"    {load:<8} {regs['val2']}, 0({regs['vs2_ptr']})",
        f"    li      {regs['val1']}, {imm_bits}",
        f"    xor     {regs['tmp']}, {regs['val2']}, {regs['val1']}",
        f"    snez    {regs['tmp']}, {regs['tmp']}              # mask bit = ({vs2}[i] != {imm})",
    ]
    _emit_mask_compare_finish(lines, regs, new_label, compare, "vmsne_vi")
    return lines


def _build_vmseq_vi_lines(context) -> list[str]:
    """RVV 1.0: vmseq.vi vd, vs2, imm => vd.mask[i] = vs2[i] == imm."""
    insn = context.instruction
    state = context.state
    allocator = context.layout
    new_label = context.new_label
    lines = []
    operands = insn.operands
    if len(operands) != 3:
        raise InstructionValidationError(insn, f"vmseq.vi currently supports unmasked RVV1.0 form only: {insn.op_str}")
    vd, vs2, imm_s = operands
    imm = _parse_int(imm_s)
    if imm < -16 or imm > 15:
        raise InstructionValidationError(insn, f"vmseq.vi immediate must be signed 5-bit (-16..15), got {imm}")
    regs = _emit_mask_result_loop_header(insn, state, allocator, new_label, lines, vd, vs2)
    load = _get_int_load(regs["sew"])
    imm_bits = imm if regs["sew"] == 64 else imm & ((1 << regs["sew"]) - 1)
    lines.insert(0, f"# vmseq.vi {vd}, {vs2}, {imm} (256-bit mode, RVV1.0 bit-packed mask)")
    compare = [
        f"    {load:<8} {regs['val2']}, 0({regs['vs2_ptr']})",
        f"    li      {regs['val1']}, {imm_bits}",
        f"    xor     {regs['tmp']}, {regs['val2']}, {regs['val1']}",
        f"    seqz    {regs['tmp']}, {regs['tmp']}              # mask bit = ({vs2}[i] == {imm})",
    ]
    _emit_mask_compare_finish(lines, regs, new_label, compare, "vmseq_vi")
    return lines


def _build_vmseq_vx_lines(context) -> list[str]:
    """RVV 1.0: vmseq.vx vd, vs2, rs1 => vd.mask[i] = vs2[i] == rs1."""
    insn = context.instruction
    state = context.state
    allocator = context.layout
    new_label = context.new_label
    lines = []
    operands = insn.operands
    if len(operands) != 3:
        raise InstructionValidationError(insn, f"vmseq.vx currently supports unmasked RVV1.0 form only: {insn.op_str}")
    vd, vs2, rs1 = operands
    regs = _emit_mask_result_loop_header(insn, state, allocator, new_label, lines, vd, vs2)
    load = _get_int_load(regs["sew"])
    lines.insert(0, f"# vmseq.vx {vd}, {vs2}, {rs1} (256-bit mode, RVV1.0 bit-packed mask)")
    compare = [
        f"    {load:<8} {regs['val2']}, 0({regs['vs2_ptr']})",
        f"    xor     {regs['tmp']}, {regs['val2']}, {rs1}",
        f"    seqz    {regs['tmp']}, {regs['tmp']}              # mask bit = ({vs2}[i] == {rs1})",
    ]
    _emit_mask_compare_finish(lines, regs, new_label, compare, "vmseq_vx")
    return lines


def _build_vmsleu_vi_lines(context) -> list[str]:
    """RVV 1.0: vmsleu.vi vd, vs2, imm => vd.mask[i] = unsigned(vs2[i]) <= unsigned(imm)."""
    insn = context.instruction
    state = context.state
    allocator = context.layout
    new_label = context.new_label
    lines = []
    operands = insn.operands
    if len(operands) != 3:
        raise InstructionValidationError(insn, f"vmsleu.vi currently supports unmasked RVV1.0 form only: {insn.op_str}")
    vd, vs2, imm_s = operands
    imm = _parse_int(imm_s)
    if imm < -16 or imm > 15:
        raise InstructionValidationError(insn, f"vmsleu.vi immediate must be signed 5-bit (-16..15), got {imm}")
    regs = _emit_mask_result_loop_header(insn, state, allocator, new_label, lines, vd, vs2)
    load = _get_int_load(regs["sew"])

    # RVV vi immediate 是 signed 5-bit，再按当前 SEW 解释为元素值；
    # 对 unsigned 比较来说，负立即数会变成对应 SEW 位宽的无符号大数。
    imm_bits = imm if regs["sew"] == 64 else imm & ((1 << regs["sew"]) - 1)
    lines.insert(0, f"# vmsleu.vi {vd}, {vs2}, {imm} (256-bit mode, RVV1.0 bit-packed mask)")
    compare = [
        f"    {load:<8} {regs['val2']}, 0({regs['vs2_ptr']})",
        f"    li      {regs['val1']}, {imm_bits}",
        f"    sltu    {regs['tmp']}, {regs['val1']}, {regs['val2']}   # tmp = (imm < {vs2}[i]) unsigned",
        f"    seqz    {regs['tmp']}, {regs['tmp']}              # mask bit = unsigned({vs2}[i]) <= unsigned({imm})",
    ]
    _emit_mask_compare_finish(lines, regs, new_label, compare, "vmsleu_vi")
    return lines


def _build_vmsgtu_vi_lines(context) -> list[str]:
    """RVV 1.0: vmsgtu.vi vd, vs2, imm => vd.mask[i] = unsigned(vs2[i]) > unsigned(imm)."""
    insn = context.instruction
    state = context.state
    allocator = context.layout
    new_label = context.new_label
    lines = []
    operands = insn.operands
    if len(operands) != 3:
        raise InstructionValidationError(insn, f"vmsgtu.vi currently supports unmasked RVV1.0 form only: {insn.op_str}")
    vd, vs2, imm_s = operands
    imm = _parse_int(imm_s)
    if imm < -16 or imm > 15:
        raise InstructionValidationError(insn, f"vmsgtu.vi immediate must be signed 5-bit (-16..15), got {imm}")
    regs = _emit_mask_result_loop_header(insn, state, allocator, new_label, lines, vd, vs2)
    load = _get_int_load(regs["sew"])

    # RVV vi immediate 是 signed 5-bit，再按当前 SEW 解释为元素值。
    imm_bits = imm if regs["sew"] == 64 else imm & ((1 << regs["sew"]) - 1)
    lines.insert(0, f"# vmsgtu.vi {vd}, {vs2}, {imm} (256-bit mode, RVV1.0 bit-packed mask)")
    compare = [
        f"    {load:<8} {regs['val2']}, 0({regs['vs2_ptr']})",
        f"    li      {regs['val1']}, {imm_bits}",
        f"    sltu    {regs['tmp']}, {regs['val1']}, {regs['val2']}   # mask bit = unsigned({vs2}[i]) > unsigned({imm})",
    ]
    _emit_mask_compare_finish(lines, regs, new_label, compare, "vmsgtu_vi")
    return lines


def _build_vmsgtu_vx_lines(context) -> list[str]:
    """RVV 1.0: vmsgtu.vx vd, vs2, rs1 => vd.mask[i] = unsigned(vs2[i]) > unsigned(rs1)."""
    insn = context.instruction
    state = context.state
    allocator = context.layout
    new_label = context.new_label
    lines = []
    operands = insn.operands
    if len(operands) != 3:
        raise InstructionValidationError(insn, f"vmsgtu.vx currently supports unmasked RVV1.0 form only: {insn.op_str}")
    vd, vs2, rs1 = operands
    regs = _emit_mask_result_loop_header(insn, state, allocator, new_label, lines, vd, vs2)
    load = _get_int_load(regs["sew"])
    shift = 64 - regs["sew"]
    lines.insert(0, f"# vmsgtu.vx {vd}, {vs2}, {rs1} (256-bit mode, RVV1.0 bit-packed mask)")
    compare = [
        f"    {load:<8} {regs['val2']}, 0({regs['vs2_ptr']})",
        f"    slli    {regs['val1']}, {rs1}, {shift}",
        f"    srli    {regs['val1']}, {regs['val1']}, {shift}",
        f"    sltu    {regs['tmp']}, {regs['val1']}, {regs['val2']}   # mask bit = unsigned({vs2}[i]) > unsigned({rs1})",
    ]
    _emit_mask_compare_finish(lines, regs, new_label, compare, "vmsgtu_vx")
    return lines


def _build_vmsle_vi_lines(context) -> list[str]:
    """RVV 1.0: vmsle.vi vd, vs2, imm => vd.mask[i] = signed(vs2[i]) <= signed(imm)."""
    insn = context.instruction
    state = context.state
    allocator = context.layout
    new_label = context.new_label
    lines = []
    operands = insn.operands
    if len(operands) != 3:
        raise InstructionValidationError(insn, f"vmsle.vi currently supports unmasked RVV1.0 form only: {insn.op_str}")
    vd, vs2, imm_s = operands
    imm = _parse_int(imm_s)
    if imm < -16 or imm > 15:
        raise InstructionValidationError(insn, f"vmsle.vi immediate must be signed 5-bit (-16..15), got {imm}")
    regs = _emit_mask_result_loop_header(insn, state, allocator, new_label, lines, vd, vs2)
    load = _get_int_load_signed(regs["sew"])
    lines.insert(0, f"# vmsle.vi {vd}, {vs2}, {imm} (256-bit mode, RVV1.0 bit-packed mask)")
    compare = [
        f"    {load:<8} {regs['val2']}, 0({regs['vs2_ptr']})",
        f"    li      {regs['val1']}, {imm}",
        f"    slt     {regs['tmp']}, {regs['val1']}, {regs['val2']}   # tmp = (imm < {vs2}[i]) signed",
        f"    seqz    {regs['tmp']}, {regs['tmp']}              # mask bit = signed({vs2}[i]) <= signed({imm})",
    ]
    _emit_mask_compare_finish(lines, regs, new_label, compare, "vmsle_vi")
    return lines


def _build_vmsleu_vv_lines(context) -> list[str]:
    """RVV 1.0: vmsleu.vv vd, vs2, vs1 => vd.mask[i] = unsigned(vs2[i]) <= unsigned(vs1[i])."""
    insn = context.instruction
    state = context.state
    allocator = context.layout
    new_label = context.new_label
    lines = []
    operands = insn.operands
    if len(operands) != 3:
        raise InstructionValidationError(insn, f"vmsleu.vv currently supports unmasked RVV1.0 form only: {insn.op_str}")
    vd, vs2, vs1 = operands
    regs = _emit_mask_result_loop_header(insn, state, allocator, new_label, lines, vd, vs2, True, vs1)
    load = _get_int_load(regs["sew"])
    lines.insert(0, f"# vmsleu.vv {vd}, {vs2}, {vs1} (256-bit mode, RVV1.0 bit-packed mask)")
    compare = [
        f"    {load:<8} {regs['val2']}, 0({regs['vs2_ptr']})",
        f"    {load:<8} {regs['val1']}, 0({regs['vs1_ptr']})",
        f"    sltu    {regs['tmp']}, {regs['val1']}, {regs['val2']}   # tmp = ({vs1}[i] < {vs2}[i]) unsigned",
        f"    seqz    {regs['tmp']}, {regs['tmp']}              # mask bit = unsigned({vs2}[i]) <= unsigned({vs1}[i])",
    ]
    _emit_mask_compare_finish(lines, regs, new_label, compare, "vmsleu_vv")
    return lines


def _build_vmsltu_vv_lines(context) -> list[str]:
    """RVV 1.0: vmsltu.vv vd, vs2, vs1 => vd.mask[i] = unsigned(vs2[i]) < unsigned(vs1[i])."""
    insn = context.instruction
    state = context.state
    allocator = context.layout
    new_label = context.new_label
    lines = []
    operands = insn.operands
    if len(operands) != 3:
        raise InstructionValidationError(insn, f"vmsltu.vv currently supports unmasked RVV1.0 form only: {insn.op_str}")
    vd, vs2, vs1 = operands
    regs = _emit_mask_result_loop_header(insn, state, allocator, new_label, lines, vd, vs2, True, vs1)
    load = _get_int_load(regs["sew"])
    lines.insert(0, f"# vmsltu.vv {vd}, {vs2}, {vs1} (256-bit mode, RVV1.0 bit-packed mask)")
    compare = [
        f"    {load:<8} {regs['val2']}, 0({regs['vs2_ptr']})",
        f"    {load:<8} {regs['val1']}, 0({regs['vs1_ptr']})",
        f"    sltu    {regs['tmp']}, {regs['val2']}, {regs['val1']}   # mask bit = unsigned({vs2}[i]) < unsigned({vs1}[i])",
    ]
    _emit_mask_compare_finish(lines, regs, new_label, compare, "vmsltu_vv")
    return lines


def _build_vmsltu_vx_lines(context) -> list[str]:
    """RVV 1.0: vmsltu.vx vd, vs2, rs1 => vd.mask[i] = unsigned(vs2[i]) < unsigned(rs1)."""
    insn = context.instruction
    state = context.state
    allocator = context.layout
    new_label = context.new_label
    lines = []
    operands = insn.operands
    if len(operands) != 3:
        raise InstructionValidationError(insn, f"vmsltu.vx currently supports unmasked RVV1.0 form only: {insn.op_str}")
    vd, vs2, rs1 = operands
    regs = _emit_mask_result_loop_header(insn, state, allocator, new_label, lines, vd, vs2)
    load = _get_int_load(regs["sew"])
    shift = 64 - regs["sew"]
    lines.insert(0, f"# vmsltu.vx {vd}, {vs2}, {rs1} (256-bit mode, RVV1.0 bit-packed mask)")
    compare = [
        f"    {load:<8} {regs['val2']}, 0({regs['vs2_ptr']})",
        f"    slli    {regs['val1']}, {rs1}, {shift}",
        f"    srli    {regs['val1']}, {regs['val1']}, {shift}",
        f"    sltu    {regs['tmp']}, {regs['val2']}, {regs['val1']}   # mask bit = unsigned({vs2}[i]) < unsigned({rs1})",
    ]
    _emit_mask_compare_finish(lines, regs, new_label, compare, "vmsltu_vx")
    return lines


def _build_vmor_mm_lines(context) -> list[str]:
    """RVV 1.0: vmor.mm vd, vs2, vs1 => bitwise OR of mask registers."""
    insn = context.instruction
    allocator = context.layout
    new_label = context.new_label
    lines = []
    operands = insn.operands
    if len(operands) != 3:
        raise InstructionValidationError(insn, f"Invalid operands for {insn.opcode}: {insn.op_str}")
    vd, vs2, vs1 = operands
    vd_off = allocator.get_offset(vd)
    vs2_off = allocator.get_offset(vs2)
    vs1_off = allocator.get_offset(vs1)

    temps = context.temp_register_allocator
    vl_reg = temps.alloc_gpr()
    byte_count = temps.alloc_gpr()
    vd_ptr = temps.alloc_gpr()
    vs2_ptr = temps.alloc_gpr()
    vs1_ptr = temps.alloc_gpr()
    b2 = temps.alloc_gpr()
    b1 = temps.alloc_gpr()
    tmp = temps.alloc_gpr()

    lines.append(f"# vmor.mm {vd}, {vs2}, {vs1} (256-bit mode, RVV1.0 bit-packed mask)")
    _load_vl_from_csr(lines, vl_reg=vl_reg, addr_reg=tmp)
    _emit_byte_count_from_vl(lines, byte_count=byte_count, vl_reg=vl_reg)
    lines.append(f"    li      {tmp}, {vd_off:#x}")
    lines.append(f"    add     {vd_ptr}, t6, {tmp}")
    lines.append(f"    li      {tmp}, {vs2_off:#x}")
    lines.append(f"    add     {vs2_ptr}, t6, {tmp}")
    lines.append(f"    li      {tmp}, {vs1_off:#x}")
    lines.append(f"    add     {vs1_ptr}, t6, {tmp}")

    loop_label = new_label("vmor_loop")
    end_label = new_label("vmor_end")
    lines.append(f"{loop_label}:")
    lines.append(f"    beqz    {byte_count}, {end_label}")
    lines.append(f"    lbu     {b2}, 0({vs2_ptr})")
    lines.append(f"    lbu     {b1}, 0({vs1_ptr})")
    lines.append(f"    or      {b2}, {b2}, {b1}")
    lines.append(f"    sb      {b2}, 0({vd_ptr})")
    lines.append(f"    addi    {vd_ptr}, {vd_ptr}, 1")
    lines.append(f"    addi    {vs2_ptr}, {vs2_ptr}, 1")
    lines.append(f"    addi    {vs1_ptr}, {vs1_ptr}, 1")
    lines.append(f"    addi    {byte_count}, {byte_count}, -1")
    lines.append(f"    j       {loop_label}")
    lines.append(f"{end_label}:")
    return lines


def _build_vmand_mm_lines(context) -> list[str]:
    """RVV 1.0: vmand.mm vd, vs2, vs1 => bitwise AND of mask registers."""
    insn = context.instruction
    allocator = context.layout
    new_label = context.new_label
    lines = []
    operands = insn.operands
    if len(operands) != 3:
        raise InstructionValidationError(insn, f"Invalid operands for {insn.opcode}: {insn.op_str}")
    vd, vs2, vs1 = operands
    vd_off = allocator.get_offset(vd)
    vs2_off = allocator.get_offset(vs2)
    vs1_off = allocator.get_offset(vs1)

    temps = context.temp_register_allocator
    vl_reg = temps.alloc_gpr()
    byte_count = temps.alloc_gpr()
    vd_ptr = temps.alloc_gpr()
    vs2_ptr = temps.alloc_gpr()
    vs1_ptr = temps.alloc_gpr()
    b2 = temps.alloc_gpr()
    b1 = temps.alloc_gpr()
    tmp = temps.alloc_gpr()

    lines.append(f"# vmand.mm {vd}, {vs2}, {vs1} (256-bit mode, RVV1.0 bit-packed mask)")
    _load_vl_from_csr(lines, vl_reg=vl_reg, addr_reg=tmp)
    _emit_byte_count_from_vl(lines, byte_count=byte_count, vl_reg=vl_reg)
    lines.append(f"    li      {tmp}, {vd_off:#x}")
    lines.append(f"    add     {vd_ptr}, t6, {tmp}")
    lines.append(f"    li      {tmp}, {vs2_off:#x}")
    lines.append(f"    add     {vs2_ptr}, t6, {tmp}")
    lines.append(f"    li      {tmp}, {vs1_off:#x}")
    lines.append(f"    add     {vs1_ptr}, t6, {tmp}")

    loop_label = new_label("vmand_loop")
    end_label = new_label("vmand_end")
    lines.append(f"{loop_label}:")
    lines.append(f"    beqz    {byte_count}, {end_label}")
    lines.append(f"    lbu     {b2}, 0({vs2_ptr})")
    lines.append(f"    lbu     {b1}, 0({vs1_ptr})")
    lines.append(f"    and     {b2}, {b2}, {b1}")
    lines.append(f"    sb      {b2}, 0({vd_ptr})")
    lines.append(f"    addi    {vd_ptr}, {vd_ptr}, 1")
    lines.append(f"    addi    {vs2_ptr}, {vs2_ptr}, 1")
    lines.append(f"    addi    {vs1_ptr}, {vs1_ptr}, 1")
    lines.append(f"    addi    {byte_count}, {byte_count}, -1")
    lines.append(f"    j       {loop_label}")
    lines.append(f"{end_label}:")
    return lines


def _build_vmnot_m_lines(context) -> list[str]:
    """RVV 1.0: vmnot.m vd, vs2 => bitwise NOT of active mask bytes."""
    insn = context.instruction
    allocator = context.layout
    new_label = context.new_label
    lines = []
    operands = insn.operands
    if len(operands) != 2:
        raise InstructionValidationError(insn, f"Invalid operands for {insn.opcode}: {insn.op_str}")
    vd, vs2 = operands
    vd_off = allocator.get_offset(vd)
    vs2_off = allocator.get_offset(vs2)

    temps = context.temp_register_allocator
    vl_reg = temps.alloc_gpr()
    byte_count = temps.alloc_gpr()
    vd_ptr = temps.alloc_gpr()
    vs2_ptr = temps.alloc_gpr()
    data = temps.alloc_gpr()
    tmp = temps.alloc_gpr()

    lines.append(f"# vmnot.m {vd}, {vs2} (256-bit mode, RVV1.0 bit-packed mask)")
    _load_vl_from_csr(lines, vl_reg=vl_reg, addr_reg=tmp)
    _emit_byte_count_from_vl(lines, byte_count=byte_count, vl_reg=vl_reg)
    lines.append(f"    li      {tmp}, {vd_off:#x}")
    lines.append(f"    add     {vd_ptr}, t6, {tmp}")
    lines.append(f"    li      {tmp}, {vs2_off:#x}")
    lines.append(f"    add     {vs2_ptr}, t6, {tmp}")

    loop_label = new_label("vmnot_loop")
    end_label = new_label("vmnot_end")
    lines.append(f"{loop_label}:")
    lines.append(f"    beqz    {byte_count}, {end_label}")
    lines.append(f"    lbu     {data}, 0({vs2_ptr})")
    lines.append(f"    xori    {data}, {data}, 255")
    lines.append(f"    sb      {data}, 0({vd_ptr})")
    lines.append(f"    addi    {vd_ptr}, {vd_ptr}, 1")
    lines.append(f"    addi    {vs2_ptr}, {vs2_ptr}, 1")
    lines.append(f"    addi    {byte_count}, {byte_count}, -1")
    lines.append(f"    j       {loop_label}")
    lines.append(f"{end_label}:")
    return lines


def _build_vmclr_m_lines(context) -> list[str]:
    """翻译无掩码 ``vmclr.m vd`` 的 bit-packed mask 清零。

    ``vmclr.m`` 是 mask 清零伪指令；此后端直接按模拟 ``vl`` 清零目标 mask
    的活动字节，避免依赖目标机是否接受该伪指令。状态基址仍只在翻译块内由
    ``t6`` 提供，目的偏移通过统一 helper 生成，避免与语义输入寄存器冲突。
    """
    insn = context.instruction
    allocator = context.layout
    new_label = context.new_label
    operands = insn.operands
    if len(operands) != 1:
        raise InstructionValidationError(insn, f"Invalid operands for {insn.opcode}: {insn.op_str}")

    vd = operands[0]
    vd_off = allocator.get_offset(vd)
    temps = context.temp_register_allocator
    vl_reg = temps.alloc_gpr()
    byte_count = temps.alloc_gpr()
    vd_ptr = temps.alloc_gpr()
    addr = temps.alloc_gpr()

    lines = [
        f"# vmclr.m {vd} (256-bit mode, RVV1.0 bit-packed mask)",
        "# 仅清零 [0, ceil(vl/8)) 的 raw mask 字节，保持与现有 mask handler 的状态布局一致。",
    ]
    _load_vl_from_csr(lines, vl_reg=vl_reg, addr_reg=addr)
    _emit_byte_count_from_vl(lines, byte_count=byte_count, vl_reg=vl_reg)
    _emit_state_ptr(lines, vd_ptr, vd_off)

    loop_label = new_label("vmclr_m_loop")
    end_label = new_label("vmclr_m_end")
    lines.append(f"{loop_label}:")
    lines.append(f"    beqz    {byte_count}, {end_label}")
    lines.append(f"    sb      zero, 0({vd_ptr})")
    lines.append(f"    addi    {vd_ptr}, {vd_ptr}, 1")
    lines.append(f"    addi    {byte_count}, {byte_count}, -1")
    lines.append(f"    j       {loop_label}")
    lines.append(f"{end_label}:")
    return lines


def _build_vfirst_m_lines(context) -> list[str]:
    """RVV 1.0: vfirst.m rd, vs2 => lowest active set mask bit, or -1."""
    insn = context.instruction
    allocator = context.layout
    new_label = context.new_label
    lines = []
    operands = insn.operands
    if len(operands) < 2:
        raise InstructionValidationError(insn, f"Invalid operands for {insn.opcode}: {insn.op_str}")
    if len(operands) > 2:
        raise InstructionValidationError(insn, f"vfirst.m masked form is not implemented yet: {insn.op_str}")
    rd, vs2 = operands
    vs2_off = allocator.get_offset(vs2)

    temps = context.temp_register_allocator
    vl_reg = temps.alloc_gpr()
    index = temps.alloc_gpr()
    ptr = temps.alloc_gpr()
    byte_reg = temps.alloc_gpr()
    bit_pos = temps.alloc_gpr()
    bit_reg = temps.alloc_gpr()
    tmp = temps.alloc_gpr()

    lines.append(f"# vfirst.m {rd}, {vs2} (256-bit mode, RVV1.0 bit-packed mask)")
    lines.append(f"    li      {rd}, -1                         # default: no active set bit")
    _load_vl_from_csr(lines, vl_reg=vl_reg, addr_reg=tmp)
    lines.append(f"    li      {index}, 0")
    lines.append(f"    li      {bit_pos}, 0")
    lines.append(f"    li      {ptr}, {vs2_off:#x}")
    lines.append(f"    add     {ptr}, t6, {ptr}")

    loop_label = new_label("vfirst_loop")
    have_byte = new_label("vfirst_have_byte")
    next_label = new_label("vfirst_next")
    found_label = new_label("vfirst_found")
    end_label = new_label("vfirst_end")

    lines.append(f"{loop_label}:")
    lines.append(f"    beqz    {vl_reg}, {end_label}")
    lines.append(f"    bnez    {bit_pos}, {have_byte}")
    lines.append(f"    lbu     {byte_reg}, 0({ptr})")
    lines.append(f"{have_byte}:")
    lines.append(f"    srl     {bit_reg}, {byte_reg}, {bit_pos}")
    lines.append(f"    andi    {bit_reg}, {bit_reg}, 1")
    lines.append(f"    bnez    {bit_reg}, {found_label}")
    lines.append(f"    addi    {index}, {index}, 1")
    lines.append(f"    addi    {bit_pos}, {bit_pos}, 1")
    lines.append(f"    li      {tmp}, 8")
    lines.append(f"    bne     {bit_pos}, {tmp}, {next_label}")
    lines.append(f"    li      {bit_pos}, 0")
    lines.append(f"    addi    {ptr}, {ptr}, 1")
    lines.append(f"{next_label}:")
    lines.append(f"    addi    {vl_reg}, {vl_reg}, -1")
    lines.append(f"    j       {loop_label}")
    lines.append(f"{found_label}:")
    lines.append(f"    mv      {rd}, {index}")
    lines.append(f"{end_label}:")
    return lines


def _build_vmerge_vvm_lines(context) -> list[str]:
    """
    RVV 1.0: vmerge.vvm vd, vs2, vs1, v0.

    The selector is always v0.mask: true selects vs1, false selects vs2.
    """
    insn = context.instruction
    state = context.state
    allocator = context.layout
    new_label = context.new_label
    lines = []
    operands = insn.operands
    if len(operands) not in (3, 4):
        raise InstructionValidationError(insn, f"Invalid operands for {insn.opcode}: {insn.op_str}")
    vd, vs2, vs1 = operands[:3]
    mask_reg = operands[3] if len(operands) == 4 else "v0"
    if mask_reg != "v0":
        raise InstructionValidationError(insn, f"vmerge.vvm selector must be v0, got {mask_reg}")

    sew = state.sew
    elem_bytes = sew // 8
    load = _get_int_load(sew)
    store = _get_int_store(sew)
    vd_off = allocator.get_offset(vd)
    vs2_off = allocator.get_offset(vs2)
    vs1_off = allocator.get_offset(vs1)
    v0_off = allocator.get_offset("v0")

    temps = context.temp_register_allocator
    vl_reg = temps.alloc_gpr()
    vd_ptr = temps.alloc_gpr()
    vs2_ptr = temps.alloc_gpr()
    vs1_ptr = temps.alloc_gpr()
    mask_ptr = temps.alloc_gpr()
    byte_reg = temps.alloc_gpr()
    bit_pos = temps.alloc_gpr()
    data = temps.alloc_gpr()
    tmp = temps.alloc_gpr()

    lines.append(f"# vmerge.vvm {vd}, {vs2}, {vs1}, v0 (256-bit mode, RVV1.0)")
    lines.append(f"# Semantic: {vd}[i] = v0.mask[i] ? {vs1}[i] : {vs2}[i]")
    _load_vl_from_csr(lines, vl_reg=vl_reg, addr_reg=tmp)
    lines.append(f"    li      {tmp}, {vd_off:#x}")
    lines.append(f"    add     {vd_ptr}, t6, {tmp}")
    lines.append(f"    li      {tmp}, {vs2_off:#x}")
    lines.append(f"    add     {vs2_ptr}, t6, {tmp}")
    lines.append(f"    li      {tmp}, {vs1_off:#x}")
    lines.append(f"    add     {vs1_ptr}, t6, {tmp}")
    lines.append(f"    li      {tmp}, {v0_off:#x}")
    lines.append(f"    add     {mask_ptr}, t6, {tmp}")
    lines.append(f"    li      {bit_pos}, 0")

    loop_label = new_label("vmerge_loop")
    have_byte = new_label("vmerge_have_byte")
    use_vs2 = new_label("vmerge_use_vs2")
    store_label = new_label("vmerge_store")
    next_label = new_label("vmerge_next")
    end_label = new_label("vmerge_end")

    lines.append(f"{loop_label}:")
    lines.append(f"    beqz    {vl_reg}, {end_label}")
    lines.append(f"    bnez    {bit_pos}, {have_byte}")
    lines.append(f"    lbu     {byte_reg}, 0({mask_ptr})")
    lines.append(f"{have_byte}:")
    lines.append(f"    srl     {tmp}, {byte_reg}, {bit_pos}")
    lines.append(f"    andi    {tmp}, {tmp}, 1")
    lines.append(f"    beqz    {tmp}, {use_vs2}")
    lines.append(f"    {load:<8} {data}, 0({vs1_ptr})            # selector true: vs1")
    lines.append(f"    j       {store_label}")
    lines.append(f"{use_vs2}:")
    lines.append(f"    {load:<8} {data}, 0({vs2_ptr})            # selector false: vs2")
    lines.append(f"{store_label}:")
    lines.append(f"    {store:<8} {data}, 0({vd_ptr})")
    lines.append(f"    addi    {vd_ptr}, {vd_ptr}, {elem_bytes}")
    lines.append(f"    addi    {vs2_ptr}, {vs2_ptr}, {elem_bytes}")
    lines.append(f"    addi    {vs1_ptr}, {vs1_ptr}, {elem_bytes}")
    lines.append(f"    addi    {bit_pos}, {bit_pos}, 1")
    lines.append(f"    li      {tmp}, 8")
    lines.append(f"    bne     {bit_pos}, {tmp}, {next_label}")
    lines.append(f"    li      {bit_pos}, 0")
    lines.append(f"    addi    {mask_ptr}, {mask_ptr}, 1")
    lines.append(f"{next_label}:")
    lines.append(f"    addi    {vl_reg}, {vl_reg}, -1")
    lines.append(f"    j       {loop_label}")
    lines.append(f"{end_label}:")
    return lines


def _emit_vmerge_vx_or_vi(
    insn: RVInstruction,
    state: StateTracker,
    allocator: SimulatedStateLayout,
    new_label,
    true_kind: str,
) -> List[str]:
    """Emit vmerge.vxm/vmerge.vim with v0 as the bit-packed selector."""
    lines = []
    operands = insn.operands
    if len(operands) not in (3, 4):
        raise InstructionValidationError(insn, f"Invalid operands for {insn.opcode}: {insn.op_str}")

    vd, vs2, true_operand = operands[:3]
    mask_reg = str(operands[3]) if len(operands) == 4 else "v0"
    if mask_reg != "v0":
        raise InstructionValidationError(insn, f"{insn.opcode} selector must be v0, got {mask_reg}")

    sew = state.sew
    elem_bytes = sew // 8
    load = _get_int_load(sew)
    store = _get_int_store(sew)
    vd_off = allocator.get_offset(vd)
    vs2_off = allocator.get_offset(vs2)
    v0_off = allocator.get_offset("v0")

    if true_kind == "imm":
        try:
            imm = _parse_int(str(true_operand))
        except ValueError:
            raise InstructionValidationError(insn, f"vmerge.vim immediate must be an integer: {insn.op_str}")
        if imm < -16 or imm > 15:
            raise InstructionValidationError(insn, f"vmerge.vim immediate must be signed 5-bit (-16..15), got {imm}")
        true_value = str(imm)
        true_comment = f"imm {imm}"
    else:
        true_value = str(true_operand)
        true_comment = f"scalar {true_value}"

    temps = TempRegisterAllocator(insn, reserved_gprs=("t6",))
    vl_reg = temps.alloc_gpr()
    vd_ptr = temps.alloc_gpr()
    vs2_ptr = temps.alloc_gpr()
    mask_ptr = temps.alloc_gpr()
    byte_reg = temps.alloc_gpr()
    bit_pos = temps.alloc_gpr()
    data = temps.alloc_gpr()
    tmp = temps.alloc_gpr()

    lines.append(f"# {insn.opcode} {vd}, {vs2}, {true_operand}, v0 (256-bit mode, RVV1.0)")
    lines.append(f"# Semantic: {vd}[i] = v0.mask[i] ? {true_comment} : {vs2}[i]")
    _load_vl_from_csr(lines, vl_reg=vl_reg, addr_reg=tmp)
    lines.append(f"    li      {tmp}, {vd_off:#x}")
    lines.append(f"    add     {vd_ptr}, t6, {tmp}")
    lines.append(f"    li      {tmp}, {vs2_off:#x}")
    lines.append(f"    add     {vs2_ptr}, t6, {tmp}")
    lines.append(f"    li      {tmp}, {v0_off:#x}")
    lines.append(f"    add     {mask_ptr}, t6, {tmp}")
    lines.append(f"    li      {bit_pos}, 0")

    loop_label = new_label(f"{insn.opcode.replace('.', '_')}_loop")
    have_byte = new_label(f"{insn.opcode.replace('.', '_')}_have_byte")
    use_vs2 = new_label(f"{insn.opcode.replace('.', '_')}_use_vs2")
    store_label = new_label(f"{insn.opcode.replace('.', '_')}_store")
    next_label = new_label(f"{insn.opcode.replace('.', '_')}_next")
    end_label = new_label(f"{insn.opcode.replace('.', '_')}_end")

    lines.append(f"{loop_label}:")
    lines.append(f"    beqz    {vl_reg}, {end_label}")
    lines.append(f"    bnez    {bit_pos}, {have_byte}")
    lines.append(f"    lbu     {byte_reg}, 0({mask_ptr})")
    lines.append(f"{have_byte}:")
    lines.append(f"    srl     {tmp}, {byte_reg}, {bit_pos}")
    lines.append(f"    andi    {tmp}, {tmp}, 1")
    lines.append(f"    beqz    {tmp}, {use_vs2}")
    if true_kind == "imm":
        lines.append(f"    li      {data}, {true_value}                # selector true: imm")
    else:
        lines.append(f"    mv      {data}, {true_value}                # selector true: scalar")
    lines.append(f"    j       {store_label}")
    lines.append(f"{use_vs2}:")
    lines.append(f"    {load:<8} {data}, 0({vs2_ptr})            # selector false: vs2")
    lines.append(f"{store_label}:")
    lines.append(f"    {store:<8} {data}, 0({vd_ptr})")
    lines.append(f"    addi    {vd_ptr}, {vd_ptr}, {elem_bytes}")
    lines.append(f"    addi    {vs2_ptr}, {vs2_ptr}, {elem_bytes}")
    lines.append(f"    addi    {bit_pos}, {bit_pos}, 1")
    lines.append(f"    li      {tmp}, 8")
    lines.append(f"    bne     {bit_pos}, {tmp}, {next_label}")
    lines.append(f"    li      {bit_pos}, 0")
    lines.append(f"    addi    {mask_ptr}, {mask_ptr}, 1")
    lines.append(f"{next_label}:")
    lines.append(f"    addi    {vl_reg}, {vl_reg}, -1")
    lines.append(f"    j       {loop_label}")
    lines.append(f"{end_label}:")
    return lines


def _build_vmerge_vxm_lines(context) -> list[str]:
    """RVV 1.0: vmerge.vxm vd, vs2, rs1, v0."""
    insn = context.instruction
    state = context.state
    allocator = context.layout
    new_label = context.new_label
    return _emit_vmerge_vx_or_vi(insn, state, allocator, new_label, "scalar")


def _build_vmerge_vim_lines(context) -> list[str]:
    """RVV 1.0: vmerge.vim vd, vs2, imm, v0."""
    insn = context.instruction
    state = context.state
    allocator = context.layout
    new_label = context.new_label
    return _emit_vmerge_vx_or_vi(insn, state, allocator, new_label, "imm")
