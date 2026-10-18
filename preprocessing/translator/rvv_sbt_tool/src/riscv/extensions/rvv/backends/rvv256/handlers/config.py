# src/riscv/extensions/rvv/backends/rvv256/handlers/config.py
"""256-bit RVV 模式配置指令 handler"""

from riscv.extensions.rvv.analysis.model import LEGAL_LMULS
from riscv.frontend.model import RVInstruction
from riscv.extensions.rvv.analysis.config import StateTracker
from riscv.extensions.rvv.translation.contracts import InstructionValidationError
from riscv.extensions.rvv.runtime.layout import CSR_OFFSETS
from riscv.extensions.rvv.runtime.access import emit_clear_vstart
from riscv.extensions.rvv.translation.vtype_decode import emit_vlmax_from_vtype

def _snapshot_state(state: StateTracker) -> tuple:
    """Keep config handlers from mutating StateTracker when they reject input."""
    return (
        state.sew, state.lmul, state.vl, state.vtype,
        state.vta, state.vma, state.config_str,
    )


def _restore_state(state: StateTracker, snapshot: tuple) -> None:
    (
        state.sew, state.lmul, state.vl, state.vtype,
        state.vta, state.vma, state.config_str,
    ) = snapshot


def _validate_backend_vtype(state: StateTracker, insn: RVInstruction) -> str | None:
    """返回静态 vtype 的结构化诊断正文，不生成汇编注释。"""
    if state.sew not in (8, 16, 32, 64):
        return f"RVV256 backend supports SEW=8/16/32/64 only: {insn.op_str}"
    if state.lmul not in LEGAL_LMULS:
        return f"Invalid LMUL for RVV256 backend: {insn.op_str}"
    return None



def _build_vsetvli_lines(context) -> list[str]:
    """
    翻译 vsetvli 指令 (vtype 从操作数字面量静态可知)

    格式: vsetvli rd, rs1, e64, m8, ta, ma
    语义:
        1. rs1 != x0: vl = min(rs1, VLMAX), rd = vl
        2. rs1 == x0 && rd != x0: vl = VLMAX, rd = vl
        3. rs1 == x0 && rd == x0: 保持 vl 不变，仅更新 vtype
    """
    insn = context.instruction
    state = context.state
    allocator = context.layout
    new_label = context.new_label
    lines = []
    operands = insn.operands

    if len(operands) < 3:
        raise InstructionValidationError(insn, f"Invalid operands for vsetvli: {insn.op_str}")

    rd = operands[0]
    rs1 = operands[1]

    snapshot = _snapshot_state(state)
    state.update(insn)

    rd_is_zero = (rd == 'zero' or rd == 'x0')
    rs1_is_zero = (rs1 == 'zero' or rs1 == 'x0')

    error = _validate_backend_vtype(state, insn)
    if error is not None:
        _restore_state(state, snapshot)
        raise InstructionValidationError(insn, error)

    vlmax = state.get_vlmax()

    vtype_value = state.get_vtype_value()
    vl_offset = CSR_OFFSETS['vl']
    vtype_offset = CSR_OFFSETS['vtype']

    temps = context.temp_register_allocator
    value_reg = temps.alloc_gpr()
    result_reg = temps.alloc_gpr()
    addr_reg = temps.alloc_gpr()

    lines.append(f"    # vsetvli {insn.op_str} (256-bit mode, VLMAX={vlmax})")

    if rs1_is_zero and rd_is_zero:
        old_vtype = temps.alloc_gpr()
        old_vlmax = temps.alloc_gpr()
        sew_reg = temps.alloc_gpr()
        base_reg = temps.alloc_gpr()
        lmul_reg = temps.alloc_gpr()
        tmp_reg = temps.alloc_gpr()
        invalid_label = new_label("vsetvli_x0_x0_invalid_vlmax")
        check_done_label = new_label("vsetvli_x0_x0_check_done")

        lines.append("    # runtime check: vsetvli x0,x0 requires unchanged VLMAX")
        lines.append(f"    li      {addr_reg}, {vtype_offset:#x}")
        lines.append(f"    add     {addr_reg}, t6, {addr_reg}")
        lines.append(f"    ld      {old_vtype}, 0({addr_reg})      # old CSR.vtype for x0,x0 VLMAX check")
        emit_vlmax_from_vtype(lines, vtype_reg=old_vtype, out_reg=old_vlmax, sew_reg=sew_reg, base_reg=base_reg, lmul_reg=lmul_reg, tmp_reg=tmp_reg, source_vlenb=allocator.vlenb, invalid_label=invalid_label, new_label=new_label, prefix="vsetvli_x0_x0_old_vlmax")
        lines.append(f"    li      {tmp_reg}, {vlmax}              # new VLMAX")
        lines.append(f"    bne     {old_vlmax}, {tmp_reg}, {invalid_label}")
        lines.append(f"    j       {check_done_label}")
        lines.append(f"{invalid_label}:")
        lines.append("    ebreak")
        lines.append(f"{check_done_label}:")

    # 写入 vtype CSR
    emit_clear_vstart(lines, addr_reg)
    lines.append(f"    li      {value_reg}, {vtype_value}       # vtype = {vtype_value:#x}")
    lines.append(f"    li      {addr_reg}, {vtype_offset:#x}")
    lines.append(f"    add     {addr_reg}, t6, {addr_reg}")
    lines.append(f"    sd      {value_reg}, 0({addr_reg})              # CSR.vtype = vtype")

    if rs1_is_zero and rd_is_zero:
        # 情况3: 保持 vl 不变
        lines.append(f"    # vl unchanged")
    elif rs1_is_zero and not rd_is_zero:
        # 情况2: vl = VLMAX
        lines.append(f"    li      {result_reg}, {vlmax}           # VL = VLMAX")
        lines.append(f"    li      {addr_reg}, {vl_offset:#x}")
        lines.append(f"    add     {addr_reg}, t6, {addr_reg}")
        lines.append(f"    sd      {result_reg}, 0({addr_reg})              # CSR.vl = VLMAX")
        lines.append(f"    mv      {rd}, {result_reg}")
    else:
        # 情况1: vl = min(rs1, VLMAX)
        lines.append(f"    li      {value_reg}, {vlmax}            # value_reg = VLMAX")
        lines.append(f"    mv      {result_reg}, {value_reg}")
        skip_label = new_label("vsetvli_skip")
        lines.append(f"    bltu    {value_reg}, {rs1}, {skip_label}")
        lines.append(f"    mv      {result_reg}, {rs1}")
        lines.append(f"{skip_label}:")
        lines.append(f"    li      {addr_reg}, {vl_offset:#x}")
        lines.append(f"    add     {addr_reg}, t6, {addr_reg}")
        lines.append(f"    sd      {result_reg}, 0({addr_reg})              # CSR.vl = VL")
        if not rd_is_zero:
            lines.append(f"    mv      {rd}, {result_reg}")

    lines.append("")
    return lines


def _build_vsetivli_lines(context) -> list[str]:
    """
    翻译 vsetivli 指令 (立即数版本)

    格式: vsetivli rd, uimm, e64, m1, ta, ma
    语义: vl = min(uimm, VLMAX), rd = vl
    """
    insn = context.instruction
    state = context.state
    new_label = context.new_label
    lines = []
    operands = insn.operands

    if len(operands) < 3:
        raise InstructionValidationError(insn, f"Invalid operands for vsetivli: {insn.op_str}")

    rd = operands[0]
    uimm_str = operands[1]

    rd_is_zero = (rd == 'zero' or rd == 'x0')

    try:
        uimm = int(uimm_str, 16) if uimm_str.startswith('0x') else int(uimm_str)
    except ValueError:
        raise InstructionValidationError(insn, f"Invalid uimm for vsetivli: {insn.op_str}")

    if not 0 <= uimm <= 31:
        raise InstructionValidationError(insn, f"vsetivli uimm out of range (0..31): {insn.op_str}")

    snapshot = _snapshot_state(state)
    state.update(insn)
    error = _validate_backend_vtype(state, insn)
    if error is not None:
        _restore_state(state, snapshot)
        raise InstructionValidationError(insn, error)

    vlmax = state.get_vlmax()
    vtype_value = state.get_vtype_value()
    vl_offset = CSR_OFFSETS['vl']
    vtype_offset = CSR_OFFSETS['vtype']

    temps = context.temp_register_allocator
    value_reg = temps.alloc_gpr()    # vtype / vlmax 值
    imm_reg = temps.alloc_gpr()      # uimm 立即数
    result_reg = temps.alloc_gpr()   # 最终 vl
    addr_reg = temps.alloc_gpr()     # CSR 地址

    lines.append(f"    # vsetivli {insn.op_str} (256-bit mode, uimm={uimm}, VLMAX={vlmax})")

    # 写入 vtype CSR
    emit_clear_vstart(lines, addr_reg)
    lines.append(f"    li      {value_reg}, {vtype_value}       # vtype = {vtype_value:#x}")
    lines.append(f"    li      {addr_reg}, {vtype_offset:#x}")
    lines.append(f"    add     {addr_reg}, t6, {addr_reg}")
    lines.append(f"    sd      {value_reg}, 0({addr_reg})              # CSR.vtype = vtype")

    # vl = min(uimm, VLMAX)
    lines.append(f"    li      {value_reg}, {vlmax}            # value_reg = VLMAX")
    lines.append(f"    li      {imm_reg}, {uimm}               # imm_reg = {uimm}")
    lines.append(f"    mv      {result_reg}, {value_reg}")
    skip_label = new_label("vsetivli_skip")
    lines.append(f"    bltu    {value_reg}, {imm_reg}, {skip_label}")
    lines.append(f"    mv      {result_reg}, {imm_reg}")
    lines.append(f"{skip_label}:")
    lines.append(f"    li      {addr_reg}, {vl_offset:#x}")
    lines.append(f"    add     {addr_reg}, t6, {addr_reg}")
    lines.append(f"    sd      {result_reg}, 0({addr_reg})              # CSR.vl = VL")

    if not rd_is_zero:
        lines.append(f"    mv      {rd}, {result_reg}")

    lines.append("")
    return lines


def _build_vsetvl_lines(context) -> list[str]:
    """
    翻译 vsetvl 指令 (vtype 来自 rs2，运行时动态确定)

    格式: vsetvl rd, rs1, rs2
    语义:
        rs2 保存 vtype CSR 值 (编码 SEW/LMUL/VTA/VMA)
        1. rs1 != x0: vl = min(rs1, VLMAX), rd = vl
        2. rs1 == x0 && rd != x0: vl = VLMAX, rd = vl
        3. rs1 == x0 && rd == x0: 保持 vl 不变，仅更新 vtype
        rd = VL

    运行时计算流程:
        1. 从 rs2 提取 sew_enc[5:3], lmul_enc[2:0]
        2. VLMAX_1024 = (1024 * LMUL) / SEW
        3. VL = min(AVL, VLMAX)、VLMAX，或在 rs1=x0/rd=x0 时保持不变
        4. 写入 simulated_cpu_state (vl @ 0x1020, vtype @ 0x1028)
    :return: 生成的汇编代码行列表
    """
    insn = context.instruction
    state = context.state
    allocator = context.layout
    new_label = context.new_label
    lines = []
    operands = insn.operands

    if len(operands) < 3:
        raise InstructionValidationError(insn, f"Invalid operands for vsetvl: {insn.op_str}")

    rd = operands[0]
    rs1 = operands[1]
    rs2 = operands[2]

    state.update(insn)

    rd_is_zero = (rd == 'zero' or rd == 'x0')
    rs1_is_zero = (rs1 == 'zero' or rs1 == 'x0')
    keep_vl = rs1_is_zero and rd_is_zero

    vl_offset = CSR_OFFSETS['vl']
    vtype_offset = CSR_OFFSETS['vtype']

    # 临时寄存器复用
    temps = context.temp_register_allocator
    addr_sew_vl = temps.alloc_gpr()   # addr → sew_enc → vl
    base_addr = temps.alloc_gpr()      # base → addr for vl store
    lmul_enc = temps.alloc_gpr()       # lmul encoding
    vlmax = temps.alloc_gpr()          # VLMAX result
    tmp = temps.alloc_gpr()            # scratch
    old_vtype = temps.alloc_gpr() if keep_vl else None
    old_vlmax = temps.alloc_gpr() if keep_vl else None

    lines.append(f"    # vsetvl {insn.op_str} (256-bit mode, vtype from {rs2})")
    lines.append("")

    invalid_label = new_label("vsetvl_invalid_vtype")
    done_label = new_label("vsetvl_done")

    if keep_vl:
        lines.append(f"    li      {base_addr}, {vtype_offset:#x}")
        lines.append(f"    add     {base_addr}, t6, {base_addr}")
        lines.append(f"    ld      {old_vtype}, 0({base_addr})      # old CSR.vtype for x0,x0 VLMAX check")
        emit_vlmax_from_vtype(lines, vtype_reg=old_vtype, out_reg=old_vlmax, sew_reg=addr_sew_vl, base_reg=base_addr, lmul_reg=lmul_enc, tmp_reg=tmp, source_vlenb=allocator.vlenb, invalid_label=invalid_label, new_label=new_label, prefix="vsetvl_old_vlmax")
        lines.append("")

    # vill 或本 backend 不支持的 vtype 编码按非法 vtype 处理。
    lines.append(f"    bltz    {rs2}, {invalid_label}              # incoming vtype has vill set")

    # SEW 编码提取 (addr_sew_vl 复用为 sew_enc)
    lines.append(f"    srli    {addr_sew_vl}, {rs2}, 3")
    lines.append(f"    andi    {addr_sew_vl}, {addr_sew_vl}, 7    # sew_enc")
    lines.append(f"    li      {tmp}, 3")
    lines.append(f"    bltu    {tmp}, {addr_sew_vl}, {invalid_label}  # e128+ unsupported in this backend")

    # LMUL 编码提取
    lines.append(f"    andi    {lmul_enc}, {rs2}, 7               # lmul_enc")
    lines.append(f"    li      {tmp}, 4")
    lines.append(f"    beq     {lmul_enc}, {tmp}, {invalid_label}     # vlmul=100 is reserved")

    # vtype CSR 写入
    lines.append(f"    li      {base_addr}, {vtype_offset:#x}")
    lines.append(f"    add     {base_addr}, t6, {base_addr}")
    lines.append(f"    sd      {rs2}, 0({base_addr})              # CSR.vtype = {rs2}")

    # VLMAX 的源 VLENB 来自统一布局对象；默认仍是 128 B，但不能在 handler
    # 中复制 ABI 常量，否则非默认 profile 会与 StateTracker 发生漂移。
    lines.append(f"    li      {base_addr}, {allocator.vlenb}")
    lines.append(
        f"    srl     {base_addr}, {base_addr}, {addr_sew_vl}  # base = VLENB >> sew_enc"
    )

    # 分支: 整数 LMUL(0-3) vs 分数 LMUL(5-7)
    frac_label = new_label("vsetvl_frac")
    vlmax_done = new_label("vsetvl_vlmax_done")

    lines.append(f"    andi    {tmp}, {lmul_enc}, 4              # bit 2 = fractional?")
    lines.append(f"    bnez    {tmp}, {frac_label}")
    lines.append(f"    sll     {vlmax}, {base_addr}, {lmul_enc}  # VLMAX = base << lmul")
    lines.append(f"    j       {vlmax_done}")
    lines.append(f"{frac_label}:")
    lines.append(f"    li      {tmp}, 8")
    lines.append(f"    sub     {tmp}, {tmp}, {lmul_enc}")
    lines.append(f"    srl     {vlmax}, {base_addr}, {tmp}       # VLMAX = base >> (8-lmul_enc)")
    lines.append(f"{vlmax_done}:")
    if keep_vl:
        lines.append(f"    bne     {old_vlmax}, {vlmax}, {invalid_label}  # x0,x0 requires unchanged VLMAX")

    # 计算 VL (addr_sew_vl 复用为 vl_reg)
    if keep_vl:
        lines.append(f"    li      {base_addr}, {vl_offset:#x}")
        lines.append(f"    add     {base_addr}, t6, {base_addr}")
        lines.append(f"    ld      {addr_sew_vl}, 0({base_addr})      # rs1=x0, rd=x0: vl unchanged")
    elif rs1_is_zero:
        lines.append(f"    mv      {addr_sew_vl}, {vlmax}            # VL = VLMAX (rs1 == x0)")
    else:
        vl_skip = new_label("vsetvl_vl_skip")
        lines.append(f"    mv      {addr_sew_vl}, {vlmax}")
        lines.append(f"    bltu    {vlmax}, {rs1}, {vl_skip}")
        lines.append(f"    mv      {addr_sew_vl}, {rs1}")
        lines.append(f"{vl_skip}:")

    # 写入 VL CSR (base_addr 复用为 addr_reg)
    if not keep_vl:
        lines.append(f"    li      {base_addr}, {vl_offset:#x}")
        lines.append(f"    add     {base_addr}, t6, {base_addr}")
        lines.append(f"    sd      {addr_sew_vl}, 0({base_addr})              # CSR.vl = VL")

    emit_clear_vstart(lines, base_addr)
    if not rd_is_zero:
        lines.append(f"    mv      {rd}, {addr_sew_vl}")

    lines.append(f"    j       {done_label}")
    lines.append(f"{invalid_label}:")
    lines.append(f"    li      {tmp}, 1")
    lines.append(f"    slli    {tmp}, {tmp}, 63                 # vill bit for RV64")
    lines.append(f"    li      {base_addr}, {vtype_offset:#x}")
    lines.append(f"    add     {base_addr}, t6, {base_addr}")
    lines.append(f"    sd      {tmp}, 0({base_addr})              # CSR.vtype = vill")
    lines.append(f"    li      {addr_sew_vl}, 0")
    lines.append(f"    li      {base_addr}, {vl_offset:#x}")
    lines.append(f"    add     {base_addr}, t6, {base_addr}")
    lines.append(f"    sd      {addr_sew_vl}, 0({base_addr})              # CSR.vl = 0")
    emit_clear_vstart(lines, base_addr)
    if not rd_is_zero:
        lines.append(f"    mv      {rd}, {addr_sew_vl}")
    lines.append(f"{done_label}:")

    return lines
