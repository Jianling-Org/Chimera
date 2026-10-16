# src/riscv/extensions/rvv/backends/scalar/handlers/config.py
"""
RVV 配置指令翻译模块

vsetvli/vsetivli/vsetvl 指令的翻译：
- 更新模拟的 CSR 寄存器 (vl, vtype)
- 这些 CSR 存储在 simulated_cpu_state 内存块中

CSR 内存布局 (来自 ``SimulatedStateLayout``):
- vl:     0x1020
- vtype:  0x1028
- vlenb:  0x1030
"""

from riscv.frontend.literals import parse_integer_literal
from riscv.extensions.rvv.translation.contracts import InstructionValidationError
from riscv.extensions.rvv.runtime.layout import CSR_OFFSETS
from riscv.extensions.rvv.runtime.access import emit_clear_vstart
from riscv.extensions.rvv.translation.vtype_decode import emit_vlmax_from_vtype


def _build_vsetvli_lines(context) -> list[str]:
    """
    翻译 vsetvli 指令

    格式: vsetvli rd, rs1, e64, m8, ta, ma

    RVV 规范语义 (关键！):
        1. rs1 != zero: vl = min(rs1, VLMAX), rd = vl
        2. rs1 == zero && rd != zero: vl = VLMAX, rd = vl (设置最大长度)
        3. rs1 == zero && rd == zero: 保持 vl 不变，仅更新 vtype

    翻译策略:
        1. 计算 VLMAX = VLEN * LMUL / SEW
        2. 根据 rs1 和 rd 的组合决定 vl 的值
        3. 将 vl 写入 CSR 内存 (0x1020)
        4. 如果 rd != zero，将 vl 写入 rd
    :return: 生成的汇编代码行列表
    """
    insn = context.instruction
    state = context.state
    lines = []
    operands = insn.operands

    if len(operands) < 3:
        raise InstructionValidationError(insn, f"Invalid operands for vsetvli: {insn.op_str}")

    rd = operands[0]    # 目标寄存器 (如 a4, a5, zero)
    rs1 = operands[1]   # 源寄存器 (如 a0, a6, zero)
    # operands[2:] 是配置参数 (e64, m8, ta, ma)

    # 更新 Python 层面的状态追踪器
    state.update(insn)

    # 获取 VLMAX 和 vtype 值
    vlmax = state.get_vlmax()
    vtype_value = state.get_vtype_value()

    # 获取 CSR 偏移量
    vl_offset = CSR_OFFSETS['vl']
    vtype_offset = CSR_OFFSETS['vtype']

    # 判断 rs1 和 rd 是否为 zero
    rs1_is_zero = (rs1 == 'zero' or rs1 == 'x0')
    rd_is_zero = (rd == 'zero' or rd == 'x0')

    # 生成注释 (简洁风格)
    lines.append(f"    # {insn.opcode} {insn.op_str}翻译开始: vlmax={vlmax}")

    # 这里使用 temp allocator，而不是继续硬编码 t1/t2/t3/t4：
    # - `rd` 和 `rs1` 在真实输入里完全可能就是某个 `t*`；
    # - 若继续硬编码同名寄存器，会在块内部先把语义值覆盖掉；
    # - 尤其 `vsetvli t1, t2, ...` 这种形式，就是之前最典型的冲突样例。
    temps = context.temp_register_allocator
    value_reg = temps.alloc_gpr()   # 用于暂存 vtype / vlmax
    source_reg = temps.alloc_gpr()  # 用于拷贝 rs1，避免直接改写语义输入
    result_reg = temps.alloc_gpr()  # 用于保存最终 vl
    addr_reg = temps.alloc_gpr()    # 用于拼接 CSR 地址

    # 写入 vtype CSR (所有情况都需要)
    # 安全方式：用寄存器中转计算 CSR 地址
    emit_clear_vstart(lines, addr_reg)
    lines.append(f"    li      {value_reg}, {vtype_value}       # {value_reg} = vtype")
    lines.append(f"    li      {addr_reg}, {vtype_offset}")
    lines.append(f"    add     {addr_reg}, t6, {addr_reg}")
    lines.append(f"    sd      {value_reg}, 0({addr_reg})              # CSR.vtype = vtype")

    # 根据 rs1 和 rd 的组合，计算 vl
    if rs1_is_zero and rd_is_zero:
        # 情况3: 保持 vl 不变
        lines.append(f"    # 保持 vl 不变")

    elif rs1_is_zero and not rd_is_zero:
        # 情况2: vl = VLMAX
        lines.append(f"    li      {result_reg}, {vlmax}          # {result_reg} = VLMAX")
        lines.append(f"    li      {addr_reg}, {vl_offset}")
        lines.append(f"    add     {addr_reg}, t6, {addr_reg}")
        lines.append(f"    sd      {result_reg}, 0({addr_reg})              # CSR.vl = VLMAX")
        lines.append(f"    mv      {rd}, {result_reg}             # {rd} = vl")

    else:
        # 情况1: vl = min(rs1, VLMAX)
        lines.append(f"    li      {value_reg}, {vlmax}          # {value_reg} = VLMAX")
        lines.append(f"    mv      {source_reg}, {rs1}            # {source_reg} = {rs1}")
        lines.append(f"    mv      {result_reg}, {value_reg}               # {result_reg} = VLMAX")
        lines.append(f"    bltu    {value_reg}, {source_reg}, 1f           # if VLMAX < rs1 skip")
        lines.append(f"    mv      {result_reg}, {source_reg}               # {result_reg} = rs1")
        lines.append(f"1:")
        lines.append(f"    li      {addr_reg}, {vl_offset}")
        lines.append(f"    add     {addr_reg}, t6, {addr_reg}")
        lines.append(f"    sd      {result_reg}, 0({addr_reg})              # CSR.vl = {result_reg}")
        if not rd_is_zero:
            lines.append(f"    mv      {rd}, {result_reg}             # {rd} = vl")

    lines.append(f"    # {insn.opcode} {insn.op_str}翻译结束: vlmax={vlmax}")
    return lines


def _build_vsetivli_lines(context) -> list[str]:
    """
    翻译 vsetivli 指令 (立即数版本)

    格式: vsetivli rd, uimm, e64, m1, ta, ma
    语义:
        rd = vl (返回实际设置的向量长度)
        vl = min(uimm, VLMAX)
    :return: 生成的汇编代码行列表
    """
    insn = context.instruction
    state = context.state
    lines = []
    operands = insn.operands

    if len(operands) < 3:
        raise InstructionValidationError(insn, f"Invalid operands for vsetivli: {insn.op_str}")

    rd = operands[0]    # 目标寄存器
    uimm = operands[1]  # 立即数 (如 0x1, 5)
    # operands[2:] 是配置参数

    # 更新状态追踪器
    state.update(insn)

    vlmax = state.get_vlmax()
    vtype_value = state.get_vtype_value()
    vl_offset = CSR_OFFSETS['vl']
    vtype_offset = CSR_OFFSETS['vtype']

    # 解析立即数
    imm_value = parse_integer_literal(uimm)

    lines.append(f"    # {insn.op_str}: imm={imm_value}, vlmax={vlmax}翻译开始")

    # `vsetivli` 也需要避免和 `rd` 冲突，因此同样改为按需选择 temp。
    temps = context.temp_register_allocator
    value_reg = temps.alloc_gpr()   # 先存 vtype，后复用为 vlmax
    imm_reg = temps.alloc_gpr()     # 保存 uimm
    result_reg = temps.alloc_gpr()  # 保存最终 vl
    addr_reg = temps.alloc_gpr()    # 拼接 CSR 地址

    # 写入 vtype CSR
    emit_clear_vstart(lines, addr_reg)
    lines.append(f"    li      {value_reg}, {vtype_value}       # {value_reg} = vtype")
    lines.append(f"    li      {addr_reg}, {vtype_offset}")
    lines.append(f"    add     {addr_reg}, t6, {addr_reg}")
    lines.append(f"    sd      {value_reg}, 0({addr_reg})              # CSR.vtype = vtype")
    lines.append(f"    li      {value_reg}, {vlmax}          # {value_reg} = VLMAX")
    lines.append(f"    li      {imm_reg}, {imm_value}          # {imm_reg} = {imm_value}")
    lines.append(f"    mv      {result_reg}, {value_reg}            # {result_reg} = VLMAX")
    lines.append(f"    bltu    {value_reg}, {imm_reg}, 1f        # if VLMAX < imm skip")
    lines.append(f"    mv      {result_reg}, {imm_reg}            # {result_reg} = imm")
    lines.append(f"1:")
    lines.append(f"    li      {addr_reg}, {vl_offset}")
    lines.append(f"    add     {addr_reg}, t6, {addr_reg}")
    lines.append(f"    sd      {result_reg}, 0({addr_reg})              # CSR.vl = {result_reg}")
    if rd != 'zero' and rd != 'x0':
        lines.append(f"    mv      {rd}, {result_reg}             # {rd} = vl")

    lines.append(f"    # {insn.op_str}: imm={imm_value}, vlmax={vlmax}翻译结束")
    return lines


def _build_vsetvl_lines(context) -> list[str]:
    """Decode dynamic vtype and apply all three rd/rs1 AVL selection rules."""
    insn = context.instruction
    state = context.state
    new_label = context.new_label
    operands = insn.operands
    if len(operands) != 3:
        raise InstructionValidationError(insn, f"Invalid operands for vsetvl: {insn.op_str}")

    rd, rs1, rs2 = operands
    state.update(insn)
    rd_is_zero = rd in ("zero", "x0")
    rs1_is_zero = rs1 in ("zero", "x0")
    keep_vl = rd_is_zero and rs1_is_zero
    temps = context.temp_register_allocator
    result = temps.alloc_gpr()
    addr = temps.alloc_gpr()
    vtype = temps.alloc_gpr()
    vlmax = temps.alloc_gpr()
    scratch = temps.alloc_gpr()
    old_vtype = temps.alloc_gpr() if keep_vl else None
    old_vlmax = temps.alloc_gpr() if keep_vl else None
    invalid = new_label("vsetvl_invalid_vtype")
    commit = new_label("vsetvl_commit")
    lines = [f"    # vsetvl {insn.op_str} (vtype from {rs2})"]

    if keep_vl:
        lines.append(f"    li      {addr}, {CSR_OFFSETS['vtype']:#x}")
        lines.append(f"    add     {addr}, t6, {addr}")
        lines.append(f"    ld      {old_vtype}, 0({addr})")
        emit_vlmax_from_vtype(
            lines, vtype_reg=old_vtype, out_reg=old_vlmax, sew_reg=result,
            base_reg=addr, lmul_reg=vtype, tmp_reg=scratch,
            source_vlenb=context.layout.vlenb, invalid_label=invalid,
            new_label=new_label, prefix="vsetvl_old_vlmax",
        )
    emit_vlmax_from_vtype(
        lines, vtype_reg=rs2, out_reg=vlmax, sew_reg=result,
        base_reg=addr, lmul_reg=vtype, tmp_reg=scratch,
        source_vlenb=context.layout.vlenb, invalid_label=invalid,
        new_label=new_label, prefix="vsetvl_new_vlmax",
    )
    if keep_vl:
        lines.append(f"    bne     {old_vlmax}, {vlmax}, {invalid}  # x0,x0 requires unchanged VLMAX")
        lines.append(f"    li      {addr}, {CSR_OFFSETS['vl']:#x}")
        lines.append(f"    add     {addr}, t6, {addr}")
        lines.append(f"    ld      {result}, 0({addr})  # rs1=x0, rd=x0: vl unchanged")
    elif rs1_is_zero:
        lines.append(f"    mv      {result}, {vlmax}")
    else:
        selected = new_label("vsetvl_vl_selected")
        lines.append(f"    mv      {result}, {vlmax}")
        lines.append(f"    bltu    {vlmax}, {rs1}, {selected}")
        lines.append(f"    mv      {result}, {rs1}")
        lines.append(f"{selected}:")
    lines.append(f"    mv      {vtype}, {rs2}")
    lines.append(f"    j       {commit}")
    lines.append(f"{invalid}:")
    lines.append(f"    li      {result}, 0")
    lines.append(f"    li      {vtype}, 1")
    lines.append(f"    slli    {vtype}, {vtype}, 63  # vill, with all other vtype bits clear")
    lines.append(f"{commit}:")
    lines.append(f"    li      {addr}, {CSR_OFFSETS['vtype']:#x}")
    lines.append(f"    add     {addr}, t6, {addr}")
    lines.append(f"    sd      {vtype}, 0({addr})")
    lines.append(f"    li      {addr}, {CSR_OFFSETS['vl']:#x}")
    lines.append(f"    add     {addr}, t6, {addr}")
    lines.append(f"    sd      {result}, 0({addr})")
    emit_clear_vstart(lines, addr)
    if not rd_is_zero:
        lines.append(f"    mv      {rd}, {result}")
    return lines
