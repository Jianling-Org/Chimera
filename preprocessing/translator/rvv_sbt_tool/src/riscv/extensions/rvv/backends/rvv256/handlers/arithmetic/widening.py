"""RVV256 widening 指令实现。"""

from __future__ import annotations

from typing import List
from riscv.frontend.model import RVInstruction
from riscv.extensions.rvv.analysis.config import StateTracker
from riscv.extensions.rvv.runtime.layout import SimulatedStateLayout
from riscv.extensions.rvv.translation.contracts import InstructionValidationError
from riscv.extensions.rvv.backends.rvv256.temp_regs import VRegTempAllocator
from riscv.extensions.rvv.translation.temps import TempRegisterAllocator
from riscv.extensions.rvv.backends.rvv256.support import (
    _chunk_size,
    _chunk_bytes,
    _emit_vsetvl_for_chunk,
    _load_vl_from_csr,
    _emit_mask_setup,
    _emit_mask_extraction_chunk,
    _emit_state_ptr,
    _get_int_load_signed,
    _get_int_load_unsigned,
    _emit_scalar_tail_vv,
    _get_int_store,
)


def _emit_unmasked_widening_binary(
    insn: RVInstruction,
    state: StateTracker,
    allocator: SimulatedStateLayout,
    new_label,
    *,
    opcode: str,
    scalar_rhs: bool,
    require_e16_m1: bool = True,
) -> List[str]:
    """
    生成不带掩码的 widening binary（加宽二元）分块路径。

    目标 vtype 使用窄元素 ``eSEW,mf2``：窄输入占 mf2，宽输入/输出因
    EEW=2*SEW 自动形成 m1。这样每块恰好写满一个 256-bit 宽结果寄存器，
    且尾部仍由 RVV 处理，不引入逐元素标量语义。
    """
    operands = list(insn.operands)
    if len(operands) != 3 or str(operands[-1]).endswith(".t"):
        raise InstructionValidationError(insn, f"{opcode} 当前只支持 unmasked 三操作数形式: {insn.op_str}")

    vd, vs2, rhs = map(str, operands)
    input_sew = state.sew
    if input_sew not in (8, 16, 32):
        raise InstructionValidationError(
            insn,
            f"{opcode} 的宽化输入只支持 SEW=8/16/32，"
            f"实际为 e{input_sew}: {insn.op_str}",
        )

    source_lmul = float(state.lmul)
    if require_e16_m1 and (input_sew != 16 or source_lmul != 1.0):
        # 本轮只声明真实工作负载使用、且已经进入目标验证清单的 e16,m1。
        # 更大的 LMUL 会改变宽目标的源寄存器组边界；在没有独立语义用例前
        # 必须 fail-fast，不能因为分块循环看似通用就扩大支持范围。
        raise InstructionValidationError(
            insn,
            f"{opcode} 当前只支持输入 e16,m1，实际为 "
            f"e{input_sew},m{state.lmul:g}: {insn.op_str}",
        )
    if not require_e16_m1 and source_lmul * 2.0 > 8.0:
        # widening 的目的 EMUL 是源 LMUL 的两倍；m8 再扩宽会超过 RVV
        # 合法范围。这里在生成前拒绝，避免产生目标汇编后才暴露编码错误。
        raise InstructionValidationError(
            insn,
            f"{opcode} 的目的 EMUL={source_lmul * 2.0:g} 超出 m8: "
            f"{insn.op_str}",
        )

    output_sew = input_sew * 2
    chunk_n = 256 // output_sew
    in_step = chunk_n * (input_sew // 8)
    out_step = chunk_n * (output_sew // 8)
    shift = {8: 4, 16: 3, 32: 2}[input_sew]

    vtemps = VRegTempAllocator(insn)
    wide_vreg = vtemps.alloc_vreg()
    narrow_vreg = vtemps.alloc_vreg()
    dst_vreg = vtemps.alloc_vreg()

    temps = TempRegisterAllocator(insn, reserved_gprs=("t6",))
    vl_reg = temps.alloc_gpr()
    full_reg = temps.alloc_gpr()
    tail_reg = temps.alloc_gpr()
    vd_ptr = temps.alloc_gpr()
    vs2_ptr = temps.alloc_gpr()
    rhs_ptr = None if scalar_rhs else temps.alloc_gpr()
    scratch = temps.alloc_gpr()

    lines = [
        f"# {opcode} {insn.op_str} (256-bit widening base path)",
        f"# 每块 {chunk_n} 个 e{input_sew} 元素，宽结果为 e{output_sew}",
    ]
    _load_vl_from_csr(lines, vl_reg=vl_reg, addr_reg=full_reg)
    lines.append(f"    srli    {full_reg}, {vl_reg}, {shift}")
    lines.append(f"    andi    {tail_reg}, {vl_reg}, {chunk_n - 1}")
    _emit_state_ptr(lines, vd_ptr, allocator.get_offset(vd))
    _emit_state_ptr(lines, vs2_ptr, allocator.get_offset(vs2))
    if rhs_ptr is not None:
        _emit_state_ptr(lines, rhs_ptr, allocator.get_offset(rhs))

    loop = new_label(f"{opcode.replace('.', '_')}_main")
    after = new_label(f"{opcode.replace('.', '_')}_after")
    end = new_label(f"{opcode.replace('.', '_')}_end")
    lines.append(f"    beqz    {full_reg}, {after}")
    _emit_vsetvl_for_chunk(lines, chunk_n, input_sew, "mf2", vl_reg, scratch_reg=scratch)
    lines.append(f"{loop}:")

    def emit_body() -> None:
        if scalar_rhs:
            lines.append(f"    vle{input_sew}.v {narrow_vreg}, ({vs2_ptr})")
            lines.append(f"    {opcode} {dst_vreg}, {narrow_vreg}, {rhs}")
        else:
            lines.append(f"    vle{output_sew}.v {wide_vreg}, ({vs2_ptr})")
            lines.append(f"    vle{input_sew}.v {narrow_vreg}, ({rhs_ptr})")
            lines.append(f"    {opcode} {dst_vreg}, {wide_vreg}, {narrow_vreg}")
        lines.append(f"    vse{output_sew}.v {dst_vreg}, ({vd_ptr})")

    emit_body()
    lines.append(f"    addi    {vs2_ptr}, {vs2_ptr}, {in_step if scalar_rhs else out_step}")
    if rhs_ptr is not None:
        lines.append(f"    addi    {rhs_ptr}, {rhs_ptr}, {in_step}")
    lines.append(f"    addi    {vd_ptr}, {vd_ptr}, {out_step}")
    lines.append(f"    addi    {full_reg}, {full_reg}, -1")
    lines.append(f"    bnez    {full_reg}, {loop}")
    lines.append(f"{after}:")
    lines.append(f"    beqz    {tail_reg}, {end}")
    lines.append(f"    vsetvli zero, {tail_reg}, e{input_sew}, mf2, ta, ma")
    emit_body()
    lines.append(f"{end}:")
    return lines


def _build_vfwmul_vf_lines(context) -> list[str]:
    """翻译真实工作负载中的 ``vfwmul.vf`` e16/Zvfh 形式。"""
    insn = context.instruction
    state = context.state
    allocator = context.layout
    new_label = context.new_label
    return _emit_unmasked_widening_binary(
        insn, state, allocator, new_label, opcode="vfwmul.vf", scalar_rhs=True
    )


def _build_vwadd_wv_lines(context) -> list[str]:
    """翻译 signed wide+narrow ``vwadd.wv``，宽源和宽目标使用 2*SEW。"""
    insn = context.instruction
    state = context.state
    allocator = context.layout
    new_label = context.new_label
    return _emit_unmasked_widening_binary(
        insn, state, allocator, new_label, opcode="vwadd.wv", scalar_rhs=False,
        require_e16_m1=False,
    )


def _build_vwaddu_vx_lines(context) -> list[str]:
    """翻译无掩码 ``vwaddu.vx vd, vs2, rs1``。

    该 form 的两个输入都是窄元素，结果是二倍宽的无符号元素；因此目标
    临时 vtype 仍采用 ``eSEW,mf2``，由原生 ``vwaddu.vx`` 负责对向量元素
    和标量低 SEW 位做零扩展。与旧的 e16,m1 专用热点模板不同，这里允许
    e8/e16/e32 以及目的 EMUL 不超过 m8 的源 LMUL；``v0.t`` 仍由 new_label
    明确拒绝，不能把未实现的 mask 语义静默降成无掩码。
    """
    insn = context.instruction
    state = context.state
    allocator = context.layout
    new_label = context.new_label
    return _emit_unmasked_widening_binary(
        insn,
        state,
        allocator,
        new_label,
        opcode="vwaddu.vx",
        scalar_rhs=True,
        require_e16_m1=False,
    )


def _build_vwaddu_wv_lines(context) -> list[str]:
    """
    翻译 vwaddu.wv 指令 (256-bit 模式, widening unsigned add)

    格式: vwaddu.wv vd, vs2, vs1
    语义: vd[i] = vs2[i] + zext(vs1[i])
          vs2/vd 为 2*SEW 宽元素, vs1 为 SEW 宽元素。
    """
    insn = context.instruction
    state = context.state
    allocator = context.layout
    new_label = context.new_label
    lines = []
    mask_suffix = ""
    operands = insn.operands
    if len(operands) != 3:
        raise InstructionValidationError(insn, f"Invalid operands for {insn.opcode}: {insn.op_str}")

    vd, vs2, vs1 = operands
    input_sew = state.sew
    output_sew = input_sew * 2
    if input_sew not in (8, 16, 32):
        raise InstructionValidationError(
            insn,
            "vwaddu.wv supports input SEW=8/16/32 "
            f"(wide e16/e32/e64), got SEW={input_sew}",
        )

    chunk_n = 256 // output_sew
    chunk_bytes_narrow = chunk_n * (input_sew // 8)
    chunk_bytes_wide = chunk_n * (output_sew // 8)
    shift_amt = {8: 4, 16: 3, 32: 2}[input_sew]
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
    vd_ptr = temps.alloc_gpr()
    vs2_ptr = temps.alloc_gpr()
    vs1_ptr = temps.alloc_gpr()
    temp = temps.alloc_gpr()

    lines.append(f"# vwaddu.wv {vd}, {vs2}, {vs1} (256-bit mode, RVV1.0)")
    lines.append(f"# Semantic: {vd}[i] = {vs2}[i] + zext({vs1}[i]), e{input_sew} -> e{output_sew}")
    lines.append("")

    _load_vl_from_csr(lines, vl_reg=vl_reg, addr_reg=chunk_count)
    lines.append(f"    srli    {chunk_count}, {vl_reg}, {shift_amt}       # {chunk_count} = vl / {chunk_n}")
    lines.append(f"    andi    {tail_count}, {vl_reg}, {mask}              # {tail_count} = vl % {chunk_n}")
    lines.append("")

    lines.append(f"    li      {temp}, {vd_off:#x}")
    lines.append(f"    add     {vd_ptr}, t6, {temp}             # {vd_ptr} = &{vd} (wide)")
    lines.append(f"    li      {temp}, {vs2_off:#x}")
    lines.append(f"    add     {vs2_ptr}, t6, {temp}            # {vs2_ptr} = &{vs2} (wide)")
    lines.append(f"    li      {temp}, {vs1_off:#x}")
    lines.append(f"    add     {vs1_ptr}, t6, {temp}            # {vs1_ptr} = &{vs1} (narrow)")
    lines.append("")

    main_loop = new_label("vwaddu_wv_main")
    after_main = new_label("vwaddu_wv_after")

    lines.append(f"    # --- 主循环: 每块处理 {chunk_n} 个元素 ---")
    lines.append(f"    # wide 输入/输出: {chunk_bytes_wide}B (e{output_sew}, LMUL=m1), narrow 输入: {chunk_bytes_narrow}B (e{input_sew}, LMUL=mf2)")
    lines.append(f"    beqz    {chunk_count}, {after_main}")
    lines.append(f"{main_loop}:")
    _emit_vsetvl_for_chunk(lines, chunk_n, input_sew, "mf2", vl_reg, scratch_reg=temp)
    lines.append(f"    vle{output_sew}.v {vs2_vreg}, ({vs2_ptr})       # 加载 wide {vs2}")
    lines.append(f"    vle{input_sew}.v {vs1_vreg}, ({vs1_ptr})       # 加载 narrow {vs1}")
    lines.append(f"    vwaddu.wv {vd_vreg}, {vs2_vreg}, {vs1_vreg}          # wide + zext(narrow)")
    lines.append(f"    vse{output_sew}.v {vd_vreg}, ({vd_ptr})        # 写回 wide {vd}")
    lines.append("")
    lines.append(f"    addi    {vs2_ptr}, {vs2_ptr}, {chunk_bytes_wide}")
    lines.append(f"    addi    {vs1_ptr}, {vs1_ptr}, {chunk_bytes_narrow}")
    lines.append(f"    addi    {vd_ptr}, {vd_ptr}, {chunk_bytes_wide}")
    lines.append(f"    addi    {chunk_count}, {chunk_count}, -1")
    lines.append(f"    bnez    {chunk_count}, {main_loop}")
    lines.append(f"{after_main}:")
    lines.append("")

    end_label = new_label("vwaddu_wv_end")
    lines.append(f"    # --- 尾部 RVV widening add chunk: 剩余 {tail_count} 个元素 ---")
    lines.append(f"    beqz    {tail_count}, {end_label}")
    lines.append(f"    vsetvli zero, {tail_count}, e{input_sew}, mf2, ta, ma")
    lines.append(f"    vle{output_sew}.v {vs2_vreg}, ({vs2_ptr})")
    lines.append(f"    vle{input_sew}.v {vs1_vreg}, ({vs1_ptr})")
    lines.append(f"    vwaddu.wv {vd_vreg}, {vs2_vreg}, {vs1_vreg}")
    lines.append(f"    vse{output_sew}.v {vd_vreg}, ({vd_ptr})")
    lines.append(f"{end_label}:")

    return lines


def _build_vwadd_vv_lines(context) -> list[str]:
    """
    翻译 vwadd.vv 指令 (256-bit 模式, signed widening add)

    格式: vwadd.vv vd, vs2, vs1
    语义: vd[i] = sext(vs2[i]) + sext(vs1[i]) (e{sew} -> e{sew*2})
    """
    insn = context.instruction
    state = context.state
    allocator = context.layout
    new_label = context.new_label
    lines = []
    operands = insn.operands
    if len(operands) != 3:
        raise InstructionValidationError(insn, f"Invalid operands for {insn.opcode}: {insn.op_str}")

    vd, vs2, vs1 = operands
    input_sew = state.sew
    output_sew = input_sew * 2
    if input_sew not in (8, 16, 32):
        raise InstructionValidationError(insn, f"vwadd.vv supports input SEW=8/16/32, got SEW={input_sew}")

    chunk_n = 256 // output_sew
    chunk_bytes_in = chunk_n * (input_sew // 8)
    chunk_bytes_out = chunk_n * (output_sew // 8)
    shift_amt = {8: 4, 16: 3, 32: 2}[input_sew]
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
    temp = temps.alloc_gpr()

    lines.append(f"# vwadd.vv {vd}, {vs2}, {vs1} (256-bit mode)")
    lines.append(f"# Semantic: {vd}[i] = sext({vs2}[i]) + sext({vs1}[i]), e{input_sew} -> e{output_sew}")
    lines.append("")

    _load_vl_from_csr(lines, vl_reg=vl_reg, addr_reg=chunk_count)
    lines.append(f"    srli    {chunk_count}, {vl_reg}, {shift_amt}       # {chunk_count} = vl / {chunk_n}")
    lines.append(f"    andi    {tail_count}, {vl_reg}, {mask}              # {tail_count} = vl % {chunk_n}")
    lines.append("")

    lines.append(f"    li      {temp}, {vs2_off:#x}")
    lines.append(f"    add     {vs2_ptr}, t6, {temp}            # {vs2_ptr} = &{vs2}")
    lines.append(f"    li      {temp}, {vs1_off:#x}")
    lines.append(f"    add     {vs1_ptr}, t6, {temp}            # {vs1_ptr} = &{vs1}")
    lines.append(f"    li      {temp}, {vd_off:#x}")
    lines.append(f"    add     {vd_ptr}, t6, {temp}             # {vd_ptr} = &{vd}")
    lines.append("")

    main_loop = new_label("vwadd_vv_main")
    after_main = new_label("vwadd_vv_after")
    end_label = new_label("vwadd_vv_end")

    lines.append(f"    # --- 主循环: 每块处理 {chunk_n} 个元素 ---")
    lines.append(f"    beqz    {chunk_count}, {after_main}")
    lines.append(f"{main_loop}:")
    _emit_vsetvl_for_chunk(lines, chunk_n, input_sew, "mf2", vl_reg, scratch_reg=temp)
    lines.append(f"    vle{input_sew}.v {vs2_vreg}, ({vs2_ptr})")
    lines.append(f"    vle{input_sew}.v {vs1_vreg}, ({vs1_ptr})")
    lines.append(f"    vwadd.vv {vd_vreg}, {vs2_vreg}, {vs1_vreg}")
    lines.append(f"    vse{output_sew}.v {vd_vreg}, ({vd_ptr})")
    lines.append(f"    addi    {vs2_ptr}, {vs2_ptr}, {chunk_bytes_in}")
    lines.append(f"    addi    {vs1_ptr}, {vs1_ptr}, {chunk_bytes_in}")
    lines.append(f"    addi    {vd_ptr}, {vd_ptr}, {chunk_bytes_out}")
    lines.append(f"    addi    {chunk_count}, {chunk_count}, -1")
    lines.append(f"    bnez    {chunk_count}, {main_loop}")
    lines.append(f"{after_main}:")
    lines.append(f"    beqz    {tail_count}, {end_label}")
    lines.append(f"    vsetvli zero, {tail_count}, e{input_sew}, mf2, ta, ma")
    lines.append(f"    vle{input_sew}.v {vs2_vreg}, ({vs2_ptr})")
    lines.append(f"    vle{input_sew}.v {vs1_vreg}, ({vs1_ptr})")
    lines.append(f"    vwadd.vv {vd_vreg}, {vs2_vreg}, {vs1_vreg}")
    lines.append(f"    vse{output_sew}.v {vd_vreg}, ({vd_ptr})")
    lines.append(f"{end_label}:")

    return lines


def _build_vwsll_vi_lines(context) -> list[str]:
    """
    翻译 vwsll.vi 指令 (256-bit 模式, widening shift left)

    格式: vwsll.vi vd, vs2, uimm
    语义: vd[i] = zext(vs2[i]) << uimm (widening: e{sew} -> e{sew*2})
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
        raise InstructionValidationError(insn, f"vwsll.vi immediate must be an integer: {insn.op_str}")

    if not 0 <= uimm <= 31:
        raise InstructionValidationError(insn, f"vwsll.vi immediate must be 5-bit unsigned (0..31), got {uimm}")

    input_sew = state.sew
    output_sew = input_sew * 2
    if input_sew not in (8, 16, 32):
        raise InstructionValidationError(
            insn,
            "vwsll.vi supports input SEW=8/16/32 "
            f"(output e16/e32/e64), got SEW={input_sew}",
        )

    chunk_n = 256 // output_sew
    chunk_bytes_in = chunk_n * (input_sew // 8)
    chunk_bytes_out = chunk_n * (output_sew // 8)
    shift_amt = {8: 4, 16: 3, 32: 2}[input_sew]
    mask = chunk_n - 1

    vd_off = allocator.get_offset(vd)
    vs2_off = allocator.get_offset(vs2)

    vtemps = VRegTempAllocator(insn)
    vs2_vreg = vtemps.alloc_vreg()
    vd_vreg = vtemps.alloc_vreg()
    if vd_vreg == "v25":
        vd_vreg = vtemps.alloc_vreg()

    temps = context.temp_register_allocator
    vl_reg = temps.alloc_gpr()
    chunk_count = temps.alloc_gpr()
    tail_count = temps.alloc_gpr()
    vs2_ptr = temps.alloc_gpr()
    vd_ptr = temps.alloc_gpr()
    temp = temps.alloc_gpr()

    lines.append(f"# vwsll.vi {vd}, {vs2}, {uimm} (256-bit mode, widening)")
    lines.append(f"# Semantic: {vd}[i] = zext({vs2}[i]) << {uimm}, e{input_sew} -> e{output_sew}")
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

    main_loop = new_label("vwsll_vi_main")
    after_main = new_label("vwsll_vi_after")

    lines.append(f"    # --- 主循环: 每块处理 {chunk_n} 个元素 ---")
    lines.append(f"    # 输入: {chunk_bytes_in}B (e{input_sew}, LMUL=mf2), 输出: {chunk_bytes_out}B (e{output_sew}, LMUL=m1)")
    lines.append(f"    beqz    {chunk_count}, {after_main}")
    lines.append(f"{main_loop}:")
    _emit_vsetvl_for_chunk(lines, chunk_n, input_sew, "mf2", vl_reg, scratch_reg=temp)
    lines.append(f"    vle{input_sew}.v {vs2_vreg}, ({vs2_ptr})       # 加载 {vs2} 块 (e{input_sew}, mf2)")
    lines.append(f"    vwsll.vi {vd_vreg}, {vs2_vreg}, {uimm}             # widening logical shift left")
    lines.append(f"    vse{output_sew}.v {vd_vreg}, ({vd_ptr})       # 写回 {vd} 块 (e{output_sew})")
    lines.append("")
    lines.append(f"    addi    {vs2_ptr}, {vs2_ptr}, {chunk_bytes_in}")
    lines.append(f"    addi    {vd_ptr}, {vd_ptr}, {chunk_bytes_out}")
    lines.append(f"    addi    {chunk_count}, {chunk_count}, -1")
    lines.append(f"    bnez    {chunk_count}, {main_loop}")
    lines.append(f"{after_main}:")
    lines.append("")

    end_label = new_label("vwsll_vi_end")
    lines.append(f"    # --- 尾部 RVV widening chunk: 剩余 {tail_count} 个元素 ---")
    lines.append(f"    beqz    {tail_count}, {end_label}")
    lines.append(f"    vsetvli zero, {tail_count}, e{input_sew}, mf2, ta, ma")
    lines.append(f"    vle{input_sew}.v {vs2_vreg}, ({vs2_ptr})")
    lines.append(f"    vwsll.vi {vd_vreg}, {vs2_vreg}, {uimm}")
    lines.append(f"    vse{output_sew}.v {vd_vreg}, ({vd_ptr})")
    lines.append(f"{end_label}:")

    return lines


def _build_vwmul_vx_lines(context) -> list[str]:
    """
    翻译 vwmul.vx 指令 (256-bit 模式, widening)

    格式: vwmul.vx vd, vs2, rs1
    语义: vd[i] = sext(vs2[i]) * sext(rs1) (widening: e{sew} -> e{sew*2})
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
    vs2 = operands[1]
    rs1 = operands[2]

    input_sew = state.sew
    output_sew = input_sew * 2

    if input_sew not in (8, 16, 32):
        raise InstructionValidationError(
            insn, f"vwmul.vx 不支持输入 SEW={input_sew}"
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

    lines.append(f"# vwmul.vx {vd}, {vs2}, {rs1} (256-bit mode)")
    lines.append(f"# Semantic: {vd}[i] = sext({vs2}[i]) * sext({rs1}), e{input_sew} -> e{output_sew}")
    lines.append("")

    _load_vl_from_csr(lines, vl_reg=vl_reg, addr_reg=chunk_count)
    lines.append(f"    srli    {chunk_count}, {vl_reg}, {shift_amt}       # {chunk_count} = vl / {chunk_n}")
    lines.append(f"    andi    {tail_count}, {vl_reg}, {mask}              # {tail_count} = vl % {chunk_n}")
    lines.append("")

    lines.append(f"    li      {temp}, {vs2_off:#x}")
    lines.append(f"    add     {vs2_ptr}, t6, {temp}            # {vs2_ptr} = &{vs2}")
    lines.append(f"    li      {temp}, {vd_off:#x}")
    lines.append(f"    add     {vd_ptr}, t6, {temp}             # {vd_ptr} = &{vd}")
    lines.append(f"    slli    {temp}, {rs1}, {64 - input_sew}              # scalar low e{input_sew} bits")
    lines.append(f"    srai    {temp}, {temp}, {64 - input_sew}              # sign-extend scalar to XLEN")
    lines.append("")

    # ========== 主循环 (256-bit 块, LMUL=mf2 用于输入) ==========
    main_loop = new_label("vwmul_vx_main")
    after_main = new_label("vwmul_vx_after")

    lines.append(f"    # --- 主循环: 每块处理 {chunk_n} 个元素 ---")
    lines.append(f"    # 输入: {chunk_bytes_in}B (LMUL=mf2), 输出: {chunk_bytes_out}B (LMUL=m1)")
    lines.append(f"    beqz    {chunk_count}, {after_main}")
    lines.append(f"{main_loop}:")
    _emit_vsetvl_for_chunk(lines, chunk_n, input_sew, "mf2", vl_reg, scratch_reg=temp)
    lines.append("")
    lines.append(f"    vle{input_sew}.v {vs2_vreg}, ({vs2_ptr})       # 加载 {vs2} 块 (e{input_sew}, mf2)")
    lines.append(f"    vwmul.vx {vd_vreg}, {vs2_vreg}, {rs1}             # {vd}[i] = sext({vs2}[i]) * sext({rs1})")
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
    tail_loop = new_label("vwmul_vx_tail")
    end_label = new_label("vwmul_vx_end")

    int_load = _get_int_load_signed(input_sew)
    int_store = _get_int_store(output_sew)

    lines.append(f"{tail_loop}:")
    lines.append(f"    beqz    {tail_count}, {end_label}")
    lines.append(f"    {int_load:<8} {chunk_count}, 0({vs2_ptr})           # {chunk_count} = sext({vs2}[i]) (e{input_sew})")
    lines.append(f"    mul     {chunk_count}, {chunk_count}, {temp}               # {chunk_count} = sext({vs2}[i]) * sext(low e{input_sew} {rs1})")
    lines.append(f"    {int_store:<8} {chunk_count}, 0({vd_ptr})            # {vd}[i] = {chunk_count}")
    lines.append(f"    addi    {vs2_ptr}, {vs2_ptr}, {elem_bytes_in}")
    lines.append(f"    addi    {vd_ptr}, {vd_ptr}, {elem_bytes_out}")
    lines.append(f"    addi    {tail_count}, {tail_count}, -1")
    lines.append(f"    j       {tail_loop}")
    lines.append(f"{end_label}:")

    return lines


def _build_vwmul_vv_lines(context) -> list[str]:
    """
    翻译 vwmul.vv 指令 (256-bit 模式, widening)

    格式: vwmul.vv vd, vs2, vs1
    语义: vd[i] = sext(vs2[i]) * sext(vs1[i]) (widening: e{sew} -> e{sew*2})
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

    input_sew = state.sew
    output_sew = input_sew * 2
    if input_sew not in (8, 16, 32):
        raise ValueError(
            f"vwmul.vv 当前仅支持输入 SEW=8/16/32 "
            f"(e8 -> e16, e16 -> e32, e32 -> e64), "
            f"实际为 SEW={state.sew}"
        )

    chunk_n = 256 // output_sew
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
    temp = temps.alloc_gpr()

    lines.append(f"# vwmul.vv {vd}, {vs2}, {vs1} (256-bit mode)")
    lines.append(f"# Semantic: {vd}[i] = sext({vs2}[i]) * sext({vs1}[i]), e{input_sew} -> e{output_sew}")
    lines.append("")

    _load_vl_from_csr(lines, vl_reg=vl_reg, addr_reg=chunk_count)
    lines.append(f"    srli    {chunk_count}, {vl_reg}, {shift_amt}       # {chunk_count} = vl / {chunk_n}")
    lines.append(f"    andi    {tail_count}, {vl_reg}, {mask}              # {tail_count} = vl % {chunk_n}")
    lines.append("")

    lines.append(f"    li      {temp}, {vs2_off:#x}")
    lines.append(f"    add     {vs2_ptr}, t6, {temp}            # {vs2_ptr} = &{vs2}")
    lines.append(f"    li      {temp}, {vs1_off:#x}")
    lines.append(f"    add     {vs1_ptr}, t6, {temp}            # {vs1_ptr} = &{vs1}")
    lines.append(f"    li      {temp}, {vd_off:#x}")
    lines.append(f"    add     {vd_ptr}, t6, {temp}             # {vd_ptr} = &{vd}")
    lines.append("")

    main_loop = new_label("vwmul_vv_main")
    after_main = new_label("vwmul_vv_after")

    lines.append(f"    # --- 主循环: 每块处理 {chunk_n} 个元素 ---")
    lines.append(f"    # 输入: {chunk_bytes_in}B/源 (LMUL=mf2), 输出: {chunk_bytes_out}B (LMUL=m1)")
    lines.append(f"    beqz    {chunk_count}, {after_main}")
    lines.append(f"{main_loop}:")
    _emit_vsetvl_for_chunk(lines, chunk_n, input_sew, "mf2", vl_reg, scratch_reg=temp)
    lines.append("")
    lines.append(f"    vle{input_sew}.v {vs2_vreg}, ({vs2_ptr})       # 加载 {vs2} 块 (e{input_sew}, mf2)")
    lines.append(f"    vle{input_sew}.v {vs1_vreg}, ({vs1_ptr})       # 加载 {vs1} 块 (e{input_sew}, mf2)")
    lines.append(f"    vwmul.vv {vd_vreg}, {vs2_vreg}, {vs1_vreg}        # widening signed multiply")
    lines.append(f"    vse{output_sew}.v {vd_vreg}, ({vd_ptr})       # 写回 {vd} 块 (e{output_sew})")
    lines.append("")
    lines.append(f"    addi    {vs2_ptr}, {vs2_ptr}, {chunk_bytes_in}")
    lines.append(f"    addi    {vs1_ptr}, {vs1_ptr}, {chunk_bytes_in}")
    lines.append(f"    addi    {vd_ptr}, {vd_ptr}, {chunk_bytes_out}")
    lines.append(f"    addi    {chunk_count}, {chunk_count}, -1")
    lines.append(f"    bnez    {chunk_count}, {main_loop}")
    lines.append(f"{after_main}:")
    lines.append("")

    int_load = _get_int_load_signed(input_sew)
    int_store = _get_int_store(output_sew)
    tail_loop = new_label("vwmul_vv_tail")
    end_label = new_label("vwmul_vv_end")
    lines.append(f"    # --- 尾部标量回退: 剩余 {tail_count} 个元素 ---")
    lines.append(f"{tail_loop}:")
    lines.append(f"    beqz    {tail_count}, {end_label}")
    lines.append(f"    {int_load:<8} {chunk_count}, 0({vs2_ptr})           # {chunk_count} = sext({vs2}[i])")
    lines.append(f"    {int_load:<8} {temp}, 0({vs1_ptr})                  # {temp} = sext({vs1}[i])")
    lines.append(f"    mul     {chunk_count}, {chunk_count}, {temp}")
    lines.append(f"    {int_store:<8} {chunk_count}, 0({vd_ptr})            # {vd}[i] = product")
    lines.append(f"    addi    {vs2_ptr}, {vs2_ptr}, {elem_bytes_in}")
    lines.append(f"    addi    {vs1_ptr}, {vs1_ptr}, {elem_bytes_in}")
    lines.append(f"    addi    {vd_ptr}, {vd_ptr}, {elem_bytes_out}")
    lines.append(f"    addi    {tail_count}, {tail_count}, -1")
    lines.append(f"    j       {tail_loop}")
    lines.append(f"{end_label}:")

    return lines


def _build_vwmulu_vx_lines(context) -> list[str]:
    """
    翻译 vwmulu.vx 指令 (256-bit 模式, unsigned widening multiply)

    格式: vwmulu.vx vd, vs2, rs1
    语义: vd[i] = zext(vs2[i]) * zext(rs1) (widening: e{sew} -> e{sew*2})
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

    input_sew = state.sew
    output_sew = input_sew * 2
    if input_sew not in (8, 16, 32):
        raise InstructionValidationError(insn, f"vwmulu.vx supports input SEW=8/16/32, got SEW={input_sew}")

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
    scalar = temps.alloc_gpr()
    temp = temps.alloc_gpr()

    lines.append(f"# vwmulu.vx {vd}, {vs2}, {rs1} (256-bit mode)")
    lines.append(f"# Semantic: {vd}[i] = zext({vs2}[i]) * zext({rs1}), e{input_sew} -> e{output_sew}")
    lines.append("")

    _load_vl_from_csr(lines, vl_reg=vl_reg, addr_reg=chunk_count)
    lines.append(f"    srli    {chunk_count}, {vl_reg}, {shift_amt}       # {chunk_count} = vl / {chunk_n}")
    lines.append(f"    andi    {tail_count}, {vl_reg}, {mask}              # {tail_count} = vl % {chunk_n}")
    lines.append("")

    lines.append(f"    li      {temp}, {vs2_off:#x}")
    lines.append(f"    add     {vs2_ptr}, t6, {temp}            # {vs2_ptr} = &{vs2}")
    lines.append(f"    li      {temp}, {vd_off:#x}")
    lines.append(f"    add     {vd_ptr}, t6, {temp}             # {vd_ptr} = &{vd}")
    lines.append(f"    slli    {scalar}, {rs1}, {64 - input_sew}              # scalar low e{input_sew} bits")
    lines.append(f"    srli    {scalar}, {scalar}, {64 - input_sew}              # zero-extend scalar to XLEN")
    lines.append("")

    main_loop = new_label("vwmulu_vx_main")
    after_main = new_label("vwmulu_vx_after")

    lines.append(f"    # --- 主循环: 每块处理 {chunk_n} 个元素 ---")
    lines.append(f"    # 输入: {chunk_bytes_in}B (LMUL=mf2), 输出: {chunk_bytes_out}B (LMUL=m1)")
    lines.append(f"    beqz    {chunk_count}, {after_main}")
    lines.append(f"{main_loop}:")
    _emit_vsetvl_for_chunk(lines, chunk_n, input_sew, "mf2", vl_reg, scratch_reg=temp)
    lines.append("")
    lines.append(f"    vle{input_sew}.v {vs2_vreg}, ({vs2_ptr})       # 加载 {vs2} 块 (e{input_sew}, mf2)")
    lines.append(f"    vwmulu.vx {vd_vreg}, {vs2_vreg}, {scalar}           # unsigned widening multiply")
    lines.append(f"    vse{output_sew}.v {vd_vreg}, ({vd_ptr})       # 写回 {vd} 块 (e{output_sew})")
    lines.append("")
    lines.append(f"    addi    {vs2_ptr}, {vs2_ptr}, {chunk_bytes_in}")
    lines.append(f"    addi    {vd_ptr}, {vd_ptr}, {chunk_bytes_out}")
    lines.append(f"    addi    {chunk_count}, {chunk_count}, -1")
    lines.append(f"    bnez    {chunk_count}, {main_loop}")
    lines.append(f"{after_main}:")
    lines.append("")

    int_load = _get_int_load_unsigned(input_sew)
    int_store = _get_int_store(output_sew)
    tail_loop = new_label("vwmulu_vx_tail")
    end_label = new_label("vwmulu_vx_end")

    lines.append(f"    # --- 尾部标量回退: 剩余 {tail_count} 个元素 ---")
    lines.append(f"{tail_loop}:")
    lines.append(f"    beqz    {tail_count}, {end_label}")
    lines.append(f"    {int_load:<8} {chunk_count}, 0({vs2_ptr})           # {chunk_count} = zext({vs2}[i]) (e{input_sew})")
    lines.append(f"    mul     {chunk_count}, {chunk_count}, {scalar}             # unsigned low-product is exact into e{output_sew}")
    lines.append(f"    {int_store:<8} {chunk_count}, 0({vd_ptr})            # {vd}[i] = product")
    lines.append(f"    addi    {vs2_ptr}, {vs2_ptr}, {elem_bytes_in}")
    lines.append(f"    addi    {vd_ptr}, {vd_ptr}, {elem_bytes_out}")
    lines.append(f"    addi    {tail_count}, {tail_count}, -1")
    lines.append(f"    j       {tail_loop}")
    lines.append(f"{end_label}:")

    return lines


def _build_vwmulu_vv_lines(context) -> list[str]:
    """
    翻译 vwmulu.vv 指令 (256-bit 模式, unsigned widening multiply)

    格式: vwmulu.vv vd, vs2, vs1
    语义: vd[i] = zext(vs2[i]) * zext(vs1[i]) (widening: e{sew} -> e{sew*2})
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
    vs1 = operands[2]

    input_sew = state.sew
    output_sew = input_sew * 2
    if input_sew not in (8, 16, 32):
        raise InstructionValidationError(insn, f"vwmulu.vv supports input SEW=8/16/32, got SEW={input_sew}")

    chunk_n = 256 // output_sew
    chunk_bytes_in = chunk_n * (input_sew // 8)
    chunk_bytes_out = chunk_n * (output_sew // 8)
    shift_amt = {8: 4, 16: 3, 32: 2}[input_sew]
    mask = chunk_n - 1
    elem_bytes_in = input_sew // 8
    elem_bytes_out = output_sew // 8

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
    temp = temps.alloc_gpr()

    lines.append(f"# vwmulu.vv {vd}, {vs2}, {vs1} (256-bit mode)")
    lines.append(f"# Semantic: {vd}[i] = zext({vs2}[i]) * zext({vs1}[i]), e{input_sew} -> e{output_sew}")
    lines.append("")

    _load_vl_from_csr(lines, vl_reg=vl_reg, addr_reg=chunk_count)
    lines.append(f"    srli    {chunk_count}, {vl_reg}, {shift_amt}       # {chunk_count} = vl / {chunk_n}")
    lines.append(f"    andi    {tail_count}, {vl_reg}, {mask}              # {tail_count} = vl % {chunk_n}")
    lines.append("")

    lines.append(f"    li      {temp}, {vs2_off:#x}")
    lines.append(f"    add     {vs2_ptr}, t6, {temp}            # {vs2_ptr} = &{vs2}")
    lines.append(f"    li      {temp}, {vs1_off:#x}")
    lines.append(f"    add     {vs1_ptr}, t6, {temp}            # {vs1_ptr} = &{vs1}")
    lines.append(f"    li      {temp}, {vd_off:#x}")
    lines.append(f"    add     {vd_ptr}, t6, {temp}             # {vd_ptr} = &{vd}")
    lines.append("")

    main_loop = new_label("vwmulu_vv_main")
    after_main = new_label("vwmulu_vv_after")

    lines.append(f"    # --- 主循环: 每块处理 {chunk_n} 个元素 ---")
    lines.append(f"    # 输入: {chunk_bytes_in}B/源 (LMUL=mf2), 输出: {chunk_bytes_out}B (LMUL=m1)")
    lines.append(f"    beqz    {chunk_count}, {after_main}")
    lines.append(f"{main_loop}:")
    _emit_vsetvl_for_chunk(lines, chunk_n, input_sew, "mf2", vl_reg, scratch_reg=temp)
    lines.append("")
    lines.append(f"    vle{input_sew}.v {vs2_vreg}, ({vs2_ptr})       # 加载 {vs2} 块 (e{input_sew}, mf2)")
    lines.append(f"    vle{input_sew}.v {vs1_vreg}, ({vs1_ptr})       # 加载 {vs1} 块 (e{input_sew}, mf2)")
    lines.append(f"    vwmulu.vv {vd_vreg}, {vs2_vreg}, {vs1_vreg}       # unsigned widening multiply")
    lines.append(f"    vse{output_sew}.v {vd_vreg}, ({vd_ptr})       # 写回 {vd} 块 (e{output_sew})")
    lines.append("")
    lines.append(f"    addi    {vs2_ptr}, {vs2_ptr}, {chunk_bytes_in}")
    lines.append(f"    addi    {vs1_ptr}, {vs1_ptr}, {chunk_bytes_in}")
    lines.append(f"    addi    {vd_ptr}, {vd_ptr}, {chunk_bytes_out}")
    lines.append(f"    addi    {chunk_count}, {chunk_count}, -1")
    lines.append(f"    bnez    {chunk_count}, {main_loop}")
    lines.append(f"{after_main}:")
    lines.append("")

    int_load = _get_int_load_unsigned(input_sew)
    int_store = _get_int_store(output_sew)
    tail_loop = new_label("vwmulu_vv_tail")
    end_label = new_label("vwmulu_vv_end")
    lines.append(f"    # --- 尾部标量回退: 剩余 {tail_count} 个元素 ---")
    lines.append(f"{tail_loop}:")
    lines.append(f"    beqz    {tail_count}, {end_label}")
    lines.append(f"    {int_load:<8} {chunk_count}, 0({vs2_ptr})           # {chunk_count} = zext({vs2}[i])")
    lines.append(f"    {int_load:<8} {temp}, 0({vs1_ptr})                  # {temp} = zext({vs1}[i])")
    lines.append(f"    mul     {chunk_count}, {chunk_count}, {temp}")
    lines.append(f"    {int_store:<8} {chunk_count}, 0({vd_ptr})            # {vd}[i] = product")
    lines.append(f"    addi    {vs2_ptr}, {vs2_ptr}, {elem_bytes_in}")
    lines.append(f"    addi    {vs1_ptr}, {vs1_ptr}, {elem_bytes_in}")
    lines.append(f"    addi    {vd_ptr}, {vd_ptr}, {elem_bytes_out}")
    lines.append(f"    addi    {tail_count}, {tail_count}, -1")
    lines.append(f"    j       {tail_loop}")
    lines.append(f"{end_label}:")

    return lines


def _build_vwmulsu_vv_lines(context) -> list[str]:
    """
    翻译 vwmulsu.vv 指令 (256-bit 模式, signed * unsigned widening multiply)

    格式: vwmulsu.vv vd, vs2, vs1
    语义: vd[i] = sext(vs2[i]) * zext(vs1[i]) (widening: e{sew} -> e{sew*2})
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
    vs1 = operands[2]

    input_sew = state.sew
    output_sew = input_sew * 2
    if input_sew not in (8, 16, 32):
        raise InstructionValidationError(insn, f"vwmulsu.vv supports input SEW=8/16/32, got SEW={input_sew}")

    chunk_n = 256 // output_sew
    chunk_bytes_in = chunk_n * (input_sew // 8)
    chunk_bytes_out = chunk_n * (output_sew // 8)
    shift_amt = {8: 4, 16: 3, 32: 2}[input_sew]
    mask = chunk_n - 1
    elem_bytes_in = input_sew // 8
    elem_bytes_out = output_sew // 8

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
    temp = temps.alloc_gpr()

    lines.append(f"# vwmulsu.vv {vd}, {vs2}, {vs1} (256-bit mode)")
    lines.append(f"# Semantic: {vd}[i] = sext({vs2}[i]) * zext({vs1}[i]), e{input_sew} -> e{output_sew}")
    lines.append("")

    _load_vl_from_csr(lines, vl_reg=vl_reg, addr_reg=chunk_count)
    lines.append(f"    srli    {chunk_count}, {vl_reg}, {shift_amt}       # {chunk_count} = vl / {chunk_n}")
    lines.append(f"    andi    {tail_count}, {vl_reg}, {mask}              # {tail_count} = vl % {chunk_n}")
    lines.append("")

    lines.append(f"    li      {temp}, {vs2_off:#x}")
    lines.append(f"    add     {vs2_ptr}, t6, {temp}            # {vs2_ptr} = &{vs2}")
    lines.append(f"    li      {temp}, {vs1_off:#x}")
    lines.append(f"    add     {vs1_ptr}, t6, {temp}            # {vs1_ptr} = &{vs1}")
    lines.append(f"    li      {temp}, {vd_off:#x}")
    lines.append(f"    add     {vd_ptr}, t6, {temp}             # {vd_ptr} = &{vd}")
    lines.append("")

    main_loop = new_label("vwmulsu_vv_main")
    after_main = new_label("vwmulsu_vv_after")

    lines.append(f"    # --- 主循环: 每块处理 {chunk_n} 个元素 ---")
    lines.append(f"    # 输入: {chunk_bytes_in}B/源 (LMUL=mf2), 输出: {chunk_bytes_out}B (LMUL=m1)")
    lines.append(f"    beqz    {chunk_count}, {after_main}")
    lines.append(f"{main_loop}:")
    _emit_vsetvl_for_chunk(lines, chunk_n, input_sew, "mf2", vl_reg, scratch_reg=temp)
    lines.append("")
    lines.append(f"    vle{input_sew}.v {vs2_vreg}, ({vs2_ptr})       # 加载 signed {vs2} 块 (e{input_sew}, mf2)")
    lines.append(f"    vle{input_sew}.v {vs1_vreg}, ({vs1_ptr})       # 加载 unsigned {vs1} 块 (e{input_sew}, mf2)")
    lines.append(f"    vwmulsu.vv {vd_vreg}, {vs2_vreg}, {vs1_vreg}      # signed * unsigned widening multiply")
    lines.append(f"    vse{output_sew}.v {vd_vreg}, ({vd_ptr})       # 写回 {vd} 块 (e{output_sew})")
    lines.append("")
    lines.append(f"    addi    {vs2_ptr}, {vs2_ptr}, {chunk_bytes_in}")
    lines.append(f"    addi    {vs1_ptr}, {vs1_ptr}, {chunk_bytes_in}")
    lines.append(f"    addi    {vd_ptr}, {vd_ptr}, {chunk_bytes_out}")
    lines.append(f"    addi    {chunk_count}, {chunk_count}, -1")
    lines.append(f"    bnez    {chunk_count}, {main_loop}")
    lines.append(f"{after_main}:")
    lines.append("")

    int_load_signed = _get_int_load_signed(input_sew)
    int_load_unsigned = _get_int_load_unsigned(input_sew)
    int_store = _get_int_store(output_sew)
    tail_loop = new_label("vwmulsu_vv_tail")
    end_label = new_label("vwmulsu_vv_end")
    lines.append(f"    # --- 尾部标量回退: 剩余 {tail_count} 个元素 ---")
    lines.append(f"{tail_loop}:")
    lines.append(f"    beqz    {tail_count}, {end_label}")
    lines.append(f"    {int_load_signed:<8} {chunk_count}, 0({vs2_ptr})      # {chunk_count} = sext({vs2}[i])")
    lines.append(f"    {int_load_unsigned:<8} {temp}, 0({vs1_ptr})           # {temp} = zext({vs1}[i])")
    lines.append(f"    mul     {chunk_count}, {chunk_count}, {temp}")
    lines.append(f"    {int_store:<8} {chunk_count}, 0({vd_ptr})            # {vd}[i] = product")
    lines.append(f"    addi    {vs2_ptr}, {vs2_ptr}, {elem_bytes_in}")
    lines.append(f"    addi    {vs1_ptr}, {vs1_ptr}, {elem_bytes_in}")
    lines.append(f"    addi    {vd_ptr}, {vd_ptr}, {elem_bytes_out}")
    lines.append(f"    addi    {tail_count}, {tail_count}, -1")
    lines.append(f"    j       {tail_loop}")
    lines.append(f"{end_label}:")

    return lines


def _build_vwmacc_vx_lines(context) -> list[str]:
    """
    翻译 vwmacc.vx 指令 (256-bit 模式, widening accumulate)

    格式: vwmacc.vx vd, rs1, vs2
    语义: vd[i] += sext(rs1) * sext(vs2[i]) (e32 -> e64)
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

    input_sew = state.sew
    output_sew = input_sew * 2
    if input_sew not in (8, 16, 32):
        raise InstructionValidationError(
            insn, f"vwmacc.vx 不支持输入 SEW={input_sew}"
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
    scalar = temps.alloc_gpr()
    temp = temps.alloc_gpr()

    if is_masked:
        mask_bit_idx = temps.alloc_gpr()
        v0_base = temps.alloc_gpr()

    lines.append(f"# vwmacc.vx {vd}, {rs1}, {vs2} (256-bit mode)")
    lines.append(f"# Semantic: {vd}[i] += sext({rs1}) * sext({vs2}[i]), e{input_sew} -> e{output_sew}")
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
    lines.append(f"    slli    {scalar}, {rs1}, {64 - input_sew}              # scalar low e{input_sew} bits")
    lines.append(f"    srai    {scalar}, {scalar}, {64 - input_sew}              # sign-extend scalar to XLEN")
    lines.append("")

    main_loop = new_label("vwmacc_vx_main")
    after_main = new_label("vwmacc_vx_after")

    lines.append(f"    # --- 主循环: 每块处理 {chunk_n} 个元素 ---")
    lines.append(f"    # 输入: {chunk_bytes_in}B (LMUL=mf2), 累加/输出: {chunk_bytes_out}B (LMUL=m1)")
    lines.append(f"    beqz    {chunk_count}, {after_main}")
    lines.append(f"{main_loop}:")
    mask_suffix = ", v0.t" if is_masked else ""
    if is_masked:
        _emit_mask_extraction_chunk(lines, input_sew, mask_bit_idx, v0_base, vl_reg, temp)

    _emit_vsetvl_for_chunk(lines, chunk_n, input_sew, "mf2", vl_reg, scratch_reg=temp)
    lines.append("")
    lines.append(f"    vle{input_sew}.v {vs2_vreg}, ({vs2_ptr})       # 加载 {vs2} 块 (e{input_sew}, mf2)")
    lines.append(f"    vle{output_sew}.v {vd_vreg}, ({vd_ptr})       # 加载 {vd} 累加块 (e{output_sew}, m1)")
    lines.append(f"    vwmacc.vx {vd_vreg}, {scalar}, {vs2_vreg}{mask_suffix}        # {vd}{mask_suffix} += sext({scalar}) * sext({vs2})")
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

    int_load_in = _get_int_load_signed(input_sew)
    int_load_out = _get_int_load_signed(output_sew)
    int_store = _get_int_store(output_sew)
    tail_loop = new_label("vwmacc_vx_tail")
    end_label = new_label("vwmacc_vx_end")
    # ========== 尾部 RVV 回退 ==========
    lines.append(f"    # --- 尾部 RVV chunk: 剩余 {tail_count} 个元素 ---")
    lines.append(f"    beqz    {tail_count}, {end_label}")
    if is_masked:
        _emit_mask_extraction_chunk(lines, input_sew, mask_bit_idx, v0_base, vl_reg, temp)
    lines.append(f"    vsetvli zero, {tail_count}, e{input_sew}, mf2, ta, ma")
    lines.append(f"    vle{input_sew}.v {vs2_vreg}, ({vs2_ptr})       # 加载 {vs2} tail (e{input_sew}, mf2)")
    lines.append(f"    vle{output_sew}.v {vd_vreg}, ({vd_ptr})       # 加载 {vd} tail (e{output_sew}, m1)")
    lines.append(f"    vwmacc.vx {vd_vreg}, {scalar}, {vs2_vreg}{mask_suffix}        # tail mac")
    lines.append(f"    vse{output_sew}.v {vd_vreg}, ({vd_ptr}){mask_suffix}       # 写回 {vd} tail (e{output_sew})")
    lines.append(f"{end_label}:")
    return lines


def _build_vwmacc_vv_lines(context) -> list[str]:
    """
    翻译 vwmacc.vv 指令 (256-bit 模式, widening accumulate)

    格式: vwmacc.vv vd, vs1, vs2
    语义: vd[i] += sext(vs1[i]) * sext(vs2[i]) (e{sew} -> e{sew*2})
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

    input_sew = state.sew
    output_sew = input_sew * 2
    if input_sew not in (8, 16, 32):
        raise InstructionValidationError(
            insn,
            "vwmacc.vv 当前仅支持输入 SEW=8/16/32 "
            f"(e8 -> e16, e16 -> e32, e32 -> e64), 实际为 SEW={state.sew}",
        )

    chunk_n = 256 // output_sew
    chunk_bytes_in = chunk_n * (input_sew // 8)
    chunk_bytes_out = chunk_n * (output_sew // 8)
    shift_amt = {8: 4, 16: 3, 32: 2}[input_sew]
    mask = chunk_n - 1
    elem_bytes_in = input_sew // 8
    elem_bytes_out = output_sew // 8

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
    vs1_ptr = temps.alloc_gpr()
    vs2_ptr = temps.alloc_gpr()
    vd_ptr = temps.alloc_gpr()
    temp = temps.alloc_gpr()
    product = temps.alloc_gpr()

    lines.append(f"# vwmacc.vv {vd}, {vs1}, {vs2} (256-bit mode)")
    lines.append(f"# Semantic: {vd}[i] += sext({vs1}[i]) * sext({vs2}[i]), e{input_sew} -> e{output_sew}")
    lines.append("")

    _load_vl_from_csr(lines, vl_reg=vl_reg, addr_reg=chunk_count)
    lines.append(f"    srli    {chunk_count}, {vl_reg}, {shift_amt}       # {chunk_count} = vl / {chunk_n}")
    lines.append(f"    andi    {tail_count}, {vl_reg}, {mask}              # {tail_count} = vl % {chunk_n}")
    lines.append("")

    lines.append(f"    li      {temp}, {vs1_off:#x}")
    lines.append(f"    add     {vs1_ptr}, t6, {temp}            # {vs1_ptr} = &{vs1}")
    lines.append(f"    li      {temp}, {vs2_off:#x}")
    lines.append(f"    add     {vs2_ptr}, t6, {temp}            # {vs2_ptr} = &{vs2}")
    lines.append(f"    li      {temp}, {vd_off:#x}")
    lines.append(f"    add     {vd_ptr}, t6, {temp}             # {vd_ptr} = &{vd}")
    lines.append("")

    main_loop = new_label("vwmacc_vv_main")
    after_main = new_label("vwmacc_vv_after")

    lines.append(f"    # --- 主循环: 每块处理 {chunk_n} 个元素 ---")
    lines.append(f"    # 输入: {chunk_bytes_in}B/源 (LMUL=mf2), 累加/输出: {chunk_bytes_out}B (LMUL=m1)")
    lines.append(f"    beqz    {chunk_count}, {after_main}")
    lines.append(f"{main_loop}:")
    _emit_vsetvl_for_chunk(lines, chunk_n, input_sew, "mf2", vl_reg, scratch_reg=temp)
    lines.append("")
    lines.append(f"    vle{input_sew}.v {vs1_vreg}, ({vs1_ptr})       # 加载 {vs1} 块 (e{input_sew}, mf2)")
    lines.append(f"    vle{input_sew}.v {vs2_vreg}, ({vs2_ptr})       # 加载 {vs2} 块 (e{input_sew}, mf2)")
    lines.append(f"    vle{output_sew}.v {vd_vreg}, ({vd_ptr})       # 加载 {vd} 累加块 (e{output_sew}, m1)")
    lines.append(f"    vwmacc.vv {vd_vreg}, {vs1_vreg}, {vs2_vreg}{mask_suffix}        # widening signed multiply-accumulate")
    lines.append(f"    vse{output_sew}.v {vd_vreg}, ({vd_ptr}){mask_suffix}       # 写回 {vd} 块 (e{output_sew})")
    lines.append("")
    lines.append(f"    addi    {vs1_ptr}, {vs1_ptr}, {chunk_bytes_in}")
    lines.append(f"    addi    {vs2_ptr}, {vs2_ptr}, {chunk_bytes_in}")
    lines.append(f"    addi    {vd_ptr}, {vd_ptr}, {chunk_bytes_out}")
    lines.append(f"    addi    {chunk_count}, {chunk_count}, -1")
    lines.append(f"    bnez    {chunk_count}, {main_loop}")
    lines.append(f"{after_main}:")
    lines.append("")

    int_load_in = _get_int_load_signed(input_sew)
    int_load_out = _get_int_load_signed(output_sew)
    int_store = _get_int_store(output_sew)
    tail_loop = new_label("vwmacc_vv_tail")
    end_label = new_label("vwmacc_vv_end")

    lines.append(f"    # --- 尾部标量回退: 剩余 {tail_count} 个元素 ---")
    lines.append(f"{tail_loop}:")
    lines.append(f"    beqz    {tail_count}, {end_label}")
    lines.append(f"    {int_load_in:<8} {product}, 0({vs1_ptr})         # {product} = sext({vs1}[i])")
    lines.append(f"    {int_load_in:<8} {temp}, 0({vs2_ptr})            # {temp} = sext({vs2}[i])")
    lines.append(f"    mul     {product}, {product}, {temp}")
    lines.append(f"    {int_load_out:<8} {temp}, 0({vd_ptr})            # {temp} = old {vd}[i]")
    lines.append(f"    add     {temp}, {temp}, {product}                # accumulate")
    lines.append(f"    {int_store:<8} {temp}, 0({vd_ptr})               # {vd}[i] = accumulated result")
    lines.append(f"    addi    {vs1_ptr}, {vs1_ptr}, {elem_bytes_in}")
    lines.append(f"    addi    {vs2_ptr}, {vs2_ptr}, {elem_bytes_in}")
    lines.append(f"    addi    {vd_ptr}, {vd_ptr}, {elem_bytes_out}")
    lines.append(f"    addi    {tail_count}, {tail_count}, -1")
    lines.append(f"    j       {tail_loop}")
    lines.append(f"{end_label}:")
    return lines


def _build_vwredsum_vs_lines(context) -> list[str]:
    """
    翻译 vwredsum.vs 指令 (256-bit 模式, widening 规约)

    格式: vwredsum.vs vd, vs2, vs1
    语义: vd[0] = vs1[0] + sum_i widen(vs2[i])
    对于 i in [0, vl), widen: e{sew} -> e{sew*2}

    策略:
    - 主循环使用 vle{sew}.v 一次加载 256-bit 块 (chunk_n 个元素)
    - 将块溢出到栈上，用标量有符号 load/add 逐元素累加到 XLEN GPR
    - 尾部标量回退处理剩余元素
    - 与 vfredusum.vs 保持一致的 chunk/tail 结构
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
    vs1 = operands[2]

    sew = state.sew
    if sew not in (8, 16, 32):
        raise ValueError(
            f"vwredsum.vs 当前仅支持 SEW=8/16/32 "
            f"(输入 e8/e16/e32, 输出 e16/e32/e64), "
            f"实际 SEW={sew}"
        )
    output_sew = sew * 2
    chunk_n = _chunk_size(sew)       # 256 / sew
    c_bytes = _chunk_bytes()         # 32
    elem_bytes_in = sew // 8
    elem_bytes_out = output_sew // 8
    shift_amt = {8: 5, 16: 4, 32: 3, 64: 2}[sew]
    mask = chunk_n - 1

    vs2_off = allocator.get_offset(vs2)
    vd_off = allocator.get_offset(vd)
    vs1_off = allocator.get_offset(vs1)

    vtemps = VRegTempAllocator(insn)
    chunk_vreg = vtemps.alloc_vreg()

    temps = context.temp_register_allocator
    vl_reg = temps.alloc_gpr()
    chunk_count = temps.alloc_gpr()
    tail_count = temps.alloc_gpr()
    vs2_ptr = temps.alloc_gpr()
    vd_ptr = temps.alloc_gpr()
    vs1_ptr = temps.alloc_gpr()
    acc_gpr = temps.alloc_gpr()
    temp = temps.alloc_gpr()

    if is_masked:
        mask_bit_idx = temps.alloc_gpr()
        v0_base = temps.alloc_gpr()

    lines.append(f"# vwredsum.vs {vd}, {vs2}, {vs1} (256-bit mode, chunked reduction)")
    lines.append(f"# Semantic: {vd}[0] = {vs1}[0] + sum_i widen({vs2}[i]), e{sew} -> e{output_sew}")
    lines.append("")

    # ========== 加载 vl 并计算块数/尾数 ==========
    if is_masked:
        _emit_mask_setup(lines, mask_bit_idx, v0_base, temp)

    _load_vl_from_csr(lines, vl_reg=vl_reg, addr_reg=chunk_count)
    lines.append(f"    srli    {chunk_count}, {vl_reg}, {shift_amt}       # {chunk_count} = vl / {chunk_n}")
    lines.append(f"    andi    {tail_count}, {vl_reg}, {mask}              # {tail_count} = vl % {chunk_n}")
    lines.append("")

    # ========== 设置指针 ==========
    lines.append(f"    li      {temp}, {vs2_off:#x}")
    lines.append(f"    add     {vs2_ptr}, t6, {temp}            # {vs2_ptr} = &{vs2}")
    lines.append(f"    li      {temp}, {vs1_off:#x}")
    lines.append(f"    add     {vs1_ptr}, t6, {temp}            # {vs1_ptr} = &{vs1}")
    lines.append("")

    # ========== 加载初始累加器值 vs1[0] ==========
    output_load = _get_int_load_signed(output_sew)
    lines.append(f"    {output_load:<8} {acc_gpr}, 0({vs1_ptr})            # {acc_gpr} = {vs1}[0] (sign-extended e{output_sew} seed)")
    lines.append("")

    # ========== 主循环: 逐块归约 vs2 ==========
    main_loop = new_label("vwredsum_main")
    after_main = new_label("vwredsum_after")

    int_load = _get_int_load_signed(sew)
    int_store = _get_int_store(output_sew)

    lines.append(f"    # --- 主循环: 逐块归约 {vs2}, 每块 {chunk_n} 个元素 ---")
    lines.append(f"    beqz    {chunk_count}, {after_main}")
    lines.append(f"{main_loop}:")
    _emit_vsetvl_for_chunk(lines, chunk_n, sew, "m1", vl_reg, scratch_reg=temp)
    lines.append("")
    lines.append(f"    vle{sew}.v {chunk_vreg}, ({vs2_ptr})         # 加载 {vs2} 块 -> {chunk_vreg}")
    lines.append(f"    addi    sp, sp, -{c_bytes}              # CHIMERA_INTERNAL_STACK")
    lines.append(f"    vse{sew}.v {chunk_vreg}, (sp)              # CHIMERA_INTERNAL_STACK spill chunk")
    lines.append("")

    # 展开 8 个元素的标量累加
    for i in range(chunk_n):
        offset = i * elem_bytes_in
        if is_masked:
            skip_label = new_label(f"red_skip_{i}")
            lines.append(f"    addi    {temp}, {mask_bit_idx}, {i}               # global mask bit for element {i}")
            lines.append(f"    srli    {vd_ptr}, {temp}, 3                       # mask byte offset")
            lines.append(f"    add     {vd_ptr}, {v0_base}, {vd_ptr}             # mask byte address")
            lines.append(f"    lbu     {vd_ptr}, 0({vd_ptr})                     # mask byte")
            lines.append(f"    andi    {temp}, {temp}, 7                         # mask bit offset")
            lines.append(f"    srl     {vd_ptr}, {vd_ptr}, {temp}                # selected bit to LSB")
            lines.append(f"    andi    {temp}, {vd_ptr}, 1                       # isolate mask bit")
            lines.append(f"    beqz    {temp}, {skip_label}")

        lines.append(f"    {int_load:<8} {temp}, {offset}(sp)              # CHIMERA_INTERNAL_STACK {temp} = sext(element[{i}])")
        lines.append(f"    add     {acc_gpr}, {acc_gpr}, {temp}            # {acc_gpr} += sext(element[{i}])")

        if is_masked:
            lines.append(f"{skip_label}:")
    lines.append(f"    addi    sp, sp, {c_bytes}               # CHIMERA_INTERNAL_STACK release")
    lines.append(f"    addi    {vs2_ptr}, {vs2_ptr}, {c_bytes}    # 前进 vs2 指针")
    if is_masked:
        lines.append(f"    addi    {mask_bit_idx}, {mask_bit_idx}, {chunk_n}")
    lines.append(f"    addi    {chunk_count}, {chunk_count}, -1")
    lines.append(f"    bnez    {chunk_count}, {main_loop}")
    lines.append(f"{after_main}:")
    lines.append("")

    # ========== 尾部标量回退 ==========
    lines.append(f"    # --- 尾部标量回退: 剩余 {tail_count} 个元素 ---")
    tail_loop = new_label("vwredsum_tail")
    tail_end = new_label("vwredsum_tail_end")

    lines.append(f"{tail_loop}:")
    lines.append(f"    beqz    {tail_count}, {tail_end}")
    if is_masked:
        skip_tail = new_label("red_skip_tail")
        lines.append(f"    srli    {vd_ptr}, {mask_bit_idx}, 3                # mask byte offset")
        lines.append(f"    add     {vd_ptr}, {v0_base}, {vd_ptr}              # mask byte address")
        lines.append(f"    lbu     {vd_ptr}, 0({vd_ptr})                      # load mask byte")
        lines.append(f"    andi    {temp}, {mask_bit_idx}, 7                  # mask bit offset")
        lines.append(f"    srl     {vd_ptr}, {vd_ptr}, {temp}                 # selected bit to LSB")
        lines.append(f"    andi    {temp}, {vd_ptr}, 1                        # isolate bit")
        lines.append(f"    beqz    {temp}, {skip_tail}                        # skip if 0")
    lines.append(f"    {int_load:<8} {temp}, 0({vs2_ptr})            # {temp} = sext({vs2}[i])")
    lines.append(f"    add     {acc_gpr}, {acc_gpr}, {temp}            # {acc_gpr} += sext({vs2}[i])")
    if is_masked:
        lines.append(f"{skip_tail}:")
        lines.append(f"    addi    {mask_bit_idx}, {mask_bit_idx}, 1")
    lines.append(f"    addi    {vs2_ptr}, {vs2_ptr}, {elem_bytes_in}")
    lines.append(f"    addi    {tail_count}, {tail_count}, -1")
    lines.append(f"    j       {tail_loop}")
    lines.append(f"{tail_end}:")
    lines.append("")

    # ========== 写回结果 ==========
    lines.append(f"    li      {temp}, {vd_off:#x}")
    lines.append(f"    add     {vd_ptr}, t6, {temp}             # {vd_ptr} = &{vd}")
    lines.append(f"    {int_store:<8} {acc_gpr}, 0({vd_ptr})            # {vd}[0] = {acc_gpr} (sum, e{output_sew})")

    return lines
