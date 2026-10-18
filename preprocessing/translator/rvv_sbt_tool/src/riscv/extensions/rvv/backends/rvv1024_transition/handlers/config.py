"""RVV256→RVV1024 过渡路径的源端配置指令翻译。

本模块处理的不是目标 RVV1024 硬件的 ``vset*``，而是迁移前
RVV256 客体所观察到的配置状态：

* 源端 VLENB 固定为 32（即 VLEN=256 bit）；
* ``vl``、``vtype`` 仍保存在既有 ``simulated_cpu_state`` 的 CSR 区；
* 后续向量 handler 会依据这些源端 CSR 把紧凑的 32B 物理寄存器状态
  Pack 到 RVV1024 临时寄存器中执行。

因此本模块绝不能执行一个“目标机 VLEN=128B”的 ``vsetvli`` 来计算客体
``vl``。它只生成普通 RV64 标量代码，严格以源端 32B VLEN 计算 VLMAX。
"""

from __future__ import annotations

from typing import List

from riscv.extensions.rvv.analysis.model import LEGAL_LMULS
from riscv.extensions.rvv.translation.contracts import InstructionValidationError
from riscv.extensions.rvv.runtime.layout import CSR_OFFSETS
from riscv.extensions.rvv.runtime.access import emit_clear_vstart
from riscv.extensions.rvv.analysis.config import StateTracker
from riscv.extensions.rvv.translation.vtype_decode import emit_vlmax_from_vtype

from riscv.extensions.rvv.backends.rvv1024_transition.operands import _validate_source_profile


# 本后端一期的输入合同。目标硬件 VLENB=128 的检查由入口 guard 负责；
# 这里仅定义客体可见的源端 VLENB，避免误把目标机宽度混入源语义计算。
from riscv.extensions.rvv.backends.rvv1024_transition.state_view import SOURCE_VLENB

def _snapshot_state(state: StateTracker) -> tuple:
    """保存静态状态，保证拒绝配置时不会污染后续指令的翻译判断。"""
    return (
        state.sew,
        state.lmul,
        state.vl,
        state.vtype,
        state.vta,
        state.vma,
        state.config_str,
    )


def _restore_state(state: StateTracker, snapshot: tuple) -> None:
    """恢复 ``_snapshot_state`` 保存的翻译期静态状态。"""
    (
        state.sew,
        state.lmul,
        state.vl,
        state.vtype,
        state.vta,
        state.vma,
        state.config_str,
    ) = snapshot





def _emit_store_csr(lines: List[str], addr_reg: str, value_reg: str, offset: int, name: str) -> None:
    """把 ``value_reg`` 写入状态块中的一个固定 CSR 槽位。"""
    lines.append(f"    li      {addr_reg}, {offset:#x}")
    lines.append(f"    add     {addr_reg}, t6, {addr_reg}")
    lines.append(f"    sd      {value_reg}, 0({addr_reg})              # CSR.{name}")


def _emit_load_csr(lines: List[str], addr_reg: str, value_reg: str, offset: int, name: str) -> None:
    """从状态块读取一个固定 CSR 槽位。"""
    lines.append(f"    li      {addr_reg}, {offset:#x}")
    lines.append(f"    add     {addr_reg}, t6, {addr_reg}")
    lines.append(f"    ld      {value_reg}, 0({addr_reg})              # CSR.{name}")


def _build_vsetvli_lines(context) -> list[str]:
    """翻译源 RVV256 ``vsetvli``，并仅更新模拟 CSR。

    语义遵循 RVV 规范的三种 AVL 形式：

    * ``rs1 != x0``：``vl = min(rs1, VLMAX)``；
    * ``rs1 == x0, rd != x0``：``vl = VLMAX``；
    * ``rs1 == x0, rd == x0``：保持 VL，且只有新旧 VLMAX 相同才合法。

    ``state`` 必须由新入口以 ``StateTracker(vlenb=32)`` 构造。实际硬件
    RVV1024 的临时配置由后续算术/访存 handler 在 Pack 后另行设置。
    """
    insn = context.instruction
    state = context.state
    new_label = context.new_label
    operands = insn.operands
    if len(operands) < 3:
        raise InstructionValidationError(
            insn, f"invalid operands for vsetvli: {insn.op_str}"
        )

    _validate_source_profile(state, insn)

    rd = str(operands[0]).strip()
    rs1 = str(operands[1]).strip()
    rd_is_zero = rd in ("zero", "x0")
    rs1_is_zero = rs1 in ("zero", "x0")

    snapshot = _snapshot_state(state)
    state.update(insn)
    try:
        _validate_source_profile(state, insn)
    except InstructionValidationError:
        _restore_state(state, snapshot)
        raise

    vlmax = state.get_vlmax()
    vtype_value = state.get_vtype_value()
    lines: List[str] = [
        f"    # 源 RVV256 vsetvli: {insn.op_str} (VLMAX={vlmax})",
    ]

    try:
        temps = context.temp_register_allocator
        value_reg = temps.alloc_gpr()
        result_reg = temps.alloc_gpr()
        addr_reg = temps.alloc_gpr()

        # x0,x0 是唯一需要读取旧 vtype 的情况。此时 VLMAX 由运行时旧值
        # 推导，不能以翻译期静态状态替代，否则跨 CFG 入口会误判。
        if rs1_is_zero and rd_is_zero:
            old_vtype = temps.alloc_gpr()
            old_vlmax = temps.alloc_gpr()
            sew_reg = temps.alloc_gpr()
            base_reg = temps.alloc_gpr()
            lmul_reg = temps.alloc_gpr()
            tmp_reg = temps.alloc_gpr()
            invalid_label = new_label("vsetvli_x0_x0_invalid_vlmax")
            check_done_label = new_label("vsetvli_x0_x0_check_done")

            lines.append("    # x0,x0：新旧 VLMAX 必须相同，VL 才可保持")
            _emit_load_csr(lines, addr_reg, old_vtype, CSR_OFFSETS["vtype"], "vtype(旧)")
            emit_vlmax_from_vtype(lines, source_vlenb=SOURCE_VLENB, vtype_reg=old_vtype, out_reg=old_vlmax, sew_reg=sew_reg, base_reg=base_reg, lmul_reg=lmul_reg, tmp_reg=tmp_reg, invalid_label=invalid_label, new_label=new_label, prefix="vsetvli_x0_x0_old_vlmax")
            lines.append(f"    li      {tmp_reg}, {vlmax}              # 新 VLMAX")
            lines.append(f"    bne     {old_vlmax}, {tmp_reg}, {invalid_label}")
            lines.append(f"    j       {check_done_label}")
            lines.append(f"{invalid_label}:")
            lines.append("    ebreak                              # 保留的 x0,x0 配置组合")
            lines.append(f"{check_done_label}:")

        # 每种合法 AVL 形式都更新 vtype；保留源端 ta/ma 位，不能把目标临时
        # 执行采用的 tu,mu 策略写回为客体可见的 vtype。
        emit_clear_vstart(lines, addr_reg)
        lines.append(f"    li      {value_reg}, {vtype_value:#x}       # 源 CSR.vtype")
        _emit_store_csr(lines, addr_reg, value_reg, CSR_OFFSETS["vtype"], "vtype")

        if rs1_is_zero and rd_is_zero:
            lines.append("    # rs1=x0 且 rd=x0：CSR.vl 保持原值")
        elif rs1_is_zero:
            lines.append(f"    li      {result_reg}, {vlmax}           # VL = VLMAX")
            _emit_store_csr(lines, addr_reg, result_reg, CSR_OFFSETS["vl"], "vl")
            lines.append(f"    mv      {rd}, {result_reg}              # rd = VL")
        else:
            skip_label = new_label("vsetvli_min_done")
            lines.append(f"    li      {value_reg}, {vlmax}            # VLMAX")
            lines.append(f"    mv      {result_reg}, {value_reg}")
            lines.append(f"    bltu    {value_reg}, {rs1}, {skip_label}")
            lines.append(f"    mv      {result_reg}, {rs1}")
            lines.append(f"{skip_label}:")
            _emit_store_csr(lines, addr_reg, result_reg, CSR_OFFSETS["vl"], "vl")
            if not rd_is_zero:
                lines.append(f"    mv      {rd}, {result_reg}              # rd = VL")
    except ValueError as error:
        _restore_state(state, snapshot)
        raise InstructionValidationError(
            insn, f"vsetvli 临时寄存器不足: {error}: {insn.op_str}"
        ) from error

    lines.append("")
    return lines


def _build_vsetivli_lines(context) -> list[str]:
    """翻译源 RVV256 ``vsetivli``，以 5-bit AVL 立即数设置模拟 ``vl``。"""
    insn = context.instruction
    state = context.state
    new_label = context.new_label
    operands = insn.operands
    if len(operands) < 3:
        raise InstructionValidationError(
            insn, f"invalid operands for vsetivli: {insn.op_str}"
        )

    _validate_source_profile(state, insn)

    rd = str(operands[0]).strip()
    uimm_text = str(operands[1]).strip()
    rd_is_zero = rd in ("zero", "x0")
    try:
        uimm = int(uimm_text, 16) if uimm_text.lower().startswith("0x") else int(uimm_text)
    except ValueError as error:
        raise InstructionValidationError(
            insn, f"invalid uimm for vsetivli: {insn.op_str}"
        ) from error
    if not 0 <= uimm <= 31:
        raise InstructionValidationError(
            insn, f"vsetivli uimm out of range (0..31): {insn.op_str}"
        )

    snapshot = _snapshot_state(state)
    state.update(insn)
    try:
        _validate_source_profile(state, insn)
    except InstructionValidationError:
        _restore_state(state, snapshot)
        raise

    vlmax = state.get_vlmax()
    vtype_value = state.get_vtype_value()
    lines: List[str] = [
        f"    # 源 RVV256 vsetivli: {insn.op_str} (uimm={uimm}, VLMAX={vlmax})",
    ]

    try:
        temps = context.temp_register_allocator
        value_reg = temps.alloc_gpr()
        imm_reg = temps.alloc_gpr()
        result_reg = temps.alloc_gpr()
        addr_reg = temps.alloc_gpr()

        emit_clear_vstart(lines, addr_reg)
        lines.append(f"    li      {value_reg}, {vtype_value:#x}       # 源 CSR.vtype")
        _emit_store_csr(lines, addr_reg, value_reg, CSR_OFFSETS["vtype"], "vtype")

        lines.append(f"    li      {value_reg}, {vlmax}            # VLMAX")
        lines.append(f"    li      {imm_reg}, {uimm}               # AVL 立即数")
        lines.append(f"    mv      {result_reg}, {value_reg}")
        skip_label = new_label("vsetivli_min_done")
        lines.append(f"    bltu    {value_reg}, {imm_reg}, {skip_label}")
        lines.append(f"    mv      {result_reg}, {imm_reg}")
        lines.append(f"{skip_label}:")
        _emit_store_csr(lines, addr_reg, result_reg, CSR_OFFSETS["vl"], "vl")
        if not rd_is_zero:
            lines.append(f"    mv      {rd}, {result_reg}              # rd = VL")
    except ValueError as error:
        _restore_state(state, snapshot)
        raise InstructionValidationError(
            insn, f"vsetivli 临时寄存器不足: {error}: {insn.op_str}"
        ) from error

    lines.append("")
    return lines


def _build_vsetvl_lines(context) -> list[str]:
    """翻译动态 vtype 的源 RVV256 ``vsetvl``。

    ``rs2`` 的 vtype 仅在运行时可知，因而此处必须由标量代码提取
    ``vsew``/``vlmul`` 并以 32B 源 VLEN 计算 VLMAX。非法 vtype 按架构
    语义在模拟状态中写入 ``vill`` 和 ``vl=0``，并向非零 ``rd`` 返回零。
    """
    insn = context.instruction
    state = context.state
    new_label = context.new_label
    operands = insn.operands
    if len(operands) < 3:
        raise InstructionValidationError(
            insn, f"invalid operands for vsetvl: {insn.op_str}"
        )

    _validate_source_profile(state, insn)

    rd = str(operands[0]).strip()
    rs1 = str(operands[1]).strip()
    rs2 = str(operands[2]).strip()
    rd_is_zero = rd in ("zero", "x0")
    rs1_is_zero = rs1 in ("zero", "x0")
    keep_vl = rd_is_zero and rs1_is_zero

    snapshot = _snapshot_state(state)
    state.update(insn)
    lines: List[str] = [
        f"    # 源 RVV256 vsetvl: {insn.op_str} (运行时 vtype={rs2})",
    ]

    try:
        temps = context.temp_register_allocator
        sew_or_vl = temps.alloc_gpr()
        addr_reg = temps.alloc_gpr()
        lmul_reg = temps.alloc_gpr()
        vlmax_reg = temps.alloc_gpr()
        tmp_reg = temps.alloc_gpr()
        old_vtype = temps.alloc_gpr() if keep_vl else None
        old_vlmax = temps.alloc_gpr() if keep_vl else None

        invalid_label = new_label("vsetvl_invalid_vtype")
        done_label = new_label("vsetvl_done")

        # x0,x0 形式要求旧、新 vtype 的 VLMAX 相同；先读取旧 vtype，避免
        # 后续提前写入 rs2 而破坏检查对象。
        if keep_vl:
            assert old_vtype is not None and old_vlmax is not None
            _emit_load_csr(lines, addr_reg, old_vtype, CSR_OFFSETS["vtype"], "vtype(旧)")
            emit_vlmax_from_vtype(lines, source_vlenb=SOURCE_VLENB, vtype_reg=old_vtype, out_reg=old_vlmax, sew_reg=sew_or_vl, base_reg=addr_reg, lmul_reg=lmul_reg, tmp_reg=tmp_reg, invalid_label=invalid_label, new_label=new_label, prefix="vsetvl_old_vlmax")

        lines.append(f"    bltz    {rs2}, {invalid_label}              # 输入 vtype 的 vill 置位")
        # 保留高位同样属于非法 vtype。不能只读取低 8 位再继续计算 VLMAX，
        # 因为那会让损坏的 rs2 值以“看似 e8,m1”的方式泄漏进迁移状态。
        lines.append(f"    srli    {tmp_reg}, {rs2}, 8")
        lines.append(f"    bnez    {tmp_reg}, {invalid_label}          # 输入 vtype 保留位非零")
        lines.append(f"    srli    {sew_or_vl}, {rs2}, 3")
        lines.append(f"    andi    {sew_or_vl}, {sew_or_vl}, 7        # vsew")
        lines.append(f"    li      {tmp_reg}, 3")
        lines.append(f"    bltu    {tmp_reg}, {sew_or_vl}, {invalid_label}  # e128+ 暂不支持")
        lines.append(f"    andi    {lmul_reg}, {rs2}, 7               # vlmul")
        lines.append(f"    li      {tmp_reg}, 4")
        lines.append(f"    beq     {lmul_reg}, {tmp_reg}, {invalid_label}  # 保留 vlmul")

        # vtype 是客体可见的 CSR，保留 rs2 中原始 ta/ma 位；目标临时 vtype
        # 由具体向量 handler 另行设置为 tu,mu，不能污染这里的值。
        _emit_store_csr(lines, addr_reg, rs2, CSR_OFFSETS["vtype"], "vtype")

        lines.append(f"    li      {addr_reg}, {SOURCE_VLENB}")
        lines.append(
            f"    srl     {addr_reg}, {addr_reg}, {sew_or_vl}  # RVV256 m1 VLMAX 基数"
        )
        frac_label = new_label("vsetvl_fractional_lmul")
        vlmax_done_label = new_label("vsetvl_vlmax_done")
        lines.append(f"    andi    {tmp_reg}, {lmul_reg}, 4")
        lines.append(f"    bnez    {tmp_reg}, {frac_label}")
        lines.append(f"    sll     {vlmax_reg}, {addr_reg}, {lmul_reg}")
        lines.append(f"    j       {vlmax_done_label}")
        lines.append(f"{frac_label}:")
        lines.append(f"    li      {tmp_reg}, 8")
        lines.append(f"    sub     {tmp_reg}, {tmp_reg}, {lmul_reg}")
        lines.append(f"    srl     {vlmax_reg}, {addr_reg}, {tmp_reg}")
        lines.append(f"{vlmax_done_label}:")

        if keep_vl:
            assert old_vlmax is not None
            lines.append(f"    bne     {old_vlmax}, {vlmax_reg}, {invalid_label}")

        if keep_vl:
            _emit_load_csr(lines, addr_reg, sew_or_vl, CSR_OFFSETS["vl"], "vl(保持)")
        elif rs1_is_zero:
            lines.append(f"    mv      {sew_or_vl}, {vlmax_reg}            # VL = VLMAX")
        else:
            min_done_label = new_label("vsetvl_min_done")
            lines.append(f"    mv      {sew_or_vl}, {vlmax_reg}")
            lines.append(f"    bltu    {vlmax_reg}, {rs1}, {min_done_label}")
            lines.append(f"    mv      {sew_or_vl}, {rs1}")
            lines.append(f"{min_done_label}:")

        if not keep_vl:
            _emit_store_csr(lines, addr_reg, sew_or_vl, CSR_OFFSETS["vl"], "vl")
        emit_clear_vstart(lines, addr_reg)
        if not rd_is_zero:
            lines.append(f"    mv      {rd}, {sew_or_vl}              # rd = VL")

        lines.append(f"    j       {done_label}")
        lines.append(f"{invalid_label}:")
        lines.append(f"    li      {tmp_reg}, 1")
        lines.append(f"    slli    {tmp_reg}, {tmp_reg}, 63         # RV64 vill")
        _emit_store_csr(lines, addr_reg, tmp_reg, CSR_OFFSETS["vtype"], "vtype(vill)")
        lines.append(f"    li      {sew_or_vl}, 0")
        _emit_store_csr(lines, addr_reg, sew_or_vl, CSR_OFFSETS["vl"], "vl(非法 vtype)")
        emit_clear_vstart(lines, addr_reg)
        if not rd_is_zero:
            lines.append(f"    mv      {rd}, {sew_or_vl}")
        lines.append(f"{done_label}:")
    except ValueError as error:
        _restore_state(state, snapshot)
        raise InstructionValidationError(
            insn, f"vsetvl 临时寄存器不足: {error}: {insn.op_str}"
        ) from error

    return lines
