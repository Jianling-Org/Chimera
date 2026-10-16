"""RVV256→RVV1024 过渡路径的向量 CSR handler。

迁移入口保存的是源 RVV256 的架构状态，因而 ``csrr`` 必须返回客体可见
的 CSR，而不是当前 RVV1024 硬件临时寄存器的 CSR。特别地：

* ``vlenb`` 固定返回 32；
* ``vstart``、``vl``、``vtype`` 从既有状态块 CSR 区读取；
* ``vxrm`` 和 ``vxsat`` 从 ``vcsr`` 的定义字段拆出，不能信任状态块中
  为旧 ABI 保留的独立槽位是否已被在线运行时初始化；
* 对可写的 ``vstart``、``vxsat``、``vxrm`` 与 ``vcsr``，CSR 写/读改写
  都只修改 source state，不把 RVV1024 临时硬件 CSR 暴露给客体；
* ``vl``、``vtype``、``vlenb`` 是只读观察值。若 RMW form 的 rs1/zimm 为
  零而不会发生写入，则可安全降为读取；其余写尝试明确拒绝。
"""

from __future__ import annotations


from riscv.extensions.rvv.translation.contracts import InstructionValidationError
from riscv.extensions.rvv.runtime.layout import CSR_OFFSETS

from riscv.extensions.rvv.backends.rvv1024_transition.operands import (
    SOURCE_VLENB,
    _VECTOR_CSR_ALIASES,
    _VECTOR_CSR_WRITE_OR_RMW_OPCODES,
    _VECTOR_CSR_IMMEDIATE_OPCODES,
    _WRITABLE_VECTOR_CSRS,
    _CSR_VALUE_OPERAND_INDEX_BY_OPCODE,
    VECTOR_CSR_OFFSETS,
    normalize_csr_operand,
    vector_csr_from_instruction,
    _is_zero_gpr,
    _parse_zimm,
    _csr_operation_kind,
    _is_rmw_opcode,
)


def _emit_state_load(lines: list[str], addr_reg: str, result_reg: str, offset: int, name: str) -> None:
    """读取状态块中的 CSR；``t6`` 始终是 wrapper 在块内建立的状态基址。"""
    lines.append(f"    li      {addr_reg}, {offset:#x}")
    lines.append(f"    add     {addr_reg}, t6, {addr_reg}")
    lines.append(f"    ld      {result_reg}, 0({addr_reg})              # 源 CSR.{name}")


def _build_csrr_lines(context) -> list[str]:
    """将 ``csrr rd, <vector-csr>`` 降低为 RVV256 源状态读取。

    读取没有副作用，因此 ``rd=x0`` 时可以不生成状态访问；这既符合架构
    语义，也避免在本来不需要的情况下占用临时寄存器。非向量 CSR 不由本
    handler 模拟，保持原指令让标量路径处理。
    """
    insn = context.instruction
    if len(insn.operands) < 2:
        raise InstructionValidationError(
            insn, f"malformed csrr instruction: {insn.op_str}"
        )

    rd = str(insn.operands[0]).strip()
    csr = normalize_csr_operand(insn.operands[1])
    if csr not in VECTOR_CSR_OFFSETS:
        operands = ", ".join(str(operand) for operand in insn.operands)
        return [f"    {insn.opcode:<8} {operands}"]

    csr_name = _VECTOR_CSR_ALIASES.get(csr, csr)
    if rd in ("zero", "x0"):
        return [f"    # csrr {rd}, {csr_name}: 读取结果丢弃，无副作用"]

    # vlenb 是源端架构常量，不应从状态块读取：状态块的字段只是入口 guard
    # 验证的输入，若它被破坏仍不能把目标 VLENB 或错误值暴露给客体。
    if csr_name == "vlenb":
        return [
            f"    # csrr {rd}, vlenb：返回源 RVV256 的架构常量",
            f"    li      {rd}, {SOURCE_VLENB}",
        ]

    try:
        addr_reg = context.temp_register_allocator.alloc_gpr()
    except ValueError as error:
        raise InstructionValidationError(
            insn, f"csrr 临时寄存器不足: {error}: {insn.op_str}"
        ) from error

    lines: list[str] = [f"    # csrr {rd}, {csr_name}：读取源 RVV256 CSR"]

    if csr_name == "vxsat":
        # RVV vcsr[0] 为 vxsat。在线保存路径目前不保证独立 vxsat 槽位
        # 已初始化，因此只能以 vcsr 作为权威来源。
        _emit_state_load(lines, addr_reg, rd, CSR_OFFSETS["vcsr"], "vcsr")
        lines.append(f"    andi    {rd}, {rd}, 1                 # vxsat = vcsr[0]")
        return lines

    if csr_name == "vxrm":
        # RVV vcsr[2:1] 为 vxrm；先右移再掩码，避免把 vxsat 或保留位泄漏到
        # 客体可观察结果中。
        _emit_state_load(lines, addr_reg, rd, CSR_OFFSETS["vcsr"], "vcsr")
        lines.append(f"    srli    {rd}, {rd}, 1                 # 取 vcsr[2:1]")
        lines.append(f"    andi    {rd}, {rd}, 3                 # vxrm")
        return lines

    if csr_name == "vcsr":
        # vcsr 只有 [2:0] 是定义字段；掩码保证状态快照中的保留位不会被误当成
        # 客体 CSR 的可见值。
        _emit_state_load(lines, addr_reg, rd, CSR_OFFSETS["vcsr"], "vcsr")
        lines.append(f"    andi    {rd}, {rd}, 7                 # vcsr 定义字段")
        return lines

    # vstart / vl / vtype 都按完整 XLEN 值读取。尤其 vstart 不能像现有
    # RVV256->RVV1024 首期的入口 guard 那样被偷偷清零；guard 负责拒绝非零
    # 迁移，CSRR 的架构语义仍必须如实返回状态中捕获到的值。
    offset = VECTOR_CSR_OFFSETS[csr]
    _emit_state_load(lines, addr_reg, rd, offset, csr_name)
    return lines


def _emit_load_visible_csr(
    lines: list[str],
    *,
    csr_name: str,
    addr_reg: str,
    result_reg: str,
) -> None:
    """读取零掩码 CSRRS/CSRRC 访问的只读 vl/vtype/vlenb。"""
    if csr_name == "vlenb":
        lines.append(f"    li      {result_reg}, {SOURCE_VLENB}       # 源 CSR.vlenb")
        return
    _emit_state_load(lines, addr_reg, result_reg, CSR_OFFSETS[csr_name], csr_name)


def _emit_load_writable_csr_raw(
    lines: list[str],
    *,
    csr_name: str,
    addr_reg: str,
    raw_reg: str,
    old_reg: str,
) -> None:
    """读取可写 CSR 的存储值与客体可见旧值。

    对 vxrm/vxsat，实际存储位置是统一的 ``state.vcsr``；``raw_reg`` 保留
    归一化后的完整 3-bit vcsr，``old_reg`` 则是 CSR 指令应返回给 rd 的字段。
    """
    storage_name = "vcsr" if csr_name in {"vxsat", "vxrm", "vcsr"} else csr_name
    _emit_state_load(lines, addr_reg, raw_reg, CSR_OFFSETS[storage_name], storage_name)
    if storage_name == "vcsr":
        # state.vcsr 的保留位不属于 RVV 客体可见状态。写路径顺便规范化，避免
        # 损坏的保留位日后被重新写入目标硬件 CSR。
        lines.append(f"    andi    {raw_reg}, {raw_reg}, 7                 # vcsr 定义字段")
    if csr_name == "vxsat":
        lines.append(f"    andi    {old_reg}, {raw_reg}, 1                 # 旧 vxsat")
    elif csr_name == "vxrm":
        lines.append(f"    srli    {old_reg}, {raw_reg}, 1                 # 旧 vxrm")
        lines.append(f"    andi    {old_reg}, {old_reg}, 3")
    else:
        lines.append(f"    mv      {old_reg}, {raw_reg}                    # 旧 {csr_name}")


def _emit_store_writable_csr(
    lines: list[str],
    *,
    csr_name: str,
    addr_reg: str,
    raw_reg: str,
    new_reg: str,
) -> None:
    """将新客体值写回可写 CSR 的 source-state 表示。"""
    if csr_name == "vstart":
        lines.append(f"    sd      {new_reg}, 0({addr_reg})              # 源 CSR.vstart")
        return
    if csr_name == "vcsr":
        lines.append(f"    andi    {new_reg}, {new_reg}, 7                 # vcsr 定义字段")
        lines.append(f"    sd      {new_reg}, 0({addr_reg})              # 源 CSR.vcsr")
        return
    if csr_name == "vxsat":
        lines.append(f"    andi    {new_reg}, {new_reg}, 1                 # 新 vxsat")
        lines.append(f"    andi    {raw_reg}, {raw_reg}, -2                # 清除 vcsr[0]")
        lines.append(f"    or      {raw_reg}, {raw_reg}, {new_reg}")
        lines.append(f"    sd      {raw_reg}, 0({addr_reg})              # 源 CSR.vcsr")
        return
    if csr_name == "vxrm":
        lines.append(f"    andi    {new_reg}, {new_reg}, 3                 # 新 vxrm")
        lines.append(f"    slli    {new_reg}, {new_reg}, 1")
        lines.append(f"    andi    {raw_reg}, {raw_reg}, -7                # 清除 vcsr[2:1]")
        lines.append(f"    or      {raw_reg}, {raw_reg}, {new_reg}")
        lines.append(f"    sd      {raw_reg}, 0({addr_reg})              # 源 CSR.vcsr")
        return
    raise ValueError(f"不可写 vector CSR: {csr_name}")


def _emit_value_operand(
    lines: list[str],
    *,
    insn,
    value_reg: str,
) -> bool:
    """准备 CSR 写源并返回该写源是否为零。

    对寄存器 form，源寄存器保持只读；对 immediate form，先 materialize 到
    临时寄存器。这样同一后续合并逻辑可覆盖 CSRWI/CSRRSI/CSRRCI。
    """
    index = _CSR_VALUE_OPERAND_INDEX_BY_OPCODE.get(insn.opcode)
    if index is None or len(insn.operands) <= index:
        raise InstructionValidationError(
            insn, f"malformed vector CSR 写指令: {insn.op_str}"
        )
    source = insn.operands[index]
    if insn.opcode in _VECTOR_CSR_IMMEDIATE_OPCODES:
        try:
            value = _parse_zimm(source)
        except ValueError as exc:
            raise InstructionValidationError(
                insn, f"{exc}: {insn.op_str}"
            ) from exc
        lines.append(f"    li      {value_reg}, {value}                 # CSR zimm")
        return value == 0
    if _is_zero_gpr(source):
        lines.append(f"    mv      {value_reg}, zero                    # CSR rs1=x0")
        return True
    lines.append(f"    mv      {value_reg}, {source}                 # CSR rs1")
    return False


def _build_vector_csr_write_lines(context) -> list[str]:
    """模拟可写 vector CSR 的写和读改写 form。

    本实现只接受 ABI 能完整表达的 vstart/vxsat/vxrm/vcsr。对 vxsat/vxrm
    的任何操作都合并到 state.vcsr；不能读写历史独立槽位，也不能原样发射到
    RVV1024 硬件。只读 CSR 的 CSRRS/CSRRC 零源 form 不写状态，按读旧值处理。
    """
    insn = context.instruction
    opcode = insn.opcode.lower()
    csr_name = vector_csr_from_instruction(insn)
    if opcode not in _VECTOR_CSR_WRITE_OR_RMW_OPCODES or csr_name is None:
        raise InstructionValidationError(
            insn, f"malformed vector CSR 写/读改写: {insn.op_str}"
        )
    try:
        operation = _csr_operation_kind(opcode)
    except ValueError as exc:
        raise InstructionValidationError(insn, f"{exc}: {insn.op_str}") from exc

    is_rmw = _is_rmw_opcode(opcode)
    rd = str(insn.operands[0]).strip() if is_rmw and insn.operands else "zero"
    rd_is_zero = _is_zero_gpr(rd)
    try:
        temps = context.temp_register_allocator
        addr_reg = temps.alloc_gpr()
        raw_reg = temps.alloc_gpr()
        old_reg = temps.alloc_gpr()
        value_reg = temps.alloc_gpr()
        new_reg = temps.alloc_gpr()
    except ValueError as error:
        raise InstructionValidationError(
            insn, f"vector CSR 临时寄存器不足: {error}: {insn.op_str}"
        ) from error

    lines: list[str] = [
        f"    # 模拟源 RVV256 CSR {opcode}: {insn.op_str}",
    ]
    source_is_zero = _emit_value_operand(
        lines, insn=insn, value_reg=value_reg
    )

    # CSRRS/CSRRC 的零 rs1/zimm 只读旧值；这一特例对只读 vl/vtype/vlenb
    # 是合法的，不能与真正的写尝试混为一谈。
    no_state_write = operation in {"set", "clear"} and source_is_zero
    if csr_name not in _WRITABLE_VECTOR_CSRS:
        if not no_state_write:
            raise InstructionValidationError(
                insn,
                "RVV256->RVV1024 不允许写只读 vector CSR "
                f"{csr_name}: {insn.op_str}",
            )
        if not rd_is_zero:
            _emit_load_visible_csr(
                lines, csr_name=csr_name, addr_reg=addr_reg, result_reg=rd
            )
        else:
            lines.append(f"    # {opcode} 对只读 {csr_name} 的零掩码：无状态写回")
        return lines

    _emit_load_writable_csr_raw(
        lines,
        csr_name=csr_name,
        addr_reg=addr_reg,
        raw_reg=raw_reg,
        old_reg=old_reg,
    )

    if not no_state_write:
        if operation == "write":
            lines.append(f"    mv      {new_reg}, {value_reg}                 # CSR 写入值")
        elif operation == "set":
            lines.append(f"    or      {new_reg}, {old_reg}, {value_reg}     # CSRRS")
        else:
            lines.append(f"    not     {value_reg}, {value_reg}")
            lines.append(f"    and     {new_reg}, {old_reg}, {value_reg}     # CSRRC")
        try:
            _emit_store_writable_csr(
                lines,
                csr_name=csr_name,
                addr_reg=addr_reg,
                raw_reg=raw_reg,
                new_reg=new_reg,
            )
        except ValueError as exc:
            raise InstructionValidationError(insn, f"{exc}: {insn.op_str}") from exc
    else:
        lines.append(f"    # {opcode} 的零 rs1/zimm：仅读取旧 {csr_name}")

    # 必须等 source state 写回后才提交 rd：rd=t6/x31 时，t6 在此之前仍是
    # wrapper 的状态基址；rd=rs1 时也已通过 wrapper 的语义输入保护保留原值。
    if is_rmw and not rd_is_zero:
        lines.append(f"    mv      {rd}, {old_reg}                    # rd = CSR 旧值")
    return lines
