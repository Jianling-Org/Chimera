"""Vector CSR reads and updates for the shared simulated-state ABI."""

from __future__ import annotations

from typing import Any

from riscv.extensions.rvv.runtime.layout import CSR_OFFSETS
from riscv.extensions.rvv.translation.contracts import InstructionValidationError
from riscv.registers import normalize_gpr_name


_VECTOR_CSR_ALIASES = {
    "0x008": "vstart",
    "0x009": "vxsat",
    "0x00a": "vxrm",
    "0x00f": "vcsr",
    "0xc20": "vl",
    "0xc21": "vtype",
    "0xc22": "vlenb",
}
VECTOR_CSR_OFFSETS = {
    **CSR_OFFSETS,
    **{number: CSR_OFFSETS[name] for number, name in _VECTOR_CSR_ALIASES.items()},
}
# operation, CSR operand index, source operand index, immediate source
_CSR_FORMS = {
    "csrr": ("read", 1, None, False),
    "csrw": ("write", 0, 1, False),
    "csrs": ("set", 0, 1, False),
    "csrc": ("clear", 0, 1, False),
    "csrwi": ("write", 0, 1, True),
    "csrsi": ("set", 0, 1, True),
    "csrci": ("clear", 0, 1, True),
    "csrrw": ("write", 1, 2, False),
    "csrrs": ("set", 1, 2, False),
    "csrrc": ("clear", 1, 2, False),
    "csrrwi": ("write", 1, 2, True),
    "csrrsi": ("set", 1, 2, True),
    "csrrci": ("clear", 1, 2, True),
}


def normalize_csr_operand(csr: Any) -> str:
    """Normalize names, hexadecimal CSR addresses, and decimal addresses."""
    text = str(csr).strip().lower()
    try:
        if text.startswith("0x"):
            return f"0x{int(text, 16):03x}"
        if text.isdigit():
            return f"0x{int(text, 10):03x}"
    except ValueError:
        pass
    return text


def is_vector_csr(csr: Any) -> bool:
    return normalize_csr_operand(csr) in VECTOR_CSR_OFFSETS


def is_vector_csr_instruction(insn) -> bool:
    form = _CSR_FORMS.get(insn.opcode)
    return bool(form is not None and len(insn.operands) > form[1]
                and is_vector_csr(insn.operands[form[1]]))


def _build_vector_csr_lines(context) -> list[str]:
    """Keep vector CSR operations in source state, with vcsr authoritative."""
    insn = context.instruction
    operation, csr_index, source_index, immediate = _CSR_FORMS[insn.opcode]
    expected_count = max(csr_index, source_index or 0) + 1
    if len(insn.operands) != expected_count:
        raise InstructionValidationError(insn, f"malformed vector CSR instruction: {insn.op_str}")
    csr = normalize_csr_operand(insn.operands[csr_index])
    if csr not in VECTOR_CSR_OFFSETS:
        raise InstructionValidationError(insn, f"not a vector CSR: {insn.op_str}")
    name = _VECTOR_CSR_ALIASES.get(csr, csr)
    rd = normalize_gpr_name(str(insn.operands[0])) if csr_index == 1 else "zero"
    if rd is None:
        raise InstructionValidationError(insn, f"invalid CSR destination: {insn.op_str}")

    source = None
    source_is_zero = False
    if source_index is not None:
        text = str(insn.operands[source_index]).strip()
        if immediate:
            try:
                source = int(text, 0)
            except ValueError as exc:
                raise InstructionValidationError(insn, f"CSR zimm must be an integer: {text}") from exc
            if not 0 <= source <= 31:
                raise InstructionValidationError(insn, f"CSR zimm must be in 0..31: {text}")
            source_is_zero = source == 0
        else:
            source = normalize_gpr_name(text)
            if source is None:
                raise InstructionValidationError(insn, f"invalid CSR source register: {text}")
            source_is_zero = source == "zero"
    writes = operation != "read" and not (operation in {"set", "clear"} and source_is_zero)
    if writes and name in {"vl", "vtype", "vlenb"}:
        raise InstructionValidationError(insn, f"cannot write read-only vector CSR {name}: {insn.op_str}")
    if not writes and rd == "zero":
        return []

    temps = context.temp_register_allocator
    addr = temps.alloc_gpr()
    raw = temps.alloc_gpr()
    old = temps.alloc_gpr()
    lines = [f"    # {insn.opcode}: simulated CSR.{name}"]
    if name == "vlenb":
        lines.append(f"    li      {old}, {context.layout.vlenb}")
    else:
        storage = "vcsr" if name in {"vcsr", "vxrm", "vxsat"} else name
        lines.append(f"    li      {addr}, {CSR_OFFSETS[storage]:#x}")
        lines.append(f"    add     {addr}, t6, {addr}")
        lines.append(f"    ld      {raw}, 0({addr})")
        if storage == "vcsr":
            lines.append(f"    andi    {raw}, {raw}, 7")
        if name == "vxrm":
            lines.append(f"    srli    {old}, {raw}, 1")
        elif name == "vxsat":
            lines.append(f"    andi    {old}, {raw}, 1")
        else:
            lines.append(f"    mv      {old}, {raw}")

    if writes:
        value = temps.alloc_gpr()
        lines.append(f"    {'li' if immediate else 'mv':<8}{value}, {source}")
        if operation == "set":
            lines.append(f"    or      {value}, {old}, {value}")
        elif operation == "clear":
            lines.append(f"    not     {value}, {value}")
            lines.append(f"    and     {value}, {old}, {value}")
        if name == "vstart":
            lines.append(f"    andi    {value}, {value}, {context.layout.vlenb * 8 - 1}")
        elif name == "vxrm":
            lines.append(f"    andi    {value}, {value}, 3")
            lines.append(f"    slli    {value}, {value}, 1")
            lines.append(f"    andi    {raw}, {raw}, 1")
            lines.append(f"    or      {value}, {value}, {raw}")
        elif name == "vxsat":
            lines.append(f"    andi    {value}, {value}, 1")
            lines.append(f"    andi    {raw}, {raw}, 6")
            lines.append(f"    or      {value}, {value}, {raw}")
        else:
            lines.append(f"    andi    {value}, {value}, 7")
        lines.append(f"    sd      {value}, 0({addr})")
        if name != "vstart":
            lines.append(f"    andi    {raw}, {value}, 1")
            lines.append(f"    sd      {raw}, {CSR_OFFSETS['vxsat'] - CSR_OFFSETS['vcsr']}({addr})")
            lines.append(f"    srli    {raw}, {value}, 1")
            lines.append(f"    sd      {raw}, {CSR_OFFSETS['vxrm'] - CSR_OFFSETS['vcsr']}({addr})")
    if rd != "zero":
        # Commit after state stores: rd may also be rs1, t6, or sp.
        lines.append(f"    mv      {rd}, {old}")
    return lines


_build_csrr_lines = _build_vector_csr_lines
_build_csrw_lines = _build_vector_csr_lines
_build_csrs_lines = _build_vector_csr_lines
_build_csrc_lines = _build_vector_csr_lines
_build_csrwi_lines = _build_vector_csr_lines
_build_csrsi_lines = _build_vector_csr_lines
_build_csrci_lines = _build_vector_csr_lines
_build_csrrw_lines = _build_vector_csr_lines
_build_csrrs_lines = _build_vector_csr_lines
_build_csrrc_lines = _build_vector_csr_lines
_build_csrrwi_lines = _build_vector_csr_lines
_build_csrrsi_lines = _build_vector_csr_lines
_build_csrrci_lines = _build_vector_csr_lines
