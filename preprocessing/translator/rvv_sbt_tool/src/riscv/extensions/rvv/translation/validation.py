"""Validate source RVV encodings before allocating or accessing simulated state."""

from __future__ import annotations

import re

from riscv.extensions.rvv.analysis.model import LEGAL_LMULS
from riscv.extensions.rvv.translation.contracts import InstructionValidationError
from riscv.registers import normalize_gpr_name


def validate_source_operands(context, operands: tuple[str, ...]) -> None:
    insn, spec, state = context.instruction, context.spec, context.state

    def reject(reason: str) -> None:
        raise InstructionValidationError(
            insn, f"{insn.opcode}: {reason}; operands={insn.op_str}",
            code="invalid-source-form",
        )

    if spec.category == "config":
        if insn.opcode != "vsetvl":
            if operands[2] not in {"e8", "e16", "e32", "e64"}:
                reject("Vector configuration supports SEW=8/16/32/64 only")
            if operands[3] not in {"mf8", "mf4", "mf2", "m1", "m2", "m4", "m8"}:
                reject(f"Invalid LMUL token: {operands[3]}")
        return
    if spec.category in {"csr", "csr-read", "csr-write"}:
        return
    if not spec.vtype_independent:
        if state.sew not in {8, 16, 32, 64} or state.lmul not in LEGAL_LMULS:
            reject(f"Invalid vector configuration: e{state.sew}, LMUL={state.lmul}")
        if spec.supported_sews and state.sew not in spec.supported_sews:
            reject(f"{insn.opcode} does not support SEW={state.sew}")
        if spec.supported_lmuls and state.lmul not in spec.supported_lmuls:
            reject(f"{insn.opcode} does not support LMUL={state.lmul:g}")

    opcode = insn.opcode
    masked = bool(operands and operands[-1] == "v0.t")
    base = operands[:-1] if masked else operands
    if opcode == "vadd.vi":
        try:
            immediate = int(base[2], 0)
        except ValueError:
            reject("vadd.vi simm5 must be an integer in -16..15")
        if not -16 <= immediate <= 15:
            reject("vadd.vi simm5 must be in -16..15")

    memory = spec.category.startswith("memory") or any(
        role in {"base", "rs1-address"} for role in spec.operand_order
    )
    if memory:
        address = re.fullmatch(r"(?:(0|[+-]?0[xX]0+))?\(([^()]+)\)", base[1])
        if address is None or normalize_gpr_name(address[2]) is None:
            reject("RVV memory operands require (rs1); nonzero offsets are not encoded")

    vectors = {}
    for index, operand in enumerate(base):
        if re.fullmatch(r"v\d+", operand):
            number = int(operand[1:])
            if not 0 <= number < 32:
                reject(f"Vector register out of range: {operand}")
            vectors[index] = number
    if not vectors:
        return

    sew, lmul = state.sew, state.lmul
    shapes = {index: (sew, lmul) for index in vectors}
    whole = re.fullmatch(r"(?:vmv([1248])r|v[ls]([1248])r(?:e(?:8|16|32|64))?)\.v", opcode)
    reduction = "red" in opcode and opcode.endswith(".vs")
    mask_result = spec.category in {"mask-compare", "mask-logic"} or opcode.startswith(
        ("vmseq.", "vmsne.", "vmslt", "vmsle", "vmsgt", "vmsge", "vmf")
    )
    store = memory and opcode.startswith("vs")
    destination = 0 in vectors and not store
    if whole:
        factor = int(whole[1] or whole[2])
        shapes = {index: (8, float(factor)) for index in vectors}
    elif opcode in {"vmv.s.x", "vmv.x.s", "vfmv.s.f", "vfmv.f.s"}:
        shapes = {index: (sew, 1.0) for index in vectors}
    elif reduction:
        wide = opcode.startswith(("vw", "vfw"))
        for index in (0, 2):
            shapes[index] = (sew * (2 if wide else 1), 1.0)
    elif memory:
        if opcode in {"vlm.v", "vsm.v"}:
            shapes[0] = (1, 1.0)
        elif "ei" in opcode:
            eew = int(re.search(r"ei(\d+)", opcode)[1])
            shapes[2] = (eew, lmul * eew / sew)
        else:
            width = re.search(r"e(8|16|32|64)", opcode)
            if width:
                eew = int(width[1])
                shapes[0] = (eew, lmul * eew / sew)
    elif opcode.startswith(("vfw", "vw")):
        shapes[0] = (sew * 2, lmul * 2)
        if opcode.endswith((".wv", ".wx")):
            shapes[1] = (sew * 2, lmul * 2)
    elif opcode.startswith(("vfncvt.", "vncvt.", "vnsr", "vnclip")):
        shapes[1] = (sew * 2, lmul * 2)
    elif opcode.startswith(("vsext.vf", "vzext.vf")):
        factor = int(opcode[-1])
        if sew // factor < 8:
            reject(f"{opcode} requires source EEW >= 8")
        shapes[1] = (sew // factor, lmul / factor)

    for index, role in enumerate(spec.operand_order):
        if index in vectors and ("mask" in role or "selector" in role):
            shapes[index] = (1, 1.0)
    if mask_result:
        shapes[0] = (1, 1.0)
    if opcode == "vrgatherei16.vv":
        shapes[2] = (16, lmul * 16 / sew)

    segment = re.search(r"seg([2-8])e", opcode) if memory else None
    if segment:
        fields = int(segment[1])
        emul = shapes[0][1]
        width = max(1, int(emul))
        if (emul not in LEGAL_LMULS or fields * emul > 8 or vectors[0] % width
                or vectors[0] + fields * width > 32):
            reject(f"Invalid NF={fields}/EMUL={emul:g} segment group at {base[0]}")

    spans = {}
    for index, (eew, emul) in shapes.items():
        if eew not in {1, 8, 16, 32, 64} or emul not in LEGAL_LMULS:
            reject(f"{base[index]} has unsupported EEW={eew}, EMUL={emul:g}")
        number = vectors[index]
        width = max(1, int(emul))
        if number % width or number + width > 32:
            reject(f"{base[index]} has misaligned or out-of-range EMUL={emul:g} group")
        spans[index] = (number, number + emul)
    if segment:
        spans[0] = (vectors[0], vectors[0] + int(segment[1]) * max(1, shapes[0][1]))

    if destination and (masked or opcode.startswith("vmerge.")) and vectors[0] == 0:
        if not (mask_result or reduction):
            reject("Masked data destination must not overlap v0")
    # Source operands cannot read the same physical register with two EEWs;
    # the execution mask counts as EEW=1, including for vector stores.
    source_registers = {}
    for index, (eew, emul) in shapes.items():
        if destination and index == 0:
            continue
        width = max(1, int(emul))
        if store and segment and index == 0:
            width *= int(segment[1])
        for number in range(vectors[index], vectors[index] + width):
            previous = source_registers.setdefault(number, eew)
            if previous != eew:
                reject(f"Source v{number} cannot be read with different EEWs")
    if masked and source_registers.get(0, 1) != 1:
        reject("Source v0 cannot provide both data and the execution mask")
    # Reduction operands are independent single-register accumulators; their
    # explicit overlap exception also permits a destination inside the source.
    if not destination or reduction or whole:
        return
    dst_start, dst_end = spans[0]
    dst_eew, _ = shapes[0]
    for index in vectors:
        if index == 0:
            continue
        src_start, src_end = spans[index]
        if max(dst_start, src_start) >= min(dst_end, src_end):
            continue
        src_eew, src_emul = shapes[index]
        forbidden_overlap = opcode.startswith(("vslideup.", "vslide1up.", "vrgather", "vcompress."))
        forbidden_overlap |= bool(segment) and "ei" in opcode
        if not forbidden_overlap:
            if dst_eew == src_eew:
                continue
            if dst_eew < src_eew and dst_start == src_start:
                continue
            if dst_eew > src_eew and src_emul >= 1 and dst_end == src_end:
                continue
        reject(f"Illegal overlapping vector groups: {base[0]}, {base[index]}")
