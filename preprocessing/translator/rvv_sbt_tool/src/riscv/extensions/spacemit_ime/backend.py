"""A100 IME registration and integer matrix lowering to native RVV."""

from dataclasses import dataclass, replace
import re
from typing import Callable

from riscv.frontend.model import RVInstruction
from riscv.extensions.rvv.translation.contracts import (
    BackendProfile, InstructionSpec, InstructionValidationError, LoweringPlan,
    LoweringResult, MaskPolicy, TailPolicy, VStartPolicy,
)
from riscv.extensions.rvv.translation.specs import HandlerRegistry
from . import block
from .rearrange import rearrange_specs


PROFILE = BackendProfile(
    name="spacemit-a100-ime-to-rvv1024", source_vlenb=128,
    target_vlenb=128, fallback_policy="raise", preflight_policy="strict",
    runtime_vtype_dispatch=False,
)


@dataclass(frozen=True)
class NativeContext:
    """Only native lowering inputs; deliberately no simulated-state layout."""

    instruction: RVInstruction
    new_label: Callable[[str], str]
    spec: InstructionSpec | None = None

    def with_spec(self, spec: InstructionSpec) -> "NativeContext":
        return replace(self, spec=spec)


@dataclass(frozen=True)
class IntegerMode:
    signed_a: bool
    signed_b: bool
    slide: int

    def a_registers(self, vs1: str) -> tuple[str, ...]:
        return (vs1, f"v{int(vs1[1:]) + 1}") if self.slide else (vs1,)


def validate(context: NativeContext) -> tuple[str, ...]:
    insn = context.instruction
    mode = context.spec.lowering_metadata
    operands = tuple(str(op).strip().lower() for op in insn.operands)
    if len(operands) != 4 or operands[3] not in {"i4", "i8"}:
        raise InstructionValidationError(insn, "A100 integer IME requires vd, vs1, vs2, i4|i8")
    if mode.slide and operands[3] != "i8":
        raise InstructionValidationError(insn, "sliding-window IME supports i8 only")
    if any(re.fullmatch(r"v(?:[0-9]|[12][0-9]|3[01])", reg) is None
           for reg in operands[:3]):
        raise InstructionValidationError(insn, "expected vector registers v0-v31")
    vd, vs1 = (int(reg[1:]) for reg in operands[:2])
    if mode.slide and vs1 % 2:
        raise InstructionValidationError(insn, "sliding-window vs1 must be even (vs1/vs1+1)")
    sources = set(mode.a_registers(operands[1])) | {operands[2]}
    if vd % 2 or sources & {f"v{vd}", f"v{vd + 1}"}:
        raise InstructionValidationError(insn, "vd must be even and vd/vd+1 must not overlap sources")
    return operands


def outputs(context: NativeContext, plan: LoweringPlan) -> frozenset[str]:
    vd = plan.normalized_operands[0]
    return frozenset((vd, f"v{int(vd[1:]) + 1}"))


def inputs(context: NativeContext, plan: LoweringPlan) -> frozenset[str]:
    _, vs1, vs2, _ = plan.normalized_operands
    return outputs(context, plan) | frozenset(plan.spec.lowering_metadata.a_registers(vs1)) | {vs2}


def _int4_products(mode: IntegerMode) -> list[str]:
    # One byte contains two K elements, low nibble first. Keep v1 as the raw
    # byte vector while extracting both products, so no extra temporary is live.
    lines = [
        "    lbu t4, 0(t0)", "    andi t4, t4, 15",
        "    vsetivli zero, 8, e8, m1, tu, mu", "    vlse8.v v1, (t2), t3",
        "    vsetivli zero, 8, e32, m1, tu, mu", "    vzext.vf4 v2, v1",
        "    vand.vi v2, v2, 15",
    ]
    if mode.signed_a:
        lines += ["    slli t4, t4, 60", "    srai t4, t4, 60"]
    if mode.signed_b:
        lines += ["    vsll.vi v2, v2, 28", "    vsra.vi v2, v2, 28"]
    lines += [
        "    vmacc.vx v0, t4, v2",
        f"    {'lb' if mode.signed_a else 'lbu'} t4, 0(t0)",
        f"    {'srai' if mode.signed_a else 'srli'} t4, t4, 4",
        f"    {'vsext' if mode.signed_b else 'vzext'}.vf4 v2, v1",
        f"    {'vsra' if mode.signed_b else 'vsrl'}.vi v2, v2, 4",
        "    vmacc.vx v0, t4, v2",
    ]
    return lines


def _int8_dot(frame: block.FrameLayout, mode: IntegerMode, inner: str,
              accumulator: str, direct: bool) -> list[str]:
    # Transpose both byte matrices once. Each K then supplies two packed words
    # of A rows and B columns; scalar word loads avoid short vector loads.
    lines = [
        "    li t3, 128", "    vsetvli zero, t3, e8, m1, tu, mu",
        "    vid.v v0", "    vand.vi v1, v0, 7", "    vsll.vi v1, v1, 4",
        "    vsrl.vi v0, v0, 3", "    vor.vv v0, v0, v1",
        f"    addi t0, sp, {frame.a_offset + mode.slide * 16}", "    vl1re8.v v2, (t0)",
        "    vrgather.vv v3, v2, v0", f"    addi t0, sp, {frame.a_offset}", "    vs1r.v v3, (t0)",
        f"    addi t1, sp, {frame.b_offset}", "    vl1re8.v v2, (t1)",
        "    vrgather.vv v3, v2, v0", "    vs1r.v v3, (t1)",
        "    li t3, 32", "    vsetvli zero, t3, e32, m1, tu, mu",
        "    vid.v v1", "    vand.vi v2, v1, 3", "    vxor.vi v2, v2, 3", "    vsll.vi v2, v2, 3",
        "    vsrl.vi v1, v1, 3", "    vxor.vi v1, v1, 3", "    vsll.vi v1, v1, 3",
        "    vid.v v3", "    vand.vi v3, v3, 4", "    vmsne.vi v0, v3, 0",
    ]
    if not direct:
        lines += [f"    addi t2, sp, {frame.c_offset}", "    vl2re32.v v4, (t2)"]
    lines += [
        "    li t6, 255", "    li t3, 16", f"{inner}:",
        "    lw t4, 0(t1)", "    lw t5, 4(t1)",
        "    vmv.v.x v6, t4", "    vmerge.vxm v6, v6, t5, v0", "    vsll.vv v6, v6, v2",
    ]
    lines.append(f"    {'vsra' if mode.signed_b else 'vsrl'}.vi v6, v6, 24")
    # Shift the selected byte to bit 24, then extend it with one right shift.
    # The indices are 24 - byte_offset, for signed and unsigned extraction.
    # Lane r*8+c represents one element of a four-row output group. v1 selects
    # A's row byte, v2 selects B's column byte, and v0 selects B's upper word.
    # Both signed and unsigned byte values fit in e32 before modulo-2^32 MACs.
    for group in range(2):
        lines += [f"    lw t4, {4 * group}(t0)", "    vmv.v.x v3, t4", "    vsll.vv v3, v3, v1"]
        lines.append(f"    {'vsra' if mode.signed_a else 'vsrl'}.vi v3, v3, 24")
        lines.append(f"    vmacc.vv v{int(accumulator[1:]) + group}, v3, v6")
    lines += [
        "    addi t0, t0, 8", "    addi t1, t1, 8", "    addi t3, t3, -1",
        f"    bnez t3, {inner}",
    ]
    if not direct:
        lines.append("    vs2r.v v4, (t2)")
    return lines


def lower(context: NativeContext, plan: LoweringPlan) -> LoweringResult:
    vd, vs1, vs2, dtype = plan.normalized_operands
    mode = plan.spec.lowering_metadata
    frame = block.FrameLayout(mode.a_registers(vs1), destination_count=2,
                              temporary_count=7 if dtype == "i8" else 3)
    row, inner, fail, done = (context.new_label(name) for name in ("row", "k", "reject", "done"))
    # A direct accumulator must survive both the body and temporary restoration.
    direct = dtype == "i8" and outputs(context, plan).isdisjoint(frame.temporary_offsets)
    lines = block.begin(frame, vd, vs2, fail, snapshot_destination=not direct)
    if dtype == "i8":
        lines += _int8_dot(frame, mode, inner, vd if direct else "v4", direct)
    else:
        lines += [
            f"    addi t0, sp, {frame.a_offset}", f"    addi t1, sp, {frame.c_offset}",
            "    li t3, 16", "    li t6, 8", f"{row}:",
            "    vsetivli zero, 8, e32, m1, tu, mu", "    vle32.v v0, (t1)",
            f"    addi t2, sp, {frame.b_offset}", "    li t5, 16", f"{inner}:",
            *_int4_products(mode),
            "    addi t0, t0, 1", "    addi t2, t2, 1", "    addi t5, t5, -1",
            f"    bnez t5, {inner}", "    vse32.v v0, (t1)",
            "    addi t1, t1, 32", "    addi t6, t6, -1", f"    bnez t6, {row}",
        ]
    lines += block.end(frame, vd, fail, done, writeback_destination=not direct)
    # The block restores all borrowed physical state. Only vd/vd+1 escape.
    return LoweringResult.lowered(lines)


REGISTRY = HandlerRegistry()
for slide in range(4):
    for suffix, signed_a, signed_b in (("", True, True), ("u", False, False),
                                      ("us", False, True), ("su", True, False)):
        REGISTRY.register(InstructionSpec(
            opcode=f"smt.vmadot{slide if slide else ''}{suffix}", category="ime-integer",
            operand_forms=(("vd,vs1,vs2,i8",) if slide else ("vd,vs1,vs2,i4", "vd,vs1,vs2,i8")),
            supported_sews=frozenset({8, 16, 32, 64}), supported_lmuls=frozenset({1}),
            mask_policy=MaskPolicy.FORBIDDEN, tail_policy=TailPolicy.NOT_APPLICABLE,
            vstart_policy=VStartPolicy.REQUIRE_ZERO, reads_old_vd=True,
            vtype_independent=False, validator=validate, lowerer=lower,
            target_mnemonic="vmacc.vv" if slide else "vmacc.vx / vmacc.vv",
            operand_order=("vd", "vs1", "vs2", "dtype"),
            signedness=f"A={'signed' if signed_a else 'unsigned'},B={'signed' if signed_b else 'unsigned'}",
            rounding_policy="integer-modulo-2^32", semantic_inputs=inputs,
            semantic_outputs=outputs, lowering_metadata=IntegerMode(signed_a, signed_b, slide),
        ))

for spec in rearrange_specs():
    REGISTRY.register(spec)
