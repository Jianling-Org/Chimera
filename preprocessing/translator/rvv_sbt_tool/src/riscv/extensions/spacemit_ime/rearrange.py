"""Whole-register layout transforms for the A100 LMUL=1 profile.

Chapter 7 mixes bit and element indices in its pseudocode. Lowering uses byte
offsets, implementing the stated interleave/de-interleave and narrow operations.
See docs/IME_RVV.md for the explicit width and nibble interpretation.
"""

from dataclasses import dataclass
import re

from riscv.extensions.rvv.translation.contracts import (
    InstructionSpec, InstructionValidationError, LoweringResult,
    MaskPolicy, TailPolicy, VStartPolicy,
)
from . import block


@dataclass(frozen=True)
class RearrangeMode:
    kind: str
    saturating: bool

    @property
    def destination_count(self) -> int:
        return 2 if self.kind in {"pack", "unpack"} else 1


def validate(context) -> tuple[str, ...]:
    insn = context.instruction
    operands = tuple(str(op).strip().lower() for op in insn.operands)
    if len(operands) != 4:
        raise InstructionValidationError(insn, "rearrangement requires vd, vs1, vs2, imm2")
    if any(re.fullmatch(r"v(?:[0-9]|[12][0-9]|3[01])", reg) is None for reg in operands[:3]):
        raise InstructionValidationError(insn, "expected vector registers v0-v31")
    try:
        imm = int(operands[3], 0)
    except ValueError:
        raise InstructionValidationError(insn, "imm2 must be an integer in [0, 3]") from None
    if not 0 <= imm <= 3:
        raise InstructionValidationError(insn, "imm2 must be an integer in [0, 3]")
    if context.spec.lowering_metadata.destination_count == 2 and int(operands[0][1:]) % 2:
        raise InstructionValidationError(insn, "pack/unpack vd must be even (vd/vd+1)")
    # Chapter 8.6 imposes no source/destination non-overlap rule. Snapshots make
    # in-place, partial-overlap, and identical-source forms safe.
    return (*operands[:3], str(imm))


def inputs(_context, plan) -> frozenset[str]:
    return frozenset(plan.normalized_operands[1:3])


def outputs(_context, plan) -> frozenset[str]:
    start = int(plan.normalized_operands[0][1:])
    return frozenset(f"v{start + i}" for i in range(plan.spec.lowering_metadata.destination_count))


def _pack(frame, chunk):
    # Copy complete chunks from the operand snapshots. Aligned scalar accesses
    # avoid A100's short-vector memory costs and require no borrowed vectors.
    width = min(chunk, 8)
    load, store = {1: ("lbu", "sb"), 2: ("lhu", "sh"),
                   4: ("lw", "sw"), 8: ("ld", "sd")}[width]
    lines = []
    for i in range(128 // chunk):
        for stream, source in enumerate((frame.a_offset, frame.b_offset)):
            for offset in range(0, chunk, width):
                lines += [f"    {load} t0, {source + i * chunk + offset}(sp)",
                          f"    {store} t0, {frame.c_offset + (2 * i + stream) * chunk + offset}(sp)"]
    return lines


def _unpack(frame, chunk, loop):
    lines = [f"    addi t0, sp, {frame.a_offset}", f"    addi t1, sp, {frame.b_offset}",
             f"    addi t2, sp, {frame.c_offset}", f"    addi t3, sp, {frame.c_offset + 128}",
             f"    li t4, {chunk}", f"    li t5, {64 // chunk}",
             "    vsetvli zero, t4, e8, m1, tu, mu", f"{loop}:"]
    for destination in ("t2", "t3"):
        lines += ["    vle8.v v0, (t0)", f"    vse8.v v0, ({destination})", "    add t0, t0, t4",
                  "    vle8.v v0, (t1)", f"    addi t6, {destination}, 64", "    vse8.v v0, (t6)",
                  "    add t1, t1, t4"]
    return lines + ["    add t2, t2, t4", "    add t3, t3, t4", "    addi t5, t5, -1", f"    bnez t5, {loop}"]


def _narrow(frame, chunk, sew, saturating, loop):
    source_width = sew * 2
    lanes = chunk * 8 // source_width
    lines = [f"    addi t0, sp, {frame.a_offset}", f"    addi t1, sp, {frame.b_offset}",
             f"    addi t2, sp, {frame.c_offset}", f"    li t3, {128 // chunk}",
             f"    li t4, {chunk}", f"    li t5, {chunk // 2}", f"{loop}:"]
    for source in ("t0", "t1"):
        lines += [f"    vsetivli zero, {lanes}, e{source_width}, m1, tu, mu", f"    vle{source_width}.v v0, ({source})"]
        if saturating:
            # Clamp with non-saturating instructions: vnclip would leak changes
            # to vxsat and also introduce a vxrm dependency absent from SCLIP.
            lines += [f"    li t6, {-1 << (sew - 1)}", "    vmax.vx v0, v0, t6",
                      f"    li t6, {(1 << (sew - 1)) - 1}", "    vmin.vx v0, v0, t6"]
        lines += [f"    vsetivli zero, {lanes}, e{sew}, mf2, tu, mu",
                  "    vnsrl.wi v2, v0, 0", f"    vse{sew}.v v2, (t2)",
                  "    add t2, t2, t5", f"    add {source}, {source}, t4"]
    return lines + ["    addi t3, t3, -1", f"    bnez t3, {loop}"]


def _nibble(frame, chunk, saturating, loop):
    lines = [f"    addi t0, sp, {frame.a_offset}", f"    addi t1, sp, {frame.b_offset}",
             f"    addi t2, sp, {frame.c_offset}", f"    li t3, {128 // chunk}",
             f"    li t4, {chunk}", f"    li t5, {chunk // 2}",
             "    vsetvli zero, t5, e8, m1, tu, mu", f"{loop}:"]
    for source in ("t0", "t1"):
        lines += ["    li t6, 2", f"    vlse8.v v0, ({source}), t6", f"    addi {source}, {source}, 1",
                  f"    vlse8.v v1, ({source}), t6", f"    addi {source}, {source}, -1"]
        if saturating:
            lines += ["    li t6, -8", "    vmax.vx v0, v0, t6", "    vmax.vx v1, v1, t6",
                      "    li t6, 7", "    vmin.vx v0, v0, t6", "    vmin.vx v1, v1, t6"]
        for register in ("v0", "v1"):
            lines.append(f"    vand.vi {register}, {register}, 15")
        lines += ["    vsll.vi v1, v1, 4", "    vor.vv v2, v0, v1", "    vse8.v v2, (t2)",
                  "    add t2, t2, t5", f"    add {source}, {source}, t4"]
    return lines + ["    addi t3, t3, -1", f"    bnez t3, {loop}"]


def lower(context, plan):
    vd, vs1, vs2, immediate = plan.normalized_operands
    imm = int(immediate)
    mode = plan.spec.lowering_metadata
    frame = block.FrameLayout((vs1,), mode.destination_count,
                              temporary_count=0 if mode.kind == "pack" else 3,
                              saved_gprs=("t0", "t1") if mode.kind == "pack" else block.GPRS,
                              changes_configuration=mode.kind != "pack")
    fail, writeback, done = (context.new_label(name) for name in ("reject", "writeback", "done"))
    # Pack writes all 256 destination bytes and never reads the old value.
    lines = block.begin(frame, vd, vs2, fail, snapshot_destination=mode.kind != "pack")
    # Guards branch before any vector calculation. Whole-register snapshots do
    # not modify source registers; the failure epilogue only needs GPR restore.
    # Scalar pack and whole-register transfers leave vl/vtype unchanged.
    # vstart is guarded at zero; these transfers also leave it at zero.
    lines += (["    srli t0, t1, 3"] if mode.kind == "pack" else
              [f"    ld t0, {block.VTYPE_OFFSET}(sp)", "    srli t0, t0, 3"])
    lines.append("    andi t0, t0, 7")
    if mode.kind in {"pack", "unpack"} and imm:
        # Nonzero immediates fix the chunk width independently of SEW. Retain
        # the supported-width check but emit only one copy of the payload.
        payload = (_pack(frame, 8 << imm) if mode.kind == "pack" else
                   _unpack(frame, 8 << imm, context.new_label("chunks")))
        lines += ["    li t1, 3", f"    bgtu t0, t1, {fail}",
                  *payload, *block.end(frame, vd, fail, done)]
        return LoweringResult.lowered(lines)
    variants = []
    for sew in sorted(plan.spec.supported_sews):
        chunk = (sew // 8 if imm == 0 else 8 << imm) if mode.kind in {"pack", "unpack"} else 4 << imm
        if mode.kind == "narrow" and chunk * 8 < 2 * sew:
            continue
        entry, loop = context.new_label(f"e{sew}"), context.new_label("chunks")
        lines += [f"    li t1, {(sew // 8).bit_length() - 1}", f"    beq t0, t1, {entry}"]
        variants.append((sew, chunk, entry, loop))
    lines.append(f"    j {fail}")
    for sew, chunk, entry, loop in variants:
        lines.append(f"{entry}:")
        if mode.kind == "pack":
            lines += _pack(frame, chunk)
        elif mode.kind == "unpack":
            lines += _unpack(frame, chunk, loop)
        elif mode.kind == "narrow":
            lines += _narrow(frame, chunk, sew, mode.saturating, loop)
        else:
            lines += _nibble(frame, chunk, mode.saturating, loop)
        lines.append(f"    j {writeback}")
    lines += [f"{writeback}:", *block.end(frame, vd, fail, done)]
    return LoweringResult.lowered(lines)


def rearrange_specs():
    for name, kind, saturated in (
        ("vpack", "pack", False), ("vupack", "unpack", False),
        ("vnpack", "narrow", False), ("vnspack", "narrow", True),
        ("vnpack4", "nibble", False), ("vnspack4", "nibble", True),
    ):
        sews = {8} if kind == "nibble" else {8, 16, 32} if kind == "narrow" else {8, 16, 32, 64}
        yield InstructionSpec(
            opcode=f"smt.{name}.vv", category="ime-rearrange", operand_forms=("vd,vs1,vs2,imm2",),
            supported_sews=frozenset(sews), supported_lmuls=frozenset({1}),
            mask_policy=MaskPolicy.FORBIDDEN, tail_policy=TailPolicy.NOT_APPLICABLE,
            vstart_policy=VStartPolicy.REQUIRE_ZERO, reads_old_vd=False, vtype_independent=False,
            validator=validate, lowerer=lower,
            target_mnemonic=("scalar-sequence" if kind == "pack" else "vnsrl.wi" if kind == "narrow"
                             else "vor.vv" if kind == "nibble" else "vle8.v"),
            operand_order=("vd", "vs1", "vs2", "imm2"),
            signedness="signed" if saturated else "bit-pattern",
            rounding_policy="signed-clamp-then-truncate" if saturated else "exact-bit-layout",
            semantic_inputs=inputs, semantic_outputs=outputs, lowering_metadata=RearrangeMode(kind, saturated),
        )
