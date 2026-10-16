"""标量后端能力表及 builder 执行适配。"""

from __future__ import annotations

from riscv.extensions.rvv.translation.lowering import (
    lower_assembly_builder,
    AssemblyLineBuilder,
)
from riscv.extensions.rvv.translation.contracts import (
    LoweringResult,
    HandlerContext,
    InstructionSpec,
    InstructionValidationError,
    LoweringPlan,
    MaskPolicy,
    TailPolicy,
    VStartPolicy,
)
from collections.abc import Sequence
from riscv.extensions.rvv.analysis.model import LEGAL_LMULS
from riscv.extensions.rvv.backends.scalar.handlers import arithmetic, config, memory
from riscv.extensions.rvv.translation import vector_csr as csr
from riscv.extensions.rvv.translation.vstart import apply_vstart_policy
from riscv.registers import normalize_fpr_name, normalize_gpr_name
from riscv.extensions.rvv.translation.specs import (
    HandlerRegistry,
    resolve_scalar_semantic_inputs,
)
from riscv.extensions.rvv.translation.validation import validate_source_operands


class ScalarLowerer:
    """执行规格绑定的私有 line builder，并保持标量 fail-fast 合同。"""

    def __call__(
        self, context: HandlerContext, plan: LoweringPlan
    ) -> LoweringResult:
        raw_builder = plan.spec.lowering_metadata
        if not callable(raw_builder):
            raise TypeError(f"{plan.spec.opcode} 的标量规格缺少 assembly builder")
        builder = raw_builder
        try:
            return lower_assembly_builder(context, plan, builder, postprocessor=apply_vstart_policy)
        except InstructionValidationError:
            raise
        except ValueError as exc:
            # 寄存器组、SEW/LMUL 和立即数门禁属于具体 form 验证失败；统一
            # 附上当前指令，避免 CLI 只看到没有地址上下文的 ValueError。
            raise InstructionValidationError(context.instruction, str(exc)) from exc


SCALAR_LOWERER = ScalarLowerer()


_ALL_SEWS = frozenset({8, 16, 32, 64})


_FLOAT_SEWS = frozenset({32, 64})


_ALL_LMULS = frozenset(LEGAL_LMULS)


def _validator(min_operands: int):
    """建立只负责结构归一化的 validator。

    更细的寄存器组、SEW 和立即数限制仍由指令族 builder 以
    ``InstructionValidationError`` 报告；不再用 ``# ERROR`` 文本回传。
    """

    def validate(context: HandlerContext) -> tuple[str, ...]:
        operands = tuple(str(operand).strip() for operand in context.instruction.operands)
        mask = operands[-1].lower() if operands and operands[-1].lower().endswith(".t") else None
        if mask is not None:
            operands = (*operands[:-1], mask)
        base_count = len(operands) - (1 if mask is not None else 0)
        if base_count < min_operands:
            raise InstructionValidationError(
                context.instruction,
                f"{context.instruction.opcode} 至少需要 {min_operands} 个非掩码操作数，"
                f"实际为 {base_count}",
            )

        spec = context.spec
        if mask is not None:
            if mask != "v0.t":
                raise InstructionValidationError(
                    context.instruction,
                    f"当前仅支持显式 v0.t masked form，实际为 {mask}",
                )
            if spec is None or spec.mask_policy is MaskPolicy.FORBIDDEN:
                raise InstructionValidationError(
                    context.instruction,
                    f"{context.instruction.opcode} 的 masked form 当前未支持",
                )
        validate_source_operands(context, operands)
        return operands

    return validate


def _semantic_outputs(
    context: HandlerContext, _plan: LoweringPlan
) -> frozenset[str]:
    insn = context.instruction
    if not insn.operands:
        return frozenset()
    if insn.opcode in {"vsetvli", "vsetivli", "vsetvl",
                        "csrr", "csrrw", "csrrwi", "csrrs", "csrrsi", "csrrc", "csrrci"}:
        register = normalize_gpr_name(str(insn.operands[0]))
        return frozenset({register}) if register and register != "zero" else frozenset()
    if insn.opcode == "vfmv.f.s":
        register = normalize_fpr_name(str(insn.operands[0]))
        return frozenset({register}) if register and register != "zero" else frozenset()
    return frozenset()


def _semantic_inputs(
    context: HandlerContext, plan: LoweringPlan
) -> frozenset[str]:
    return resolve_scalar_semantic_inputs(
        context.instruction, _semantic_outputs(context, plan)
    )


def _register(
    registry: HandlerRegistry,
    *,
    opcode: str,
    category: str,
    form: str,
    operand_order: tuple[str, ...],
    min_operands: int,
    builder: AssemblyLineBuilder,
    mask_policy: MaskPolicy,
    sews: frozenset[int] = _ALL_SEWS,
    lmuls: frozenset[float] = _ALL_LMULS,
    reads_old_vd: bool = False,
    vtype_independent: bool = False,
    signedness: str,
    rounding_policy: str,
    state_reads: Sequence[str] = ("vl", "vtype", "vreg"),
    state_writes: Sequence[str] = ("vreg",),
) -> None:
    registry.register(InstructionSpec(
        opcode=opcode,
        category=category,
        operand_forms=(form,),
        supported_sews=sews,
        supported_lmuls=lmuls,
        mask_policy=mask_policy,
        tail_policy=(
            TailPolicy.NOT_APPLICABLE
            if category in {"config", "memory-store", "csr"}
            else TailPolicy.UNDISTURBED
        ),
        vstart_policy=(
            VStartPolicy.NOT_APPLICABLE
            if category in {"config", "csr"}
            else VStartPolicy.REQUIRE_ZERO
        ),
        reads_old_vd=reads_old_vd or mask_policy is MaskPolicy.V0_ONLY,
        vtype_independent=vtype_independent,
        validator=_validator(min_operands),
        lowerer=SCALAR_LOWERER,
        semantic_inputs=_semantic_inputs,
        semantic_outputs=_semantic_outputs,
        state_reads=frozenset(state_reads) | (
            frozenset() if category in {"config", "csr"} else {"vstart"}
        ),
        state_writes=frozenset(state_writes) | (
            frozenset() if category in {"config", "csr"} else {"vstart"}
        ),
        scalar_instruction_matcher=(csr.is_vector_csr_instruction if category == "csr" else None),
        # 标量后端不是把源 opcode 一对一映射为目标向量 mnemonic，而是发射
        # 带循环/掩码/状态访问的标量序列；不能在能力文档中误写成源 opcode。
        target_mnemonic="scalar-sequence",
        operand_order=operand_order,
        signedness=signedness,
        rounding_policy=rounding_policy,
        lowering_metadata=builder,
    ))


def build_scalar_registry() -> HandlerRegistry:
    """构造标量后端 registry；重复 opcode 会在构造期立即失败。"""

    registry = HandlerRegistry()

    for opcode, form, order, count, builder in (
        (
            "vsetvli",
            "rd, rs1, eSEW, LMUL, tail, mask",
            ("rd", "rs1", "sew", "lmul", "tail", "mask"),
            6,
            config._build_vsetvli_lines,
        ),
        (
            "vsetivli",
            "rd, uimm5, eSEW, LMUL, tail, mask",
            ("rd", "uimm5", "sew", "lmul", "tail", "mask"),
            6,
            config._build_vsetivli_lines,
        ),
        (
            "vsetvl",
            "rd, rs1, rs2",
            ("rd", "rs1", "rs2"),
            3,
            config._build_vsetvl_lines,
        ),
    ):
        _register(
            registry,
            opcode=opcode,
            category="config",
            form=form,
            operand_order=order,
            min_operands=count,
            builder=builder,
            mask_policy=MaskPolicy.FORBIDDEN,
            sews=frozenset(),
            signedness="not-applicable",
            rounding_policy="not-applicable",
            state_reads=("vl", "vtype", "vlenb"),
            state_writes=("vl", "vtype", "vstart"),
        )

    for opcodes, form, order in (
        (("csrr",), "rd, vector-csr", ("rd", "vector-csr")),
        (("csrw", "csrs", "csrc"), "vector-csr, rs1", ("vector-csr", "rs1")),
        (("csrwi", "csrsi", "csrci"), "vector-csr, zimm", ("vector-csr", "zimm")),
        (("csrrw", "csrrs", "csrrc"), "rd, vector-csr, rs1", ("rd", "vector-csr", "rs1")),
        (("csrrwi", "csrrsi", "csrrci"), "rd, vector-csr, zimm", ("rd", "vector-csr", "zimm")),
    ):
        for opcode in opcodes:
            _register(
                registry, opcode=opcode, category="csr", form=form,
                operand_order=order, min_operands=len(order),
                builder=csr._build_vector_csr_lines, mask_policy=MaskPolicy.FORBIDDEN,
                sews=frozenset(), lmuls=frozenset(), vtype_independent=True,
                signedness="raw-csr-value", rounding_policy="not-applicable",
                state_reads=("vector-csr", "vcsr"),
                state_writes=() if opcode == "csrr" else ("vector-csr",),
            )

    arithmetic_specs = (
        ("vfmacc.vf", "vd, rs1, vs2", ("vd", "fp-rs1", "vs2"), 3, arithmetic._build_vfmacc_vf_lines, _FLOAT_SEWS, True, False, MaskPolicy.V0_ONLY, "floating-point", "architectural-frm"),
        ("vfnmsac.vf", "vd, rs1, vs2", ("vd", "fp-rs1", "vs2"), 3, arithmetic._build_vfnmsac_vf_lines, _FLOAT_SEWS, True, False, MaskPolicy.V0_ONLY, "floating-point", "architectural-frm"),
        ("vfmacc.vv", "vd, vs1, vs2", ("vd", "vs1", "vs2"), 3, arithmetic._build_vfmacc_vv_lines, _FLOAT_SEWS, True, False, MaskPolicy.V0_ONLY, "floating-point", "architectural-frm"),
        ("vfwmacc.vv", "wide vd, narrow vs1, narrow vs2", ("wide-vd", "narrow-vs1", "narrow-vs2"), 3, arithmetic._build_vfwmacc_vv_lines, frozenset({32}), True, False, MaskPolicy.V0_ONLY, "floating-point", "architectural-frm"),
        ("vadd.vv", "vd, vs2, vs1", ("vd", "vs2", "vs1"), 3, arithmetic._build_vadd_vv_lines, _ALL_SEWS, False, False, MaskPolicy.V0_ONLY, "modular-integer", "exact-integer"),
        ("vadd.vi", "vd, vs2, simm5", ("vd", "vs2", "simm5"), 3, arithmetic._build_vadd_vi_lines, _ALL_SEWS, False, False, MaskPolicy.V0_ONLY, "modular-integer", "exact-integer"),
        ("vadd.vx", "vd, vs2, rs1", ("vd", "vs2", "rs1"), 3, arithmetic._build_vadd_vx_lines, _ALL_SEWS, False, False, MaskPolicy.V0_ONLY, "modular-integer", "exact-integer"),
        ("vfmv.v.f", "vd, fp-rs1", ("vd", "fp-rs1"), 2, arithmetic._build_vfmv_v_f_lines, _FLOAT_SEWS, False, False, MaskPolicy.FORBIDDEN, "floating-point", "not-applicable"),
        ("vfmv.f.s", "fp-rd, vs2", ("fp-rd", "vs2"), 2, arithmetic._build_vfmv_f_s_lines, _FLOAT_SEWS, False, False, MaskPolicy.FORBIDDEN, "floating-point", "not-applicable"),
        ("vmv1r.v", "raw vd, raw vs2", ("raw-vd", "raw-vs2"), 2, arithmetic._build_whole_register_move_lines, frozenset(), False, True, MaskPolicy.FORBIDDEN, "bit-preserving", "not-applicable"),
        ("vmv2r.v", "raw vd, raw vs2", ("raw-vd", "raw-vs2"), 2, arithmetic._build_whole_register_move_lines, frozenset(), False, True, MaskPolicy.FORBIDDEN, "bit-preserving", "not-applicable"),
        ("vmv4r.v", "raw vd, raw vs2", ("raw-vd", "raw-vs2"), 2, arithmetic._build_whole_register_move_lines, frozenset(), False, True, MaskPolicy.FORBIDDEN, "bit-preserving", "not-applicable"),
        ("vmv.v.i", "vd, simm5", ("vd", "simm5"), 2, arithmetic._build_vmv_v_i_lines, _ALL_SEWS, False, False, MaskPolicy.FORBIDDEN, "bit-preserving", "exact-integer"),
        ("vmv.v.x", "vd, rs1", ("vd", "rs1"), 2, arithmetic._build_vmv_v_x_lines, _ALL_SEWS, False, False, MaskPolicy.FORBIDDEN, "bit-preserving", "exact-integer"),
        ("vmv.s.x", "vd, rs1", ("vd", "rs1"), 2, arithmetic._build_vmv_s_x_lines, _ALL_SEWS, True, False, MaskPolicy.FORBIDDEN, "bit-preserving", "exact-integer"),
        ("vfredusum.vs", "vd(m1), vs2(LMUL), vs1(m1)", ("vd-m1", "vs2-lmul", "vs1-m1"), 3, arithmetic._build_vfredusum_vs_lines, _FLOAT_SEWS, True, False, MaskPolicy.V0_ONLY, "floating-point", "architectural-frm"),
        ("vid.v", "vd", ("vd",), 1, arithmetic._build_vid_v_lines, _ALL_SEWS, False, False, MaskPolicy.FORBIDDEN, "unsigned-index", "exact-integer"),
        ("vfncvt.f.xu.w", "narrow vd, wide unsigned vs2", ("narrow-vd", "wide-unsigned-vs2"), 2, arithmetic._build_vfncvt_f_xu_w_lines, frozenset({32}), False, False, MaskPolicy.V0_ONLY, "unsigned-integer-to-floating-point", "architectural-frm"),
        ("vfmul.vf", "vd, vs2, fp-rs1", ("vd", "vs2", "fp-rs1"), 3, arithmetic._build_vfmul_vf_lines, _FLOAT_SEWS, False, False, MaskPolicy.V0_ONLY, "floating-point", "architectural-frm"),
        ("vand.vi", "vd, vs2, simm5", ("vd", "vs2", "simm5"), 3, arithmetic._build_integer_lines, _ALL_SEWS, False, False, MaskPolicy.V0_ONLY, "bit-preserving", "exact-integer"),
        ("vor.vv", "vd, vs2, vs1", ("vd", "vs2", "vs1"), 3, arithmetic._build_integer_lines, _ALL_SEWS, False, False, MaskPolicy.V0_ONLY, "bit-preserving", "exact-integer"),
        ("vsll.vi", "vd, vs2, uimm5", ("vd", "vs2", "uimm5"), 3, arithmetic._build_integer_lines, _ALL_SEWS, False, False, MaskPolicy.V0_ONLY, "logical-shift", "exact-integer"),
        ("vsrl.vi", "vd, vs2, uimm5", ("vd", "vs2", "uimm5"), 3, arithmetic._build_integer_lines, _ALL_SEWS, False, False, MaskPolicy.V0_ONLY, "logical-shift", "exact-integer"),
        ("vsrl.vx", "vd, vs2, rs1", ("vd", "vs2", "rs1"), 3, arithmetic._build_integer_lines, _ALL_SEWS, False, False, MaskPolicy.V0_ONLY, "logical-shift", "exact-integer"),
        ("vsub.vx", "vd, vs2, rs1", ("vd", "vs2", "rs1"), 3, arithmetic._build_integer_lines, _ALL_SEWS, False, False, MaskPolicy.V0_ONLY, "modular-integer", "exact-integer"),
        ("vmacc.vx", "vd, rs1, vs2", ("vd", "rs1", "vs2"), 3, arithmetic._build_integer_lines, _ALL_SEWS, True, False, MaskPolicy.V0_ONLY, "modular-integer", "exact-integer"),
        ("vwmacc.vv", "wide vd, narrow vs1, narrow vs2", ("wide-vd", "narrow-vs1", "narrow-vs2"), 3, arithmetic._build_integer_lines, frozenset({8, 16, 32}), True, False, MaskPolicy.V0_ONLY, "signed-widen-multiply", "exact-integer"),
        ("vzext.vf2", "vd, half-width vs2", ("vd", "narrow-vs2"), 2, arithmetic._build_integer_lines, frozenset({16, 32, 64}), False, False, MaskPolicy.V0_ONLY, "zero-extension", "exact-integer"),
        ("vmseq.vi", "mask vd, vs2, simm5", ("mask-vd", "vs2", "simm5"), 3, arithmetic._build_vmseq_vi_lines, _ALL_SEWS, True, False, MaskPolicy.V0_ONLY, "equality-compare", "exact-integer"),
        ("vfcvt.f.x.v", "vd, signed vs2", ("vd", "signed-vs2"), 2, arithmetic._build_float_conversion_lines, _FLOAT_SEWS, False, False, MaskPolicy.V0_ONLY, "signed-integer-to-floating-point", "architectural-frm"),
        ("vfwcvt.f.f.v", "wide vd, narrow vs2", ("wide-vd", "narrow-vs2"), 2, arithmetic._build_float_conversion_lines, frozenset({16, 32}), False, False, MaskPolicy.V0_ONLY, "floating-point", "architectural-frm"),
    )
    for (
        opcode, form, order, count, builder, sews, reads_old_vd, independent,
        mask_policy, signedness, rounding_policy,
    ) in arithmetic_specs:
        lmuls = _ALL_LMULS
        if opcode in {"vwmacc.vv", "vfwcvt.f.f.v", "vfwmacc.vv", "vfncvt.f.xu.w"}:
            lmuls = frozenset(value for value in lmuls if value <= 4)
        elif opcode == "vzext.vf2":
            lmuls = frozenset(value for value in lmuls if value >= 0.25)
        _register(
            registry,
            opcode=opcode,
            category="arithmetic",
            form=form,
            operand_order=order,
            min_operands=count,
            builder=builder,
            mask_policy=mask_policy,
            sews=sews,
            lmuls=lmuls,
            reads_old_vd=reads_old_vd,
            vtype_independent=independent,
            signedness=signedness,
            rounding_policy=rounding_policy,
        )

    memory_specs = (
        ("vle8.v", "vd, (rs1)", ("vd", "base"), 2, memory._build_narrow_load_lines, "memory-load"),
        ("vle16.v", "vd, (rs1)", ("vd", "base"), 2, memory._build_narrow_load_lines, "memory-load"),
        ("vle64.v", "vd, (rs1)", ("vd", "base"), 2, memory._build_vle64_v_lines, "memory-load"),
        ("vle32.v", "vd, (rs1)", ("vd", "base"), 2, memory._build_vle32_v_lines, "memory-load"),
        ("vse64.v", "vs3, (rs1)", ("vs3", "base"), 2, memory._build_vse64_v_lines, "memory-store"),
        ("vse32.v", "vs3, (rs1)", ("vs3", "base"), 2, memory._build_vse32_v_lines, "memory-store"),
        ("vlse64.v", "vd, (rs1), rs2", ("vd", "base", "byte-stride"), 3, memory._build_vlse64_v_lines, "memory-load"),
        ("vsse64.v", "vs3, (rs1), rs2", ("vs3", "base", "byte-stride"), 3, memory._build_vsse64_v_lines, "memory-store"),
        ("vlse32.v", "vd, (rs1), rs2", ("vd", "base", "byte-stride"), 3, memory._build_vlse32_v_lines, "memory-load"),
        ("vsse32.v", "vs3, (rs1), rs2", ("vs3", "base", "byte-stride"), 3, memory._build_vsse32_v_lines, "memory-store"),
        ("vlseg2e64.v", "tuple vd, (rs1)", ("tuple-vd", "base"), 2, memory._build_vlseg2e64_v_lines, "memory-load"),
        ("vsseg2e64.v", "tuple vs3, (rs1)", ("tuple-vs3", "base"), 2, memory._build_vsseg2e64_v_lines, "memory-store"),
        ("vlsseg2e64.v", "tuple vd, (rs1), rs2", ("tuple-vd", "base", "byte-stride"), 3, memory._build_vlsseg2e64_v_lines, "memory-load"),
        ("vssseg2e64.v", "tuple vs3, (rs1), rs2", ("tuple-vs3", "base", "byte-stride"), 3, memory._build_vssseg2e64_v_lines, "memory-store"),
        ("vlseg2e32.v", "tuple vd, (rs1)", ("tuple-vd", "base"), 2, memory._build_vlseg2e32_v_lines, "memory-load"),
        ("vsseg2e32.v", "tuple vs3, (rs1)", ("tuple-vs3", "base"), 2, memory._build_vsseg2e32_v_lines, "memory-store"),
        ("vlsseg2e32.v", "tuple vd, (rs1), rs2", ("tuple-vd", "base", "byte-stride"), 3, memory._build_vlsseg2e32_v_lines, "memory-load"),
        ("vssseg2e32.v", "tuple vs3, (rs1), rs2", ("tuple-vs3", "base", "byte-stride"), 3, memory._build_vssseg2e32_v_lines, "memory-store"),
    )
    for opcode, form, order, count, builder, category in memory_specs:
        _register(
            registry,
            opcode=opcode,
            category=category,
            form=form,
            operand_order=order,
            min_operands=count,
            builder=builder,
            mask_policy=MaskPolicy.V0_ONLY,
            signedness=(
                "signed-byte-stride" if "byte-stride" in order else "not-applicable"
            ),
            rounding_policy="not-applicable",
            state_writes=("vreg",) if category == "memory-load" else (),
        )

    return registry
