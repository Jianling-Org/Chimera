"""RVV1024→RVV256 后端的原生结构化 lowering engine。

宽/保守 profile 的路径选择属于 lowering，而不是 opcode dispatcher。该组件
只消费 ``HandlerContext``、``LoweringPlan`` 和规格元数据；dispatcher 只负责
registry、标签会话和公开 plan/lower 调用。
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Callable

from riscv.extensions.rvv.instruction import peek_mask_operand
from riscv.extensions.rvv.backends.rvv256.lowering_metadata import lowering_metadata
from riscv.extensions.rvv.backends.rvv256.wide import (
    emit_wide_arithmetic,
    emit_wide_hot_arithmetic,
    emit_wide_mask,
    emit_wide_memory,
    emit_wide_reduction,
    emit_wide_whole_register_memory,
    emit_wide_whole_register_move,
)
from riscv.extensions.rvv.translation.lowering import (
    AssemblyBuilderOutput,
    lower_assembly_builder,
)
from riscv.extensions.rvv.translation.contracts import (
    HandlerContext,
    InstructionValidationError,
    LoweringDiagnostic,
    LoweringPlan,
    LoweringResult,
    LoweringStatus,
)
from riscv.extensions.rvv.translation.vstart import apply_vstart_policy
from riscv.extensions.rvv.translation.temps import TempRegisterAllocationError


class CandidateStatus(str, Enum):
    """RVV256 lowering 候选的显式决策。"""

    NOT_APPLICABLE = "not-applicable"
    LOWERED = "lowered"


@dataclass(frozen=True, slots=True)
class CandidateAttempt:
    """隔离历史 emitter 的 ``None``，避免其跨越 lowering 模块边界。"""

    status: CandidateStatus
    assembly: AssemblyBuilderOutput | None = None

    def __post_init__(self) -> None:
        if self.status is CandidateStatus.LOWERED:
            if self.assembly is None:
                raise RuntimeError("LOWERED 候选必须携带汇编结果")
        elif self.assembly is not None:
            raise RuntimeError("NOT_APPLICABLE 候选不能携带汇编结果")


def rvv256_fallback_result(
    status: LoweringStatus, diagnostic: LoweringDiagnostic
) -> LoweringResult:
    """把结构化拒绝转换为 RVV256 对外稳定的 ``ebreak`` 合同。"""

    return LoweringResult.rejected(
        status,
        diagnostic,
        lines=(
            f"# RVV256 fallback: {diagnostic.message}",
            "# fallback to ebreak",
            "    ebreak",
        ),
        fallback_kind="ebreak",
    )


class RVV256Lowerer:
    """按 profile 执行宽规划或规格 builder，并保持 ebreak fallback 合同。"""

    def __init__(self, *, wide_lmul: bool):
        self.wide_lmul = bool(wide_lmul)

    @staticmethod
    def _attempt_emitter(
        emitter: Callable[[], AssemblyBuilderOutput | None],
    ) -> CandidateAttempt:
        """把历史 emitter 的可选返回值收敛为显式候选决策。"""

        translated = emitter()
        if translated is None:
            return CandidateAttempt(CandidateStatus.NOT_APPLICABLE)
        return CandidateAttempt(CandidateStatus.LOWERED, assembly=translated)

    @classmethod
    def _first_candidate(
        cls, emitters: tuple[Callable[[], AssemblyBuilderOutput | None], ...]
    ) -> CandidateAttempt:
        """按既定优先级选择首个可用候选。"""

        for emitter in emitters:
            attempt = cls._attempt_emitter(emitter)
            if attempt.status is not CandidateStatus.NOT_APPLICABLE:
                return attempt
        return CandidateAttempt(CandidateStatus.NOT_APPLICABLE)

    def _build_lines(
        self, context: HandlerContext, plan: LoweringPlan
    ) -> AssemblyBuilderOutput:
        insn = context.instruction
        state = context.state
        allocator = context.layout
        dispatcher = context.new_label

        metadata = lowering_metadata(plan.spec)
        builder = metadata.builder

        if plan.spec.category == "csr":
            if builder is None:
                raise RuntimeError(
                    f"{insn.opcode} 的 CSR 规格缺少 assembly builder"
                )
            return builder(context)

        # Whole-register form 只搬运固定 raw bytes，不读取 vl/vtype；优先走
        # 原生 vl*r/vs*r 路径，避免误落入逐元素 builder。
        attempt = self._first_candidate((
            lambda: emit_wide_whole_register_move(
                insn, allocator, dispatcher, wide_lmul=self.wide_lmul
            ),
            lambda: emit_wide_whole_register_memory(
                insn, allocator, dispatcher, wide_lmul=self.wide_lmul
            ),
        ))
        if attempt.status is CandidateStatus.LOWERED:
            return attempt.assembly

        is_masked = peek_mask_operand(insn) is not None

        # mask compare/logic/scan 在两种 profile 都有显式实现，且必须先于
        # 普通宽算术规划；否则 mask 结果会被当成普通数据向量提交。
        attempt = self._attempt_emitter(lambda: emit_wide_mask(
            insn,
            state,
            allocator,
            dispatcher,
            wide_lmul=self.wide_lmul,
        ))
        if attempt.status is CandidateStatus.LOWERED:
            return attempt.assembly

        # Hardware-validated forms have one implementation in both profiles.
        primary_hotspot = not is_masked and (
            insn.opcode == "vfwmacc.vv"
            or (insn.opcode in {"vmacc.vx", "vwmacc.vv"}
                and state.sew == 16 and state.lmul == 1)
            or (insn.opcode in {"vfmacc.vv", "vle32.v"}
                and state.sew == 32 and state.lmul == 8)
        )
        if primary_hotspot:
            if insn.opcode == "vfmacc.vv":
                translated = emit_wide_arithmetic(insn, state, allocator, dispatcher, plan.spec)
            elif insn.opcode == "vle32.v":
                translated = emit_wide_memory(insn, state, allocator, dispatcher)
            else:
                translated = emit_wide_hot_arithmetic(insn, state, allocator, dispatcher)
            if translated is None:
                raise InstructionValidationError(
                    insn,
                    f"RVV256 primary lowering is not available for this shape: {insn.op_str}",
                    status=LoweringStatus.UNSUPPORTED,
                    code="unsupported-primary-shape",
                )
            return translated

        if self.wide_lmul:
            attempt = self._first_candidate((
                lambda: emit_wide_reduction(insn, state, allocator, dispatcher),
                lambda: emit_wide_hot_arithmetic(insn, state, allocator, dispatcher),
                lambda: emit_wide_arithmetic(insn, state, allocator, dispatcher, plan.spec),
                lambda: emit_wide_memory(insn, state, allocator, dispatcher),
            ))
            if attempt.status is CandidateStatus.LOWERED:
                return attempt.assembly

            # 只由宽 profile 提供的 masked form 若因具体 shape 无法规划，
            # 必须拒绝，不能落入会忽略 v0.t 的保守 builder。
            if is_masked and not metadata.conservative_mask_supported:
                raise InstructionValidationError(
                    insn,
                    "RVV256 wide masked form is not available for this shape: "
                    f"{insn.op_str}",
                    status=LoweringStatus.UNSUPPORTED,
                    code="unsupported-wide-mask-shape",
                )

        if builder is not None:
            translated = builder(context)
            return translated

        raise InstructionValidationError(
            insn,
            f"RVV256 未实现 opcode: {insn.opcode} ({insn.op_str})",
            status=LoweringStatus.UNSUPPORTED,
            code="unsupported-opcode",
        )

    def __call__(
        self, context: HandlerContext, plan: LoweringPlan
    ) -> LoweringResult:
        try:
            return lower_assembly_builder(
                context, plan, lambda bound: self._build_lines(bound, plan),
                postprocessor=apply_vstart_policy,
            )
        except InstructionValidationError as exc:
            return rvv256_fallback_result(exc.status, exc.diagnostic)
        except TempRegisterAllocationError as exc:
            diagnostic = LoweringDiagnostic(
                "invalid-form", f"{context.instruction.opcode}: {exc}"
            )
            return rvv256_fallback_result(LoweringStatus.INVALID, diagnostic)


__all__ = ["RVV256Lowerer", "rvv256_fallback_result"]
