"""RVV256→RVV1024 过渡后端的原生结构化 lowerer。"""

from __future__ import annotations

from riscv.extensions.rvv.instruction import is_vector_instruction, is_config_instruction
from riscv.extensions.rvv.translation.temps import (
    TempRegisterAllocationError, TempRegisterAllocator,
)
from riscv.extensions.rvv.backends.rvv1024_transition import state_view
from riscv.extensions.rvv.backends.rvv1024_transition.temp_regs import RegisterAllocationError
from riscv.extensions.rvv.backends.rvv1024_transition.lowering_metadata import (
    lowering_metadata,
)
from riscv.extensions.rvv.translation.lowering import AssemblyFragments, lower_assembly_builder
from riscv.extensions.rvv.translation.contracts import (
    HandlerContext,
    InstructionValidationError,
    LoweringDiagnostic,
    LoweringPlan,
    LoweringResult,
    LoweringStatus,
    VStartPolicy,
)


def rvv1024_fallback_result(
    status: LoweringStatus, diagnostic: LoweringDiagnostic
) -> LoweringResult:
    """把结构化拒绝转换为反向过渡路径的 ``ebreak`` 合同。"""

    return LoweringResult.rejected(
        status,
        diagnostic,
        lines=(
            f"# RVV1024 fallback: {diagnostic.message}",
            "# fallback to ebreak",
            "    ebreak",
        ),
        fallback_kind="ebreak",
    )


class TransitionLowerer:
    """执行规格绑定 builder，并在结构化结果冻结前施加迁移 guard。

    guard、vcsr 恢复/写回和 ``vstart`` 清零仍位于 clobber 捕获作用域内；
    prepare 阶段只运行 validator，不会调用本对象或产生任何标签。
    """

    @staticmethod
    def _postprocess(
        context: HandlerContext,
        plan: LoweringPlan,
        fragments: AssemblyFragments,
    ) -> AssemblyFragments:
        """在每个迁移入口施加 profile guard，并维护 vcsr/vstart 写回。"""
        insn = context.instruction
        lines = list(fragments.body_lines)
        delayed_semantic_result = list(fragments.post_state_lines)
        if not lines:
            return AssemblyFragments((), tuple(delayed_semantic_result))
        temps = TempRegisterAllocator(insn, reserved_gprs=("t6",))
        state_vlenb_reg = temps.alloc_gpr()
        # Each guard comparison value is dead before the next CSR read.
        hardware_vlenb_reg = state_vlenb_reg
        vstart_reg = state_vlenb_reg
        scratch_reg = temps.alloc_gpr()

        reject_label = context.new_label("profile_reject")
        done_label = context.new_label("profile_ok")
        guarded: list[str] = [
            f"    # RVV256→RVV1024 迁移 profile guard: {insn.opcode}",
        ]
        state_view.emit_profile_guard(
            guarded,
            state_vlenb_reg,
            hardware_vlenb_reg,
            vstart_reg,
            scratch_reg,
            reject_label,
            require_zero_vstart=plan.spec.vstart_policy is VStartPolicy.REQUIRE_ZERO,
        )

        # CSR operations preserve vstart; config builders reset it before rd.
        hot_mac = (insn.opcode == "vmacc.vx" and context.state.sew == 16
                   and context.state.lmul == 1
                   and not any(str(op).endswith(".t") for op in insn.operands))
        is_data_vector = is_vector_instruction(insn) and not is_config_instruction(insn)
        body_lines = lines
        first_vector = next(
            (line.split()[0] for line in lines if line.lstrip().startswith("v")),
            None,
        )
        if is_data_vector:
            # A CSR write can serialize execution; equal state needs no write.
            vcsr_offset = state_view.CSR_OFFSETS["vcsr"] - state_view.CSR_OFFSETS["vstart"]
            guarded.append(f"    ld      {state_vlenb_reg}, {vcsr_offset}({scratch_reg})       # 源 CSR.vcsr")
            csr_equal = context.new_label("vcsr_equal")
            # The CSR page address is dead after loading the source vcsr.
            guarded.append(f"    csrr    {scratch_reg}, vcsr")
            guarded.append(f"    beq     {scratch_reg}, {state_vlenb_reg}, {csr_equal}")
            guarded.append(f"    csrw    vcsr, {state_vlenb_reg}        # 恢复源 vxrm/vxsat")
            guarded.append(f"{csr_equal}:")
            # vset resets vstart before the first data operation.
            if first_vector not in {"vsetvli", "vsetivli", "vsetvl"}:
                guarded.append("    csrw    vstart, zero                  # 一期只允许 vstart=0")

        guarded.extend(body_lines)

        if is_data_vector:
            # 非饱和指令不修改 vcsr；保留入口恢复即可保证硬件与状态块一致。
            if "vcsr" in plan.spec.state_writes:
                guarded.append(f"    csrr    {state_vlenb_reg}, vcsr       # 捕获目标执行后的 vcsr")
                state_view.emit_store_csr(guarded, state_vlenb_reg, scratch_reg, "vcsr")
            if hot_mac:
                # Guarded zero stays zero: this MAC cannot write the disjoint CSR page.
                guarded.append("    # Guarded zero source vstart remains zero: only vector payload is written.")
            else:
                state_view.emit_clear_state_vstart(guarded, scratch_reg)

        # 客体标量结果若写 t6，必须等状态写回完成后再提交；它仍属于正常
        # 路径，必须放在跳过拒绝分支的无条件跳转之前。
        guarded.extend(delayed_semantic_result)

        # guard 的拒绝分支必须跳过正常正文；不能让顺序执行自然跌入 ebreak。
        guarded.append(f"    j       {done_label}")
        guarded.append(f"{reject_label}:")
        guarded.append("    ebreak                                  # profile 或 vstart 不满足迁移前提")
        guarded.append(f"{done_label}:")
        return AssemblyFragments(tuple(guarded))

    def __call__(
        self, context: HandlerContext, plan: LoweringPlan
    ) -> LoweringResult:
        metadata = lowering_metadata(plan.spec)
        builder = metadata.builder
        if not callable(builder):
            raise TypeError(
                f"{plan.spec.opcode} 的过渡规格缺少 assembly builder"
            )
        try:
            return lower_assembly_builder(
                context,
                plan,
                builder,
                postprocessor=self._postprocess,
            )
        except (RegisterAllocationError, TempRegisterAllocationError) as exc:
            raise InstructionValidationError(context.instruction, str(exc)) from exc


TRANSITION_LOWERER = TransitionLowerer()


__all__ = ["TRANSITION_LOWERER", "TransitionLowerer", "rvv1024_fallback_result"]
