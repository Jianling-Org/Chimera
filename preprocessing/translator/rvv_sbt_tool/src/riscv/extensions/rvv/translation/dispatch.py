"""CFG 入口 vtype 的静态/运行时分发发射器。

程序级分析可为一条指令给出零个、一个或多个可能的源
vtype。本组件负责选择直接降低、单候选降低或运行时 CSR
分支；它只从 registry/``BackendProfile`` 读取能力，不维护另一份
opcode 白名单。
"""

from __future__ import annotations

from riscv.extensions.rvv.instruction import is_vector_instruction, is_config_instruction
from collections.abc import Sequence
from riscv.extensions.rvv.translation.temps import TempRegisterAllocator
from riscv.extensions.rvv.translation.contracts import EmissionSession, BackendProfile
from riscv.extensions.rvv.translation.contracts import (
    FALLBACK_POLICIES,
    BackendDispatcherProtocol,
    InstructionValidationError,
    LoweringDiagnostic,
    LoweringResult,
    LoweringStatus,
    UnsupportedInstructionError,
)
from riscv.extensions.rvv.runtime.access import STATE_BASE_MARKER
from riscv.extensions.rvv.runtime.layout import SimulatedStateLayout
from riscv.extensions.rvv.analysis.config import StateTracker
from riscv.extensions.rvv.runtime.layout import CSR_OFFSETS
from riscv.extensions.rvv.analysis.model import InstructionAnalysis
from riscv.frontend.model import RVInstruction
from riscv.extensions.rvv.analysis.model import VTypeSpec


class VTypeDispatchEmitter:
    """将一条指令的 CFG vtype 事实转换为结构化降低结果。"""

    @staticmethod
    def handles(insn: RVInstruction, dispatcher: BackendDispatcherProtocol) -> bool:
        return is_vector_instruction(insn) or dispatcher.handles_scalar_instruction(insn)

    def dispatch(
        self,
        insn: RVInstruction,
        state: StateTracker,
        allocator: SimulatedStateLayout,
        dispatcher: BackendDispatcherProtocol,
        *,
        instruction_analysis: InstructionAnalysis | None = None,
        session: EmissionSession | None = None,
        profile: BackendProfile | None = None,
        fallback_policy: str = "raise",
    ) -> LoweringResult:
        """根据分析候选选择直接、单候选或运行时 vtype 分发。"""

        # 程序模式只能服从 prepare 固化的 profile；即使内部调用方误传另一
        # 个字符串，也不能覆盖后端的 fail-closed/ebreak 合同。片段模式
        # 没有 PreparedTranslation，故由三条公开入口显式传入同一 profile 字段。
        if profile is not None:
            fallback_policy = profile.fallback_policy
            dispatcher.bind_emission_session(session)
        if fallback_policy not in FALLBACK_POLICIES:
            raise ValueError(f"未知 fallback 策略: {fallback_policy!r}")

        # 被后端截获的向量 CSR 标量指令不依赖 vtype，不能把“没有候选”当成
        # unknown vector state。
        if instruction_analysis is not None and not is_vector_instruction(insn):
            instruction_analysis = None

        known_vtypes = (
            list(instruction_analysis.known_specs())
            if instruction_analysis is not None
            else []
        )
        has_unknown_vtype = bool(
            instruction_analysis is not None
            and instruction_analysis.has_unknown_candidate()
        )
        runtime_dispatch_enabled = (
            profile.runtime_vtype_dispatch if profile is not None else True
        )

        # vset* 的入站 vtype 不参与自身语义：字面 form 指定
        # 新 vtype，vsetvl 则从 rs2 运行时取值。
        if is_config_instruction(insn):
            return self._dispatch_with_state(
                insn,
                state,
                allocator,
                dispatcher,
                session=session,
                fallback_policy=fallback_policy,
            )

        vtype_independent = dispatcher.is_vtype_independent_instruction(insn)
        if vtype_independent:
            return self._dispatch_with_state(
                insn,
                state,
                allocator,
                dispatcher,
                session=session,
                fallback_policy=fallback_policy,
            )
        if not known_vtypes and not has_unknown_vtype:
            return self._dispatch_with_state(
                insn,
                state,
                allocator,
                dispatcher,
                session=session,
                fallback_policy=fallback_policy,
            )
        if not known_vtypes:
            return self._failure_result(
                insn,
                "source vtype analysis contains only unknown entries",
                fallback_policy,
                dispatcher=dispatcher,
            )

        if len(known_vtypes) == 1 and not has_unknown_vtype:
            case_state = self._state_for_source_vtype(state, known_vtypes[0])
            result = self._dispatch_with_state(
                insn,
                case_state,
                allocator,
                dispatcher,
                session=session,
                vtype_candidates=(known_vtypes[0],),
                fallback_policy=fallback_policy,
            )
            return result

        if not runtime_dispatch_enabled:
            return self._failure_result(
                insn,
                "backend profile disables runtime vtype dispatch",
                fallback_policy,
                dispatcher=dispatcher,
            )

        result = self._emit_runtime_dispatch(
            insn,
            state,
            allocator,
            dispatcher,
            known_vtypes,
            session=session,
            fallback_policy=fallback_policy,
        )
        return result

    def _dispatch_with_state(
        self,
        insn: RVInstruction,
        state: StateTracker,
        allocator: SimulatedStateLayout,
        dispatcher: BackendDispatcherProtocol,
        *,
        session: EmissionSession | None,
        fallback_policy: str,
        vtype_candidates: tuple[VTypeSpec, ...] = (),
    ) -> LoweringResult:
        """消费 prepare 产生的计划，或在片段模式现场计划/降低。"""

        try:
            plan = None
            if session is not None and session.preflight_plan_index:
                key = (int(insn.address), tuple(vtype_candidates))
                plan = session.preflight_plan_index.get(key)
                if plan is None:
                    raise RuntimeError(
                        "发射阶段缺少 prepare 已验证计划: "
                        f"0x{insn.address:x} {insn.opcode} {vtype_candidates}"
                    )
            backend_context = dispatcher.make_context(
                insn,
                state,
                allocator,
                emission_session=session,
            )
            if plan is None:
                plan = dispatcher.plan(
                    backend_context,
                    vtype_candidates=tuple(vtype_candidates),
                )
            result = dispatcher.lower(backend_context, plan)
        except InstructionValidationError as exc:
            return self._failure_result(
                insn, exc.detail, fallback_policy, dispatcher=dispatcher
            )
        except UnsupportedInstructionError as exc:
            return self._failure_result(
                insn, str(exc), fallback_policy, dispatcher=dispatcher
            )

        if not isinstance(result, LoweringResult):
            raise TypeError(
                f"{type(dispatcher).__name__}.lower() 必须返回 LoweringResult"
            )
        if not result.is_lowered:
            reason = "; ".join(
                diagnostic.message for diagnostic in result.diagnostics
            )
            # RVV256 dispatcher 已经返回结构化 ``ebreak`` 结果时，片段路径
            # 直接保留其历史诊断文本；运行时多候选会在外层补充候选信息。
            if (
                fallback_policy == "ebreak"
                and result.fallback_kind == "ebreak"
            ):
                return result
            return self._failure_result(
                insn, reason, fallback_policy, dispatcher=dispatcher
            )
        return result

    @staticmethod
    def _state_for_source_vtype(
        state: StateTracker, source_vtype: VTypeSpec
    ) -> StateTracker:
        case_state = state.clone()
        case_state.apply_vtype_spec(source_vtype)
        return case_state

    def _emit_runtime_dispatch(
        self,
        insn: RVInstruction,
        state: StateTracker,
        allocator: SimulatedStateLayout,
        dispatcher: BackendDispatcherProtocol,
        known_vtypes: Sequence[VTypeSpec],
        *,
        session: EmissionSession | None,
        fallback_policy: str,
    ) -> LoweringResult:
        """为多个 CFG 候选发射 CSR.vtype 运行时分支。"""

        temps = TempRegisterAllocator(insn, reserved_gprs=("t6",))
        vtype_addr = temps.alloc_gpr()
        vtype_reg = temps.alloc_gpr()
        case_reg = temps.alloc_gpr()
        case_labels = [
            self._get_dispatch_label(dispatcher, f"vtype_case_{index}")
            for index, _ in enumerate(known_vtypes)
        ]
        end_label = self._get_dispatch_label(dispatcher, "vtype_dispatch_end")

        lines = [
            f"    # runtime vtype dispatch for {insn.opcode} {insn.op_str}".rstrip(),
            f"    li      {vtype_addr}, {CSR_OFFSETS['vtype']:#x}",
            f"    add     {vtype_addr}, t6, {vtype_addr}  # {STATE_BASE_MARKER}",
            f"    ld      {vtype_reg}, 0({vtype_addr})      # dispatch on simulated CSR.vtype",
        ]
        case_results: list[LoweringResult] = []
        for label, source_vtype in zip(case_labels, known_vtypes):
            value = self._encode_source_vtype(state, source_vtype)
            lines.append(f"    li      {case_reg}, {value}       # {source_vtype}")
            lines.append(f"    beq     {vtype_reg}, {case_reg}, {label}")
        lines.extend((
            "    # No analyzed vtype case matched at runtime",
            "    ebreak",
        ))

        for label, source_vtype in zip(case_labels, known_vtypes):
            lines.append(f"{label}:")
            case_state = self._state_for_source_vtype(state, source_vtype)
            case_result = self._dispatch_analyzed_case(
                insn,
                case_state,
                allocator,
                dispatcher,
                source_vtype,
                session=session,
                fallback_policy=fallback_policy,
            )
            case_results.append(case_result)
            lines.extend(case_result.assembly_lines)
            lines.append(f"    j       {end_label}")
        lines.append(f"{end_label}:")

        return LoweringResult.lowered(
            lines,
            clobbered_gprs=frozenset({vtype_addr, vtype_reg, case_reg}).union(
                *(result.clobbered_gprs for result in case_results)
            ),
            clobbered_fprs=frozenset().union(
                *(result.clobbered_fprs for result in case_results)
            ),
            clobbered_vregs=frozenset().union(
                *(result.clobbered_vregs for result in case_results)
            ),
            semantic_inputs=frozenset().union(
                *(result.semantic_inputs for result in case_results)
            ),
            semantic_outputs=frozenset().union(
                *(result.semantic_outputs for result in case_results)
            ),
            state_reads=frozenset({"vtype"}).union(
                *(result.state_reads for result in case_results)
            ),
            state_writes=frozenset().union(
                *(result.state_writes for result in case_results)
            ),
        )

    def _dispatch_analyzed_case(
        self,
        insn: RVInstruction,
        case_state: StateTracker,
        allocator: SimulatedStateLayout,
        dispatcher: BackendDispatcherProtocol,
        source_vtype: VTypeSpec,
        *,
        session: EmissionSession | None,
        fallback_policy: str,
    ) -> LoweringResult:
        """降低一个已分析候选，将候选级不支持转为 ebreak。"""

        try:
            result = self._dispatch_with_state(
                insn,
                case_state,
                allocator,
                dispatcher,
                session=session,
                fallback_policy=fallback_policy,
                vtype_candidates=(source_vtype,),
            )
        except UnsupportedInstructionError as exc:
            return self._failure_result(
                insn,
                f"vtype case {source_vtype}: {exc}",
                fallback_policy,
                dispatcher=dispatcher,
            )
        if not result.is_lowered:
            detail = "; ".join(
                diagnostic.message for diagnostic in result.diagnostics
            )
            return self._failure_result(
                insn,
                f"vtype case {source_vtype}: {detail}",
                fallback_policy,
                dispatcher=dispatcher,
            )
        return result

    def _encode_source_vtype(
        self, state: StateTracker, source_vtype: VTypeSpec
    ) -> int:
        return self._state_for_source_vtype(
            state, source_vtype
        ).get_vtype_value()

    @staticmethod
    def _get_dispatch_label(
        dispatcher: BackendDispatcherProtocol, prefix: str
    ) -> str:
        """所有正式后端都必须由自己的标签命名空间分配标签。"""

        return dispatcher.get_loop_label(prefix)

    @staticmethod
    def _emit_unsupported_fallback(
        insn: RVInstruction, reason: str
    ) -> list[str]:
        return [
            f"    # Unsupported RVV instruction lowered to ebreak: "
            f"{insn.opcode} {insn.op_str}".rstrip(),
            f"    # fallback to ebreak; Reason: {reason}",
            "    ebreak",
        ]

    def _unsupported_result(
        self, insn: RVInstruction, reason: str
    ) -> LoweringResult:
        return LoweringResult.rejected(
            LoweringStatus.UNSUPPORTED,
            LoweringDiagnostic("unsupported-vector", reason),
            lines=self._emit_unsupported_fallback(insn, reason),
            fallback_kind="ebreak",
        )

    def _failure_result(
        self,
        insn: RVInstruction,
        reason: str,
        fallback_policy: str,
        dispatcher: BackendDispatcherProtocol | None = None,
    ) -> LoweringResult:
        """按 profile 把结构化失败转换为 ebreak 或 fail-closed 异常。

        ebreak 的注释文本是后端对外合同（例如 RVV256 的 ``RVV256 fallback``
        标记被 CLI 测试消费）；因此优先使用 dispatcher 提供的品牌化结果，
        仅当后端没有实现时退回 core 的通用模板。这样同一策略只有一种
        诊断文案来源。
        """

        if fallback_policy == "ebreak":
            branded = (
                None
                if dispatcher is None
                else dispatcher.fallback_result(insn, reason)
            )
            if branded is not None:
                return branded
            return self._unsupported_result(insn, reason)
        # ``raise``（标量）与 ``reject``（整文件过渡）都禁止输出半成品；
        # 两个名称保留了调用合同上的语义差别，异常类型则统一供 CLI 处理。
        raise UnsupportedInstructionError(insn, detail=reason)


__all__ = ["VTypeDispatchEmitter"]
