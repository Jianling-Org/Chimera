"""后端 profile、能力入口与标签会话绑定。"""

from __future__ import annotations

from riscv.extensions.rvv.translation.contracts import BackendProfile
from riscv.extensions.rvv.runtime.geometry import (
    RVV256_TO_RVV1024_GEOMETRY,
    TranslationGeometry,
)
from riscv.extensions.rvv.translation.contracts import (
    HandlerContext,
    LoweringDiagnostic,
    LoweringPlan,
    LoweringResult,
    LoweringStatus,
)
from riscv.extensions.rvv.translation.temps import TempRegisterAllocator
from riscv.extensions.rvv.backends.rvv1024_transition.lowering import rvv1024_fallback_result
from riscv.extensions.rvv.backends.rvv1024_transition.specs import TRANSITION_REGISTRY


def make_transition_profile(
    *,
    source_vlenb: int = RVV256_TO_RVV1024_GEOMETRY.source_vlenb,
    target_vlenb: int = RVV256_TO_RVV1024_GEOMETRY.target_vlenb,
    runtime_vtype_guard: bool = True,
    geometry: TranslationGeometry | None = None,
) -> BackendProfile:
    """建立过渡后端配置，明确 instruction failure 的 fallback 策略。

    本后端只接受 32→128；显式 geometry 与数值方向参数必须一致。
    """

    resolved = RVV256_TO_RVV1024_GEOMETRY
    if (source_vlenb, target_vlenb) != (resolved.source_vlenb, resolved.target_vlenb):
        raise ValueError("过渡 profile 只支持 RVV256→RVV1024 (32→128)")
    if geometry is not None and geometry != resolved:
        raise ValueError("过渡 profile 的 geometry 必须为 RVV256→RVV1024 (32→128)")

    return BackendProfile(
        name="rvv256-to-rvv1024-transition-experimental",
        source_vlenb=resolved.source_vlenb,
        target_vlenb=resolved.target_vlenb,
        # 可安全表示为单条 ebreak 的指令级失败不再阻断整份程序；
        # CFG/vtype 预检仍保留，用于选择正常 lowering 或安全 fallback。
        fallback_policy="ebreak",
        preflight_policy=(
            "mixed-unknown-runtime-guard" if runtime_vtype_guard else "strict"
        ),
        runtime_vtype_dispatch=runtime_vtype_guard,
    )


class RVV1024Dispatcher:
    """分发新路径首批 handler，并统一注入迁移 profile 与 CSR 收尾合同。"""

    def __init__(self):
        self._loop_counter = 0
        self._emission_session = None
        # Registry 在模块导入期构造且完全不可变；PreparedTranslation 因而可
        # 在 JAL 多轮发射中新建 dispatcher，而不受 bound-method 身份影响。
        self.registry = TRANSITION_REGISTRY

    def get_loop_label(self, prefix: str = "transition") -> str:
        """生成程序级共享 dispatcher 中仍唯一的局部标签。"""
        if self._emission_session is None:
            index = self._loop_counter
            self._loop_counter += 1
        else:
            index = self._emission_session.next_label_index(
                "rvv1024-transition-dispatcher"
            )
        label = f".L_rvv1024_{prefix}_{index}"
        return label

    def bind_emission_session(self, session) -> None:
        """程序模式把所有过渡 handler 标签编号绑定到本轮会话。"""

        self._emission_session = session

    def handles_scalar_instruction(self, insn) -> bool:
        """把向量 CSR 读取从 emitter 的普通标量路径截获。"""
        return self.registry.handles_scalar_instruction(insn)

    def is_vtype_independent_instruction(self, insn) -> bool:
        """判断可在未知 vtype 下安全处理的迁移指令。

        整寄存器 move 只按固定源物理字节数传输；向量 CSR 读取也只是读取
        已保存的状态字段。``vsm.v`` 则固定以 e8,m2 建立 source ``vl``，
        只写 ``ceil(VL/8)`` 个 mask byte，故同样不需要猜测 source vtype。
        这些 form 都不能因为调用点前没有 ``vset*`` 而被预检误拒绝；普通
        逐元素指令仍必须具有可解释的源端 vtype。
        """
        spec = self.registry.get(insn.opcode)
        return bool(spec and spec.vtype_independent)

    def make_context(
        self,
        insn,
        state,
        allocator,
        *,
        emission_session=None,
    ) -> HandlerContext:
        """构造 plan/lower 共用上下文；布局来自唯一 ABI 对象。"""

        if emission_session is not None:
            self.bind_emission_session(emission_session)
        return HandlerContext(
            instruction=insn,
            state=state,
            new_label=self.get_loop_label,
            layout=allocator,
            temp_register_allocator=TempRegisterAllocator(
                insn, reserved_gprs=("t6",)
            ),
        )

    def plan(
        self,
        context: HandlerContext,
        *,
        vtype_candidates: tuple[object, ...] = (),
    ) -> LoweringPlan:
        return self.registry.plan(context, vtype_candidates=vtype_candidates)

    def lower(
        self, context: HandlerContext, plan: LoweringPlan
    ) -> LoweringResult:
        return self.registry.lower(context, plan)

    def fallback_result(self, insn, reason: str) -> LoweringResult:
        """生成反向过渡路径统一的 ``ebreak`` 诊断结果。"""

        return rvv1024_fallback_result(
            LoweringStatus.UNSUPPORTED,
            LoweringDiagnostic("unsupported-vector", reason),
        )
