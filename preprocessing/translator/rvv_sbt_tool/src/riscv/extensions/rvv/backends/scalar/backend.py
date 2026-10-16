"""后端 profile、能力入口与标签会话绑定。"""

from __future__ import annotations

from riscv.extensions.rvv.translation.contracts import BackendProfile
from riscv.extensions.rvv.runtime.layout import DEFAULT_VLENB
from riscv.extensions.rvv.translation.contracts import (
    HandlerContext,
    LoweringPlan,
    LoweringResult,
)
from riscv.frontend.model import RVInstruction
from riscv.extensions.rvv.analysis.config import StateTracker
from riscv.extensions.rvv.runtime.layout import SimulatedStateLayout
from riscv.extensions.rvv.backends.scalar.specs import build_scalar_registry
from riscv.extensions.rvv.translation.temps import TempRegisterAllocator


def make_scalar_profile(*, vlenb: int = DEFAULT_VLENB) -> BackendProfile:
    """建立与调用方模拟 VLEN 一致的标量后端配置。"""

    return BackendProfile(
        name="scalar-rv64",
        source_vlenb=vlenb,
        target_vlenb=vlenb,
        fallback_policy="raise",
        preflight_policy="none",
    )


class ScalarDispatcher:
    """
    指令分发器：将 RVV 指令分发到对应的处理函数
    """

    def __init__(self):
        """
        初始化分发器，建立指令到处理函数的映射表
        """
        # 循环标签计数器 (实例变量，每个发射会话独占)
        self._loop_counter = 0
        self._emission_session = None

        self.registry = build_scalar_registry()


    def get_loop_label(self, prefix: str = "math") -> str:
        """
        生成唯一的循环标签 (实例方法，按发射会话维护)

        :param prefix: 标签前缀
        :return: 唯一标签字符串
        """
        if self._emission_session is None:
            index = self._loop_counter
            self._loop_counter += 1
        else:
            index = self._emission_session.next_label_index("scalar-dispatcher")
        label = f".L_{prefix}_loop_{index}"
        return label

    def bind_emission_session(self, session) -> None:
        """程序模式把标签所有权绑定到本轮 EmissionSession。"""

        self._emission_session = session
    def make_context(
        self,
        insn: RVInstruction,
        state: StateTracker,
        allocator: SimulatedStateLayout,
        *,
        emission_session=None,
    ) -> HandlerContext:
        """建立本条指令的不可变 handler 上下文。"""

        if emission_session is not None:
            self.bind_emission_session(emission_session)
        return HandlerContext(
            instruction=insn,
            state=state,
            new_label=self.get_loop_label,
            layout=allocator,
            # 结构化上下文保留本条指令的临时标量寄存器分配器。现有复杂
            # builder 仍可在局部建立独立分配阶段，但不再需要从四个散参数
            # 重新拼装默认分配器。
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

    def fallback_result(self, insn: RVInstruction, reason: str) -> None:
        """标量后端策略为 ``raise``，不提供任何运行时 fallback 文案。

        ``None`` 表示未提供后端专用模板；core 的 ebreak 策略可使用通用
        模板。当前 scalar profile 使用 raise，不执行运行时 fallback。
        """

        return None

    def is_vtype_independent_instruction(self, insn: RVInstruction) -> bool:
        spec = self.registry.get(insn.opcode)
        return bool(spec and spec.vtype_independent)

    def handles_scalar_instruction(self, insn: RVInstruction) -> bool:
        """截获对模拟向量 CSR 的访问。"""

        return self.registry.handles_scalar_instruction(insn)
