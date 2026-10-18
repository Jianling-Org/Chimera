"""后端 profile、能力入口与标签会话绑定。"""

from __future__ import annotations

from riscv.extensions.rvv.translation.contracts import BackendProfile
from riscv.extensions.rvv.runtime.geometry import (
    RVV1024_TO_RVV256_GEOMETRY,
    TranslationGeometry,
    geometry_for_direction,
)
from riscv.extensions.rvv.backends.rvv256.specs import build_rvv256_registry
from riscv.extensions.rvv.backends.rvv256.lowering import rvv256_fallback_result
from riscv.extensions.rvv.translation.temps import TempRegisterAllocator
from riscv.extensions.rvv.translation.contracts import (
    HandlerContext,
    LoweringDiagnostic,
    LoweringPlan,
    LoweringResult,
    LoweringStatus,
)
from riscv.frontend.model import RVInstruction


def make_rvv256_profile(
    *,
    wide_lmul: bool = True,
    source_vlenb: int | None = None,
    geometry: TranslationGeometry | None = None,
) -> BackendProfile:
    """构造 1024→256 profile，并验证方向几何已登记。

    ``source_vlenb`` 是兼容旧签名的参数；方向校验发生在 profile 构造期，
    因此 ``rvv_sbt_rvv.py`` 各入口传入非法 ``--vlenb``（例如 64/256）会
    在生成任何汇编之前被拒绝，而不是静默产出与状态槽布局矛盾的代码。
    ``geometry`` 允许显式传入，但必须与已登记方向一致。
    """

    resolved = geometry or RVV1024_TO_RVV256_GEOMETRY
    if source_vlenb is not None:
        # 经由白名单解析方向，未登记的组合立即失败。
        resolved = geometry_for_direction(
            source_vlenb, RVV1024_TO_RVV256_GEOMETRY.target_vlenb
        )
    elif geometry is not None:
        geometry_for_direction(geometry.source_vlenb, geometry.target_vlenb)
    return BackendProfile(
        name="rvv256-wide" if wide_lmul else "rvv256-conservative",
        source_vlenb=resolved.source_vlenb,
        target_vlenb=resolved.target_vlenb,
        fallback_policy="ebreak",
        preflight_policy="none",
    )


class RVV256Dispatcher:
    """
    256-bit RVV 指令分发器；配置、算术、掩码、访存和 CSR 能力均由唯一
    registry 的 ``InstructionSpec.category`` 派生，不再保存兼容 handler 表。
    """

    def __init__(self, wide_lmul: bool = True):
        """初始化 profile 专用 registry 和只读能力视图。

        ``wide_lmul=True`` 是默认宽 LMUL profile；``False`` 保留既有
        conservative（保守）路径。两种 profile 注册相同 opcode，仅掩码
        能力和 lowering 选择不同。
        """

        self._loop_counter = 0
        self._emission_session = None
        self.wide_lmul = bool(wide_lmul)
        self.registry = build_rvv256_registry(wide_lmul=self.wide_lmul)

    def make_context(
        self,
        insn,
        state,
        allocator,
        *,
        emission_session=None,
    ) -> HandlerContext:
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

    def get_loop_label(self, prefix: str = "loop") -> str:
        """
        生成唯一的循环标签

        :param prefix: 标签前缀
        :return: 唯一的标签名
        """
        if self._emission_session is None:
            index = self._loop_counter
            self._loop_counter += 1
        else:
            index = self._emission_session.next_label_index("rvv256-dispatcher")
        label = f".L_rvv256_{prefix}_{index}"
        return label

    def bind_emission_session(self, session) -> None:
        """程序模式把所有 handler 标签编号收口到本轮发射会话。"""

        self._emission_session = session

    def fallback_result(self, insn: RVInstruction, reason: str) -> LoweringResult:
        """RVV256 后端唯一的 ebreak 诊断文本生产者。

        ``fallback_policy=ebreak`` 时，无论失败发生在 registry 查找、
        validator 还是 builder 阶段，都由本方法统一生成带 ``RVV256
        fallback`` 标记的结构化结果，保证 CLI/测试只依赖一种文案。
        """

        return rvv256_fallback_result(
            LoweringStatus.UNSUPPORTED,
            LoweringDiagnostic("unsupported-vector", reason),
        )

    def handles_scalar_instruction(self, insn) -> bool:
        """判断本后端是否需要截获表面上属于标量的 vector CSR 指令。"""
        return self.registry.handles_scalar_instruction(insn)

    def is_vtype_independent_instruction(self, insn) -> bool:
        """
        判断指令是否完全不依赖当前 vl/vtype。

        该能力是 CFG unknown-vtype 门禁的一部分，必须保持窄范围。逐元素
        load/store 即使名称相似也不能加入，否则迁移时会按错误的 SEW/LMUL
        解释 ``simulated_cpu_state``。
        """
        spec = self.registry.get(insn.opcode)
        return bool(spec is not None and spec.vtype_independent)
