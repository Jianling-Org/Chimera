"""RVV 翻译数据契约与本轮会话；不依赖执行组件或具体后端。"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import replace, dataclass, field
from enum import Enum
from typing import Protocol, TypeAlias, Any, Callable
from riscv.extensions.rvv.analysis.config import StateTracker
from riscv.extensions.rvv.runtime.layout import SimulatedStateLayout
from riscv.extensions.rvv.translation.temps import TempRegisterAllocator
from riscv.frontend.model import RVInstruction


FALLBACK_POLICIES = frozenset({"raise", "ebreak", "reject"})


PREFLIGHT_POLICIES = frozenset({
    "none",
    "strict",
    "mixed-unknown-runtime-guard",
})


class LoweringStatus(str, Enum):
    """一条指令降低后的结构化状态。"""

    LOWERED = "lowered"
    UNSUPPORTED = "unsupported"
    INVALID = "invalid"


class MaskPolicy(str, Enum):
    """规格允许的执行掩码范围。"""

    FORBIDDEN = "forbidden"
    V0_ONLY = "v0-only"
    REQUIRED_V0 = "required-v0"


class TailPolicy(str, Enum):
    """目标值的 tail（尾部元素）保持策略。"""

    AGNOSTIC = "agnostic"
    UNDISTURBED = "undisturbed"
    NOT_APPLICABLE = "not-applicable"


class VStartPolicy(str, Enum):
    """当前后端对非零 ``vstart`` 的处理方式。"""

    REQUIRE_ZERO = "require-zero"
    CLEAR_ON_SUCCESS = "clear-on-success"
    ARCHITECTURAL = "architectural"
    NOT_APPLICABLE = "not-applicable"


@dataclass(frozen=True, slots=True)
class BackendProfile:
    """真正控制运行行为的后端配置。

    展示性字段、临时分配器类型和 registry 对象都不属于 profile；这些对象
    由具体 dispatcher/发射会话持有，避免 profile 声明与真实实现发生漂移。
    """

    name: str
    source_vlenb: int
    target_vlenb: int
    fallback_policy: str
    preflight_policy: str
    runtime_vtype_dispatch: bool = True

    def __post_init__(self) -> None:
        if not self.name:
            raise ValueError("BackendProfile.name 不能为空")
        if self.source_vlenb <= 0 or self.target_vlenb <= 0:
            raise ValueError("源/目标 VLENB 必须为正整数")
        if self.fallback_policy not in FALLBACK_POLICIES:
            raise ValueError(
                "未知 fallback 策略: "
                f"{self.fallback_policy!r}; 可选值为 {sorted(FALLBACK_POLICIES)}"
            )
        if self.preflight_policy not in PREFLIGHT_POLICIES:
            raise ValueError(
                "未知 preflight 策略: "
                f"{self.preflight_policy!r}; 可选值为 {sorted(PREFLIGHT_POLICIES)}"
            )


@dataclass(frozen=True, slots=True)
class LoweringDiagnostic:
    """机器可判定、同时可直接展示给用户的降低诊断。"""

    code: str
    message: str

    def __post_init__(self) -> None:
        if not self.code or not self.message:
            raise ValueError("降低诊断的 code/message 不能为空")


@dataclass(frozen=True, slots=True)
class HandlerContext:
    """传给 validator/lowerer 的单条指令上下文。

    标签分配由后端绑定的 new_label 提供；handler 不持有 dispatcher 或程序会话。
    """

    instruction: RVInstruction
    state: StateTracker
    new_label: Callable[[str], str]
    layout: SimulatedStateLayout
    temp_register_allocator: TempRegisterAllocator
    spec: "InstructionSpec | None" = None

    def with_spec(self, spec: "InstructionSpec") -> "HandlerContext":
        return replace(self, spec=spec)


Validator: TypeAlias = Callable[[HandlerContext], tuple[str, ...]]


Lowerer: TypeAlias = Callable[[HandlerContext, "LoweringPlan"], "LoweringResult"]


RegisterResolver: TypeAlias = Callable[[HandlerContext, "LoweringPlan"], frozenset[str]]


ScalarInstructionMatcher: TypeAlias = Callable[[Any], bool]


def _empty_registers(_context: HandlerContext, _plan: "LoweringPlan") -> frozenset[str]:
    return frozenset()


@dataclass(frozen=True, slots=True)
class InstructionSpec:
    """一个 opcode 的唯一能力与语义事实来源。"""

    opcode: str
    category: str
    operand_forms: tuple[str, ...]
    supported_sews: frozenset[int]
    supported_lmuls: frozenset[float]
    mask_policy: MaskPolicy
    tail_policy: TailPolicy
    vstart_policy: VStartPolicy
    reads_old_vd: bool
    vtype_independent: bool
    validator: Validator
    lowerer: Lowerer
    # 数据驱动指令族和复杂 handler 都必须在构造规格时明确给出这些语义轴；
    # 它们没有“后端稍后决定”的默认值，避免不完整规格进入 registry。
    target_mnemonic: str
    operand_order: tuple[str, ...]
    signedness: str
    rounding_policy: str
    semantic_inputs: RegisterResolver = _empty_registers
    semantic_outputs: RegisterResolver = _empty_registers
    state_reads: frozenset[str] = frozenset()
    state_writes: frozenset[str] = frozenset()
    # 少量 CSR 指令在解析器中属于“标量外观”，但其语义必须访问模拟向量
    # 状态。截获条件属于 opcode 能力规格，而不是 dispatcher 私有白名单；
    # None 表示该规格永远不从普通标量路径截获。
    scalar_instruction_matcher: ScalarInstructionMatcher | None = None
    # 复杂后端可把只读规划描述放入 lowering_metadata。字段只承载静态事实，
    # 不能包含标签或汇编行。
    lowering_metadata: Any = None

    def __post_init__(self) -> None:
        if not self.opcode or not self.category:
            raise ValueError("InstructionSpec 的 opcode/category 不能为空")
        if not self.operand_forms:
            raise ValueError(f"{self.opcode} 必须显式声明至少一个 operand form")
        if not isinstance(self.target_mnemonic, str) or not self.target_mnemonic:
            raise ValueError(f"{self.opcode} 必须显式声明 target_mnemonic")
        if not self.operand_order or any(not role for role in self.operand_order):
            raise ValueError(f"{self.opcode} 必须显式声明非空 operand_order")
        if self.signedness in {
            "",
            "backend-defined",
            "opcode-explicit",
            "handler-explicit",
        }:
            raise ValueError(f"{self.opcode} 必须声明实际 signedness，不能使用占位词")
        if self.rounding_policy in {
            "",
            "backend-defined",
            "opcode-explicit-vxrm-or-exact",
        }:
            raise ValueError(
                f"{self.opcode} 必须声明实际 rounding_policy，不能使用占位词"
            )


@dataclass(frozen=True, slots=True)
class LoweringPlan:
    """prepare 阶段产生、可跨多轮发射复用的静态计划。"""

    instruction: RVInstruction
    spec: InstructionSpec
    normalized_operands: tuple[str, ...]
    vtype_candidates: tuple[Any, ...] = ()

    def __post_init__(self) -> None:
        if self.instruction is None:
            raise ValueError("LoweringPlan.instruction 不能为空")
        if self.spec.opcode != self.instruction.opcode:
            raise ValueError(
                "LoweringPlan 的规格与指令 opcode 不一致: "
                f"{self.spec.opcode!r} != {self.instruction.opcode!r}"
            )


@dataclass(frozen=True, slots=True)
class LoweringResult:
    """不可变的单条指令降低结果。

    调用方必须显式读取 ``assembly_lines``。这里刻意不实现迭代、索引或
    ``len()``，避免结构化结果再次被当成旧 ``list[str]`` handler 返回值；
    状态、诊断和破坏集合也就不会在只消费汇编文本时被意外丢弃。
    """

    assembly_lines: tuple[str, ...]
    status: LoweringStatus
    diagnostics: tuple[LoweringDiagnostic, ...] = ()
    clobbered_gprs: frozenset[str] = frozenset()
    clobbered_fprs: frozenset[str] = frozenset()
    clobbered_vregs: frozenset[str] = frozenset()
    semantic_inputs: frozenset[str] = frozenset()
    semantic_outputs: frozenset[str] = frozenset()
    state_reads: frozenset[str] = frozenset()
    state_writes: frozenset[str] = frozenset()
    fallback_kind: str | None = None

    def __post_init__(self) -> None:
        if any(not isinstance(line, str) for line in self.assembly_lines):
            raise TypeError("LoweringResult.assembly_lines 只能包含字符串")
        if self.status is LoweringStatus.LOWERED and self.fallback_kind is not None:
            raise ValueError("成功降低结果不能携带 fallback_kind")
        if self.status is not LoweringStatus.LOWERED and not self.diagnostics:
            raise ValueError("失败降低结果必须携带结构化诊断")

    @classmethod
    def lowered(
        cls,
        lines: Sequence[str],
        *,
        clobbered_gprs: frozenset[str] = frozenset(),
        clobbered_fprs: frozenset[str] = frozenset(),
        clobbered_vregs: frozenset[str] = frozenset(),
        semantic_inputs: frozenset[str] = frozenset(),
        semantic_outputs: frozenset[str] = frozenset(),
        state_reads: frozenset[str] = frozenset(),
        state_writes: frozenset[str] = frozenset(),
    ) -> "LoweringResult":
        return cls(
            assembly_lines=tuple(lines),
            status=LoweringStatus.LOWERED,
            clobbered_gprs=clobbered_gprs,
            clobbered_fprs=clobbered_fprs,
            clobbered_vregs=clobbered_vregs,
            semantic_inputs=semantic_inputs,
            semantic_outputs=semantic_outputs,
            state_reads=state_reads,
            state_writes=state_writes,
        )

    @classmethod
    def rejected(
        cls,
        status: LoweringStatus,
        diagnostic: LoweringDiagnostic,
        *,
        lines: Sequence[str] = (),
        fallback_kind: str | None = None,
    ) -> "LoweringResult":
        if status is LoweringStatus.LOWERED:
            raise ValueError("rejected() 不能构造成功状态")
        return cls(
            assembly_lines=tuple(lines),
            status=status,
            diagnostics=(diagnostic,),
            fallback_kind=fallback_kind,
        )

    @property
    def is_lowered(self) -> bool:
        return self.status is LoweringStatus.LOWERED

    def with_assembly(self, lines: Sequence[str]) -> "LoweringResult":
        return replace(self, assembly_lines=tuple(lines))

    def with_metadata(
        self,
        *,
        clobbered_gprs: frozenset[str] | None = None,
        clobbered_fprs: frozenset[str] | None = None,
        clobbered_vregs: frozenset[str] | None = None,
        semantic_inputs: frozenset[str] | None = None,
        semantic_outputs: frozenset[str] | None = None,
        state_reads: frozenset[str] | None = None,
        state_writes: frozenset[str] | None = None,
    ) -> "LoweringResult":
        return replace(
            self,
            clobbered_gprs=self.clobbered_gprs if clobbered_gprs is None else clobbered_gprs,
            clobbered_fprs=self.clobbered_fprs if clobbered_fprs is None else clobbered_fprs,
            clobbered_vregs=self.clobbered_vregs if clobbered_vregs is None else clobbered_vregs,
            semantic_inputs=self.semantic_inputs if semantic_inputs is None else semantic_inputs,
            semantic_outputs=self.semantic_outputs if semantic_outputs is None else semantic_outputs,
            state_reads=self.state_reads if state_reads is None else state_reads,
            state_writes=self.state_writes if state_writes is None else state_writes,
        )


class InstructionValidationError(ValueError):
    """validator 拒绝某个已注册 opcode 的具体 form。"""

    def __init__(
        self,
        instruction: RVInstruction,
        detail: str,
        *,
        status: LoweringStatus = LoweringStatus.INVALID,
        code: str = "invalid-form",
    ):
        if status is LoweringStatus.LOWERED:
            raise ValueError("InstructionValidationError 不能使用 LOWERED 状态")
        self.instruction = instruction
        self.detail = detail
        self.status = status
        self.diagnostic = LoweringDiagnostic(code=code, message=detail)
        super().__init__(detail)


class UnsupportedInstructionError(RuntimeError):
    """后端遇到未注册或当前形态未实现的指令。

    所有后端共用这一异常类型，发射器因此可以按类型选择 fallback
    策略，而不必比较异常类名字符串。消息格式沿用既有 CLI 合同。
    """

    def __init__(self, instruction: RVInstruction, detail: str | None = None):
        self.instruction = instruction
        # ``insn`` 是既有测试和调用方使用的属性名，属于公开兼容边界。
        self.insn = instruction
        self.detail = detail
        op_str = f" {instruction.op_str}" if instruction.op_str else ""
        message = (
            f"Unsupported instruction at 0x{instruction.address:04x}: "
            f"{instruction.opcode}{op_str}"
        )
        if detail:
            message = f"{message} ({detail})"
        super().__init__(message)


class BackendDispatcherProtocol(Protocol):
    """后端 dispatcher 必须提供的结构化接口。"""

    def make_context(
        self,
        insn: Any,
        state: Any,
        allocator: Any,
        *,
        emission_session: Any = None,
    ) -> HandlerContext:
        ...

    def plan(
        self,
        context: HandlerContext,
        *,
        vtype_candidates: tuple[object, ...] = (),
    ) -> LoweringPlan:
        ...

    def lower(self, context: HandlerContext, plan: LoweringPlan) -> LoweringResult:
        ...

    def get_loop_label(self, prefix: str = "loop") -> str:
        ...

    def bind_emission_session(self, session: Any) -> None:
        ...

    def handles_scalar_instruction(self, insn: Any) -> bool:
        ...

    def is_vtype_independent_instruction(self, insn: Any) -> bool:
        ...

    def fallback_result(self, insn: Any, reason: str) -> "LoweringResult | None":
        """返回该后端品牌化的运行时 fallback 结果。

        只有 ``fallback_policy=ebreak`` 的后端需要实现；返回 ``None`` 表示
        使用 core 的通用 ebreak 模板。fail-closed（``raise``/``reject``）
        后端不会被调用。ebreak 的注释文本属于后端对外合同，由后端而不是
        core 统一生产，避免同一策略出现两种诊断文案。
        """
        ...


@dataclass
class EmissionSession:
    """一轮发射独占的可变状态，不能写回准备结果。"""

    label_counters: dict[str, int] = field(default_factory=dict)
    preflight_plan_index: dict[tuple[int, tuple[Any, ...]], Any] = field(
        default_factory=dict
    )

    def next_label_index(self, namespace: str) -> int:
        """分配本轮、指定后端命名空间内的确定性标签编号。"""

        if not namespace:
            raise ValueError("标签命名空间不能为空")
        index = self.label_counters.get(namespace, 0)
        self.label_counters[namespace] = index + 1
        return index
