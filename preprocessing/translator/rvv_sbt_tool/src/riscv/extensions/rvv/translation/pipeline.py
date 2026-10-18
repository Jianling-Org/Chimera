"""RVV 翻译准备与发射生命周期：一次分析、每轮独立会话。"""

from __future__ import annotations

from riscv.frontend.analysis import analyze_structure, validate_structure
from riscv.extensions.rvv.analysis.dataflow import VectorConfigAnalyzer
from riscv.extensions.rvv.analysis.model import ProgramAnalysis, VTypeSpec, parse_init_vtype
from riscv.extensions.rvv.instruction import is_vector_instruction
from dataclasses import dataclass, field
from riscv.codegen.control_flow import EmissionOptions
from typing import Any, Callable, Iterator, Mapping
from riscv.extensions.rvv.translation.contracts import BackendProfile, EmissionSession
from riscv.frontend.model import RVFunction, RVProgram


def analyze_program(program: RVProgram, *, initial_vtype: VTypeSpec | None = None) -> ProgramAnalysis:
    if not isinstance(program, RVProgram):
        raise TypeError("analyze_program() requires RVProgram")
    structure = analyze_structure(program)
    return VectorConfigAnalyzer().analyze_program(program, structure, initial_vtype=initial_vtype)


_PREPARED_FACTORY_TOKEN = object()


@dataclass(frozen=True)
class PreparedTranslation:
    """由流水线独占构造的程序级准备结果。"""

    program: RVProgram
    analysis: ProgramAnalysis
    backend_profile: BackendProfile
    init_vtype: str | None = None
    preflight_plans: tuple[Any, ...] = ()
    _factory_token: object = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        if self._factory_token is not _PREPARED_FACTORY_TOKEN:
            raise TypeError("PreparedTranslation 只能由 TranslationPipeline.prepare() 构造")

    @classmethod
    def _from_pipeline(
        cls,
        *,
        program: RVProgram,
        analysis: ProgramAnalysis,
        backend_profile: BackendProfile,
        init_vtype: str | None,
        preflight_plans: tuple[Any, ...],
    ) -> "PreparedTranslation":
        """供 ``TranslationPipeline.prepare()`` 使用的唯一构造入口。"""

        return cls(
            program=program,
            analysis=analysis,
            backend_profile=backend_profile,
            init_vtype=init_vtype,
            preflight_plans=preflight_plans,
            _factory_token=_PREPARED_FACTORY_TOKEN,
        )


@dataclass(frozen=True)
class EmissionContext:
    """向发射组件暴露准备结果和本轮状态的只读组合。"""

    prepared: PreparedTranslation
    options: EmissionOptions
    session: EmissionSession

    @property
    def program(self) -> RVProgram:
        return self.prepared.program

    @property
    def analysis(self) -> ProgramAnalysis:
        return self.prepared.analysis

    @property
    def backend_profile(self) -> BackendProfile:
        return self.prepared.backend_profile


def _validate_analyzed_program(
    program: RVProgram,
    analysis: ProgramAnalysis,
) -> None:
    """校验刚生成的分析结构，不再次计算输入指纹。"""

    validate_structure(program, analysis.structure)
    for function in program.functions:
        if not function.instructions:
            continue
        function_analysis = analysis.functions.get(function.start_addr)
        if function_analysis is None:
            raise ValueError(
                f"函数 {function.name}@0x{function.start_addr:x} 缺少 FunctionAnalysis"
            )
        for instruction in function.instructions:
            if is_vector_instruction(instruction) and instruction.address not in function_analysis.instructions:
                raise ValueError(
                    f"向量指令 0x{instruction.address:x} 缺少 InstructionAnalysis"
                )


class TranslationPipeline:
    """程序翻译唯一生命周期入口。"""

    def __init__(
        self,
        emitter: Any,
        *,
        preflight_planner: Callable[
            [RVProgram, ProgramAnalysis], tuple[Any, ...] | None
        ] | None = None,
    ):
        self.emitter = emitter
        # 后端预检器属于流水线工厂配置，不属于某次 prepare 调用参数。这样
        # 调用方不能在同一流水线中临时注入另一套分析/预检实现。
        self.preflight_planner = preflight_planner

    def prepare(
        self,
        program: RVProgram,
        *,
        backend_profile: BackendProfile,
        init_vtype: str | None = None,
    ) -> PreparedTranslation:
        """分析、校验并预检一次，之后不得再套用外部旧分析。"""

        if not isinstance(program, RVProgram):
            raise TypeError("prepare() 需要 RVProgram")
        # preflight_policy 必须真实控制准备阶段，而不是只出现在 profile
        # 的展示信息中。普通后端不得偷偷执行额外预检；fail-closed 后端也
        # 不能在缺失预检实现时继续进入发射阶段。
        requires_preflight = backend_profile.preflight_policy != "none"
        if requires_preflight and self.preflight_planner is None:
            raise ValueError(
                f"后端 {backend_profile.name} 的 preflight_policy="
                f"{backend_profile.preflight_policy!r} 要求提供预检器"
            )
        if not requires_preflight and self.preflight_planner is not None:
            raise ValueError(
                f"后端 {backend_profile.name} 声明 preflight_policy='none'，"
                "不得注入额外预检器"
            )
        initial_vtype = parse_init_vtype(init_vtype) if init_vtype else None
        analysis = (
            analyze_program(program, initial_vtype=initial_vtype)
            if initial_vtype is not None
            else analyze_program(program)
        )
        _validate_analyzed_program(program, analysis)
        plans = (
            ()
            if self.preflight_planner is None
            else (self.preflight_planner(program, analysis) or ())
        )
        return PreparedTranslation._from_pipeline(
            program=program,
            analysis=analysis,
            backend_profile=backend_profile,
            init_vtype=init_vtype,
            preflight_plans=tuple(plans),
        )

    @staticmethod
    def _new_session(prepared: PreparedTranslation) -> EmissionSession:
        """把不可变预检结果投影为本轮独占的稳定地址索引。

        指令对象身份不是程序语义，也无法跨序列化、复制或重建保持稳定；
        预检与发射之间只能使用计划规定的源指令地址和 vtype 候选定位。
        """

        plan_index: dict[tuple[int, tuple[Any, ...]], Any] = {}
        for plan in prepared.preflight_plans:
            key = (int(plan.instruction.address), tuple(plan.vtype_candidates))
            if key in plan_index:
                raise ValueError(
                    "PreparedTranslation 含重复后端计划: "
                    f"0x{plan.instruction.address:x} {plan.instruction.opcode} "
                    f"{plan.vtype_candidates}"
                )
            plan_index[key] = plan
        return EmissionSession(preflight_plan_index=plan_index)

    def emit_function(
        self,
        prepared: PreparedTranslation,
        *,
        state_factory: Callable[[], Any],
        allocator_factory: Callable[[], Any],
        dispatcher_factory: Callable[[], Any],
        emission_options: EmissionOptions = EmissionOptions(),
        text_only: bool = False,
        func_name: str | None = None,
        raw: bool = False,
        tls_state: bool = True,
    ) -> str:
        """使用准备结果发射单个函数，同时保持旧片段输出包装合同。"""

        functions = tuple(prepared.program.functions)
        if len(functions) != 1:
            raise ValueError(
                "emit_function() 要求 PreparedTranslation 恰好包含一个函数"
            )
        function: RVFunction = functions[0]
        context = EmissionContext(
            prepared,
            emission_options,
            self._new_session(prepared),
        )
        return self.emitter.emit_function(
            context=context,
            function=function,
            state_factory=state_factory,
            allocator_factory=allocator_factory,
            dispatcher_factory=dispatcher_factory,
            text_only=text_only,
            func_name=func_name or function.name or "translated_func",
            raw=raw,
            tls_state=tls_state,
        )

    def emit_program(
        self,
        prepared: PreparedTranslation,
        *,
        state_factory: Callable[[], Any],
        allocator_factory: Callable[[], Any],
        dispatcher_factory: Callable[[], Any],
        emission_options: EmissionOptions = EmissionOptions(),
        text_only: bool = False,
        lib_name: str = "main",
    ) -> str:
        return "\n".join(self.iter_emit_program(
            prepared, state_factory=state_factory,
            allocator_factory=allocator_factory, dispatcher_factory=dispatcher_factory,
            emission_options=emission_options, text_only=text_only, lib_name=lib_name,
        ))

    def iter_emit_program(
        self,
        prepared: PreparedTranslation,
        *,
        state_factory: Callable[[], Any],
        allocator_factory: Callable[[], Any],
        dispatcher_factory: Callable[[], Any],
        emission_options: EmissionOptions = EmissionOptions(),
        text_only: bool = False,
        lib_name: str = "main",
        program_context: dict[str, Mapping[int, str]] | None = None,
    ) -> Iterator[str]:
        """使用既有准备结果发射一轮，不重复分析或结构校验。"""

        session = self._new_session(prepared)
        context = EmissionContext(prepared, emission_options, session)
        return self.emitter.iter_chunks(
            context=context,
            state_factory=state_factory,
            allocator_factory=allocator_factory,
            dispatcher_factory=dispatcher_factory,
            text_only=text_only,
            init_vtype=prepared.init_vtype,
            lib_name=lib_name,
            program_context=program_context,
        )
