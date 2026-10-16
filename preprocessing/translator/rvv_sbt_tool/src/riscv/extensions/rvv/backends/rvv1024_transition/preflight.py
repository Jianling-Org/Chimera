"""RVV256→RVV1024 过渡翻译的 CFG/vtype 与 lowering 预检。

预检仍然在写出正式汇编前检查源状态布局和每条潜在迁移入口。启用
``allow_ebreak_fallback`` 后，可由单条 ``ebreak`` 安全表示的 lowering 失败
不再阻断整份程序；预检放弃这类程序的不完整计划，让发射阶段按后端 profile
重新规划并生成带诊断的 fallback。
"""

from __future__ import annotations

from riscv.extensions.rvv.instruction import is_vector_instruction, is_config_instruction
from dataclasses import dataclass
from typing import Iterable, Sequence

from riscv.extensions.rvv.analysis.model import LEGAL_LMULS
from riscv.extensions.rvv.translation.contracts import (
    InstructionValidationError,
    LoweringPlan,
    UnsupportedInstructionError,
)
from riscv.extensions.rvv.runtime.layout import SimulatedStateLayout
from riscv.extensions.rvv.analysis.config import StateTracker
from riscv.extensions.rvv.analysis.model import (
    FunctionAnalysis,
    InstructionAnalysis,
    ProgramAnalysis,
)
from riscv.frontend.model import RVProgram


# 新迁移后端的 source vtype 静态形状白名单。通用 StateTracker 为兼容历史
# 调试入口，会宽松地把某些 raw vtype 编码降成默认 e64/m1；过渡路径不能继承
# 这种行为，因为它随后会按错误的 RVV256 raw group 布局 Pack 状态。
_SUPPORTED_SOURCE_SEWS = frozenset({8, 16, 32, 64})
_SUPPORTED_SOURCE_LMULS = frozenset(LEGAL_LMULS)


def _raw_init_vtype_value(init_vtype: str) -> int | None:
    """若 ``--init-vtype`` 是 raw CSR 数值则返回其值，否则返回 ``None``。

    保持与 StateTracker 接口兼容：十进制和 ``0x`` 十六进制都属于 raw 形式；
    语义形式（例如 ``sew=32,lmul=1``）由后续 StateTracker 统一解析。
    """
    text = str(init_vtype).strip()
    if text.startswith(("0x", "0X")):
        return int(text, 16)
    if text.isdigit():
        return int(text, 10)
    return None


def validate_transition_init_vtype(init_vtype: str | None) -> None:
    """严格验证新路径显式提供的初始 source vtype。

    迁移器将该参数视为任意入口的 RVV256 物理组解释依据，故不能接受 vill、
    vtype[62:8] 保留位、保留 vlmul=100 或一期未实现的 SEW。通用
    StateTracker 仍保留其历史宽松解析，避免改变旧后端；严格门禁只属于本
    RVV256→RVV1024 过渡入口。
    """
    if not init_vtype:
        return

    try:
        raw_value = _raw_init_vtype_value(init_vtype)
    except ValueError as exc:
        raise ValueError(f"--init-vtype raw 数值无效: {init_vtype!r}") from exc

    if raw_value is not None:
        # VTYPE 是 XLEN=64 CSR；超出范围的 Python 整数也不能被隐式截断。
        if not 0 <= raw_value < (1 << 64):
            raise ValueError("--init-vtype raw 值必须位于 0..2^64-1")
        if raw_value & (1 << 63):
            raise ValueError("--init-vtype 含 vill 位，过渡路径拒绝未知 source vtype")
        if raw_value >> 8:
            raise ValueError(
                "--init-vtype 的 vtype[62:8] 保留位非零，过渡路径拒绝猜测 source 布局"
            )
        vsew = (raw_value >> 3) & 0x7
        vlmul = raw_value & 0x7
        if vsew > 3:
            raise ValueError(
                f"--init-vtype 的 vsew={vsew} 不在一期支持的 e8/e16/e32/e64 范围"
            )
        if vlmul == 0b100:
            raise ValueError("--init-vtype 使用保留 vlmul=100 编码")

    # 再借用统一 parser 验证语义形式，并以新路径实际支持的 static shape
    # 收束结果。这样 ``sew=128`` 或非标准 LMUL 不会等到某条数据指令才失败。
    probe = StateTracker(vlenb=32)
    probe.apply_init_vtype(init_vtype)
    if probe.sew not in _SUPPORTED_SOURCE_SEWS:
        raise ValueError(
            f"--init-vtype 的 SEW=e{probe.sew} 不在一期支持的 e8/e16/e32/e64 范围"
        )
    if probe.lmul not in _SUPPORTED_SOURCE_LMULS:
        raise ValueError(f"--init-vtype 的 LMUL={probe.lmul:g} 不受一期支持")


@dataclass(frozen=True)
class TransitionPreflightIssue:
    """一条不能进入过渡代码生成的源指令诊断。"""

    address: int
    opcode: str
    detail: str

    def format(self) -> str:
        return f"0x{self.address:x}: {self.opcode}: {self.detail}"


class TransitionPreflightError(RuntimeError):
    """存在不可恢复预检问题时抛出，调用方不得写出半成品汇编。"""

    def __init__(self, issues: Sequence[TransitionPreflightIssue]):
        self.issues = tuple(issues)
        message = "RVV256→RVV1024 过渡预检失败:\n" + "\n".join(
            f"  - {issue.format()}" for issue in self.issues
        )
        super().__init__(message)


def _is_vector_or_vector_csr(insn, dispatcher) -> bool:
    """与 ``ProgramEmitter`` 保持一致地识别需要后端处理的指令。"""
    if is_vector_instruction(insn):
        return True
    return dispatcher.handles_scalar_instruction(insn)


def _instruction_vtype_facts(
    analysis: InstructionAnalysis | None,
) -> tuple[list, bool]:
    """读取流水线显式传入的分析结果，不依赖指令对象上的派生缓存。"""

    if analysis is None:
        return [], False
    return list(analysis.known_specs()), analysis.has_unknown_candidate()


def _plan_one(
    insn,
    state,
    allocator,
    dispatcher,
    *,
    vtype_candidates: tuple[object, ...] = (),
) -> tuple[LoweringPlan | None, str | None, bool]:
    """只建立结构化计划；不得调用 lowerer 或生成任何汇编。"""

    try:
        context = dispatcher.make_context(
            insn,
            state,
            allocator,
        )
        plan = dispatcher.plan(context, vtype_candidates=vtype_candidates)
    except InstructionValidationError as exc:
        return None, exc.diagnostic.message, True
    except UnsupportedInstructionError as exc:
        return None, str(exc), True
    except ValueError as exc:
        # 形状、立即数和寄存器组门禁属于输入问题；不要吞掉
        # NameError/AttributeError 等 translator 编程错误。
        return None, str(exc), False
    return plan, None, False


def preflight_instruction_stream(
    instructions: Iterable,
    *,
    analysis: FunctionAnalysis,
    dispatcher_factory,
    source_vlenb: int = 32,
    init_vtype: str | None = None,
    allow_ebreak_fallback: bool = False,
) -> tuple[LoweringPlan, ...]:
    """预检线性指令流中的全部 V 指令。

    这里复用与真实生成相同的 ``StateTracker`` 更新规则。单函数/片段
    模式的入口状态由 ``--init-vtype`` 或线性 ``vset*`` 提供；程序分析必须
    通过显式 ``analysis`` 参数传入，并按每条指令的完整候选逐一检查。未知
    vtype 默认会被拒绝，因为迁移路径不能猜测源 RVV256 物理寄存器组；启用
    ``allow_ebreak_fallback`` 后，这类单条指令会由发射阶段生成 fallback。
    """
    validate_transition_init_vtype(init_vtype)
    dispatcher = dispatcher_factory()
    state = StateTracker(vlenb=source_vlenb)
    if init_vtype:
        state.apply_init_vtype(init_vtype)
        # StateTracker 的通用 init API 刻意不修改 config_str；对严格迁移预检
        # 而言，调用方显式播种就是“已知入口 vtype”，需单独留下来源标记。
        state.config_str = f"init:{init_vtype}"
    allocator = SimulatedStateLayout()
    issues: list[TransitionPreflightIssue] = []
    plans: list[LoweringPlan] = []
    fallback_required = False

    def record_issue(
        address: int,
        opcode: str,
        detail: str,
        *,
        recoverable: bool = True,
    ) -> None:
        nonlocal fallback_required
        if allow_ebreak_fallback and recoverable:
            fallback_required = True
            return
        issues.append(TransitionPreflightIssue(address, opcode, detail))
    # ``StateTracker`` 为兼容旧后端，会在 vsetvl 后保留上一份静态
    # SEW/LMUL；那份值不能被新路径误当作当前源 vtype。这里单独记录这一
    # 不确定性，直到后续字面 vset* 或 InstructionAnalysis 提供新形状。
    dynamic_vtype_after_vsetvl = False

    for insn in instructions:
        if not _is_vector_or_vector_csr(insn, dispatcher):
            continue

        # 配置指令自身不依赖前一条 vtype；handler 会在成功时推进 state。
        instruction_analysis = analysis.at(insn.address)
        known_specs, source_unknown = _instruction_vtype_facts(
            instruction_analysis
        )
        is_config = is_config_instruction(insn)
        vtype_independent = dispatcher.is_vtype_independent_instruction(insn)

        if (
            dynamic_vtype_after_vsetvl
            and not is_config
            and not known_specs
            and not vtype_independent
        ):
            record_issue(
                insn.address,
                insn.opcode,
                "前序 vsetvl 的 vtype 来自运行时寄存器，后续指令缺少静态 vtype 分析",
            )
            continue

        if (
            source_unknown
            and not known_specs
            and not state.config_str
            and not is_config
            and not vtype_independent
        ):
            # 片段入口经过 prepare 后会携带明确的 primary-entry unknown。
            # 对调用者而言，这仍是“既没有 --init-vtype，也没有前置
            # vset*”；保留原诊断以区别输入缺配置和 CFG 多路径歧义。
            record_issue(
                insn.address,
                insn.opcode,
                "缺少前置 vset* 或静态 vtype 分析",
            )
            continue

        if source_unknown and not is_config and not vtype_independent:
            record_issue(
                insn.address,
                insn.opcode,
                "入口 vtype 含 unknown 候选，过渡路径不能安全解释 RVV256 物理寄存器组",
            )
            continue

        if known_specs and not is_config and not vtype_independent:
            for candidate in known_specs:
                candidate_state = state.clone()
                candidate_state.apply_vtype_spec(candidate)
                plan, detail, recoverable = _plan_one(
                    insn,
                    candidate_state,
                    allocator,
                    dispatcher,
                    vtype_candidates=(candidate,),
                )
                if detail:
                    record_issue(
                        insn.address,
                        insn.opcode,
                        f"vtype {candidate}: {detail}",
                        recoverable=recoverable,
                    )
                elif plan is not None:
                    plans.append(plan)
            continue

        # 没有内部分析时，至少必须已有线性配置或由调用方 --init-vtype 播种。
        # ``StateTracker`` 的默认 e64,m1 是历史单元测试便利值，不能被误当成
        # 任意迁移入口的真实 vtype。
        if not is_config and not state.config_str and not vtype_independent:
            record_issue(
                insn.address,
                insn.opcode,
                "缺少前置 vset* 或静态 vtype 分析",
            )
            continue

        plan, detail, recoverable = _plan_one(
            insn,
            state,
            allocator,
            dispatcher,
        )
        if detail:
            record_issue(
                insn.address,
                insn.opcode,
                detail,
                recoverable=recoverable,
            )
        elif plan is not None:
            plans.append(plan)

        if is_config:
            if detail is None:
                # validator 始终在 clone 上检查配置；只有完整成功后才推进
                # 线性 preflight 状态，确保失败 form 不污染随后指令。
                state.update(insn)
            if insn.opcode == "vsetvl":
                dynamic_vtype_after_vsetvl = True
            elif insn.opcode in {"vsetvli", "vsetivli"} and detail is None:
                dynamic_vtype_after_vsetvl = False

    if issues:
        raise TransitionPreflightError(issues)
    if fallback_required:
        # 只保留完整成功程序的 plan；一旦存在 fallback，发射阶段必须重新
        # plan 全部指令，避免 session 把缺少计划的 fallback 当成流水线错误。
        return ()
    return tuple(plans)


def preflight_program(
    program: RVProgram,
    *,
    analysis: ProgramAnalysis,
    dispatcher_factory,
    source_vlenb: int = 32,
    init_vtype: str | None = None,
    allow_mixed_unknown_vtype: bool = True,
    allow_ebreak_fallback: bool = False,
) -> tuple[LoweringPlan, ...]:
    """按函数重置静态状态后预检完整 objdump 程序。

    程序 emitter 会为每条原始地址生成 ``branch_j_target_*``，也就是任一
    数据 V 指令都可能成为迁移入口。线性扫描中“前面刚好出现过 vset*”不能
    证明所有 CFG 前驱都具有同一 vtype；因此非 vtype-independent 的数据 V
    指令必须携带内部 ``InstructionAnalysis`` 产出的完整候选。单条/片段
    API 仍可使用显式 ``--init-vtype`` 或线性 vset*；程序模式在缺失此
    元数据时不会按文件顺序猜测 RVV256 raw group 布局，而是按 profile 选择
    诊断 + ``ebreak`` 或不可恢复失败。

    ``allow_mixed_unknown_vtype`` 默认启用：仅当分析同时给出至少一个完整已知
    候选时放行，生成器随后会读取模拟状态中的 source ``vtype``，对已知候选生成
    运行时分支，未命中候选则执行 ``ebreak``。unknown-only 指令默认拒绝；启用
    ``allow_ebreak_fallback`` 后则由发射阶段生成 fallback。两项都关闭可恢复
    旧的严格拒绝策略。
    """
    validate_transition_init_vtype(init_vtype)
    issues: list[TransitionPreflightIssue] = []
    plans: list[LoweringPlan] = []
    fallback_required = False

    def record_issue(
        address: int,
        opcode: str,
        detail: str,
        *,
        recoverable: bool = True,
    ) -> None:
        nonlocal fallback_required
        if allow_ebreak_fallback and recoverable:
            fallback_required = True
            return
        issues.append(TransitionPreflightIssue(address, opcode, detail))
    for function in program.functions:
        if not function.instructions:
            continue
        function_analysis = analysis.for_function(function.start_addr)
        if function_analysis is None:
            raise ValueError(
                f"函数 {function.name}@0x{function.start_addr:x} 缺少预检分析"
            )
        dispatcher = dispatcher_factory()
        state = StateTracker(vlenb=source_vlenb)
        if init_vtype:
            state.apply_init_vtype(init_vtype)
            state.config_str = f"init:{init_vtype}"
        allocator = SimulatedStateLayout()
        for insn in function.instructions:
            if not _is_vector_or_vector_csr(insn, dispatcher):
                continue
            instruction_analysis = function_analysis.at(insn.address)
            known_specs, source_unknown = _instruction_vtype_facts(
                instruction_analysis
            )
            is_config = is_config_instruction(insn)
            vtype_independent = dispatcher.is_vtype_independent_instruction(insn)

            # 该门禁只属于程序模式：每个原偏移都是潜在迁移入口，不能把顺序
            # 扫描得到的 StateTracker 形状误当作所有基本块前驱都满足的事实。
            # whole-register/raw mask move 与向量 CSR 可由 opcode 独立解释，
            # 故维持它们的 vtype-independent 白名单豁免。
            if (
                not is_config
                and not vtype_independent
                and not known_specs
            ):
                detail = (
                    "程序级任意迁移入口缺少内部 InstructionAnalysis；"
                    "不能以线性前序 vset* 猜测 RVV256 物理寄存器组布局"
                )
                if source_unknown:
                    detail = (
                        "程序级入口 vtype 含 unknown 候选；"
                        "过渡路径不能安全解释 RVV256 物理寄存器组"
                    )
                record_issue(insn.address, insn.opcode, detail)
                continue
            if (
                source_unknown
                and not is_config
                and not vtype_independent
                and not (allow_mixed_unknown_vtype and known_specs)
            ):
                record_issue(
                    insn.address,
                    insn.opcode,
                    "入口 vtype 含 unknown 候选，过渡路径不能安全解释 RVV256 物理寄存器组",
                )
                continue
            if known_specs and not is_config and not vtype_independent:
                for candidate in known_specs:
                    candidate_state = state.clone()
                    candidate_state.apply_vtype_spec(candidate)
                    plan, detail, recoverable = _plan_one(
                        insn,
                        candidate_state,
                        allocator,
                        dispatcher,
                        vtype_candidates=(candidate,),
                    )
                    if detail:
                        record_issue(
                            insn.address,
                            insn.opcode,
                            f"vtype {candidate}: {detail}",
                            recoverable=recoverable,
                        )
                    elif plan is not None:
                        plans.append(plan)
                continue
            plan, detail, recoverable = _plan_one(
                insn,
                state,
                allocator,
                dispatcher,
            )
            if detail:
                record_issue(
                    insn.address,
                    insn.opcode,
                    detail,
                    recoverable=recoverable,
                )
            elif plan is not None:
                plans.append(plan)
            if is_config:
                if detail is None:
                    state.update(insn)
    if issues:
        raise TransitionPreflightError(issues)
    if fallback_required:
        return ()
    return tuple(plans)
