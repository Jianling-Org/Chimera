"""结构化 lowerer 共用的汇编 builder 执行边界。

``InstructionSpec.lowerer`` 始终接收 :class:`HandlerContext` 与
:class:`LoweringPlan` 并返回 :class:`LoweringResult`。具体指令族可以把复杂的
汇编构造拆成私有 line builder，但 builder 同样只能读取结构化上下文，不能
重新暴露旧的 ``(insn, state, allocator, dispatcher)`` handler 接口。
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import TypeAlias

from riscv.extensions.rvv.translation.temps import capture_clobbers
from riscv.extensions.rvv.translation.contracts import (
    HandlerContext,
    LoweringPlan,
    LoweringResult,
)


@dataclass(frozen=True, slots=True)
class AssemblyFragments:
    """结构化区分普通正文与必须在状态收尾后执行的汇编行。"""

    body_lines: tuple[str, ...]
    post_state_lines: tuple[str, ...] = ()


AssemblyBuilderOutput: TypeAlias = Sequence[str] | AssemblyFragments
AssemblyLineBuilder: TypeAlias = Callable[
    [HandlerContext], AssemblyBuilderOutput
]
AssemblyPostprocessor: TypeAlias = Callable[
    [HandlerContext, LoweringPlan, AssemblyFragments], AssemblyFragments
]


def _validate_assembly_lines(
    value: Sequence[str], *, opcode: str, producer: str
) -> tuple[str, ...]:
    """冻结汇编行，并拒绝字符串被误当作字符序列。

    此处只验证内部数据合同，不从文本内容推测降低状态、诊断或寄存器破坏；
    这些信息必须由异常类型、InstructionSpec 和 clobber 捕获器提供。
    """

    if (
        isinstance(value, (str, bytes))
        or not isinstance(value, Sequence)
        or any(not isinstance(line, str) for line in value)
    ):
        raise TypeError(f"{opcode} 的 {producer} 必须返回字符串序列")
    return tuple(value)


def freeze_assembly_fragments(
    value: AssemblyBuilderOutput, *, opcode: str, producer: str
) -> AssemblyFragments:
    """冻结 builder 输出，同时保留状态收尾后的显式执行阶段。"""

    if isinstance(value, AssemblyFragments):
        return AssemblyFragments(
            _validate_assembly_lines(
                value.body_lines, opcode=opcode, producer=f"{producer} body"
            ),
            _validate_assembly_lines(
                value.post_state_lines,
                opcode=opcode,
                producer=f"{producer} post-state",
            ),
        )
    return AssemblyFragments(
        _validate_assembly_lines(value, opcode=opcode, producer=producer)
    )


def lower_assembly_builder(
    context: HandlerContext,
    plan: LoweringPlan,
    builder: AssemblyLineBuilder,
    *,
    postprocessor: AssemblyPostprocessor | None = None,
) -> LoweringResult:
    """执行一个结构化 line builder 并生成不可变降低结果。

    临时寄存器分配发生在同一个捕获作用域内，因此 builder 和后处理阶段产生
    的 GPR/FPR/vreg 破坏都会进入 ``LoweringResult``，无需反解析汇编文本。
    异常策略由各后端原生 lowerer/profile 决定：标量提升为失败，RVV256 和
    RVV1024 过渡路径生成带诊断的 ebreak；公共层不擅自吞掉异常。
    """

    with capture_clobbers() as clobbers:
        fragments = freeze_assembly_fragments(
            builder(context),
            opcode=context.instruction.opcode,
            producer="assembly builder",
        )
        if postprocessor is not None:
            fragments = freeze_assembly_fragments(
                postprocessor(context, plan, fragments),
                opcode=context.instruction.opcode,
                producer="assembly postprocessor",
            )
        lines = fragments.body_lines + fragments.post_state_lines
    return LoweringResult.lowered(
        lines,
        clobbered_gprs=frozenset(clobbers.gprs),
        clobbered_fprs=frozenset(clobbers.fprs),
        clobbered_vregs=frozenset(clobbers.vregs),
    )


__all__ = [
    "AssemblyBuilderOutput",
    "AssemblyFragments",
    "AssemblyLineBuilder",
    "AssemblyPostprocessor",
    "freeze_assembly_fragments",
    "lower_assembly_builder",
]
