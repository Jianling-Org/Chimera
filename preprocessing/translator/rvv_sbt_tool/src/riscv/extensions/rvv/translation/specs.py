"""RVV 能力规格装配、计划校验与 lowering 调用。"""

from __future__ import annotations

from riscv.registers import (
    collect_scalar_register_uses,
    normalize_fpr_name,
    normalize_gpr_name,
)
from collections.abc import Callable, Iterable, Iterator, Mapping
from typing import TypeAlias
from dataclasses import replace
from types import MappingProxyType
from riscv.extensions.rvv.translation.contracts import (
    HandlerContext,
    InstructionSpec,
    InstructionValidationError,
    LoweringPlan,
    LoweringResult,
    LoweringStatus,
)


_CONFIG_INPUT_INDICES = {
    "vsetvli": (1,),
    "vsetvl": (1, 2),
}


_CSR_GPR_INPUT_INDEX = {
    "csrw": 1,
    "csrs": 1,
    "csrc": 1,
    "csrrw": 2,
    "csrrs": 2,
    "csrrc": 2,
}


def resolve_scalar_semantic_inputs(
    instruction,
    semantic_outputs: Iterable[str],
) -> frozenset[str]:
    """返回规范 ABI 名称的显式 GPR/FPR 输入集合。"""

    gprs, fprs = collect_scalar_register_uses(instruction)
    outputs = set(semantic_outputs)
    inputs = (gprs | fprs) - outputs

    indices = _CONFIG_INPUT_INDICES.get(instruction.opcode, ())
    csr_index = _CSR_GPR_INPUT_INDEX.get(instruction.opcode)
    if csr_index is not None:
        indices = (*indices, csr_index)

    for index in indices:
        if index >= len(instruction.operands):
            continue
        register = normalize_gpr_name(str(instruction.operands[index]))
        if register and register != "zero":
            inputs.add(register)
    return frozenset(inputs)


SemanticResolver: TypeAlias = Callable[[HandlerContext, LoweringPlan], frozenset[str]]


def expand_semantic_groups(
    groups: Iterable[tuple[tuple[str, ...], str]],
    *,
    backend_label: str,
    fact_name: str,
) -> dict[str, str]:
    """展开显式 opcode 语义分组；重复事实属于规格表错误。"""

    result: dict[str, str] = {}
    for opcodes, value in groups:
        for opcode in opcodes:
            if opcode in result:
                raise ValueError(
                    f"{backend_label} {fact_name} 重复声明: {opcode}"
                )
            result[opcode] = value
    return result


def make_scalar_result_resolvers(
    *,
    gpr_result_opcodes: frozenset[str],
    fpr_result_opcodes: frozenset[str] = frozenset(),
) -> tuple[SemanticResolver, SemanticResolver]:
    """生成 ``(semantic_outputs, semantic_inputs)`` 解析器对。

    规则：opcode 命中 ``gpr_result_opcodes`` 时，其第一个操作数是写入的
    GPR 标量结果；命中 ``fpr_result_opcodes`` 时为 FPR 结果。其余 opcode
    不声明标量结果。``semantic_inputs`` 由输出集合经统一的标量寄存器使用
    分析推导。
    """

    def semantic_outputs(context: HandlerContext, _plan: LoweringPlan) -> frozenset[str]:
        insn = context.instruction
        if not insn.operands:
            return frozenset()
        if insn.opcode in gpr_result_opcodes:
            register = normalize_gpr_name(str(insn.operands[0]))
        elif insn.opcode in fpr_result_opcodes:
            register = normalize_fpr_name(str(insn.operands[0]))
        else:
            return frozenset()
        return frozenset({register}) if register else frozenset()

    def semantic_inputs(context: HandlerContext, plan: LoweringPlan) -> frozenset[str]:
        return resolve_scalar_semantic_inputs(
            context.instruction, semantic_outputs(context, plan)
        )

    return semantic_outputs, semantic_inputs


class HandlerRegistry:
    """按 opcode 唯一注册规格，并提供 prepare/lower 两阶段入口。"""

    def __init__(self) -> None:
        self._specs: dict[str, InstructionSpec] = {}
        self._categories: dict[str, dict[str, InstructionSpec]] = {}

    def register(self, spec: InstructionSpec) -> None:
        existing = self._specs.get(spec.opcode)
        if existing is not None:
            raise ValueError(
                f"重复注册 opcode {spec.opcode!r}: "
                f"{existing.category!r} 与 {spec.category!r}"
            )
        self._specs[spec.opcode] = spec
        self._categories.setdefault(spec.category, {})[spec.opcode] = spec

    def get(self, opcode: str) -> InstructionSpec | None:
        return self._specs.get(opcode)

    def require(self, opcode: str, instruction=None) -> InstructionSpec:
        spec = self.get(opcode)
        if spec is None:
            raise InstructionValidationError(
                instruction,
                f"后端未注册 opcode: {opcode}",
                status=LoweringStatus.UNSUPPORTED,
                code="unsupported-opcode",
            )
        return spec

    def supports(self, opcode: str) -> bool:
        return opcode in self._specs

    def handles_scalar_instruction(self, instruction) -> bool:
        """按规格判断标量外观指令是否应进入当前后端。

        opcode 注册只是第一层条件；matcher 还必须验证 CSR 操作数确实属于
        模拟向量状态，避免把普通 ``csrr cycle`` 等标量 CSR 错误截获。
        """

        spec = self.get(instruction.opcode)
        matcher = None if spec is None else spec.scalar_instruction_matcher
        return bool(matcher is not None and matcher(instruction))

    def categories(self) -> tuple[str, ...]:
        return tuple(sorted(self._categories))

    def by_category(self, category: str) -> Mapping[str, InstructionSpec]:
        return MappingProxyType(self._categories.get(category, {}))

    def snapshot(self) -> Mapping[str, InstructionSpec]:
        return MappingProxyType(dict(self._specs))

    def plan(
        self,
        context: HandlerContext,
        *,
        vtype_candidates: tuple[object, ...] = (),
    ) -> LoweringPlan:
        spec = self.require(context.instruction.opcode, context.instruction)
        bound_context = context.with_spec(spec)
        operands = spec.validator(bound_context)
        if not isinstance(operands, tuple) or any(
            not isinstance(operand, str) for operand in operands
        ):
            raise TypeError(f"{spec.opcode} validator 必须返回 tuple[str, ...]")
        return LoweringPlan(
            instruction=context.instruction,
            spec=spec,
            normalized_operands=operands,
            vtype_candidates=tuple(vtype_candidates),
        )

    def lower(self, context: HandlerContext, plan: LoweringPlan) -> LoweringResult:
        registered = self.require(plan.spec.opcode, plan.instruction)
        if registered is not plan.spec:
            raise ValueError(f"{plan.spec.opcode} 的 LoweringPlan 不属于当前 registry")
        if plan.instruction is not context.instruction:
            raise ValueError("LoweringPlan 与 HandlerContext 指令对象不一致")
        bound_context = replace(
            context.with_spec(plan.spec),
            instruction=replace(context.instruction, operands=list(plan.normalized_operands)),
        )
        result = plan.spec.lowerer(bound_context, plan)
        if not isinstance(result, LoweringResult):
            raise TypeError(
                f"{plan.spec.opcode} lowerer 必须返回 LoweringResult，"
                f"实际为 {type(result).__name__}"
            )
        if result.is_lowered:
            result = result.with_metadata(
                semantic_inputs=plan.spec.semantic_inputs(bound_context, plan),
                semantic_outputs=plan.spec.semantic_outputs(bound_context, plan),
                state_reads=plan.spec.state_reads,
                state_writes=plan.spec.state_writes,
            )
        return result

    def __iter__(self) -> Iterator[InstructionSpec]:
        for opcode in sorted(self._specs):
            yield self._specs[opcode]

    def __len__(self) -> int:
        return len(self._specs)
