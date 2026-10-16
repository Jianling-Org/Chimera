"""基于工作表的 RVV vtype/AVL CFG 数据流分析。"""

from __future__ import annotations

from riscv.extensions.rvv.instruction import is_vector_instruction, is_config_instruction
from collections import deque
from dataclasses import dataclass
import re
from typing import Iterable

from riscv.extensions.rvv.analysis.model import (
    AnalysisMetrics,
    FunctionAnalysis,
    FunctionVTypeSummary,
    InstructionAnalysis,
    ProgramAnalysis,
    VTypeEffect,
    VTypeEffectKind,
)
from riscv.frontend.model import CallGraph
from riscv.frontend.model import RVFunction, RVInstruction, RVProgram
from riscv.extensions.rvv.analysis.model import (
    AVLInfo,
    AVLKind,
    UNKNOWN_SECONDARY_ENTRY_CANDIDATE,
    UNKNOWN_UNREACHABLE_CANDIDATE,
    UNKNOWN_VTYPE_CANDIDATE,
    VTypeCandidate,
    VTypeSpec,
)
from riscv.frontend.call_graph import bottom_up_sccs
from riscv.frontend.text_index import TextProgramIndex
from riscv.frontend.literals import parse_integer_literal
from riscv.registers import normalize_gpr_name
from riscv.frontend.model import ProgramStructure, FunctionStructure


VSET_OPS = {"vsetivli", "vsetvli", "vsetvl"}
CONDITIONAL_BRANCH_OPS = {
    "beq", "bne", "blt", "bge", "bltu", "bgeu",
    "beqz", "bnez", "bltz", "bgez", "blez", "bgtz",
}
SCALAR_STORE_OPS = {
    "sb", "sh", "sw", "sd", "fsw", "fsd",
    "c.sw", "c.sd", "c.fsw", "c.fsd", "c.swsp", "c.sdsp",
    "c.fswsp", "c.fsdsp",
}
NO_SCALAR_DESTINATION_OPS = CONDITIONAL_BRANCH_OPS | SCALAR_STORE_OPS | {
    "j", "jr", "ret", "tail", "call", "ecall", "ebreak", "fence", "fence.i",
    "nop", "csrw", "csrs", "csrc", "csrwi", "csrsi", "csrci",
}
CALL_CLOBBERED = {
    "ra", "a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7",
    "t0", "t1", "t2", "t3", "t4", "t5", "t6",
}


def _candidate_semantic_key(candidate: VTypeCandidate) -> tuple[object, ...]:
    """返回不含来源地址的 vtype 候选语义键。

    同一 vtype 从不同 vset 或调用点到达时，来源地址不应导致数据流
    集合无限增长；AVL 和 unknown_reason 仍保留，因为它们分别承载
    活动长度信息和未知原因。
    """

    return (
        candidate.sew,
        candidate.lmul,
        candidate.vta,
        candidate.vma,
        candidate.avl,
        candidate.unknown_reason,
    )


def _deduplicate_candidates(
    candidates: Iterable[VTypeCandidate],
) -> frozenset[VTypeCandidate]:
    by_key: dict[tuple[object, ...], VTypeCandidate] = {}
    ordered = sorted(
        candidates,
        key=lambda candidate: (
            candidate.display(),
            candidate.avl.display(),
            candidate.source_instruction if candidate.source_instruction is not None else -1,
            candidate.unknown_reason or "",
        ),
    )
    for candidate in ordered:
        by_key.setdefault(_candidate_semantic_key(candidate), candidate)
    return frozenset(by_key.values())


@dataclass(frozen=True)
class _State:
    """工作表中的抽象状态。

    ``configs`` 是 may-set：任一路径可到达的 vtype 都必须保留。
    ``constants`` 是 must-map：只有所有前驱都给出相同常量时才保留。
    """

    configs: frozenset[VTypeCandidate]
    constants: tuple[tuple[str, int], ...] = ()
    provenance: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        if len(self.configs) > 1:
            object.__setattr__(self, "configs", _deduplicate_candidates(self.configs))

    def constant_map(self) -> dict[str, int]:
        return dict(self.constants)

    def merge(self, incoming: "_State") -> "_State":
        if self == incoming:
            return self
        current = self.constant_map()
        other = incoming.constant_map()
        common = {
            register: value
            for register, value in current.items()
            if other.get(register) == value
        }
        return _State(
            configs=self.configs | incoming.configs,
            constants=tuple(sorted(common.items())),
            provenance=self.provenance | incoming.provenance,
        )


@dataclass(frozen=True)
class _EffectState:
    """函数摘要分析使用的 vtype 效果工作表状态。"""

    effects: frozenset[VTypeEffect]

    def merge(self, incoming: "_EffectState") -> "_EffectState":
        if incoming.effects.issubset(self.effects):
            return self
        return _EffectState(effects=self.effects | incoming.effects)


class VectorConfigAnalyzer:
    """在当前项目的指令模型上运行前向 CFG 数据流分析。"""

    def analyze_program(
        self,
        program: RVProgram,
        structure: ProgramStructure,
        *,
        initial_vtype: VTypeSpec | None = None,
    ) -> ProgramAnalysis:
        target = program
        functions = target.functions
        call_graph = structure.call_graph
        summaries = self._compute_function_summaries(target, call_graph, structure)
        analyses: dict[int, FunctionAnalysis] = {}
        for function in functions:
            if not function.instructions:
                continue
            analyses[function.start_addr] = self.analyze_function(
                function,
                structure=structure.functions[function.start_addr],
                call_graph=call_graph,
                function_summaries=summaries,
                initial_vtype=initial_vtype,
            )
        metrics = self._collect_metrics(target, analyses)
        result = ProgramAnalysis(
            functions=analyses,
            structure=structure,
            function_summaries=summaries,
            metrics=metrics,
        )
        return result

    def analyze_function(
        self,
        function: RVFunction,
        *,
        structure: FunctionStructure,
        call_graph: CallGraph | None = None,
        function_summaries: dict[int, FunctionVTypeSummary] | None = None,
        initial_vtype: VTypeSpec | None = None,
    ) -> FunctionAnalysis:
        # Interprocedural effects have already been summarized for every
        # function. Scalar-only bodies have no vtype consumers to materialize.
        if not any(is_vector_instruction(insn) for insn in function.instructions):
            return FunctionAnalysis(
                function.start_addr,
                structure,
                {},
                vtype_summary=(function_summaries or {}).get(function.start_addr),
            )
        cfg = structure.cfg
        instructions = {instruction.address: instruction for instruction in function.instructions}
        entry_addresses = tuple(
            address
            for address in cfg.entry_points()
            if address in instructions
        )
        if not entry_addresses:
            result = FunctionAnalysis(
                function.start_addr,
                structure,
                {},
            )
            return result

        primary_entry = cfg.entry_address
        before: dict[int, _State] = {}
        worklist: deque[int] = deque()
        queued: set[int] = set()

        # 主入口和没有直接前驱的次级入口都要启动一次数据流。次级入口
        # 不能继承主入口的 vtype，仍以显式 unknown 开始；如果其局部路径
        # 随后执行 vset，向量指令便可恢复为确定配置。
        for entry in entry_addresses:
            is_primary = entry == primary_entry
            seed_candidate = (
                VTypeCandidate.from_spec(initial_vtype)
                if is_primary and initial_vtype is not None
                else UNKNOWN_VTYPE_CANDIDATE
                if is_primary
                else UNKNOWN_SECONDARY_ENTRY_CANDIDATE
            )
            seed = _State(
                configs=frozenset({seed_candidate}),
                provenance=frozenset(
                    {
                        "explicit-initial-vtype"
                        if is_primary and initial_vtype is not None
                        else "primary-entry"
                        if is_primary
                        else "secondary-entry"
                    }
                ),
            )
            current = before.get(entry)
            before[entry] = seed if current is None else current.merge(seed)
            if entry not in queued:
                worklist.append(entry)
                queued.add(entry)

        while worklist:
            address = worklist.popleft()
            queued.discard(address)
            state = before[address]
            instruction = instructions[address]
            outgoing = self._transfer(
                instruction,
                state,
                call_graph=call_graph,
                function_summaries=function_summaries,
            )

            for successor in instruction.successors:
                if successor not in instructions:
                    continue
                merged = self._merge_states(before.get(successor), outgoing)
                if merged == before.get(successor):
                    continue
                before[successor] = merged
                if successor not in queued:
                    worklist.append(successor)
                    queued.add(successor)

        instruction_results: dict[int, InstructionAnalysis] = {}
        for instruction in function.instructions:
            # Scalar instructions still participate in the fixed point above;
            # only RVV instructions consume persistent vtype facts at emission.
            if not is_vector_instruction(instruction):
                continue
            state = before.get(instruction.address)
            if state is None:
                # 这类块既没有直接前驱，也没有被 CFGBuilder 识别为候选
                # 入口。保留独立原因，避免把 CFG 建模缺口伪装成动态
                # vsetvl；后端仍应按 unknown/fallback 处理。
                state = _State(
                    configs=frozenset({UNKNOWN_UNREACHABLE_CANDIDATE}),
                    provenance=frozenset({"unreachable"}),
                )
            candidates = state.configs or frozenset({UNKNOWN_VTYPE_CANDIDATE})
            complete = [candidate for candidate in candidates if candidate.known_vtype]
            definite = complete[0] if len(candidates) == 1 and len(complete) == 1 else None
            avl = tuple(sorted({candidate.avl for candidate in candidates}, key=lambda item: item.display()))
            analysis = InstructionAnalysis(
                address=instruction.address,
                possible_vtypes=frozenset(candidates),
                definite_vtype=definite,
                vtype_unknown=any(not candidate.known_vtype for candidate in candidates),
                avl_information=avl,
                provenance=self._format_provenance(state.provenance),
            )
            instruction_results[instruction.address] = analysis

        result = FunctionAnalysis(
            function.start_addr,
            structure,
            instruction_results,
            vtype_summary=(
                function_summaries.get(function.start_addr)
                if function_summaries is not None
                else None
            ),
        )
        return result

    @staticmethod
    def _merge_states(current: _State | None, incoming: _State) -> _State:
        return incoming if current is None else current.merge(incoming)

    @staticmethod
    def _format_provenance(provenance: frozenset[str]) -> str:
        """将数据流入口集合压缩为稳定的调试来源标签。"""

        if "unreachable" in provenance or not provenance:
            return "internal-cfg:unreachable"
        if {"primary-entry", "secondary-entry"}.issubset(provenance):
            return "internal-cfg:multi-entry"
        if "secondary-entry" in provenance:
            return "internal-cfg:secondary-entry"
        if "explicit-initial-vtype" in provenance:
            return "internal-cfg:explicit-initial-vtype"
        if "call-summary" in provenance:
            return "internal-cfg:call-summary"
        return "internal-cfg:primary-entry"

    def _transfer(
        self,
        instruction: RVInstruction,
        state: _State,
        *,
        call_graph: CallGraph | None = None,
        function_summaries: dict[int, FunctionVTypeSummary] | None = None,
    ) -> _State:
        # vsetvli 的 rs1 读取发生在 rd 写回之前，因此先用 incoming 常量解码。
        incoming_constants = state.constant_map()
        configs = state.configs
        is_call = self._is_call_instruction(instruction)
        if instruction.opcode.lower() in VSET_OPS:
            configs = frozenset({self._decode_vset(instruction, incoming_constants)})
        elif is_call:
            configs = frozenset(
                self._apply_call_summary(
                    instruction,
                    state.configs,
                    call_graph=call_graph,
                    function_summaries=function_summaries,
                )
            )

        constants = incoming_constants
        self._update_scalar_constants(instruction, constants)
        provenance = state.provenance
        if is_call and call_graph is not None:
            provenance = provenance | {"call-summary"}
        constant_items = tuple(sorted(constants.items()))
        if (configs == state.configs and constant_items == state.constants
                and provenance == state.provenance):
            return state
        return _State(
            configs=configs,
            constants=constant_items,
            provenance=provenance,
        )

    @staticmethod
    def _is_call_instruction(instruction: RVInstruction) -> bool:
        """判断会把控制权交给其他函数、并可能改变 vtype 的指令。"""

        return TextProgramIndex.is_call(instruction)

    def _apply_call_summary(
        self,
        instruction: RVInstruction,
        incoming: frozenset[VTypeCandidate],
        *,
        call_graph: CallGraph | None,
        function_summaries: dict[int, FunctionVTypeSummary] | None,
    ) -> set[VTypeCandidate]:
        """将一个函数摘要应用到调用点的 vtype 候选集合。"""

        inputs = incoming or frozenset({UNKNOWN_VTYPE_CANDIDATE})
        summary: FunctionVTypeSummary | None = None
        if call_graph is not None and function_summaries is not None:
            edge = call_graph.edge_for_call(instruction.address)
            if (
                edge is not None
                and edge.target_function_start is not None
                and edge.target_is_function_entry
            ):
                summary = function_summaries.get(edge.target_function_start)

        if summary is None or not summary.normal_return:
            edge = call_graph.edge_for_call(instruction.address) if call_graph else None
            if edge is not None and edge.target_function_start is not None:
                unresolved_reason = (
                    "direct call target is an interior function address without "
                    "a function-entry summary"
                    if not edge.target_is_function_entry
                    else "callee has no statically known normal return effect"
                )
            else:
                unresolved_reason = (
                    "call may change vtype in an unanalyzed callee"
                    if edge is None or edge.kind.value == "indirect-call"
                    else "call target is external or unresolved"
                )
            return {
                VTypeCandidate(
                    None,
                    None,
                    None,
                    None,
                    avl=AVLInfo(),
                    source_instruction=instruction.address,
                    unknown_reason=unresolved_reason,
                )
            }

        output: set[VTypeCandidate] = set()
        effects = summary.effects or frozenset({
            VTypeEffect.unknown(
                "callee has no statically known normal return effect",
                source_instruction=instruction.address,
            )
        })
        for candidate in inputs:
            for effect in effects:
                if effect.kind is VTypeEffectKind.PRESERVE_INPUT:
                    output.add(candidate)
                elif effect.kind is VTypeEffectKind.SET_CONSTANT:
                    # 构造时已经验证完整 vtype；这里仍保留候选对象中的
                    # AVL 信息，不把函数摘要简化成 ta/ma 默认值。
                    if effect.candidate is not None:
                        output.add(effect.candidate)
                else:
                    output.add(
                        VTypeCandidate(
                            None,
                            None,
                            None,
                            None,
                            avl=AVLInfo(),
                            source_instruction=(
                                effect.source_instruction or instruction.address
                            ),
                            unknown_reason=(
                                effect.reason
                                or "callee vtype summary is unknown"
                            ),
                        )
                    )
        return output or {
            VTypeCandidate(
                None,
                None,
                None,
                None,
                avl=AVLInfo(),
                source_instruction=instruction.address,
                unknown_reason="callee vtype summary produced no normal effect",
            )
        }

    def _compute_function_summaries(
        self,
        program: RVProgram,
        call_graph: CallGraph,
        structure: ProgramStructure,
    ) -> dict[int, FunctionVTypeSummary]:
        """按调用图叶到根的顺序计算函数 vtype 摘要。

        对递归 SCC 内部的调用不做猜测，直接使用 UNKNOWN；这样既避免
        递归固定点中的乐观初始化，也保持摘要结果单调、可复现。
        """

        functions = {
            function.start_addr: function
            for function in program.functions
            if function.instructions
        }
        summaries: dict[int, FunctionVTypeSummary] = {}
        for component in bottom_up_sccs(call_graph, functions):
            recursive = len(component) > 1 or any(
                edge.target_is_function_entry
                and edge.target_function_start == function_start
                for function_start in component
                for edge in call_graph.edges_for(function_start)
            )
            recursive_members = set(component) if recursive else set()
            for function_start in sorted(component):
                function = functions.get(function_start)
                if function is None:
                    continue
                summaries[function_start] = self._summarize_function(
                    function,
                    structure=structure.functions[function_start],
                    call_graph=call_graph,
                    summaries=summaries,
                    recursive_members=recursive_members,
                )
        return summaries

    def _summarize_function(
        self,
        function: RVFunction,
        *,
        structure: FunctionStructure,
        call_graph: CallGraph,
        summaries: dict[int, FunctionVTypeSummary],
        recursive_members: set[int],
    ) -> FunctionVTypeSummary:
        """用 ``PRESERVE_INPUT`` 符号状态分析一个函数的返回效果。"""

        cfg = structure.cfg
        instructions = {
            instruction.address: instruction
            for instruction in function.instructions
        }
        entries = tuple(
            address for address in cfg.entry_points() if address in instructions
        )
        if not entries:
            return FunctionVTypeSummary(
                effects=frozenset({
                    VTypeEffect.unknown(
                        "function has no recognized text entry",
                        source_instruction=function.start_addr,
                    )
                }),
                normal_return=False,
                unknown_exit=True,
            )

        before: dict[int, _EffectState] = {}
        worklist: deque[int] = deque()
        queued: set[int] = set()
        seed = _EffectState(effects=frozenset({VTypeEffect.preserve()}))
        for entry in entries:
            before[entry] = seed
            worklist.append(entry)
            queued.add(entry)

        return_effects: set[VTypeEffect] = set()
        normal_return = False
        unknown_exit = False

        while worklist:
            address = worklist.popleft()
            queued.discard(address)
            instruction = instructions[address]
            state = before[address]
            outgoing = self._transfer_effects(
                instruction,
                state,
                call_graph=call_graph,
                summaries=summaries,
                recursive_members=recursive_members,
            )
            opcode = instruction.opcode.lower()

            if opcode == "ret":
                return_effects.update(outgoing.effects)
                normal_return = True
                continue
            if opcode in {"ecall", "ebreak", "jr"}:
                unknown_exit = True
                continue
            if opcode == "jalr" and not TextProgramIndex.is_call(instruction):
                unknown_exit = True
                continue

            tail_edge = call_graph.edge_for_call(instruction.address)
            is_tail_transfer = (
                tail_edge is not None
                and tail_edge.kind.value == "tail-call"
            )
            if is_tail_transfer:
                tail_effects = self._effects_for_call(
                    instruction,
                    call_graph=call_graph,
                    summaries=summaries,
                    recursive_members=recursive_members,
                )
                return_effects.update(
                    self._compose_effects(outgoing.effects, tail_effects)
                )
                normal_return = True
                continue

            if not instruction.successors:
                if opcode in {"j", "tail"} or (
                    opcode == "jal"
                    and len(instruction.operands) > 1
                    and str(instruction.operands[0]).strip().lower() in {"x0", "zero"}
                ):
                    unknown_exit = True
                else:
                    # 函数末尾缺少显式 ret 时，文本不足以证明这是正常
                    # 返回；例如函数可能被截断，或通过未建模的间接路径
                    # 离开。不能把普通指令的文件末尾当成隐式返回。
                    unknown_exit = True
                    return_effects.add(
                        VTypeEffect.unknown(
                            "function ends without an explicit return",
                            source_instruction=instruction.address,
                        )
                    )
                continue

            for successor in instruction.successors:
                if successor not in instructions:
                    continue
                incoming = before.get(successor)
                merged = (
                    outgoing
                    if incoming is None
                    else incoming.merge(outgoing)
                )
                if merged == incoming:
                    continue
                before[successor] = merged
                if successor not in queued:
                    worklist.append(successor)
                    queued.add(successor)

        # CFG 中存在未解析的间接出口时，文本无法证明该路径不会以另一
        # 个 vtype 返回。若函数已有正常返回，显式加入 unknown；若没有
        # 正常返回，也必须把摘要标成 unknown，避免调用者乐观传播。
        if cfg.unknown_exit:
            unknown_exit = True
            return_effects.add(
                VTypeEffect.unknown(
                    "function has unresolved text control-flow exit",
                    source_instruction=function.start_addr,
                )
            )
        if not normal_return or not return_effects:
            return_effects.add(
                VTypeEffect.unknown(
                    "function has no statically known normal return effect",
                    source_instruction=function.start_addr,
                )
            )

        return FunctionVTypeSummary(
            effects=frozenset(return_effects),
            normal_return=normal_return,
            unknown_exit=unknown_exit,
        )

    def _transfer_effects(
        self,
        instruction: RVInstruction,
        state: _EffectState,
        *,
        call_graph: CallGraph,
        summaries: dict[int, FunctionVTypeSummary],
        recursive_members: set[int],
    ) -> _EffectState:
        """执行函数摘要层的 transfer，不生成具体目标汇编。"""

        opcode = instruction.opcode.lower()
        if opcode in VSET_OPS:
            candidate = self._decode_vset(instruction, {})
            if candidate.known_vtype:
                return _EffectState(effects=frozenset({
                    VTypeEffect.set_constant(
                        candidate,
                        source_instruction=instruction.address,
                    )
                }))
            return _EffectState(effects=frozenset({
                VTypeEffect.unknown(
                    candidate.unknown_reason or "dynamic vector configuration",
                    source_instruction=instruction.address,
                )
            }))
        if self._is_call_instruction(instruction):
            callee_effects = self._effects_for_call(
                instruction,
                call_graph=call_graph,
                summaries=summaries,
                recursive_members=recursive_members,
            )
            return _EffectState(
                # ``PRESERVE_INPUT`` 只表示被调函数不改 vtype；它必须与
                # 当前函数在调用前已经产生的效果组合，而不能覆盖它。
                effects=frozenset(self._compose_effects(state.effects, callee_effects))
            )
        return state

    def _effects_for_call(
        self,
        instruction: RVInstruction,
        *,
        call_graph: CallGraph,
        summaries: dict[int, FunctionVTypeSummary],
        recursive_members: set[int],
    ) -> set[VTypeEffect]:
        """取得调用点摘要；任何未解析情况都保守退化为 UNKNOWN。"""

        edge = call_graph.edge_for_call(instruction.address)
        if edge is None or edge.target_function_start is None:
            return {
                VTypeEffect.unknown(
                    "call target is external or unresolved",
                    source_instruction=instruction.address,
                )
            }
        if not edge.target_is_function_entry:
            return {
                VTypeEffect.unknown(
                    "direct call target is an interior function address without "
                    "a function-entry summary",
                    source_instruction=instruction.address,
                )
            }
        if edge.target_function_start in recursive_members:
            return {
                VTypeEffect.unknown(
                    "recursive call summary is intentionally conservative",
                    source_instruction=instruction.address,
                )
            }
        summary = summaries.get(edge.target_function_start)
        if summary is None or not summary.normal_return:
            return {
                VTypeEffect.unknown(
                    "callee has no statically known normal return effect",
                    source_instruction=instruction.address,
                )
            }
        return set(summary.effects) or {
            VTypeEffect.unknown(
                "callee summary contains no effect",
                source_instruction=instruction.address,
            )
        }

    @staticmethod
    def _compose_effects(
        incoming: frozenset[VTypeEffect],
        callee: set[VTypeEffect],
    ) -> set[VTypeEffect]:
        """组合当前路径效果和被调用函数的返回效果。"""

        result: set[VTypeEffect] = set()
        for before in incoming:
            for after in callee:
                if after.kind is VTypeEffectKind.PRESERVE_INPUT:
                    result.add(before)
                elif after.kind is VTypeEffectKind.SET_CONSTANT:
                    result.add(after)
                else:
                    result.add(after)
        return result

    @staticmethod
    def _collect_metrics(
        program: RVProgram,
        analyses: dict[int, FunctionAnalysis],
    ) -> AnalysisMetrics:
        """从最终结果生成可比较的 dump.S 分析统计。"""

        known_vector_count = 0
        unknown_vector_count = 0
        unknown_reasons: dict[str, int] = {}

        for function in program.functions:
            function_analysis = analyses.get(function.start_addr)
            if function_analysis is None:
                continue
            for instruction in function.instructions:
                if not is_vector_instruction(instruction) or is_config_instruction(instruction):
                    continue
                instruction_analysis = function_analysis.at(instruction.address)
                if instruction_analysis.vtype_unknown:
                    unknown_vector_count += 1
                    reasons = {
                        candidate.unknown_reason or "unknown"
                        for candidate in instruction_analysis.possible_vtypes
                        if not candidate.known_vtype
                    }
                    for reason in reasons or {"unknown"}:
                        unknown_reasons[reason] = unknown_reasons.get(reason, 0) + 1
                else:
                    known_vector_count += 1

        return AnalysisMetrics(
            known_vector_count=known_vector_count,
            unknown_vector_count=unknown_vector_count,
            unknown_reasons=unknown_reasons,
        )

    def _update_scalar_constants(
        self,
        instruction: RVInstruction,
        constants: dict[str, int],
    ) -> None:
        operation = instruction.opcode.lower()
        destination = self._defined_scalar_register(instruction)

        if TextProgramIndex.is_call(instruction):
            for register in CALL_CLOBBERED:
                constants.pop(register, None)

        if destination is None:
            return

        # 先删除旧值；下面只有在确定新值时才重新写入。
        incoming_constants = dict(constants)
        constants.pop(destination, None)
        operands = [normalize_gpr_name(str(operand)) or str(operand).strip().lower()
                    for operand in instruction.operands]

        value: int | None = None
        if operation == "li" and len(operands) >= 2:
            value = self._parse_integer(operands[1])
        elif operation == "mv" and len(operands) >= 2:
            value = incoming_constants.get(operands[1])
        elif operation in {"addi", "addiw"} and len(operands) >= 3:
            source = incoming_constants.get(operands[1])
            immediate = self._parse_integer(operands[2])
            if source is not None and immediate is not None:
                value = source + immediate
        elif operation in {"add", "sub"} and len(operands) >= 3:
            left = incoming_constants.get(operands[1])
            right = incoming_constants.get(operands[2])
            if left is not None and right is not None:
                value = left + right if operation == "add" else left - right
        elif operation == "lui" and len(operands) >= 2:
            immediate = self._parse_integer(operands[1])
            if immediate is not None:
                value = immediate << 12

        if value is not None:
            constants[destination] = value

    @staticmethod
    def _defined_scalar_register(instruction: RVInstruction) -> str | None:
        operation = instruction.opcode.lower()
        operands = instruction.operands
        if operation in NO_SCALAR_DESTINATION_OPS or not operands:
            return None
        if operation == "jal" and len(operands) == 1:
            return "ra"
        if operation == "jalr" and len(operands) == 1:
            return "ra"
        destination = normalize_gpr_name(str(operands[0]))
        return destination if destination != "zero" else None

    def _decode_vset(
        self,
        instruction: RVInstruction,
        constants: dict[str, int],
    ) -> VTypeCandidate:
        operands = [normalize_gpr_name(str(operand)) or str(operand).strip().lower()
                    for operand in instruction.operands]
        operation = instruction.opcode.lower()
        if len(operands) < 2:
            return VTypeCandidate(
                None, None, None, None,
                avl=AVLInfo(),
                source_instruction=instruction.address,
                unknown_reason="malformed vector configuration instruction",
            )

        if operation == "vsetvl":
            avl = self._decode_avl(operands[1], constants, allow_immediate=False)
            return VTypeCandidate(
                None,
                None,
                None,
                None,
                avl=avl,
                source_instruction=instruction.address,
                unknown_reason="vsetvl vtype comes from a runtime register",
            )

        sew: int | None = None
        lmul: float | None = None
        vta: int | None = None
        vma: int | None = None
        for token in operands[2:]:
            if token.startswith("e") and token[1:].isdigit():
                sew = int(token[1:])
            elif token in {"m1", "m2", "m4", "m8", "mf2", "mf4", "mf8"}:
                lmul = {
                    "m1": 1.0,
                    "m2": 2.0,
                    "m4": 4.0,
                    "m8": 8.0,
                    "mf2": 0.5,
                    "mf4": 0.25,
                    "mf8": 0.125,
                }[token]
            elif token in {"ta", "tu"}:
                vta = 1 if token == "ta" else 0
            elif token in {"ma", "mu"}:
                vma = 1 if token == "ma" else 0

        avl = self._decode_avl(
            operands[1],
            constants,
            allow_immediate=operation == "vsetivli",
        )
        missing = []
        if sew is None:
            missing.append("SEW")
        if lmul is None:
            missing.append("LMUL")
        if vta is None:
            missing.append("VTA")
        if vma is None:
            missing.append("VMA")
        reason = f"missing {', '.join(missing)}" if missing else None
        return VTypeCandidate(
            sew,
            lmul,
            vta,
            vma,
            avl=avl,
            source_instruction=instruction.address,
            unknown_reason=reason,
        )

    @classmethod
    def _decode_avl(
        cls,
        operand: str,
        constants: dict[str, int],
        *,
        allow_immediate: bool,
    ) -> AVLInfo:
        if operand in {"zero", "x0"}:
            return AVLInfo(kind=AVLKind.X0, register=operand)
        if allow_immediate:
            immediate = cls._parse_integer(operand)
            if immediate is not None:
                return AVLInfo(kind=AVLKind.CONSTANT, value=immediate)
        key = normalize_gpr_name(operand) or operand
        if key in constants:
            return AVLInfo(
                kind=AVLKind.CONSTANT,
                value=constants[key],
                register=operand,
            )
        return AVLInfo(kind=AVLKind.UNKNOWN, register=operand)

    @staticmethod
    def _parse_integer(value: str) -> int | None:
        try:
            return parse_integer_literal(value)
        except ValueError:
            return None


__all__ = ["VectorConfigAnalyzer"]
