# src/riscv/extensions/rvv/translation/emitter.py
"""
代码发射器：将翻译后的指令组装成完整的汇编文件

单函数/片段和程序都只从 ``PreparedTranslation`` 进入公开 ``emit_*``
入口；具体函数正文由私有方法发射，不再暴露历史 ``generate_*`` facade。
"""

from typing import Callable, Iterator, List, Mapping
from riscv.extensions.rvv.analysis.model import FunctionAnalysis
from riscv.frontend.model import RVFunction, RVInstruction
from riscv.frontend.model import CFGEdgeKind
from riscv.frontend.text_index import TextProgramIndex
from riscv.extensions.rvv.analysis.config import StateTracker
from riscv.extensions.rvv.translation.contracts import BackendDispatcherProtocol
from riscv.extensions.rvv.translation.pipeline import EmissionContext
from riscv.codegen.control_flow import ControlFlowEmitter
from riscv.codegen.control_flow import ControlFlowContext
from riscv.extensions.rvv.runtime.access import StateAccessEmitter
from riscv.extensions.rvv.translation.dispatch import VTypeDispatchEmitter
from riscv.extensions.rvv.translation.block import VectorBlockEmitter
from riscv.extensions.rvv.runtime.contract import LEGACY_OUTPUT_CONTRACT
from riscv.extensions.rvv.runtime.layout import DEFAULT_VLENB, SimulatedStateLayout


_PROGRAM_SECTION_INSTRUCTIONS = 65536


def is_vlenb_read(instruction: RVInstruction) -> bool:
    """The legacy scalar path recognizes this exact named CSR form."""
    return (
        instruction.opcode == "csrr"
        and len(instruction.operands) == 2
        and str(instruction.operands[1]).strip() == "vlenb"
    )


class ProgramEmitter:
    """
    汇编代码发射器

    将 RVV 指令流翻译为完整的标量 RISC-V 汇编文件
    """

    def __init__(
        self,
        vlenb: int = DEFAULT_VLENB,
        state_base_mode: str = "initial-exec",
        state_symbol: str = LEGACY_OUTPUT_CONTRACT.state_symbol,
        lookup_profile: int = LEGACY_OUTPUT_CONTRACT.lookup_profile,
        non_tls_state_symbol: str | None = None,
    ):
        """
        初始化发射器

        :param vlenb: VLEN/8 (向量长度字节数)，默认 128 (VLEN=1024)
        :param state_base_mode: TLS 状态基址获取模式：
            - ``initial-exec``：直接通过 ``tp`` 取得当前线程 TLS（线程局部存储）地址；
            - ``helper``：调用兼容辅助函数，适用于不能保证启动期加载 TLS 的环境。
        :param state_symbol: 当前翻译方向使用的 TLS/状态对象符号。两条 RVV
            过渡路径必须传入不同符号，避免把不同 payload 布局解释到同一状态块。
        :param lookup_profile: 程序级间接控制流查表函数的方向编号；旧兼容入口为
            ``0``，RVV1024→RVV256 为 ``1``，RVV256→RVV1024 为 ``2``。
        :param non_tls_state_symbol: 非 TLS 输出使用的状态对象符号。默认值会保留
            旧标量 fixture 的 ``simulated_cpu_state``，专用双向入口则退化为其
            新的方向专用状态符号。
        """
        if non_tls_state_symbol is None:
            non_tls_state_symbol = (
                LEGACY_OUTPUT_CONTRACT.non_tls_state_symbol
                if state_symbol == LEGACY_OUTPUT_CONTRACT.state_symbol
                else state_symbol
            )
        # 状态符号和查表 profile 是翻译输出 ABI 的一对契约字段。二者必须
        # 由同一个后端入口注入，避免只改状态名却仍把控制流查询发到另一
        # 条翻译路径。profile=0 只保留给旧标量/兼容入口。
        self.state_access = StateAccessEmitter(
            state_base_mode=state_base_mode,
            state_symbol=state_symbol,
            lookup_profile=lookup_profile,
            non_tls_state_symbol=non_tls_state_symbol,
            layout=SimulatedStateLayout(vlenb),
        )
        # 程序级间接控制流只读取 StateAccessEmitter 的明确 ABI 字段；
        # ProgramEmitter 不再复制一组同名状态属性，避免两份所有权漂移。
        self.control_flow = ControlFlowEmitter(
            lookup_profile=lookup_profile,
        )
        self.vtype_dispatch = VTypeDispatchEmitter()
        self.vector_block = VectorBlockEmitter(self.state_access)

    def _emit_function_assembly(
        self,
        insn_list: List[RVInstruction],
        state: StateTracker,
        allocator: SimulatedStateLayout,
        dispatcher: BackendDispatcherProtocol,
        func_name: str = "translated_func",
        text_only: bool = False,
        init_vtype: str | None = None,
        raw: bool = False,
        tls_state: bool = True,
        fallback_policy: str = "raise",
        context: EmissionContext | None = None,
        function_analysis: FunctionAnalysis | None = None,
    ) -> str:
        """
        生成单个函数的汇编代码 (带函数标签和 ret)

        :param insn_list: 指令列表
        :param state: 向量状态追踪器
        :param allocator: 寄存器分配器
        :param dispatcher: 指令分发器
        :param func_name: 函数名
        :param text_only: 是否只保留 `.text` 与正文，去掉包装性汇编字段
        :param init_vtype: 用于播种 StateTracker 的 vtype 值，不产生输出
        :param raw: 是否只输出纯翻译块（无函数标签/ret/.comm，仅 state-base load + handler 输出）
        :param tls_state: 是否通过 TLS 访问 simulated_cpu_state
        :param fallback_policy: 后端 profile 声明的失败策略；标量使用
            ``raise``，RVV256 使用 ``ebreak``，过渡后端使用 ``reject``。
        :return: 完整的汇编代码字符串
        """
        lines = []

        if not raw and not text_only:
            lines.append("    .text")
            lines.append("")

        # 在默认模式下，输出完整的函数元数据，方便单独汇编、链接和运行。
        # 但有些 CFG / 静态分析工具只希望看到 `.text` 与正文内容，
        # 不希望额外出现 `.globl/.type/.size/.comm` 这类"包装字段"。
        # 因此这里提供 `text_only` 开关：
        # - False: 保持原有完整输出
        # - True: 仅保留 `.text`、标签与指令正文
        if not raw and not text_only:
            lines.append(f"    .globl  {func_name}")
            lines.append(f"    .type   {func_name}, @function")
        if not raw:
            lines.append(f"{func_name}:")

        # 播种 StateTracker 内部状态 (仅 Python 层面，不产出汇编代码)
        if init_vtype:
            state.apply_init_vtype(init_vtype)

        numeric_labels = {
            insn.address: self.control_flow.translated_local_label(
                func_name, insn.label, insn.address
            )
            for insn in insn_list if insn.label and insn.label.isdigit()
        }
        # 翻译指令
        for insn in insn_list:
            if insn.label and insn.label != func_name:
                lines.append(f"{numeric_labels.get(insn.address, insn.label)}:")
            if self.vtype_dispatch.handles(insn, dispatcher):
                translated = self.vtype_dispatch.dispatch(
                    insn,
                    state,
                    allocator,
                    dispatcher,
                    # 片段模式通常没有 CFG，但如果测试或上层已经把
                    # InstructionAnalysis 挂在指令对象上，仍应沿用同一
                    # vtype 分发合同，而不是重新读取任何文本注释。
                    instruction_analysis=(
                        function_analysis.at(insn.address)
                        if function_analysis is not None
                        else None
                    ),
                    profile=context.backend_profile if context is not None else None,
                    session=context.session if context is not None else None,
                    fallback_policy=fallback_policy,
                )
                lines.extend(self.vector_block.wrap(insn, translated, tls_state=tls_state))
                lines.append("")
            else:
                if is_vlenb_read(insn):
                    lines.append(f"    li      {insn.operands[0]}, {state.vlenb}")
                elif insn.opcode:
                    operands = insn.operands
                    target_index = TextProgramIndex.target_operand_index(insn)
                    target = str(operands[target_index]) if target_index is not None else ""
                    if (not insn.raw_bytes_hex and target[:-1].isdigit()
                            and target[-1:] in {"b", "f"}):
                        edges = function_analysis.structure.cfg.edges_for_source(insn.address)
                        target_address = next((
                            edge.target_address for edge in edges
                            if edge.kind in {
                                CFGEdgeKind.CONDITIONAL_BRANCH, CFGEdgeKind.UNCONDITIONAL_JUMP,
                                CFGEdgeKind.DIRECT_CALL, CFGEdgeKind.TAIL_CALL,
                            }
                        ), None)
                        if target_address not in numeric_labels:
                            raise ValueError(f"0x{insn.address:x}: unresolved numeric local label {target}")
                        operands = list(operands)
                        operands[target_index] = numeric_labels[target_address]
                    lines.extend(self.control_flow.emit_scalar_instruction(insn, operands))

        # 函数返回 (如果没有显式的 ret, 且非 raw 模式)
        if not raw:
            last = next((i for i in reversed(insn_list) if i.opcode), None)
            terminates = last is not None and (
                last.opcode in {"ret", "jr", "j", "tail", "c.j", "c.jr"}
                or (last.opcode == "jalr" and len(last.operands) > 1
                    and str(last.operands[0]).lower() in {"zero", "x0"})
                or (last.opcode == "jal" and len(last.operands) > 1
                    and str(last.operands[0]).lower() in {"zero", "x0"})
            )
            if not terminates:
                lines.append("    ret")
                lines.append("")

        if not raw and not text_only:
            # 函数大小标记
            lines.append(f"    .size   {func_name}, .-{func_name}")
            lines.append("")

        return "\n".join(lines)

    def emit_function(
        self,
        *,
        context: EmissionContext,
        function: RVFunction,
        state_factory: Callable[[], StateTracker],
        allocator_factory: Callable[[], SimulatedStateLayout],
        dispatcher_factory: Callable[[], BackendDispatcherProtocol],
        text_only: bool = False,
        func_name: str = "translated_func",
        raw: bool = False,
        tls_state: bool = True,
    ) -> str:
        """从 ``PreparedTranslation`` 发射兼容的单函数/片段输出。

        与程序模式不同，本入口不添加 ``_translated`` 后缀、原偏移标签或
        程序数据段；但其 CFG/vtype、preflight、profile 和发射会话都来自
        同一个准备结果，不能再绕过流水线现场构造另一套状态判断。
        """

        function_analysis = context.analysis.for_function(function.start_addr)
        if function.instructions and function_analysis is None:
            raise ValueError(
                f"函数 {function.name}@0x{function.start_addr:x} 缺少 FunctionAnalysis"
            )
        return self._emit_function_assembly(
            insn_list=function.instructions,
            state=state_factory(),
            allocator=allocator_factory(),
            dispatcher=dispatcher_factory(),
            func_name=func_name,
            text_only=text_only,
            init_vtype=context.prepared.init_vtype,
            raw=raw,
            tls_state=tls_state,
            fallback_policy=context.backend_profile.fallback_policy,
            context=context,
            function_analysis=function_analysis,
        )

    def emit(
        self,
        context: EmissionContext,
        state_factory: Callable[[], StateTracker],
        allocator_factory: Callable[[], SimulatedStateLayout],
        dispatcher_factory: Callable[[], BackendDispatcherProtocol],
        text_only: bool = False,
        init_vtype: str | None = None,
        lib_name: str = "main",
    ) -> str:
        return "\n".join(self.iter_chunks(
            context, state_factory, allocator_factory, dispatcher_factory,
            text_only=text_only, init_vtype=init_vtype, lib_name=lib_name,
        ))

    def iter_chunks(
        self,
        context: EmissionContext,
        state_factory: Callable[[], StateTracker],
        allocator_factory: Callable[[], SimulatedStateLayout],
        dispatcher_factory: Callable[[], BackendDispatcherProtocol],
        text_only: bool = False,
        init_vtype: str | None = None,
        lib_name: str = "main",
        program_context: dict[str, Mapping[int, str]] | None = None,
    ) -> Iterator[str]:
        """
        按准备结果和本轮发射上下文生成完整 objdump 程序汇编。

        该路径保持 RVV handler 语义不变，只负责函数级包装、局部标签去冲突
        和 `# 原偏移` 注释输出。

        fallback 行为由 ``context.backend_profile`` 唯一决定，调用点不能再用
        布尔参数覆盖后端合同。
        """
        # ``TranslationPipeline.prepare`` 已在任何输出产生前完成全程序
        # 分析、结构校验和后端预检；探测轮不得在这里重复这些线性工作。
        functions = (
            function
            for function in context.program.functions
            if "@plt" not in function.name
        )
        if not text_only:
            yield "    .text"
            yield ""

        dispatcher = dispatcher_factory()

        if program_context is None:
            functions = list(functions)
            program_context = self.control_flow.build_program_context(functions)
        cross_function_veneers = self.control_flow.collect_cross_function_jump_veneers(
            context.analysis.structure.call_graph,
        )
        section_instructions = 0
        section_number = 0
        for function in functions:
            if not function.instructions:
                continue
            if not text_only and section_instructions >= _PROGRAM_SECTION_INSTRUCTIONS:
                section_number += 1
                section_instructions = 0
                # GAS inserts deferred branch relocations into each section's
                # relocation array. Bound that work without splitting a function.
                yield f'    .section .text,"ax",@progbits,unique,{section_number}'

            state = state_factory()
            allocator = allocator_factory()

            yield "\n".join(self._emit_translated_function(
                context=context,
                function=function,
                state=state,
                allocator=allocator,
                dispatcher=dispatcher,
                text_only=text_only,
                init_vtype=init_vtype,
                lib_name=lib_name,
                program_context=program_context,
                cross_function_veneers=cross_function_veneers,
                tls_state=True,
            ).splitlines())
            yield ""
            section_instructions += len(function.instructions)

        if not text_only:
            yield from self._emit_program_data_definitions(lib_name)
            yield ""

    def _emit_translated_function(
        self,
        context: EmissionContext,
        function: RVFunction,
        state: StateTracker,
        allocator: SimulatedStateLayout,
        dispatcher: BackendDispatcherProtocol,
        cross_function_veneers: Mapping[str, tuple[str, str]],
        text_only: bool = False,
        init_vtype: str | None = None,
        lib_name: str = "main",
        program_context: dict[str, Mapping[int, str]] | None = None,
        tls_state: bool = True,
    ) -> str:
        """生成单个 objdump 函数对应的 `<func>_translated`。"""
        # ``emit`` 已在进入函数循环前消费一次性准备结果。
        # 这里不能重复计算输入指纹；完整 dump 的函数数和指令数都可能
        # 很大，函数级重复校验会把线性发射退化为近似平方级开销。
        function_analysis = context.analysis.for_function(function.start_addr)
        if function_analysis is None:
            raise ValueError(
                f"函数 {function.name}@0x{function.start_addr:x} 缺少 FunctionAnalysis"
            )
        program_context = (
            program_context
            or self.control_flow.build_program_context([function])
        )
        translated_name = program_context["function_addresses"][function.start_addr]
        label_map = self.control_flow.build_local_label_map(
            function, translated_name
        )
        address_label_map = program_context["address_labels"]
        control_context = ControlFlowContext(context.analysis.structure, context.options)
        function_address_map = program_context["function_addresses"]
        original_base_symbol = self.control_flow.original_base_symbol_name(lib_name)
        local_addresses = {item.address for item in function.instructions}
        active_long_jump_veneers = self.control_flow.collect_long_jump_veneers(
            control_context,
            function,
            translated_name,
            address_label_map,
            local_addresses,
        )
        lines: List[str] = []

        if not text_only:
            lines.append(f"    .globl  {translated_name}")
            # Both directions export the same names. Internal references must
            # bind to this DSO even when another variant is loaded globally.
            lines.append(f"    .protected {translated_name}")
            lines.append(f"    .type   {translated_name}, @function")
        if init_vtype:
            state.apply_init_vtype(init_vtype)

        for index, insn in enumerate(function.instructions):
            address_label = self.control_flow.translated_address_label(insn.address)
            for veneers in (cross_function_veneers, active_long_jump_veneers):
                if address_label in veneers:
                    veneer_label, skip_label = veneers[address_label]
                    lines.extend(
                        self.control_flow.emit_local_jump_veneer(
                            target_label=address_label,
                            veneer_label=veneer_label,
                            skip_label=skip_label,
                        )
                    )
            # Public/source labels must bypass restoration. Only a saved-frame
            # jump enters the veneer, including at a function's first instruction.
            if index == 0:
                lines.append(f"{translated_name}:")
            if insn.label and insn.label != function.name:
                label = (
                    self.control_flow.translated_local_label(
                        function.name, insn.label, insn.address
                    )
                    if insn.label.isdigit()
                    else label_map.get(insn.label, insn.label)
                )
                lines.append(f"{label}:")
            if address_label:
                lines.append(f"{address_label}:")

            lines.append(f"    # 原偏移: 0x{insn.address:x}")

            if self.vtype_dispatch.handles(insn, dispatcher):
                translated = self.vtype_dispatch.dispatch(
                    insn,
                    state,
                    allocator,
                    dispatcher,
                    instruction_analysis=function_analysis.at(insn.address),
                    profile=context.backend_profile, session=context.session,
                    fallback_policy=context.backend_profile.fallback_policy,
                )
                lines.extend(self.vector_block.wrap(insn, translated, tls_state=tls_state))
                lines.append("")
                continue

            if is_vlenb_read(insn):
                lines.append(f"    li      {insn.operands[0]}, {state.vlenb}")
                continue

            if insn.opcode:
                operands = self.control_flow.rewrite_operands(
                    insn,
                    function,
                    label_map,
                    address_label_map,
                    function_address_map,
                    context=control_context,
                )
                if (
                    context.options.emit_jump_site_markers
                    and insn.opcode == "j"
                    and self.control_flow.local_jump_target_label(
                        control_context,
                        function,
                        insn,
                        address_label_map,
                        local_addresses,
                    )
                    is not None
                ):
                    # 该标签只用于把可重定位对象中的 R_RISCV_JAL 映射回
                    # 源指令地址；它不是 branch_j_target，也不会进入迁移表。
                    lines.append(f"chimera_j_site_{insn.address:x}:")
                lines.extend(
                    self.control_flow.emit_program_scalar(
                        insn,
                        operands=operands,
                        base_delta_symbol=original_base_symbol,
                        context=control_context,
                        active_long_jump_veneers=active_long_jump_veneers,
                    )
                )

        if not text_only:
            lines.append(f"    .size   {translated_name}, .-{translated_name}")

        return "\n".join(lines)

    def _emit_program_data_definitions(
        self,
        lib_name: str,
    ) -> List[str]:
        """Emit data definitions that used to be supplied by offline post-processing."""
        # simulated state 由在线运行时定义；翻译输出只负责原始映像基址槽。
        # 起始空行保留既有汇编排版，避免无语义的 golden 输出漂移。
        lines: List[str] = [""]

        base_sym = self.control_flow.original_base_symbol_name(lib_name)
        lines.extend([
            "    .section .data",
            "    .balign 8",
            f"    .globl {base_sym}",
            f"    .type {base_sym}, @object",
            f"    .size {base_sym}, 8",
            f"{base_sym}:",
            "    .zero 8",
        ])
        return lines
