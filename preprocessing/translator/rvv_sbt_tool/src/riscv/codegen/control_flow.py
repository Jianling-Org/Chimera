"""RISC-V 控制流重写及本轮发射输入。"""

from __future__ import annotations

from dataclasses import dataclass
from riscv.frontend.model import CFGEdgeKind
from riscv.frontend.literals import parse_integer_literal
from riscv.frontend.model import PLTTarget, ProgramStructure
import re
from collections import Counter
from collections.abc import Iterable, Iterator, Mapping
from array import array
from bisect import bisect_left
from typing import Any, Callable
from riscv.registers import CALL_CLOBBERED_FPRS, CALL_CLOBBERED_GPRS, normalize_gpr_name
from riscv.frontend.model import CallEdge, CallEdgeKind, CallGraph
from riscv.frontend.model import RVFunction, RVInstruction
from riscv.frontend.text_index import TextProgramIndex


_QUERY_FP_START = len(CALL_CLOBBERED_GPRS) * 8
_QUERY_FCSR_SLOT = _QUERY_FP_START + len(CALL_CLOBBERED_FPRS) * 8
_QUERY_EXTRA_START = _QUERY_FCSR_SLOT + 8


@dataclass(frozen=True)
class EmissionOptions:
    """单轮发射选项；JAL 探测只改变这部分状态。"""

    long_jump_sites: frozenset[int] = frozenset()
    emit_jump_site_markers: bool = False

    def __post_init__(self) -> None:
        try:
            normalized = frozenset(int(site) for site in self.long_jump_sites)
        except (TypeError, ValueError) as exc:
            raise ValueError(
                "long_jump_sites 必须是可转换为整数的源指令地址集合"
            ) from exc
        if any(site < 0 for site in normalized):
            raise ValueError("long_jump_sites 不能包含负数源指令地址")
        object.__setattr__(self, "long_jump_sites", normalized)


@dataclass(frozen=True)
class ControlFlowContext:
    structure: ProgramStructure
    options: EmissionOptions


class AddressLabels(Mapping[int, str]):
    """Format deterministic labels on demand instead of retaining N strings."""

    def __init__(self, addresses: Iterable[int], label: Callable[[int], str]):
        ordered = sorted(addresses)
        self.addresses = array("Q", (
            address for index, address in enumerate(ordered)
            if index == 0 or address != ordered[index - 1]
        ))
        self.label = label

    def __getitem__(self, address: int) -> str:
        index = bisect_left(self.addresses, address)
        if index == len(self.addresses) or self.addresses[index] != address:
            raise KeyError(address)
        return self.label(address)

    def __iter__(self) -> Iterator[int]:
        return iter(self.addresses)

    def __len__(self) -> int:
        return len(self.addresses)


class ControlFlowEmitter:
    """集中实现程序标签、直接跳转、间接查表和 JAL 跳板。"""

    _mem_operand_pattern = re.compile(
        r"^(?P<offset>[-+]?(?:0[xX][0-9a-fA-F]+|0[bB][01]+|\d+))?"
        r"\((?P<base>[A-Za-z][A-Za-z0-9]*)\)$"
    )

    def __init__(self, *, lookup_profile: int):
        self.lookup_profile = lookup_profile

    @staticmethod
    def sanitize_symbol_component(name: str) -> str:
        """把 objdump 符号收窄为保守的 assembler 符号。"""

        sanitized = re.sub(r"[^A-Za-z0-9_.$]", "_", name)
        if not sanitized:
            sanitized = "anonymous"
        if sanitized[0].isdigit():
            sanitized = f"fn_{sanitized}"
        return sanitized

    def translated_function_name(self, name: str) -> str:
        return f"{self.sanitize_symbol_component(name)}_translated"

    def translated_local_label(
        self, function_name: str, label: str, address: int
    ) -> str:
        safe_func = self.sanitize_symbol_component(function_name)
        safe_label = self.sanitize_symbol_component(label).replace(".", "_")
        return f".Lchimera_{safe_func}_{safe_label}_{address:x}"

    @staticmethod
    def translated_address_label(address: int) -> str:
        return f"branch_j_target_{address:x}"

    def original_base_symbol_name(self, lib_name: str) -> str:
        return f"{self.sanitize_symbol_component(lib_name)}_original_base_addr"

    def build_program_context(
        self, functions: list[RVFunction]
    ) -> dict[str, Mapping[int, str]]:
        """构造全程序唯一的函数和原地址标签表。"""

        name_counts = Counter(function.name for function in functions)
        function_addresses: dict[int, str] = {}
        for function in functions:
            if name_counts[function.name] > 1:
                translated_name = (
                    f"{self.sanitize_symbol_component(function.name)}_"
                    f"{function.start_addr:x}_translated"
                )
            else:
                translated_name = self.translated_function_name(function.name)
            function_addresses[function.start_addr] = translated_name

        address_labels = AddressLabels(
            (insn.address for function in functions for insn in function.instructions),
            self.translated_address_label,
        )
        return {
            "function_addresses": function_addresses,
            "address_labels": address_labels,
        }

    def build_local_label_map(
        self, function: RVFunction, translated_name: str
    ) -> dict[str, str]:
        label_map = {function.name: translated_name}
        for insn in function.instructions:
            if not insn.label or insn.label == function.name:
                continue
            label_map[insn.label] = self.translated_local_label(
                function.name, insn.label, insn.address
            )
        return label_map

    @staticmethod
    def _analysis_control_flow_edge(
        context: ControlFlowContext | None,
        function: RVFunction,
        insn: RVInstruction,
    ) -> Any | None:
        if context is None or context.structure is None:
            return None
        function_analysis = context.structure.functions.get(function.start_addr)
        if function_analysis is None:
            return None
        return next(
            (
                edge
                for edge in function_analysis.cfg.edges_for_source(insn.address)
                if edge.kind
                in {
                    CFGEdgeKind.CONDITIONAL_BRANCH,
                    CFGEdgeKind.UNCONDITIONAL_JUMP,
                    CFGEdgeKind.DIRECT_CALL,
                    CFGEdgeKind.TAIL_CALL,
                }
            ),
            None,
        )

    def local_jump_target_label(
        self,
        context: ControlFlowContext,
        function: RVFunction,
        insn: RVInstruction,
        address_label_map: Mapping[int, str],
        local_addresses: set[int] | frozenset[int] | None = None,
    ) -> str | None:
        """仅为 CFG 证明的同函数 ``j`` 返回本地目标标签。"""

        if insn.opcode != "j":
            return None
        edge = self._analysis_control_flow_edge(context, function, insn)
        target_address = getattr(edge, "target_address", None)
        if local_addresses is None:
            local_addresses = {item.address for item in function.instructions}
        if target_address not in local_addresses:
            return None
        return address_label_map.get(target_address)

    def _long_jump_veneer_labels(
        self, translated_name: str, target_label: str
    ) -> tuple[str, str]:
        safe_function = self.sanitize_symbol_component(translated_name)
        safe_target = self.sanitize_symbol_component(target_label)
        stem = f"{safe_function}_{safe_target}"
        return (
            f".Lchimera_veneer_{stem}",
            f".Lchimera_veneer_skip_{stem}",
        )

    def collect_long_jump_veneers(
        self,
        context: ControlFlowContext,
        function: RVFunction,
        translated_name: str,
        address_label_map: Mapping[int, str],
        local_addresses: set[int] | frozenset[int],
    ) -> dict[str, tuple[str, str]]:
        """按目标共享本轮确认超范围的本地 ``j`` 跳板。"""

        veneers: dict[str, tuple[str, str]] = {}
        for insn in function.instructions:
            if insn.address not in context.options.long_jump_sites:
                continue
            target_label = self.local_jump_target_label(
                context,
                function,
                insn,
                address_label_map,
                local_addresses,
            )
            if target_label is not None:
                veneers.setdefault(
                    target_label,
                    self._long_jump_veneer_labels(translated_name, target_label),
                )
        return veneers

    def collect_cross_function_jump_veneers(
        self, call_graph: CallGraph | None,
    ) -> dict[str, tuple[str, str]]:
        # Global call-graph facts remain resident for streamed programs. Avoid
        # loading every function's instructions just to find incoming jumps.
        veneers = {}
        if call_graph is not None:
            for edge in call_graph.edge_by_call_address.values():
                target = self._cross_function_jump_target(edge)
                if target is not None:
                    label = self.translated_address_label(target)
                    veneers.setdefault(
                        label, self._long_jump_veneer_labels("cross_function", label),
                    )
        return veneers

    @staticmethod
    def emit_local_jump_veneer(
        target_label: str, veneer_label: str, skip_label: str
    ) -> list[str]:
        return [
            f"    j       {skip_label}",
            f"{veneer_label}:",
            "    ld      t0, 0(sp)",
            "    addi    sp, sp, 16",
            f"    j       {target_label}",
            f"{skip_label}:",
        ]

    @staticmethod
    def _emit_local_long_jump(
        veneer_label: str, source_address: int
    ) -> list[str]:
        # ``%pcrel_lo`` 必须引用 AUIPC 所在的配对标签，否则
        # GNU linker 会报 missing matching %pcrel_hi。
        pair_label = f".Lchimera_pcrel_j_{source_address:x}"
        return [
            "    addi    sp, sp, -16  # 保存 j 的 t0，保持原指令寄存器语义",
            "    sd      t0, 0(sp)",
            f"{pair_label}:",
            f"    auipc   t0, %pcrel_hi({veneer_label})",
            f"    jalr    x0, %pcrel_lo({pair_label})(t0)",
        ]

    def rewrite_operands(
        self,
        insn: RVInstruction,
        function: RVFunction,
        label_map: dict[str, str],
        address_label_map: Mapping[int, str],
        function_address_map: dict[int, str],
        *,
        context: ControlFlowContext | None,
    ) -> list[object]:
        """只按 CFG/调用图证据重写直接控制流目标。"""

        rewritten: list[object] = []
        target_index = self._direct_control_flow_target_index(insn)
        edge = (
            self._analysis_control_flow_edge(context, function, insn)
            if target_index is not None else None
        )
        for index, operand in enumerate(insn.operands):
            if not isinstance(operand, str):
                rewritten.append(operand)
                continue
            if target_index == index:
                mapped = self._map_control_flow_edge_target(
                    insn=insn,
                    edge=edge,
                    context=context,
                    address_label_map=address_label_map,
                    function_address_map=function_address_map,
                )
                if mapped is not None:
                    rewritten.append(mapped)
                    continue
            if target_index != index and operand in label_map:
                rewritten.append(label_map[operand])
            else:
                rewritten.append(operand)
        return rewritten

    @staticmethod
    def _map_control_flow_edge_target(
        *,
        insn: RVInstruction,
        edge: object,
        context: ControlFlowContext | None,
        address_label_map: Mapping[int, str],
        function_address_map: dict[int, str],
    ) -> str | None:
        if edge is None:
            return None
        target_address = getattr(edge, "target_address", None)
        if target_address is None:
            return None

        call_edge = None
        if context is not None and context.structure.call_graph is not None:
            call_edge = context.structure.call_graph.edge_for_call(insn.address)
        if (
            call_edge is not None
            and call_edge.target_function_start is not None
            and call_edge.target_is_function_entry
        ):
            mapped = function_address_map.get(call_edge.target_function_start)
            if mapped is not None:
                return mapped
        mapped = address_label_map.get(target_address)
        if mapped is not None:
            return mapped
        return None

    @staticmethod
    def _direct_control_flow_target_index(insn: RVInstruction) -> int | None:
        if insn.opcode in {"j", "call", "tail"}:
            return 0 if insn.operands else None
        if insn.opcode == "jal":
            return len(insn.operands) - 1 if insn.operands else None
        if insn.opcode in {"beqz", "bnez", "blez", "bgez", "bltz", "bgtz"}:
            return 1
        if insn.opcode in {"beq", "bne", "blt", "bge", "bltu", "bgeu"}:
            return 2
        return None

    @staticmethod
    def _cross_function_jump_target(edge: CallEdge | None) -> int | None:
        """Return the exact target of a proven internal cross-function tail edge."""
        if (
            edge is None
            or edge.kind is not CallEdgeKind.TAIL_CALL
            or not edge.resolved
            or edge.target_address is None
            or edge.target_function_start is None
            or edge.caller_function_start == edge.target_function_start
        ):
            return None
        return edge.target_address

    def _emit_direct_control_flow_instruction(
        self,
        insn: RVInstruction,
        operands: list[object],
        *,
        context: ControlFlowContext | None,
        active_long_jump_veneers: dict[str, tuple[str, str]],
        original_base_symbol: str,
    ) -> list[str] | None:
        target_index = self._direct_control_flow_target_index(insn)
        if target_index is None or not operands:
            return None
        target_op = str(operands[target_index]).strip()
        is_plt_target = "@plt" in target_op

        if is_plt_target:
            candidate = context.structure.plt_candidates.get(insn.address) if context else None
            if insn.opcode in {"call", "tail", "j"}:
                return self._emit_plt_target_lookup(
                    insn, target_op, tail=insn.opcode != "call",
                    plt_target=candidate, original_base_symbol=original_base_symbol,
                )
            if insn.opcode == "jal":
                rd = str(operands[0]).strip() if len(operands) > 1 else "ra"
                if rd in {"ra", "x1", "zero", "x0"}:
                    return self._emit_plt_target_lookup(
                        insn, target_op, tail=rd in {"zero", "x0"},
                        plt_target=candidate, original_base_symbol=original_base_symbol,
                    )

        if insn.opcode == "call":
            return [f"    call    {target_op}"]
        if insn.opcode == "tail":
            return [f"    tail    {target_op}"]
        if insn.opcode == "j" or (
            insn.opcode == "jal" and len(operands) > 1
            and str(operands[0]).strip() in {"zero", "x0"}
        ):
            call_graph = context.structure.call_graph if context else None
            target = self._cross_function_jump_target(
                call_graph.edge_for_call(insn.address) if call_graph else None
            )
            if target is not None:
                # An original JAL x0 writes no GPR. A tail pseudoinstruction
                # would consume t1 whenever the linker cannot shorten it.
                target_label = self.translated_address_label(target)
                veneer, _ = self._long_jump_veneer_labels("cross_function", target_label)
                return self._emit_local_long_jump(veneer, insn.address)
        if insn.opcode == "j":
            veneer = active_long_jump_veneers.get(target_op)
            if (
                context is not None
                and insn.address in context.options.long_jump_sites
                and veneer is not None
            ):
                return self._emit_local_long_jump(veneer[0], insn.address)
            return [f"    j       {target_op}"]

        if insn.opcode != "jal":
            return None
        if len(operands) == 1:
            return [f"    call    {target_op}"]
        rd = str(operands[0]).strip()
        if rd in {"x0", "zero"}:
            return [f"    j       {target_op}"]
        if rd in {"ra", "x1"}:
            return [f"    call    {target_op}"]
        if is_plt_target:
            return self._emit_unsupported_scalar_fallback(
                insn,
                "custom link-register direct calls to @plt are not supported; "
                "RISC-V psABI reserves @plt call relocations for call/tail pseudoinstructions",
            )
        return None

    def _emit_plt_target_lookup(
        self, insn: RVInstruction, target: str, *, tail: bool,
        plt_target: PLTTarget | None, original_base_symbol: str,
    ) -> list[str]:
        """Resolve a DSO GOT function address before selecting its code variant."""
        symbol = target.removesuffix("@plt")
        lines = self._emit_query_call_prologue(extra_slots=1)
        lines.extend(self._emit_plt_address_load(
            insn, symbol, plt_target, original_base_symbol,
        ))
        lines.extend(self._emit_checked_query_call())
        # t1 is a caller-saved scratch register also used by tail expansion.
        lines.append("    mv      t1, a0")
        lines.extend(self._emit_query_restore_registers(skip={"t1"}))
        lines.extend((
            f"    addi    sp, sp, {self._query_frame_size(extra_slots=1)}",
            f"    jalr    {'x0' if tail else 'ra'}, 0(t1)",
        ))
        return lines

    @staticmethod
    def _emit_plt_address_load(
        insn: RVInstruction, symbol: str, plt_target: PLTTarget | None,
        original_base_symbol: str,
    ) -> list[str]:
        if not re.fullmatch(r"[A-Za-z_.$][A-Za-z0-9_.$]*", symbol):
            if (not re.fullmatch(r"\*ABS\*\+0x[0-9a-fA-F]+", symbol)
                    or plt_target is None or plt_target.got_address is None):
                raise ValueError(
                    f"0x{insn.address:x}: cannot resolve PLT target {symbol}@plt: "
                    "no ordinary symbol or recognized RV64 IFUNC GOT slot"
                )
            # The loader has already resolved IRELATIVE slots. Calling the
            # address encoded in *ABS*+... would instead invoke the resolver.
            return [
                f"    la      a1, {original_base_symbol}",
                "    ld      a1, 0(a1)",
                f"    li      t0, {plt_target.got_address}",
                "    add     a1, a1, t0",
                "    ld      a1, 0(a1)",
            ]
        pair_label = f".Lchimera_plt_got_{insn.address:x}"
        return [
            f"{pair_label}:",
            f"    auipc   a1, %got_pcrel_hi({symbol})",
            f"    ld      a1, %pcrel_lo({pair_label})(a1)",
        ]

    def emit_scalar_instruction(
        self,
        insn: RVInstruction,
        operands: list[object] | None = None,
    ) -> list[str]:
        operands = insn.operands if operands is None else operands
        if insn.opcode == "fence" and operands == ["w", "unknown"]:
            return ["    fence.tso"]
        if operands:
            return [
                f"    {insn.opcode:<8} "
                + ", ".join(str(operand) for operand in operands)
            ]
        return [f"    {insn.opcode}"]

    def emit_program_scalar(
        self,
        insn: RVInstruction,
        operands: list[object],
        base_delta_symbol: str,
        *,
        context: ControlFlowContext | None,
        active_long_jump_veneers: dict[str, tuple[str, str]],
    ) -> list[str]:
        direct = self._emit_direct_control_flow_instruction(
            insn,
            operands,
            context=context,
            active_long_jump_veneers=active_long_jump_veneers,
            original_base_symbol=base_delta_symbol,
        )
        if direct is not None:
            return direct
        if insn.opcode == "auipc" and len(operands) >= 2:
            return self._emit_auipc_with_original_base(
                insn, operands, base_delta_symbol
            )
        if insn.opcode in {"jalr", "jr", "ret"}:
            candidate = context.structure.plt_candidates.get(insn.address) if context else None
            return self._emit_indirect_jump_lookup(
                insn, operands, plt_candidate=candidate,
                original_base_symbol=base_delta_symbol,
            )
        return self.emit_scalar_instruction(insn, operands)

    @staticmethod
    def _emit_auipc_with_original_base(
        insn: RVInstruction,
        operands: list[object],
        original_base_symbol: str,
    ) -> list[str]:
        rd = normalize_gpr_name(str(operands[0])) or str(operands[0])
        temp = "t1" if rd == "t0" else "t0"
        imm_str = str(operands[1]).strip()
        offset_32bit = TextProgramIndex.auipc_displacement(insn)
        target_rel_addr = insn.address + offset_32bit
        if rd == "sp":
            # Commit SP only after the old stack has restored every temporary.
            return [
                f"    # auipc translation: original address 0x{insn.address:x}, imm {imm_str}",
                "    addi    sp, sp, -32",
                "    sd      t0, 0(sp)",
                "    sd      t1, 8(sp)",
                f"    la      t0, {original_base_symbol}",
                "    ld      t0, 0(t0)",
                f"    li      t1, {target_rel_addr}",
                "    add     t0, t0, t1",
                "    sd      t0, 16(sp)",
                "    ld      t1, 8(sp)",
                "    ld      t0, 0(sp)",
                "    ld      sp, 16(sp)",
            ]
        return [
            f"    # auipc translation: original address 0x{insn.address:x}, imm {imm_str}",
            "    addi    sp, sp, -16",
            f"    sd      {temp}, 0(sp)",
            f"    la      {temp}, {original_base_symbol}",
            f"    ld      {temp}, 0({temp})",
            f"    li      {rd}, {target_rel_addr}",
            f"    add     {rd}, {rd}, {temp}",
            f"    ld      {temp}, 0(sp)",
            "    addi    sp, sp, 16",
        ]

    def _emit_indirect_jump_lookup(
        self, insn: RVInstruction, operands: list[object], *,
        plt_candidate: PLTTarget | None = None,
        original_base_symbol: str = "",
    ) -> list[str]:
        try:
            parsed = self._parse_indirect_jump_operands(insn.opcode, operands)
        except ValueError as exc:
            raise ValueError(
                f"Invalid {insn.opcode} at {insn.address:#x}: {insn.op_str}: {exc}"
            ) from exc
        if parsed is None:
            raise ValueError(f"Invalid {insn.opcode} operands at {insn.address:#x}: {insn.op_str}")
        rd, base_reg, offset = parsed
        base_reg = normalize_gpr_name(base_reg)
        if base_reg is None:
            raise ValueError(f"Invalid {insn.opcode} base register at {insn.address:#x}: {insn.op_str}")
        link_reg = normalize_gpr_name(rd) if rd else ("zero" if insn.opcode == "jr" else "ra")
        no_link = link_reg == "zero"
        target_slot = _QUERY_EXTRA_START
        original_target_slot = target_slot + 8
        extra_slots = 2 if no_link else 1
        frame_size = self._query_frame_size(extra_slots=extra_slots)
        lines = [
            f"    # {insn.opcode} target remap: translated/original address -> translated address",
            *self._emit_query_call_prologue(extra_slots=extra_slots),
        ]
        # The prologue uses t0 to save fcsr. Read volatile source registers
        # from their saved slots rather than from the now-modified registers.
        if base_reg in CALL_CLOBBERED_GPRS:
            slot = CALL_CLOBBERED_GPRS.index(base_reg) * 8
            lines.append(f"    ld      a1, {slot}(sp)")
        elif base_reg == "sp":
            lines.append(f"    addi    a1, sp, {frame_size}")
        else:
            lines.append(f"    mv      a1, {base_reg}")
        if offset:
            lines.append(f"    addi    a1, a1, {offset}")
        lines.append("    andi    a1, a1, -2")
        if no_link:
            lines.append(f"    sd      a1, {original_target_slot}(sp)")
        if plt_candidate is not None:
            query_label = f".Lchimera_indirect_query_{insn.address:x}"
            lines.extend((
                f"    la      t0, {original_base_symbol}",
                "    ld      t0, 0(t0)",
                f"    li      t1, {plt_candidate.address}",
                "    add     t0, t0, t1",
                f"    bne     a1, t0, {query_label}",
            ))
            symbol = plt_candidate.symbol.removesuffix("@plt")
            lines.extend(self._emit_plt_address_load(
                insn, symbol, plt_candidate, original_base_symbol,
            ))
            lines.append(f"{query_label}:")
        lines.extend(self._emit_checked_query_call())
        if no_link:
            # A no-link jump cannot borrow a source GPR for the mapped target.
            # Keep identity jumps exact and reject remaps with the source state
            # restored, including RET's read-only ra.
            reject_label = f".Lchimera_indirect_reject_{insn.address:x}"
            lines.extend((
                f"    ld      t0, {original_target_slot}(sp)",
                f"    bne     a0, t0, {reject_label}",
                *self._emit_query_call_epilogue(extra_slots=extra_slots),
                *self.emit_scalar_instruction(insn, operands),
                f"{reject_label}:",
                *self._emit_query_call_epilogue(extra_slots=extra_slots),
                "    # Unsupported no-link indirect target remap",
                "    ebreak",
            ))
            return lines
        lines.append(f"    sd      a0, {target_slot}(sp)")
        jump_reg = link_reg
        if jump_reg in {"sp", "zero"}:
            jump_reg = "t1"
        lines.extend(self._emit_query_restore_registers(skip={jump_reg}))
        lines.append(f"    ld      {jump_reg}, {target_slot}(sp)")
        lines.append(f"    addi    sp, sp, {frame_size}")
        if rd:
            lines.append(f"    jalr    {rd}, 0({jump_reg})")
        else:
            lines.append(f"    jalr    {jump_reg}")
        return lines

    def _parse_indirect_jump_operands(
        self, opcode: str, operands: list[object]
    ) -> tuple[str | None, str, int] | None:
        string_ops = [str(operand).strip() for operand in operands]
        if opcode == "ret":
            return ("zero", "ra", 0) if not string_ops else None
        if opcode == "jr":
            if len(string_ops) != 1:
                return None
            base_reg, offset = self._parse_jump_target_operand(string_ops[0])
            return (None, base_reg, offset) if base_reg is not None else None
        if len(string_ops) == 1:
            base_reg, offset = self._parse_jump_target_operand(string_ops[0])
            return (None, base_reg, offset) if base_reg is not None else None
        if len(string_ops) == 3:
            try:
                return string_ops[0], string_ops[1], parse_integer_literal(string_ops[2])
            except ValueError as exc:
                raise ValueError(f"Invalid JALR offset: {string_ops[2]!r}") from exc
        if len(string_ops) == 2:
            base_reg, offset = self._parse_jump_target_operand(string_ops[1])
            return (
                (string_ops[0], base_reg, offset)
                if base_reg is not None
                else None
            )
        return None

    def _parse_jump_target_operand(self, operand: str) -> tuple[str | None, int]:
        match = self._mem_operand_pattern.match(operand)
        if not match:
            if "(" in operand or ")" in operand:
                raise ValueError(f"Invalid JALR target operand: {operand!r}")
            return operand, 0
        try:
            offset = parse_integer_literal(match.group("offset") or "0")
        except ValueError as exc:
            raise ValueError(f"Invalid JALR offset in {operand!r}") from exc
        return match.group("base"), offset

    def _emit_checked_query_call(self) -> list[str]:
        # The caller reserves one extra slot, reused for the result by JALR.
        # Keep the request for diagnosis even if the query clobbers a1. This
        # interior trap has no reverse-map entry: Runtime must terminate, not
        # restore an original PC while the query frame is still active.
        return [
            f"    sd      a1, {_QUERY_EXTRA_START}(sp)",
            f"    li      a0, {self.lookup_profile}",
            "    call    query_original_translated_map@plt",
            "    bnez    a0, 1f",
            f"    ld      a1, {_QUERY_EXTRA_START}(sp)",
            f"    li      a0, {self.lookup_profile}",
            "    ebreak",
            "1:",
        ]

    def _emit_query_call_prologue(self, extra_slots: int = 0) -> list[str]:
        frame_size = self._query_frame_size(extra_slots)
        lines = [f"    addi    sp, sp, -{frame_size}"]
        lines.extend(
            f"    sd      {register}, {index * 8}(sp)"
            for index, register in enumerate(
                CALL_CLOBBERED_GPRS
            )
        )
        lines.extend(
            f"    fsd     {register}, {_QUERY_FP_START + index * 8}(sp)"
            for index, register in enumerate(CALL_CLOBBERED_FPRS)
        )
        lines.extend(("    frcsr   t0", f"    sd      t0, {_QUERY_FCSR_SLOT}(sp)"))
        return lines

    def _emit_query_call_epilogue(self, extra_slots: int = 0) -> list[str]:
        lines = self._emit_query_restore_registers()
        lines.append(f"    addi    sp, sp, {self._query_frame_size(extra_slots)}")
        return lines

    def _emit_query_restore_registers(
        self, skip: set[str] | None = None
    ) -> list[str]:
        skip = skip or set()
        # Restore fcsr before t0, and preserve FP arguments and return values
        # across every injected query, including callback JALR and RET.
        return [
            f"    ld      t0, {_QUERY_FCSR_SLOT}(sp)",
            "    fscsr   t0",
            *(
                f"    fld     {register}, {_QUERY_FP_START + index * 8}(sp)"
                for index, register in enumerate(CALL_CLOBBERED_FPRS)
            ),
        ] + [
            f"    ld      {register}, {index * 8}(sp)"
            for index, register in enumerate(
                CALL_CLOBBERED_GPRS
            )
            if register not in skip
        ]

    def _query_frame_size(self, extra_slots: int = 0) -> int:
        slots = _QUERY_EXTRA_START // 8 + extra_slots
        return ((slots * 8 + 15) // 16) * 16

    @staticmethod
    def _emit_unsupported_scalar_fallback(
        insn: RVInstruction, reason: str
    ) -> list[str]:
        return [
            f"    # Unsupported scalar instruction lowered to ebreak: "
            f"{insn.opcode} {insn.op_str}".rstrip(),
            f"    # Reason: {reason}",
            "    ebreak",
        ]
