"""Scalar expression propagation over the instruction CFG."""

from __future__ import annotations

from collections import deque
import warnings as py_warnings

from ...core.data_model import Function, Instruction
from ...core.contracts import StackSemantics
from ...core.monitor import argument, monitored, returned
from .model import (
    AnalysisWarning,
    ExpressionState,
    FunctionExpressionResult,
    IrreducibleLoopWarning,
    LoopInfo,
    StackAccessKind,
)
from .loops import _LoopAnalyzer
from .expressions import (
    Constant,
    Expr,
    LoopInput,
    PostLoopInput,
    Unknown,
    _Unknown,
    substitute,
    walk_loop_inputs,
)

# region Unified CFG expression analysis


class _ScalarExpressionSolver:
    """Propagate scalar expressions on the full instruction CFG.

    Natural-loop back edges are ignored only by this expression analysis.
    At a loop header, every register written anywhere in that natural loop is
    replaced with a stable ``loop_<header>(reg)`` input before the header
    instruction executes.  Irreducible-loop instructions conservatively set
    their written scalar registers to ``Unknown``.
    """

    def __init__(self, semantics: StackSemantics) -> None:
        self._stack_semantics = semantics
        self._semantics = semantics.symbolic

    def analyze(
        self,
        function: Function,
        loop_info: LoopInfo,
    ) -> dict[int, ExpressionState]:
        if not function.insts:
            return {}

        instructions = function.instruction_by_address
        entry = function.insts[0].addr
        incoming: dict[int, ExpressionState] = {
            entry: self._semantics.initial_state()
        }
        before_states: dict[int, ExpressionState] = {}
        outgoing_states: dict[int, ExpressionState] = {}
        header_inputs: dict[int, ExpressionState] = {}
        worklist: deque[int] = deque([entry])
        queued = {entry}

        while worklist:
            address = worklist.popleft()
            queued.discard(address)
            instruction = instructions[address]
            if address in loop_info.header_written_registers:
                header_inputs[address] = dict(incoming[address])
            before = self._apply_header_summary(
                address,
                incoming[address],
                loop_info,
            )
            before_states[address] = before

            if address in loop_info.irreducible_addresses:
                outgoing = self._irreducible_transfer(instruction, before)
            else:
                outgoing = self._semantics.transfer_instruction(instruction, before)

            if outgoing == outgoing_states.get(address):
                continue
            outgoing_states[address] = outgoing

            for successor in instruction.succ:
                if successor not in instructions:
                    continue
                if (address, successor) in loop_info.back_edges:
                    continue
                current = incoming.get(successor)
                merged = (
                    dict(outgoing)
                    if current is None
                    else self._semantics.join_states((current, outgoing))
                )
                if merged == current:
                    continue
                incoming[successor] = merged
                if successor not in queued:
                    worklist.append(successor)
                    queued.add(successor)

        self._normalize_loop_exits(
            function, loop_info, before_states, outgoing_states, header_inputs
        )
        return before_states

    def _normalize_loop_exits(
        self,
        function: Function,
        loop_info: LoopInfo,
        before_states: dict[int, ExpressionState],
        outgoing_states: dict[int, ExpressionState],
        header_inputs: dict[int, ExpressionState],
    ) -> None:
        instructions = function.instruction_by_address
        # Per-loop replacement maps, in innermost-first order.
        plans: list[tuple[frozenset[int], dict[Expr, Expr]]] = []
        for loop in loop_info.natural_loops:
            exit_edges = [
                (address, successor)
                for address in loop.addresses
                for successor in instructions[address].succ
                if successor in instructions and successor not in loop.addresses
            ]
            if not exit_edges:
                continue
            replacements: dict[Expr, Expr] = {}
            for register in loop.written_registers:
                symbol = LoopInput(loop.header, register)
                exit_values = [outgoing_states.get(tail, {}).get(register, Unknown) for tail, _ in exit_edges]
                if exit_values and all(value == symbol for value in exit_values):
                    replacement = header_inputs.get(loop.header, {}).get(register, Unknown)
                    if isinstance(replacement, Expr):
                        replacements[symbol] = replacement
                else:
                    replacements[symbol] = PostLoopInput(loop.header, register)
            if replacements:
                plans.append((loop.addresses, replacements))
        if not plans:
            return

        # Reverse index: loop_input symbol -> addresses whose state references it.
        # substitute() is a no-op on any state that does not mention the symbol,
        # so only indexed addresses ever change; reaching them via the index
        # avoids the per-loop forward reachability BFS entirely.
        index: dict[Expr, set[int]] = {}
        for address, state in before_states.items():
            for value in state.values():
                if isinstance(value, Expr):
                    for symbol in walk_loop_inputs(value):
                        index.setdefault(symbol, set()).add(address)

        for loop_addresses, replacements in plans:
            affected: set[int] = set()
            for symbol in replacements:
                affected |= index.get(symbol, set())
            affected -= loop_addresses
            for address in affected:
                state = before_states.get(address)
                if state is None:
                    continue
                new_state = {
                    register: substitute(value, replacements) if isinstance(value, Expr) else value
                    for register, value in state.items()
                }
                before_states[address] = new_state
                # The address no longer references the replaced symbols.
                for symbol in replacements:
                    bucket = index.get(symbol)
                    if bucket is not None:
                        bucket.discard(address)
                # Substitution may inject outer-loop loop_input symbols (from
                # header_inputs); index them so the enclosing loop, which is
                # processed later (innermost-first), still reaches this address.
                for value in new_state.values():
                    if isinstance(value, Expr):
                        for symbol in walk_loop_inputs(value):
                            index.setdefault(symbol, set()).add(address)


    def address_expression(
        self,
        operand: str,
        state: ExpressionState,
    ) -> Expr | _Unknown:
        return self._semantics.address_expression(operand, state)

    def _apply_header_summary(
        self,
        address: int,
        incoming: ExpressionState,
        loop_info: LoopInfo,
    ) -> ExpressionState:
        written = loop_info.header_written_registers.get(address)
        if not written:
            return dict(incoming)
        result = dict(incoming)
        for register in written:
            result[register] = self._semantics.loop_input(address, register)
        result["zero"] = self._semantics.constant(0)
        return result

    def _irreducible_transfer(
        self,
        instruction: Instruction,
        before: ExpressionState,
    ) -> ExpressionState:
        result = dict(before)
        for register in self._stack_semantics.written_scalar_registers(instruction):
            result[register] = Unknown
        result["zero"] = Constant(0)
        return result


class _FunctionExpressionAnalyzer:
    def __init__(
        self, semantics: StackSemantics, *, emit_warnings: bool = True
    ) -> None:
        self._semantics = semantics
        self._loop_analyzer = _LoopAnalyzer(semantics)
        self._solver = _ScalarExpressionSolver(semantics)
        self._emit_warnings = emit_warnings

    @monitored(
        "safety.expression-analysis",
        variables=(
            argument("function", label="function", path=("name",)),
            argument("function", label="function_start", path=("start",)),
            returned(label="expression_states", path=("before_states",), transform=len),
            returned(
                label="conservative_addresses",
                path=("conservative_addresses",),
                transform=len,
            ),
            returned(label="warnings", path=("warnings",), transform=len),
        ),
    )
    def analyze(
        self,
        function: Function,
        vlen_sensitive_addresses: frozenset[int],
    ) -> FunctionExpressionResult:
        loop_info = self._loop_analyzer.analyze(function)
        before_states = self._solver.analyze(function, loop_info)
        conservative: set[int] = set()
        diagnostics: list[AnalysisWarning] = []
        instructions = function.instruction_by_address

        for component in loop_info.irreducible_loops:
            triggering_stores = tuple(
                sorted(
                    address
                    for address in component.addresses
                    if address in vlen_sensitive_addresses
                    and address in instructions
                    and StackAccessKind(
                        self._semantics.stack_access_kind(instructions[address])
                    ) is StackAccessKind.STORE
                )
            )
            if not triggering_stores:
                continue
            message = (
                "binary stack analysis degraded in function "
                f"{function.name} ({function.start:#x}): irreducible loop "
                "contains VLEN-sensitive vector store(s) "
                f"{', '.join(f'{address:#x}' for address in triggering_stores)}; "
                "a function-scoped irreducible object is used for conservative "
                "backward liveness"
            )
            diagnostic = AnalysisWarning(
                code="irreducible-loop-degraded",
                message=message,
                function_start=function.start,
                addresses=triggering_stores,
            )
            diagnostics.append(diagnostic)
            if self._emit_warnings:
                py_warnings.warn(
                    message,
                    IrreducibleLoopWarning,
                    stacklevel=3,
                )

        return FunctionExpressionResult(
            loop_info=loop_info,
            before_states=before_states,
            conservative_addresses=frozenset(conservative),
            after_states={
                address: (
                    self._solver._irreducible_transfer(instructions[address], state)
                    if address in loop_info.irreducible_addresses
                    else self._semantics.symbolic.transfer_instruction(
                        instructions[address], state
                    )
                )
                for address, state in before_states.items()
                if address in instructions
            },
            warnings=tuple(diagnostics),
        )

# endregion
