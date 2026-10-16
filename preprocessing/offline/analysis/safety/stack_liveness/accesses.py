"""Select vector accesses and construct stack-object DEF/USE facts."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Hashable

from ...core.data_model import Function, Instruction
from ...core.contracts import VectorStackSemantics
from ...core.monitor import argument, monitored, returned
from .model import (
    MODE_REASON_COMPLETE_COVERAGE,
    MODE_REASON_INCOMPLETE_COVERAGE,
    MODE_REASON_NO_SECTION,
    AccessMode,
    ChimeraMetadata,
    ExpressionState,
    FunctionAccessPlan,
    FunctionExpressionResult,
    LoopInfo,
    StackAccess,
    StackAccessFacts,
    StackAccessKind,
    StackAddressStatus,
    StackObjectId,
)
from .expressions import Expr
from .solver import _FunctionExpressionAnalyzer
from .instruction_facts import _function_exit_addresses

# region Access selection and DEF/USE construction


class _VLenSensitiveAccessSelector:
    """Select the set U of all VLEN-sensitive vector memory accesses."""

    def __init__(
        self, semantics: VectorStackSemantics, min_vlen_bits: int
    ) -> None:
        self._min_vlen_bits = min_vlen_bits
        self._semantics = semantics

    def select(
        self,
        function: Function,
        config_result: Any,
    ) -> set[int]:
        return {
            instruction.addr
            for instruction in function.insts
            if self._is_target_access(
                instruction,
                self._semantics.config_at(config_result, instruction.addr),
            )
        }

    def _is_target_access(
        self,
        instruction: Instruction,
        configs: frozenset[object],
    ) -> bool:
        if self._semantics.vector_memory_operand(instruction) is None:
            return False
        if self._semantics.is_whole_register_access(instruction):
            return True
        return any(
            self._semantics.is_vlen_sensitive_config(
                config,
                min_vlen_bits=self._min_vlen_bits,
            )
            for config in configs
        )


def _access_mode_value(mode: object) -> str:
    """Render an :class:`AccessMode` as its documented value.

    ``AccessMode`` is a ``str`` enum, so plain ``str()`` writes
    ``"AccessMode.BINARY_INCOMPLETE"`` -- which no consumer matches on.  Every
    emitted form (debug events, reports) uses the value instead.
    """

    return str(getattr(mode, "value", mode))


class _VectorAccessPlanner:
    """Choose compiler-metadata mode or pure-binary mode, per function.

    The choice is a property of ``U`` versus ``M`` of *this* function, never of
    the section:

    * no section                    -> binary recovery over all of ``U``;
    * section and ``U - M`` empty   -> metadata is authoritative here;
    * section and ``U - M`` non-empty -> the function falls back to binary
      recovery over all of ``U``.

    The fallback never mixes compiler object ids with binary object ids and
    never injects the partial metadata records into use/def: a half-recorded
    function is analysed the same way a non-instrumented one is.  An empty
    section, records belonging to other functions, or an instrumented subset of
    translation units are all the same shape for this function -- none of them
    authorizes ignoring its uncovered accesses.
    """

    def __init__(self, selector: _VLenSensitiveAccessSelector) -> None:
        self._selector = selector

    @monitored(
        "safety.access-selection",
        variables=(
            argument("function", label="function", path=("name",)),
            argument("function", label="function_start", path=("start",)),
            returned(label="metadata_mode", path=("metadata_mode",)),
            returned(
                label="sensitive_accesses",
                path=("vlen_sensitive_addresses",),
                transform=len,
            ),
            returned(label="candidate_addresses", path=("candidate_addresses",), transform=len),
            returned(
                label="has_metadata_section", path=("has_metadata_section",)
            ),
            returned(
                label="metadata_covered_accesses",
                path=("metadata_covered_count",),
            ),
            returned(
                label="uncovered_sensitive_accesses",
                path=("uncovered_sensitive_addresses",),
                transform=len,
            ),
            returned(
                label="access_mode",
                path=("access_mode",),
                transform=_access_mode_value,
            ),
            returned(label="mode_reason", path=("mode_reason",)),
        ),
    )
    def plan(
        self,
        function: Function,
        metadata: ChimeraMetadata,
        config_result: Any,
    ) -> FunctionAccessPlan:
        sensitive = frozenset(self._selector.select(function, config_result))
        if not metadata.has_stackobj_map_section:
            return FunctionAccessPlan(
                vlen_sensitive_addresses=sensitive,
                compiler_access_ids={},
                binary_addresses=sensitive,
                metadata_mode=False,
                has_metadata_section=False,
                metadata_covered_count=0,
                uncovered_sensitive_addresses=frozenset(),
                access_mode=AccessMode.BINARY_NO_SECTION,
                mode_reason=MODE_REASON_NO_SECTION,
            )
        covered = {
            address: metadata.stack_ids[address]
            for address in sensitive
            if address in metadata.stack_ids
        }
        missing = sensitive.difference(covered)
        if missing:
            # Whole-function fallback: every sensitive access of this function
            # is recovered from the binary, and the partial records stay out of
            # this round's use/def facts.
            return FunctionAccessPlan(
                vlen_sensitive_addresses=sensitive,
                compiler_access_ids={},
                binary_addresses=sensitive,
                metadata_mode=False,
                has_metadata_section=True,
                metadata_covered_count=len(covered),
                uncovered_sensitive_addresses=frozenset(missing),
                access_mode=AccessMode.BINARY_INCOMPLETE,
                mode_reason=MODE_REASON_INCOMPLETE_COVERAGE,
            )
        return FunctionAccessPlan(
            vlen_sensitive_addresses=sensitive,
            compiler_access_ids=covered,
            binary_addresses=frozenset(),
            metadata_mode=True,
            has_metadata_section=True,
            metadata_covered_count=len(covered),
            uncovered_sensitive_addresses=frozenset(),
            access_mode=AccessMode.METADATA_COMPLETE,
            mode_reason=MODE_REASON_COMPLETE_COVERAGE,
        )


class _StackObjectRegistry:
    """Intern canonical binary stack-address expressions."""

    def __init__(self) -> None:
        self._compiler_objects: dict[int, StackObjectId] = {}
        self._expression_objects: dict[tuple[Hashable, ...], StackObjectId] = {}
        self._next_binary_id = 0

    def compiler_object(self, compiler_id: int) -> StackObjectId:
        if compiler_id not in self._compiler_objects:
            self._compiler_objects[compiler_id] = StackObjectId(
                "compiler", compiler_id
            )
        return self._compiler_objects[compiler_id]

    def resolve_expression(self, expression: Expr) -> StackObjectId:
        key = expression.key()
        existing = self._expression_objects.get(key)
        if existing is not None:
            return existing
        result = StackObjectId("binary", self._next_binary_id)
        self._next_binary_id += 1
        self._expression_objects[key] = result
        return result

    def from_expression(self, expression: Expr) -> StackObjectId:
        return self.resolve_expression(expression)


@dataclass(frozen=True)
class _AddressResolution:
    status: StackAddressStatus
    expression: Expr | None = None


class _StackAddressResolver:
    def __init__(self, semantics: VectorStackSemantics) -> None:
        self._semantics = semantics

    def resolve(
        self,
        instruction: Instruction,
        before_state: ExpressionState,
    ) -> _AddressResolution:
        operand = self._semantics.vector_memory_operand(instruction)
        if operand is None:
            return _AddressResolution(StackAddressStatus.UNRESOLVED)
        expression = self._semantics.symbolic.address_expression(operand, before_state)
        if not isinstance(expression, Expr):
            return _AddressResolution(StackAddressStatus.UNRESOLVED)
        return _AddressResolution(
            StackAddressStatus(
                self._semantics.symbolic.classify_stack_address(expression)
            ),
            expression,
        )


class _StackAccessFactBuilder:
    def __init__(self, semantics: VectorStackSemantics) -> None:
        self._semantics = semantics
        self._resolver = _StackAddressResolver(semantics)

    def build(
        self,
        *,
        function: Function,
        plan: FunctionAccessPlan,
        expressions: FunctionExpressionResult | None,
        config_result: Any,
    ) -> StackAccessFacts:
        if plan.metadata_mode:
            return self._build_from_metadata(function, plan, config_result)
        if expressions is None:
            raise AssertionError("binary mode requires expression-analysis results")
        return self._build_from_binary(
            function,
            plan,
            expressions,
            config_result,
        )

    def _make_access(
        self,
        instruction: Instruction,
        stack_id: StackObjectId,
        source: str,
        config_result: Any,
        expression: Expr | None = None,
    ) -> StackAccess:
        return StackAccess(
            instruction_addr=instruction.addr,
            kind=StackAccessKind(self._semantics.stack_access_kind(instruction)),
            stack_id=stack_id,
            config=self._semantics.config_at(config_result, instruction.addr),
            source=source,
            address_expression=expression,
        )

    def _build_from_metadata(
        self,
        function: Function,
        plan: FunctionAccessPlan,
        config_result: Any,
    ) -> StackAccessFacts:
        instructions = function.instruction_by_address
        registry = _StackObjectRegistry()
        accesses = {
            address: self._make_access(
                instructions[address],
                registry.compiler_object(object_id),
                "compiler",
                config_result,
            )
            for address, object_id in plan.compiler_access_ids.items()
        }
        uses, defs = self._build_use_def(accesses)
        return StackAccessFacts(
            accesses=accesses,
            uses=uses,
            defs=defs,
            conservative_addresses=frozenset(),
            rejected_nonstack_addresses=frozenset(),
        )

    def _build_from_binary(
        self,
        function: Function,
        plan: FunctionAccessPlan,
        expressions: FunctionExpressionResult,
        config_result: Any,
    ) -> StackAccessFacts:
        instructions = function.instruction_by_address
        registry = _StackObjectRegistry()
        accesses: dict[int, StackAccess] = {}
        rejected: set[int] = set()
        conservative = set(expressions.conservative_addresses)

        for address in plan.binary_addresses:
            instruction = instructions[address]
            resolution = self._resolver.resolve(
                instruction,
                expressions.before_states.get(address, {}),
            )
            if resolution.status is StackAddressStatus.NON_STACK:
                rejected.add(address)
                continue
            if resolution.status is StackAddressStatus.UNRESOLVED:
                conservative.update(
                    self._ordinary_conservative_scope(
                        function,
                        expressions.loop_info,
                        address,
                    )
                )
                continue
            assert resolution.expression is not None
            accesses[address] = self._make_access(
                instruction,
                registry.resolve_expression(resolution.expression),
                "binary",
                config_result,
                resolution.expression,
            )

        uses, defs = self._build_use_def(accesses)
        irreducible_object = StackObjectId("irreducible", f"{function.start:x}")
        has_irreducible_store = False
        for address in plan.binary_addresses & expressions.loop_info.irreducible_addresses:
            instruction = instructions[address]
            if StackAccessKind(self._semantics.stack_access_kind(instruction)) is StackAccessKind.STORE:
                defs[address] = defs.get(address, frozenset()) | frozenset({irreducible_object})
                has_irreducible_store = True
        if has_irreducible_store:
            for address in _function_exit_addresses(function):
                uses[address] = uses.get(address, frozenset()) | frozenset({irreducible_object})
        return StackAccessFacts(
            accesses=accesses,
            uses=uses,
            defs=defs,
            conservative_addresses=frozenset(conservative),
            rejected_nonstack_addresses=frozenset(rejected),
        )

    @staticmethod
    def _build_use_def(
        accesses: dict[int, StackAccess],
    ) -> tuple[
        dict[int, frozenset[StackObjectId]],
        dict[int, frozenset[StackObjectId]],
    ]:
        uses: dict[int, frozenset[StackObjectId]] = {}
        defs: dict[int, frozenset[StackObjectId]] = {}
        for address, access in accesses.items():
            target = uses if access.kind is StackAccessKind.LOAD else defs
            target[address] = frozenset({access.stack_id})
        return uses, defs

    @staticmethod
    def _ordinary_conservative_scope(
        function: Function,
        loop_info: LoopInfo,
        address: int,
    ) -> set[int]:
        loop = loop_info.innermost_natural_loop(address)
        result = (
            set(loop.addresses)
            if loop is not None
            else {instruction.addr for instruction in function.insts}
        )
        result.difference_update(_function_exit_addresses(function))
        return result


# endregion
