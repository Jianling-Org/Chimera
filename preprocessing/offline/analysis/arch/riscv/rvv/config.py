"""Infer RVV vector configuration: SEW, LMUL, and AVL source.

The analysis result is structured so it can be shared by both:

* annotation tooling for human-readable dump annotations;
* ``analysis/stack_analysis.py`` for deciding which vector memory accesses
  belong to the configured VLEN migration range.

This module deliberately separates three responsibilities:

* :class:`VectorConfigAnalyzer` performs CFG data-flow propagation;
* :class:`_State` represents and merges abstract analysis states;
* module-level helpers parse and format individual textual values.
"""

from __future__ import annotations

from collections import deque
from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from fractions import Fraction
import re

from ....core.algorithm.address_states import (
    AddressStateMap,
    address_domain,
    retained_entries,
)
from ....core.data_model import Function, Instruction, Program
from ....core.monitor import PhaseMemoryMonitor, argument, monitored, returned


VSET_OPS = {"vsetivli", "vsetvli", "vsetvl"}

SCALAR_REGISTER_RE = re.compile(
    r"^(?:x(?:[0-9]|[12][0-9]|3[01])|zero|ra|sp|gp|tp|fp|"
    r"t[0-6]|s(?:[0-9]|1[01])|a[0-7])$"
)

CONDITIONAL_BRANCH_OPS = {
    "beq",
    "bne",
    "blt",
    "bge",
    "bltu",
    "bgeu",
    "beqz",
    "bnez",
    "bltz",
    "bgez",
    "blez",
    "bgtz",
}

SCALAR_STORE_OPS = {
    "sb",
    "sh",
    "sw",
    "sd",
    "fsw",
    "fsd",
    "c.sw",
    "c.sd",
    "c.fsw",
    "c.fsd",
    "c.swsp",
    "c.sdsp",
    "c.fswsp",
    "c.fsdsp",
}

NO_SCALAR_DESTINATION_OPS = (
    CONDITIONAL_BRANCH_OPS
    | SCALAR_STORE_OPS
    | {
        "j",
        "jr",
        "ret",
        "tail",
        "ecall",
        "ebreak",
        "fence",
        "fence.i",
        "nop",
        "csrw",
        "csrs",
        "csrc",
        "csrwi",
        "csrsi",
        "csrci",
    }
)


class AVLKind(str, Enum):
    """How the AVL operand of a vector configuration was determined."""

    X0 = "x0"
    CONSTANT = "constant"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class VectorConfig:
    """Structured vector configuration active before an instruction."""

    sew: int | None
    lmul: Fraction | None
    avl_kind: AVLKind
    avl_value: int | None = None
    source_instruction: int | None = None

    @property
    def known_vtype(self) -> bool:
        return self.sew is not None and self.lmul is not None

    def display(self) -> str:
        """Return a compact annotation used in rewritten dump files."""

        sew = f"e{self.sew}" if self.sew is not None else "e?"
        lmul = _format_lmul(self.lmul)
        if self.avl_kind is AVLKind.CONSTANT:
            avl = str(self.avl_value)
        else:
            avl = self.avl_kind.value
        return f"{sew},{lmul},avl={avl}"


UNKNOWN_CONFIG = VectorConfig(None, None, AVLKind.UNKNOWN)

#: The single shared "no configuration known yet" set.  Every instruction
#: without an explicit reaching configuration resolves to this object instead
#: of a freshly allocated ``frozenset`` per lookup.
UNKNOWN_CONFIGS: frozenset[VectorConfig] = frozenset({UNKNOWN_CONFIG})


@dataclass(frozen=True)
class VectorConfigResult:
    """Vector configurations reaching each instruction entry.

    ``before_by_address`` keeps one entry per instruction of the analysed
    function but stores only the addresses whose configuration set differs
    from :data:`UNKNOWN_CONFIGS`; the rest resolve to that shared set.  The
    value is a read-only :class:`~collections.abc.Mapping`, so plain
    dictionaries remain acceptable where a caller builds one directly.
    """

    before_by_address: Mapping[int, frozenset[VectorConfig]]

    def at(self, address: int) -> frozenset[VectorConfig]:
        return self.before_by_address.get(address, UNKNOWN_CONFIGS)

    def annotation(self, address: int) -> str:
        values = sorted(config.display() for config in self.at(address))
        return ";".join(values) if values else "unknown"


@dataclass(frozen=True)
class _State:
    """Abstract state propagated through the instruction CFG.

    ``configs`` is a may-set: a configuration is kept when it can reach the
    current point through any predecessor path.

    ``constants`` is a must-map: a scalar register remains constant only when
    every predecessor agrees on the same value.
    """

    configs: frozenset[VectorConfig]
    constants: tuple[tuple[str, int], ...] = ()

    def constant_map(self) -> dict[str, int]:
        return dict(self.constants)

    def merge(self, incoming: "_State") -> "_State":
        """Join another predecessor state into this state."""

        current_constants = self.constant_map()
        incoming_constants = incoming.constant_map()
        common_constants = {
            register: value
            for register, value in current_constants.items()
            if incoming_constants.get(register) == value
        }
        return _State(
            configs=self.configs | incoming.configs,
            constants=tuple(sorted(common_constants.items())),
        )


class VectorConfigAnalyzer:
    """Forward data-flow analysis over the instruction CFG."""

    @monitored(
        "safety.vector-config",
        variables=(
            argument("program", label="functions", path=("functions",), transform=len),
            argument("program", label="instructions", path=("instructions",), transform=len),
            returned(label="result_functions", transform=len),
            returned(
                label="configuration_points",
                transform=lambda results: sum(
                    len(result.before_by_address) for result in results.values()
                ),
            ),
        ),
    )
    def analyze_program(self, program: Program) -> dict[int, VectorConfigResult]:
        monitor = PhaseMemoryMonitor("safety.vector-config.memory")
        monitor.begin(functions=len(program.functions))
        results: dict[int, VectorConfigResult] = {}
        retained_total = 0
        for function in program.functions:
            item = monitor.begin_item(function.name, function.start, len(function.insts))
            result = self.analyze_function(function)
            retained = retained_entries(result.before_by_address)
            retained_total += retained
            item.end(retained=retained)
            results[function.start] = result
        monitor.end(functions=len(results), configuration_points=retained_total)
        return results

    def analyze_function(self, function: Function) -> VectorConfigResult:
        if not function.insts:
            return VectorConfigResult(AddressStateMap((), UNKNOWN_CONFIGS))

        instructions = function.instruction_by_address
        entry = function.insts[0].addr
        before: dict[int, _State] = {entry: _State(UNKNOWN_CONFIGS)}
        worklist = deque([entry])
        queued = {entry}

        while worklist:
            address = worklist.popleft()
            queued.discard(address)

            instruction = instructions[address]
            outgoing = self._transfer(instruction, before[address])

            for successor in instruction.succ:
                if successor not in instructions:
                    continue

                merged = self._merge_states(before.get(successor), outgoing)
                if merged == before.get(successor):
                    continue

                before[successor] = merged
                if successor not in queued:
                    worklist.append(successor)
                    queued.add(successor)

        # One address domain per function: the instruction addresses are used
        # by every per-instruction result of this function, so they are built
        # once here rather than once per consumer.
        domain = address_domain(
            tuple(instruction.addr for instruction in function.insts)
        )
        # Intern the distinct configuration sets inside this single function
        # analysis: instructions that share a reaching configuration also share
        # one ``frozenset`` object.  The cache is local, so it is released with
        # the analysis instead of growing a global one.
        interned: dict[frozenset[VectorConfig], frozenset[VectorConfig]] = {}
        entries: dict[int, frozenset[VectorConfig]] = {}
        for instruction in function.insts:
            state = before.get(instruction.addr)
            if state is None:
                # Unreachable instruction: exactly the shared unknown set, so
                # it stays out of the exception dictionary.
                continue
            configs = interned.setdefault(state.configs, state.configs)
            if configs != UNKNOWN_CONFIGS:
                entries[instruction.addr] = configs
        return VectorConfigResult(
            AddressStateMap(domain, UNKNOWN_CONFIGS, entries)
        )

    @staticmethod
    def _merge_states(current: _State | None, incoming: _State) -> _State:
        """Merge a predecessor state into an instruction-entry state."""

        return incoming if current is None else current.merge(incoming)

    def _transfer(self, instruction: Instruction, state: _State) -> _State:
        """Apply one instruction's abstract effect to ``state``."""

        constants = state.constant_map()
        self._update_scalar_constants(instruction, constants)

        configs = state.configs
        if instruction.op in VSET_OPS:
            configs = frozenset({self._decode_vset(instruction, constants)})

        return _State(
            configs=configs,
            constants=tuple(sorted(constants.items())),
        )

    def _update_scalar_constants(
        self,
        instruction: Instruction,
        constants: dict[str, int],
    ) -> None:
        """Update the small constant environment used to resolve AVL.

        At this stage only ``li reg, imm`` creates a known constant.  Any
        instruction that may define the same scalar register removes the old
        value.  More scalar transfer rules can be added here later without
        changing the CFG worklist.
        """

        destination = self._defined_scalar_register(instruction)

        if instruction.op == "li" and len(instruction.args) >= 2:
            value = _parse_integer(instruction.args[1])
            if destination is not None and value is not None:
                constants[destination] = value
                return

        if destination is not None:
            constants.pop(destination, None)

    @staticmethod
    def _defined_scalar_register(instruction: Instruction) -> str | None:
        """Return the scalar register possibly defined by ``instruction``.

        The rule intentionally uses explicit no-destination categories instead
        of mnemonic prefixes.  Prefix tests such as ``op.startswith('s')`` are
        incorrect because instructions including ``sub`` and ``slli`` do write
        scalar destinations.
        """

        operation = instruction.op.lower()
        arguments = instruction.args

        if operation in NO_SCALAR_DESTINATION_OPS or not arguments:
            return None

        if operation == "call":
            return "ra"

        if operation == "jal":
            # ``jal target`` is the pseudo form ``jal ra, target``.
            if len(arguments) == 1:
                return "ra"

        if operation == "jalr":
            # ``jalr rs1`` is the pseudo form ``jalr ra, 0(rs1)``.
            if len(arguments) == 1:
                return "ra"

        destination = arguments[0].lower()
        if destination in {"zero", "x0"}:
            return None
        return destination if SCALAR_REGISTER_RE.fullmatch(destination) else None

    def _decode_vset(
        self,
        instruction: Instruction,
        constants: dict[str, int],
    ) -> VectorConfig:
        """Decode one vset instruction using the incoming constant map."""

        if instruction.op == "vsetvl" or len(instruction.args) < 2:
            return VectorConfig(
                None,
                None,
                AVLKind.UNKNOWN,
                source_instruction=instruction.addr,
            )

        sew, lmul = _parse_vtype_operands(instruction.args[2:])
        avl_operand = instruction.args[1].lower()

        if avl_operand in {"zero", "x0"}:
            return VectorConfig(
                sew,
                lmul,
                AVLKind.X0,
                source_instruction=instruction.addr,
            )

        if instruction.op == "vsetivli":
            avl = _parse_integer(avl_operand)
            return VectorConfig(
                sew=sew,
                lmul=lmul,
                avl_kind=(AVLKind.CONSTANT if avl is not None else AVLKind.UNKNOWN),
                avl_value=avl,
                source_instruction=instruction.addr,
            )

        avl = constants.get(avl_operand)
        return VectorConfig(
            sew=sew,
            lmul=lmul,
            avl_kind=(AVLKind.CONSTANT if avl is not None else AVLKind.UNKNOWN),
            avl_value=avl,
            source_instruction=instruction.addr,
        )


class VTypeAnalyzer:
    """Compatibility wrapper that returns text annotations by address."""

    def __init__(
        self,
        program: Program,
        results: dict[int, VectorConfigResult] | None = None,
    ):
        self.program = program
        self.results = results or VectorConfigAnalyzer().analyze_program(program)

    def analyze(self) -> dict[int, str]:
        annotations: dict[int, str] = {}
        for function in self.program.functions:
            result = self.results[function.start]
            for instruction in function.insts:
                if instruction.op.startswith("v") and instruction.op not in VSET_OPS:
                    annotations[instruction.addr] = result.annotation(instruction.addr)
        return annotations


def _parse_vtype_operands(parts: list[str]) -> tuple[int | None, Fraction | None]:
    """Parse the SEW and LMUL fields from vset operand tokens."""

    sew: int | None = None
    lmul: Fraction | None = None

    for part in parts:
        token = part.strip().lower()
        if re.fullmatch(r"e\d+", token):
            sew = int(token[1:])
        elif re.fullmatch(r"m(?:f[248]|[1248])", token):
            lmul = _parse_lmul(token)

    return sew, lmul


def _parse_lmul(token: str) -> Fraction | None:
    """Convert an RVV LMUL token such as ``m2`` or ``mf4`` to a fraction."""

    if token.startswith("mf"):
        return Fraction(1, int(token[2:]))
    if token.startswith("m"):
        return Fraction(int(token[1:]), 1)
    return None


def _format_lmul(value: Fraction | None) -> str:
    """Format a structured LMUL value for dump annotations."""

    if value is None:
        return "m?"
    if value.denominator == 1:
        return f"m{value.numerator}"
    return f"mf{value.denominator}"


def _parse_integer(token: str) -> int | None:
    """Parse decimal or base-prefixed integer text."""

    try:
        return int(token, 0)
    except ValueError:
        return None
