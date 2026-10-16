"""Backward liveness analysis for RISC-V vector registers.

This module only answers where vector-register data is live.  It deliberately
does not classify an instruction as a migration safe point by itself.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import re

from ....core.algorithm.address_states import retained_entries
from ....core.algorithm.dataflow import solve_backward_liveness
from ....core.data_model.program import Function, Instruction, Program
from ....core.monitor import argument, monitored, returned
# The call/jump classification lives with the CFG builder so that the CFG and
# every consumer of it share one definition; it is re-exported here because
# this module's public surface has always carried it.
from ..control_flow import is_call_instruction


VECTOR_REGISTER_RE = re.compile(r"(?<![\w.])v(\d+)(?:\.t)?(?![\w.])")
VSET_OPS = {"vsetvli", "vsetivli", "vsetvl"}

# Virtual register number modelling the vector *state* (vtype + vl) as a
# liveness entity: vset* instructions define it and vector instructions use
# it, so the interval between a vset* and the first dependent vector
# instruction is no longer mistaken for a point where the vector state is
# dead.  Migrating in that interval would resume the other code body with a
# stale vtype, and the next vector instruction would raise SIGILL (vill).
# Real vector registers are 0..31.
VECTOR_STATE_REGISTER = 32

_X0_OPERANDS = {"x0", "zero"}

# Scalar CSR operands that observe the vector state when read.
_VECTOR_STATE_CSRS = {"vtype", "vl"}


@dataclass(frozen=True)
class VectorFunctionLiveness:
    """Per-instruction live-in vector registers for one function.

    ``live_before`` is a read-only mapping that answers every instruction
    address of the function while only retaining the non-empty register sets;
    plain dictionaries remain acceptable as inputs.
    """

    function_start: int
    live_before: Mapping[int, frozenset[int]]


@dataclass(frozen=True)
class VectorLivenessResult:
    by_function: dict[int, VectorFunctionLiveness]

    @property
    def live_before(self) -> dict[int, frozenset[int]]:
        """Explicit flattened export; the analysis path never expands this."""

        return {
            address: registers
            for function in self.by_function.values()
            for address, registers in function.live_before.items()
        }

    @property
    def nonempty_state_count(self) -> int:
        """Number of retained non-empty live-in sets across all functions."""

        return sum(
            retained_entries(function.live_before)
            for function in self.by_function.values()
        )


def vector_registers(text: str) -> set[int]:
    return {int(number) for number in VECTOR_REGISTER_RE.findall(text)}


def instruction_use_def(instruction: Instruction) -> tuple[set[int], set[int]]:
    """Extract only the vector-register facts needed by this analysis."""

    if is_call_instruction(instruction):
        # A call ends the incoming vector-register lifetime.  The vector
        # state is likewise call-clobbered under the RISC-V vector psABI,
        # so the virtual state register dies here as well; callees that
        # observe the incoming vtype without their own vset* violate the
        # psABI and are outside this analysis's contract.
        return set(), set(range(VECTOR_STATE_REGISTER + 1))
    if instruction.op in VSET_OPS:
        uses: set[int] = set()
        if (
            instruction.op != "vsetivli"
            and len(instruction.args) >= 2
            and instruction.args[0].strip().lower() in _X0_OPERANDS
            and instruction.args[1].strip().lower() in _X0_OPERANDS
        ):
            # vsetvli/vsetvl with rd=x0, rs1=x0 keeps the current vl, so it
            # observes the previous vector state before redefining it.
            uses = {VECTOR_STATE_REGISTER}
        return uses, {VECTOR_STATE_REGISTER}
    if instruction.op.startswith("csr"):
        # csrr*/csr* forms reading vtype or vl observe the vector state.
        if any(
            argument.strip().lower() in _VECTOR_STATE_CSRS
            for argument in instruction.args[1:]
        ):
            return {VECTOR_STATE_REGISTER}, set()
        return set(), set()
    if not instruction.op.startswith("v"):
        return set(), set()
    if not instruction.args:
        return {VECTOR_STATE_REGISTER}, set()

    operands = ",".join(instruction.args)
    if instruction.op.startswith("vs") or instruction.op.startswith("vmv.x"):
        return vector_registers(operands) | {VECTOR_STATE_REGISTER}, set()

    definitions = vector_registers(instruction.args[0])
    uses = vector_registers(",".join(instruction.args[1:])) | {VECTOR_STATE_REGISTER}
    return uses, definitions


__all__ = [
    "VectorFunctionLiveness",
    "VectorLivenessAnalyzer",
    "VectorLivenessResult",
    "is_call_instruction",
    "vector_registers",
]


class VectorLivenessAnalyzer:
    @monitored(
        "safety.register-liveness",
        variables=(
            argument("program", label="functions", path=("functions",), transform=len),
            returned(label="result_functions", path=("by_function",), transform=len),
            returned(
                label="nonempty_live_before",
                # Count retained entries per function instead of expanding the
                # flattened ``live_before`` export, which would materialise one
                # dict entry per instruction of the whole program.
                path=("by_function",),
                transform=lambda functions: sum(
                    retained_entries(function.live_before)
                    for function in functions.values()
                ),
            ),
        ),
    )
    def analyze_program(self, program: Program) -> VectorLivenessResult:
        return VectorLivenessResult(
            by_function={
                function.start: self.analyze_function(function)
                for function in program.functions
            }
        )

    def analyze_function(self, function: Function) -> VectorFunctionLiveness:
        instructions = function.instruction_by_address
        predecessors = _instruction_predecessors(function)
        addresses = [instruction.addr for instruction in function.insts]
        # live_after is a solver local: no consumer reads it, so it is not
        # stored on the result (it would double the per-instruction maps).
        live_before, _live_after = solve_backward_liveness(
            addresses,
            successors=lambda address: instructions[address].succ,
            predecessors=lambda address: predecessors[address],
            use_def=lambda address: instruction_use_def(instructions[address]),
        )

        return VectorFunctionLiveness(
            function_start=function.start,
            live_before=live_before,
        )


def _instruction_predecessors(function: Function) -> dict[int, set[int]]:
    predecessors = {instruction.addr: set() for instruction in function.insts}
    for instruction in function.insts:
        for successor in instruction.succ:
            if successor in predecessors:
                predecessors[successor].add(instruction.addr)
    return predecessors
