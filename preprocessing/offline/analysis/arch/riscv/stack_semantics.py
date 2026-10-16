"""RISC-V implementation of stack-analysis semantic operations."""

from __future__ import annotations

import re

from .registers import (
    ADDRESS_OPERAND_RE,
    REGISTER_ALIASES,
    SCALAR_REGISTERS,
    WHOLE_REGISTER_ACCESS_RE,
    canonical_register,
)
from .rvv.config import AVLKind
from .rvv.liveness import is_call_instruction
from .control_flow import is_tail_call_instruction
from .scalar_semantics import _RiscVSymbolicSemantics, written_scalar_registers

#: Minimum VLEN (in bits) mandated by the RVV application-class profile.
#: VLEN sensitivity asks whether an access moves a VLEN-dependent number of
#: bytes across all architecturally legal VLENs, so the architectural
#: minimum - not the deployment ``min_vlen_bits`` - is the threshold.
RVV_MIN_VLEN_BITS = 128

#: Scalar load/store mnemonic -> access width in bytes.
SCALAR_ACCESS_WIDTH = {
    "lb": 1, "lbu": 1, "lh": 2, "lhu": 2, "lw": 4, "lwu": 4, "ld": 8,
    "sb": 1, "sh": 2, "sw": 4, "sd": 8,
}

#: The A extension, after stripping the ``.aq`` / ``.rl`` / ``.aqrl`` ordering
#: suffixes objdump appends.  ``lr`` only reads; ``sc`` and every ``amo``
#: write memory, and an atomic write is a write - the effect model has no
#: silence for it.  But *what* they write differs: ``amoswap`` discards the
#: old memory content, every other ``amo`` consumes it (old <op> rs2), and
#: ``sc`` may not store at all.
ATOMIC_READ_PREFIXES = ("lr.",)
ATOMIC_WRITE_PREFIXES = (
    "amoswap", "amoadd", "amoand", "amoor", "amoxor",
    "amomin", "amomax", "amominu", "amomaxu", "sc.",
)
ATOMIC_SWAP_PREFIXES = ("amoswap",)
ATOMIC_RMW_PREFIXES = (
    "amoadd", "amoand", "amoor", "amoxor",
    "amomin", "amomax", "amominu", "amomaxu",
)
ATOMIC_CONDITIONAL_PREFIXES = ("sc.",)


def _strip_atomic_suffixes(op: str) -> str:
    for suffix in (".aqrl", ".aq", ".rl"):
        if op.endswith(suffix):
            return op[: -len(suffix)]
    return op


def _atomic_access_width(op: str) -> int | None:
    stem = _strip_atomic_suffixes(op)
    if not stem.startswith(ATOMIC_READ_PREFIXES + ATOMIC_WRITE_PREFIXES):
        return None
    if stem.endswith(".d"):
        return 8
    if stem.endswith(".w"):
        return 4
    return None


def _is_atomic_read(op: str) -> bool:
    return _strip_atomic_suffixes(op).startswith(ATOMIC_READ_PREFIXES)


def _is_atomic_write(op: str) -> bool:
    return _strip_atomic_suffixes(op).startswith(ATOMIC_WRITE_PREFIXES)


def _is_rmw_atomic(op: str) -> bool:
    return _strip_atomic_suffixes(op).startswith(ATOMIC_RMW_PREFIXES)


def _is_conditional_store(op: str) -> bool:
    return _strip_atomic_suffixes(op).startswith(ATOMIC_CONDITIONAL_PREFIXES)

#: Conditional branches.  Their first operand is the *condition*, not a
#: destination, so a consumer that assumes "args[0] is written" sees no read at
#: all - which is exactly how a branch on a VLEN-derived value used to become
#: invisible to the dependency analysis.
BRANCH_OPS = frozenset(
    {
        "beq", "bne", "blt", "bge", "bltu", "bgeu",
        "beqz", "bnez", "blez", "bgez", "bltz", "bgtz",
        "bleu", "bgtu",
    }
)

#: Registers the RISC-V calling convention lets a callee destroy: a call is a
#: definition of every one of them, and nothing but the callee's own summary
#: can say what the new value is.
CALLER_SAVED_SCALAR_REGISTERS = frozenset(
    {"ra"}
    | {f"t{index}" for index in range(7)}
    | {f"a{index}" for index in range(8)}
)

_DISPLACEMENT_RE = re.compile(r"^(-?(?:0x[0-9a-fA-F]+|\d+))?\((.*)\)$")


class RiscvStackSemantics:
    # Implements: VectorStackSemantics (RVV-only vector surface on top of
    # scalar stack semantics). Generic consumers should still type the
    # attribute as StackSemantics unless they actually need the vector
    # surface; the safety step is the canonical VectorStackSemantics user.

    def __init__(self) -> None:
        self._symbolic = _RiscVSymbolicSemantics()

    @property
    def symbolic(self):
        return self._symbolic

    def scalar_width_facts(self, instruction, configs=()):
        from .scalar_width_facts import scalar_width_facts
        return scalar_width_facts(instruction, self, configs)

    def scalar_width_cache_reads(self, instruction, incoming_expressions, width_registers):
        from .scalar_width_facts import scalar_width_cache_reads
        return scalar_width_cache_reads(instruction, incoming_expressions, width_registers)

    def scalar_width_is_independent(self, instruction, incoming, min_vlen_bits):
        """Prove a fixed requested VL fits even on the narrowest target."""
        from .scalar_width_facts import fixed_requested_vl
        return fixed_requested_vl(instruction, incoming, min_vlen_bits)

    @staticmethod
    def written_scalar_registers(instruction) -> set[str]:
        return written_scalar_registers(instruction)

    @staticmethod
    def read_scalar_registers(instruction) -> set[str]:
        """Return scalar registers read by an instruction's operands.

        The stack-frame analysis only needs register dependencies, so operands
        that are immediates, CSRs, vector registers, or labels are ignored.
        Memory operands contribute their base register.
        """
        registers: set[str] = set()
        for operand in instruction.args[1:]:
            match = ADDRESS_OPERAND_RE.fullmatch(operand.strip())
            token = match.group(2) if match is not None else operand.strip()
            token = token.split("#", 1)[0].strip()
            canonical = canonical_register(token)
            if canonical in SCALAR_REGISTERS or canonical in REGISTER_ALIASES.values():
                registers.add(canonical)
        return registers

    @staticmethod
    def scalar_memory_operand(instruction) -> tuple[str, int, int] | None:
        """Return ``(base_register, displacement, byte_width)`` of a scalar access.

        ``None`` for anything that is not a scalar load or store: the origin
        prover must never treat an unrecognised access as if it did not touch
        memory.
        """

        op = instruction.op.lower()
        width = SCALAR_ACCESS_WIDTH.get(op) or _atomic_access_width(op)
        if width is None:
            return None
        for operand in instruction.args[1:]:
            match = ADDRESS_OPERAND_RE.fullmatch(operand.strip())
            if match is None:
                continue
            base = canonical_register(match.group(2))
            displacement = match.group(1) or "0"
            try:
                offset = int(displacement, 0)
            except ValueError:
                return None
            return base, offset, width
        return None

    @staticmethod
    def condition_scalar_registers(instruction) -> set[str]:
        """Registers a conditional branch's condition is computed from.

        Kept separate from :meth:`read_scalar_registers`, which follows the
        "args[0] is the destination" convention every other instruction uses:
        widening that convention here would change the setup-region walk of
        the frame analysis, which is a different question from control
        dependence.
        """

        if instruction.op.lower() not in BRANCH_OPS:
            return set()
        registers: set[str] = set()
        for operand in instruction.args:
            token = operand.strip().split("#", 1)[0].strip()
            canonical = canonical_register(token)
            if canonical in SCALAR_REGISTERS or canonical in REGISTER_ALIASES.values():
                registers.add(canonical)
        return registers

    @staticmethod
    def stored_scalar_register(instruction) -> str | None:
        """The register a scalar store writes to memory, if it is a store.

        An atomic write keeps the operand order ``rd, rs2, (addr)``: the
        stored value is ``rs2``, not the destination the old value lands in.
        """

        op = instruction.op.lower()
        atomic = _is_atomic_write(op)
        if op not in {"sb", "sh", "sw", "sd"} and not atomic:
            return None
        if not instruction.args:
            return None
        index = 1 if atomic else 0
        canonical = canonical_register(instruction.args[index].strip())
        if canonical in SCALAR_REGISTERS or canonical in REGISTER_ALIASES.values():
            return canonical
        return None

    @staticmethod
    def is_scalar_store(instruction) -> bool:
        op = instruction.op.lower()
        return op in {"sb", "sh", "sw", "sd"} or _is_atomic_write(op)

    @staticmethod
    def is_scalar_load(instruction) -> bool:
        op = instruction.op.lower()
        return op in {"lb", "lbu", "lh", "lhu", "lw", "lwu", "ld"} or _is_atomic_read(op)

    @staticmethod
    def is_read_modify_write(instruction) -> bool:
        """Whether the atomic write consumes the old memory content.

        ``amoswap`` discards it, so its stored value is described by ``rs2``
        alone; every other ``amo`` writes ``old <op> rs2`` - the old content
        is a value source the proof must account for.
        """

        return _is_rmw_atomic(instruction.op.lower())

    @staticmethod
    def is_conditional_store(instruction) -> bool:
        """Whether the store may not store at all (``sc``).

        Executing the instruction is not storing: on a failed reservation the
        old memory content survives, so the write is never coverage.
        """

        return _is_conditional_store(instruction.op.lower())

    @staticmethod
    def vector_memory_base(instruction) -> tuple[str, int] | None:
        """Return ``(base_register, displacement)`` of a vector memory operand."""

        text = RiscvStackSemantics.vector_memory_operand(instruction)
        if text is None:
            return None
        match = ADDRESS_OPERAND_RE.fullmatch(text.strip())
        if match is None:
            return None
        base = canonical_register(match.group(2))
        try:
            return base, int(match.group(1) or "0", 0)
        except ValueError:
            return None

    @staticmethod
    def is_call_instruction(instruction) -> bool:
        return is_call_instruction(instruction)

    @staticmethod
    def is_tail_call_instruction(instruction, function) -> bool:
        return is_tail_call_instruction(instruction, function)

    @staticmethod
    def may_write_memory(instruction) -> bool:
        """Whether the instruction may write memory at all.

        The RISC-V memory-writing surface is closed - scalar stores, the A
        extension and vector stores - and all three are modelled.  This is
        the backstop for the effect classification: an instruction the
        prover's modelling missed must be treated as a write, never as
        silence.
        """

        op = instruction.op.lower()
        if op in SCALAR_ACCESS_WIDTH:
            return op in {"sb", "sh", "sw", "sd"}
        if _atomic_access_width(op) is not None:
            return _is_atomic_write(op)
        vector = RiscvStackSemantics.vector_memory_operand(instruction)
        if vector is not None:
            return RiscvStackSemantics.stack_access_kind(instruction) == "store"
        return False

    @staticmethod
    def call_clobbered_scalar_registers(instruction) -> frozenset[str]:
        """Registers a call destroys, whatever the callee's body says.

        Only ``ra`` is *written* in the instruction encoding, but the calling
        convention lets the callee destroy every caller-saved register: a value
        kept across a call is not the value that was there before it.
        """

        if not is_call_instruction(instruction):
            return frozenset()
        return CALLER_SAVED_SCALAR_REGISTERS

    @staticmethod
    def vector_memory_operand(instruction) -> str | None:
        op = instruction.op.lower()
        if not (
            op.startswith("vl")
            or (op.startswith("vs") and not op.startswith("vset"))
        ):
            return None
        operands = [
            operand.strip()
            for operand in instruction.args
            if ADDRESS_OPERAND_RE.fullmatch(operand.strip())
        ]
        return operands[0] if len(operands) == 1 else None

    @staticmethod
    def stack_access_kind(instruction) -> str:
        op = instruction.op.lower()
        if op.startswith("vl"):
            return "load"
        if op.startswith("vs") and not op.startswith("vset"):
            return "store"
        raise ValueError(
            f"instruction at {instruction.addr:#x} is not vector memory: {instruction.op}"
        )

    @staticmethod
    def is_whole_register_access(instruction) -> bool:
        return WHOLE_REGISTER_ACCESS_RE.match(instruction.op) is not None

    @staticmethod
    def is_vlen_sensitive_config(
        config, *, min_vlen_bits: int
    ) -> bool:
        """Whether the byte count moved by the access varies with hardware VLEN.

        With constant AVL: ``VLMAX = VLEN * LMUL / SEW`` and
        ``vl = min(AVL, VLMAX)``, so the moved byte count is VLEN-dependent
        exactly when AVL exceeds VLMAX at the architectural minimum VLEN::

            sensitive  <=>  AVL * SEW > RVV_MIN_VLEN_BITS * LMUL

        ``min_vlen_bits`` (the deployment minimum VLEN) is intentionally not
        the threshold: sensitivity is a property of the instruction for all
        architecturally legal VLENs.  It stays in the generic contract for
        architectures without a fixed specification minimum.
        """
        if config.avl_kind is AVLKind.X0:
            return True
        if (
            config.avl_kind is not AVLKind.CONSTANT
            or config.avl_value is None
            or config.sew is None
            or config.lmul is None
        ):
            return False
        return config.avl_value * config.sew > RVV_MIN_VLEN_BITS * config.lmul

    @staticmethod
    def config_at(result, address: int) -> frozenset[object]:
        return result.at(address)


__all__ = ["RiscvStackSemantics", "RVV_MIN_VLEN_BITS"]
