"""RISC-V scalar transfer semantics used through the target adapter."""

from __future__ import annotations

from typing import Iterable

from ...core.data_model import Instruction
from ...safety.stack_liveness.expressions import (
    Constant,
    Expr,
    Input,
    LoopInput,
    Unknown,
    VLENB,
    _Unknown,
    _and,
    _constant_value,
    _sign_extend,
    _word,
    _word_shift_left,
    _word_shift_right,
    add,
    classify_stack_address_expression,
    is_stack_address_expression,
    multiply,
    scale,
    shift_right,
)
from .registers import (
    ADDRESS_OPERAND_RE,
    CALLER_SAVED,
    NO_DESTINATION,
    REGISTER_ALIASES,
    SCALAR_REGISTERS,
    SCALAR_STORES,
    canonical_register,
)
from .rvv.liveness import is_call_instruction


def _canonical_register(register: str) -> str:
    return canonical_register(register)


def _integer(operand: str) -> int | None:
    token = (
        operand.split("#", 1)[0].strip().split(None, 1)[0] if operand.strip() else ""
    )
    try:
        return int(token, 0)
    except ValueError:
        return None


def initial_register_state() -> dict[str, Expr | _Unknown]:
    """Return the function-entry scalar state."""

    canonical_registers = set(REGISTER_ALIASES.values())
    state: dict[str, Expr | _Unknown] = {
        register: Input(register)
        for register in canonical_registers
        if register != "zero"
    }
    state["zero"] = Constant(0)
    return state

def join_states(
    states: Iterable[dict[str, Expr | _Unknown]],
) -> dict[str, Expr | _Unknown]:
    states = list(states)
    if not states:
        return {}
    registers = set().union(*(state.keys() for state in states))
    joined: dict[str, Expr | _Unknown] = {}
    for register in registers:
        values = [state.get(register, Unknown) for state in states]
        joined[register] = (
            values[0] if all(value == values[0] for value in values) else Unknown
        )
    joined["zero"] = Constant(0)
    return joined


def _value(state: dict[str, Expr | _Unknown], register: str) -> Expr | _Unknown:
    return state.get(_canonical_register(register), Unknown)


def _write(
    state: dict[str, Expr | _Unknown], register: str, value: Expr | _Unknown
) -> None:
    register = _canonical_register(register)
    if register != "zero":
        state[register] = value


def _address_expression(
    operand: str, state: dict[str, Expr | _Unknown]
) -> Expr | _Unknown:
    match = ADDRESS_OPERAND_RE.search(operand)
    if match is None:
        return Unknown
    base = _value(state, match.group(2))
    displacement = _integer(match.group(1) or "0")
    return (
        add(base, Constant(displacement))
        if isinstance(base, Expr) and displacement is not None
        else Unknown
    )


def transfer_instruction(
    instruction: Instruction,
    before: dict[str, Expr | _Unknown],
) -> dict[str, Expr | _Unknown]:
    """Return the scalar register state after one instruction."""

    state = dict(before)
    args = instruction.args
    op = instruction.op.lower()

    if is_call_instruction(instruction):
        for register in CALLER_SAVED:
            _write(state, register, Unknown)
        return state

    if not args:
        return state

    destination = _canonical_register(args[0])

    if op == "li" and len(args) >= 2:
        immediate = _integer(args[1])
        _write(
            state,
            destination,
            Constant(immediate) if immediate is not None else Unknown,
        )

    elif op == "lui" and len(args) >= 2:
        immediate = _integer(args[1])

        if immediate is None:
            result: Expr | _Unknown = Unknown
        else:
            # RV64 LUI sign-extends its 32-bit result to XLEN.
            upper = (immediate & 0xFFFFF) << 12
            result = Constant(_sign_extend(upper, 32))

        _write(state, destination, result)

    elif op == "auipc" and len(args) >= 2:
        immediate = _integer(args[1])

        if immediate is None:
            result = Unknown
        else:
            upper = (immediate & 0xFFFFF) << 12
            upper = _sign_extend(upper, 32)
            result = Constant(instruction.addr + upper)

        _write(state, destination, result)

    elif op == "mv" and len(args) >= 2:
        _write(state, destination, _value(before, args[1]))

    elif op in {"addi", "addiw"} and len(args) >= 3:
        source = _value(before, args[1])
        immediate = _integer(args[2])

        if isinstance(source, Expr) and immediate is not None:
            result = add(source, Constant(immediate))

            if op == "addiw":
                result = _word(result)
        else:
            result = Unknown

        _write(state, destination, result)

    elif op in {"add", "sub", "addw", "subw"} and len(args) >= 3:
        left = _value(before, args[1])
        right = _value(before, args[2])

        if isinstance(left, Expr) and isinstance(right, Expr):
            if op.startswith("add"):
                result = add(left, right)
            else:
                result = add(left, scale(right, -1))

            if op.endswith("w"):
                result = _word(result)
        else:
            result = Unknown

        _write(state, destination, result)

    elif op == "slli" and len(args) >= 3:
        source = _value(before, args[1])
        shift = _integer(args[2])

        result = (
            scale(source, 1 << shift)
            if (isinstance(source, Expr) and shift is not None and 0 <= shift < 64)
            else Unknown
        )

        _write(state, destination, result)

    elif op == "slliw" and len(args) >= 3:
        source = _value(before, args[1])
        shift = _integer(args[2])

        result = (
            _word_shift_left(source, shift)
            if (isinstance(source, Expr) and shift is not None and 0 <= shift < 32)
            else Unknown
        )

        _write(state, destination, result)

    elif op in {"sll", "sllw"} and len(args) >= 3:
        source = _value(before, args[1])
        shift_value = _value(before, args[2])

        if not isinstance(source, Expr) or not isinstance(shift_value, Expr):
            result = Unknown
        else:
            amount = _constant_value(shift_value)

            if amount is not None:
                if op == "sll":
                    result = scale(source, 1 << (amount & 63))
                else:
                    result = _word_shift_left(source, amount & 31)
            elif op == "sll":
                # Preserve a symbolic variable shift instead of degrading it.
                masked_shift = _and(shift_value, 63)
                result = Expr("shl", (source, masked_shift))
            else:
                result = Unknown

        _write(state, destination, result)

    elif op in {"srliw", "sraiw"} and len(args) >= 3:
        source = _value(before, args[1])
        shift = _integer(args[2])

        result = (
            _word_shift_right(
                source,
                shift,
                arithmetic=(op == "sraiw"),
            )
            if (isinstance(source, Expr) and shift is not None and 0 <= shift < 32)
            else Unknown
        )

        _write(state, destination, result)

    elif op in {"srli", "srai"} and len(args) >= 3:
        # XLEN-wide shift-right, not the W-instruction family: the full 64-bit
        # source is shifted, so the result keeps the source's dependency
        # instead of being truncated to 32 bits.  This is the operation the
        # vectorised ``vec`` stack-allocation size computation uses, and
        # leaving it unmodelled used to turn the whole ``sp`` adjustment into
        # an unknown value.
        source = _value(before, args[1])
        shift = _integer(args[2])

        result = (
            shift_right(source, shift, arithmetic=(op == "srai"))
            if (isinstance(source, Expr) and shift is not None and 0 <= shift < 64)
            else Unknown
        )

        _write(state, destination, result)

    elif op in {"srl", "sra"} and len(args) >= 3:
        source = _value(before, args[1])
        shift_value = _value(before, args[2])

        if not isinstance(source, Expr) or not isinstance(shift_value, Expr):
            result = Unknown
        else:
            amount = _constant_value(shift_value)

            if amount is not None:
                result = shift_right(
                    source, amount & 63, arithmetic=(op == "sra")
                )
            else:
                # Preserve a symbolic variable shift instead of degrading it.
                result = Expr(
                    "ashr" if op == "sra" else "lshr",
                    (source, _and(shift_value, 63)),
                )

        _write(state, destination, result)

    elif op in {"sh1add", "sh2add", "sh3add"} and len(args) >= 3:
        first = _value(before, args[1])
        second = _value(before, args[2])
        factor = {
            "sh1add": 2,
            "sh2add": 4,
            "sh3add": 8,
        }[op]

        result = (
            add(second, scale(first, factor))
            if isinstance(first, Expr) and isinstance(second, Expr)
            else Unknown
        )

        _write(state, destination, result)

    elif op in {"mul", "mulw"} and len(args) >= 3:
        left = _value(before, args[1])
        right = _value(before, args[2])

        if isinstance(left, Expr) and isinstance(right, Expr):
            # Preserve non-constant multiplication as a symbolic expression.
            result = multiply(left, right)

            if op == "mulw":
                result = _word(result)
        else:
            result = Unknown

        _write(state, destination, result)

    elif op == "andi" and len(args) >= 3:
        source = _value(before, args[1])
        mask = _integer(args[2])

        result = (
            _and(source, mask)
            if isinstance(source, Expr) and mask is not None
            else Unknown
        )

        _write(state, destination, result)

    elif op in {"ld", "lw", "lwu"} and len(args) >= 2:
        address = _address_expression(args[1], before)

        if not isinstance(address, Expr):
            value: Expr | _Unknown = Unknown
        elif op == "ld":
            value = Expr("load", (64, address))
        elif op == "lw":
            loaded = Expr("load", (32, address))
            value = Expr("sext32", (loaded,))
        else:
            loaded = Expr("load", (32, address))
            value = Expr("zext32", (loaded,))

        _write(state, destination, value)

    elif op in {
        "csrr",
        "csrrs",
        "csrrc",
        "csrrw",
        "csrrsi",
        "csrrci",
        "csrrwi",
    } and len(args) >= 2:
        csr = args[1].lower()

        _write(
            state,
            destination,
            VLENB if csr == "vlenb" else Unknown,
        )

    elif op == "sext.w" and len(args) >= 2:
        source = _value(before, args[1])

        _write(
            state,
            destination,
            _word(source) if isinstance(source, Expr) else Unknown,
        )

    elif op == "zext.w" and len(args) >= 2:
        source = _value(before, args[1])

        _write(
            state,
            destination,
            (_word(source, "zext32") if isinstance(source, Expr) else Unknown),
        )

    elif op in {"vsetvli", "vsetivli", "vsetvl"}:
        _write(state, destination, Unknown)

    elif op.startswith("v") or op in NO_DESTINATION or op in SCALAR_STORES:
        pass

    elif destination in SCALAR_REGISTERS:
        _write(state, destination, Unknown)

    return state


class _RiscVSymbolicSemantics:
    """Scalar symbolic algebra and single-instruction transfer semantics."""

    constant = staticmethod(Constant)
    input = staticmethod(Input)
    loop_input = staticmethod(LoopInput)
    add = staticmethod(add)
    scale = staticmethod(scale)
    multiply = staticmethod(multiply)
    classify_stack_address = staticmethod(classify_stack_address_expression)
    is_stack_address = staticmethod(is_stack_address_expression)
    initial_state = staticmethod(initial_register_state)
    join_states = staticmethod(join_states)
    address_expression = staticmethod(_address_expression)
    transfer_instruction = staticmethod(transfer_instruction)



# endregion


def written_scalar_registers(instruction: Instruction) -> set[str]:
    before = initial_register_state()
    after = transfer_instruction(instruction, before)
    return {
        register
        for register, value in after.items()
        if register != "zero" and value != before.get(register, Unknown)
    }


__all__ = [name for name in globals() if not name.startswith("__")]
