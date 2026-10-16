"""Architecture-neutral symbolic and affine expression algebra."""

from dataclasses import dataclass
from typing import Iterable

# region Symbolic expressions
class _Unknown:
    def __repr__(self):
        return "Unknown"


Unknown = _Unknown()


@dataclass(frozen=True)
class Expr:
    kind: str
    args: tuple[object, ...]

    def __add__(self, other: "Expr") -> "Expr":
        return add(self, other)

    def __sub__(self, other: "Expr") -> "Expr":
        return add(self, scale(other, -1))

    def scale(self, factor: int) -> "Expr":
        return scale(self, factor)

    def key(self) -> tuple[object, ...]:
        return (self.kind,) + tuple(
            argument.key() if isinstance(argument, Expr) else argument
            for argument in self.args
        )

    def __str__(self) -> str:
        if self.kind == "const":
            return str(self.args[0])
        if self.kind == "input":
            return f"input({self.args[0]})"
        if self.kind == "loop_input":
            return f"loop_{self.args[0]:x}({self.args[1]})"
        if self.kind == "vlenb":
            return "VLENB"
        if self.kind == "add":
            return " + ".join(str(item) for item in self.args)
        if self.kind == "scale":
            return f"{self.args[1]}*({self.args[0]})"
        if self.kind == "mul":
            return f"({self.args[0]} * {self.args[1]})"
        if self.kind == "load":
            return f"Load{self.args[0]}({self.args[1]})"
        if self.kind == "and":
            return f"({self.args[0]} & {self.args[1]})"
        if self.kind == "trunc32":
            return f"Truncate32({self.args[0]})"
        if self.kind == "sext32":
            return f"SignExtend32({self.args[0]})"
        if self.kind == "zext32":
            return f"ZeroExtend32({self.args[0]})"
        if self.kind == "shl":
            return f"ShiftLeft({self.args[0]}, {self.args[1]})"
        if self.kind == "lshr":
            return f"LogicalShiftRight64({self.args[0]}, {self.args[1]})"
        if self.kind == "ashr":
            return f"ArithmeticShiftRight64({self.args[0]}, {self.args[1]})"
        if self.kind == "shl32":
            return f"ShiftLeft32({self.args[0]}, {self.args[1]})"
        if self.kind == "lshr32":
            return f"LogicalShiftRight32({self.args[0]}, {self.args[1]})"
        if self.kind == "ashr32":
            return f"ArithmeticShiftRight32({self.args[0]}, {self.args[1]})"

        return f"{self.kind}({', '.join(map(str, self.args))})"


def Constant(value: int) -> Expr:
    return Expr("const", (value,))


def Input(register: str) -> Expr:
    """Return a function-entry input symbol."""

    return Expr("input", (str(register),))


def LoopInput(header: int, register: str) -> Expr:
    return Expr("loop_input", (int(header), register))


def PostLoopInput(header: int, register: str) -> Expr:
    """A fresh value used when loop-exit restoration cannot be proven."""

    return Expr("post_loop_input", (int(header), register))


def substitute(expression: Expr, replacements: dict[Expr, Expr]) -> Expr:
    direct = replacements.get(expression)
    if direct is not None:
        return direct
    changed = False
    arguments: list[object] = []
    for argument in expression.args:
        if isinstance(argument, Expr):
            value = substitute(argument, replacements)
            changed = changed or value != argument
            arguments.append(value)
        else:
            arguments.append(argument)
    return Expr(expression.kind, tuple(arguments)) if changed else expression


VLENB = Expr("vlenb", ())


def _affine_terms(expression: Expr) -> tuple[dict[Expr, int], int] | None:
    """Return integer affine coefficients for stack-address classification.

    Only constants, region inputs, VLENB, additions, and integer scales are
    affine here.  Loads, masks, word truncation/extension, and variable
    multiplication remain valid symbolic expressions, but they cannot prove a
    stack-relative address.
    """

    if expression.kind == "const":
        value = expression.args[0]
        assert isinstance(value, int)
        return {}, value
    if expression.kind in {"input", "loop_input", "post_loop_input", "vlenb"}:
        return {expression: 1}, 0
    if expression.kind == "add":
        coefficients: dict[Expr, int] = {}
        constant = 0
        for item in expression.args:
            if not isinstance(item, Expr):
                return None
            affine = _affine_terms(item)
            if affine is None:
                return None
            item_coefficients, item_constant = affine
            constant += item_constant
            for atom, coefficient in item_coefficients.items():
                coefficients[atom] = coefficients.get(atom, 0) + coefficient
                if coefficients[atom] == 0:
                    del coefficients[atom]
        return coefficients, constant
    if expression.kind == "scale":
        base, factor = expression.args
        if not isinstance(base, Expr) or not isinstance(factor, int):
            return None
        affine = _affine_terms(base)
        if affine is None:
            return None
        coefficients, constant = affine
        return (
            {atom: coefficient * factor for atom, coefficient in coefficients.items()},
            constant * factor,
        )
    return None


def classify_stack_address_expression(expression: Expr) -> str:
    """Classify a symbolic address as stack, non-stack, or unresolved.

    A proven stack address contains exactly one function-entry ``input(sp)``
    term with coefficient one.  Integer-affine offsets may contain constants,
    VLENB, function inputs, and stable loop inputs.  A ``loop_H(sp)`` term means
    that the loop modifies SP and the relation to the function stack base is no
    longer known, so the result is unresolved rather than non-stack.
    """

    affine = _affine_terms(expression)
    if affine is None:
        return "unresolved"

    coefficients, _ = affine
    function_sp_coefficient = 0
    has_loop_input = False
    has_loop_sp = False

    for atom, coefficient in coefficients.items():
        if atom.kind == "vlenb":
            continue
        if atom.kind == "input":
            register = atom.args[0]
            if not isinstance(register, str):
                return "unresolved"
            if register == "sp":
                function_sp_coefficient += coefficient
            continue
        if atom.kind == "loop_input":
            header, register = atom.args
            if not isinstance(header, int) or not isinstance(register, str):
                return "unresolved"
            if coefficient != 0:
                has_loop_input = True
            if register == "sp" and coefficient != 0:
                has_loop_sp = True
            continue
        if atom.kind == "post_loop_input":
            return "unresolved"
        return "unresolved"

    if has_loop_sp:
        return "unresolved"
    if function_sp_coefficient == 1:
        return "stack"
    if function_sp_coefficient == 0:
        return "unresolved" if has_loop_input else "non_stack"
    return "unresolved"

def is_stack_address_expression(expression: Expr) -> bool:
    """Compatibility predicate for callers that only need a yes/no answer."""

    return classify_stack_address_expression(expression) == "stack"


def _constant_value(value: Expr) -> int | None:
    if value.kind != "const":
        return None

    constant = value.args[0]
    assert isinstance(constant, int)
    return constant


def _sign_extend(value: int, bits: int) -> int:
    mask = (1 << bits) - 1
    value &= mask
    sign_bit = 1 << (bits - 1)

    if value & sign_bit:
        value -= 1 << bits

    return value


def scale(value: Expr, factor: int) -> Expr:
    if factor == 0:
        return Constant(0)

    if factor == 1:
        return value

    constant = _constant_value(value)
    if constant is not None:
        return Constant(constant * factor)

    if value.kind == "scale":
        base, old_factor = value.args
        assert isinstance(base, Expr)
        assert isinstance(old_factor, int)
        return scale(base, old_factor * factor)

    if value.kind == "add":
        return add(
            *(scale(item, factor) for item in value.args if isinstance(item, Expr))
        )

    return Expr("scale", (value, factor))


def add(*values: Expr) -> Expr:
    """Build a canonical sum and combine structurally identical terms."""

    coefficients: dict[Expr, int] = {}
    constant = 0

    def collect(value: Expr, factor: int = 1) -> None:
        nonlocal constant

        if value.kind == "add":
            for item in value.args:
                assert isinstance(item, Expr)
                collect(item, factor)
            return

        item_constant = _constant_value(value)
        if item_constant is not None:
            constant += factor * item_constant
            return

        if value.kind == "scale":
            base, nested_factor = value.args
            assert isinstance(base, Expr)
            assert isinstance(nested_factor, int)
            collect(base, factor * nested_factor)
            return

        coefficients[value] = coefficients.get(value, 0) + factor

    for value in values:
        collect(value)

    terms: list[Expr] = []

    for base in sorted(coefficients, key=str):
        factor = coefficients[base]

        if factor != 0:
            terms.append(scale(base, factor))

    if constant != 0:
        terms.append(Constant(constant))

    if not terms:
        return Constant(0)

    if len(terms) == 1:
        return terms[0]

    return Expr("add", tuple(terms))


def multiply(left: Expr, right: Expr) -> Expr:
    """Build a canonical multiplication expression."""

    left_constant = _constant_value(left)
    right_constant = _constant_value(right)

    if left_constant is not None:
        return scale(right, left_constant)

    if right_constant is not None:
        return scale(left, right_constant)

    # mul is commutative, so sort operands for stable equality.
    first, second = sorted((left, right), key=str)
    return Expr("mul", (first, second))


def _word(value: Expr, extension: str = "sext32") -> Expr:
    """Truncate to 32 bits and extend to XLEN."""

    constant = _constant_value(value)
    if constant is not None:
        narrowed = constant & 0xFFFFFFFF

        if extension == "sext32":
            narrowed = _sign_extend(narrowed, 32)

        return Constant(narrowed)

    if value.kind == extension:
        return value

    truncated = value if value.kind == "trunc32" else Expr("trunc32", (value,))

    return Expr(extension, (truncated,))


def _word_shift_left(value: Expr, shift: int) -> Expr:
    if shift == 0:
        return _word(value)

    constant = _constant_value(value)
    if constant is not None:
        result = ((constant & 0xFFFFFFFF) << shift) & 0xFFFFFFFF
        return Constant(_sign_extend(result, 32))

    truncated = Expr("trunc32", (value,))
    shifted = Expr("shl32", (truncated, shift))
    return Expr("sext32", (shifted,))


def _word_shift_right(
    value: Expr,
    shift: int,
    *,
    arithmetic: bool,
) -> Expr:
    if shift == 0:
        return _word(value)

    constant = _constant_value(value)
    if constant is not None:
        word = constant & 0xFFFFFFFF

        if arithmetic:
            word = _sign_extend(word, 32)

        result = word >> shift
        return Constant(_sign_extend(result, 32))

    truncated = Expr("trunc32", (value,))
    kind = "ashr32" if arithmetic else "lshr32"
    shifted = Expr(kind, (truncated, shift))

    # Every W instruction sign-extends its 32-bit result to XLEN.
    return Expr("sext32", (shifted,))


def _and(value: Expr, mask: int) -> Expr:
    if mask == 0:
        return Constant(0)

    if mask == -1:
        return value

    constant = _constant_value(value)
    if constant is not None:
        return Constant(constant & mask)

    return Expr("and", (value, Constant(mask)))


def shift_right(value: Expr, shift: int, *, arithmetic: bool) -> Expr:
    """Return an RV64 right shift, keeping the source dependency.

    XLEN-wide shifts are a different operation from the ``*32`` family used by
    the ``W`` instructions: the source keeps all 64 bits and is not truncated
    or sign-extended afterwards.  The operation is therefore modelled as an
    opaque 64-bit shift node rather than being folded away — ``(x << 32) >> 29``
    is a derived value whose relation to ``x`` is not expressible with the
    affine algebra, and flattening it would drop the dependency on the source
    registers that the VLEN stack-frame analysis reasons about.
    """

    if shift == 0:
        return value

    constant = _constant_value(value)
    if constant is not None:
        if arithmetic:
            return Constant(_sign_extend(constant, 64) >> shift)
        return Constant((constant & ((1 << 64) - 1)) >> shift)

    return Expr("ashr" if arithmetic else "lshr", (value, Constant(shift)))


# region VLEN dependency levels

#: Values proven not to be derived from the hardware VLEN.
DEPENDENCY_INDEPENDENT = 0
#: Values that cannot be proven either way.
DEPENDENCY_UNKNOWN = 1
#: Values derived from a ``vlenb`` read.
DEPENDENCY_VLEN = 2

#: Expression kinds whose result depends on the source operands and nothing
#: else.  Any kind missing here is treated as unmodellable and therefore
#: cannot carry an independence proof.
_DEPENDENCY_PRESERVING_KINDS = frozenset(
    {
        "add",
        "scale",
        "mul",
        "and",
        "shl",
        "lshr",
        "ashr",
        "shl32",
        "lshr32",
        "ashr32",
        "trunc32",
        "sext32",
        "zext32",
    }
)


def vlen_dependency(value: object) -> int:
    """Classify a scalar value by its dependency on the hardware VLEN.

    ``DEPENDENCY_INDEPENDENT`` is a proof obligation, not a default:
    constants, function-entry register inputs and loop-carried symbols are
    arbitrary values that are nevertheless never VLEN-derived, and an operation
    stays independent exactly when *every* operand was proven independent.
    Memory sources, call results, unmodellable operations and post-loop
    placeholders cannot be proven either way and remain
    ``DEPENDENCY_UNKNOWN``; anything fed by a ``vlenb`` read becomes
    ``DEPENDENCY_VLEN``.

    Unknown must never be collapsed into independent: an unprovable value may
    still be VLEN-sized, so treating it as safe is exactly the error this
    classification exists to prevent.
    """

    stack = [value]
    # ``vlenb`` wins over everything: a value that consumes a VLEN read is
    # VLEN-derived even when another operand is unmodellable.  Unmodellable
    # operands are only remembered so that a tree without any ``vlenb`` still
    # reports "cannot prove independence" instead of "independent".
    unproven = False
    while stack:
        item = stack.pop()
        if not isinstance(item, Expr):
            unproven = True
            continue
        kind = item.kind
        if kind == "vlenb":
            return DEPENDENCY_VLEN
        if kind == "const" or kind == "input" or kind == "loop_input":
            continue
        if kind in _DEPENDENCY_PRESERVING_KINDS:
            stack.extend(
                argument for argument in item.args if isinstance(argument, Expr)
            )
            continue
        # Loads, post-loop placeholders and every unmodelled operation.
        unproven = True

    return DEPENDENCY_UNKNOWN if unproven else DEPENDENCY_INDEPENDENT


# endregion


def walk_loop_inputs(expression: Expr) -> frozenset[Expr]:
    """Collect every ``loop_input`` symbol referenced by an expression tree."""
    found: set[Expr] = set()
    stack = [expression]
    while stack:
        node = stack.pop()
        if not isinstance(node, Expr):
            continue
        if node.kind == "loop_input":
            found.add(node)
            continue
        stack.extend(
            argument for argument in node.args if isinstance(argument, Expr)
        )
    return frozenset(found)

