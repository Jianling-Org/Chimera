"""Operand roles for scalar values observing RVV hardware width.

Separate from stack-size symbolic semantics: stores and branches read their
first operand and FP moves may carry scalar bits. Calls expose their target,
SP and standard ABI volatile epochs without inventing parameter/return uses.
"""
from ...core.contracts.services import ScalarWidthInstruction
from .control_flow import is_call_instruction
from .registers import NO_DESTINATION, SCALAR_STORES, canonical_register
from ...safety.stack_liveness.expressions import Expr
from fractions import Fraction

_FP_NAMES = (
    [f"ft{i}" for i in range(8)] + ["fs0", "fs1"] +
    [f"fa{i}" for i in range(8)] + [f"fs{i}" for i in range(2, 12)] +
    [f"ft{i}" for i in range(8, 12)]
)
_FP_ALIASES = {name: f"f{i}" for i, name in enumerate(_FP_NAMES)}
_CALLER_VOLATILE = frozenset(
    {"ra", *(f"t{i}" for i in range(7)), *(f"a{i}" for i in range(8))}
    | {f"f{i}" for i in (*range(8), *range(10, 18), *range(28, 32))})
_REGISTERS = frozenset({"ra", "sp", "gp", "tp"} |
    {f"a{i}" for i in range(8)} | {f"s{i}" for i in range(12)} |
    {f"t{i}" for i in range(7)} | {f"f{i}" for i in range(32)})
_SCALAR_OPS = frozenset({
    "li", "lui", "auipc", "mv", "nop", "neg", "negw", "not", "seqz", "snez",
    "slt", "sltu", "slti", "sltiu", "sltz", "sgtz", "add", "sub", "addw", "subw",
    "addi", "addiw", "mul", "mulw", "mulh", "mulhu", "mulhsu", "div", "divu",
    "divw", "divuw", "rem", "remu", "remw", "remuw", "and", "or", "xor",
    "andi", "ori", "xori", "sll", "srl", "sra", "sllw", "srlw", "sraw",
    "slli", "srli", "srai", "slliw", "srliw", "sraiw", "sext.w", "zext.w",
    "sext.b", "sext.h", "zext.b", "zext.h", "add.uw", "sh1add", "sh2add",
    "sh3add", "sh1add.uw", "sh2add.uw", "sh3add.uw", "slli.uw", "andn",
    "orn", "xnor", "min", "max", "minu", "maxu", "rol", "ror", "rori",
    "clz", "ctz", "cpop", "clzw", "ctzw", "cpopw", "rev8", "orc.b",
    "bset", "bclr", "binv", "bext", "bseti", "bclri", "binvi", "bexti",
})
_CSRS = {"vlenb": "csr-vlenb", "vl": "csr-vl", "vtype": "csr-vtype",
         "0xc22": "csr-vlenb", "0xc20": "csr-vl", "0xc21": "csr-vtype",
         "3106": "csr-vlenb", "3104": "csr-vl", "3105": "csr-vtype"}
_MEMORY_WIDTHS = {
    "lb": 1, "lbu": 1, "lh": 2, "lhu": 2, "lw": 4, "lwu": 4, "ld": 8,
    "sb": 1, "sh": 2, "sw": 4, "sd": 8,
    "flw": 4, "fld": 8, "fsw": 4, "fsd": 8,
}
_INTEGER_REGISTERS = _REGISTERS - {f'f{i}' for i in range(32)}
_CONSTANT_OPS = frozenset({'li', 'lui', 'auipc'})
_UNARY_OPS = frozenset({
    'mv', 'neg', 'negw', 'not', 'seqz', 'snez', 'sltz', 'sgtz',
    'sext.w', 'zext.w', 'sext.b', 'sext.h', 'zext.b', 'zext.h',
    'clz', 'ctz', 'cpop', 'clzw', 'ctzw', 'cpopw', 'rev8', 'orc.b',
})
_IMMEDIATE_OPS = frozenset({
    'addi', 'addiw', 'slti', 'sltiu', 'andi', 'ori', 'xori', 'slli',
    'srli', 'srai', 'slliw', 'srliw', 'sraiw', 'slli.uw', 'rori',
    'bseti', 'bclri', 'binvi', 'bexti',
})
# The leaf certificate is deliberately narrower than generic provenance
# roles. Extending the latter must not silently extend effect-proof coverage.
_LEAF_REGISTER_OPS = frozenset({
    'li', 'lui', 'auipc', 'mv', 'nop', 'addi', 'addiw', 'add', 'sub', 'addw', 'subw',
    'slli', 'slliw', 'sll', 'sllw', 'srli', 'srai', 'srliw', 'sraiw', 'srl', 'sra',
    'sh1add', 'sh2add', 'sh3add', 'mul', 'mulw', 'andi', 'sext.w', 'zext.w',
})


def _register_only_shape(op, args):
    """Explicit integer operand coverage, not a mnemonic-prefix guess."""
    if op == 'nop':
        return not args
    if op not in _LEAF_REGISTER_OPS:
        return False
    registers = args
    if op in _CONSTANT_OPS | _IMMEDIATE_OPS:
        if len(args) != (2 if op in _CONSTANT_OPS else 3):
            return False
        try:
            int(args[-1], 0)
        except ValueError:
            return False
        registers = args[:-1]
    elif len(args) != (2 if op in _UNARY_OPS else 3):
        return False
    return all(canonical_register(arg) in _INTEGER_REGISTERS | {'zero'} for arg in registers)


def _register(token):
    token = token.strip().lower()
    token = _FP_ALIASES.get(token, canonical_register(token))
    if token in _REGISTERS:
        return token
    return None


def _constant_operand(token, incoming):
    """Return a proved integer constant for a literal or incoming register."""
    if str(token).strip().lower() in {"zero", "x0"}:
        return 0
    try:
        return int(token, 0)
    except (TypeError, ValueError):
        register = _register(token)
        value = incoming.get(register) if register is not None else None
        if isinstance(value, Expr) and value.kind == "const" and value.args:
            constant = value.args[0]
            return constant if isinstance(constant, int) else None
        return None


def scalar_width_cache_reads(instruction, incoming_expressions, width_registers):
    """Return width-bearing inputs for a local copy or pure width conversion.

    Mixed arithmetic with an ordinary input is not a cache copy. The accepted
    register names are canonicalized so ABI names, x-register aliases, FP
    names, and compressed spellings use the same rule as instruction facts.
    """
    raw_op = instruction.op.lower()
    compressed = raw_op.startswith("c.")
    op = raw_op.removeprefix("c.")
    args = tuple(str(arg).split("#", 1)[0].strip() for arg in instruction.args)
    width = {register for token in width_registers
             if (register := _register(str(token))) is not None}
    incoming = {}
    for token, value in incoming_expressions.items():
        register = _register(str(token))
        if register is not None:
            incoming[register] = value

    # Frame analysis already owns the stack extent proof. Keep an actual
    # width-derived allocation/restoration operand in local provenance even
    # when the other SP operand is symbolic rather than constant.
    if args and _register(args[0]) == "sp" and op in {
        "add", "sub", "addi", "addiw", "addw", "subw", "mv",
    }:
        sp_sources = {_register(token) for token in args[1:]}
        if sp_sources & width:
            return sp_sources & width

    if op in {"mv", "fmv.x.d", "fmv.x.w", "fmv.d.x", "fmv.s.x",
              "vmv.s.x", "vmv.v.x", "vfmv.s.f"} and len(args) == 2:
        sources = [_register(args[1])]
    elif op in {"neg", "negw", "not", "sext.w", "zext.w", "sext.b", "sext.h",
                "zext.b", "zext.h", "sltz", "sgtz", "clz", "ctz", "cpop",
                "clzw", "ctzw", "cpopw", "rev8", "orc.b"} and len(args) == 2:
        sources = [_register(args[1])]
    elif op in {"slli", "srli", "srai", "slliw", "srliw", "sraiw", "rori",
                "slli.uw"} and len(args) == 3:
        if _constant_operand(args[2], incoming) is None:
            return set()
        sources = [_register(args[1])]
    elif op in {"addi", "addiw"} and len(args) == 3:
        if _constant_operand(args[2], incoming) is None:
            return set()
        sources = [_register(args[1])]
    elif op in {"add", "addw", "sub", "subw", "mul", "mulw", "div", "divu",
                "divw", "divuw", "rem", "remu", "remw", "remuw", "and", "or", "xor"}:
        expected = 2 if compressed else 3
        if len(args) != expected:
            return set()
        operands = list(args[1:])
        if compressed:
            # c.add/c.sub/c.and/... read the old destination as well as rs2.
            operands.insert(0, args[0])
        sources = [_register(token) for token in operands]
        if any(register is None and token.lower() not in {"zero", "x0"}
               for register, token in zip(sources, operands)):
            return set()
        width_sources = [register for register in sources if register in width]
        constants = [_constant_operand(token, incoming) for token in operands
                     if _register(token) not in width]
        if not width_sources or not constants or any(value is None for value in constants):
            return set()
        if op in {"mul", "mulw"} and 0 in constants:
            return set()
        if op in {"div", "divu", "divw", "divuw", "rem", "remu", "remw", "remuw"}:
            if sources[0] not in width or constants[-1] == 0:
                return set()
        return set(width_sources)
    elif compressed and op in {"addi", "addiw", "slli", "srli", "srai"} and len(args) == 2:
        if _constant_operand(args[1], incoming) is None:
            return set()
        sources = [_register(args[0])]
    else:
        return set()

    if not sources or any(register is None for register in sources):
        return set()
    return {register for register in sources if register in width}


def fixed_requested_vl(instruction, incoming, min_vlen_bits):
    """A constant AVL bounded by minimum VLMAX is width independent.

    The rs1=zero, rd!=zero form requests VLMAX, not an AVL of zero.
    Unsupported/unknown VTYPE or AVL is never an independence proof.
    """
    op, args = instruction.op, instruction.args
    if op not in {"vsetvli", "vsetivli", "vsetvl"} or len(args) < 3:
        return False
    if op == "vsetivli":
        try:
            avl = int(args[1], 0)
        except ValueError:
            return False
    else:
        register = canonical_register(args[1])
        if register == "zero":
            return False
        value = incoming.get(register)
        if not isinstance(value, Expr) or value.kind != "const":
            return False
        avl = value.args[0]
    if op == "vsetvl":
        value = incoming.get(canonical_register(args[2]))
        if not isinstance(value, Expr) or value.kind != "const" or value.args[0] & ~0xff:
            return False
        vtype = value.args[0]
        sew = 8 << ((vtype >> 3) & 7)
        lmul = {0: Fraction(1), 1: Fraction(2), 2: Fraction(4), 3: Fraction(8),
                5: Fraction(1, 8), 6: Fraction(1, 4), 7: Fraction(1, 2)}.get(vtype & 7)
    else:
        if len(args) < 4:
            return False
        if args[2] not in {"e8", "e16", "e32", "e64"}:
            return False
        sew = int(args[2][1:])
        lmul = {"m1": Fraction(1), "m2": Fraction(2), "m4": Fraction(4),
                "m8": Fraction(8), "mf2": Fraction(1, 2), "mf4": Fraction(1, 4),
                "mf8": Fraction(1, 8)}.get(args[3])
    return (lmul in {Fraction(1, 8), Fraction(1, 4), Fraction(1, 2), Fraction(1),
                    Fraction(2), Fraction(4), Fraction(8)}
            and sew in {8, 16, 32, 64}
            # The RVV/V adapter requires ELEN>=64. Fractional LMUL capacity
            # alone does not guarantee a wider SEW is supported on both harts;
            # only the mandatory SEW<=LMUL*ELEN range establishes this proof.
            and sew <= 64 * min(Fraction(1), lmul)
            and 0 <= avl <= int(min_vlen_bits * lmul / sew))


def scalar_width_facts(instruction, semantics, configs=()):
    op = instruction.op.lower().removeprefix("c.")
    if op in {"lwsp", "ldsp", "swsp", "sdsp", "flwsp", "fldsp", "fswsp", "fsdsp"}:
        op = op.removesuffix("sp")
    args = tuple(str(arg).split("#", 1)[0].strip() for arg in instruction.args)
    ret = (op in {"ret", "mret", "sret", "uret"}
           or op == "jr" and args and canonical_register(args[0]) == "ra"
           or op == "jalr" and len(args) > 1
           and canonical_register(args[0]) == "zero"
           and (args[1] in {"ra", "x1", "0(ra)", "0(x1)"}
                and (len(args) < 3 or args[2] in {"0", "0x0"})))
    call = is_call_instruction(instruction)
    if ret:
        normal_return = (op == 'ret' and not args
            or op == 'jr' and len(args) == 1 and canonical_register(args[0]) == 'ra'
            or op == 'jalr' and args and canonical_register(args[0]) == 'zero'
            and (len(args) == 2 and args[1] in {'0(ra)', '0(x1)'}
                 or len(args) == 3 and canonical_register(args[1]) == 'ra'
                 and args[2] in {'0', '0x0'}))
        return ScalarWidthInstruction(reads={"ra", "sp"}, returns=True,
                                      register_only=bool(normal_return))
    if call:
        reads = set()
        target_reads = set()
        # The destination is a link register, not an input. The call target
        # register is nevertheless a use (including the implicit c.jalr form).
        target_args = args if len(args) == 1 and op == "jalr" else args[1:]
        for token in target_args:
            token = token.split("(")[-1].rstrip(")")
            reg = _register(token)
            if reg:
                reads.add(reg)
                target_reads.add(reg)
        # The ``call target`` pseudo has an implicit ``ra`` destination, while
        # ``call link,target`` uses its explicit destination. Only a missing
        # operand or an unrecognised explicit link should avoid the ordinary
        # ABI call effects; treating either as implicit ``ra`` weakens exit
        # liveness for custom-link and malformed pseudos.
        link = ("ra" if len(args) == 1 else _register(args[0]) if args else None)
        reads.add("sp")
        return ScalarWidthInstruction(frozenset(reads | {"sp"}),
            frozenset((_CALLER_VOLATILE if link == "ra" else set()) | ({link} if link else set())),
            call=True, call_value_reads=frozenset(reads),
            call_target_reads=frozenset(target_reads))

    store = op in SCALAR_STORES or semantics.is_scalar_store(instruction)
    load = (op in {"lb", "lbu", "lh", "lhu", "lw", "lwu", "ld", "flw", "fld"}
            or semantics.is_scalar_load(instruction) or op.startswith("amo"))
    memory = semantics.scalar_memory_operand(instruction)
    if memory is None and op in _MEMORY_WIDTHS:
        from .registers import ADDRESS_OPERAND_RE
        for arg in args[1:]:
            match = ADDRESS_OPERAND_RE.fullmatch(arg)
            if match:
                try:
                    memory = (canonical_register(match.group(2)),
                              int(match.group(1) or "0", 0), _MEMORY_WIDTHS[op])
                except ValueError:
                    memory = None
                break
    no_destination = ((store and not semantics.is_scalar_store(instruction))
                      or op in NO_DESTINATION)
    # Integer scalar stores have no rd; atomic writes do.
    if store and op in {"sb", "sh", "sw", "sd", "fsw", "fsd"}:
        no_destination = True
    writes = set()
    if args and not no_destination:
        destination = _register(args[0])
        if destination:
            writes.add(destination)
    reads = set()
    for token in args if no_destination else args[1:]:
        token = token.split("(")[-1].rstrip(")")
        register = _register(token)
        if register:
            reads.add(register)
    if instruction.op.startswith("c.") and len(args) == 2 and op in {
        "add", "sub", "xor", "or", "and", "addw", "subw",
        "addi", "addiw", "slli", "srli", "srai", "andi",
    }:
        reads.update(writes)
    known = (op in _SCALAR_OPS or op in NO_DESTINATION or memory is not None
             or op.startswith(("v", "f", "csr", "amo", "lr.", "sc.")))
    if not known:
        reads.update(writes)
    source = None
    if writes and op in {"vsetvli", "vsetivli", "vsetvl"}:
        source = op
    elif writes and op.startswith("csrr") and len(args) > 1:
        source = _CSRS.get(args[1].lower())
    stored = (semantics.stored_scalar_register(instruction) if store else None)
    if store and op in {"sb", "sh", "sw", "sd", "fsw", "fsd"}:
        stored = _register(args[0])
    from .scalar_width_vectors import vector_width_roles
    vector = vector_width_roles(instruction, semantics, configs)
    vector_unknown = vector.pop('unmodelled', False)
    # Explicit access to vstart needs a restart-prefix proof before a whole
    # register definition can be used as a complete overwrite. Normal psABI
    # entry/return has vstart=0; do not extend that assumption across this CSR.
    restart = op.startswith('csr') and any(
        arg.lower() == 'vstart' or arg.lower() in {'8', '0x8', '0x008', '0x0008'} for arg in args)
    return ScalarWidthInstruction(frozenset(reads), frozenset(writes), source,
        memory, load, store, stored,
        semantics.is_conditional_store(instruction) or semantics.is_read_modify_write(instruction),
        unmodelled=not known or vector_unknown or restart or op in {"ecall", "ebreak"},
        vector_restart_unproven=restart,
        register_only=(not instruction.op.lower().startswith('c.') or op == 'nop')
                      and _register_only_shape(op, args), **vector)
