"""Bounded scalar ABI call-closure proofs; no library/function-name exemptions.

This closes only callback reachability across a native boundary. The caller's
vector objects, width caches, and width-selected CFG regions stay unsafe.
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass
import hashlib
import re

from ..arch.riscv.control_flow import CONDITIONAL_BRANCHES, direct_target
from ..arch.riscv.registers import canonical_register
from .external_leaf import _SCALAR


class ClosureRefusal(ValueError):
    pass


PRESERVED = ('ra', 'gp', 'tp', *(f's{i}' for i in range(12)), *(f'fs{i}' for i in range(12)))
VOLATILE = (*(f'a{i}' for i in range(8)), *(f't{i}' for i in range(7)),
            *(f'fa{i}' for i in range(8)), *(f'ft{i}' for i in range(12)))
LOADS = {'lb': 1, 'lbu': 1, 'lh': 2, 'lhu': 2, 'lw': 4, 'lwu': 4, 'ld': 8,
         'flh': 2, 'flw': 4, 'fld': 8}
STORES = {'sb': 1, 'sh': 2, 'sw': 4, 'sd': 8, 'fsh': 2, 'fsw': 4, 'fsd': 8}
INTEGER_EXTRA = {'sh1add', 'sh2add', 'sh3add', 'sh1add.uw', 'sh2add.uw', 'sh3add.uw',
                 'add.uw', 'clz', 'clzw', 'ctz', 'ctzw', 'cpop', 'cpopw', 'min', 'max',
                 'minu', 'maxu', 'orc.b', 'rev8', 'bclr', 'bclri', 'bset', 'bseti',
                 'bext', 'bexti', 'binv', 'binvi'}
FP = re.compile(r'f(?:add|sub|mul|div|min|max|sqrt|sgnj|sgnjn|sgnjx|madd|msub|nmadd|nmsub|'
                r'abs|neg|mv|cvt|eq|le|lt|class|li|round|roundnx)\.(?:[a-z0-9]+\.?)+$')
MEMORY = re.compile(r'^(-?(?:0x[0-9a-f]+|\d+))?\((\w+)\)$', re.I)
MASK64 = (1 << 64)-1
FP_REGISTERS = ('ft0', 'ft1', 'ft2', 'ft3', 'ft4', 'ft5', 'ft6', 'ft7',
                'fs0', 'fs1', 'fa0', 'fa1', 'fa2', 'fa3', 'fa4', 'fa5', 'fa6', 'fa7',
                'fs2', 'fs3', 'fs4', 'fs5', 'fs6', 'fs7', 'fs8', 'fs9', 'fs10', 'fs11',
                'ft8', 'ft9', 'ft10', 'ft11')


def register(value):
    value = canonical_register(value.split('#', 1)[0].strip())
    if re.fullmatch(r'f(?:[0-9]|[12][0-9]|3[01])', value):
        return FP_REGISTERS[int(value[1:])]
    return value


def integer(value):
    return int(value.split('#', 1)[0].strip().split()[0], 0)


def initial_registers():
    values = {reg: ('entry', reg) for reg in PRESERVED}
    values.update(zero=('constant', 0), sp=('frame', 0))
    return values


def plus(a, b):
    if a is None or b is None:
        return None
    if a[0] == b[0] == 'constant':
        return ('constant', (a[1]+b[1]) & MASK64)
    if b[0] == 'constant' and a[0] in {'frame', 'address', 'tls-address'}:
        offset = b[1] if b[1] < 1 << 63 else b[1]-(1 << 64)
        if a[0] == 'frame':
            return ('frame', a[1]+offset)
        return (*a[:-1], a[-1]+offset)
    if a[0] == 'constant':
        return plus(b, a)
    if a == ('entry', 'tp') and b[0] == 'tls-offset':
        return ('tls-address', *b[1:], 0)
    if b == ('entry', 'tp') and a[0] == 'tls-offset':
        return ('tls-address', *a[1:], 0)
    return None


@dataclass
class State:
    registers: dict
    slots: dict

    def copy(self):
        return State(dict(self.registers), dict(self.slots))

    def merge(self, other):
        registers = {key: value for key, value in self.registers.items()
                     if value is not None and value == other.registers.get(key)}
        slots = {key: value for key, value in self.slots.items()
                 if value is not None and value == other.slots.get(key)}
        return State(registers, slots)


def address_of(operand, state):
    match = MEMORY.fullmatch(operand.split('#', 1)[0].strip())
    if not match:
        return None
    return plus(state.registers.get(register(match[2])),
                ('constant', integer(match[1] or '0') & MASK64))


def balanced(state):
    return (state.registers.get('sp') == ('frame', 0)
            and all(state.registers.get(reg) == ('entry', reg) for reg in PRESERVED))


def frame_range(address, size, state):
    sp = state.registers.get('sp')
    if (address is None or address[0] != 'frame' or sp is None or sp[0] != 'frame'
            or not sp[1] <= address[1] or address[1]+size > 0):
        raise ClosureRefusal('unproved-private-scalar-frame-access')
    return address[1]


def frame_load(offset, size, state):
    parts = [state.slots.get(offset+i) for i in range(size)]
    if parts[0] is not None and all(part == (parts[0][0], i, size)
                                    for i, part in enumerate(parts)):
        return parts[0][0]
    return None


def branch_decision(instruction, state):
    op, args = instruction.op, instruction.args
    a = state.registers.get(register(args[0]))
    b = (state.registers.get(register(args[1]))
         if op in {'beq', 'bne', 'blt', 'bge', 'bltu', 'bgeu'} else ('constant', 0))
    if a is None or b is None:
        return None
    if op in {'beq', 'beqz', 'bne', 'bnez'} and a == b:
        return op in {'beq', 'beqz'}
    if a[0] != 'constant' or b[0] != 'constant':
        return None
    x, y = a[1], b[1]
    sx, sy = (v if v < 1 << 63 else v-(1 << 64) for v in (x, y))
    return {'beq': x == y, 'bne': x != y, 'beqz': x == 0, 'bnez': x != 0,
            'blt': sx < sy, 'bge': sx >= sy, 'bltu': x < y, 'bgeu': x >= y,
            'bltz': sx < 0, 'bgez': sx >= 0, 'blez': sx <= 0, 'bgtz': sx > 0}[op]


class NativeCallClosure:
    """Environment supplies exact ELF-backed bodies, immutable loads and TLS bounds.

    Every ordinary/tail target is followed. Indirect callbacks, unknown writes,
    vector/CSR/system instructions, unbalanced ABI state, and exhausted budgets
    fail closed. Branch pruning uses only constants and bound immutable loads.
    """
    def __init__(self, environment, *, maximum_functions=64, maximum_code_bytes=131072):
        self.environment = environment
        self.maximum_functions = maximum_functions
        self.maximum_code_bytes = maximum_code_bytes
        self.memo = {}
        self.active = set()
        self.loaded = {}
        self.total_code_bytes = 0

    def prove(self, key):
        if key in self.memo:
            return self.memo[key]
        if key in self.active:
            raise ClosureRefusal('recursive-native-call-closure')
        if len(self.loaded) >= self.maximum_functions and key not in self.loaded:
            raise ClosureRefusal('native-call-function-budget-exhausted')
        if key not in self.loaded:
            body, code = self.environment.body(key)
            self.total_code_bytes += len(code)
            if self.total_code_bytes > self.maximum_code_bytes:
                raise ClosureRefusal('native-call-code-budget-exhausted')
            self.loaded[key] = body, code
        body, code = self.loaded[key]
        if not 0 < len(code) <= 4096 or not body.insts:
            raise ClosureRefusal('invalid-native-function-extent')
        cursor = body.start
        for insn in body.insts:
            token = insn.machine_code
            word = (bytes.fromhex(token)[::-1]
                    if re.fullmatch(r'[0-9a-fA-F]{4}|[0-9a-fA-F]{8}', token) else b'')
            offset = insn.addr-body.start
            if (insn.addr != cursor or len(word) != insn.size or insn.size not in {2, 4}
                    or word != code[offset:offset+insn.size]):
                raise ClosureRefusal('incomplete-or-mismatched-native-bytes')
            cursor += insn.size
            if (insn.op not in _SCALAR | INTEGER_EXTRA | set(LOADS) | set(STORES)
                    | CONDITIONAL_BRANCHES | {'ret', 'jr', 'j', 'jal', 'jalr', 'call', 'tail'}
                    and FP.fullmatch(insn.op) is None):
                raise ClosureRefusal('unsupported-native-instruction:'+insn.op)
        if cursor != body.start+len(code):
            raise ClosureRefusal('incomplete-native-function-extent')
        self.active.add(key)
        try:
            proof = self._walk(key, body)
        except ClosureRefusal as error:
            raise ClosureRefusal(f'{key[0]}:{body.start:#x}: {error}') from error
        finally:
            self.active.remove(key)
        proof.update(address=body.start, size=len(code), code_sha256=hashlib.sha256(code).hexdigest())
        self.memo[key] = proof
        return proof

    def _walk(self, key, body):
        instructions = {i.addr: i for i in body.insts}
        states = {body.start: State(initial_registers(), {})}
        queue = deque([body.start])
        edges, pruned, returns = set(), set(), set()
        budget = max(256, len(instructions)*64)

        def put(target, state):
            if target not in instructions:
                raise ClosureRefusal('native-edge-outside-instruction-boundaries')
            prior = states.get(target)
            merged = prior.merge(state) if prior is not None else state.copy()
            if prior != merged:
                states[target] = merged
                queue.append(target)

        while queue:
            budget -= 1
            if budget < 0:
                raise ClosureRefusal('native-abi-dataflow-budget-exhausted')
            pc = queue.popleft();insn = instructions[pc];state = states[pc].copy()
            op, args = insn.op, insn.args
            next_pc = pc+insn.size
            if op == 'ret' or op == 'jr' and tuple(args) in {('ra',), ('x1',)}:
                if not balanced(state):
                    raise ClosureRefusal('native-return-does-not-preserve-entry-abi')
                returns.add(pc);continue
            if op in CONDITIONAL_BRANCHES:
                # A later loop join can widen an earlier constant. Only the
                # final branch fact belongs in the published pruning proof.
                pruned = {edge for edge in pruned if edge[0] != pc}
                target = direct_target(insn)
                decision = branch_decision(insn, state)
                if decision is not False:
                    if target in instructions:
                        put(target, state)
                    else:
                        self._tail(key, insn, state, edges);returns.add(pc)
                if decision is not True:
                    put(next_pc, state)
                if decision is not None:
                    pruned.add((pc, target if decision is False else next_pc))
                continue
            if op == 'j' and direct_target(insn) in instructions:
                put(direct_target(insn), state);continue
            if op in {'j', 'tail'}:
                self._tail(key, insn, state, edges);returns.add(pc);continue
            if op in {'jal', 'jalr', 'call', 'jr'}:
                if (op == 'jr' or op == 'jalr' or len(args) > 1 and args[0] not in {'ra', 'x1'}):
                    raise ClosureRefusal('indirect-or-nonstandard-native-call')
                callee = self.environment.target(key, direct_target(insn))
                self.prove(callee);edges.add(callee)
                for register in VOLATILE:
                    state.registers.pop(register, None)
                state.registers.pop('ra', None)
                put(next_pc, state);continue
            self._transfer(key, insn, state)
            put(next_pc, state)
        if not returns:
            raise ClosureRefusal('no-proven-native-return')
        return dict(callees=tuple(sorted(edges)), proven_returns=tuple(sorted(returns)),
                    pruned_edges=tuple(sorted(pruned)))

    def _tail(self, key, instruction, state, edges):
        if not balanced(state):
            raise ClosureRefusal('native-tail-call-does-not-preserve-entry-abi')
        callee = self.environment.target(key, direct_target(instruction))
        self.prove(callee);edges.add(callee)

    def _transfer(self, key, instruction, state):
        op, args = instruction.op, instruction.args
        if op == 'nop':
            return
        reg = lambda value: state.registers.get(register(value))
        destination = register(args[0]) if args else None
        value = None
        if op in LOADS | STORES:
            size = (LOADS | STORES)[op]
            address = address_of(args[1], state)
            if address is not None and address[0] == 'frame':
                offset = frame_range(address, size, state)
                if op in STORES:
                    stored = reg(args[0])
                    if size < 8:
                        stored = (('constant', stored[1] & ((1 << (size*8))-1))
                                  if stored is not None and stored[0] == 'constant' else None)
                    for i in range(size):
                        state.slots.pop(offset+i, None)
                        if stored is not None:
                            state.slots[offset+i] = (stored, i, size)
                else:
                    value = frame_load(offset, size, state)
            elif op in STORES:
                if address is None or not self.environment.tls_write(address, size):
                    raise ClosureRefusal(f'native-store-may-alias-caller-or-control-state:{instruction.addr:#x}')
            elif address is not None:
                value = self.environment.load(key, address, size)
            if op in STORES:
                return
            if size < 8 and value is not None:
                if value[0] == 'constant':
                    bits = size*8
                    n = value[1] & ((1 << bits)-1)
                    if op in {'flh', 'flw'}:
                        # FLEN=64 loads NaN-box narrower FP data. Keeping only
                        # its low bits could falsely prune an integer branch
                        # after fmv.x.d reads the full register.
                        n |= MASK64 ^ ((1 << bits)-1)
                    elif op in {'lb', 'lh', 'lw'} and n & (1 << (bits-1)):
                        n -= 1 << bits
                    value = ('constant', n & MASK64)
                else:
                    value = ('extended-load', op, value)
        elif op == 'li':
            value = ('constant', integer(args[1]) & MASK64)
        elif op == 'lui':
            n = (integer(args[1]) << 12) & 0xffffffff
            value = ('constant', (n if n < 1 << 31 else n-(1 << 32)) & MASK64)
        elif op == 'auipc':
            n = (integer(args[1]) << 12) & 0xffffffff
            value = ('address', key[0], instruction.addr+(n if n < 1 << 31 else n-(1 << 32)))
        elif op in {'mv', 'fmv.d', 'fmv.x.d', 'fmv.d.x'}:
            value = reg(args[1])
        elif op == 'addi':
            value = plus(reg(args[1]), ('constant', integer(args[2]) & MASK64))
        elif op == 'add':
            value = plus(reg(args[1]), reg(args[2]))
        elif op in {'sub', 'xor'}:
            a, b = reg(args[1]), reg(args[2])
            if a is not None and a == b:
                value = ('constant', 0)
            elif a is not None and b is not None and a[0] == b[0] == 'constant':
                value = ('constant', ((a[1]-b[1]) if op == 'sub' else a[1]^b[1]) & MASK64)
        if destination == 'zero':
            return
        if destination == 'sp':
            if value is None or value[0] != 'frame' or not -4096 <= value[1] <= 0 or value[1] % 16:
                raise ClosureRefusal('unproved-native-stack-adjustment')
            state.slots = {offset: byte for offset, byte in state.slots.items() if offset >= value[1]}
        if destination in {'gp', 'tp'} and value != ('entry', destination):
            raise ClosureRefusal('native-changes-thread-or-global-pointer')
        if value is None:
            state.registers.pop(destination, None)
        else:
            state.registers[destination] = value
