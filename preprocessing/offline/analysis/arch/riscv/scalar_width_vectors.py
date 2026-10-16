"""RVV operand roles for width provenance, not a lane-value proof.

May-groups include widening aliases. Only unmasked whole-register operations
establish complete definitions. Lane writes retain old provenance. Unknown
effects fail closed rather than inventing a definition.
"""
import re
from dataclasses import replace
from math import ceil

from .rvv.liveness import vector_registers
from .registers import ADDRESS_OPERAND_RE, SCALAR_REGISTERS, canonical_register

_WHOLE_MOVE = re.compile(r"vmv([1248])r\.v$")
_WHOLE_LOAD = re.compile(r"vl([1248])r(?:e(?:8|16|32|64))?\.v$")
_WHOLE_STORE = re.compile(r"vs([1248])r\.v$")
# RVV 1.0 assembly aliases. Normalize only their operand roles; no lane-value
# equivalence proof or new whole-register definition is implied here.
_ALIASES = {
    'vfabs.v': 'vfsgnjx.vv', 'vfneg.v': 'vfsgnjn.vv', 'vmnot.m': 'vmnand.mm',
    'vwcvt.x.x.v': 'vwadd.vx', 'vwcvtu.x.x.v': 'vwaddu.vx',
}
_VECTOR_NAME = re.compile(r'v(?:[0-9]|[12][0-9]|3[01])$')
_MEMORY = re.compile(
    r"v[ls](?:e(?:8|16|32|64)(?:ff)?|s(?:seg[2-8])?e(?:8|16|32|64)|"
    r"[uo]x(?:seg[2-8])?ei(?:8|16|32|64)|seg[2-8]e(?:8|16|32|64)(?:ff)?|"
    r"[1248]re(?:8|16|32|64)|[1248]r|m)\.v$")
# These standard arithmetic families have register/CSR effects only.
# A mnemonic outside the surface is not covered just because it starts 'v'.
_ARITHMETIC = frozenset((
    "vadd vsub vrsub vand vor vxor vsll vsrl vsra vnsrl vnsra "
    "vmin vminu vmax vmaxu vmul vmulh vmulhu vmulhsu vdiv vdivu vrem vremu "
    "vmacc vnmsac vmadd vnmsub vwmul vwmulu vwmulsu vwmacc vwmaccu vwmaccsu vwmaccus "
    "vwadd vwaddu vwsub vwsubu vmerge vmv vadc vmadc vsbc vmsbc "
    "vmseq vmsne vmslt vmsltu vmsle vmsleu vmsgt vmsgtu "
    "vsaddu vsadd vssub vssubu vaaddu vaadd vasubu vasub vsmul vssrl vssra vnclip vnclipu "
    "vredsum vredand vredor vredxor vredmin vredminu vredmax vredmaxu vwredsum vwredsumu "
    "vslideup vslidedown vslide1up vslide1down vfslide1up vfslide1down "
    "vfadd vfsub vfrsub vfmul vfdiv vfrdiv vfmacc vfnmacc vfmsac vfnmsac "
    "vfmadd vfnmadd vfmsub vfnmsub vfwmul vfwmacc vfwnmacc vfwmsac vfwnmsac "
    "vfwadd vfwsub vfsqrt vfrec7 vfrsqrt7 vfmin vfmax vfsgnj vfsgnjn vfsgnjx "
    "vfmerge vfmv vfcvt vfncvt vfwcvt vmfeq vmfne vmflt vmfle vmfgt vmfge "
    "vfredusum vfredosum vfredmin vfredmax vfwredusum vfwredosum "
    "vmandnot vmand vmor vmxor vmornot vmnand vmnor vmxnor vcpop vfirst "
    "vmsbf vmsif vmsof viota vid vcompress vrgather vrgatherei16 vsext vzext "
    "vclz vctz vbrev vbrev8 vrev8 vrol vror vwsll"
).split())


def _group(base, size):
    return frozenset(range(base, min(32, base + size)))


def vector_width_roles(instruction, semantics, configs=()):
    args = tuple(str(a).split('#', 1)[0].strip() for a in instruction.args)
    if args != tuple(instruction.args):
        instruction = replace(instruction, args=args)
    op = instruction.op.lower()
    if not op.startswith('v') or op.startswith('vset'):
        return {}
    alias_valid = True
    canonical = _ALIASES.get(op)
    if canonical is not None:
        alias_valid = (len(args) in {2,3} and len(args) >= 2
            and all(_VECTOR_NAME.fullmatch(a) for a in args[:2])
            and (len(args) == 2 or args[2] == 'v0.t' and op != 'vmnot.m'))
        if alias_valid:
            second = 'zero' if op in {'vwcvt.x.x.v','vwcvtu.x.x.v'} else args[1]
            op, args = canonical, (*args[:2], second, *args[2:])
            instruction = replace(instruction, op=op, args=args)
    configs = tuple(configs)
    known = bool(configs) and all(c.lmul is not None and c.sew is not None for c in configs)
    size = max(1, max(ceil(c.lmul) for c in configs)) if known else 8
    broad_size = min(32, size * 2)
    if 'seg' in op:
        broad_size = 32
    masked = any(str(a).endswith('.t') for a in args)
    move, load, store = _WHOLE_MOVE.fullmatch(op), _WHOLE_LOAD.fullmatch(op), _WHOLE_STORE.fullmatch(op)
    memory = semantics.vector_memory_operand(instruction)
    memory_kind = ('load' if op.startswith('vl') else 'store') if memory is not None else None
    eew = re.search(r'e(?:i)?(8|16|32|64)', op)
    if memory_kind and known and eew:
        broad_size = max(broad_size, max(ceil(c.lmul * int(eew.group(1)) / c.sew) for c in configs))
    recognized = alias_valid and bool(move or _MEMORY.fullmatch(op) or op.split('.')[0] in _ARITHMETIC)
    if _MEMORY.fullmatch(op) and memory is None:
        recognized = False
    destination = vector_registers(args[0]) if args else set()
    masks = frozenset().union(*(vector_registers(str(a)) for a in args if str(a).endswith('.t')))
    reads = vector_registers(','.join(a for a in args[1:] if not str(a).endswith('.t')))
    writes, must = set(), set()
    if memory_kind == 'store':
        reads.update(destination)
    else:
        writes.update(destination)
    if op in {'vmv.s.x', 'vfmv.s.f', 'vmv.x.s', 'vfmv.f.s'} or op.endswith('.mm'):
        read_size = write_size = 1
    elif move or load or store:
        read_size = write_size = int((move or load or store).group(1))
    else:
        write_size = size if op in {'vmv.v.x', 'vmv.v.i', 'vfmv.v.f'} else broad_size
        read_size = broad_size
    vector_reads = frozenset().union(*(_group(r, read_size) for r in reads)) | masks
    vector_writes = frozenset().union(*(_group(r, write_size) for r in writes))
    store_values = (frozenset().union(*(_group(r, read_size) for r in destination))
                    if memory_kind == 'store' else frozenset())
    # An index may alias the destination register: its old value is still an
    # address input. Do not remove it by subtracting the destination set.
    indexed_memory = bool(memory_kind and re.match(r'v[ls][uo]x', op))
    index_bases = (vector_registers(','.join(
        a for a in args[2:] if not str(a).endswith('.t'))) if indexed_memory else set())
    index_reads = (frozenset().union(*(_group(r, read_size) for r in index_bases))
                   if index_bases else frozenset())
    if memory_kind == 'store':
        value_bases = destination
    elif memory_kind == 'load':
        value_bases = set()
    else:
        value_bases = vector_registers(','.join(
            a for a in args[1:] if not str(a).endswith('.t')))
    if memory_kind != 'store':
        value_bases.difference_update(index_bases)
    vector_value_reads = frozenset().union(*(_group(r, read_size) for r in value_bases))
    complete_store = False
    if move or load or store:
        n = write_size
        bases = destination | (reads if move else set())
        valid = (not masked and len(args) == 2 and len(destination) == 1
                 and (len(reads) == 1 if move else memory_kind in {'load', 'store'})
                 and all(r % n == 0 and r + n <= 32 for r in bases))
        if valid:
            if store:
                complete_store = True
            else:
                must.update(vector_writes)
        else:
            recognized = False
    addresses = set()
    memory_location = None
    if memory_kind:
        for arg in args[1:]:
            match = ADDRESS_OPERAND_RE.fullmatch(str(arg).strip())
            if match:
                addresses.add(canonical_register(match.group(2)))
                memory_location = (canonical_register(match.group(2)), int(match.group(1) or '0', 0))
            elif not vector_registers(str(arg)):
                token = canonical_register(str(arg).strip())
                if token in SCALAR_REGISTERS:
                    addresses.add(token)
    span = None
    if memory_kind and (load or store):
        span = (0, int((load or store).group(1)))
    elif memory_kind and re.fullmatch(r'v[ls]e(?:8|16|32|64)(?:ff)?\.v', op):
        if configs and all(c.avl_kind.value == 'constant' and c.avl_value is not None
                           and c.avl_value >= 0 for c in configs):
            span = (max(c.avl_value for c in configs) * int(eew.group(1)) // 8, 0)
    return dict(vector_data_write=bool(vector_writes), vector_reads=vector_reads,
                vector_value_reads=vector_value_reads,
                vector_writes=vector_writes, vector_must_writes=frozenset(must),
                vector_address_reads=frozenset(addresses), vector_memory_kind=memory_kind,
                vector_memory=memory_location, vector_memory_span=span,
                vector_store_complete=complete_store,
                vector_store_values=store_values, vector_mask_reads=masks,
                vector_memory_address_vectors=index_reads,
                unmodelled=not recognized)
