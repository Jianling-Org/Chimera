"""Live scalar hardware-width values, independent of vector/stack-frame data.

Forward may-provenance intersects backward value liveness. Register death is
not memory death: proved private frame bytes retain spill provenance until a
covering write. Unresolved value escapes and unfinished dataflow fail closed.
"""
from collections import deque
from dataclasses import dataclass, replace
from functools import partial

from ...core.algorithm.address_states import AddressStateMap, EMPTY_STATES, address_domain
from ...core.algorithm.dataflow import solve_backward_liveness
from .dependencies import _known_control_dependence
from .expressions import Expr, Constant, Input, VLENB, _affine_terms, classify_stack_address_expression
from .instruction_facts import instruction_predecessors
from .model import (
    ActiveOrigin, AnalysisWarning, ORIGIN_LOCAL_SCALAR, ScalarWidthSource, StackObjectId,
    VLEN_SCALAR_ESCAPE, ScalarLeafCallDiagnostic, ScalarWidthEvidence, ScalarWidthSlotDiagnostic,
)

VLEN_SCALAR_DATA = StackObjectId("vlen_scalar", "hardware-width-cache")
_MARKER = frozenset({VLEN_SCALAR_DATA})
_ANY_FRAME = ("frame", None)


@dataclass(frozen=True, slots=True)
class _Region:
    start: Expr | None
    width: Expr | None
    stack_id: StackObjectId | None = None


@dataclass(frozen=True, slots=True)
class _Slot:
    region: _Region
    selected: bool = False


@dataclass(frozen=True, slots=True)
class _State:
    registers: frozenset[str] = frozenset()
    frame_bytes: frozenset[int] = frozenset()
    escaped: bool = False
    vectors: frozenset[int] = frozenset()
    # Selection provenance is a may-dependency, not proof that width bits
    # themselves were written. Keep it distinct when reporting memory scope.
    selected_registers: frozenset[str] = frozenset()
    selected_vectors: frozenset[int] = frozenset()
    selected_bytes: frozenset[int] = frozenset()
    slots: frozenset[_Slot] = frozenset()


_EMPTY = _State()


def _join(values):
    values = tuple(values)
    if not values:
        return _EMPTY
    if len(values) == 1:
        return values[0]
    return _State(frozenset().union(*(v.registers for v in values)),
                  frozenset().union(*(v.frame_bytes for v in values)),
                  any(v.escaped for v in values),
                  frozenset().union(*(v.vectors for v in values)),
                  frozenset().union(*(v.selected_registers for v in values)),
                  frozenset().union(*(v.selected_vectors for v in values)),
                  frozenset().union(*(v.selected_bytes for v in values)),
                  frozenset().union(*(v.slots for v in values)))


def _nonnegative(value, min_bytes=1):
    affine = _affine_terms(value) if isinstance(value, Expr) else None
    return (affine is not None
            and all(atom == VLENB and coefficient >= 0 for atom, coefficient in affine[0].items())
            and affine[1] + sum(affine[0].values()) * min_bytes >= 0)


def _region_is_private(region, incoming, min_bytes=1):
    sp = incoming.get('sp', Input('sp'))
    if region.start is None or region.width is None or not isinstance(sp, Expr):
        return False
    allocation = Input('sp') - sp
    affine = _affine_terms(allocation)
    return (affine is not None and _nonnegative(allocation, min_bytes)
            and (affine[1] > 0 or affine[0].get(VLENB, 0) > 0)
            and _nonnegative(region.start - sp, min_bytes)
            and _nonnegative(Input('sp') - region.start - region.width, min_bytes))


def _covers_region(write, old, min_bytes=1):
    return (write.start is not None and old.start is not None
            and write.width is not None and old.width is not None
            and _nonnegative(old.start - write.start, min_bytes)
            and _nonnegative(write.start + write.width - old.start - old.width, min_bytes))


def _regions_may_overlap(left, right, min_bytes=1):
    if left.start is None or right.start is None:
        return True
    if (left.width is not None and _nonnegative(right.start - left.start - left.width, min_bytes)
        or right.width is not None and _nonnegative(left.start - right.start - right.width, min_bytes)):
        return False
    # A function-entry pointer predates allocation of the proven private slot.
    affine = _affine_terms(left.start)
    if affine is not None:
        coefficients, _ = affine
        if not coefficients:
            return False
        if (len(coefficients) == 1 and next(iter(coefficients.values())) == 1
            and next(iter(coefficients)).kind == 'input'
            and next(iter(coefficients)).args[0] != 'sp'):
            return False
    return True


def _memory_region(fact, incoming, semantics, access=None):
    memory = fact.vector_memory or (fact.memory[:2] if fact.memory else None)
    if memory is None:
        return _Region(None, None)
    base, offset = memory
    expression = semantics.symbolic.address_expression(f'{offset}({base})', incoming)
    start = expression if isinstance(expression, Expr) else None
    if access is not None and access.address_expression is not None:
        start = access.address_expression
    span = fact.vector_memory_span
    width = (Constant(span[0]) + VLENB.scale(span[1]) if span is not None else
             Constant(fact.memory[2]) if fact.memory else None)
    return _Region(start, width, access.stack_id if access is not None else None)


def _reclaimed(region, state):
    sp = state.get('sp')
    return (isinstance(sp, Expr) and region.start is not None and region.width is not None
            and _nonnegative(sp - region.start - region.width))


def _address_selects_private_content(region, state):
    """Relocating a whole private frame is not selecting its stored value."""
    sp = state.get('sp', Input('sp'))
    delta = (_affine_terms(region.start - sp)
             if region.start is not None and isinstance(sp, Expr) else None)
    return delta is None or bool(delta[0])


def _frame_location(fact, incoming):
    if fact.memory is None:
        return None
    base, offset, width = fact.memory
    value = incoming.get(base)
    affine = _affine_terms(value) if isinstance(value, Expr) else None
    if affine is None or affine[0] != {Expr("input", ("sp",)): 1}:
        return None
    return affine[1] + offset, width


def _private_frame(location, incoming):
    value = incoming.get("sp")
    affine = _affine_terms(value) if isinstance(value, Expr) else None
    if affine is None or affine[0] != {Expr("input", ("sp",)): 1}:
        return False
    start, width = location
    return affine[1] < 0 and start >= affine[1] and start + width <= 0


def _may_alias_private_frame(fact, incoming):
    if fact.memory is None:
        return True
    value = incoming.get(fact.memory[0])
    affine = _affine_terms(value) if isinstance(value, Expr) else None
    if affine is None:
        return True
    coefficients, _ = affine
    if not coefficients:
        return False
    # Entry pointers were captured before the callee allocated its private
    # frame. As in the origin prover, only that ownership proof authorizes
    # disjointness; loop/loaded/mixed addresses retain possible aliases.
    return not (len(coefficients) == 1 and next(iter(coefficients.values())) == 1
                and next(iter(coefficients)).kind == "input"
                and next(iter(coefficients)).args[0] != "sp")


def _warning(function, address, reason, *, proof=None, gaps=(), evidence=None):
    detail = "live hardware-width scalar value: " + reason
    return AnalysisWarning(VLEN_SCALAR_ESCAPE, detail, function.start, (address,),
        details=(detail,), origins=(ActiveOrigin(
            origin=ORIGIN_LOCAL_SCALAR, object_source="vlen_scalar",
            object_id=str(VLEN_SCALAR_DATA), dependency="unproven" if gaps else "vlen",
            detail=detail, proof=proof, gaps=gaps, width_evidence=evidence),))


def _byte_intervals(values):
    """Compact diagnostic coordinates; byte provenance is never changed."""
    intervals = []
    for byte in sorted(values):
        if intervals and intervals[-1][1] == byte:
            intervals[-1] = (intervals[-1][0], byte + 1)
        else:
            intervals.append((byte, byte + 1))
    return tuple(intervals[:64]), len(intervals)


def _diagnostic_expression(value):
    """Render bounded AST prefixes instead of building then slicing a string."""
    if value is None:
        return None, False
    parts = []
    remaining, nodes = 512, 64
    truncated = False

    def append(text):
        nonlocal remaining, truncated
        truncated |= len(text) > remaining
        parts.append(text[:remaining])
        remaining -= min(len(text), remaining)

    def visit(item, depth=0):
        nonlocal nodes, truncated
        if remaining == 0 or nodes == 0 or depth >= 16:
            truncated = True
            append('...')
            return
        nodes -= 1
        if isinstance(item, Expr):
            truncated |= len(item.kind) > 64 or len(item.args) > 8
            append(item.kind[:64] + '(')
            for index, argument in enumerate(item.args[:8]):
                if index:
                    append(', ')
                visit(argument, depth + 1)
            append(')')
        elif isinstance(item, str):
            truncated |= len(item) > 128
            append(repr(item[:128]))
        elif isinstance(item, int) and item.bit_length() <= 256:
            append(str(item))
        else:
            # Do not invoke arbitrary __str__/__repr__ or expand huge integers.
            truncated = True
            append('<' + type(item).__name__[:64] + '>')

    visit(value)
    return ''.join(parts), truncated


def _width_evidence(address, incoming, wanted, fact, region, private, controls,
                    *, prover, instruction):
    """Observe the final may-state after existing forward/backward analysis.

    Failure to render evidence must not add or remove an unsafe obligation.
    The cached call getter cannot request another proof or consume budget.
    """
    kind = ('call' if fact.call else 'vector-store' if fact.vector_memory_kind == 'store' else
            'scalar-store' if fact.store else 'return' if fact.returns else 'instruction')
    try:
        truncated = False

        def expression(value):
            nonlocal truncated
            label, cut = _diagnostic_expression(value)
            truncated |= cut
            return label

        frame, frame_count = _byte_intervals(incoming.frame_bytes)
        selected_frame, selected_frame_count = _byte_intervals(incoming.selected_bytes)
        live_bytes = (incoming.frame_bytes if _ANY_FRAME in wanted else
                      {byte for byte in incoming.frame_bytes if ('frame', byte) in wanted})
        live_frame, live_frame_count = _byte_intervals(live_bytes)
        truncated |= frame_count > 64 or live_frame_count > 64 or selected_frame_count > 64
        # Sorting by bounded expression labels avoids comparing Expr objects;
        # the byte/slot identity used by liveness remains the original object.
        slots = []
        for slot in incoming.slots:
            slots.append(ScalarWidthSlotDiagnostic(
                expression(slot.region.start), expression(slot.region.width),
                str(slot.region.stack_id) if slot.region.stack_id is not None else None,
                slot.selected, ('slot', slot) in wanted))
        slots.sort(key=lambda slot: (slot.start or '', slot.width or '', slot.object_id or '', slot.selected, slot.live))
        truncated |= len(slots) > 64
        call_effect = (ScalarLeafCallDiagnostic('not-requested', 'callee-effects-out-of-scope')
                       if fact.call else None)
        scalar_address = ({fact.memory[0]} if fact.memory else set()) | fact.vector_address_reads
        scalar_content = {fact.stored_value} if fact.store and fact.stored_value is not None else set()
        guards = tuple(sorted(controls))
        truncated |= len(guards) > 64
        return ScalarWidthEvidence(
            kind=kind,
            width_registers=tuple(sorted(incoming.registers)),
            selection_registers=tuple(sorted(incoming.selected_registers)),
            live_width_registers=tuple(sorted(incoming.registers & wanted)),
            width_vectors=tuple(sorted(incoming.vectors)),
            selection_vectors=tuple(sorted(incoming.selected_vectors)),
            live_width_vectors=tuple(sorted(r for r in incoming.vectors if ('vector', r) in wanted)),
            frame_intervals=frame, selection_frame_intervals=selected_frame, live_frame_intervals=live_frame,
            frame_byte_count=len(incoming.frame_bytes), frame_interval_count=frame_count,
            selection_frame_interval_count=selected_frame_count,
            slots=tuple(slots[:64]), slot_count=len(slots),
            content_registers=tuple(sorted(scalar_content & incoming.registers)),
            content_vectors=tuple(sorted(fact.vector_store_values & incoming.vectors)),
            content_selection_registers=tuple(sorted(scalar_content & incoming.selected_registers)),
            content_selection_vectors=tuple(sorted(fact.vector_store_values & incoming.selected_vectors)),
            address_registers=tuple(sorted(scalar_address & incoming.registers)),
            address_vectors=tuple(sorted(fact.vector_memory_address_vectors & incoming.vectors)),
            mask_vectors=tuple(sorted(fact.vector_mask_reads & incoming.vectors)),
            control_addresses=guards[:64], control_count=len(guards),
            return_registers=tuple(sorted(fact.reads & incoming.registers)) if fact.returns else (),
            memory_start=expression(region.start), memory_width=expression(region.width),
            memory_private=private, prior_unclosed_effect=incoming.escaped,
            call_effect=call_effect, truncated=truncated)
    except Exception as error:
        return ScalarWidthEvidence(kind, diagnostic_error=type(error).__name__)


def analyze_scalar_width_liveness(function, expressions, semantics, *, domain=None,
                                  min_vlen_bits=256, update_budget=None, config_result=None,
                                  stack_facts=None, prover=None,
                                  resolved_lifetime_transfers=frozenset()):
    """Return marker live-in, source records, warnings, and fallback status.

    Missing capability is an error, not evidence that scalar width is absent.
    The no-source fast path retains no per-instruction provenance or liveness.
    """
    domain = domain or address_domain(tuple(i.addr for i in function.insts))
    empty = AddressStateMap(domain, EMPTY_STATES)
    facts = {i.addr: semantics.scalar_width_facts(i,
        semantics.config_at(config_result, i.addr) if config_result is not None else ())
        for i in function.insts}
    if any(f.vector_restart_unproven for f in facts.values()):
        facts = {a: replace(f, vector_must_writes=frozenset(), vector_store_complete=False)
                 if f.vector_must_writes or f.vector_store_complete else f for a, f in facts.items()}
    independence = getattr(semantics, "scalar_width_is_independent", None)
    fixed_results = {
        i.addr for i in function.insts if facts[i.addr].source_kind
        and callable(independence) and independence(
            i, expressions.before_states.get(i.addr, {}), min_vlen_bits)}
    for address in fixed_results:
        facts[address] = replace(facts[address], source_kind=None)
    sources = tuple(ScalarWidthSource(a, next(iter(f.writes)), f.source_kind)
                    for a, f in facts.items() if f.source_kind)
    if not sources or not function.insts:
        return empty, sources, (), False
    instructions = function.instruction_by_address
    covers = partial(_covers_region, min_bytes=min_vlen_bits // 8)
    overlaps = partial(_regions_may_overlap, min_bytes=min_vlen_bits // 8)
    predecessors = instruction_predecessors(function)
    locations = {a: _frame_location(f, expressions.before_states.get(a, {}))
                 for a, f in facts.items() if f.memory is not None}
    aliases = {a: _may_alias_private_frame(f, expressions.before_states.get(a, {}))
               for a, f in facts.items() if f.load}
    accesses = stack_facts.accesses if stack_facts is not None else {}
    regions = {a: _memory_region(f, expressions.before_states.get(a, {}), semantics, accesses.get(a))
               for a, f in facts.items() if f.memory or f.vector_memory}
    private = {a for a, region in regions.items()
               if _region_is_private(region, expressions.before_states.get(a, {}), min_vlen_bits // 8)}
    control, _, control_fallback = _known_control_dependence(function, semantics)
    by_controller = {}
    for a, controllers in control.items():
        for controller in controllers:
            by_controller.setdefault(controller, set()).add(a)
    known_guards = set()
    before, after = {}, {}
    escapes = {}
    scope = {}
    call_effects = {}
    fallback = False
    control_fallback_used = False
    entry = function.insts[0].addr
    work = deque([entry])
    queued = {entry}
    remaining = max(256, len(domain) * 64) if update_budget is None else update_budget
    reached = set()
    while work:
        if remaining <= 0:
            detail = "scalar width dataflow budget exhausted; value lifetime is unproven"
            markers = {a: _MARKER for a in domain}
            return AddressStateMap(domain, EMPTY_STATES, markers), sources, (
                _warning(function, sources[0].address, detail),), True
        remaining -= 1
        address = work.popleft()
        queued.discard(address)
        incoming = _join(after.get(p, _EMPTY) for p in predecessors[address])
        first = address not in reached
        reached.add(address)
        before[address] = incoming
        fact = facts[address]
        controlled = bool(control.get(address, set()) & known_guards)
        branch_reads = semantics.condition_scalar_registers(instructions[address])
        if (branch_reads and (branch_reads & incoming.registers or controlled)
            and address not in known_guards):
            known_guards.add(address)
            for dependent in by_controller.get(address, ()):
                if dependent not in queued:
                    work.append(dependent)
                    queued.add(dependent)
            if control_fallback:
                fallback = True
                control_fallback_used = True
        registers = set(incoming.registers)
        frame = set(incoming.frame_bytes)
        vectors = set(incoming.vectors)
        selected_registers = set(incoming.selected_registers)
        selected_vectors = set(incoming.selected_vectors)
        selected_bytes = set(incoming.selected_bytes)
        slots = set(incoming.slots)
        escaped = incoming.escaped
        if fact.unmodelled:
            has_local_width = bool(incoming.registers or incoming.frame_bytes
                                   or incoming.vectors or incoming.slots)
            if has_local_width:
                escaped = True
                fallback = True
                escapes[address] = "instruction effects on width-bearing state are not modelled"
            elif controlled:
                escapes[address] = "instruction is width-controlled; selection alone is not cache content"
        location = locations.get(address)
        region = regions.get(address, _Region(None, None))
        touched_slots = {slot for slot in incoming.slots if overlaps(region, slot.region)}
        memory_tainted = (bool(frame) and aliases.get(address, True) if location is None else
                          any(b in frame for b in range(location[0], location[0] + location[1])))
        memory_tainted |= bool(touched_slots)
        memory_selected = (bool(selected_bytes) and aliases.get(address, True) if location is None else
                           any(b in selected_bytes for b in range(location[0], location[0] + location[1])))
        memory_selected |= any(slot.selected for slot in touched_slots)
        vector_input = bool(fact.vector_value_reads & incoming.vectors)
        vector_selected = (bool(fact.vector_reads & incoming.selected_vectors)
            or bool((fact.vector_mask_reads | fact.vector_memory_address_vectors) & incoming.vectors))
        scalar_value_reads = fact.reads - fact.vector_address_reads
        cache_reads = semantics.scalar_width_cache_reads(
            instructions[address], expressions.before_states.get(address, {}), incoming.registers)
        value_tainted = bool(cache_reads) or vector_input
        unsupported_width_inputs = scalar_value_reads & incoming.registers - cache_reads
        value_selected = (bool(fact.reads & incoming.selected_registers) or controlled
                          or vector_selected or bool(unsupported_width_inputs))
        if address in fixed_results:
            # A bounded AVL proves the value of this execution, not which
            # width-selected arm executes it.
            value_tainted = False
            value_selected = controlled
        if fact.vector_data_write and not fact.vector_writes and value_tainted:
            # An adapter declaring a transfer without usable group facts has
            # not supplied a lifetime proof. Preserve the old refusal.
            escaped = True
            fallback = True
            escapes[address] = "vector transfer has no modelled register-group lifetime"
        if fact.vector_writes:
            # A register-only transfer is still local, not a permanent escape.
            # Partial/masked lane definitions cannot kill old group contents.
            vectors.difference_update(fact.vector_must_writes)
            selected_vectors.difference_update(fact.vector_must_writes)
            vector_tainted = (vector_input or bool(cache_reads))
            selection = (vector_selected or controlled or
                bool(scalar_value_reads & incoming.selected_registers)
                or bool(unsupported_width_inputs))
            if fact.vector_memory_kind == 'load':
                # Data, address selection and execution guard are distinct.
                # A selected address can change the value; it does not prove
                # that memory held a persistent hardware-width cache.
                byte_hits = {b for b in incoming.frame_bytes if overlaps(
                    region, _Region(Input('sp') + Constant(b), Constant(1)))}
                address_selected = bool(fact.vector_address_reads &
                                         (incoming.registers | incoming.selected_registers))
                if address in private and not _address_selects_private_content(
                    region, expressions.before_states.get(address, {})):
                    address_selected = False
                vector_tainted |= bool(touched_slots or byte_hits)
                selection |= (memory_selected or bool(byte_hits & incoming.selected_bytes)
                              or address_selected)
                if address_selected or memory_selected or controlled:
                    escapes[address] = "vector load location or execution is width-selected; loaded bits are not cache content"
            if vector_tainted:
                vectors.update(fact.vector_writes)
                if selection:
                    selected_vectors.update(fact.vector_writes)
            elif selection:
                selected_vectors.update(fact.vector_writes)
        if fact.vector_memory_kind == 'store':
            stored_width = bool(fact.vector_store_values & incoming.vectors)
            stored_selected = bool(fact.vector_store_values & incoming.selected_vectors)
            write_controlled = (controlled or bool(fact.vector_mask_reads & incoming.vectors)
                                or bool(fact.vector_mask_reads & incoming.selected_vectors))
            address_selected = (bool(fact.vector_address_reads &
                                     (incoming.registers | incoming.selected_registers))
                                or bool(fact.vector_memory_address_vectors & incoming.vectors))
            address_selected |= bool(fact.vector_memory_address_vectors & incoming.selected_vectors)
            private_relocated = (address in private and not _address_selects_private_content(
                region, expressions.before_states.get(address, {})))
            if private_relocated:
                address_selected = False
                memory_selected = False
            if address in private:
                # Use the recovered stack object's identity and a proven
                # private extent. Store alone is not an escape. Predicated or
                # partial writes cannot erase prior content/selection tags.
                if fact.vector_store_complete:
                    slots = {slot for slot in slots if not covers(region, slot.region)}
                    covered = {b for b in frame if covers(
                        region, _Region(Input('sp') + Constant(b), Constant(1)))}
                    frame.difference_update(covered)
                    selected_bytes.difference_update(covered)
                if stored_width:
                    slots.add(_Slot(region, stored_selected))
            elif stored_width or stored_selected or write_controlled or address_selected:
                # Keep location/content gaps diagnostic-only; they do not
                # change the local lifetime of a known non-stack cache write.
                absolute = (_affine_terms(region.start) if region.start is not None else None)
                known_nonstack = (absolute is not None and not absolute[0]
                    and not fact.vector_memory_address_vectors and len(fact.vector_address_reads) == 1)
                gaps = []
                if stored_selected or address_selected:
                    gaps.append('width-selected-memory-effect-unproven')
                if write_controlled:
                    gaps.append('width-controlled-write-unproven')
                if stored_width and known_nonstack and region.width is not None:
                    escapes[address] = "vector memory contains hardware-width data at a proven non-stack address; outside supported cache storage"
                    scope[address] = ('unsupported-nonstack-width-data', tuple(gaps))
                else:
                    if (known_nonstack or region.start is not None
                        and classify_stack_address_expression(region.start) == 'stack'):
                        gaps.append('width-store-extent-unproven')
                    else:
                        gaps.append('width-store-address-unproven')
                    escapes[address] = "vector memory write: content, address selection and control require separate location/effect evidence"
                    scope[address] = (None, tuple(gaps))
                    if stored_width:
                        escaped = True
        if fact.load:
            # Without equal-content evidence, a width-selected address can
            # select a different value. Unrelated addresses do not inherit
            # width merely because another private slot carried it.
            address_reads = fact.reads & ({fact.memory[0]} if fact.memory else set())
            address_selected = bool(address_reads & (incoming.registers | incoming.selected_registers))
            private_relocated = (address in private and not _address_selects_private_content(
                region, expressions.before_states.get(address, {})))
            if private_relocated:
                address_selected = False
                memory_selected = False
            value_tainted = memory_tainted
            value_selected = memory_selected or controlled or address_selected
            if address_selected or memory_selected or controlled:
                escapes[address] = "load location or execution is width-selected; loaded bits are not cache content"
        if fact.call:
            standard_call = "ra" in fact.writes
            if standard_call:
                # Standard psABI calls end caller-volatile cache epochs. The
                # actual indirect target and SP remain uses; arguments and
                # synthesized return values are outside local provenance.
                registers.difference_update(fact.writes)
                selected_registers.difference_update(fact.writes)
                vectors.clear()
                selected_vectors.clear()
                if controlled:
                    escapes[address] = "call execution is width-selected; selection alone is not cache content"
            else:
                # Custom link conventions retain the explicit unknown-call
                # guard. No ABI argument list is treated as local evidence.
                possible_inputs = ((incoming.registers - fact.writes)
                                   | (incoming.registers & fact.call_target_reads))
                returns_tainted = (bool(possible_inputs or incoming.vectors)
                                   or bool(incoming.frame_bytes or incoming.slots))
                if returns_tainted:
                    escaped = True
                    escapes[address] = "custom call effects on width-bearing state are unproven"
                registers.difference_update(fact.writes)
                selected_registers.difference_update(fact.writes)
        else:
            registers.difference_update(fact.writes)
            selected_registers.difference_update(fact.writes)
            if fact.source_kind or value_tainted:
                registers.update(fact.writes)
                if value_selected:
                    selected_registers.update(fact.writes)
            elif value_selected:
                selected_registers.update(fact.writes)
        if fact.store:
            stored = fact.stored_value in incoming.registers
            stored_selected = fact.stored_value in incoming.selected_registers
            if controlled:
                escapes[address] = "store execution is width-selected; selection alone is not cache content"
            if fact.memory and fact.memory[0] in (incoming.registers | incoming.selected_registers) and address not in private:
                escapes[address] = "write address is width-selected; subsequent memory lifetime is unproven"
            if address in private and not fact.unstable_write:
                slots = {slot for slot in slots if not covers(region, slot.region)}
            if location is not None and _private_frame(location, expressions.before_states.get(address, {})):
                start, width = location
                if not fact.unstable_write:
                    frame.difference_update(range(start, start + width))
                    selected_bytes.difference_update(range(start, start + width))
                if stored or fact.unstable_write and memory_tainted:
                    frame.update(range(start, start + width))
                    if fact.stored_value in incoming.selected_registers or memory_selected:
                        selected_bytes.update(range(start, start + width))
            elif address in private:
                # A scalar reload/store can alias the same symbolic VLEN-sized
                # private spill even when fixed-byte frame recovery cannot.
                if stored or fact.unstable_write and memory_tainted:
                    slots.add(_Slot(region, fact.stored_value in incoming.selected_registers or memory_selected))
            elif stored or stored_selected:
                escapes[address] = "stored through an address not proved private to this frame"
                affine = _affine_terms(region.start) if region.start is not None else None
                known_nonstack = (affine is not None and not affine[0]
                    and classify_stack_address_expression(region.start) != 'stack')
                if stored and known_nonstack:
                    scope[address] = ('unsupported-nonstack-width-data', ())
                elif stored:
                    gap = ('width-store-extent-unproven'
                           if region.start is not None
                           and classify_stack_address_expression(region.start) == 'stack'
                           else 'width-store-address-unproven')
                    scope[address] = (None, (gap,))
                if stored and not known_nonstack:
                    escaped = True
        if fact.returns and fact.reads & incoming.registers:
            escapes[address] = "return uses width-dependent result or control state; caller lifetime is unproven"
        if "sp" in fact.writes:
            # Symbolic restoration to a fixed entry-SP offset is an actual
            # value proof; arithmetic operand taint must not pin a restored
            # stack forever. A width-selected allocation keeps its guard.
            sp = expressions.after_states.get(address, {}).get("sp")
            affine = _affine_terms(sp) if isinstance(sp, Expr) else None
            if affine is not None and affine[0] == {Expr("input", ("sp",)): 1}:
                if not controlled:
                    registers.discard("sp")
                    selected_registers.discard("sp")
                # Under the same standard-ABI ownership proof used for a
                # private spill, bytes below a reclaimed SP are no longer
                # live frame storage. Explicit earlier escapes stay sticky.
                frame = {byte for byte in frame if byte >= affine[1]}
                selected_bytes.intersection_update(frame)
            slots = {slot for slot in slots if not _reclaimed(slot.region, expressions.after_states.get(address, {}))}
        # Reuse immutable unchanged sets: otherwise an ordinary instruction
        # duplicates every live spill byte in every retained CFG state.
        outgoing = _State(
            incoming.registers if registers == incoming.registers else frozenset(registers),
            incoming.frame_bytes if frame == incoming.frame_bytes else frozenset(frame), escaped,
            incoming.vectors if vectors == incoming.vectors else frozenset(vectors),
            incoming.selected_registers if selected_registers == incoming.selected_registers else frozenset(selected_registers),
            incoming.selected_vectors if selected_vectors == incoming.selected_vectors else frozenset(selected_vectors),
            incoming.selected_bytes if selected_bytes == incoming.selected_bytes else frozenset(selected_bytes),
            incoming.slots if slots == incoming.slots else frozenset(slots))
        if first or outgoing != after.get(address, _EMPTY):
            after[address] = outgoing
            for successor in instructions[address].succ:
                if successor in instructions and successor not in queued:
                    work.append(successor)
                    queued.add(successor)

    # Restrict byte liveness to bytes which actually carried width provenance.
    # Ordinary frame loads/stores must not allocate a full per-instruction map.
    width_bytes = frozenset().union(*(s.frame_bytes for s in after.values()))
    width_slots = frozenset().union(*(s.slots for s in after.values()))
    uses, defs = {}, {}
    for address, fact in facts.items():
        use = set(fact.reads)
        define = set(fact.writes)
        # Branch guards and memory addresses select an execution/location;
        # they do not consume cached width bits as data.
        use.difference_update(semantics.condition_scalar_registers(instructions[address]))
        if fact.memory is not None:
            address_register = fact.memory[0]
            if address_register != fact.stored_value:
                use.discard(address_register)
        use.difference_update(fact.vector_address_reads)
        use.update(('vector', r) for r in fact.vector_value_reads)
        use.update(('vector', r) for r in fact.vector_store_values)
        define.update(('vector', r) for r in fact.vector_must_writes)
        standard_call = fact.call and 'ra' in fact.writes
        if standard_call:
            use = set(fact.call_target_reads | {'sp'})
            define.update(('vector', register) for register in range(32))
        location = locations.get(address)
        if fact.load:
            if location is None:
                if aliases.get(address, True):
                    use.add(_ANY_FRAME)
            else:
                start, width = location
                use.update(("frame", b) for b in range(start, start + width) if b in width_bytes)
        region = regions.get(address, _Region(None, None))
        if fact.load or fact.vector_memory_kind == 'load':
            use.update(('slot', slot) for slot in width_slots if overlaps(region, slot.region))
        if fact.vector_memory_kind == 'load':
            use.update(('frame', b) for b in width_bytes if overlaps(
                region, _Region(Input('sp') + Constant(b), Constant(1))))
        if fact.call and not standard_call:
            # Without a no-alias/escape proof, the callee can access a private
            # cache through a passed pointer even if the caller never reloads.
            # Keep the same possible register inputs used by forward refusal
            # live before the call, including copies outside ABI arguments.
            incoming = before.get(address, _EMPTY)
            use.update(incoming.registers - fact.writes)
            use.update(incoming.registers & fact.call_target_reads)
            use.update(('vector', register) for register in incoming.vectors)
            use.add(_ANY_FRAME)
            use.update(('slot', slot) for slot in width_slots)
        if fact.store and location is not None and not fact.unstable_write:
            start, width = location
            define.update(("frame", b) for b in range(start, start + width) if b in width_bytes)
        if fact.unstable_write and location is not None:
            start, width = location
            use.update(("frame", b) for b in range(start, start + width) if b in width_bytes)
        if address in private and (fact.vector_store_complete or fact.store and not fact.unstable_write):
            define.update(('slot', slot) for slot in width_slots if covers(region, slot.region))
            if fact.vector_store_complete:
                define.update(('frame', b) for b in width_bytes if covers(
                    region, _Region(Input('sp') + Constant(b), Constant(1))))
        if fact.unstable_write:
            use.update(('slot', slot) for slot in width_slots if overlaps(region, slot.region))
        if 'sp' in fact.writes:
            define.update(('slot', slot) for slot in width_slots if _reclaimed(
                slot.region, expressions.after_states.get(address, {})))
        # An unresolved non-return transfer cannot establish that scalar state
        # dies; the destination may still use it.
        if (semantics.is_tail_call_instruction(instructions[address], function)
            or not instructions[address].succ and not fact.returns):
            if address in resolved_lifetime_transfers:
                # A complete internal ABI transfer ends this local cache epoch.
                # Its actual target operands and SP remain real machine uses.
                use.add('sp')
            else:
                # An unknown boundary cannot establish that cached values die;
                # retain the fail-closed all-cache exit use.
                use.update(before.get(address, _EMPTY).registers)
                use.update(('vector', r) for r in before.get(address, _EMPTY).vectors)
                use.add(_ANY_FRAME)
                use.update(('slot', slot) for slot in width_slots)
        uses[address], defs[address] = use, define
    live, _ = solve_backward_liveness(domain,
        successors=lambda a: instructions[a].succ, predecessors=lambda a: predecessors[a],
        use_def=lambda a: (uses[a], defs[a]))
    markers = {}
    for address, incoming in before.items():
        wanted = live[address]
        if (incoming.escaped
            or bool(incoming.registers & wanted)
            or any(('vector', r) in wanted for r in incoming.vectors)
            or any(('slot', slot) in wanted for slot in incoming.slots)
            or incoming.frame_bytes and (
                _ANY_FRAME in wanted or any(("frame", b) in wanted for b in incoming.frame_bytes))
            ):
            markers[address] = _MARKER
    if control_fallback_used:
        escapes.setdefault(sources[0].address, "width-controlled CFG lifetime could not be closed")
    warnings = tuple(_warning(function, a, reason, proof=scope.get(a, (None, ()))[0],
                              gaps=scope.get(a, (None, ()))[1],
                              evidence=_width_evidence(a, before.get(a, _EMPTY), live[a], facts[a],
                                  regions.get(a, _Region(None, None)), a in private,
                                  control.get(a, set()) & known_guards,
                                  prover=prover, instruction=instructions[a]))
                     for a, reason in sorted(escapes.items()))
    warning_addresses = set(escapes)
    call_snapshots = []
    for address, fact in facts.items():
        if not fact.call or address not in before or address in warning_addresses:
            continue
        incoming, wanted = before[address], live[address]
        local_live = (bool(incoming.registers & wanted)
            or any(('vector', register) in wanted for register in incoming.vectors)
            or any(('slot', slot) in wanted for slot in incoming.slots)
            or bool(incoming.frame_bytes and (_ANY_FRAME in wanted
                or any(('frame', byte) in wanted for byte in incoming.frame_bytes))))
        if not local_live:
            continue
        detail = "local scalar-width cache copies remain live across this call"
        call_snapshots.append(_warning(function, address, detail,
            proof='local-cache-live-at-call',
            evidence=_width_evidence(address, incoming, wanted, fact,
                regions.get(address, _Region(None, None)), address in private,
                control.get(address, set()) & known_guards,
                prover=None, instruction=instructions[address])))
    warnings += tuple(call_snapshots)
    return AddressStateMap(domain, EMPTY_STATES, markers), sources, warnings, fallback
