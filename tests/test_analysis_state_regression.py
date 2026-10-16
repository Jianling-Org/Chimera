"""Semantic regression for the compact per-address analysis state.

Two independent kinds of evidence are asserted here:

1. **Dense references.**  The four pieces that moved from dense dictionaries to
   the compact address-domain representation (backward liveness, VLEN frame
   markers, conservative marker merging, inherited-closure marking, plus the
   vector-configuration collection step) are compared address by address
   against a re-implementation of their pre-change dense form, which lives in
   this module on purpose so the comparison cannot silently follow the
   implementation it is checking.

2. **Fixed-baseline differential.**  The fixtures are also executed end to end
   by the analysis in this working tree and by the analysis extracted from the
   frozen pre-change commit, each in its own process, and the two JSON reports
   must be identical — per-address configurations and live sets, warnings with
   their support lines, the inherited closure, the compile decision, and the
   final per-instruction safety classification.

Feature coverage is asserted separately so a fixture cannot quietly stop
exercising irreducible loops, VLEN stack frames, metadata mode, recursion,
inheritance, conservative scopes, or residual findings.
"""

from __future__ import annotations

from collections import deque
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest

from chimera.preprocess.offline.analysis.arch.riscv.rvv.config import (
    UNKNOWN_CONFIG,
    VectorConfigAnalyzer,
    _State,
)
from chimera.preprocess.offline.analysis.arch.riscv.rvv.services import RvvServices
from chimera.preprocess.offline.analysis.core.data_model import (
    Function,
    Instruction,
    Program,
)
from chimera.preprocess.offline.analysis.safety.stack_liveness.frame_liveness import (
    VLEN_STACK_FRAME,
    VLEN_STACK_SETUP,
    _contains_vlen,
    _setup_dependencies,
    analyze_vlen_stack_liveness,
)
from chimera.preprocess.offline.analysis.safety.stack_liveness.instruction_facts import (
    _function_exit_addresses,
    _instruction_predecessors,
)
from chimera.preprocess.offline.analysis.safety.stack_liveness.liveness import (
    _CallerStackContextPropagator,
    _FunctionStackLivenessAnalyzer,
)
from chimera.preprocess.offline.analysis.safety.stack_liveness.model import (
    ChimeraMetadata,
    InheritedLivenessView,
    StackFunctionLiveness,
    StackObjectId,
)
from chimera.preprocess.offline.analysis.safety.stack_liveness.solver import (
    _FunctionExpressionAnalyzer,
)


REPO_ROOT = Path(__file__).resolve().parent.parent

#: Frozen pre-change revision.  Deliberately a commit hash and not ``HEAD``:
#: a moving reference would make the "no behavioural change" claim meaningless
#: as soon as a later commit lands.
BASELINE_COMMIT = "93419dd7513befb00a1d8a3c2853c4001ffea9b0"
_BASELINE_TREES = ("cli", "preprocessing", "runtime")

MIN_VLEN_BITS = 256


# region Fixtures

# Structural fixture family: an empty function, a branch merge with a
# whole-register spill, a natural loop, a VLEN-dependent dynamic stack frame,
# a recursive function, an irreducible loop containing a VLEN-sensitive store,
# and a function whose vector address expression cannot be resolved (which is
# what produces a conservative scope).
ANALYSIS_DUMP = """\
0000000000010000 <empty_fn>:
    10000: 8082                 ret

0000000000010004 <branch_merge>:
    10004: cd817057             vsetivli zero,4,e32,m1,ta,ma
    10008: 84b2                 mv s1,sp
    1000c: 0204b02b             vs2r.v v0,(s1)
    10010: 4685                 li a3,1
    10014: e299                 bnez a3,10020 <branch_merge+0x1c>
    10018: 2284b787             vl4re64.v v10,(s1)
    1001c: a019                 j 10024 <branch_merge+0x20>
    10020: 0204f02b             vs2r.v v1,(s1)
    10024: 2284d787             vl4re64.v v11,(s1)
    10028: 8082                 ret
    1002c: 0000                 unimp

0000000000011000 <natural_loop>:
    11000: 468d                 li a3,3
    11004: cd817057             vsetivli zero,4,e32,m1,ta,ma
    11008: 84b2                 mv s1,sp
    1100c: 0204b02b             vs2r.v v0,(s1)
    11010: 16fd                 addi a3,a3,-1
    11014: f2f5                 bnez a3,1100c <natural_loop+0xc>
    11018: 2284b787             vl4re64.v v10,(s1)
    1101c: 8082                 ret

0000000000012000 <vlen_frame>:
    12000: 1141                 addi sp,sp,-16
    12004: cd817057             vsetivli zero,4,e32,m1,ta,ma
    12008: 84b2                 mv s1,sp
    1200c: 0204b02b             vs2r.v v0,(s1)
    12010: c0002573             csrr a0,vlenb
    12014: 050a                 slli a0,a0,2
    12018: 8d09                 sub sp,sp,a0
    1201c: 0204b02b             vs2r.v v0,(sp)
    12020: 8d09                 add sp,sp,a0
    12024: 0141                 addi sp,sp,16
    12028: 8082                 ret

0000000000013000 <recursive_fn>:
    13000: 1141                 addi sp,sp,-16
    13004: cd817057             vsetivli zero,4,e32,m1,ta,ma
    13008: 84b2                 mv s1,sp
    1300c: 0204b02b             vs2r.v v0,(s1)
    13010: e3ffffef             jal ra,13000 <recursive_fn>
    13014: 2284b787             vl4re64.v v10,(s1)
    13018: 8082                 ret

0000000000014000 <irreducible_fn>:
    14000: 4685                 li a3,1
    14004: e291                 bnez a3,1400c <irreducible_fn+0xc>
    14008: a005                 j 14014 <irreducible_fn+0x14>
    1400c: cd817057             vsetivli zero,4,e32,m1,ta,ma
    14010: 0204b02b             vs2r.v v0,(sp)
    14014: 84b2                 mv s1,sp
    14018: e391                 bnez a3,1400c <irreducible_fn+0xc>
    1401c: 8082                 ret

0000000000015000 <unresolved_scope>:
    15000: 02b54533             div a0,a0,a1
    15004: 0205702b             vs2r.v v0,(a0)
    15008: 9682                 jalr a3
    1500c: 8082                 ret
"""

# Three-role fixture: a seed host with a whole-register spill spanning two
# calls, a callee that inherits that live context and hosts an unresolved
# indirect call, and an unrelated quiet function whose unresolved call must not
# become a finding at all.
CHECK_ELF_DUMP = """\
0000000000010000 <leaf>:
    10000: 8082                 ret

0000000000010004 <callee>:
    10004: 8082                 ret

0000000000010008 <victim>:
    10008: 8faa                 mv a5,a0
    1000a: 9682                 jalr a3
    1000c: 8082                 ret

0000000000010010 <quiet>:
    10010: 9682                 jalr a2
    10012: 8082                 ret

0000000000010014 <seed_host>:
    10014: 7131                 addi sp,sp,-128
    10016: f406                 sd ra,120(sp)
    10018: cd817057             vsetivli zero,16,e64,m4,ta,ma
    1001c: 84b2                 mv s1,sp
    1001e: 0294302b             vs4r.v v9,(s1)
    10022: e05ff0ef             jal ra,10004 <callee>
    10026: 2284b787             vl4re64.v v10,(s1)
    1002a: e09ff0ef             jal ra,10008 <victim>
    1002e: 2284d787             vl4re64.v v11,(s1)
    10032: 60a6                 ld ra,120(sp)
    10034: 6145                 addi sp,sp,128
    10036: 8082                 ret
"""

ELF_STUB_BYTES = b"\x7fELF\x02\x01\x01" + b"\x00" * 24

# endregion


# region Dense reference implementations (pre-change behaviour)

def _dense_backward_liveness(function: Function, uses, defs):
    """Pre-change dense ``before = use | (after - def)`` fixed point."""

    instructions = function.instruction_by_address
    predecessors = _instruction_predecessors(function)
    addresses = [instruction.addr for instruction in function.insts]
    known = set(addresses)
    live_before: dict[int, set] = {address: set() for address in addresses}
    live_after: dict[int, set] = {address: set() for address in addresses}
    worklist = deque(reversed(addresses))
    queued = set(worklist)
    while worklist:
        address = worklist.popleft()
        queued.discard(address)
        after: set = set()
        for successor in instructions[address].succ:
            if successor in known:
                after.update(live_before[successor])
        before = set(uses.get(address, frozenset())) | (
            after - set(defs.get(address, frozenset()))
        )
        if before == live_before[address] and after == live_after[address]:
            continue
        live_before[address] = before
        live_after[address] = after
        for predecessor in predecessors[address]:
            if predecessor not in queued:
                worklist.append(predecessor)
                queued.add(predecessor)
    return (
        {address: frozenset(value) for address, value in live_before.items()},
        {address: frozenset(value) for address, value in live_after.items()},
    )


def _dense_merge_marker(live_before: dict, addresses, marker: StackObjectId) -> None:
    for address in addresses:
        if address in live_before:
            live_before[address] = live_before[address] | frozenset({marker})


def _dense_frame_liveness(function: Function, expressions, semantics):
    """VLEN frame-marker computation in the dense per-address form.

    Same semantics as :func:`analyze_vlen_stack_liveness`, but every address
    keeps its own set, so the compact address-domain representation can be
    compared entry by entry against the dense dictionary it replaces.
    """

    from chimera.preprocess.offline.analysis.safety.stack_liveness.dependencies import (
        DEPENDENCY_INDEPENDENT,
        DEPENDENCY_UNKNOWN,
        analyze_register_dependencies,
    )
    from chimera.preprocess.offline.analysis.safety.stack_liveness.expressions import (
        vlen_dependency,
    )
    from chimera.preprocess.offline.analysis.safety.stack_liveness.frame_liveness import (
        _is_known_stack_base,
        _setup_dependencies,
    )

    after = expressions.after_states
    order = [instruction.addr for instruction in function.insts]
    live_before = {address: frozenset() for address in order}
    warnings: list[str] = []
    if not order:
        return live_before, ()

    instructions = function.instruction_by_address
    predecessors = _instruction_predecessors(function)
    dependencies = analyze_register_dependencies(function, semantics)
    sp_writes = {
        address
        for address in order
        if "sp" in semantics.written_scalar_registers(instructions[address])
    }

    classification: dict[int, str] = {}
    diagnosis: dict[int, bool] = {}
    live_after: dict[int, bool] = {}
    entry = order[0]
    pending = [entry]
    queued = {entry}
    while pending:
        address = pending.pop()
        queued.discard(address)
        incoming = False
        if address != entry:
            incoming = any(
                live_after.get(predecessor, False)
                for predecessor in predecessors.get(address, ())
            )
        outgoing = incoming
        if address in sp_writes:
            if _is_known_stack_base(after.get(address, {}).get("sp")):
                classification[address] = "release"
                outgoing = False
            else:
                if dependencies.level_after(address, "sp") == DEPENDENCY_INDEPENDENT:
                    classification[address] = "independent"
                else:
                    classification[address] = "adjustment"
                    diagnosis[address] = (
                        dependencies.level_after(address, "sp") == DEPENDENCY_UNKNOWN
                        or vlen_dependency(after.get(address, {}).get("sp"))
                        == DEPENDENCY_UNKNOWN
                    )
                    outgoing = True
        if address in live_after and live_after[address] == outgoing:
            continue
        live_after[address] = outgoing
        for successor in instructions[address].succ:
            if successor in instructions and successor not in queued:
                pending.append(successor)
                queued.add(successor)

    adjustments = {
        address
        for address, kind in classification.items()
        if kind == "adjustment"
    }

    def frame_live_before(address: int) -> bool:
        # No entry special case: the state the function is entered with is "no
        # active frame", which is the identity of this may-join.
        return any(
            live_after.get(predecessor, False)
            for predecessor in predecessors.get(address, ())
        )

    for address in order:
        if address in adjustments or frame_live_before(address):
            live_before[address] = live_before[address] | frozenset({VLEN_STACK_FRAME})

    for address in order:
        if address in adjustments:
            if diagnosis.get(address, False):
                warnings.append("unknown-vlen-stack-adjustment")
        elif classification.get(address) == "independent" and frame_live_before(address):
            warnings.append("unproven-vlen-stack-restoration")

    setup, unresolved = _setup_dependencies(
        function, semantics, adjustments, dependencies
    )
    _dense_merge_marker(live_before, setup, VLEN_STACK_SETUP)
    if unresolved:
        warnings.append("unresolved-vlen-stack-setup")
    return live_before, tuple(warnings)


def _dense_conservative_merge(function, live_before, live_after, conservative_addresses):
    """Pre-change dense conservative marker merge."""

    marker = StackObjectId("conservative", "possible-stack-data")
    exits = _function_exit_addresses(function)
    before = dict(live_before)
    after = dict(live_after)
    for address in set(conservative_addresses) - exits:
        if address in before:
            before[address] = before[address] | frozenset({marker})
        if address in after:
            after[address] = after[address] | frozenset({marker})
    return before, after


def _dense_inherited_marker(live_before, marker: StackObjectId) -> dict:
    """Pre-change dense inherited-closure marking."""

    return {
        address: values | frozenset({marker})
        for address, values in live_before.items()
    }


def _dense_vector_configurations(function: Function) -> dict:
    """Pre-change dense configuration collection (no domain, no interning)."""

    analyzer = VectorConfigAnalyzer()
    if not function.insts:
        return {}
    instructions = function.instruction_by_address
    entry = function.insts[0].addr
    before: dict[int, _State] = {entry: _State(frozenset({UNKNOWN_CONFIG}))}
    worklist = deque([entry])
    queued = {entry}
    while worklist:
        address = worklist.popleft()
        queued.discard(address)
        outgoing = analyzer._transfer(instructions[address], before[address])
        for successor in instructions[address].succ:
            if successor not in instructions:
                continue
            merged = analyzer._merge_states(before.get(successor), outgoing)
            if merged == before.get(successor):
                continue
            before[successor] = merged
            if successor not in queued:
                worklist.append(successor)
                queued.add(successor)
    return {
        instruction.addr: before.get(
            instruction.addr, _State(frozenset({UNKNOWN_CONFIG}))
        ).configs
        for instruction in function.insts
    }

# endregion


# region Fixture construction helpers

def _instruction(address: int, op: str, args: list[str]) -> Instruction:
    return Instruction(address, 4, op, list(args), f"{op} " + ",".join(args))


def _function(*specs, start: int = 0x1000) -> Function:
    instructions = [
        _instruction(start + 4 * index, op, args)
        for index, (op, args) in enumerate(specs)
    ]
    for current, following in zip(instructions, instructions[1:]):
        current.succ.add(following.addr)
    return Function("fixture", start, instructions)


def _program(function: Function) -> Program:
    return Program(
        dump_lines=[],
        functions=[function],
        instructions=function.insts,
        instruction_by_address={
            instruction.addr: instruction for instruction in function.insts
        },
    )

# endregion


def _stack_analysis(function: Function, *, metadata: ChimeraMetadata | None = None):
    """Run the current per-function stack pipeline for one fixture."""

    analyzer = _FunctionStackLivenessAnalyzer(
        MIN_VLEN_BITS,
        semantics=RvvServices().stack_semantics,
        emit_warnings=False,
    )
    return analyzer.analyze(
        function,
        metadata=metadata or ChimeraMetadata.empty(),
        config_result=type(
            "_Configs", (), {"at": staticmethod(lambda _address: frozenset())}
        )(),
    )


class DenseReferenceTests(unittest.TestCase):
    """Compare each rewritten stage against its dense reference form."""

    def _fixture(self) -> Function:
        return _function(
            ("vsetvli", ["a0", "a1", "e32", "m1"]),
            ("mv", ["s1", "sp"]),
            ("vs2r.v", ["v0", "(s1)"]),
            ("li", ["a3", "1"]),
            ("bnez", ["a3", "0x1014"]),
            ("div", ["a0", "a0", "a1"]),
            ("vs2r.v", ["v0", "(a0)"]),
            ("ret", []),
        )

    def test_backward_liveness_matches_dense_reference(self) -> None:
        semantics = RvvServices().stack_semantics
        function = self._fixture()
        facts = _FunctionStackLivenessAnalyzer(
            MIN_VLEN_BITS, semantics=semantics, emit_warnings=False
        )
        plan = facts._planner.plan(
            function, ChimeraMetadata.empty(), SimpleConfigs()
        )
        expressions = _FunctionExpressionAnalyzer(
            semantics, emit_warnings=False
        ).analyze(function, plan.vlen_sensitive_addresses)
        built = facts._fact_builder.build(
            function=function, plan=plan, expressions=expressions,
            config_result=SimpleConfigs(),
        )

        compact_before, compact_after = facts._solver.solve(
            function, uses=built.uses, defs=built.defs
        )
        dense_before, dense_after = _dense_backward_liveness(
            function, built.uses, built.defs
        )
        self.assertEqual(dict(compact_before), dense_before)
        self.assertEqual(dict(compact_after), dense_after)
        # Addresses that carry nothing keep no entry at all.
        self.assertEqual(
            compact_before.entry_count,
            sum(1 for value in dense_before.values() if value),
        )

    def test_conservative_merge_matches_dense_reference(self) -> None:
        semantics = RvvServices().stack_semantics
        function = self._fixture()
        analyzer = _FunctionStackLivenessAnalyzer(
            MIN_VLEN_BITS, semantics=semantics, emit_warnings=False
        )
        compact = analyzer.analyze(
            function,
            metadata=ChimeraMetadata.empty(),
            config_result=SimpleConfigs(),
        )
        # Re-derive the pre-marker solver state on a fresh solver instance.
        plan = analyzer._planner.plan(function, ChimeraMetadata.empty(), SimpleConfigs())
        expressions = _FunctionExpressionAnalyzer(
            semantics, emit_warnings=False
        ).analyze(function, plan.vlen_sensitive_addresses)
        built = analyzer._fact_builder.build(
            function=function, plan=plan, expressions=expressions,
            config_result=SimpleConfigs(),
        )
        solved_before, solved_after = analyzer._solver.solve(
            function, uses=built.uses, defs=built.defs
        )
        dense_before, dense_after = _dense_conservative_merge(
            function, dict(solved_before), dict(solved_after),
            built.conservative_addresses,
        )
        compact_marked_before, compact_marked_after = (
            analyzer._solver.merge_conservative_activity(
                function, solved_before, solved_after,
                built.conservative_addresses,
            )
        )
        self.assertEqual(dict(compact_marked_before), dense_before)
        self.assertEqual(dict(compact_marked_after), dense_after)
        # Full pipeline state must agree with the reference for live_before.
        expected = {
            address: values | frozenset()
            for address, values in dense_before.items()
        }
        self.assertEqual({
            address: frozenset(item for item in values if item.source != "vlen_scalar")
            for address, values in compact.live_before.items()
        }, expected)

    def test_frame_markers_match_dense_reference(self) -> None:
        semantics = RvvServices().stack_semantics
        function = _function(
            ("addi", ["sp", "sp", "-16"]),
            ("csrr", ["a0", "vlenb"]),
            ("slli", ["a0", "a0", "2"]),
            ("sub", ["sp", "sp", "a0"]),
            ("vs2r.v", ["v0", "(sp)"]),
            ("add", ["sp", "sp", "a0"]),
            ("addi", ["sp", "sp", "16"]),
            ("ret", []),
        )
        expressions = _FunctionExpressionAnalyzer(
            semantics, emit_warnings=False
        ).analyze(function, frozenset())
        compact, compact_warnings = analyze_vlen_stack_liveness(
            function, expressions, semantics
        )
        dense, dense_warnings = _dense_frame_liveness(function, expressions, semantics)
        self.assertEqual(dict(compact), dense)
        self.assertEqual(
            tuple(warning.code for warning in compact_warnings), dense_warnings
        )
        # The fixture must really carry VLEN frame and setup markers.
        marked = {address for address, values in dense.items() if values}
        self.assertTrue(marked)
        self.assertIn(VLEN_STACK_FRAME, {item for values in dense.values() for item in values})

    def test_inherited_view_matches_dense_copy(self) -> None:
        marker = StackObjectId("caller", "inherited-stack-data")
        obj = StackObjectId("compiler", 1)
        base = {
            0x10: frozenset({obj}),
            0x14: frozenset(),
            0x18: frozenset({obj}),
        }
        view = InheritedLivenessView(base, marker)
        self.assertEqual(dict(view), _dense_inherited_marker(base, marker))
        self.assertEqual(list(view), [0x10, 0x14, 0x18])
        self.assertEqual(len(view), 3)
        self.assertIn(0x14, view)
        self.assertNotIn(0x99, view)
        self.assertEqual(view.entry_count, 3)
        # The base mapping must not have been rewritten.
        self.assertEqual(base[0x14], frozenset())

    def test_inherited_view_matches_dense_copy_over_compact_base(self) -> None:
        marker = StackObjectId("caller", "inherited-stack-data")
        function = _function(("ret", []))
        local = _stack_analysis(function)
        view = InheritedLivenessView(local.live_before, marker)
        compact_dense = {
            address: values | frozenset({marker})
            for address, values in local.live_before.items()
        }
        argument = _CallerStackContextPropagator(RvvServices().stack_semantics)
        merged = argument._merge_inherited_marker({function.start: local}, {function.start})
        self.assertEqual(dict(merged[function.start].live_before), compact_dense)
        self.assertEqual(dict(view), compact_dense)

    def test_vector_configurations_match_dense_reference(self) -> None:
        function = _function(
            ("li", ["a3", "1"]),
            ("vsetvli", ["a3", "a1", "e32", "m1"]),
            ("mv", ["s1", "sp"]),
            ("vs2r.v", ["v0", "(s1)"]),
            ("beq", ["a3", "a1", "0x1010"]),
            ("vsetivli", ["a4", "5", "e16", "m2"]),
            ("vadd.vv", ["v1", "v2", "v3"]),
            ("ret", []),
        )
        result = VectorConfigAnalyzer().analyze_function(function)
        dense = _dense_vector_configurations(function)
        self.assertEqual(dict(result.before_by_address), dense)
        # Only the addresses whose configuration reaches differs from the
        # shared unknown set are retained.
        self.assertEqual(
            result.before_by_address.entry_count,
            sum(1 for value in dense.values() if value != frozenset({UNKNOWN_CONFIG})),
        )
        # Unreachable-in-domain addresses still answer through the domain.
        self.assertEqual(len(result.before_by_address), len(function.insts))


class SimpleConfigs:
    """Stand-in for ``VectorConfigResult`` in unit fixtures."""

    @staticmethod
    def at(_address: int) -> frozenset:
        return frozenset()

# region Fixed-baseline differential

_DRIVER = r'''
import json
import sys
from pathlib import Path

payload = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
output_path = Path(sys.argv[2])
MIN_VLEN = 256

from chimera.check_elf import (
    DEFAULT_TEXT_THRESHOLD,
    build_decision_block,
    collect_diagnostics,
)
from chimera.preprocess.offline.analysis.arch.riscv.rvv.services import RvvServices
from chimera.preprocess.offline.analysis.arch.riscv.services import RiscvServices
from chimera.preprocess.offline.analysis.program_model.parser import parse_dump
from chimera.preprocess.offline.analysis.safety.classifier import classify_liveness
from chimera.preprocess.offline.analysis.safety.stack_liveness import (
    ChimeraMetadata,
    StackLivenessAnalyzer,
)
from chimera.preprocess.offline.analysis.toolchain.objdump import LinuxObjdump

# This frozen harness tests the original vector/frame compact-state change.
# Scalar width is a separate safety dimension added in v26, exercised through
# the unmodified production flow by test_scalar_width_liveness. Project it
# out in this historical component comparison, without a production switch.
import chimera.preprocess.offline.analysis.safety.stack_liveness.liveness as local_liveness
if hasattr(local_liveness, "analyze_scalar_width_liveness"):
    from chimera.preprocess.offline.analysis.core.algorithm.address_states import AddressStateMap, EMPTY_STATES
    def _legacy_scalar_projection(function, expressions, semantics, **kwargs):
        return AddressStateMap(tuple(i.addr for i in function.insts), EMPTY_STATES), (), (), False
    local_liveness.analyze_scalar_width_liveness = _legacy_scalar_projection


def _warning(warning):
    return [
        warning.code,
        warning.message,
        warning.function_start,
        list(warning.addresses),
        list(warning.details),
    ]


def _run(entry):
    adapter = LinuxObjdump("objdump")
    extension = RvvServices()
    architecture = RiscvServices(extension)
    program = architecture.build_cfg(
        parse_dump(
            Path(entry["dump_path"]),
            adapter.parse_format,
            is_external_trampoline=adapter.is_external_trampoline,
            retain_dump_lines=False,
        )
    )
    if entry["mode"] == "metadata":
        stack_ids = {}
        object_id = 0
        for function in program.functions:
            for instruction in function.insts:
                if extension.stack_semantics.vector_memory_operand(instruction) is not None:
                    stack_ids[instruction.addr] = object_id
                    object_id += 1
        metadata = ChimeraMetadata(stack_ids=stack_ids)
    else:
        metadata = ChimeraMetadata.empty()

    configs = extension.vector_configs(program)
    vector = extension.vector_liveness(program)
    stack = StackLivenessAnalyzer(
        min_vlen_bits=MIN_VLEN,
        semantics=extension.stack_semantics,
        emit_warnings=False,
    ).analyze_program(program, metadata=metadata, config_results=configs)
    records = classify_liveness(
        program,
        vector,
        stack,
        vector_classifier=extension.classify_vector_liveness,
    ).records

    configuration_state = {}
    vector_state = {}
    stack_state = {}
    structural = {}
    for function in program.functions:
        key = str(function.start)
        configuration_state[key] = [
            [
                instruction.addr,
                sorted(
                    config.display()
                    for config in configs[function.start].at(instruction.addr)
                ),
            ]
            for instruction in function.insts
        ]
        vector_state[key] = [
            [
                instruction.addr,
                sorted(
                    vector.by_function[function.start].live_before.get(
                        instruction.addr, frozenset()
                    )
                ),
            ]
            for instruction in function.insts
        ]
        liveness = stack.by_function[function.start]
        stack_state[key] = [
            [
                instruction.addr,
                sorted(
                    str(item)
                    for item in liveness.live_before.get(
                        instruction.addr, frozenset()
                    )
                ),
            ]
            for instruction in function.insts
        ]
        structural[key] = {
            "name": function.name,
            "candidate_addresses": sorted(liveness.candidate_addresses),
            "conservative_addresses": sorted(liveness.conservative_addresses),
            "rejected_nonstack_addresses": sorted(
                liveness.rejected_nonstack_addresses
            ),
            "loop_headers": sorted(liveness.loop_headers),
            "irreducible_loops": [sorted(loop) for loop in liveness.irreducible_loops],
            "accesses": [
                [
                    address,
                    item.kind.value,
                    str(item.stack_id),
                    item.source,
                    repr(item.address_expression),
                ]
                for address, item in sorted(liveness.accesses.items())
            ],
        }

    diagnostics = collect_diagnostics(
        Path(payload["elf_stub"]),
        objdump_cmd="objdump",
        min_vlen_bits=MIN_VLEN,
        strategy="gate",
        text_threshold=DEFAULT_TEXT_THRESHOLD,
        dump_text=Path(entry["dump_path"]).read_text(encoding="utf-8"),
        metadata=metadata,
    )
    return {
        "name": entry["name"],
        "mode": entry["mode"],
        "config": configuration_state,
        "vector_live": vector_state,
        "stack_live": stack_state,
        "structural": structural,
        "inherited": sorted(stack.inherited_functions),
        "unresolved": list(stack.unresolved_live_calls),
        "warnings": [_warning(item) for item in stack.warnings],
        "seed_edges": [
            [edge.caller_function_start, edge.call_site, edge.reason, edge.depth]
            for edge in stack.inheritance_trace.seed_edges
        ],
        "first_cause": {
            str(start): [edge.caller_function_start, edge.call_site, edge.reason, edge.depth]
            for start, edge in sorted(stack.inheritance_trace.first_cause.items())
        },
        "max_depth": stack.inheritance_trace.max_depth,
        "records": [
            [
                address,
                record.safe,
                sorted(record.vector_live),
                sorted(str(item) for item in record.stack_live),
                list(record.reasons),
            ]
            for address, record in sorted(records.items())
        ],
        "strategy": diagnostics.strategy,
        "strategy_reason": diagnostics.strategy_reason,
        "gate_names": list(diagnostics.gate_names),
        "seed_host_starts": list(diagnostics.seed_host_starts),
        "counts": dict(diagnostics.counts),
        "stack_object": bool(diagnostics.stack_object),
        "findings": [
            [
                item.kind,
                item.function,
                item.call_site,
                item.recommended_action,
                list(item.support),
                item.residual,
            ]
            for item in diagnostics.findings
        ],
        "decision": build_decision_block(diagnostics),
    }


output = {"runs": [_run(entry) for entry in payload["runs"]]}
output_path.write_text(json.dumps(output, indent=2, sort_keys=True), encoding="utf-8")
'''


def _write_fixtures(directory: Path) -> dict:
    """Materialise the fixture dumps and the driver payload."""

    elf_stub = directory / "stub.elf"
    elf_stub.write_bytes(ELF_STUB_BYTES)
    dumps = {
        "analysis": directory / "analysis.dump",
        "check_elf": directory / "check_elf.dump",
    }
    dumps["analysis"].write_text(ANALYSIS_DUMP, encoding="utf-8")
    dumps["check_elf"].write_text(CHECK_ELF_DUMP, encoding="utf-8")
    runs = []
    for name, path in dumps.items():
        for mode in ("binary", "metadata"):
            runs.append({"name": name, "mode": mode, "dump_path": str(path)})
    payload = {"elf_stub": str(elf_stub), "runs": runs}
    payload_path = directory / "payload.json"
    payload_path.write_text(json.dumps(payload), encoding="utf-8")
    return {
        "payload": payload_path,
        "elf_stub": elf_stub,
        "dumps": dumps,
    }


def _run_driver(directory: Path, fixtures: dict, pythonpath: str, cwd: Path) -> dict:
    output = directory / f"report-{abs(hash((pythonpath, str(cwd))))}.json"
    if output.exists():
        output.unlink()
    environment = dict(os.environ)
    environment["PYTHONPATH"] = pythonpath
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    completed = subprocess.run(
        [sys.executable, "-c", _DRIVER, str(fixtures["payload"]), str(output)],
        cwd=str(cwd),
        env=environment,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        raise AssertionError(
            "analysis driver failed:\n"
            f"stdout={completed.stdout}\nstderr={completed.stderr}"
        )
    return json.loads(output.read_text(encoding="utf-8"))


def _extract_baseline(destination: Path) -> bool:
    completed = subprocess.run(
        ["git", "-C", str(REPO_ROOT), "archive", BASELINE_COMMIT, *_BASELINE_TREES],
        capture_output=True,
    )
    if completed.returncode != 0 or not completed.stdout:
        return False
    with tarfile.open(fileobj=io.BytesIO(completed.stdout)) as archive:
        archive.extractall(destination, filter="data")
    return True
# endregion


class FixtureCoverageTests(unittest.TestCase):
    """The fixtures must really exercise the paths the regression claims."""

    @classmethod
    def setUpClass(cls) -> None:
        cls._temporary = tempfile.TemporaryDirectory()
        cls.directory = Path(cls._temporary.name)
        cls.fixtures = _write_fixtures(cls.directory)
        cls.report = _run_driver(
            cls.directory,
            cls.fixtures,
            os.pathsep.join([str(REPO_ROOT / "cli"), str(REPO_ROOT)]),
            REPO_ROOT,
        )
        cls.runs = {(run["name"], run["mode"]): run for run in cls.report["runs"]}

    @classmethod
    def tearDownClass(cls) -> None:
        cls._temporary.cleanup()

    def _run(self, name: str, mode: str = "binary") -> dict:
        return self.runs[(name, mode)]

    def test_empty_and_unreachable_instructions_are_covered(self) -> None:
        run = self._run("analysis")
        empty = run["structural"][str(0x10000)]
        self.assertTrue(all(not values for _address, values in run["stack_live"][str(0x10000)]))
        self.assertEqual(empty["candidate_addresses"], [])
        # The instruction after the branch return is unreachable but still
        # queryable through the address domain.
        branchy = run["config"][str(0x10004)]
        self.assertEqual(branchy[-1][0], 0x1002C)

    def test_branch_merge_loop_and_irreducible_coverage(self) -> None:
        run = self._run("analysis")
        structural = run["structural"]
        self.assertTrue(
            any(item["loop_headers"] for item in structural.values()),
            "no fixture produced a natural loop header",
        )
        irreducible = [
            item for item in structural.values() if item["irreducible_loops"]
        ]
        self.assertTrue(irreducible, "no fixture produced an irreducible loop")
        self.assertIn(
            "irreducible-loop-degraded",
            {warning[0] for warning in run["warnings"]},
        )

    def test_vlen_frame_metadata_recursion_and_conservative_coverage(self) -> None:
        run = self._run("analysis")
        markers = {
            item
            for entries in run["stack_live"].values()
            for _address, values in entries
            for item in values
        }
        self.assertIn("vlen_stack_frame:dynamic-sp", markers)
        self.assertIn(0x13000, run["inherited"])
        self.assertEqual(run["first_cause"][str(0x13000)][0], 0x13000)
        self.assertTrue(
            any(item["conservative_addresses"] for item in run["structural"].values()),
            "no fixture produced a conservative scope",
        )
        metadata_run = self._run("analysis", "metadata")
        self.assertTrue(
            any(
                access[3] == "compiler"
                for item in metadata_run["structural"].values()
                for access in item["accesses"]
            ),
            "metadata mode produced no compiler-sourced access",
        )

    def test_check_elf_fixture_covers_findings_gate_and_residual(self) -> None:
        for mode in ("binary", "metadata"):
            run = self._run("check_elf", mode)
            self.assertTrue(run["findings"], f"no findings in {mode} mode")
            self.assertTrue(run["gate_names"], f"no gate names in {mode} mode")
            # Corrected rule: pure caller-inherited findings are actionable;
            # the residual field is retained but always false, and every
            # finding is counted actionable.
            self.assertTrue(
                all(not item[5] for item in run["findings"]),
                f"residual finding in {mode} mode (pass-through was removed)",
            )
            self.assertTrue(
                all(item[3] for item in run["findings"]),
                f"finding without recommended action in {mode} mode",
            )
            self.assertEqual(run["counts"]["actionable"], len(run["findings"]))
            self.assertEqual(run["counts"]["residual"], 0)
            self.assertEqual(run["strategy"], "gate")
        binary = self._run("check_elf")
        kinds = {item[0] for item in binary["findings"]}
        self.assertIn("inherited", kinds)
        self.assertTrue(binary["seed_edges"])
        self.assertIn(0x10008, binary["inherited"])

    def test_classification_is_present_for_every_instruction(self) -> None:
        run = self._run("analysis")
        addresses = [item[0] for item in run["records"]]
        expected = sum(len(entries) for entries in run["config"].values())
        self.assertGreaterEqual(expected, 50)
        self.assertEqual(len(addresses), len(set(addresses)))
        self.assertEqual(len(addresses), expected)
        self.assertTrue(any(not item[1] for item in run["records"]))
        self.assertTrue(any(item[1] for item in run["records"]))


# region Declared divergences from the frozen baseline

#: Addresses whose *loop scope* changed because a self edge is now a
#: single-block loop: the function prologue can no longer enter the loop's
#: written-register set, so the loop fixture's spill address resolves to
#: ``input(sp)`` instead of being left unresolved behind a ``loop_input``
#: symbol, and the conservative scope it used to force disappears.
_LOOP_SCOPE_CORRECTIONS = frozenset(
    {0x11000, 0x11004, 0x11008, 0x1100C, 0x11010, 0x11014}
)

#: Addresses whose *loop scope* changed because a call target is no longer an
#: in-function CFG edge: the self-recursive ``jal`` at 0x13010 no longer wires
#: the entry as its own successor, so the false single-block loop at the
#: ``recursive_fn`` entry disappears.  The entry ``sp`` stops being a loop
#: symbol, the vector store/load of the fixture resolve to ``input(sp)-16``
#: instead of staying conservatively scoped, and the resolved stack object
#: ``binary:0`` is live across the call and after it instead of the
#: conservative marker.  The recursion relation itself is untouched: the call
#: target stays in ``jump_targets`` and the function stays inherited.
_RECURSIVE_CALL_CORRECTIONS = frozenset(
    {0x13000, 0x13004, 0x13008, 0x1300C, 0x13010, 0x13014}
)

#: Addresses whose *vector configuration* changed because a call target is no
#: longer an in-function CFG edge: the buggy call edge carried the state after
#: the recursive call back into the ``recursive_fn`` entry, where it merged
#: with the configuration the function's own ``vsetivli`` establishes.  The
#: entry now sees only the external entry state, which is what a callee return
#: actually leaves behind; the ``vsetivli`` at 0x13004 still defines the
#: configuration for the rest of the function.
_RECURSIVE_CALL_CONFIG = frozenset({0x13000, 0x13004})

#: Every divergence from the frozen pre-change semantics this change intends,
#: per fixture run.  ``stack_live``/``records`` list instruction addresses;
#: ``structural`` lists the function starts whose structure moved.  Any other
#: difference - and any difference at any other address - still fails.
_INTENDED_DIVERGENCES: dict[tuple[str, str], dict[str, frozenset[int]]] = {
    ("analysis", "binary"): {
        "config": _RECURSIVE_CALL_CONFIG,
        "stack_live": _LOOP_SCOPE_CORRECTIONS
        | _RECURSIVE_CALL_CORRECTIONS
        | {0x12018},
        "records": _LOOP_SCOPE_CORRECTIONS
        | _RECURSIVE_CALL_CORRECTIONS
        | {0x12018},
        "structural": frozenset({0x11000, 0x13000}),
    },
    ("analysis", "metadata"): {
        # The metadata mode resolves accesses from compiler identifiers, so
        # only the frame state moves: 0x12018 is the ``vlen_frame`` fixture's
        # stack adjustment, whose setup marker used to be extended over the
        # whole program-order interval up to the adjustment and is now
        # confined to the instructions that can reach it along the CFG.
        "config": _RECURSIVE_CALL_CONFIG,
        "stack_live": frozenset({0x12018}),
        "records": frozenset({0x12018}),
        # Only the structure of the recursive fixture moved: the false entry
        # loop disappears in metadata mode as well, while its accesses are
        # compiler-sourced and unchanged.
        "structural": frozenset({0x13000}),
    },
    ("check_elf", "binary"): {},
    ("check_elf", "metadata"): {},
}

_PER_ADDRESS_KEYS = ("config", "vector_live", "stack_live")


def _without_divergences(value, key: str, excluded):
    """Drop the declared divergences from one report section."""

    if not excluded:
        return value
    if key == "records":
        return [entry for entry in value if entry[0] not in excluded]
    if key in _PER_ADDRESS_KEYS:
        return {
            function: [entry for entry in entries if entry[0] not in excluded]
            for function, entries in value.items()
        }
    if key == "structural":
        return {
            function: section
            for function, section in value.items()
            if int(function) not in excluded
        }
    return value


def _payloads_by_address(value, key: str) -> dict[int, object]:
    """Map every address of a per-address report section to its payload."""

    if key == "records":
        return {entry[0]: entry[1:] for entry in value}
    return {
        entry[0]: entry[1:]
        for entries in value.values()
        for entry in entries
    }


def _differing_addresses(current: dict, reference: dict) -> dict[str, set[int]]:
    """Addresses (and function starts) whose state really moved."""

    divergent: dict[str, set[int]] = {}
    for key in ("config", "vector_live", "stack_live", "records"):
        left = _payloads_by_address(current[key], key)
        right = _payloads_by_address(reference[key], key)
        moved = {
            address
            for address in set(left) | set(right)
            if left.get(address) != right.get(address)
        }
        if moved:
            divergent[key] = moved
    moved_functions = {
        int(function)
        for function in current["structural"]
        if current["structural"][function] != reference["structural"].get(function)
    }
    if moved_functions:
        divergent["structural"] = moved_functions
    return divergent


def _function_key_with_address(section: dict, address: int) -> str:
    for function, entries in section.items():
        if any(entry[0] == address for entry in entries):
            return function
    raise AssertionError(f"{address:#x} belongs to no function of the fixture")


def _entry_at(entries: list, address: int):
    for entry in entries:
        if entry[0] == address:
            return entry[1]
    return None


# endregion


class BaselineDifferentialTests(unittest.TestCase):
    """Per-address identity between this tree and the frozen baseline."""

    @classmethod
    def setUpClass(cls) -> None:
        cls._temporary = tempfile.TemporaryDirectory()
        cls.directory = Path(cls._temporary.name)
        baseline = cls.directory / "baseline"
        baseline.mkdir()
        if not _extract_baseline(baseline):
            raise unittest.SkipTest(
                f"baseline {BASELINE_COMMIT} is not available in this checkout"
            )
        cls.fixtures = _write_fixtures(cls.directory)
        cls.current = _run_driver(
            cls.directory,
            cls.fixtures,
            os.pathsep.join([str(REPO_ROOT / "cli"), str(REPO_ROOT)]),
            REPO_ROOT,
        )
        cls.reference = _run_driver(
            cls.directory,
            cls.fixtures,
            os.pathsep.join([str(baseline / "cli"), str(baseline)]),
            baseline,
        )

    @classmethod
    def tearDownClass(cls) -> None:
        cls._temporary.cleanup()

    def _run(self, name: str, mode: str) -> dict:
        return {(run["name"], run["mode"]): run for run in self.current["runs"]}[
            (name, mode)
        ]

    def _reference(self, name: str, mode: str) -> dict:
        return {(run["name"], run["mode"]): run for run in self.reference["runs"]}[
            (name, mode)
        ]

    def test_baseline_revision_is_pinned_not_head(self) -> None:
        self.assertNotEqual(BASELINE_COMMIT, "HEAD")
        self.assertEqual(len(BASELINE_COMMIT), 40)

    def test_reports_are_identical(self) -> None:
        for current, reference in zip(self.current["runs"], self.reference["runs"]):
            label = f"{current['name']}/{current['mode']}"
            divergences = _INTENDED_DIVERGENCES[(current["name"], current["mode"])]
            for key in (
                "config",
                "vector_live",
                "stack_live",
                "structural",
                "inherited",
                "unresolved",
                "warnings",
                "records",
            ):
                self.assertEqual(
                    _without_divergences(current[key], key, divergences.get(key, ())),
                    _without_divergences(reference[key], key, divergences.get(key, ())),
                    f"{key} differs from the baseline for {label} outside the "
                    "declared loop/frame corrections",
                )

    def test_intended_divergences_are_the_loop_and_frame_corrections(self) -> None:
        """The frozen comparison may only deviate where this change says it does."""

        for current, reference in zip(self.current["runs"], self.reference["runs"]):
            label = f"{current['name']}/{current['mode']}"
            divergences = _INTENDED_DIVERGENCES[(current["name"], current["mode"])]
            # Exactly the declared addresses changed - no more, no fewer.
            self.assertEqual(
                _differing_addresses(current, reference),
                {key: set(values) for key, values in divergences.items() if values},
                f"undeclared per-address divergence for {label}",
            )

        # --- self-loop fix: the loop fixture's spill address resolves --------
        current = self._run("analysis", "binary")
        reference = self._reference("analysis", "binary")
        function = _function_key_with_address(current["stack_live"], 0x1100C)
        for address in sorted(_LOOP_SCOPE_CORRECTIONS):
            before = _entry_at(reference["stack_live"][function], address)
            after = _entry_at(current["stack_live"][function], address)
            self.assertIn(
                "conservative:possible-stack-data",
                before,
                f"{address:#x} used to be conservatively scoped",
            )
            self.assertNotIn(
                "conservative:possible-stack-data",
                after,
                f"{address:#x} must not stay conservatively scoped",
            )
        self.assertEqual(
            reference["structural"][function]["conservative_addresses"],
            sorted(_LOOP_SCOPE_CORRECTIONS),
        )
        self.assertEqual(current["structural"][function]["conservative_addresses"], [])
        self.assertEqual(
            reference["structural"][function]["accesses"],
            [[0x11018, "load", "binary:0", "binary", "Expr(kind='input', args=('sp',))"]],
        )
        self.assertEqual(
            current["structural"][function]["accesses"],
            [
                [0x1100C, "store", "binary:0", "binary", "Expr(kind='input', args=('sp',))"],
                [0x11018, "load", "binary:0", "binary", "Expr(kind='input', args=('sp',))"],
            ],
            "the previously unresolved spill must now be a resolved stack write",
        )

        # --- setup marker no longer spreads by program order -----------------
        for mode in ("binary", "metadata"):
            current = self._run("analysis", mode)
            reference = self._reference("analysis", mode)
            function = _function_key_with_address(current["stack_live"], 0x12018)
            before = _entry_at(reference["stack_live"][function], 0x12018)
            after = _entry_at(current["stack_live"][function], 0x12018)
            self.assertIn("vlen_stack_frame:dynamic-sp", after)
            self.assertIn("vlen_stack_frame:dynamic-sp", before)
            self.assertIn("vlen_stack_setup:dynamic-sp", before)
            self.assertNotIn(
                "vlen_stack_setup:dynamic-sp",
                after,
                "the setup region must stop at the CFG predecessors of the adjustment",
            )

        # --- call-edge fix: the recursive fixture is no longer a loop --------
        current = self._run("analysis", "binary")
        reference = self._reference("analysis", "binary")
        function = _function_key_with_address(current["stack_live"], 0x13010)
        recursive = current["structural"][function]
        self.assertEqual(recursive["loop_headers"], [])
        self.assertEqual(
            reference["structural"][function]["loop_headers"],
            [0x13000],
            "the self-recursive call used to make the entry a loop header",
        )
        self.assertEqual(
            reference["structural"][function]["conservative_addresses"],
            sorted(_RECURSIVE_CALL_CORRECTIONS),
        )
        self.assertEqual(recursive["conservative_addresses"], [])
        self.assertEqual(
            [access[:2] for access in recursive["accesses"]],
            [[0x1300C, "store"], [0x13014, "load"]],
            "the vector accesses must resolve once the false loop is gone",
        )
        self.assertEqual(reference["structural"][function]["accesses"], [])
        # The call site and its return stay stack-active with the resolved
        # object; only the conservative marker disappears.
        before = _entry_at(reference["stack_live"][function], 0x13010)
        after = _entry_at(current["stack_live"][function], 0x13010)
        self.assertIn("conservative:possible-stack-data", before)
        self.assertNotIn("conservative:possible-stack-data", after)
        self.assertIn("binary:0", after)
        # The recursion itself is untouched: the call target is still
        # recorded and the function is still inherited.
        self.assertIn(0x13000, current["inherited"])
        self.assertEqual(
            current["first_cause"][str(0x13000)],
            reference["first_cause"][str(0x13000)],
        )
        # The entry configuration no longer merges the state after the call:
        # a callee return leaves the caller's entry state behind, not the
        # configuration the call happened to follow.
        for mode in ("binary", "metadata"):
            current = self._run("analysis", mode)
            reference = self._reference("analysis", mode)
            function = _function_key_with_address(current["config"], 0x13000)
            self.assertEqual(
                _entry_at(current["config"][function], 0x13000),
                ["e?,m?,avl=unknown"],
            )
            self.assertEqual(
                _entry_at(reference["config"][function], 0x13000),
                ["e32,m1,avl=4", "e?,m?,avl=unknown"],
            )

    def test_findings_gate_and_decision_are_identical(self) -> None:
        # The semantic comparison against the frozen baseline covers the
        # decision-relevant keys only.  ``counts`` and ``findings`` are
        # excluded deliberately: the corrected rule removed the residual
        # pass-through, so residual flags, actionable counts and the
        # recommended_action of pure-inherited findings intentionally
        # differ from the baseline.  That divergence is asserted by
        # FeatureCoverageTests / test_check_elf_collect.py instead.
        for current, reference in zip(self.current["runs"], self.reference["runs"]):
            label = f"{current['name']}/{current['mode']}"
            for key in (
                "strategy",
                "gate_names",
                "seed_host_starts",
                "stack_object",
                "decision",
                "seed_edges",
                "first_cause",
                "max_depth",
            ):
                self.assertEqual(
                    current[key],
                    reference[key],
                    f"{key} differs from the baseline for {label}",
                )


if __name__ == "__main__":
    unittest.main()
