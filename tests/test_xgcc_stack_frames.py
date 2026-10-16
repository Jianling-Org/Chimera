"""VLEN stack-frame behaviour on the real gate-2 ``xgcc`` disassembly.

The fixture in :mod:`xgcc_stack_fixture` is the machine code of the five
functions the gate-2 check reported, so these tests pin the two corrections
against evidence rather than against a hand-written approximation:

* a self edge is a single-block loop, so a function prologue can no longer be
  reported as loop-written and ``sp`` can no longer turn into a ``loop_input``;
* a VLEN stack frame is decided from the proven VLEN dependency of the stack
  adjustment and propagated along the CFG, so the independent error branch at
  ``0x21e34`` no longer inherits the frame state of a branch that cannot reach
  the adjustment.

The four fixed-frame functions must carry *no* frame state at all even though
they read ``vlenb`` and run vector loops; the ``close_at_file`` frame must
survive as an unproven allocation (its size comes from a memory load), and the
state must still cross a call into the callee.
"""

from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

import xgcc_stack_fixture as fixture

from chimera.preprocess.offline.analysis.arch.riscv.rvv.config import VSET_OPS
from chimera.preprocess.offline.analysis.arch.riscv.rvv.services import (
    RiscvStackSemantics,
    RvvServices,
)
from chimera.preprocess.offline.analysis.core.contracts import StackSemantics
from chimera.preprocess.offline.analysis.safety.stack_liveness.dependencies import (
    DEPENDENCY_INDEPENDENT,
    DEPENDENCY_UNKNOWN,
    DEPENDENCY_VLEN,
    analyze_register_dependencies,
)
from chimera.preprocess.offline.analysis.safety.stack_liveness.expressions import (
    walk_loop_inputs,
)
from chimera.preprocess.offline.analysis.safety.stack_liveness.frame_liveness import (
    VLEN_STACK_FRAME,
    VLEN_STACK_SETUP,
    analyze_vlen_stack_liveness,
)
from chimera.preprocess.offline.analysis.safety.stack_liveness.model import (
    ChimeraMetadata,
)
from chimera.preprocess.offline.analysis.safety.stack_liveness.solver import (
    _FunctionExpressionAnalyzer,
)

SEMANTICS: StackSemantics = RiscvStackSemantics()

#: The straight-line epilogue that follows the proven frame restore, taken from
#: the dump: ``addi sp,s0,-96`` .. ``ret``.
EPILOGUE_AFTER_RESTORE = (
    0x21DD8, 0x21DDA, 0x21DDC, 0x21DDE, 0x21DE0,
    0x21DE2, 0x21DE4, 0x21DE6, 0x21DE8, 0x21DEA,
)

#: The two natural loops of ``close_at_file``: one scalar copy loop and one
#: vectorised copy loop, both written as a single self-edge block.
EXPECTED_LOOPS = {0x21D7A: 5, 0x21E0E: 5}


def _expressions(function):
    return _FunctionExpressionAnalyzer(SEMANTICS, emit_warnings=False).analyze(
        function, frozenset()
    )


def _frame_markers(function):
    expressions = _expressions(function)
    live_before, warnings = analyze_vlen_stack_liveness(
        function, expressions, SEMANTICS
    )
    return expressions, live_before, warnings


def _addresses_with(function, live_before, marker):
    return [
        instruction.addr
        for instruction in function.insts
        if marker in live_before.get(instruction.addr, frozenset())
    ]


def dependencies_level(function, address: int, register: str = "sp") -> int:
    """Dependency level the register-level dataflow reports for one address."""

    return analyze_register_dependencies(function, SEMANTICS).level_after(
        address, register
    )


class FixtureIntegrityTests(unittest.TestCase):
    """The fixture must really be the reported disassembly."""

    def test_functions_and_boundaries_are_preserved(self) -> None:
        program = fixture.load_program()
        self.assertEqual(
            [function.name for function in program.functions][:5],
            list(fixture.ALL_FUNCTIONS),
        )
        sizes = {function.name: len(function.insts) for function in program.functions}
        # Instruction counts of the vetted dumps: the fixture keeps the machine
        # code, the addresses and the function boundaries verbatim.
        self.assertEqual(sizes[fixture.CLOSE_AT_FILE], 173)
        self.assertEqual(sizes[fixture.FIXED_FRAME_FUNCTIONS[0]], 135)
        self.assertEqual(sizes[fixture.FIXED_FRAME_FUNCTIONS[1]], 294)
        self.assertEqual(sizes[fixture.FIXED_FRAME_FUNCTIONS[2]], 1114)
        self.assertEqual(sizes[fixture.FIXED_FRAME_FUNCTIONS[3]], 158)

    def test_fixture_carries_no_build_paths(self) -> None:
        self.assertNotIn("/root/", fixture.STACK_FUNCTIONS_DUMP)
        self.assertNotIn("/root/", fixture.STUB_CALLEE_DUMP)

    def test_reported_call_sites_keep_their_addresses(self) -> None:
        close_at_file = fixture.function(fixture.load_program(), fixture.CLOSE_AT_FILE)
        addresses = {instruction.addr for instruction in close_at_file.insts}
        for address in (
            fixture.DYNAMIC_ADJUSTMENT,
            fixture.FRAME_RESTORE,
            fixture.INDEPENDENT_ERROR_CALL,
        ) + fixture.ADJUSTED_ERROR_CALLS:
            self.assertIn(address, addresses)


class SelfLoopScopeTests(unittest.TestCase):
    """The prologue must not enter the loop's written-register set."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.function = fixture.function(
            fixture.load_program(), fixture.CLOSE_AT_FILE
        )
        cls.expressions = _expressions(cls.function)

    def test_vectorised_loops_are_single_blocks_without_sp(self) -> None:
        loops = {
            loop.header: loop for loop in self.expressions.loop_info.natural_loops
        }
        self.assertEqual(
            {header: len(loop.addresses) for header, loop in loops.items()},
            EXPECTED_LOOPS,
        )
        for loop in loops.values():
            self.assertNotIn(
                "sp",
                loop.written_registers,
                "a self edge must not report the function prologue as loop-written",
            )
            self.assertGreater(
                min(loop.addresses),
                fixture.DYNAMIC_ADJUSTMENT,
                "the copy loops run inside the dynamically allocated region",
            )

    def test_sp_stays_a_function_value_at_every_loop_header(self) -> None:
        for header in EXPECTED_LOOPS:
            with self.subTest(header=hex(header)):
                state = self.expressions.before_states[header]["sp"]
                self.assertEqual(
                    walk_loop_inputs(state),
                    frozenset(),
                    "sp must not be summarised as a loop-carried symbol",
                )


class FixedFrameFunctionTests(unittest.TestCase):
    """Fixed frames plus vector loops must not produce frame state."""

    def test_fixed_frame_functions_have_no_vlen_frame_state(self) -> None:
        program = fixture.load_program()
        for name in fixture.FIXED_FRAME_FUNCTIONS:
            function = fixture.function(program, name)
            with self.subTest(function=name):
                _, live_before, warnings = _frame_markers(function)
                self.assertEqual(
                    _addresses_with(function, live_before, VLEN_STACK_FRAME),
                    [],
                    f"{name} has a fixed stack frame",
                )
                self.assertEqual(
                    _addresses_with(function, live_before, VLEN_STACK_SETUP), []
                )
                self.assertEqual([warning.code for warning in warnings], [])

    def test_fixed_frame_functions_do_still_contain_vector_work(self) -> None:
        # The point of the test above: those functions really do read vlenb and
        # run vector loops, so "no frame state" is a statement about the frame,
        # not about the code being empty.
        program = fixture.load_program()
        for name in fixture.FIXED_FRAME_FUNCTIONS:
            function = fixture.function(program, name)
            with self.subTest(function=name):
                self.assertTrue(
                    any(
                        instruction.op == "csrr"
                        and any(
                            str(argument).lower() == "vlenb"
                            for argument in instruction.args[1:]
                        )
                        for instruction in function.insts
                    ),
                    f"{name} reads vlenb",
                )
                self.assertTrue(
                    any(
                        instruction.op.startswith("v")
                        and instruction.op not in VSET_OPS
                        for instruction in function.insts
                    ),
                    f"{name} runs vector instructions",
                )


class DynamicFrameBranchTests(unittest.TestCase):
    """The dynamic frame must stay inside the region that can reach it."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.function = fixture.function(
            fixture.load_program(), fixture.CLOSE_AT_FILE
        )
        cls.expressions, cls.live_before, cls.warnings = _frame_markers(cls.function)

    def test_independent_error_branch_does_not_inherit_the_frame(self) -> None:
        # 0x21e24..0x21e34 is reached from 0x21c7e, before the adjustment.
        for address in (0x21E24, 0x21E2C, 0x21E30, fixture.INDEPENDENT_ERROR_CALL):
            with self.subTest(address=hex(address)):
                self.assertFalse(self.live_before.get(address))

    def test_adjusted_branches_and_seed_sites_keep_the_frame(self) -> None:
        for address in fixture.ADJUSTED_ERROR_CALLS + fixture.SEED_CALL_SITES:
            with self.subTest(address=hex(address)):
                self.assertIn(
                    VLEN_STACK_FRAME, self.live_before.get(address, frozenset())
                )
        self.assertIn(
            VLEN_STACK_FRAME,
            self.live_before.get(fixture.DYNAMIC_ADJUSTMENT, frozenset()),
        )

    def test_frame_is_released_only_after_the_proven_restore(self) -> None:
        # The restoring instruction itself stays unsafe; the straight-line
        # epilogue after it becomes safe again.
        self.assertIn(VLEN_STACK_FRAME, self.live_before[fixture.FRAME_RESTORE])
        for address in EPILOGUE_AFTER_RESTORE:
            with self.subTest(address=hex(address)):
                self.assertNotIn(
                    VLEN_STACK_FRAME,
                    self.live_before.get(address, frozenset()),
                    f"{address:#x} is after the proven restore",
                )

    def test_setup_region_is_the_cfg_predecessor_chain(self) -> None:
        setup = _addresses_with(self.function, self.live_before, VLEN_STACK_SETUP)
        # The region starts at the load that seeds the size computation and
        # stops before the adjustment; it must not cover the function prologue
        # nor the independent branch.
        self.assertEqual(min(setup), 0x21C82)
        self.assertLess(max(setup), fixture.DYNAMIC_ADJUSTMENT)
        self.assertNotIn(0x21C5E, setup)
        self.assertNotIn(fixture.INDEPENDENT_ERROR_CALL, setup)

    def test_unproven_size_is_reported_not_silently_accepted(self) -> None:
        self.assertEqual(
            [warning.code for warning in self.warnings],
            ["unknown-vlen-stack-adjustment"],
        )
        self.assertEqual(self.warnings[0].addresses, (fixture.DYNAMIC_ADJUSTMENT,))


class ConservativeBehaviourTests(unittest.TestCase):
    """Irreducible and recursive code must stay conservative."""

    def test_irreducible_loop_of_the_layout_constructor_is_preserved(self) -> None:
        from chimera.preprocess.offline.analysis.safety.stack_liveness.analyzer import (
            StackLivenessAnalyzer,
        )

        program = fixture.load_program()
        extension = RvvServices()
        layout = fixture.function(program, fixture.FIXED_FRAME_FUNCTIONS[2])
        result = StackLivenessAnalyzer(
            min_vlen_bits=256,
            semantics=extension.stack_semantics,
            emit_warnings=False,
        ).analyze_program(
            program,
            metadata=ChimeraMetadata.empty(),
            config_results=extension.vector_configs(program),
        )

        local = result.by_function[layout.start]
        self.assertTrue(local.irreducible_loops)
        self.assertIn(
            "irreducible-loop-degraded",
            {warning.code for warning in local.warnings},
        )
        # The vector accesses inside the irreducible loop stay conservatively
        # scoped - that is a real vector stack access, not a frame artefact.
        self.assertTrue(local.conservative_addresses)
        self.assertEqual(
            _addresses_with(layout, local.live_before, VLEN_STACK_FRAME), []
        )

    def test_recursive_frame_with_a_clobbered_restore_stays_marked(self) -> None:
        from chimera.preprocess.offline.analysis.core.data_model import (
            Function,
            Instruction,
        )

        specs = [
            ("csrr", ["a0", "vlenb"]),
            ("sub", ["sp", "sp", "a0"]),
            ("jal", ["ra", "0x1000"]),
            ("add", ["sp", "sp", "a0"]),
            ("ret", []),
        ]
        instructions = [
            Instruction(0x1000 + index * 4, 4, op, args, f"{op} " + ",".join(args))
            for index, (op, args) in enumerate(specs)
        ]
        for current, following in zip(instructions, instructions[1:]):
            current.succ.add(following.addr)
        # The recursive call re-enters the function entry.
        instructions[2].succ.add(0x1000)
        function = Function("recursive_frame", 0x1000, instructions)

        _, live_before, warnings = _frame_markers(function)

        # ``a0`` is caller-saved, so the ``add sp,sp,a0`` after the call cannot
        # prove the restore: the frame state must survive to the return.
        self.assertIn(VLEN_STACK_FRAME, live_before[0x100C])
        self.assertIn(VLEN_STACK_FRAME, live_before[0x1010])
        self.assertIn(
            "unknown-vlen-stack-adjustment",
            {warning.code for warning in warnings},
        )


class DependencyPropagationTests(unittest.TestCase):
    """Unproven VLEN dependence must never be reported as safe."""

    @staticmethod
    def _graph(specs, edges, start=0x2000):
        """Build a function from (op, args) specs and explicit CFG edges.

        Every instruction is its own basic block and both the block-level and
        the instruction-level CFG are wired, because loop discovery runs on
        blocks while the expression and dependency solvers run on instructions.
        """

        from chimera.preprocess.offline.analysis.core.data_model import (
            BasicBlock,
            Function,
            Instruction,
        )

        instructions = [
            Instruction(start + index * 4, 4, op, list(args), f"{op} " + ",".join(args))
            for index, (op, args) in enumerate(specs)
        ]
        by_address = {instruction.addr: instruction for instruction in instructions}
        blocks = {instruction.addr: BasicBlock([instruction]) for instruction in instructions}
        for source, destination in edges:
            by_address[source].succ.add(destination)
            blocks[source].successors.append(blocks[destination])
            blocks[destination].predecessors.append(blocks[source])
        return Function(
            "dependency",
            start,
            insts=instructions,
            blocks=list(blocks.values()),
        )

    @staticmethod
    def _marked(function):
        _, live_before, _ = _frame_markers(function)
        return [
            instruction.addr
            for instruction in function.insts
            if VLEN_STACK_FRAME in live_before.get(instruction.addr, frozenset())
        ]

    def test_unrelated_vlenb_does_not_taint_a_locally_sized_allocation(self) -> None:
        # The size is computed inside this function from constants only, so the
        # coexisting ``vlenb`` read must not produce frame state.
        function = self._graph(
            [
                ("csrr", ["a7", "vlenb"]),
                ("li", ["a1", "64"]),
                ("slli", ["a1", "a1", "1"]),
                ("sub", ["sp", "sp", "a1"]),
                ("addi", ["a3", "a3", "1"]),
                ("add", ["sp", "sp", "a1"]),
                ("ret", []),
            ],
            [(0x2000, 0x2004), (0x2004, 0x2008), (0x2008, 0x200C),
             (0x200C, 0x2010), (0x2010, 0x2014), (0x2014, 0x2018)],
        )

        self.assertEqual(self._marked(function), [])

    def test_caller_supplied_size_is_not_proven_independent(self) -> None:
        # ``a0`` arrives from the caller, which may itself have read ``vlenb``
        # before the call: "this function did not create the value" is not a
        # proof of independence, so the adjustment must stay marked.
        function = self._graph(
            [("sub", ["sp", "sp", "a0"]), ("jalr", ["ra", "a2", "0"])],
            [(0x2000, 0x2004)],
        )
        expressions, live_before, warnings = _frame_markers(function)

        self.assertEqual(self._marked(function), [0x2000, 0x2004])
        self.assertIn(
            "unknown-vlen-stack-adjustment",
            {warning.code for warning in warnings},
        )
        del expressions, live_before

    def test_caller_supplied_size_stays_unknown_behind_a_prefix(self) -> None:
        # The external entry state is a real in-edge, not a property of the
        # first instruction: an incoming parameter keeps its unproven level
        # when something else executes before it is used.  Each prefix below
        # was observed to reset ``a0`` to "independent" when the entry rule was
        # applied only to the entry instruction itself.
        prefixes = {
            "nothing": [],
            "nop": [("nop", [])],
            "fixed prologue": [("addi", ["sp", "sp", "-16"])],
            "unrelated move": [
                ("mv", ["t0", "a0"]),
                ("addi", ["sp", "sp", "-16"]),
            ],
            "unrelated arithmetic": [
                ("addi", ["a3", "a3", "1"]),
                ("slli", ["a3", "a3", "2"]),
            ],
        }

        for label, prefix in prefixes.items():
            with self.subTest(prefix=label):
                specs = list(prefix) + [
                    ("sub", ["sp", "sp", "a0"]),
                    ("jalr", ["ra", "a2", "0"]),
                ]
                function = self._graph(
                    specs,
                    [
                        (0x2000 + index * 4, 0x2004 + index * 4)
                        for index in range(len(specs) - 1)
                    ],
                )
                adjustment = 0x2000 + len(prefix) * 4
                expressions, live_before, warnings = _frame_markers(function)

                self.assertEqual(
                    dependencies_level(function, adjustment),
                    DEPENDENCY_UNKNOWN,
                    f"{label}: the caller's value must not become proven",
                )
                self.assertIn(adjustment, self._marked(function))
                self.assertIn(
                    "unknown-vlen-stack-adjustment",
                    {warning.code for warning in warnings},
                )
                del expressions, live_before

    def test_local_constant_size_stays_independent_behind_a_prologue(self) -> None:
        # The size is proven independent *inside* this function, so a fixed
        # prologue in front of it and the unproven entry parameters elsewhere
        # must not turn it into frame state.
        function = self._graph(
            [
                ("addi", ["sp", "sp", "-16"]),
                ("li", ["a1", "64"]),
                ("sub", ["sp", "sp", "a1"]),
                ("ret", []),
            ],
            [(0x2000, 0x2004), (0x2004, 0x2008), (0x2008, 0x200C)],
        )

        self.assertEqual(dependencies_level(function, 0x2008), DEPENDENCY_INDEPENDENT)
        self.assertEqual(self._marked(function), [])

    def test_entry_parameter_is_not_reset_by_an_unrelated_write(self) -> None:
        # Only the register an instruction writes may change level: every other
        # incoming parameter must stay unproven for the whole function.
        function = self._graph(
            [
                ("addi", ["a3", "a3", "1"]),
                ("addi", ["a4", "a4", "1"]),
                ("sub", ["sp", "sp", "a0"]),
                ("ret", []),
            ],
            [(0x2000, 0x2004), (0x2004, 0x2008), (0x2008, 0x200C)],
        )
        dependencies = analyze_register_dependencies(function, SEMANTICS)

        self.assertEqual(
            dependencies.level_after(0x2004, "a0"), DEPENDENCY_UNKNOWN
        )
        self.assertEqual(
            dependencies.level_after(0x2004, "a5"), DEPENDENCY_UNKNOWN
        )
        self.assertEqual(
            dependencies.level_after(0x2004, "a3"), DEPENDENCY_UNKNOWN
        )

    def test_entry_carve_outs_are_zero_and_the_relative_stack_base(self) -> None:
        # ``zero`` is a constant and the entry ``sp`` is the reference the frame
        # is measured against; every other incoming value is unproven.
        dependencies = analyze_register_dependencies(
            self._graph([("ret", [])], []), SEMANTICS
        )

        self.assertEqual(
            dependencies.level_before(0x2000, "sp"), DEPENDENCY_INDEPENDENT
        )
        self.assertEqual(
            dependencies.level_before(0x2000, "zero"), DEPENDENCY_INDEPENDENT
        )
        for register in ("a0", "a1", "t0", "ra", "s0"):
            with self.subTest(register=register):
                self.assertEqual(
                    dependencies.level_before(0x2000, register),
                    DEPENDENCY_UNKNOWN,
                )

    def test_back_edge_to_the_function_entry_keeps_the_taint(self) -> None:
        # The entry may be reached again through a back edge, so the entry
        # state must be the join of the external entry state and the real CFG
        # predecessors.  Here ``a0`` becomes ``vlenb``-derived inside the loop
        # and is carried back into the entry, where ``t0`` picks it up.
        function = self._graph(
            [
                ("mv", ["t0", "a0"]),      # 0x2000 entry
                ("csrr", ["a0", "vlenb"]),  # 0x2004
                ("addi", ["a1", "a1", "-1"]),  # 0x2008
                ("bnez", ["a1", "0x2000"]),  # 0x200C back edge to the entry
                ("sub", ["sp", "sp", "t0"]),  # 0x2010
                ("jalr", ["ra", "a2", "0"]),  # 0x2014
            ],
            [(0x2000, 0x2004), (0x2004, 0x2008), (0x2008, 0x200C),
             (0x200C, 0x2000), (0x200C, 0x2010), (0x2010, 0x2014)],
        )
        dependencies = analyze_register_dependencies(function, SEMANTICS)

        self.assertEqual(
            dependencies.level_after(0x2000, "a0"),
            DEPENDENCY_VLEN,
            "the value carried back into the entry must not be dropped",
        )
        self.assertEqual(
            dependencies.level_after(0x2000, "t0"), DEPENDENCY_VLEN
        )
        self.assertIn(0x2010, self._marked(function))
        self.assertIn(0x2014, self._marked(function))

    def test_back_edge_to_the_function_entry_keeps_the_frame_state(self) -> None:
        # The frame state must survive a back edge to the entry as well: the
        # adjustment sits inside the loop, so the entry is only frame-live
        # because the back edge carries the state into it.
        function = self._graph(
            [
                ("addi", ["t0", "t0", "1"]),   # 0x2000 entry, before any adjust
                ("csrr", ["a0", "vlenb"]),      # 0x2004
                ("sub", ["sp", "sp", "a0"]),    # 0x2008 adjustment
                ("addi", ["t1", "t1", "-1"]),   # 0x200C
                ("bnez", ["t1", "0x2000"]),     # 0x2010 back edge to the entry
                ("ret", []),                    # 0x2014
            ],
            [(0x2000, 0x2004), (0x2004, 0x2008), (0x2008, 0x200C),
             (0x200C, 0x2010), (0x2010, 0x2000), (0x2010, 0x2014)],
        )
        marked = self._marked(function)

        self.assertIn(
            0x2000,
            marked,
            "the entry is frame-live through the back edge, not reset to safe",
        )
        self.assertIn(0x2004, marked)

    def test_load_derived_size_is_not_proven_independent(self) -> None:
        function = self._graph(
            [
                ("lw", ["a1", "0(a0)"]),
                ("sub", ["sp", "sp", "a1"]),
                ("add", ["sp", "sp", "a1"]),
                ("ret", []),
            ],
            [(0x2000, 0x2004), (0x2004, 0x2008), (0x2008, 0x200C)],
        )

        self.assertEqual(self._marked(function), [0x2004, 0x2008])

    def test_unknown_operation_keeps_the_dependency(self) -> None:
        function = self._graph(
            [
                ("csrr", ["a0", "vlenb"]),
                ("div", ["a1", "a0", "a2"]),
                ("sub", ["sp", "sp", "a1"]),
                ("ret", []),
            ],
            [(0x2000, 0x2004), (0x2004, 0x2008), (0x2008, 0x200C)],
        )

        self.assertEqual(self._marked(function), [0x2008, 0x200C])

    def test_memory_round_trip_keeps_the_dependency(self) -> None:
        function = self._graph(
            [
                ("csrr", ["a0", "vlenb"]),
                ("sd", ["a0", "0(sp)"]),
                ("ld", ["a1", "0(sp)"]),
                ("sub", ["sp", "sp", "a1"]),
                ("ret", []),
            ],
            [(0x2000, 0x2004), (0x2004, 0x2008), (0x2008, 0x200C), (0x200C, 0x2010)],
        )

        self.assertEqual(self._marked(function), [0x200C, 0x2010])

    def test_path_merge_keeps_the_vlen_path(self) -> None:
        # Only one of the two reaching paths derives ``a1`` from ``vlenb``.
        function = self._graph(
            [
                ("beqz", ["a2", "0x200C"]),
                ("csrr", ["a1", "vlenb"]),
                ("addi", ["a3", "a3", "1"]),
                ("sub", ["sp", "sp", "a1"]),
                ("ret", []),
            ],
            [(0x2000, 0x2004), (0x2000, 0x200C), (0x2004, 0x2008),
             (0x2008, 0x200C), (0x200C, 0x2010)],
        )

        self.assertEqual(self._marked(function), [0x200C, 0x2010])

    def test_path_merge_of_proven_paths_stays_independent(self) -> None:
        # Both reaching paths write ``a1`` from constants *inside* this
        # function before the adjustment uses it, so the definition dominates
        # the use on every path and the proof survives the merge.  (A path that
        # simply skips the definition would keep the caller's value - see the
        # test below.)
        function = self._graph(
            [
                ("beqz", ["a2", "0x2008"]),
                ("li", ["a1", "32"]),
                ("li", ["a1", "64"]),          # 0x2008, reached on both paths
                ("sub", ["sp", "sp", "a1"]),   # 0x200C
                ("ret", []),
            ],
            [(0x2000, 0x2004), (0x2000, 0x2008), (0x2004, 0x2008),
             (0x2008, 0x200C), (0x200C, 0x2010)],
        )

        self.assertEqual(self._marked(function), [])

    def test_merge_of_a_local_constant_and_the_entry_value_stays_unknown(self) -> None:
        # One path proves ``a1`` independent with a local constant, the other
        # does not write it at all and therefore still carries the caller's
        # value.  Independence must only survive a merge when *every* reaching
        # path proves it, so this adjustment stays unproven.
        function = self._graph(
            [
                ("beqz", ["a2", "0x2008"]),
                ("li", ["a1", "32"]),          # 0x2004 the proving path
                ("sub", ["sp", "sp", "a1"]),   # 0x2008 the merge point
                ("ret", []),
            ],
            [(0x2000, 0x2004), (0x2000, 0x2008), (0x2004, 0x2008),
             (0x2008, 0x200C)],
        )
        expressions, live_before, warnings = _frame_markers(function)

        self.assertEqual(
            dependencies_level(function, 0x2008), DEPENDENCY_UNKNOWN
        )
        self.assertIn(0x2008, self._marked(function))
        self.assertIn(
            "unknown-vlen-stack-adjustment",
            {warning.code for warning in warnings},
        )
        del expressions, live_before

    def test_loop_carried_vlen_value_is_not_merged_away(self) -> None:
        # The loop writes ``a0`` from a ``vlenb`` read; at the header the
        # expression model replaces ``a0`` with a loop symbol, so only the
        # dependency dataflow can keep the taint.
        function = self._graph(
            [
                ("li", ["a0", "0"]),
                ("csrr", ["a1", "vlenb"]),
                ("addi", ["a0", "a0", "1"]),   # 0x2008 loop header
                ("add", ["a0", "a0", "a1"]),
                ("sub", ["sp", "sp", "a0"]),   # 0x2010 adjustment
                ("bne", ["a0", "a2", "0x2008"]),
                ("ret", []),
            ],
            [(0x2000, 0x2004), (0x2004, 0x2008), (0x2008, 0x200C),
             (0x200C, 0x2010), (0x2010, 0x2014), (0x2014, 0x2018),
             (0x2014, 0x2008)],
        )

        marked = self._marked(function)
        # The back edge really forms a natural loop whose body writes ``a0``
        # (and ``sp``), so the header summary is exercised.
        expressions = _expressions(function)
        self.assertTrue(expressions.loop_info.natural_loops)
        self.assertIn(0x2008, expressions.loop_info.header_written_registers)
        self.assertIn(
            "a0", expressions.loop_info.header_written_registers[0x2008]
        )
        self.assertIn(0x2010, marked)
        self.assertIn(0x2018, marked)


class CrossCallPropagationTests(unittest.TestCase):
    """The frame state must still travel into the callee."""

    @classmethod
    def setUpClass(cls) -> None:
        import warnings as py_warnings

        from chimera.check_elf import collect_diagnostics
        from chimera.preprocess.offline.analysis.safety.stack_liveness.model import (
            IrreducibleLoopWarning,
        )

        cls.temporary = tempfile.TemporaryDirectory()
        stub = Path(cls.temporary.name) / "stub.elf"
        stub.write_bytes(b"\x7fELF\x02\x01\x01" + b"\x00" * 24)
        with py_warnings.catch_warnings():
            # The layout constructor carries an irreducible loop; the analysis
            # warning is asserted through the diagnostics tuple instead of the
            # console.
            py_warnings.simplefilter("ignore", IrreducibleLoopWarning)
            cls.result = collect_diagnostics(
                stub,
                objdump_cmd="objdump",
                strategy="gate",
                dump_text=fixture.STACK_FUNCTIONS_DUMP + fixture.STUB_CALLEE_DUMP,
                metadata=ChimeraMetadata.empty(),
            )

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temporary.cleanup()

    def test_seed_sites_are_the_active_internal_call_sites_only(self) -> None:
        seed_sites = {
            (edge.caller_function_start, edge.call_site)
            for edge in self.result.analysis.stack.inheritance_trace.seed_edges
        }
        self.assertEqual(
            seed_sites,
            {(0x21C5E, 0x21D06), (0x21C5E, 0x21D26)},
        )

    def test_callee_inherits_the_frame_state(self) -> None:
        stack = self.result.analysis.stack
        self.assertIn(fixture.STUB_CALLEE_ADDRESS, stack.inherited_functions)
        self.assertTrue(
            stack.by_function[fixture.STUB_CALLEE_ADDRESS].live_before.get(0x9F000)
        )

    def test_seed_carries_the_frame_marker_as_its_local_object(self) -> None:
        document = self._inheritance_document()
        self.assertTrue(document["seed_edges"])
        for entry in document["seed_edges"]:
            objects = {obj["id"] for obj in entry["local_active_objects"]}
            self.assertEqual(objects, {"vlen_stack_frame:dynamic-sp"})

    def test_finding_shape_and_witness_survive_the_correction(self) -> None:
        document = self._inheritance_document()
        unresolved = [item for item in document["findings"]
                      if item["diagnostic_code"] == "unresolved-active-indirect-call"]
        self.assertEqual(len(unresolved), 1)
        finding = unresolved[0]
        # Width observations are warning-only. All actual active external
        # boundaries and the inherited unresolved boundary remain findings.
        self.assertEqual(self.result.counts["active_external_calls"], 59)
        self.assertEqual(len(document["findings"]), 60)
        self.assertEqual(finding["kind"], "inherited")
        self.assertEqual(finding["function"], fixture.STUB_CALLEE)
        self.assertTrue(finding["witness_reached_seed"])
        self.assertFalse(finding["diagnostics_incomplete"])
        # The callee has no vector code of its own, so its finding is explained
        # by the inherited state - exactly the shape of the gate-2 report.  The
        # frame marker itself is the *seed's* local object (asserted above).
        self.assertIn(
            "live caller-inherited stack data",
            " ".join(finding["activity_explanation"]),
        )
        self.assertEqual(document["closure_size"], 1)

    def test_independent_branch_is_quiet_but_adjusted_external_calls_are_not(self) -> None:
        document = self._inheritance_document()
        sites = {entry["call_site"] for entry in document["seed_edges"]}
        sites |= {finding["call_site"] for finding in document["findings"]}
        self.assertNotIn(hex(fixture.INDEPENDENT_ERROR_CALL), sites)
        for address in fixture.ADJUSTED_ERROR_CALLS:
            self.assertNotIn(hex(address), {entry["call_site"] for entry in document["seed_edges"]})
            # These known callees are outside the fixture's partial Program.
            # The calls follow the UNKNOWN allocation, so v24 must report them
            # as pending local sources rather than silently discarding them.
            # v30 excludes selection and inferred ABI returns from local
            # cache content; the UNKNOWN frame's missing proof still remains.
            finding = next(item for item in document["findings"]
                           if item["call_site"] == hex(address)
                           and item["diagnostic_code"] == "active-external-call")
            self.assertEqual(finding["diagnostic_code"], "active-external-call")
            self.assertEqual(finding["origin_status"], "unproven")
            self.assertTrue(finding["external_targets"])
            self.assertEqual({origin["dependency"] for origin in finding["activity_origins"]},
                             {"unknown"})
            self.assertNotIn("local-vlen-scalar",
                          {origin["origin"] for origin in finding["activity_origins"]})

    def test_strict_finding_rule_and_report_shape_are_unchanged(self) -> None:
        from chimera.check_elf import (
            _diagnostics_payload,
            build_decision_block,
            has_actionable_findings,
        )

        self.assertTrue(has_actionable_findings(self.result))
        self.assertTrue(all(not item.residual for item in self.result.findings))
        payload = _diagnostics_payload(self.result)
        self.assertEqual(
            set(payload),
            {
                "strategy",
                "strategy_reason",
                "text_bytes",
                "summary",
                "gate_names",
                "pending_proof_names",
                "missing_internal_targets",
                "findings",
                "warnings",
                "unknown_stack_size_policy",
                "assumption",
                "conditional",
                "scope_exclusion_count",
                "external_scalar_leaves",
            },
        )
        self.assertEqual(payload["unknown_stack_size_policy"], "conservative")
        self.assertEqual(
            payload["assumption"],
            "Unknown scalar stack allocation sizes remain conservatively VLEN-sensitive.",
        )
        self.assertFalse(payload["conditional"])
        self.assertEqual(payload["scope_exclusion_count"], 0)
        self.assertEqual(payload["summary"]["findings_total"], len(self.result.findings))
        # Every finding carries the structured origins next to the prose:
        # classification reads the records, humans read the lines.
        # ``gate_listed`` was added by check version 19: it says whether the
        # host is a candidate for gate recompilation. v24 additionally records
        # the diagnostic class and known external alternatives; neither list
        # membership nor the action establishes discharge.
        self.assertTrue(
            all(
                set(item)
                == set(
                    (
                        "kind",
                        "diagnostic_code",
                        "external_targets",
                        "function",
                        "call_site",
                        "recommended_action",
                        "support",
                        "activity_origins",
                        "origin_status",
                        "residual",
                        "gate_listed",
                    )
                )
                for item in payload["findings"]
            )
        )
        self.assertTrue(
            all(item["activity_origins"] for item in payload["findings"])
        )
        decision = build_decision_block(self.result)
        self.assertEqual(
            set(decision), {"strategy", "vector_gate", "function_pointer_plugin", "stack_object_plugin", "gate"}
        )

    def _inheritance_document(self) -> dict:
        from chimera.check_elf import export_inheritance_diagnostics

        output = Path(self.temporary.name) / "inheritance.json"
        export_inheritance_diagnostics(self.result, output, content_hash="0" * 64)
        return json.loads(output.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
