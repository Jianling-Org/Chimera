"""Recursive calls on the real gate-2 disassembly: CFG, frames, propagation."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import xgcc_stack_fixture as fixture

from chimera.preprocess.offline.analysis.arch.riscv.rvv.config import VSET_OPS
from chimera.preprocess.offline.analysis.arch.riscv.rvv.services import RvvServices
from chimera.preprocess.offline.analysis.arch.riscv.services import RiscvServices
from chimera.preprocess.offline.analysis.program_model.parser import parse_dump
from chimera.preprocess.offline.analysis.toolchain.objdump import LinuxObjdump
from chimera.preprocess.offline.analysis.safety.stack_liveness.expressions import (
    walk_loop_inputs,
)
from chimera.preprocess.offline.analysis.safety.stack_liveness.frame_liveness import (
    VLEN_STACK_FRAME,
    VLEN_STACK_SETUP,
    analyze_vlen_stack_liveness,
)
from chimera.preprocess.offline.analysis.safety.stack_liveness.liveness import (
    _CallTargetResolver,
)
from chimera.preprocess.offline.analysis.safety.stack_liveness.model import (
    ChimeraMetadata,
)
from chimera.preprocess.offline.analysis.safety.stack_liveness.solver import (
    _FunctionExpressionAnalyzer,
)

SEMANTICS = RvvServices().stack_semantics


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


def _program_from_dump(dump: str):
    adapter = LinuxObjdump("objdump")
    with tempfile.TemporaryDirectory() as directory:
        source = Path(directory) / "dump.txt"
        source.write_text(dump, encoding="utf-8")
        parsed = parse_dump(
            source,
            adapter.parse_format,
            is_external_trampoline=adapter.is_external_trampoline,
            retain_dump_lines=False,
        )
    return RiscvServices(RvvServices()).build_cfg(parsed)


class FixtureIntegrityTests(unittest.TestCase):
    """The fixture must really be the reported disassembly."""

    def test_functions_and_boundaries_are_preserved(self) -> None:
        program = fixture.load_recursive_program()
        self.assertEqual(
            [function.name for function in program.functions],
            list(fixture.RECURSIVE_FUNCTIONS),
        )
        sizes = {function.name: len(function.insts) for function in program.functions}
        self.assertEqual(sizes[fixture.ELF_ADD], 1959)
        self.assertEqual(sizes[fixture.DWARF_LOOKUP_PC], 433)
        self.assertEqual(sizes[fixture.D_COUNT_TEMPLATES_SCOPES], 59)
        starts = {
            function.name: function.start for function in program.functions
        }
        self.assertEqual(starts[fixture.ELF_ADD], 0x88E82)
        self.assertEqual(starts[fixture.DWARF_LOOKUP_PC], 0x8E8FE)
        self.assertEqual(starts[fixture.D_COUNT_TEMPLATES_SCOPES], 0x996FE)

    def test_fixture_carries_no_build_paths(self) -> None:
        self.assertNotIn("/root/", fixture.RECURSIVE_FUNCTIONS_DUMP)
        self.assertNotIn("文件格式", fixture.RECURSIVE_FUNCTIONS_DUMP)

    def test_reported_call_sites_keep_their_addresses(self) -> None:
        program = fixture.load_recursive_program()
        for name, addresses in (
            (fixture.ELF_ADD, fixture.ELF_ADD_RECURSIVE_CALLS
                + fixture.ELF_ADD_INDIRECT_CALLS),
            (fixture.DWARF_LOOKUP_PC, (fixture.DWARF_LOOKUP_PC_RECURSIVE_CALL,)
                + fixture.DWARF_LOOKUP_PC_INDIRECT_CALLS
                + fixture.DWARF_LOOKUP_PC_VECTOR_STORES),
            (fixture.D_COUNT_TEMPLATES_SCOPES,
                fixture.D_COUNT_TEMPLATES_SCOPES_RECURSIVE_CALLS
                + (fixture.D_COUNT_TEMPLATES_SCOPES_JUMP_TABLE,)),
        ):
            function = fixture.function(program, name)
            present = {instruction.addr for instruction in function.insts}
            for address in addresses:
                with self.subTest(function=name, address=hex(address)):
                    self.assertIn(address, present)


class RecursiveCallCfgTests(unittest.TestCase):
    """The entry is independent of its call sites; the target still resolves."""

    def _function(self, name):
        return fixture.function(fixture.load_recursive_program(), name)

    def test_entry_has_no_call_site_predecessor(self) -> None:
        for name in (fixture.ELF_ADD, fixture.DWARF_LOOKUP_PC):
            with self.subTest(function=name):
                function = self._function(name)
                self.assertEqual(
                    [block.start for block in function.blocks[0].predecessors],
                    [],
                    "a recursive call must not wire the entry as its successor",
                )

    def test_recursive_call_keeps_only_the_return_successor(self) -> None:
        function = self._function(fixture.DWARF_LOOKUP_PC)
        call = function.instruction_by_address[
            fixture.DWARF_LOOKUP_PC_RECURSIVE_CALL
        ]
        self.assertEqual(call.succ, {0x8EC86})
        self.assertEqual(call.jump_targets, {function.start})
        call_block = next(
            block
            for block in function.blocks
            if any(
                instruction.addr == fixture.DWARF_LOOKUP_PC_RECURSIVE_CALL
                for instruction in block.instructions
            )
        )
        self.assertEqual(
            [block.start for block in call_block.successors], [0x8EC86]
        )

    def test_recursive_calls_still_resolve_for_the_call_graph(self) -> None:
        program = fixture.load_recursive_program()
        by_start = {function.start: function for function in program.functions}
        resolver = _CallTargetResolver()
        metadata = ChimeraMetadata.empty()
        for name, addresses in (
            (fixture.ELF_ADD, fixture.ELF_ADD_RECURSIVE_CALLS),
            (fixture.DWARF_LOOKUP_PC, (fixture.DWARF_LOOKUP_PC_RECURSIVE_CALL,)),
            (
                fixture.D_COUNT_TEMPLATES_SCOPES,
                fixture.D_COUNT_TEMPLATES_SCOPES_RECURSIVE_CALLS,
            ),
        ):
            function = fixture.function(program, name)
            for address in addresses:
                with self.subTest(function=name, address=hex(address)):
                    instruction = function.instruction_by_address[address]
                    self.assertEqual(
                        resolver.resolve(instruction, by_start, metadata),
                        {function.start},
                    )

    def test_recursion_is_recorded_on_the_entry(self) -> None:
        function = self._function(fixture.D_COUNT_TEMPLATES_SCOPES)
        self.assertEqual(
            function.insts[0].jump_sources,
            set(fixture.D_COUNT_TEMPLATES_SCOPES_RECURSIVE_CALLS),
        )

    def test_jump_table_dispatch_stays_unresolved(self) -> None:
        function = self._function(fixture.D_COUNT_TEMPLATES_SCOPES)
        jump = function.instruction_by_address[
            fixture.D_COUNT_TEMPLATES_SCOPES_JUMP_TABLE
        ]
        self.assertEqual(jump.op, "jr")
        self.assertEqual(jump.jump_targets, set())
        self.assertEqual(jump.succ, set())

    def test_false_entry_loop_is_gone(self) -> None:
        for name, start in (
            (fixture.ELF_ADD, fixture.ELF_ADD_ALLOCATION),
            (fixture.DWARF_LOOKUP_PC, fixture.DWARF_LOOKUP_PC_ALLOCATION),
        ):
            with self.subTest(function=name):
                function = self._function(name)
                expressions = _expressions(function)
                self.assertNotIn(
                    start, expressions.loop_info.header_written_registers
                )
                self.assertEqual(
                    walk_loop_inputs(expressions.before_states[start]["sp"]),
                    frozenset(),
                    "the entry sp must stay the function's own base",
                )

    def test_real_loops_survive(self) -> None:
        function = self._function(fixture.ELF_ADD)
        expressions = _expressions(function)
        headers = expressions.loop_info.header_written_registers
        self.assertIn(0x894D0, headers)
        self.assertGreaterEqual(len(headers), 8)


class FixedFrameTests(unittest.TestCase):
    """Fixed frames plus vector work must not produce frame state."""

    def _marked(self, name):
        function = fixture.function(fixture.load_recursive_program(), name)
        expressions, live_before, warnings = _frame_markers(function)
        return function, expressions, live_before, warnings

    def test_fixed_frames_have_no_vlen_frame_state(self) -> None:
        for name, allocation, restore in (
            (fixture.ELF_ADD, fixture.ELF_ADD_ALLOCATION, fixture.ELF_ADD_RESTORE),
            (
                fixture.DWARF_LOOKUP_PC,
                fixture.DWARF_LOOKUP_PC_ALLOCATION,
                fixture.DWARF_LOOKUP_PC_RESTORE,
            ),
        ):
            with self.subTest(function=name):
                function, _expressions, live_before, warnings = self._marked(name)
                self.assertEqual(
                    _addresses_with(function, live_before, VLEN_STACK_FRAME), []
                )
                self.assertEqual(
                    _addresses_with(function, live_before, VLEN_STACK_SETUP), []
                )
                self.assertEqual([warning.code for warning in warnings], [])
                self.assertNotIn(
                    VLEN_STACK_FRAME,
                    live_before.get(allocation, frozenset()),
                )
                self.assertNotIn(
                    VLEN_STACK_FRAME, live_before.get(restore, frozenset())
                )

    def test_dwarf_lookup_pc_still_contains_vector_work(self) -> None:
        function = fixture.function(
            fixture.load_recursive_program(), fixture.DWARF_LOOKUP_PC
        )
        self.assertTrue(
            any(
                instruction.op.startswith("v")
                and instruction.op not in VSET_OPS
                for instruction in function.insts
            ),
            "dwarf_lookup_pc runs vector instructions",
        )


class EndToEndFindingsTests(unittest.TestCase):
    """The false findings disappear; the genuine one stays."""

    @classmethod
    def setUpClass(cls) -> None:
        from chimera.check_elf import collect_diagnostics

        cls.temporary = tempfile.TemporaryDirectory()
        stub = Path(cls.temporary.name) / "stub.elf"
        stub.write_bytes(b"\x7fELF\x02\x01\x01" + b"\x00" * 24)
        synthetic = (
            "0000000000002000 <vlen_host>:\n"
            "    2000: c2202573             csrr a0,vlenb\n"
            "    2004: 40a00533             sub sp,sp,a0\n"
            "    2008: 9682                 jalr a3\n"
            "    200c: 40a00533             add sp,sp,a0\n"
            "    2010: 8082                 ret\n"
        )
        cls.result = collect_diagnostics(
            stub,
            objdump_cmd="objdump",
            strategy="gate",
            dump_text=synthetic + "\n" + fixture.RECURSIVE_FUNCTIONS_DUMP,
            metadata=ChimeraMetadata.empty(),
        )

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temporary.cleanup()

    def test_only_the_genuine_host_is_reported(self) -> None:
        self.assertEqual(
            [
                (finding.function, finding.call_site, finding.kind)
                for finding in self.result.findings
                if finding.diagnostic_code != "escaping-vlen-scalar-value"
            ],
            [("vlen_host", "0x2008", "local-root")],
        )
        self.assertEqual(
            [(item.function, item.call_site) for item in self.result.findings
             if item.diagnostic_code == "escaping-vlen-scalar-value"],
            [],
        )

    def test_the_five_false_findings_are_gone(self) -> None:
        sites = {
            (finding.function, finding.call_site)
            for finding in self.result.findings
        }
        for name, addresses in (
            (fixture.ELF_ADD, fixture.ELF_ADD_INDIRECT_CALLS),
            (fixture.DWARF_LOOKUP_PC, fixture.DWARF_LOOKUP_PC_INDIRECT_CALLS),
        ):
            for address in addresses:
                with self.subTest(function=name, address=hex(address)):
                    self.assertNotIn((name, hex(address)), sites)

    def test_source_proof_gaps_stay_conservative(self) -> None:
        stack = self.result.analysis.stack
        self.assertTrue(stack.missing_callees)
        self.assertIn(0x8C220, stack.missing_callees)


class RecursiveCallPropagationTests(unittest.TestCase):
    """A recursive call inside an active frame still propagates."""

    DUMP = (
        "0000000000001000 <recursive_frame>:\n"
        "    1000: c2202573             csrr a0,vlenb\n"
        "    1004: 40a00533             sub sp,sp,a0\n"
        "    1008: e3ffffef             jal ra,1000 <recursive_frame>\n"
        "    100c: 9682                 jalr a3\n"
        "    1010: 40a00533             add sp,sp,a0\n"
        "    1014: 8082                 ret\n"
    )

    @classmethod
    def setUpClass(cls) -> None:
        from chimera.check_elf import collect_diagnostics

        cls.temporary = tempfile.TemporaryDirectory()
        stub = Path(cls.temporary.name) / "stub.elf"
        stub.write_bytes(b"\x7fELF\x02\x01\x01" + b"\x00" * 24)
        cls.result = collect_diagnostics(
            stub,
            objdump_cmd="objdump",
            strategy="gate",
            dump_text=cls.DUMP,
            metadata=ChimeraMetadata.empty(),
        )

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temporary.cleanup()

    def test_recursive_call_marks_the_function_inherited(self) -> None:
        stack = self.result.analysis.stack
        self.assertEqual(sorted(stack.inherited_functions), [0x1000])
        self.assertEqual(
            [
                (edge.caller_function_start, edge.call_site, edge.reason)
                for edge in stack.inheritance_trace.seed_edges
            ],
            [(0x1000, 0x1008, "seed")],
        )

    def test_unresolved_indirect_call_still_warns(self) -> None:
        stack = self.result.analysis.stack
        self.assertEqual(list(stack.unresolved_live_calls), [0x100C])
        self.assertEqual(
            [
                (finding.function, finding.call_site, finding.kind)
                for finding in self.result.findings
                if finding.diagnostic_code != "escaping-vlen-scalar-value"
            ],
            [("recursive_frame", "0x100c", "local-root")],
        )
        self.assertEqual(
            [item.call_site for item in self.result.findings
             if item.diagnostic_code == "escaping-vlen-scalar-value"],
            [],
        )

    def test_genuine_frame_is_not_cleared(self) -> None:
        function = fixture.function(_program_from_dump(self.DUMP), "recursive_frame")
        expressions, live_before, warnings = _frame_markers(function)
        self.assertIn(VLEN_STACK_FRAME, live_before.get(0x1008, frozenset()))
        self.assertIn(
            "unknown-vlen-stack-adjustment",
            {warning.code for warning in warnings},
        )


class TrueEntryLoopTests(unittest.TestCase):
    """A real back edge into the entry keeps the conservative behaviour."""

    def _marked(self, dump):
        function = fixture.function(_program_from_dump(dump), "entry_loop")
        expressions, live_before, warnings = _frame_markers(function)
        return function, expressions, live_before, warnings

    def test_conditional_back_edge_to_the_entry(self) -> None:
        _function, expressions, live_before, warnings = self._marked(
            "0000000000010000 <entry_loop>:\n"
            "    1000: c2202573             csrr a0,vlenb\n"
            "    1004: 40a00533             sub sp,sp,a0\n"
            "    1008: fff28293             addi t0,t0,-1\n"
            "    100c: fc029ee3             bnez t0,1000 <entry_loop>\n"
            "    1010: 40a00533             add sp,sp,a0\n"
            "    1014: 8082                 ret\n"
        )
        self.assertIn(0x1000, expressions.loop_info.header_written_registers)
        self.assertIn(VLEN_STACK_FRAME, live_before.get(0x1004, frozenset()))
        self.assertEqual(
            [warning.code for warning in warnings],
            ["unknown-vlen-stack-adjustment"],
        )

    def test_unconditional_jump_back_to_the_entry(self) -> None:
        _function, expressions, live_before, _warnings = self._marked(
            "0000000000010000 <entry_loop>:\n"
            "    1000: c2202573             csrr a0,vlenb\n"
            "    1004: 40a00533             sub sp,sp,a0\n"
            "    1008: fff28293             addi t0,t0,-1\n"
            "    100c: fd0296e3             bnez t0,1014 <entry_loop+0x14>\n"
            "    1010: a819                 j 1000 <entry_loop>\n"
            "    1014: 40a00533             add sp,sp,a0\n"
            "    1018: 8082                 ret\n"
        )
        self.assertIn(0x1000, expressions.loop_info.header_written_registers)
        self.assertIn(VLEN_STACK_FRAME, live_before.get(0x1004, frozenset()))

    def test_explicit_zero_link_jump_back_to_the_entry(self) -> None:
        _function, expressions, live_before, _warnings = self._marked(
            "0000000000010000 <entry_loop>:\n"
            "    1000: c2202573             csrr a0,vlenb\n"
            "    1004: 40a00533             sub sp,sp,a0\n"
            "    1008: fff28293             addi t0,t0,-1\n"
            "    100c: fd0296e3             bnez t0,1014 <entry_loop+0x14>\n"
            "    1010: 0000006f             jal zero,1000 <entry_loop>\n"
            "    1014: 40a00533             add sp,sp,a0\n"
            "    1018: 8082                 ret\n"
        )
        self.assertIn(0x1000, expressions.loop_info.header_written_registers)
        self.assertIn(VLEN_STACK_FRAME, live_before.get(0x1004, frozenset()))


if __name__ == "__main__":
    unittest.main()
