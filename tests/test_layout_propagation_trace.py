"""Counterexamples the propagation trace must refuse to accept.

Shapes a naive call-graph walk gets wrong:

1. **name-prefix conflict** -- ``<foobar>`` must not resolve to ``foo``;
2. **in-function jump** -- ``j foo+0x20`` / ``jal x0`` must not become a call
   edge just because the opcode spelling looks like a transfer;
3. **non-active first edge** -- a call that does not carry the original object
   is not a seed for it, even when the callee is otherwise reachable;
4. **invented target** -- a call to ``0x9000 <external@plt>`` must not
   become an edge to ``host`` merely because ``host`` starts at ``0x8000``.
   Only an exact function entry (production ``_CallTargetResolver`` rule)
   may be a target; unknown targets, external trampolines and out-of-range
   addresses keep the gap;
5. **disassembly-suspected edges** -- a path built from objdump-inferred
   edges cannot authorise ``analysis-trace``, even with a correctly bound
   inheritance report.  Only production resolver edges can;
6. **inherited hops** -- the production ``InheritedLivenessView`` puts the
   shared ``caller:inherited-stack-data`` marker in a callee, **not** the
   original object id.  Requiring the original id on hop 2+ rejects a real
   chain; accepting the shared marker as proof cross-contaminates sources;
7. **converging sources** -- two distinct sources reaching one host must not
   swap parents or source ids;
8. **wrong ELF** -- an inheritance report bound to a different binary must be
   refused an upgrade, even when the addresses coincide.

The trace only upgrades to ``analysis-trace`` (propagation evidence) when the
first hop proves the original object live and a **distinct source id** then
travels the analyzer-resolved call edges.  Anything weaker is
``callgraph-path-only`` or ``insufficient-evidence``.
"""

from __future__ import annotations

import json
import unittest
from pathlib import Path
import tempfile

from layout_mode_diagnosis import (
    IRREDUCIBLE_SOURCE,
    complete_coverage_metadata,
    forced_metadata_mode,
)
from layout_propagation_trace import (
    CALLER_MARKER,
    CallEdge,
    active_call_edges,
    call_edges_from_objdump,
    callgraph_only_result,
    describe,
    function_at,
    function_containing,
    function_summary,
    load_inheritance,
    load_production_program,
    object_active_call_sites,
    parse_objdump_line,
    parse_symbol_address,
    parse_symbol_name,
    resolve_call_target,
    resolved_call_edges,
    seeds_from_inheritance,
    trace_from_bound_edges,
    trace_from_elf,
    trace_from_inheritance,
    trace_source_propagation,
)
import xgcc_stack_fixture as fixture

from chimera.preprocess.offline.analysis.core.data_model import (
    Function,
    Instruction,
    Program,
)
from chimera.preprocess.offline.analysis.safety.stack_liveness.analyzer import (
    StackLivenessAnalyzer,
)
from chimera.preprocess.offline.analysis.safety.stack_liveness.model import (
    ChimeraMetadata,
    InheritedLivenessView,
    StackFunctionLiveness,
    StackObjectId,
)

LAYOUT = fixture.FIXED_FRAME_FUNCTIONS[2]
LAYOUT_START = 0x50418


def _instruction(addr: int, op: str, args, text: str) -> Instruction:
    instruction = Instruction(addr, 4, op, list(args), text)
    # The CFG builder records the transfer target on ``jump_targets``; the
    # synthetic edges here do the same so ``_CallTargetResolver`` can read
    # them exactly as it reads a real parsed program.
    if args and op in {"jal", "jalr", "j", "call"}:
        try:
            instruction.jump_targets.add(int(str(args[-1]), 16))
        except ValueError:
            pass
    return instruction


def _function(name: str, start: int, instructions) -> Function:
    function = Function(name, start, list(instructions))
    for current, following in zip(instructions, instructions[1:]):
        current.succ.add(following.addr)
    return function


def _program(*functions: Function) -> Program:
    instructions = [i for f in functions for i in f.insts]
    return Program(
        dump_lines=[],
        functions=list(functions),
        instructions=instructions,
        instruction_by_address={i.addr: i for i in instructions},
    )


class NamePrefixConflictTests(unittest.TestCase):
    """``<foobar>`` is not ``foo``; ``<foo+0x20>`` is still inside ``foo``."""

    def test_parse_symbol_name_matches_the_whole_name(self) -> None:
        self.assertEqual(parse_symbol_name("<foobar>"), "foobar")
        self.assertEqual(parse_symbol_name("<foo>"), "foo")
        self.assertEqual(parse_symbol_name("<foo+0x20>"), "foo")
        self.assertEqual(parse_symbol_name("<foo-0x20>"), "foo")
        self.assertIsNone(parse_symbol_name("<>"))

    def test_substring_match_would_have_welded_foobar_onto_foo(self) -> None:
        functions = {"foo": 0x1000, "foobar": 0x2000}

        # The bug this pins: ``candidate in rest`` sees "foo" inside "foobar"
        # and inside "<foo+0x20>", and then attributes the edge to whichever
        # candidate happened to come first.  Whole-name resolution must not.
        self.assertEqual(parse_symbol_address("<foobar>", functions), 0x2000)
        self.assertEqual(parse_symbol_address("<foo>", functions), 0x1000)
        self.assertEqual(parse_symbol_address("<foo+0x20>", functions), 0x1020)

        # And the name-prefix pair must never share an identity.
        self.assertNotEqual(
            parse_symbol_address("<foo>", functions),
            parse_symbol_address("<foobar>", functions),
        )

    def test_objdump_line_with_prefixed_name_does_not_resolve_to_the_prefix(
        self,
    ) -> None:
        functions = {"foo": 0x1000, "foobar": 0x2000}
        candidate = parse_objdump_line(
            "   2000:\t34d000ef          \tjal\t2000 <foobar>", functions
        )
        self.assertIsNotNone(candidate)
        assert candidate is not None
        self.assertEqual(candidate.target_name, "foobar")
        self.assertEqual(candidate.target_address, 0x2000)
        self.assertTrue(candidate.is_call)

    def test_function_at_uses_address_ranges_not_names(self) -> None:
        functions = ((0x1000, "foo"), (0x2000, "foobar"))
        self.assertEqual(function_at(functions, 0x2010), (0x2000, "foobar"))
        self.assertEqual(function_at(functions, 0x1010), (0x1000, "foo"))


class InFunctionJumpTests(unittest.TestCase):
    """``j`` / ``tail`` / ``jal x0`` are not call edges."""

    def test_jump_opcodes_are_not_calls(self) -> None:
        functions = {"foo": 0x1000}
        jump = parse_objdump_line(
            "   1020:\ta809               \tj\t1040 <foo+0x40>", functions
        )
        self.assertIsNotNone(jump)
        assert jump is not None
        self.assertFalse(jump.is_call)
        self.assertEqual(jump.target_name, "foo")
        self.assertEqual(jump.target_address, 0x1040)

    def test_explicit_zero_link_register_is_a_jump(self) -> None:
        functions = {"foo": 0x1000}
        spelled = parse_objdump_line(
            "   1020:\t00008067           \tjalr\tzero,0(ra)", functions
        )
        self.assertIsNotNone(spelled)
        assert spelled is not None
        self.assertFalse(spelled.is_call)

    def test_one_operand_jal_is_a_call(self) -> None:
        functions = {"foo": 0x1000}
        call = parse_objdump_line(
            "   1020:\t34d000ef           \tjal\t2000 <foo>", functions
        )
        self.assertIsNotNone(call)
        assert call is not None
        self.assertTrue(call.is_call)

    def test_in_function_jump_never_becomes_a_propagation_step(self) -> None:
        # foo jumps to foo+0x40; bar is a separate function.  A jump is not a
        # call edge, so the trace cannot use it to reach bar.
        instructions = [
            _instruction(0x1000, "jal", ["ra", "0x3000"], "jal ra,0x3000"),
            _instruction(0x1004, "j", ["0x1040"], "j 0x1040"),
            _instruction(0x1040, "ret", [], "ret"),
        ]
        foo = _function("foo", 0x1000, instructions)
        bar_instructions = [
            _instruction(0x3000, "jal", ["ra", "0x4000"], "jal ra,0x4000"),
            _instruction(0x3004, "ret", [], "ret"),
        ]
        bar = _function("bar", 0x3000, bar_instructions)
        host_instructions = [_instruction(0x4000, "ret", [], "ret")]
        host = _function("host", 0x4000, host_instructions)
        program = _program(foo, bar, host)

        result = callgraph_only_result(program, 0x1000, 0x4000)
        # foo -> bar -> host exists via calls, so reachability sees it ...
        self.assertEqual(result.grade, "callgraph-path-only")
        # ... but the intra-function jump at 0x1004 must never appear as a hop.
        for step in trace_source_propagation(
            program,
            {},
            StackObjectId(IRREDUCIBLE_SOURCE, "1000"),
            0x1000,
            0x4000,
        ).steps:
            self.assertNotEqual(step.call_site, 0x1004)


class NonActiveFirstEdgeTests(unittest.TestCase):
    """A reachable call that does not carry the object is not a conduit."""

    @staticmethod
    def _chain_program():
        """src --call--> mid --call--> host, with nothing live anywhere."""

        src = _function(
            "src",
            0x1000,
            [
                _instruction(0x1000, "jal", ["ra", "0x2000"], "jal ra,0x2000"),
                _instruction(0x1004, "ret", [], "ret"),
            ],
        )
        mid = _function(
            "mid",
            0x2000,
            [
                _instruction(0x2000, "jal", ["ra", "0x3000"], "jal ra,0x3000"),
                _instruction(0x2004, "ret", [], "ret"),
            ],
        )
        host = _function(
            "host",
            0x3000,
            [_instruction(0x3000, "ret", [], "ret")],
        )
        # ``_CallTargetResolver`` keys on ``jump_targets``; the CFG builder
        # fills that for real programs and the helper above mirrors it.
        program = _program(src, mid, host)
        empty = {
            function.start: StackFunctionLiveness(
                function_start=function.start,
                live_before={},
                accesses={},
            )
            for function in program.functions
        }
        return program, empty

    def test_callgraph_path_without_activity_is_not_propagation(self) -> None:
        program, empty = self._chain_program()
        marker = StackObjectId(IRREDUCIBLE_SOURCE, "1000")

        weak = callgraph_only_result(program, 0x1000, 0x3000)
        self.assertEqual(weak.grade, "callgraph-path-only")
        self.assertFalse(weak.is_propagation_evidence)

        strong = trace_source_propagation(program, empty, marker, 0x1000, 0x3000)
        self.assertNotEqual(strong.grade, "analysis-trace")
        self.assertFalse(strong.is_propagation_evidence)
        self.assertEqual(strong.first_edge_carried_object, False)

    def test_active_first_edge_upgrades_the_trace_to_propagation_evidence(
        self,
    ) -> None:
        program, empty = self._chain_program()
        marker = StackObjectId(IRREDUCIBLE_SOURCE, "1000")
        # Seed: the original object is live at the first call.  The second hop
        # deliberately does NOT carry the original object -- see
        # ``ProductionInheritanceTests`` for the production representation.
        empty[0x1000] = StackFunctionLiveness(
            function_start=0x1000,
            live_before={0x1000: frozenset({marker})},
            accesses={},
        )

        result = trace_source_propagation(program, empty, marker, 0x1000, 0x3000)
        self.assertEqual(result.grade, "analysis-trace")
        self.assertTrue(result.is_propagation_evidence)
        self.assertTrue(result.first_edge_carried_object)
        self.assertEqual([step.call_site for step in result.steps], [0x1000, 0x2000])
        # Exactly the first hop is the seed; the second carries the source id.
        self.assertEqual([step.first_hop for step in result.steps], [True, False])
        self.assertTrue(all(step.source_id == str(marker) for step in result.steps))

    def test_describe_never_claims_evidence_for_the_weak_grade(self) -> None:
        program, empty = self._chain_program()
        weak = describe(
            callgraph_only_result(program, 0x1000, 0x3000)
        )
        self.assertFalse(weak["is_propagation_evidence"])
        self.assertEqual(weak["grade"], "callgraph-path-only")


class RealLayoutSeedTests(unittest.TestCase):
    """On the real fixture, the first hop must be an object-active call."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.program = fixture.load_program()
        cls.function = fixture.function(cls.program, LAYOUT)
        extension = None
        from chimera.preprocess.offline.analysis.arch.riscv.rvv.services import (
            RvvServices,
        )

        extension = RvvServices()
        cls.result = StackLivenessAnalyzer(
            min_vlen_bits=256,
            semantics=extension.stack_semantics,
            emit_warnings=False,
        ).analyze_program(
            cls.program,
            metadata=ChimeraMetadata.empty(),
            config_results=extension.vector_configs(cls.program),
        )
        cls.marker = StackObjectId(IRREDUCIBLE_SOURCE, f"{cls.function.start:x}")

    def test_layout_has_object_active_seed_calls(self) -> None:
        # Seeds: call sites inside layout whose live set carries the object.
        # This is the set the propagation may start from -- including calls
        # whose callee is outside the fixture and therefore not walkable here.
        sites = object_active_call_sites(
            self.program,
            self.result.by_function,
            self.marker,
            caller_start=LAYOUT_START,
        )
        self.assertTrue(sites)

        # Conduits: only resolved in-program edges.  The fixture contains just
        # five functions, so this subset may be smaller than the seed set --
        # which is exactly why the two must not be conflated.
        edges = active_call_edges(
            self.program,
            self.result.by_function,
            self.marker,
            metadata=ChimeraMetadata.empty(),
        )
        carried = [
            e for e in edges if e.first_hop_active and e.caller_start == LAYOUT_START
        ]
        for edge in carried:
            self.assertTrue(edge.targets)
        for edge in carried:
            self.assertIn(edge.call_site, sites)

    def test_incomplete_coverage_keeps_the_object_active_seed_calls(self) -> None:
        """An empty stack-object section is incomplete coverage, not silence.

        Under the previous rule the forced "section present, zero records"
        state selected metadata mode and every source of ``layout`` simply
        disappeared.  Coverage is now decided per function, so the function
        falls back to binary recovery and its seeds are still there.
        """

        from chimera.preprocess.offline.analysis.arch.riscv.rvv.services import (
            RvvServices,
        )

        extension = RvvServices()
        metadata_result = StackLivenessAnalyzer(
            min_vlen_bits=256,
            semantics=extension.stack_semantics,
            emit_warnings=False,
        ).analyze_program(
            self.program,
            metadata=forced_metadata_mode(),
            config_results=extension.vector_configs(self.program),
        )
        binary_sites = object_active_call_sites(
            self.program,
            self.result.by_function,
            self.marker,
            caller_start=LAYOUT_START,
        )
        fallback_sites = object_active_call_sites(
            self.program,
            metadata_result.by_function,
            self.marker,
            caller_start=LAYOUT_START,
        )
        self.assertTrue(binary_sites)
        self.assertEqual(fallback_sites, binary_sites)
        self.assertEqual(
            metadata_result.by_function[LAYOUT_START].access_mode,
            "binary-incomplete-coverage",
        )

    def test_complete_coverage_has_no_object_active_seed_calls(self) -> None:
        """Only a mapping that really covers the function removes the seeds."""

        from chimera.preprocess.offline.analysis.arch.riscv.rvv.services import (
            RvvServices,
        )

        extension = RvvServices()
        metadata_result = StackLivenessAnalyzer(
            min_vlen_bits=256,
            semantics=extension.stack_semantics,
            emit_warnings=False,
        ).analyze_program(
            self.program,
            metadata=complete_coverage_metadata(self.program, self.function),
            config_results=extension.vector_configs(self.program),
        )
        self.assertEqual(
            object_active_call_sites(
                self.program,
                metadata_result.by_function,
                self.marker,
                caller_start=LAYOUT_START,
            ),
            [],
        )
        self.assertEqual(
            metadata_result.by_function[LAYOUT_START].access_mode,
            "metadata-complete-coverage",
        )

    def test_trace_downgrades_when_the_object_never_reaches_the_host(self) -> None:
        # Pick a host that is not in the fixture (no function at 0x3f176):
        # the forward trace must not invent a path to it.
        result = trace_source_propagation(
            self.program,
            self.result.by_function,
            self.marker,
            LAYOUT_START,
            0x3F176,
            metadata=ChimeraMetadata.empty(),
        )
        self.assertNotEqual(result.grade, "analysis-trace")
        self.assertFalse(result.is_propagation_evidence)


class ProductionInheritanceTests(unittest.TestCase):
    """Two hops using the production ``InheritedLivenessView`` representation.

    The intermediate function carries ``caller:inherited-stack-data``, **not**
    the original object id.  Requiring the original id on hop 2+ would reject
    this real chain.
    """

    def test_two_hop_chain_through_the_shared_caller_marker(self) -> None:
        src = _function(
            "src",
            0x1000,
            [
                _instruction(0x1000, "jal", ["ra", "0x2000"], "jal ra,0x2000"),
                _instruction(0x1004, "ret", [], "ret"),
            ],
        )
        mid = _function(
            "mid",
            0x2000,
            [
                _instruction(0x2000, "jal", ["ra", "0x3000"], "jal ra,0x3000"),
                _instruction(0x2004, "ret", [], "ret"),
            ],
        )
        host = _function(
            "host",
            0x3000,
            [_instruction(0x3000, "ret", [], "ret")],
        )
        program = _program(src, mid, host)
        marker = StackObjectId(IRREDUCIBLE_SOURCE, "1000")

        # Production shape: the source owns the object; the callee is entered
        # into the inherited closure and gets the shared marker only.
        local = {
            0x1000: StackFunctionLiveness(
                function_start=0x1000,
                live_before={0x1000: frozenset({marker})},
                accesses={},
            ),
            0x2000: StackFunctionLiveness(
                function_start=0x2000,
                live_before=InheritedLivenessView(
                    {0x2000: frozenset()}, CALLER_MARKER
                ),
                accesses={},
            ),
            0x3000: StackFunctionLiveness(
                function_start=0x3000,
                live_before=InheritedLivenessView(
                    {0x3000: frozenset()}, CALLER_MARKER
                ),
                accesses={},
            ),
        }
        # The mid hop really carries only the shared marker -- assert that
        # first so a future change back to "original object every hop" fails
        # for the right reason.
        self.assertIn(CALLER_MARKER, local[0x2000].live_before[0x2000])
        self.assertNotIn(marker, local[0x2000].live_before[0x2000])

        result = trace_source_propagation(program, local, marker, 0x1000, 0x3000)
        self.assertEqual(result.grade, "analysis-trace")
        self.assertEqual([step.call_site for step in result.steps], [0x1000, 0x2000])
        self.assertEqual([step.first_hop for step in result.steps], [True, False])

    def test_shared_caller_marker_alone_is_not_proof_of_this_source(self) -> None:
        # mid is in some inherited closure (marker live) but src never handed
        # our object over.  The shared marker must not be read as "from layout".
        src = _function(
            "src",
            0x1000,
            [
                _instruction(0x1000, "jal", ["ra", "0x2000"], "jal ra,0x2000"),
                _instruction(0x1004, "ret", [], "ret"),
            ],
        )
        mid = _function(
            "mid",
            0x2000,
            [
                _instruction(0x2000, "jal", ["ra", "0x3000"], "jal ra,0x3000"),
                _instruction(0x2004, "ret", [], "ret"),
            ],
        )
        host = _function(
            "host",
            0x3000,
            [_instruction(0x3000, "ret", [], "ret")],
        )
        program = _program(src, mid, host)
        marker = StackObjectId(IRREDUCIBLE_SOURCE, "1000")
        local = {
            0x1000: StackFunctionLiveness(
                function_start=0x1000,
                live_before={},
                accesses={},
            ),
            0x2000: StackFunctionLiveness(
                function_start=0x2000,
                live_before=InheritedLivenessView({}, CALLER_MARKER),
                accesses={},
            ),
            0x3000: StackFunctionLiveness(
                function_start=0x3000,
                live_before=InheritedLivenessView({}, CALLER_MARKER),
                accesses={},
            ),
        }
        result = trace_source_propagation(program, local, marker, 0x1000, 0x3000)
        self.assertNotEqual(result.grade, "analysis-trace")
        self.assertFalse(result.is_propagation_evidence)


class ConvergingSourcesTests(unittest.TestCase):
    """Two distinct sources reaching one host must not swap identities."""

    def test_each_source_keeps_its_own_path_and_source_id(self) -> None:
        # A(0x1000) --0x1000--> mid(0x2000) --0x2000--> host(0x3000)
        # B(0x4000) --0x4000--> mid(0x2000) --0x2000--> host(0x3000)
        a = _function(
            "a",
            0x1000,
            [
                _instruction(0x1000, "jal", ["ra", "0x2000"], "jal ra,0x2000"),
                _instruction(0x1004, "ret", [], "ret"),
            ],
        )
        b = _function(
            "b",
            0x4000,
            [
                _instruction(0x4000, "jal", ["ra", "0x2000"], "jal ra,0x2000"),
                _instruction(0x4004, "ret", [], "ret"),
            ],
        )
        mid = _function(
            "mid",
            0x2000,
            [
                _instruction(0x2000, "jal", ["ra", "0x3000"], "jal ra,0x3000"),
                _instruction(0x2004, "ret", [], "ret"),
            ],
        )
        host = _function(
            "host",
            0x3000,
            [_instruction(0x3000, "ret", [], "ret")],
        )
        program = _program(a, b, mid, host)
        marker_a = StackObjectId(IRREDUCIBLE_SOURCE, "1000")
        marker_b = StackObjectId(IRREDUCIBLE_SOURCE, "4000")
        local = {
            0x1000: StackFunctionLiveness(
                function_start=0x1000,
                live_before={0x1000: frozenset({marker_a})},
                accesses={},
            ),
            0x4000: StackFunctionLiveness(
                function_start=0x4000,
                live_before={0x4000: frozenset({marker_b})},
                accesses={},
            ),
            0x2000: StackFunctionLiveness(
                function_start=0x2000,
                live_before=InheritedLivenessView({}, CALLER_MARKER),
                accesses={},
            ),
            0x3000: StackFunctionLiveness(
                function_start=0x3000,
                live_before=InheritedLivenessView({}, CALLER_MARKER),
                accesses={},
            ),
        }

        trace_a = trace_source_propagation(program, local, marker_a, 0x1000, 0x3000)
        trace_b = trace_source_propagation(program, local, marker_b, 0x4000, 0x3000)

        self.assertEqual(trace_a.grade, "analysis-trace")
        self.assertEqual(trace_b.grade, "analysis-trace")

        # Each source keeps its own id on every hop -- no swapping.
        self.assertEqual(trace_a.source_id, str(marker_a))
        self.assertEqual(trace_b.source_id, str(marker_b))
        self.assertTrue(all(s.source_id == str(marker_a) for s in trace_a.steps))
        self.assertTrue(all(s.source_id == str(marker_b) for s in trace_b.steps))

        # The first hop is each source's own seed call, never the other's.
        self.assertEqual(trace_a.steps[0].call_site, 0x1000)
        self.assertEqual(trace_b.steps[0].call_site, 0x4000)
        self.assertNotIn(0x4000, [s.call_site for s in trace_a.steps])
        self.assertNotIn(0x1000, [s.call_site for s in trace_b.steps])

        # The shared mid hop is present in both (they really converge) but is
        # attributed to the right parent each time.
        mid_hop_a = next(s for s in trace_a.steps if s.callee == 0x2000)
        mid_hop_b = next(s for s in trace_b.steps if s.callee == 0x2000)
        self.assertEqual(mid_hop_a.caller, 0x1000)
        self.assertEqual(mid_hop_b.caller, 0x4000)


class InheritanceBindingTests(unittest.TestCase):
    """An inheritance report must be bound to the audited ELF."""

    SHA = "3b022cb21ef1e5ce80768ac84a8862f14bbf568650b28c75210d884c46a65e1d"
    OTHER = "a2bea33939ed6e6aa6b7aa7e5032ecbd5f561493b96d7c1e765430dde8baa012"

    @staticmethod
    def _document(digest: str, fmt: str = "chimera-inheritance-diagnostics-v2"):
        return {
            "format": fmt,
            "elf": {"path": "/x/xgcc", "content_sha256": digest},
            "seed_edges": [
                {
                    "caller_function_ref": 0,
                    "call_site": "0x1000",
                    "reason": "seed",
                    "depth": 1,
                    "local_active_objects": [
                        {"id": "irreducible:1000", "metadata_source": "irreducible"}
                    ],
                }
            ],
        }

    def _write(self, payload: dict) -> Path:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        path = Path(temporary.name) / "inheritance.json"
        path.write_text(json.dumps(payload), encoding="utf-8")
        return path

    def test_matching_digest_is_accepted(self) -> None:
        document, reason = load_inheritance(
            self._write(self._document(self.SHA)), self.SHA
        )
        self.assertEqual(reason, "")
        self.assertIsNotNone(document)

    def test_wrong_elf_digest_refuses_the_upgrade(self) -> None:
        # Same addresses, different binary: must NOT upgrade.
        document, reason = load_inheritance(
            self._write(self._document(self.OTHER)), self.SHA
        )
        self.assertIsNone(document)
        self.assertIn("different ELF", reason)

    def test_missing_digest_refuses_the_upgrade(self) -> None:
        payload = self._document(self.SHA)
        payload["elf"] = {"path": "/x/xgcc"}
        document, reason = load_inheritance(self._write(payload), self.SHA)
        self.assertIsNone(document)
        self.assertIn("content_sha256", reason)

    def test_unknown_format_refuses_the_upgrade(self) -> None:
        document, reason = load_inheritance(
            self._write(self._document(self.SHA, fmt="something-else")), self.SHA
        )
        self.assertIsNone(document)
        self.assertIn("unknown inheritance format", reason)

    def test_absent_file_refuses_the_upgrade(self) -> None:
        document, reason = load_inheritance(
            Path(tempfile.gettempdir()) / "no-such-inheritance.json", self.SHA
        )
        self.assertIsNone(document)
        self.assertIn("no inheritance report", reason)

    def test_unbound_report_caps_the_grade_at_callgraph_only(self) -> None:
        # The graph really reaches the host, and the report names a seed --
        # but the report is not bound to this ELF, so the grade must not rise.
        src = _function(
            "src",
            0x1000,
            [
                _instruction(0x1000, "jal", ["ra", "0x2000"], "jal ra,0x2000"),
                _instruction(0x1004, "ret", [], "ret"),
            ],
        )
        mid = _function(
            "mid",
            0x2000,
            [
                _instruction(0x2000, "jal", ["ra", "0x3000"], "jal ra,0x3000"),
                _instruction(0x2004, "ret", [], "ret"),
            ],
        )
        host = _function(
            "host",
            0x3000,
            [_instruction(0x3000, "ret", [], "ret")],
        )
        program = _program(src, mid, host)
        edges = resolved_call_edges(program)

        bound_result = trace_from_inheritance(
            self._document(self.SHA),
            call_edges=edges,
            source_object_id="irreducible:1000",
            source_start=0x1000,
            host_start=0x3000,
            inheritance_bound=True,
        )
        self.assertEqual(bound_result.grade, "analysis-trace")

        unbound_result = trace_from_inheritance(
            self._document(self.OTHER),
            call_edges=edges,
            source_object_id="irreducible:1000",
            source_start=0x1000,
            host_start=0x3000,
            inheritance_bound=False,
        )
        self.assertNotEqual(unbound_result.grade, "analysis-trace")
        self.assertFalse(unbound_result.is_propagation_evidence)
        self.assertIn("not bound", unbound_result.reason)

    def test_generic_caller_marker_is_never_a_seed(self) -> None:
        document = self._document(self.SHA)
        document["seed_edges"][0]["local_active_objects"] = [
            {"id": "caller:inherited-stack-data", "metadata_source": "caller"}
        ]
        self.assertEqual(
            seeds_from_inheritance(document, str(CALLER_MARKER), 0x1000), []
        )
        self.assertEqual(
            seeds_from_inheritance(document, "irreducible:1000", 0x1000), []
        )


class ScriptUsesTheUnifiedEntryTests(unittest.TestCase):
    """The forensics script must call the testable entry, not a private walk.

    Reconciled with the thin-driver form (``layout_forensics_driver.run_trace``):
    the grading rules no longer live in the script at all, so these pins check
    that the script delegates and stays free of the old inline walk.
    """

    def test_script_imports_under_isolated_python_outside_checkout(self) -> None:
        import subprocess
        import sys

        root = Path(__file__).resolve().parents[1]
        script = (root / "tools/k3-forensics-layout-metadata.sh").read_text(
            encoding="utf-8"
        )
        # Execute the launcher's import shim exactly as the shell expands it.
        # -I hides cwd/PYTHONPATH, as on K3.
        program = script.split('-c "', 1)[1].split('" || true', 1)[0]
        program = program.replace("$CHIMERA", str(root))
        program = program.split("run_trace(", 1)[0]
        with tempfile.TemporaryDirectory() as directory:
            completed = subprocess.run(
                [sys.executable, "-I", "-c", program],
                capture_output=True, text=True, cwd=directory,
            )
        self.assertEqual(completed.returncode, 0, completed.stderr)

    def test_script_calls_the_driver_entry_not_a_private_walk(self) -> None:
        root = Path(__file__).resolve().parents[1]
        script = (root / "tools" / "k3-forensics-layout-metadata.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn("from layout_forensics_driver import", script)
        self.assertIn("run_trace(", script)
        # The old inline walk is gone: no private BFS, no name-substring
        # target resolution, no parallel grading table in the script.
        self.assertNotIn("candidate in rest", script)
        self.assertNotIn("line_by_caller", script)
        self.assertNotIn("trace_from_inheritance", script)
        self.assertNotIn("call_edges_from_objdump", script)
        # Grading vocabulary is still surfaced (driver log + summary grep).
        self.assertIn("is_propagation_evidence", script)
        self.assertIn("g2_filled", script)
        self.assertIn("path_grade", script)
        self.assertIn("callgraph-path-only", script)

    def test_script_leaves_trace_from_elf_out_of_the_script(self) -> None:
        root = Path(__file__).resolve().parents[1]
        script = (root / "tools" / "k3-forensics-layout-metadata.sh").read_text(
            encoding="utf-8"
        )
        driver = (root / "tests" / "layout_forensics_driver.py").read_text(
            encoding="utf-8"
        )
        # Strong evidence comes from the production pipeline; the script must
        # not reload the Program (trace_from_elf) or grade anything itself.
        self.assertNotIn("trace_from_elf", script)
        self.assertNotIn("load_production_program", script)
        self.assertNotIn("resolved_call_edges", script)
        self.assertNotIn('path_grade == "production"', script)
        # The production grading rule lives in the driver, unchanged.
        self.assertIn("trace_from_bound_edges", driver)
        self.assertIn('path_grade == "production"', driver)
        self.assertNotIn("trace_from_elf(", driver)


class InventedTargetTests(unittest.TestCase):
    """A target that is not a function entry must not become an edge.

    Reviewer repro: ``layout=0x1000 middle=0x2000 host=0x8000`` with real
    calls ``layout -> middle`` and ``middle -> 0x9000 <external@plt>``.  The
    old ``function_at`` containment lookup attributed ``0x9000`` to ``host``
    and invented ``layout -> middle -> host``, which would then grade
    ``analysis-trace``.  No call in the binary ever points at ``host``.
    """

    FUNCTIONS = ((0x1000, "layout"), (0x2000, "middle"), (0x8000, "host"))
    LINES = {
        "layout": ["   1000:\t34d000ef           \tjal\t2000 <middle>"],
        "middle": ["   2000:\t34d000ef           \tjal\t9000 <external@plt>"],
    }

    def test_function_at_does_not_claim_out_of_range_addresses(self) -> None:
        # 0x9000 is past host's entry and host has no known end; without an
        # explicit end it must not swallow a foreign address either when the
        # caller asks for a bounded lookup.
        self.assertEqual(
            function_at(self.FUNCTIONS, 0x9000, ends={0x8000: 0x8100}), None
        )
        self.assertEqual(
            function_at(self.FUNCTIONS, 0x8500, ends={0x8000: 0x8100}), None
        )
        # Containment still works inside a known range.
        self.assertEqual(
            function_at(self.FUNCTIONS, 0x2004, ends={0x2000: 0x3000}),
            (0x2000, "middle"),
        )

    def test_resolve_call_target_requires_an_exact_entry(self) -> None:
        entries = {start: name for start, name in self.FUNCTIONS}
        self.assertEqual(resolve_call_target(entries, 0x2000), 0x2000)
        # A call to external@plt is NOT a call to host.
        self.assertIsNone(resolve_call_target(entries, 0x9000))
        # Mid-body addresses are not entries either.
        self.assertIsNone(resolve_call_target(entries, 0x2004))
        self.assertIsNone(resolve_call_target(entries, 0x8500))
        self.assertIsNone(resolve_call_target(entries, None))
        # External trampolines stop at the binary boundary.
        self.assertIsNone(
            resolve_call_target(entries, 0x2000, external_trampolines={0x2000})
        )

    def test_external_plt_target_does_not_invent_a_host_edge(self) -> None:
        edges = call_edges_from_objdump(self.FUNCTIONS, self.LINES)
        pairs = {
            (edge.caller_start, edge.targets) for edge in edges
        }
        # The real edge survives ...
        self.assertIn((0x1000, (0x2000,)), pairs)
        # ... and the invented one is gone.  This is the whole point:
        # nothing may claim middle -> host.
        self.assertNotIn((0x2000, (0x8000,)), pairs)
        self.assertFalse(
            any(edge.caller_start == 0x2000 for edge in edges),
            f"invented edge from middle: {edges}",
        )

    def test_unresolved_target_keeps_the_gap_rather_than_walking_on(self) -> None:
        edges = call_edges_from_objdump(self.FUNCTIONS, self.LINES)
        by_caller = {edge.caller_start: edge for edge in edges}
        # middle's only call is unresolved; the graph simply stops there.
        self.assertNotIn(0x2000, by_caller)

    def test_traced_path_cannot_reach_host_when_no_edge_points_at_it(self) -> None:
        marker = StackObjectId(IRREDUCIBLE_SOURCE, "1000")
        document = {
            "format": "chimera-inheritance-diagnostics-v2",
            "elf": {"content_sha256": "00" * 32},
            "seed_edges": [
                {
                    "caller_function_ref": 0,
                    "call_site": "0x1000",
                    "reason": "seed",
                    "depth": 1,
                    "local_active_objects": [{"id": "irreducible:1000"}],
                }
            ],
        }
        edges = call_edges_from_objdump(self.FUNCTIONS, self.LINES)
        result = trace_from_inheritance(
            document,
            call_edges=edges,
            source_object_id="irreducible:1000",
            source_start=0x1000,
            host_start=0x8000,
            inheritance_bound=True,
        )
        # Even with a correctly bound inheritance report the invented edge
        # must not exist, so the host is unreachable and the grade stays low.
        self.assertNotEqual(result.grade, "analysis-trace")
        self.assertFalse(result.is_propagation_evidence)

    def test_disassembly_edges_cannot_authorise_analysis_trace(self) -> None:
        # Same shape but with a *real* middle -> host edge that exists.  The
        # edges are still disassembly-suspected, so the grade must be capped
        # even though inheritance is bound and the path is real.
        functions = ((0x1000, "layout"), (0x2000, "middle"), (0x8000, "host"))
        lines = {
            "layout": ["   1000:\t34d000ef           \tjal\t2000 <middle>"],
            "middle": ["   2000:\t34d000ef           \tjal\t8000 <host>"],
        }
        document = {
            "format": "chimera-inheritance-diagnostics-v2",
            "elf": {"content_sha256": "00" * 32},
            "seed_edges": [
                {
                    "caller_function_ref": 0,
                    "call_site": "0x1000",
                    "reason": "seed",
                    "depth": 1,
                    "local_active_objects": [{"id": "irreducible:1000"}],
                }
            ],
        }
        edges = call_edges_from_objdump(functions, lines)
        result = trace_from_inheritance(
            document,
            call_edges=edges,
            source_object_id="irreducible:1000",
            source_start=0x1000,
            host_start=0x8000,
            inheritance_bound=True,
        )
        self.assertEqual(result.grade, "callgraph-path-only")
        self.assertFalse(result.is_propagation_evidence)
        self.assertIn("disassembly-suspected", result.reason)

        # The analyzer-resolved equivalent of the same two hops does qualify.
        analyzer_edges = [
            CallEdge(
                call_site=0x1000,
                caller_start=0x1000,
                targets=(0x2000,),
                first_hop_active=False,
                resolved_by="analyzer",
            ),
            CallEdge(
                call_site=0x2000,
                caller_start=0x2000,
                targets=(0x8000,),
                first_hop_active=False,
                resolved_by="analyzer",
            ),
        ]
        strong = trace_from_inheritance(
            document,
            call_edges=analyzer_edges,
            source_object_id="irreducible:1000",
            source_start=0x1000,
            host_start=0x8000,
            inheritance_bound=True,
        )
        self.assertEqual(strong.grade, "analysis-trace")
        self.assertTrue(strong.is_propagation_evidence)


class ProductionResolvedPathTests(unittest.TestCase):
    """``trace_from_elf`` is the only path that may authorise ``analysis-trace``.

    It builds a real ``Program`` through the production parse/CFG pipeline
    (``LinuxObjdump`` + ``parse_dump`` + ``RiscvServices.build_cfg``), a real
    ``ChimeraMetadata``, and call edges from the production
    ``_CallTargetResolver`` -- every edge ``resolved_by="analyzer"``.
    """

    DUMP = r"""
0000000000001000 <src>:
    1000:	34d000ef          	jal	2000 <mid>
    1004:	00008067          	ret
0000000000002000 <mid>:
    2000:	34d000ef          	jal	8000 <host>
    2004:	00008067          	ret
0000000000008000 <host>:
    8000:	00008067          	ret
"""

    def _document(self, digest: str) -> dict:
        return {
            "format": "chimera-inheritance-diagnostics-v2",
            "elf": {"path": "/x/x", "content_sha256": digest},
            "seed_edges": [
                {
                    "caller_function_ref": 0,
                    "call_site": "0x1000",
                    "reason": "seed",
                    "depth": 1,
                    "local_active_objects": [{"id": "irreducible:1000"}],
                }
            ],
        }

    def _write(self, payload: dict) -> Path:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        path = Path(temporary.name) / "inheritance.json"
        path.write_text(json.dumps(payload), encoding="utf-8")
        return path

    def test_production_pipeline_yields_analyzer_edges(self) -> None:
        program, metadata = load_production_program(
            dump_text=self.DUMP, metadata=ChimeraMetadata.empty()
        )
        starts = {function.start for function in program.functions}
        self.assertEqual(starts, {0x1000, 0x2000, 0x8000})
        edges = resolved_call_edges(program, metadata=metadata)
        self.assertTrue(edges)
        self.assertTrue(all(edge.resolved_by == "analyzer" for edge in edges))
        pairs = {(edge.caller_start, edge.targets) for edge in edges}
        self.assertIn((0x1000, (0x2000,)), pairs)
        self.assertIn((0x2000, (0x8000,)), pairs)

    def test_function_containing_uses_real_instruction_bounds(self) -> None:
        program, _ = load_production_program(
            dump_text=self.DUMP, metadata=ChimeraMetadata.empty()
        )
        self.assertEqual(function_containing(program, 0x2004), (0x2000, "mid"))
        self.assertEqual(function_containing(program, 0x8000), (0x8000, "host"))
        # Past the last instruction of the last function: not swallowed.
        self.assertIsNone(function_containing(program, 0x9000))

    def test_bound_inheritance_on_production_edges_is_analysis_trace(self) -> None:
        digest = "11" * 32
        result = trace_from_elf(
            dump_text=self.DUMP,
            metadata=ChimeraMetadata.empty(),
            inheritance_path=self._write(self._document(digest)),
            source_start=0x1000,
            host_start=0x8000,
            source_object_id="irreducible:1000",
            expected_sha256=digest,
        )
        self.assertEqual(result.grade, "analysis-trace")
        self.assertTrue(result.is_propagation_evidence)
        self.assertEqual([step.call_site for step in result.steps], [0x1000, 0x2000])
        self.assertEqual([step.first_hop for step in result.steps], [True, False])

    def test_unbound_inheritance_on_production_edges_stays_low(self) -> None:
        import contextlib
        import io

        captured = io.StringIO()
        with contextlib.redirect_stdout(captured):
            result = trace_from_elf(
                dump_text=self.DUMP,
                metadata=ChimeraMetadata.empty(),
                inheritance_path=self._write(self._document("22" * 32)),
                source_start=0x1000,
                host_start=0x8000,
                source_object_id="irreducible:1000",
                expected_sha256="11" * 32,
            )
        self.assertNotEqual(result.grade, "analysis-trace")
        self.assertFalse(result.is_propagation_evidence)
        # The delegation must keep surfacing the refusal reason.
        self.assertIn("inheritance refused:", captured.getvalue())

    def test_missing_inheritance_stays_low_even_with_production_edges(self) -> None:
        result = trace_from_elf(
            dump_text=self.DUMP,
            metadata=ChimeraMetadata.empty(),
            inheritance_path=None,
            source_start=0x1000,
            host_start=0x8000,
            source_object_id="irreducible:1000",
            expected_sha256="11" * 32,
        )
        self.assertNotEqual(result.grade, "analysis-trace")
        self.assertFalse(result.is_propagation_evidence)

    def test_unresolvable_targets_do_not_invent_edges(self) -> None:
        # mid calls external@plt, which is not a program function.  The
        # production resolver drops it; no edge may reach host.
        dump = r"""
0000000000001000 <src>:
    1000:	34d000ef          	jal	2000 <mid>
    1004:	00008067          	ret
0000000000002000 <mid>:
    2000:	34d000ef          	jal	9000 <external@plt>
    2004:	00008067          	ret
0000000000008000 <host>:
    8000:	00008067          	ret
"""
        program, metadata = load_production_program(
            dump_text=dump, metadata=ChimeraMetadata.empty()
        )
        edges = resolved_call_edges(program, metadata=metadata)
        pairs = {(edge.caller_start, edge.targets) for edge in edges}
        self.assertIn((0x1000, (0x2000,)), pairs)
        self.assertNotIn((0x2000, (0x8000,)), pairs)

        digest = "33" * 32
        result = trace_from_elf(
            dump_text=dump,
            metadata=ChimeraMetadata.empty(),
            inheritance_path=self._write(self._document(digest)),
            source_start=0x1000,
            host_start=0x8000,
            source_object_id="irreducible:1000",
            expected_sha256=digest,
        )
        self.assertNotEqual(result.grade, "analysis-trace")
        self.assertFalse(result.is_propagation_evidence)


class BoundEdgesHelperTests(unittest.TestCase):
    """``trace_from_bound_edges`` must match ``trace_from_elf`` grading.

    It receives edges that already exist, so it must never reload the
    Program.  Edge-source checks stay: disassembly edges still cannot
    authorise ``analysis-trace``.
    """

    SHA = "ab" * 32

    @staticmethod
    def _document(digest: str) -> dict:
        return {
            "format": "chimera-inheritance-diagnostics-v2",
            "elf": {"path": "/x/x", "content_sha256": digest},
            "seed_edges": [
                {
                    "caller_function_ref": 0,
                    "call_site": "0x1000",
                    "reason": "seed",
                    "depth": 1,
                    "local_active_objects": [{"id": "irreducible:1000"}],
                }
            ],
        }

    def _write(self, payload: dict) -> Path:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        path = Path(temporary.name) / "inheritance.json"
        path.write_text(json.dumps(payload), encoding="utf-8")
        return path

    @staticmethod
    def _analyzer_edges() -> list:
        return [
            CallEdge(
                call_site=0x1000,
                caller_start=0x1000,
                targets=(0x2000,),
                first_hop_active=False,
                resolved_by="analyzer",
            ),
            CallEdge(
                call_site=0x2000,
                caller_start=0x2000,
                targets=(0x8000,),
                first_hop_active=False,
                resolved_by="analyzer",
            ),
        ]

    def test_bound_edges_on_analyzer_edges_is_analysis_trace(self) -> None:
        result = trace_from_bound_edges(
            self._analyzer_edges(),
            inheritance_path=self._write(self._document(self.SHA)),
            expected_sha256=self.SHA,
            source_object_id="irreducible:1000",
            source_start=0x1000,
            host_start=0x8000,
        )
        self.assertEqual(result.grade, "analysis-trace")
        self.assertTrue(result.is_propagation_evidence)
        self.assertEqual([s.call_site for s in result.steps], [0x1000, 0x2000])

    def test_bound_edges_without_inheritance_stays_low(self) -> None:
        result = trace_from_bound_edges(
            self._analyzer_edges(),
            inheritance_path=None,
            expected_sha256=self.SHA,
            source_object_id="irreducible:1000",
            source_start=0x1000,
            host_start=0x8000,
        )
        self.assertNotEqual(result.grade, "analysis-trace")
        self.assertFalse(result.is_propagation_evidence)

    def test_bound_edges_with_wrong_elf_stays_low(self) -> None:
        refusals: list[str] = []
        result = trace_from_bound_edges(
            self._analyzer_edges(),
            inheritance_path=self._write(self._document("cd" * 32)),
            expected_sha256=self.SHA,
            source_object_id="irreducible:1000",
            source_start=0x1000,
            host_start=0x8000,
            on_refused=refusals.append,
        )
        self.assertNotEqual(result.grade, "analysis-trace")
        self.assertFalse(result.is_propagation_evidence)
        # The bind-failure reason must reach the caller, not be discarded.
        self.assertEqual(len(refusals), 1)
        self.assertIn("different ELF", refusals[0])

    def test_disassembly_edges_stay_capped(self) -> None:
        edges = [
            CallEdge(
                call_site=site,
                caller_start=caller,
                targets=(callee,),
                first_hop_active=False,
                resolved_by="disassembly",
            )
            for site, caller, callee in ((0x1000, 0x1000, 0x2000), (0x2000, 0x2000, 0x8000))
        ]
        result = trace_from_bound_edges(
            edges,
            inheritance_path=self._write(self._document(self.SHA)),
            expected_sha256=self.SHA,
            source_object_id="irreducible:1000",
            source_start=0x1000,
            host_start=0x8000,
        )
        self.assertEqual(result.grade, "callgraph-path-only")
        self.assertFalse(result.is_propagation_evidence)


class FunctionSummaryTests(unittest.TestCase):
    """The summary must never expand the object graph."""

    def test_summary_is_bounded_and_does_not_call_repr(self) -> None:
        program = fixture.load_program()
        function = fixture.function(program, LAYOUT)
        original = Function.__repr__

        def _forbidden(self):
            raise AssertionError("object-graph repr must not run in forensics logging")

        Function.__repr__ = _forbidden  # type: ignore[method-assign]
        try:
            text = function_summary(function)
        finally:
            Function.__repr__ = original  # type: ignore[method-assign]

        self.assertIn(function.name, text)
        self.assertIn(f"{function.start:#x}", text)
        self.assertIn("insts=", text)
        self.assertIn("blocks=", text)
        self.assertNotIn("Instruction(", text)
        self.assertNotIn("BasicBlock(", text)


if __name__ == "__main__":
    unittest.main()
