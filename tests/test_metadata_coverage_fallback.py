"""Per-function metadata coverage: an uncovered access must never vanish.

The old rule selected the local-analysis mode from the *ELF*: if
``.chimera.stackobj_map`` existed, compiler metadata was authoritative and
every VLEN-sensitive access without a record was silently dropped.  A product
with an empty section, with records for other functions only, or with a partly
instrumented set of translation units therefore looked clean while its sources
were still there -- ``layout`` of the gate-2 ``xgcc`` is the worked example.

The tests below pin the corrected rule:

* coverage is decided per function, from ``U`` versus ``M``;
* an incomplete coverage falls back to binary recovery for the whole function,
  without mixing compiler object ids and binary object ids;
* a complete coverage keeps the metadata route unchanged;
* the fallback never manufactures a conservative source out of an access the
  binary proved to be non-stack, and never adds marks to a function with no
  sensitive access at all;
* the sources the fallback recovers reach the gate candidate list through the
  existing propagation chain, with no hardcoded name.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from elf_fixture import build_elf

import layout_gate_source_fixture as ab
import layout_mode_diagnosis as diag
import xgcc_stack_fixture as fixture

import json

from chimera.check_elf import (
    _diagnostics_payload,
    collect_diagnostics,
    export_inheritance_diagnostics,
)
from chimera.preprocess.offline.analysis.arch.riscv.rvv.services import (
    RiscvStackSemantics,
)
from chimera.preprocess.offline.analysis.core.data_model.program import (
    Function,
    Instruction,
    Program,
)
from chimera.preprocess.offline.analysis.safety.stack_liveness.analyzer import (
    StackLivenessAnalyzer,
)
from chimera.preprocess.offline.analysis.safety.stack_liveness.model import (
    ACTIVE_EXTERNAL_CALL,
    UNRESOLVED_ACTIVE_CALL,
    AccessMode,
    ChimeraMetadata,
    StackObjectId,
)

LAYOUT = fixture.FIXED_FRAME_FUNCTIONS[2]
CLOSE_AT_FILE = fixture.CLOSE_AT_FILE


def _instruction(start: int, index: int, op: str, args: list[str]) -> Instruction:
    return Instruction(
        start + index * 4,
        4,
        op,
        list(args),
        f"{op} " + ",".join(args),
    )


def _linked(instructions: list[Instruction]) -> None:
    for current, following in zip(instructions, instructions[1:]):
        current.succ.add(following.addr)


def _mixed_access_function(start: int = 0x1000) -> Function:
    """One stack store, one *non-stack* store, one stack load, one return.

    Whole-register accesses are VLEN-sensitive regardless of the vector
    configuration, so no vsetivli is needed to build ``U`` here.
    """

    specs = (
        ("vs1r.v", ["v8", "(sp)"]),
        ("vs1r.v", ["v8", "(a0)"]),
        ("vl1r.v", ["v8", "(sp)"]),
        ("ret", []),
    )
    instructions = [
        _instruction(start, index, op, args)
        for index, (op, args) in enumerate(specs)
    ]
    _linked(instructions)
    return Function("mixed", start, instructions)


def _scalar_only_function(start: int = 0x2000) -> Function:
    """A function with no vector memory access at all: ``U`` is empty."""

    instructions = [
        _instruction(start, 0, "addi", ["sp", "sp", "-16"]),
        _instruction(start, 1, "sd", ["ra", "8(sp)"]),
        _instruction(start, 2, "ret", []),
    ]
    _linked(instructions)
    return Function("scalar", start, instructions)


def _program(*functions: Function) -> Program:
    instructions = [item for function in functions for item in function.insts]
    return Program(
        dump_lines=[],
        functions=list(functions),
        instructions=instructions,
        instruction_by_address={item.addr: item for item in instructions},
    )


def _config_result():
    return SimpleNamespace(at=lambda _address: frozenset())


def _analyze(program: Program, metadata: ChimeraMetadata):
    return StackLivenessAnalyzer(
        min_vlen_bits=256,
        semantics=RiscvStackSemantics(),
        emit_warnings=False,
    ).analyze_program(
        program,
        metadata=metadata,
        config_results={
            function.start: _config_result() for function in program.functions
        },
    )


def _elf(root: Path, name: str) -> Path:
    return build_elf(root / name, sections=())


class CoverageFallbackUnitTests(unittest.TestCase):
    """The three coverage states on small, fully controlled programs."""

    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.program = _program(_mixed_access_function())
        self.function = self.program.functions[0]
        self.stack_store = 0x1000
        self.non_stack_store = 0x1004
        self.stack_load = 0x1008

    def _local(self, metadata: ChimeraMetadata):
        return _analyze(self.program, metadata).by_function[self.function.start]

    def test_partial_coverage_sends_the_whole_u_to_binary_recovery(self) -> None:
        # Only the stack store is recorded: coverage is incomplete.
        partial = ChimeraMetadata(
            stack_ids={self.stack_store: 11}, has_stackobj_map_section=True
        )
        local = self._local(partial)

        self.assertFalse(local.metadata_mode if hasattr(local, "metadata_mode") else False)
        self.assertEqual(local.access_mode, AccessMode.BINARY_INCOMPLETE)
        self.assertTrue(local.has_metadata_section)
        self.assertEqual(local.sensitive_access_count, 3)
        self.assertEqual(local.metadata_covered_count, 1)
        self.assertEqual(
            local.uncovered_sensitive_addresses,
            frozenset({self.non_stack_store, self.stack_load}),
        )
        # Every sensitive access was analysed, not just the recorded one.
        self.assertEqual(
            set(local.accesses) | set(local.rejected_nonstack_addresses),
            set(local.candidate_addresses),
        )
        # No compiler object id leaked into the fallback facts.
        self.assertEqual(
            {access.stack_id.source for access in local.accesses.values()},
            {"binary"},
        )
        self.assertNotIn(
            StackObjectId("compiler", 11),
            {access.stack_id for access in local.accesses.values()},
        )

    def test_complete_coverage_keeps_the_metadata_result(self) -> None:
        complete = ChimeraMetadata(
            stack_ids={
                self.stack_store: 11,
                self.non_stack_store: 12,
                self.stack_load: 13,
            },
            has_stackobj_map_section=True,
        )
        local = self._local(complete)

        self.assertEqual(local.access_mode, AccessMode.METADATA_COMPLETE)
        self.assertEqual(local.metadata_covered_count, 3)
        self.assertEqual(local.uncovered_sensitive_addresses, frozenset())
        self.assertEqual(sorted(local.accesses), [0x1000, 0x1004, 0x1008])
        self.assertEqual(
            {access.stack_id.source for access in local.accesses.values()},
            {"compiler"},
        )
        self.assertEqual(local.rejected_nonstack_addresses, frozenset())
        self.assertEqual(local.conservative_addresses, frozenset())

    def test_uncovered_but_proven_non_stack_stays_excluded(self) -> None:
        """An uncovered access is not a conservative source by default.

        The binary proves ``(a0)`` is not a stack address, so the fallback
        keeps it in the rejected bucket instead of manufacturing a source.
        """

        partial = ChimeraMetadata(
            stack_ids={self.stack_store: 11}, has_stackobj_map_section=True
        )
        local = self._local(partial)

        self.assertEqual(
            local.rejected_nonstack_addresses, frozenset({self.non_stack_store})
        )
        self.assertNotIn(self.non_stack_store, local.conservative_addresses)
        self.assertEqual(local.conservative_addresses, frozenset())

    def test_function_without_sensitive_accesses_gains_no_marks(self) -> None:
        program = _program(_scalar_only_function())
        local = _analyze(
            program,
            ChimeraMetadata(has_stackobj_map_section=True),
        ).by_function[program.functions[0].start]

        self.assertEqual(local.sensitive_access_count, 0)
        self.assertEqual(local.uncovered_sensitive_addresses, frozenset())
        self.assertEqual(local.conservative_addresses, frozenset())
        self.assertEqual(local.accesses, {})
        self.assertEqual(local.access_mode, AccessMode.METADATA_COMPLETE)


class LayoutCoverageStateTests(unittest.TestCase):
    """The real ``layout`` body under three metadata states."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.program = fixture.load_program()
        cls.function = fixture.function(cls.program, LAYOUT)

    def _run(self, metadata: ChimeraMetadata):
        from chimera.preprocess.offline.analysis.arch.riscv.rvv.services import (
            RvvServices,
        )

        extension = RvvServices()
        return StackLivenessAnalyzer(
            min_vlen_bits=256,
            semantics=extension.stack_semantics,
            emit_warnings=False,
        ).analyze_program(
            self.program,
            metadata=metadata,
            config_results=extension.vector_configs(self.program),
        ).by_function[self.function.start]

    def test_three_states_give_one_effective_binary_result(self) -> None:
        absent = self._run(ChimeraMetadata.empty())
        empty_section = self._run(
            ChimeraMetadata(has_stackobj_map_section=True)
        )
        # Records that belong to *other* functions are not coverage of this
        # one; nor is a section carrying a single unrelated address.
        other_functions = self._run(
            ChimeraMetadata(stack_ids={0x21C5E: 1, 0x9F000: 2})
        )

        self.assertEqual(absent.access_mode, AccessMode.BINARY_NO_SECTION)
        self.assertEqual(empty_section.access_mode, AccessMode.BINARY_INCOMPLETE)
        self.assertEqual(other_functions.access_mode, AccessMode.BINARY_INCOMPLETE)

        for label, local in (
            ("empty-section", empty_section),
            ("other-function-records", other_functions),
        ):
            with self.subTest(state=label):
                self.assertEqual(local.accesses, absent.accesses)
                self.assertEqual(
                    local.conservative_addresses, absent.conservative_addresses
                )
                self.assertEqual(
                    local.rejected_nonstack_addresses,
                    absent.rejected_nonstack_addresses,
                )
                self.assertEqual(
                    local.candidate_addresses, absent.candidate_addresses
                )
                self.assertGreater(len(local.candidate_addresses), 0)
                # The sources survive in every state: the unresolved accesses
                # of this function degrade conservatively in all three.
                self.assertTrue(local.conservative_addresses)

    def test_vlen_frame_analysis_runs_in_every_coverage_state(self) -> None:
        """The VLEN-frame path is not part of the mode switch.

        Metadata mode may replace *stack-object* recovery, but a dynamic
        VLEN-dependent frame adjustment is still analysed in every state.
        """

        states = {
            "no-section": ChimeraMetadata.empty(),
            "empty-section": ChimeraMetadata(has_stackobj_map_section=True),
            "complete": diag.complete_coverage_metadata(
                self.program,
                fixture.function(self.program, CLOSE_AT_FILE),
            ),
        }
        origins = {}
        for label, metadata in states.items():
            from chimera.preprocess.offline.analysis.arch.riscv.rvv.services import (
                RvvServices,
            )

            extension = RvvServices()
            stack = StackLivenessAnalyzer(
                min_vlen_bits=256,
                semantics=extension.stack_semantics,
                emit_warnings=False,
            ).analyze_program(
                self.program,
                metadata=metadata,
                config_results=extension.vector_configs(self.program),
            )
            local = stack.by_function[
                fixture.function(self.program, CLOSE_AT_FILE).start
            ]
            origins[label] = tuple(
                (origin.source, origin.adjustment, origin.dependency)
                for origin in local.frame_origins
            )
        self.assertTrue(origins["no-section"])
        self.assertEqual(origins["empty-section"], origins["no-section"])
        self.assertEqual(origins["complete"], origins["no-section"])

    def test_coverage_counts_are_reported_per_function(self) -> None:
        local = self._run(ChimeraMetadata(has_stackobj_map_section=True))

        self.assertTrue(local.has_metadata_section)
        self.assertEqual(local.metadata_covered_count, 0)
        self.assertEqual(local.sensitive_access_count, len(local.candidate_addresses))
        self.assertEqual(
            local.uncovered_sensitive_addresses, local.candidate_addresses
        )
        self.assertEqual(local.mode_reason, "incomplete-metadata-coverage")


class GateSourceChainTests(unittest.TestCase):
    """The A/B field fixture through the production check pipeline."""

    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.elf = _elf(self.root, "ab.elf")

    def _check(self, dump: str, metadata: ChimeraMetadata, *, policy="conservative"):
        return collect_diagnostics(
            self.elf,
            objdump_cmd="objdump",
            dump_text=dump,
            metadata=metadata,
            strategy="gate",
            unknown_stack_size_policy=policy,
        )

    def test_source_host_enters_the_gate_list_through_propagation(self) -> None:
        result = self._check(ab.a_dump(), ChimeraMetadata(has_stackobj_map_section=True))
        stack = result.analysis.stack

        # The gate list is produced by the propagation chain: the entries are
        # the seed callers whose local state crossed a call. Informational
        # width observations alone are not sources. No name is hardcoded.
        seed_callers = {
            edge.caller_function_start
            for edge in stack.inheritance_trace.seed_edges
        }
        gated_starts = {
            function.start
            for function in result.analysis.program.functions
            if function.name in result.gate_names
        }
        self.assertTrue(seed_callers)
        self.assertEqual(gated_starts, seed_callers)
        self.assertIn(LAYOUT, result.gate_names)

        # The stub only inherits: it is the host of the finding and it must
        # never replace the source on the gate list.
        unresolved = [item for item in result.findings
                      if item.diagnostic_code == UNRESOLVED_ACTIVE_CALL]
        self.assertEqual(len(unresolved), 1)
        finding = unresolved[0]
        # This is a partial Program: the other callees have no bodies here.
        # v24 additionally reports its active known external boundaries.
        self.assertEqual(result.counts["active_external_calls"], 51)
        # Proven local register lifetimes no longer emit an escape per vector
        # instruction; the real layout source and inheritance are unchanged.
        self.assertEqual(len(result.findings), 52)
        self.assertEqual(finding.kind, "inherited")
        self.assertEqual(finding.function, ab.SINK_NAME)
        self.assertNotIn(ab.SINK_NAME, result.gate_names)
        self.assertTrue(result.pure_inherited_starts)
        self.assertFalse(finding.gate_listed)

    def test_same_result_for_every_incomplete_coverage_state(self) -> None:
        states = {
            "no-section": ChimeraMetadata.empty(),
            "empty-section": ChimeraMetadata(has_stackobj_map_section=True),
            "other-function-records": ChimeraMetadata(
                stack_ids={0x21C5E: 1, 0x9F000: 2}
            ),
        }
        results = {
            label: self._check(ab.a_dump(), metadata)
            for label, metadata in states.items()
        }
        baseline = results["no-section"]
        for label, result in results.items():
            with self.subTest(state=label):
                self.assertEqual(result.gate_names, baseline.gate_names)
                self.assertEqual(len(result.findings), len(baseline.findings))
                self.assertEqual(
                    [(item.kind, item.function, item.call_site)
                     for item in result.findings],
                    [(item.kind, item.function, item.call_site)
                     for item in baseline.findings],
                )

    def test_unrelated_records_do_not_silence_another_function(self) -> None:
        baseline = self._check(ab.a_dump(), ChimeraMetadata.empty())
        stack = baseline.analysis.stack
        other = fixture.function(
            baseline.analysis.program, CLOSE_AT_FILE
        )
        # Records that really do cover a *different* function: the strongest
        # form of "another part of the image was instrumented".
        unrelated = {
            address: 100 + index
            for index, address in enumerate(
                sorted(stack.by_function[other.start].candidate_addresses)
            )
        }
        self.assertTrue(unrelated)
        with_records = self._check(
            ab.a_dump(),
            ChimeraMetadata(stack_ids=unrelated, has_stackobj_map_section=True),
        )

        self.assertEqual(with_records.gate_names, baseline.gate_names)
        self.assertEqual(len(with_records.findings), len(baseline.findings))
        self.assertEqual(
            [(item.kind, item.function, item.call_site)
             for item in with_records.findings],
            [(item.kind, item.function, item.call_site)
             for item in baseline.findings],
        )

    def test_inheritance_report_carries_the_documented_mode_value(self) -> None:
        """The report must not serialise the enum name.

        ``str(AccessMode.BINARY_INCOMPLETE)`` is "AccessMode.BINARY_...", which
        no downstream tool matches on: a fallback function would silently drop
        out of every "which functions fell back" query.
        """

        result = self._check(
            ab.a_dump(), ChimeraMetadata(has_stackobj_map_section=True)
        )
        out = self.root / "xgcc.inheritance.json"
        export_inheritance_diagnostics(result, out, content_hash="0" * 64)
        document = json.loads(out.read_text(encoding="utf-8"))
        entry = next(
            item for item in document["functions"] if item["name"] == LAYOUT
        )
        self.assertEqual(entry["access_mode"], "binary-incomplete-coverage")
        self.assertEqual(entry["mode_reason"], "incomplete-metadata-coverage")
        self.assertTrue(entry["has_metadata_section"])
        self.assertTrue(entry["uncovered_sensitive_addresses"])
        self.assertNotIn("AccessMode", json.dumps(document))
        # A function with nothing sensitive is genuinely fully covered.
        modes = {item["access_mode"] for item in document["functions"]}
        self.assertIn("metadata-complete-coverage", modes)

    def test_diagnostics_payload_marks_the_gated_host(self) -> None:
        result = self._check(
            ab.a_dump(), ChimeraMetadata(has_stackobj_map_section=True)
        )
        payload = _diagnostics_payload(result)
        for finding in payload["findings"]:
            self.assertIn("gate_listed", finding)
            # The source is a gate candidate, the scalar sink is not. Neither
            # value establishes discharge without checking a rebuilt ELF.
            self.assertEqual(finding["gate_listed"], finding["function"] in result.gate_names)
        sink = [item for item in payload["findings"] if item["function"] == ab.SINK_NAME]
        self.assertEqual(len(sink), 1)
        self.assertFalse(sink[0]["gate_listed"])

    def test_vector_only_removal_does_not_erase_scalar_width_cache(self) -> None:
        """The synthetic B removes v* instructions, but retains CSR reads.

        This isolates the old vector/stack dimension; it cannot represent a
        fully recompiled scalar function or prove its scalar caches dead.
        """

        a = self._check(ab.a_dump(), ChimeraMetadata(has_stackobj_map_section=True))
        b = self._check(ab.b_dump(), ChimeraMetadata(has_stackobj_map_section=True))

        self.assertTrue(a.gate_names)
        self.assertIn(LAYOUT, b.gate_names)
        scalar = [item for item in b.findings if item.function == LAYOUT
                  and any(origin.origin == "local-vlen-scalar" for origin in item.origins)]
        self.assertTrue(scalar)
        self.assertTrue(all(item.gate_listed for item in scalar))
        # The devectorized function keeps no conservative or irreducible mark.
        local = b.analysis.stack.by_function[_layout_start(a)]
        self.assertEqual(local.candidate_addresses, frozenset())
        self.assertEqual(local.conservative_addresses, frozenset())
        self.assertFalse(local.conservative_addresses)
        self.assertTrue(local.scalar_width_sources)

    def test_conditional_scalar_scope_keeps_known_width_sources_in_both_groups(self) -> None:
        a = self._check(ab.a_dump(), ChimeraMetadata(has_stackobj_map_section=True),
                        policy="assume-scalar-independent")
        b = self._check(ab.b_dump(), ChimeraMetadata(has_stackobj_map_section=True),
                        policy="assume-scalar-independent")
        self.assertIn(LAYOUT, a.gate_names)
        self.assertTrue(a.findings)
        self.assertIn(LAYOUT, b.gate_names)
        self.assertTrue(b.findings)
        self.assertTrue(all(item.origin_status != "unproven" for item in b.findings))
        self.assertTrue(a.conditional)
        self.assertTrue(b.conditional)

    def test_fixture_is_independent_of_the_desktop_archive(self) -> None:
        """Both dumps come from the bundled fixture, not from a build path."""

        self.assertIn(f"<{ab.SINK_NAME}>", ab.a_dump())
        self.assertNotEqual(ab.a_dump(), ab.b_dump())
        self.assertTrue(ab.sink_call_sites(ab.a_dump()))
        self.assertEqual(
            ab.sink_call_sites(ab.a_dump()), ab.sink_call_sites(ab.b_dump())
        )


def _layout_start(result) -> int:
    for function in result.analysis.program.functions:
        if function.name == LAYOUT:
            return function.start
    raise AssertionError("layout not found in the fixture program")


if __name__ == "__main__":
    unittest.main()
