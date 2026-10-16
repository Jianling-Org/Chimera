"""Regression cover for the layout / metadata-mode divergence.

Five behaviours are pinned:

1. an *incomplete* coverage of ``layout`` -- no section, an empty section, or
   records that belong to other functions -- falls back to whole-function
   binary recovery and yields the same effective analysis as no section at all;
2. a *complete* coverage keeps the metadata route: metadata is authoritative
   for that function and the propagatable degradation objects disappear;
3. the three metadata states stay distinguishable end to end (section missing,
   present and empty, present with records);
4. a gate that zeroes every stack-object record no longer flips the effective
   mode on its own: with no section the function was already on binary
   recovery, and losing records must never lose a source;
5. the diagnosis is read-only: it does not touch an ELF, a check credential,
   a decision or a safety criterion, and a forced metadata mode is never a
   safety pass.
"""

from __future__ import annotations

import hashlib
import json
import struct
import tempfile
import unittest
from pathlib import Path

import xgcc_stack_fixture as fixture
import layout_mode_diagnosis as diag

from elf_fixture import build_elf

from chimera.preprocess.offline.analysis.safety.stack_liveness.model import (
    ChimeraMetadata,
)

LAYOUT = fixture.FIXED_FRAME_FUNCTIONS[2]
_STACKOBJ_RECORD = struct.Struct("<QI")


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _stackobj_payload(*records: tuple[int, int]) -> bytes:
    return b"".join(
        _STACKOBJ_RECORD.pack(address, object_id)
        for address, object_id in records
    )


class LayoutModeSwitchTests(unittest.TestCase):
    """The real gate-2 ``layout`` body under the three metadata states."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.program = fixture.load_program()
        cls.function = fixture.function(cls.program, LAYOUT)
        cls.comparison = diag.diagnose_function(cls.program, cls.function)
        cls.complete = cls.comparison.extra["metadata-complete"]

    def test_incomplete_coverage_falls_back_to_the_binary_result(self) -> None:
        comparison = self.comparison

        # The irreducible-loop warning is a property of the CFG and must not
        # depend on which local-analysis mode ran.
        self.assertTrue(comparison.binary.has_irreducible_warning)
        self.assertTrue(comparison.metadata.has_irreducible_warning)
        self.assertTrue(comparison.warning_parity)
        self.assertEqual(comparison.binary.warnings, comparison.metadata.warnings)

        # An empty section is incomplete coverage for this function, so the
        # whole function goes through binary recovery: the effective result is
        # the binary result, object for object and call site for call site.
        self.assertTrue(comparison.metadata.coverage_incomplete)
        self.assertFalse(comparison.metadata.plan.metadata_mode)
        self.assertTrue(comparison.binary_fallback_parity)
        self.assertFalse(comparison.object_divergence)

        self.assertTrue(comparison.binary.has_propagatable_irreducible_object)
        self.assertTrue(comparison.metadata.has_propagatable_irreducible_object)
        self.assertEqual(
            comparison.binary.irreducible_object_live_at,
            comparison.metadata.irreducible_object_live_at,
        )

        # Local active call sites: 48 with the irreducible mark, in *both*
        # runs.  Losing the records must not lose the source.
        self.assertEqual(len(comparison.binary.irreducible_call_sites), 48)
        self.assertEqual(len(comparison.metadata.irreducible_call_sites), 48)
        self.assertEqual(
            comparison.binary.irreducible_call_sites,
            comparison.metadata.irreducible_call_sites,
        )

        only_binary, only_metadata = comparison.call_site_delta
        self.assertEqual(only_binary, ())
        self.assertEqual(only_metadata, ())

    def test_complete_coverage_keeps_the_metadata_route(self) -> None:
        complete = self.complete

        self.assertTrue(complete.plan.metadata_mode)
        self.assertFalse(complete.coverage_incomplete)
        self.assertEqual(
            complete.plan.access_mode, "metadata-complete-coverage"
        )
        self.assertEqual(len(complete.plan.compiler_access_ids),
                         len(complete.plan.vlen_sensitive_addresses))
        self.assertEqual(complete.plan.binary_addresses, ())

        # The propagatable degradation object is a property of the *binary*
        # fact builder only: with complete coverage it is never built, which
        # is the documented 48 -> 0 delta.
        self.assertFalse(complete.has_propagatable_irreducible_object)
        self.assertEqual(complete.irreducible_call_sites, ())
        self.assertTrue(self.comparison.complete_coverage_divergence)

    def test_access_plan_split_is_recorded_per_mode(self) -> None:
        binary = self.comparison.binary.plan
        incomplete = self.comparison.metadata.plan
        complete = self.complete.plan

        self.assertFalse(binary.metadata_mode)
        self.assertEqual(binary.access_mode, "binary-no-section")
        self.assertFalse(binary.has_metadata_section)
        self.assertEqual(binary.uncovered_sensitive_addresses, ())
        self.assertGreater(len(binary.binary_addresses), 0)
        self.assertEqual(binary.compiler_access_ids, {})

        # Incomplete: every sensitive access is uncovered and went to binary
        # recovery; no compiler record was injected into the facts.
        self.assertFalse(incomplete.metadata_mode)
        self.assertEqual(incomplete.access_mode, "binary-incomplete-coverage")
        self.assertTrue(incomplete.has_metadata_section)
        self.assertTrue(incomplete.coverage_incomplete)
        self.assertEqual(
            incomplete.uncovered_sensitive_addresses,
            incomplete.vlen_sensitive_addresses,
        )
        self.assertEqual(incomplete.binary_addresses,
                         incomplete.vlen_sensitive_addresses)
        self.assertEqual(incomplete.compiler_access_ids, {})

        # Complete: metadata is authoritative and binary recovery is off.
        self.assertTrue(complete.metadata_mode)
        self.assertEqual(
            complete.uncovered_sensitive_addresses, ()
        )
        self.assertEqual(
            complete.metadata_covered_count,
            len(complete.vlen_sensitive_addresses),
        )

        # The VLEN-sensitive set U is a property of the code, not the mode.
        self.assertEqual(
            binary.vlen_sensitive_addresses, incomplete.vlen_sensitive_addresses
        )
        self.assertEqual(
            binary.vlen_sensitive_addresses, complete.vlen_sensitive_addresses
        )
        self.assertGreater(len(binary.vlen_sensitive_addresses), 0)

    def test_conservative_objects_follow_the_effective_mode(self) -> None:
        self.assertTrue(self.comparison.binary.conservative_addresses)
        self.assertTrue(self.comparison.binary.conservative_object_live_at)
        # Fallback: identical conservative set, not an empty one.
        self.assertEqual(
            self.comparison.binary.conservative_addresses,
            self.comparison.metadata.conservative_addresses,
        )
        # Complete coverage: the metadata route creates no conservative set.
        self.assertEqual(self.complete.conservative_addresses, ())
        self.assertEqual(self.complete.conservative_object_live_at, ())
        self.assertIn("conservative", self.comparison.binary.object_sources)
        self.assertIn("conservative", self.comparison.metadata.object_sources)
        self.assertNotIn("conservative", self.complete.object_sources)

    def test_diagnosis_reports_warning_and_object_as_separate_facts(self) -> None:
        payload = diag.comparison_to_json(self.comparison)

        self.assertTrue(payload["read_only"])
        self.assertTrue(payload["forced_metadata_mode_is_not_a_safety_pass"])
        binary = payload["binary"]
        incomplete = payload["metadata_empty"]
        complete = payload["metadata-complete"]
        self.assertTrue(binary["has_irreducible_warning"])
        self.assertTrue(incomplete["has_irreducible_warning"])
        self.assertTrue(binary["has_propagatable_irreducible_object"])
        # Incomplete coverage falls back, so the object is still there ...
        self.assertTrue(incomplete["has_propagatable_irreducible_object"])
        self.assertTrue(incomplete["coverage_incomplete"])
        # ... and only complete coverage removes it.
        self.assertFalse(complete["has_propagatable_irreducible_object"])
        self.assertFalse(complete["coverage_incomplete"])
        self.assertTrue(payload["binary_fallback_parity"])
        self.assertTrue(payload["complete_coverage_divergence"])


class MetadataThreeStateTests(unittest.TestCase):
    """Missing / empty / populated ``.chimera.stackobj_map`` stay distinct."""

    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def _write(self, name: str, stackobj: bytes | None) -> Path:
        sections = []
        if stackobj is not None:
            sections.append((".chimera.stackobj_map", stackobj, False))
        return build_elf(self.root / name, sections=tuple(sections))

    def test_three_states_select_three_different_metadata_objects(self) -> None:
        missing = ChimeraMetadata.from_elf(self._write("missing.elf", None))
        empty = ChimeraMetadata.from_elf(self._write("empty.elf", b""))
        populated = ChimeraMetadata.from_elf(
            self._write(
                "populated.elf", _stackobj_payload((0x1000, 7), (0x1004, 7))
            )
        )

        # Missing: binary mode, no capability.
        self.assertFalse(missing.has_stackobj_map_section)
        self.assertEqual(missing.stack_ids, {})
        self.assertEqual(missing.capabilities, frozenset())

        # Present and empty: metadata mode, capability claimed, zero records.
        # This is the "plugin fully processed, nothing to record" state and it
        # is NOT the same as the section being absent.
        self.assertTrue(empty.has_stackobj_map_section)
        self.assertEqual(empty.stack_ids, {})
        self.assertEqual(empty.capabilities, frozenset({"stack_access_ids"}))

        # Present with records: metadata mode plus a real mapping.
        self.assertTrue(populated.has_stackobj_map_section)
        self.assertEqual(populated.stack_ids, {0x1000: 7, 0x1004: 7})
        self.assertEqual(populated.capabilities, frozenset({"stack_access_ids"}))

    def test_empty_state_selects_the_binary_fallback_in_the_planner(self) -> None:
        program = fixture.load_program()
        function = fixture.function(program, LAYOUT)

        empty = diag.run_mode(
            program,
            function,
            label="empty",
            metadata=ChimeraMetadata(has_stackobj_map_section=True),
        )
        absent = diag.run_mode(
            program,
            function,
            label="absent",
            metadata=ChimeraMetadata.empty(),
        )
        complete = diag.run_mode(
            program,
            function,
            label="complete",
            metadata=diag.complete_coverage_metadata(program, function),
        )

        # "Section present, zero records" is incomplete coverage: the planner
        # must not read it as "nothing to analyse".
        self.assertFalse(empty.plan.metadata_mode)
        self.assertTrue(empty.plan.coverage_incomplete)
        self.assertFalse(absent.plan.metadata_mode)
        self.assertFalse(absent.plan.coverage_incomplete)
        self.assertEqual(
            empty.plan.binary_addresses, absent.plan.binary_addresses
        )
        self.assertGreater(len(absent.plan.binary_addresses), 0)

        # Only a mapping that really covers the function selects metadata.
        self.assertTrue(complete.plan.metadata_mode)
        self.assertEqual(complete.plan.binary_addresses, ())
        self.assertGreater(len(complete.plan.compiler_access_ids), 0)


class GateZeroedRecordsTests(unittest.TestCase):
    """Gate eliminates every stack-object record -> the section goes away.

    Losing the records must not lose a source: with or without the section, a
    function whose coverage is incomplete is analysed from the binary, so the
    "before" and "after" states give the same local sources here.
    """

    def test_zeroing_the_records_does_not_remove_a_local_source(
        self,
    ) -> None:
        program = fixture.load_program()
        function = fixture.function(program, LAYOUT)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            # Before the gate: a section with one record per interesting access.
            before_path = build_elf(
                root / "before.elf",
                sections=(
                    (
                        ".chimera.stackobj_map",
                        _stackobj_payload((function.start, 1)),
                        False,
                    ),
                ),
            )
            before_bytes = before_path.read_bytes()
            before = ChimeraMetadata.from_elf(before_path)

            # After the gate: the RVV spills that produced the records are
            # gone, the plugin has nothing to emit, and the section is not
            # created at all.  This is the real xgcc stack -> gate2 shape.
            after_path = build_elf(root / "after.elf", sections=())
            after_bytes = after_path.read_bytes()
            after = ChimeraMetadata.from_elf(after_path)

        self.assertTrue(before.has_stackobj_map_section)
        self.assertFalse(after.has_stackobj_map_section)

        before_run = diag.run_mode(
            program, function, label="before", metadata=before
        )
        after_run = diag.run_mode(program, function, label="after", metadata=after)

        # One record for a function with several sensitive accesses is still
        # incomplete coverage, so both states run binary recovery.
        self.assertFalse(before_run.plan.metadata_mode)
        self.assertFalse(after_run.plan.metadata_mode)
        self.assertTrue(before_run.coverage_incomplete)
        self.assertFalse(after_run.coverage_incomplete)

        # The warning is present in both ...
        self.assertTrue(before_run.has_irreducible_warning)
        self.assertTrue(after_run.has_irreducible_warning)

        # ... and so is the propagatable object: dropping the records is a
        # capability loss, not evidence that the source is gone.  Under the
        # previous rule this object existed only without the section, which is
        # what let a half-instrumented product look clean.
        self.assertTrue(before_run.has_propagatable_irreducible_object)
        self.assertTrue(after_run.has_propagatable_irreducible_object)
        self.assertEqual(
            before_run.irreducible_call_sites, after_run.irreducible_call_sites
        )
        self.assertGreater(len(after_run.irreducible_call_sites), 0)

        # A record set that goes to zero *while the section stays* is a third
        # state and must not be confused with the section disappearing: it is
        # incomplete coverage and falls back as well.
        zeroed = ChimeraMetadata.from_elf(
            build_elf(
                root / "zeroed.elf",
                sections=((".chimera.stackobj_map", b"", False),),
            )
        )
        self.assertTrue(zeroed.has_stackobj_map_section)
        zeroed_run = diag.run_mode(
            program, function, label="zeroed", metadata=zeroed
        )
        self.assertFalse(zeroed_run.plan.metadata_mode)
        self.assertTrue(zeroed_run.has_propagatable_irreducible_object)
        self.assertEqual(
            zeroed_run.irreducible_call_sites, after_run.irreducible_call_sites
        )

        # The bytes of the synthetic "before" image are distinct from the
        # "after" image; only the metadata state differs.
        self.assertNotEqual(before_bytes[:64], after_bytes[:64])


class DiagnosisIsReadOnlyTests(unittest.TestCase):
    def test_diagnosis_does_not_touch_the_elf_decision_or_credentials(self) -> None:
        program = fixture.load_program()
        function = fixture.function(program, LAYOUT)

        with tempfile.TemporaryDirectory() as directory:
            elf = Path(directory) / "probe.elf"
            build_elf(
                elf,
                sections=(
                    (".chimera.stackobj_map", _stackobj_payload((0x1000, 3)), False),
                ),
            )
            decision = Path(directory) / "decision.json"
            decision.write_text('{"gate": {"names": ["layout"]}}', encoding="utf-8")
            credential = Path(directory) / "check.credential"
            credential.write_text("issued", encoding="utf-8")

            before = {
                "elf": _sha256(elf),
                "elf_size": elf.stat().st_size,
                "decision": _sha256(decision),
                "credential": _sha256(credential),
                "metadata": ChimeraMetadata.from_elf(elf),
            }

            comparison = diag.diagnose_function(program, function)
            payload = diag.comparison_to_json(comparison)

            after = {
                "elf": _sha256(elf),
                "elf_size": elf.stat().st_size,
                "decision": _sha256(decision),
                "credential": _sha256(credential),
                "metadata": ChimeraMetadata.from_elf(elf),
            }

        self.assertEqual(before["elf"], after["elf"])
        self.assertEqual(before["elf_size"], after["elf_size"])
        self.assertEqual(before["decision"], after["decision"])
        self.assertEqual(before["credential"], after["credential"])
        self.assertEqual(before["metadata"], after["metadata"])

        # The export advertises its own contract so a reader cannot mistake a
        # forced mode for a safety pass.
        self.assertTrue(payload["read_only"])
        self.assertTrue(payload["forced_metadata_mode_is_not_a_safety_pass"])

    def test_forced_metadata_mode_is_explicitly_not_a_safety_pass(self) -> None:
        forced = diag.forced_metadata_mode()
        self.assertTrue(forced.has_stackobj_map_section)
        self.assertEqual(forced.stack_ids, {})
        # Capability is claimed with zero records; nothing here asserts that
        # any real ELF carried the section.
        self.assertEqual(forced.capabilities, frozenset({"stack_access_ids"}))

    def test_json_export_is_serialisable_and_names_the_format(self) -> None:
        program = fixture.load_program()
        function = fixture.function(program, LAYOUT)
        payload = diag.comparison_to_json(diag.diagnose_function(program, function))
        text = json.dumps(payload)
        self.assertIn("chimera-layout-mode-diagnosis-v2", text)
        self.assertIn("has_propagatable_irreducible_object", text)
        self.assertIn("coverage_incomplete", text)
        self.assertIn("uncovered_sensitive_addresses", text)


class ConservativeSourceClassificationTests(unittest.TestCase):
    """The binary-mode conservative set is the reclassification of accesses
    that were *not resolved*, not newly generated vector code."""

    def test_binary_exposes_every_sensitive_access_of_an_uncovered_function(
        self,
    ) -> None:
        program = fixture.load_program()
        function = fixture.function(program, LAYOUT)
        comparison = diag.diagnose_function(program, function)

        binary = comparison.binary.plan
        incomplete = comparison.metadata.plan
        complete = comparison.extra["metadata-complete"].plan

        # Same code, same U.  An uncovered function keeps all of them as
        # binary candidates and degrades the unresolved ones conservatively;
        # nothing is dropped because a record happened to be missing.
        self.assertEqual(
            set(binary.vlen_sensitive_addresses),
            set(incomplete.vlen_sensitive_addresses),
        )
        self.assertEqual(
            len(binary.binary_addresses), len(binary.vlen_sensitive_addresses)
        )
        self.assertEqual(
            len(incomplete.binary_addresses),
            len(incomplete.vlen_sensitive_addresses),
        )
        # Complete coverage, by contrast, maps every access.
        self.assertEqual(
            len(complete.compiler_access_ids),
            len(complete.vlen_sensitive_addresses),
        )

        # The conservative scope is non-empty exactly when binary recovery ran
        # and left unresolved addresses behind.
        self.assertTrue(comparison.binary.conservative_addresses)
        self.assertEqual(
            comparison.binary.conservative_addresses,
            comparison.metadata.conservative_addresses,
        )
        self.assertEqual(
            set(comparison.binary.conservative_addresses),
            set(comparison.binary.conservative_object_live_at),
        )


class AbsenceFromA0IsNotProofTests(unittest.TestCase):
    """`U \\ A0` is "not covered", not "proven not a target".

    The plugin can skip an access because it is ``ProvenNotCurrentLocalAlloca``
    (proven), because it is ``MultipleLocations`` (unrepresentable), because it
    is ``UnknownProvenance`` (unjudgeable), or because the access is not on the
    plugin's recorded surface at all (only ``CallBase`` is scanned; the
    intrinsic whitelist has no ``vs1r/vs2r/vl1r/vl2r``).  None of those four is
    a proof, so an uncovered access must reach the binary analysis instead of
    disappearing.
    """

    def test_uncovered_accesses_reach_the_binary_analysis(self) -> None:
        program = fixture.load_program()
        function = fixture.function(program, LAYOUT)
        comparison = diag.diagnose_function(program, function)

        # With an incomplete mapping every sensitive address is uncovered and
        # therefore analysed from the binary: it is a conservative address or
        # a resolved access, never a silent drop.
        incomplete = comparison.metadata
        self.assertEqual(
            incomplete.plan.uncovered_sensitive_addresses,
            incomplete.plan.vlen_sensitive_addresses,
        )
        self.assertTrue(incomplete.conservative_addresses)
        self.assertTrue(incomplete.created_stack_object_ids)
        self.assertTrue(incomplete.object_sources)

        # Only a *complete* mapping may leave no binary trace, and it does so
        # because every access was mapped, not because it was dropped.
        complete = comparison.extra["metadata-complete"]
        self.assertEqual(complete.plan.uncovered_sensitive_addresses, ())
        self.assertEqual(
            len(complete.plan.compiler_access_ids),
            len(complete.plan.vlen_sensitive_addresses),
        )

        binary = comparison.binary
        self.assertTrue(binary.conservative_addresses)
        self.assertTrue(binary.created_stack_object_ids)

    def test_uncovered_does_not_equal_rejected_non_stack(self) -> None:
        """Binary recovery records an explicit non-stack rejection; falling
        back must not turn an uncovered access into a rejection."""
        program = fixture.load_program()
        function = fixture.function(program, LAYOUT)

        from chimera.preprocess.offline.analysis.arch.riscv.rvv.services import (
            RvvServices,
        )
        from chimera.preprocess.offline.analysis.safety.stack_liveness.analyzer import (
            StackLivenessAnalyzer,
        )

        extension = RvvServices()
        binary = StackLivenessAnalyzer(
            min_vlen_bits=256, semantics=extension.stack_semantics, emit_warnings=False
        ).analyze_program(
            program,
            metadata=ChimeraMetadata.empty(),
            config_results=extension.vector_configs(program),
        ).by_function[function.start]
        fallback = StackLivenessAnalyzer(
            min_vlen_bits=256, semantics=extension.stack_semantics, emit_warnings=False
        ).analyze_program(
            program,
            metadata=diag.forced_metadata_mode(),
            config_results=extension.vector_configs(program),
        ).by_function[function.start]
        complete = StackLivenessAnalyzer(
            min_vlen_bits=256, semantics=extension.stack_semantics, emit_warnings=False
        ).analyze_program(
            program,
            metadata=diag.complete_coverage_metadata(program, function),
            config_results=extension.vector_configs(program),
        ).by_function[function.start]

        # The fallback reuses the binary verdicts exactly: the same rejected
        # set, the same candidates.  An uncovered access is not "rejected".
        self.assertEqual(
            fallback.rejected_nonstack_addresses,
            binary.rejected_nonstack_addresses,
        )
        self.assertEqual(fallback.candidate_addresses, binary.candidate_addresses)
        self.assertEqual(fallback.access_mode, "binary-incomplete-coverage")
        self.assertEqual(
            fallback.uncovered_sensitive_addresses,
            fallback.candidate_addresses,
        )
        # The metadata route has no rejected bucket at all; an empty field must
        # never be read as "nothing to reject".
        self.assertEqual(complete.rejected_nonstack_addresses, frozenset())
        self.assertEqual(complete.access_mode, "metadata-complete-coverage")


if __name__ == "__main__":
    unittest.main()
