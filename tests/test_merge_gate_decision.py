"""Union decision merging and gate-source verification.

The merger only reads: it unions the gate lists of several reports, keeps the
orthogonal switches sticky, and diffs against an earlier decision *without*
writing it back.  The verifier answers "did this function reach the candidate
list, and under which coverage mode" -- it never adds a name.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

TOOL = Path(__file__).resolve().parents[1] / "tools" / "merge_gate_decision.py"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _report(path: Path, names: list[str], *, strategy: str = "gate",
            stack_object: bool = True, version: int = 19) -> dict:
    document = {
        "elf": {"path": str(path), "content_sha256": "0" * 64},
        "checks": [{"id": "safety.stack-liveness", "version": version,
                    "passed": False, "diagnostics": {}}],
        "decision": {
            "strategy": strategy,
            "vector_gate": {"enabled": strategy == "gate", "names_source": "x"},
            "function_pointer_plugin": False,
            "stack_object_plugin": stack_object,
            "gate": {"enabled": strategy == "gate", "names": list(names)},
        },
    }
    path.write_text(json.dumps(document, indent=2), encoding="utf-8")
    return document


def _inheritance(path: Path, functions: list[dict],
                 seed_edges: list[dict] | None = None) -> Path:
    path.write_text(
        json.dumps({"format": "chimera-inheritance-diagnostics-v2",
                    "functions": functions,
                    "seed_edges": seed_edges or []}, indent=2),
        encoding="utf-8",
    )
    return path


#: The complete coverage accounting the verifier demands.  The counts must add
#: up (covered + uncovered == sensitive), otherwise the record is
#: self-contradictory and the verifier must stop.
LAYOUT_COVERAGE = {
    "name": "layout",
    "has_metadata_section": True,
    "sensitive_access_count": 10,
    "metadata_covered_count": 0,
    "uncovered_sensitive_addresses": [f"0x504f{i:x}" for i in range(10)],
    "access_mode": "binary-incomplete-coverage",
    "mode_reason": "incomplete-metadata-coverage",
    "frame_origins": [],
}


def _run(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(TOOL), *args],
        capture_output=True,
        text=True,
        check=False,
    )


class MergeDecisionTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def test_union_deduplicates_and_keeps_switches_sticky(self) -> None:
        a = self.root / "a.check.json"
        b = self.root / "b.check.json"
        _report(a, ["zeta", "alpha"])
        _report(b, ["alpha", "mid"], stack_object=False)
        out = self.root / "union.json"
        baseline = self.root / "old.decision.json"
        baseline.write_text(json.dumps({
            "strategy": "gate",
            "vector_gate": {"enabled": True, "names_source": "x"},
            "function_pointer_plugin": False,
            "stack_object_plugin": True,
            "gate": {"enabled": True, "names": ["alpha", "gone"]},
        }, indent=2), encoding="utf-8")
        before = _sha256(baseline)

        completed = _run("merge", "--report", str(a), "--report", str(b),
                         "--baseline", str(baseline), "--out", str(out),
                         "--summary", str(self.root / "union.md"))
        self.assertEqual(completed.returncode, 0, completed.stderr)

        payload = json.loads(out.read_text(encoding="utf-8"))
        decision = payload["decision"]
        self.assertEqual(decision["gate"]["names"], ["alpha", "mid", "zeta"])
        # Sticky: one report needed the metadata route, so the union keeps it.
        self.assertTrue(decision["stack_object_plugin"])
        self.assertEqual(decision["strategy"], "gate")
        provenance = payload["provenance"]
        self.assertEqual(provenance["added"], ["mid", "zeta"])
        self.assertEqual(provenance["removed"], ["gone"])
        self.assertEqual(provenance["union_count"], 3)
        self.assertEqual(len(provenance["sources"]), 2)
        self.assertEqual(provenance["sources"][0]["check_versions"], [19])

        # The old decision is read-only evidence.
        self.assertEqual(_sha256(baseline), before)
        summary = (self.root / "union.md").read_text(encoding="utf-8")
        self.assertIn("union gate count: 3", summary)
        self.assertIn("added: 2", summary)

    def test_different_strategies_are_refused(self) -> None:
        a = self.root / "a.check.json"
        b = self.root / "b.check.json"
        _report(a, ["alpha"])
        _report(b, ["beta"], strategy="svf")
        completed = _run("merge", "--report", str(a), "--report", str(b),
                         "--out", str(self.root / "union.json"))
        self.assertEqual(completed.returncode, 3)
        self.assertIn("different strategies", completed.stderr)

    def test_missing_input_is_reported_not_crashed(self) -> None:
        completed = _run("merge", "--report", str(self.root / "nope.json"),
                         "--out", str(self.root / "union.json"))
        self.assertEqual(completed.returncode, 3)
        self.assertIn("input error", completed.stderr)


class VerifySourceTests(unittest.TestCase):
    """The name on the list is not the point; the reason it got there is."""

    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def _verify(self, names: list[str], functions: list[dict],
                seed_edges: list[dict] | None = None,
                *, inheritance: bool = True,
                findings: list[dict] | None = None,
                extra: tuple[str, ...] = ()) -> tuple[int, dict]:
        report = self.root / "xgcc.check.json"
        _report(report, names)
        if findings is not None:
            document = json.loads(report.read_text(encoding="utf-8"))
            document["checks"][0]["diagnostics"]["findings"] = findings
            report.write_text(json.dumps(document, indent=2), encoding="utf-8")
        out = self.root / "verify.json"
        args = ["verify-source", "--report", str(report),
                "--function", "layout", "--json", str(out)]
        if inheritance:
            args += ["--inheritance-report",
                     str(_inheritance(self.root / "xgcc.inheritance.json",
                                      functions, seed_edges))]
        completed = _run(*args, *extra)
        payload = json.loads(out.read_text(encoding="utf-8")) if out.exists() else {}
        return completed.returncode, payload

    def test_candidate_is_confirmed_with_its_fallback_and_seed_evidence(
        self,
    ) -> None:
        code, payload = self._verify(
            ["layout", "other"],
            [dict(LAYOUT_COVERAGE)],
            # function_ref 0 is ``layout``; the edge carries a local object.
            [{"caller_function_ref": 0, "call_site": "0x50564",
              "reason": "seed", "depth": 1,
              "local_active_objects": [
                  {"id": "irreducible:50418", "metadata_source": "irreducible",
                   "accesses": []}]}],
        )
        self.assertEqual(code, 0)
        self.assertEqual(payload["verdict"], "verified")
        self.assertTrue(payload["gate_candidate"])
        self.assertTrue(payload["coverage_fields_complete"])
        self.assertTrue(payload["coverage_fallback_applied"])
        self.assertTrue(payload["metadata_did_not_cover_function"])
        self.assertTrue(payload["has_local_source"])
        self.assertEqual(payload["local_source_evidence"]["seed_count"], 1)
        self.assertEqual(payload["gate_names_count"], 2)

    def test_a_local_finding_of_the_function_is_local_source_evidence(self) -> None:
        code, payload = self._verify(
            ["layout"], [dict(LAYOUT_COVERAGE)],
            findings=[{"kind": "local-root", "function": "layout",
                       "call_site": "0x50564",
                       "recommended_action": "disable-autovec-file",
                       "activity_origins": [
                           {"origin": "local-vlen-frame", "object": "vlen_stack_frame",
                            "dependency": "vlen"}]}],
        )
        self.assertEqual(code, 0)
        self.assertEqual(payload["verdict"], "verified")
        self.assertTrue(payload["has_local_source"])
        self.assertEqual(payload["local_source_evidence"]["seed_count"], 0)

    def test_structured_local_origins_overrule_an_inherited_kind(self) -> None:
        """A mixed finding: inherited *and* local activity is still a source."""

        code, payload = self._verify(
            ["layout"], [dict(LAYOUT_COVERAGE)],
            findings=[{"kind": "inherited", "function": "layout",
                       "call_site": "0x50564", "origin_status": "mixed",
                       "activity_origins": [
                           {"origin": "inherited", "object": "caller:inherited"},
                           {"origin": "irreducible", "object": "irreducible:50418"}]}],
        )
        self.assertEqual(code, 0)
        self.assertTrue(payload["has_local_source"])

    def test_a_pure_inherited_finding_is_not_a_local_source(self) -> None:
        """Regression: an inherited-only finding used to satisfy the check.

        Live state that belongs to an upstream frame proves nothing about this
        function's own sources, so the verification must stop.
        """

        code, payload = self._verify(
            ["layout"], [dict(LAYOUT_COVERAGE)],
            findings=[{"kind": "inherited", "function": "layout",
                       "call_site": "0x50564", "origin_status": "inherited",
                       "activity_origins": [
                           {"origin": "inherited",
                            "object": "caller:inherited-stack-data"}]}],
        )
        self.assertEqual(code, 4)
        self.assertEqual(payload["verdict"], "no-local-source")
        self.assertFalse(payload["has_local_source"])
        self.assertTrue(payload["local_source_evidence"]["local_findings"])
        self.assertFalse(
            payload["local_source_evidence"]["local_findings"][0]["local"]
        )

    def test_an_unproven_local_frame_still_counts_as_local(self) -> None:
        code, payload = self._verify(
            ["layout"], [dict(LAYOUT_COVERAGE)],
            findings=[{"kind": "local-root", "function": "layout",
                       "call_site": "0x50564", "origin_status": "unproven",
                       "activity_origins": [
                           {"origin": "local-vlen-frame", "object": "vlen_stack_frame",
                            "dependency": "unknown"}]}],
        )
        self.assertEqual(code, 0)
        self.assertTrue(payload["has_local_source"])

    def test_name_only_with_an_empty_inheritance_report_is_rejected(self) -> None:
        """Regression: ``gate.names=["layout"]`` plus an empty report used to
        return success -- the name proved nothing about the fix."""

        code, payload = self._verify(["layout"], [])
        self.assertEqual(code, 4)
        self.assertEqual(payload["verdict"], "missing-coverage-evidence")
        self.assertFalse(payload["coverage_fields_complete"])
        self.assertFalse(payload["coverage_fallback_applied"])

    def test_absent_coverage_fields_are_not_read_as_complete(self) -> None:
        """A consumer must not read missing fields as "fully covered"."""

        code, payload = self._verify(["layout"], [{"name": "layout"}])
        self.assertEqual(code, 4)
        self.assertEqual(payload["coverage"], {})
        self.assertNotIn("access_mode", payload["coverage"])

    def test_a_fully_covered_function_is_not_the_fix(self) -> None:
        coverage = dict(LAYOUT_COVERAGE)
        coverage.update(
            access_mode="metadata-complete-coverage",
            mode_reason="complete-metadata-coverage",
            metadata_covered_count=10,
            uncovered_sensitive_addresses=[],
        )
        code, payload = self._verify(
            ["layout"], [coverage],
            [{"caller_function_ref": 0, "call_site": "0x50564",
              "reason": "seed", "depth": 1,
              "local_active_objects": [{"id": "compiler:1",
                                        "metadata_source": "compiler",
                                        "accesses": []}]}],
        )
        self.assertEqual(code, 4)
        self.assertEqual(payload["verdict"], "covered-by-metadata")
        self.assertFalse(payload["metadata_did_not_cover_function"])

    def test_fallback_without_a_local_source_is_rejected(self) -> None:
        code, payload = self._verify(["layout"], [dict(LAYOUT_COVERAGE)])
        self.assertEqual(code, 4)
        self.assertEqual(payload["verdict"], "no-local-source")
        self.assertTrue(payload["coverage_fallback_applied"])
        self.assertFalse(payload["has_local_source"])

    def test_section_present_with_a_no_section_mode_is_contradictory(self) -> None:
        """Regression: the fields were only checked for presence.

        ``has_metadata_section=true`` next to ``binary-no-section`` describes a
        state that cannot occur, and it is not the fallback this round needs.
        """

        contradicted = dict(LAYOUT_COVERAGE)
        contradicted.update(
            access_mode="binary-no-section",
            mode_reason="no-stackobj-section",
            metadata_covered_count=10,
            uncovered_sensitive_addresses=[],
        )
        code, payload = self._verify(
            ["layout"], [contradicted],
            [{"caller_function_ref": 0, "call_site": "0x50564",
              "reason": "seed", "depth": 1,
              "local_active_objects": [{"id": "irreducible:50418",
                                        "metadata_source": "irreducible",
                                        "accesses": []}]}],
        )
        self.assertEqual(code, 4)
        self.assertEqual(payload["verdict"], "inconsistent-coverage")
        self.assertFalse(payload["coverage_consistent"])
        self.assertTrue(payload["coverage_consistency_problems"])
        self.assertFalse(payload["coverage_fallback_applied"])

    def test_counts_that_do_not_add_up_are_contradictory(self) -> None:
        skewed = dict(LAYOUT_COVERAGE)
        skewed.update(
            sensitive_access_count=10,
            metadata_covered_count=10,
            uncovered_sensitive_addresses=["0x504f6"],
        )
        code, payload = self._verify(["layout"], [skewed])
        self.assertEqual(code, 4)
        self.assertEqual(payload["verdict"], "inconsistent-coverage")
        self.assertIn(
            "!= sensitive_access_count",
            " ".join(payload["coverage_consistency_problems"]),
        )

    def test_mode_reason_must_match_the_mode(self) -> None:
        mismatched = dict(LAYOUT_COVERAGE)
        mismatched.update(mode_reason="no-stackobj-section")
        code, payload = self._verify(["layout"], [mismatched])
        self.assertEqual(code, 4)
        self.assertEqual(payload["verdict"], "inconsistent-coverage")

    def test_no_section_is_rejected_while_the_fallback_is_required(self) -> None:
        """Without the section there is no coverage to be incomplete about."""

        absent_section = dict(LAYOUT_COVERAGE)
        absent_section.update(
            has_metadata_section=False,
            access_mode="binary-no-section",
            mode_reason="no-stackobj-section",
            metadata_covered_count=0,
        )
        code, payload = self._verify(
            ["layout"], [absent_section],
            [{"caller_function_ref": 0, "call_site": "0x50564",
              "reason": "seed", "depth": 1,
              "local_active_objects": [{"id": "irreducible:50418",
                                        "metadata_source": "irreducible",
                                        "accesses": []}]}],
        )
        self.assertEqual(code, 4)
        self.assertEqual(payload["verdict"], "no-coverage-fallback")
        # Relaxing the requirement is explicit, and recorded in the payload.
        relaxed, relaxed_payload = self._verify(
            ["layout"], [absent_section],
            [{"caller_function_ref": 0, "call_site": "0x50564",
              "reason": "seed", "depth": 1,
              "local_active_objects": [{"id": "irreducible:50418",
                                        "metadata_source": "irreducible",
                                        "accesses": []}]}],
            extra=("--no-require-fallback",),
        )
        self.assertEqual(relaxed, 0)
        self.assertFalse(relaxed_payload["require_fallback"])
        self.assertTrue(relaxed_payload["metadata_did_not_cover_function"])

    def test_non_candidate_stops_the_pipeline(self) -> None:
        code, payload = self._verify(["other"], [dict(LAYOUT_COVERAGE)])
        self.assertEqual(code, 2)
        self.assertEqual(payload["verdict"], "not-a-candidate")


if __name__ == "__main__":
    unittest.main()
