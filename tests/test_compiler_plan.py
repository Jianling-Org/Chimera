from __future__ import annotations

import hashlib
import json
import os
import shlex
import subprocess
import tempfile
import unittest
from pathlib import Path

from chimera.compiler_plan import load_rebuild_plan, publish_rebuild_plan


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _scope(version: int = 24, *, policy: str = "conservative") -> dict:
    return {
        "target": {"os": "linux", "arch": "riscv64", "extension": "rvv",
                   "runtime_scene": "linux_riscv64_rvv_v1"},
        "runtime_abi": 1,
        "checks": [{"id": "safety.stack-liveness", "version": version,
                    "parameters": {"unknown_stack_size_policy": policy}}],
    }


def _report(elf: Path, *, version: int = 24, policy: str = "conservative",
            names: list[str] | None = None, strategy: str = "gate",
            function_pointer: bool = False, checks: list | None = None,
            scope_checks: list | None = None) -> dict:
    digest = _sha256(elf.read_bytes())
    scope = _scope(version, policy=policy)
    if scope_checks is not None:
        scope["checks"] = scope_checks
    fingerprint = _sha256(_canonical({"elf_sha256": digest, "scope": scope}).encode())
    actual_checks = checks if checks is not None else [
        {"id": "safety.stack-liveness", "version": version,
         "parameters": {"unknown_stack_size_policy": policy}, "passed": False,
         "diagnostics": {}}
    ]
    return {
        "schema": "chimera.check.v1",
        "elf": {"path": str(elf.resolve()), "content_sha256": digest},
        "target": scope["target"], "runtime_abi": 1,
        "check_scope": scope, "check_fingerprint": fingerprint,
        "checks": actual_checks, "passed": False, "message": "findings",
        "decision": {
            "strategy": strategy,
            "vector_gate": {"enabled": strategy == "gate", "names_source": "report"},
            "function_pointer_plugin": function_pointer,
            "stack_object_plugin": False,
            "gate": {"enabled": strategy == "gate", "names": names or []},
        },
    }


class CompilerPlanTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.out = self.root / "plan with spaces"
        self.out.mkdir()
        (self.out / "reports").mkdir()
        self.profile = self.root / "profile.toml"
        self.profile.write_text('name = "test"\n', encoding="utf-8")
        self.elf = self.root / "input elf"
        self.elf.write_bytes(b"original elf bytes")
        self.report = self.root / "report.json"
        self.report.write_text(json.dumps(_report(self.elf, names=["foo", "bar"])),
                               encoding="utf-8")
        self.launcher = ["python with spaces", "-I", "-m", "chimera.pkg"]

    def tearDown(self):
        self.temp.cleanup()

    def publish(self, stage="gate", reports=None):
        return publish_rebuild_plan(self.out, stage=stage, profile=self.profile,
                                    reports=reports or [self.report], launcher=self.launcher)

    def test_metadata_stage_forces_stack_only_and_load_returns_owned_decision(self):
        path = self.publish("metadata")
        decision, owned_path = load_rebuild_plan(self.out)
        self.assertEqual(path, self.out / "build-plan.json")
        self.assertEqual(owned_path, self.out / "decision.json")
        self.assertEqual(decision["strategy"], "none")
        self.assertFalse(decision["vector_gate"]["enabled"])
        self.assertFalse(decision["function_pointer_plugin"])
        self.assertTrue(decision["stack_object_plugin"])
        self.assertEqual(decision["gate"]["names"], [])
        self.assertEqual(json.loads(self.report.read_text())["decision"]["strategy"], "gate")

    def test_gate_stage_unions_names_and_saves_snapshots_and_script(self):
        second_elf = self.root / "input2"
        second_elf.write_bytes(b"elf two")
        second_report = self.root / "report2.json"
        second_report.write_text(json.dumps(_report(second_elf, names=["baz", "foo"])),
                                 encoding="utf-8")
        self.publish(reports=[self.report, second_report])
        decision, _ = load_rebuild_plan(self.out)
        self.assertEqual(decision["strategy"], "gate")
        self.assertEqual(decision["gate"]["names"], ["bar", "baz", "foo"])
        plan = json.loads((self.out / "build-plan.json").read_text())
        self.assertEqual(len(plan["reports"]), 2)
        self.assertTrue((self.out / plan["profile"]["path"]).is_file())
        self.assertEqual(plan["profile"]["path"], "profile.snapshot.toml")
        self.assertTrue((self.out / plan["reports"][0]["path"]).is_file())
        self.assertTrue((self.out / "cc").is_file())
        self.assertTrue((self.out / "cxx").is_file())
        self.assertEqual(json.loads(self.report.read_text())["decision"]["gate"]["names"],
                         ["foo", "bar"])

    def test_external_report_is_copied_into_owned_reports(self):
        original = self.report.read_bytes()
        self.publish()
        plan = json.loads((self.out / "build-plan.json").read_text())
        frozen = self.out / plan["reports"][0]["path"]
        self.assertNotEqual(frozen.resolve(), self.report.resolve())
        self.assertEqual(frozen.read_bytes(), original)
        self.assertEqual(self.report.read_bytes(), original)

    def test_check_outcome_order_may_differ_from_canonical_scope_order(self):
        doc = _report(self.elf)
        alpha = {"id": "a.check", "version": 2, "parameters": {"mode": "a"}}
        omega = {"id": "z.check", "version": 1, "parameters": {"mode": "z"}}
        doc["check_scope"]["checks"] = [alpha, omega]
        doc["checks"] = [
            {**omega, "passed": False, "diagnostics": {}},
            {**alpha, "passed": False, "diagnostics": {}},
        ]
        doc["check_fingerprint"] = _sha256(_canonical({
            "elf_sha256": doc["elf"]["content_sha256"], "scope": doc["check_scope"]
        }).encode())
        self.report.write_text(json.dumps(doc), encoding="utf-8")
        self.publish()
        self.assertTrue((self.out / "build-plan.json").is_file())

    def test_same_check_id_with_distinct_full_identities_is_allowed(self):
        doc = _report(self.elf)
        one = {"id": "same.check", "version": 1, "parameters": {"mode": "one"}}
        two = {"id": "same.check", "version": 2, "parameters": {"mode": "two"}}
        doc["check_scope"]["checks"] = [one, two]
        doc["checks"] = [{**two, "passed": False, "diagnostics": {}},
                          {**one, "passed": False, "diagnostics": {}}]
        doc["check_fingerprint"] = _sha256(_canonical({
            "elf_sha256": doc["elf"]["content_sha256"], "scope": doc["check_scope"]
        }).encode())
        self.report.write_text(json.dumps(doc), encoding="utf-8")
        self.publish()

    def test_gate_stage_allows_no_findings_with_none_strategy(self):
        self.report.write_text(json.dumps(_report(self.elf, strategy="none")), encoding="utf-8")
        self.publish()
        decision, _ = load_rebuild_plan(self.out)
        self.assertEqual(decision["strategy"], "none")
        self.assertFalse(decision["gate"]["enabled"])

    def test_mismatched_scope_is_rejected(self):
        other_elf = self.root / "other"
        other_elf.write_bytes(b"two")
        other = self.root / "other.json"
        other.write_text(json.dumps(_report(other_elf, policy="strict")), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "scope"):
            self.publish(reports=[self.report, other])

    def test_mismatched_check_version_is_rejected(self):
        other_elf = self.root / "other"
        other_elf.write_bytes(b"two")
        other = self.root / "other.json"
        other.write_text(json.dumps(_report(other_elf, version=23)), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "scope"):
            self.publish(reports=[self.report, other])

    def test_invalid_report_identity_and_fingerprint_are_rejected(self):
        doc = _report(self.elf)
        doc["check_fingerprint"] = "0" * 64
        self.report.write_text(json.dumps(doc), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "fingerprint"):
            self.publish()

    def test_report_elf_hash_must_match_original_file(self):
        doc = _report(self.elf)
        self.elf.write_bytes(b"changed after check")
        self.report.write_text(json.dumps(doc), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "ELF|elf"):
            self.publish()

    def test_empty_checks_and_malformed_check_schema_are_rejected(self):
        doc = _report(self.elf)
        doc["checks"] = []
        self.report.write_text(json.dumps(doc), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "check"):
            self.publish()

    def test_bad_report_schema_is_rejected(self):
        doc = _report(self.elf)
        doc["schema"] = "chimera.check.v2"
        self.report.write_text(json.dumps(doc), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "schema"):
            self.publish()

    def test_gate_stage_rejects_svf_and_function_pointer_routes(self):
        self.report.write_text(json.dumps(_report(self.elf, strategy="svf",
                                                  function_pointer=True)), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "strategy|function.pointer|SVF|svf"):
            self.publish()

    def test_gate_names_reject_line_breaks_and_nul(self):
        for name in ("line\nbreak", "line\rbreak", "nul\x00name"):
            self.report.write_text(json.dumps(_report(self.elf, names=[name])), encoding="utf-8")
            with self.subTest(name=repr(name)), self.assertRaisesRegex(ValueError, "name"):
                self.publish()

    def test_existing_owned_paths_are_never_overwritten(self):
        for name in ("cc", "cxx", "decision.json", "build-plan.json"):
            path = self.out / name
            path.write_text("keep", encoding="utf-8")
            with self.subTest(name=name), self.assertRaisesRegex(FileExistsError, name):
                self.publish()
            self.assertEqual(path.read_text(), "keep")
            path.unlink()

    def test_missing_profile_is_rejected_without_partial_publication(self):
        self.profile.unlink()
        with self.assertRaisesRegex((ValueError, FileNotFoundError), "profile|Profile"):
            self.publish()
        self.assertFalse((self.out / "cc").exists())

    def test_report_tampering_after_publication_is_detected(self):
        self.publish()
        plan = json.loads((self.out / "build-plan.json").read_text())
        snapshot = self.out / plan["reports"][0]["path"]
        snapshot.write_text(snapshot.read_text() + " ", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "report|digest|hash"):
            load_rebuild_plan(self.out)

    def test_decision_tampering_after_publication_is_detected(self):
        self.publish()
        decision_file = self.out / "decision.json"
        doc = json.loads(decision_file.read_text())
        doc["decision"]["gate"]["names"] = ["injected"]
        decision_file.write_text(json.dumps(doc), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "decision|digest|hash"):
            load_rebuild_plan(self.out)

    def test_load_requires_enabled_fields_to_be_booleans(self):
        self.publish()
        decision_path = self.out / "decision.json"
        doc = json.loads(decision_path.read_text())
        doc["decision"]["gate"]["enabled"] = 1
        decision_bytes = (json.dumps(doc, indent=2, ensure_ascii=False) + "\n").encode()
        decision_path.write_bytes(decision_bytes)
        plan_path = self.out / "build-plan.json"
        plan = json.loads(plan_path.read_text())
        plan["decision"]["sha256"] = _sha256(decision_bytes)
        plan_path.write_text(json.dumps(plan, indent=2, ensure_ascii=False) + "\n")
        with self.assertRaisesRegex(ValueError, "decision|effective"):
            load_rebuild_plan(self.out)

    def test_manifest_owned_paths_must_be_safe_nonempty_strings(self):
        self.publish()
        plan_path = self.out / "build-plan.json"
        original = json.loads(plan_path.read_text())
        for path in ("", "../outside.json", "./reports/report.json", "reports/../x",
                     None, 7, "reports/\x00bad.json"):
            plan = json.loads(json.dumps(original))
            plan["reports"][0]["path"] = path
            plan_path.write_text(json.dumps(plan), encoding="utf-8")
            with self.subTest(path=repr(path)), self.assertRaises(ValueError):
                load_rebuild_plan(self.out)

    def test_relative_output_directory_is_canonicalized(self):
        relative = Path(os.path.relpath(self.out, Path.cwd()))
        path = publish_rebuild_plan(relative, stage="gate", profile=self.profile,
                                    reports=[self.report], launcher=self.launcher)
        self.assertTrue(path.is_absolute())
        cc = (self.out / "cc").read_text(encoding="utf-8")
        self.assertIn(shlex.quote(os.fspath(self.out.resolve())), cc)

    def test_missing_unsupported_stage_and_failed_publish_cleanup(self):
        with self.assertRaisesRegex(ValueError, "stage"):
            self.publish("future")
        with self.assertRaisesRegex(ValueError, "stage"):
            self.publish("metadata-gate")

        # Force a late failure after the profile snapshot is written. The
        # colliding user report remains untouched and no partial plan files
        # are left behind.
        (self.out / "reports" / "0001-report.json").write_text("keep", encoding="utf-8")
        with self.assertRaisesRegex(FileExistsError, "snapshot"):
            self.publish()
        self.assertEqual((self.out / "reports" / "0001-report.json").read_text(), "keep")
        for name in ("profile.snapshot.toml", "decision.json", "build-plan.json", "cc", "cxx"):
            self.assertFalse((self.out / name).exists(), name)

    @unittest.skipIf(os.name == "nt" and not os.environ.get("BASH"), "set BASH to a POSIX shell on Windows")
    def test_cc_forwards_arbitrary_arguments_through_launcher(self):
        capture = self.root / "argv.json"
        executable = self.root / "launcher.py"
        executable.write_text(
            "import json,sys; open(sys.argv[1], 'w').write(json.dumps(sys.argv[2:]))\n",
            encoding="utf-8",
        )
        self.publish()
        # Replace the entry with a launcher that records the argv while retaining
        # the exact quoting/forwarding form produced by the service.
        out = self.root / "runtime output"
        out.mkdir()
        (out / "reports").mkdir()
        publish_rebuild_plan(out, stage="gate", profile=self.profile, reports=[self.report],
                             launcher=[os.fspath(Path(os.sys.executable)), os.fspath(executable),
                                       os.fspath(capture)])
        for name, selector in (("cc", []), ("cxx", ["--cxx"])):
            entry = out / name
            command = [os.fspath(entry)] if os.name != "nt" else [os.environ["BASH"], os.fspath(entry)]
            result = subprocess.run([*command, "arg with spaces", "$(literal)", ""],
                                    check=False, capture_output=True, text=True)
            with self.subTest(name=name):
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(json.loads(capture.read_text()), ["llvm", "--build-plan",
                                 os.fspath(out), *selector, "--", "arg with spaces", "$(literal)", ""])


if __name__ == "__main__":
    unittest.main()
