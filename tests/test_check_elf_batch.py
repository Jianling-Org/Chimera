"""Native sequential check-elf batches and fixed compiler entry publication."""
from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from chimera import cli
from chimera import llvm_wrapper
from chimera.elf_state import CHECKED, PROBLEMATIC, ElfStateRegistry
from chimera.preprocess.offline.analysis_profile.checks import (
    BinaryCheckOutcome, BinaryCheckPlan, BinaryCheckRequest,
)


class CheckElfBatchTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.profile = self.root / "profile.toml"
        self.profile.write_text("# fixed test profile\n", encoding="utf-8")
        self.first = self.root / "xgcc"
        self.second = self.root / "cc1"
        self.first.write_bytes(b"xgcc test payload")
        self.second.write_bytes(b"cc1 test payload")
        self.calls = []
        self.candidate_scans = []
        self.candidate_functions = []
        self.fail_on = None
        self.during_check = None
        self.during_configuration = None
        self.negative = set()
        self.registry = ElfStateRegistry(self.root / "registry.json")
        self.configuration = SimpleNamespace(
            base=SimpleNamespace(tools=SimpleNamespace(objdump="objdump")),
        )

        def runner(path, context):
            self.calls.append(path)
            if self.during_check is not None:
                self.during_check(path)
            if path == self.fail_on:
                raise RuntimeError("objdump failed for cc1")
            passed = path not in self.negative
            inheritance = context.overrides.get("inheritance_report")
            if inheritance is not None:
                Path(inheritance).parent.mkdir(parents=True, exist_ok=True)
                Path(inheritance).write_text(json.dumps({"elf": path.name}), encoding="utf-8")
            return BinaryCheckOutcome(
                passed=passed, actionable=not passed,
                diagnostics={"findings": [] if passed else [{"kind": "local-root"}]},
                decision={
                    "strategy": "gate", "function_pointer_plugin": False,
                    "stack_object_plugin": False,
                    "vector_gate": {"enabled": True},
                    "gate": {"enabled": True, "names": [path.name, "shared"]},
                },
            )

        self.plan = BinaryCheckPlan(
            configuration=self.configuration,
            target_key=("linux", "riscv64", "rvv", "linux_riscv64_rvv_v1"),
            runtime_abi=1,
            requests=(BinaryCheckRequest(
                "safety.stack-liveness", 23, {"min_vlen_bits": 256}, runner,
            ),),
        )

    def invoke(self, *options):
        argv = ["check-elf", "--profile", str(self.profile), "--strategy", "gate", *map(str, options)]
        def configuration(_arguments):
            if self.during_configuration is not None:
                self.during_configuration()
            return self.configuration

        def scan(path, command):
            import hashlib
            self.candidate_scans.append((path, command))
            return {"elf": {"path": str(path.resolve()),
                            "content_sha256": hashlib.sha256(path.read_bytes()).hexdigest()},
                    "functions": self.candidate_functions}

        with mock.patch("chimera.compiler_plan.scan_width_gate_candidates", side_effect=scan), \
            mock.patch.object(cli, "_configuration", side_effect=configuration), \
            mock.patch.object(cli, "build_check_plan", return_value=self.plan), \
            mock.patch.object(cli, "ElfStateRegistry", return_value=self.registry), \
            mock.patch.object(cli, "write_latest_pointer"), \
            contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            try:
                return cli.main(argv, command_group="pkg", prog="chimera-pkg")
            except SystemExit as error:
                return error.code

    def rebuild(self, stage="metadata", *extra):
        output = self.root / "next build"
        rc = self.invoke(
            "--input", self.first, "--input", self.second,
            "--rebuild-stage", stage, "--rebuild-dir", output, *extra,
        )
        return rc, output


    def test_gate_publication_automatically_scans_actual_inputs(self):
        from chimera.gate_candidates import candidates_from_dump
        from test_gate_candidates import DUMP
        self.candidate_functions = list(candidates_from_dump(DUMP.splitlines()))[:1]
        rc, output = self.rebuild("gate")
        self.assertEqual(rc, 0)
        self.assertEqual(self.candidate_scans, [(self.first, "objdump"), (self.second, "objdump")])
        from chimera.compiler_plan import load_rebuild_plan
        decision, _ = load_rebuild_plan(output)
        self.assertIn("quiet_width_vector", decision["gate"]["names"])

    def test_multiple_inputs_are_checked_sequentially(self):
        rc = self.invoke("--input", self.first, "--input", self.second)
        self.assertEqual(rc, 0)
        self.assertEqual(self.calls, [self.first, self.second])
        self.assertTrue(Path(str(self.first) + ".check.json").is_file())
        self.assertTrue(Path(str(self.second) + ".check.json").is_file())

    def test_one_input_preserves_custom_report_and_inheritance_paths(self):
        report = self.root / "one.json"
        inheritance = self.root / "trace.json"
        rc = self.invoke("--input", self.first, "--json", report, "--inheritance-report", inheritance)
        self.assertEqual(rc, 0)
        self.assertEqual(json.loads(report.read_text(encoding="utf-8"))["elf"]["path"], str(self.first))
        self.assertTrue(inheritance.is_file())

    def test_batch_explicit_output_directories_do_not_collide(self):
        report_dir = self.root / "check reports"
        trace_dir = self.root / "trace reports"
        rc = self.invoke(
            "--input", self.first, "--input", self.second,
            "--json", report_dir, "--inheritance-report", trace_dir,
        )
        self.assertEqual(rc, 0)
        self.assertEqual(len(list(report_dir.glob("*.check.json"))), 2)
        self.assertEqual(len(list(trace_dir.glob("*.inheritance.json"))), 2)

    def test_strict_uses_all_input_results(self):
        self.negative.add(self.first)
        rc = self.invoke("--input", self.first, "--input", self.second, "--strict")
        self.assertEqual(rc, 1)
        self.assertEqual(self.calls, [self.first, self.second])
        self.assertEqual(self.registry.entry(self.first).status, PROBLEMATIC)
        self.assertEqual(self.registry.entry(self.second).status, CHECKED)

    def test_metadata_entries_are_published_after_complete_negative_checks(self):
        self.negative.add(self.first)
        rc, output = self.rebuild()
        self.assertEqual(rc, 0)
        self.assertEqual(self.calls, [self.first, self.second])
        self.assertTrue((output / "cc").is_file())
        self.assertTrue((output / "cxx").is_file())
        self.assertEqual(len(list((output / "reports").glob("*.check.json"))), 2)
        self.assertEqual(len(list((output / "reports").glob("*.inheritance.json"))), 2)
        decision = json.loads((output / "decision.json").read_text(encoding="utf-8"))["decision"]
        self.assertTrue(decision["stack_object_plugin"])
        self.assertFalse(decision["gate"]["enabled"])

    def test_gate_stage_merges_both_decisions_and_keeps_metadata(self):
        rc, output = self.rebuild("gate")
        self.assertEqual(rc, 0)
        decision = json.loads((output / "decision.json").read_text(encoding="utf-8"))["decision"]
        self.assertEqual(decision["gate"]["names"], ["cc1", "shared", "xgcc"])
        self.assertTrue(decision["stack_object_plugin"])
        self.assertFalse(decision["function_pointer_plugin"])

    def test_strict_negative_still_publishes_a_remediation_plan(self):
        self.negative.add(self.second)
        rc, output = self.rebuild("gate", "--strict")
        self.assertEqual(rc, 1)
        self.assertTrue((output / "cc").is_file())

    def test_operational_failure_preserves_reports_without_compiler_entries(self):
        self.fail_on = self.second
        rc, output = self.rebuild()
        self.assertEqual(rc, 2)
        self.assertEqual(self.calls, [self.first, self.second])
        self.assertEqual(len(list((output / "reports").glob("*.check.json"))), 1)
        self.assertFalse((output / "cc").exists())
        self.assertFalse((output / "cxx").exists())
        self.assertFalse((output / "build-plan.json").exists())

    def test_duplicate_canonical_inputs_are_rejected_before_analysis(self):
        rc = self.invoke("--input", self.first, "--input", self.first.parent / "." / self.first.name)
        self.assertEqual(rc, 2)
        self.assertEqual(self.calls, [])

    def test_report_cannot_overwrite_input_or_profile(self):
        for destination in (self.first, self.second, self.profile):
            with self.subTest(destination=destination):
                rc = self.invoke("--input", self.first, "--input", self.second, "--json", destination)
                self.assertEqual(rc, 2)
                self.assertEqual(self.calls, [])
        rc = self.invoke("--input", self.first, "--json", self.first)
        self.assertEqual(rc, 2)
        self.assertEqual(self.first.read_bytes(), b"xgcc test payload")

    def test_check_and_inheritance_paths_cannot_be_the_same(self):
        destination = self.root / "shared.json"
        rc = self.invoke("--input", self.first, "--json", destination, "--inheritance-report", destination)
        self.assertEqual(rc, 2)
        self.assertEqual(self.calls, [])

    def test_existing_rebuild_directory_is_not_reused(self):
        output = self.root / "next build"
        output.mkdir()
        marker = output / "cc"
        marker.write_text("keep existing compiler", encoding="utf-8")
        rc, _ = self.rebuild()
        self.assertEqual(rc, 2)
        self.assertEqual(self.calls, [])
        self.assertEqual(marker.read_text(encoding="utf-8"), "keep existing compiler")

    def test_rebuild_options_must_be_given_together(self):
        for options in (("--rebuild-stage", "metadata"), ("--rebuild-dir", self.root / "new")):
            with self.subTest(options=options):
                self.assertEqual(self.invoke("--input", self.first, *options), 2)
                self.assertEqual(self.calls, [])

    def test_rebuild_requires_a_nonempty_check_scope(self):
        self.plan = BinaryCheckPlan(self.configuration, self.plan.target_key, 1, ())
        rc, output = self.rebuild()
        self.assertEqual(rc, 2)
        self.assertEqual(self.calls, [])
        self.assertFalse((output / "cc").exists())

    def test_profile_change_while_loading_configuration_stops_before_analysis(self):
        self.during_configuration = lambda: self.profile.write_text(
            "# different safety policy\n", encoding="utf-8",
        )
        rc, output = self.rebuild()
        self.assertEqual(rc, 2)
        self.assertEqual(self.calls, [])
        self.assertFalse((output / "cc").exists())

    def test_profile_change_during_analysis_retains_reports_but_no_entries(self):
        self.during_check = lambda _path: self.profile.write_text(
            "# changed policy\n", encoding="utf-8",
        )
        rc, output = self.rebuild()
        self.assertEqual(rc, 2)
        self.assertEqual(len(list((output / "reports").glob("*.check.json"))), 2)
        self.assertFalse((output / "cc").exists())

    def test_input_change_during_analysis_does_not_create_a_credential(self):
        self.during_check = lambda path: path.write_bytes(b"changed ELF")
        rc, output = self.rebuild()
        self.assertEqual(rc, 2)
        self.assertIsNone(self.registry.entry(self.first))
        self.assertFalse((output / "cc").exists())

    def test_interrupt_retains_completed_reports_without_entries(self):
        def interrupt(path):
            if path == self.second:
                raise KeyboardInterrupt
        self.during_check = interrupt
        rc, output = self.rebuild()
        self.assertEqual(rc, 130)
        self.assertEqual(len(list((output / "reports").glob("*.check.json"))), 1)
        self.assertFalse((output / "cc").exists())

    def test_same_basename_inputs_have_distinct_owned_reports(self):
        self.second = self.root / "other" / "xgcc"
        self.second.parent.mkdir()
        self.second.write_bytes(b"different project component")
        rc, output = self.rebuild()
        self.assertEqual(rc, 0)
        self.assertEqual(
            sorted(path.name for path in (output / "reports").glob("*.check.json")),
            ["0001-xgcc.check.json", "0002-xgcc.check.json"],
        )

    def test_report_hardlink_to_input_is_rejected_before_analysis(self):
        alias = self.root / "aliased.json"
        try:
            alias.hardlink_to(self.first)
        except OSError as error:
            self.skipTest(str(error))
        rc = self.invoke("--input", self.first, "--json", alias)
        self.assertEqual(rc, 2)
        self.assertEqual(self.calls, [])
        self.assertEqual(self.first.read_bytes(), b"xgcc test payload")

    def test_atomic_report_temporary_cannot_overwrite_an_input(self):
        self.first = self.root / "output.json.tmp"
        self.first.write_bytes(b"original ELF")
        rc = self.invoke("--input", self.first, "--json", self.root / "output.json")
        self.assertEqual(rc, 2)
        self.assertEqual(self.calls, [])
        self.assertEqual(self.first.read_bytes(), b"original ELF")

    def test_output_cannot_be_another_reports_temporary(self):
        report = self.root / "report.json"
        rc = self.invoke(
            "--input", self.first, "--json", report,
            "--inheritance-report", self.root / "report.json.tmp",
        )
        self.assertEqual(rc, 2)
        self.assertEqual(self.calls, [])

    def test_reports_cannot_use_compiler_plan_reserved_paths(self):
        for name in ("cc", "cxx", "decision.json", "build-plan.json", "profile.snapshot.toml"):
            with self.subTest(name=name):
                output = self.root / ("next-" + name)
                rc = self.invoke(
                    "--input", self.first, "--rebuild-stage", "metadata",
                    "--rebuild-dir", output, "--json", output / name,
                )
                self.assertEqual(rc, 2)
                self.assertEqual(self.calls, [])

    def test_report_file_cannot_be_another_output_parent(self):
        report = self.root / "reports.json"
        rc = self.invoke(
            "--input", self.first, "--json", report,
            "--inheritance-report", report / "trace.json",
        )
        self.assertEqual(rc, 2)
        self.assertEqual(self.calls, [])

    def compile_from_plan(self, plan_dir, *compiler_options, returncode=0):
        bin_dir = self.root / "llvm-bin"
        plugin_dir = self.root / "llvm-plugins"
        bin_dir.mkdir(exist_ok=True)
        plugin_dir.mkdir(exist_ok=True)
        for name in ("clang", "clang++"):
            (bin_dir / name).touch()
        for name in ("ChimeraStackObject.so", "ChimeraVectorGate.so"):
            (plugin_dir / name).touch()
        compiler = mock.Mock(return_value=SimpleNamespace(returncode=returncode))
        with mock.patch.object(llvm_wrapper, "_toolchain_paths", return_value=(bin_dir, plugin_dir)), \
            mock.patch.object(llvm_wrapper, "load_latest_pointer", side_effect=AssertionError("unrelated latest was read")), \
            mock.patch.object(llvm_wrapper.subprocess, "run", compiler), \
            contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            code = cli.main([
                "llvm", "--build-plan", str(plan_dir), "--cxx", "--",
                *map(str, compiler_options),
            ], command_group="pkg", prog="chimera-pkg")
        return code, compiler

    def test_native_metadata_then_gate_plans_reach_the_real_wrapper_consumer(self):
        self.negative.add(self.first)
        rc, metadata = self.rebuild("metadata")
        self.assertEqual(rc, 0)
        code, compiler = self.compile_from_plan(metadata, "-c", "real file.cc", "-o", "out.o")
        self.assertEqual(code, 0)
        argv = compiler.call_args.args[0]
        self.assertTrue(any("ChimeraStackObject.so" in part for part in argv))
        self.assertFalse(any("ChimeraVectorGate.so" in part for part in argv))

        gate = self.root / "gate stage"
        rc = self.invoke(
            "--input", self.first, "--input", self.second,
            "--rebuild-stage", "gate", "--rebuild-dir", gate,
        )
        self.assertEqual(rc, 0)
        code, compiler = self.compile_from_plan(gate, "-c", "real file.cc", "-o", "out.o")
        self.assertEqual(code, 0)
        argv = compiler.call_args.args[0]
        self.assertTrue(any("ChimeraStackObject.so" in part for part in argv))
        self.assertTrue(any("ChimeraVectorGate.so" in part for part in argv))
        names_file = Path(compiler.call_args.kwargs["env"]["CHIMERA_GATE_LIST"])
        self.assertEqual(names_file.read_text(encoding="utf-8"), "cc1\nshared\nxgcc\n")
        self.assertEqual(self.registry.entry(self.first).status, PROBLEMATIC)

    def test_generated_plan_corruption_is_rejected_by_the_native_llvm_cli(self):
        rc, output = self.rebuild("gate")
        self.assertEqual(rc, 0)
        (output / "decision.json").write_text('{"gate": false}', encoding="utf-8")
        code, compiler = self.compile_from_plan(output, "-c", "real file.cc")
        self.assertEqual(code, 2)
        compiler.assert_not_called()


if __name__ == "__main__":
    unittest.main()
