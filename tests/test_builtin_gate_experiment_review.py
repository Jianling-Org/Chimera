"""Independent review: run orchestration, binding, and real wrapper expansion."""
import hashlib
import json
import shlex
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from tools import builtin_gate_experiment as exp
from tools import builtin_gate_inputs as inputs


class ExperimentReviewTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="builtin experiment review ")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.cwd = self.root / "run" / "build-gate4" / "gcc"
        self.cwd.mkdir(parents=True)
        self.origin = self.root / "run" / "reports" / "origin"
        self.origin.mkdir(parents=True)
        self.source = self.root / "src" / "c-family" / "c-cppbuiltin.cc"
        self.source.parent.mkdir(parents=True)
        self.source.write_text("source", encoding="utf-8")
        self.wrapper = self.origin / "gate4-cxx"
        self.wrapper.write_text("archived wrapper", encoding="utf-8")
        self.decision = self.origin / "gate4.decision.json"
        self.decision.write_text(json.dumps({"decision": {
            "stack_object_plugin": True, "gate": {"enabled": True, "names": ["other"]}}}), encoding="utf-8")
        for name in ("cc1", "xgcc"):
            (self.cwd / name).write_bytes(name.encode())
        (self.origin / "build.exit.txt").write_text("0")
        (self.origin / "build.time.txt").write_text("Exit status: 0\n")
        (self.origin / "elf.sha256").write_text("".join(
            exp.sha256(self.cwd / name) + "  " + name + "\n" for name in ("cc1", "xgcc")))
        (self.origin / "inputs.sha256").write_text(exp.sha256(self.decision) + "  gate4.decision.json\n")
        argv = [self.wrapper.as_posix(), "-O2", "-c", "-o", inputs.OUTPUT, self.source.as_posix()]
        raw = shlex.join(argv)
        self.log = self.origin / "build.log"
        self.log.write_text(f"make[1]: Entering directory '{self.cwd.as_posix()}'\n{raw}\n"
                            f"make[1]: Leaving directory '{self.cwd.as_posix()}'\n", encoding="utf-8")
        with self.log.open(encoding="utf-8") as stream:
            entry = inputs.find_compile(stream)
        self.obj = self.root / "collected.o"
        self.obj.write_bytes(b"object")
        self.compiler = self.root / "toolchain" / "clang++"
        self.compiler.parent.mkdir()
        self.compiler.write_bytes(b"compiler")
        self.plugins = [self.root / "stack.so", self.root / "gate.so"]
        for path in self.plugins:
            path.write_bytes(path.name.encode())
        self.collection = {
            "schema": "chimera-builtin-gate-inputs-v1", "symbol": exp.SYMBOL,
            "historical": {"valid": True,
                "decision": {"path": str(self.decision), "sha256": exp.sha256(self.decision)},
                "verified_elfs": {name: {"path": str(self.cwd / name), "sha256": exp.sha256(self.cwd / name)}
                                  for name in ("xgcc", "cc1")}},
            "logged_compile_entry": entry,
            "build_log": {"path": str(self.log), "sha256": exp.sha256(self.log)},
            "historical_wrapper_candidates": [{"path": str(self.wrapper), "sha256": exp.sha256(self.wrapper)}],
            "archived_wrapper_copy": {"path": str(self.wrapper), "sha256": exp.sha256(self.wrapper)},
            "object": {"path": str(self.obj), "sha256": exp.sha256(self.obj)},
            "current": {"compiler": {"path": str(self.compiler), "sha256": exp.sha256(self.compiler)},
                "plugins": [{"path": str(path), "sha256": exp.sha256(path)} for path in self.plugins],
                "source_candidates": [{"path": str(self.source), "sha256": exp.sha256(self.source)}]},
            "dwarf_compile_units": [{"name": str(self.source), "comp_dir": str(self.cwd)}]}
        self.collection_path = self.root / "collection.json"
        self.out = self.root / "experiment"
        self.args = SimpleNamespace(out=self.out, collection=self.collection_path, policy=exp.POLICY,
                                    objdump=str(self.compiler), readelf=str(self.compiler))
        self.dump = f"Disassembly of section .text:\n\n0000 <{exp.SYMBOL}>:\n 0:\t00008067\tret\n"
        self.coords = exp.forensic._object_coordinates(self.dump, "REL")

    def save(self):
        self.collection_path.write_text(json.dumps(self.collection), encoding="utf-8")

    def invoke(self, a_match=True, b_exit=0, b_facts=None, b_complete=True):
        self.save()
        calls = []

        def capture(_out, params, _decision, **_kwargs):
            self.assertEqual(list(params), self.collection["logged_compile_entry"]["argv"][1:])
            return {"expanded_argv": [str(self.compiler), *[f"-fpass-plugin={p}" for p in self.plugins], *params],
                    "compiler_invocation": str(self.compiler), "compiler_sha256": exp.sha256(self.compiler)}

        def group(label, *_args):
            calls.append(label)
            return {"label": label, "compile": {"exit_code": b_exit if label == "B" else 0},
                    "function_inspected": True,
                    "object_exists": label == "A" or b_exit == 0,
                    "object_coordinates": self.coords if a_match else [],
                    "vector_evidence": {"instruction_count": 1, "vector_instruction_count": 0,
                                        "vector_instructions": [], "vs2r_v": [], "vlen_reads": []},
                    "local_source": {"label": label,
                        "status": "complete" if label == "A" or b_complete else "incomplete",
                        "facts": (b_facts or {}) if label == "B" else {}, "gaps": []}}

        with patch.object(exp, "capture_current_wrapper", side_effect=capture), \
                patch.object(exp, "_run_group", side_effect=group), \
                patch.object(exp.forensic, "_run_capture", side_effect=[(0, self.dump), (0, "Type: REL")]):
            rc = exp.run(self.args)
        return rc, json.loads((self.out / "result.json").read_text(encoding="utf-8")), calls

    def test_actual_run_orders_a_before_b_and_preserves_decision(self):
        original = self.decision.read_bytes()
        rc, result, calls = self.invoke()
        self.assertEqual(rc, 0, result.get("gaps"))
        self.assertEqual(calls, ["A", "B"])
        self.assertEqual(self.decision.read_bytes(), original)
        self.assertEqual((self.out / "group-A/decision.json").read_bytes(), original)
        variant = json.loads((self.out / "binding/decision-B.json").read_text())
        variant["decision"]["gate"]["names"] = ["other"]
        self.assertEqual(variant, json.loads(original))
        self.assertFalse(result["root_cause_confirmed"])

    def test_actual_run_mismatch_does_not_invoke_b(self):
        rc, result, calls = self.invoke(a_match=False)
        self.assertNotEqual(rc, 0)
        self.assertEqual(calls, ["A"])
        self.assertEqual(result["status"], "stopped-before-B")
        self.assertFalse((self.out / "group-B").exists())

    def test_actual_b_failure_cannot_claim_vector_elimination(self):
        rc, result, calls = self.invoke(b_exit=1)
        self.assertEqual(calls, ["A", "B"])
        self.assertNotEqual(rc, 0)
        self.assertIsNone(result["vector_delta"]["vector_instructions_eliminated"])

    def test_changed_wrapper_and_decision_each_block_binding(self):
        for field in ("historical_wrapper_candidates", "historical"):
            with self.subTest(field=field):
                target = self.wrapper if field == "historical_wrapper_candidates" else self.decision
                original = target.read_bytes()
                target.write_bytes(original + b"changed")
                with self.assertRaises(ValueError):
                    exp.validate_collection(self.collection, self.collection_path)
                target.write_bytes(original)

    def test_argv_cannot_diverge_from_hashed_log(self):
        self.collection["logged_compile_entry"]["argv"].insert(1, "-O0")
        with self.assertRaisesRegex(ValueError, "build log entry"):
            exp.validate_collection(self.collection, self.collection_path)

    def test_existing_output_remains_unchanged(self):
        self.out.mkdir()
        sentinel = self.out / "report.md"
        sentinel.write_text("previous report")
        with self.assertRaises(ValueError):
            exp.run(self.args)
        self.assertEqual(sentinel.read_text(), "previous report")
        self.assertEqual(list(self.out.iterdir()), [sentinel])

    def test_vector_absence_does_not_override_retained_frame_marker(self):
        rc, result, _ = self.invoke(b_facts={"vlen_frame_marker_live_at": ["0x4"]})
        self.assertEqual(rc, 0)
        self.assertTrue(result["vector_delta"]["vector_instructions_eliminated"])
        self.assertFalse(result["fully_eliminated"])

    def test_local_incomplete_keeps_overall_elimination_unknown(self):
        rc, result, _ = self.invoke(b_complete=False)
        self.assertNotEqual(rc, 0)
        self.assertIsNone(result["fully_eliminated"])
        self.assertIn("incomplete", " ".join(result["gaps"]))

    def test_target_name_in_comment_is_not_a_function_definition(self):
        self.assertFalse(exp._has_exact_function_header(f"0000 <other>:\n # {exp.SYMBOL}\n"))

    def test_already_gated_target_is_rejected_before_compilation(self):
        document = json.loads(self.decision.read_text())
        document["decision"]["gate"]["names"].append(exp.SYMBOL)
        self.decision.write_text(json.dumps(document), encoding="utf-8")
        digest = exp.sha256(self.decision)
        self.collection["historical"]["decision"]["sha256"] = digest
        (self.origin / "inputs.sha256").write_text(digest + "  gate4.decision.json\n")
        rc, result, calls = self.invoke()
        self.assertNotEqual(rc, 0)
        self.assertEqual(calls, [])

    def test_capture_real_wrapper_without_executing_compiler(self):
        from chimera import llvm_wrapper
        compiler_bin = self.root / "llvm" / "bin"
        compiler_bin.mkdir(parents=True)
        (compiler_bin / "clang++").write_bytes(b"compiler")
        plugin_dir = self.root / "plugins"
        plugin_dir.mkdir()
        for name in ("ChimeraStackObject.so", "ChimeraVectorGate.so"):
            (plugin_dir / name).write_bytes(b"plugin")
        with patch.object(llvm_wrapper, "_toolchain_paths", return_value=(compiler_bin, plugin_dir)):
            captured = exp.capture_current_wrapper(
                self.out, ["-c", "source.cc", "-o", "original.o"], self.decision.read_bytes(),
                wrapper=llvm_wrapper.run_llvm_wrapper, expected_compiler=compiler_bin / "clang++")
        self.assertEqual(captured["expanded_argv"][1:3], [
            f"-fpass-plugin={plugin_dir / 'ChimeraStackObject.so'}",
            f"-fpass-plugin={plugin_dir / 'ChimeraVectorGate.so'}"])
        self.assertFalse((self.root / "original.o").exists())
        self.assertTrue(any(self.out.glob("*.gate_names.txt")))


if __name__ == "__main__":
    unittest.main()
