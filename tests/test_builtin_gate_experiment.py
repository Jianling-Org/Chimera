from __future__ import annotations

import hashlib
import json
import subprocess
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from tools import builtin_gate_experiment as experiment


def put(path: Path, value: bytes | str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(value.encode() if isinstance(value, str) else value)
    return path


def collection_fixture(root: Path) -> dict:
    source = put(root / "c-family" / "c-cppbuiltin.cc", "source")
    obj = put(root / "c-cppbuiltin.o", b"object")
    wrapper = put(root / "gate4-cxx", b"wrapper")
    decision = put(root / "gate4.decision.json", json.dumps({"decision": {"gate": {
        "enabled": True, "names": ["other"]}}}))
    wrapper_arg, source_arg = wrapper.as_posix(), source.as_posix()
    raw = f"{wrapper_arg} -c -o c-family/c-cppbuiltin.o {source_arg}"
    log = put(root / "build.log", f"make[1]: Entering directory '{root}'\n{raw}\n"
              f"make[1]: Leaving directory '{root}'\n")
    entry = {"line_number": 2, "raw_line": raw,
        "raw_line_sha256": hashlib.sha256(raw.encode()).hexdigest(),
        "argv": [wrapper_arg, "-c", "-o", "c-family/c-cppbuiltin.o", source_arg],
        "cwd": str(root), "source": str(source)}
    return {
        "schema": "chimera-builtin-gate-inputs-v1", "symbol": experiment.SYMBOL,
        "historical": {"valid": True, "decision": {"path": str(decision),
            "sha256": experiment.sha256(decision)}},
        "build_log": {"path": str(log), "sha256": experiment.sha256(log)},
        "logged_compile_entry": entry,
        "historical_wrapper_candidates": [{"path": str(wrapper),
            "sha256": experiment.sha256(wrapper)}],
        "archived_wrapper_copy": {"path": str(wrapper), "sha256": experiment.sha256(wrapper)},
        "object": {"path": str(obj), "sha256": experiment.sha256(obj)},
        "current": {"source_candidates": [{"path": str(source),
            "sha256": experiment.sha256(source)}],
            "compiler": {"path": str(root / "clang-21"), "sha256": "compiler-hash"},
            "plugins": [{"path": str(root / "stack.so"), "sha256": "stack-hash"},
                        {"path": str(root / "gate.so"), "sha256": "gate-hash"}]},
        "dwarf_compile_units": [{"name": str(source), "comp_dir": str(root)}],
    }


class BuiltinGateExperimentTests(unittest.TestCase):
    def test_collection_rehashes_inputs_binds_exact_log_entry_and_preserves_history_caveat(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            collection = collection_fixture(root)
            bound = experiment.validate_collection(collection, root / "collection.json")
            self.assertIn("compiler-plugin-and-object-bindings-incomplete", bound["historical_identity"])
            self.assertEqual(bound["cwd"], root.resolve())
            put(Path(collection["object"]["path"]), b"changed")
            with self.assertRaisesRegex(ValueError, "object hash"):
                experiment.validate_collection(collection, root / "collection.json")

    def test_collection_rejects_non_unique_compile_entry_and_dwarf_mismatch(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            collection = collection_fixture(root)
            collection["logged_compile_entries"] = [collection["logged_compile_entry"]] * 2
            with self.assertRaisesRegex(ValueError, "unique"):
                experiment.validate_collection(collection, root / "collection.json")
            collection = collection_fixture(root)
            collection["dwarf_compile_units"][0]["name"] = str(root / "wrong.cc")
            with self.assertRaisesRegex(ValueError, "DWARF"):
                experiment.validate_collection(collection, root / "collection.json")

    def test_wrapper_capture_stops_before_compile_rejects_other_subprocess_and_multiple_calls(self):
        with TemporaryDirectory() as temporary:
            out = Path(temporary) / "capture"

            def invoke(arguments):
                self.assertFalse(arguments.llvm_params[0].startswith("clang"))
                subprocess.run(["C:/toolchain/bin/clang++", "-c", "source.cc"])
                return 0

            capture = experiment.capture_current_wrapper(
                out, ["-O2", "-c", "source.cc"], "decision bytes", wrapper=invoke)
            self.assertEqual(capture["status"], "captured")
            self.assertEqual(Path(capture["compiler_invocation"]).name, "clang++")
            self.assertEqual(list(out.parent.iterdir()), [out])

            def unsafe(_arguments):
                subprocess.run(["python", "-c", "print('no')"])
                return 0

            with self.assertRaisesRegex(RuntimeError, "non-compiler"):
                experiment.capture_current_wrapper(out, ["-c"], "x", wrapper=unsafe)

            def multiple(_arguments):
                try:
                    subprocess.run(["clang++", "-c"])
                except BaseException:
                    subprocess.run(["clang++", "-c"])
                return 0

            with self.assertRaisesRegex(RuntimeError, "multiple"):
                experiment.capture_current_wrapper(out, ["-c"], "x", wrapper=multiple)

    def test_a_mismatch_stops_b_and_failed_b_is_not_ready(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            a_path = put(root / "A.json", json.dumps({"decision": {"gate": {
                "enabled": True, "names": ["other"]}}}))
            b_path = root / "B.json"
            original = [{"section": ".text", "offset": 0, "instruction": "ret", "relocations": []}]
            ran = []

            def mismatch_group(label, *_args):
                ran.append(label)
                return {"compile": {"exit_code": 0}, "object_exists": True,
                        "object_coordinates": [{"section": ".text", "offset": 0,
                                                 "instruction": "nop", "relocations": []}]}

            stopped = experiment.execute_ab(root, a_path, b_path, [], root, "objdump", "readelf",
                original, run_group=mismatch_group)
            self.assertEqual(ran, ["A"])
            self.assertEqual(stopped["status"], "stopped-before-B")
            self.assertFalse(b_path.exists())

            ran.clear()

            def failed_b_group(label, *_args):
                ran.append(label)
                if label == "A":
                    return {"compile": {"exit_code": 0}, "object_exists": True,
                        "object_coordinates": original, "vector_evidence": experiment.forensic.vector_evidence(
                            "Disassembly of section .text:\n0000: 13 00 00 00 ret\n"),
                        "local_source": {"status": "complete", "facts": {}, "gaps": []}}
                return {"compile": {"exit_code": 1}, "object_exists": False, "function_inspected": False,
                        "vector_evidence": experiment.forensic.vector_evidence(""),
                        "local_source": {"status": "incomplete", "facts": {}, "gaps": ["compile failed"]}}

            failed = experiment.execute_ab(root, a_path, b_path, [], root, "objdump", "readelf",
                original, run_group=failed_b_group)
            self.assertEqual(ran, ["A", "B"])
            self.assertEqual(failed["status"], "B-incomplete-unproven")
            self.assertIsNone(failed["vector_delta"]["vector_instructions_eliminated"])
            self.assertIsNone(failed["fully_eliminated"])

    def test_both_local_analyses_use_the_same_requested_policy(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            calls = []
            with patch.object(experiment.forensic, "local_source_observation",
                              side_effect=lambda *a, **kw: calls.append(kw) or {"status": "incomplete"}):
                experiment.observe_local_source(root / "a.o", root / "A", "A")
                experiment.observe_local_source(root / "b.o", root / "B", "B")
            self.assertEqual([call["unknown_stack_size_policy"] for call in calls],
                             ["assume-scalar-independent"] * 2)

    def test_binding_failure_writes_failure_record_without_running_a_or_b(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            collection = put(root / "collection.json", json.dumps({"schema": "bad"}))
            args = type("Args", (), {"out": root / "out", "collection": collection,
                "policy": experiment.POLICY, "objdump": "objdump", "readelf": "readelf"})()
            self.assertEqual(experiment.run(args), 2)
            result = json.loads((root / "out" / "result.json").read_text())
            self.assertEqual(result["status"], "failed")
            self.assertEqual(result["groups"], {})
            self.assertTrue((root / "out" / "report.md").is_file())


if __name__ == "__main__":
    unittest.main()
