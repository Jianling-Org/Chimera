"""Independent review of input binding and evidence preservation; no compiler runs."""
import json
import shlex
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tools import builtin_gate_inputs as collector


class CollectionReviewTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="builtin review ")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.run = self.root / "run"
        self.origin = self.run / "reports" / "gate4-original"
        self.cwd = self.run / "build-gate4" / "gcc"
        self.source = self.root / "source" / "gcc" / collector.SOURCE
        self.wrapper = self.origin / "wrappers" / "gate4-cxx"
        self.wrapper.parent.mkdir(parents=True)
        self.source.parent.mkdir(parents=True)
        (self.cwd / "c-family").mkdir(parents=True)
        self.source.write_text("static void builtin_define_type_minmax() {}\n", encoding="utf-8")
        self.wrapper.write_text("#!/bin/sh\nexec compiler llvm --cxx --list decision -- \"$@\"\n", encoding="utf-8")
        (self.cwd / collector.OUTPUT).write_bytes(b"fixture object")
        for name in ("xgcc", "cc1"):
            (self.cwd / name).write_bytes(name.encode())
        # The real historical file had a shell bookkeeping error; time is authoritative.
        (self.origin / "build.exit.txt").write_text("1\n", encoding="utf-8")
        (self.origin / "build.time.txt").write_text("Exit status: 0\n", encoding="utf-8")
        decision = self.origin / "gate4.decision.json"
        decision.write_text(json.dumps({"decision": {"gate": {"enabled": True, "names": ["other"]}}}), encoding="utf-8")
        (self.origin / "inputs.sha256").write_text(collector.sha256(decision) + "  gate4.decision.json\n", encoding="utf-8")
        (self.origin / "elf.sha256").write_text("".join(
            collector.sha256(self.cwd / name) + "  " + name + "\n" for name in ("xgcc", "cc1")), encoding="utf-8")
        self.command = " ".join(shlex.quote(x) for x in [self.wrapper.as_posix(), "-O2", "-c", "-o", collector.OUTPUT, self.source.as_posix()])
        self.write_log(self.command)
        (self.origin / "gate4.decision.gate_names.implicit_vector_census.tsv").write_text(
            "implicit-vector-census\tLV\t" + collector.SYMBOL + "\tformed\n"
            "implicit-vector-census\tLV\t" + collector.SYMBOL + "Other\tblocked\n", encoding="utf-8")
        self.out = self.run / "reports" / "fresh" / "collection"
        self.cu_source = self.source.as_posix()
        self.fail_tool = None
        self.calls = []

    def write_log(self, *commands):
        (self.origin / "build.log").write_text(
            "make[1]: Entering directory '" + self.cwd.as_posix() + "'\n" +
            "\n".join(commands) + "\nmake[1]: Leaving directory '" + self.cwd.as_posix() + "'\n", encoding="utf-8")

    def capture(self, argv, output):
        self.calls.append(argv)
        text = ""
        if "nm-defined" in output.name:
            text = "0000000000000010 t " + collector.SYMBOL + "\n"
        if "readelf-cu" in output.name:
            text = (" <0><c>: Abbrev Number: 1 (DW_TAG_compile_unit)\n"
                    "    DW_AT_name : (indirect string, offset: 0x1): " + self.cu_source + "\n"
                    "    DW_AT_comp_dir : " + self.cwd.as_posix() + "\n"
                    " <1><20>: Abbrev Number: 2 (DW_TAG_subprogram)\n"
                    "    DW_AT_name : misleading_child_function\n")
        output.write_text(text, encoding="utf-8")
        return {"argv": argv, "returncode": 1 if self.fail_tool == output.name else 0}

    def run_collect(self):
        with patch.object(collector.shutil, "which", side_effect=lambda tool: tool), patch.object(collector, "run_capture", side_effect=self.capture):
            return collector.collect(self.run, self.origin, self.out, None, [])

    def test_real_shape_keeps_wrapper_unexpanded_and_historical_gaps(self):
        r = self.run_collect()
        self.assertTrue(r["historical"]["valid"])
        self.assertTrue(r["wrapper_path_match"])
        self.assertFalse(r["compiled"])
        self.assertFalse(r["replay_ready"])
        self.assertFalse(r["root_confirmed"])
        self.assertEqual(r["dwarf_compile_units"][0]["name"], self.cu_source)
        self.assertEqual(len(r["census"]["matches"]), 1)
        self.assertEqual(r["current"]["source_candidates"][0]["sha256"], collector.sha256(self.source))
        self.assertTrue(any("historical compiler" in g for g in r["gaps"]))
        self.assertTrue(all(argv[0] in {"nm", "readelf", "objdump"} for argv in self.calls))
        self.assertEqual(json.loads((self.out / "collection.json").read_text(encoding="utf-8")), r)

    def test_similar_wrapper_path_does_not_match(self):
        self.write_log(self.command.replace("gate4-cxx", "gate4-cxx-unrelated"))
        r = self.run_collect()
        self.assertFalse(r["wrapper_path_match"])

    def test_two_compile_lines_are_a_gap_not_an_arbitrary_choice(self):
        self.write_log(self.command, self.command)
        r = self.run_collect()
        self.assertNotIn("logged_compile_entry", r)
        self.assertTrue(any("found 2" in g for g in r["gaps"]))
        self.assertTrue((self.out / "report.md").is_file())

    def test_same_basename_wrong_cu_path_does_not_bind(self):
        self.cu_source = (self.root / "different" / "c-family" / "c-cppbuiltin.cc").as_posix()
        r = self.run_collect()
        self.assertTrue(any("uniquely bind" in g for g in r["gaps"]))

    def test_failed_cu_inspection_does_not_use_its_partial_stdout(self):
        self.fail_tool = "readelf-cu.txt"
        r = self.run_collect()
        self.assertNotIn("dwarf_compile_units", r)
        self.assertIn("readelf-cu inspection failed", r["gaps"])
        self.assertTrue((self.out / "report.md").is_file())

    def test_existing_output_cannot_be_overwritten_even_by_failure_handler(self):
        self.out.mkdir(parents=True)
        previous = self.out / "collection.json"
        previous.write_bytes(b"previous evidence")
        rc = collector.main(["--run", str(self.run), "--origin", str(self.origin), "--out", str(self.out)])
        self.assertEqual(rc, 2)
        self.assertEqual(previous.read_bytes(), b"previous evidence")

    def test_missing_object_is_recorded_without_claiming_replay_ready(self):
        (self.cwd / collector.OUTPUT).unlink()
        r = self.run_collect()
        self.assertFalse(r["replay_ready"])
        self.assertTrue(any("object missing" in g for g in r["gaps"]))

    def test_missing_current_tool_identities_are_explicit_gaps(self):
        with patch.object(collector.shutil, "which", side_effect=lambda tool: tool), patch.object(collector, "run_capture", side_effect=self.capture):
            r = collector.collect(self.run, self.origin, self.out,
                                  self.root / "missing-clang", [self.root / "missing-plugin"])
        self.assertTrue(any("current compiler" in g for g in r["gaps"]))
        self.assertTrue(any("current plugin" in g for g in r["gaps"]))

    def test_undefined_weak_symbol_is_not_a_function_definition(self):
        self.assertFalse(collector.has_exact_definition("                 w " + collector.SYMBOL))
        self.assertFalse(collector.has_exact_definition("00000010 D " + collector.SYMBOL))

    def test_history_mismatch_stops_cli_but_keeps_report(self):
        (self.cwd / "cc1").write_bytes(b"changed")
        with patch.object(collector.shutil, "which", side_effect=lambda tool: tool), patch.object(collector, "run_capture", side_effect=self.capture):
            rc = collector.main(["--run", str(self.run), "--origin", str(self.origin), "--out", str(self.out)])
        self.assertEqual(rc, 2)
        self.assertTrue((self.out / "report.md").is_file())
        self.assertFalse(json.loads((self.out / "collection.json").read_text(encoding="utf-8"))["historical"]["valid"])


if __name__ == "__main__":
    unittest.main()
