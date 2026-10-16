import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from tools import builtin_gate_inputs as collector


class BuiltinGateInputsTests(unittest.TestCase):
    def test_selects_unique_logged_compile_and_directory_scope(self):
        lines = [
            "make[4]: Entering directory '/src/gcc'",
            "g++ -c -o c-family/c-cppbuiltin.o c-family/c-cppbuiltin.cc",
            "make[4]: Leaving directory '/src/gcc'",
        ]
        found = collector.find_compile(lines)
        self.assertEqual(found["line_number"], 2)
        self.assertEqual(found["cwd"], "/src/gcc")
        self.assertEqual(found["output"], "c-family/c-cppbuiltin.o")
        self.assertIn("UNEXPANDED", found["status"])

    def test_rejects_shell_syntax_and_ambiguous_compile_rows(self):
        for command in (
            "g++ -c $(touch x) -o c-family/c-cppbuiltin.o c-family/c-cppbuiltin.cc",
            "g++ -c -o c-family/c-cppbuiltin.o c-family/c-cppbuiltin.cc && echo x",
            "g++ -c -o c-family/c-cppbuiltin.o c-family/c-cppbuiltin.cc; echo x",
        ):
            with self.subTest(command=command), self.assertRaises(ValueError):
                collector.parse_compile(command)
        with self.assertRaises(ValueError):
            collector.find_compile(["g++ -c -o c-family/c-cppbuiltin.o c-family/c-cppbuiltin.cc"] * 2)

    def test_exact_defined_symbol_is_required(self):
        exact = "0000000000001234 T _ZL26builtin_define_type_minmaxPKcS0_P9tree_node"
        self.assertTrue(collector.has_exact_definition(exact))
        self.assertFalse(collector.has_exact_definition("                 U " + collector.SYMBOL))
        self.assertFalse(collector.has_exact_definition("0000 T " + collector.SYMBOL + "Extra"))
        self.assertFalse(collector.has_exact_definition(exact + "\n" + exact))

    def test_historical_binding_checks_manifest_hashes(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            origin, build = root / "origin", root / "build"
            (origin / "wrappers").mkdir(parents=True)
            (build / "gcc").mkdir(parents=True)
            (origin / "build.exit.txt").write_text("0\n")
            (origin / "build.time.txt").write_text("Exit status: 0\n")
            (build / "gcc" / "xgcc").write_bytes(b"xgcc")
            (build / "gcc" / "cc1").write_bytes(b"cc1")
            decision = b'{"ok": true}\n'
            (origin / "gate4.decision.json").write_bytes(decision)
            files = {"xgcc": build / "gcc" / "xgcc", "cc1": build / "gcc" / "cc1",
                     "gate4.decision.json": origin / "gate4.decision.json"}
            (origin / "elf.sha256").write_text("".join(f"{collector.sha256(p)}  {name}\n" for name, p in list(files.items())[:2]))
            (origin / "inputs.sha256").write_text(f"{collector.sha256(files['gate4.decision.json'])}  gate4.decision.json\n")
            result = collector.validate_history(origin, build)
            self.assertTrue(result["valid"])
            self.assertEqual(result["verified_elfs"]["cc1"]["sha256"], collector.sha256(files["cc1"]))
            (origin / "inputs.sha256").write_text("0" * 64 + "  gate4.decision.json\n")
            self.assertFalse(collector.validate_history(origin, build)["valid"])

    def test_parallel_scope_overlap_is_not_guessed(self):
        lines = [
            "make[1]: Entering directory '/src/gcc'",
            "make[2]: Entering directory '/src/gcc/c-family'",
            "make[2]: Entering directory '/other/c-family'",
            "g++ -c -o c-family/c-cppbuiltin.o c-family/c-cppbuiltin.cc",
        ]
        with self.assertRaisesRegex(ValueError, "ambiguous"):
            collector.find_compile(lines)

    def test_inspection_failure_keeps_stdout_stderr_and_status(self):
        import sys
        with tempfile.TemporaryDirectory() as td:
            output = Path(td) / "tool.out"
            result = collector.run_capture(
                [sys.executable, "-c",
                 "import sys; print('partial'); print('diagnostic', file=sys.stderr); sys.exit(7)"], output)
            self.assertEqual(result["returncode"], 7)
            self.assertIn("partial", output.read_text())
            self.assertIn("diagnostic", Path(result["stderr_path"]).read_text())

    def test_dwarf_parser_keeps_compile_unit_attributes_out_of_children(self):
        with tempfile.TemporaryDirectory() as td:
            dump = Path(td) / "dwarf.txt"
            dump.write_text(
                " <0><b>: Abbrev Number: 1 (DW_TAG_compile_unit)\n"
                " <1><c>: Abbrev Number: 2 (DW_TAG_subprogram)\n"
                "    <d> DW_AT_name : child-function\n"
                " <0><e>: Abbrev Number: 1 (DW_TAG_compile_unit)\n"
                "    <f> DW_AT_name : c-cppbuiltin.cc\n"
                "    <10> DW_AT_comp_dir : /src/gcc\n"
            )
            self.assertEqual(collector.read_cu_facts(dump),
                             [{"name": "c-cppbuiltin.cc", "comp_dir": "/src/gcc"}])

    def test_current_identity_is_explicitly_not_historical(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "tool"
            p.write_bytes(b"current")
            self.assertEqual(collector.identity(p)["provenance"], "CURRENT")


if __name__ == "__main__":
    unittest.main()
