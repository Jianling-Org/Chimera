"""Run real local analysis under the experiment's declared size policy."""
import tempfile
import unittest
from types import SimpleNamespace
from pathlib import Path
from unittest.mock import patch

from tools import layout_codegen_forensics as forensic


class ExperimentPolicyTests(unittest.TestCase):
    DUMP = ("Disassembly of section .text:\n\n"
            "0000000000000000 <_Zf>:\n"
            " 0:\t40a10133\tsub sp,sp,a0\n"
            " 4:\t000080e7\tjalr ra\n"
            " 8:\t00008067\tret\n")

    def facts(self, policy):
        with tempfile.TemporaryDirectory() as tmp:
            control = forensic.resolve_local_control_flow(self.DUMP, {})
            facts, error = forensic._production_local_facts(
                self.DUMP, "_Zf", Path(tmp), "A", control,
                unknown_stack_size_policy=policy)
            self.assertIsNone(error, error)
            self.assertEqual(facts["unknown_stack_size_policy"], policy)
            return facts

    def test_scalar_unknown_is_excluded_only_under_explicit_scope(self):
        self.assertTrue(self.facts("conservative")["vlen_frame_marker_live_at"])
        self.assertFalse(self.facts("assume-scalar-independent")["vlen_frame_marker_live_at"])

    def test_known_vlen_dependency_survives_scope(self):
        with patch.object(self, "DUMP", self.DUMP.replace(
                " 0:\t40a10133\tsub sp,sp,a0\n",
                " 0:\tc2202573\tcsrr a0,vlenb\n 2:\t40a10133\tsub sp,sp,a0\n")):
            self.assertTrue(self.facts("assume-scalar-independent")["vlen_frame_marker_live_at"])

    def test_failed_relocation_read_cannot_report_complete(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            obj = root / "source.o"
            obj.write_bytes(b"fixture")
            with patch.object(forensic, "_run_capture", side_effect=[
                    (0, "Type: REL"), (0, self.DUMP),
                    (0, ""), (0, ""), (1, "")]), \
                    patch.object(forensic, "_production_local_facts", return_value=({}, None)) as analyze:
                result = forensic.local_source_observation(
                    obj, "_Zf", root / "out", SimpleNamespace(readelf="readelf", objdump="objdump"),
                    "A", unknown_stack_size_policy="assume-scalar-independent")
            self.assertEqual(result["status"], "incomplete")
            self.assertTrue(result["gaps"])
            analyze.assert_not_called()

    def test_failed_dump_even_with_partial_instructions_cannot_be_complete(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            obj = root / "source.o"
            obj.write_bytes(b"fixture")
            with patch.object(forensic, "_run_capture", side_effect=[
                    (0, "Type: REL"), (1, self.DUMP), (0, ""), (0, ""), (0, "")]), \
                    patch.object(forensic, "_production_local_facts", return_value=({}, None)) as analyze:
                result = forensic.local_source_observation(
                    obj, "_Zf", root / "out", SimpleNamespace(readelf="readelf", objdump="objdump"), "A")
            self.assertEqual(result["status"], "incomplete")
            analyze.assert_not_called()


if __name__ == "__main__":
    unittest.main()
