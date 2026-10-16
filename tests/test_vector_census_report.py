from __future__ import annotations

import importlib.util
import io
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
REPORT_PATH = ROOT / "examples" / "scripts" / "build" / "vector_census_report.py"


def load_report_module():
    spec = importlib.util.spec_from_file_location("vector_census_report", REPORT_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {REPORT_PATH}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class VectorCensusReportTests(unittest.TestCase):
    def setUp(self):
        self.report = load_report_module()
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def write(self, name: str, text: str) -> Path:
        path = self.root / name
        path.write_text(text, encoding="utf-8")
        return path

    def test_deduplicates_events_and_totals_by_function_union(self):
        gate = self.write("gate.txt", "_Z3foov\n_Z3barv\n")
        census = self.write(
            "census.tsv",
            "implicit-vector-census\tLV\t_Z3foov\tblocked\n"
            "implicit-vector-census\tLV\t_Z3foov\tblocked\n"
            "implicit-vector-census\tSLP\t_Z3foov\tblocked\n"
            "implicit-vector-census\tMEMOP\t_Z3barv\tformed\n"
            "implicit-vector-census\tMERGE\t_Z3bazv\tformed\n",
        )

        rows = self.report.build_rows(census, gate)

        self.assertEqual(rows["LV"], (1, 1, 0))
        self.assertEqual(rows["SLP"], (1, 1, 0))
        self.assertEqual(rows["MEMOP"], (1, 0, 1))
        self.assertEqual(rows["MERGE"], (1, 0, 1))
        self.assertEqual(rows["TOTAL"], (3, 1, 2))

    def test_constructor_and_destructor_variants_are_canonicalized(self):
        gate = self.write("gate.txt", "_ZN1AC1Ei\n_ZN1AD1Ei\n")
        census = self.write(
            "census.tsv",
            "implicit-vector-census\tLV\t_ZN1AC2Ei\tblocked\n"
            "implicit-vector-census\tSLP\t_ZN1AD2Ei\tblocked\n",
        )
        rows = self.report.build_rows(census, gate)
        self.assertEqual(rows["TOTAL"], (2, 2, 0))

    def test_zero_denominator_is_dash_and_rates_have_two_decimals(self):
        gate = self.write("gate.txt", "_Z3foov\n")
        census = self.write(
            "census.tsv", "implicit-vector-census\tLV\t_Z3foov\tblocked\n"
        )
        output = io.StringIO()
        self.report.print_report(self.report.build_rows(census, gate), output)
        text = output.getvalue()
        self.assertIn("Loop Vectorizer", text)
        self.assertIn("100.00%", text)
        self.assertRegex(text, r"SLP Vectorizer\s+\|\s+0\s+\|\s+0\s+\|\s+0\s+\|\s+-")

    def test_rejects_malformed_unknown_conflicting_and_non_gate_blocked(self):
        gate = self.write("gate.txt", "_Z3foov\n")
        cases = {
            "bad.tsv": "implicit-vector-census\tLV\tonly-three\n",
            "unknown.tsv": "implicit-vector-census\tMAGIC\t_Z3foov\tformed\n",
            "action.tsv": "implicit-vector-census\tLV\t_Z3foov\tmaybe\n",
            "conflict.tsv": (
                "implicit-vector-census\tLV\t_Z3foov\tformed\n"
                "implicit-vector-census\tLV\t_Z3foov\tblocked\n"
            ),
            "cross-mechanism-conflict.tsv": (
                "implicit-vector-census\tLV\t_Z3foov\tformed\n"
                "implicit-vector-census\tSLP\t_Z3foov\tblocked\n"
            ),
            "nongate.tsv": "implicit-vector-census\tLV\t_Z3barv\tblocked\n",
        }
        for name, contents in cases.items():
            with self.subTest(name=name):
                with self.assertRaises(ValueError):
                    self.report.build_rows(self.write(name, contents), gate)


if __name__ == "__main__":
    unittest.main()
