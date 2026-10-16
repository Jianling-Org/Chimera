from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PATCH = ROOT / "preprocessing" / "offline" / "toolchain" / "llvm-21.1.0" / "patches" / "0012-chimera-single-face-implicit-vector-census.patch"
INLINE_PATCH = ROOT / "preprocessing" / "offline" / "toolchain" / "llvm-21.1.0" / "patches" / "0009-chimera-vectorizer-guards-and-census.patch"
PLUGIN = ROOT / "preprocessing" / "offline" / "toolchain" / "llvm-21.1.0" / "plugins" / "plugins" / "vector_gate" / "VectorGatePlugin.cpp"
WRAPPER = ROOT / "cli" / "chimera" / "llvm_wrapper.py"
E2E = ROOT / "preprocessing" / "offline" / "toolchain" / "llvm-21.1.0" / "plugins" / "tests" / "vector_gate" / "run.sh"


class VectorCensusPatchContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = PATCH.read_text(encoding="utf-8")
        cls.inline_text = INLINE_PATCH.read_text(encoding="utf-8")

    def test_defines_one_strict_census_schema(self):
        self.assertIn("implicit-vector-census\\t", self.text)
        self.assertIn("ChimeraImplicitVectorCensus.h", self.text)
        for mechanism in ("LV", "SLP", "MEMOP", "MERGE"):
            self.assertIn(f"ChimeraImplicitVectorMechanism::{mechanism}", self.text)

    def test_moves_lv_and_slp_gate_to_commit_points(self):
        self.assertIn("processLoopInVPlanNativePath", self.text)
        self.assertGreaterEqual(
            self.text.count("chimeraRecordImplicitVectorDecision("), 8
        )
        self.assertIn("vectorizeStoreChain", self.text)
        self.assertIn("tryToVectorizeList", self.text)
        self.assertIn("HorizontalReduction", self.text)
        self.assertIn("chimeraAssertImplicitVectorCommitAllowed", self.text)

    def test_memop_requires_late_function_id(self):
        self.assertIn("chimera-census-function-id", self.text)
        self.assertIn("missing chimera census function id", self.text)

    def test_census_header_closes_guard_and_disambiguates_fatal_error(self):
        self.assertIn(
            "+#endif // LLVM_IR_CHIMERAIMPLICITVECTORCENSUS_H", self.text
        )
        self.assertIn(
            '+    report_fatal_error(StringRef("cannot append Chimera implicit-vector census: " +',
            self.text,
        )

    def test_census_header_hunk_includes_every_added_line(self):
        lines = self.text.splitlines()
        header = next(
            index
            for index, line in enumerate(lines)
            if line.startswith("@@ -0,0 +1,")
        )
        match = re.fullmatch(r"@@ -0,0 \+1,(\d+) @@", lines[header])
        self.assertIsNotNone(match)
        next_diff = next(
            index
            for index in range(header + 1, len(lines))
            if lines[index].startswith("diff --git ")
        )
        added = lines[header + 1 : next_diff]
        self.assertEqual(int(match.group(1)), len(added))
        self.assertEqual(
            added[-1], "+#endif // LLVM_IR_CHIMERAIMPLICITVECTORCENSUS_H"
        )

    def test_census_id_is_not_attached_to_prelink_bitcode(self):
        plugin = PLUGIN.read_text(encoding="utf-8")
        self.assertIn("ThinOrFullLTOPhase::ThinLTOPreLink", plugin)
        self.assertIn("ThinOrFullLTOPhase::FullLTOPreLink", plugin)
        self.assertIn("registerFullLinkTimeOptimizationLastEPCallback", plugin)

    def test_vector_gate_does_not_emit_per_module_missing_warnings(self):
        plugin = PLUGIN.read_text(encoding="utf-8")
        self.assertNotIn("gate list matched no function", plugin)
        self.assertNotIn("listed function(s) not found in this module", plugin)
        self.assertNotIn("unsigned gated", plugin)
        self.assertNotIn("const unsigned missing", plugin)

    def test_inline_gate_only_blocks_gated_callee_into_open_caller(self):
        self.assertIn(
            '!CB.getCaller()->hasFnAttribute("chimera-no-vectorize")',
            self.inline_text,
        )
        self.assertNotIn(
            'if (CB.getCaller()->hasFnAttribute("chimera-no-vectorize"))',
            self.inline_text,
        )

    def test_parallel_wrappers_publish_gate_list_atomically(self):
        wrapper = WRAPPER.read_text(encoding="utf-8")
        self.assertIn("tempfile.NamedTemporaryFile(", wrapper)
        self.assertIn("os.replace(temporary, target)", wrapper)

    def test_e2e_covers_all_mechanisms_and_explicit_rvv(self):
        e2e = E2E.read_text(encoding="utf-8")
        for mechanism in ("LV", "SLP", "MEMOP", "MERGE"):
            self.assertIn(f"implicit-vector-census\\t{mechanism}", e2e)
        self.assertIn("__riscv_vle32_v_f32m1", e2e)
        self.assertIn("explicit RVV load disappeared", e2e)
        self.assertIn("gated caller did not record the blocked LV decision", e2e)
        self.assertIn("ungated helper was outlined", e2e)


if __name__ == "__main__":
    unittest.main()
