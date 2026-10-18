"""Contracts for the target-machine-only experiment driver."""
import importlib
import re
import unittest
from pathlib import Path


class DriverContractTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(__file__).resolve().parents[1]
        self.script = (self.root / "tools/k3-builtin-gate-experiment.sh").read_text(encoding="utf-8")

    def test_identity_modules_exist_and_import(self):
        import chimera  # namespace registration
        specs = re.findall(r"'(chimera[^']+)=([^']+)'", self.script)
        self.assertGreaterEqual(len(specs), 12)
        for name, source in specs:
            with self.subTest(module=name):
                self.assertTrue((self.root / source).is_file())
                importlib.import_module(name)

    def test_isolated_installed_execution_and_approved_policy(self):
        self.assertIn('unset PYTHONPATH PYTHONHOME', self.script)
        self.assertIn('"$PY" -I "$CHIMERA/tools/builtin_gate_experiment.py"', self.script)
        self.assertIn('--policy assume-scalar-independent', self.script)
        self.assertIn('builtin-gate-inputs-20261001T064917Z-7Rt302/collection/collection.json', self.script)
        self.assertNotIn('eval ', self.script)
        self.assertNotIn('make ', self.script)
        self.assertNotIn('layout-codegen-collect-', self.script)

    def test_failure_packaging_uses_exit_trap(self):
        self.assertIn('trap finish EXIT', self.script)
        self.assertIn('"$OUT/workflow.exit.txt"', self.script)
        self.assertIn('tar -czf "$OUT.tar.gz"', self.script)
        self.assertIn('exit "$experiment_rc"', self.script)
        self.assertNotIn('chmod ', self.script)


if __name__ == "__main__":
    unittest.main()
