"""Missing diagnostic inputs must fail before creating experiment output."""

import os
from pathlib import Path
import subprocess
import tempfile
import unittest


class DiagnosticDriverInputTests(unittest.TestCase):
    def test_missing_required_inputs_create_no_reports(self):
        tools = Path(__file__).resolve().parents[1] / "tools"
        cases = [
            ("k3-builtin-gate-experiment.sh", "COLLECTION"),
            ("k3-collect-builtin-gate-inputs.sh", "ORIGIN"),
            ("k3-gate-source-audit.sh", "EXPECTED_GATE_COUNT"),
        ]
        for name, missing in cases:
            with self.subTest(script=name, missing=missing), tempfile.TemporaryDirectory() as temp:
                env = os.environ.copy()
                env.pop("VIRTUAL_ENV", None)
                env.update(RUN=temp, VENV=temp, GATE_DECISION="/unused/decision.json")
                env.pop(missing, None)
                result = subprocess.run(
                    ["bash", str(tools / name)], env=env,
                    capture_output=True, text=True, timeout=10,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(missing, result.stderr)
                self.assertFalse((Path(temp) / "reports").exists())


if __name__ == "__main__":
    unittest.main()
