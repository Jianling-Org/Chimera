"""The stage wrapper generator, executed for real.

The generator used to be an inline heredoc inside the K3 driver.  A missing
``import`` in it (``sys`` was used, never imported) survived ``bash -n`` and
only failed hours into a rebuild, so the block is now a program with tests:

* the tool is *executed*, and the files it produces are inspected;
* the generated script must be valid ``sh`` (when a shell is available);
* a fake ``chimera-pkg`` in front of it proves the wrapper forwards its
  arguments instead of swallowing them.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

TOOL = Path(__file__).resolve().parents[1] / "tools" / "write_gate_wrapper.py"


def _decision(path: Path, names: list[str]) -> Path:
    path.write_text(
        json.dumps(
            {
                "schema": "chimera-gate-decision-union-v1",
                "decision": {
                    "strategy": "gate",
                    "vector_gate": {"enabled": True, "names_source": "union"},
                    "function_pointer_plugin": False,
                    "stack_object_plugin": True,
                    "gate": {"enabled": True, "names": names},
                },
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    return path


class WriteGateWrapperTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.decision = _decision(self.root / "gate3.decision.json", ["layout"])

    def _run(self, *args: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, str(TOOL), *args],
            capture_output=True,
            text=True,
            check=False,
        )

    def test_tool_writes_both_wrappers_with_the_fixed_decision(self) -> None:
        wrapper_dir = self.root / "wrappers"
        completed = self._run(
            "--wrapper-dir", str(wrapper_dir),
            "--pkg", "/venv/bin/chimera-pkg",
            "--decision", str(self.decision),
            "--prefix", "gate3",
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)

        cc = wrapper_dir / "gate3-cc"
        cxx = wrapper_dir / "gate3-cxx"
        self.assertTrue(cc.is_file())
        self.assertTrue(cxx.is_file())
        self.assertTrue(os.access(cc, os.X_OK))
        self.assertTrue(os.access(cxx, os.X_OK))

        cc_text = cc.read_text(encoding="utf-8")
        cxx_text = cxx.read_text(encoding="utf-8")
        # Both bind the decision explicitly: no "latest check" pointer.
        self.assertIn("--list", cc_text)
        self.assertIn(str(self.decision), cc_text)
        self.assertIn(str(self.decision), cxx_text)
        # Only the C++ flavour asks for the C++ driver.
        self.assertNotIn("--cxx", cc_text)
        self.assertIn("--cxx", cxx_text)
        # Arguments are forwarded verbatim after the option terminator.
        self.assertTrue(cc_text.rstrip().endswith('"$@"'))
        self.assertIn(" -- ", cc_text)

    @unittest.skipUnless(shutil.which("sh"), "no POSIX shell on this platform")
    def test_generated_wrapper_is_valid_sh_and_forwards_arguments(self) -> None:
        wrapper_dir = self.root / "wrappers"
        # A stand-in for chimera-pkg: record what the wrapper passes through.
        fake_pkg = self.root / "fake-pkg"
        fake_pkg.write_text(
            '#!/bin/sh\nprintf "%s\\n" "$@" > "$RECORD"\n', encoding="utf-8"
        )
        fake_pkg.chmod(0o755)
        completed = self._run(
            "--wrapper-dir", str(wrapper_dir),
            "--pkg", str(fake_pkg),
            "--decision", str(self.decision),
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        wrapper = wrapper_dir / "gate3-cc"

        syntax = subprocess.run(
            ["sh", "-n", str(wrapper)], capture_output=True, text=True, check=False
        )
        self.assertEqual(syntax.returncode, 0, syntax.stderr)

        record = self.root / "argv.txt"
        run = subprocess.run(
            ["sh", str(wrapper), "-c", "-O2", "-o", "out.o", "src.c"],
            capture_output=True,
            text=True,
            check=False,
            env={**os.environ, "RECORD": str(record)},
        )
        self.assertEqual(run.returncode, 0, run.stderr)
        forwarded = record.read_text(encoding="utf-8").splitlines()
        self.assertEqual(forwarded[0], "llvm")
        self.assertIn("--list", forwarded)
        self.assertEqual(forwarded[-5:], ["-c", "-O2", "-o", "out.o", "src.c"])

    def test_missing_decision_is_refused(self) -> None:
        completed = self._run(
            "--wrapper-dir", str(self.root / "wrappers"),
            "--pkg", "/venv/bin/chimera-pkg",
            "--decision", str(self.root / "absent.json"),
        )
        self.assertEqual(completed.returncode, 3)
        self.assertIn("input error", completed.stderr)
        self.assertFalse((self.root / "wrappers").exists())

    def test_empty_pkg_is_refused(self) -> None:
        with self.assertRaises(ValueError):
            sys.path.insert(0, str(TOOL.parent))
            try:
                import write_gate_wrapper as module

                module.write_wrappers(self.root / "w", "", str(self.decision))
            finally:
                sys.path.remove(str(TOOL.parent))
                sys.modules.pop("write_gate_wrapper", None)


if __name__ == "__main__":
    unittest.main()
