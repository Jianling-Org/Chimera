from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path

from tools.k3_unknown_stack_scope_evidence import validate_gate4_history


class K3UnknownStackScopeEvidenceTests(unittest.TestCase):
    def test_historical_workflow_guard_and_stale_profile_hash_do_not_block_valid_binaries(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            origin = root / "origin"
            build = root / "build-gate4" / "gcc"
            origin.mkdir()
            build.mkdir(parents=True)
            xgcc, cc1 = build / "xgcc", build / "cc1"
            xgcc.write_bytes(b"existing xgcc")
            cc1.write_bytes(b"existing cc1")
            decision = origin / "gate4.decision.json"
            decision.write_text('{"gate": "historical"}\n', encoding="utf-8")
            stale_profile = root / "live-profile.toml"
            stale_profile.write_text("changed after collection", encoding="utf-8")
            (origin / "build.exit.txt").write_text("1\n", encoding="utf-8")
            (origin / "build.time.txt").write_text("Exit status: 0\n", encoding="utf-8")
            (origin / "elf.sha256").write_text(
                f"{hashlib.sha256(xgcc.read_bytes()).hexdigest()}  build-gate4/gcc/xgcc\n"
                f"{hashlib.sha256(cc1.read_bytes()).hexdigest()}  build-gate4/gcc/cc1\n",
                encoding="utf-8",
            )
            (origin / "inputs.sha256").write_text(
                f"{hashlib.sha256(stale_profile.read_bytes()).hexdigest()}  old/repo/profile.toml\n"
                f"{hashlib.sha256(decision.read_bytes()).hexdigest()}  gate4.decision.json\n"
                f"{hashlib.sha256(decision.read_bytes()).hexdigest()}  copied/gate4.decision.json\n",
                encoding="utf-8",
            )

            result = validate_gate4_history(origin, build.parent, decision)
            self.assertEqual(result["build_exit_file"], 1)
            self.assertEqual(result["gnu_time_exit"], 0)
            self.assertTrue(result["stale_live_profile_hashes_ignored"])
            self.assertEqual(set(result["verified_elfs"]), {"xgcc", "cc1"})

            (origin / "inputs.sha256").write_text(
                (origin / "inputs.sha256").read_text(encoding="utf-8")
                + f"{'0' * 64}  conflicting/gate4.decision.json\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "conflicting archived hashes"):
                validate_gate4_history(origin, build.parent, decision)
            # Restore the matching manifest for the explicit bad-input cases.
            lines = [
                line for line in (origin / "inputs.sha256").read_text(encoding="utf-8").splitlines()
                if "conflicting/gate4.decision.json" not in line
            ]
            (origin / "inputs.sha256").write_text("\n".join(lines) + "\n", encoding="utf-8")

            xgcc.write_bytes(b"wrong xgcc")
            with self.assertRaisesRegex(ValueError, "xgcc binary"):
                validate_gate4_history(origin, build.parent, decision)
            xgcc.write_bytes(b"existing xgcc")
            wrong_decision = root / "wrong-decision.json"
            wrong_decision.write_text("{}\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "decision"):
                validate_gate4_history(origin, build.parent, wrong_decision)


if __name__ == "__main__":
    unittest.main()
