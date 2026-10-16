from __future__ import annotations

import tempfile
import tomllib
import unittest
from pathlib import Path

from tools.unknown_stack_scope_profile import scoped_profile_bytes, write_scoped_profile


class UnknownStackScopeProfileTests(unittest.TestCase):
    def test_profile_helper_only_adds_explicit_safety_policy_and_snapshots_both(self):
        seed = Path("examples/platforms/k3/linux-riscv64-rvv-256-to-1024.toml")
        original = seed.read_bytes()
        generated = scoped_profile_bytes(original)
        seed_doc = tomllib.loads(original.decode("utf-8"))
        generated_doc = tomllib.loads(generated.decode("utf-8"))

        generated_safety = next(
            step for step in generated_doc["profile"]["workflow"]["steps"]
            if step["step"] == "safety"
        )
        self.assertEqual(
            generated_safety["parameters"],
            {"min_vlen_bits": 256, "compiler_metadata": [], "unknown_stack_size_policy": "assume-scalar-independent"},
        )
        generated_safety["parameters"].pop("unknown_stack_size_policy")
        self.assertEqual(generated_doc, seed_doc)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target_dir = root / "repo" / "examples" / "platforms" / "k3"
            target_dir.mkdir(parents=True)
            seed_path = target_dir / "seed.toml"
            seed_path.write_bytes(original)
            target = target_dir / "scoped.toml"
            snapshots = root / "evidence"
            record = write_scoped_profile(seed_path, target, snapshots)
            self.assertEqual(target.read_bytes(), generated)
            self.assertEqual((snapshots / "profile.seed-v20.snapshot.toml").read_bytes(), original)
            self.assertEqual((snapshots / "profile.scoped.snapshot.toml").read_bytes(), generated)
            self.assertEqual(record["policy"], "assume-scalar-independent")

    def test_profile_helper_rejects_ambiguous_safety_step(self):
        seed = Path("examples/platforms/k3/linux-riscv64-rvv-256-to-1024.toml").read_bytes()
        repeated = seed + b"\n[[profile.workflow.steps]]\nstep = \"safety\"\n"
        with self.assertRaisesRegex(ValueError, "expected one safety step"):
            scoped_profile_bytes(repeated)

    def test_conservative_policy_is_replaced_and_existing_target_is_never_overwritten(self):
        original = Path("examples/platforms/k3/linux-riscv64-rvv-256-to-1024.toml").read_bytes()
        explicit_conservative = original.replace(
            b"parameters = { min_vlen_bits = 256, compiler_metadata = [] }",
            b'parameters = { min_vlen_bits = 256, compiler_metadata = [], unknown_stack_size_policy = "conservative" }',
        )
        changed = tomllib.loads(scoped_profile_bytes(explicit_conservative).decode("utf-8"))
        baseline = tomllib.loads(original.decode("utf-8"))
        changed_safety = next(step for step in changed["profile"]["workflow"]["steps"] if step["step"] == "safety")
        baseline_safety = next(step for step in baseline["profile"]["workflow"]["steps"] if step["step"] == "safety")
        self.assertEqual(
            changed_safety["parameters"],
            {**baseline_safety["parameters"], "unknown_stack_size_policy": "assume-scalar-independent"},
        )
        changed_safety["parameters"].pop("unknown_stack_size_policy")
        self.assertEqual(changed, baseline)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "seed.toml"
            source.write_bytes(original)
            with self.assertRaisesRegex(ValueError, "must not overwrite"):
                write_scoped_profile(source, source, root / "same")
            target = root / "scoped.toml"
            target.write_bytes(b"user-owned")
            with self.assertRaises(FileExistsError):
                write_scoped_profile(source, target, root / "snapshot")
            self.assertEqual(target.read_bytes(), b"user-owned")


if __name__ == "__main__":
    unittest.main()
