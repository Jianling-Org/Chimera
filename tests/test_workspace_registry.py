from __future__ import annotations

from dataclasses import replace
from hashlib import sha256
from pathlib import Path
import tempfile
import unittest

from chimera.preprocess.offline.analysis.core.workspace import WorkspaceSession
from chimera.runtime.manifest import ArtifactRecord, ModuleRecord


class WorkspaceRegistryTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.stage = self.root / ".ready.staging-test"
        self.stage.mkdir()
        self.session = WorkspaceSession(
            root=self.root,
            stage=self.stage,
            destination=self.root / "ready",
        )

    def artifact(self) -> ArtifactRecord:
        path = self.stage / "artifacts" / "a.so"
        path.parent.mkdir()
        path.write_bytes(b"artifact")
        return ArtifactRecord(
            "one", "module", "main", "analysis", "elf", 1,
            frozenset(), "artifacts/a.so", sha256(b"artifact").hexdigest(),
        )

    def test_registry_rejects_duplicate_artifact_path(self) -> None:
        self.session.registry.register_module(
            ModuleRecord("main", "main", "app", "original", "target", "0" * 64)
        )
        first = self.artifact()
        self.session.registry.register_artifact(first)

        with self.assertRaisesRegex(ValueError, "artifact path"):
            self.session.registry.register_artifact(
                replace(first, artifact_id="two")
            )

    def test_registration_validates_file_hash(self) -> None:
        self.session.registry.register_module(
            ModuleRecord("main", "main", "app", "original", "target", "0" * 64)
        )

        with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
            self.session.registry.register_artifact(
                replace(self.artifact(), sha256="0" * 64)
            )

    def test_session_rejects_registration_after_abort(self) -> None:
        self.session.abort()

        with self.assertRaisesRegex(RuntimeError, "finished"):
            self.session.registry.register_module(
                ModuleRecord("main", "main", "app", "original", "target", "0" * 64)
            )

    def test_publication_validators_are_unique_and_run_by_id(self) -> None:
        self.session.registry.register_module(
            ModuleRecord("main", "main", "app", "original", "target", "0" * 64)
        )
        calls: list[str] = []
        self.session.register_validator("z.last", lambda _manifest: calls.append("z"))
        self.session.register_validator("a.first", lambda _manifest: calls.append("a"))

        with self.assertRaisesRegex(ValueError, "duplicate publication validator"):
            self.session.register_validator("a.first", lambda _manifest: None)

        self.session.freeze(
            runtime_abi=1,
            target_os="linux",
            target_arch="riscv64",
            target_arch_extension="rvv",
            runtime_scene="linux_riscv64_rvv_v1",
        )
        self.assertEqual(calls, ["a", "z"])


if __name__ == "__main__":
    unittest.main()
