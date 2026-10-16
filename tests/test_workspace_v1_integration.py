from __future__ import annotations

from dataclasses import replace
from hashlib import sha256
import os
import logging
from pathlib import Path
import struct
from types import SimpleNamespace
import tempfile
import unittest
import warnings
from unittest.mock import Mock, patch

from chimera.preprocess.offline.analysis import AnalysisContext
from chimera.preprocess.offline.analysis.core.workspace import WorkspaceSession
from chimera.preprocess.offline.analysis.finalize_workspace import FinalizeWorkspaceStep
from chimera.preprocess.offline.analysis_profile.pipeline import PreparePipeline
from chimera.preprocess.offline.analysis_profile.plan import ExecutionPlan, PlannedStep
from chimera.preprocess.offline.analysis_profile.target import (
    current_target_bundle, validate_linux_riscv64_rvv_publication,
)
from chimera.runtime.manifest import (
    ArtifactRecord, ModuleRecord, VariantPropertyRecord, VariantRecord,
)
from chimera.runtime.validate import VerificationError, verify_workspace
import chimera.runtime.validate.workspace as workspace_verifier


class WorkspaceV1IntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def _session(self, name: str = "ready") -> WorkspaceSession:
        stage = self.root / f".{name}.staging-integration"
        (stage / "artifacts").mkdir(parents=True)
        return WorkspaceSession(
            root=self.root,
            stage=stage,
            destination=self.root / name,
        )

    @staticmethod
    def _services():
        return SimpleNamespace(
            platform=SimpleNamespace(runner=Mock()),
            toolchain=SimpleNamespace(
                compiler=SimpleNamespace(compile=Mock()),
            ),
            architecture=Mock(),
        )

    def _register_artifact(
        self,
        session: WorkspaceSession,
        artifact_id: str,
        owner_kind: str,
        owner_id: str,
        capability: str,
        representation: str,
        *,
        required_by: frozenset[str] = frozenset(),
    ) -> ArtifactRecord:
        relative = f"artifacts/{artifact_id}.{representation}"
        path = session.stage / relative
        if capability == "runtime":
            ident = b"\x7fELF\x02\x01\x01" + bytes(9)
            content = struct.pack(
                "<16sHHIQQQIHHHHHH",
                ident, 3, 243, 1, 0, 0, 0, 0, 64, 56, 0, 64, 0, 0,
            )
        else:
            content = (artifact_id + "\n").encode()
        path.write_bytes(content)
        record = ArtifactRecord(
            artifact_id,
            owner_kind,
            owner_id,
            capability,
            representation,
            1,
            required_by,
            relative,
            sha256(content).hexdigest(),
        )
        session.registry.register_artifact(record)
        return record

    def _context(self, session: WorkspaceSession) -> AnalysisContext:
        return AnalysisContext(
            input_elf=self.root / "app",
            stage=session.stage,
            config=SimpleNamespace(),
            target_os="linux",
            target_arch="riscv64",
            target_arch_extension="rvv",
            runtime_scene="linux_riscv64_rvv_v1",
            runtime_abi=1,
            services=self._services(),
            target_bundle=current_target_bundle(),
        ).put_global("workspace_session", session)

    def _register_core(self, session: WorkspaceSession, variants: int) -> None:
        session.register_validator(
            "scene.linux_riscv64_rvv_v1.topology",
            validate_linux_riscv64_rvv_publication,
        )
        session.registry.register_module(
            ModuleRecord("main", "main", "app", "original", "target", "0" * 64)
        )
        self._register_artifact(
            session,
            "runtime",
            "workspace",
            "root",
            "runtime",
            "elf",
            required_by=frozenset({"runtime"}),
        )
        directions = ((1024, 256), (256, 1024))
        for source, target in directions[:variants]:
            variant_id = f"main_vlen{source}_to_vlen{target}"
            session.registry.register_variant(
                VariantRecord(variant_id, "main")
            )
            for side, value in (("input", source), ("output", target)):
                session.registry.register_variant_property(
                    VariantPropertyRecord(
                        variant_id, side, "architecture", "token", "riscv64"
                    )
                )
                session.registry.register_variant_property(
                    VariantPropertyRecord(
                        variant_id, side, "architecture_extension", "token", "rvv"
                    )
                )
                session.registry.register_variant_property(
                    VariantPropertyRecord(
                        variant_id, side, "vector_vlen_bits", "u64", str(value)
                    )
                )
            self._register_artifact(
                session,
                f"translated-{source}-{target}",
                "variant",
                variant_id,
                "translated-code",
                "elf",
                required_by=frozenset({"runtime"}),
            )
            self._register_artifact(
                session,
                f"offset-map-{source}-{target}-elf",
                "variant",
                variant_id,
                "offset-map",
                "elf",
                required_by=frozenset({"runtime"}),
            )

    def _finalize(self, session: WorkspaceSession):
        return FinalizeWorkspaceStep().run(
            self._context(session)
        ).require_global("manifest")

    def test_minimal_workspace_has_no_program_or_safety_products(self) -> None:
        session = self._session()
        self._register_core(session, variants=1)

        manifest = self._finalize(session)

        self.assertFalse(any(a.capability == "safety" for a in manifest.artifacts))
        self.assertEqual(
            sum(a.capability == "translated-code" for a in manifest.artifacts), 1
        )
        self.assertEqual(
            sum(
                a.capability == "offset-map" and a.representation == "elf"
                for a in manifest.artifacts
            ),
            1,
        )
        self.assertTrue((self.root / "ready" / "artifacts" / "modules.tsv").is_file())

    def test_safety_workspace_has_one_module_safety_and_two_variant_maps(self) -> None:
        session = self._session()
        self._register_core(session, variants=2)
        self._register_artifact(
            session,
            "safety-elf",
            "module",
            "main",
            "safety",
            "elf",
            required_by=frozenset({"runtime"}),
        )

        manifest = self._finalize(session)

        self.assertEqual(len(manifest.variants), 2)
        self.assertEqual(
            sum(
                a.owner_kind == "module"
                and a.capability == "safety"
                and a.representation == "elf"
                for a in manifest.artifacts
            ),
            1,
        )
        self.assertEqual(
            sum(
                a.owner_kind == "variant"
                and a.capability == "offset-map"
                and a.representation == "elf"
                for a in manifest.artifacts
            ),
            2,
        )
        self.assertFalse(
            any(a.representation == "json" for a in manifest.artifacts)
        )

    def test_unknown_optional_analysis_survives_finalize_and_verify(self) -> None:
        session = self._session()
        self._register_core(session, variants=1)
        custom = self._register_artifact(
            session,
            "risk-report",
            "module",
            "main",
            "control-flow-risk",
            "json",
        )
        manifest = self._finalize(session)
        noop_verifiers = {key: (lambda *_args: None) for key in workspace_verifier.VERIFIERS}

        with patch.dict(workspace_verifier.VERIFIERS, noop_verifiers):
            verified = verify_workspace(
                self.root / "ready", SimpleNamespace(), check_host=False
            )

        self.assertEqual(verified, manifest)
        self.assertIn(custom, verified.artifacts)

    def test_unknown_runtime_required_analysis_fails_verify(self) -> None:
        session = self._session()
        self._register_core(session, variants=1)
        custom = self._register_artifact(
            session,
            "risk-report",
            "module",
            "main",
            "control-flow-risk",
            "json",
        )
        session.registry.artifacts[custom.artifact_id] = replace(
            custom, required_by=frozenset({"runtime"})
        )
        self._finalize(session)
        noop_verifiers = {key: (lambda *_args: None) for key in workspace_verifier.VERIFIERS}

        with patch.dict(workspace_verifier.VERIFIERS, noop_verifiers):
            with self.assertRaisesRegex(
                VerificationError, "unsupported required capability"
            ):
                verify_workspace(
                    self.root / "ready", SimpleNamespace(), check_host=False
                )

    def test_failure_before_finalize_aborts_staging(self) -> None:
        source = self.root / "app"
        source.write_bytes(b"input")
        stage = self.root / ".ready.staging-integration"
        destination = self.root / "ready"

        class OpenWorkspace:
            def run(inner_self, context):
                stage.mkdir()
                session = WorkspaceSession(
                    root=self.root, stage=stage, destination=destination
                )
                return context.with_stage(stage).put_global(
                    "workspace_session", session
                )

        class FailTranslation:
            def run(inner_self, context):
                raise RuntimeError("translator failed")

        profile = SimpleNamespace(
            target_os="linux",
            target_arch="riscv64",
            target_arch_extension="rvv",
            runtime_scene="linux_riscv64_rvv_v1",
            runtime_abi=1,
        )
        configuration = SimpleNamespace(
            base=SimpleNamespace(), profile=profile
        )
        plan = ExecutionPlan(
            configuration,
            self._services(),
            (
                PlannedStep("001:open", "open", OpenWorkspace(), {}),
                PlannedStep("002:translate", "translate", FailTranslation(), {}),
            ),
            current_target_bundle(),
        )

        with self.assertRaisesRegex(RuntimeError, "translator failed"):
            PreparePipeline(plan).prepare(source)

        self.assertFalse(destination.exists())
        self.assertFalse(stage.exists())

    def test_publication_validator_failure_aborts_staging(self) -> None:
        source = self.root / "app"
        source.write_bytes(b"input")
        stage = self.root / ".invalid.staging-integration"
        destination = self.root / "invalid"

        class OpenInvalidWorkspace:
            def run(inner_self, context):
                stage.mkdir()
                (stage / "artifacts").mkdir()
                session = WorkspaceSession(
                    root=self.root, stage=stage, destination=destination
                )
                session.registry.register_module(
                    ModuleRecord("main", "main", "app", "original", "target", "0" * 64)
                )
                session.register_validator(
                    "test.reject", lambda _manifest: (_ for _ in ()).throw(
                        ValueError("publication rejected")
                    )
                )
                return context.with_stage(stage).put_global(
                    "workspace_session", session
                )

        profile = SimpleNamespace(
            target_os="linux", target_arch="riscv64",
            target_arch_extension="rvv",
            runtime_scene="linux_riscv64_rvv_v1", runtime_abi=1,
        )
        plan = ExecutionPlan(
            SimpleNamespace(base=SimpleNamespace(), profile=profile),
            self._services(),
            (
                PlannedStep("001:open", "open", OpenInvalidWorkspace(), {}),
                PlannedStep(
                    "002:finalize", "finalize-workspace",
                    FinalizeWorkspaceStep(), {},
                ),
            ),
        )

        with self.assertRaisesRegex(ValueError, "publication rejected"):
            PreparePipeline(plan).prepare(source)

        self.assertFalse(stage.exists())
        self.assertFalse(destination.exists())

    def test_commit_keeps_backup_when_restore_fails(self) -> None:
        destination = self.root / "ready"
        stage = self.root / ".ready.staging-rollback"
        destination.mkdir()
        stage.mkdir()
        (destination / "manifest").write_text("old", encoding="utf-8")
        (stage / "manifest").write_text("new", encoding="utf-8")
        session = WorkspaceSession(
            root=self.root, stage=stage, destination=destination
        )
        original_replace = os.replace
        calls = 0

        def fail_restore(source, target):
            nonlocal calls
            calls += 1
            if calls in (2, 3):
                raise OSError("restore failed")
            return original_replace(source, target)

        with patch(
            "chimera.preprocess.offline.analysis.core.workspace.session.os.replace",
            side_effect=fail_restore,
        ):
            with self.assertRaisesRegex(RuntimeError, "backup"):
                session.commit()

        backups = list(self.root.glob(".ready.old-*"))
        self.assertEqual(len(backups), 1)
        self.assertTrue((backups[0] / "manifest").is_file())
        self.assertTrue(stage.exists())
        session.abort()
        self.assertFalse(stage.exists())

    def test_commit_restores_old_workspace_when_publish_rename_fails(self) -> None:
        destination = self.root / "ready"
        stage = self.root / ".ready.staging-restore"
        destination.mkdir()
        stage.mkdir()
        (destination / "manifest").write_text("old", encoding="utf-8")
        (stage / "manifest").write_text("new", encoding="utf-8")
        session = WorkspaceSession(
            root=self.root, stage=stage, destination=destination
        )
        original_replace = os.replace
        calls = 0

        def fail_publish(source, target):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise OSError("publish failed")
            return original_replace(source, target)

        with patch(
            "chimera.preprocess.offline.analysis.core.workspace.session.os.replace",
            side_effect=fail_publish,
        ):
            with self.assertRaisesRegex(OSError, "publish failed"):
                session.commit()

        self.assertEqual((destination / "manifest").read_text(encoding="utf-8"), "old")
        self.assertFalse(list(self.root.glob(".ready.old-*")))
        session.abort()
        self.assertFalse(stage.exists())

    def test_successful_commit_survives_backup_cleanup_failure(self) -> None:
        destination = self.root / "ready"
        stage = self.root / ".ready.staging-cleanup"
        destination.mkdir()
        stage.mkdir()
        (destination / "manifest").write_text("old", encoding="utf-8")
        (stage / "manifest").write_text("new", encoding="utf-8")
        session = WorkspaceSession(
            root=self.root, stage=stage, destination=destination
        )
        original_rmtree = __import__("shutil").rmtree

        def fail_backup_cleanup(path, *args, **kwargs):
            if Path(path).name.startswith(".ready.old-"):
                raise OSError("cleanup failed")
            return original_rmtree(path, *args, **kwargs)

        with patch(
            "chimera.preprocess.offline.analysis.core.workspace.session.shutil.rmtree",
            side_effect=fail_backup_cleanup,
        ):
            with warnings.catch_warnings():
                warnings.simplefilter("error")
                with self.assertLogs(
                    "chimera.preprocess.offline.analysis.core.workspace.session",
                    level=logging.WARNING,
                ) as logs:
                    published = session.commit()

        self.assertEqual(published, destination)
        self.assertEqual((destination / "manifest").read_text(encoding="utf-8"), "new")
        self.assertTrue(list(self.root.glob(".ready.old-*")))
        self.assertTrue(any("backup" in line and ".ready.old-" in line for line in logs.output))
        self.assertTrue(session._finished)


if __name__ == "__main__":
    unittest.main()
