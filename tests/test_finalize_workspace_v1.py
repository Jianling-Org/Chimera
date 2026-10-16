from __future__ import annotations

from hashlib import sha256
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import Mock

from elf_fixture import build_elf

from chimera.preprocess.offline.analysis import AnalysisContext
from chimera.preprocess.offline.analysis.core.workspace import (
    WorkspaceSession,
    anchor_file,
)
from chimera.preprocess.offline.analysis.finalize_workspace import FinalizeWorkspaceStep
from chimera.preprocess.offline.analysis_profile.target import validate_linux_riscv64_rvv_publication
from chimera.runtime.manifest import (
    ArtifactRecord, ModuleRecord, VariantPropertyRecord, VariantRecord,
)


class FinalizeWorkspaceV1Tests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.stage = self.root / ".ready.staging-test"
        (self.stage / "artifacts").mkdir(parents=True)
        self.session = WorkspaceSession(
            root=self.root,
            stage=self.stage,
            destination=self.root / "ready",
        )
        self.session.registry.register_module(
            ModuleRecord("main", "main", "app", "original", "target", "0" * 64)
        )
        self.session.registry.register_variant(
            VariantRecord("main_vlen1024_to_vlen256", "main")
        )
        for side, value in (("input", "1024"), ("output", "256")):
            self.session.registry.register_variant_property(
                VariantPropertyRecord(
                    "main_vlen1024_to_vlen256", side,
                    "architecture", "token", "riscv64",
                )
            )
            self.session.registry.register_variant_property(
                VariantPropertyRecord(
                    "main_vlen1024_to_vlen256", side,
                    "architecture_extension", "token", "rvv",
                )
            )
            self.session.registry.register_variant_property(
                VariantPropertyRecord(
                    "main_vlen1024_to_vlen256", side,
                    "vector_vlen_bits", "u64", value,
                )
            )
        self.session.register_validator(
            "scene.linux_riscv64_rvv_v1.topology",
            validate_linux_riscv64_rvv_publication,
        )
        self.register_artifact(
            "runtime", "workspace", "root", "runtime", "runtime.so"
        )
        self.register_artifact(
            "translated", "variant", "main_vlen1024_to_vlen256",
            "translated-code", "translated.so",
        )
        self.register_artifact(
            "map", "variant", "main_vlen1024_to_vlen256",
            "offset-map", "map.so",
        )

    def register_artifact(
        self,
        artifact_id: str,
        owner_kind: str,
        owner_id: str,
        capability: str,
        filename: str,
    ) -> None:
        path = self.stage / "artifacts" / filename
        path.write_bytes(artifact_id.encode())
        abi = 1
        self.session.registry.register_artifact(ArtifactRecord(
            artifact_id, owner_kind, owner_id, capability, "elf", abi,
            frozenset({"runtime"}), f"artifacts/{filename}",
            sha256(path.read_bytes()).hexdigest(),
        ))

    def context(self) -> AnalysisContext:
        services = SimpleNamespace(
            platform=SimpleNamespace(runner=Mock()),
            toolchain=SimpleNamespace(
                compiler=SimpleNamespace(compile=Mock()),
            ),
            architecture=Mock(),
        )
        return (
            AnalysisContext(
                input_elf=self.root / "app",
                stage=self.stage,
                config=SimpleNamespace(),
                target_os="linux",
                target_arch="riscv64",
                target_arch_extension="rvv",
                runtime_scene="linux_riscv64_rvv_v1",
                runtime_abi=1,
                services=services,
            )
            .put_global("workspace_session", self.session)
            .put_global("modules", ())
            .put_global("runtime_artifact", object())
            .put_global("translations", {})
            .put_global("offset_maps", {})
        )

    def test_finalize_only_writes_manifest_and_commits(self) -> None:
        context = self.context()

        updated = FinalizeWorkspaceStep().run(context)

        self.assertEqual(
            updated.require_global("published_workspace"), self.root / "ready"
        )
        self.assertTrue((self.root / "ready" / "artifacts" / "modules.tsv").is_file())
        context.services.platform.runner.assert_not_called()
        context.services.toolchain.compiler.compile.assert_not_called()

    def test_finalize_accepts_workspace_without_safety_artifacts(self) -> None:
        manifest = FinalizeWorkspaceStep().run(
            self.context()
        ).require_global("manifest")

        self.assertFalse(
            any(artifact.capability == "safety" for artifact in manifest.artifacts)
        )

    def test_finalize_refuses_to_publish_when_an_input_changed(self) -> None:
        """Publication is the last point at which the inputs can be checked.

        Every analysis step re-opened its input by path, so committing without
        this check would publish artifacts describing bytes that are gone.
        """

        tracked = build_elf(self.root / "app")
        self.session.anchors = (anchor_file(tracked),)
        with tracked.open("ab") as stream:
            stream.write(b"\x00" * 128)

        with self.assertRaisesRegex(ValueError, "changed after it was analysed"):
            FinalizeWorkspaceStep().run(self.context())

        # Nothing was published: the failed check precedes the commit.
        self.assertFalse((self.root / "ready").exists())

    def test_finalize_rejects_variant_without_offset_map_elf(self) -> None:
        del self.session.registry.artifacts["map"]
        del self.session.registry._artifact_paths["artifacts/map.so"]

        with self.assertRaisesRegex(ValueError, r"(?i)variant.*offset-map.*elf"):
            FinalizeWorkspaceStep().run(self.context())


if __name__ == "__main__":
    unittest.main()
