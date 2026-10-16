from __future__ import annotations

from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, call, patch

from chimera.runtime.bpf.transaction import PreparationRegistrar
from chimera.runtime.manifest import (
    ArtifactRecord,
    ModuleRecord,
    VariantPropertyRecord,
    VariantRecord,
    WorkspaceManifest,
)


class RegistrationManifestV1Tests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        (self.root / "scalar").mkdir()
        (self.root / "scalar" / "libdep.so").write_bytes(b"elf")
        # The application is resolved on the machine, not shipped, so it lives
        # outside the Workspace entirely.
        self.application = self.root / "opt" / "app"
        self.application.parent.mkdir()
        self.application.write_bytes(b"application")
        self.registry = Mock()
        self.registry.register_migratable_file.return_value = 41
        with patch(
            "chimera.runtime.bpf.transaction.ChimeraRegistry",
            return_value=self.registry,
        ):
            self.registrar = PreparationRegistrar("map")

    def artifact(
        self,
        artifact_id: str,
        owner_kind: str,
        owner_id: str,
        capability: str,
        representation: str,
        path: str,
        required_by: frozenset[str],
    ) -> ArtifactRecord:
        return ArtifactRecord(
            artifact_id, owner_kind, owner_id, capability, representation, 1,
            required_by, path, "0" * 64,
        )

    def manifest(self, artifacts=(), variants=()) -> WorkspaceManifest:
        properties = tuple(
            item
            for variant in variants
            for item in (
                VariantPropertyRecord(
                    variant.variant_id, "input", "vector_vlen_bits", "u64", "1024"
                ),
                VariantPropertyRecord(
                    variant.variant_id, "output", "vector_vlen_bits", "u64", "256"
                ),
            )
        )
        return WorkspaceManifest(
            1, "linux", "riscv64", "rvv", "linux_riscv64_rvv_v1",
            (
                ModuleRecord("main", "main", "app", "original", "target", "0" * 64),
                ModuleRecord(
                    "dep", "dependency", "libdep.so", "scalar", "package", "0" * 64
                ),
            ),
            tuple(variants), properties, tuple(artifacts),
        )

    def resolved(self) -> dict:
        return {"main": self.application}

    def test_registration_uses_each_delivery_source(self) -> None:
        variant = VariantRecord("main_vlen1024_to_vlen256", "main")

        self.registrar.register(
            self.root, self.manifest(variants=(variant,)),
            resolved_paths=self.resolved(),
        )

        self.assertEqual(
            self.registry.register_migratable_file.call_args_list,
            [
                call(self.application),
                call(self.root / "scalar" / "libdep.so"),
            ],
        )

    def test_registration_requires_a_resolved_target_module(self) -> None:
        # Guessing the application's inode from the Workspace would announce a
        # file that is not the application.
        with self.assertRaisesRegex(Exception, "resolved path"):
            self.registrar.register(self.root, self.manifest())
        self.registry.register_migratable_file.assert_not_called()

    def test_register_required_artifacts_are_rejected(self) -> None:
        # Safety points moved to the prepare-time ebreak patch, so no
        # capability may remain marked for the register consumer.
        cases = (
            ("control-flow-risk", "json"),
            ("safety", "json"),
            ("offset-map", "json"),
            ("translated-code", "elf"),
        )
        for capability, representation in cases:
            with self.subTest(capability=capability):
                stale = self.artifact(
                    "stale", "module", "main", capability, representation,
                    "custom/stale.json", frozenset({"register"}),
                )
                with self.assertRaisesRegex(
                    Exception, "unsupported required capability"
                ):
                    self.registrar.register(
                        self.root, self.manifest((stale,)),
                        resolved_paths=self.resolved(),
                    )
                self.registry.register_migratable_file.assert_not_called()

    def test_runtime_required_artifacts_do_not_block_registration(self) -> None:
        runtime_only = self.artifact(
            "translated", "variant", "main_vlen1024_to_vlen256",
            "translated-code", "elf", "custom/translated.elf",
            frozenset({"runtime"}),
        )

        self.registrar.register(
            self.root, self.manifest((runtime_only,)),
            resolved_paths=self.resolved(),
        )

        # Both modules are announced: one from the machine, one from the
        # package.
        self.assertEqual(
            self.registry.register_migratable_file.call_count, 2
        )

    def test_registration_is_repeatable_and_writes_no_state_file(self) -> None:
        # Kernel map content is lost on reboot, so re-registration must not be
        # blocked by any persisted "already registered" marker.
        manifest = self.manifest()

        first = self.registrar.register_workspace(
            self.root, manifest, resolved_paths=self.resolved()
        )
        second = self.registrar.register_workspace(
            self.root, manifest, resolved_paths=self.resolved()
        )

        self.assertEqual(self.registry.register_migratable_file.call_count, 4)
        self.assertEqual(first.map_keys, 2)
        self.assertEqual(second.map_keys, 4)
        self.assertFalse((self.root / ".chimera-registration.json").exists())


if __name__ == "__main__":
    unittest.main()
