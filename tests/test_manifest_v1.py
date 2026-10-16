from __future__ import annotations

from dataclasses import replace
from hashlib import sha256
from pathlib import Path
import tempfile
import unittest

from chimera.runtime.manifest import (
    ArtifactRecord,
    ModuleRecord,
    VariantRecord,
    VariantPropertyRecord,
    WorkspaceManifest,
    read_manifest,
    write_manifest,
    variant_fingerprint,
)


class ManifestV1Tests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.manifest_path = self.root / "artifacts" / "modules.tsv"

    def artifact(self, **changes: object) -> ArtifactRecord:
        content = b"{}\n"
        path = self.root / "generated" / "main.risk.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        record = ArtifactRecord(
            artifact_id="risk-json",
            owner_kind="module",
            owner_id="main",
            capability="control-flow-risk",
            representation="json",
            abi=1,
            required_by=frozenset(),
            path="generated/main.risk.json",
            sha256=sha256(content).hexdigest(),
        )
        return replace(record, **changes)

    def manifest(self, artifact: ArtifactRecord) -> WorkspaceManifest:
        return WorkspaceManifest(
            runtime_abi=1,
            target_os="linux",
            target_arch="riscv64",
            target_arch_extension="rvv",
            runtime_scene="linux_riscv64_rvv_v1",
            modules=(ModuleRecord("main", "main", "app", "original", "target", "0" * 64),),
            variants=(VariantRecord("main_v1024_v256", "main"),),
            variant_properties=(
                VariantPropertyRecord(
                    "main_v1024_v256", "input", "architecture", "token", "riscv64"
                ),
                VariantPropertyRecord(
                    "main_v1024_v256", "input", "architecture_extension", "token", "rvv"
                ),
                VariantPropertyRecord(
                    "main_v1024_v256", "input", "vector_vlen_bits", "u64", "1024"
                ),
                VariantPropertyRecord(
                    "main_v1024_v256", "output", "architecture", "token", "riscv64"
                ),
                VariantPropertyRecord(
                    "main_v1024_v256", "output", "architecture_extension", "token", "rvv"
                ),
                VariantPropertyRecord(
                    "main_v1024_v256", "output", "vector_vlen_bits", "u64", "256"
                ),
            ),
            artifacts=(artifact,),
        )

    def test_unknown_optional_capability_round_trips_without_schema_change(self) -> None:
        manifest = self.manifest(self.artifact())

        write_manifest(manifest, self.manifest_path)

        self.assertEqual(
            read_manifest(self.manifest_path, workspace_root=self.root),
            manifest,
        )

    def test_module_rejects_dot_runtime_names(self) -> None:
        for runtime_name in (".", ".."):
            with self.subTest(runtime_name=runtime_name):
                with self.assertRaisesRegex(ValueError, "runtime_name"):
                    ModuleRecord("main", "main", runtime_name, "original", "target", "0" * 64).validate()

    def test_artifact_cannot_replace_a_packaged_module_input(self) -> None:
        # Only packaged modules occupy a path inside the Workspace, and
        # that path is the one an artifact must not overwrite.
        manifest = replace(
            self.manifest(self.artifact(path="scalar/libdep.so")),
            modules=(
                ModuleRecord("main", "main", "app", "original", "target", "0" * 64),
                ModuleRecord(
                    "dep", "dependency", "libdep.so", "scalar", "package", "0" * 64
                ),
            ),
        )
        with self.assertRaisesRegex(ValueError, "module input"):
            manifest.validate()

    def test_artifact_may_reuse_a_target_module_name(self) -> None:
        # The application is resolved on the target machine, so its name
        # is free inside the package.
        manifest = self.manifest(self.artifact(path="scalar/app"))
        manifest.validate()

    def test_required_by_is_written_deterministically(self) -> None:
        manifest = self.manifest(
            self.artifact(required_by=frozenset({"runtime", "register"}))
        )

        write_manifest(manifest, self.manifest_path)

        self.assertIn(
            "\tregister,runtime\t",
            self.manifest_path.read_text(encoding="utf-8"),
        )

    def test_manifest_text_capacity_is_measured_in_utf8_bytes(self) -> None:
        ModuleRecord("m" * 255, "main", "app", "original", "target", "0" * 64).validate()
        ModuleRecord("main", "main", "界" * 85, "original", "target", "0" * 64).validate()

        for record in (
            ModuleRecord("m" * 256, "main", "app", "original", "target", "0" * 64),
            ModuleRecord("main", "main", "界" * 85 + "a", "original", "target", "0" * 64),
        ):
            with self.subTest(record=record):
                with self.assertRaisesRegex(ValueError, "UTF-8 bytes"):
                    record.validate()

    def test_property_tokens_obey_manifest_text_capacity(self) -> None:
        VariantPropertyRecord(
            "variant", "input", "property", "token", "t" * 255
        ).validate()

        with self.assertRaisesRegex(ValueError, "UTF-8 bytes"):
            VariantPropertyRecord(
                "variant", "input", "property", "token", "t" * 256
            ).validate()

    def test_artifact_path_and_required_by_obey_serialized_capacity(self) -> None:
        self.artifact(path="p" * 255).validate()
        self.artifact(required_by=frozenset({"a" * 127, "b" * 127})).validate()

        cases = (
            self.artifact(path="p" * 256),
            self.artifact(required_by=frozenset({"a" * 128, "b" * 127})),
        )
        for artifact in cases:
            with self.subTest(artifact=artifact):
                with self.assertRaisesRegex(ValueError, "UTF-8 bytes"):
                    artifact.validate()

    def test_header_and_representation_capacities_match_c_fields(self) -> None:
        manifest = self.manifest(self.artifact(representation="r" * 31))
        replace(
            manifest,
            target_os="o" * 31,
            runtime_scene="s" * 255,
        ).validate()

        cases = (
            replace(manifest, target_os="o" * 32),
            replace(manifest, runtime_scene="s" * 256),
            self.manifest(self.artifact(representation="r" * 32)),
        )
        for malformed in cases:
            with self.subTest(malformed=malformed):
                with self.assertRaisesRegex(ValueError, "UTF-8 bytes"):
                    malformed.validate()

    def test_codec_rejects_overlong_text_on_write_and_read(self) -> None:
        manifest = self.manifest(self.artifact())
        with self.assertRaisesRegex(ValueError, "UTF-8 bytes"):
            write_manifest(
                replace(manifest, runtime_scene="s" * 256),
                self.manifest_path,
            )

        write_manifest(manifest, self.manifest_path)
        valid = self.manifest_path.read_text(encoding="utf-8")
        self.manifest_path.write_text(
            valid.replace(
                "# runtime_scene=linux_riscv64_rvv_v1",
                f"# runtime_scene={'s' * 256}",
            ),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(ValueError, "UTF-8 bytes"):
            read_manifest(self.manifest_path)

    def test_artifact_owner_must_exist(self) -> None:
        manifest = self.manifest(self.artifact(owner_id="missing"))

        with self.assertRaisesRegex(ValueError, "unknown module owner"):
            manifest.validate()

    def test_artifact_path_cannot_escape_workspace(self) -> None:
        manifest = self.manifest(self.artifact(path="../escape.json"))

        with self.assertRaisesRegex(ValueError, "safe workspace-relative"):
            manifest.validate(workspace_root=self.root)

    def test_hash_is_verified(self) -> None:
        manifest = self.manifest(self.artifact(sha256="0" * 64))

        with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
            manifest.validate(workspace_root=self.root)

    def test_manifest_magic_is_the_only_accepted_magic(self) -> None:
        write_manifest(self.manifest(self.artifact()), self.manifest_path)
        self.assertEqual(
            self.manifest_path.read_text(encoding="utf-8").splitlines()[0],
            "# chimera-workspace-manifest-v2",
        )

        for magic in (
            "# chimera-workspace-manifest-v7",
            "# chimera-workspace-manifest-v8",
        ):
            text = self.manifest_path.read_text(encoding="utf-8")
            self.manifest_path.write_text(text.replace(
                "# chimera-workspace-manifest-v2", magic, 1
            ), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "run.*prepare.*again"):
                read_manifest(self.manifest_path)
            self.manifest_path.write_text(text, encoding="utf-8")

    def test_noncanonical_property_value_is_rejected(self) -> None:
        manifest = self.manifest(self.artifact())
        malformed = replace(
            manifest,
            variant_properties=(replace(
                manifest.variant_properties[0], value="01024"
            ), *manifest.variant_properties[1:]),
        )

        with self.assertRaisesRegex(ValueError, "non-canonical"):
            malformed.validate()

    def test_noncanonical_abi_integers_are_rejected_by_codec(self) -> None:
        write_manifest(self.manifest(self.artifact()), self.manifest_path)
        valid = self.manifest_path.read_text(encoding="utf-8")

        self.manifest_path.write_text(
            valid.replace("# runtime_abi=1", "# runtime_abi=+1"),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(ValueError, "canonical positive u64"):
            read_manifest(self.manifest_path)

        self.manifest_path.write_text(
            valid.replace("\tjson\t1\t-\t", "\tjson\t01\t-\t"),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(ValueError, "canonical positive u64"):
            read_manifest(self.manifest_path)

    def test_variant_fingerprint_binds_identity_module_and_properties(self) -> None:
        manifest = self.manifest(self.artifact())

        fingerprint = variant_fingerprint(manifest, "main_v1024_v256")
        changed = replace(
            manifest,
            variant_properties=tuple(
                replace(item, value="2048")
                if (item.side, item.name) == ("input", "vector_vlen_bits")
                else item
                for item in manifest.variant_properties
            ),
        )

        self.assertEqual(
            fingerprint,
            "55061f6476f527472e025168d4ee025648465fceadceb7b6d114d308ec8b40bf",
        )
        self.assertNotEqual(
            fingerprint, variant_fingerprint(changed, "main_v1024_v256")
        )


if __name__ == "__main__":
    unittest.main()
