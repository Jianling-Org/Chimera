from __future__ import annotations

from dataclasses import replace
from hashlib import sha256
from pathlib import Path
import struct
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

from chimera.runtime.manifest import (
    ArtifactRecord,
    ModuleRecord,
    VariantRecord,
    VariantPropertyRecord,
    WorkspaceManifest,
    write_manifest,
)
from chimera.runtime.validate import VerificationError, verify_workspace
import chimera.runtime.validate.workspace as workspace_verifier

if __package__:
    from .test_translator_routing import ROUTE_CASES
else:
    from test_translator_routing import ROUTE_CASES


class WorkspaceVerifyV1Tests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        (self.root / "artifacts").mkdir()
        content = b"{}\n"
        path = self.root / "generated" / "custom-risk.json"
        path.parent.mkdir()
        path.write_bytes(content)
        self.unknown = ArtifactRecord(
            "risk", "module", "main", "control-flow-risk", "json", 1,
            frozenset(), "generated/custom-risk.json",
            sha256(content).hexdigest(),
        )
        self.settings = SimpleNamespace(nm="nm")

    def core_artifact(
        self,
        artifact_id: str,
        owner_kind: str,
        owner_id: str,
        capability: str,
    ) -> ArtifactRecord:
        path = self.root / "artifacts" / f"{artifact_id}.so"
        if capability == "runtime":
            ident = b"\x7fELF\x02\x01\x01" + bytes(9)
            content = struct.pack(
                "<16sHHIQQQIHHHHHH",
                ident, 3, 243, 1, 0, 0, 0, 0, 64, 56, 0, 64, 0, 0,
            )
        else:
            content = artifact_id.encode()
        path.write_bytes(content)
        return ArtifactRecord(
            artifact_id, owner_kind, owner_id, capability, "elf",
            1,
            frozenset({"runtime"}), f"artifacts/{artifact_id}.so",
            sha256(content).hexdigest(),
        )

    def publish(
        self,
        artifact: ArtifactRecord,
        *,
        source_vlen: int = 1024,
        target_vlen: int = 256,
    ) -> WorkspaceManifest:
        variant = VariantRecord(f"main_v{source_vlen}_v{target_vlen}", "main")
        manifest = WorkspaceManifest(
            1, "linux", "riscv64", "rvv", "linux_riscv64_rvv_v1",
            (ModuleRecord("main", "main", "app", "original", "target", "0" * 64),),
            (variant,),
            (
                VariantPropertyRecord(
                    variant.variant_id, "input", "architecture", "token", "riscv64"
                ),
                VariantPropertyRecord(
                    variant.variant_id, "input", "architecture_extension", "token", "rvv"
                ),
                VariantPropertyRecord(
                    variant.variant_id, "input", "vector_vlen_bits", "u64",
                    str(source_vlen),
                ),
                VariantPropertyRecord(
                    variant.variant_id, "output", "architecture", "token", "riscv64"
                ),
                VariantPropertyRecord(
                    variant.variant_id, "output", "architecture_extension", "token", "rvv"
                ),
                VariantPropertyRecord(
                    variant.variant_id, "output", "vector_vlen_bits", "u64",
                    str(target_vlen),
                ),
            ),
            tuple(sorted((
                self.core_artifact("runtime", "workspace", "root", "runtime"),
                self.core_artifact(
                    "translated", "variant", variant.variant_id, "translated-code"
                ),
                self.core_artifact(
                    "offset-map", "variant", variant.variant_id, "offset-map"
                ),
                artifact,
            ), key=lambda item: item.artifact_id)),
        )
        write_manifest(manifest, self.root / "artifacts" / "modules.tsv")
        return manifest

    def verify(self):
        noops = {key: (lambda *_args: None) for key in workspace_verifier.VERIFIERS}
        with patch.dict(workspace_verifier.VERIFIERS, noops):
            return verify_workspace(self.root, self.settings, check_host=False)

    def test_unknown_optional_capability_is_hash_checked_then_ignored(self) -> None:
        manifest = self.publish(self.unknown)

        self.assertEqual(self.verify(), manifest)

    def test_unknown_runtime_required_capability_is_rejected(self) -> None:
        self.publish(
            replace(self.unknown, required_by=frozenset({"runtime"}))
        )

        with self.assertRaisesRegex(
            VerificationError, "unsupported required capability"
        ):
            self.verify()

    def test_scene_rejects_endpoint_properties_with_wrong_kinds(self) -> None:
        cases = (
            (("input", "vector_vlen_bits"), "bool", "true", "kind u64"),
            (("input", "vector_vlen_bits"), "i64", "1024", "kind u64"),
            (("input", "architecture"), "bool", "true", "kind token"),
            (("output", "architecture_extension"), "bool", "true", "kind token"),
        )
        for key, kind, value, message in cases:
            with self.subTest(property=key, kind=kind):
                manifest = self.publish(self.unknown)
                manifest = replace(
                    manifest,
                    variant_properties=tuple(
                        replace(item, value_kind=kind, value=value)
                        if (item.side, item.name) == key else item
                        for item in manifest.variant_properties
                    ),
                )
                write_manifest(manifest, self.root / "artifacts" / "modules.tsv")
                with self.assertRaisesRegex(VerificationError, message):
                    self.verify()

    def test_scene_accepts_only_supported_rvv_routes(self) -> None:
        for source_vlen, target_vlen, supported in ROUTE_CASES:
            with self.subTest(source=source_vlen, target=target_vlen):
                self.publish(
                    self.unknown,
                    source_vlen=source_vlen,
                    target_vlen=target_vlen,
                )
                if supported:
                    self.verify()
                else:
                    with self.assertRaisesRegex(
                        VerificationError, "unsupported RVV translation route"
                    ):
                        self.verify()

    def test_missing_runtime_core_artifact_is_rejected(self) -> None:
        manifest = WorkspaceManifest(
            1, "linux", "riscv64", "rvv", "linux_riscv64_rvv_v1",
            (ModuleRecord("main", "main", "app", "original", "target", "0" * 64),),
            (), (), (self.unknown,),
        )
        write_manifest(manifest, self.root / "artifacts" / "modules.tsv")

        with self.assertRaisesRegex(VerificationError, "runtime/elf"):
            self.verify()

    def test_module_without_translation_variant_is_rejected(self) -> None:
        runtime = self.core_artifact(
            "runtime", "workspace", "root", "runtime"
        )
        manifest = WorkspaceManifest(
            1, "linux", "riscv64", "rvv", "linux_riscv64_rvv_v1",
            (ModuleRecord("main", "main", "app", "original", "target", "0" * 64),),
            (), (), (runtime, self.unknown),
        )
        write_manifest(manifest, self.root / "artifacts" / "modules.tsv")

        with self.assertRaisesRegex(VerificationError, "translation variant"):
            self.verify()


if __name__ == "__main__":
    unittest.main()
