from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

from chimera.preprocess.offline.analysis.offsetmap.codegen import (
    export_json as export_offset_map_json,
)
from chimera.preprocess.offline.analysis.safety.exporters import (
    export_json as export_safety_json,
)
from chimera.runtime.manifest import (
    ArtifactRecord,
    ModuleRecord,
    VariantPropertyRecord,
    VariantRecord,
    WorkspaceManifest,
    variant_fingerprint,
)
from chimera.runtime.validate.capabilities import (
    CapabilityVerificationError,
    verify_offset_map_json,
    verify_safety_json,
    verify_translated_elf,
)


class TranslatedCodeV1Tests(unittest.TestCase):
    def manifest(self) -> WorkspaceManifest:
        variant = VariantRecord("main_vlen1024_to_vlen256", "main")
        artifact = ArtifactRecord(
            "translated", "variant", variant.variant_id,
            "translated-code", "elf", 1, frozenset({"runtime"}),
            "artifacts/translated.so", "0" * 64,
        )
        return WorkspaceManifest(
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
                    variant.variant_id, "input", "vector_vlen_bits", "u64", "1024"
                ),
                VariantPropertyRecord(
                    variant.variant_id, "output", "architecture", "token", "riscv64"
                ),
                VariantPropertyRecord(
                    variant.variant_id, "output", "architecture_extension", "token", "rvv"
                ),
                VariantPropertyRecord(
                    variant.variant_id, "output", "vector_vlen_bits", "u64", "256"
                ),
            ),
            (artifact,),
        )

    def symbols(self, manifest: WorkspaceManifest) -> set[str]:
        variant = manifest.variants[0]
        safe = "chimera_main_vlen1024_to_vlen256"
        return {
            f"{variant.variant_id}_original_base_addr",
            f"{safe}_translated_code_abi_v1",
            f"{safe}_translation_fingerprint_"
            f"{variant_fingerprint(manifest, variant.variant_id)}",
        }

    def test_verifier_binds_manifest_properties_to_dso_provenance(self) -> None:
        manifest = self.manifest()
        artifact = manifest.artifacts[0]
        exported_symbols = self.symbols(manifest)
        safe = "chimera_main_vlen1024_to_vlen256"
        self.assertIn(f"{safe}_translated_code_abi_v1", exported_symbols)
        self.assertNotIn(f"{safe}_translated_code_abi_v2", exported_symbols)
        self.assertEqual(artifact.abi, 1)
        with patch(
            "chimera.runtime.validate.capabilities._exported_symbols",
            return_value=exported_symbols,
        ):
            verify_translated_elf(
                Path("translated.so"), artifact, manifest, SimpleNamespace()
            )

    def test_changed_endpoint_property_rejects_original_dso(self) -> None:
        original = self.manifest()
        changes = {
            ("input", "architecture"): "other64",
            ("input", "architecture_extension"): "other",
            ("input", "vector_vlen_bits"): "2048",
        }
        for key, value in changes.items():
            with self.subTest(property=key):
                changed = replace(
                    original,
                    variant_properties=tuple(
                        replace(item, value=value)
                        if (item.side, item.name) == key else item
                        for item in original.variant_properties
                    ),
                )
                with patch(
                    "chimera.runtime.validate.capabilities._exported_symbols",
                    return_value=self.symbols(original),
                ):
                    with self.assertRaisesRegex(
                        CapabilityVerificationError, "translation_fingerprint"
                    ):
                        verify_translated_elf(
                            Path("translated.so"), changed.artifacts[0], changed,
                            SimpleNamespace(),
                        )

    def test_analysis_json_exports_and_verifiers_require_v1_formats(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            safety_path = root / "safety.json"
            offset_path = root / "offset-map.json"
            export_safety_json(
                SimpleNamespace(source_path=None),
                SimpleNamespace(records={}),
                safety_path,
            )
            export_offset_map_json({}, offset_path)
            safety_json = json.loads(safety_path.read_text(encoding="utf-8"))
            offset_json = json.loads(offset_path.read_text(encoding="utf-8"))
            self.assertEqual(
                safety_json,
                {
                    "format": "chimera-safety-v1",
                    "unknown_stack_size_policy": "conservative",
                    "assumption": "Unknown scalar stack allocation sizes remain conservatively VLEN-sensitive.",
                    "conditional": False,
                    "scope_exclusion_count": 0,
                    "scope_exclusions": [],
                    "entries": [],
                },
            )
            self.assertEqual(
                offset_json,
                {"format": "chimera-offset-map-v1", "entries": []},
            )
            verify_safety_json(
                safety_path,
                ArtifactRecord(
                    "safety", "module", "main", "safety", "json", 1,
                    frozenset(), "safety.json", "0" * 64,
                ),
                self.manifest(),
                SimpleNamespace(),
            )
            verify_offset_map_json(
                offset_path,
                ArtifactRecord(
                    "offset-map", "variant", "main_vlen1024_to_vlen256",
                    "offset-map", "json", 1, frozenset(), "offset-map.json",
                    "0" * 64,
                ),
                self.manifest(),
                SimpleNamespace(),
            )

    def test_analysis_json_verifiers_reject_wrong_owner_or_abi(self) -> None:
        safety = ArtifactRecord(
            "safety", "module", "main", "safety", "json", 1,
            frozenset(), "safety.json", "0" * 64,
        )
        offset_map = ArtifactRecord(
            "offset-map", "variant", "main_vlen1024_to_vlen256",
            "offset-map", "json", 1, frozenset(), "offset-map.json",
            "0" * 64,
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            safety_path = root / "safety.json"
            offset_path = root / "offset-map.json"
            safety_path.write_text(
                json.dumps({"format": "chimera-safety-v1", "entries": []}),
                encoding="utf-8",
            )
            offset_path.write_text(
                json.dumps({"format": "chimera-offset-map-v1", "entries": []}),
                encoding="utf-8",
            )
            cases = (
                (
                    "safety-owner", verify_safety_json, safety_path,
                    replace(safety, owner_kind="variant"),
                    "invalid safety JSON owner or ABI",
                ),
                (
                    "safety-abi", verify_safety_json, safety_path,
                    replace(safety, abi=2),
                    "invalid safety JSON owner or ABI",
                ),
                (
                    "offset-map-owner", verify_offset_map_json, offset_path,
                    replace(offset_map, owner_kind="module"),
                    "invalid offset-map JSON owner or ABI",
                ),
                (
                    "offset-map-abi", verify_offset_map_json, offset_path,
                    replace(offset_map, abi=2),
                    "invalid offset-map JSON owner or ABI",
                ),
            )
            for label, verifier, path, artifact, message in cases:
                with self.subTest(case=label):
                    with self.assertRaisesRegex(
                        CapabilityVerificationError, message
                    ):
                        verifier(
                            path, artifact, self.manifest(), SimpleNamespace()
                        )

    def test_analysis_json_verifiers_reject_development_formats(self) -> None:
        cases = (
            ("safety", "chimera-safety-v3"),
            ("offset-map", "chimera-offset-map-v2"),
            ("offset-map", "chimera-offset-map-v3"),
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for capability, format_name in cases:
                with self.subTest(format=format_name):
                    path = root / f"{capability}.json"
                    path.write_text(
                        json.dumps({"format": format_name}), encoding="utf-8"
                    )
                    artifact = ArtifactRecord(
                        capability, "module" if capability == "safety" else "variant",
                        "main" if capability == "safety" else "main_vlen1024_to_vlen256",
                        capability, "json", 1, frozenset(), path.name, "0" * 64,
                    )
                    verifier = (
                        verify_safety_json
                        if capability == "safety" else verify_offset_map_json
                    )
                    with self.assertRaisesRegex(
                        CapabilityVerificationError, "unsupported.*JSON format"
                    ):
                        verifier(path, artifact, self.manifest(), SimpleNamespace())


if __name__ == "__main__":
    unittest.main()
