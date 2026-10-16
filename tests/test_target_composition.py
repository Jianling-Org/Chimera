from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from chimera.preprocess.offline.analysis.arch.riscv import RiscvServices
from chimera.preprocess.offline.analysis.arch.riscv.rvv import RvvServices
from chimera.preprocess.offline.analysis.platform.linux import LinuxServices
from chimera.preprocess.offline.analysis.toolchain.translator import ExternalTranslator
from chimera.preprocess.offline.analysis.translation.model import TranslationRequest
from chimera.preprocess.offline.analysis_profile.target import (
    TargetCatalog,
    TargetKey,
    registered_target_catalog,
    validate_linux_riscv64_rvv_publication,
)
from chimera.preprocess.offline.config.loader import parse_base_config
from chimera.preprocess.offline.config import TranslationEndpoint
from chimera.runtime.manifest import (
    ArtifactRecord,
    ModuleRecord,
    VariantPropertyRecord,
    VariantRecord,
    WorkspaceManifest,
)

if __package__:
    from .test_translator_routing import ROUTE_CASES
else:
    from test_translator_routing import ROUTE_CASES


class TargetCompositionTests(unittest.TestCase):
    def test_current_bundle_is_selected_by_complete_target_key(self) -> None:
        key = TargetKey(
            "linux", "riscv64", "rvv", "linux_riscv64_rvv_v1"
        )

        bundle = registered_target_catalog()[key]
        with tempfile.TemporaryDirectory() as temporary:
            config = parse_base_config(
                {"tools": {"cc": "gcc"}},
                source=Path(temporary) / "profile.toml",
            )
            services = bundle.create_services(config)

        self.assertEqual(bundle.key, key)
        self.assertIsInstance(services.architecture, RiscvServices)
        self.assertIsInstance(services.architecture.extension, RvvServices)
        self.assertIsInstance(services.platform, LinuxServices)
        # Linker relaxation is an RVV scene policy, injected by the target
        # composition root rather than the generic compiler adapter.
        command = services.toolchain.compiler.compile(
            [Path("translated.S")], Path("translated.so")
        )
        self.assertIn("-Wl,--relax", command)
        self.assertEqual(bundle.runtime.system_name, "Linux")
        self.assertEqual(bundle.runtime.elf_machine, 243)
        self.assertEqual(bundle.runtime.abi, 1)
        self.assertEqual(
            bundle.plan_completion_requirements,
            frozenset({
                "modules", "runtime_artifact", "translations", "offset_maps"
            }),
        )

    def test_catalog_rejects_duplicates_and_reports_complete_unsupported_key(self) -> None:
        bundle = registered_target_catalog()[TargetKey(
            "linux", "riscv64", "rvv", "linux_riscv64_rvv_v1"
        )]
        with self.assertRaisesRegex(ValueError, "duplicate target bundle"):
            TargetCatalog((bundle, bundle))

        with self.assertRaisesRegex(
            ValueError,
            "freebsd.*riscv64.*rvv.*linux_riscv64_rvv_v1",
        ):
            registered_target_catalog().select(TargetKey(
                "freebsd", "riscv64", "rvv", "linux_riscv64_rvv_v1"
            ))

    def test_publication_accepts_only_supported_rvv_routes(self) -> None:
        for source_vlen, target_vlen, supported in ROUTE_CASES:
            with self.subTest(source=source_vlen, target=target_vlen):
                variant = VariantRecord("variant", "main")
                properties = tuple(
                    VariantPropertyRecord(
                        variant.variant_id,
                        side,
                        name,
                        kind,
                        value,
                    )
                    for side, vlen in (
                        ("input", source_vlen), ("output", target_vlen)
                    )
                    for name, kind, value in (
                        ("architecture", "token", "riscv64"),
                        ("architecture_extension", "token", "rvv"),
                        ("vector_vlen_bits", "u64", str(vlen)),
                    )
                )
                artifacts = (
                    ArtifactRecord(
                        "runtime", "workspace", "root", "runtime", "elf",
                        1, frozenset({"runtime"}), "runtime.so", "0" * 64,
                    ),
                    ArtifactRecord(
                        "translated", "variant", variant.variant_id,
                        "translated-code", "elf", 1, frozenset({"runtime"}),
                        "translated.so", "0" * 64,
                    ),
                    ArtifactRecord(
                        "offset-map", "variant", variant.variant_id,
                        "offset-map", "elf", 1, frozenset({"runtime"}),
                        "offset-map.so", "0" * 64,
                    ),
                )
                manifest = WorkspaceManifest(
                    1, "linux", "riscv64", "rvv", "linux_riscv64_rvv_v1",
                    (ModuleRecord("main", "main", "app", "original", "target", "0" * 64),),
                    (variant,), properties, artifacts,
                )
                if supported:
                    validate_linux_riscv64_rvv_publication(manifest)
                else:
                    with self.assertRaisesRegex(
                        ValueError, "unsupported RVV translation route"
                    ):
                        validate_linux_riscv64_rvv_publication(manifest)


class TranslatorAdapterTests(unittest.TestCase):
    def _request(self, root: Path, translator: Path) -> TranslationRequest:
        return TranslationRequest(
            module=None,
            source_endpoint=TranslationEndpoint.parse(
                "riscv64;rvv;vlen=1024", field="source"
            ),
            target_endpoint=TranslationEndpoint.parse(
                "riscv64;rvv;vlen=256", field="target"
            ),
            translator_path=translator,
            native_dump=root / "native.dump",
            assembly_output=root / "translated.S",
            library_output=root / "translated.so",
            translated_dump_output=root / "translated.dump",
            symbol_namespace="main_vlen1024_to_vlen256",
            input_properties={},
            output_properties={},
        )

    def test_uses_fixed_argv_and_preserves_paths_with_spaces(self) -> None:
        with tempfile.TemporaryDirectory(prefix="translator route ") as temporary:
            root = Path(temporary)
            translator = root / "translator script.py"
            translator.write_text("# external\n", encoding="utf-8")
            request = self._request(root / "workspace with spaces", translator)

            command = ExternalTranslator(python="python3").command(request)

        self.assertEqual(command, [
            "python3", str(translator), str(request.native_dump),
            request.symbol_namespace, "-o", str(request.assembly_output),
        ])

    def test_rechecks_selected_translator_at_execution(self) -> None:
        request = self._request(Path("work"), Path("missing-translator.py"))
        with self.assertRaisesRegex(FileNotFoundError, "selected translator"):
            ExternalTranslator(python="python3").command(request)


class SceneCmakeTests(unittest.TestCase):
    def test_root_cmake_loads_a_sanitized_scene_fragment(self) -> None:
        root = Path("runtime/CMakeLists.txt").read_text(encoding="utf-8")
        fragment = Path(
            "runtime/interfaces/profiles/linux_riscv64_rvv_v1/runtime.cmake"
        )

        self.assertIn("CHIMERA_SCENE MATCHES", root)
        self.assertIn("interfaces/profiles/${CHIMERA_SCENE}/runtime.cmake", root)
        self.assertNotIn(
            'if(NOT CHIMERA_SCENE STREQUAL "linux_riscv64_rvv_v1"', root
        )
        self.assertTrue(fragment.is_file())


if __name__ == "__main__":
    unittest.main()
