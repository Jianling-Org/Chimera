"""Target-independent translation production contracts."""

from __future__ import annotations

import unittest
import tempfile
from types import SimpleNamespace
from pathlib import Path

from chimera.preprocess.offline.analysis.translation.model import (
    TranslationKey,
    TranslationProductionSpec,
)
from chimera.preprocess.offline.analysis.translation import TranslationStep
from chimera.preprocess.offline.analysis.toolchain.artifact_emitter import (
    GnuArtifactEmitter,
)
from chimera.preprocess.offline.analysis import AnalysisContext
from chimera.preprocess.offline.analysis.core.data_model import (
    DELIVERY_TARGET,
    AnalysisModule,
)
from chimera.preprocess.offline.analysis.core.workspace import WorkspaceSession
from chimera.runtime.manifest import ModuleRecord
from chimera.preprocess.offline.config import TranslationEndpoint


class TranslationSemanticsContractTests(unittest.TestCase):
    def test_key_is_endpoint_based_and_orders_by_canonical_endpoint(self):
        source = TranslationEndpoint("toy", "scalar", "v1")
        target = TranslationEndpoint("toy", "wide", "v2")
        key = TranslationKey("module", source, target)
        self.assertEqual(key.source_endpoint, source)
        self.assertEqual(key.target_endpoint, target)
        self.assertEqual(key.canonical_route, ("toy;scalar;v1", "toy;wide;v2"))

        # Canonical strings are the ordering contract.  Tuple ordering would
        # put an endpoint with a common architecture prefix in a different
        # position because ';' sorts after '-'.
        prefixed = TranslationKey(
            "module",
            TranslationEndpoint("toy", "wide", "v2"),
            target,
        )
        plain = TranslationKey(
            "module",
            TranslationEndpoint("toy-wide", "scalar", "v1"),
            target,
        )
        self.assertLess(plain, prefixed)

    def test_production_spec_carries_all_paths_and_properties(self):
        spec = TranslationProductionSpec(
            variant_id="module-toy",
            artifact_id="translated-code-module-toy",
            symbol_namespace="module_toy",
            input_properties={"architecture": "toy"},
            output_properties={"architecture": "toy"},
            assembly_path=Path("generated/module.S"),
            translated_dump_path=Path("dump/module.dump"),
            provenance_path=Path("generated/module.provenance.S"),
            library_path=Path("artifacts/module.so"),
            offset_map_assembly_path=Path("generated/module.maps.S"),
            offset_map_document_path=Path("generated/module.maps.json"),
            offset_map_library_path=Path("artifacts/module.maps.so"),
            offset_map_artifact_id="offset-map-module-toy-elf",
        )
        self.assertEqual(spec.library_path, Path("artifacts/module.so"))
        self.assertEqual(spec.input_properties["architecture"], "toy")

        with self.assertRaisesRegex(ValueError, "inside staging"):
            TranslationProductionSpec(
                variant_id="module-toy",
                artifact_id="translated-code-module-toy",
                symbol_namespace="module_toy",
                input_properties={}, output_properties={},
                assembly_path=Path("../outside.S"),
                translated_dump_path=Path("dump/module.dump"),
                provenance_path=Path("generated/module.provenance.S"),
                library_path=Path("artifacts/module.so"),
                offset_map_assembly_path=Path("generated/module.maps.S"),
                offset_map_document_path=Path("generated/module.maps.json"),
                offset_map_library_path=Path("artifacts/module.maps.so"),
                offset_map_artifact_id="offset-map-module-toy-elf",
            )

    def test_translation_step_uses_scene_spec_without_vlen_arguments(self):
        class Semantics:
            def validate_route(self, source, target):
                assert source.architecture == "toy"
                assert target.extension == "wide"

            def production_spec(self, module_id, source, target, _stage):
                return TranslationProductionSpec(
                    variant_id=f"{module_id}-toy",
                    artifact_id=f"translated-{module_id}-toy",
                    symbol_namespace=f"{module_id}_toy",
                    input_properties={"architecture": source.architecture},
                    output_properties={"extension": target.extension},
                    assembly_path=Path("generated/toy.S"),
                    translated_dump_path=Path("dump/toy.dump"),
                    provenance_path=Path("metadata/provenance/toy.S"),
                    library_path=Path("artifacts/toy.so"),
                    offset_map_assembly_path=Path("generated/toy.maps.S"),
                    offset_map_document_path=Path("generated/toy.maps.json"),
                    offset_map_library_path=Path("artifacts/toy.maps.so"),
                    offset_map_artifact_id="offset-toy-elf",
                    suffix="toy",
                )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage = root / "stage"
            (stage / "scalar").mkdir(parents=True)
            session = WorkspaceSession(
                root=root, stage=stage, destination=root / "published"
            )
            source = stage / "scalar" / "app"
            source.write_bytes(b"input")
            session.registry.register_module(ModuleRecord("main", "main", "app", "original", "target", "0" * 64))
            native_dump = stage / "dump" / "main.dump"
            native_dump.parent.mkdir()
            native_dump.write_text("dump\n", encoding="utf-8")

            def run(command, *, stdout_path=None):
                if stdout_path is None:
                    if hasattr(command[-1], "write_text"):
                        command[-1].write_text("label\n", encoding="utf-8")
                else:
                    stdout_path.write_text("translated\n", encoding="utf-8")

            compile_options = []

            def compile_(sources, output, **kwargs):
                compile_options.append(kwargs)
                output.parent.mkdir(parents=True, exist_ok=True)
                output.write_bytes(b"artifact")
                return ("compile",)

            module = AnalysisModule(
                "main", source, source, False, True, DELIVERY_TARGET
            )
            context = AnalysisContext(
                input_elf=source,
                stage=stage,
                config=SimpleNamespace(),
                target_os="toy-os",
                target_arch="toy",
                target_arch_extension="wide",
                runtime_scene="toy-scene",
                runtime_abi=1,
                services=SimpleNamespace(
                    platform=SimpleNamespace(
                        dependencies=lambda _module_path, _library_roots: (),
                        interpreter=lambda _path: None,
                        load_base=lambda _path: 0,
                        load_segments=lambda _path: (),
                        virtual_to_file_offset=lambda _segments, _address: 0,
                        dynamic_search_paths=lambda _path: {},
                        runner=SimpleNamespace(run=run),
                    ),
                    toolchain=SimpleNamespace(
                        artifact_emitter=GnuArtifactEmitter(word_directive=".dword"),
                        translator=SimpleNamespace(command=lambda request: (request.assembly_output,)),
                        compiler=SimpleNamespace(compile=compile_),
                        disassembler=SimpleNamespace(
                            command=lambda _path: ("dump",),
                        ),
                    ),
                ),
                target_bundle=SimpleNamespace(translation_semantics=Semantics()),
            ).put_global("workspace_session", session).put_global(
                "modules", (module,)
            ).put_global("native_dumps", {"main": native_dump})

            updated = TranslationStep(
                source_endpoint=TranslationEndpoint("toy", "scalar", "v1"),
                target_endpoint=TranslationEndpoint("toy", "wide", "v2"),
                translator_path=root / "translator",
            ).run(context)

            key = next(iter(updated.require_global("translations")))
            self.assertEqual(key.canonical_route, ("toy;scalar;v1", "toy;wide;v2"))
            self.assertIn("translated-main-toy", session.registry.artifacts)
            self.assertEqual(compile_options, [{
                "flags": ("-fPIC", "-shared", "-Wl,-Bsymbolic-functions")
            }])


if __name__ == "__main__":
    unittest.main()
