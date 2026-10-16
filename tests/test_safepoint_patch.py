from __future__ import annotations

from hashlib import sha256
from dataclasses import replace
from pathlib import Path
import struct
from types import SimpleNamespace
import tempfile
import unittest

from chimera.preprocess.offline.analysis import AnalysisContext
from chimera.preprocess.offline.analysis.core.data_model import (
    DELIVERY_TARGET,
    AnalysisModule,
)
from chimera.preprocess.offline.analysis.core.workspace import WorkspaceSession
from chimera.preprocess.offline.analysis.offsetmap.model import OffsetMapArtifact
from chimera.preprocess.offline.analysis.platform.linux.elf import (
    load_base,
    load_segments,
    virtual_to_file_offset,
)
from chimera.preprocess.offline.analysis.safety.classifier import (
    SafetyAnalysisResult,
    SafetyRecord,
)
from chimera.preprocess.offline.analysis.safety.result import SafetyPipelineResult
from chimera.preprocess.offline.analysis.safepoint_patch import (
    PatchSafepointsStep,
    check_unpatched_productions,
)
from chimera.preprocess.offline.analysis.translation.model import (
    TranslatedModule,
    TranslationKey,
)
from chimera.preprocess.offline.analysis_profile.target import (
    RvvTrapPatchServices,
    RvvTranslationSemantics,
)
from chimera.preprocess.offline.config import TranslationEndpoint
from chimera.runtime.manifest import ArtifactRecord

TEXT_FILE_OFFSET = 0x1000
TEXT_VADDR = 0x10000
TEXT_SIZE = 0x100


def build_elf(code: bytes) -> bytes:
    """Minimal ELF64 LE with one executable PT_LOAD covering `code`."""

    header = bytearray(64)
    header[:4] = b"\x7fELF"
    header[4] = 2  # ELFCLASS64
    header[5] = 1  # little-endian
    header[6] = 1  # version
    struct.pack_into("<HHI", header, 16, 3, 243, 1)  # DYN, RISC-V, version
    struct.pack_into("<Q", header, 32, 64)  # e_phoff
    struct.pack_into("<HHH", header, 52, 64, 56, 1)  # ehsize, phentsize, phnum
    program = struct.pack(
        "<IIQQQQQQ",
        1,  # PT_LOAD
        5,  # R+X
        TEXT_FILE_OFFSET,
        TEXT_VADDR,
        TEXT_VADDR,
        TEXT_SIZE,
        TEXT_SIZE,
        0x1000,
    )
    image = bytes(header) + program
    image += b"\0" * (TEXT_FILE_OFFSET - len(image))
    assert len(code) <= TEXT_SIZE
    return image + code + b"\0" * (TEXT_SIZE - len(code))


class PatchSafepointsTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.stage = self.root / "stage"
        (self.stage / "artifacts").mkdir(parents=True)
        (self.stage / "scalar").mkdir()
        self.session = WorkspaceSession(
            root=self.root,
            stage=self.stage,
            destination=self.root / "published",
        )
        # code slot 0: 4-byte nop; slot 4: 2-byte c.nop; slot 6: 4-byte nop
        code = struct.pack("<IHI", 0x00000013, 0x0001, 0x00000013)
        self.library = (
            self.stage / "artifacts" / "libtranslated_main_vlen1024_to_vlen256.so"
        )
        self.library.write_bytes(build_elf(code))
        self.main_local = self.stage / "scalar" / "app"
        self.main_local.write_bytes(build_elf(code))
        source = TranslationEndpoint("riscv64", "rvv", "vlen=1024")
        target = TranslationEndpoint("riscv64", "rvv", "vlen=256")
        self.spec = RvvTranslationSemantics().production_spec(
            "main", source, target, self.stage
        )
        self.unpatched_library = self.stage / self.spec.unpatched_library_path
        self.unpatched_library.parent.mkdir(parents=True, exist_ok=True)
        self.unpatched_library.write_bytes(self.library.read_bytes())
        self.unpatched_checksum = self.stage / self.spec.unpatched_library_sha256_path
        self.unpatched_checksum.write_text(
            sha256(self.unpatched_library.read_bytes()).hexdigest() + "\n",
            encoding="ascii",
        )
        self.key = TranslationKey("main", source, target)

    def _context(self) -> AnalysisContext:
        services = SimpleNamespace(
            platform=SimpleNamespace(
                dependencies=lambda _module_path, _library_roots: (),
                interpreter=lambda _path: None,
                load_base=load_base,
                load_segments=load_segments,
                virtual_to_file_offset=virtual_to_file_offset,
                dynamic_search_paths=lambda _path: {},
            ),
        )
        original_base = TEXT_VADDR
        records = {
            original_base + 0x10: SafetyRecord(
                original_base + 0x10, True, frozenset(), frozenset()
            ),
            original_base + 0x20: SafetyRecord(
                original_base + 0x20, True, frozenset(), frozenset()
            ),
            original_base + 0x30: SafetyRecord(
                original_base + 0x30, False, frozenset(), frozenset()
            ),
            # safe but absent from the offset-map: tolerated, not patched
            original_base + 0x40: SafetyRecord(
                original_base + 0x40, True, frozenset(), frozenset()
            ),
        }
        safety = SafetyPipelineResult(
            module_id="main",
            vector_configs=None,
            vector_liveness=None,
            stack_liveness=None,
            safety=SafetyAnalysisResult(records=records, vector=None, stack=None),
            warnings=(),
        )
        translated = TranslatedModule(
            key=self.key,
            assembly=self.stage / "generated" / "main.translated.S",
            library=self.library,
            native_dump=self.stage / "dump" / "main.dump",
            translated_dump=self.stage / "dump" / "main.translated.dump",
            symbol_namespace="main",
            fingerprint="",
            spec=self.spec,
        )
        offset_map = OffsetMapArtifact(
            key=self.key,
            mapping={0x10: 0x0, 0x20: 0x4, 0x30: 0x6},
            assembly=self.stage / "generated" / "main.maps.S",
            document=self.stage / "generated" / "main.maps.json",
            library=self.stage / "artifacts" / "liboffsetmap_main.so",
            original_base=original_base,
        )
        module = AnalysisModule(
            module_id="main",
            source=self.main_local,
            selected_path=self.main_local,
            is_scalar=False,
            is_main=True,
            delivery=DELIVERY_TARGET,
        )
        return AnalysisContext(
            input_elf=self.main_local,
            stage=self.stage,
            config=SimpleNamespace(),
            target_os="linux",
            target_arch="riscv64",
            target_arch_extension="rvv",
            runtime_scene="linux_riscv64_rvv_v1",
            runtime_abi=1,
            services=services,
            target_bundle=SimpleNamespace(
                trap_patch_services=RvvTrapPatchServices()
            ),
        ).put_global(
            "workspace_session", self.session
        ).put_global(
            "modules", (module,)
        ).put_global(
            "safety_analysis", safety
        ).put_global(
            "translations", {self.key: translated}
        ).put_global(
            "offset_maps", {self.key: offset_map}
        )

    def test_safe_slots_become_ebreak_and_artifact_hash_is_refreshed(self) -> None:
        content = self.library.read_bytes()
        self.session.registry.register_artifact(ArtifactRecord(
            "translated-code-main-vlen1024-to-vlen256",
            "variant", "main_vlen1024_to_vlen256", "translated-code", "elf", 1,
            frozenset({"runtime"}),
            "artifacts/libtranslated_main_vlen1024_to_vlen256.so",
            sha256(content).hexdigest(),
        ))

        updated = PatchSafepointsStep().run(self._context())

        patched = self.library.read_bytes()
        self.assertEqual(
            struct.unpack_from("<I", patched, TEXT_FILE_OFFSET)[0], 0x00100073
        )
        self.assertEqual(
            struct.unpack_from("<H", patched, TEXT_FILE_OFFSET + 4)[0], 0x9002
        )
        # unsafe slot (translated rva 0x6) stays untouched
        self.assertEqual(
            struct.unpack_from("<I", patched, TEXT_FILE_OFFSET + 6)[0], 0x00000013
        )
        self.assertEqual(
            updated.require_global("patched_safepoints"), {self.key: 2}
        )
        record = self.session.registry.artifacts[
            "translated-code-main-vlen1024-to-vlen256"
        ]
        self.assertEqual(record.sha256, sha256(patched).hexdigest())
        self.assertEqual(record.required_by, frozenset({"runtime"}))

    def test_repatch_is_idempotent(self) -> None:
        step = PatchSafepointsStep()
        first = step.run(self._context()).require_global("patched_safepoints")
        image = self.library.read_bytes()

        second = step.run(self._context()).require_global("patched_safepoints")

        self.assertEqual(first, second)
        self.assertEqual(self.library.read_bytes(), image)

    def test_missing_unpatched_copy_is_rejected_without_touching_library(self) -> None:
        self.unpatched_library.unlink()
        before = self.library.read_bytes()
        with self.assertRaises(FileNotFoundError):
            PatchSafepointsStep().run(self._context())
        self.assertEqual(self.library.read_bytes(), before)

    def test_unpatched_copy_preflight_selects_only_missing_translation(self) -> None:
        planned = SimpleNamespace(
            name="translate",
            identifier="007:translate",
            parameters={"source": self.key.source_endpoint, "target": self.key.target_endpoint},
        )
        inspection = SimpleNamespace(
            stage=self.stage,
        )
        def iter_productions(_inspection):
            yield planned.identifier, RvvTranslationSemantics().production_spec(
                "main", planned.parameters["source"], planned.parameters["target"],
                self.stage,
            )
        self.unpatched_library.unlink()
        self.assertEqual(
            check_unpatched_productions(inspection, iter_productions),
            frozenset({"007:translate"}),
        )
        self.unpatched_library.write_bytes(self.library.read_bytes())
        self.assertEqual(
            check_unpatched_productions(inspection, iter_productions), frozenset()
        )

    def test_unpatched_checker_accepts_custom_producer_identifier_and_spec(self) -> None:
        raw = self.stage / "generated" / "custom" / "raw.so"
        checksum = raw.with_suffix(raw.suffix + ".sha256")
        raw.parent.mkdir(parents=True, exist_ok=True)
        raw.write_bytes(b"custom producer")
        checksum.write_text(sha256(raw.read_bytes()).hexdigest() + "\n", encoding="ascii")
        spec = SimpleNamespace(
            unpatched_library_path=raw.relative_to(self.stage),
            unpatched_library_sha256_path=checksum.relative_to(self.stage),
        )
        inspection = SimpleNamespace(stage=self.stage)

        def iter_productions(_inspection):
            yield "009:custom-producer", spec

        self.assertEqual(check_unpatched_productions(inspection, iter_productions), frozenset())
        checksum.write_text("0" * 64 + "\n", encoding="ascii")
        self.assertEqual(
            check_unpatched_productions(inspection, iter_productions),
            frozenset({"009:custom-producer"}),
        )

    def test_other_module_variants_are_not_patched(self) -> None:
        dep_source = TranslationEndpoint("riscv64", "rvv", "vlen=1024")
        dep_target = TranslationEndpoint("riscv64", "rvv", "vlen=256")
        dep_spec = RvvTranslationSemantics().production_spec(
            "dep", dep_source, dep_target, self.stage
        )
        dep_key = TranslationKey("dep", dep_source, dep_target)
        dep_library = (
            self.stage / "artifacts" / "libtranslated_dep_vlen1024_to_vlen256.so"
        )
        dep_library.write_bytes(build_elf(struct.pack("<I", 0x00000013)))
        context = self._context()
        translations = dict(context.require_global("translations"))
        translations[dep_key] = TranslatedModule(
            key=dep_key,
            assembly=self.stage / "generated" / "dep.translated.S",
            library=dep_library,
            native_dump=self.stage / "dump" / "dep.dump",
            translated_dump=self.stage / "dump" / "dep.translated.dump",
            symbol_namespace="dep",
            fingerprint="",
            spec=dep_spec,
        )
        offset_maps = dict(context.require_global("offset_maps"))
        offset_maps[dep_key] = OffsetMapArtifact(
            key=dep_key,
            mapping={0x10: 0x0},
            assembly=self.stage / "generated" / "dep.maps.S",
            document=self.stage / "generated" / "dep.maps.json",
            library=self.stage / "artifacts" / "liboffsetmap_dep.so",
            original_base=TEXT_VADDR,
        )
        context = context.put_global("translations", translations).put_global(
            "offset_maps", offset_maps
        )

        updated = PatchSafepointsStep().run(context)

        self.assertEqual(
            struct.unpack_from("<I", dep_library.read_bytes(), TEXT_FILE_OFFSET)[0],
            0x00000013,
        )
        self.assertEqual(
            updated.require_global("patched_safepoints"), {self.key: 2}
        )

    def test_trap_patch_must_preserve_reported_slot_width(self) -> None:
        class BadTrap:
            max_instruction_bytes = 4

            @staticmethod
            def trap_for_instruction(_instruction_bytes):
                return 4, b"\x02\x90"

        context = self._context()
        context = replace(
            context, target_bundle=SimpleNamespace(trap_patch_services=BadTrap())
        )
        before = self.library.read_bytes()
        with self.assertRaisesRegex(ValueError, "length does not match"):
            PatchSafepointsStep().run(context)
        self.assertEqual(self.library.read_bytes(), before)

    def test_generic_step_uses_scene_trap_encoding_without_rvv_assumptions(self) -> None:
        class ToyTrap:
            max_instruction_bytes = 4

            @staticmethod
            def trap_for_instruction(instruction_bytes):
                if len(instruction_bytes) < 2:
                    raise ValueError("truncated toy instruction")
                return 2, b"\xce\xfa"

        context = replace(
            self._context(),
            target_bundle=SimpleNamespace(trap_patch_services=ToyTrap()),
        )
        before = self.library.read_bytes()

        PatchSafepointsStep().run(context)

        patched = self.library.read_bytes()
        self.assertEqual(patched[TEXT_FILE_OFFSET:TEXT_FILE_OFFSET + 2], b"\xce\xfa")
        self.assertEqual(
            patched[TEXT_FILE_OFFSET + 4:TEXT_FILE_OFFSET + 6], b"\xce\xfa"
        )
        # The generic step did not infer a RISC-V instruction width or encode
        # an ebreak; it used the scene-provided two-byte trap and preserved
        # the remaining bytes in each original slot.
        self.assertNotEqual(patched, before)

    def test_generic_patch_accepts_target_defined_one_and_eight_byte_slots(self) -> None:
        class OneByteTrap:
            max_instruction_bytes = 1

            @staticmethod
            def trap_for_instruction(_instruction_bytes):
                return 1, b"\x7f"

        class EightByteTrap:
            max_instruction_bytes = 8

            @staticmethod
            def trap_for_instruction(_instruction_bytes):
                return 8, b"\x8e" * 8

        platform = SimpleNamespace(
            load_base=load_base,
            load_segments=load_segments,
            virtual_to_file_offset=virtual_to_file_offset,
            dynamic_search_paths=lambda _path: {},
        )
        for trap, expected in ((OneByteTrap(), b"\x7f"), (EightByteTrap(), b"\x8e" * 8)):
            with self.subTest(width=len(expected)):
                library = self.stage / f"artifacts/{len(expected)}.so"
                library.write_bytes(build_elf(b"\0" * 16))
                context = SimpleNamespace(platform=platform)
                self.assertEqual(
                    PatchSafepointsStep._patch_library(
                        context, library, [0], trap
                    ),
                    1,
                )
                self.assertEqual(
                    library.read_bytes()[TEXT_FILE_OFFSET:TEXT_FILE_OFFSET + len(expected)],
                    expected,
                )

    def test_patch_rejects_offset_before_the_containing_segment(self) -> None:
        class OneByteTrap:
            max_instruction_bytes = 1

            @staticmethod
            def trap_for_instruction(_instruction_bytes):
                return 1, b"\x7f"

        platform = SimpleNamespace(
            load_base=load_base,
            load_segments=load_segments,
            virtual_to_file_offset=lambda _segments, _address: 0,
            dynamic_search_paths=lambda _path: {},
        )
        with self.assertRaisesRegex(ValueError, "outside the image"):
            PatchSafepointsStep._patch_library(
                SimpleNamespace(platform=platform), self.library, [0], OneByteTrap()
            )

    def test_rvv_rejects_truncated_and_long_instruction_slots(self) -> None:
        trap = RvvTrapPatchServices()
        with self.assertRaisesRegex(ValueError, "truncated"):
            trap.trap_for_instruction(b"\x03\x00")
        with self.assertRaisesRegex(ValueError, "long instructions"):
            trap.trap_for_instruction(b"\x1f\x00\x00\x00")


if __name__ == "__main__":
    unittest.main()
