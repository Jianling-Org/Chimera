from __future__ import annotations

from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from chimera.preprocess.offline.analysis.toolchain.artifact_emitter import (
    GnuArtifactEmitter,
)


class ArtifactEmitterTests(unittest.TestCase):
    def test_host_gnu_emitter_accepts_quad_output_and_streams_rows(self) -> None:
        assembler = shutil.which("as")
        if assembler is None:
            self.skipTest("host GNU assembler is unavailable")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "table.S"
            output = root / "table.o"
            rows = ((value,) for value in (1, 0x1234, 0xFFFFFFFFFFFFFFFF))
            GnuArtifactEmitter().emit_u64_table(
                source, (("chimera_toy_table", rows),)
            )
            result = subprocess.run(
                [assembler, str(source), "-o", str(output)],
                capture_output=True,
                text=True,
            )
            exists = output.exists()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(exists)

    def test_translation_provenance_creates_nested_parent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "metadata" / "provenance" / "translation.S"
            GnuArtifactEmitter().emit_translation_provenance(
                output,
                symbol_namespace="main_toy",
                fingerprint="a" * 64,
            )
            text = output.read_text(encoding="utf-8")
        self.assertIn("chimera_main_toy_translated_code_abi_v1", text)
        self.assertIn("chimera_main_toy_translation_fingerprint_" + "a" * 64, text)


if __name__ == "__main__":
    unittest.main()
