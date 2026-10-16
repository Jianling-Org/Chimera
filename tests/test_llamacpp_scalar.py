from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "examples" / "scripts" / "build" / "install_llamacpp_scalar.py"
SPEC = importlib.util.spec_from_file_location("install_llamacpp_scalar", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class LlamaCppScalarTests(unittest.TestCase):
    def _source(self, root: Path, suffix: str = "one") -> Path:
        source = root / "source"
        source.mkdir()
        for name in MODULE.SCALAR_FILES:
            (source / name).write_bytes(f"{name}:{suffix}".encode())
        return source

    def test_install_writes_all_files_and_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = self._source(root)
            destination = root / "scalar"

            MODULE.install(source, destination)

            for name in MODULE.SCALAR_FILES:
                self.assertEqual(
                    (destination / name).read_bytes(), (source / name).read_bytes()
                )
            manifest = json.loads(
                (destination / ".chimera-llamacpp.json").read_text(encoding="utf-8")
            )
            self.assertEqual(manifest["schema_version"], 1)
            self.assertEqual(set(manifest["files"]), set(MODULE.SCALAR_FILES))

    def test_install_refuses_unmanaged_conflicting_file(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = self._source(root)
            destination = root / "scalar"
            destination.mkdir()
            (destination / "libc.so.6").write_bytes(b"user library")

            with self.assertRaisesRegex(ValueError, "scalar conflict"):
                MODULE.install(source, destination)

    def test_install_updates_only_an_unchanged_managed_file(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = self._source(root, "one")
            destination = root / "scalar"
            MODULE.install(source, destination)
            old_hash = hashlib.sha256((destination / "libc.so.6").read_bytes()).hexdigest()

            for name in MODULE.SCALAR_FILES:
                (source / name).write_bytes(f"{name}:two".encode())
            MODULE.install(source, destination)

            self.assertNotEqual(
                old_hash,
                hashlib.sha256((destination / "libc.so.6").read_bytes()).hexdigest(),
            )

    def test_install_refuses_a_user_modified_managed_file(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = self._source(root)
            destination = root / "scalar"
            MODULE.install(source, destination)
            (destination / "libc.so.6").write_bytes(b"user modification")

            with self.assertRaisesRegex(ValueError, "scalar conflict"):
                MODULE.install(source, destination)


if __name__ == "__main__":
    unittest.main()
