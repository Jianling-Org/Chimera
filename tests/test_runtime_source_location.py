from __future__ import annotations

from pathlib import Path
import tempfile
import unittest
from unittest import mock

from chimera.preprocess.offline.analysis.build_runtime import source


class RuntimeSourceRootTests(unittest.TestCase):
    def test_editable_checkout_runtime_is_used(self) -> None:
        # An editable install exposes the repository root through the package
        # finder, so runtime/ (with CMakeLists.txt) is directly reachable.
        with tempfile.TemporaryDirectory() as temporary:
            runtime = Path(temporary) / "runtime"
            runtime.mkdir()
            (runtime / "CMakeLists.txt").write_text("# cmake\n", encoding="utf-8")
            with mock.patch.object(
                source.importlib.resources, "files", return_value=Path(temporary)
            ):
                self.assertEqual(source.runtime_source_root(), runtime)

    def test_bundled_wheel_runtime_source_is_used(self) -> None:
        # A built wheel ships the CMake install tree under runtime_source/.
        with tempfile.TemporaryDirectory() as temporary:
            bundled = Path(temporary) / "runtime_source"
            bundled.mkdir()
            (bundled / "CMakeLists.txt").write_text("# cmake\n", encoding="utf-8")
            with mock.patch.object(
                source.importlib.resources, "files", return_value=Path(temporary)
            ):
                self.assertEqual(source.runtime_source_root(), bundled)

    def test_missing_everywhere_raises(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            with mock.patch.object(
                source.importlib.resources, "files", return_value=Path(temporary)
            ):
                with self.assertRaisesRegex(
                    FileNotFoundError, "runtime source bundle is not installed"
                ):
                    source.runtime_source_root()


if __name__ == "__main__":
    unittest.main()
