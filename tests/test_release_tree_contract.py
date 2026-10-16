from __future__ import annotations

from pathlib import Path
import tomllib
import unittest

from chimera.check_elf import safety_binary_check_request


ROOT = Path(__file__).resolve().parents[1]


class ReleaseTreeContractTests(unittest.TestCase):
    def test_publication_has_required_files_and_complete_wheel_package_sources(self) -> None:
        required = (
            "README.md",
            "pyproject.toml",
            "Makefile",
            "cli/chimera/cli.py",
            "preprocessing/offline/config/__init__.py",
            "runtime/CMakeLists.txt",
            "tests/run_tests.py",
            "tools/build_release_wheel.py",
            "examples/applications/hello-world/README.md",
            "doc/README.md",
            "preprocessing/translator/rvv_sbt_tool/rvv_sbt_rvv.py",
            "preprocessing/translator/rvv_sbt_tool/rvv_sbt_rvv1024.py",
            "preprocessing/translator/rvv_sbt_tool/rvv_sbt.py",
            "preprocessing/translator/rvv_sbt_tool/ime_sbt_rvv.py",
            "doc/developer/translator/limitations.md",
        )
        missing = [name for name in required if not (ROOT / name).is_file()]
        self.assertEqual([], missing, "release tree is missing required files")

        with (ROOT / "pyproject.toml").open("rb") as stream:
            project = tomllib.load(stream)
        package_sources = tuple(
            Path(source)
            for source in project["tool"]["scikit-build"]["wheel"]["packages"].values()
        )
        self.assertTrue(package_sources, "wheel package mapping must not be empty")
        missing_sources = [source.as_posix() for source in package_sources if not (ROOT / source).is_dir()]
        self.assertEqual([], missing_sources, "wheel package mapping points outside the publication tree")
        self.assertFalse(
            any(source.as_posix().startswith("preprocessing/translator/") for source in package_sources),
            "translator is supplied in the source checkout, not bundled in the wheel",
        )

    def test_current_safety_check_identity_uses_v31_fingerprint(self) -> None:
        parameters = {"min_vlen_bits": 256, "compiler_metadata": []}
        request = safety_binary_check_request(parameters)
        self.assertEqual(31, request.version)
        changed = safety_binary_check_request({"min_vlen_bits": 128, "compiler_metadata": []})
        self.assertNotEqual(request.identity, changed.identity)


if __name__ == "__main__":
    unittest.main()
