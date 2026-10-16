from __future__ import annotations

from pathlib import Path
import os
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


class ToolchainSourceInstallTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("cmake"), "cmake is required")
    def test_installed_bundle_matches_toolchain_source_root_layout(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            build = root / "build"
            prefix = root / "prefix"
            configure = [
                "cmake",
                "-S",
                str(ROOT / "runtime"),
                "-B",
                str(build),
                "-DCHIMERA_INSTALL_TOOLCHAIN_SOURCE=ON",
            ]
            if os.name == "nt":
                make = shutil.which("mingw32-make")
                if make is None:
                    self.skipTest("mingw32-make is required on Windows")
                configure.extend(
                    ["-G", "MinGW Makefiles", f"-DCMAKE_MAKE_PROGRAM={make}"]
                )
            subprocess.run(
                configure,
                check=True,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
            subprocess.run(
                ["cmake", "--install", str(build), "--prefix", str(prefix)],
                check=True,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
            )

            bundle = prefix / "chimera" / "toolchain_source"
            self.assertTrue((bundle / "plugins" / "CMakeLists.txt").is_file())
            self.assertTrue(any((bundle / "patches").glob("*.patch")))
            self.assertTrue(any((bundle / "svf-patches").glob("*.patch")))


if __name__ == "__main__":
    unittest.main()
