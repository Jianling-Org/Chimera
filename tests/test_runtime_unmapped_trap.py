"""An exit trap without a reverse map must terminate instead of re-trapping."""

from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


class NativeUnmappedTrapTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        compiler = shutil.which("cc") or shutil.which("gcc")
        if compiler is None:
            raise unittest.SkipTest("a native C compiler is required")
        cls.temporary = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.executable = Path(cls.temporary.name) / (
            "signal-contract.exe" if sys.platform == "win32" else "signal-contract"
        )
        runtime = ROOT / "runtime"
        includes = (
            "interfaces/abi", "interfaces/abi/linux_riscv64_rvv_v1",
            "interfaces/uapi/linux", "runtime/mapping",
            "runtime/migration/linux_riscv64_rvv_v1",
            "runtime/state/linux_riscv64_rvv_v1",
        )
        sources = (
            "tests/runtime/test_chimera_signal.c",
            "interfaces/uapi/linux/chimera_signal.c",
            "runtime/migration/linux_riscv64_rvv_v1/signal_handlers.c",
        )
        command = [compiler, "-std=c11", "-Wall", "-Wextra", "-Werror"]
        if not sys.platform.startswith("linux"):
            command.append("-DCHIMERA_PORTABLE_SIGNAL_TEST=1")
        for include in includes:
            command.extend(("-I", str(runtime / include)))
        command.extend(str(runtime / source) for source in sources)
        command.extend(("-o", str(cls.executable)))
        subprocess.run(command, check=True, capture_output=True, text=True, timeout=30)

    def run_contract(self, *arguments):
        return subprocess.run(
            [str(self.executable), *arguments],
            capture_output=True, text=True, timeout=3,
        )

    def assert_unmapped_exit(self, result):
        self.assertEqual(result.returncode, 133, result.stderr)
        self.assertEqual(result.stdout, "")
        self.assertEqual(
            result.stderr,
            "chimera: exit trap has no reverse offset-map entry; "
            "pc=0x00000000000050f0; execution stopped\n",
        )

    def test_unmapped_exit_does_not_return_to_the_trap(self):
        self.assert_unmapped_exit(self.run_contract("--unmapped-exit"))

    @unittest.skipUnless(sys.platform.startswith("linux"), "requires Linux sigaction")
    def test_installed_sigtrap_handler_stops_on_missing_reverse_map(self):
        self.assert_unmapped_exit(self.run_contract("--unmapped-trap"))

    def test_mapped_exit_and_migration_contracts_still_pass(self):
        result = self.run_contract()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("exit trap has no reverse offset-map entry", result.stderr)


if __name__ == "__main__":
    unittest.main()
