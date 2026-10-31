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
        # Keep real Linux sigaction while simulating the kernel ACK endpoint.
        command = [compiler, "-std=c11", "-Wall", "-Wextra", "-Werror",
                   "-DCHIMERA_SIGNAL_TEST_ACK=1"]
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

    @unittest.skipUnless(sys.platform.startswith("linux"), "requires Linux waitpid")
    def test_policy_notification_restarts_child_wait(self):
        source = Path(self.temporary.name) / "restart-wait.c"
        executable = source.with_suffix("")
        source.write_text(r'''
#define _GNU_SOURCE
#include <assert.h>
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>
#include "chimera_signal.h"
static volatile sig_atomic_t received;
static void notify(int n, siginfo_t *i, void *c) {
    (void)n; (void)i; (void)c; received = 1;
}
int main(void) {
    struct chimera_linux_signal_binding binding = {SIGUSR1, notify};
    assert(chimera_linux_install_signal_bindings(&binding, 1));
    pid_t parent = getpid(), child = fork();
    assert(child >= 0);
    if (!child) {
        usleep(100000); assert(kill(parent, SIGUSR1) == 0);
        usleep(100000); _exit(23);
    }
    int status = 0;
    assert(waitpid(child, &status, 0) == child);
    assert(received && WIFEXITED(status) && WEXITSTATUS(status) == 23);
    return 0;
}
''')
        runtime = ROOT / "runtime"
        subprocess.run([shutil.which("cc"), "-Wall", "-Wextra", "-Werror",
                        "-I" + str(runtime / "interfaces/uapi/linux"),
                        str(source), str(runtime / "interfaces/uapi/linux/chimera_signal.c"),
                        "-o", str(executable)], check=True, timeout=30)
        subprocess.run([str(executable)], check=True, timeout=3)


if __name__ == "__main__":
    unittest.main()
