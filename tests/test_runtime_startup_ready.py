"""The launch PID is announced by Runtime after successful initialization."""

from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from chimera import cli
from chimera.runtime.preload import runtime_environment


ROOT = Path(__file__).resolve().parents[1]


class LaunchReadyNotificationTests(unittest.TestCase):
    def test_run_does_not_announce_a_pid_before_launch(self):
        output, errors = StringIO(), StringIO()
        with (
            mock.patch.object(cli, "load_user_settings", return_value=SimpleNamespace()),
            mock.patch.object(cli, "_workspace", return_value=Path("workspace")),
            mock.patch.object(cli, "verify_workspace_installation"),
            mock.patch.object(cli, "launch", side_effect=RuntimeError("launch failed")),
            redirect_stdout(output), redirect_stderr(errors),
        ):
            result = cli.main(
                ["run", "--input", "application", "--workspace", "workspace"],
                command_group="user", prog="chimera-user",
            )
        self.assertEqual(result, 2)
        self.assertIn("launch failed", errors.getvalue())
        self.assertNotIn("parent_thread_id=", output.getvalue())

    def test_launch_marks_only_its_own_process_for_the_ready_notification(self):
        artifact = SimpleNamespace(
            owner_kind="workspace", owner_id="root", capability="runtime",
            representation="elf", path="artifacts/runtime/libchimera_inject.so",
        )
        manifest = SimpleNamespace(artifacts=(artifact,))
        with (
            mock.patch.dict(os.environ, {"CHIMERA_LAUNCH_PID": "inherited-pid"}),
            mock.patch("chimera.runtime.preload.environment.os.getpid", return_value=12345),
        ):
            environment = runtime_environment(Path("workspace"), manifest)
        self.assertEqual(environment["CHIMERA_LAUNCH_PID"], "12345")


@unittest.skipUnless(sys.platform.startswith("linux"), "requires Linux constructors and exec")
class NativeRuntimeReadyNotificationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        compiler = shutil.which("cc")
        if compiler is None:
            raise unittest.SkipTest("a native C compiler is required")
        cls.temporary = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.executable = Path(cls.temporary.name) / "runtime-ready-application"
        subprocess.run(
            [compiler, "-std=c11", "-Wall", "-Wextra", "-Werror",
             "-I", str(ROOT / "runtime/runtime/migration/linux_riscv64_rvv_v1"),
             str(ROOT / "runtime/runtime/inject/inject.c"),
             str(ROOT / "runtime/tests/runtime/fixtures/runtime_ready_application.c"),
             "-o", str(cls.executable)],
            check=True, capture_output=True, text=True,
        )

    def run_application(self, *, success=True, launch_pid="self", child=False):
        environment = dict(os.environ)
        environment.pop("LD_PRELOAD", None)
        environment.pop("CHIMERA_LAUNCH_PID", None)
        environment["CHIMERA_WORKSPACE"] = "test-workspace"
        environment["CHIMERA_TEST_INIT_RESULT"] = "1" if success else "0"
        if launch_pid == "self":
            prefix = ["/bin/sh", "-c", 'export CHIMERA_LAUNCH_PID=$$; exec "$@"', "ready-test"]
        else:
            prefix = []
            if launch_pid is not None:
                environment["CHIMERA_LAUNCH_PID"] = launch_pid
        return subprocess.run(
            [*prefix, str(self.executable), *(("exec-child",) if child else ())],
            env=environment, capture_output=True, text=True, check=True, timeout=10,
        ).stdout.splitlines()

    def test_success_announces_after_handlers_and_before_application(self):
        lines = self.run_application()
        self.assertEqual(lines[:2], ["runtime-initializing", "handlers-installed"])
        self.assertRegex(lines[2], r"^parent_thread_id=[1-9][0-9]*$")
        self.assertEqual(lines[3:], ["application-started"])

    def test_initialization_failure_does_not_announce_ready(self):
        lines = self.run_application(success=False)
        self.assertEqual(lines, ["runtime-initializing", "application-started"])

    def test_unmarked_direct_launch_does_not_announce_a_parent(self):
        lines = self.run_application(launch_pid=None)
        self.assertFalse(any(line.startswith("parent_thread_id=") for line in lines))

    def test_stale_or_invalid_launch_marker_does_not_announce_a_parent(self):
        for marker in ("1", "", "not-a-pid", "-1", "999999999999999999999999"):
            with self.subTest(marker=marker):
                lines = self.run_application(launch_pid=marker)
                self.assertFalse(any(line.startswith("parent_thread_id=") for line in lines))

    def test_exec_child_does_not_replace_the_launch_parent_notification(self):
        lines = self.run_application(child=True)
        announcements = [line for line in lines if re.match(r"parent_thread_id=", line)]
        self.assertEqual(len(announcements), 1)
        self.assertEqual(lines.count("handlers-installed"), 2)
        self.assertEqual(lines.count("application-started"), 2)


if __name__ == "__main__":
    unittest.main()
