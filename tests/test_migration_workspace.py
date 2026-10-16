"""Runtime migration discovers the target process's Workspace before writing control."""

from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from chimera import cli
from chimera.runtime.manifest import ModuleRecord, WorkspaceManifest, write_manifest


class MigrationWorkspaceTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.proc = self.root / "proc"
        self._add_group(100, [100, 101, 102])
        self.workspace = self._workspace(self.root / "workspace with spaces")
        self.environ = self.proc / "100" / "environ"
        self.environ.write_bytes(
            b"PATH=/bin\0CHIMERA_WORKSPACE=" + os.fsencode(self.workspace) + b"\0"
        )
        self.control = self.root / "migration-control"
        self.control.write_text("unchanged\n", encoding="ascii")
        self.settings = SimpleNamespace(
            workspace_root=self.root,
            runtime=SimpleNamespace(ai_thread_control=self.control),
        )

    def _add_group(self, tgid, tids):
        task = self.proc / str(tgid) / "task"
        task.mkdir(parents=True)
        for tid in tids:
            status = self.proc / str(tid) / "status"
            status.parent.mkdir(parents=True, exist_ok=True)
            handlers = (1 << (5 - 1)) | (1 << (41 - 1))
            status.write_text(
                f"Name:\ttest\nTgid:\t{tgid}\n"
                f"SigCgt:\t{handlers:016x}\nSigIgn:\t{0:016x}\nSigBlk:\t{0:016x}\n",
                encoding="ascii",
            )
            (task / str(tid)).mkdir()

    def _signal_status(self, tid, *, caught=0, ignored=0, blocked=0, tgid=100):
        (self.proc / str(tid) / "status").write_text(
            f"Name:\ttest\nTgid:\t{tgid}\n"
            f"SigCgt:\t{caught:016x}\nSigIgn:\t{ignored:016x}\nSigBlk:\t{blocked:016x}\n",
            encoding="ascii",
        )

    def _workspace(self, root, scene="linux_riscv64_rvv_v1"):
        write_manifest(
            WorkspaceManifest(
                runtime_abi=1, target_os="linux", target_arch="riscv64",
                target_arch_extension="rvv", runtime_scene=scene,
                modules=(ModuleRecord("main", "main", "app", "original", "target", "0" * 64),),
                variants=(), variant_properties=(), artifacts=(),
            ),
            root / "artifacts" / "modules.tsv",
        )
        return root.resolve()

    def _invoke(self, options, *, direction="1024-to-256"):
        # Exercise real status/task/environ files, resolving only the /proc
        # root to the fixture. No test writes to a host migration interface.
        def fixture_path(value, *args):
            if value == "/proc":
                return self.proc
            return Path(value, *args)

        out, err = StringIO(), StringIO()
        with (
            mock.patch.object(cli, "Path", side_effect=fixture_path),
            mock.patch.object(cli, "load_user_settings", return_value=self.settings),
            redirect_stdout(out), redirect_stderr(err),
        ):
            try:
                result = cli.main(
                    ["migrate", "--direction", direction, *options],
                    command_group="user", prog="chimera-user",
                )
            except SystemExit as error:
                self.fail(f"migrate rejected its arguments before runtime dispatch: {error}; {err.getvalue()}")
        return result, out.getvalue(), err.getvalue()

    def _parent(self, **kwargs):
        return self._invoke(["--parent-thread", "100", "--migration-count", "1"], **kwargs)

    def _assert_stopped(self, result, message):
        code, _out, error = result
        self.assertEqual(code, 2, error)
        self.assertIn(message, error)
        self.assertEqual(self.control.read_text(encoding="ascii"), "unchanged\n")

    def test_parent_mode_does_not_require_workspace_argument(self):
        result, out, error = self._parent()
        self.assertEqual(result, 0, error)
        self.assertIn("selected_threads=1", out)
        self.assertEqual(self.control.read_text(encoding="ascii"), "-102\n")

    def test_explicit_threads_discover_their_single_thread_group_workspace(self):
        result, out, error = self._invoke(["--threads", "101", "102"])
        self.assertEqual(result, 0, error)
        self.assertIn("selected_threads=2", out)
        self.assertIn("-101 -102", out)

    def test_nonleader_parent_uses_tgid_environment(self):
        (self.proc / "101" / "environ").write_bytes(b"CHIMERA_WORKSPACE=wrong\0")
        result, _out, error = self._invoke([
            "--parent-thread", "101", "--migration-count", "1",
        ])
        self.assertEqual(result, 0, error)
        self.assertEqual(self.control.read_text(encoding="ascii"), "-102\n")

    def test_reverse_direction_uses_the_existing_scene_adapter(self):
        result, _out, error = self._parent(direction="256-to-1024")
        self.assertEqual(result, 0, error)
        self.assertEqual(self.control.read_text(encoding="ascii"), "102\n")

    def test_workspace_environment_does_not_authorize_migration_before_handlers(self):
        self._signal_status(102)
        self._assert_stopped(self._parent(), "not ready")

    def test_partial_signal_installation_is_not_ready(self):
        for caught in (1 << (5 - 1), 1 << (41 - 1)):
            with self.subTest(caught=caught):
                self._signal_status(102, caught=caught)
                self._assert_stopped(self._parent(), "not ready")

    def test_reverse_migration_also_requires_installed_handlers(self):
        self._signal_status(102)
        self._assert_stopped(self._parent(direction="256-to-1024"), "not ready")

    def test_explicit_workspace_cannot_bypass_handler_check(self):
        self._signal_status(101)
        self._assert_stopped(self._invoke([
            "--workspace", str(self.workspace), "--threads", "101",
        ]), "not ready")

    def test_all_selected_threads_are_checked_before_the_first_write(self):
        self._signal_status(102)
        self._assert_stopped(self._invoke(["--threads", "101", "102"]), "not ready")

    def test_blocked_migration_signal_is_not_ready(self):
        self._signal_status(
            102, caught=(1 << (5 - 1)) | (1 << (41 - 1)), blocked=1 << (41 - 1),
        )
        self._assert_stopped(self._parent(), "blocked")

    def test_ignored_signal_cannot_stand_in_for_a_handler(self):
        self._signal_status(102, caught=1 << (5 - 1), ignored=1 << (41 - 1))
        self._assert_stopped(self._parent(), "not ready")

    def test_missing_signal_status_is_not_assumed_ready(self):
        (self.proc / "102" / "status").write_text("Tgid:\t100\n", encoding="ascii")
        self._assert_stopped(self._parent(), "status")

    def test_malformed_signal_status_is_not_assumed_ready(self):
        path = self.proc / "102" / "status"
        path.write_text("Tgid:\t100\nSigCgt:\tnot-hex\nSigIgn:\t0\nSigBlk:\t0\n", encoding="ascii")
        self._assert_stopped(self._parent(), "status")

    def test_duplicate_signal_status_is_not_assumed_ready(self):
        path = self.proc / "102" / "status"
        with path.open("a", encoding="ascii") as stream:
            stream.write("SigCgt:\t0\n")
        self._assert_stopped(self._parent(), "status")

    def test_unreadable_selected_thread_status_stops_before_control_write(self):
        original = Path.read_text

        def unreadable(path, *args, **kwargs):
            if path == self.proc / "102" / "status":
                raise PermissionError("status access denied")
            return original(path, *args, **kwargs)

        with mock.patch.object(Path, "read_text", unreadable):
            self._assert_stopped(self._parent(), "status")

    def test_thread_group_change_stops_before_control_write(self):
        self._signal_status(102, caught=(1 << (5 - 1)) | (1 << (41 - 1)), tgid=200)
        self._assert_stopped(self._parent(), "no longer belongs")

    def test_unicode_thread_name_does_not_hide_valid_signal_status(self):
        path = self.proc / "102" / "status"
        contents = path.read_bytes()
        for name in ("\u7ebf\u7a0b".encode("utf-8"), b"test\xff"):
            with self.subTest(name=name):
                path.write_bytes(contents.replace(b"test", name))
                result, _out, error = self._parent()
                self.assertEqual(result, 0, error)

    def test_disappeared_selected_thread_stops_before_control_write(self):
        (self.proc / "102" / "status").unlink()
        self._assert_stopped(self._parent(), "status")

    def test_explicit_workspace_remains_available_without_target_environment(self):
        self.environ.unlink()
        result, _out, error = self._invoke([
            "--workspace", str(self.workspace), "--threads", "101",
        ])
        self.assertEqual(result, 0, error)
        self.assertEqual(self.control.read_text(encoding="ascii"), "-101\n")

    def test_explicit_workspace_id_is_resolved_as_before(self):
        self.environ.unlink()
        self._workspace(self.root / "demo")
        result, _out, error = self._invoke([
            "--workspace", "demo", "--threads", "101",
        ])
        self.assertEqual(result, 0, error)

    def test_callers_environment_cannot_replace_the_targets_missing_workspace(self):
        self.environ.write_bytes(b"PATH=/bin\0")
        with mock.patch.dict(os.environ, {"CHIMERA_WORKSPACE": str(self.workspace)}):
            self._assert_stopped(self._parent(), "--workspace")

    def test_empty_environment_value_stops_before_control_write(self):
        self.environ.write_bytes(b"CHIMERA_WORKSPACE=\0")
        self._assert_stopped(self._parent(), "--workspace")

    def test_duplicate_environment_values_are_not_guessed(self):
        entry = b"CHIMERA_WORKSPACE=" + os.fsencode(self.workspace) + b"\0"
        self.environ.write_bytes(entry * 2)
        self._assert_stopped(self._parent(), "--workspace")

    def test_relative_environment_path_is_not_resolved_against_the_callers_cwd(self):
        self.environ.write_bytes(b"CHIMERA_WORKSPACE=relative-workspace\0")
        self._assert_stopped(self._parent(), "--workspace")

    def test_missing_process_environment_stops_before_control_write(self):
        self.environ.unlink()
        self._assert_stopped(self._parent(), "--workspace")

    def test_unreadable_process_environment_has_an_explicit_workspace_hint(self):
        original = Path.read_bytes

        def unreadable(path):
            if path == self.environ:
                raise PermissionError("environment access denied")
            return original(path)

        with mock.patch.object(Path, "read_bytes", unreadable):
            self._assert_stopped(self._parent(), "--workspace")

    def test_process_workspace_must_still_exist(self):
        self.environ.write_bytes(b"CHIMERA_WORKSPACE=" + os.fsencode(self.root / "missing") + b"\0")
        self._assert_stopped(self._parent(), "workspace path does not exist")

    def test_malformed_manifest_stops_before_control_write(self):
        (self.workspace / "artifacts" / "modules.tsv").write_text("invalid", encoding="utf-8")
        self._assert_stopped(self._parent(), "Manifest")

    def test_installation_integrity_is_checked_for_discovered_workspace(self):
        (self.workspace / ".workspack-install.json").write_text("{}", encoding="utf-8")
        self._assert_stopped(self._parent(), "marker")

    def test_unknown_scene_has_no_hardcoded_fallback(self):
        other = self._workspace(self.root / "other", scene="other_scene")
        self.environ.write_bytes(b"CHIMERA_WORKSPACE=" + os.fsencode(other) + b"\0")
        self._assert_stopped(self._parent(), "migration is unsupported")

    def test_unknown_route_stops_before_control_write(self):
        self._assert_stopped(self._parent(direction="invalid-route"), "migration route is unsupported")

    def test_cross_group_threads_are_rejected_before_control_write(self):
        self._add_group(200, [200, 201])
        self._assert_stopped(self._invoke(["--threads", "101", "201"]), "one thread group")

    def test_disappeared_parent_stops_before_control_write(self):
        (self.proc / "100" / "status").unlink()
        self._assert_stopped(self._parent(), "thread does not exist")

    @unittest.skipUnless(sys.platform.startswith("linux"), "requires real Linux /proc")
    def test_linux_reads_workspace_from_a_live_process_environment(self):
        # Real /proc lookup, with a temporary control file instead of the
        # kernel migration endpoint: this test cannot migrate a host thread.
        process = subprocess.Popen(
            [sys.executable, "-u", "-c", (
                "import signal, sys; "
                "signal.signal(5, lambda *_: None); "
                "signal.signal(41, lambda *_: None); "
                "print('ready'); sys.stdin.readline()"
            )],
            env={**os.environ, "CHIMERA_WORKSPACE": str(self.workspace)},
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True,
        )
        try:
            self.assertEqual(process.stdout.readline().strip(), "ready")
            with (
                mock.patch.object(cli, "load_user_settings", return_value=self.settings),
                redirect_stdout(StringIO()), redirect_stderr(StringIO()),
            ):
                result = cli.main([
                    "migrate", "--direction", "1024-to-256",
                    "--parent-thread", str(process.pid), "--migration-count", "1",
                ], command_group="user", prog="chimera-user")
            self.assertEqual(result, 0)
            self.assertEqual(self.control.read_text(encoding="ascii"), f"-{process.pid}\n")
        finally:
            if process.poll() is None:
                process.terminate()
            process.communicate(timeout=5)

    @unittest.skipUnless(sys.platform.startswith("linux"), "requires real Linux /proc")
    def test_linux_unready_process_is_not_sent_a_migration_request(self):
        process = subprocess.Popen(
            [sys.executable, "-u", "-c", "import sys; print('started'); sys.stdin.readline()"],
            env={**os.environ, "CHIMERA_WORKSPACE": str(self.workspace)},
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True,
        )
        try:
            self.assertEqual(process.stdout.readline().strip(), "started")
            error = StringIO()
            with (
                mock.patch.object(cli, "load_user_settings", return_value=self.settings),
                redirect_stdout(StringIO()), redirect_stderr(error),
            ):
                result = cli.main([
                    "migrate", "--direction", "1024-to-256",
                    "--parent-thread", str(process.pid), "--migration-count", "1",
                ], command_group="user", prog="chimera-user")
            self._assert_stopped((result, "", error.getvalue()), "not ready")
            self.assertIsNone(process.poll())
        finally:
            if process.poll() is None:
                process.terminate()
            process.communicate(timeout=5)


if __name__ == "__main__":
    unittest.main()
