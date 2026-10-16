"""check-elf objdump streaming: failure reporting and temp-file cleanup."""

from __future__ import annotations

import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from chimera.check_elf import collect_diagnostics
from chimera.preprocess.offline.analysis.safety.stack_liveness import (
    ChimeraMetadata,
)

ELF_STUB_BYTES = b"\x7fELF\x02\x01\x01" + b"\x00" * 24


def _temp_dir_listing(directory: Path) -> set[str]:
    return {entry.name for entry in directory.iterdir()}


class ObjdumpFailureTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.elf = self.root / "app.elf"
        self.elf.write_bytes(ELF_STUB_BYTES)

    def _fake_objdump_script(self, body: str) -> Path:
        """Write a fake 'objdump' executable usable on the current OS."""

        if os.name == "nt":
            script = self.root / "fake_objdump.cmd"
            script.write_text(body, encoding="utf-8")
            return script
        script = self.root / "fake_objdump.sh"
        script.write_text(body, encoding="utf-8", newline="\n")
        script.chmod(script.stat().st_mode | stat.S_IXUSR)
        return script

    def test_failure_reports_bounded_stderr_and_cleans_temp_files(self):
        long_error = "E" * 5000
        if os.name == "nt":
            body = f"@echo off\r\n1>&2 echo {long_error}\r\nexit /b 3\r\n"
        else:
            body = f"#!/bin/sh\necho {long_error} 1>&2\nexit 3\n"
        script = self._fake_objdump_script(body)

        temp_root = self.root / "temp"
        temp_root.mkdir()
        before = _temp_dir_listing(temp_root)
        with mock.patch.dict(os.environ, {"TMPDIR": str(temp_root)}), \
                mock.patch.object(tempfile, "tempdir", str(temp_root)):
            with self.assertRaises(RuntimeError) as raised:
                collect_diagnostics(
                    self.elf,
                    objdump_cmd=str(script),
                    metadata=None,
                )
        message = str(raised.exception)
        self.assertIn("disassembly failed", message)
        # Only a bounded prefix of stderr is embedded in the error text.
        self.assertLessEqual(len(message.split(": ", 1)[-1]), 400)
        self.assertEqual(_temp_dir_listing(temp_root), before)

    def test_interrupt_cleans_temp_files(self):
        dump_text = (
            "0000000000010000 <f>:\n"
            "    10000:\t8082                \tret\n"
        )

        def fake_run(*args, **kwargs):
            raise KeyboardInterrupt()

        temp_root = self.root / "temp"
        temp_root.mkdir()
        before = _temp_dir_listing(temp_root)
        with mock.patch.dict(os.environ, {"TMPDIR": str(temp_root)}), \
                mock.patch.object(tempfile, "tempdir", str(temp_root)), \
                mock.patch("subprocess.run", side_effect=fake_run):
            with self.assertRaises(KeyboardInterrupt):
                collect_diagnostics(self.elf, objdump_cmd="objdump")
        self.assertEqual(_temp_dir_listing(temp_root), before)
        self.assertTrue(dump_text)  # keep the fixture referenced

    def test_success_streams_through_temp_file(self):
        if os.name == "nt":
            body = (
                "@echo off\r\n"
                "echo 0000000000010000 ^<f^>:\r\n"
                "echo     10000:\t8082                \tret\r\n"
            )
        else:
            body = (
                "#!/bin/sh\n"
                "printf '%s\\n' '0000000000010000 <f>:'\n"
                "printf '%s\\n' '    10000:\t8082                \tret'\n"
            )
        script = self._fake_objdump_script(body)
        temp_root = self.root / "temp"
        temp_root.mkdir()
        before = _temp_dir_listing(temp_root)
        with mock.patch.dict(os.environ, {"TMPDIR": str(temp_root)}), \
                mock.patch.object(tempfile, "tempdir", str(temp_root)):
            result = collect_diagnostics(
                self.elf,
                objdump_cmd=str(script),
                strategy="gate",
                metadata=ChimeraMetadata.empty(),
            )
        self.assertEqual(result.findings, ())
        self.assertEqual(_temp_dir_listing(temp_root), before)

    def test_debug_events_emit_stage_markers(self):
        from io import StringIO

        from chimera.preprocess.offline.analysis.core.monitor import monitoring

        stream = StringIO()
        with monitoring(enabled=True, stream=stream):
            collect_diagnostics(
                self.elf,
                objdump_cmd="objdump",
                strategy="gate",
                dump_text=(
                    "0000000000010000 <f>:\n"
                    "    10000:\t8082                \tret\n"
                ),
                metadata=ChimeraMetadata.empty(),
            )
        output = stream.getvalue()
        self.assertIn("offline.check-elf.parse.start", output)
        self.assertIn("offline.check-elf.parse.finish", output)
        self.assertIn("offline.check-elf.cfg-build.start", output)
        self.assertIn("offline.check-elf.cfg-build.finish", output)
        # dump_text seam skips objdump, so no disassemble events.
        self.assertNotIn("offline.check-elf.disassemble.start", output)

    def test_no_debug_output_when_disabled(self):
        from io import StringIO

        from chimera.preprocess.offline.analysis.core.monitor import monitoring

        stream = StringIO()
        with monitoring(enabled=False, stream=stream):
            collect_diagnostics(
                self.elf,
                objdump_cmd="objdump",
                strategy="gate",
                dump_text=(
                    "0000000000010000 <f>:\n"
                    "    10000:\t8082                \tret\n"
                ),
                metadata=ChimeraMetadata.empty(),
            )
        self.assertEqual(stream.getvalue(), "")


if __name__ == "__main__":
    unittest.main()
