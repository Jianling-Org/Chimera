"""Streaming parser equivalence: retained vs discarded dump lines."""

from __future__ import annotations

import io
import tempfile
import unittest
from pathlib import Path

from chimera.preprocess.offline.analysis.core.data_model import CompactIntSet
from chimera.preprocess.offline.analysis.core.monitor import monitoring
from chimera.preprocess.offline.analysis.program_model.parser import (
    _memory_fields,
    parse_dump,
)
from chimera.preprocess.offline.analysis.toolchain.objdump import LinuxObjdump


def _format():
    return LinuxObjdump("objdump").parse_format


DUMP = """\

Disassembly of section .text:

0000000000010000 <main>:
    10000:\t7131                \taddi\tsp,sp,-128
    10002:\t00800617            \tauipc\ta2,0x800
    10006:\t8082                \tret

0000000000010008 <helper@plt>:
    10008:\t8082                \tret

000000000001000c <worker>:
    1000c:\t8faa                \tmv\ta5,a0
    1000e:\t9682                \tjalr\ta3
    10010:\t8082                \tret
"""

# Same content but the last line has no trailing newline.
DUMP_NO_FINAL_NEWLINE = DUMP.rstrip("\n")


class ParseDumpEquivalenceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def _write(self, content: str, name: str = "sample.dump") -> Path:
        path = Path(self.tmp.name) / name
        path.write_text(content, encoding="utf-8", newline="")
        return path

    def _parse(self, path: Path, retain: bool):
        return parse_dump(
            path,
            _format(),
            is_external_trampoline=LinuxObjdump.is_external_trampoline,
            retain_dump_lines=retain,
        )

    def _assert_same_model(self, retained, streamed):
        self.assertEqual(
            [(f.name, f.start, f.is_external_trampoline) for f in retained.functions],
            [(f.name, f.start, f.is_external_trampoline) for f in streamed.functions],
        )
        for kept, dropped in zip(retained.functions, streamed.functions):
            self.assertEqual(
                [
                    (i.addr, i.size, i.op, i.args, i.text, i.machine_code,
                     i.operand, i.line_index)
                    for i in kept.insts
                ],
                [
                    (i.addr, i.size, i.op, i.args, i.text, i.machine_code,
                     i.operand, i.line_index)
                    for i in dropped.insts
                ],
            )
        self.assertEqual(
            sorted(retained.instruction_by_address),
            sorted(streamed.instruction_by_address),
        )

    def test_streaming_matches_retained_mode(self):
        path = self._write(DUMP)
        retained = self._parse(path, retain=True)
        streamed = self._parse(path, retain=False)
        self._assert_same_model(retained, streamed)
        self.assertEqual(retained.dump_lines, DUMP.rstrip("\n").split("\n"))
        self.assertEqual(streamed.dump_lines, [])
        # Text and line numbers survive streaming for diagnostics.
        self.assertEqual(streamed.instructions[0].line_index, 4)
        self.assertIn("addi", streamed.instructions[0].text)
        self.assertTrue(streamed.functions[1].is_external_trampoline)


    def test_last_line_without_newline(self):
        path = self._write(DUMP_NO_FINAL_NEWLINE, "nonl.dump")
        retained = self._parse(path, retain=True)
        streamed = self._parse(path, retain=False)
        self._assert_same_model(retained, streamed)
        self.assertEqual(len(streamed.instructions), len(retained.instructions))
        self.assertEqual(streamed.instructions[-1].op, "ret")

    def test_empty_file(self):
        path = self._write("", "empty.dump")
        for retain in (True, False):
            program = self._parse(path, retain=retain)
            self.assertEqual(program.functions, [])
            self.assertEqual(program.instructions, [])
            self.assertEqual(program.dump_lines, [])
            self.assertEqual(program.instruction_by_address, {})

    def test_non_instruction_lines_are_skipped(self):
        path = self._write(DUMP)
        program = self._parse(path, retain=False)
        self.assertEqual([f.name for f in program.functions],
                         ["main", "helper@plt", "worker"])
        # Lines before the first function header must not attach anywhere.
        self.assertEqual(len(program.instructions), 7)

    def test_default_mode_keeps_dump_lines(self):
        path = self._write(DUMP)
        program = parse_dump(path, _format())
        self.assertEqual(program.dump_lines, DUMP.rstrip("\n").split("\n"))

    def test_cfg_fields_use_compact_sets(self):
        path = self._write(DUMP)
        program = self._parse(path, retain=False)
        for instruction in program.instructions:
            self.assertIsInstance(instruction.succ, CompactIntSet)
            self.assertIsInstance(instruction.jump_targets, CompactIntSet)
            self.assertIsInstance(instruction.jump_sources, CompactIntSet)

    def test_debug_progress_events_flush(self):
        stream = io.StringIO()
        import chimera.preprocess.offline.analysis.program_model.parser as parser_module

        path = self._write(DUMP)
        original = parser_module._PROGRESS_EVERY
        parser_module._PROGRESS_EVERY = 2  # force progress emission in tests
        try:
            with monitoring(enabled=True, stream=stream):
                self._parse(path, retain=False)
        finally:
            parser_module._PROGRESS_EVERY = original
        lines = stream.getvalue().strip().splitlines()
        self.assertTrue(lines)
        self.assertTrue(
            all("offline.parse-dump.progress" in line for line in lines)
        )
        self.assertTrue(all("instructions=" in line for line in lines))

    def test_memory_fields_never_raise(self):
        fields = _memory_fields()
        self.assertIsInstance(fields, dict)
        for key, value in fields.items():
            self.assertIn(key, {"vmrss", "vmhwm", "vmswap"})
            self.assertIsInstance(value, int)


if __name__ == "__main__":
    unittest.main()
