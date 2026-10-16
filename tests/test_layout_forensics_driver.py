"""Behaviour tests for the K3 forensics driver.

These run the *real* driver code (``layout_forensics_driver.run_trace``) on a
small real disassembly fixture.  They must not only grep the shell script
text.  The two known field overheads are pinned here:

1. no log line may expand a ``Program``/``Function``/instruction/edge graph;
2. one forensics run loads the Program, builds the CFG and resolves call
   edges exactly once.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from contextlib import contextmanager
from unittest import mock

import layout_forensics_driver
import layout_propagation_trace
import xgcc_stack_fixture as fixture

from chimera.preprocess.offline.analysis.core.data_model import Function
from chimera.preprocess.offline.analysis.safety.stack_liveness.model import (
    ChimeraMetadata,
)

LAYOUT = fixture.FIXED_FRAME_FUNCTIONS[2]
LAYOUT_START = 0x50418
SHA = "ee" * 32

# Minimal real objdump text: three functions, two real calls.
SMALL_DUMP = r"""
0000000000001000 <src>:
    1000:	34d000ef          	jal	2000 <mid>
    1004:	00008067          	ret
0000000000002000 <mid>:
    2000:	34d000ef          	jal	8000 <host>
    2004:	00008067          	ret
0000000000008000 <host>:
    8000:	00008067          	ret
"""


def _document(digest: str) -> dict:
    return {
        "format": "chimera-inheritance-diagnostics-v2",
        "elf": {"path": "/x/x", "content_sha256": digest},
        "seed_edges": [
            {
                "caller_function_ref": 0,
                "call_site": "0x1000",
                "reason": "seed",
                "depth": 1,
                "local_active_objects": [{"id": "irreducible:1000"}],
            }
        ],
    }


class DriverTestCase(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.out = self.root / "out"
        self.out.mkdir()

    def _inheritance(self, digest: str = SHA) -> Path:
        path = self.root / "inheritance.json"
        path.write_text(json.dumps(_document(digest)), encoding="utf-8")
        return path

    def _run(self, **kwargs):
        base = dict(
            elf=None,
            out=self.out,
            site=0x8000,
            layout_symbol="src",
            inheritance=str(self._inheritance()),
            dump_text=SMALL_DUMP,
            metadata=ChimeraMetadata.empty(),
            expected_sha256=SHA,
        )
        base.update(kwargs)
        return layout_forensics_driver.run_trace(**base)


class BoundedLoggingTests(DriverTestCase):
    """A Function repr sentinel must never fire during the driver run."""

    def test_summary_output_does_not_expand_the_object_graph(self) -> None:
        original = Function.__repr__

        def _forbidden(self):
            raise AssertionError("object-graph repr must not run in forensics logging")

        Function.__repr__ = _forbidden  # type: ignore[method-assign]
        try:
            payload = self._run()
        finally:
            Function.__repr__ = original  # type: ignore[method-assign]

        self.assertIn("g2_filled", payload)
        log_text = (self.out / "smallest-site-trace.log").read_text(encoding="utf-8")
        self.assertIn("insts=", log_text)
        self.assertNotIn("Instruction(", log_text)
        self.assertNotIn("BasicBlock(", log_text)
        self.assertNotIn("functions=[", log_text)


class ParseOnceTests(DriverTestCase):
    """One run must load the Program and resolve call edges exactly once."""

    def test_load_cfg_and_edge_resolution_run_once(self) -> None:
        counts = {"load": 0, "resolve": 0}
        real_load = layout_propagation_trace.load_production_program
        real_resolve = layout_propagation_trace.resolved_call_edges

        def counting_load(*args, **kwargs):
            counts["load"] += 1
            return real_load(*args, **kwargs)

        def counting_resolve(*args, **kwargs):
            counts["resolve"] += 1
            return real_resolve(*args, **kwargs)

        # Count through both bindings: the driver holds from-imports, while
        # trace_from_elf resolves the same functions via this module's globals.
        original_load = layout_forensics_driver.load_production_program
        original_resolve = layout_forensics_driver.resolved_call_edges
        original_trace_load = layout_propagation_trace.load_production_program
        original_trace_resolve = layout_propagation_trace.resolved_call_edges
        layout_forensics_driver.load_production_program = counting_load
        layout_forensics_driver.resolved_call_edges = counting_resolve
        layout_propagation_trace.load_production_program = counting_load
        layout_propagation_trace.resolved_call_edges = counting_resolve
        try:
            self._run()
        finally:
            layout_forensics_driver.load_production_program = original_load
            layout_forensics_driver.resolved_call_edges = original_resolve
            layout_propagation_trace.load_production_program = original_trace_load
            layout_propagation_trace.resolved_call_edges = original_trace_resolve

        self.assertEqual(counts["load"], 1, "Program/metadata must be loaded once")
        self.assertEqual(counts["resolve"], 1, "call edges must be resolved once")


class GradeParityTests(DriverTestCase):
    """Strong-path grading must match the pre-refactor rules."""

    def test_bound_production_edges_yield_analysis_trace(self) -> None:
        payload = self._run()
        self.assertEqual(payload["grade"], "analysis-trace")
        self.assertTrue(payload["is_propagation_evidence"])
        self.assertEqual(payload["path_grade"], "production")
        self.assertTrue(payload["g2_filled"])

    def test_wrong_elf_keeps_g2_unfilled(self) -> None:
        payload = self._run(expected_sha256="11" * 32)
        self.assertFalse(payload["is_propagation_evidence"])
        self.assertFalse(payload["g2_filled"])

    def test_missing_inheritance_keeps_g2_unfilled(self) -> None:
        payload = self._run(inheritance=None)
        self.assertFalse(payload["is_propagation_evidence"])
        self.assertFalse(payload["g2_filled"])


class StageEventTests(DriverTestCase):
    def test_failed_disassembly_is_logged_as_error_and_cleans_tempfile(self):
        import io

        log = io.StringIO()
        dump_paths = []

        def fail_objdump(*args, **kwargs):
            dump_paths.append(Path(kwargs["stdout"].name))
            return subprocess.CompletedProcess(args[0], 2)

        with mock.patch("subprocess.run", side_effect=fail_objdump):
            with self.assertRaisesRegex(RuntimeError, "disassembly failed"):
                layout_propagation_trace.load_production_program(
                    self.root / "fake.elf",
                    metadata=ChimeraMetadata.empty(),
                    stage_factory=lambda name: layout_forensics_driver._Stage(log, name),
                )
        self.assertIn("stage=disassemble end status=error", log.getvalue())
        self.assertNotIn("status=ok", log.getvalue())
        self.assertNotIn("stage=parse", log.getvalue())
        self.assertTrue(dump_paths)
        self.assertTrue(all(not path.exists() for path in dump_paths))

    """Stage events: order, KiB memory fields, and sampler failure tolerance."""

    def test_stage_order_and_fields(self) -> None:
        self._run()
        log_text = (self.out / "smallest-site-trace.log").read_text(encoding="utf-8")
        for stage in (
            "parse",
            "cfg",
            "call_edges",
            "bind",
            "propagate",
        ):
            self.assertIn(f"stage={stage} begin", log_text)
            self.assertIn(f"stage={stage} end", log_text)
        self.assertIn("pid=", log_text)
        self.assertIn("elapsed_s=", log_text)
        # KiB-suffixed counters, present-or-omitted but never object sizes.
        if layout_forensics_driver._memory_fields():
            self.assertIn("vmrss_kib=", log_text)
        self.assertNotIn("objgraph", log_text)

    def test_parse_and_cfg_events_wrap_the_real_operations(self) -> None:
        active = []
        observed = []

        @contextmanager
        def stage_factory(name):
            active.append(name)
            observed.append((name, "begin"))
            try:
                yield
            except BaseException:
                observed.append((name, "error"))
                raise
            else:
                observed.append((name, "end"))
            finally:
                active.pop()

        real_parse = layout_propagation_trace.parse_dump
        real_cfg = layout_propagation_trace.RiscvServices.build_cfg

        def check_parse(*args, **kwargs):
            self.assertEqual(active[-1], "parse")
            return real_parse(*args, **kwargs)

        def check_cfg(program):
            self.assertEqual(active[-1], "cfg")
            return real_cfg(program)

        def check_disassemble(*args, **kwargs):
            self.assertEqual(active[-1], "disassemble")
            kwargs["stdout"].write(SMALL_DUMP.encode("utf-8"))
            return subprocess.CompletedProcess(args[0], 0)

        with tempfile.TemporaryDirectory() as directory:
            elf = Path(directory) / "input.elf"
            elf.write_bytes(b"fixture")
            with mock.patch.object(layout_propagation_trace, "parse_dump", side_effect=check_parse), \
                 mock.patch.object(layout_propagation_trace.RiscvServices, "build_cfg", side_effect=check_cfg), \
             mock.patch.object(subprocess, "run", side_effect=check_disassemble):
                layout_propagation_trace.load_production_program(
                    elf,
                    metadata=ChimeraMetadata.empty(),
                    stage_factory=stage_factory,
                )

        self.assertEqual(
            observed,
            [("disassemble", "begin"), ("disassemble", "end"),
             ("parse", "begin"), ("parse", "end"),
             ("cfg", "begin"), ("cfg", "end")],
        )

    def test_metadata_event_wraps_the_real_elf_read(self) -> None:
        def check_from_elf(path):
            log_text = (self.out / "smallest-site-trace.log").read_text(encoding="utf-8")
            self.assertIn("stage=metadata begin", log_text)
            self.assertNotIn("stage=metadata end", log_text)
            return ChimeraMetadata.empty()

        with tempfile.TemporaryDirectory() as directory:
            elf = Path(directory) / "input.elf"
            elf.write_bytes(b"fixture")
            with mock.patch.object(ChimeraMetadata, "from_elf", side_effect=check_from_elf):
                payload = self._run(elf=elf, metadata=None)
        self.assertTrue(payload["g2_filled"])

    def test_stage_end_marks_failed_operations(self) -> None:
        def fail(*args, **kwargs):
            raise RuntimeError("parse failed")

        with mock.patch.object(layout_propagation_trace, "parse_dump", side_effect=fail):
            self._run()

        log_text = (self.out / "smallest-site-trace.log").read_text(encoding="utf-8")
        self.assertIn("stage=parse end status=error", log_text)

    def test_bind_and_propagate_events_wrap_real_operations(self) -> None:
        real_edges = layout_forensics_driver.resolved_call_edges
        real_load = layout_propagation_trace.load_inheritance
        real_trace = layout_propagation_trace.trace_from_inheritance

        def check_edges(*args, **kwargs):
            log_text = (self.out / "smallest-site-trace.log").read_text(encoding="utf-8")
            self.assertIn("stage=call_edges begin", log_text)
            self.assertNotIn("stage=call_edges end", log_text)
            return real_edges(*args, **kwargs)

        def check_load(*args, **kwargs):
            log_text = (self.out / "smallest-site-trace.log").read_text(encoding="utf-8")
            self.assertIn("stage=bind begin", log_text)
            self.assertNotIn("stage=bind end", log_text)
            return real_load(*args, **kwargs)

        def check_trace(*args, **kwargs):
            log_text = (self.out / "smallest-site-trace.log").read_text(encoding="utf-8")
            self.assertIn("stage=propagate begin", log_text)
            self.assertNotIn("stage=propagate end", log_text)
            return real_trace(*args, **kwargs)

        with mock.patch.object(layout_forensics_driver, "resolved_call_edges", side_effect=check_edges), \
             mock.patch.object(layout_propagation_trace, "load_inheritance", side_effect=check_load), \
             mock.patch.object(layout_propagation_trace, "trace_from_inheritance", side_effect=check_trace):
            payload = self._run()
        self.assertTrue(payload["g2_filled"])

    def test_begin_comes_before_end_for_each_stage(self) -> None:
        self._run()
        lines = (
            (self.out / "smallest-site-trace.log")
            .read_text(encoding="utf-8")
            .splitlines()
        )
        for stage in ("parse", "cfg", "call_edges", "bind", "propagate"):
            begin = next(i for i, l in enumerate(lines) if f"stage={stage} begin" in l)
            end = next(i for i, l in enumerate(lines) if f"stage={stage} end" in l)
            self.assertLess(begin, end)

    def test_memory_sampling_failure_is_tolerated(self) -> None:
        import layout_forensics_driver as driver

        original = driver._memory_fields
        driver._memory_fields = lambda: {}  # sampler broken
        try:
            payload = self._run()
        finally:
            driver._memory_fields = original
        self.assertIn("g2_filled", payload)
        log_text = (self.out / "smallest-site-trace.log").read_text(encoding="utf-8")
        self.assertIn("stage=parse begin", log_text)


class StrongPathToleranceTests(DriverTestCase):
    """A failing strong path must not abort the run or lose the JSON payload.

    Mirror of the weak-path contract: "diagnosis must not abort the run".  A
    corrupt-but-digest-matched inheritance report (or any other strong-path
    blow-up) must leave ``strong_result`` unset, continue, and still write
    ``smallest-site-trace.json`` with ``g2_filled: False``.
    """

    def test_failing_strong_pipeline_still_writes_payload(self) -> None:
        original = layout_forensics_driver.trace_from_bound_edges

        def broken(*args, **kwargs):
            raise ValueError("strong pipeline blew up")

        layout_forensics_driver.trace_from_bound_edges = broken
        try:
            payload = self._run()
        finally:
            layout_forensics_driver.trace_from_bound_edges = original

        written = json.loads(
            (self.out / "smallest-site-trace.json").read_text(encoding="utf-8")
        )
        self.assertEqual(written, payload, "payload must be written despite the failure")
        self.assertFalse(payload["is_propagation_evidence"])
        self.assertFalse(payload["g2_filled"])
        self.assertNotEqual(payload["grade"], "analysis-trace")
        log_text = (self.out / "smallest-site-trace.log").read_text(encoding="utf-8")
        self.assertIn("strong pipeline unavailable:", log_text)
        self.assertIn("wrote", log_text)


class WeakPathTests(DriverTestCase):
    """The elf-backed weak path must degrade, never abort, the run.

    Approach (b) subprocess seams: ``elf_fixture.build_elf`` emits no symbol
    table (``nm`` reports "no symbols") and this host's binutils has no
    RISC-V target and no ``--disassemble=NAME`` form, so canned
    ``nm``/``objdump`` output is served to the real weak-path orchestration
    (nm parse, BFS, edge build, ``trace_from_bound_edges``).
    """

    NM_TWO_FUNCTIONS = (
        "0000000000001000 t src\n"
        "0000000000008000 T host\n"
    )
    OBJDUMP_BY_SYMBOL = {
        "src": (
            "src:     file format elf64-little\n"
            "\n"
            "Disassembly of section .text:\n"
            "\n"
            "0000000000001000 <src>:\n"
            "    1000:\t34d000ef           \tjal\t8000 <host>\n"
            "    1004:\t00008067           \tret\n"
        ),
        "host": (
            "host:     file format elf64-little\n"
            "\n"
            "Disassembly of section .text:\n"
            "\n"
            "0000000000008000 <host>:\n"
            "    8000:\t00008067           \tret\n"
        ),
    }

    def _elf(self) -> Path:
        path = self.root / "tiny.elf"
        path.write_bytes(b"\x7fELF-weak-path-fixture")
        return path

    def _check_output_seam(self, responder):
        """Replace the driver's ``subprocess.check_output``; returns restore fn."""

        original = layout_forensics_driver.subprocess.check_output

        def restore() -> None:
            layout_forensics_driver.subprocess.check_output = original

        def fake(cmd, *args, **kwargs):
            return responder(list(cmd))

        layout_forensics_driver.subprocess.check_output = fake
        return restore

    def test_failing_weak_pipeline_still_writes_strong_payload(self) -> None:
        baseline = self._run()
        elf = self._elf()

        def broken(cmd):
            raise FileNotFoundError(f"{cmd[0]}: not found")

        restore = self._check_output_seam(broken)
        try:
            payload = self._run(elf=elf)
        finally:
            restore()

        written = json.loads(
            (self.out / "smallest-site-trace.json").read_text(encoding="utf-8")
        )
        self.assertEqual(payload, baseline, "strong result must survive a weak failure")
        self.assertEqual(written, payload, "payload must be written despite the failure")
        self.assertEqual(payload["grade"], "analysis-trace")
        self.assertEqual(payload["path_grade"], "production")
        self.assertEqual(payload["selected_path"], "strong")
        self.assertTrue(payload["g2_filled"])
        self.assertEqual(payload["production_call_edges"], 2)
        self.assertEqual(payload["suspected_call_edges"], 0)
        self.assertIsNone(payload["weak_grade"])
        self.assertFalse(payload["weak_is_propagation_evidence"])
        log_text = (self.out / "smallest-site-trace.log").read_text(encoding="utf-8")
        self.assertIn("weak pipeline unavailable:", log_text)
        self.assertIn("wrote", log_text)

    def test_weak_path_builds_disassembly_suspected_from_nm_objdump(self) -> None:
        elf = self._elf()

        def serve(cmd):
            if cmd[0] == "nm":
                return self.NM_TWO_FUNCTIONS
            symbol = next(
                (
                    arg.split("=", 1)[1]
                    for arg in cmd
                    if arg.startswith("--disassemble=")
                ),
                None,
            )
            return self.OBJDUMP_BY_SYMBOL[symbol]

        restore = self._check_output_seam(serve)
        try:
            payload = self._run(elf=elf, dump_text="", inheritance=None)
        finally:
            restore()

        self.assertTrue((self.out / "smallest-site-trace.json").is_file())
        self.assertEqual(payload["path_grade"], "disassembly-suspected")
        self.assertEqual(payload["selected_path"], "weak")
        self.assertEqual(payload["suspected_call_edges"], 1)
        self.assertEqual(payload["grade"], "callgraph-path-only")
        self.assertFalse(payload["is_propagation_evidence"])
        self.assertFalse(payload["g2_filled"])
        self.assertEqual(payload["weak_grade"], "callgraph-path-only")
        self.assertFalse(payload["weak_is_propagation_evidence"])
        log_text = (self.out / "smallest-site-trace.log").read_text(encoding="utf-8")
        self.assertIn("nm host 0x8000", log_text)
        self.assertIn("suspected call edges=1", log_text)
        self.assertNotIn("weak pipeline unavailable:", log_text)


class IsolatedImportTests(unittest.TestCase):
    """``python -I`` must import the driver with only explicit sys.path inserts."""

    def test_driver_imports_under_dash_I(self) -> None:
        root = Path(__file__).resolve().parents[1]
        code = (
            "import sys\n"
            f"sys.path.insert(0, {str(root)!r})\n"
            f"sys.path.insert(0, {str(root / 'tests')!r})\n"
            f"sys.path.insert(0, {str(root / 'cli')!r})\n"
            "import layout_forensics_driver\n"
            "import layout_propagation_trace\n"
            "print('ok', hasattr(layout_forensics_driver, 'run_trace'), "
            "hasattr(layout_propagation_trace, 'trace_from_bound_edges'))\n"
        )
        env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
        completed = subprocess.run(
            [sys.executable, "-I", "-c", code],
            capture_output=True,
            text=True,
            env=env,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("ok True True", completed.stdout)


if __name__ == "__main__":
    unittest.main()
