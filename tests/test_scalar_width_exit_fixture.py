"""Bounded regressions from the frozen llama.cpp native disassembly."""
from pathlib import Path
import tempfile
import unittest

from chimera.check_elf import collect_diagnostics
from chimera.preprocess.offline.analysis.arch.riscv.rvv import RvvServices
from chimera.preprocess.offline.analysis.arch.riscv.services import RiscvServices
from chimera.preprocess.offline.analysis.program_model.parser import parse_dump
from chimera.preprocess.offline.analysis.safety.classifier import classify_liveness
from chimera.preprocess.offline.analysis.safety.stack_liveness import (
    ChimeraMetadata, StackLivenessAnalyzer,
)
from chimera.preprocess.offline.analysis.toolchain.objdump import LinuxObjdump


FIXTURE = Path(__file__).parent / "fixtures" / "llama_width_exit_cache.dump"
WIDTH = "live_vlen_scalar_data"
ABORT_SITES = (0x3AEA4E, 0x3AEA72, 0x3AEA96, 0x3AED26, 0x3AED4A, 0x3AED6E)


class NativeWidthExitFixtureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        rvv = RvvServices()
        program = RiscvServices(rvv).build_cfg(
            parse_dump(FIXTURE, LinuxObjdump("objdump").parse_format))
        metadata = ChimeraMetadata(has_stackobj_map_section=True)
        stack = StackLivenessAnalyzer(
            semantics=rvv.stack_semantics, emit_warnings=False,
            unknown_stack_size_policy="assume-scalar-independent",
        ).analyze_program(program, metadata=metadata, config_results=rvv.vector_configs(program))
        cls.program, cls.stack = program, stack
        cls.safety = classify_liveness(program, rvv.vector_liveness(program), stack,
                                      rvv.classify_vector_liveness)

    def test_real_diagnostic_exits_do_not_invent_cache_uses(self):
        for site in ABORT_SITES:
            with self.subTest(site=hex(site)):
                self.assertIn("ggml_abort", self.program.instruction_by_address[site].operand)
                self.assertNotIn(WIDTH, self.safety.records[site].reasons)
        self.assertNotIn(0x39284, self.stack.inherited_functions)

    def test_real_width_cache_across_normal_work_is_retained(self):
        self.assertEqual(self.program.instruction_by_address[0x3AEB5C].op, "vsetvli")
        self.assertIn(WIDTH, self.safety.records[0x3AEB78].reasons)
        self.assertIn(0x3796F4, self.stack.inherited_functions)
        self.assertFalse(self.safety.records[0x3796F8].safe)
        # The atomic work body has no descendant call boundary.
        self.assertFalse(any(w.function_start == 0x3796F4 and w.code in {
            "active-external-call", "unresolved-active-indirect-call",
        } for w in self.stack.warnings))

    def test_real_abort_callback_does_not_inherit_from_dead_caches(self):
        with tempfile.TemporaryDirectory() as directory:
            elf = Path(directory) / "fixture.elf"
            elf.write_bytes(b"\x7fELF\x02\x01\x01" + b"\0" * 24)
            result = collect_diagnostics(
                elf, objdump_cmd="objdump", strategy="gate",
                dump_text=FIXTURE.read_text(encoding="utf-8"),
                metadata=ChimeraMetadata(has_stackobj_map_section=True),
                unknown_stack_size_policy="assume-scalar-independent",
            )
        self.assertFalse(any(f.function == "ggml_abort" for f in result.findings))
        self.assertEqual(result.findings, ())


if __name__ == "__main__":
    unittest.main()
