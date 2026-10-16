"""Regressions for register-dependency scheduling and fail-closed budgets."""

from __future__ import annotations

import unittest
import tempfile
from pathlib import Path
from unittest.mock import patch

from chimera.preprocess.offline.analysis.arch.riscv.rvv.services import RvvServices
from chimera.preprocess.offline.analysis.arch.riscv.services import RiscvServices
from chimera.preprocess.offline.analysis.program_model.parser import parse_dump
from chimera.check_elf import _build_inheritance_diagnostics, collect_diagnostics
from chimera.preprocess.offline.analysis.safety.stack_liveness import dependencies as dependency_module
from chimera.preprocess.offline.analysis.safety.stack_liveness.dependencies import (
    DEPENDENCY_UNKNOWN,
    analyze_register_dependencies,
)
from chimera.preprocess.offline.analysis.safety.stack_liveness.frame_liveness import (
    analyze_vlen_stack_liveness,
)
from chimera.preprocess.offline.analysis.safety.stack_liveness.model import (
    ChimeraMetadata,
)
from chimera.preprocess.offline.analysis.safety.stack_liveness.solver import (
    _FunctionExpressionAnalyzer,
)
from chimera.preprocess.offline.analysis.toolchain.objdump import LinuxObjdump


ROOT = Path(__file__).parent / "fixtures" / "vlen-dependency-budget"
INDUCTION_DUMP = ROOT / "vectorizable_induction.disasm.txt"


class VlenDependencyBudgetTests(unittest.TestCase):
    def setUp(self):
        self.rvv = RvvServices()
        self.semantics = self.rvv.stack_semantics
        self.adapter = LinuxObjdump("objdump")

    def _parse(self, source: Path):
        parsed = parse_dump(
            source,
            self.adapter.parse_format,
            is_external_trampoline=self.adapter.is_external_trampoline,
            retain_dump_lines=False,
        )
        return RiscvServices(self.rvv).build_cfg(parsed)

    def test_real_induction_solver_converges_without_widening_to_global_vlen(self):
        program = self._parse(INDUCTION_DUMP)
        function, = program.functions
        self.assertEqual(len(function.insts), 3398)
        dependencies = analyze_register_dependencies(
            function,
            self.semantics,
            capture_known_vlen_control=True,
        )

        self.assertFalse(dependencies.register_dependency_budget_exhausted)
        for address in (0xD6F63A, 0xD6F644):
            with self.subTest(adjustment=hex(address)):
                self.assertEqual(dependencies.level_after(address, "sp"), DEPENDENCY_UNKNOWN)
                self.assertFalse(dependencies.vlen_controlled_before(address, "sp"))
                self.assertFalse(dependencies.vlen_controlled_after(address, "sp"))

    def test_exhaustion_preserves_uncertainty_and_emits_frame_gap(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "budget-exhaustion-mini.dump"
            source.write_text(
                "0000000000001000 <budget_exhaustion>:\n"
                " 1000: 00000013 csrr t0,vlenb\n"
                " 1004: 00000013 beqz t0,0x1010\n"
                " 1008: 00000013 jal ra,0x9000\n"
                " 100c: 00000013 nop\n"
                " 1010: 00000013 sub sp,sp,a0\n"
                " 1014: 00000013 ret\n",
                encoding="utf-8",
            )
            program = self._parse(source)
            function, = program.functions
            analyzer = _FunctionExpressionAnalyzer(
                self.semantics, emit_warnings=False
            )
            expressions = analyzer.analyze(function, frozenset())

        # Entry and its known-VLEN branch are processed, then the deliberately
        # tiny work budget expires before the stack adjustment is reached.
        class FakeProver:
            calls = 0

            def prove_adjustment(self, _function, _address):
                self.calls += 1
                return type(
                    "Verdict",
                    (),
                    {
                        "proven": True,
                        "status": "independent",
                        "proof_id": "fake-proof",
                        "reason": "fake independent proof",
                    },
                )()

        for update_limit in (0, 3, 5):
            with self.subTest(update_limit=update_limit):
                prover = FakeProver()
                with patch.object(
                    dependency_module, "_MAX_UPDATES_FACTOR", 0
                ), patch.object(
                    dependency_module, "_MAX_UPDATES_FLOOR", update_limit
                ):
                    dependencies = analyze_register_dependencies(
                        function,
                        self.semantics,
                        capture_known_vlen_control=True,
                    )
                    origins = []
                    exclusions = []
                    live, warnings = analyze_vlen_stack_liveness(
                        function,
                        expressions,
                        self.semantics,
                        prover=prover,
                        origins=origins,
                        scope_exclusions=exclusions,
                        unknown_stack_size_policy="assume-scalar-independent",
                    )

                self.assertTrue(dependencies.register_dependency_budget_exhausted)
                self.assertFalse(dependencies.vlen_controlled_after(0x1010, "a0"))
                self.assertTrue(dependencies.control_dependent(0x1010))
                self.assertEqual(prover.calls, 0)
                self.assertTrue(live.get(0x1010))
                self.assertEqual(exclusions, [])
                origin, = [item for item in origins if item.adjustment == 0x1010]
                self.assertEqual(origin.dependency, "unknown")
                self.assertIn("register-dependency-budget-exhausted", origin.gaps)
                self.assertTrue(
                    any(
                        warning.code == "register-dependency-budget-exhausted"
                        and warning.addresses == (0x1010,)
                        for warning in warnings
                    )
                )

    def test_collect_diagnostics_keeps_budget_gap_actionable_and_out_of_gate(self):
        source = (
            "0000000000001000 <budget_host>:\n"
            " 1000: 00000013 sub sp,sp,a0\n"
            " 1004: 00000013 jalr a2\n"
            " 1008: 00000013 csrr t0,vlenb\n"
            " 100c: 00000013 beqz t0,0x1014\n"
            " 1010: 00000013 ret\n"
            " 1014: 00000013 ret\n"
        )
        with tempfile.TemporaryDirectory() as directory:
            elf = Path(directory) / "budget-host.elf"
            elf.write_bytes(b"test ELF placeholder")
            with patch.object(dependency_module, "_MAX_UPDATES_FACTOR", 0), patch.object(
                dependency_module, "_MAX_UPDATES_FLOOR", 0
            ):
                result = collect_diagnostics(
                    elf,
                    objdump_cmd="objdump",
                    strategy="gate",
                    dump_text=source,
                    metadata=ChimeraMetadata.empty(),
                    unknown_stack_size_policy="assume-scalar-independent",
                )

        finding, = result.findings
        self.assertEqual(finding.origin_status, "unproven")
        self.assertEqual(result.counts["actionable"], 1)
        self.assertEqual(result.gate_names, ())
        payload = _build_inheritance_diagnostics(result, "0" * 64)
        local, = [
            entry
            for entry in payload["functions"]
            if entry["name"] == "budget_host"
        ]
        allocation, = local["frame_origins"]
        self.assertEqual(allocation["dependency"], "unknown")
        self.assertIn("register-dependency-budget-exhausted", allocation["gaps"])


if __name__ == "__main__":
    unittest.main()
