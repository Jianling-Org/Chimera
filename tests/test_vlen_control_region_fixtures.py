"""Gate4 disassemblies retained for the VLEN control-region correction."""

from __future__ import annotations

import json
import unittest
from pathlib import Path

from chimera.preprocess.offline.analysis.arch.riscv.rvv.services import RvvServices
from chimera.preprocess.offline.analysis.arch.riscv.services import RiscvServices
from chimera.preprocess.offline.analysis.program_model.parser import parse_dump
from chimera.preprocess.offline.analysis.safety.stack_liveness.dependencies import (
    analyze_register_dependencies,
)
from chimera.preprocess.offline.analysis.safety.stack_liveness.frame_liveness import (
    analyze_vlen_stack_liveness,
)
from chimera.preprocess.offline.analysis.safety.stack_liveness.solver import (
    _FunctionExpressionAnalyzer,
)
from chimera.preprocess.offline.analysis.toolchain.objdump import LinuxObjdump


FIXTURES = Path(__file__).parent / "fixtures" / "vlen-control-regions"


class VlenControlRegionRealDumpTests(unittest.TestCase):
    def test_six_exact_gate4_functions_keep_evidence_based_frame_origins(self):
        targets = json.loads((FIXTURES / "targets.json").read_text(encoding="utf-8"))
        adapter = LinuxObjdump("objdump")
        rvv = RvvServices()
        semantics = rvv.stack_semantics
        expected_excluded = {
            "_ZL25check_offload_target_namePKcl": {0x21BA4},
            "_ZL17output_file_namesv": {0x8373D4},
            "_ZL21vn_reference_lookup_3P6ao_refP9tree_nodePvP15translate_flags": {
                0xCE7A2A
            },
            "_ZL28vect_lower_load_permutationsP14_loop_vec_infoP8hash_mapI3vecIP14_stmt_vec_info7va_heap6vl_ptrEP9_slp_tree21simple_hashmap_traitsI10bst_traitsS9_EERK11array_sliceIS9_Eb": {
                0xDA2B74
            },
        }
        expected_retained = {
            "_ZL26builtin_define_type_minmaxPKcS0_P9tree_node": {
                0x7185D2,
                0x718622,
                0x718644,
            },
            "_Z23cl_optimization_restoreP11gcc_optionsS0_P15cl_optimization": {
                0xA69490
            },
        }

        self.assertEqual(len(targets), 6)
        self.assertEqual(len(list(FIXTURES.glob("*.disasm.txt"))), 6)
        for target in targets:
            with self.subTest(symbol=target["symbol"]):
                parsed = parse_dump(
                    FIXTURES / target["file"],
                    adapter.parse_format,
                    is_external_trampoline=adapter.is_external_trampoline,
                    retain_dump_lines=False,
                )
                program = RiscvServices(rvv).build_cfg(parsed)
                function = next(
                    item
                    for item in program.functions
                    if item.start == int(target["function_start"], 16)
                )
                self.assertEqual(function.name, target["symbol"])
                expressions = _FunctionExpressionAnalyzer(
                    semantics, emit_warnings=False
                ).analyze(function, frozenset())
                origins = []
                exclusions = []
                analyze_vlen_stack_liveness(
                    function,
                    expressions,
                    semantics,
                    origins=origins,
                    scope_exclusions=exclusions,
                    unknown_stack_size_policy="assume-scalar-independent",
                )
                origin_addresses = {item.adjustment for item in origins}
                excluded_addresses = {item.adjustment for item in exclusions}
                expected = expected_excluded.get(function.name)
                if expected is not None:
                    self.assertTrue(expected <= excluded_addresses)
                    self.assertTrue(expected.isdisjoint(origin_addresses))
                expected = expected_retained.get(function.name)
                if expected is not None:
                    self.assertTrue(expected <= origin_addresses)
                    self.assertTrue(expected.isdisjoint(excluded_addresses))
                dependency = analyze_register_dependencies(
                    function,
                    semantics,
                    capture_known_vlen_control=True,
                )
                self.assertFalse(dependency.known_control_fallback)


if __name__ == "__main__":
    unittest.main()
