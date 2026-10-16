"""Resolved internal transfer exit-liveness regressions."""
from pathlib import Path
import tempfile
import unittest

from chimera.preprocess.offline.analysis.arch.riscv.rvv import RvvServices
from chimera.preprocess.offline.analysis.arch.riscv.services import RiscvServices
from chimera.preprocess.offline.analysis.program_model.parser import parse_dump
from chimera.preprocess.offline.analysis.toolchain.objdump import LinuxObjdump
from chimera.preprocess.offline.analysis.safety.classifier import classify_liveness
from chimera.preprocess.offline.analysis.safety.stack_liveness import (
    ChimeraMetadata, StackLivenessAnalyzer,
)
from chimera.preprocess.offline.analysis.safety.stack_liveness.model import CallTargetEntry


def analyze(specs, *, metadata=None, external=()):
    lines = []
    for start, name, body in specs:
        lines.append(f"\n{start:016x} <{name}>:")
        for index, (op, args) in enumerate(body):
            lines.append(f" {start + 4 * index:x}:\t00000013\t{op}\t{args}")
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "exit-liveness.dump"
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        rvv = RvvServices()
        program = RiscvServices(rvv).build_cfg(
            parse_dump(path, LinuxObjdump("objdump").parse_format))
    for function in program.functions:
        if function.name in external:
            function.is_external_trampoline = True
    stack = StackLivenessAnalyzer(
        semantics=rvv.stack_semantics, emit_warnings=False).analyze_program(
            program, metadata=metadata or ChimeraMetadata.empty(),
            config_results=rvv.vector_configs(program))
    safety = classify_liveness(program, rvv.vector_liveness(program), stack,
                               rvv.classify_vector_liveness)
    return program, stack, safety


class ScalarWidthExitLivenessTests(unittest.TestCase):
    def test_direct_per_function_caller_without_evidence_stays_conservative(self):
        text = ("0000000000001000 <caller>:\n"
                " 1000:\t00000013\tcsrr\ts4,vlenb\n"
                " 1004:\t00000013\tjal\tra,2000 <known_body>\n"
                "\n0000000000002000 <known_body>:\n"
                " 2000:\t00000013\tret\n")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "direct-local.dump"
            path.write_text(text, encoding="utf-8")
            rvv = RvvServices()
            program = RiscvServices(rvv).build_cfg(
                parse_dump(path, LinuxObjdump("objdump").parse_format))
        analyzer = StackLivenessAnalyzer(semantics=rvv.stack_semantics,
                                         emit_warnings=False)
        local = analyzer._function_analyzer.analyze(
            program.functions[0], metadata=ChimeraMetadata.empty(),
            config_result=rvv.vector_configs(program)[0x1000])
        self.assertTrue(local.live_before[0x1004])

    def test_final_resolved_call_does_not_invent_a_continuation_use(self):
        program, stack, safety = analyze([
            (0x1000, "caller", [("csrr", "s4,vlenb"),
                                 ("jal", "ra,2000 <known_body>")]),
            (0x2000, "known_body", [("ret", "")]),
        ])
        self.assertTrue(safety.records[0x1004].safe)
        self.assertTrue(safety.records[0x2000].safe)
        self.assertNotIn(0x2000, stack.inherited_functions)

    def test_a_callee_own_final_callback_does_not_import_local_exit_state(self):
        program, stack, safety = analyze([
            (0x1000, "caller", [("jal", "ra,2000 <known_body>")]),
            (0x2000, "known_body", [("csrr", "s4,vlenb"),
                                     ("jal", "ra,3000 <callback>")]),
            (0x3000, "callback", [("ret", "")]),
        ])
        self.assertTrue(safety.records[0x2004].safe)
        self.assertTrue(safety.records[0x3000].safe)
        self.assertNotIn(0x3000, stack.inherited_functions)

    def test_resolved_exit_does_not_erase_genuinely_inherited_context(self):
        _, stack, safety = analyze([
            (0x1000, "outer", [("mv", "s0,sp"),
                                ("vsetvli", "t0,zero,e32,m2,ta,ma"),
                                ("sub", "sp,sp,t0"),
                                ("jal", "ra,2000 <middle>")]),
            (0x2000, "middle", [("jal", "ra,3000 <callback>")]),
            (0x3000, "callback", [("ret", "")]),
        ])
        self.assertIn(0x2000, stack.inherited_functions)
        self.assertIn(0x3000, stack.inherited_functions)
        self.assertFalse(safety.records[0x2000].safe)

    def test_known_zero_link_tail_forms_end_local_cache_lifetime(self):
        for op, operands in (("j", "2000 <known_body>"),
                             ("tail", "2000 <known_body>"),
                             ("jal", "zero,2000 <known_body>"),
                             ("jal", "x0,2000 <known_body>")):
            with self.subTest(op=op, operands=operands):
                _, _, safety = analyze([
                    (0x1000, "caller", [("csrr", "s4,vlenb"), (op, operands)]),
                    (0x2000, "known_body", [("ret", "")]),
                ])
                self.assertTrue(safety.records[0x1004].safe)

    def test_width_used_only_as_a_branch_selector_is_not_an_exit_cache_use(self):
        _, _, safety = analyze([
            (0x1000, "caller", [
                ("csrr", "s4,vlenb"),
                ("beqz", "s4,100c <caller+0xc>"),
                ("j", "2000 <known_body>"),
                ("j", "2000 <known_body>"),
            ]),
            (0x2000, "known_body", [("ret", "")]),
        ])
        self.assertTrue(safety.records[0x1000].safe)
        self.assertTrue(safety.records[0x1008].safe)
        self.assertTrue(safety.records[0x100C].safe)

    def test_width_guarded_branch_to_complete_internal_entry_is_not_a_content_use(self):
        _, stack, safety = analyze([
            (0x1000, "caller", [("csrr", "s4,vlenb"),
                                 ("beqz", "s4,2000 <known_body>"),
                                 ("li", "a0,0"), ("ret", "")]),
            (0x2000, "known_body", [("ret", "")]),
        ])
        self.assertTrue(safety.records[0x1004].safe)
        self.assertNotIn(0x2000, stack.inherited_functions)

    def test_unresolved_empty_mixed_external_and_plt_targets_stay_conservative(self):
        cases = (
            ("missing", (), (), [("jal", "ra,9000 <missing>")]),
            ("empty", (), (), [("jalr", "ra,t2")]),
            ("mixed", (0x2000, 0x9000), (), [("jalr", "ra,t2")]),
            ("empty-body", (), (), [("jal", "ra,2000 <known_body>")]),
            ("plt", (), ("known_body",), [("jal", "ra,2000 <known_body>")]),
        )
        for label, targets, external, transfer in cases:
            with self.subTest(label=label):
                metadata = ChimeraMetadata.empty()
                if label in {"empty", "mixed"}:
                    metadata = ChimeraMetadata(function_pointer={
                        0x1004: CallTargetEntry(0x1004, targets)})
                target_body = [] if label == "empty-body" else [("ret", "")]
                specs = [(0x1000, "caller", [("csrr", "s4,vlenb"), *transfer]),
                         (0x2000, "known_body", target_body)]
                _, _, safety = analyze(specs, metadata=metadata, external=external)
                self.assertFalse(safety.records[0x1004].safe)

    def test_complete_singleton_and_multi_internal_indirect_sets_end_dead_cache(self):
        for targets in ((0x2000,), (0x2000, 0x3000)):
            with self.subTest(targets=targets):
                metadata = ChimeraMetadata(function_pointer={
                    0x1004: CallTargetEntry(0x1004, targets)})
                specs = [
                    (0x1000, "caller", [("csrr", "s4,vlenb"), ("jalr", "ra,t2")]),
                    (0x2000, "known_body", [("ret", "")]),
                    (0x3000, "alternate_body", [("ret", "")]),
                ]
                _, _, safety = analyze(specs, metadata=metadata)
                self.assertTrue(safety.records[0x1004].safe)

    def test_local_jump_stays_in_the_function_cfg(self):
        _, stack, safety = analyze([
            (0x1000, "caller", [("csrr", "s4,vlenb"),
                                 ("j", "1008 <caller+0x8>"),
                                 ("add", "t0,s4,zero"), ("ret", "")]),
        ])
        self.assertFalse(safety.records[0x1004].safe)
        self.assertFalse(stack.inherited_functions)

    def test_unmodelled_tail_spelling_does_not_get_an_abi_exit_rule(self):
        _, _, safety = analyze([
            (0x1000, "caller", [("csrr", "s4,vlenb"),
                                 ("custom.tail", "2000")]),
            (0x2000, "known_body", [("ret", "")]),
        ])
        self.assertFalse(safety.records[0x1004].safe)

    def test_custom_link_call_does_not_get_the_ordinary_abi_exit_rule(self):
        _, _, safety = analyze([
            (0x1000, "caller", [("csrr", "s4,vlenb"),
                                 ("jal", "t0,2000 <known_body>")]),
            (0x2000, "known_body", [("ret", "")]),
        ])
        self.assertFalse(safety.records[0x1004].safe)

    def test_call_link_defaults_only_for_implicit_or_explicit_ra(self):
        _, _, custom_link_safety = analyze([
            (0x1000, "caller", [("csrr", "s4,vlenb"),
                                 ("call", "t0,2000 <known_body>")]),
            (0x2000, "known_body", [("ret", "")]),
        ])
        self.assertFalse(custom_link_safety.records[0x1004].safe)
        for operands in ("2000 <known_body>", "ra,2000 <known_body>"):
            with self.subTest(operands=operands):
                _, _, standard_call_safety = analyze([
                    (0x1000, "caller", [("csrr", "s4,vlenb"),
                                         ("call", operands)]),
                    (0x2000, "known_body", [("ret", "")]),
                ])
                self.assertTrue(standard_call_safety.records[0x1004].safe)

    def test_malformed_call_pseudos_do_not_gain_an_ordinary_abi_exit_rule(self):
        for operands in ("", "bogus,2000 <known_body>"):
            with self.subTest(operands=operands):
                _, _, safety = analyze([
                    (0x1000, "caller", [("csrr", "s4,vlenb"),
                                         ("call", operands)]),
                    (0x2000, "known_body", [("ret", "")]),
                ])
                self.assertFalse(safety.records[0x1004].safe)

    def test_resolved_indirect_exit_keeps_width_dependent_target_and_sp_uses(self):
        for body, target in (
            ([ ("csrr", "t2,vlenb"), ("jalr", "ra,t2") ], 0x1004),
            ([ ("csrr", "s4,vlenb"), ("sub", "sp,sp,s4"),
               ("jal", "ra,2000 <known_body>") ], 0x1008),
            ([ ("csrr", "t2,vlenb"), ("jalr", "zero,t2") ], 0x1004),
            ([ ("csrr", "s4,vlenb"), ("sub", "sp,sp,s4"),
               ("j", "2000 <known_body>") ], 0x1008),
        ):
            with self.subTest(body=body):
                call_addr = 0x1004 if body[-1][0] == "jalr" else 0x1008
                metadata = ChimeraMetadata(function_pointer={
                    call_addr: CallTargetEntry(call_addr, (0x2000,))})
                _, _, safety = analyze([
                    (0x1000, "caller", body),
                    (0x2000, "known_body", [("ret", "")]),
                ], metadata=metadata)
                self.assertFalse(safety.records[target].safe)

    def test_true_scalar_and_private_spill_uses_after_a_normal_call_stay_live(self):
        for body, use_address in (
            ([("csrr", "s4,vlenb"), ("jal", "ra,2000 <known_body>"),
              ("add", "t0,s4,zero"), ("ret", "")], 0x1004),
            ([("addi", "sp,sp,-64"), ("csrr", "t0,vlenb"),
              ("sd", "t0,8(sp)"), ("li", "t0,0"),
              ("jal", "ra,2000 <known_body>"), ("ld", "s4,8(sp)"),
              ("add", "t1,s4,zero"), ("addi", "sp,sp,64"), ("ret", "")], 0x1010),
        ):
            with self.subTest(body=body):
                _, _, safety = analyze([
                    (0x1000, "caller", body),
                    (0x2000, "known_body", [("ret", "")]),
                ])
                self.assertFalse(safety.records[use_address].safe)


if __name__ == "__main__":
    unittest.main()
