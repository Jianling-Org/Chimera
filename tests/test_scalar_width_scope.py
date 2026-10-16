"""Accepted local scalar-width cache scope through the production pipeline."""
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


WIDTH = "live_vlen_scalar_data"


def _program(functions):
    lines = []
    sites = {}
    for start, name, body in functions:
        lines.append(f"\n{start:016x} <{name}>:")
        sites[name] = []
        for index, (op, args) in enumerate(body):
            address = start + 4 * index
            sites[name].append(address)
            lines.append(f" {address:x}:\t00000013\t{op}\t{args}")
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "scope.dump"
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        rvv = RvvServices()
        program = RiscvServices(rvv).build_cfg(
            parse_dump(path, LinuxObjdump("objdump").parse_format))
    stack = StackLivenessAnalyzer(semantics=rvv.stack_semantics, emit_warnings=False).analyze_program(
        program, metadata=ChimeraMetadata.empty(), config_results=rvv.vector_configs(program))
    safety = classify_liveness(program, rvv.vector_liveness(program), stack,
                               rvv.classify_vector_liveness)
    return rvv, program, stack, safety, sites


class ScalarWidthScopeTests(unittest.TestCase):
    def test_supported_copy_and_pure_width_adapter(self):
        from chimera.preprocess.offline.analysis.arch.riscv.scalar_width_facts import scalar_width_cache_reads
        from chimera.preprocess.offline.analysis.safety.stack_liveness.expressions import Input, Constant
        from chimera.preprocess.offline.analysis.core.data_model.program import Instruction

        width = {"t0"}
        incoming = {"t0": Input("vlenb"), "t1": Constant(4), "a0": Input("a0")}
        cases = (
            ("mv", ("s4", "t0"), {"t0"}),
            ("fmv.d.x", ("fs0", "x5"), {"t0"}),
            ("c.mv", ("x20", "x5"), {"t0"}),
            ("slli", ("s4", "t0", "2"), {"t0"}),
            ("add", ("s4", "t0", "t1"), {"t0"}),
            ("mul", ("s4", "t0", "t1"), {"t0"}),
        )
        for op, args, expected in cases:
            with self.subTest(op=op):
                instruction = Instruction(0x1000, 4, op, args, "")
                self.assertEqual(scalar_width_cache_reads(instruction, incoming, width), expected)
        zero_product = Instruction(0x1000, 4, "mul", ("s4", "t0", "zero"), "")
        self.assertEqual(scalar_width_cache_reads(zero_product, incoming, width), set())
        compressed_addi = Instruction(0x1000, 2, "c.addi", ("x20", "4"), "")
        self.assertEqual(scalar_width_cache_reads(
            compressed_addi, {"s4": Input("vlenb")}, {"x20"}), {"s4"})

    def test_mixed_ordinary_input_arithmetic_does_not_copy_width(self):
        from chimera.preprocess.offline.analysis.arch.riscv.scalar_width_facts import scalar_width_cache_reads
        from chimera.preprocess.offline.analysis.safety.stack_liveness.expressions import Input
        from chimera.preprocess.offline.analysis.core.data_model.program import Instruction

        instruction = Instruction(0x1000, 4, "add", ("s4", "t0", "a0"), "")
        self.assertEqual(scalar_width_cache_reads(
            instruction, {"t0": Input("vlenb"), "a0": Input("a0")}, {"t0"}), set())

    def test_volatile_copies_end_at_ordinary_call_but_callee_saved_copy_survives(self):
        _, _, stack, safety, sites = _program([(0x1000, "caller", [
            ("csrr", "t0,vlenb"), ("mv", "s4,t0"), ("mv", "a2,t0"),
            ("jal", "ra,2000 <callee>"), ("add", "t1,s4,zero"),
            ("li", "a0,0"), ("ret", "")]),
            (0x2000, "callee", [("li", "a0,0"), ("ret", "")])])
        call = sites["caller"][3]
        self.assertIn(WIDTH, safety.records[call].reasons)
        self.assertIn(WIDTH, safety.records[sites["caller"][4]].reasons)
        snapshots = [w for w in stack.warnings if w.code == "escaping-vlen-scalar-value"
                     and call in w.addresses]
        self.assertTrue(snapshots)
        self.assertTrue(any(w.origins[0].width_evidence.call_effect.status == "not-requested"
                            and not w.origins[0].width_evidence.prior_unclosed_effect
                            for w in snapshots))

    def test_dead_width_argument_does_not_seed_a_complete_internal_callee(self):
        _, _, stack, safety, sites = _program([(0x1000, "caller", [
            ("csrr", "a0,vlenb"), ("jal", "ra,2000 <callee>"),
            ("li", "a0,0"), ("ret", "")]),
            (0x2000, "callee", [("li", "a0,0"), ("ret", "")])])
        self.assertTrue(safety.records[sites["caller"][1]].safe)
        self.assertNotIn(0x2000, stack.inherited_functions)

    def test_callee_saved_cache_survives_known_call_and_inherits_to_descendant(self):
        _, _, stack, safety, sites = _program([(0x1000, "caller", [
            ("csrr", "s4,vlenb"), ("jal", "ra,2000 <carrier>"),
            ("add", "t1,s4,zero"), ("li", "a0,0"), ("ret", "")]),
            (0x2000, "carrier", [("jal", "ra,3000 <descendant>"), ("li", "a0,0"), ("ret", "")]),
            (0x3000, "descendant", [("li", "a0,0"), ("ret", "")])])
        self.assertIn(WIDTH, safety.records[sites["caller"][1]].reasons)
        self.assertIn(0x2000, stack.inherited_functions)
        self.assertIn(0x3000, stack.inherited_functions)

    def test_selection_and_selected_load_do_not_create_width_content(self):
        _, _, stack, safety, sites = _program([(0x1000, "selection", [
            ("csrr", "t0,vlenb"), ("add", "s1,a0,t0"), ("li", "t0,0"),
            ("ld", "s4,0(s1)"), ("li", "s1,0"), ("mv", "t1,s4"),
            ("li", "a0,0"), ("ret", "")])])
        self.assertNotIn(WIDTH, safety.records[sites["selection"][5]].reasons)

    def test_selected_branch_store_and_call_are_diagnostic_only(self):
        _, _, stack, safety, sites = _program([(0x1000, "selection", [
            ("csrr", "t0,vlenb"), ("beqz", "t0,100c <selection+0xc>"),
            ("sd", "zero,0(a0)"), ("jal", "ra,2000 <callee>"),
            ("li", "a0,0"), ("ret", "")]),
            (0x2000, "callee", [("li", "a0,0"), ("ret", "")])])
        self.assertTrue(safety.records[sites["selection"][3]].safe)
        self.assertTrue(safety.records[sites["selection"][4]].safe)
        selection_warnings = [w for w in stack.warnings if w.code == "escaping-vlen-scalar-value"]
        self.assertTrue(any(set(w.addresses) & {sites["selection"][2], sites["selection"][3]}
                            for w in selection_warnings))

    def test_ordinary_parameter_load_is_not_width_content(self):
        _, _, _, safety, sites = _program([(0x1000, "parameter", [
            ("ld", "s4,0(a0)"), ("mv", "t1,s4"), ("li", "a0,0"), ("ret", "")])])
        self.assertNotIn(WIDTH, safety.records[sites["parameter"][1]].reasons)

    def test_return_reads_only_ra_and_sp_not_abi_return_registers(self):
        rvv, program, stack, safety, sites = _program([(0x1000, "void_local", [
            ("csrr", "a0,vlenb"), ("ret", "")])])
        facts = rvv.stack_semantics.scalar_width_facts(program.functions[0].insts[1])
        self.assertEqual(facts.reads, frozenset({"ra", "sp"}))
        self.assertTrue(safety.records[sites["void_local"][1]].safe)

    def test_selection_only_does_not_make_unmodelled_instruction_or_custom_call_sticky(self):
        _, _, _, safety, sites = _program([(0x1000, "selection", [
            ("csrr", "t0,vlenb"), ("beqz", "t0,1010 <selection+0x10>"),
            ("li", "t0,0"), ("custom", "t1,a0"), ("jal", "t0,3000 <custom_link>"),
            ("li", "a0,0"), ("ret", "")])])
        self.assertTrue(safety.records[sites["selection"][5]].safe)
        self.assertTrue(safety.records[sites["selection"][6]].safe)

    def test_vector_mask_and_index_width_are_selection_only(self):
        _, _, _, safety, sites = _program([(0x1000, "vector_select", [
            ("csrr", "a2,vlenb"), ("vmv.s.x", "v0,a2"), ("li", "a2,0"),
            ("vadd.vv", "v8,v16,v18,v0.t"), ("vmv.x.s", "s4,v8"),
            ("li", "t0,0"), ("csrr", "a2,vlenb"), ("vmv.s.x", "v8,a2"),
            ("li", "a2,0"), ("vluxei32.v", "v10,(s1),v8"),
            ("vmv.x.s", "s5,v10"), ("add", "t1,s4,zero"),
            ("add", "t2,s5,zero"), ("li", "a0,0"), ("ret", "")])])
        self.assertNotIn(WIDTH, safety.records[sites["vector_select"][11]].reasons)
        self.assertNotIn(WIDTH, safety.records[sites["vector_select"][12]].reasons)

    def test_vector_operand_used_as_both_data_and_mask_keeps_data_width(self):
        from chimera.preprocess.offline.analysis.core.data_model.program import Instruction

        rvv, program, _, safety, sites = _program([(0x1000, "data_mask_alias", [
            ("csrr", "a2,vlenb"), ("vmv.s.x", "v0,a2"), ("li", "a2,0"),
            ("vadd.vv", "v8,v0,v16,v0.t"), ("vmv.x.s", "s4,v8"),
            ("li", "a0,0"), ("ret", "")])])
        facts = rvv.stack_semantics.scalar_width_facts(program.functions[0].insts[3])
        self.assertIn(0, facts.vector_value_reads)
        self.assertIn(WIDTH, safety.records[sites["data_mask_alias"][4]].reasons)
        load = rvv.stack_semantics.scalar_width_facts(Instruction(
            0x1010, 4, "vluxei32.v", ("v8", "(s1)", "v8"), ""))
        store = rvv.stack_semantics.scalar_width_facts(Instruction(
            0x1014, 4, "vsuxei32.v", ("v8", "(s1)", "v8"), ""))
        self.assertNotIn(8, load.vector_value_reads)
        self.assertIn(8, load.vector_memory_address_vectors)
        self.assertIn(8, store.vector_value_reads)
        self.assertIn(8, store.vector_memory_address_vectors)

    def test_selected_vector_load_to_store_warns_without_pinning_later_code(self):
        _, _, stack, safety, sites = _program([(0x1000, "selected_load_store", [
            ("csrr", "a2,vlenb"), ("add", "t0,a1,a2"), ("vle32.v", "v8,(t0)"),
            ("li", "a2,0"), ("li", "t0,0"), ("li", "s1,8192"),
            ("vse32.v", "v8,(s1)"), ("vmv8r.v", "v8,v16"),
            ("li", "a0,0"), ("ret", "")])])
        origins = [origin for warning in stack.warnings
                   if warning.code == "escaping-vlen-scalar-value"
                   and sites["selected_load_store"][6] in warning.addresses
                   for origin in warning.origins]
        self.assertTrue(any("width-selected-memory-effect-unproven" in origin.gaps
                            for origin in origins))
        self.assertTrue(safety.records[sites["selected_load_store"][9]].safe)

    def test_known_nonstack_vector_width_store_stays_warning_only_when_selected(self):
        _, _, stack, safety, sites = _program([(0x1000, "selected_store", [
            ("li", "s1,8192"), ("csrr", "a2,vlenb"),
            ("beqz", "a2,1014 <selected_store+0x14>"),
            ("vmv.s.x", "v8,a2"), ("vs1r.v", "v8,(s1)"),
            ("vmv1r.v", "v8,v16"), ("li", "a2,0"),
            ("li", "a0,0"), ("ret", "")])])
        self.assertTrue(safety.records[sites["selected_store"][8]].safe)
        origins = [origin for warning in stack.warnings
                   if warning.code == "escaping-vlen-scalar-value"
                   and sites["selected_store"][4] in warning.addresses
                   for origin in warning.origins]
        self.assertTrue(any(origin.proof == "unsupported-nonstack-width-data"
                            and "width-controlled-write-unproven" in origin.gaps
                            for origin in origins))

    def test_scalar_vector_roundtrip_stays_local_across_call(self):
        _, _, _, safety, sites = _program([(0x1000, "roundtrip", [
            ("csrr", "t0,vlenb"), ("vmv.s.x", "v8,t0"), ("li", "t0,0"),
            ("vmv.x.s", "s4,v8"), ("jal", "ra,2000 <callee>"),
            ("add", "t1,s4,zero"), ("li", "a0,0"), ("ret", "")]),
            (0x2000, "callee", [("li", "a0,0"), ("ret", "")])])
        self.assertIn(WIDTH, safety.records[sites["roundtrip"][4]].reasons)
        self.assertIn(WIDTH, safety.records[sites["roundtrip"][5]].reasons)

    def test_nonstack_width_store_warns_without_pinning_later_independent_call(self):
        _, _, stack, safety, sites = _program([(0x1000, "store", [
            ("csrr", "s4,vlenb"), ("li", "s1,8192"), ("sd", "s4,0(s1)"),
            ("li", "s4,0"), ("jal", "ra,2000 <callee>"), ("li", "a0,0"), ("ret", "")]),
            (0x2000, "callee", [("li", "a0,0"), ("ret", "")])])
        self.assertTrue(any(w.code == "escaping-vlen-scalar-value" for w in stack.warnings))
        self.assertTrue(safety.records[sites["store"][4]].safe)
        self.assertTrue(any(origin.proof == "unsupported-nonstack-width-data"
                            and not origin.gaps
                            for warning in stack.warnings
                            for origin in warning.origins
                            if sites["store"][2] in warning.addresses))

    def test_spill_reload_preserves_local_width_content(self):
        _, _, _, safety, sites = _program([(0x1000, "spill", [
            ("addi", "sp,sp,-32"), ("csrr", "t0,vlenb"), ("sd", "t0,8(sp)"),
            ("li", "t0,0"), ("ld", "s4,8(sp)"), ("add", "t1,s4,zero"),
            ("addi", "sp,sp,32"), ("li", "a0,0"), ("ret", "")])])
        self.assertIn(WIDTH, safety.records[sites["spill"][4]].reasons)
        self.assertIn(WIDTH, safety.records[sites["spill"][5]].reasons)


if __name__ == "__main__":
    unittest.main()
