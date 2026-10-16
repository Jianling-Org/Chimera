"""Local ABI cache scope and the separate optional scalar-leaf effect API."""
from pathlib import Path
from dataclasses import replace
import tempfile
import unittest
from unittest.mock import patch

from chimera.check_elf import collect_diagnostics
from chimera.preprocess.offline.analysis.arch.riscv.rvv import RvvServices
from chimera.preprocess.offline.analysis.arch.riscv.services import RiscvServices
from chimera.preprocess.offline.analysis.program_model.parser import parse_dump
from chimera.preprocess.offline.analysis.toolchain.objdump import LinuxObjdump
from chimera.preprocess.offline.analysis.safety.classifier import classify_liveness
from chimera.preprocess.offline.analysis.safety.stack_liveness import (
    ChimeraMetadata, StackLivenessAnalyzer,
)
from chimera.preprocess.offline.analysis.safety.stack_liveness.model import CallTargetEntry
from chimera.preprocess.offline.analysis.safety.stack_liveness.origins import OriginProver


WIDTH = 'live_vlen_scalar_data'


def make_program(caller, *callees):
    """Addresses come from the specs, including branch references by index."""
    specs = [(0x1000, 'caller', caller)] + [
        (0x2000 + 0x1000 * index, f'callee{index}', body)
        for index, body in enumerate(callees)
    ]
    lines = []
    for start, name, body in specs:
        lines.append(f'\n{start:016x} <{name}>:')
        for index, (op, args) in enumerate(body):
            if callable(args):
                args = args(tuple(start + 4 * i for i in range(len(body))))
            lines.append(f' {start + 4 * index:x}:\t00000013\t{op}\t{args}')
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / 'leaf.dump'
        path.write_text('\n'.join(lines) + '\n', encoding='utf-8')
        rvv = RvvServices()
        program = RiscvServices(rvv).build_cfg(parse_dump(path, LinuxObjdump('objdump').parse_format))
    return program, rvv


class ScalarWidthCallEffectsTests(unittest.TestCase):
    def analyze(self, caller, *callees, targets=None, summary_budget=None):
        program, rvv = make_program(caller, *callees)
        calls = [i for i in program.functions[0].insts if rvv.stack_semantics.is_call_instruction(i)]
        metadata = (ChimeraMetadata(function_pointer={calls[0].addr: CallTargetEntry(
            calls[0].addr, tuple(targets))}) if targets is not None else ChimeraMetadata.empty())
        options = {} if summary_budget is None else {'summary_budget': summary_budget}
        prover = OriginProver(program, rvv.stack_semantics, metadata=metadata, **options)
        stack = StackLivenessAnalyzer(semantics=rvv.stack_semantics, emit_warnings=False).analyze_program(
            program, metadata=metadata, config_results=rvv.vector_configs(program), prover=prover)
        safety = classify_liveness(program, rvv.vector_liveness(program), stack,
                                   rvv.classify_vector_liveness)
        return safety, stack, tuple(i.addr for i in program.functions[0].insts), prover

    def assert_no_escape(self, stack):
        # Informational live-call snapshots are allowed; they do not create
        # unresolved effects or ask a callee-body prover to discharge them.
        for warning in stack.warnings:
            if warning.code == 'escaping-vlen-scalar-value':
                for origin in warning.origins:
                    evidence = origin.width_evidence
                    self.assertIsNotNone(evidence)
                    self.assertFalse(evidence.prior_unclosed_effect)
                    if evidence.call_effect is not None:
                        self.assertEqual(evidence.call_effect.status, 'not-requested')

    def test_actual_constant_overwrite_ends_the_only_cache(self):
        safety, stack, sites, _ = self.analyze([
            ('csrr', 'a0,vlenb'), ('jal', 'ra,2000 <callee0>'), ('ret', '')],
            [('li', 'a0,0'), ('ret', '')])
        self.assertTrue(safety.records[sites[1]].safe)
        self.assertTrue(safety.records[sites[2]].safe)
        self.assert_no_escape(stack)

    def test_callee_copy_to_return_does_not_import_argument_taint(self):
        safety, stack, sites, _ = self.analyze([
            ('csrr', 't0,vlenb'), ('jal', 'ra,2000 <callee0>'),
            ('mv', 's4,a0'), ('add', 't1,s4,zero'), ('li', 'a0,0'), ('ret', '')],
            [('mv', 'a0,t0'), ('ret', '')])
        for index in (1, 2, 3):
            self.assertNotIn(WIDTH, safety.records[sites[index]].reasons)
        self.assert_no_escape(stack)

    def test_callee_temporary_result_does_not_import_argument_taint(self):
        safety, stack, sites, _ = self.analyze([
            ('csrr', 'a2,vlenb'), ('jal', 'ra,2000 <callee0>'),
            ('li', 'a2,0'), ('add', 't1,t0,zero'), ('ret', '')],
            [('mv', 't0,a2'), ('ret', '')])
        self.assertNotIn(WIDTH, safety.records[sites[3]].reasons)
        self.assert_no_escape(stack)

    def test_surviving_caller_copy_is_not_erased_by_a0_overwrite(self):
        safety, stack, sites, _ = self.analyze([
            ('csrr', 'a0,vlenb'), ('mv', 's4,a0'), ('jal', 'ra,2000 <callee0>'),
            ('add', 't1,s4,zero'), ('ret', '')], [('li', 'a0,0'), ('ret', '')])
        self.assertIn(WIDTH, safety.records[sites[2]].reasons)
        self.assertIn(WIDTH, safety.records[sites[3]].reasons)
        self.assert_no_escape(stack)

    def test_actual_call_target_is_live_without_tainting_callee_output(self):
        safety, stack, sites, _ = self.analyze([
            ('csrr', 'a0,vlenb'), ('jalr', 'a0'), ('add', 't0,a0,zero'),
            ('li', 'a0,0'), ('ret', '')], [('li', 'a0,7'), ('ret', '')], targets=(0x2000,))
        self.assertIn(WIDTH, safety.records[sites[1]].reasons)
        self.assertNotIn(WIDTH, safety.records[sites[2]].reasons)
        self.assert_no_escape(stack)

    def test_guarded_overwrite_has_selection_diagnostics_without_cache_content(self):
        safety, stack, sites, _ = self.analyze([
            ('mv', 's1,ra'), ('li', 'a0,32'), ('csrr', 't2,vlenb'),
            ('beqz', lambda pcs: f't2,{pcs[5]:x}'), ('jal', 'ra,2000 <callee0>'),
            ('add', 't0,a0,zero'), ('li', 'a0,0'), ('mv', 'ra,s1'), ('ret', '')],
            [('li', 'a0,16'), ('ret', '')])
        self.assertNotIn(WIDTH, safety.records[sites[5]].reasons)
        self.assert_no_escape(stack)

    def test_multiple_targets_do_not_extend_an_abi_volatile_cache_epoch(self):
        safety, stack, sites, _ = self.analyze([
            ('csrr', 't0,vlenb'), ('jalr', 't2'), ('add', 't1,t0,zero'), ('ret', '')],
            [('li', 't0,0'), ('ret', '')], [('nop', ''), ('ret', '')], targets=(0x2000, 0x3000))
        self.assertNotIn(WIDTH, safety.records[sites[1]].reasons)
        self.assertNotIn(WIDTH, safety.records[sites[2]].reasons)
        self.assert_no_escape(stack)

    def test_private_dead_spill_is_not_a_leaf_call_escape(self):
        safety, stack, sites, _ = self.analyze([
            ('addi', 'sp,sp,-64'), ('csrr', 't0,vlenb'), ('sd', 't0,8(sp)'),
            ('li', 't0,0'), ('jal', 'ra,2000 <callee0>'),
            ('addi', 'sp,sp,64'), ('ret', '')], [('li', 'a0,0'), ('ret', '')])
        self.assertTrue(safety.records[sites[4]].safe)
        self.assert_no_escape(stack)

    def test_private_spill_with_later_reload_stays_live_through_leaf_call(self):
        safety, stack, sites, _ = self.analyze([
            ('addi', 'sp,sp,-64'), ('csrr', 't0,vlenb'), ('sd', 't0,8(sp)'),
            ('li', 't0,0'), ('jal', 'ra,2000 <callee0>'), ('ld', 's4,8(sp)'),
            ('add', 't1,s4,zero'), ('addi', 'sp,sp,64'), ('ret', '')],
            [('li', 'a0,0'), ('ret', '')])
        for index in (4, 5, 6):
            self.assertIn(WIDTH, safety.records[sites[index]].reasons)
        self.assert_no_escape(stack)

    def test_callee_parameter_store_is_outside_local_value_propagation(self):
        safety, stack, sites, _ = self.analyze([
            ('csrr', 'a0,vlenb'), ('li', 'a1,8192'), ('jal', 'ra,2000 <callee0>'), ('ret', '')],
            [('sd', 'a0,0(a1)'), ('li', 'a0,0'), ('ret', '')])
        self.assertNotIn(WIDTH, safety.records[sites[3]].reasons)
        self.assert_no_escape(stack)

    def test_local_abi_epoch_does_not_require_a_callee_summary_budget(self):
        safety, stack, sites, prover = self.analyze([
            ('csrr', 'a0,vlenb'), ('jal', 'ra,2000 <callee0>'), ('ret', '')],
            [('li', 'a0,0'), ('ret', '')], summary_budget=0)
        self.assertNotIn(WIDTH, safety.records[sites[2]].reasons)
        self.assertFalse(prover._scalar_leaf_effects)

    def test_sp_stays_live_but_a_callee_return_is_not_a_local_width_copy(self):
        safety, stack, sites, _ = self.analyze([
            ('csrr', 's5,vlenb'), ('sub', 'sp,sp,s5'), ('jal', 'ra,2000 <callee0>'),
            ('add', 'sp,sp,s5'), ('mv', 's4,a0'), ('add', 't1,s4,zero'),
            ('li', 'a0,0'), ('ret', '')], [('mv', 'a0,sp'), ('ret', '')])
        self.assertIn(WIDTH, safety.records[sites[2]].reasons)
        self.assertNotIn(WIDTH, safety.records[sites[5]].reasons)

    def test_constant_intermediate_is_not_reintroduced_as_entry_input(self):
        safety, stack, sites, _ = self.analyze([
            ('csrr', 'a0,vlenb'), ('jal', 'ra,2000 <callee0>'), ('ret', '')],
            [('li', 'a0,0'), ('addi', 'a0,a0,1'), ('ret', '')])
        self.assertTrue(safety.records[sites[1]].safe)
        self.assertTrue(safety.records[sites[2]].safe)
        self.assert_no_escape(stack)

    def test_no_local_return_copy_is_synthesized_before_actual_overwrites(self):
        safety, stack, sites, _ = self.analyze([
            ('csrr', 't0,vlenb'), ('jal', 'ra,2000 <callee0>'),
            ('li', 't0,0'), ('li', 'a0,0'), ('nop', ''), ('ret', '')],
            [('mv', 'a0,t0'), ('ret', '')])
        self.assertNotIn(WIDTH, safety.records[sites[1]].reasons)
        self.assertTrue(safety.records[sites[4]].safe)
        self.assert_no_escape(stack)

    def test_all_targets_overwriting_a_register_can_end_its_cache(self):
        safety, stack, sites, _ = self.analyze([
            ('csrr', 'a0,vlenb'), ('jalr', 't2'), ('ret', '')],
            [('li', 'a0,0'), ('ret', '')], [('li', 'a0,1'), ('ret', '')], targets=(0x2000, 0x3000))
        self.assertTrue(safety.records[sites[1]].safe)
        self.assertTrue(safety.records[sites[2]].safe)
        self.assert_no_escape(stack)

    def test_new_ra_link_does_not_carry_the_callers_old_width_value(self):
        safety, stack, sites, _ = self.analyze([
            ('csrr', 'ra,vlenb'), ('jal', 'ra,2000 <callee0>'), ('ret', '')],
            [('mv', 'a0,ra'), ('ret', '')])
        self.assertTrue(safety.records[sites[1]].safe)
        self.assertTrue(safety.records[sites[2]].safe)
        self.assert_no_escape(stack)

    def test_no_width_fast_path_does_not_request_callee_effects(self):
        _, _, _, prover = self.analyze([
            ('li', 'a0,1'), ('jal', 'ra,2000 <callee0>'), ('ret', '')],
            [('li', 'a0,0'), ('ret', '')])
        self.assertFalse(prover._scalar_leaf_effects)

    def test_callee_arithmetic_does_not_import_parameter_width_into_return(self):
        safety, stack, sites, _ = self.analyze([
            ('csrr', 'a0,vlenb'), ('jal', 'ra,2000 <callee0>'), ('add', 's4,a0,zero'),
            ('li', 'a0,0'), ('ret', '')],
            [('slli', 't0,a0,1'), ('sub', 'a0,t0,a0'), ('li', 't0,0'), ('ret', '')])
        self.assertNotIn(WIDTH, safety.records[sites[2]].reasons)
        self.assert_no_escape(stack)

    def test_vector_roundtrip_with_known_leaf_has_no_permanent_call_escape(self):
        safety, stack, sites, _ = self.analyze([
            ('csrr', 'a2,vlenb'), ('vmv.s.x', 'v8,a2'), ('li', 'a2,0'),
            ('vmv.x.s', 's4,v8'), ('jal', 'ra,2000 <callee0>'),
            ('add', 't0,s4,zero'), ('ret', '')], [('li', 'a0,0'), ('ret', '')])
        self.assertIn(WIDTH, safety.records[sites[4]].reasons)
        self.assertIn(WIDTH, safety.records[sites[5]].reasons)
        self.assert_no_escape(stack)

    def test_callee_proof_refusal_does_not_extend_local_volatile_inputs(self):
        for body, options in (
            ([('mv', 'a0,t0'), ('fence', ''), ('ret', '')], {}),
            ([('mv', 'a0,t0'), ('ret', '')], {'summary_budget': 0}),
        ):
            with self.subTest(body=body, options=options):
                safety, stack, sites, _ = self.analyze([
                    ('csrr', 't0,vlenb'), ('jal', 'ra,2000 <callee0>'), ('li', 't0,0'),
                    ('add', 's4,a0,zero'), ('li', 'a0,0'), ('ret', '')], body, **options)
                self.assertNotIn(WIDTH, safety.records[sites[1]].reasons)
                self.assertNotIn(WIDTH, safety.records[sites[3]].reasons)
                self.assert_no_escape(stack)

    def test_missing_body_does_not_import_a_volatile_input_or_return_cache(self):
        safety, stack, sites, _ = self.analyze([
            ('csrr', 't0,vlenb'), ('jal', 'ra,9000 <missing>'), ('li', 't0,0'),
            ('add', 's4,a0,zero'), ('li', 'a0,0'), ('ret', '')])
        self.assertNotIn(WIDTH, safety.records[sites[1]].reasons)
        self.assertNotIn(WIDTH, safety.records[sites[3]].reasons)
        self.assert_no_escape(stack)

    def test_missing_callee_does_not_invent_a_use_of_dead_volatile_input(self):
        safety, _, sites, _ = self.analyze([
            ('csrr', 't0,vlenb'), ('nop', ''), ('jal', 'ra,9000 <missing>'),
            ('li', 't0,0'), ('add', 's4,a0,zero'), ('li', 'a0,0'), ('ret', '')])
        self.assertNotIn(WIDTH, safety.records[sites[1]].reasons)

    def test_local_preserved_copy_reaches_the_finding_and_gate_source_chain(self):
        program, _ = make_program([
            ('csrr', 's4,vlenb'), ('jal', 'ra,2000 <callee0>'), ('li', 't0,0'),
            ('jal', 'ra,9000 <external>'), ('mv', 't1,s4'), ('ret', '')],
            [('mv', 'a0,t0'), ('ret', '')])
        call = program.functions[0].insts[3].addr
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'test-seam.elf'
            path.write_bytes(b'\x7fELF\x02\x01\x01' + b'\0' * 24)
            result = collect_diagnostics(path, objdump_cmd='objdump', strategy='gate',
                dump_text='\n'.join(program.dump_lines), metadata=ChimeraMetadata.empty())
        self.assertIn('caller', result.gate_names)
        self.assertTrue(any(f.call_site == hex(call) for f in result.findings))

    def test_dead_register_cache_does_not_pin_a_proven_nonreading_call(self):
        safety, stack, sites, _ = self.analyze([
            ('csrr', 's4,vlenb'), ('nop', ''), ('jal', 'ra,2000 <callee0>'), ('ret', '')],
            [('li', 'a0,0'), ('ret', '')])
        self.assertTrue(safety.records[sites[1]].safe)
        self.assertTrue(safety.records[sites[2]].safe)
        self.assert_no_escape(stack)

    def test_standard_call_ends_a_vector_cache_epoch_without_importing_a_return(self):
        safety, stack, sites, _ = self.analyze([
            ('csrr', 'a2,vlenb'), ('vmv.s.x', 'v8,a2'), ('li', 'a2,0'),
            ('nop', ''), ('jal', 'ra,2000 <callee0>'), ('vmv1r.v', 'v8,v16'),
            ('add', 's4,a0,zero'), ('li', 'a0,0'), ('ret', '')],
            [('vmv.x.s', 'a0,v8'), ('ret', '')])
        self.assertNotIn(WIDTH, safety.records[sites[3]].reasons)
        self.assertNotIn(WIDTH, safety.records[sites[6]].reasons)
        self.assert_no_escape(stack)

    def test_dead_vector_copy_is_not_an_escape_through_proven_scalar_leaf(self):
        safety, stack, sites, _ = self.analyze([
            ('csrr', 'a2,vlenb'), ('vmv.s.x', 'v8,a2'), ('li', 'a2,0'),
            ('jal', 'ra,2000 <callee0>'), ('vmv1r.v', 'v8,v16'), ('ret', '')],
            [('li', 'a0,0'), ('ret', '')])
        self.assertTrue(safety.records[sites[3]].safe)
        self.assert_no_escape(stack)


class ScalarLeafCertificateTests(unittest.TestCase):
    def prepare(self, body, *, call=('jal', 'ra,2000 <callee0>'), metadata=None,
                summary_budget=128, other=()):
        program, rvv = make_program([call, ('ret', '')], body, *other)
        prover = OriginProver(program, rvv.stack_semantics,
                              metadata=metadata, summary_budget=summary_budget)
        return program, rvv, prover

    def effect(self, body, **options):
        program, _, prover = self.prepare(body, **options)
        return prover.scalar_leaf_call_effects(program.functions[0].insts[0])

    def test_positive_effect_names_actual_reads_and_independent_outputs(self):
        effect = self.effect([('mv', 't1,t0'), ('li', 'a0,0'), ('addi', 'a0,a0,1'), ('ret', '')])
        self.assertIsNotNone(effect)
        self.assertIn('t0', effect.entry_reads)
        self.assertNotIn('a0', effect.entry_reads)
        self.assertEqual(dict(effect.register_dependencies), {'a0': frozenset(), 't1': frozenset({'t0'})})

    def test_memory_vector_csr_fp_system_and_unknown_effects_refuse(self):
        for instruction in (
            ('ld', 't0,0(a1)'), ('sd', 'a0,0(a1)'), ('sc.d', 't0,a0,0(a1)'),
            ('vsetvli', 'zero,zero,e32,m1,ta,ma'), ('vmv.v.x', 'v8,a0'),
            ('csrr', 't0,vlenb'), ('fmv.d.x', 'fa0,a0'), ('fence', ''),
            ('ecall', ''), ('custom', 't0,a0'),
        ):
            with self.subTest(instruction=instruction):
                self.assertIsNone(self.effect([instruction, ('li', 'a0,0'), ('ret', '')]))

    def test_unsupported_value_dependency_is_not_accepted_after_later_cover(self):
        self.assertIsNone(self.effect([('div', 't0,a0,a1'), ('li', 't0,0'), ('ret', '')]))

    def test_protected_register_writes_refuse_even_when_value_is_constant(self):
        for register in ('sp', 'gp', 'tp', 'ra', 's0', 's4', 's11', 'x2', 'fp'):
            with self.subTest(register=register):
                self.assertIsNone(self.effect([('li', f'{register},0'), ('ret', '')]))

    def test_malformed_and_fp_operands_never_supply_a_capability(self):
        for instruction in (('li', 'a0,label'), ('li', 'a0,1,2'), ('mv', 'a0,fa0'),
                            ('add', 'a0,a1,unknown'), ('nop', 'a0'), ('ret', 'a0')):
            with self.subTest(instruction=instruction):
                self.assertIsNone(self.effect([instruction, ('ret', '')]))

    def test_privileged_return_does_not_satisfy_the_normal_call_contract(self):
        for op in ('mret', 'sret', 'uret'):
            with self.subTest(op=op):
                self.assertIsNone(self.effect([('li', 'a0,0'), (op, '')]))

    def test_64_instruction_limit_includes_the_return(self):
        self.assertIsNotNone(self.effect([('nop', '')] * 63 + [('ret', '')]))
        self.assertIsNone(self.effect([('nop', '')] * 64 + [('ret', '')]))

    def test_branch_loop_nested_call_and_early_return_refuse(self):
        for body in (
            [('beqz', lambda pcs: f'a1,{pcs[2]:x}'), ('li', 'a0,0'), ('ret', '')],
            [('j', lambda pcs: f'{pcs[0]:x}'), ('ret', '')],
            [('jal', 'ra,2000 <callee0>'), ('ret', '')],
            [('ret', ''), ('li', 'a0,0'), ('ret', '')],
        ):
            with self.subTest(body=body):
                self.assertIsNone(self.effect(body))

    def test_incomplete_or_unbuilt_cfg_does_not_supply_effects(self):
        for corruption in ('gap', 'unbuilt', 'external-edge', 'extra-entry'):
            with self.subTest(corruption=corruption):
                program, _, prover = self.prepare([('li', 'a0,0'), ('ret', '')])
                callee = program.functions[1]
                if corruption == 'gap':
                    callee.insts[0].size = 2
                elif corruption == 'unbuilt':
                    callee.blocks.clear()
                elif corruption == 'external-edge':
                    callee.insts[0].succ.add(0x8000)
                else:
                    callee.insts[-1].jump_sources.add(program.functions[0].start)
                self.assertIsNone(prover.scalar_leaf_call_effects(program.functions[0].insts[0]))

    def test_missing_or_external_alternative_never_uses_internal_subset(self):
        for targets in ((0x2000, 0x9000), (0x2000, 0x3000)):
            with self.subTest(targets=targets):
                metadata = ChimeraMetadata(function_pointer={0x1000: CallTargetEntry(0x1000, targets)})
                program, _, prover = self.prepare([('li', 'a0,0'), ('ret', '')],
                    call=('jalr', 't2'), metadata=metadata, other=([('ret', '')],))
                program.functions[-1].is_external_trampoline = True
                self.assertIsNone(prover.scalar_leaf_call_effects(program.functions[0].insts[0]))

    def test_indirect_metadata_alternatives_are_not_pruned_by_objdump_comment(self):
        metadata = ChimeraMetadata(function_pointer={0x1000: CallTargetEntry(0x1000, (0x2000, 0x9000))})
        self.assertIsNone(self.effect([('li', 'a0,0'), ('ret', '')],
            call=('jalr', 't2 # 2000 <callee0>'), metadata=metadata))

    def test_complete_indirect_metadata_keeps_the_other_targets_entry_copy(self):
        metadata = ChimeraMetadata(function_pointer={0x1000: CallTargetEntry(0x1000, (0x2000, 0x3000))})
        effect = self.effect([('li', 'a0,0'), ('ret', '')],
            call=('jalr', 't2 # 2000 <callee0>'), metadata=metadata, other=([('ret', '')],))
        self.assertIsNotNone(effect)
        self.assertEqual(dict(effect.register_dependencies)['a0'], frozenset({'a0'}))

    def test_explicit_empty_target_metadata_cannot_be_replaced_by_comment(self):
        metadata = ChimeraMetadata(function_pointer={0x1000: CallTargetEntry(0x1000, ())})
        self.assertIsNone(self.effect([('li', 'a0,0'), ('ret', '')],
            call=('jalr', 't2 # 2000 <callee0>'), metadata=metadata))

    def test_alternate_link_register_is_outside_the_standard_ra_capability(self):
        self.assertIsNone(self.effect([('li', 'a0,0'), ('ret', '')], call=('jal', 't0,2000 <callee0>')))

    def test_default_false_capability_cannot_be_treated_as_a_clean_summary(self):
        program, rvv, prover = self.prepare([('li', 'a0,0'), ('ret', '')])
        original = rvv.stack_semantics.scalar_width_facts
        with patch.object(rvv.stack_semantics, 'scalar_width_facts',
                          side_effect=lambda i: replace(original(i), register_only=False)):
            self.assertIsNone(prover.scalar_leaf_call_effects(program.functions[0].insts[0]))

    def test_effect_cache_is_shared_by_calls_and_charged_to_summary_budget(self):
        program, rvv, prover = self.prepare([('li', 'a0,0'), ('ret', '')], summary_budget=1)
        call = program.functions[0].insts[0]
        first = prover.scalar_leaf_call_effects(call)
        self.assertIsNotNone(first)
        self.assertEqual(first, prover.scalar_leaf_call_effects(call))
        self.assertEqual(prover._summary_requests, 1)
        self.assertIsNone(prover._summary(program.functions[1].start))
        self.assertTrue(prover.budget_exhausted)


if __name__ == '__main__':
    unittest.main()
