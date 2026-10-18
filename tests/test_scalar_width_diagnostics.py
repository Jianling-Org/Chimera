"""Read-only effect diagnostics and v30 local-cache input observations."""
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from chimera.check_elf import (
    _build_inheritance_diagnostics, _diagnostics_payload, _origins_payload, collect_diagnostics,
)
from chimera.preprocess.offline.analysis.safety.stack_liveness import ChimeraMetadata
from chimera.preprocess.offline.analysis.safety.stack_liveness.model import CallTargetEntry
import test_scalar_width_call_effects as leaf_cases
from test_scalar_width_call_effects import make_program


class ScalarLeafDiagnosticTests(unittest.TestCase):
    def inspect(self, body, **options):
        program, _, prover = leaf_cases.ScalarLeafCertificateTests().prepare(body, **options)
        call = program.functions[0].insts[0]
        effect = prover.scalar_leaf_call_effects(call)
        self.assertTrue(hasattr(prover, 'scalar_leaf_call_diagnostic'),
                        'callee refusals need a cached structured diagnostic')
        return effect, prover.scalar_leaf_call_diagnostic(call), prover

    def test_memory_refusal_records_the_first_instruction(self):
        effect, diagnostic, _ = self.inspect([('ld', 't0,0(a1)'), ('li', 'a0,0'), ('ret', '')])
        self.assertIsNone(effect)
        self.assertEqual(diagnostic.status, 'refused')
        self.assertTrue(diagnostic.targets_complete)
        target = diagnostic.targets[0]
        self.assertEqual((target.target, target.reason, target.instruction, target.opcode),
                         (0x2000, 'memory-effects', 0x2000, 'ld'))
        self.assertEqual(target.instruction_count, 3)

    def test_accepted_diagnostic_is_not_an_extra_effect_analysis(self):
        effect, diagnostic, prover = self.inspect([('li', 'a0,0'), ('ret', '')])
        self.assertIsNotNone(effect)
        self.assertEqual(diagnostic.status, 'accepted')
        self.assertEqual(diagnostic.targets[0].status, 'accepted')
        requests = prover._summary_requests
        cache = dict(prover._scalar_leaf_effects)
        program, _ = make_program([('jal', 'ra,2000'), ('ret', '')], [('li', 'a0,0'), ('ret', '')])
        for _ in range(3):
            self.assertEqual(prover.scalar_leaf_call_diagnostic(program.functions[0].insts[0]), diagnostic)
        self.assertEqual(prover._summary_requests, requests)
        self.assertEqual(prover._scalar_leaf_effects, cache)

    def test_instruction_limit_is_named_without_a_fake_instruction_witness(self):
        effect, diagnostic, _ = self.inspect([('nop', '')] * 64 + [('ret', '')])
        self.assertIsNone(effect)
        target = diagnostic.targets[0]
        self.assertEqual(target.reason, 'instruction-limit-exceeded')
        self.assertEqual(target.instruction_count, 65)
        self.assertIsNone(target.instruction)

    def test_budget_refusal_preserves_the_original_budget_flag(self):
        effect, diagnostic, prover = self.inspect([('li', 'a0,0'), ('ret', '')], summary_budget=0)
        self.assertIsNone(effect)
        self.assertEqual(diagnostic.targets[0].reason, 'analysis-budget-exhausted')
        self.assertTrue(prover._budget_exhausted)
        self.assertEqual(prover._summary_requests, 0)

    def test_protected_register_write_has_a_concrete_witness(self):
        effect, diagnostic, _ = self.inspect([('li', 'sp,0'), ('ret', '')])
        self.assertIsNone(effect)
        self.assertEqual(diagnostic.targets[0].reason, 'protected-register-write')
        self.assertEqual(diagnostic.targets[0].registers, ('sp',))

    def test_unmodelled_and_nested_call_refusals_are_distinct(self):
        for instruction, reason in [(('custom', 't0,a0'), 'instruction-effects-unmodelled'),
                                    # The production CFG splits this recursive
                                    # call before the instruction capability pass.
                                    (('jal', 'ra,2000'), 'nonlinear-callee-cfg')]:
            with self.subTest(instruction=instruction):
                effect, diagnostic, _ = self.inspect([instruction, ('ret', '')])
                self.assertIsNone(effect)
                self.assertEqual(diagnostic.targets[0].reason, reason)

    def test_fp_register_effects_are_not_mislabeled_integer_protected_writes(self):
        effect, diagnostic, _ = self.inspect([('fmv.d.x', 'fa0,a0'), ('ret', '')])
        self.assertIsNone(effect)
        self.assertEqual(diagnostic.targets[0].reason, 'floating-point-effects')

    def test_unsupported_return_is_not_mislabeled_by_implicit_abi_fp_reads(self):
        for instruction in [('ret', 'a0'), ('mret', '')]:
            with self.subTest(instruction=instruction):
                effect, diagnostic, _ = self.inspect([('li', 'a0,0'), instruction])
                self.assertIsNone(effect)
                self.assertEqual(diagnostic.targets[0].reason, 'normal-return-unproven')

    def test_reporting_failure_cannot_replace_the_original_effect_result(self):
        program, _, prover = leaf_cases.ScalarLeafCertificateTests().prepare([('li', 'a0,0'), ('ret', '')])
        with patch.object(prover, '_declared_scalar_targets', side_effect=RuntimeError('diagnostic rendering')):
            try:
                effect = prover.scalar_leaf_call_effects(program.functions[0].insts[0])
            except RuntimeError:
                self.fail('diagnostic recording changed the original proof execution')
        self.assertIsNotNone(effect)
        diagnostic = prover.scalar_leaf_call_diagnostic(program.functions[0].insts[0])
        self.assertEqual(diagnostic.status, 'unavailable')
        self.assertEqual(diagnostic.reason, 'diagnostic-recording-failed')

    def test_missing_observation_of_a_cached_effect_does_not_restart_its_proof(self):
        _, _, prover = self.inspect([('li', 'a0,0'), ('ret', '')])
        prover._scalar_leaf_diagnostics.clear()
        program, _ = make_program([('jal', 'ra,2000'), ('ret', '')], [('li', 'a0,0'), ('ret', '')])
        requests = prover._summary_requests
        try:
            effect = prover.scalar_leaf_call_effects(program.functions[0].insts[0])
        except KeyError:
            self.fail('absent diagnostic metadata invalidated the cached proof result')
        self.assertIsNotNone(effect)
        self.assertEqual(prover._summary_requests, requests)
        self.assertEqual(prover.scalar_leaf_call_diagnostic(program.functions[0].insts[0]).targets[0].status, 'unavailable')

    def test_missing_direct_body_keeps_the_declared_target(self):
        effect, diagnostic, prover = self.inspect([('ret', '')], call=('jal', 'ra,9000 <missing>'))
        self.assertIsNone(effect)
        self.assertFalse(diagnostic.targets_complete)
        self.assertEqual(diagnostic.reason, 'missing-callee-body')
        self.assertEqual(diagnostic.targets[0].target, 0x9000)
        self.assertEqual(diagnostic.targets[0].status, 'unavailable')
        self.assertIn(0x9000, prover._missing_callees)

    def test_mixed_declared_targets_do_not_become_an_internal_subset_proof(self):
        metadata = ChimeraMetadata(function_pointer={0x1000: CallTargetEntry(0x1000, (0x2000, 0x9000))})
        effect, diagnostic, prover = self.inspect([('ret', '')], call=('jalr', 't2'), metadata=metadata)
        self.assertIsNone(effect)
        self.assertEqual(diagnostic.target_source, 'metadata')
        self.assertFalse(diagnostic.targets_complete)
        self.assertEqual([t.target for t in diagnostic.targets], [0x2000, 0x9000])
        self.assertEqual([t.status for t in diagnostic.targets], ['not-examined', 'unavailable'])
        self.assertFalse(prover._scalar_leaf_effects)

    def test_refusal_does_not_analyze_the_remaining_targets_for_reporting(self):
        metadata = ChimeraMetadata(function_pointer={0x1000: CallTargetEntry(0x1000, (0x2000, 0x3000))})
        effect, diagnostic, prover = self.inspect([('ld', 't0,0(a1)'), ('ret', '')],
            call=('jalr', 't2'), metadata=metadata, other=([('li', 'a0,0'), ('ret', '')],))
        self.assertIsNone(effect)
        self.assertTrue(diagnostic.targets_complete)
        self.assertEqual([t.status for t in diagnostic.targets], ['refused', 'not-examined'])
        self.assertNotIn(0x3000, prover._scalar_leaf_effects)
        self.assertEqual(prover._summary_requests, 0)

    def test_getter_before_a_request_does_no_resolution_or_proof_work(self):
        program, _, prover = leaf_cases.ScalarLeafCertificateTests().prepare([('li', 'a0,0'), ('ret', '')])
        self.assertTrue(hasattr(prover, 'scalar_leaf_call_diagnostic'))
        self.assertIsNone(prover.scalar_leaf_call_diagnostic(program.functions[0].insts[0]))
        self.assertFalse(prover._scalar_leaf_effects)
        self.assertEqual(prover._summary_requests, 0)

    def test_target_display_bound_does_not_shortcut_the_actual_complete_proof(self):
        callees = [[('li', 'a0,0'), ('ret', '')] for _ in range(65)]
        targets = tuple(0x2000 + 0x1000 * i for i in range(65))
        metadata = ChimeraMetadata(function_pointer={0x1000: CallTargetEntry(0x1000, targets)})
        effect, diagnostic, prover = self.inspect(callees[0], call=('jalr', 't2'),
            metadata=metadata, other=tuple(callees[1:]))
        self.assertIsNotNone(effect)
        self.assertTrue(diagnostic.targets_complete)
        self.assertEqual(diagnostic.target_count, 65)
        self.assertEqual(len(diagnostic.targets), 64)
        self.assertTrue(diagnostic.truncated)
        self.assertEqual(prover._summary_requests, 65)

    def test_first_refusal_beyond_the_target_display_limit_is_not_lost(self):
        callees = [[('li', 'a0,0'), ('ret', '')] for _ in range(64)]
        callees += [[('ld', 't0,0(a1)'), ('ret', '')]]
        targets = tuple(0x2000 + 0x1000 * i for i in range(65))
        metadata = ChimeraMetadata(function_pointer={0x1000: CallTargetEntry(0x1000, targets)})
        effect, diagnostic, prover = self.inspect(callees[0], call=('jalr', 't2'),
            metadata=metadata, other=tuple(callees[1:]))
        self.assertIsNone(effect)
        refusal = getattr(diagnostic, 'first_refusal', None)
        self.assertIsNotNone(refusal, 'the real rejecting target must survive display truncation')
        self.assertEqual((refusal.target, refusal.reason), (targets[-1], 'memory-effects'))
        self.assertEqual(len(diagnostic.targets), 64)
        self.assertTrue(diagnostic.truncated)
        self.assertEqual(prover._summary_requests, 64)


class WidthInputDiagnosticTests(unittest.TestCase):
    def analyze(self, body, *callees, **options):
        return leaf_cases.ScalarWidthCallEffectsTests().analyze(body, *callees, **options)

    def evidence(self, stack, site):
        warnings = [w for w in stack.warnings if w.code == 'escaping-vlen-scalar-value' and site in w.addresses]
        self.assertTrue(warnings)
        origin = warnings[0].origins[0]
        self.assertIsNotNone(getattr(origin, 'width_evidence', None), 'width warning needs a structured input snapshot')
        return origin.width_evidence

    def test_live_call_snapshot_names_the_actual_preserved_local_copy(self):
        _, stack, sites, _ = self.analyze([
            ('csrr', 's4,vlenb'), ('jal', 'ra,9000'), ('mv', 't1,s4'), ('ret', '')])
        evidence = self.evidence(stack, sites[1])
        self.assertEqual(evidence.kind, 'call')
        self.assertIn('s4', evidence.width_registers)
        self.assertIn('s4', evidence.live_width_registers)
        self.assertEqual(evidence.call_effect.status, 'not-requested')

    def test_snapshot_distinguishes_dead_vector_copy_from_live_extracted_scalar(self):
        _, stack, sites, _ = self.analyze([
            ('csrr', 'a2,vlenb'), ('vmv.s.x', 'v8,a2'), ('li', 'a2,0'),
            ('vmv.x.s', 's4,v8'), ('jal', 'ra,2000'),
            ('vmv1r.v', 'v8,v16'), ('mv', 't1,s4'), ('ret', '')],
            [('vmv.x.s', 'a0,v8'), ('ret', '')])
        evidence = self.evidence(stack, sites[4])
        self.assertIn(8, evidence.width_vectors)
        self.assertNotIn(8, evidence.live_width_vectors)
        self.assertIn('s4', evidence.live_width_registers)
        self.assertNotIn('a2', evidence.width_registers)
        self.assertEqual(evidence.call_effect.status, 'not-requested')

    def test_private_spill_inputs_are_compacted_into_byte_intervals(self):
        _, stack, sites, _ = self.analyze([
            ('addi', 'sp,sp,-64'), ('csrr', 't0,vlenb'), ('sd', 't0,8(sp)'), ('li', 't0,0'),
            ('jal', 'ra,2000'), ('ld', 's4,8(sp)'), ('mv', 't1,s4'),
            ('addi', 'sp,sp,64'), ('ret', '')],
            [('ld', 't0,0(a1)'), ('li', 'a0,0'), ('ret', '')])
        evidence = self.evidence(stack, sites[4])
        self.assertEqual(evidence.frame_byte_count, 8)
        self.assertEqual(evidence.frame_intervals, ((-56, -48),))
        self.assertEqual(evidence.live_frame_intervals, ((-56, -48),))

    def test_guarded_constant_spill_is_a_store_warning_without_width_bytes(self):
        safety, stack, sites, _ = self.analyze([
            ('addi', 'sp,sp,-64'), ('li', 't0,16'), ('csrr', 'a2,vlenb'),
            ('beqz', lambda pcs: f'a2,{pcs[5]:x}'), ('sd', 't0,8(sp)'),
            ('li', 'a2,0'), ('jal', 'ra,9000'), ('addi', 'sp,sp,64'), ('ret', '')])
        evidence = self.evidence(stack, sites[4])
        self.assertEqual(evidence.control_addresses, (sites[3],))
        self.assertEqual(evidence.frame_intervals, ())
        self.assertTrue(evidence.memory_private)
        self.assertNotIn('live_vlen_scalar_data', safety.records[sites[6]].reasons)

    def test_vector_content_and_address_dependencies_are_separate(self):
        _, stack, sites, _ = self.analyze([
            ('li', 's1,8192'), ('csrr', 'a2,vlenb'), ('vmv.s.x', 'v8,a2'),
            ('li', 'a2,0'), ('vs1r.v', 'v8,(s1)'), ('li', 'a0,0'), ('ret', '')])
        evidence = self.evidence(stack, sites[4])
        self.assertEqual(evidence.kind, 'vector-store')
        self.assertIn(8, evidence.content_vectors)
        self.assertFalse(evidence.address_registers)
        self.assertFalse(evidence.control_addresses)
        self.assertFalse(evidence.memory_private)

    def test_chunk_address_dependency_is_not_labeled_width_content(self):
        _, stack, sites, _ = self.analyze([
            ('vsetvli', 'a2,a1,e32,m1,ta,ma'), ('slli', 't0,a2,2'), ('add', 's1,s1,t0'),
            ('vse32.v', 'v8,(s1)'), ('li', 'a2,0'), ('li', 's1,0'), ('li', 't0,0'),
            ('li', 'a0,0'), ('ret', '')])
        evidence = self.evidence(stack, sites[3])
        self.assertFalse(evidence.content_vectors)
        self.assertEqual(evidence.address_registers, ())
        self.assertIn('s1', evidence.selection_registers)
        self.assertFalse(evidence.control_addresses)

    def test_width_controlled_store_keeps_its_guard_address(self):
        _, stack, sites, _ = self.analyze([
            ('csrr', 't2,vlenb'), ('beqz', lambda pcs: f't2,{pcs[3]:x}'),
            ('vs1r.v', 'v8,(s1)'), ('li', 't2,0'), ('li', 'a0,0'), ('ret', '')])
        evidence = self.evidence(stack, sites[2])
        self.assertEqual(evidence.control_addresses, (sites[1],))
        self.assertFalse(evidence.content_vectors)
        self.assertFalse(evidence.address_registers)

    def test_return_does_not_invent_a_possible_abi_result_observation(self):
        safety, stack, sites, _ = self.analyze([('csrr', 'a0,vlenb'), ('ret', '')])
        self.assertFalse(any(sites[1] in warning.addresses for warning in stack.warnings))
        self.assertNotIn('live_vlen_scalar_data', safety.records[sites[1]].reasons)

    def test_fragment_display_limit_preserves_the_total_and_unsafe_state(self):
        body = [('addi', 'sp,sp,-2048'), ('csrr', 't0,vlenb')]
        body += [('sd', f't0,{16 * i}(sp)') for i in range(70)]
        body += [('li', 't0,0')]
        call_index = len(body)
        body += [('jal', 'ra,2000')]
        for index in range(70):
            body += [('ld', f't1,{16 * index}(sp)'), ('mv', 't2,t1')]
        body += [('addi', 'sp,sp,2048'), ('ret', '')]
        safety, stack, sites, _ = self.analyze(body, [('ld', 't0,0(a1)'), ('ret', '')])
        evidence = self.evidence(stack, sites[call_index])
        self.assertEqual(evidence.frame_byte_count, 560)
        self.assertEqual(evidence.frame_interval_count, 70)
        self.assertEqual(len(evidence.frame_intervals), 64)
        self.assertTrue(evidence.truncated)
        self.assertIn('live_vlen_scalar_data', safety.records[sites[call_index]].reasons)
        self.assertNotIn('live_vlen_scalar_data', safety.records[sites[-1]].reasons)

    def test_both_report_consumers_export_the_same_optional_evidence(self):
        caller = [('csrr', 's4,vlenb'), ('jal', 'ra,2000'), ('mv', 't1,s4'), ('ret', '')]
        program, _ = make_program(caller, [('ld', 't0,0(a1)'), ('ret', '')])
        with tempfile.TemporaryDirectory() as directory:
            elf = Path(directory) / 'fixture.elf'
            elf.write_bytes(b'\x7fELF\x02\x01\x01' + b'\0' * 24)
            content_hash = hashlib.sha256(elf.read_bytes()).hexdigest()
            result = collect_diagnostics(elf, objdump_cmd='objdump', strategy='gate',
                dump_text='\n'.join(program.dump_lines), metadata=ChimeraMetadata.empty())
        normal = _diagnostics_payload(result)
        inherited = _build_inheritance_diagnostics(result, content_hash)
        call_site = hex(program.functions[0].insts[1].addr)
        first = next(f for f in normal['warnings'] if call_site in f['addresses'] and f['diagnostic_code'] == 'escaping-vlen-scalar-value')
        second = next(f for f in inherited['warnings'] if call_site in f['addresses'] and f['diagnostic_code'] == 'escaping-vlen-scalar-value')
        self.assertIn('width_evidence', first['activity_origins'][0])
        evidence = first['activity_origins'][0]['width_evidence']
        self.assertEqual(evidence, second['activity_origins'][0]['width_evidence'])
        self.assertEqual(evidence['schema'], 'chimera-width-obligation-v1')
        self.assertEqual(evidence['call_effect']['status'], 'not-requested')
        self.assertFalse(first['actionable'])
        self.assertEqual(evidence['provenance_scope'], 'incoming-may-state')
        json.dumps(normal)
        json.dumps(inherited)

    def test_unrelated_origin_keeps_the_old_json_field_set(self):
        from chimera.preprocess.offline.analysis.safety.stack_liveness.model import ActiveOrigin
        origin = ActiveOrigin('inherited', 'caller', 'caller:inherited-stack-data', 'existing')
        self.assertEqual(set(_origins_payload((origin,))[0]),
                         {'origin', 'object', 'allocation', 'release', 'dependency', 'proof', 'gaps', 'detail',
                          'control_guard_address', 'width_source_candidates'})

    def test_old_origin_shape_without_the_optional_field_remains_serializable(self):
        from types import SimpleNamespace
        origin = SimpleNamespace(origin='inherited', object_id='caller:inherited-stack-data',
            allocation=None, release=None, dependency=None, proof=None, gaps=(), detail='existing')
        try:
            payload = _origins_payload((origin,))[0]
        except AttributeError:
            self.fail('optional diagnostic field broke the old origin serialization shape')
        self.assertNotIn('width_evidence', payload)

    def test_expression_labels_do_not_call_an_unbounded_full_renderer(self):
        from chimera.preprocess.offline.analysis.safety.stack_liveness.expressions import Expr
        from chimera.preprocess.offline.analysis.safety.stack_liveness.scalar_width import (
            _EMPTY, _Region, _diagnostic_expression, _width_evidence,
        )

        class RenderTrap(Expr):
            def __str__(self):
                raise AssertionError('full expression renderer must not run')

        program, rvv = make_program([('vse32.v', 'v8,(s1)'), ('ret', '')])
        instruction = program.functions[0].insts[0]
        fact = rvv.stack_semantics.scalar_width_facts(instruction)
        evidence = _width_evidence(instruction.addr, _EMPTY, frozenset(), fact,
            _Region(RenderTrap('input', ('sp',)), None), False, (), prover=None, instruction=instruction)
        self.assertIsNone(evidence.diagnostic_error)
        self.assertIn('sp', evidence.memory_start)
        shared = Expr('input', ('sp',))
        for _ in range(40):
            shared = Expr('add', (shared, shared))
        label, truncated = _diagnostic_expression(shared)
        self.assertLessEqual(len(label), 512)
        self.assertTrue(truncated)


if __name__ == '__main__':
    unittest.main()
