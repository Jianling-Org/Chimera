"""Production-flow regressions for scalar hardware-width caches."""
from pathlib import Path
import tempfile
import unittest

from chimera.check_elf import collect_diagnostics, _build_inheritance_diagnostics, _diagnostics_payload
from chimera.preprocess.offline.analysis.arch.riscv.rvv import RvvServices
from chimera.preprocess.offline.analysis.arch.riscv.services import RiscvServices
from chimera.preprocess.offline.analysis.program_model.parser import parse_dump
from chimera.preprocess.offline.analysis.toolchain.objdump import LinuxObjdump
from chimera.preprocess.offline.analysis.safety.classifier import classify_liveness
from chimera.preprocess.offline.analysis.safety.stack_liveness import ChimeraMetadata, StackLivenessAnalyzer


def dump_for(body, *, carrier=False):
    lines = ['0000000000001000 <width_source>:']
    sites = []
    for index, (op, args) in enumerate(body):
        address = 0x1000 + 4 * index
        sites.append(address)
        lines.append(f' {address:x}:\t00000013\t{op}\t{args}')
    if carrier:
        lines += ['', '0000000000002000 <carrier>:',
                  ' 2000:\t00000013\tjalr\tt2', ' 2004:\t00000013\tret']
    return '\n'.join(lines) + '\n', sites


class ScalarWidthLivenessTests(unittest.TestCase):
    def analyze(self, body, *, carrier=False, policy='conservative', metadata=None):
        text, sites = dump_for(body, carrier=carrier)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'source.dump'
            path.write_text(text, encoding='utf-8')
            rvv = RvvServices()
            program = RiscvServices(rvv).build_cfg(parse_dump(path, LinuxObjdump('objdump').parse_format))
            stack = StackLivenessAnalyzer(semantics=rvv.stack_semantics, emit_warnings=False,
                unknown_stack_size_policy=policy).analyze_program(program,
                metadata=metadata or ChimeraMetadata.empty(), config_results=rvv.vector_configs(program))
            safety = classify_liveness(program, rvv.vector_liveness(program), stack,
                                       rvv.classify_vector_liveness)
            return safety, stack, sites

    def test_cached_vlenb_across_call_is_unsafe_and_seeds_carrier(self):
        safety, stack, sites = self.analyze([
            ('csrr', 'a2,vlenb'), ('srli', 's4,a2,1'),
            ('jal', 'ra,2000 <carrier>'), ('add', 'a2,s4,zero'),
            ('li', 'a0,0'), ('ret', '')], carrier=True)
        self.assertFalse(safety.records[sites[2]].safe)
        self.assertFalse(safety.records[sites[3]].safe)
        self.assertIn('live_vlen_scalar_data', safety.records[sites[2]].reasons)
        self.assertIn(0x2000, stack.inherited_functions)
        self.assertFalse(safety.records[0x2000].safe)
        self.assertEqual(stack.warnings[-1].origins[0].origin, 'inherited')

    def test_dead_or_overwritten_width_cache_does_not_pin_safepoints(self):
        for body in (
            [('csrr', 's4,vlenb'), ('li', 's4,7'), ('mv', 't0,s4'), ('ret', '')],
            [('csrr', 's4,vlenb'), ('nop', ''), ('ret', '')],
        ):
            with self.subTest(body=body):
                safety, _, _ = self.analyze(body)
                self.assertTrue(all(record.safe for record in safety.records.values()))

    def test_vector_length_sources_and_csr_aliases(self):
        for op, args in (
            ('csrr', 's4,vlenb'), ('csrr', 's4,0xc22'),
            ('csrrs', 's4,vl,zero'), ('csrr', 's4,0xc20'),
            ('vsetvli', 's4,zero,e32,m2,ta,ma'),
            ('vsetivli', 's4,31,e32,m2,ta,ma'),
            ('vsetvl', 's4,a1,a2'),
        ):
            with self.subTest(op=op, args=args):
                safety, _, sites = self.analyze([(op, args), ('add', 't0,s4,zero'), ('ret', '')])
                self.assertIn('live_vlen_scalar_data', safety.records[sites[1]].reasons)

    def test_zero_destination_never_creates_a_scalar_cache(self):
        safety, stack, _ = self.analyze([('vsetvli', 'zero,zero,e32,m2,ta,ma'), ('ret', '')])
        self.assertFalse(any('live_vlen_scalar_data' in r.reasons for r in safety.records.values()))
        self.assertFalse(stack.by_function[0x1000].scalar_width_sources)

    def test_scalar_store_and_reload_keep_width_live(self):
        safety, _, sites = self.analyze([
            ('addi', 'sp,sp,-64'), ('csrr', 't0,vlenb'), ('sd', 't0,8(sp)'),
            ('li', 't0,0'), ('jal', 'ra,2000 <carrier>'),
            ('ld', 's4,8(sp)'), ('add', 't1,s4,zero'),
            ('addi', 'sp,sp,64'), ('li', 'a0,0'), ('ret', '')], carrier=True)
        for index in (2, 4, 5, 6):
            self.assertIn('live_vlen_scalar_data', safety.records[sites[index]].reasons)

    def test_compressed_scalar_load_preserves_spilled_width(self):
        safety, _, sites = self.analyze([
            ('addi', 'sp,sp,-64'), ('csrr', 't0,vlenb'), ('c.sdsp', 't0,8(sp)'),
            ('li', 't0,0'), ('c.ldsp', 's4,8(sp)'), ('c.sdsp', 'zero,8(sp)'),
            ('add', 't1,s4,zero'), ('addi', 'sp,sp,64'), ('ret', '')])
        self.assertIn('live_vlen_scalar_data', safety.records[sites[6]].reasons)

    def test_float_spill_and_reload_preserve_scalar_width_bits(self):
        safety, _, sites = self.analyze([
            ('addi', 'sp,sp,-64'), ('csrr', 't0,vlenb'), ('fmv.d.x', 'fs0,t0'),
            ('fsd', 'fs0,8(sp)'), ('li', 't0,0'), ('fmv.d.x', 'fs0,zero'),
            ('fld', 'fs1,8(sp)'), ('sd', 'zero,8(sp)'), ('fmv.x.d', 's4,fs1'),
            ('add', 't1,s4,zero'), ('addi', 'sp,sp,64'), ('ret', '')])
        self.assertIn('live_vlen_scalar_data', safety.records[sites[9]].reasons)

    def test_full_slot_overwrite_releases_memory_cache(self):
        safety, _, sites = self.analyze([
            ('addi', 'sp,sp,-64'), ('csrr', 't0,vlenb'), ('sd', 't0,8(sp)'),
            ('sd', 'zero,8(sp)'), ('li', 't0,0'), ('jal', 'ra,2000 <carrier>'),
            ('ld', 's4,8(sp)'), ('add', 't1,s4,zero'),
            ('addi', 'sp,sp,64'), ('ret', '')], carrier=True)
        # End the independent register copy too; an unknown call cannot prove
        # that a physically retained t0 was never copied into a return value.
        self.assertTrue(safety.records[sites[5]].safe)
        self.assertTrue(safety.records[sites[7]].safe)

    def test_reclaimed_private_frame_cache_does_not_pin_a_later_call(self):
        safety, _, sites = self.analyze([
            ('addi', 'sp,sp,-64'), ('csrr', 't0,vlenb'), ('sd', 't0,8(sp)'),
            ('li', 't0,0'), ('addi', 'sp,sp,64'),
            ('jal', 'ra,2000 <carrier>'), ('ret', '')], carrier=True)
        self.assertTrue(safety.records[sites[5]].safe)

    def test_partial_slot_overwrite_cannot_erase_remaining_width_bytes(self):
        safety, _, sites = self.analyze([
            ('addi', 'sp,sp,-64'), ('csrr', 't0,vlenb'), ('sd', 't0,8(sp)'),
            ('sw', 'zero,8(sp)'), ('ld', 's4,8(sp)'), ('add', 't1,s4,zero'),
            ('addi', 'sp,sp,64'), ('ret', '')])
        self.assertIn('live_vlen_scalar_data', safety.records[sites[4]].reasons)

    def test_branch_selection_does_not_make_selected_constants_width_content(self):
        safety, _, sites = self.analyze([
            ('csrr', 's4,vlenb'), ('beqz', 's4,1010 <width_source+0x10>'),
            ('li', 's1,32'), ('j', '1014 <width_source+0x14>'),
            ('li', 's1,64'), ('add', 't0,s1,zero'), ('ret', '')])
        self.assertNotIn('live_vlen_scalar_data', safety.records[sites[1]].reasons)
        self.assertNotIn('live_vlen_scalar_data', safety.records[sites[5]].reasons)

    def test_register_alias_and_backedge_do_not_lose_taint(self):
        safety, _, sites = self.analyze([
            ('csrr', 'x20,vlenb'), ('add', 't0,x20,zero'),
            ('bnez', 'a2,1004 <width_source+0x4>'), ('ret', '')])
        self.assertIn('live_vlen_scalar_data', safety.records[sites[1]].reasons)

    def test_dead_width_argument_does_not_create_a_call_use(self):
        safety, stack, sites = self.analyze([
            ('csrr', 'a0,vlenb'), ('jal', 'ra,2000 <carrier>'),
            ('li', 'a0,0'), ('ret', '')], carrier=True)
        self.assertTrue(safety.records[sites[1]].safe)
        self.assertNotIn(0x2000, stack.inherited_functions)

    def test_callee_parameter_store_does_not_import_caller_width_values(self):
        text, sites = dump_for([
            ('csrr', 'a0,vlenb'), ('li', 'a1,8192'), ('jal', 'ra,2000 <capture>'),
            ('li', 'a0,0'), ('ret', '')])
        text += ('\n0000000000002000 <capture>:\n'
                 ' 2000:\t00000013\tsd\ta0,0(a1)\n'
                 ' 2004:\t00000013\tli\ta0,0\n'
                 ' 2008:\t00000013\tret\n')
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'test-seam.elf'
            path.write_bytes(b'\x7fELF\x02\x01\x01' + b'\0' * 24)
            result = collect_diagnostics(path, objdump_cmd='objdump', strategy='gate',
                dump_text=text, metadata=ChimeraMetadata.empty())
            self.assertEqual(result.gate_names, ())
            self.assertEqual(result.findings, ())

    def test_return_does_not_invent_an_abi_result_use(self):
        safety, stack, sites = self.analyze([('csrr', 'a0,vlenb'), ('ret', '')])
        self.assertNotIn('live_vlen_scalar_data', safety.records[sites[1]].reasons)
        self.assertFalse(stack.warnings)

    def test_unknown_location_of_actual_width_store_remains_an_explicit_gap(self):
        _, stack, _ = self.analyze([
            ('csrr', 's4,vlenb'), ('sd', 's4,0(s1)'), ('li', 'a0,0'), ('ret', '')])
        self.assertIn('escaping-vlen-scalar-value', [warning.code for warning in stack.warnings])

    def test_unknown_size_scope_cannot_exclude_known_width_cache(self):
        safety, _, sites = self.analyze([
            ('csrr', 's4,vlenb'), ('add', 't0,s4,zero'), ('ret', '')],
            policy='assume-scalar-independent')
        self.assertFalse(safety.records[sites[1]].safe)

    def test_width_derived_sp_is_implicit_live_context_at_a_call(self):
        safety, _, sites = self.analyze([
            ('mv', 's0,sp'), ('vsetvli', 't0,zero,e32,m2,ta,ma'),
            ('sub', 'sp,sp,t0'), ('li', 't0,0'), ('jal', 'ra,2000 <carrier>'),
            ('mv', 'sp,s0'), ('li', 'a0,0'), ('ret', '')], carrier=True,
            policy='assume-scalar-independent')
        self.assertIn('live_vlen_scalar_data', safety.records[sites[4]].reasons)

    def test_proved_sp_restoration_releases_its_old_width_provenance(self):
        safety, _, sites = self.analyze([
            ('csrr', 't0,vlenb'), ('sub', 'sp,sp,t0'), ('add', 'sp,sp,t0'),
            ('li', 't0,0'), ('jal', 'ra,2000 <carrier>'), ('ret', '')], carrier=True)
        self.assertTrue(safety.records[sites[4]].safe)
        self.assertTrue(safety.records[sites[5]].safe)

    def test_return_with_unrestored_width_context_cannot_silently_pass(self):
        safety, stack, sites = self.analyze([
            ('vsetvli', 't0,zero,e32,m2,ta,ma'), ('sub', 'sp,sp,t0'),
            ('li', 't0,0'), ('li', 'a0,0'), ('ret', '')], policy='assume-scalar-independent')
        self.assertIn('live_vlen_scalar_data', safety.records[sites[4]].reasons)
        self.assertIn('escaping-vlen-scalar-value', [w.code for w in stack.warnings])

    def test_gate_names_and_structured_origin_are_derived_from_scalar_source(self):
        text, _ = dump_for([
            ('csrr', 's4,vlenb'), ('jal', 'ra,2000 <carrier>'),
            ('add', 't0,s4,zero'), ('ret', '')], carrier=True)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'test-seam.elf'
            path.write_bytes(b'\x7fELF\x02\x01\x01' + b'\0' * 24)
            result = collect_diagnostics(path, objdump_cmd='objdump', strategy='gate',
                dump_text=text, metadata=ChimeraMetadata.empty())
            self.assertEqual(result.gate_names, ('width_source',))
            payload = _build_inheritance_diagnostics(result, 'a' * 64)
            function = next(item for item in payload['functions'] if item['name'] == 'width_source')
            self.assertEqual(function['scalar_width_sources'][0]['address'], '0x1000')
            self.assertEqual(payload['seed_edges'][0]['local_active_objects'][0]['metadata_source'], 'vlen_scalar')

    def test_dead_private_spill_is_not_live_only_because_a_pointer_is_an_argument(self):
        safety, stack, sites = self.analyze([
            ('addi', 'sp,sp,-64'), ('csrr', 't0,vlenb'), ('sd', 't0,8(sp)'),
            ('addi', 'a0,sp,8'), ('jal', 'ra,2000 <carrier>'),
            ('addi', 'sp,sp,64'), ('li', 'a0,0'), ('ret', '')], carrier=True)
        self.assertNotIn('live_vlen_scalar_data', safety.records[sites[4]].reasons)
        self.assertNotIn(0x2000, stack.inherited_functions)

    def test_float_register_bit_move_preserves_scalar_width_provenance(self):
        safety, _, sites = self.analyze([
            ('csrr', 't0,vlenb'), ('fmv.d.x', 'fs0,t0'), ('li', 't0,0'),
            ('fmv.x.d', 't1,fs0'), ('add', 't2,t1,zero'), ('ret', '')])
        self.assertIn('live_vlen_scalar_data', safety.records[sites[3]].reasons)

    def test_atomic_old_value_and_conditional_store_do_not_erase_width(self):
        for opcode in ('amoadd.d', 'amoswap.d', 'sc.d'):
            with self.subTest(opcode=opcode):
                safety, _, sites = self.analyze([
                    ('addi', 'sp,sp,-64'), ('csrr', 't0,vlenb'), ('sd', 't0,8(sp)'),
                    ('addi', 't1,sp,8'), (opcode, 't2,zero,(t1)'),
                    ('add', 't3,t2,zero') if opcode == 'amoswap.d' else ('ld', 't3,8(sp)'),
                    ('add', 't4,t3,zero'), ('addi', 'sp,sp,64'), ('ret', '')])
                self.assertIn('live_vlen_scalar_data', safety.records[sites[5]].reasons)

    def test_unmodelled_effect_cannot_clear_a_live_width(self):
        safety, stack, sites = self.analyze([
            ('csrr', 's4,vlenb'), ('custom.effect', 's4'),
            ('add', 't0,s4,zero'), ('ret', '')])
        self.assertFalse(safety.records[sites[2]].safe)
        self.assertTrue(stack.by_function[0x1000].scalar_width_fallback)
        self.assertIn('escaping-vlen-scalar-value', [w.code for w in stack.warnings])

    def test_no_source_fast_path_keeps_ordinary_scalar_code_safe(self):
        safety, stack, _ = self.analyze([
            ('addi', 't0,a0,7'), ('sd', 't0,0(s1)'), ('ret', '')])
        self.assertTrue(all(r.safe for r in safety.records.values()))
        self.assertFalse(stack.by_function[0x1000].scalar_width_sources)

    def test_width_in_caller_saved_register_dies_after_an_actual_overwrite(self):
        # The actual callee is proved not to read t0. An opaque callee cannot
        # establish that it did not already copy t0 into another live value.
        from unittest.mock import patch
        original_dump_for = dump_for

        def known_leaf(body, *, carrier=False):
            text, sites = original_dump_for(body)
            return (text + '\n0000000000002000 <carrier>:\n'
                    ' 2000:\t00000013\tli\ta0,0\n'
                    ' 2004:\t00000013\tret\n', sites)

        with patch(__name__ + '.dump_for', side_effect=known_leaf):
            safety, stack, sites = self.analyze([
                ('csrr', 't0,vlenb'), ('jal', 'ra,2000 <carrier>'),
                ('li', 't0,7'), ('add', 't1,t0,zero'), ('ret', '')], carrier=True)
        self.assertTrue(safety.records[sites[1]].safe)
        self.assertTrue(safety.records[sites[3]].safe)
        self.assertFalse(stack.inherited_functions)

    def test_normal_call_ends_the_caller_volatile_cache_epoch(self):
        safety, stack, sites = self.analyze([
            ('csrr', 't0,vlenb'), ('jal', 'ra,2000 <carrier>'),
            ('add', 't1,t0,zero'), ('ret', '')], carrier=True)
        self.assertNotIn('live_vlen_scalar_data', safety.records[sites[1]].reasons)
        self.assertNotIn('live_vlen_scalar_data', safety.records[sites[2]].reasons)
        self.assertNotIn(0x2000, stack.inherited_functions)

    def test_load_from_disjoint_frame_slot_does_not_inherit_width(self):
        safety, _, sites = self.analyze([
            ('addi', 'sp,sp,-64'), ('csrr', 't0,vlenb'), ('sd', 't0,8(sp)'),
            ('ld', 't1,16(sp)'), ('add', 't2,t1,zero'), ('addi', 'sp,sp,64'), ('ret', '')])
        self.assertTrue(safety.records[sites[3]].safe)
        self.assertTrue(safety.records[sites[4]].safe)

    def test_branch_to_external_body_cannot_drop_unused_local_scalar_context(self):
        safety, stack, sites = self.analyze([
            ('csrr', 's4,vlenb'), ('bnez', 'a2,8000 <external>'), ('ret', '')])
        self.assertFalse(safety.records[sites[1]].safe)
        self.assertIn('active-external-call', [w.code for w in stack.warnings])

    def test_budget_exhaustion_is_unsafe_not_a_partial_proof(self):
        from chimera.preprocess.offline.analysis.safety.stack_liveness.scalar_width import analyze_scalar_width_liveness
        from chimera.preprocess.offline.analysis.safety.stack_liveness.solver import _FunctionExpressionAnalyzer
        text, sites = dump_for([('csrr', 's4,vlenb'), ('add', 't0,s4,zero'), ('ret', '')])
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'source.dump'
            path.write_text(text, encoding='utf-8')
            rvv = RvvServices()
            program = RiscvServices(rvv).build_cfg(parse_dump(path, LinuxObjdump('objdump').parse_format))
            function = program.functions[0]
            expr = _FunctionExpressionAnalyzer(rvv.stack_semantics, emit_warnings=False).analyze(function, frozenset())
            live, sources, warnings, fallback = analyze_scalar_width_liveness(
                function, expr, rvv.stack_semantics, update_budget=1)
            self.assertTrue(fallback)
            self.assertTrue(all(live[site] for site in sites))
            self.assertTrue(sources)
            self.assertIn('budget exhausted', warnings[0].message)

    def test_independent_control_does_not_taint_constant_selected_value(self):
        safety, _, sites = self.analyze([
            ('csrr', 's4,vlenb'), ('li', 's4,7'), ('beqz', 's4,1014 <width_source+0x14>'),
            ('li', 's1,32'), ('j', '1018 <width_source+0x18>'),
            ('li', 's1,64'), ('add', 't0,s1,zero'), ('ret', '')])
        self.assertTrue(safety.records[sites[6]].safe)

    def test_constant_requested_vl_fitting_narrow_target_is_independent(self):
        for body in (
            [('vsetivli', 's4,8,e32,m1,ta,ma'), ('mv', 't0,s4'), ('ret', '')],
            [('li', 'a2,8'), ('vsetvli', 's4,a2,e32,m1,ta,ma'), ('mv', 't0,s4'), ('ret', '')],
            [('li', 'a2,4'), ('li', 'a3,24'), ('vsetvl', 's4,a2,a3'), ('mv', 't0,s4'), ('ret', '')],
            [('vsetivli', 's4,8,e8,mf2,ta,ma'), ('mv', 't0,s4'), ('ret', '')],
        ):
            with self.subTest(body=body):
                safety, _, _ = self.analyze(body)
                self.assertFalse(any('live_vlen_scalar_data' in r.reasons for r in safety.records.values()))

    def test_capacity_alone_does_not_prove_optional_fractional_vtype_support(self):
        for body in (
            [('vsetivli', 's4,1,e64,mf2,ta,ma'), ('mv', 't0,s4'), ('ret', '')],
            [('li', 'a2,1'), ('li', 'a3,31'), ('vsetvl', 's4,a2,a3'),
             ('mv', 't0,s4'), ('ret', '')],
        ):
            with self.subTest(body=body):
                safety, _, sites = self.analyze(body)
                self.assertIn('live_vlen_scalar_data', safety.records[sites[-2]].reasons)

    def test_fixed_vl_selected_by_a_width_guard_is_not_width_content(self):
        safety, _, sites = self.analyze([
            ('csrr', 't0,vlenb'), ('beqz', 't0,1010 <width_source+0x10>'),
            ('vsetivli', 's4,8,e32,m1,ta,ma'), ('j', '1014 <width_source+0x14>'),
            ('li', 's4,16'), ('add', 't1,s4,zero'), ('ret', '')])
        for index in (2, 4, 5):
            self.assertNotIn('live_vlen_scalar_data', safety.records[sites[index]].reasons)

    def test_guarded_call_return_selection_does_not_create_width_content(self):
        safety, _, sites = self.analyze([
            ('li', 'a0,16'), ('csrr', 't0,vlenb'),
            ('beqz', 't0,1010 <width_source+0x10>'),
            ('jal', 'ra,2000 <carrier>'), ('mv', 's4,a0'), ('li', 'a0,0'),
            ('add', 't1,s4,zero'), ('ret', '')], carrier=True)
        self.assertNotIn('live_vlen_scalar_data', safety.records[sites[6]].reasons)

    def test_guarded_call_is_warned_without_importing_parameter_memory_content(self):
        safety, stack, sites = self.analyze([
            ('addi', 'sp,sp,-64'), ('sd', 'zero,8(sp)'), ('addi', 'a0,sp,8'),
            ('csrr', 't0,vlenb'), ('beqz', 't0,1018 <width_source+0x18>'),
            ('jal', 'ra,2000 <carrier>'), ('ld', 's4,8(sp)'),
            ('add', 't1,s4,zero'), ('addi', 'sp,sp,64'),
            ('li', 'a0,0'), ('ret', '')], carrier=True)
        self.assertNotIn('live_vlen_scalar_data', safety.records[sites[7]].reasons)
        self.assertIn('escaping-vlen-scalar-value', [w.code for w in stack.warnings])

    def test_nested_width_control_does_not_turn_selected_constants_into_caches(self):
        safety, _, sites = self.analyze([
            ('csrr', 't0,vlenb'), ('beqz', 't0,1020 <width_source+0x20>'),
            ('beqz', 'a2,1014 <width_source+0x14>'), ('li', 's4,16'),
            ('j', '1018 <width_source+0x18>'), ('li', 's4,32'),
            ('add', 't1,s4,zero'), ('j', '1024 <width_source+0x24>'),
            ('li', 's4,64'), ('add', 't2,s4,zero'), ('ret', '')])
        self.assertNotIn('live_vlen_scalar_data', safety.records[sites[6]].reasons)

    def test_tracked_vector_roundtrip_keeps_scalar_cache_alive_across_call(self):
        safety, stack, sites = self.analyze([
            ('csrr', 't0,vlenb'), ('vmv.s.x', 'v8,t0'), ('li', 't0,0'),
            ('vmv.x.s', 's4,v8'), ('jal', 'ra,2000 <carrier>'),
            ('add', 't1,s4,zero'), ('ret', '')], carrier=True)
        self.assertIn('live_vlen_scalar_data', safety.records[sites[5]].reasons)
        self.assertIn('live_vlen_scalar_data', safety.records[sites[4]].reasons)
        self.assertIn('unresolved-active-indirect-call', [w.code for w in stack.warnings])
        # The roundtrip itself is modelled. The later opaque call retains its
        # own effect gap, which must not masquerade as a transfer failure.
        self.assertFalse(any(w.code == 'escaping-vlen-scalar-value'
            and set(w.addresses) & {sites[1], sites[3]} for w in stack.warnings))

    def test_dead_width_controlled_vector_does_not_escape(self):
        safety, stack, sites = self.analyze([
            ('csrr', 't0,vlenb'), ('beqz', 't0,1010 <width_source+0x10>'),
            ('vmv.v.i', 'v8,0'), ('j', '1010 <width_source+0x10>'),
            ('li', 't0,0'), ('li', 'a0,0'), ('ret', '')])
        self.assertNotIn('live_vlen_scalar_data', safety.records[sites[-1]].reasons)
        self.assertNotIn('escaping-vlen-scalar-value', [w.code for w in stack.warnings])

    def test_whole_group_overwrite_ends_scalar_to_vector_lifetime(self):
        safety, stack, sites = self.analyze([
            ('vsetivli', 'zero,8,e32,m2,ta,ma'), ('csrr', 't0,vlenb'),
            ('vmv.v.x', 'v8,t0'), ('li', 't0,0'), ('vmv2r.v', 'v8,v16'),
            ('jal', 'ra,2000 <carrier>'), ('li', 'a0,0'), ('ret', '')], carrier=True)
        self.assertNotIn('live_vlen_scalar_data', safety.records[sites[5]].reasons)
        self.assertNotIn('escaping-vlen-scalar-value', [w.code for w in stack.warnings])

    def test_one_register_overwrite_cannot_clear_the_other_lmul_register(self):
        safety, stack, sites = self.analyze([
            ('vsetivli', 'zero,8,e32,m2,ta,ma'), ('csrr', 't0,vlenb'),
            ('vmv.v.x', 'v8,t0'), ('li', 't0,0'), ('vmv1r.v', 'v8,v16'),
            ('vmv.x.s', 't1,v9'), ('sd', 't1,0(a1)'), ('li', 't1,0'),
            ('li', 'a0,0'), ('ret', '')])
        self.assertIn('live_vlen_scalar_data', safety.records[sites[6]].reasons)
        self.assertIn('escaping-vlen-scalar-value', [w.code for w in stack.warnings])

    def test_masked_and_partial_lane_writes_do_not_kill_vector_width(self):
        for overwrite in ('vadd.vx', 'vmv.s.x'):
            with self.subTest(overwrite=overwrite):
                args = 'v8,v12,zero,v0.t' if overwrite == 'vadd.vx' else 'v8,zero'
                safety, stack, sites = self.analyze([
                    ('csrr', 't0,vlenb'), ('vmv.s.x', 'v8,t0'),
                    ('li', 't0,0'), (overwrite, args),
                    ('vmv.x.s', 't1,v8'), ('sd', 't1,0(a1)'),
                    ('li', 't1,0'), ('li', 'a0,0'), ('ret', '')])
                self.assertIn('live_vlen_scalar_data', safety.records[sites[5]].reasons)
                self.assertIn('escaping-vlen-scalar-value', [w.code for w in stack.warnings])

    def test_vector_copy_keeps_width_after_original_group_is_overwritten(self):
        safety, stack, sites = self.analyze([
            ('vsetivli', 'zero,8,e32,m2,ta,ma'), ('csrr', 't0,vlenb'),
            ('vmv.v.x', 'v8,t0'), ('vmv2r.v', 'v10,v8'), ('li', 't0,0'),
            ('vmv2r.v', 'v8,v16'), ('vmv.x.s', 't1,v11'), ('sd', 't1,0(a1)'),
            ('li', 't1,0'), ('li', 'a0,0'), ('ret', '')])
        self.assertIn('live_vlen_scalar_data', safety.records[sites[7]].reasons)
        self.assertIn('escaping-vlen-scalar-value', [w.code for w in stack.warnings])

    def test_real_scalar_vector_roundtrip_to_external_memory_stays_refused(self):
        safety, stack, sites = self.analyze([
            ('csrr', 't0,vlenb'), ('vmv.s.x', 'v8,t0'), ('li', 't0,0'),
            ('vmv.x.s', 't1,v8'), ('sd', 't1,0(a1)'), ('li', 't1,0'),
            ('li', 'a0,0'), ('ret', '')])
        self.assertIn('live_vlen_scalar_data', safety.records[sites[-1]].reasons)
        self.assertIn('escaping-vlen-scalar-value', [w.code for w in stack.warnings])

    def test_width_selected_vector_store_reports_memory_effect_not_vector_def(self):
        safety, stack, sites = self.analyze([
            ('csrr', 't0,vlenb'), ('add', 't1,a1,t0'), ('vse32.v', 'v8,(t1)'),
            ('li', 't1,0'), ('li', 't0,0'), ('li', 'a0,0'), ('ret', '')])
        warnings = [w for w in stack.warnings if w.code == 'escaping-vlen-scalar-value']
        self.assertTrue(warnings)
        self.assertTrue(any('vector memory' in w.message for w in warnings))
        self.assertNotIn('live_vlen_scalar_data', safety.records[sites[-1]].reasons)

    def test_unknown_vector_effect_cannot_close_a_width_lifetime(self):
        safety, stack, sites = self.analyze([
            ('csrr', 't0,vlenb'), ('vmv.s.x', 'v8,t0'), ('li', 't0,0'),
            ('vunknown.vv', 'v16,v8,v12'), ('li', 'a0,0'), ('ret', '')])
        self.assertIn('live_vlen_scalar_data', safety.records[sites[-1]].reasons)
        self.assertIn('escaping-vlen-scalar-value', [w.code for w in stack.warnings])

    def test_vector_store_and_shift_operand_roles_are_distinct(self):
        from chimera.preprocess.offline.analysis.core.data_model.program import Instruction
        sem = RvvServices().stack_semantics
        store = sem.scalar_width_facts(Instruction(0x1000, 4, 'vse32.v', ('v8', '(t1)'), ''))
        self.assertFalse(store.vector_data_write)
        self.assertEqual(getattr(store, 'vector_memory_kind', None), 'store')
        self.assertEqual(getattr(store, 'vector_address_reads', frozenset()), frozenset({'t1'}))
        shift = sem.scalar_width_facts(Instruction(0x1004, 4, 'vsll.vx', ('v8', 'v12', 't1'), ''))
        self.assertTrue(shift.vector_data_write)
        self.assertIsNone(getattr(shift, 'vector_memory_kind', None))

    def test_wide_memory_eew_keeps_the_last_emul_register_tainted(self):
        _, stack, sites = self.analyze([
            ('vsetivli', 'zero,8,e8,m1,ta,ma'), ('csrr', 't0,vlenb'),
            ('add', 't1,a1,t0'), ('vle64.v', 'v8,(t1)'),
            ('li', 't1,0'), ('li', 't0,0'), ('vmv.x.s', 't2,v15'),
            ('sd', 't2,0(a2)'), ('li', 't2,0'), ('li', 'a0,0'), ('ret', '')])
        self.assertTrue(any(sites[7] in w.addresses and w.code == 'escaping-vlen-scalar-value'
                            for w in stack.warnings))

    def test_explicit_vector_restart_cannot_authorize_whole_register_kills(self):
        safety, stack, sites = self.analyze([
            ('csrr', 't0,vlenb'), ('vmv.s.x', 'v8,t0'), ('li', 't0,0'),
            ('li', 't1,1'), ('csrw', 'vstart,t1'), ('vmv1r.v', 'v8,v16'),
            ('vmv.x.s', 't2,v8'), ('sd', 't2,0(a1)'),
            ('li', 't2,0'), ('li', 'a0,0'), ('ret', '')])
        self.assertIn('live_vlen_scalar_data', safety.records[sites[-1]].reasons)
        self.assertIn('escaping-vlen-scalar-value', [w.code for w in stack.warnings])

    def test_missing_vector_lifetime_capability_stays_unproven(self):
        from dataclasses import replace
        from unittest.mock import patch
        from chimera.preprocess.offline.analysis.arch.riscv.stack_semantics import RiscvStackSemantics
        original = RiscvStackSemantics.scalar_width_facts
        def legacy(self, instruction, configs=()):
            fact = original(self, instruction, configs)
            if instruction.op == 'vmv.s.x':
                return replace(fact, vector_writes=frozenset(), vector_reads=frozenset(),
                               vector_must_writes=frozenset())
            return fact
        with patch.object(RiscvStackSemantics, 'scalar_width_facts', legacy):
            safety, stack, sites = self.analyze([
                ('csrr', 't0,vlenb'), ('vmv.s.x', 'v8,t0'), ('li', 't0,0'),
                ('li', 'a0,0'), ('ret', '')])
        self.assertIn('live_vlen_scalar_data', safety.records[sites[-1]].reasons)
        self.assertIn('escaping-vlen-scalar-value', [w.code for w in stack.warnings])

    def test_invalid_whole_group_cannot_claim_a_complete_definition(self):
        from chimera.preprocess.offline.analysis.core.data_model.program import Instruction
        sem = RvvServices().stack_semantics
        for op, args in (
            ('vmv2r.v', ('v9', 'v16')), ('vmv1r.v', ('v8', 'a0')),
            ('vl1re64.v', ('v8', 'v16')),
        ):
            with self.subTest(op=op, args=args):
                fact = sem.scalar_width_facts(Instruction(0x1000, 4, op, args, ''))
                self.assertFalse(fact.vector_must_writes)
                self.assertTrue(fact.unmodelled)

    def test_whole_load_and_its_alias_release_an_overwritten_vector_group(self):
        for opcode in ('vl2re8.v', 'vl2r.v'):
            with self.subTest(opcode=opcode):
                safety, stack, sites = self.analyze([
                    ('vsetivli', 'zero,8,e32,m2,ta,ma'), ('csrr', 't0,vlenb'),
                    ('vmv.v.x', 'v8,t0'), ('li', 't0,0'), (opcode, 'v8,(a1)'),
                    ('vmv.x.s', 's4,v9'), ('jal', 'ra,2000 <carrier>'),
                    ('add', 't1,s4,zero'), ('li', 'a0,0'), ('ret', '')], carrier=True)
                self.assertNotIn('live_vlen_scalar_data', safety.records[sites[6]].reasons)
                self.assertNotIn('live_vlen_scalar_data', safety.records[sites[7]].reasons)
                self.assertNotIn('escaping-vlen-scalar-value', [w.code for w in stack.warnings])

    def test_objdump_comment_cannot_hide_a_width_selected_vector_store(self):
        safety, stack, sites = self.analyze([
            ('csrr', 't0,vlenb'), ('add', 't1,a1,t0'),
            ('vse32.v', 'v8,(t1) # 2000 <buffer>'),
            ('li', 't1,0'), ('li', 't0,0'), ('li', 'a0,0'), ('ret', '')])
        self.assertNotIn('live_vlen_scalar_data', safety.records[sites[-1]].reasons)
        self.assertTrue(any(w.code == 'escaping-vlen-scalar-value' and 'vector memory' in w.message
                            for w in stack.warnings))

    def test_entry_pointer_load_does_not_alias_new_private_cache(self):
        safety, _, sites = self.analyze([
            ('mv', 's1,a0'), ('addi', 'sp,sp,-64'), ('csrr', 't0,vlenb'),
            ('sd', 't0,8(sp)'), ('ld', 't1,0(s1)'), ('sd', 'zero,8(sp)'),
            ('add', 't2,t1,zero'), ('addi', 'sp,sp,64'), ('ret', '')])
        # Clear the original cache before checking the loaded value, so this
        # assertion cannot be satisfied/failed by the independent frame state.
        self.assertNotIn('live_vlen_scalar_data', safety.records[sites[6]].reasons)

    def test_private_vector_spill_reload_returns_width_to_scalar(self):
        safety, stack, sites = self.analyze([
            ('mv', 's0,sp'), ('csrr', 'a2,vlenb'), ('sub', 'sp,sp,a2'),
            ('vmv.s.x', 'v8,a2'), ('li', 'a2,0'), ('vs1r.v', 'v8,(sp)'),
            ('vmv1r.v', 'v8,v16'), ('vl1re8.v', 'v10,(sp)'),
            ('vmv.x.s', 's4,v10'), ('mv', 'sp,s0'), ('jal', 'ra,2000 <carrier>'),
            ('add', 't1,s4,zero'), ('li', 'a0,0'), ('ret', '')], carrier=True)
        self.assertIn('live_vlen_scalar_data', safety.records[sites[11]].reasons)
        self.assertFalse(any(w.code == 'escaping-vlen-scalar-value'
            and set(w.addresses) & {sites[5], sites[7], sites[8]} for w in stack.warnings))

    def test_scalar_reload_of_vector_spill_keeps_the_width_copy(self):
        safety, stack, sites = self.analyze([
            ('mv', 's0,sp'), ('csrr', 'a2,vlenb'), ('sub', 'sp,sp,a2'),
            ('vmv.s.x', 'v8,a2'), ('li', 'a2,0'), ('vs1r.v', 'v8,(sp)'),
            ('vmv1r.v', 'v8,v16'), ('ld', 's4,0(sp)'), ('mv', 'sp,s0'),
            ('add', 't1,s4,zero'), ('li', 'a0,0'), ('ret', '')])
        self.assertIn('live_vlen_scalar_data', safety.records[sites[9]].reasons)
        self.assertNotIn('escaping-vlen-scalar-value', [w.code for w in stack.warnings])

    def test_private_vector_spill_complete_overwrite_ends_its_lifetime(self):
        safety, stack, sites = self.analyze([
            ('mv', 's0,sp'), ('csrr', 'a2,vlenb'), ('sub', 'sp,sp,a2'),
            ('vmv.s.x', 'v8,a2'), ('li', 'a2,0'), ('vs1r.v', 'v8,(sp)'),
            ('vmv1r.v', 'v8,v16'), ('vs1r.v', 'v16,(sp)'),
            ('ld', 's4,0(sp)'), ('mv', 'sp,s0'), ('jal', 'ra,2000 <carrier>'),
            ('add', 't1,s4,zero'), ('li', 'a0,0'), ('ret', '')], carrier=True)
        self.assertNotIn('live_vlen_scalar_data', safety.records[sites[10]].reasons)
        self.assertNotIn('live_vlen_scalar_data', safety.records[sites[11]].reasons)
        self.assertNotIn('escaping-vlen-scalar-value', [w.code for w in stack.warnings])

    def test_private_vector_spill_death_does_not_become_permanent_escape(self):
        safety, stack, sites = self.analyze([
            ('mv', 's0,sp'), ('csrr', 'a2,vlenb'), ('sub', 'sp,sp,a2'),
            ('vmv.s.x', 'v8,a2'), ('li', 'a2,0'), ('vs1r.v', 'v8,(sp)'),
            ('vmv1r.v', 'v8,v16'), ('mv', 'sp,s0'), ('jal', 'ra,2000 <carrier>'),
            ('li', 'a0,0'), ('ret', '')], carrier=True)
        self.assertNotIn('live_vlen_scalar_data', safety.records[sites[8]].reasons)
        self.assertNotIn('escaping-vlen-scalar-value', [w.code for w in stack.warnings])

    def test_partial_and_masked_stack_writes_cannot_erase_vector_cache(self):
        for op, args in [('sb', 'zero,0(sp)'), ('vse8.v', 'v16,(sp),v0.t')]:
            with self.subTest(op=op):
                safety, _, sites = self.analyze([
                    ('mv', 's0,sp'), ('csrr', 'a2,vlenb'), ('sub', 'sp,sp,a2'),
                    ('vmv.s.x', 'v8,a2'), ('li', 'a2,0'), ('vs1r.v', 'v8,(sp)'),
                    ('vmv1r.v', 'v8,v16'), ('vsetivli', 'zero,1,e8,m1,ta,ma'),
                    (op, args), ('ld', 's4,0(sp)'), ('mv', 'sp,s0'),
                    ('add', 't1,s4,zero'), ('li', 'a0,0'), ('ret', '')])
                self.assertIn('live_vlen_scalar_data', safety.records[sites[11]].reasons)

    def test_stack_group_alias_survives_overwriting_only_one_register_region(self):
        safety, _, sites = self.analyze([
            ('mv', 's0,sp'), ('csrr', 'a2,vlenb'), ('slli', 't0,a2,1'),
            ('sub', 'sp,sp,t0'), ('vsetivli', 'zero,8,e32,m2,ta,ma'),
            ('vmv.v.x', 'v8,a2'), ('add', 's1,sp,a2'), ('li', 'a2,0'), ('li', 't0,0'),
            ('vs2r.v', 'v8,(sp)'), ('vmv2r.v', 'v8,v16'), ('vs1r.v', 'v16,(sp)'),
            ('vl1re8.v', 'v10,(s1)'), ('vmv.x.s', 's4,v10'), ('mv', 'sp,s0'),
            ('add', 't1,s4,zero'), ('li', 'a0,0'), ('ret', '')])
        self.assertIn('live_vlen_scalar_data', safety.records[sites[15]].reasons)

    def test_confirmed_nonstack_width_data_write_is_explicitly_out_of_scope(self):
        _, stack, _ = self.analyze([
            ('li', 's1,8192'), ('csrr', 'a2,vlenb'), ('vmv.s.x', 'v8,a2'),
            ('li', 'a2,0'), ('vs1r.v', 'v8,(s1)'), ('vmv1r.v', 'v8,v16'),
            ('li', 'a0,0'), ('ret', '')])
        origins = [o for w in stack.warnings if w.code == 'escaping-vlen-scalar-value'
                   for o in w.origins]
        self.assertTrue(any(o.proof == 'unsupported-nonstack-width-data' for o in origins))

    def test_unproved_store_location_is_a_gap_not_confirmed_nonstack_escape(self):
        safety, stack, sites = self.analyze([
            ('ld', 's1,0(a0)'), ('csrr', 'a2,vlenb'), ('vmv.s.x', 'v8,a2'),
            ('li', 'a2,0'), ('vs1r.v', 'v8,(s1)'), ('vmv1r.v', 'v8,v16'),
            ('li', 'a0,0'), ('ret', '')])
        origins = [o for w in stack.warnings if w.code == 'escaping-vlen-scalar-value'
                   for o in w.origins]
        self.assertTrue(any('width-store-address-unproven' in o.gaps for o in origins))
        self.assertFalse(any(o.proof == 'unsupported-nonstack-width-data' for o in origins))
        self.assertIn('live_vlen_scalar_data', safety.records[sites[-1]].reasons)

    def test_access_length_alone_does_not_invent_persistent_width_content(self):
        safety, stack, sites = self.analyze([
            ('vsetvli', 'a2,a1,e32,m1,ta,ma'), ('vse32.v', 'v8,(s1)'),
            ('li', 'a2,0'), ('li', 'a0,0'), ('ret', '')])
        self.assertNotIn('escaping-vlen-scalar-value', [w.code for w in stack.warnings])
        self.assertNotIn('live_vlen_scalar_data', safety.records[sites[-1]].reasons)

    def test_chunk_address_effect_is_not_a_confirmed_persistent_width_cache(self):
        _, stack, _ = self.analyze([
            ('vsetvli', 'a2,a1,e32,m1,ta,ma'), ('slli', 't0,a2,2'),
            ('add', 's1,s1,t0'), ('vse32.v', 'v8,(s1)'),
            ('li', 'a2,0'), ('li', 's1,0'), ('li', 't0,0'), ('li', 'a0,0'), ('ret', '')])
        origins = [o for w in stack.warnings if w.code == 'escaping-vlen-scalar-value'
                   for o in w.origins]
        self.assertTrue(any('width-selected-memory-effect-unproven' in o.gaps for o in origins))
        self.assertFalse(any(o.proof == 'unsupported-nonstack-width-data' for o in origins))

    def test_width_guard_of_observable_store_is_preserved_separately(self):
        safety, stack, sites = self.analyze([
            ('li', 's1,8192'), ('csrr', 'a2,vlenb'), ('beqz', 'a2,1010 <width_source+0x10>'),
            ('vs1r.v', 'v8,(s1)'), ('li', 'a2,0'), ('li', 'a0,0'), ('ret', '')])
        origins = [o for w in stack.warnings if w.code == 'escaping-vlen-scalar-value'
                   for o in w.origins]
        self.assertTrue(any('width-controlled-write-unproven' in o.gaps for o in origins))
        self.assertNotIn('live_vlen_scalar_data', safety.records[sites[-1]].reasons)

    def test_clearing_a2_ends_only_that_scalar_copy(self):
        for keep_copy in (False, True):
            with self.subTest(keep_copy=keep_copy):
                body = [('csrr', 'a2,vlenb'), ('mv', 's4,a2'), ('li', 'a2,0')]
                if not keep_copy:
                    body.append(('li', 's4,0'))
                call_index = len(body)
                body += [('jal', 'ra,2000 <carrier>'), ('add', 't0,s4,zero'),
                         ('li', 'a0,0'), ('ret', '')]
                safety, stack, sites = self.analyze(body, carrier=True)
                self.assertEqual('live_vlen_scalar_data' in safety.records[sites[call_index]].reasons,
                                 keep_copy)
                self.assertFalse(any(w.code == 'escaping-vlen-scalar-value'
                    and set(w.addresses) & {sites[0], sites[1], sites[2]}
                    for w in stack.warnings))

    def test_private_vector_spill_reuses_compiler_stack_object_identity(self):
        body = [
            ('mv', 's0,sp'), ('csrr', 'a2,vlenb'), ('sub', 'sp,sp,a2'),
            ('vmv.s.x', 'v8,a2'), ('li', 'a2,0'), ('vs1r.v', 'v8,(sp)'),
            ('vmv1r.v', 'v8,v16'), ('vl1re8.v', 'v10,(sp)'),
            ('vmv.x.s', 's4,v10'), ('mv', 'sp,s0'), ('add', 't1,s4,zero'),
            ('li', 'a0,0'), ('ret', '')]
        _, sites = dump_for(body)
        metadata = ChimeraMetadata(stack_ids={sites[5]: 17, sites[7]: 17}, has_stackobj_map_section=True)
        safety, stack, _ = self.analyze(body, metadata=metadata)
        self.assertIn('live_vlen_scalar_data', safety.records[sites[10]].reasons)
        access = stack.by_function[0x1000].accesses[sites[5]]
        self.assertEqual((access.stack_id.source, access.stack_id.value), ('compiler', 17))
        self.assertNotIn('escaping-vlen-scalar-value', [w.code for w in stack.warnings])

    def test_unproved_vector_extent_cannot_be_treated_as_private(self):
        safety, stack, sites = self.analyze([
            ('addi', 'sp,sp,-64'), ('csrr', 'a2,vlenb'), ('vmv.s.x', 'v8,a2'),
            ('li', 'a2,0'), ('vs1r.v', 'v8,(sp)'), ('vmv1r.v', 'v8,v16'),
            ('addi', 'sp,sp,64'), ('li', 'a0,0'), ('ret', '')])
        origins = [o for w in stack.warnings if w.code == 'escaping-vlen-scalar-value' for o in w.origins]
        self.assertTrue(any('width-store-extent-unproven' in o.gaps for o in origins))
        self.assertIn('live_vlen_scalar_data', safety.records[sites[-1]].reasons)

    def test_width_mask_is_an_effect_gap_not_proof_of_stored_width_content(self):
        _, stack, _ = self.analyze([
            ('li', 's1,8192'), ('csrr', 'a2,vlenb'), ('vmv.s.x', 'v0,a2'),
            ('li', 'a2,0'), ('vse32.v', 'v8,(s1),v0.t'), ('vmv1r.v', 'v0,v16'),
            ('li', 'a0,0'), ('ret', '')])
        origins = [o for w in stack.warnings if w.code == 'escaping-vlen-scalar-value' for o in w.origins]
        self.assertTrue(any('width-controlled-write-unproven' in o.gaps for o in origins))
        self.assertFalse(any(o.proof == 'unsupported-nonstack-width-data' for o in origins))

    def test_selected_load_cannot_later_masquerade_as_confirmed_width_bits(self):
        _, stack, _ = self.analyze([
            ('csrr', 'a2,vlenb'), ('add', 't0,a1,a2'), ('vle32.v', 'v8,(t0)'),
            ('li', 'a2,0'), ('li', 't0,0'), ('li', 's1,8192'),
            ('vse32.v', 'v8,(s1)'), ('vmv8r.v', 'v8,v16'), ('li', 'a0,0'), ('ret', '')])
        origins = [o for w in stack.warnings if w.code == 'escaping-vlen-scalar-value' for o in w.origins]
        self.assertTrue(any('width-selected-memory-effect-unproven' in o.gaps for o in origins))
        self.assertFalse(any(o.proof == 'unsupported-nonstack-width-data' for o in origins))
        self.assertFalse(any('width-store-address-unproven' in o.gaps for o in origins))

    def test_width_index_aliasing_the_load_destination_stays_a_selection_gap(self):
        _, stack, _ = self.analyze([
            ('li', 's1,8192'), ('csrr', 'a2,vlenb'), ('vmv.s.x', 'v8,a2'),
            ('li', 'a2,0'), ('vluxei32.v', 'v8,(s1),v8'),
            ('vse32.v', 'v8,(s1)'), ('vmv8r.v', 'v8,v16'), ('li', 'a0,0'), ('ret', '')])
        origins = [o for w in stack.warnings if w.code == 'escaping-vlen-scalar-value' for o in w.origins]
        self.assertTrue(any('width-selected-memory-effect-unproven' in o.gaps for o in origins))
        self.assertFalse(any(o.proof == 'unsupported-nonstack-width-data' for o in origins))

    def test_dead_vector_copy_does_not_pin_a_later_safepoint(self):
        safety, stack, sites = self.analyze([
            ('csrr', 'a2,vlenb'), ('vmv.s.x', 'v8,a2'), ('li', 'a2,0'),
            ('li', 'a0,0'), ('ret', '')])
        self.assertNotIn('live_vlen_scalar_data', safety.records[sites[-1]].reasons)
        self.assertNotIn('escaping-vlen-scalar-value', [w.code for w in stack.warnings])

    def test_exported_report_distinguishes_nonstack_content_and_address_gap(self):
        import json
        for known in (True, False):
            with self.subTest(known=known), tempfile.TemporaryDirectory() as directory:
                body = [('li' if known else 'ld', 's1,8192' if known else 's1,0(a0)'),
                        ('csrr', 'a2,vlenb'), ('vmv.s.x', 'v8,a2'), ('li', 'a2,0'),
                        ('vs1r.v', 'v8,(s1)'), ('li', 'a0,0'), ('ret', '')]
                text, _ = dump_for(body)
                path = Path(directory) / 'test-seam.elf'
                path.write_bytes(b'\x7fELF\x02\x01\x01' + b'\0' * 24)
                result = collect_diagnostics(path, objdump_cmd='objdump', strategy='gate',
                    dump_text=text, metadata=ChimeraMetadata.empty())
                payload = json.loads(json.dumps(_diagnostics_payload(result)))
                origins = [o for f in payload['warnings']
                           if f['diagnostic_code'] == 'escaping-vlen-scalar-value'
                           for o in f['activity_origins']]
                if known:
                    self.assertTrue(any(o['proof'] == 'unsupported-nonstack-width-data' for o in origins))
                else:
                    self.assertTrue(any('width-store-address-unproven' in o['gaps'] for o in origins))
                    self.assertFalse(any(o['proof'] == 'unsupported-nonstack-width-data' for o in origins))

    def test_standard_vector_aliases_do_not_create_an_external_escape(self):
        for opcode in ('vfabs.v', 'vfneg.v', 'vmnot.m', 'vwcvt.x.x.v', 'vwcvtu.x.x.v'):
            with self.subTest(opcode=opcode):
                safety, stack, sites = self.analyze([
                    ('csrr', 'a2,vlenb'), (opcode, 'v8,v16'), ('li', 'a2,0'),
                    ('li', 'a0,0'), ('ret', '')])
                self.assertNotIn('escaping-vlen-scalar-value', [w.code for w in stack.warnings])
                self.assertNotIn('live_vlen_scalar_data', safety.records[sites[-1]].reasons)

    def test_standard_vector_aliases_preserve_a_real_width_roundtrip(self):
        for opcode in ('vfabs.v', 'vfneg.v', 'vmnot.m', 'vwcvt.x.x.v', 'vwcvtu.x.x.v'):
            with self.subTest(opcode=opcode):
                safety, stack, sites = self.analyze([
                    ('csrr', 'a2,vlenb'), ('vmv.s.x', 'v16,a2'), ('li', 'a2,0'),
                    (opcode, 'v8,v16'), ('vmv.x.s', 's4,v8'), ('jal', 'ra,2000 <carrier>'),
                    ('add', 't0,s4,zero'), ('li', 'a0,0'), ('ret', '')], carrier=True)
                self.assertIn('live_vlen_scalar_data', safety.records[sites[5]].reasons)
                self.assertIn('live_vlen_scalar_data', safety.records[sites[6]].reasons)
                self.assertFalse(any(w.code == 'escaping-vlen-scalar-value'
                    and set(w.addresses) & {sites[1], sites[3], sites[4]}
                    for w in stack.warnings))

    def test_standard_alias_operand_shapes_and_partial_definitions_are_checked(self):
        from chimera.preprocess.offline.analysis.core.data_model.program import Instruction
        sem = RvvServices().stack_semantics
        for opcode in ('vfabs.v', 'vfneg.v', 'vwcvt.x.x.v', 'vwcvtu.x.x.v'):
            with self.subTest(opcode=opcode):
                valid = sem.scalar_width_facts(Instruction(0x1000,4,opcode,('v8','v16','v0.t'),''))
                self.assertFalse(valid.unmodelled)
                self.assertIn(0,valid.vector_mask_reads)
                self.assertFalse(valid.vector_must_writes)
                invalid = sem.scalar_width_facts(Instruction(0x1000,4,opcode,('v8','a0'),''))
                self.assertTrue(invalid.unmodelled)
        mask = sem.scalar_width_facts(Instruction(0x1000,4,'vmnot.m',('v8','v16'),''))
        self.assertFalse(mask.unmodelled)
        self.assertEqual(mask.vector_reads,frozenset({16}))
        self.assertEqual(mask.vector_writes,frozenset({8}))
        self.assertFalse(mask.vector_must_writes)
        invalid_mask = sem.scalar_width_facts(Instruction(0x1000,4,'vmnot.m',('v8','v16','v0.t'),''))
        self.assertTrue(invalid_mask.unmodelled)

    def test_unresolved_pointer_load_keeps_possible_private_cache_dependency(self):
        safety, _, sites = self.analyze([
            ('ld', 's1,0(a0)'), ('addi', 'sp,sp,-64'), ('csrr', 't0,vlenb'),
            ('sd', 't0,8(sp)'), ('ld', 't1,0(s1)'), ('sd', 'zero,8(sp)'),
            ('add', 't2,t1,zero'), ('addi', 'sp,sp,64'), ('ret', '')])
        self.assertIn('live_vlen_scalar_data', safety.records[sites[6]].reasons)

    def test_width_selected_load_address_does_not_create_width_content(self):
        safety, _, sites = self.analyze([
            ('csrr', 't0,vlenb'), ('add', 's1,a0,t0'), ('li', 't0,0'),
            ('ld', 's4,0(s1)'), ('li', 's1,0'), ('mv', 't1,s4'), ('ret', '')])
        self.assertNotIn('live_vlen_scalar_data', safety.records[sites[5]].reasons)

    def test_constant_store_through_width_selected_address_is_warning_only(self):
        safety, stack, sites = self.analyze([
            ('csrr', 't0,vlenb'), ('add', 's1,a0,t0'), ('sd', 'zero,0(s1)'),
            ('li', 't0,0'), ('li', 's1,0'), ('nop', ''), ('ret', '')])
        self.assertIn('escaping-vlen-scalar-value', [w.code for w in stack.warnings])
        self.assertNotIn('live_vlen_scalar_data', safety.records[sites[5]].reasons)

    def test_captured_decode_keeps_s4_cache_unsafe_and_generates_a_gate_source(self):
        text = (Path(__file__).parent / 'fixtures' / 'llama_decode_vlen_cache.dump').read_text(
            encoding='utf-8')
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'test-seam.elf'
            path.write_bytes(b'\x7fELF\x02\x01\x01' + b'\0' * 24)
            result = collect_diagnostics(path, objdump_cmd='objdump', strategy='gate',
                dump_text=text, metadata=ChimeraMetadata.empty(),
                unknown_stack_size_policy='assume-scalar-independent')
            function = result.analysis.program.functions[0]
            # These coordinates come from the captured disassembly, not from
            # a hand-counted synthetic instruction sequence.
            instructions = function.instruction_by_address
            self.assertEqual(instructions[0x24891E].args, ('a2', 'vlenb'))
            self.assertEqual(instructions[0x24892E].args, ('s4', 'a2', '0x1'))
            self.assertEqual(instructions[0x248974].op, 'jalr')
            rvv = RvvServices()
            safety = classify_liveness(result.analysis.program,
                rvv.vector_liveness(result.analysis.program), result.analysis.stack,
                rvv.classify_vector_liveness)
            self.assertIn('live_vlen_scalar_data',
                          safety.records[0x248974].reasons)
            self.assertIn(function.name, result.gate_names)
            sources = result.analysis.stack.by_function[function.start].scalar_width_sources
            self.assertIn((0x24891E, 'a2', 'csr-vlenb'),
                          {(source.address, source.register, source.kind) for source in sources})


if __name__ == '__main__':
    unittest.main()
