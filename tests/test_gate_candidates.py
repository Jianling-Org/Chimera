"""Proactive gate selection before a boundary becomes unsafe after rebuilding."""
from __future__ import annotations

import hashlib
import json
import unittest
from unittest import mock

from chimera.gate_candidates import candidates_from_dump
from chimera.compiler_plan import load_rebuild_plan, publish_rebuild_plan
import test_compiler_plan as planner_fixtures

DUMP = """0000000000001000 <quiet_width_vector>:
 1000: c2202573 csrr a0,vlenb
 1004: cd817057 vsetivli zero,16,e64,m4,ta,ma
 1008: 5e003457 vmv.v.i v8,0
 100c: 00008067 ret
0000000000002000 <width_only>:
 2000: c2202573 csrr a0,vlenb
 2004: 00008067 ret
0000000000003000 <vector_only>:
 3000: 5e003457 vmv.v.i v8,0
 3004: 00008067 ret
0000000000004000 <configuration_only>:
 4000: c2202573 csrr a0,vlenb
 4004: cd817057 vsetivli zero,16,e64,m4,ta,ma
 4008: 00008067 ret
0000000000005000 <numeric_csr>:
 5000: c2202573 csrrs a1,0xc22,zero
 5004: 02056407 vle64.v v8,(a0)
 5008: 00008067 ret
0000000000006000 <discarded_width>:
 6000: c2202573 csrr zero,vlenb
 6004: 5e003457 vmv.v.i v8,0
 6008: 00008067 ret
0000000000007000 <external@plt>:
 7000: c2202573 csrr a0,vlenb
 7004: 5e003457 vmv.v.i v8,0
 7008: 00008067 ret
"""


class WidthCandidateScanTests(unittest.TestCase):
    def test_local_width_and_vector_evidence_without_any_boundary(self):
        result = list(candidates_from_dump(iter(DUMP.splitlines())))
        self.assertEqual([x['name'] for x in result], ['quiet_width_vector', 'numeric_csr'])
        self.assertEqual(result[0]['width_reads'],
                         [{'address': '0x1000', 'register': 'a0', 'kind': 'csr-vlenb'}])
        self.assertEqual(result[0]['vector_instruction']['address'], '0x1008')

    def test_evidence_is_not_combined_across_function_boundaries(self):
        body = DUMP[DUMP.index('0000000000002000'):DUMP.index('0000000000004000')]
        self.assertEqual(list(candidates_from_dump(body.splitlines())), [])

    def test_safety_unknown_prose_does_not_create_candidates(self):
        self.assertEqual(list(candidates_from_dump([
            '0000000000001000 <unknown_scalar_size>:',
            ' 1000: 40a10133 sub sp,sp,a0',
            ' # unresolved-memory-source vlenb vmv.v.i',
            ' 1004: 00008067 ret'])), [])


class CandidatePlanTests(unittest.TestCase):
    setUp = planner_fixtures.CompilerPlanTests.setUp
    tearDown = planner_fixtures.CompilerPlanTests.tearDown
    # Exercise the real planner/integrity loader; only objdump's fixture input
    # is substituted because the base planner fixtures are not real ELFs.
    def publish_candidates(self, functions=None, stage='gate'):
        evidence = list(candidates_from_dump(DUMP.splitlines()))[:1] if functions is None else functions
        def scan(path, command):
            self.assertEqual(command, 'test-objdump')
            return {'elf': {'path': str(path.resolve()),
                            'content_sha256': hashlib.sha256(path.read_bytes()).hexdigest()},
                    'functions': evidence}
        with mock.patch('chimera.compiler_plan.scan_width_gate_candidates', side_effect=scan) as scanner:
            publish_rebuild_plan(self.out, stage=stage, profile=self.profile,
                                 reports=[self.report], launcher=self.launcher,
                                 gate_candidate_objdump='test-objdump')
            self.assertEqual(scanner.call_count, int(stage == 'gate'))

    def test_adds_no_finding_host_and_preserves_original_report(self):
        original = self.report.read_bytes()
        self.publish_candidates()
        decision, _ = load_rebuild_plan(self.out)
        self.assertEqual(decision['gate']['names'], ['bar', 'foo', 'quiet_width_vector'])
        self.assertEqual(self.report.read_bytes(), original)
        inventory = json.loads((self.out/'gate-candidates.json').read_text())
        self.assertEqual(inventory['inputs'][0]['functions'][0]['name'], 'quiet_width_vector')

    def test_none_strategy_activates_gate_for_preventive_candidate(self):
        self.report.write_text(json.dumps(planner_fixtures._report(self.elf, strategy='none')))
        self.publish_candidates()
        decision, _ = load_rebuild_plan(self.out)
        self.assertEqual(decision['strategy'], 'gate')
        self.assertEqual(decision['gate']['names'], ['quiet_width_vector'])

    def test_metadata_stage_does_not_scan_or_add_candidates(self):
        self.publish_candidates(stage='metadata')
        self.assertFalse((self.out/'gate-candidates.json').exists())
        self.assertEqual(load_rebuild_plan(self.out)[0]['gate']['names'], [])

    def test_inventory_tampering_is_rejected(self):
        self.publish_candidates()
        path = self.out/'gate-candidates.json'
        path.write_text(path.read_text()+' ')
        with self.assertRaisesRegex(ValueError, 'candidate.*digest'):
            load_rebuild_plan(self.out)

    def test_rehashed_inventory_must_match_report_elf(self):
        self.publish_candidates()
        path = self.out/'gate-candidates.json'
        doc = json.loads(path.read_text())
        doc['inputs'][0]['elf']['content_sha256'] = '0'*64
        path.write_text(json.dumps(doc))
        plan_path = self.out/'build-plan.json'
        plan = json.loads(plan_path.read_text())
        plan['gate_candidates']['sha256'] = hashlib.sha256(path.read_bytes()).hexdigest()
        plan_path.write_text(json.dumps(plan))
        with self.assertRaisesRegex(ValueError, 'candidate ELF identity'):
            load_rebuild_plan(self.out)

    def test_rehashed_decision_cannot_omit_a_pinned_candidate(self):
        self.publish_candidates()
        path = self.out/'decision.json'
        doc = json.loads(path.read_text())
        doc['decision']['gate']['names'].remove('quiet_width_vector')
        path.write_text(json.dumps(doc))
        plan_path = self.out/'build-plan.json'
        plan = json.loads(plan_path.read_text())
        plan['decision']['sha256'] = hashlib.sha256(path.read_bytes()).hexdigest()
        plan_path.write_text(json.dumps(plan))
        with self.assertRaisesRegex(ValueError, 'effective decision'):
            load_rebuild_plan(self.out)

    def test_inventory_cannot_be_dropped_from_new_policy_plan(self):
        self.publish_candidates()
        path = self.out/"build-plan.json"
        doc = json.loads(path.read_text())
        del doc["gate_candidates"]
        path.write_text(json.dumps(doc))
        with self.assertRaisesRegex(ValueError, "requires its pinned inventory"):
            load_rebuild_plan(self.out)
