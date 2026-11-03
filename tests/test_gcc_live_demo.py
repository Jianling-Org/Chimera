"""Offline false-positive and deterministic-input checks; no K3 workload."""
import ast
import copy
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('gcc_live_demo', ROOT/'experiments/gcc-demo/demo.py')
demo = importlib.util.module_from_spec(spec)
spec.loader.exec_module(demo)


class LiveDemoEvidence(unittest.TestCase):
    def setUp(self):
        self.ids = set(range(1, 17))
        self.samples = [dict(phase='eight', tasks=[dict(pid=i, cpu=(i-1)%8) for i in range(1, 17)]),
                        dict(phase='sixteen', tasks=[dict(pid=i, cpu=i-1) for i in range(1, 17)])]
        self.replay = dict(physical_commits=[dict(tid=9, timestamp=12)], raw_accepted_ack_count=1,
                           route_counts={'256-to-1024': 1, '1024-to-256': 0})
        self.before = dict.fromkeys(demo.LEDGERS+demo.MOVES+(demo.TIMEOUT,), 0)
        self.after = dict(self.before);self.after[demo.MOVES[0]] = 1

    def validate(self):
        return demo.validate_evidence(self.samples, self.ids, self.replay, self.before, self.after, 10)

    def test_same_processes_physical_commit_and_both_cpu_sets(self):
        self.assertEqual(self.validate()['phase2_cpu_seen'], list(range(16)))

    def test_cpu_expansion_without_real_commit_is_not_migration(self):
        self.replay['physical_commits'] = []
        with self.assertRaises(RuntimeError):self.validate()

    def test_commit_before_expansion_is_not_live_transition(self):
        self.replay['physical_commits'][0]['timestamp'] = 9
        with self.assertRaises(RuntimeError):self.validate()

    def test_other_task_cannot_supply_cpu_activity(self):
        self.samples[1]['tasks'][0]['pid'] = 999
        with self.assertRaises(RuntimeError):self.validate()

    def test_only_eight_cpus_after_expansion_does_not_pass(self):
        for row in self.samples[1]['tasks']:row['cpu'] %= 8
        with self.assertRaises(RuntimeError):self.validate()

    def test_global_counter_must_equal_raw_evidence(self):
        self.after[demo.MOVES[0]] = 2
        with self.assertRaises(RuntimeError):self.validate()

    def test_ready_does_not_ignore_blocked_migration_signals(self):
        row=dict(ready='1', exec_ready='1', preference='prefer-x100', caught=hex((1 << 4)|(1 << 40)), blocked='0')
        self.assertTrue(demo.initialized(row));row['blocked']='10'
        self.assertFalse(demo.initialized(row))

    def test_timeout_or_ledger_is_not_success(self):
        self.after[demo.TIMEOUT] = 1
        with self.assertRaises(RuntimeError):self.validate()
        self.after[demo.TIMEOUT] = 0;self.after[demo.LEDGERS[0]] = 1
        with self.assertRaises(RuntimeError):self.validate()

    def test_wrong_object_or_numerical_result_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            ref=Path(directory)/'reference.o';obj=Path(directory)/'worker.o'
            ref.write_bytes(b'accepted');obj.write_bytes(b'wrong')
            with self.assertRaises(RuntimeError):demo.check_outputs([obj], ref, [(0, 'abcd\n')], 'abcd\n')
            obj.write_bytes(ref.read_bytes())
            with self.assertRaises(RuntimeError):demo.check_outputs([obj], ref, [(0, 'bad\n')], 'abcd\n')
            self.assertEqual(demo.check_outputs([obj], ref, [(0, 'abcd\n')], 'abcd\n'), demo.sha(ref))

    def test_input_bytes_and_integer_reference_match_accepted_fixture(self):
        original=ast.parse((ROOT/'experiments/gcc-validation/k3-20261029/harness/runtime_smoke.py').read_bytes())
        node=next(n for n in original.body if isinstance(n, ast.FunctionDef) and n.name=='fixture')
        namespace={};exec(compile(ast.Module(body=[node], type_ignores=[]), '<accepted-fixture>', 'exec'), namespace)
        for count in (1, 192):self.assertEqual(demo.fixture(count), namespace['fixture'](count))

    def test_busy_model_or_audit_prevents_demo(self):
        own='chimera-gcc-demo-123456789abc.service'
        with patch.object(demo.subprocess, 'check_output', return_value='chimera-model42-audit.service loaded active running Audit\n'):
            with self.assertRaises(RuntimeError):demo.busy_guard(own)
        with patch.object(demo.subprocess, 'check_output', return_value=own+' loaded active running Demo\n'):
            demo.busy_guard(own)


if __name__ == '__main__':unittest.main()
