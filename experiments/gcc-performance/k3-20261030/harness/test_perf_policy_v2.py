"""Boundary regressions for the authorized exception and separate attempt epoch."""
import importlib.util
import json
from pathlib import Path
import unittest
from perf_storage_policy_v2 import MESSAGE_PREFIX, classify_kernel_record, validate_storage_sample


def record(status=2, priority=3, prefix=MESSAGE_PREFIX, context='', flags='-'):
    return f'{priority},10,1000,{flags};{prefix}{status}\n{context}'.encode()


class BoundaryTests(unittest.TestCase):
    def test_authorized_actual_maintenance_states(self):
        for value in (0, 1, 2):
            with self.subTest(value=value):
                validate_storage_sample(dict(bkops_status=value, critical_health=0))

    def test_critical_and_unknown_states_remain_fatal(self):
        for value in (3, 4, 255, -1, True, False, '2', 2.0, None):
            with self.subTest(value=value), self.assertRaises((AssertionError, TypeError)):
                validate_storage_sample(dict(bkops_status=value, critical_health=0))

    def test_critical_health_remains_fatal(self):
        for value in (1, 2, 255, -1, False, '0', None):
            with self.subTest(value=value), self.assertRaises(AssertionError):
                validate_storage_sample(dict(bkops_status=2, critical_health=value))

    def test_missing_health_data_remains_fatal(self):
        with self.assertRaises(KeyError):
            validate_storage_sample(dict(bkops_status=2))

    def test_exact_maintenance_records_are_retained(self):
        for status in (1, 2):
            with self.subTest(status=status):
                self.assertEqual(classify_kernel_record(record(status), True), f'known-ufs-bkops-status{status}')

    def test_exception_requires_explicit_enable(self):
        self.assertEqual(classify_kernel_record(record(), False), 'alert')

    def test_status3_and_unknown_log_still_fail(self):
        for status in (0, 3, 4, 12):
            with self.subTest(status=status):
                self.assertEqual(classify_kernel_record(record(status), True), 'alert')

    def test_other_controller_and_io_errors_still_fail(self):
        for prefix in (MESSAGE_PREFIX.replace('c0e00000', 'c1e00000'), 'I/O error, dev sda, sector ', MESSAGE_PREFIX + 'unexpected '):
            with self.subTest(prefix=prefix):
                self.assertEqual(classify_kernel_record(record(prefix=prefix), True), 'alert')

    def test_priority_flags_and_extra_context_not_widened(self):
        for raw in (record(priority=4), record(priority=0), record(flags='c'),
                    record(context=' DEVICE=other\n'),
                    record(context=' SUBSYSTEM=platform\n SUBSYSTEM=platform\n')):
            with self.subTest(raw=raw):
                self.assertEqual(classify_kernel_record(raw, True), 'alert')

    def test_expected_context_remains_valid(self):
        raw = record(context=' SUBSYSTEM=platform\n DEVICE=+platform:c0e00000.ufshc\n')
        self.assertEqual(classify_kernel_record(raw, True), 'known-ufs-bkops-status2')

    def test_informational_markers_remain_visible(self):
        self.assertEqual(classify_kernel_record(b'6,11,2000,-;control begin\n', True), 'informational')

    def test_malformed_record_fails(self):
        for raw in (b'no header', b'3,1;message', b'3,-1,1000,-;message', b'3,1,1000,-;'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                classify_kernel_record(raw, True)

    def test_real_failure_is_not_rewritten(self):
        root = Path('/root/chimera-gcc-performance-578ab8321-20261029')
        if not root.exists():
            self.skipTest('Real remote evidence check runs on K3')
        failed = json.loads((root/'results/u24-r2-x100.json').read_text())
        self.assertFalse(failed['passed'])
        samples = [json.loads(line) for line in (root/'evidence/u24-r2-x100/storage-health.jsonl').read_text().splitlines()]
        self.assertEqual(samples[-1]['bkops_status'], 2)
        validate_storage_sample(samples[-1])
        oldfile = Path('/root/chimera-gcc-validation-578ab8321/kernel_event_policy.py')
        spec = importlib.util.spec_from_file_location('original_preserved_policy', oldfile)
        old = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(old)
        with self.assertRaises(AssertionError):
            old.validate_storage_sample(samples[-1])

    def test_plan_never_reuses_old_round_ids(self):
        root = Path('/root/chimera-gcc-performance-578ab8321-20261029')
        if not root.exists():
            self.skipTest('Full import requires the K3 validation environment')
        from performance_controller_v2 import plan
        rows = plan()
        self.assertEqual(len(rows), 108)
        self.assertEqual(sum(r['measured'] for r in rows), 89)
        self.assertTrue(all(r['run_id'].startswith('a2-') for r in rows))
        self.assertEqual(len({r['run_id'] for r in rows}), 108)
        self.assertEqual(sum(r['kind'] == 'image' for r in rows), 12)


if __name__ == '__main__':
    unittest.main(verbosity=2)
