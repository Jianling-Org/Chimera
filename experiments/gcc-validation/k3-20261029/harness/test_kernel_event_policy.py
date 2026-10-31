import unittest
from kernel_event_policy import KNOWN_MESSAGE, classify_kernel_record, validate_storage_sample


def record(message=KNOWN_MESSAGE, priority=3, context='', flags='-'):
    return f'{priority},860,156676026803,{flags};{message}\n{context}'.encode()


class KnownKernelEventTests(unittest.TestCase):
    def test_exact_known_event_requires_explicit_authorization(self):
        event = record(context=' SUBSYSTEM=platform\n DEVICE=+platform:c0e00000.ufshc\n')
        self.assertEqual(classify_kernel_record(event), 'alert')
        self.assertEqual(classify_kernel_record(event, True), 'known-ufs-bkops-status1')

    def test_other_statuses_controllers_and_extra_message_never_match(self):
        for message in (KNOWN_MESSAGE[:-1] + '2', KNOWN_MESSAGE[:-1] + '3',
                        KNOWN_MESSAGE[:-1] + '10', KNOWN_MESSAGE.replace('c0e00000', 'c0f00000'),
                        KNOWN_MESSAGE + ' I/O error', KNOWN_MESSAGE + '\ncritical failure'):
            self.assertEqual(classify_kernel_record(record(message), True), 'alert')

    def test_other_device_context_and_continued_records_fail(self):
        for event in (record(context=' DEVICE=+platform:c0f00000.ufshc\n'),
                      record(context=' SUBSYSTEM=block\n'), record(flags='c')):
            self.assertEqual(classify_kernel_record(event, True), 'alert')

    def test_more_urgent_severity_and_userspace_facility_cannot_use_exception(self):
        for priority in (0, 1, 2, 4, 11):
            self.assertEqual(classify_kernel_record(record(priority=priority), True), 'alert')

    def test_unrelated_io_and_warning_records_still_fail(self):
        for message in ('I/O error, dev sda, sector 123', 'WARNING: scheduler error',
                        'ufshcd-spacemit-k3: critical health failure'):
            self.assertEqual(classify_kernel_record(record(message), True), 'alert')
        self.assertEqual(classify_kernel_record(record('ordinary info', 6), True), 'informational')

    def test_malformed_evidence_does_not_pass(self):
        for block in (b'broken', b'3,860,bad,-;message\n', b'3,860,1;message\n'):
            with self.assertRaises(ValueError):
                classify_kernel_record(block, True)


class StorageBoundaryTests(unittest.TestCase):
    def test_noncritical_status0_and1_require_zero_health(self):
        for status in (0, 1):
            validate_storage_sample(dict(bkops_status=status, critical_health=0))

    def test_performance_critical_unknown_and_wrong_type_statuses_fail(self):
        for status in (2, 3, -1, 4, '1', True):
            with self.assertRaises(AssertionError):
                validate_storage_sample(dict(bkops_status=status, critical_health=0))

    def test_health_failure_and_missing_fields_fail(self):
        for health in (1, 2, '0', None, False):
            with self.assertRaises(AssertionError):
                validate_storage_sample(dict(bkops_status=1, critical_health=health))
        with self.assertRaises(KeyError):
            validate_storage_sample(dict(bkops_status=0))


if __name__ == '__main__':
    unittest.main()
