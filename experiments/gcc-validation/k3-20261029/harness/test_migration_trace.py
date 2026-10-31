import unittest
from migration_trace import replay


def line(tid, stamp, text):
    return f' cc1-{tid} [001] ...1 {stamp:.6f}: {text}\n'


class TraceReplayTests(unittest.TestCase):
    def test_interleaved_tids_pair_only_real_accepted_ack_and_cpu_commit(self):
        data = [line(10, 1.0, 'ack_enter: generation=1 action=1'),
                line(11, 1.1, 'ack_enter: generation=2 action=2'),
                line(10, 1.2, 'sched_prefer_a100_migrate: pid=10 src_cpu=1 dst_cpu=8 reason=INITIAL'),
                line(11, 1.3, 'ack_return: result=0'), line(10, 1.4, 'ack_return: result=8'),
                line(10, 2.0, 'ack_enter: generation=3 action=1'),
                line(10, 2.1, 'sched_prefer_a100_migrate: pid=10 src_cpu=8 dst_cpu=2 reason=IDLE_PULL'),
                line(10, 2.2, 'ack_return: result=8')]
        audit = replay(data, {10, 11})
        self.assertEqual(audit['route_counts'], {'256-to-1024': 1, '1024-to-256': 1})
        self.assertEqual(audit['both_route_tids'], [10])
        self.assertEqual(audit['raw_accepted_ack_count'], 2)

    def test_rejected_ack_cannot_prove_cpu_commit(self):
        data = [line(10, 1, 'ack_enter: generation=1 action=1'),
                line(10, 2, 'sched_prefer_a100_migrate: pid=10 src_cpu=1 dst_cpu=8 reason=INITIAL'),
                line(10, 3, 'ack_return: result=-11')]
        with self.assertRaisesRegex(ValueError, 'accepted raw ACK'):
            replay(data, {10})

    def test_other_tid_commit_is_not_current_workload_evidence(self):
        data = [line(99, 1, 'sched_prefer_a100_migrate: pid=99 src_cpu=1 dst_cpu=8 reason=INITIAL')]
        self.assertEqual(replay(data, {10})['physical_commits'], [])

    def test_missing_raw_ack_return_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'Incomplete'):
            replay([line(10, 1, 'ack_enter: generation=1 action=1')], {10})


if __name__ == '__main__':
    unittest.main()
