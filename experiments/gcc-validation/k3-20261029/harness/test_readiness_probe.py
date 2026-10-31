import unittest
from readiness_probe import initialization_ready

READY = dict(ready='1', exec_requires_ready='1', preference='prefer-x100',
             SigCgt=f'{(1 << 4) | (1 << 40):x}', SigBlk='0')


class InitializationWitnessTests(unittest.TestCase):
    def test_transient_signal_handler_mask_requires_a_later_complete_witness(self):
        handling = {**READY, 'SigBlk': f'{1 << 40:x}'}
        self.assertFalse(initialization_ready(handling))
        self.assertTrue(initialization_ready(READY))

    def test_permanently_blocked_or_missing_handler_never_counts_ready(self):
        for sample in ({**READY, 'SigBlk': f'{1 << 4:x}'}, {**READY, 'SigCgt': '0'}):
            self.assertFalse(initialization_ready(sample))

    def test_kernel_ready_exec_gate_and_preference_are_all_required(self):
        for key, value in [('ready', '0'), ('exec_requires_ready', '0'), ('preference', 'none')]:
            self.assertFalse(initialization_ready({**READY, key: value}))

    def test_exit_or_incomplete_proc_sample_cannot_be_an_initialization_witness(self):
        self.assertFalse(initialization_ready({**READY, 'SigCgt': '0', 'SigBlk': '0'}))
        self.assertFalse(initialization_ready({**READY, 'SigBlk': None}))


if __name__ == '__main__':
    unittest.main()
