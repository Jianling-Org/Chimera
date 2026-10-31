from types import SimpleNamespace
import unittest
from unittest.mock import patch
import resource_policy as resources


class ResourceBudgetTests(unittest.TestCase):
    def test_prepare_budget_covers_both_routes_swap_and_margin(self):
        p = resources.policy('prepare_cc1')
        self.assertEqual(p['required_free_bytes'], 50 * resources.GIB)
        self.assertGreaterEqual(p['required_free_bytes'], p['swap_bytes'] + p['workspace_budget_bytes'] + p['disk_margin_bytes'])
        self.assertGreaterEqual(p['disk_margin_bytes'], 2 * 3 * resources.GIB)

    def test_insufficient_disk_fails_before_any_allocation_or_swap(self):
        with patch.object(resources, 'check_path'), patch.object(resources.shutil, 'disk_usage', return_value=SimpleNamespace(free=49 * resources.GIB)), patch.object(resources.subprocess, 'run') as run, patch.object(resources.os, 'open') as open_file:
            with self.assertRaisesRegex(RuntimeError, 'Insufficient disk before allocation'):
                resources.enable('prepare_cc1-2', resources.policy('prepare_cc1'))
            run.assert_not_called()
            open_file.assert_not_called()

    def test_memory_swap_limits_and_nonprepare_timeout_remain_unchanged(self):
        p = resources.policy('prepare_cc1')
        self.assertEqual((p['memory_high'], p['memory_max'], p['swap_max'], p['runtime_max']), ('12G', '13G', '16G', '18h'))
        self.assertEqual(resources.policy('metadata_cc1')['runtime_max'], '6h')
        self.assertEqual(resources.policy('strict_cc1')['runtime_max'], '6h')
        self.assertNotIn('required_free_bytes', resources.policy('metadata_cc1'))


if __name__ == '__main__':
    unittest.main()
