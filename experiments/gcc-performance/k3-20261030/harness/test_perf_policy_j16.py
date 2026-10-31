"""All maintenance checks unchanged; validate the current isolated j16 plan."""
import json
from pathlib import Path
from test_perf_policy_v2 import BoundaryTests as PriorBoundaryTests
class BoundaryTests(PriorBoundaryTests):
    def test_plan_never_reuses_old_round_ids(self):
        from image_controller_j16_v2 import build_rows
        rows=build_rows()
        self.assertEqual(len(rows),12)
        self.assertEqual(sum(r['measured'] for r in rows),9)
        self.assertEqual({r['workers'] for r in rows},{16})
        current={r['run_id'] for r in rows}
        self.assertEqual(len(current),12)
        prior=Path('/root/chimera-gcc-performance-578ab8321-20261029/performance-plan-attempt2.json')
        local=Path(__file__).parent/'image-plan-j16.json'
        for path in (prior,local):
            self.assertTrue(current.isdisjoint({r['run_id'] for r in json.loads(path.read_text())['rows']}))
        for mode in ('x100','auto-x100','auto-a100'):
            self.assertEqual(sum(r['measured'] and r['mode']==mode for r in rows),3)
