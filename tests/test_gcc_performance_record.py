# SPDX-License-Identifier: Apache-2.0
"""Offline checks for the published K3 record; no device operations or imports."""
from __future__ import annotations
import ast
import hashlib
import importlib.util
from io import StringIO
import json
import math
from pathlib import Path, PurePosixPath
import statistics
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1] / 'experiments/gcc-performance/k3-20261030'

def load(relative):
    return json.loads((ROOT / relative).read_text(encoding='utf-8'))

def digest(relative):
    return hashlib.sha256((ROOT / relative).read_bytes()).hexdigest()

class GccPerformanceRecordTests(unittest.TestCase):
    def test_snapshot_and_publication_byte_identities(self):
        manifest = load('provenance.json')['files']
        actual = {p.relative_to(ROOT).as_posix() for directory in ('harness', 'results')
                  for p in (ROOT / directory).rglob('*')
                  if p.is_file() and '__pycache__' not in p.parts}
        self.assertEqual(set(manifest), actual)
        for name, record in manifest.items():
            with self.subTest(name=name):
                self.assertNotIn('..', PurePosixPath(name).parts)
                self.assertFalse(PurePosixPath(name).is_absolute())
                self.assertEqual((ROOT / name).stat().st_size, record['bytes'])
                self.assertEqual(digest(name), record['sha256'])
        publication = load('results/report-publication.json')
        self.assertEqual(digest('results/同16并发性能报告.zh-CN.md'), publication['report_sha256'])
        self.assertEqual(digest('results/performance-summary-j16.json'), publication['summary_sha256'])
        charts = load('results/chart-publication.json')
        self.assertEqual(charts['input_summary_sha256'], publication['summary_sha256'])
        for row in charts['files']:
            self.assertEqual(digest('results/' + row['name']), row['sha256'])

    def test_actual_completion_scope_and_frozen_sources(self):
        done = load('results/completion.json')
        self.assertTrue(done['performance_completed'])
        self.assertEqual(done['scope'], 'assume-scalar-independent')
        self.assertEqual(done['all_groups_image_jobs'], 16)
        self.assertEqual(done['native_compiler_cpu_mask'], '0-7')
        self.assertEqual((done['new_image_rounds'], done['retained_unit_rounds']), (12, 96))
        for stage in ('controller', 'prelaunch', 'audit', 'report'):
            self.assertEqual(done[stage + '_actual_exit'], 'success/exited/0')
        self.assertTrue(done['watchdog_stopped'])
        self.assertEqual(done['automation_status'], 'deleted')
        for filename in ('protocol-checks.json', 'protocol-checks-attempt2.json'):
            for name, expected in load('results/' + filename)['source_sha256'].items():
                self.assertEqual(digest('harness/' + name), expected)
        for name in ('final_audit_j16_1.py', 'build_report_j16_1.py'):
            self.assertEqual(digest('harness/' + name), done['files'][name]['sha256'])
        self.assertTrue(done['old_image_times_not_pooled'])

    def test_image_schedule_controls_concurrency_and_order(self):
        tree = ast.parse((ROOT / 'harness/image_controller_j16_v2.py').read_text(encoding='utf-8'))
        function = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'build_rows')
        namespace = {}
        exec(compile(ast.Module(body=[function], type_ignores=[]), '<isolated schedule>', 'exec'), namespace)
        rows = namespace['build_rows']()
        modes = {'x100', 'auto-x100', 'auto-a100'}
        self.assertEqual(len(rows), 12)
        self.assertEqual(len({r['run_id'] for r in rows}), 12)
        self.assertEqual({r['workers'] for r in rows}, {16})
        self.assertEqual({r['kind'] for r in rows}, {'image'})
        self.assertEqual(sum(r['measured'] for r in rows), 9)
        self.assertTrue(all(r['run_id'].startswith('i5-') for r in rows))
        for mode in modes:
            self.assertEqual(sum(r['mode'] == mode and not r['measured'] for r in rows), 1)
            self.assertEqual(sum(r['mode'] == mode and r['measured'] for r in rows), 3)
            positions = {next(i for i, r in enumerate(rows[3 + repeat*3:6 + repeat*3])
                              if r['mode'] == mode) for repeat in range(3)}
            self.assertEqual(positions, {0, 1, 2})

    def test_statistics_recomputed_from_all_published_samples(self):
        summary = load('results/performance-summary-j16.json')
        image, units = summary['image_statistics'], summary['unit_statistics']
        self.assertEqual({r['workers'] for r in image}, {16})
        self.assertEqual({(r['workers'], r['mode']) for r in units},
                         {(w, m) for w in (1, 8, 16, 24)
                          for m in ('x100', 'auto-x100', 'auto-a100', 'static16')})
        groups = {(r['kind'], r['workers'], r['mode']): r for r in image + units}
        self.assertEqual(len(groups), 19)
        self.assertEqual(sum(r['n'] for r in groups.values()), 89)
        for (kind, workers, mode), row in groups.items():
            with self.subTest(kind=kind, workers=workers, mode=mode):
                values = row['raw_seconds']; med = statistics.median(values)
                self.assertEqual(len(values), 3 if kind == 'image' else 5)
                self.assertEqual(row['n'], len(values))
                self.assertTrue(all(math.isfinite(v) and v > 0 for v in values))
                self.assertEqual((row['median_seconds'], row['min_seconds'], row['max_seconds']),
                                 (med, min(values), max(values)))
                native = groups[(kind, workers, 'x100')]['median_seconds']
                self.assertAlmostEqual(row['throughput_per_second'], (1 if kind == 'image' else 64) / med)
                self.assertAlmostEqual(row['speedup_vs_native'], native / med)
                self.assertAlmostEqual(row['time_reduction_percent'], (1 - med / native) * 100)

    def test_recorded_cpu_use_and_no_image_pooling(self):
        summary = load('results/performance-summary-j16.json')
        self.assertTrue(summary['old_j8_image_primary_comparison_superseded'])
        self.assertTrue(summary['old_image_times_not_pooled'])
        self.assertEqual(summary['audit_actual_exit'], 'success/exited/0')
        self.assertEqual({r['mode'] for r in summary['image_cpu']}, {'x100', 'auto-x100', 'auto-a100'})
        for row in summary['image_cpu']:
            self.assertTrue(row['raw_cpu_ticks_recomputed'])
            self.assertEqual(row['cpus_observed'], list(range(8 if row['mode'] == 'x100' else 16)))
            self.assertTrue(all(0 <= v <= 100 for v in row['cluster_system_mean_busy_percent'].values()))
            self.assertGreater(row['mean_child_cpu_equivalent_cores'], 0)
            self.assertLess(row['mean_child_cpu_equivalent_cores'], 16)

    def test_archived_python_syntax_and_stdout_fix(self):
        for path in (ROOT / 'harness').rglob('*.py'):
            compile(path.read_bytes(), str(path), 'exec')
        launcher = (ROOT / 'harness/native-launch-image-v3.c').read_text(encoding='utf-8')
        self.assertNotIn('environment[entries++]=pid_env', launcher)
        for setting in ('LD_PRELOAD=', 'CHIMERA_BOOTSTRAP=', 'CHIMERA_REGISTRY='):
            self.assertIn('environment[entries++]="' + setting, launcher)
        self.assertIn('inherit:', launcher)

    def test_preserved_device_independent_maintenance_boundaries(self):
        def module(name, filename):
            spec = importlib.util.spec_from_file_location(name, ROOT / 'harness' / filename)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            return mod
        policy = module('_gcc_record_policy', 'perf_storage_policy_v2.py')
        with patch.dict(sys.modules, {'perf_storage_policy_v2': policy}):
            cases = module('_gcc_record_boundaries', 'test_perf_policy_v2.py')
        device_only = {'test_real_failure_is_not_rewritten', 'test_plan_never_reuses_old_round_ids'}
        names = [name for name in unittest.defaultTestLoader.getTestCaseNames(cases.BoundaryTests)
                 if name not in device_only]
        self.assertEqual(len(names), 12)
        output = StringIO()
        result = unittest.TextTestRunner(stream=output).run(
            unittest.TestSuite(cases.BoundaryTests(name) for name in names))
        self.assertEqual(result.testsRun, 12)
        self.assertFalse(result.skipped)
        self.assertTrue(result.wasSuccessful(), output.getvalue())

if __name__ == '__main__':
    unittest.main()
