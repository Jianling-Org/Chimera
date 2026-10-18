import argparse
import json
from pathlib import Path
import random
import statistics
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1]))
from verify.ime_q3_gemm.summarize import kde_mode

parser = argparse.ArgumentParser(description='Summarize correctness-gated in-process paired GEMM samples')
parser.add_argument('directory', type=Path)
args = parser.parse_args()
workload = json.loads((HERE/'workload.json').read_text())
cases = {case['name']: case for case in workload['cases']}
rows = []
seen = set()
inputs = {}
for path in sorted(args.directory.rglob('*.json')):
    record = json.loads(path.read_text())
    if 'pairs' not in record:
        continue
    name = record.get('case') or path.name.split('-')[0]
    case = cases[name]
    direction = 'forward' if record['target_vlenb'] == 32 else 'reverse'
    profile = workload['paths'][direction]
    baseline, candidate = record['seconds_per_call_baseline'], record['seconds_per_call_candidate']
    assert record['validation'] == 'PASS' and record['max_abs_error'] == 0
    assert record['canaries_and_inputs_intact'] and record['translation_state_intact']
    assert record['initial_gate_errors'] == [0, 0]
    assert record['state_mode'] == 'independent TLS per variant'
    assert (record['M'], record['N'], record['K']) == (case['M'], case['N'], case['K'])
    assert record['samples'] == len(baseline) == len(candidate) == len(record['pairs'])
    assert record['pair_orders'] == ['AB' if i % 2 == 0 else 'BA' for i in range(record['samples'])]
    assert all(x > 0 for x in baseline + candidate)
    assert record['source_state_vlenb_baseline'] == record['source_state_vlenb_candidate'] == [record['source_vlenb']] * 8
    assert record['source_vlenb'] * 8 == profile['source_vlen_bits']
    assert record['target_vlenb'] * 8 == profile['target_vlen_bits']
    assert record['threads'] == 8
    assert record['affinity_masks'] == [1 << cpu for cpu in profile['worker_cpus']]
    for pair in record['pairs']:
        for variant in ('baseline', 'candidate'):
            sample = pair[variant]
            assert sample['validation'] == 'PASS' and sample['max_abs_error'] == 0 and sample['canaries_and_inputs_intact']
            for cpu, worker in zip(profile['worker_cpus'], sample['worker_environment']):
                assert worker['cpu_before'] == worker['cpu_after'] == cpu
                assert worker['vlenb_before'] == worker['vlenb_after'] == record['target_vlenb']
                assert worker['frequency_before_khz'] == worker['frequency_after_khz'] == profile['frequency_khz']
    previous = inputs.setdefault(name, record['input_hashes'])
    assert previous == record['input_hashes']
    key = (path.parent.name, name, direction)
    assert key not in seen, key
    seen.add(key)
    gains = [(1-c/b)*100 for b, c in zip(baseline, candidate)]
    rng = random.Random(20261013)
    medians = sorted(statistics.median(rng.choices(gains, k=len(gains))) for _ in range(10000))
    row = {'experiment': path.parent.name, 'case': name, 'use': case['use'], 'direction': direction,
        'samples': len(gains), 'baseline_kde_ms': kde_mode(baseline)*1000,
        'candidate_kde_ms': kde_mode(candidate)*1000,
        'baseline_median_ms': statistics.median(baseline)*1000,
        'candidate_median_ms': statistics.median(candidate)*1000,
        'paired_median_time_reduction_percent': statistics.median(gains),
        'paired_bootstrap_95_interval_percent': [medians[249], medians[9749]],
        'positive_pairs': sum(g > 0 for g in gains), 'input_hashes': record['input_hashes'],
        'raw_file': str(path.relative_to(args.directory))}
    rows.append(row)
    print(json.dumps({k:v for k,v in row.items() if k not in ('input_hashes','raw_file')}))
result = {'operator': workload['primary_symbol'],
    'method': 'Paired median time reduction; 10000 iid paired bootstrap replicates, seed 20261013. KDE: Gaussian global mode with Scott bandwidth.',
    'interval_boundary': 'Bootstrap intervals describe these paired samples; they do not account for serial autocorrelation or predict other shapes.',
    'rows': rows}
(args.directory/'summary.json').write_text(json.dumps(result, indent=2)+'\n')
