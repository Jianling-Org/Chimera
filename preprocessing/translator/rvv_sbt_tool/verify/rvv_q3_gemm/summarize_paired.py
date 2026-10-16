import argparse
import json
from pathlib import Path
import random
import statistics
import sys

from validation import read_json, require_fields

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1]))
from verify.ime_q3_gemm.summarize import kde_mode

parser = argparse.ArgumentParser(description='Summarize correctness-gated in-process paired GEMM samples')
parser.add_argument('directory', type=Path)
args = parser.parse_args()
workload = read_json(HERE/'workload.json')
cases = {case['name']: case for case in workload['cases']}
rows = []
seen = set()
inputs = {}
for path in sorted(args.directory.rglob('*.json')):
    record = read_json(path)
    if 'pairs' not in record:
        continue
    require_fields(record, ('K', 'M', 'N', 'affinity_masks', 'canaries_and_inputs_intact', 'initial_gate_errors', 'input_hashes', 'max_abs_error', 'pair_orders', 'pairs', 'samples', 'seconds_per_call_baseline', 'seconds_per_call_candidate', 'source_state_vlenb_baseline', 'source_state_vlenb_candidate', 'source_vlenb', 'state_mode', 'target_vlenb', 'threads', 'translation_state_intact', 'validation'), path)
    name = record.get('case') or path.name.split('-')[0]
    case = cases[name]
    direction = 'forward' if record['target_vlenb'] == 32 else 'reverse'
    profile = workload['paths'][direction]
    baseline, candidate = record['seconds_per_call_baseline'], record['seconds_per_call_candidate']
    if record['samples'] not in (20, 50):
        raise ValueError(f'{path}: paired samples must be 20 or 50')
    if not (record['validation'] == 'PASS' and record['max_abs_error'] == 0):
        raise ValueError(f"{path}: validation failed: validation={record['validation']!r}; max_abs_error={record['max_abs_error']!r}")
    if not (record['canaries_and_inputs_intact'] and record['translation_state_intact']):
        raise ValueError(f"{path}: validation failed: canaries_and_inputs_intact={record['canaries_and_inputs_intact']!r}; translation_state_intact={record['translation_state_intact']!r}")
    if record['initial_gate_errors'] != [0, 0]:
        raise ValueError(f"{path}: validation failed: initial_gate_errors={record['initial_gate_errors']!r}")
    if record['state_mode'] != 'independent TLS per variant':
        raise ValueError(f"{path}: validation failed: state_mode={record['state_mode']!r}")
    if (record['M'], record['N'], record['K']) != (case['M'], case['N'], case['K']):
        raise ValueError(f"{path}: validation failed: M={record['M']!r}; N={record['N']!r}; K={record['K']!r}; expected_M={case['M']!r}; expected_N={case['N']!r}; expected_K={case['K']!r}")
    if not record['samples'] == len(baseline) == len(candidate) == len(record['pairs']):
        raise ValueError(f"{path}: validation failed: samples={record['samples']!r}; len(baseline)={len(baseline)!r}; len(candidate)={len(candidate)!r}; len(pairs)={len(record['pairs'])!r}")
    if record['pair_orders'] != ['AB' if i % 2 == 0 else 'BA' for i in range(record['samples'])]:
        raise ValueError(f"{path}: validation failed: pair_orders={record['pair_orders']!r}; samples={record['samples']!r}")
    if not all((x > 0 for x in baseline + candidate)):
        raise ValueError(f'{path}: validation failed: baseline={baseline!r}; candidate={candidate!r}')
    if not record['source_state_vlenb_baseline'] == record['source_state_vlenb_candidate'] == [record['source_vlenb']] * 8:
        raise ValueError(f"{path}: validation failed: source_state_vlenb_baseline={record['source_state_vlenb_baseline']!r}; source_state_vlenb_candidate={record['source_state_vlenb_candidate']!r}; source_vlenb={record['source_vlenb']!r}")
    if record['source_vlenb'] * 8 != profile['source_vlen_bits']:
        raise ValueError(f"{path}: validation failed: source_vlenb={record['source_vlenb']!r}; profile_source_vlen_bits={profile['source_vlen_bits']!r}")
    if record['target_vlenb'] * 8 != profile['target_vlen_bits']:
        raise ValueError(f"{path}: validation failed: target_vlenb={record['target_vlenb']!r}; profile_target_vlen_bits={profile['target_vlen_bits']!r}")
    if record['threads'] != 8:
        raise ValueError(f"{path}: validation failed: threads={record['threads']!r}")
    if record['affinity_masks'] != [1 << cpu for cpu in profile['worker_cpus']]:
        raise ValueError(f"{path}: validation failed: affinity_masks={record['affinity_masks']!r}; profile_worker_cpus={profile['worker_cpus']!r}")
    for index, pair in enumerate(record['pairs']):
        context = f"{path}: pair={index}"
        require_fields(pair, ('pair', 'order', 'gain', 'baseline', 'candidate'), context)
        if pair['pair'] != index or pair['order'] != record['pair_orders'][index]:
            raise ValueError(f"{context}: index/order mismatch: pair={pair['pair']!r}, order={pair['order']!r}")
        expected_gain = baseline[index] / candidate[index]
        if pair['gain'] != expected_gain:
            raise ValueError(f"{context}: gain={pair['gain']!r}, expected={expected_gain!r}")
        for variant, timings in (('baseline', baseline), ('candidate', candidate)):
            sample = pair[variant]
            require_fields(sample, ('seconds_per_call', 'validation', 'max_abs_error',
                                    'canaries_and_inputs_intact', 'worker_environment'),
                           f"{context}/{variant}")
            if sample['seconds_per_call'] != timings[index]:
                raise ValueError(f"{context}/{variant}: seconds_per_call={sample['seconds_per_call']!r}, array_value={timings[index]!r}")
            if not (sample['validation'] == 'PASS' and sample['max_abs_error'] == 0 and sample['canaries_and_inputs_intact']):
                raise ValueError(f"{path}: validation failed: validation={sample['validation']!r}; max_abs_error={sample['max_abs_error']!r}; canaries_and_inputs_intact={sample['canaries_and_inputs_intact']!r}")
            if len(sample['worker_environment']) != 8 or len(profile['worker_cpus']) != 8:
                raise ValueError(f'{path}: {variant} requires eight worker observations')
            for cpu, worker in zip(profile['worker_cpus'], sample['worker_environment']):
                if not worker['cpu_before'] == worker['cpu_after'] == cpu:
                    raise ValueError(f"{path}: validation failed: worker_cpu_before={worker['cpu_before']!r}; worker_cpu_after={worker['cpu_after']!r}; cpu={cpu!r}")
                if not worker['vlenb_before'] == worker['vlenb_after'] == record['target_vlenb']:
                    raise ValueError(f"{path}: validation failed: worker_vlenb_before={worker['vlenb_before']!r}; worker_vlenb_after={worker['vlenb_after']!r}; target_vlenb={record['target_vlenb']!r}")
                if not worker['frequency_before_khz'] == worker['frequency_after_khz'] == profile['frequency_khz']:
                    raise ValueError(f"{path}: validation failed: worker_frequency_before_khz={worker['frequency_before_khz']!r}; worker_frequency_after_khz={worker['frequency_after_khz']!r}; profile_frequency_khz={profile['frequency_khz']!r}")
    previous = inputs.setdefault(name, record['input_hashes'])
    if previous != record['input_hashes']:
        raise ValueError(f"{path}: validation failed: previous={previous!r}; input_hashes={record['input_hashes']!r}")
    key = (path.parent.name, name, direction)
    if key in seen:
        raise ValueError(f'{path}: validation failed: key={key!r}')
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
if not rows:
    raise ValueError(f'{args.directory}: no paired measurement records')
result = {'operator': workload['primary_symbol'],
    'method': 'Paired median time reduction; 10000 iid paired bootstrap replicates, seed 20261013. KDE: Gaussian global mode with Scott bandwidth.',
    'interval_boundary': 'Bootstrap intervals describe these paired samples; they do not account for serial autocorrelation or predict other shapes.',
    'rows': rows}
(args.directory/'summary.json').write_text(json.dumps(result, indent=2)+'\n')
