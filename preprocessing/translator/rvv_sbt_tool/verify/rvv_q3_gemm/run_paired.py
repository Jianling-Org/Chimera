#!/usr/bin/env python3
"""Run one in-process AB/BA experiment for selected pinned GEMM shapes."""
import argparse
import hashlib
import json
import math
from pathlib import Path
import subprocess
import time

from validation import read_json, require_fields

HERE=Path(__file__).resolve().parent


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--direction',choices=('forward','reverse'),required=True)
    parser.add_argument('--samples',choices=(20,50),type=int,default=50)
    parser.add_argument('--cases',nargs='+',choices=('ffn_up_m32','ffn_down_m32','attn_q_m32','attn_kv_m32'))
    args=parser.parse_args()
    workload=read_json(HERE/'workload.json')
    manifest=read_json(HERE/f'build-{args.direction}.json')
    binary=HERE/f'bench-paired-{args.direction}'
    if sha(binary) != manifest['binary_sha256']:
        raise ValueError(f"{binary}: validation failed: sha(binary)={sha(binary)!r}; manifest_binary_sha256={manifest['binary_sha256']!r}")
    if manifest['default_samples'] != args.samples:
        raise ValueError(f"{binary}: validation failed: manifest_default_samples={manifest['default_samples']!r}; requested_samples={args.samples!r}")
    cpu_first,target,source,frequency=(0,32,128,2200000) if args.direction=='forward' else (8,128,32,1800000)
    for case in workload['cases']:
        if args.cases and case['name'] not in args.cases:
            continue
        reference=HERE/f"{case['name']}.ref"
        actual_digest=sha(reference)
        expected_digest=workload['reference_sha256'][case['name']]
        if actual_digest != expected_digest:
            raise ValueError(f"{reference}: validation failed: actual_sha256={actual_digest!r}; expected_sha256={expected_digest!r}")
        command=['timeout','300s','taskset','-c',f'{cpu_first}-{cpu_first+7}',str(binary),'measure',
                 str(case['M']),str(case['N']),str(case['K']),str(reference),str(args.samples)]
        if args.direction=='reverse':
            command=['sh','-c','printf 0 > /proc/set_ai_thread && exec "$@"','sh',*command]
        suffix=f"{case['name']}-{args.direction}-{args.samples}pairs-{manifest['binary_sha256'][:12]}-{time.time_ns()}"
        stderr=HERE/(suffix+'.stderr')
        with stderr.open('w') as stream:
            result=subprocess.run(command,cwd=HERE,text=True,stdout=subprocess.PIPE,stderr=stream)
        raw=HERE/(suffix+'.stdout')
        raw.write_text(result.stdout)
        if result.returncode:
            raise RuntimeError(f'Paired harness exited {result.returncode}; stdout={raw}; stderr={stderr}')
        record=read_json(raw)
        require_fields(record, ('K', 'M', 'N', 'affinity_masks', 'canaries_and_inputs_intact', 'max_abs_error', 'pair_orders', 'pairs', 'samples', 'seconds_per_call_baseline', 'seconds_per_call_candidate', 'source_state_vlenb_baseline', 'source_state_vlenb_candidate', 'source_vlenb', 'state_mode', 'target_vlenb', 'threads', 'translation_state_intact', 'validation', 'vlenb'), raw)
        if not (record['validation'] == 'PASS' and record['max_abs_error'] == 0):
            raise ValueError(f"{raw}: validation failed: validation={record['validation']!r}; max_abs_error={record['max_abs_error']!r}")
        if not (record['canaries_and_inputs_intact'] and record['translation_state_intact']):
            raise ValueError(f"{raw}: validation failed: canaries_and_inputs_intact={record['canaries_and_inputs_intact']!r}; translation_state_intact={record['translation_state_intact']!r}")
        if record['state_mode'] != 'independent TLS per variant':
            raise ValueError(f"{raw}: validation failed: state_mode={record['state_mode']!r}")
        if record['samples'] != args.samples:
            raise ValueError(f"{raw}: validation failed: samples={record['samples']!r}; requested_samples={args.samples!r}")
        if not len(record['seconds_per_call_baseline']) == len(record['seconds_per_call_candidate']) == len(record['pairs']) == args.samples:
            raise ValueError(f"{raw}: validation failed: len(seconds_per_call_baseline)={len(record['seconds_per_call_baseline'])!r}; len(seconds_per_call_candidate)={len(record['seconds_per_call_candidate'])!r}; len(pairs)={len(record['pairs'])!r}; requested_samples={args.samples!r}")
        if record['pair_orders'] != ['AB' if pair % 2 == 0 else 'BA' for pair in range(args.samples)]:
            raise ValueError(f"{raw}: validation failed: pair_orders={record['pair_orders']!r}; requested_samples={args.samples!r}")
        if (record['M'], record['N'], record['K']) != (case['M'], case['N'], case['K']):
            raise ValueError(f"{raw}: validation failed: M={record['M']!r}; N={record['N']!r}; K={record['K']!r}; expected_M={case['M']!r}; expected_N={case['N']!r}; expected_K={case['K']!r}")
        if not (record['source_vlenb'] == source and record['target_vlenb'] == record['vlenb'] == target):
            raise ValueError(f"{raw}: validation failed: source_vlenb={record['source_vlenb']!r}; source={source!r}; target_vlenb={record['target_vlenb']!r}; vlenb={record['vlenb']!r}; target={target!r}")
        if not (record['threads'] == 8 and record['affinity_masks'] == [1 << cpu_first + t for t in range(8)]):
            raise ValueError(f"{raw}: validation failed: threads={record['threads']!r}; affinity_masks={record['affinity_masks']!r}; cpu_first={cpu_first!r}")
        if not record['source_state_vlenb_baseline'] == record['source_state_vlenb_candidate'] == [source] * 8:
            raise ValueError(f"{raw}: validation failed: source_state_vlenb_baseline={record['source_state_vlenb_baseline']!r}; source_state_vlenb_candidate={record['source_state_vlenb_candidate']!r}; source={source!r}")
        for pair,item in enumerate(record['pairs']):
            if not (item['pair'] == pair and item['order'] == record['pair_orders'][pair]):
                raise ValueError(f"{raw}: validation failed: pair_orders={record['pair_orders']!r}")
            baseline=record['seconds_per_call_baseline'][pair]
            candidate=record['seconds_per_call_candidate'][pair]
            if not all(math.isfinite(value) and value > 0 for value in (baseline, candidate)):
                raise ValueError(f'{raw}: pair {pair} requires positive finite timings')
            if item['gain'] != baseline / candidate:
                raise ValueError(f'{raw}: validation failed: baseline={baseline!r}; candidate={candidate!r}')
            for variant,expected in (('baseline',baseline),('candidate',candidate)):
                sample=item[variant]
                if not (sample['validation'] == 'PASS' and sample['max_abs_error'] == 0 and sample['canaries_and_inputs_intact']):
                    raise ValueError(f"{raw}: validation failed: validation={sample['validation']!r}; max_abs_error={sample['max_abs_error']!r}; canaries_and_inputs_intact={sample['canaries_and_inputs_intact']!r}")
                if sample['seconds_per_call'] != expected:
                    raise ValueError(f"{raw}: validation failed: seconds_per_call={sample['seconds_per_call']!r}; expected={expected!r}")
                if len(sample['worker_environment']) != 8:
                    raise ValueError(f"{raw}: validation failed: len(worker_environment)={len(sample['worker_environment'])!r}")
                for t,worker in enumerate(sample['worker_environment']):
                    if not worker['cpu_before'] == worker['cpu_after'] == cpu_first + t:
                        raise ValueError(f"{raw}: validation failed: worker_cpu_before={worker['cpu_before']!r}; worker_cpu_after={worker['cpu_after']!r}; cpu_first={cpu_first!r}")
                    if not worker['vlenb_before'] == worker['vlenb_after'] == target:
                        raise ValueError(f"{raw}: validation failed: worker_vlenb_before={worker['vlenb_before']!r}; worker_vlenb_after={worker['vlenb_after']!r}; target={target!r}")
                    if not worker['frequency_before_khz'] == worker['frequency_after_khz'] == frequency:
                        raise ValueError(f"{raw}: validation failed: worker_frequency_before_khz={worker['frequency_before_khz']!r}; worker_frequency_after_khz={worker['frequency_after_khz']!r}; frequency={frequency!r}")
        record.update(case=case['name'],direction=args.direction,build_manifest=manifest,
                      reference_sha256=sha(reference),raw_stdout=str(raw),stderr=str(stderr))
        output=HERE/(suffix+'.json')
        output.write_text(json.dumps(record,indent=2)+'\n')
        print(json.dumps({'case':case['name'],'direction':args.direction,'samples':args.samples,
                          'validation':record['validation'],'output':str(output)}),flush=True)
