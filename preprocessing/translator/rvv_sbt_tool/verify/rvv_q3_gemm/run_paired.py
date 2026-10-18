#!/usr/bin/env python3
"""Run one in-process AB/BA experiment for selected pinned GEMM shapes."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import time

HERE=Path(__file__).resolve().parent


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--direction',choices=('forward','reverse'),required=True)
    parser.add_argument('--samples',choices=(20,50),type=int,default=50)
    parser.add_argument('--cases',nargs='+',choices=('ffn_up_m32','ffn_down_m32','attn_q_m32','attn_kv_m32'))
    args=parser.parse_args()
    workload=json.loads((HERE/'workload.json').read_text())
    manifest=json.loads((HERE/f'build-{args.direction}.json').read_text())
    binary=HERE/f'bench-paired-{args.direction}'
    assert sha(binary)==manifest['binary_sha256']
    assert manifest['default_samples']==args.samples, 'Rebuild with the requested BENCH_SAMPLES'
    cpu_first,target,source,frequency=(0,32,128,2200000) if args.direction=='forward' else (8,128,32,1800000)
    for case in workload['cases']:
        if args.cases and case['name'] not in args.cases:
            continue
        reference=HERE/f"{case['name']}.ref"
        assert sha(reference)==workload['reference_sha256'][case['name']]
        command=['timeout','300s','taskset','-c',f'{cpu_first}-{cpu_first+7}',str(binary),'measure',
                 str(case['M']),str(case['N']),str(case['K']),str(reference),str(args.samples)]
        if args.direction=='reverse':
            command=['sh','-c','printf 0 > /proc/set_ai_thread; exec "$@"','sh',*command]
        suffix=f"{case['name']}-{args.direction}-{args.samples}pairs-{manifest['binary_sha256'][:12]}-{time.time_ns()}"
        stderr=HERE/(suffix+'.stderr')
        with stderr.open('w') as stream:
            result=subprocess.run(command,cwd=HERE,text=True,stdout=subprocess.PIPE,stderr=stream)
        raw=HERE/(suffix+'.stdout')
        raw.write_text(result.stdout)
        if result.returncode:
            raise RuntimeError(f'Paired harness exited {result.returncode}; stdout={raw}; stderr={stderr}')
        record=json.loads(result.stdout)
        assert record['validation']=='PASS' and record['max_abs_error']==0
        assert record['canaries_and_inputs_intact'] and record['translation_state_intact']
        assert record['state_mode']=='independent TLS per variant'
        assert record['samples']==args.samples
        assert len(record['seconds_per_call_baseline'])==len(record['seconds_per_call_candidate'])==len(record['pairs'])==args.samples
        assert record['pair_orders']==['AB' if pair%2==0 else 'BA' for pair in range(args.samples)]
        assert (record['M'],record['N'],record['K'])==(case['M'],case['N'],case['K'])
        assert record['source_vlenb']==source and record['target_vlenb']==record['vlenb']==target
        assert record['threads']==8 and record['affinity_masks']==[1<<(cpu_first+t) for t in range(8)]
        assert record['source_state_vlenb_baseline']==record['source_state_vlenb_candidate']==[source]*8
        for pair,item in enumerate(record['pairs']):
            assert item['pair']==pair and item['order']==record['pair_orders'][pair]
            baseline=record['seconds_per_call_baseline'][pair]
            candidate=record['seconds_per_call_candidate'][pair]
            assert item['gain']==baseline/candidate
            for variant,expected in (('baseline',baseline),('candidate',candidate)):
                sample=item[variant]
                assert sample['validation']=='PASS' and sample['max_abs_error']==0 and sample['canaries_and_inputs_intact']
                assert sample['seconds_per_call']==expected
                assert len(sample['worker_environment'])==8
                for t,worker in enumerate(sample['worker_environment']):
                    assert worker['cpu_before']==worker['cpu_after']==cpu_first+t
                    assert worker['vlenb_before']==worker['vlenb_after']==target
                    assert worker['frequency_before_khz']==worker['frequency_after_khz']==frequency
        record.update(case=case['name'],direction=args.direction,build_manifest=manifest,
                      reference_sha256=sha(reference),raw_stdout=str(raw),stderr=str(stderr))
        output=HERE/(suffix+'.json')
        output.write_text(json.dumps(record,indent=2)+'\n')
        print(json.dumps({'case':case['name'],'direction':args.direction,'samples':args.samples,
                          'validation':record['validation'],'output':str(output)}),flush=True)
