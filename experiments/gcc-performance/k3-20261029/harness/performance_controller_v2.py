"""Serial round orchestration; systemd --wait, not an interactive SSH monitor."""
import argparse,statistics
from perf_common_v2 import *

def plan():
    modes=list(MODES)
    orders=[modes,[modes[1],modes[3],modes[0],modes[2]],[modes[3],modes[2],modes[1],modes[0]],[modes[2],modes[0],modes[3],modes[1]],list(reversed(modes))]
    rows=[]
    for workers in (1,8,16,24):
        for mode in modes:rows.append(dict(run_id=f'u{workers}-warm-{mode}',kind='units',mode=mode,workers=workers,measured=False))
        for repeat,order in enumerate(orders,1):
            for mode in order:rows.append(dict(run_id=f'u{workers}-r{repeat}-{mode}',kind='units',mode=mode,workers=workers,measured=True))
    main=modes[:3]
    for mode in main:rows.append(dict(run_id='image-warm-'+mode,kind='image',mode=mode,workers=8 if mode=='x100' else 16,measured=False))
    for repeat in range(3):
        for mode in main[repeat:]+main[:repeat]:rows.append(dict(run_id=f'image-r{repeat+1}-{mode}',kind='image',mode=mode,workers=8 if mode=='x100' else 16,measured=True))
    assert len(rows)==108 and sum(row['measured'] for row in rows)==89
    for row in rows:row['run_id']='a2-'+row['run_id']
    return rows

def launch(row):
    name=row['run_id'];result=P/'results'/(name+'.json')
    if result.exists():return verify_previous(name)[0]
    assert not (P/'evidence'/name).exists(),'Unfinishedroundexists; inspectinstead of overwriting'
    args=['--run-id',name,'--kind',row['kind'],'--mode',row['mode'],'--workers',str(row['workers'])]
    if row['measured']:args.append('--measured')
    unit='chimera-gcc-perf-'+name+'.service'
    runtime='4h' if row['kind']=='image' else '2h'
    command=['systemd-run','--wait','--unit='+unit,'--service-type=exec','--working-directory='+str(P),
      '--property=MemoryHigh=10G','--property=MemoryMax=12G','--property=MemorySwapMax=0','--property=OOMPolicy=stop',
      '--property=RuntimeMaxSec='+runtime,'--property=TimeoutStopSec=30s','--property=KillMode=control-group',
      '--property=ExecStopPost=/usr/bin/python3 '+str(P/'record_resources.py')+' '+name,
      '--property=StandardOutput=append:'+str(P/'logs'/(name+'.log')),
      '--property=StandardError=append:'+str(P/'logs'/(name+'.log')),
      '--setenv=CHIMERA_USER_CONFIG='+str(V/'user.toml'),'--setenv=PYTHONUNBUFFERED=1',
      '/usr/bin/time','-v','-o',str(P/'results'/(name+'.time.txt')),str(V/'venv/bin/python'),str(P/'performance_round_v2.py'),*args]
    save(P/'evidence'/(name+'-launch.json'),dict(command=command))
    completed=subprocess.run(command,capture_output=True,text=True)
    save(P/'evidence'/(name+'-unit-wait.json'),dict(rc=completed.returncode,stdout=completed.stdout,stderr=completed.stderr))
    assert completed.returncode==0,('Roundunitfailed',name,completed.returncode)
    result,resource=verify_previous(name)
    assert all(result[k]==row[k] for k in ('run_id','kind','mode','workers','measured'))
    return result

def main(attempt):
    assert attempt==2;verify_authorization();verify_previous('prelaunch-2')
    accepted=load(P/'evidence/attempt2-prelaunch/result.json');assert accepted['passed'] and accepted['rc']==0
    assert accepted['authorization_sha256']==sha(P/'storage-policy-authorization-attempt2.json')
    assert all(sha(P/name)==digest for name,digest in accepted['frozen_source_sha256'].items()),'Prelaunch frozen identity changed'
    unit=f'chimera-gcc-perf-controller-{attempt}.service';root=P/'evidence'/f'controller-{attempt}'
    assert not root.exists();root.mkdir();verify_setup();verify_previous('preflight-1');guard();zero_ledgers()
    from performance_round_v2 import temperatures,platform_settings
    if (P/'platform-settings.json').exists():assert load(P/'platform-settings.json')==platform_settings()
    else:save(P/'platform-settings.json',platform_settings())
    rows=plan();document=dict(data_epoch='attempt-2',storage_policy=POLICY,prior_attempt_not_pooled=True,rows=rows,unit_concurrency_points=[1,8,16,24],unit_tasks=64,unit_warmups_each=1,unit_measured_each=5,image_warmups_each=1,image_measured_each=3,core_comparison='nativeX1008-j8 vsauto16-j16 forImage;sameconcurrencyunitresultsandstaticmixedcontrolreportedseparately',source_sha256={name:sha(P/name) for name in ('performance_controller_v2.py','performance_round_v2.py','perf_common_v2.py','perf_storage_policy_v2.py','perf_common.py','native-launch.c','bin/native-launch','storage-policy-authorization-attempt2.json')})
    if (P/'performance-plan-attempt2.json').exists():assert load(P/'performance-plan-attempt2.json')==document
    else:save(P/'performance-plan-attempt2.json',document)
    state('performance_controller','running',unit,step='idle_temperature_baseline',total_rounds=len(rows))
    if not (P/'temperature-baseline-attempt2.json').exists():
        time.sleep(120)
        samples=[]
        for _ in range(5):samples.append(temperatures());time.sleep(2)
        assert samples[0] and all(set(s)==set(samples[0]) for s in samples)
        baseline={key:int(statistics.median(s[key] for s in samples)) for key in samples[0]}
        save(P/'temperature-baseline-attempt2.json',dict(temperature_millicelsius=baseline,initial_idle_seconds=130,allowed_start_above_baseline_millicelsius=3000,samples=samples))
    completed=[]
    for ordinal,row in enumerate(rows,1):
        assert all(sha(P/name)==digest for name,digest in document['source_sha256'].items()),'Frozenbenchmarkharnesschanged'
        state('performance_controller','running',unit,step='dispatch_round',ordinal=ordinal,total_rounds=len(rows),next_round=row,completed_rounds=len(completed))
        result=launch(row)
        resource=load(P/'results'/(row['run_id']+'.resources.json'))
        completed.append(dict(**row,wall_seconds=result['wall_seconds'],throughput_objects_per_second=result['throughput_objects_per_second'],result_sha256=sha(P/'results'/(row['run_id']+'.json')),resource_sha256=sha(P/'results'/(row['run_id']+'.resources.json')),peak_bytes=int(resource['memory.peak']),swap_peak_bytes=int(resource['memory.swap.peak']),migration_deltas=result['migration_deltas']))
        save(root/'progress.json',dict(completed=completed,remaining=len(rows)-len(completed)))
    groups={}
    for row in completed:
        if row['measured']:groups.setdefault((row['kind'],row['workers'],row['mode']),[]).append(row['wall_seconds'])
    summary=[]
    for (kind,workers,mode),values in groups.items():
        assert len(values)==(5 if kind=='units' else 3)
        summary.append(dict(kind=kind,workers=workers,mode=mode,runs=len(values),raw_seconds=values,median_seconds=statistics.median(values),min_seconds=min(values),max_seconds=max(values)))
    result=dict(passed=True,rc=0,data_epoch='attempt-2',storage_policy=POLICY,prior_attempt_not_pooled=True,attempt=attempt,total_rounds=len(completed),measured_rounds=sum(r['measured'] for r in completed),rounds=completed,summary=summary,independent_audit_and_chinese_report_pending=True,conditional_scope='assume-scalar-independent',completed_utc=datetime.datetime.now(datetime.timezone.utc).isoformat())
    save(P/'results'/f'controller-{attempt}.json',result);state('performance_controller','phase_complete',unit,rc=0,independent_audit_and_report_pending=True)

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--attempt',type=int,required=True);a=parser.parse_args()
    try:main(a.attempt)
    except BaseException as error:
        save(P/'results'/f'controller-{a.attempt}.json',dict(passed=False,rc=1,error=repr(error)))
        state('performance_controller','failed',f'chimera-gcc-perf-controller-{a.attempt}.service',rc=1,error=repr(error));raise
