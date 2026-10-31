"""Balanced fresh Image comparison: every mode uses exactly make -j16."""
import statistics
from perf_common_j16 import *

UNIT='chimera-gcc-j16-controller-2.service'
ROOT=P/'evidence/controller-2'

def build_rows():
    modes=('x100','auto-x100','auto-a100');rows=[]
    for mode in modes:rows.append(dict(run_id='i5-warm-'+mode,kind='image',mode=mode,workers=16,measured=False))
    for repeat in range(3):
        for mode in modes[repeat:]+modes[:repeat]:
            rows.append(dict(run_id=f'i5-r{repeat+1}-{mode}',kind='image',mode=mode,workers=16,measured=True))
    assert len(rows)==12 and all(x['workers']==16 for x in rows)
    assert all(sum(x['measured'] and x['mode']==m for x in rows)==3 for m in modes)
    return rows

def run_unit(record,script,args,runtime,memory='12G',high='10G'):
    assert not (P/'results'/(record+'.json')).exists() and not (P/'evidence'/record).exists()
    command=['systemd-run','--wait','--unit=chimera-gcc-j16-'+record+'.service','--service-type=exec',
      '--working-directory='+str(P),'--property=MemoryHigh='+high,'--property=MemoryMax='+memory,
      '--property=MemorySwapMax=0','--property=OOMPolicy=stop','--property=RuntimeMaxSec='+runtime,
      '--property=TimeoutStopSec=30s','--property=KillMode=control-group',
      '--property=ExecStopPost=/usr/bin/python3 '+str(P/'record_resources.py')+' '+record,
      '--property=StandardOutput=append:'+str(P/'logs'/(record+'.log')),
      '--property=StandardError=append:'+str(P/'logs'/(record+'.log')),
      '--setenv=CHIMERA_USER_CONFIG='+str(V/'user.toml'),'--setenv=PYTHONUNBUFFERED=1',
      '/usr/bin/time','-v','-o',str(P/'results'/(record+'.time.txt')),str(V/'venv/bin/python'),str(P/script),*args]
    save(P/'evidence'/(record+'-launch.json'),dict(command=command))
    wait=subprocess.run(command,capture_output=True,text=True)
    save(P/'evidence'/(record+'-unit-wait.json'),dict(rc=wait.returncode,stdout=wait.stdout,stderr=wait.stderr))
    assert wait.returncode==0,(record,wait.returncode)
    return verify_previous(record)

def main():
    assert not ROOT.exists();ROOT.mkdir()
    plan=load(P/'image-plan-j16-attempt2.json');assert plan['rows']==build_rows() and plan['all_groups_make_jobs']==16
    assert plan['native_cpu_mask']=='0-7' and plan['automatic_eligible_cpu_groups']==['0-7','8-15']
    for name,digest in plan['source_sha256'].items():assert sha(P/name)==digest,name
    state('j16_controller','running',UNIT,step='current_inputs_prelaunch',total_image_rounds=12)
    run_unit('prelaunch-2','prelaunch_j16_v2.py',[],'1h','2G','1536M')
    from performance_round_j16_v2 import temperatures,platform_settings
    assert platform_settings()==load(P/'platform-settings.json')
    state('j16_controller','running',UNIT,step='idle_temperature_baseline',total_image_rounds=12)
    time.sleep(120);samples=[]
    for _ in range(5):samples.append(temperatures());time.sleep(2)
    assert samples[0] and all(set(s)==set(samples[0]) for s in samples)
    baseline={k:int(statistics.median(s[k] for s in samples)) for k in samples[0]}
    save(P/'temperature-baseline.json',dict(temperature_millicelsius=baseline,initial_idle_seconds=130,samples=samples,allowed_start_above_baseline_millicelsius=3000))
    completed=[]
    for ordinal,row in enumerate(plan['rows'],1):
        for name,digest in plan['source_sha256'].items():assert sha(P/name)==digest,name
        assert row['workers']==16
        state('j16_controller','running',UNIT,step='dispatch_image',ordinal=ordinal,total_image_rounds=12,next_round=row,completed_images=len(completed))
        args=['--run-id',row['run_id'],'--kind','image','--mode',row['mode'],'--workers','16']
        if row['measured']:args.append('--measured')
        result,resources=run_unit(row['run_id'],'performance_round_j16_v2.py',args,'4h')
        assert all(result[k]==v for k,v in row.items())
        completed.append(dict(**row,wall_seconds=result['wall_seconds'],result_sha256=sha(P/'results'/(row['run_id']+'.json')),
          resource_sha256=sha(P/'results'/(row['run_id']+'.resources.json')),peak_bytes=int(resources['memory.peak']),
          swap_peak_bytes=int(resources['memory.swap.peak']),migration_deltas=result['migration_deltas']))
        save(ROOT/'progress.json',dict(completed=completed,remaining_images=12-len(completed)))
    summary=[]
    native=statistics.median(r['wall_seconds'] for r in completed if r['measured'] and r['mode']=='x100')
    for mode in ('x100','auto-x100','auto-a100'):
        values=[r['wall_seconds'] for r in completed if r['measured'] and r['mode']==mode];assert len(values)==3
        med=statistics.median(values)
        summary.append(dict(mode=mode,workers=16,raw_seconds=values,median_seconds=med,min_seconds=min(values),max_seconds=max(values),speedup_vs_native_j16=native/med,time_reduction_percent=(1-med/native)*100))
    save(P/'results/controller-2.json',dict(passed=True,rc=0,rounds=completed,summary=summary,image_epoch='image-j16-v2',all_groups_make_jobs=16,
      measured_images=9,warmups=3,prior_j8_image_times_not_pooled=True,independent_final_audit_and_report_pending=True,
      conditional_scope='assume-scalar-independent',completed_utc=datetime.datetime.now(datetime.timezone.utc).isoformat()))
    state('j16_controller','phase_complete',UNIT,rc=0,independent_final_audit_and_report_pending=True)

if __name__=='__main__':
    try:main()
    except BaseException as error:
        save(P/'results/controller-2.json',dict(passed=False,rc=1,error=repr(error)))
        state('j16_controller','failed',UNIT,error=repr(error));raise
