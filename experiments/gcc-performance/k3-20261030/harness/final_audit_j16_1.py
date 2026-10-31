"""Independent replay: preserved unit-v2 evidence and fresh all-j16 Image data."""
from pathlib import Path
import collections,datetime,gzip,hashlib,importlib.util,json,os,statistics,subprocess,sys,traceback,unittest
P=Path('/root/chimera-gcc-performance-j16-578ab8321-20261030')
BASE=Path('/root/chimera-gcc-performance-578ab8321-20261029')
V=Path('/root/chimera-gcc-validation-578ab8321')
A=P/'audits/final-1';UNIT='chimera-gcc-j16-final-audit-1.service';SECTION='start'
PLAN='8053c33ca740840436afe8f4364bf0c32f4bf4982aa360aa0757c343b38c5059'
OLD_AUDITOR='858a8674483963857cc941d2cdf8dcd2aa77fe84d29b96ac14fa2de06ab871ea'
assert hashlib.sha256((BASE/'final_audit_performance_2.py').read_bytes()).hexdigest()==OLD_AUDITOR
spec=importlib.util.spec_from_file_location('accepted_evidence_replay',BASE/'final_audit_performance_2.py')
prior=importlib.util.module_from_spec(spec);spec.loader.exec_module(prior)
sha=prior.sha;load=prior.load;save=prior.save

def progress(section,**fields):
 global SECTION
 SECTION=section;record=dict(section=section,utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),**fields)
 save(A/'progress.json',record);print(json.dumps(record),flush=True)
 save(P/'state.json',dict(phase='independent_final_audit',status='phase_complete' if section=='complete' else 'running',active_unit=UNIT,updated_utc=record['utc'],section=section,final_report_pending=True,**fields))

def actual(name,root=P):
 r=load(root/'results'/(name+'.json'));c=load(root/'results'/(name+'.resources.json'))
 assert r['passed'] is True and r['rc']==0,(name,r)
 assert [c[k] for k in ('SERVICE_RESULT','EXIT_CODE','EXIT_STATUS')]==['success','exited','0'],(name,c)
 events=dict(line.split() for line in c['memory.events'].splitlines())
 assert events['oom']==events['oom_kill']=='0' and c['memory.swap.peak']=='0'
 for suffix in ('json','resources.json','time.txt'):sha(root/'results'/(name+'.'+suffix))
 return r,c

def baseline(name,root=P):
 x=load(root/name);sha(root/name)
 assert x['initial_idle_seconds']==130 and len(x['samples'])==5 and len(x['temperature_millicelsius'])==7
 assert x['temperature_millicelsius']=={k:int(statistics.median(s[k] for s in x['samples'])) for k in x['samples'][0]}
 return x

def parse_mask(text):
 cpus=set()
 for item in text.split(','):
  if '-' in item:
   a,b=map(int,item.split('-'));assert 0<=a<=b<16;cpus.update(range(a,b+1))
  else:cpus.add(int(item))
 assert cpus and cpus<=set(range(16));return cpus

def metrics(d,r):
 path=d/'metrics.jsonl.gz';sha(path);m=r['metrics'];assert load(d/'metrics-audit.json')==m
 h=hashlib.sha256();size=0;n=0;first=None;last=None;gaps=[];peak=0;cpus=collections.Counter();cc=collections.Counter();ready=0;processes={};max_compilers=0
 for line in gzip.open(path,'rb'):
  h.update(line);size+=len(line);x=json.loads(line);n+=1;t=x['monotonic']
  if last is not None:assert t>last;gaps.append(t-last)
  else:first=t
  last=t;peak=max(peak,x['memory_current_bytes']);assert x['frequency_khz']=={'0':2200000,'8':1800000}
  max_compilers=max(max_compilers,len(x['compiler_processes']))
  for proc in x['compiler_processes']:
   cpu=proc['cpu'];assert 0<=cpu<16 and proc['executable'] in (prior.GCC,prior.CC1) and proc['starttime'].isdigit() and proc['state'] not in ('Z','X','x')
   parse_mask(proc['allowed_cpus']);cpus[str(cpu)]+=1
   if proc['executable']==prior.CC1:cc['x100' if cpu<8 else 'a100']+=1
   key=(proc['pid'],proc['starttime'],proc['executable']);row=processes.setdefault(key,dict(cpus=[],ready_observed=False))
   if cpu not in row['cpus']:row['cpus'].append(cpu)
   if r['mode']=='x100':assert cpu<8 and proc['preference']=='none' and proc['allowed_cpus']=='0-7'
   else:
    assert proc['preference']==r['mode'].replace('auto-','prefer-')
    if proc['ready']=='1' and proc['exec_requires_ready']=='1':row['ready_observed']=True;ready+=1
 assert n==m['samples'] and size==m['uncompressed_bytes'] and h.hexdigest()==m['uncompressed_sha256'] and peak==m['sampled_peak_memory_current_bytes']
 assert n>0 and cpus and first<=r['measurement_started_monotonic']+2 and last>=r['measurement_ended_monotonic']-2
 recorded={(x['pid'],x['starttime'],x['executable']):dict(cpus=x['cpus'],ready_observed=x['ready_observed']) for x in m['processes']}
 assert recorded==processes,'Raw process identity/cpu/ready aggregation mismatch'
 assert set(m['cpu_ticks_before'])==set(m['cpu_ticks_after'])=={'cpu'+str(i) for i in range(16)}
 util={}
 for cpu,a in m['cpu_ticks_before'].items():
  b=m['cpu_ticks_after'][cpu];assert len(a)==len(b) and all(y>=x for x,y in zip(a,b))
  delta=[y-x for x,y in zip(a,b)];total=sum(delta[:8]);busy=total-delta[3]-delta[4];assert total>0 and 0<=busy<=total
  util[cpu]=dict(total_ticks=total,busy_ticks=busy,busy_percent=100*busy/total)
 assert util==m['cpu_utilization'],'CPU utilization is not reproduced from saved raw ticks'
 if r['mode'].startswith('auto-'):assert ready>0 and cc['x100']>0 and cc['a100']>0 and len(cpus)==16
 else:assert not cc['a100'] and set(map(int,cpus))<=set(range(8))
 sha(d/'metrics-audit.json')
 cluster={name:dict(mean_system_busy_percent=sum(util['cpu'+str(i)]['busy_percent'] for i in ids)/8,equivalent_system_busy_cores=sum(util['cpu'+str(i)]['busy_percent'] for i in ids)/100) for name,ids in (('x100',range(8)),('a100',range(8,16)))}
 return dict(samples=n,processes=len(processes),cpu_observations=dict(cpus),cc1_cluster_observations=dict(cc),max_sample_gap_seconds=max(gaps,default=0),sampled_peak_bytes=peak,raw_cpu_ticks_recomputed=True,cpu_utilization=util,cluster_system_utilization=cluster,max_sampled_compiler_processes=max_compilers,native_mask_verified=r['mode']=='x100',automatic_both_clusters_observed=r['mode'].startswith('auto-'))

def image_round(row,plan,base,canonical):
 name=row['run_id'];r,c=actual(name);d=P/'evidence'/name
 assert all(r[k]==row[k] for k in ('run_id','kind','mode','workers','measured'))
 assert r['kind']=='image' and r['workers']==16 and name.startswith('i5-')
 assert sha(P/'results'/(name+'.json'))==row['result_sha256'] and sha(P/'results'/(name+'.resources.json'))==row['resource_sha256']
 assert r['worker_source_sha256']==plan['source_sha256']['performance_round_j16_v2.py'] and r['data_epoch']=='image-j16-v2'
 assert r['storage_policy_authorization_sha256']==prior.AUTH and r['conditional_scope']=='assume-scalar-independent' and r['config_sha256']==prior.CONFIG and r['tasks_sha256']==prior.TASKS
 start,end=r['measurement_started_monotonic'],r['measurement_ended_monotonic'];assert end>start and abs(end-start-r['wall_seconds'])<1e-9 and r['wall_seconds']==row['wall_seconds']
 prior.ledgers(r);assert {k:r['kernel_after'][k]-r['kernel_before'][k] for k in prior.MOVES}==r['migration_deltas']==row['migration_deltas']
 if r['mode']=='x100':assert all(v==0 for v in r['migration_deltas'].values())
 else:assert all(v>0 for v in r['migration_deltas'].values())
 launchpath=P/'evidence'/(name+'-launch.json');launch=load(launchpath)['command'];sha(launchpath)
 for flag in ('--property=MemoryMax=12G','--property=MemoryHigh=10G','--property=MemorySwapMax=0','--property=RuntimeMaxSec=4h'):assert flag in launch
 assert str(P/'performance_round_j16_v2.py') in launch and launch[launch.index('--workers')+1]=='16'
 waitpath=P/'evidence'/(name+'-unit-wait.json');assert load(waitpath)['rc']==0;sha(waitpath)
 assert int(c['memory.max'])==12*1024**3 and c['memory.swap.max']=='0' and int(c['memory.peak'])==row['peak_bytes'] and int(c['memory.peak'])<12*1024**3
 cooling=load(d/'cooling.json');sha(d/'cooling.json');assert cooling['seconds']<1800
 thresholds={k:v+3000 for k,v in base['temperature_millicelsius'].items()};assert cooling['start_thresholds']==thresholds and set(cooling['samples'][-1]['temperature_millicelsius'])==set(thresholds)
 assert all(cooling['samples'][-1]['temperature_millicelsius'][k]<=v for k,v in thresholds.items())
 assert not r['jobs'] and r['artifacts']==canonical and r['successful_image_intermediates_removed'] and r['stdout_notification_omitted'] is True and r['launcher_sha256']==plan['source_sha256']['bin/native-launch-image-v3']
 capacity=load(d/'capacity.json');sha(d/'capacity.json');assert capacity['allocated_bytes']>=12*1024**3 and capacity['residual_bytes']>=capacity['required_margin_bytes']==6*1024**3
 for log in ('olddefconfig.log','prepare.log','make-image.log'):sha(d/log)
 met=metrics(d,r);assert met['sampled_peak_bytes']<=int(c['memory.peak'])
 return dict(run_id=name,kind='image',mode=r['mode'],workers=16,measured=r['measured'],seconds=r['wall_seconds'],actual_exit='success/exited/0',peak_bytes=int(c['memory.peak']),usage=r['usage_seconds'],child_cpu_equivalent_cores=(r['usage_seconds']['child_user']+r['usage_seconds']['child_system'])/r['wall_seconds'],migration_deltas=r['migration_deltas'],kernel=prior.kernel(d,r['kernel']),health=prior.health(d,r['storage_health']),metrics=met,result_sha256=row['result_sha256'],resource_sha256=row['resource_sha256'])

def main():
 assert not A.exists();A.mkdir(parents=True);os.umask(0o077)
 parent,resource=actual('controller-2');assert parent['image_epoch']=='image-j16-v2' and parent['all_groups_make_jobs']==16 and len(parent['rounds'])==12 and parent['measured_images']==9 and parent['warmups']==3
 assert sha(P/'image-plan-j16-attempt2.json')==PLAN;plan=load(P/'image-plan-j16-attempt2.json')
 assert plan['native_cpu_mask']=='0-7' and plan['automatic_eligible_cpu_groups']==['0-7','8-15']
 for name,digest in plan['source_sha256'].items():assert sha(P/name)==digest,name
 assert sha(BASE/'completion.json')=='b9562014670a5aaed6214cf02459703856a7ca3d208b6e6d2a96314cd853df91'
 old_audit,_=actual('final-audit-2',BASE);assert old_audit['audit_source_sha256']==OLD_AUDITOR and sha(BASE/'audits/final-2/evidence-sha256.json')==old_audit['evidence_manifest_sha256']
 for name in ('config.common','tasks.json','environment.json','platform-settings.json','storage-policy-authorization-attempt2.json','bin/native-launch-image-v3'):assert sha(P/name)==sha(BASE/name),name
 assert sha(P/'config.common')==prior.CONFIG and sha(P/'tasks.json')==prior.TASKS and sha(P/'storage-policy-authorization-attempt2.json')==prior.AUTH
 old_wrapper=(BASE/'bin/cc-image-v3').read_text();assert (P/'bin/cc-image-v3').read_text()==old_wrapper.replace(str(BASE/'bin/native-launch-image-v3'),str(P/'bin/native-launch-image-v3'))
 from performance_round_j16_v2 import platform_settings
 assert platform_settings()==load(P/'platform-settings.json')
 from test_perf_policy_j16 import BoundaryTests
 with (A/'policy-regressions.log').open('w') as log:tests=unittest.TextTestRunner(stream=log,verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(BoundaryTests))
 assert tests.wasSuccessful() and tests.testsRun==14 and not tests.skipped;sha(A/'policy-regressions.log')
 progress('current_source_and_artifact_receipts')
 prior.A=A;source=prior.source_audit();save(A/'source.json',source);workspaces=prior.workspace_audit();save(A/'workspaces.json',workspaces)
 pre,_=actual('prelaunch-2');assert pre['source']==source and pre['receipt_rows']==78 and pre['compiler_probe_cases']==12 and pre['policy_tests']==14
 pre_directory=P/'evidence/prelaunch-2';pre_report=dict(kernel=prior.kernel(pre_directory,pre['kernel']),health=prior.health(pre_directory,pre['health']))
 assert pre['capacity']['allocated_bytes']>=12*1024**3 and pre['capacity']['residual_bytes']>=6*1024**3
 for name in ('version','macro-version','cc-version','as-version'):
  reference=None
  for mode in ('x100','auto-x100','auto-a100'):
   path=pre_directory/(mode+'-'+name+'.json');row=load(path);sha(path);assert row['rc']==0 and 'parent_thread_id=' not in row['stdout']
   if reference is None:reference=row['stdout']
   else:assert row['stdout']==reference
  if name=='cc-version':assert reference=='GCC 150200\n'
  if name=='macro-version':assert reference=='GCC 15 2 0\n'
 progress('raw_ack_cpu_ready_preflight_replay')
 pf={str(i):prior.preflight(i) for i in (1,3)};save(A/'preflight-replay.json',pf)
 canonical=load(P/'artifacts/canonical-image-j16/hashes.json');sha(P/'artifacts/canonical-image-j16/hashes.json')
 assert canonical==load(BASE/'artifacts/canonical-image-v3/hashes.json')
 for name,digest in canonical.items():assert sha(P/'artifacts/canonical-image-j16'/name)==sha(BASE/'artifacts/canonical-image-v3'/name)==digest
 for task in load(P/'tasks.json'):assert sha(task['source'])==task['source_sha256'] and sha(BASE/'work/seed'/task['target'])==task['baseline_object_sha256']
 progress('retained_unit_raw_evidence_replay')
 unit_plan=load(BASE/'performance-plan-attempt2.json');sha(BASE/'performance-plan-attempt2.json');assert all(sha(BASE/name)==digest for name,digest in unit_plan['source_sha256'].items())
 unit_rows=load(BASE/'evidence/controller-2/progress.json')['completed'][:96];assert len(unit_rows)==96
 assert unit_rows==load(BASE/'image-plan-v3.json')['unit_results']
 unit_base=baseline('temperature-baseline-attempt2.json',BASE);rows=[]
 for row,scheduled in zip(unit_rows,unit_plan['rows'][:96]):
  assert all(row[k]==v for k,v in scheduled.items());rows.append(prior.round_audit(row,unit_plan,unit_base))
 images=load(P/'evidence/controller-2/progress.json');assert images['remaining_images']==0 and images['completed']==parent['rounds']
 image_base=baseline('temperature-baseline.json');assert len(plan['rows'])==12 and len({x['run_id'] for x in plan['rows']})==12
 for row,scheduled in zip(parent['rounds'],plan['rows']):
  assert all(row[k]==v for k,v in scheduled.items());progress('new_image_raw_metrics_ticks_kernel_health_replay',run_id=row['run_id'],completed_images=len(rows)-96,total_images=12)
  rows.append(image_round(row,plan,image_base,canonical))
 assert len(rows)==108 and sum(x['measured'] for x in rows)==89
 stats=[]
 for kind,workers,mode in sorted({(r['kind'],r['workers'],r['mode']) for r in rows if r['measured']}):
  selected=[r for r in rows if r['measured'] and (r['kind'],r['workers'],r['mode'])==(kind,workers,mode)];values=[r['seconds'] for r in selected];assert len(values)==(3 if kind=='image' else 5)
  stats.append(dict(kind=kind,workers=workers,mode=mode,n=len(values),raw_seconds=values,median_seconds=statistics.median(values),min_seconds=min(values),max_seconds=max(values),throughput_per_second=(1 if kind=='image' else 64)/statistics.median(values)))
 native=next(x['median_seconds'] for x in stats if x['kind']=='image' and x['mode']=='x100')
 for item in parent['summary']:
  group=next(x for x in stats if x['kind']=='image' and x['mode']==item['mode']);assert all(item[k]==group[k] for k in ('raw_seconds','median_seconds','min_seconds','max_seconds'))
  assert abs(item['speedup_vs_native_j16']-native/group['median_seconds'])<1e-12
 for index,key,root in (('controller-1-failure.json','files',P),('controller-2-image-failure.json','files',BASE),('controller-1-storage-failure.json','original_files_unchanged',BASE)):
  path=root/'evidence'/index;sha(path)
  for row in load(path)[key]:assert sha(row['path'])==row['sha256']
 assert sha(P/'evidence/controller-1-failure.json')=='0746b392f5c74e28c7171fee32ffbbbfd6c7da8eb27853b212f730bda567df34'
 assert (BASE/'work/image').is_dir() and not (P/'work/image-j16').exists() and not (P/'work/image-capacity-probe').exists()
 from runtime_smoke import stats as counters
 final=counters();assert all(final[k]==0 for k in prior.LEDGERS) and final['prefer_a100_fail_timeout']==0
 trace=Path('/sys/kernel/tracing');assert not list((trace/'instances').glob('chimera_gcc_perf_578ab8321_*')) and 'chimera_gcc_perf_578ab8321_' not in (trace/'kprobe_events').read_text()
 assert not Path('/proc/swaps').read_text().splitlines()[1:]
 for name in ('source.json','workspaces.json','preflight-replay.json'):sha(A/name)
 save(A/'rounds.json',rows);save(A/'statistics.json',stats);sha(A/'rounds.json');sha(A/'statistics.json')
 result=dict(passed=True,rc=0,commit=prior.COMMIT,kernel=os.uname().release,conditional_scope='assume-scalar-independent',rounds=108,measured_rounds=89,warmups=19,retained_unit_rounds=96,new_image_rounds=12,image_all_groups_make_jobs=16,current_source=source,workspaces=workspaces,prelaunch=pre_report,preflights={i:{k:v for k,v in x.items() if k!='cases_detail'} for i,x in pf.items()},statistics=stats,final_counters=final,all_original_failures_retained=True,prior_images_not_pooled=True,old_validation_modified=False,current_native_mask_and_auto_all16_cpu_observations_verified=True,raw_cpu_ticks_recomputed=True,receipts_republished=False,removed_intermediates_limitation='Successful intermediates were deleted after per-round hashes matched both canonical manifests; this replay rehashes retained canonicals, not removed files',storage_sample_limitation='Discrete samples; no duration or causal performance impact inference',audit_source_sha256=sha(__file__),plan_sha256=PLAN,completed_utc=datetime.datetime.now(datetime.timezone.utc).isoformat())
 save(A/'evidence-sha256.json',prior.EVIDENCE);result['evidence_manifest_sha256']=sha(A/'evidence-sha256.json');result['evidence_files']=len(prior.EVIDENCE)
 save(P/'results/final-audit-1.json',result);progress('complete',passed=True,rounds=108,evidence_files=result['evidence_files']);print(json.dumps(dict(passed=True,evidence_files=result['evidence_files'],new_image_rounds=12)),flush=True)

if __name__=='__main__':
 try:main()
 except BaseException as error:
  value=dict(passed=False,rc=1,section=SECTION,error=repr(error),traceback=traceback.format_exc(),utc=datetime.datetime.now(datetime.timezone.utc).isoformat());save(P/'results/final-audit-1.json',value)
  save(P/'state.json',dict(phase='independent_final_audit',status='failed',active_unit=UNIT,updated_utc=value['utc'],section=SECTION,error=value['error']));print(json.dumps(value),flush=True);raise
