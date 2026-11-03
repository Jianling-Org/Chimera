from pathlib import Path
from collections import Counter
import datetime,gzip,hashlib,json,math,os,re,shlex,subprocess,sys,tarfile,traceback

P=Path('/root/chimera-runtime-retest-20261031');N=P/'model42-runtime-ppl2pct-v5-attempt1';B=P/'model42-attempt4'
D=P/'model42-ppl2pct-v5-attempt1-independent-audit2'
UNIT='chimera-model42-ppl2pct-v5-attempt1-independent-audit-2.service'

def now():return datetime.datetime.now(datetime.timezone.utc).isoformat()
def load(p):return json.loads(Path(p).read_bytes())
def sha(p):
 h=hashlib.sha256()
 with Path(p).open('rb') as f:
  for chunk in iter(lambda:f.read(4*1024**2),b''):h.update(chunk)
 return h.hexdigest()
def save(p,x):
 with Path(p).open('x',encoding='utf-8') as f:json.dump(x,f,ensure_ascii=False,indent=2);f.write('\n')
def good_resource(row):
 assert [row[k] for k in ['SERVICE_RESULT','EXIT_CODE','EXIT_STATUS']]==['success','exited','0']
 assert row['memory.swap.peak']=='0'
 assert all(int(line.split()[1])==0 for line in row['memory.events'].splitlines() if line.split()[0] in ['oom','oom_kill','oom_group_kill'])
def resources():
 D.mkdir(exist_ok=True);g=Path('/sys/fs/cgroup')/Path('/proc/self/cgroup').read_text().split('0::',1)[1].strip().lstrip('/')
 r={k:os.environ.get(k) for k in ['SERVICE_RESULT','EXIT_CODE','EXIT_STATUS']};r.update({k:(g/k).read_text().strip() for k in ['memory.peak','memory.swap.peak','memory.events']});save(D/'unit.resources.json',r)
 try:good_resource(r);passed=(D/'verification.json').exists() and load(D/'verification.json')['passed']
 except (AssertionError,KeyError):passed=False
 save(D/'completion.json',dict(passed=passed,resources=r,full_model_qualification_marker_written=False))

def kernel_records(raw):
 records=[]
 for line in raw.splitlines(keepends=True):
  if re.match(rb'^\d+,\d+,\d+,[^;]*;',line):records.append(line)
  else:
   assert records and re.fullmatch(rb' [A-Z][A-Z0-9_]*=[^\r\n]*\n',line),'Unknown kernel continuation'
   records[-1]+=line
 assert records and b''.join(records)==raw
 return records

def main():
 assert UNIT in Path('/proc/self/cgroup').read_text() and not D.exists();D.mkdir()
 try:
  completion=load(N/'completion.json');result=load(N/'result.json');worker=load(N/'unit.resources.json');parent=load(P/'model42-runtime-ppl2pct-v5-controller-1.resources.json')
  assert completion['passed'] and completion['runner_rc']==0 and result['passed'] and result['protocol']=='llama-scalar-retest-v5'
  good_resource(worker);good_resource(parent);assert worker['trace_cleanup_passed'] and completion['resources']==worker
  assert int(worker['memory.max'])==12*1024**3 and int(parent['memory.max'])==1024**3
  evidence=load(N/'evidence-sha256.json');assert sha(N/'evidence-sha256.json')==completion['evidence_manifest_sha256']=='dd6048b4947a60e603eb28ce82d8a061468df1b603b93fbff1e6fc4afd532d9c'
  for relative,item in evidence.items():
   p=Path(relative);assert not p.is_absolute() and '..' not in p.parts and (N/p).resolve().is_relative_to(N)
   assert (N/p).stat().st_size==item['bytes'] and sha(N/p)==item['sha256'],'Original evidence SHA mismatch: '+relative
  save(D/'original-evidence-verification.json',dict(passed=True,files=len(evidence),bytes=sum(x['bytes'] for x in evidence.values()),manifest_sha256=sha(N/'evidence-sha256.json'),completion_sha256=sha(N/'completion.json'),result_sha256=sha(N/'result.json')))
  for name in ['model-suite-v7-upload-sha256.json','model-stage12-helpers-sha256.json','model-stage13-launch-binding1.json','model42-restore4-frozen.json']:
   document=load(P/name)
   assert all(sha(path)==expected for path,expected in document.items()),'Frozen input changed: '+name
  binding=load(P/'model42-runtime-ppl2pct-v5-launch1-binding.json')
  assert all(sha(path)==expected for path,expected in binding['files'].items())
  assert load(P/'model42-input-audit1-independent-local-verification.json')['passed']
  input_audit=P/'model42-restore4-independent-input-audit1'
  good_resource(load(input_audit/'unit.resources.json'));assert load(input_audit/'completion.json')['passed'] and load(input_audit/'verification.json')['passed']
  assert all(sha(path)==expected for path,expected in load(N/'harness-sha256.json').items())
  cfg=load(N/'run-config.json');assert cfg==load(P/'model42-ppl2pct-v5.json') and sha(P/'model42-ppl2pct-v5.json')=='82fdeda63e7f50c876aa3209ada93a151c9f90ceeab4a5df0f754fd8f51739ee'
  sys.path.insert(0,str(P/'model-suite-checkout-v7/experiments/runtime-evaluation'))
  import evaluation_common as common
  import run_llama_acceptance as model
  import model_thread_trace as threadtrace
  replay_backend=common.backend('_independent_model42_replay','experiments/gcc-validation/k3-20261029/harness/migration_trace.py')
  assert common.validate_config(cfg,'llama')==cfg
  assert cfg['cpus']==list(range(8,16)) and cfg['threads']==[2,4,8,12,16,24,32] and cfg['repeat_16']==10 and cfg['minimum_mixed_seconds']==7200
  assert cfg['relative_ppl_tolerance']==.02 and cfg['application_configuration']=='original-default' and 'diagnostic_configuration' not in cfg
  identities=common.input_identities(cfg,'llama');assert identities==load(N/'inputs-before.json')
  bootstrap=load(P/'startup-attempt1/inputs-before.json')['assets']['bootstrap'];assert identities['assets']['bootstrap']['sha256']==bootstrap['sha256']
  proof=load(P/'model42-ppl2pct-v5-input-qualification.json');assert proof['passed'] and proof['config_sha256']==sha(P/'model42-ppl2pct-v5.json')
  save(D/'current-inputs.json',identities)
  source=Path(cfg['source_tree']);sys.path[:0]=[str(source/'cli'),str(source)];sys.meta_path[:]=[x for x in sys.meta_path if type(x).__name__!='ScikitBuildRedirectingFinder']
  from chimera.preprocess.offline.config import BaseConfig
  from chimera.runtime.validate import verify_workspace
  from chimera.workspace import verify_workspace_installation
  W=Path(cfg['workspaces'][0]['path']);assert W==B/'workspaces/llama42';verify_workspace_installation(W);manifest=verify_workspace(W,BaseConfig(data_root=B/'data',workspace_root=B/'workspaces',scalar_root=B/'native-scalar-base'))
  assert len(manifest.modules)==7 and len(manifest.artifacts)==31
  assert len((W/'artifacts/verified-files.tsv').read_text().splitlines())==40
  for artifact in manifest.artifacts:assert sha(W/artifact.path)==artifact.sha256
  for row in manifest.modules:
   if row.role=='dependency':assert row.selected_kind=='original' and row.delivery=='target'
  for name in ['build','check','prepare','controller']:good_resource(load(B/(name+'.resources.json')))
  for name in ['prepare','verify','bootstrap-register']:assert load(B/(name+'.exit.json'))['returncode']==0
  check=load(B/'check.json');assert check['passed'] and check['summary']['findings_total']==0 and check['summary']['stack_object_plugin'] is True
  scalar=load(B/'build-record.json');build=load(B/'source-build-record.json')
  assert scalar['protocol']=='llama-scalar-retest-v1' and scalar['control_compile_audit']['passed']
  assert build['passed'] and build['elf_sha256']==scalar['elf_sha256']==identities['assets']['elf']['sha256'] and build['profile_sha256']==identities['assets']['profile']['sha256'] and build['gate_names']==1328
  assert scalar['scalar_control_sha256']==sha(B/'scalar-control.cmake')==sha(P/'scalar-control-model42.cmake')
  assert not list((B/'native-scalar-base').iterdir()) and 'external_scalar_leaf_contracts' not in (B/'profile.toml').read_text() and not build['production_chimera_modified']
  assert sha(B/'build/compile_commands.json')==build['compile_commands_sha256']
  assert all(sha(path)==expected for path,expected in build['toolchain_inputs'].items())
  assert len(build['patches'])==4 and all(sha(row['path'])==row['sha256'] for row in build['patches'])
  assert load(B/'gate/decision.json')['decision']['gate']['names'] and len(load(B/'gate/decision.json')['decision']['gate']['names'])==1328
  # Independently reproduce the source archive plus the four exact patches.
  archive=next(Path(p) for p in build['toolchain_inputs'] if p.endswith('/llama-source-base.tar'))
  reconstruction=D/'reconstructed-llama-source';reconstruction.mkdir()
  with tarfile.open(archive) as tar:tar.extractall(reconstruction,filter='data')
  for patch in build['patches']:
   row=subprocess.run(['git','apply','--check',patch['path']],cwd=reconstruction,capture_output=True,text=True,timeout=30);assert row.returncode==0,row.stderr
   row=subprocess.run(['git','apply',patch['path']],cwd=reconstruction,capture_output=True,text=True,timeout=30);assert row.returncode==0,row.stderr
  with (reconstruction/'CMakeLists.txt').open('a') as f:f.write('\ninclude('+json.dumps(str(B/'scalar-control.cmake'))+')\n')
  inventory=load(cfg['assets']['llama_source_inventory']['path'])
  for row in inventory['files']:
   p=reconstruction/row['path'];assert sha(p)==row['sha256'] and (os.readlink(p) if p.is_symlink() else None)==row['symlink'],'Reconstructed source differs: '+row['path']
  assert len([p for p in reconstruction.rglob('*') if p.is_file() and '.git' not in p.relative_to(reconstruction).parts])==len(inventory['files'])==3019
  compile_rows=load(B/'build/compile_commands.json');built_objects=[];control_targets=Counter();ggml_rows=0;unbuilt_targets=Counter()
  controls={'llama','llama-common','llama-common-base','cpp-httplib','llama-perplexity-impl','llama-perplexity'}
  for row in compile_rows:
   argv=row.get('arguments') or shlex.split(row['command'])
   assert str(B/'gate') in argv[0] and not any(x.startswith('-DLLAMA_USE_OPENSSL') for x in argv)
   opt=max((i for i,x in enumerate(argv) if re.fullmatch(r'-O(?:[0-3szg]|fast)',x)),default=-1)
   for off,on in [('-fno-vectorize','-fvectorize'),('-fno-slp-vectorize','-fslp-vectorize')]:
    assert max((i for i,x in enumerate(argv) if x==off),default=-1)>max(opt,max((i for i,x in enumerate(argv) if x==on),default=-1))
   output=argv[argv.index('-o')+1];target=re.search(r'CMakeFiles/([^/]+)\.dir/',output)[1];obj=Path(row['directory'])/output;march=[x for x in argv if x.startswith('-march=')][-1]
   if target in controls:assert march=='-march=rv64gc';control_targets[target]+=1
   elif target.startswith('ggml'):assert re.match(r'-march=rv64[^_]*v',march);ggml_rows+=1
   else:assert not obj.exists();unbuilt_targets[target]+=1;continue
   assert obj.exists();built_objects.append(dict(path=str(obj),sha256=sha(obj),bytes=obj.stat().st_size))
  assert dict(control_targets)==scalar['control_compile_audit']['control_targets'] and set(control_targets)==controls and ggml_rows==scalar['control_compile_audit']['ggml_rvv_commands']>0
  configure=load(B/'configure.exit.json')['argv'];assert '-DGGML_OPENMP=ON' in configure and '-DLLAMA_OPENSSL=OFF' in configure and '-DCMAKE_INTERPROCEDURAL_OPTIMIZATION=OFF' in configure and built_objects
  control_proof=load(B/'scalar-control-proof.json');elf=B/'inputs/llama-perplexity';control_functions={}
  for symbol in control_proof['control_functions']:
   raw=subprocess.check_output(['objdump','-d','--no-show-raw-insn','--disassemble='+symbol,str(elf)])
   assert raw==(B/(symbol+'.asm')).read_bytes()
   lines=[x for x in raw.decode().splitlines() if re.match(r'^\s*[0-9a-f]+:',x)]
   vector=[x for x in lines if re.match(r'^\s*[0-9a-f]+:\s+v[a-z]',x) or 'vlenb' in x]
   assert lines and not vector;control_functions[symbol]=dict(instructions=len(lines),vector_or_width_instructions=vector)
  assert control_functions==control_proof['control_functions']
  fresh=D/'full-elf-disassembly.txt'
  with fresh.open('wb') as f:subprocess.run(['objdump','-d','--no-show-raw-insn',str(elf)],stdout=f,check=True,timeout=120)
  assert sha(fresh)==sha(B/'full-disassembly.txt')==control_proof['disassembly_sha256']
  vectors=sum(bool(re.match(r'^\s*[0-9a-f]+:\s+v[a-z]',x)) for x in fresh.open());assert vectors==control_proof['whole_elf_vector_instructions']>0
  save(D/'source-and-build-verification.json',dict(passed=True,archive=str(archive),patches=build['patches'],reconstructed_files=len(inventory['files']),scalar_include=str(B/'scalar-control.cmake'),scalar_control_sha256=sha(B/'scalar-control.cmake'),compile_commands=len(compile_rows),selected_existing_objects=built_objects,control_targets=dict(control_targets),ggml_rvv_commands=ggml_rows,exported_unbuilt_targets=dict(unbuilt_targets),control_functions=control_functions,whole_elf_vector_instructions=vectors,disassembly_sha256=sha(fresh),configuration_argv=configure,strict_check_sha256=sha(B/'check.json'),profile_sha256=build['profile_sha256'],conditional_safety_scope='assume-scalar-independent/minVLEN256; StackObject and1328 gates; no scalar leaf exemption'))
  owner=load(N/'owner.json');trace_name=common.trace_name(owner['unit']);assert owner['protocol']=='llama-scalar-retest-v5'
  assert load(N/'trace-cleanup.json')==dict(passed=True,name=trace_name)
  assert not (Path('/sys/kernel/tracing/instances')/trace_name).exists() and trace_name+'/' not in Path('/sys/kernel/tracing/kprobe_events').read_text()
  baseline=load(N/'temperature-baseline.json');assert baseline['idle_seconds']==130 and len(baseline['samples'])==5
  summaries=[];route_totals=Counter();owned_total=0;short_total=0;predicate_total=0;sampled_total=0;unblocked_all_cases=0;prior_end=-math.inf;previous_counters=result['evidence']['counters_before']
  aggregate=[result['native_reference'],*result['cases']]
  expected_prefix=[('native-reference',16),*[(r['stage'],r['threads']) for r in model.prefix(cfg)]]
  rounds=len(result['cases']);assert rounds==result['rounds'] and rounds>17 and len(aggregate)==rounds+1
  for index,aggregate_row in enumerate(aggregate):
   if index<len(expected_prefix):stage,threads=expected_prefix[index]
   else:stage,threads='mixed',cfg['threads'][(index-len(expected_prefix))%7]
   directory=N/f'{index:04d}-{stage}-t{threads}';case=load(directory/'case.json');automatic=index>0;command=directory/'command' if automatic else directory
   exitrow=load(command/'exit.json');samples=load(command/'samples-summary.json')
   assert case['stage']==stage and case['threads']==threads and case['cwd']==str(N)
   for key in ['argv','pid','rc','timed_out','started_monotonic','ended_monotonic','seconds']:assert case[key]==exitrow[key]
   assert exitrow['rc']==0 and not exitrow['timed_out'] and exitrow['seconds']>0 and exitrow['seconds']==exitrow['ended_monotonic']-exitrow['started_monotonic'] and exitrow['started_monotonic']>=prior_end
   prior_end=exitrow['ended_monotonic']
   argv=exitrow['argv'];expected_args=model.arguments(cfg,threads)
   if automatic:assert argv[1:5]==[str(P/'model-suite-checkout-v7/experiments/runtime-evaluation/run_llama_acceptance.py'),'--launch',str(N/'run-config.json'),str(N)] and argv[5:]==expected_args
   else:assert argv==model.native_arguments(cfg,16)
   text='\n'.join((command/name).read_text(errors='replace') for name in ['stdout.log','stderr.log']);values=re.findall(r'Final estimate:\s*PPL\s*=\s*([^\s]+)',text,re.I);assert len(values)==1
   ppl=float(values[0]);assert math.isfinite(ppl) and ppl>0 and ppl==case['ppl']==aggregate_row['ppl']
   if index==0:native_ppl=ppl
   else:assert abs(ppl-native_ppl)<=native_ppl*.02
   assert samples==case['samples'] and samples['error'] is None and samples['maximum_live_threads']>=threads and samples['period_seconds']==.05
   digest=hashlib.sha256();size=0;observed={};maximum=0;last_stamp=-math.inf;sample_count=0
   with gzip.open(command/'process-samples.jsonl.gz','rb') as f:
    for line in f:
     digest.update(line);size+=len(line);sample=json.loads(line);assert sample['monotonic']>=last_stamp;last_stamp=sample['monotonic'];sample_count+=1;maximum=max(maximum,len(sample['tasks']))
     cg=sample['cgroup'];assert cg['memory.swap.peak']=='0' and cg['memory.swap.max']=='0' and int(cg['memory.max'])<=12*1024**3
     assert all(int(x.split()[1])==0 for x in cg['memory.events'].splitlines() if x.split()[0] in ['oom','oom_kill','oom_group_kill'])
     for cpu,freq in sample['frequencies'].items():assert freq['scaling_governor']=='userspace' and int(freq['scaling_setspeed'])==(2200000 if int(cpu)<8 else 1800000)
     for task in sample['tasks']:
      assert int(task['status']['Tgid'])==exitrow['pid'] and task['cpu'] in range(16)
      assert task['ready']==model.initialization_ready(task['status'],'prefer-a100')
      if automatic:assert task['preference']=='prefer-a100'
      else:assert task['preference']=='none' and task['cpu'] in range(8,16) and task['allowed_cpus']=='8-15'
      prior=observed.setdefault(task['tid'],dict(tid=task['tid'],starttime=task['starttime'],cpus=[],ready=False));assert prior['starttime']==task['starttime']
      if task['cpu'] not in prior['cpus']:prior['cpus'].append(task['cpu'])
      prior['ready']|=task['ready']
   assert list(observed.values())==samples['rows'] and digest.hexdigest()==samples['uncompressed_sha256'] and size==samples['raw_bytes'] and maximum==samples['maximum_live_threads']
   before,after=case['counters_before'],case['counters_after']
   assert all(before[k]==after[k]==0 for k in common.LEDGERS) and before[common.TIMEOUT]==after[common.TIMEOUT]==previous_counters[common.TIMEOUT]
   assert all(before[k]==previous_counters[k] for k in common.MOVES);previous_counters=after
   row=dict(index=index,directory=str(directory),stage=stage,threads=threads,pid=exitrow['pid'],seconds=exitrow['seconds'],ppl=ppl,relative_ppl_delta=abs(ppl-native_ppl)/native_ppl,sample_rows=sample_count,sampled_threads=len(observed),maximum_live_threads=maximum,raw_samples_sha256=digest.hexdigest(),case_sha256=sha(directory/'case.json'))
   if automatic:
    for name,file in [('full_case',directory/'case.json'),('full_trace',directory/'trace-summary.json')]:assert aggregate_row[name]==dict(path=str(file),sha256=sha(file))
    saved=load(directory/'trace-summary.json');assert saved==case['trace']
    assert saved['kernel_btf_sha256']==load(cfg['assets']['thread_layout']['path'])['btf_sha256']
    assert set(saved['per_cpu'])=={'cpu'+str(n) for n in range(16)}
    for text in saved['per_cpu'].values():
     loss={line.partition(':')[0].strip():line.partition(':')[2].strip() for line in text.splitlines() if ':' in line}
     assert all(key in loss and int(loss[key])==0 for key in ['overrun','commit overrun','dropped events'])
    for name,expected in [('kprobe_profile',['ack_enter','ack_return']),('task_state_probe_profile',['state_ack','state_exit','eligible_enter','eligible_return'])]:
     lines=saved[name];assert len(lines)==len(expected)
     assert {line.split()[0] for line in lines}=={trace_name+'_'+suffix for suffix in expected} and all(int(line.split()[-1])==0 for line in lines)
    digest=hashlib.sha256();trace_bytes=0;lines=[]
    with gzip.open(directory/'raw-ack-and-cpu.trace.gz','rb') as f:
     for line in f:digest.update(line);trace_bytes+=len(line);lines.append(line.decode())
    assert digest.hexdigest()==saved['uncompressed_sha256'] and trace_bytes==saved['uncompressed_bytes']
    own=threadtrace.lifecycle(lines,exitrow['pid'],cfg['assets']['elf']['path'],samples,os.sysconf('SC_CLK_TCK'));assert own==saved['lifecycle']
    replay=replay_backend.replay(lines,set(own['owned_tids']));assert replay==saved['replay']
    eligible=threadtrace.eligibility(lines,exitrow['pid'],own,replay);assert eligible==saved['migration_eligibility']
    assert replay['raw_accepted_ack_count']==len(replay['physical_commits']) and any(commit['tid']==exitrow['pid'] for commit in replay['physical_commits'])
    assert len(eligible['commit_witnesses'])==len(replay['physical_commits']) and eligible['all_commits_have_positive_kernel_predicate']
    initialized=dict(rows=[dict(tid=t['tid'],ready=bool(t['kernel_published_ready_rows']) or t['proc_ready'],start_boottime_ns=t['start_boottime_ns']) for t in own['threads']],maximum_live_threads=maximum,readiness_source='kernel published-ready and installed handlers; pre-migration eligibility checked separately')
    assert initialized==load(directory/'kernel-initialization-validation.json') and eligible==load(directory/'eligibility-summary.json')
    model.validate_migration(initialized,dict(replay=replay),threads,exitrow['pid'],before,after)
    for key,route in zip(common.MOVES,['256-to-1024','1024-to-256']):assert after[key]-before[key]==replay['route_counts'][route]
    route_totals.update(replay['route_counts']);owned_total+=len(own['owned_tids']);short_total+=len(own['short_thread_tids']);sampled_total+=len(own['sampled_tids']);predicate_total+=len(eligible['commit_witnesses']);unblocked_all_cases+=own['all_threads_signal_unblocked_observed']
    row.update(routes=replay['route_counts'],owned_threads=len(own['owned_tids']),short_threads=len(own['short_thread_tids']),predicate_witnesses=len(eligible['commit_witnesses']),trace_uncompressed_sha256=digest.hexdigest(),all_threads_published_ready=True,all_threads_signal_unblocked_observed=own['all_threads_signal_unblocked_observed'])
    del lines,own,replay,eligible,saved,initialized
   else:common.no_migration(before,after);assert case['trace'] is None
   summaries.append(row)
   with (D/'case-audits.jsonl').open('a') as f:f.write(json.dumps(row)+'\n')
  mixed=[r for r in summaries if r['stage']=='mixed'];mixed_seconds=sum(r['seconds'] for r in mixed)
  assert len(mixed)==result['mixed_rounds'] and mixed_seconds==result['mixed_active_seconds'] and mixed_seconds>=7200
  assert dict(route_totals)==result['route_counts'] and all(route_totals.values())
  assert [result['evidence']['counters_after'][k]-result['evidence']['counters_before'][k] for k in common.MOVES]==[route_totals[r] for r in ['256-to-1024','1024-to-256']]
  assert all(result['evidence']['counters_before'][k]==result['evidence']['counters_after'][k]==0 for k in common.LEDGERS)
  assert result['evidence']['counters_before'][common.TIMEOUT]==result['evidence']['counters_after'][common.TIMEOUT]
  kernel=load(N/'kernel-continuous-audit.json');raw=gzip.decompress((N/'kernel-continuous.kmsg.gz').read_bytes());assert hashlib.sha256(raw).hexdigest()==kernel['uncompressed_sha256'] and len(raw)==kernel['uncompressed_bytes']
  records=kernel_records(raw);seq=[];maintenance=[];markers=[]
  for record in records:
   header,message=record.decode().split(';',1);priority,number,tick,flags=header.split(',');seq.append(int(number));body=message.splitlines()[0];metadata=message.splitlines()[1:]
   if body==f'chimera-gcc-validation:{N.name}:begin':assert int(priority)==14 and not metadata;markers.append('begin')
   elif body==f'chimera-gcc-validation:{N.name}:end':assert int(priority)==14 and not metadata;markers.append('end')
   else:
    assert int(priority)==3 and re.fullmatch(r'ufshcd-spacemit-k3 c0e00000.ufshc: ufshcd_bkops_exception_event_handler: device raised urgent BKOPS exception for bkops status [12]',body)
    assert all(line in [' SUBSYSTEM=platform',' DEVICE=+platform:c0e00000.ufshc'] for line in metadata);maintenance.append(record.decode())
  assert seq==list(range(seq[0],seq[-1]+1)) and [seq[0],seq[-1]]==kernel['sequence_endpoints'] and markers==['begin','end']
  assert maintenance==kernel['known_background_events'] and len(maintenance)==kernel['known_background_event_count'] and not kernel['errors'] and not kernel['alerts']
  health=[json.loads(line) for line in (N/'storage-health.jsonl').read_text().splitlines()];assert health and all(r['critical_health']==0 and r['bkops_status'] in [0,1,2] for r in health)
  assert health[0]['monotonic_seconds']<=aggregate[0]['started_monotonic'] and health[-1]['monotonic_seconds']>=aggregate[-1]['ended_monotonic']
  bkops=dict(Counter(str(r['bkops_status']) for r in health));assert bkops==result['evidence']['health']['sample_counts_by_bkops_status']
  proof=dict(passed=True,scope='Independent complete model42 v5 attempt1 raw-evidence audit; qualified marker still waits for audit actual exit0',verified_utc=now(),protocol=cfg['protocol'],relative_ppl_tolerance=.02,application_configuration='original-default',automatic_preference='prefer-a100',native_reference_ppl=native_ppl,automatic_rounds=rounds,mixed_rounds=len(mixed),mixed_actual_application_seconds=mixed_seconds,matrix_threads=cfg['threads'],repeat_16=10,route_counts=dict(route_totals),physical_commits=predicate_total,main_thread_actual_migration_cases=rounds,owned_thread_instances=owned_total,short_thread_instances=short_total,sampled_thread_instances=sampled_total,all_threads_published_initialization_ready=True,all_commits_positive_kernel_predicate=True,all_cases_all_signals_unblocked_observed_count=unblocked_all_cases,raw_ready_bools_unchanged=True,maximum_relative_ppl_delta=max(r['relative_ppl_delta'] for r in summaries[1:]),automatic_ppl_range=[min(r['ppl'] for r in summaries[1:]),max(r['ppl'] for r in summaries[1:])],nine_ledgers_zero=True,timeout_increment=0,trace_loss_zero=True,six_private_probes_cleaned=True,original_evidence_files=len(evidence),original_evidence_bytes=sum(x['bytes'] for x in evidence.values()),evidence_manifest_sha256=sha(N/'evidence-sha256.json'),completion_path=str(N/'completion.json'),completion_sha256=sha(N/'completion.json'),result_path=str(N/'result.json'),result_sha256=sha(N/'result.json'),case_audits_sha256=sha(D/'case-audits.jsonl'),source_build_verification_sha256=sha(D/'source-and-build-verification.json'),input_identities_sha256=sha(D/'current-inputs.json'),all_40_receipts_current=True,all_3019_source_files_reconstructed=True,kernel_sequences=seq,kernel_sha256=kernel['uncompressed_sha256'],kernel_maintenance_events=len(maintenance),unknown_kernel_alerts=0,health_samples=len(health),bkops_counts=bkops,health_max_observed_gap_seconds=max(b['monotonic_seconds']-a['monotonic_seconds'] for a,b in zip(health,health[1:])),health_period_seconds=30,model_parent_resources=parent,model_worker_resources=worker,model42_started=True,historical_numbers_reproduced=False,numerical_difference_cause_resolved=False,conditional_safety_scope='StackObject/1328 gates/assume-scalar-independent/minVLEN256; no host-libc exemption',limitations=['2percent is the user-authorized acceptance tolerance; the original cross-cluster numerical cause remains unresolved.','Initialization published-ready and per-migration kernel eligibility are separate; not every thread is asserted to be continuously signal-unblocked.','Detailed tracing elapsed time is functional acceptance time, not inference throughput.','BKOPS sampling is discrete; no duration or causal performance cost is inferred.'])
  report=f'''# 报告4.2：标量控制编译配置完整重测与独立复核

本轮llama-scalar-retest-v5在新的标量控制编译工件上以用户明确确认的相对PPL2%验收，原默认应用参数，不加-fa off或诊断回调。原模型父子运行均实际success/exited0；独立原始证据复核通过，本审计本身最终实际退出另以completion/resources为准，不以报告文字代替actual退出。

本轮新原生静态A100 CPU8–15/t16，PPL {native_ppl}；自动从X100启动prefer-a100。七线程档2/4/8/12/16/24/32与十次t16完成，{len(mixed)}轮混合累计{mixed_seconds:.9f}真实应用monotonic秒，总{rounds}自动命令。所有命令实际rc0、有唯一有限正PPL且相对参考<=2%，最大相对偏差{proof['maximum_relative_ppl_delta']*100:.9f}%，自动PPL范围{proof['automatic_ppl_range']}。详细探针时间只作功能与安全验收，不写作推理吞吐；不复用41PPL或旧123/66。

完整raw生命周期/初始化/迁移前内核hmp_runtime_ready正返回/ACK及物理CPU独立重放，两向提交{route_totals['256-to-1024']}/{route_totals['1024-to-256']}，逐轮和全局增量精确一致，{rounds}轮主线程均真实迁移。{owned_total}归属线程实例含{short_total}个未被50ms采样覆盖的短线程，全部有内核TGID/CLONE_THREAD/start_boottime/创建退出链、真实初始化发布和5/41handler旁证；{predicate_total}提交均有此前内核资格正返回。原始采样ready保持原样，初始化与当次资格分别披露，不宣称所有线程始终可被中断。九账本0、迁移timeout无增、无事件丢失、六私有探针清理通过。

原件{len(evidence)}份/{proof['original_evidence_bytes']}bytes全SHA，所有case/trace引用、每条命令内部monotonic、源码archive+四patch+scalar-control附加include重建3019文件、{len(compile_rows)}项实际导出编译选项与{len(built_objects)}项实际编译对象、控制函数和整个ELF重新反汇编、当前ELF/Profile/Runtime/bootstrap/registry及全部40receipt均复核。控制目标rv64gc且所有导出命令有效禁auto loop/SLP，GGML显式RVV保留；OpenMP ON/OpenSSL OFF。构建记录仍llama-scalar-retest-v1，运行记录v5，是新编译配置对照，不能声称复现旧不同软件/输入/make继承的66例。应用四patch和StackObject/1328gate/assume-scalar-independent/minVLEN256保持，empty native-scalar-base/原生依赖original-target，没有错误libc豁免，生产Runtime/分析器/内核未修改。

kernel原始SHA {kernel['uncompressed_sha256']}、seq {seq}连续，begin/end及{len(maintenance)}项精确授权维护分类均通过，合法SUBSYSTEM/DEVICE元数据续行原样归入逻辑记录，未知告警0。{len(health)}次健康BKOPS计数{bkops}，criticalhealth0；不推断离散状态2持续时长或因果性能损失。worker最终峰值{worker['memory.peak']}bytes、parent{parent['memory.peak']}bytes，均swap0/OOM0，trace清理正常。

4.1已独立通过，本报告须本审计actual0及本地必要原字节独立核验后才能与4.1共同闭环。2%是用户授权验收口径，原跨簇数值差异原因仍未定位，不报告成数值问题已修复；所有旧1%和空间/准入/诊断失败原样保护、不混池。本次隧道断开仅延后读取结果，未重跑或拼接原测试。
'''
  (D/'4.2-完整重测独立审计报告.zh-CN.md').write_text(report,encoding='utf-8')
  changes=f'''# 性能报告4.2本轮修改意见

以llama-scalar-retest-v5单列本次标量控制编译配置，明确原生A100/t16的新参考PPL{native_ppl}、自动X100 prefer-a100、七档/十次及{len(mixed)}混合轮/{mixed_seconds:.9f}真实应用秒、{rounds}自动轮和独立重放后的双向{dict(route_totals)}。写明控制rv64gc与有效禁自动loop/SLP、GGML显式RVV保留、OpenMP ON/OpenSSL OFF和四patch/附加scalar include。2%为用户明确确认的口径，数值原因未定位，旧失败和旧不同输入软件make继承66例不能重分类或混池。分别披露初始化ready发布、原50ms ready和每次内核资格正返回；保留九账本/timeout/原始SHA/健康/OOMswap/清理及BKOPS离散观察局限。详细探针耗时不是推理吞吐，原性能报告如需要吞吐数据应独立测量，不能将本次功能验收时长替代。
'''
  (D/'性能报告4.2修改意见.zh-CN.md').write_text(changes,encoding='utf-8')
  proof['report_path']=str(D/'4.2-完整重测独立审计报告.zh-CN.md');proof['report_sha256']=sha(proof['report_path']);proof['report_change_notes_path']=str(D/'性能报告4.2修改意见.zh-CN.md');proof['report_change_notes_sha256']=sha(proof['report_change_notes_path'])
  save(D/'verification.json',proof)
 except BaseException:
  (D/'failure.log').write_text(traceback.format_exc());raise

if __name__=='__main__':
 if len(sys.argv)>1:resources()
 else:main()
