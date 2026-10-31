"""Read-only replay of the accepted unit-v2 and Image-v3 benchmark evidence."""
from pathlib import Path
import collections, datetime, gzip, hashlib, importlib.util, json, os, re
import statistics, subprocess, sys, tarfile, traceback

P=Path('/root/chimera-gcc-performance-578ab8321-20261029')
V=Path('/root/chimera-gcc-validation-578ab8321')
K=Path('/root/chimera-kernel-update-d02cd7352')
S=P/'kernel-source'
A=P/'audits/final-2'
UNIT='chimera-gcc-perf-final-audit-2.service'
COMMIT='578ab8321c0788ab8cba1ad24324f220e1e4a149'
KH='d02cd73523ab4c7e7e952969b8d2a95925ae64d9'
AUTH='342afb5c200c4bcb9e947e80b09352fae60ded03d435f13a4f22abef1aa095c2'
CONFIG='0ecfe62d06dbe0bca2dd1dc1ba61e9cbec26071c9ef3200c782c89459b8e1cf4'
TASKS='720a0fddcbad5973b5e3f779878c837894b43601c54ed4a7bc6e9112e44eca47'
LEDGERS=('policy_a100_assigned_regular','policy_a100_assigned_ai','policy_x100_assigned_regular','policy_x100_assigned_ai','prefer_assigned_regular','prefer_assigned_ai','prefer_pending_to_regular','prefer_pending_to_ai','prefer_a100_cpu_reservations')
MOVES=('prefer_a100_x100_to_a100_migrations','prefer_a100_a100_to_x100_migrations')
GCC=str(V/'build-gate/gcc/xgcc'); CC1=str(V/'build-gate/gcc/cc1')
EVIDENCE={}; CACHE={}; SECTION='start'

def load(p): return json.loads(Path(p).read_text())
def save(p,x): Path(p).write_text(json.dumps(x,ensure_ascii=False,indent=2)+'\n')
def rawsha(b): return hashlib.sha256(b).hexdigest()
def sha(p):
    p=Path(p); st=p.stat(); key=(st.st_dev,st.st_ino,st.st_size,st.st_mtime_ns,st.st_ctime_ns)
    if key not in CACHE:
        h=hashlib.sha256()
        with p.open('rb') as f:
            for b in iter(lambda:f.read(4*1024**2),b''): h.update(b)
        st2=p.stat(); assert key==(st2.st_dev,st2.st_ino,st2.st_size,st2.st_mtime_ns,st2.st_ctime_ns),str(p)
        CACHE[key]=h.hexdigest()
    EVIDENCE[str(p)]={'bytes':st.st_size,'sha256':CACHE[key]}; return CACHE[key]
def numbers(p):
    s=Path(p).stat(); return [s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns//10**9,s.st_mtime_ns%10**9,s.st_ctime_ns//10**9,s.st_ctime_ns%10**9]
def progress(section,**extra):
    global SECTION
    SECTION=section; x=dict(section=section,utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),**extra)
    save(A/'progress.json',x); print(json.dumps(x),flush=True)
    save(P/'state.json',dict(phase='independent_final_audit',status='phase_complete' if section=='complete' else 'running',active_unit=UNIT,updated_utc=x['utc'],section=section,final_report_pending=True,**extra))
def normal(name):
    r=load(P/'results'/(name+'.json')); c=load(P/'results'/(name+'.resources.json'))
    assert r['passed'] is True and r['rc']==0,name
    assert [c[k] for k in ('SERVICE_RESULT','EXIT_CODE','EXIT_STATUS')]==['success','exited','0'],(name,c)
    e=dict(x.split() for x in c['memory.events'].splitlines())
    assert e['oom']==e['oom_kill']=='0' and c['memory.swap.peak']=='0',(name,c)
    for suffix in ('json','resources.json','time.txt'): sha(P/'results'/(name+'.'+suffix))
    return r,c
def ledgers(r):
    for side in ('kernel_before','kernel_after'):
        assert all(r[side][k]==0 for k in LEDGERS)
    assert r['kernel_before']['prefer_a100_fail_timeout']==r['kernel_after']['prefer_a100_fail_timeout']

def kernel(directory,k):
    compressed=directory/'kernel-continuous.kmsg.gz'; sha(compressed)
    raw=gzip.decompress(compressed.read_bytes()); assert len(raw)==k['uncompressed_bytes'] and rawsha(raw)==k['uncompressed_sha256']
    assert not k['errors'] and not k['alerts']
    assert load(directory/'kernel-continuous-audit.json')==k
    blocks=[]
    for line in raw.splitlines(keepends=True):
        if re.match(rb'^\d+,\d+,\d+,[^;\n]*;',line): blocks.append(line)
        else:
            assert blocks; blocks[-1]+=line
    assert blocks and b''.join(blocks)==raw
    seq=[]; marks=[]; known=[]; counts=collections.Counter()
    prefix='chimera-gcc-validation:'+directory.name+':'
    message='ufshcd-spacemit-k3 c0e00000.ufshc: ufshcd_bkops_exception_event_handler: device raised urgent BKOPS exception for bkops status '
    for block in blocks:
        head,sep,body=block.partition(b';'); assert sep
        fields=head.decode().split(','); assert len(fields)==4
        pri,n,ts=map(int,fields[:3]); assert 0<=pri<=191 and n>=0 and ts>=0; seq.append(n)
        lines=body.decode('utf-8').splitlines(); assert lines
        if (pri&7)<=4:
            status=next((i for i in (1,2) if lines[0]==message+str(i)),None)
            assert status and pri==3 and fields[3]=='-' and len(lines[1:])==len(set(lines[1:])) and set(lines[1:])<={' SUBSYSTEM=platform',' DEVICE=+platform:c0e00000.ufshc'},block
            known.append(block.decode()); counts[str(status)]+=1
        if lines[0].startswith(prefix): marks.append(lines[0][len(prefix):])
    assert seq==list(range(seq[0],seq[-1]+1)) and k['sequence_endpoints']==[seq[0],seq[-1]]
    assert marks==['begin','end'] and k['informational_control_markers']==marks
    assert k['known_background_events']==known and k['known_background_event_count']==len(known)
    sha(directory/'kernel-continuous-audit.json')
    for name in ('dmesg-before.txt','dmesg-after.txt'): sha(directory/name)
    return dict(records=len(blocks),sequences=[seq[0],seq[-1]],known_log_counts=dict(counts),raw_sha256=rawsha(raw),unexpected_alerts=0)

def health(directory,summary=None):
    path=directory/'storage-health.jsonl'; sha(path)
    rows=[json.loads(x) for x in path.read_text().splitlines()]; assert len(rows)>=2
    counts=collections.Counter(); last=None
    for row in rows:
        assert type(row['bkops_status']) is int and row['bkops_status'] in (0,1,2) and type(row['critical_health']) is int and row['critical_health']==0
        if last is not None: assert row['monotonic_seconds']>last
        last=row['monotonic_seconds']; counts[str(row['bkops_status'])]+=1
    if summary is not None:
        assert summary['sample_counts_by_bkops_status']==dict(counts)
        assert summary['status2_samples']==[r for r in rows if r['bkops_status']==2]
        assert summary['status2_performance_environment_observed']==bool(counts['2'])
    return dict(samples=len(rows),counts=dict(counts),status2_observed=bool(counts['2']),maximum_gap_seconds=max(b['monotonic_seconds']-a['monotonic_seconds'] for a,b in zip(rows,rows[1:])))

def source_audit():
    initial=load(P/'evidence/setup-1/inputs.json')
    assert initial['chimera_commit']==COMMIT and initial['kernel_head']==KH
    assert os.uname().release=='6.18.3-chimera-d02cd7352'
    assert Path('/proc/sys/kernel/random/boot_id').read_text().strip()==initial['boot_id']
    assert subprocess.check_output(['git','-C',str(V/'source'),'rev-parse','HEAD'],text=True).strip()==COMMIT
    assert not subprocess.check_output(['git','-C',str(V/'source'),'status','--porcelain'],text=True).strip()
    assert subprocess.check_output(['git','-C',str(K/'source'),'rev-parse','HEAD'],text=True).strip()==KH
    patch=(P/'evidence/setup-1/kernel-source.patch').read_bytes()
    assert rawsha(patch)==initial['kernel_patch_sha256']=='36187c29e41ab210088c157e235d099aeebfe96ed9f746c3c4304965ddcf2d63'
    assert patch==(K/'source.patch').read_bytes()==subprocess.check_output(['git','-C',str(K/'source'),'diff','--binary','HEAD'])
    patched='drivers/gpu/drm/spacemit/spacemit_bootloader.c'
    assert sha(S/patched)==sha(K/'source'/patched)
    proc=subprocess.Popen(['git','-C',str(K/'source'),'archive','--format=tar',KH],stdout=subprocess.PIPE)
    h=hashlib.sha256(); names=set(); count=0; total=0; normalized_links=[]
    class Reader:
        def read(self,n=-1):
            b=proc.stdout.read(n); h.update(b); return b
    reader=Reader()
    with tarfile.open(fileobj=reader,mode='r|') as tar:
        for member in tar:
            path=S/member.name
            if member.isdir(): continue
            names.add(member.name)
            if member.issym():
                filtered=tarfile.data_filter(member,str(S))
                assert filtered is not None and path.is_symlink() and os.readlink(path)==filtered.linkname,member.name
                if filtered.linkname!=member.linkname:normalized_links.append(dict(path=member.name,archive_target=member.linkname,extracted_target=filtered.linkname))
                continue
            assert member.isfile(),member.name
            data=tar.extractfile(member); digest=hashlib.sha256()
            for block in iter(lambda:data.read(1024**2),b''):digest.update(block)
            if member.name!=patched: assert sha(path)==digest.hexdigest(),member.name
            count+=1; total+=member.size
    while reader.read(1024**2):pass
    proc.stdout.close(); assert proc.wait()==0
    assert h.hexdigest()==initial['kernel_git_archive_sha256']
    actual={str(f.relative_to(S)) for f in S.rglob('*') if f.is_file() or f.is_symlink()}
    assert actual==names,('Unexpected source entries',list(actual^names)[:25])
    return dict(files=count,bytes=total,archive_sha256=h.hexdigest(),patch_sha256=rawsha(patch),full_current_source_matches_fixed_archive_plus_exact_patch=True,exact_original_data_filter_normalized_links=normalized_links)

def workspace_audit():
    completion=load(V/'completion.json'); assert completion['acceptance_passed'] and completion['commit']==COMMIT
    for rel,row in completion['files'].items(): assert sha(V/rel)==row['sha256'],rel
    sys.path.insert(0,str(V)); from worker import source_imports
    source_imports()
    import final_independent_audit as official
    assert sha(Path(official.__file__))==completion['files']['final_independent_audit.py']['sha256']
    official.E=A/'workspaces'; official.E.mkdir()
    registration=load(V/'stage-results/bootstrap-register-1.json')
    assert registration['passed'] and registration['rc']==0
    official_resources=load(V/'stage-results/bootstrap-register-1.resources.json')
    assert [official_resources[k] for k in ('SERVICE_RESULT','EXIT_CODE','EXIT_STATUS')]==['success','exited','0']
    rows={name:official.audit_workspace(name,registration) for name in ('xgcc','cc1')}
    assert sum(v['receipt_rows'] for v in rows.values())==78
    EVIDENCE.update(official.EVIDENCE)
    expected=load(P/'evidence/attempt2-prelaunch/result.json')['identity_sha256']
    for rel,digest in expected.items():assert sha(V/rel)==digest,rel
    return {name:{k:v for k,v in row.items() if k!='artifacts'} for name,row in rows.items()}

def replay_trace(lines,selected):
    # Fresh parser of raw entries, returns and committed CPU moves.
    stacks=collections.defaultdict(list); accepted=[]; capabilities=[]; commits=[]; unmatched=[]
    for index,line in enumerate(lines,1):
        m=re.search(r'-(\d+)\s+\[\d+\].*?\s(\d+\.\d+):\s(.*)',line)
        if not m:continue
        tid,t,detail=int(m[1]),float(m[2]),m[3]
        if 'ack_enter:' in detail:
            fields=dict(re.findall(r'(generation|action)=([^\s]+)',detail));assert len(fields)==2
            stacks[tid].append(dict(tid=tid,generation=int(fields['generation'],0),action=int(fields['action'],0),enter_time=t,enter_sequence=index))
        elif 'ack_return:' in detail:
            m=re.search(r'result=(-?(?:0x[0-9a-f]+|\d+))',detail);assert m
            if not stacks[tid]:unmatched.append(tid);continue
            row=stacks[tid].pop(); row.update(return_time=t,return_sequence=index,result=int(m[1],0))
            if row['result']==8 and row['action']==1:accepted.append(row)
            if row['result']==8 and row['action']==7:capabilities.append(row)
        elif 'sched_prefer_a100_migrate:' in detail:
            m=re.search(r'pid=(\d+) src_cpu=(\d+) dst_cpu=(\d+) reason=(\S+)',detail)
            if m:commits.append(dict(tid=int(m[1]),src_cpu=int(m[2]),dst_cpu=int(m[3]),reason=m[4],timestamp=t,sequence=index))
    assert not (set(unmatched)&selected) and not any(stacks[t] for t in selected)
    physical=[]; by_tid=collections.defaultdict(set); used=set()
    for row in commits:
        if row['tid'] not in selected:continue
        a,b=row['src_cpu'],row['dst_cpu'];assert 0<=a<16 and 0<=b<16
        if (a<8)==(b<8):continue
        matching=[x for x in accepted if x['tid']==row['tid'] and x['enter_time']<=row['timestamp']<=x['return_time']]
        assert len(matching)==1
        ack=matching[0]; assert ack['generation']>0 and (row['tid'],ack['generation']) not in used
        used.add((row['tid'],ack['generation'])); route='256-to-1024' if a<8 else '1024-to-256'
        physical.append(dict(**row,route=route,ack=ack));by_tid[row['tid']].add(route)
    return dict(physical_commits=physical,route_counts={k:sum(x['route']==k for x in physical) for k in ('256-to-1024','1024-to-256')},both_route_tids=[t for t,v in by_tid.items() if len(v)==2],raw_accepted_ack_count=sum(x['tid'] in selected for x in accepted),capability_ack_count=sum(x['tid'] in selected for x in capabilities))

def independent_stdout(count):
    mod=2**32; word=0x12345678
    for n in range(count):
        word=(word+n)%mod; constant=(0x9e3779b9*(n+1))%mod
        for i in range(64):
            word^=(word*8192)%mod;word^=word//131072;word^=(word*32)%mod;word=(word+constant+i)%mod
    for i in range(2048):word^=(((i*2654435761)%mod)*1664525+1013904223)%mod
    return f'{word:08x}\n'

def preflight(attempt):
    record='preflight-'+str(attempt); result,res=normal(record); root=P/'evidence'/record
    refs=load(root/'references.json'); assert len(refs)==2
    for count,x in refs.items():
        count=int(count); assert x['stdout']==x['expected_stdout']==independent_stdout(count)
        assert sha(root/f'reference-{count}.o')==x['object_sha256'] and sha(root/f'reference-{count}.exe')==x['executable_sha256']
        run=subprocess.run([str(root/f'reference-{count}.exe')],capture_output=True,timeout=30,env={k:v for k,v in os.environ.items() if k not in ('LD_PRELOAD','CHIMERA_WORKSPACE','CHIMERA_REGISTRY','CHIMERA_AUTOMIGRATE')})
        assert run.returncode==0 and run.stdout.decode()==independent_stdout(count)
    summaries=[]; routes=collections.defaultdict(collections.Counter); unreg=collections.Counter()
    for mode in ('x100','auto-x100','auto-a100','static16'):
        for num in range(1,4 if mode.startswith('auto-') else 2):
            directory=root/f'{mode}-{num}'; row=load(directory/'result.json');sha(directory/'result.json')
            assert row['passed'] and row['workers']==16 and len(row['outputs'])==16 and 0<row['seconds']<300;ledgers(row)
            ready=load(directory/'all-ready.json');sha(directory/'all-ready.json')
            assert ready['samples']==[x['samples'] for x in row['outputs']] and ready['workers']==16
            selected=set(); children=set()
            for worker in row['outputs']:
                n=192 if worker['index']==0 else 768
                assert worker['functions']==n and sha(directory/f'worker-{worker["index"]:02d}.o')==worker['object_sha256']==refs[str(n)]['object_sha256']
                log=directory/f'worker-{worker["index"]:02d}.log'; text=log.read_text();sha(log)
                for exe,name in ((GCC,'xgcc'),(CC1,'cc1')):
                    sample=worker['samples'][exe];assert sample['executable']==exe and sample['pid'] not in selected
                    selected.add(sample['pid'])
                    if name=='cc1':children.add(sample['pid'])
                    if mode.startswith('auto-'):
                        assert sample['ready']=='1' and sample['exec_requires_ready']=='1' and sample['preference']==mode.replace('auto-','prefer-')
                        mask=(1<<4)|(1<<40);assert int(sample['SigCgt'],16)&mask==mask and int(sample['SigBlk'],16)&mask==0
                        assert re.fullmatch('[0-9a-f]{64}',sample['maps_sha256'])
                        assert f'initialized pid={sample["pid"]} executable={exe} workspace={V/"workspaces"/name}' in text
                    else:
                        assert sample['preference']=='none';ai=mode=='static16' and worker['index']%2==1
                        assert (sample['cpu']>=8)==ai
            unregistered=set(map(int,row['unregistered_assembler_samples']))
            trace=row['trace']; raw=gzip.decompress((directory/'raw-ack-cpu.trace.gz').read_bytes());sha(directory/'raw-ack-cpu.trace.gz')
            assert len(raw)==trace['uncompressed_bytes'] and rawsha(raw)==trace['uncompressed_sha256']
            fresh=replay_trace(raw.decode().splitlines(),selected|unregistered);assert fresh==trace['replay']
            assert len(trace['per_cpu'])==16 and len(trace['kprobe_profile'])==2
            for stats in trace['per_cpu'].values():
                fields=dict((k.strip(),v.strip()) for k,_,v in (l.partition(':') for l in stats.splitlines()))
                assert all(int(fields[k])==0 for k in ('overrun','commit overrun','dropped events'))
            assert all(int(x.split()[-1])==0 for x in trace['kprobe_profile'])
            assert not any(x['tid'] in unregistered for x in fresh['physical_commits'])
            child=[x for x in fresh['physical_commits'] if x['tid'] in children];assert child==row['child_commits']
            if mode.startswith('auto-'):
                assert fresh['capability_ack_count']>=32
                for samples in row['unregistered_assembler_samples'].values():
                    assert all(x['ready']=='0' and x['exec_requires_ready']=='1' for x in samples)
                unreg[mode]+=sum(map(len,row['unregistered_assembler_samples'].values()))
            else:assert not fresh['physical_commits'] and all(row['kernel_before'][k]==row['kernel_after'][k] for k in MOVES)
            routes[mode].update(x['route'] for x in child)
            summaries.append(dict(mode=mode,number=num,child_routes=dict(collections.Counter(x['route'] for x in child)),same_tid_roundtrips=len({x['tid'] for x in child if x['route']=='256-to-1024'}&{x['tid'] for x in child if x['route']=='1024-to-256'})))
    assert len(summaries)==result['cases']==8 and result['workers']==128
    for mode in ('auto-x100','auto-a100'):
        assert dict(routes[mode])==result['child_routes'][mode] and all(routes[mode][k]>0 for k in ('256-to-1024','1024-to-256'))
        assert unreg[mode]==result['unregistered_assembler_samples'][mode]>0
    probes=None
    if attempt==3:
        directory=root/'compiler-probes'; probe=load(directory/'result.json');sha(directory/'result.json')
        assert probe==result['probe_report'] and probe['passed'] and probe['probe_cases']==12 and probe['policy_tests']==14
        for name in ('version','macro-version','cc-version','as-version'):
            reference=None
            for mode in ('x100','auto-x100','auto-a100'):
                path=directory/(mode+'-'+name+'.json'); row=load(path);sha(path)
                assert row['rc']==0 and 'parent_thread_id=' not in row['stdout']
                if reference is None:reference=row['stdout']
                else:assert row['stdout']==reference
            if name=='cc-version':assert reference=='GCC 150200\n'
            if name=='macro-version':assert reference=='GCC 15 2 0\n'
        probes=dict(cases=12,kernel=kernel(directory,probe['kernel']),health=health(directory,probe['health']))
    return dict(actual_exit='success/exited/0',cases=8,chains=128,routes={k:dict(v) for k,v in routes.items()},unregistered_samples=dict(unreg),cases_detail=summaries,kernel=kernel(root,result['kernel']),health=health(root),compiler_probes=probes)

def metrics(directory,r):
    path=directory/'metrics.jsonl.gz';sha(path); m=r['metrics']; assert load(directory/'metrics-audit.json')==m
    h=hashlib.sha256();size=0;n=0; last=None;first=None;gaps=[];peak=0;cpus=collections.Counter();cc=collections.Counter(); ready=0; static=collections.defaultdict(set)
    with gzip.open(path,'rb') as stream:
        for line in stream:
            h.update(line);size+=len(line);x=json.loads(line);n+=1;t=x['monotonic']
            if last is not None:assert t>last;gaps.append(t-last)
            else:first=t
            last=t; peak=max(peak,x['memory_current_bytes']);assert x['frequency_khz']=={'0':2200000,'8':1800000}
            for proc in x['compiler_processes']:
                cpu=proc['cpu']; assert 0<=cpu<16 and proc['executable'] in (GCC,CC1)
                cpus[str(cpu)]+=1
                if proc['executable']==CC1:cc['x100' if cpu<8 else 'a100']+=1
                if r['mode']=='x100':assert cpu<8 and proc['preference']=='none'
                elif r['mode']=='static16':assert proc['preference']=='none';static[proc['pid']].add(cpu//8)
                else:
                    assert proc['preference']==r['mode'].replace('auto-','prefer-')
                    ready+=proc['ready']=='1'
    assert all(len(v)==1 for v in static.values())
    assert n==m['samples'] and size==m['uncompressed_bytes'] and h.hexdigest()==m['uncompressed_sha256'] and peak==m['sampled_peak_memory_current_bytes']
    assert n>0 and cpus and first<=r['measurement_started_monotonic']+2 and last>=r['measurement_ended_monotonic']-2
    for proc in m['processes']:
        assert proc['starttime'].isdigit() and proc['executable'] in (GCC,CC1) and proc['cpus'] and all(0<=cpu<16 for cpu in proc['cpus'])
        if r['mode']=='x100':assert all(cpu<8 for cpu in proc['cpus'])
        elif r['mode']=='static16':assert len({cpu//8 for cpu in proc['cpus']})==1
    if r['mode'].startswith('auto-'):assert ready>0
    sha(directory/'metrics-audit.json')
    return dict(samples=n,processes=len(m['processes']),cpu_observations=dict(cpus),cc1_cluster_observations=dict(cc),max_sample_gap_seconds=max(gaps,default=0),sampled_peak_bytes=peak)

def round_audit(row,plan,baseline):
    name=row['run_id'];r,c=normal(name);d=P/'evidence'/name
    for key in ('run_id','kind','mode','workers','measured'):assert r[key]==row[key]
    assert sha(P/'results'/(name+'.json'))==row['result_sha256'] and sha(P/'results'/(name+'.resources.json'))==row['resource_sha256']
    expected_worker='performance_round_v2.py' if r['kind']=='units' else 'performance_round_image_v3.py'
    assert r['worker_source_sha256']==plan['source_sha256'][expected_worker]
    assert r['data_epoch']==('attempt-2' if r['kind']=='units' else 'image-v3') and r['storage_policy_authorization_sha256']==AUTH
    assert r['conditional_scope']=='assume-scalar-independent' and r['config_sha256']==CONFIG and r['tasks_sha256']==TASKS
    start,end=r['measurement_started_monotonic'],r['measurement_ended_monotonic']
    assert end>start and abs(end-start-r['wall_seconds'])<1e-9 and r['wall_seconds']==row['wall_seconds']
    ledgers(r)
    assert {k:r['kernel_after'][k]-r['kernel_before'][k] for k in MOVES}==r['migration_deltas']==row['migration_deltas']
    if r['mode'] in ('x100','static16'):assert all(v==0 for v in r['migration_deltas'].values())
    launch=load(P/'evidence'/(name+'-launch.json'))['command'];sha(P/'evidence'/(name+'-launch.json'))
    assert '--property=MemoryMax=12G' in launch and '--property=MemoryHigh=10G' in launch and '--property=MemorySwapMax=0' in launch
    assert '--property=RuntimeMaxSec='+('2h' if r['kind']=='units' else '4h') in launch and str(P/expected_worker) in launch
    wait=load(P/'evidence'/(name+'-unit-wait.json'));assert wait['rc']==0;sha(P/'evidence'/(name+'-unit-wait.json'))
    assert int(c['memory.max'])==12*1024**3 and c['memory.swap.max']=='0' and int(c['memory.peak'])==row['peak_bytes']
    cooling=load(d/'cooling.json');sha(d/'cooling.json');assert cooling['seconds']<1800
    thresholds={k:v+3000 for k,v in baseline['temperature_millicelsius'].items()}
    assert cooling['start_thresholds']==thresholds and set(cooling['samples'][-1]['temperature_millicelsius'])==set(thresholds)
    assert all(cooling['samples'][-1]['temperature_millicelsius'][k]<=v for k,v in thresholds.items())
    if r['kind']=='units':
        tasks=load(P/'tasks.json'); assert len(r['jobs'])==64 and {x['index'] for x in r['jobs']}==set(range(64))
        assert r['artifacts']=={x['target']:x['baseline_object_sha256'] for x in tasks}
        assert abs(r['throughput_objects_per_second']-64/r['wall_seconds'])<1e-9
        for job in r['jobs']:
            assert job['rc']==0 and job['target']==tasks[job['index']]['target'] and start<=job['started_monotonic']<=job['ended_monotonic']<=end
            assert abs(job['seconds']-(job['ended_monotonic']-job['started_monotonic']))<1e-9
            assert job['slot']<r['workers'];sha(d/f'job-{job["index"]:03d}.log')
            if r['mode']=='static16':assert job['static_group']==('x100' if job['slot']%2==0 else 'a100')
    else:
        assert not r['jobs'] and r['artifacts']==load(P/'artifacts/canonical-image-v3/hashes.json')
        assert r['successful_image_intermediates_removed'] and r['stdout_notification_omitted'] is True and r['launcher_sha256']==plan['source_sha256']['bin/native-launch-image-v3']
        capacity=load(d/'capacity.json');assert capacity['allocated_bytes']>=12*1024**3 and capacity['residual_bytes']>=capacity['required_margin_bytes']==6*1024**3
        sha(d/'capacity.json')
        for log in ('olddefconfig.log','prepare.log','make-image.log'):sha(d/log)
    out=dict(run_id=name,kind=r['kind'],mode=r['mode'],workers=r['workers'],measured=r['measured'],seconds=r['wall_seconds'],actual_exit='success/exited/0',peak_bytes=int(c['memory.peak']),usage=r['usage_seconds'],migration_deltas=r['migration_deltas'],kernel=kernel(d,r['kernel']),health=health(d,r['storage_health']),metrics=metrics(d,r))
    return out

def main():
    assert not A.exists(); A.mkdir(parents=True);os.umask(0o077)
    normal('image-controller-3')
    failed_index=P/'evidence/final-audit-1-failure.json'
    assert sha(failed_index)=='003252be70bddae2c5e7b2e4f9588edffbde2ced29ab5a464e603bd1c8c9d78f'
    for entry in load(failed_index)['files']:assert sha(entry['path'])==entry['sha256']
    progress('current_source_and_frozen_inputs')
    unit_plan=load(P/'performance-plan-attempt2.json');image_plan=load(P/'image-plan-v3.json')
    assert image_plan['unit_plan_sha256']==sha(P/'performance-plan-attempt2.json')
    assert sha(P/'storage-policy-authorization-attempt2.json')==AUTH and sha(P/'config.common')==CONFIG and sha(P/'tasks.json')==TASKS
    for plan in (unit_plan,image_plan):
        for name,digest in plan['source_sha256'].items():assert sha(P/name)==digest,name
    expected_wrapper='#!/bin/sh\nmode=${CHIMERA_PERF_MODE:-x100}\nif [ "$mode" = static16 ]; then mode=${CHIMERA_PERF_STATIC_GROUP:?}; fi\nexec '+str(P/'bin/native-launch')+' "$mode" '+GCC+' -B'+str(V/'build-gate/gcc')+'/ "$@"\n'
    assert (P/'bin/cc').read_text()==expected_wrapper;sha(P/'bin/cc')
    current_settings={}
    for cpu in (0,8):
        root=Path(f'/sys/devices/system/cpu/cpu{cpu}/cpufreq')
        current_settings[str(cpu)]={p.name:p.read_text().strip() for p in (root/'scaling_governor',root/'scaling_min_freq',root/'scaling_max_freq',root/'scaling_setspeed') if p.exists()}
    assert current_settings==load(P/'platform-settings.json');sha(P/'platform-settings.json')
    import unittest
    from test_perf_policy_v2 import BoundaryTests
    with (A/'policy-regressions.log').open('w') as output:
        tests=unittest.TextTestRunner(stream=output,verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(BoundaryTests))
    assert tests.wasSuccessful() and tests.testsRun==14 and not tests.skipped
    source=source_audit();save(A/'source.json',source)
    progress('current_workspace_artifact_receipt_and_native_table_binding')
    workspaces=workspace_audit();save(A/'workspaces.json',workspaces)
    progress('preflight_raw_ack_cpu_and_initialization_replay')
    pf={str(i):preflight(i) for i in (1,3)};save(A/'preflight-replay.json',pf)
    canonical=load(P/'artifacts/canonical-image-v3/hashes.json')
    for name,digest in canonical.items():assert sha(P/'artifacts/canonical-image-v3'/name)==digest
    for task in load(P/'tasks.json'):assert sha(task['source'])==task['source_sha256'] and sha(P/'work/seed'/task['target'])==task['baseline_object_sha256']
    setup=load(P/'setup-accepted.json');assert sha(P/'results'/(setup['record']+'.json'))==setup['result_sha256'];normal(setup['record'])
    parent,_=normal('image-controller-3');assert len(parent['image_rounds'])==12 and parent['measured_images']==9
    unit_rows=load(P/'evidence/controller-2/progress.json')['completed'][:96];image_rows=load(P/'evidence/image-controller-3/progress.json')['completed']
    assert unit_rows==image_plan['unit_results'] and image_rows==parent['image_rounds']
    assert len(unit_rows)==96 and len(image_rows)==12
    rows=[]
    for plan,items,schedule,base in ((unit_plan,unit_rows,unit_plan['rows'][:96],'temperature-baseline-attempt2.json'),(image_plan,image_rows,image_plan['rows'],'temperature-baseline-image-v3.json')):
        baseline=load(P/base);sha(P/base);assert baseline['initial_idle_seconds']==130 and len(baseline['samples'])==5
        assert baseline['temperature_millicelsius']=={k:int(statistics.median(s[k] for s in baseline['samples'])) for k in baseline['samples'][0]}
        for row,scheduled in zip(items,schedule):
            assert all(row[k]==v for k,v in scheduled.items())
            progress('round_raw_metrics_kernel_health_replay',run_id=row['run_id'],completed=len(rows),total=108)
            rows.append(round_audit(row,plan,baseline))
    assert sum(x['measured'] for x in rows)==89
    progress('statistics_and_preservation')
    groups=[]
    for kind,workers,mode in sorted({(r['kind'],r['workers'],r['mode']) for r in rows if r['measured']}):
        sample=[x for x in rows if x['measured'] and (x['kind'],x['workers'],x['mode'])==(kind,workers,mode)];values=[x['seconds'] for x in sample]
        assert len(values)==(5 if kind=='units' else 3)
        groups.append(dict(kind=kind,workers=workers,mode=mode,n=len(values),raw_seconds=values,median_seconds=statistics.median(values),min_seconds=min(values),max_seconds=max(values),throughput_per_second=(64 if kind=='units' else 1)/statistics.median(values)))
    old=load(P/'results/controller-2.json'); assert old['passed'] is False and old['rc']==1
    assert load(P/'results/a2-image-warm-auto-x100.json')['passed'] is False
    for index,key in (('controller-2-image-failure.json','files'),('controller-1-storage-failure.json','original_files_unchanged')):
        original=load(P/'evidence'/index);sha(P/'evidence'/index)
        for row in original[key]:assert sha(row['path'])==row['sha256']
    assert (P/'work/image').is_dir() and not (P/'work/image-v3').exists()
    from runtime_smoke import stats
    final=stats();assert all(final[k]==0 for k in LEDGERS) and final['prefer_a100_fail_timeout']==0
    trace=Path('/sys/kernel/tracing');assert not list((trace/'instances').glob('chimera_gcc_perf_578ab8321_*')) and 'chimera_gcc_perf_578ab8321_' not in (trace/'kprobe_events').read_text()
    assert not Path('/proc/swaps').read_text().splitlines()[1:]
    save(A/'rounds.json',rows);save(A/'statistics.json',groups);sha(A/'rounds.json');sha(A/'statistics.json')
    result=dict(passed=True,rc=0,commit=COMMIT,kernel=os.uname().release,conditional_scope='assume-scalar-independent',rounds=108,measured_rounds=89,warmups=19,unit_rounds=96,image_rounds=12,current_source=source,workspaces=workspaces,preflights={i:{k:v for k,v in x.items() if k!='cases_detail'} for i,x in pf.items()},statistics=groups,final_counters=final,all_original_failures_retained=True,prior_affected_images_not_pooled=True,task_trace_and_probes_clean=True,receipts_republished=False,old_validation_modified=False,prior_audit_failure_preserved=True,audit_method_fix='Apply the exact original tarfile data extraction filter to symlink target text; full file contents and exact patch checks unchanged',removed_image_intermediates='Per-round recorded exact canonical comparison; retained canonical rehashed, removed intermediates cannot be rehashed',storage_sample_limitation='Discrete samples; no duration or causal performance impact inference',audit_source_sha256=sha(__file__),completed_utc=datetime.datetime.now(datetime.timezone.utc).isoformat())
    save(A/'evidence-sha256.json',EVIDENCE);result['evidence_manifest_sha256']=sha(A/'evidence-sha256.json');result['evidence_files']=len(EVIDENCE)
    save(P/'results/final-audit-2.json',result);progress('complete',passed=True,rounds=108,evidence_files=result['evidence_files'])
    print(json.dumps(result),flush=True)

if __name__=='__main__':
    try:main()
    except BaseException as error:
        value=dict(passed=False,rc=1,section=SECTION,error=repr(error),traceback=traceback.format_exc(),utc=datetime.datetime.now(datetime.timezone.utc).isoformat())
        save(P/'results/final-audit-2.json',value)
        save(P/'state.json',dict(phase='independent_final_audit',status='failed',active_unit=UNIT,updated_utc=value['utc'],section=SECTION,error=value['error']))
        print(json.dumps(value),flush=True);raise
