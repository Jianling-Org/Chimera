"""Untimed four-group proof, including real -c -> unregistered assembler exec."""
from pathlib import Path
import argparse,collections,gzip,json,os,signal,subprocess,threading,time
from perf_common import *

def run_case(mode,number,trace,root,references,health,kernel):
    directory=root/f'{mode}-{number}';directory.mkdir()
    before=zero_ledgers();guard();jobs=[];release=threading.Event();selected=set();unregistered={};cpu_seen=collections.defaultdict(set)
    started=time.monotonic();active=False
    try:
        trace.start(directory/'raw-ack-cpu.trace.gz');active=True
        for index in range(16):
            functions=192 if index==0 else 768
            source,expected=smoke.fixture(functions)
            selected_mode=('x100' if index%2==0 else 'a100') if mode=='static16' else mode
            target=directory/f'worker-{index:02d}.o'
            command=native_command(selected_mode,'-O2','-mabi=lp64d','-frandom-seed=chimera-perf-578ab8321','-fno-ident','-march=rv64gcv','-mrvv-vector-bits=scalable','-c','-x','c','-','-o',target)
            log=(directory/f'worker-{index:02d}.log').open('wb')
            process=subprocess.Popen(command,stdin=subprocess.PIPE,stdout=log,stderr=subprocess.STDOUT,env=environment(mode,True),start_new_session=True)
            job=dict(index=index,functions=functions,source=source,expected=expected,mode=selected_mode,target=target,command=command,process=process,log=log,samples={},errors=[])
            def feed(job=job):
                try:
                    assert release.wait(180)
                    job['process'].stdin.write(job['source']);job['process'].stdin.close()
                except BaseException as error:job['errors'].append(repr(error))
            job['feeder']=threading.Thread(target=feed,daemon=True);job['feeder'].start();jobs.append(job)
        all_ready=False;last_health=0
        while any(job['process'].poll() is None for job in jobs):
            elapsed=time.monotonic()-started;assert elapsed<300,'Untimedpreflightcase exceeded300s'
            if elapsed-last_health>5:
                health.check();guard();assert not kernel.alerts and not kernel.errors
                assert trace.failure is None,trace.failure;last_health=elapsed
            for job in jobs:
                process=job['process']
                if process.poll() is not None:
                    assert all_ready and process.returncode==0,(mode,process.pid,process.returncode);continue
                try:
                    child_ids=(Path('/proc')/str(process.pid)/'task'/str(process.pid)/'children').read_text().split()
                except OSError:child_ids=[]
                for pid in [process.pid,*map(int,child_ids)]:
                    try:
                        sample=sample_status(pid);exe=sample['executable'];cpu_seen[pid].add(sample['cpu'])
                        if exe not in (str(smoke.GCC),str(smoke.CC1)):
                            if Path(exe).name.endswith('-as') or Path(exe).name in ('as','ld','riscv64-linux-gnu-ld.bfd'):
                                unregistered.setdefault(pid,[]).append(sample)
                            continue
                        selected.add(pid)
                        if mode in ('x100','static16'):
                            ai=job['mode']=='a100'
                            assert (sample['cpu']>=8)==ai,(mode,job['mode'],sample)
                            assert sample['preference']=='none',sample
                            if exe not in job['samples']:job['samples'][exe]=sample
                        elif exe not in job['samples']:
                            preference=mode.replace('auto-','prefer-')
                            if not initialized(sample,preference):continue
                            workspace=V/'workspaces'/('xgcc' if exe==str(smoke.GCC) else 'cc1')
                            maps=(Path('/proc')/str(pid)/'maps').read_text()
                            assert str(workspace/'artifacts/runtime/libchimera_inject.so') in maps
                            sample['maps_sha256']=hashlib.sha256(maps.encode()).hexdigest()
                            job['samples'][exe]=sample
                    except (OSError,ProcessLookupError):pass
            if not all_ready and all(set(job['samples'])=={str(smoke.GCC),str(smoke.CC1)} for job in jobs):
                all_ready=True;save(directory/'all-ready.json',dict(samples=[j['samples'] for j in jobs],mode=mode,workers=16));release.set()
            time.sleep(0.005)
        assert all_ready
        for job in jobs:
            job['feeder'].join(timeout=2);assert not job['feeder'].is_alive() and not job['errors'];job['log'].close()
        deadline=time.monotonic()+3
        while any(smoke.stats()[k] for k in LEDGERS) and time.monotonic()<deadline:time.sleep(0.02)
        after=zero_ledgers();assert after['prefer_a100_fail_timeout']==before['prefer_a100_fail_timeout']
        capture=trace.finish(selected|set(unregistered));active=False
        child_ids={j['samples'][str(smoke.CC1)]['pid'] for j in jobs}
        children=[x for x in capture['replay']['physical_commits'] if x['tid'] in child_ids]
        assert not [x for x in capture['replay']['physical_commits'] if x['tid'] in unregistered],'Unregisteredassembler mustnotcrossVLEN'
        if mode in ('x100','static16'):
            assert not capture['replay']['physical_commits']
            assert after['prefer_a100_x100_to_a100_migrations']==before['prefer_a100_x100_to_a100_migrations']
            assert after['prefer_a100_a100_to_x100_migrations']==before['prefer_a100_a100_to_x100_migrations']
        else:
            assert capture['replay']['capability_ack_count']>=32
            for samples in unregistered.values():
                assert all(s['ready']=='0' and s['exec_requires_ready']=='1' for s in samples),samples
        outputs=[]
        for job in jobs:
            actual=sha(job['target']);assert actual==references[job['functions']]['object_sha256']
            text=(directory/f'worker-{job["index"]:02d}.log').read_text()
            if mode.startswith('auto-'):
                for exe,name in ((smoke.GCC,'xgcc'),(smoke.CC1,'cc1')):
                    pid=job['samples'][str(exe)]['pid']
                    assert f'initialized pid={pid} executable={exe} workspace={V/"workspaces"/name}' in text
            outputs.append(dict(index=job['index'],functions=job['functions'],object_sha256=actual,command=job['command'],samples=job['samples']))
        cpus=sorted({cpu for values in cpu_seen.values() for cpu in values})
        if mode=='static16':assert any(c<8 for c in cpus) and any(c>=8 for c in cpus)
        value=dict(passed=True,mode=mode,number=number,workers=16,seconds=time.monotonic()-started,outputs=outputs,trace=capture,child_commits=children,unregistered_assembler_samples={str(k):v for k,v in unregistered.items()},cpu_seen=cpus,kernel_before=before,kernel_after=after)
        save(directory/'result.json',value);return value
    except BaseException as error:
        save(directory/'failure.json',dict(error=repr(error),jobs=[dict(pid=j['process'].pid,rc=j['process'].poll(),command=j['command'],samples=j['samples'],errors=j['errors']) for j in jobs]));raise
    finally:
        for job in jobs:
            proc=job['process']
            if proc.poll() is None:
                os.killpg(proc.pid,signal.SIGTERM)
                try:proc.wait(timeout=10)
                except subprocess.TimeoutExpired:os.killpg(proc.pid,signal.SIGKILL);proc.wait(timeout=5)
            if not job['log'].closed:job['log'].close()
        if active:
            try:save(directory/'failed-trace.json',trace.finish(selected|set(unregistered)))
            except BaseException as error:save(directory/'trace-finish-error.json',dict(error=repr(error)))

def main(attempt):
    record=f'preflight-{attempt}';unit=f'chimera-gcc-perf-{record}.service';root=P/'evidence'/record
    verify_setup();guard();zero_ledgers();assert not root.exists();root.mkdir()
    state('preflight','running',unit,evidence=str(root))
    references={}
    for count in (192,768):
        source,expected=smoke.fixture(count);obj=root/f'reference-{count}.o'
        command=native_command('x100','-O2','-mabi=lp64d','-frandom-seed=chimera-perf-578ab8321','-fno-ident','-march=rv64gcv','-mrvv-vector-bits=scalable','-c','-x','c','-','-o',obj)
        c=subprocess.run(command,input=source,capture_output=True,env=environment(),timeout=120);assert c.returncode==0,c.stderr
        exe=obj.with_suffix('.exe');c=subprocess.run(['/usr/bin/gcc','-march=rv64gcv','-mabi=lp64d','-no-pie',str(obj),'-o',str(exe)],capture_output=True,env=environment(),timeout=60);assert c.returncode==0,c.stderr
        c=subprocess.run([str(exe)],capture_output=True,env=environment(),timeout=30);assert c.returncode==0 and c.stdout.decode()==expected
        references[count]=dict(object_sha256=sha(obj),executable_sha256=sha(exe),stdout=c.stdout.decode(),expected_stdout=expected)
    save(root/'references.json',references)
    trace=TraceCapture(f'chimera_gcc_perf_578ab8321_pf{attempt}');health=StorageHealth(root);kernel=KernelLog(root,True)
    kernel.start();cases=[];health.check(force=True)
    try:
        trace.configure()
        for mode in MODES:
            repeats=3 if mode.startswith('auto-') else 1
            for number in range(1,repeats+1):
                state('preflight','running',unit,mode=mode,case=number,completed_cases=len(cases))
                cases.append(run_case(mode,number,trace,root,references,health,kernel))
    finally:
        try:trace.close()
        finally:kernel_result=kernel.finish()
    assert not kernel_result['errors'] and not kernel_result['alerts'];health.check(force=True)
    routes={};unregistered={}
    for mode in ('auto-x100','auto-a100'):
        commits=[c for case in cases if case['mode']==mode for c in case['child_commits']]
        assert commits,('NeedrealacceptedACKandCPUcommit',mode)
        routes[mode]=dict(collections.Counter(c['route'] for c in commits))
        samples=[rows for case in cases if case['mode']==mode for rows in case['unregistered_assembler_samples'].values()]
        assert samples,('Needunregisteredassemblerevidence',mode);unregistered[mode]=sum(len(rows) for rows in samples)
    value=dict(passed=True,rc=0,attempt=attempt,cases=len(cases),workers=sum(c['workers'] for c in cases),references=references,child_routes=routes,unregistered_assembler_samples=unregistered,kernel=kernel_result,all_ledgers_zero=True,controls_zero_migration=True,config_sha256=sha(P/'config.common'),source_tasks_sha256=sha(P/'tasks.json'),completed_utc=datetime.datetime.now(datetime.timezone.utc).isoformat())
    save(P/'results'/(record+'.json'),value);state('preflight','phase_complete',unit,rc=0,evidence=str(root));print(json.dumps(value),flush=True)

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--attempt',type=int,required=True);a=parser.parse_args()
    try:main(a.attempt)
    except BaseException as error:
        save(P/'results'/f'preflight-{a.attempt}.json',dict(passed=False,rc=1,error=repr(error)))
        state('preflight','failed',f'chimera-gcc-perf-preflight-{a.attempt}.service',rc=1,error=repr(error));raise
