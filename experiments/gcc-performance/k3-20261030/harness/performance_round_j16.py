"""One bounded measured/warmup round, common instrumentation for all modes."""
import argparse,concurrent.futures,gzip,resource,threading,signal
from perf_common_j16 import *

def temperatures():
    values={}
    for p in Path('/sys/class/thermal').glob('thermal_zone*/temp'):
        try:values[p.parent.name+':'+(p.parent/'type').read_text().strip()]=int(p.read_text().strip())
        except OSError:pass
    return values
def frequencies():
    values={}
    for cpu in (0,8):
        p=Path(f'/sys/devices/system/cpu/cpu{cpu}/cpufreq/scaling_cur_freq')
        try:values[str(cpu)]=int(p.read_text().strip())
        except OSError:pass
    return values
def platform_settings():
    values={}
    for cpu in (0,8):
        root=Path(f'/sys/devices/system/cpu/cpu{cpu}/cpufreq')
        values[str(cpu)]={path.name:path.read_text().strip() for path in (root/'scaling_governor',root/'scaling_min_freq',root/'scaling_max_freq',root/'scaling_setspeed') if path.exists()}
    return values
def cpu_ticks():
    return {fields[0]:list(map(int,fields[1:])) for fields in (line.split() for line in Path('/proc/stat').read_text().splitlines()) if fields and fields[0].startswith('cpu') and fields[0]!='cpu'}
def cgroup():
    return Path('/sys/fs/cgroup')/Path('/proc/self/cgroup').read_text().split('0::',1)[1].strip().lstrip('/')
def thermal_wait(root):
    reference=load(P/'temperature-baseline.json')['temperature_millicelsius'];assert reference,'No thermal monitoring available'
    start=time.monotonic();samples=[]
    while True:
        now=temperatures();samples.append(dict(monotonic=time.monotonic(),temperature_millicelsius=now))
        assert set(now)==set(reference),'Thermal sensor set changed'
        if all(now[k]<=v+3000 for k,v in reference.items()):break
        assert time.monotonic()-start<1800,'Cannot reach common starttemperature within30min; do not count a hot run'
        time.sleep(5)
    save(root/'cooling.json',dict(seconds=time.monotonic()-start,samples=samples,start_thresholds={k:v+3000 for k,v in reference.items()}))

class Monitor:
    def __init__(self,root,mode,kernel,health):
        self.root,self.mode,self.kernel,self.health=root,mode,kernel,health
        self.stop=threading.Event();self.failure=None;self.samples=0;self.processes={};self.total_bytes=0;self.digest=hashlib.sha256();self.peak_memory=0
    def start(self):
        group=cgroup();self.cpu_before=cpu_ticks()
        def collect():
            try:
                with gzip.open(self.root/'metrics.jsonl.gz','wb',compresslevel=1) as output:
                    while not self.stop.is_set():
                        guard();self.health.check();assert not self.kernel.errors and not self.kernel.alerts
                        memory=int((group/'memory.current').read_text());self.peak_memory=max(self.peak_memory,memory)
                        sample=dict(monotonic=time.monotonic(),temperatures=temperatures(),frequency_khz=frequencies(),memory_current_bytes=memory,compiler_processes=[])
                        for pid in (group/'cgroup.procs').read_text().split():
                            path=Path('/proc')/pid
                            try:
                                before=os.readlink(path/'exe')
                                if before not in (str(smoke.GCC),str(smoke.CC1)):continue
                                raw=(path/'stat').read_text();fields=raw[raw.rfind(')')+2:].split();cpu=int(fields[36]);starttime=fields[19]
                                if fields[0] in ('Z','X','x') or int(fields[6])&4:continue  # PF_EXITING
                                status=(path/'status').read_text();after=os.readlink(path/'exe')
                                if before!=after:continue
                                values=dict((k,v.strip()) for k,v in (line.split(':',1) for line in status.splitlines() if ':' in line))
                                key=pid+':'+starttime+':'+before
                                row=self.processes.setdefault(key,dict(pid=int(pid),starttime=starttime,executable=before,cpus=[],ready_observed=False))
                                if cpu not in row['cpus']:row['cpus'].append(cpu)
                                pref=values.get('Hmp_preference');ready=values.get('Hmp_runtime_ready')
                                if self.mode=='x100':assert cpu<8 and pref=='none' and values.get('Cpus_allowed_list')=='0-7',(self.mode,cpu,pref)
                                elif self.mode=='static16':assert pref=='none' and len({x//8 for x in row['cpus']})==1,(self.mode,row)
                                else:
                                    assert pref==self.mode.replace('auto-','prefer-'),(self.mode,pref)
                                    if ready=='1' and values.get('Hmp_exec_requires_ready')=='1':row['ready_observed']=True
                                sample['compiler_processes'].append(dict(pid=int(pid),executable=before,cpu=cpu,preference=pref,ready=ready,starttime=starttime,state=fields[0],allowed_cpus=values.get('Cpus_allowed_list'),exec_requires_ready=values.get('Hmp_exec_requires_ready')))
                            except (OSError,ProcessLookupError,ValueError):continue
                        payload=(json.dumps(sample,separators=(',',':'))+'\n').encode();output.write(payload);self.digest.update(payload);self.total_bytes+=len(payload);self.samples+=1
                        save(self.root/'monitor-latest.json',dict(samples=self.samples,temperature_millicelsius=sample['temperatures'],frequency_khz=sample['frequency_khz'],observed_compiler_processes=len(self.processes)))
                        self.stop.wait(0.5)
            except BaseException as error:
                self.failure=repr(error)
                if getattr(self,'abort',None):self.abort()
        self.thread=threading.Thread(target=collect,daemon=True);self.thread.start()
    def check(self):assert self.failure is None,self.failure
    def finish(self):
        self.stop.set();self.thread.join(timeout=10);assert not self.thread.is_alive();self.check()
        after=cpu_ticks();util={}
        for cpu,first in self.cpu_before.items():
            delta=[b-a for a,b in zip(first,after[cpu])];total=sum(delta[:8]);idle=delta[3]+delta[4]
            util[cpu]=dict(total_ticks=total,busy_ticks=total-idle,busy_percent=100*(total-idle)/total if total else 0)
        value=dict(samples=self.samples,uncompressed_bytes=self.total_bytes,uncompressed_sha256=self.digest.hexdigest(),processes=list(self.processes.values()),cpu_utilization=util,cpu_ticks_before=self.cpu_before,cpu_ticks_after=after,sampled_peak_memory_current_bytes=self.peak_memory,instrumentation='Same0.5sproc/temperature/frequency/memory sampling; detailedkprobeanddebugoff')
        save(self.root/'metrics-audit.json',value);return value

def check_receipts():
    for name in ('xgcc','cc1'):
        for line in (V/'workspaces'/name/'artifacts/verified-files.tsv').read_text().splitlines():
            path,digest,*fields=line.split('\t');st=Path(path).stat()
            assert list(map(int,fields))==[st.st_dev,st.st_ino,st.st_size,st.st_mtime_ns//10**9,st.st_mtime_ns%10**9,st.st_ctime_ns//10**9,st.st_ctime_ns%10**9],path

def full_capacity(root):
    path=P/'work/image-capacity-probe';assert not path.exists()
    fd=os.open(path,os.O_CREAT|os.O_EXCL|os.O_RDWR,0o600)
    try:
        os.posix_fallocate(fd,0,12*1024**3);os.fsync(fd);allocated=os.fstat(fd).st_blocks*512;remaining=shutil.disk_usage(P).free
        assert allocated>=12*1024**3 and remaining>=6*1024**3
    finally:
        os.close(fd);assert path.resolve().parent==(P/'work').resolve();path.unlink()
    save(root/'capacity.json',dict(allocated_bytes=allocated,residual_bytes=remaining,required_margin_bytes=6*1024**3))

def prepare_image(root):
    path=P/'work/image-j16';assert not path.exists(),'Prior image worktree exists; inspect before cleanup'
    path.mkdir();(path/'.chimera-performance-owned').write_text(str(P));shutil.copy2(P/'config.common',path/'.config')
    command=['/usr/bin/make','-C',str(S),'O='+str(path),'ARCH=riscv','CC='+str(P/'bin/cc-image-v3'),'HOSTCC=/usr/bin/gcc','HOSTCXX=/usr/bin/g++']
    for args,name in ((['olddefconfig'],'olddefconfig'),(['-j2','prepare','scripts'],'prepare')):
        with (root/(name+'.log')).open('wb') as log:
            p=subprocess.run(command+args,env=environment('x100'),stdin=subprocess.DEVNULL,stdout=log,stderr=subprocess.STDOUT,timeout=1200)
        assert p.returncode==0,(name,p.returncode)
    assert sha(path/'.config')==sha(P/'config.common'),'Commonconfigchanged'
    return path,command

def execute(args,root,kernel,health):
    verify_authorization();guard();verify_setup();verify_previous('preflight-3');check_receipts()
    reference=load(BASE/'results/preflight-1.json');assert sha(P/'config.common')==reference['config_sha256'] and sha(P/'tasks.json')==reference['source_tasks_sha256']
    tasks=load(P/'tasks.json');assert len(tasks)==64
    for task in tasks:assert sha(Path(task['source']))==task['source_sha256']
    image=None
    if args.kind=='image':full_capacity(root);image,make_command=prepare_image(root)
    thermal_wait(root);assert platform_settings()==load(P/'platform-settings.json'),'Startgovernor/frequencysettingschanged';health.check(force=True);before=zero_ledgers();active={};lock=threading.Lock();slots={};slot_count=0
    monitor=Monitor(root,args.mode,kernel,health);monitor.start()
    first_children=resource.getrusage(resource.RUSAGE_CHILDREN);first_self=resource.getrusage(resource.RUSAGE_SELF)
    started=time.monotonic();jobs=[];pool=None
    def terminate():
        with lock:current=list(active.values())
        for proc in current:
            if proc.poll() is None:
                try:os.killpg(proc.pid,signal.SIGTERM)
                except ProcessLookupError:pass
        for proc in current:
            try:proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                try:os.killpg(proc.pid,signal.SIGKILL)
                except ProcessLookupError:pass
    def launch(command,log_path,env,cwd=None,timeout=3600):
        monitor.check()
        with log_path.open('wb') as log:
            proc=subprocess.Popen(command,env=env,cwd=cwd,stdin=subprocess.DEVNULL,stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
            with lock:active[proc.pid]=proc
            try:
                monitor.check()
                # Blocking waitpid wakes immediately: polling at0.2s would
                # quantize short compile times and idle each queue slot.
                proc.wait()
                assert proc.returncode==0,(command,proc.returncode)
                return proc.pid
            finally:
                if proc.poll() is None:
                    try:os.killpg(proc.pid,signal.SIGTERM);proc.wait(timeout=10)
                    except ProcessLookupError:pass
                with lock:active.pop(proc.pid,None)
    def job(index,task):
        nonlocal slot_count
        thread=threading.get_ident()
        with lock:
            if thread not in slots:slots[thread]=slot_count;slot_count+=1
            slot=slots[thread]
        assigned='x100' if slot%2==0 else 'a100'
        env=environment(args.mode,False,assigned if args.mode=='static16' else None)
        t=time.monotonic();pid=launch(['/bin/sh','-c',task['command']],root/f'job-{index:03d}.log',env,W,1200)
        ended=time.monotonic()
        return dict(index=index,target=task['target'],slot=slot,static_group=assigned if args.mode=='static16' else None,pid=pid,seconds=ended-t,started_monotonic=t,ended_monotonic=ended,rc=0)
    monitor.abort=terminate
    try:
        if args.kind=='units':
            pool=concurrent.futures.ThreadPoolExecutor(max_workers=args.workers)
            futures={pool.submit(job,index,task) for index,task in enumerate(tasks)}
            while futures:
                done,futures=concurrent.futures.wait(futures,timeout=0.5,return_when=concurrent.futures.FIRST_COMPLETED)
                monitor.check()
                for future in done:jobs.append(future.result())
            pool.shutdown();pool=None
        else:
            command=make_command+['-j'+str(args.workers),'Image']
            launch(command,root/'make-image.log',environment(args.mode),timeout=3*3600)
        ended=time.monotonic();seconds=ended-started
        last_children=resource.getrusage(resource.RUSAGE_CHILDREN);last_self=resource.getrusage(resource.RUSAGE_SELF)
    except BaseException:
        terminate()
        if pool:pool.shutdown(wait=True,cancel_futures=True)
        raise
    finally:
        metrics=monitor.finish()
    after=zero_ledgers();assert after['prefer_a100_fail_timeout']==before['prefer_a100_fail_timeout']
    if args.mode in ('x100','static16'):
        assert after['prefer_a100_x100_to_a100_migrations']==before['prefer_a100_x100_to_a100_migrations'] and after['prefer_a100_a100_to_x100_migrations']==before['prefer_a100_a100_to_x100_migrations']
    assert not kernel.errors and not kernel.alerts;health.check(force=True)
    artifacts={}
    if args.kind=='units':
        for task in tasks:
            actual=sha(W/task['target']);assert actual==task['baseline_object_sha256'],task['target'];artifacts[task['target']]=actual
    else:
        mapping={'Image':'arch/riscv/boot/Image','vmlinux':'vmlinux','System.map':'System.map','config':'.config'}
        for name,relative in mapping.items():
            path=image/relative;artifacts[name]=sha(path)
        canonical=P/'artifacts/canonical-image-j16';canonical.parent.mkdir(exist_ok=True)
        if not canonical.exists():
            assert args.mode=='x100' and not args.measured,'Firstcanonicalimage must be nativewarmup'
            canonical.mkdir()
            for name,relative in mapping.items():shutil.copy2(image/relative,canonical/name)
            save(canonical/'hashes.json',artifacts)
        assert artifacts==load(canonical/'hashes.json'),'FullImageartifactmismatch'
        assert artifacts==load(BASE/'artifacts/canonical-image-v3/hashes.json'),'Previously accepted canonical artifact mismatch'
        assert image==P/'work/image-j16' and image.resolve()==image and not image.is_symlink()
        assert (image/'.chimera-performance-owned').read_text()==str(P)
        shutil.rmtree(image)
    usage=dict(child_user=last_children.ru_utime-first_children.ru_utime,child_system=last_children.ru_stime-first_children.ru_stime,harness_user=last_self.ru_utime-first_self.ru_utime,harness_system=last_self.ru_stime-first_self.ru_stime)
    return dict(passed=True,rc=0,run_id=args.run_id,kind=args.kind,mode=args.mode,workers=args.workers,measured=args.measured,wall_seconds=seconds,measurement_started_monotonic=started,measurement_ended_monotonic=ended,throughput_objects_per_second=64/seconds if args.kind=='units' else None,usage_seconds=usage,jobs=sorted(jobs,key=lambda x:x['index']),artifacts=artifacts,metrics=metrics,kernel_before=before,kernel_after=after,migration_deltas={k:after[k]-before[k] for k in ('prefer_a100_x100_to_a100_migrations','prefer_a100_a100_to_x100_migrations')},config_sha256=sha(P/'config.common'),tasks_sha256=sha(P/'tasks.json'),conditional_scope='assume-scalar-independent',successful_image_intermediates_removed=image is not None,worker_source_sha256=sha(P/'performance_round_j16.py'))

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--run-id',required=True);parser.add_argument('--kind',choices=('units','image'),required=True);parser.add_argument('--mode',choices=MODES,required=True);parser.add_argument('--workers',type=int,required=True);parser.add_argument('--measured',action='store_true');args=parser.parse_args()
    import re,signal
    assert args.run_id.startswith('i4-') and args.kind=='image' and re.fullmatch('[a-z0-9-]+',args.run_id) and args.workers==16 and args.mode in ('x100','auto-x100','auto-a100')
    root=P/'evidence'/args.run_id;result_path=P/'results'/(args.run_id+'.json');unit='chimera-gcc-j16-'+args.run_id+'.service'
    assert not root.exists() and not result_path.exists(),'Refuseoverwriteexistinground'
    root.mkdir();state('performance_round','running',unit,run_id=args.run_id,kind=args.kind,mode=args.mode,workers=args.workers,measured=args.measured)
    kernel=KernelLog(root,True);health=StorageHealth(root);kernel.start()
    try:
        result=execute(args,root,kernel,health);result['kernel']=kernel.finish();kernel=None
        assert not result['kernel']['errors'] and not result['kernel']['alerts'];result['data_epoch']='image-j16-v1';result['launcher_sha256']=sha(P/'bin/native-launch-image-v3');result['stdout_notification_omitted']=True;result['storage_policy_authorization_sha256']=sha(P/'storage-policy-authorization-attempt2.json');result['storage_health']=health.summary();result['completed_utc']=datetime.datetime.now(datetime.timezone.utc).isoformat()
        save(result_path,result);state('performance_round','phase_complete',unit,rc=0,run_id=args.run_id,wall_seconds=result['wall_seconds'])
    except BaseException as error:
        result=dict(passed=False,rc=1,run_id=args.run_id,error=repr(error),data_epoch='image-j16-v1',storage_health=health.summary())
        if kernel:
            try:result['kernel']=kernel.finish()
            except BaseException as final:result['kernel_finish_error']=repr(final)
        save(result_path,result);state('performance_round','failed',unit,rc=1,run_id=args.run_id,error=repr(error));raise
