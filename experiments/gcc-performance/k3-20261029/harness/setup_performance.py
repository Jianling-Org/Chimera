"""Prepare isolated real-kernel workloads; no performance result is produced."""
from pathlib import Path
import datetime,hashlib,json,math,os,shlex,shutil,subprocess,sys,tarfile,time
P=Path('/root/chimera-gcc-performance-578ab8321-20261029')
V=Path('/root/chimera-gcc-validation-578ab8321')
K=Path('/root/chimera-kernel-update-d02cd7352')
S=P/'kernel-source';W=P/'work/seed';E=P/'evidence/setup-1'
sys.path.insert(0,str(V))
from runtime_acceptance_v5 import KernelLog
from kernel_event_policy import StorageHealth
from worker import source_imports
UNIT='chimera-gcc-perf-setup-1.service'
START=time.monotonic()

def save(path,value):Path(path).write_text(json.dumps(value,ensure_ascii=False,indent=2)+'\n')
def digest(path):
    h=hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda:stream.read(4*1024**2),b''):h.update(block)
    return h.hexdigest()
def state(status,step,**extra):
    d=dict(phase='setup',status=status,step=step,active_unit=UNIT,updated_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),**extra)
    save(P/'state.json.new',d);(P/'state.json.new').replace(P/'state.json')
    with (P/'events.jsonl').open('a') as stream:stream.write(json.dumps(d)+'\n')
    print(json.dumps(d),flush=True)
def run(args,name,env=None,cwd=None):
    assert shutil.disk_usage(P).free>=6*1024**3
    print('COMMAND',shlex.join(map(str,args)),flush=True)
    with (E/(name+'.log')).open('wb') as log:
        p=subprocess.run(list(map(str,args)),cwd=cwd,env=env,stdin=subprocess.DEVNULL,stdout=log,stderr=subprocess.STDOUT)
    assert p.returncode==0,(name,p.returncode)
    health.check();assert not kernel.errors and not kernel.alerts,(kernel.errors,kernel.alerts)
def main():
    assert not E.exists();E.mkdir()
    state('running','verify_current_inputs')
    completion=json.loads((V/'completion.json').read_text());assert completion['acceptance_passed']
    assert os.uname().release=='6.18.3-chimera-d02cd7352'
    assert not Path('/proc/swaps').read_text().splitlines()[1:]
    for rel,row in completion['files'].items():assert digest(V/rel)==row['sha256'],rel
    receipt_rows=0
    for name in ('xgcc','cc1'):
        f=V/'workspaces'/name/'artifacts/verified-files.tsv'
        for line in f.read_text().splitlines():
            path,expected,*fields=line.split('\t');st=Path(path).stat()
            assert list(map(int,fields))==[st.st_dev,st.st_ino,st.st_size,st.st_mtime_ns//10**9,st.st_mtime_ns%10**9,st.st_ctime_ns//10**9,st.st_ctime_ns%10**9]
            assert digest(path)==expected,path;receipt_rows+=1
    source_imports()
    from chimera.runtime.preload.bootstrap_launch import bootstrap_tunables
    assert bootstrap_tunables('')=='glibc.rtld.optional_static_tls=65536'
    head=subprocess.check_output(['git','-C',str(K/'source'),'rev-parse','HEAD'],text=True).strip()
    assert head=='d02cd73523ab4c7e7e952969b8d2a95925ae64d9'
    patch=subprocess.check_output(['git','-C',str(K/'source'),'diff','--binary','HEAD'])
    assert patch==(K/'source.patch').read_bytes(),'Kernel source has additional changes; preserve and inspect'
    (E/'kernel-source.patch').write_bytes(patch)
    tree=subprocess.check_output(['git','-C',str(K/'source'),'ls-tree','-rl','HEAD'],text=True)
    source_bytes=sum(int(line.split(None,4)[3]) for line in tree.splitlines() if line.split(None,4)[1]=='blob')
    source_reserve=(math.ceil(source_bytes/1024**3)+1)*1024**3
    required_allocation=source_reserve+12*1024**3
    probe=P/'work/capacity-probe';assert not probe.exists()
    descriptor=os.open(probe,os.O_CREAT|os.O_EXCL|os.O_RDWR,0o600)
    try:
        os.posix_fallocate(descriptor,0,required_allocation);os.fsync(descriptor)
        allocated=os.fstat(descriptor).st_blocks*512;remaining=shutil.disk_usage(P).free
        assert allocated>=required_allocation and remaining>=6*1024**3
    finally:
        os.close(descriptor);assert probe.resolve().parent==(P/'work').resolve();probe.unlink()
    save(E/'capacity.json',dict(source_logical_bytes=source_bytes,source_reserve_bytes=source_reserve,working_budget_bytes=12*1024**3,actual_allocated_bytes=allocated,residual_bytes=remaining,required_margin_bytes=6*1024**3,probe_removed=True))
    state('running','isolate_kernel_source',source_bytes=source_bytes)
    assert not S.exists();S.mkdir()
    archive=subprocess.Popen(['git','-C',str(K/'source'),'archive','--format=tar','HEAD'],stdout=subprocess.PIPE)
    archive_sha=hashlib.sha256()
    class Reader:
        def read(self,size=-1):
            data=archive.stdout.read(size);archive_sha.update(data);return data
    reader=Reader()
    with tarfile.open(fileobj=reader,mode='r|') as tar:tar.extractall(S,filter='data')
    while reader.read(1024**2):pass
    archive.stdout.close();assert archive.wait()==0
    run(['git','apply',E/'kernel-source.patch'],'apply-kernel-patch',cwd=S)
    assert digest(S/'drivers/gpu/drm/spacemit/spacemit_bootloader.c')==digest(K/'source/drivers/gpu/drm/spacemit/spacemit_bootloader.c')
    save(E/'inputs.json',dict(chimera_commit=completion['commit'],kernel_head=head,kernel_patch_sha256=digest(E/'kernel-source.patch'),kernel_git_archive_sha256=archive_sha.hexdigest(),receipt_rows_verified=receipt_rows,boot_id=Path('/proc/sys/kernel/random/boot_id').read_text().strip()))
    state('running','compile_scalar_launcher')
    run(['/usr/bin/gcc','-O2','-march=rv64gc','-mabi=lp64d','-nostdlib','-static','-fno-pie','-no-pie','-ffreestanding','-fno-builtin','-fno-stack-protector','-msmall-data-limit=0','-mno-relax','-Wl,--no-relax','-Wl,-e,_start',P/'native-launch.c','-o',P/'bin/native-launch'],'compile-launcher')
    cc=P/'bin/cc';cc.write_text('#!/bin/sh\nmode=${CHIMERA_PERF_MODE:-x100}\nif [ "$mode" = static16 ]; then mode=${CHIMERA_PERF_STATIC_GROUP:?}; fi\nexec '+str(P/'bin/native-launch')+' "$mode" '+str(V/'build-gate/gcc/xgcc')+' -B'+str(V/'build-gate/gcc')+'/ "$@"\n');cc.chmod(0o755)
    W.mkdir();shutil.copy2(K/'config.build',W/'.config')
    run([S/'scripts/config','--file',W/'.config','--disable','DEBUG_INFO','--enable','DEBUG_INFO_NONE','--disable','DEBUG_INFO_DWARF_TOOLCHAIN_DEFAULT','--disable','DEBUG_INFO_DWARF4','--disable','DEBUG_INFO_DWARF5','--disable','DEBUG_INFO_BTF','--disable','DEBUG_INFO_BTF_MODULES','--disable','GDB_SCRIPTS','--disable','LOCALVERSION_AUTO','--set-str','LOCALVERSION','-chimera-perf'],'benchmark-config')
    env=dict(os.environ,LC_ALL='C',TZ='UTC',SOURCE_DATE_EPOCH='1793232000',KBUILD_BUILD_TIMESTAMP='Thu Oct 29 00:00:00 UTC 2026',KBUILD_BUILD_USER='chimera-bench',KBUILD_BUILD_HOST='k3',KBUILD_BUILD_VERSION='1',CHIMERA_PERF_MODE='x100',CHIMERA_USER_CONFIG=str(V/'user.toml'))
    for key in ('LD_PRELOAD','CCACHE_PREFIX','CCACHE_DIR','MAKEFLAGS','MFLAGS','CHIMERA_WORKSPACE','CHIMERA_REGISTRY','CHIMERA_RESOURCES','CHIMERA_AUTOMIGRATE','CHIMERA_VERIFY_TABLES_ONLY'):env.pop(key,None)
    env['CCACHE_DISABLE']='1'
    command=['/usr/bin/make','-C',str(S),'O='+str(W),'ARCH=riscv','CC='+str(cc),'HOSTCC=/usr/bin/gcc','HOSTCXX=/usr/bin/g++']
    state('running','kernel_olddefconfig')
    run(command+['olddefconfig'],'olddefconfig',env)
    config=(W/'.config').read_text()
    assert 'CONFIG_DEBUG_INFO_BTF=y' not in config and 'CONFIG_DEBUG_INFO=y' not in config
    assert 'CONFIG_GCC_PLUGINS=y' not in config,'Kernel GCC plugin coverage must be reviewed before using this config'
    shutil.copy2(W/'.config',P/'config.common')
    save(E/'config.json',dict(sha256=digest(P/'config.common'),source_config=str(K/'config.build'),source_config_sha256=digest(K/'config.build'),changes='Disable DWARF/BTF/GDB scripts; fixedlocalversion and buildmetadata, sameforALLgroups',environment={k:env[k] for k in ('LC_ALL','TZ','SOURCE_DATE_EPOCH','KBUILD_BUILD_TIMESTAMP','KBUILD_BUILD_USER','KBUILD_BUILD_HOST','KBUILD_BUILD_VERSION')},make_command=command))
    state('running','kernel_prepare')
    run(command+['-j2','prepare','scripts'],'prepare-scripts',env)
    candidates={}
    for category in ('kernel','mm','fs','lib'):
        original=K/'source'/category
        paths=list(original.glob('.*.o.cmd'))
        if category=='kernel':paths+=list((original/'sched').glob('.*.o.cmd'))
        candidates[category]=[(path.parent.relative_to(K/'source')/path.name[1:-4]).as_posix() for path in sorted(paths)]
    selected=[]
    priority=['lib/bsearch.o','kernel/fork.o','mm/mmap.o','kernel/sched/core.o','kernel/sched/fair.o','mm/page_alloc.o','mm/memory.o','fs/namei.o','fs/inode.o','kernel/exit.o','init/main.o']
    ordered=list(priority)
    while any(candidates.values()):
        for values in candidates.values():
            if values:ordered.append(values.pop(0))
    for target in ordered:
        if target not in selected and (S/Path(target).with_suffix('.c')).is_file():selected.append(target)
        if len(selected)==64:break
    assert len(selected)==64,('Need64real compileunits',len(selected))
    save(P/'tasks.selected.json',selected)
    state('running','native_real_compile_pilot_64')
    run(command+['-j8','V=1',*selected],'native-64-pilot',env)
    tasks=[]
    for target in selected:
        path=W/Path(target).parent/('.'+Path(target).name+'.cmd')
        lines=path.read_text().splitlines();matches=[line.split(' := ',1)[1] for line in lines if line.startswith(('savedcmd_','cmd_')) and ' := ' in line]
        assert len(matches)==1 and str(cc) in matches[0],str(path)
        tasks.append(dict(target=target,command=matches[0],source=str(S/Path(target).with_suffix('.c')),source_sha256=digest(S/Path(target).with_suffix('.c')),baseline_object_sha256=digest(W/target),baseline_bytes=(W/target).stat().st_size))
    save(P/'tasks.json',tasks)
    assert digest(W/'.config')==digest(P/'config.common')
    save(P/'environment.json',{k:env[k] for k in ('LC_ALL','TZ','SOURCE_DATE_EPOCH','KBUILD_BUILD_TIMESTAMP','KBUILD_BUILD_USER','KBUILD_BUILD_HOST','KBUILD_BUILD_VERSION','CCACHE_DISABLE','CHIMERA_USER_CONFIG')})
    value=dict(passed=True,rc=0,phase='setup',tasks=len(tasks),config_sha256=digest(P/'config.common'),source_head=head,kernel_patch_sha256=digest(E/'kernel-source.patch'),launcher_sha256=digest(P/'bin/native-launch'),free_bytes=shutil.disk_usage(P).free,seconds=time.monotonic()-START,next_stage='four-group_correctness_and_physical_migration_preflight_not_timed',completed_utc=datetime.datetime.now(datetime.timezone.utc).isoformat())
    return value

if __name__=='__main__':
    kernel=None
    try:
        # Metadata lives in this performance namespace, never the old acceptance.
        E.parent.mkdir(exist_ok=True)
        health=StorageHealth(P/'evidence')
        health.check(force=True)
        kernel=KernelLog(P/'evidence',allow_known_ufs=True);kernel.start()
        result=main()
        result['kernel']=kernel.finish();kernel=None
        assert not result['kernel']['errors'] and not result['kernel']['alerts']
        save(P/'results/setup-1.json',result);state('phase_complete','setup_complete',rc=0,evidence=str(E))
    except BaseException as error:
        failure=dict(passed=False,rc=1,error=repr(error))
        if kernel:
            try:failure['kernel']=kernel.finish()
            except BaseException as final_error:failure['kernel_finish_error']=repr(final_error)
        save(P/'results/setup-1.json',failure);state('failed','setup_failed',rc=1,error=repr(error));raise
