"""Resume valid source/config preparation; derive units from CURRENT Kbuild."""
from pathlib import Path
import datetime,json,os,re,shlex,shutil,subprocess,sys,time
P=Path('/root/chimera-gcc-performance-578ab8321-20261029');V=Path('/root/chimera-gcc-validation-578ab8321')
S=P/'kernel-source';W=P/'work/seed';E=P/'evidence/setup-2';UNIT='chimera-gcc-perf-setup-2.service'
sys.path.insert(0,str(V))
from runtime_acceptance_v5 import KernelLog
from kernel_event_policy import StorageHealth
from worker import sha
START=time.monotonic()
def save(path,value):Path(path).write_text(json.dumps(value,ensure_ascii=False,indent=2)+'\n')
def state(status,step,**extra):
    value=dict(phase='setup',attempt=2,status=status,step=step,active_unit=UNIT,updated_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),**extra)
    save(P/'state.json.new',value);(P/'state.json.new').replace(P/'state.json')
    with (P/'events.jsonl').open('a') as stream:stream.write(json.dumps(value)+'\n')
    print(json.dumps(value),flush=True)
def run(args,name,env):
    assert shutil.disk_usage(P).free>=6*1024**3
    print('COMMAND',shlex.join(map(str,args)),flush=True)
    with (E/(name+'.log')).open('wb') as output:
        c=subprocess.run(list(map(str,args)),env=env,stdin=subprocess.DEVNULL,stdout=output,stderr=subprocess.STDOUT)
    assert c.returncode==0,(name,c.returncode)
    health.check();assert not kernel.alerts and not kernel.errors

def main():
    failed=json.loads((P/'results/setup-1.json').read_text())
    assert failed['rc']==1 and 'Need64real compileunits' in failed['error']
    resource=json.loads((P/'results/setup-1.resources.json').read_text())
    assert [resource[k] for k in ('SERVICE_RESULT','EXIT_CODE','EXIT_STATUS')]==['exit-code','exited','1']
    assert sha(W/'.config')==sha(P/'config.common')
    first=json.loads((P/'evidence/setup-1/inputs.json').read_text())
    cfg=json.loads((P/'evidence/setup-1/config.json').read_text())
    assert sha(P/'config.common')==cfg['sha256']
    assert os.uname().release=='6.18.3-chimera-d02cd7352'
    env=dict(os.environ);env.update(cfg['environment'])
    env.update(CHIMERA_USER_CONFIG=str(V/'user.toml'),CHIMERA_PERF_MODE='x100',CCACHE_DISABLE='1')
    for key in ('LD_PRELOAD','MAKEFLAGS','MFLAGS','CHIMERA_REGISTRY','CHIMERA_WORKSPACE','CHIMERA_RESOURCES','CHIMERA_AUTOMIGRATE','CHIMERA_VERIFY_TABLES_ONLY'):env.pop(key,None)
    command=cfg['make_command']
    save(E/'diagnosis.json',dict(cause='Old in-tree kernel object-command caches have been removed; original collector foundonly11priorityfiles',fix='QuerynewpreparedKbuild dry-run for configuredCtargets; actualcompile captures freshcommands',original_failure_preserved=True,source_reextracted=False,previous_setup_inputs=first))
    state('running','current_kbuild_task_discovery')
    run(command+['-n','-j1','V=1','kernel/','mm/','fs/','lib/'],'current-kbuild-dry-run',env)
    text=(E/'current-kbuild-dry-run.log').read_text()
    discovered={category:[] for category in ('kernel','mm','fs','lib')}
    for target,source in re.findall(r'-c\s+-o\s+([^\s;\x27\x22]+\.o)\s+([^\s;\x27\x22]+\.c)',text):
        relative=Path(target)
        if relative.is_absolute() or '..' in relative.parts or relative.parts[0] not in discovered:continue
        if not (S/relative.with_suffix('.c')).is_file():continue
        values=discovered[relative.parts[0]]
        if target not in values:values.append(target)
    save(E/'discovered-targets.json',discovered)
    ordered=[]
    priorities=('lib/bsearch.o','kernel/fork.o','mm/mmap.o','kernel/sched/core.o','kernel/sched/fair.o','mm/page_alloc.o','mm/memory.o','fs/namei.o','fs/inode.o','kernel/exit.o')
    all_targets={target for values in discovered.values() for target in values}
    for target in priorities:
        if target in all_targets:ordered.append(target)
    groups={k:list(v) for k,v in discovered.items()}
    while any(groups.values()):
        for values in groups.values():
            if values:
                target=values.pop(0)
                if target not in ordered:ordered.append(target)
    selected=ordered[:64];assert len(selected)==64,('CurrentconfiguredKbuildneed64units',len(selected),{k:len(v) for k,v in discovered.items()})
    save(P/'tasks.selected.json',selected)
    state('running','native_real_compile_pilot_64',discovered={k:len(v) for k,v in discovered.items()})
    run(command+['-j8','V=1',*selected],'native-64-pilot',env)
    tasks=[]
    for target in selected:
        path=W/Path(target).parent/('.'+Path(target).name+'.cmd')
        matches=[line.split(' := ',1)[1] for line in path.read_text().splitlines() if line.startswith(('savedcmd_','cmd_')) and ' := ' in line]
        assert len(matches)==1 and str(P/'bin/cc') in matches[0],str(path)
        source=S/Path(target).with_suffix('.c')
        tasks.append(dict(target=target,command=matches[0],source=str(source),source_sha256=sha(source),baseline_object_sha256=sha(W/target),baseline_bytes=(W/target).stat().st_size))
    save(P/'tasks.json',tasks)
    save(P/'environment.json',{k:env[k] for k in ('LC_ALL','TZ','SOURCE_DATE_EPOCH','KBUILD_BUILD_TIMESTAMP','KBUILD_BUILD_USER','KBUILD_BUILD_HOST','KBUILD_BUILD_VERSION','CCACHE_DISABLE','CHIMERA_USER_CONFIG')})
    assert sha(W/'.config')==sha(P/'config.common')
    return dict(passed=True,rc=0,attempt=2,phase='setup',tasks=len(tasks),config_sha256=sha(P/'config.common'),source_head=first['kernel_head'],kernel_patch_sha256=first['kernel_patch_sha256'],launcher_sha256=sha(P/'bin/native-launch'),source_tasks_sha256=sha(P/'tasks.json'),free_bytes=shutil.disk_usage(P).free,seconds=time.monotonic()-START,previous_failure_preserved=True,next_stage='four-group_correctness_preflight_not_timed',completed_utc=datetime.datetime.now(datetime.timezone.utc).isoformat())

if __name__=='__main__':
    assert not E.exists();E.mkdir();health=StorageHealth(E);kernel=KernelLog(E,True)
    kernel.start()
    try:
        health.check(force=True);result=main();result['kernel']=kernel.finish();kernel=None
        assert not result['kernel']['errors'] and not result['kernel']['alerts']
        save(P/'results/setup-2.json',result)
        save(P/'setup-accepted.json',dict(record='setup-2',result_sha256=sha(P/'results/setup-2.json'),requires_actual_systemd_normal_exit=True))
        state('phase_complete','setup_complete',rc=0,evidence=str(E))
    except BaseException as error:
        result=dict(passed=False,rc=1,error=repr(error))
        if kernel:
            try:result['kernel']=kernel.finish()
            except BaseException as final:result['kernel_finish_error']=repr(final)
        save(P/'results/setup-2.json',result);state('failed','setup_failed',rc=1,error=repr(error));raise
