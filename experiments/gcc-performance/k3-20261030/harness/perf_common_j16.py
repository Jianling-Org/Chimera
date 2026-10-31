from pathlib import Path
import datetime,hashlib,json,os,shutil,subprocess,sys,time
BASE=Path('/root/chimera-gcc-performance-578ab8321-20261029')
P=Path('/root/chimera-gcc-performance-j16-578ab8321-20261030')
V=Path('/root/chimera-gcc-validation-578ab8321')
S=BASE/'kernel-source';W=BASE/'work/seed'
sys.path.insert(0,str(V))
import runtime_smoke as smoke
from migration_trace import TraceCapture
from runtime_acceptance_v5 import KernelLog
from kernel_event_policy import StorageHealth
LEDGERS=('policy_a100_assigned_regular','policy_a100_assigned_ai','policy_x100_assigned_regular','policy_x100_assigned_ai','prefer_assigned_regular','prefer_assigned_ai','prefer_pending_to_regular','prefer_pending_to_ai','prefer_a100_cpu_reservations')
MODES=('x100','auto-x100','auto-a100','static16')
def load(path):return json.loads(Path(path).read_text())
def save(path,value):Path(path).write_text(json.dumps(value,ensure_ascii=False,indent=2)+'\n')
def sha(path):
    h=hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda:stream.read(4*1024**2),b''):h.update(block)
    return h.hexdigest()
def state(phase,status,unit,**extra):
    value=dict(phase=phase,status=status,active_unit=unit,updated_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),**extra)
    save(P/'state.json.new',value);(P/'state.json.new').replace(P/'state.json')
    with (P/'events.jsonl').open('a') as output:output.write(json.dumps(value)+'\n')
    print(json.dumps(value),flush=True)
def environment(mode='x100',trace=False,static_group=None):
    env=dict(os.environ);env.update(load(P/'environment.json'))
    for key in ('LD_PRELOAD','CHIMERA_WORKSPACE','CHIMERA_RESOURCES','CHIMERA_REGISTRY','CHIMERA_BOOTSTRAP','CHIMERA_AUTOMIGRATE','CHIMERA_LAUNCH_PID','CHIMERA_VERIFY_TABLES_ONLY','CHIMERA_BOOTSTRAP_TRACE','CHIMERA_PERF_TRACE','CHIMERA_PERF_STATIC_GROUP','CCACHE_PREFIX','MAKEFLAGS','MFLAGS'):
        env.pop(key,None)
    env['CCACHE_DISABLE']='1';env['CHIMERA_PERF_MODE']=mode
    if trace:env['CHIMERA_PERF_TRACE']='1'
    if static_group:env['CHIMERA_PERF_STATIC_GROUP']=static_group
    return env
def verify_previous(name):
    directory=BASE if name in ('setup-2','preflight-1','preflight-3') else P
    result=load(directory/'results'/(name+'.json'));resource=load(directory/'results'/(name+'.resources.json'))
    assert result['passed'] and result['rc']==0,name
    assert [resource[k] for k in ('SERVICE_RESULT','EXIT_CODE','EXIT_STATUS')]==['success','exited','0'],resource
    events=dict(line.split() for line in resource['memory.events'].splitlines())
    assert events['oom_kill']=='0' and resource['memory.swap.peak']=='0'
    return result,resource
def guard():
    assert shutil.disk_usage(P).free>=6*1024**3,'Unchanged6GiBnormaldiskmargin'
    assert not Path('/proc/swaps').read_text().splitlines()[1:],'Formalperformance requireszeroSwap'
def verify_setup():
    record=load(BASE/'setup-accepted.json')
    assert sha(BASE/'results'/(record['record']+'.json'))==record['result_sha256']
    return verify_previous(record['record'])
def zero_ledgers():
    values=smoke.stats();assert all(values[k]==0 for k in LEDGERS),values
    return values
def native_command(mode,*args):return [str(P/'bin/native-launch-image-v3'),mode,str(V/'build-gate/gcc/xgcc'),'-B'+str(V/'build-gate/gcc')+'/',*map(str,args)]
def sample_status(pid):
    sample=smoke.status(pid)
    text=(Path('/proc')/str(pid)/'status').read_text()
    values=dict(line.split(':',1) for line in text.splitlines() if ':' in line)
    sample['allowed_cpus']=values.get('Cpus_allowed_list','').strip()
    return sample
def initialized(sample,preference):
    if sample.get('ready')!='1' or sample.get('exec_requires_ready')!='1' or sample.get('preference')!=preference:return False
    required=(1<<4)|(1<<40)
    try:return int(sample['SigCgt'],16)&required==required and int(sample['SigBlk'],16)&required==0
    except (KeyError,TypeError,ValueError):return False

# Identical authorized maintenance policy; its ROOT intentionally reads the original authorization.
from perf_storage_policy_v2 import KernelLog, StorageHealth, POLICY, verify_authorization
