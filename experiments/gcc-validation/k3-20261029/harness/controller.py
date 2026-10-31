#!/usr/bin/env python3
import argparse,fcntl,json,os
from pathlib import Path
import shutil,subprocess,time
from resource_policy import policy, enable, disable
from phase_outcome import classify

R=Path('/root/chimera-gcc-validation-578ab8321')
phases=['preflight','metadata_xgcc','metadata_cc1','gate_plan','gate_configure','gate_build',
        'strict_xgcc','strict_cc1','prepare_xgcc','prepare_cc1']
p=argparse.ArgumentParser();p.add_argument('--retry-phase',choices=phases);a=p.parse_args()
lock=(R/'controller.lock').open('w');fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
os.umask(0o077)
for directory in ('logs','stage-results','tmp'):(R/directory).mkdir(exist_ok=True)

def write_state(phase,status,**extra):
    d={'phase':phase,'status':status,'pid':os.getpid(),'commit':'578ab8321c0788ab8cba1ad24324f220e1e4a149',
       'updated_utc':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),**extra}
    temp=R/'state.json.new';temp.write_text(json.dumps(d,indent=2)+'\n');temp.replace(R/'state.json')
    with (R/'events.jsonl').open('a') as f:f.write(json.dumps(d)+'\n')
    print(json.dumps(d),flush=True)

try:
    assert (R/'setup.done').exists()
    for phase in phases:
        result_path=R/'stage-results'/(phase+'.json')
        previous=json.loads(result_path.read_text()) if result_path.exists() else None
        if previous and previous['rc']==0:
            verified_rc,outcome=classify(R,phase,previous['attempt'],previous['unit'],0)
            if verified_rc:
                previous.update(controller_reported_rc=0,rc=verified_rc,exit_validation=outcome)
                result_path.write_text(json.dumps(previous,indent=2)+'\n')
            else:continue
        if previous and a.retry_phase!=phase:
            write_state(phase,'failed',error='Existing failed phase requires diagnosis before explicit retry',result=str(result_path));raise SystemExit(2)
        if shutil.disk_usage('/').free<3*1024**3:
            write_state(phase,'failed',error='Disk guard: root available below 3 GiB');raise SystemExit(28)
        attempt=(previous.get('attempt',0) if previous else 0)+1
        unit=f'chimera-gcc-{phase.replace("_","-")}-{attempt}'
        log=R/'logs'/f'{phase}-{attempt}.log'
        record_id=f'{phase}-{attempt}'
        settings=policy(phase)
        env={'PATH':f'{R}/venv/bin:{R}/bin:{R}/toolchain/llvm/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
             'PYTHONPATH':f'{R}/source/cli:{R}/source','PYTHONUNBUFFERED':'1','TMPDIR':str(R/'tmp'),
             'CHIMERA_TOOLCHAIN_BUILD':str(R/'toolchain'),
             'CHIMERA_TOOLCHAIN_SOURCE_ROOT':str(R/'source/preprocessing/offline/toolchain/llvm-21.1.0'),
             'CHIMERA_USER_CONFIG':str(R/'user.toml'),'CHIMERA_WORKSPACE_ROOT':str(R/'workspaces')}
        command=['systemd-run','--quiet','--unit',unit,'--wait','--pipe',
                 '-p','Type=exec','-p','MemoryHigh='+settings['memory_high'],
                 '-p','MemoryMax='+settings['memory_max'],'-p','MemorySwapMax='+settings['swap_max'],
                 '-p','RuntimeMaxSec='+settings['runtime_max'],'-p','OOMPolicy=stop','-p','KillMode=control-group',
                 '-p','WorkingDirectory='+str(R/'source'),
                 '-p',f'ExecStopPost=/usr/bin/python3 {R}/record_cgroup.py {record_id}']
        for key,value in env.items():command+=['--setenv',key+'='+value]
        interpreter='/usr/bin/python3' if phase=='preflight' else str(R/'venv/bin/python')
        command+=['/usr/bin/time','-v','-o',str(R/'stage-results'/(record_id+'.time.txt')),
                  interpreter,str(R/'worker.py'),phase]
        enable(record_id,settings)
        try:
            write_state(phase,'running',active_unit=unit+'.service',log=str(log),attempt=attempt,resource_policy=settings)
            started=time.monotonic()
            with log.open('w') as output:rc=subprocess.run(command,stdout=output,stderr=subprocess.STDOUT).returncode
        finally:
            if settings['swap_bytes']:disable(record_id)
        runner_rc=rc
        rc,outcome=classify(R,phase,attempt,unit+'.service',runner_rc)
        result={'phase':phase,'rc':rc,'seconds':time.monotonic()-started,'attempt':attempt,
                'unit':unit+'.service','log':str(log),'resources':str(R/'stage-results'/(record_id+'.resources.json')),
                'resource_policy':settings,'runner_rc':runner_rc,'exit_validation':outcome}
        result_path.write_text(json.dumps(result,indent=2)+'\n')
        if rc:
            write_state(phase,'failed',**{k:v for k,v in result.items() if k!='phase'});raise SystemExit(rc)
        write_state(phase,'phase_complete',**{k:v for k,v in result.items() if k!='phase'})
        subprocess.run(['systemctl','reset-failed',unit+'.service'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    write_state('prepared_ready_for_runtime','needs_continuation',
                next_steps='Verify both workspaces, publish bootstrap registry, prove real xgcc-to-cc1 initialization and bidirectional physical migration, correctness/concurrency/repeated/two-hour acceptance. Preparation alone is not overall success.')
except BaseException as error:
    if not isinstance(error,SystemExit):write_state('controller_exception','failed',error=repr(error))
    raise
