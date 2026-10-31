# SPDX-License-Identifier: Apache-2.0
"""Shared evidence and bounded execution for new K3 evaluation runs."""
from pathlib import Path, PurePosixPath, PureWindowsPath
import argparse
import datetime
import gzip
import hashlib
import importlib.util
import json
import math
import os
import platform
import re
import shutil
import signal
import statistics
import subprocess
import sys
import threading
import time
import uuid

ROOT = Path(__file__).resolve().parents[2]
LEDGERS = ('policy_a100_assigned_regular', 'policy_a100_assigned_ai',
           'policy_x100_assigned_regular', 'policy_x100_assigned_ai',
           'prefer_assigned_regular', 'prefer_assigned_ai', 'prefer_pending_to_regular',
           'prefer_pending_to_ai', 'prefer_a100_cpu_reservations')
MOVES = ('prefer_a100_x100_to_a100_migrations', 'prefer_a100_a100_to_x100_migrations')
TIMEOUT = 'prefer_a100_fail_timeout'
STARTUP_NAMES = ('cc1-version', 'tiny-c', 'lib-bsearch', 'kernel-fork', 'mm-mmap')
MODEL_SHA = '6d58c8fbdaa822b004d7ba473f9b9ad4d1ef7c2dd2c4cf9f9856451aa44bf0ca'
CORPUS_SHA = 'b62ca0b765cc22e0f1ab25b0a53ae2b04c5a462650c49bbb9b18c315c1c18033'
FORBIDDEN_ENV = ('LD_PRELOAD', 'CHIMERA_BOOTSTRAP', 'CHIMERA_REGISTRY',
                 'CHIMERA_WORKSPACE', 'CHIMERA_RESOURCES', 'CHIMERA_AUTOMIGRATE',
                 'CHIMERA_LAUNCH_PID', 'CHIMERA_VERIFY_TABLES_ONLY', 'CHIMERA_BOOTSTRAP_TRACE')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(4 * 1024**2), b''):
            digest.update(block)
    return digest.hexdigest()


def save(path, value):
    path = Path(path)
    temporary = path.with_name(path.name + '.new')
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    temporary.replace(path)


def gzip_identity(path):
    digest=hashlib.sha256()
    count=0
    with gzip.open(path,'rb') as stream:
        for block in iter(lambda:stream.read(1024**2),b''):
            digest.update(block)
            count+=len(block)
    return dict(bytes=count,sha256=digest.hexdigest())


def backend(name, relative):
    path = ROOT / relative
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def validate_config(config, kind):
    require(config.get('protocol') == kind + '-retest-v1', 'Wrong or missing protocol version')
    require(re.fullmatch(r'[0-9a-f]{40}', config.get('source_commit', '')), 'Pin source_commit')
    require(bool(config.get('source_tree')) and bool(config.get('kernel')), 'Pin source_tree and kernel')
    require(config.get('cpus') == list(range(8)), 'Native and startup placement must be CPU0-7')
    required = {'bootstrap', 'registry', 'profile'} | ({'gcc', 'cc1'} if kind == 'startup' else {'elf', 'model', 'corpus'})
    assets = config.get('assets', {})
    require(required <= assets.keys(), 'Missing required input assets: ' + repr(sorted(required-assets.keys())))
    for name, row in assets.items():
        require(bool(row.get('path')) and re.fullmatch(r'[0-9a-f]{64}', row.get('sha256', ''))
                and row['sha256'] != '0'*64, 'Fill asset path and SHA256: ' + name)
        require(PurePosixPath(row['path']).is_absolute() or PureWindowsPath(row['path']).is_absolute(), 'Use absolute asset paths')
    bootstrap_path=re.sub(r'^[A-Za-z]:','',assets['bootstrap']['path'])
    require(not re.search(r'[: \t\n]',bootstrap_path), 'Bootstrap path contains preload separators')
    require(bool(config.get('workspaces')), 'List the prepared Workspace directories')
    for row in config['workspaces']:
        require(type(row.get('receipt_rows')) is int and row['receipt_rows'] > 0, 'Pin Workspace receipt counts')
        require(set(row.get('sha256', {})) == {'workspace.json', 'artifacts/verified-files.tsv',
                'artifacts/verified-variants.tsv', 'artifacts/verified-tables.tsv'}, 'Pin all Workspace receipt files')
        require(all(re.fullmatch(r'[0-9a-f]{64}', value) and value != '0'*64 for value in row['sha256'].values()), 'Fill Workspace SHA256 values')
    require(not set(config.get('environment', {})) & set(FORBIDDEN_ENV), 'Environment overrides migration controls')
    if kind == 'startup':
        rows = config.get('workloads', [])
        require(sorted(row['name'] for row in rows) == sorted(STARTUP_NAMES), 'Provide the five startup workloads exactly once')
        for row in rows:
            require(bool(row.get('argv')) and all(isinstance(arg, str) for arg in row['argv']), 'argv must be a nonempty string array')
            require(not any('REPLACE_' in arg for arg in row['argv']), 'Replace example compiler arguments')
            require(type(row.get('timeout_seconds')) is int and 0 < row['timeout_seconds'] <= 600, 'Bound each startup command to 1..600 seconds')
            require(row.get('initialized_assets') and set(row['initialized_assets']) <= assets.keys(), 'Pin initialized executables for each workload')
            require(row['argv'][0] in (assets['gcc']['path'],assets['cc1']['path']), 'Invoke the pinned compiler directly')
            require(row.get('stdin_asset') is None or row['stdin_asset'] in assets, 'Pin stdin files as assets')
            require(bool(row.get('cwd')), 'Pin the compiler working directory')
            require(not any(arg in ('-MD','-MMD','-MF','-MT','-MQ') or arg.startswith(('-Wp,-MD,','-Wp,-MMD,','-save-temps'))
                            for arg in row['argv']), 'Remove dependency-file and temporary-file writes from startup commands')
            if row['name']!='cc1-version':
                require(sum('{output}' in arg for arg in row['argv'])==1, 'Each compile needs exactly one owned output placeholder')
        require(config.get('repeats') == 3, 'The startup protocol uses three alternating pairs')
        require(len(config.get('inventories',[])) >= 2 and all(name in assets for name in config['inventories']), 'Pin source and prepared-header inventories')
    else:
        require(assets['model']['sha256']==MODEL_SHA and assets['corpus']['sha256']==CORPUS_SHA,
                'This protocol fixes the TinyLlama model and corpus from report 4.1')
        require(config.get('threads') == [2,4,8,12,16,24,32], 'Keep the recorded seven thread counts')
        require(config.get('repeat_16') == 10 and config.get('minimum_mixed_seconds') == 7200, 'Require ten repeats and 7200 active mixed seconds')
        require(config.get('absolute_ppl_tolerance') == 0.01, 'Declare absolute PPL tolerance 0.01 before execution')
    return config


def input_identities(config, kind):
    require(platform.system() == 'Linux' and platform.machine().lower() in ('riscv64', 'riscv'), 'Hardware runs require Linux RISC-V K3')
    require(platform.release() == config['kernel'], 'Kernel release differs from configuration')
    tree = Path(config['source_tree'])
    head = subprocess.check_output(['git', '-C', str(tree), 'rev-parse', 'HEAD'], text=True).strip()
    require(head == config['source_commit'], 'Source commit differs')
    require(not subprocess.check_output(['git', '-C', str(tree), 'status', '--porcelain'], text=True).strip(), 'Measured source tree must be clean')
    identities = {}
    for name, row in config['assets'].items():
        path = Path(row['path']).resolve(strict=True)
        require(path.is_file() and sha(path) == row['sha256'], 'Input SHA mismatch: ' + name)
        identities[name] = dict(path=str(path), sha256=row['sha256'], bytes=path.stat().st_size)
    workspaces = []
    inventories = {}
    for name in config.get('inventories',[]):
        inventory=json.loads(Path(identities[name]['path']).read_text())
        require(inventory['files'], 'Empty input inventory')
        for row in inventory['files']:
            path=Path(inventory['root'])/row['path']
            require(not Path(row['path']).is_absolute() and '..' not in Path(row['path']).parts, 'Inventory path escapes its root')
            require(sha(path)==row['sha256'] and (os.readlink(path) if path.is_symlink() else None)==row['symlink'], 'Source/header inventory changed: '+str(path))
        inventories[name]=dict(sha256=identities[name]['sha256'],files=len(inventory['files']))
    for row in config['workspaces']:
        directory = Path(row['path']).resolve(strict=True)
        for relative, expected in row['sha256'].items():
            require(sha(directory/relative) == expected, 'Workspace receipt changed: ' + relative)
        receipts = (directory/'artifacts/verified-files.tsv').read_text().splitlines()
        require(len(receipts) == row['receipt_rows'], 'Workspace receipt count differs')
        for line in receipts:
            path, expected, *fields = line.split('\t')
            st = Path(path).stat()
            actual = [st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns//10**9, st.st_mtime_ns%10**9,
                      st.st_ctime_ns//10**9, st.st_ctime_ns%10**9]
            require(list(map(int, fields)) == actual and sha(path) == expected, 'Workspace input identity changed: ' + path)
        workspaces.append(dict(path=str(directory), receipt_rows=len(receipts), sha256=row['sha256']))
    lines = Path(identities['registry']['path']).read_text().splitlines()
    require(lines and lines[0] == 'chimera-registry-v1', 'Invalid registry header')
    entries = [line.split('\t') for line in lines[1:]]
    for name in (('gcc','cc1') if kind == 'startup' else ('elf',)):
        asset = identities[name]
        matches = [row for row in entries if len(row)==5 and row[0]==asset['path']]
        require(len(matches)==1, 'Registry must contain exactly one row for ' + name)
        row = matches[0]
        require(row[1]==asset['sha256'] and row[2] in [w['path'] for w in workspaces]
                and sha(row[3])==row[4], 'Registry binding differs for ' + name)
    return dict(source_commit=head, kernel=platform.release(), boot_id=Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
                assets=identities, workspaces=workspaces, inventories=inventories)


def environment(config, bootstrap=False, trace=False):
    env = dict(os.environ)
    for key in FORBIDDEN_ENV:
        env.pop(key, None)
    env.update(config.get('environment', {}))
    env['LC_ALL'] = 'C'
    # Same TLS reservation for native and initialized runs; no stdout PID notice.
    pieces=[]
    reserve=65536
    for item in env.get('GLIBC_TUNABLES','').split(':'):
        if item.startswith('glibc.rtld.optional_static_tls='):
            reserve=max(reserve,int(item.split('=',1)[1],0))
        elif item:
            pieces.append(item)
    env['GLIBC_TUNABLES'] = ':'.join([*pieces, 'glibc.rtld.optional_static_tls='+str(reserve)])
    if bootstrap:
        env.update(LD_PRELOAD=config['assets']['bootstrap']['path'], CHIMERA_BOOTSTRAP=config['assets']['bootstrap']['path'],
                   CHIMERA_REGISTRY=config['assets']['registry']['path'])
        if trace:
            env['CHIMERA_BOOTSTRAP_TRACE'] = '1'
    return env


def counters():
    result = {}
    for line in Path('/proc/prefer_a100_stats').read_text().splitlines():
        key, value = line.split(maxsplit=1)
        if value.isdigit():
            result[key] = int(value)
    require(set(LEDGERS+MOVES+(TIMEOUT,)) <= result.keys(), 'Missing kernel counters')
    return result


def zero_ledgers():
    deadline = time.monotonic() + 10
    while True:
        value = counters()
        if all(value[key] == 0 for key in LEDGERS):
            return value
        require(time.monotonic() < deadline, 'Outstanding migration ledgers; preserve evidence and stop')
        time.sleep(0.05)


def no_migration(before, after):
    require(all(after[key] == before[key] for key in MOVES+(TIMEOUT,)), 'Unexpected migration or migration timeout')
    require(all(after[key] == 0 for key in LEDGERS), 'Outstanding migration ledgers')


def temperatures():
    return {str(path): int(path.read_text()) for path in Path('/sys/class/thermal').glob('thermal_zone*/temp')}


def frequencies():
    result = {}
    for cpu in range(16):
        root = Path('/sys/devices/system/cpu')/f'cpu{cpu}/cpufreq'
        result[str(cpu)] = {name: (root/name).read_text().strip() for name in
                           ('scaling_governor','scaling_setspeed','scaling_cur_freq')}
    return result


def cgroup():
    return Path('/sys/fs/cgroup')/Path('/proc/self/cgroup').read_text().split('0::',1)[1].strip().lstrip('/')


def cgroup_values():
    root = cgroup()
    return {name:(root/name).read_text().strip() for name in
            ('memory.current','memory.peak','memory.swap.peak','memory.events','memory.max','memory.swap.max')}


def kill_group(process):
    if process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass


def run_command(argv, directory, env, cwd, timeout, stdin=None, sampler=None, check=None):
    """Block in waitpid without timeout polling, which quantizes short timings."""
    directory.mkdir()
    source = Path(stdin).open('rb') if stdin else subprocess.DEVNULL
    process = None
    timer = None
    started = time.monotonic()
    try:
        with (directory/'stdout.log').open('wb') as stdout, (directory/'stderr.log').open('wb') as stderr:
            started = time.monotonic()
            process = subprocess.Popen(argv, stdin=source, stdout=stdout, stderr=stderr,
                                       env=env, cwd=cwd, start_new_session=True)
            owner=getattr(check,'__self__',None)
            if owner is not None:
                owner.active=process
            expired = threading.Event()
            def abort():
                expired.set()
                kill_group(process)
            timer = threading.Timer(timeout, abort)
            timer.start()
            if sampler:
                sampler.start(process)
            rc = process.wait()
            ended = time.monotonic()
        result = dict(argv=argv, cwd=str(cwd), pid=process.pid, rc=rc, timed_out=expired.is_set(),
                      started_monotonic=started, ended_monotonic=ended, seconds=ended-started)
        save(directory/'exit.json', result)
        if sampler:
            result['samples'] = sampler.finish()
        if check:
            check()
        require(rc==0 and not expired.is_set(), 'Command failed or timed out: ' + str(directory))
        return result
    finally:
        if timer:
            timer.cancel()
        if process is not None and process.poll() is None:
            kill_group(process)
            process.wait()
        if sampler and getattr(sampler, 'thread', None) is not None:
            sampler.finish()
        if stdin:
            source.close()
        owner=getattr(check,'__self__',None)
        if owner is not None:
            owner.active=None


class Suite:
    def __init__(self, config, directory, kind):
        self.config, self.directory, self.kind = config, directory, kind
        self.policy = backend('_retest_policy', 'experiments/gcc-performance/k3-20261030/harness/perf_storage_policy_v2.py')
        self.kernel = self.policy.KernelLog(directory, True)
        self.health = self.policy.StorageHealth(directory)
        self.stop = threading.Event()
        self.error = None
        self.active = None

    def check(self):
        require(self.error is None, 'Health collector failed: '+str(self.error))
        require(not self.kernel.errors and not self.kernel.alerts, 'Kernel evidence contains an error or unknown alert')
        require(shutil.disk_usage(self.directory).free >= 6*1024**3, 'Available space below six GiB')
        require(not Path('/proc/swaps').read_text().splitlines()[1:], 'These runtime tests require zero swap')

    def start(self):
        self.initial = input_identities(self.config, self.kind)
        save(self.directory/'inputs-before.json', self.initial)
        self.before = zero_ledgers()
        require(os.sched_getaffinity(0) >= set(range(16 if self.kind=='llama' else 8)), 'Required CPUs unavailable to this unit')
        os.sched_setaffinity(0, set(range(8)))
        status = Path('/proc/self/status').read_text()
        require(re.search(r'^Hmp_preference:\s+none\s*$', status, re.M), 'Runner inherited a migration preference')
        limits = cgroup_values()
        require(limits['memory.swap.max']=='0' and int(limits['memory.max'])<=12*1024**3, 'Run inside the bounded unit')
        self.platform = frequencies()
        for cpu, values in self.platform.items():
            require(values['scaling_governor']=='userspace' and int(values['scaling_setspeed'])==(2200000 if int(cpu)<8 else 1800000), 'Unexpected frozen frequency setting')
        self.kernel.start()
        def collect():
            try:
                while not self.stop.is_set():
                    self.health.check()
                    self.check()
                    self.stop.wait(0.5)
            except BaseException as error:
                self.error = repr(error)
                if self.active is not None:
                    kill_group(self.active)
        self.thread = threading.Thread(target=collect, daemon=True)
        self.thread.start()
        time.sleep(120)
        values = []
        for _ in range(5):
            values.append(temperatures())
            time.sleep(2)
        require(values[0] and all(set(row)==set(values[0]) for row in values), 'No stable thermal sensor set')
        self.baseline = {key:statistics.median(row[key] for row in values) for key in values[0]}
        save(self.directory/'temperature-baseline.json', dict(idle_seconds=130, samples=values, baseline=self.baseline))
        self.check()

    def cool(self):
        started = time.monotonic()
        while True:
            self.check()
            current = temperatures()
            require(set(current)==set(self.baseline), 'Thermal sensor set changed')
            if all(current[key] <= value+3000 for key,value in self.baseline.items()):
                break
            require(time.monotonic()-started < 1800, 'Could not reach common start temperature')
            self.stop.wait(1)
        current_frequency = frequencies()
        require(all(current_frequency[cpu][key]==values[key] for cpu,values in self.platform.items()
                    for key in ('scaling_governor','scaling_setspeed')), 'Frequency policy changed')
        self.health.check(force=True)
        return dict(wait_seconds=time.monotonic()-started, temperature=current, frequency=current_frequency)

    def finish(self):
        if hasattr(self, 'thread'):
            self.stop.set()
            self.thread.join(timeout=10)
        kernel = self.kernel.finish() if hasattr(self.kernel, 'thread') else None
        require(kernel is not None, 'Kernel collection did not start')
        raw=gzip_identity(self.directory/'kernel-continuous.kmsg.gz')
        require(raw['bytes']==kernel['uncompressed_bytes'] and raw['sha256']==kernel['uncompressed_sha256'],
                'Raw kernel evidence differs from the collector digest')
        self.check()
        self.health.check(force=True)
        save(self.directory/'health-summary.json', self.health.summary())
        current=frequencies()
        require(all(current[cpu][key]==values[key] for cpu,values in self.platform.items()
                    for key in ('scaling_governor','scaling_setspeed')), 'Frequency policy changed before completion')
        require(input_identities(self.config,self.kind)==self.initial, 'Inputs or boot changed during test')
        after = zero_ledgers()
        require(after[TIMEOUT]==self.before[TIMEOUT], 'Migration timeout counter increased')
        return dict(kernel=kernel, health=self.health.summary(), counters_before=self.before, counters_after=after)


def record_resources(directory):
    value = {key:os.environ.get(key) for key in ('SERVICE_RESULT','EXIT_CODE','EXIT_STATUS')}
    value.update(cgroup_values())
    value['trace_cleanup_passed']=cleanup_trace(Path(directory))
    save(Path(directory)/'unit.resources.json',value)


def check_output_location(config,output):
    protected=[Path(config['source_tree']).resolve(),*[Path(row['path']).resolve() for row in config['workspaces']]]
    protected.extend(Path(row['cwd']).resolve() for row in config.get('workloads',[]))
    for name in config.get('inventories',[]):
        row=config['assets'][name]
        require(sha(row['path'])==row['sha256'], 'Input inventory identity differs before launch')
        protected.append(Path(json.loads(Path(row['path']).read_text())['root']).resolve())
    require(not any(output.is_relative_to(root) for root in protected), 'Place results outside measured source, seed and Workspace trees')


def trace_name(unit):
    require(re.fullmatch(r'chimera-retest-llama-[0-9a-f]{10}',unit), 'Invalid owned trace unit')
    return 'chimera_gcc_model_'+unit.rsplit('-',1)[1]


def cleanup_trace(directory):
    """ExecStopPost also runs after SIGKILL/OOM; touch only this unit's group."""
    if not (directory/'trace-owner.json').exists():
        return True
    try:
        owner=json.loads((directory/'owner.json').read_text())
        record=json.loads((directory/'trace-owner.json').read_text())
        name=trace_name(owner['unit'])
        require(record==dict(unit=owner['unit'],name=name), 'Trace ownership differs')
        capture=backend('_retest_trace_cleanup','experiments/gcc-validation/k3-20261029/harness/migration_trace.py').TraceCapture(name)
        definitions=(capture.root/'kprobe_events').read_text()
        expected=(name+'_ack_enter',name+'_ack_return')
        capture.registered=[event for event in expected if name+'/'+event in definitions]
        capture.close()
        remaining=(capture.root/'kprobe_events').read_text()
        require(not capture.instance.exists() and name+'/' not in remaining, 'Owned trace cleanup incomplete')
        save(directory/'trace-cleanup.json',dict(passed=True,name=name))
        return True
    except BaseException as error:
        save(directory/'trace-cleanup.json',dict(passed=False,error=repr(error)))
        return False


def completion_passed(rc, result, resources):
    try:
        events=dict(line.split() for line in resources.get('memory.events','').splitlines())
    except ValueError:
        return False
    return (rc==0 and result.get('passed') is True
            and [resources.get(key) for key in ('SERVICE_RESULT','EXIT_CODE','EXIT_STATUS')]==['success','exited','0']
            and resources.get('memory.swap.peak')=='0'
            and all(events.get(key)=='0' for key in ('oom','oom_kill','oom_group_kill'))
            and resources.get('trace_cleanup_passed',True) is True)


def entry(kind, plan, execute):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config',type=Path,required=True)
    parser.add_argument('--output',type=Path)
    action=parser.add_mutually_exclusive_group(required=True)
    action.add_argument('--plan',action='store_true')
    action.add_argument('--run',action='store_true')
    action.add_argument('--inside-unit',action='store_true',help=argparse.SUPPRESS)
    args=parser.parse_args()
    config=validate_config(json.loads(args.config.read_text(encoding='utf-8')),kind)
    if args.plan:
        print(json.dumps(plan(config),ensure_ascii=False,indent=2))
        return 0
    require(args.output is not None, '--output must name a new experiment directory')
    output=args.output.resolve()
    if args.run:
        require(platform.system()=='Linux', 'Hardware execution requires Linux systemd')
        check_output_location(config,output)
        output.mkdir(parents=True,exist_ok=False)
        unit='chimera-retest-'+kind+'-'+uuid.uuid4().hex[:10]
        save(output/'owner.json',dict(unit=unit,protocol=config['protocol']))
        save(output/'run-config.json',config)
        code=list(Path(__file__).parent.glob('*.py'))+[
             ROOT/'experiments/gcc-validation/k3-20261029/harness/migration_trace.py',
             ROOT/'experiments/gcc-performance/k3-20261030/harness/perf_storage_policy_v2.py']
        save(output/'harness-sha256.json',{str(path):sha(path) for path in code})
        import shlex
        command=['systemd-run','--wait','--pipe','--service-type=exec','--unit='+unit,
                 '--property=MemoryHigh=10G','--property=MemoryMax=12G','--property=MemorySwapMax=0',
                 '--property=RuntimeMaxSec='+('45min' if kind=='startup' else '4h'),
                 '--property=KillMode=control-group','--property=OOMPolicy=stop',
                 '--property=ExecStopPost='+shlex.join([sys.executable,str(Path(__file__).resolve()),'--record-resources',str(output)]),
                 sys.executable,str(Path(sys.argv[0]).resolve()),'--config',str(output/'run-config.json'),
                 '--output',str(output),'--inside-unit']
        save(output/'unit-launch.json',dict(argv=command))
        with (output/'unit.log').open('wb') as stream:
            rc=subprocess.run(command,stdout=stream,stderr=subprocess.STDOUT).returncode
        resources=json.loads((output/'unit.resources.json').read_text()) if (output/'unit.resources.json').exists() else {}
        result=json.loads((output/'result.json').read_text()) if (output/'result.json').exists() else {}
        passed=completion_passed(rc,result,resources)
        manifest={str(path.relative_to(output)):dict(bytes=path.stat().st_size,sha256=sha(path))
                  for path in output.rglob('*') if path.is_file()}
        save(output/'evidence-sha256.json',manifest)
        save(output/'completion.json',dict(passed=passed,runner_rc=rc,resources=resources,
             evidence_manifest_sha256=sha(output/'evidence-sha256.json'),
             completed_utc=datetime.datetime.now(datetime.timezone.utc).isoformat()))
        return 0 if passed else 1
    owner=json.loads((output/'owner.json').read_text())
    require(owner['unit']+'.service' in str(cgroup()), 'Internal worker must run in its owned unit')
    import fcntl
    with (output/'run.lock').open('w') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        def interrupted(number,frame):
            raise InterruptedError('Worker interrupted by signal '+str(number))
        signal.signal(signal.SIGTERM,interrupted)
        signal.signal(signal.SIGINT,interrupted)
        suite=Suite(config,output,kind)
        result=dict(passed=False,protocol=config['protocol'])
        try:
            frozen=json.loads((output/'harness-sha256.json').read_text())
            require(all(sha(path)==expected for path,expected in frozen.items()), 'Harness changed after launch')
            suite.start()
            result.update(execute(config,output,suite))
            require(all(sha(path)==expected for path,expected in frozen.items()), 'Harness changed during execution')
            result['passed']=True
        except BaseException as error:
            result.update(passed=False,error=repr(error))
        finally:
            try:
                result['evidence']=suite.finish()
            except BaseException as error:
                result.update(passed=False,evidence_error=repr(error))
            save(output/'result.json',result)
    return 0 if result['passed'] else 1


if __name__=='__main__':
    if len(sys.argv)==3 and sys.argv[1]=='--record-resources':
        record_resources(sys.argv[2])
    elif len(sys.argv)==4 and sys.argv[1]=='--inventory':
        root=Path(sys.argv[2]).resolve(strict=True)
        target=Path(sys.argv[3]).resolve()
        require(not target.is_relative_to(root), 'Place inventory outside the measured input tree')
        require(not target.exists(), 'Inventory output already exists')
        rows=[dict(path=path.relative_to(root).as_posix(),sha256=sha(path),symlink=os.readlink(path) if path.is_symlink() else None)
              for path in sorted(root.rglob('*')) if path.is_file() and '.git' not in path.relative_to(root).parts]
        require(bool(rows), 'No input files found')
        save(target,dict(root=str(root),files=rows))
    else:
        raise SystemExit('Use --inventory ROOT NEW_JSON or --record-resources OUTPUT')
