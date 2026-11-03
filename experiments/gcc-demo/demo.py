#!/usr/bin/env python3
"""K3: the same 16 cc1 jobs, eight CPUs first, then automatic cross-VLEN migration.

Uses previously accepted GCC/Workspace artifacts. Never prepares or rebuilds them.
Only the newly owned systemd unit's AllowedCPUs changes; no manual HMP requests.
"""
import argparse
from collections import Counter
import datetime
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shlex
import signal
import subprocess
import sys
import threading
import time
import uuid

V = Path('/root/chimera-gcc-validation-578ab8321')
BASE = Path('/root/chimera-gcc-performance-578ab8321-20261029')
J16 = Path('/root/chimera-gcc-performance-j16-578ab8321-20261030')
GCC, CC1 = V/'build-gate/gcc/xgcc', V/'build-gate/gcc/cc1'
LAUNCHER = BASE/'bin/native-launch-image-v3'
LEDGERS = ('policy_a100_assigned_regular', 'policy_a100_assigned_ai',
           'policy_x100_assigned_regular', 'policy_x100_assigned_ai',
           'prefer_assigned_regular', 'prefer_assigned_ai',
           'prefer_pending_to_regular', 'prefer_pending_to_ai',
           'prefer_a100_cpu_reservations')
MOVES = ('prefer_a100_x100_to_a100_migrations', 'prefer_a100_a100_to_x100_migrations')
TIMEOUT = 'prefer_a100_fail_timeout'


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def sha(path):
    value = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(4*1024**2), b''):
            value.update(block)
    return value.hexdigest()


def save(path, value):
    with Path(path).open('x', encoding='utf-8') as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2)
        stream.write('\n')


def fixture(count):
    """Unsigned arithmetic; identical to the accepted runtime-smoke fixture."""
    lines = ['typedef unsigned int U; extern int printf(const char *, ...);']
    h = 0x12345678
    for n in range(count):
        k = (0x9e3779b9 * (n+1)) & 0xffffffff
        lines.append(f'__attribute__((noinline)) U f{n}(U x) {{ for(U i=0;i<64;i++) {{ x^=x<<13; x^=x>>17; x^=x<<5; x+={k}u+i; }} return x; }}')
        h = (h+n) & 0xffffffff
        for i in range(64):
            h ^= (h << 13) & 0xffffffff
            h ^= h >> 17
            h ^= (h << 5) & 0xffffffff
            h = (h+k+i) & 0xffffffff
    lines.append('__attribute__((noinline)) void vector_loop(U *restrict a,const U *restrict b) { for(U i=0;i<2048;i++) a[i]=b[i]*1664525u+1013904223u; }')
    lines.append('int main(void) { U h=0x12345678u; U a[2048],b[2048];')
    lines += [f'h=f{n}(h+{n}u);' for n in range(count)]
    lines.append('for(U i=0;i<2048;i++) b[i]=i*2654435761u; vector_loop(a,b); for(U i=0;i<2048;i++) h^=a[i]; printf("%08x\\n",h); return 0; }')
    for i in range(2048):
        h ^= (((i*2654435761) & 0xffffffff)*1664525+1013904223) & 0xffffffff
    return ('\n'.join(lines)+'\n').encode(), f'{h:08x}\n'


def stats():
    values = {k: int(v) for k, v in (line.split() for line in Path('/proc/prefer_a100_stats').read_text().splitlines()) if v.isdigit()}
    require(set(LEDGERS+MOVES+(TIMEOUT,)) <= values.keys(), 'Missing kernel counters')
    return values


def busy_guard(own_unit=None):
    text = subprocess.check_output(['systemctl', 'list-units', '--state=active,activating', '--no-legend', '--plain', 'chimera*'], text=True)
    others = [line for line in text.splitlines() if line.split()[0] != own_unit]
    require(not others, 'Another Chimera task is active; wait for it to finish:\n'+'\n'.join(others))


def preflight(own_unit=None):
    require(os.geteuid() == 0 and platform.machine() == 'riscv64', 'Run as root on the accepted K3')
    busy_guard(own_unit)
    require(platform.release() == '6.18.3-chimera-d02cd7352', 'Kernel identity differs')
    require(not Path('/proc/swaps').read_text().splitlines()[1:], 'Swap must be inactive')
    filesystem = os.statvfs('/root')
    require(filesystem.f_bavail*filesystem.f_frsize >= 6*1024**3, 'Less than 6GiB free')
    available = int(next(x.split()[1] for x in Path('/proc/meminfo').read_text().splitlines() if x.startswith('MemAvailable:')))*1024
    require(available >= 12*1024**3, 'Need at least12GiB MemAvailable before the 16-job demonstration')
    summary = json.loads((J16/'completion.json').read_bytes())
    require(summary['acceptance'] == 'passed_conditional' and summary['audit_actual_exit'] == 'success/exited/0', 'Previous GCC acceptance missing')
    require(sha(J16/'performance-summary-j16.json') == summary['summary_sha256'], 'GCC summary identity differs')
    require(summary['commit'] == '578ab8321c0788ab8cba1ad24324f220e1e4a149', 'Measured commit differs')
    require(sha(LAUNCHER) == 'dc0f6c431f333c706403663f1bb6680db9aa05e0eb7e8dab48cb19009a25a9e0', 'Native launcher changed')
    receipts = []
    for name in ('xgcc', 'cc1'):
        for line in (V/'workspaces'/name/'artifacts/verified-files.tsv').read_text().splitlines():
            path, digest, *identity = line.split('\t');p = Path(path);st = p.stat()
            actual = [st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns//10**9, st.st_mtime_ns%10**9, st.st_ctime_ns//10**9, st.st_ctime_ns%10**9]
            require(list(map(int, identity)) == actual and sha(p) == digest, 'Workspace receipt changed: '+path)
            receipts.append(path)
    require(len(receipts) == 78, 'Expected the accepted 78 GCC receipts')
    require(all(stats()[k] == 0 for k in LEDGERS), 'Outstanding migration ledgers')


def environment():
    result = dict(os.environ)
    result.update(json.loads((BASE/'environment.json').read_bytes()))
    for key in list(result):
        if key.startswith('CHIMERA_') or key in ('LD_PRELOAD', 'MAKEFLAGS', 'MFLAGS', 'CCACHE_PREFIX'):
            result.pop(key, None)
    result.update(CHIMERA_USER_CONFIG=str(V/'user.toml'), CCACHE_DISABLE='1', LC_ALL='C')
    return result


def compile_command(mode, target):
    return [str(LAUNCHER), mode, str(GCC), '-B'+str(GCC.parent)+'/', '-O2', '-mabi=lp64d',
            '-frandom-seed=chimera-gcc-live-demo-v1', '-fno-ident', '-g0', '-march=rv64gcv',
            '-mrvv-vector-bits=scalable', '-c', '-x', 'c', '-', '-o', str(target)]


def task(pid):
    root = Path('/proc')/str(pid);exe = os.readlink(root/'exe')
    raw = (root/'stat').read_text();fields = raw[raw.rfind(')')+2:].split()
    status = dict(line.split(':', 1) for line in (root/'status').read_text().splitlines() if ':' in line)
    status = {k: v.strip() for k, v in status.items()}
    require(os.readlink(root/'exe') == exe, 'Task exec raced with sampling')
    return dict(pid=pid, executable=exe, starttime=fields[19], cpu=int(fields[36]), state=fields[0],
                preference=status.get('Hmp_preference'), ready=status.get('Hmp_runtime_ready'),
                exec_ready=status.get('Hmp_exec_requires_ready'), caught=status.get('SigCgt'), blocked=status.get('SigBlk'))


def initialized(row):
    mask = (1 << 4) | (1 << 40)
    return (row['ready'] == row['exec_ready'] == '1' and row['preference'] == 'prefer-x100'
            and int(row['caught'], 16) & mask == mask and int(row['blocked'], 16) & mask == 0)


def validate_evidence(samples, cc1_ids, replay, before, after, split):
    first = [s for s in samples if s['phase'] == 'eight']
    second = [s for s in samples if s['phase'] == 'sixteen']
    require(first and second, 'Both observed phases are required')
    require(all(r['pid'] in cc1_ids for s in samples for r in s['tasks']), 'Unrelated PID in compiler evidence')
    require(all(row['cpu'] < 8 for s in first for row in s['tasks']), 'Eight-CPU phase escaped its cpuset')
    require(any({r['pid'] for r in s['tasks']} == cc1_ids for s in first), 'Did not observe the same 16 cc1 jobs in phase1')
    require({r['cpu'] for s in first for r in s['tasks']} == set(range(8)), 'Did not observe compilation on all eight initial CPUs')
    all_cpus = {row['cpu'] for s in second for row in s['tasks']}
    require(all_cpus == set(range(16)), 'Did not observe compiler work on all16 CPUs; do not claim the demonstration passed')
    require(any({r['pid'] for r in s['tasks']} == cc1_ids and {r['cpu']//8 for r in s['tasks']} == {0, 1} for s in second), 'No same16-job two-cluster observation in one sampling cycle')
    commits = replay['physical_commits']
    require(any(c['tid'] in cc1_ids and c['timestamp'] >= split for c in commits), 'No accepted physical migration of an original cc1 after the cpuset opened')
    require(replay['raw_accepted_ack_count'] == len(commits), 'ACK/physical commit mismatch')
    for key, route in zip(MOVES, ('256-to-1024', '1024-to-256')):
        require(after[key]-before[key] == replay['route_counts'][route], 'Global/raw directional counters differ')
    require(before[TIMEOUT] == after[TIMEOUT] and all(before[k] == after[k] == 0 for k in LEDGERS), 'Timeout or outstanding migration ledger')
    return dict(phase1_cpu_seen=sorted({r['cpu'] for s in first for r in s['tasks']}), phase2_cpu_seen=sorted(all_cpus),
                same_cc1_pids=sorted(cc1_ids), routes=replay['route_counts'], physical_commits=len(commits))


def check_outputs(objects, reference, programs, expected):
    digest = sha(reference)
    require(all(p.is_file() and sha(p) == digest for p in objects), 'Compiled object differs from native reference')
    require(all(rc == 0 and stdout == expected for rc, stdout in programs), 'Compiled program failed the independent integer reference')
    return digest


def resource_record(out, unit):
    group = Path('/sys/fs/cgroup')/Path('/proc/self/cgroup').read_text().split('0::', 1)[1].strip().lstrip('/')
    row = {k: os.environ.get(k) for k in ('SERVICE_RESULT', 'EXIT_CODE', 'EXIT_STATUS')}
    row.update({k: (group/k).read_text().strip() for k in ('memory.peak', 'memory.swap.peak', 'memory.events')})
    save(out/'unit.resources.json', row)
    # This runs even after RuntimeMaxSec/OOM/interrupt. Never clear another
    # unit's probes, and preserve actual resources before attempting cleanup.
    try:
        require(json.loads((out/'launch.json').read_bytes())['unit'] == unit, 'Cleanup owner differs')
        sys.path.insert(0, str(V))
        from migration_trace import TraceCapture
        name = 'chimera_gcc_demo_'+unit.split('-')[-1].split('.')[0]
        capture = TraceCapture(name)
        lines = (capture.root/'kprobe_events').read_text().splitlines()
        capture.registered = [name+suffix for suffix in ('_ack_enter', '_ack_return')
                              if any(name+'/'+name+suffix+' ' in line for line in lines)]
        capture.close()
        require(not capture.instance.exists() and name+'/' not in (capture.root/'kprobe_events').read_text(), 'Owned trace cleanup incomplete')
        save(out/'trace-cleanup.json', dict(passed=True, namespace=name))
    except BaseException as error:
        save(out/'trace-cleanup.json', dict(passed=False, error=repr(error)))
        raise


def worker(args):
    out = args.output;require(args.unit in Path('/proc/self/cgroup').read_text(), 'Worker must run in its owned systemd unit')
    preflight(args.unit)
    group = Path('/sys/fs/cgroup')/Path('/proc/self/cgroup').read_text().split('0::', 1)[1].strip().lstrip('/')
    require((group/'cpuset.cpus.effective').read_text().strip() == '0-7', 'Initial effective cpuset must be0-7')
    sys.path[:0] = [str(BASE), str(V)]
    from migration_trace import TraceCapture
    from perf_storage_policy_v2 import KernelLog, StorageHealth
    trace = TraceCapture('chimera_gcc_demo_'+args.unit.split('-')[-1].split('.')[0])
    kernel, health = KernelLog(out, True), StorageHealth(out)
    jobs=[];feeders=[];logs=[];samples=[];cc1={};selected=set();release=threading.Event();feed_errors=[];reference_process=None
    kernel.start();active_trace=False;done=False
    try:
        source, expected = fixture(args.functions);(out/'input.c').write_bytes(source)
        print('Preparing the native reference (not the 16-job phase)...', flush=True)
        reference = out/'reference.o'
        with (out/'input.c').open('rb') as input_file, (out/'reference.log').open('wb') as reference_log:
            reference_process = subprocess.Popen(compile_command('x100', reference), stdin=input_file, stdout=reference_log, stderr=subprocess.STDOUT, env=environment(), start_new_session=True)
            reference_start=time.monotonic()
            while reference_process.poll() is None:
                health.check();require(not kernel.errors and not kernel.alerts, 'Kernel evidence/health failure')
                require(time.monotonic()-reference_start < 240, 'Reference compilation timed out')
                require(os.statvfs(out).f_bavail*os.statvfs(out).f_frsize >= 6*1024**3, 'Less than6GiB free')
                time.sleep(.1)
        require(reference_process.returncode == 0, 'Native reference compilation failed')
        before=stats();require(all(before[k] == 0 for k in LEDGERS), 'Outstanding ledgers')
        trace.configure();trace.start(out/'raw-ack-cpu.trace.gz');active_trace=True
        for i in range(16):
            log=(out/f'worker-{i:02d}.log').open('wb');logs.append(log)
            process=subprocess.Popen(compile_command('auto-x100', out/f'worker-{i:02d}.o'), stdin=subprocess.PIPE, stdout=log, stderr=subprocess.STDOUT, env=environment(), start_new_session=True)
            jobs.append(process);selected.add(process.pid)
            def feed(p=process):
                try:
                    require(release.wait(120), 'Source release timed out');p.stdin.write(source);p.stdin.close()
                except BaseException as error:feed_errors.append(repr(error))
            t=threading.Thread(target=feed, daemon=True);t.start();feeders.append(t)
        ready_deadline=time.monotonic()+90
        while len(cc1) != 16:
            require(time.monotonic() < ready_deadline, '16 initialized cc1 jobs did not appear')
            for p in jobs:
                require(p.poll() is None, 'Compiler exited before source release')
                for pid in (Path('/proc')/str(p.pid)/'task'/str(p.pid)/'children').read_text().split():
                    try:row=task(int(pid))
                    except (OSError, RuntimeError):continue
                    if row['executable'] == str(CC1) and initialized(row):
                        require(row['cpu'] < 8, 'Initial compiler escaped X100')
                        maps=(Path('/proc')/pid/'maps').read_text()
                        require(str(V/'workspaces/cc1/artifacts/runtime/libchimera_inject.so') in maps, 'Missing cc1 runtime mapping')
                        cc1[row['pid']]=row;selected.add(row['pid'])
            health.check();require(not kernel.errors and not kernel.alerts, 'Kernel evidence/health failure');time.sleep(.01)
        save(out/'initial-cc1.json', list(cc1.values()));(out/'cc1-pids.csv').write_text(','.join(map(str, sorted(cc1)))+'\n')
        print(f'PHASE1: same16 cc1 processes, AllowedCPUs=0-7, {args.hold_seconds}s. PID list: {out}/cc1-pids.csv', flush=True)
        start=time.monotonic();split=None;release.set()
        while any(p.poll() is None for p in jobs):
            stamp=time.monotonic();require(stamp-start < 600, 'Demo compilation timed out')
            health.check();require(not kernel.errors and not kernel.alerts, 'Kernel evidence/health failure')
            require(not feed_errors, repr(feed_errors));require(trace.failure is None, 'Trace collector failed')
            require(os.statvfs(out).f_bavail*os.statvfs(out).f_frsize >= 6*1024**3, 'Less than6GiB free')
            if split is None and stamp-start >= args.hold_seconds:
                require(all(p.poll() is None for p in jobs), 'Compilation was too short for the live transition; increase --functions')
                # Only expand this newly owned cpuset. Automatic HMP+Runtime
                # decide actual cross-VLEN transfers; no manual set_ai_thread.
                split=time.monotonic()
                subprocess.run(['systemctl', 'set-property', '--runtime', args.unit, 'AllowedCPUs=0-15'], check=True, timeout=10)
                require((group/'cpuset.cpus.effective').read_text().strip() == '0-15', 'Cpuset expansion did not take effect')
                save(out/'cpuset-transition.json', dict(started_monotonic=split, confirmed_monotonic=time.monotonic(), old='0-7', new='0-15', unit=args.unit))
                print('PHASE2: same running compiler jobs; CPUs0-15 available, automatic migration enabled.', flush=True)
            rows=[]
            for pid, initial in cc1.items():
                try:row=task(pid)
                except (OSError, RuntimeError):continue
                require(row['starttime'] == initial['starttime'] and row['executable'] == str(CC1), 'Compiler PID identity changed')
                if row['state'] not in ('Z', 'X', 'x'):rows.append(row)
            sample=dict(monotonic=time.monotonic(), phase='eight' if split is None else 'sixteen', tasks=rows)
            samples.append(sample)
            with (out/'samples.jsonl').open('a') as f:f.write(json.dumps(sample)+'\n')
            time.sleep(.1)
        require(split is not None, 'Jobs completed before the demonstration transition')
        for t in feeders:t.join(timeout=5);require(not t.is_alive(), 'Source feeder still active')
        require(not feed_errors and all(p.returncode == 0 for p in jobs), 'Compilation failed')
        for log in logs:log.close()
        after=stats();capture=trace.finish(selected);active_trace=False;save(out/'trace.json', capture)
        observed=validate_evidence(samples, set(cc1), capture['replay'], before, after, split)
        executable=out/'compiled-program';command=['/usr/bin/gcc', '-march=rv64gcv', '-mabi=lp64d', '-no-pie', str(out/'worker-00.o'), '-o', str(executable)]
        linked=subprocess.run(command, capture_output=True, env=environment(), timeout=60)
        (out/'link.log').write_bytes(linked.stdout+linked.stderr);require(linked.returncode == 0, 'Program link failed')
        programs=[]
        for mode in ('x100', 'a100'):
            checked=subprocess.run([str(LAUNCHER), mode, str(executable)], capture_output=True, env=environment(), timeout=30)
            programs.append((checked.returncode, checked.stdout.decode()));save(out/(mode+'-program.json'), dict(rc=checked.returncode, stdout=checked.stdout.decode(), expected=expected))
        digest=check_outputs([out/f'worker-{i:02d}.o' for i in range(16)], reference, programs, expected)
        save(out/'result.json', dict(passed=True, scope='live demonstration, not a throughput measurement or a replacement for full acceptance', **observed, object_sha256=digest, expected_stdout=expected, counters_before=before, counters_after=after))
        done=True
    finally:
        release.set()
        for p in jobs+([reference_process] if reference_process is not None else []):
            if p.poll() is None:
                try:os.killpg(p.pid, signal.SIGKILL)
                except ProcessLookupError:pass
                p.wait(timeout=10)
        for log in logs:
            if not log.closed:log.close()
        if active_trace:
            try:save(out/'failed-trace.json', trace.finish(selected))
            except BaseException as error:save(out/'failed-trace-error.json', dict(error=repr(error)))
        trace.close();health.check(force=True);kernel_result=kernel.finish();save(out/'health-summary.json', health.summary())
        require(not kernel_result['errors'] and not kernel_result['alerts'], 'Kernel evidence failed')
        require(done, 'Demo did not complete')
    print('PASS: same compiler PIDs migrated; all16 object SHAs equal native reference; program correct on X100 and A100.', flush=True)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true', help='Read-only prerequisite check; refuses while any other Chimera unit is active')
    parser.add_argument('--functions', type=int, default=6144, help='Fixture size, default6144; increase if compilation ends before phase2')
    parser.add_argument('--hold-seconds', type=float, default=15, help='Initial8-CPU observation window, default15')
    parser.add_argument('--output', type=Path)
    parser.add_argument('--worker', action='store_true', help=argparse.SUPPRESS)
    parser.add_argument('--resources', action='store_true', help=argparse.SUPPRESS)
    parser.add_argument('--unit', help=argparse.SUPPRESS)
    args=parser.parse_args()
    require(192 <= args.functions <= 16384 and 3 <= args.hold_seconds <= 60, 'functions192..16384; hold-seconds3..60')
    if args.resources:resource_record(args.output, args.unit);return
    if args.worker:
        require(re.fullmatch(r'chimera-gcc-demo-[0-9a-f]{12}\.service', args.unit or ''), 'Invalid owned unit')
        try:worker(args)
        except BaseException as error:
            save(args.output/'failure.json', dict(error=repr(error)));raise
        return
    preflight()
    if args.check:print('READY: accepted GCC/78 receipts match; no other active Chimera tasks; no workload started.');return
    tag=uuid.uuid4().hex[:12];unit='chimera-gcc-demo-'+tag+'.service'
    out=args.output or Path('/root/chimera-gcc-live-demo')/(datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'-'+tag)
    out=out.resolve()
    require(not any(out == p or p in out.parents for p in (V, BASE, J16, Path('/root/chimera-runtime-retest-20261031'))), 'Output must not be inside protected experiment roots')
    out.mkdir(parents=True, exist_ok=False);print('Evidence directory: '+str(out), flush=True)
    script=str(Path(__file__).resolve());python=sys.executable
    command=['systemd-run', '--wait', '--pipe', '--service-type=exec', '--unit='+unit, '--property=AllowedCPUs=0-7', '--property=MemoryMax=12G', '--property=MemoryHigh=10G', '--property=MemorySwapMax=0', '--property=RuntimeMaxSec=15min', '--property=LimitCORE=0', '--property=OOMPolicy=stop', '--property=KillMode=control-group', '--property=ExecStopPost='+shlex.join([python, '-B', script, '--resources', '--unit', unit, '--output', str(out)]), python, '-B', script, '--worker', '--unit', unit, '--output', str(out), '--functions', str(args.functions), '--hold-seconds', str(args.hold_seconds)]
    save(out/'launch.json', dict(argv=command, script_sha256=sha(script), unit=unit))
    try:rc=subprocess.run(command).returncode
    except KeyboardInterrupt:
        subprocess.run(['systemctl', 'stop', unit], timeout=30)
        raise RuntimeError('Interrupted; stopped only '+unit+'. Evidence retained: '+str(out))
    row=json.loads((out/'unit.resources.json').read_bytes())
    require(rc == 0 and [row[k] for k in ('SERVICE_RESULT','EXIT_CODE','EXIT_STATUS')] == ['success','exited','0'], 'Demo unit failed; preserve '+str(out))
    require(row['memory.swap.peak'] == '0' and all(int(x.split()[1]) == 0 for x in row['memory.events'].splitlines() if x.split()[0] in ('oom','oom_kill','oom_group_kill')), 'Swap/OOM occurred')
    require(json.loads((out/'result.json').read_bytes())['passed'], 'Missing passing evidence')
    require(json.loads((out/'trace-cleanup.json').read_bytes())['passed'], 'Private trace cleanup failed')
    print('Demo actual exit0, zero swap/OOM. Evidence: '+str(out))


if __name__ == '__main__':
    try:main()
    except (RuntimeError, OSError, subprocess.SubprocessError) as error:
        print('FAIL: '+str(error), file=sys.stderr);sys.exit(1)
