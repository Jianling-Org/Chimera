"""Actual current xgcc -> cc1 bootstrap readiness and deterministic C compilation."""
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import threading
import time

from worker import sha, source_imports


def save(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n')

R = Path('/root/chimera-gcc-validation-578ab8321')
E = R / 'provenance/runtime-smoke-1'
RESULT = R / 'stage-results/runtime-smoke-1.json'
UNIT = 'chimera-gcc-runtime-smoke-1.service'
OUT = R / 'runtime-validation'
GCC = R / 'build-gate/gcc/xgcc'
CC1 = R / 'build-gate/gcc/cc1'
REGISTRY = OUT / 'registry.tsv'
BOOTSTRAP = R / 'build/runtime/libchimera-bootstrap.so'


def state(status, **extra):
    v = dict(phase='runtime_smoke', status=status,
             updated_utc=time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
             commit='578ab8321c0788ab8cba1ad24324f220e1e4a149', **extra)
    save(R / 'state.json.new', v)
    (R / 'state.json.new').replace(R / 'state.json')
    with (R / 'events.jsonl').open('a') as f:
        f.write(json.dumps(v) + '\n')


def fixture(count=192):
    lines = ['typedef unsigned int U; extern int printf(const char *, ...);']
    for n in range(count):
        k = (0x9e3779b9 * (n + 1)) & 0xffffffff
        lines.append(f'__attribute__((noinline)) U f{n}(U x) {{ for(U i=0;i<64;i++) {{ x^=x<<13; x^=x>>17; x^=x<<5; x+={k}u+i; }} return x; }}')
    lines.append('__attribute__((noinline)) void vector_loop(U *restrict a,const U *restrict b) { for(U i=0;i<2048;i++) a[i]=b[i]*1664525u+1013904223u; }')
    lines.append('int main(void) { U h=0x12345678u; U a[2048],b[2048];')
    for n in range(count):
        lines.append(f'h=f{n}(h+{n}u);')
    lines.append('for(U i=0;i<2048;i++) b[i]=i*2654435761u; vector_loop(a,b); for(U i=0;i<2048;i++) h^=a[i]; printf("%08x\\n",h); return 0; }')
    h = 0x12345678
    for n in range(count):
        h = (h + n) & 0xffffffff
        k = (0x9e3779b9 * (n + 1)) & 0xffffffff
        for i in range(64):
            h ^= (h << 13) & 0xffffffff
            h ^= h >> 17
            h ^= (h << 5) & 0xffffffff
            h = (h + k + i) & 0xffffffff
    for i in range(2048):
        b = (i * 2654435761) & 0xffffffff
        h ^= (b * 1664525 + 1013904223) & 0xffffffff
    return ('\n'.join(lines) + '\n').encode(), f'{h:08x}\n'


def environment():
    env = dict(os.environ)
    for key in ('LD_PRELOAD', 'CHIMERA_WORKSPACE', 'CHIMERA_RESOURCES', 'CHIMERA_AUTOMIGRATE',
                'CHIMERA_REGISTRY', 'CHIMERA_VERIFY_TABLES_ONLY', 'CHIMERA_LAUNCH_PID'):
        env.pop(key, None)
    env['CHIMERA_USER_CONFIG'] = str(R / 'user.toml')
    return env


def status(pid):
    root = Path('/proc') / str(pid)
    values = dict(line.split(':', 1) for line in (root / 'status').read_text().splitlines() if ':' in line)
    values = {k: v.strip() for k, v in values.items()}
    raw_stat = (root / 'stat').read_text()
    fields = raw_stat[raw_stat.rfind(')') + 2:].split()
    return dict(pid=pid, executable=os.readlink(root / 'exe'),
                preference=values.get('Hmp_preference'), ready=values.get('Hmp_runtime_ready'),
                exec_requires_ready=values.get('Hmp_exec_requires_ready'),
                thread_type=values.get('Hmp_thread_type'), starttime=fields[19], cpu=int(fields[36]),
                SigCgt=values.get('SigCgt'), SigBlk=values.get('SigBlk'),
                VmRSS=values.get('VmRSS'), VmHWM=values.get('VmHWM'))


def stats():
    result = {}
    for line in Path('/proc/prefer_a100_stats').read_text().splitlines():
        k, v = line.split(maxsplit=1)
        if v.isdigit(): result[k] = int(v)
    return result


def compile_command(assembly, flags):
    return [str(GCC), '-B' + str(GCC.parent) + '/', '-O2', '-mabi=lp64d',
            '-frandom-seed=chimera-578ab8321', '-fno-ident', *flags,
            '-S', '-x', 'c', '-', '-o', str(assembly)]


def check_program(assembly, flags, expected, label):
    executable = assembly.with_suffix('.exe')
    command = ['/usr/bin/gcc', '-mabi=lp64d', *flags, '-no-pie', str(assembly), '-o', str(executable)]
    p = subprocess.run(command, capture_output=True, env=environment(), timeout=120)
    (E / f'{label}-link.log').write_bytes(p.stdout + p.stderr)
    assert p.returncode == 0, ('link', label, p.returncode)
    p = subprocess.run([str(executable)], capture_output=True, env=environment(), timeout=30)
    assert p.returncode == 0 and p.stdout.decode() == expected, (label, p.returncode, p.stdout, expected)
    return dict(assembly_sha256=sha(assembly), executable_sha256=sha(executable),
                stdout=p.stdout.decode(), rc=p.returncode)


def bootstrap_compile(source, assembly, flags, label):
    source_imports()
    from chimera.runtime.launcher.migration import registered_migration_adapters
    adapter = registered_migration_adapters().select(('linux', 'riscv64', 'rvv', 'linux_riscv64_rvv_v1'))
    env = environment()
    env['CHIMERA_BOOTSTRAP_TRACE'] = '1'
    command = [str(R / 'bin/chimera-user'), 'run', '--registry', str(REGISTRY),
               '--bootstrap', str(BOOTSTRAP), '--preference', 'prefer-x100',
               *compile_command(assembly, flags)]
    log_path = E / f'{label}-bootstrap.log'
    gate = threading.Event()
    feeder_errors = []
    samples = {}
    before = stats()
    started = time.monotonic()
    with log_path.open('wb') as log:
        process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=log, stderr=subprocess.STDOUT,
                                   env=env, start_new_session=True)
        def feed():
            try:
                if not gate.wait(120): raise RuntimeError('cc1 did not publish ready before source feed deadline')
                for start in range(0, len(source), 512):
                    process.stdin.write(source[start:start + 512])
                    process.stdin.flush()
                    time.sleep(0.02)
                process.stdin.close()
            except BaseException as error:
                feeder_errors.append(repr(error))
        feeder = threading.Thread(target=feed, daemon=True)
        feeder.start()
        try:
            while process.poll() is None:
                assert time.monotonic() - started < 240, 'bootstrap compilation timed out'
                pids = [process.pid]
                try:
                    pids += [int(x) for x in (Path('/proc') / str(process.pid) / 'task' / str(process.pid) / 'children').read_text().split()]
                except OSError:
                    pass
                for pid in pids:
                    try:
                        sample = status(pid)
                        if (sample['executable'] in (str(GCC), str(CC1))
                                and sample['ready'] == '1' and sample['exec_requires_ready'] == '1'
                                and sample['preference'] == 'prefer-x100'):
                            adapter.require_ready(pid, [pid], proc_root=Path('/proc'))
                            if sample['executable'] not in samples:
                                sample['maps'] = (Path('/proc') / str(pid) / 'maps').read_text()
                                samples[sample['executable']] = sample
                            if sample['executable'] == str(CC1): gate.set()
                    except (OSError, ProcessLookupError):
                        pass
                time.sleep(0.02)
            feeder.join(timeout=2)
            assert not feeder.is_alive() and not feeder_errors, feeder_errors
            assert process.returncode == 0, ('bootstrap compile', process.returncode)
            assert set(samples) == {str(GCC), str(CC1)}, ('missing native ready evidence', samples)
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGTERM)
                process.wait(timeout=10)
    text = log_path.read_text()
    for exe, workspace in ((GCC, R / 'workspaces/xgcc'), (CC1, R / 'workspaces/cc1')):
        pid = samples[str(exe)]['pid']
        assert f'initialized pid={pid} executable={exe} workspace={workspace}' in text
        assert str(workspace / 'artifacts') in samples[str(exe)]['maps']
    after = stats()
    for key in ('prefer_assigned_regular', 'prefer_assigned_ai', 'prefer_pending_to_regular',
                'prefer_pending_to_ai', 'prefer_a100_cpu_reservations'):
        assert after[key] == before[key] == 0, (key, before[key], after[key])
    assert after['prefer_a100_fail_timeout'] == before['prefer_a100_fail_timeout']
    value = dict(command=command, rc=process.returncode, seconds=time.monotonic() - started,
                 ready_samples=samples, kernel_before=before, kernel_after=after,
                 actual_migration_required=False, actual_migration_pending=True)
    save(E / f'{label}-readiness.json', value)
    return {k: v for k, v in value.items() if k != 'ready_samples'}


def main():
    os.umask(0o077)
    assert not RESULT.exists()
    registered = json.loads((R / 'stage-results/bootstrap-register-1.json').read_text())
    assert registered['rc'] == 0 and registered['passed'] and sha(REGISTRY) == registered['registry_sha256']
    resource = json.loads((R / 'stage-results/bootstrap-register-1.resources.json').read_text())
    assert [resource[k] for k in ('SERVICE_RESULT', 'EXIT_CODE', 'EXIT_STATUS')] == ['success', 'exited', '0']
    E.mkdir(exist_ok=False)
    state('running', active_unit=UNIT, log=str(R / 'logs/runtime-smoke-1.log'))
    source, expected = fixture()
    (OUT / 'compiler-fixture.c').write_bytes(source)
    save(E / 'fixture.json', dict(source_sha256=hashlib.sha256(source).hexdigest(),
                                 bytes=len(source), functions=192, expected_stdout=expected))
    results = {}
    for label, flags in [('scalar', ['-march=rv64gc']),
                         ('rvv', ['-march=rv64gcv', '-mrvv-vector-bits=scalable'])]:
        native = OUT / f'native-{label}.s'
        command = compile_command(native, flags)
        started = time.monotonic()
        completed = subprocess.run(command, input=source, capture_output=True, env=environment(), timeout=180)
        (E / f'{label}-native.log').write_bytes(completed.stdout + completed.stderr)
        assert completed.returncode == 0, ('native compile', label, completed.returncode)
        reference = check_program(native, flags, expected, label + '-native')
        reference['compile_seconds'] = time.monotonic() - started
        migrated = OUT / f'bootstrap-{label}.s'
        execution = bootstrap_compile(source, migrated, flags, label)
        actual = check_program(migrated, flags, expected, label + '-bootstrap')
        assert actual['assembly_sha256'] == reference['assembly_sha256'], ('assembly mismatch', label)
        vector_instructions = len(re.findall(r'\bvset(?:i?vli|vl)\b', native.read_text()))
        if label == 'scalar': assert vector_instructions == 0
        else: assert vector_instructions > 0
        results[label] = dict(passed=True, flags=flags, native=reference, bootstrap=actual,
                              execution=execution, generated_vset_instructions=vector_instructions)
        save(E / f'{label}-result.json', results[label])
    value = dict(rc=0, passed=True, cases=results, conditional_scope='assume-scalar-independent',
                 scope='Compiler bootstrap parent/exec-child initialization and readiness, deterministic scalar and RVV target code generation; actual physical migration/concurrency/stability remain pending',
                 completed_utc=time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()))
    save(RESULT, value)
    state('phase_complete', rc=0, evidence=str(E), next_steps='physical bidirectional compiler migration, concurrency, repeated and two-hour stability')
    print(json.dumps(value), flush=True)


if __name__ == '__main__':
    try:
        main()
    except BaseException as error:
        save(RESULT, dict(rc=1, passed=False, error=repr(error), evidence=str(E)))
        state('failed', rc=1, error=repr(error), evidence=str(E))
        raise
