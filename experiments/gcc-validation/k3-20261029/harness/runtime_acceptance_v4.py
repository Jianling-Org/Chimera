"""Bounded real compiler migration/concurrency and separate two-hour acceptance."""
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import select
import signal
import subprocess
import threading
import time

import runtime_smoke as smoke
from migration_trace import TraceCapture
from readiness_probe import initialization_ready
from worker import sha

R = smoke.R
LEDGERS = ('policy_a100_assigned_regular', 'policy_a100_assigned_ai',
           'policy_x100_assigned_regular', 'policy_x100_assigned_ai',
           'prefer_assigned_regular', 'prefer_assigned_ai',
           'prefer_pending_to_regular', 'prefer_pending_to_ai', 'prefer_a100_cpu_reservations')


def save(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n')


class KernelLog:
    def __init__(self, directory):
        self.directory = directory
        self.stop = threading.Event()
        self.errors = []
        self.alerts = []
        self.sequence = []
        self.raw_bytes = 0
        self.digest = hashlib.sha256()
        self.marker_prefix = 'chimera-gcc-validation:' + directory.name + ':'
        self.markers_seen = []

    def marker(self, name):
        # Informational control messages prove that a quiet kernel log reader
        # is live and bracket this measurement; they do not change runtime or
        # scheduler state. Never write a warning or clear existing kernel logs.
        payload = ('<6>' + self.marker_prefix + name + '\n').encode()
        descriptor = os.open('/dev/kmsg', os.O_WRONLY | os.O_CLOEXEC)
        try:
            assert os.write(descriptor, payload) == len(payload)
        finally:
            os.close(descriptor)

    def start(self):
        (self.directory / 'dmesg-before.txt').write_bytes(subprocess.check_output(['dmesg', '--raw']))
        self.fd = os.open('/dev/kmsg', os.O_RDONLY | os.O_NONBLOCK)
        os.lseek(self.fd, 0, os.SEEK_END)
        def collect():
            last_sequence = None
            try:
                with gzip.open(self.directory / 'kernel-continuous.kmsg.gz', 'wb', compresslevel=1) as output:
                    drained = 0
                    while True:
                        ready, _, _ = select.select([self.fd], [], [], 0.1)
                        if not ready:
                            if self.stop.is_set():
                                drained += 1
                                if drained >= 3: break
                            continue
                        try:
                            block = os.read(self.fd, 1024 * 1024)
                        except BlockingIOError:
                            continue
                        if not block: continue
                        drained = 0
                        self.raw_bytes += len(block)
                        assert self.raw_bytes < 512 * 1024**2, 'Kernel evidence budget exceeded'
                        self.digest.update(block)
                        output.write(block)
                        header, _, body = block.partition(b';')
                        priority, seq, _, _ = header.decode().split(',', 3)
                        seq = int(seq)
                        if last_sequence is not None:
                            assert seq == last_sequence + 1, 'Kernel log sequence gap'
                        if not self.sequence: self.sequence.append(seq)
                        last_sequence = seq
                        message = body.decode(errors='replace')
                        for marker in ('begin', 'end'):
                            if self.marker_prefix + marker in message:
                                self.markers_seen.append(marker)
                        if int(priority) & 7 <= 4:
                            self.alerts.append(block.decode(errors='replace'))
                    if last_sequence is not None: self.sequence.append(last_sequence)
            except BaseException as error:
                self.errors.append(repr(error))
        self.thread = threading.Thread(target=collect, daemon=True)
        self.thread.start()
        self.marker('begin')

    def finish(self):
        self.marker('end')
        self.stop.set()
        self.thread.join(timeout=10)
        os.close(self.fd)
        assert not self.thread.is_alive(), 'Kernel collector did not stop'
        (self.directory / 'dmesg-after.txt').write_bytes(subprocess.check_output(['dmesg', '--raw']))
        if self.markers_seen != ['begin', 'end']:
            self.errors.append('Kernel log control markers missing or out of order')
        value = dict(sequence_endpoints=self.sequence, errors=self.errors, alerts=self.alerts,
                     informational_control_markers=self.markers_seen,
                     uncompressed_bytes=self.raw_bytes, uncompressed_sha256=self.digest.hexdigest())
        save(self.directory / 'kernel-continuous-audit.json', value)
        return value


class Acceptance:
    def __init__(self, stage, attempt, matrix_attempt=3):
        self.stage = stage
        self.attempt = attempt
        self.matrix_attempt = matrix_attempt
        self.record_id = f'runtime-{stage}-{attempt}'
        self.unit = 'chimera-gcc-' + self.record_id + '.service'
        self.evidence = R / 'provenance' / self.record_id
        self.output = R / 'runtime-validation' / self.record_id
        self.result = R / 'stage-results' / (self.record_id + '.json')
        self.results = []
        self.references = {}
        self.trace = TraceCapture('chimera_gcc_578ab8321_' + ('m' if stage == 'matrix' else 's') + str(attempt))
        self.started = time.monotonic()

    def state(self, status, **extra):
        value = dict(phase='runtime_' + self.stage, status=status,
                     commit='578ab8321c0788ab8cba1ad24324f220e1e4a149',
                     updated_utc=time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                     active_unit=self.unit, log=str(R / 'logs' / (self.record_id + '.log')),
                     completed_cases=len(self.results), **extra)
        save(R / 'state.json.new', value)
        (R / 'state.json.new').replace(R / 'state.json')
        with (R / 'events.jsonl').open('a') as f: f.write(json.dumps(value) + '\n')

    def verify_input(self):
        assert subprocess.check_output(['git', '-C', str(R / 'source'), 'rev-parse', 'HEAD'], text=True).strip() == '578ab8321c0788ab8cba1ad24324f220e1e4a149'
        assert not subprocess.check_output(['git', '-C', str(R / 'source'), 'status', '--porcelain'], text=True).strip()
        assert sha(R / 'profile.gcc.toml') == '1905a136b12c3b4cb71508d546042767b2311780bbf9527c4d218dde6c11ef38'
        registered = json.loads((R / 'stage-results/bootstrap-register-1.json').read_text())
        assert registered['passed'] and registered['rc'] == 0
        assert sha(smoke.REGISTRY) == registered['registry_sha256']
        assert sha(smoke.BOOTSTRAP) == registered['bootstrap_sha256']
        for row in registered['records']:
            assert sha(Path(row[0])) == row[1] and sha(Path(row[3])) == row[4]
        assert json.loads((R / 'stage-results/runtime-smoke-1.json').read_text())['passed']
        resource = json.loads((R / 'stage-results/runtime-smoke-1.resources.json').read_text())
        assert [resource[k] for k in ('SERVICE_RESULT', 'EXIT_CODE', 'EXIT_STATUS')] == ['success', 'exited', '0']
        if self.stage == 'stability':
            assert json.loads((R / f'stage-results/runtime-matrix-{self.matrix_attempt}.json').read_text())['passed']
            resource = json.loads((R / f'stage-results/runtime-matrix-{self.matrix_attempt}.resources.json').read_text())
            assert [resource[k] for k in ('SERVICE_RESULT', 'EXIT_CODE', 'EXIT_STATUS')] == ['success', 'exited', '0']
        import shutil
        assert shutil.disk_usage(R).free >= 10 * 1024**3, 'Need6GiB margin plus4GiB runtime/evidence budget'
        assert all(smoke.stats()[key] == 0 for key in LEDGERS), 'Other preference load or stale accounting exists'

    def hardware(self):
        source = self.evidence / 'vlen-probe.c'
        binary = self.output / 'vlen-probe'
        source.write_text('''#define _GNU_SOURCE
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sched.h>
#include <stdlib.h>
#include <sys/syscall.h>
int main(int argc,char **argv) {
 if(argc>1 && argv[1][0]=='a') { int f=open("/proc/set_ai_thread",O_WRONLY); if(f<0)return 10;
 if(write(f,"0\\n",2)!=2)return 11; close(f); }
 /* This BSP expands unmanaged affinity to the entire HMP cluster. Mark the
    helper strict/unready, never ready, so it preserves a validated CPU mask
    while remaining ineligible for any automatic cross-VLEN migration. */
 char request[64]; int n=snprintf(request,sizeof(request),"inherit:%ld\\n",(long)getpid());
 int pref=open("/proc/prefer_x100",O_WRONLY);if(pref<0)return 13;
 if(write(pref,request,n)!=n)return 14;close(pref);
 if(argc>2) { cpu_set_t set; CPU_ZERO(&set); CPU_SET(atoi(argv[2]),&set);
 if(sched_setaffinity(0,sizeof(set),&set))return 12;
 cpu_set_t actual;CPU_ZERO(&actual);
 if(sched_getaffinity(0,sizeof(actual),&actual)||CPU_COUNT(&actual)!=1||!CPU_ISSET(atoi(argv[2]),&actual))return 15; }
 unsigned cpu=999,node=999;if(syscall(SYS_getcpu,&cpu,&node,0))return 16;
 unsigned long bytes; __asm__ volatile("csrr %0,vlenb":"=r"(bytes));
 n=snprintf(request,sizeof(request),"-%ld\\n",(long)getpid());
 pref=open("/proc/prefer_x100",O_WRONLY);if(pref<0||write(pref,request,n)!=n)return 17;close(pref);
 printf("%lu %u\\n",bytes*8,cpu); return 0;
}
''')
        subprocess.run(['/usr/bin/gcc', '-O2', '-march=rv64gcv', '-fno-tree-vectorize',
                        '-fno-tree-slp-vectorize', str(source), '-o', str(binary)], check=True)
        values = []
        for selected_cpu in range(16):
            args = ['regular' if selected_cpu < 8 else 'ai', str(selected_cpu)]
            p = subprocess.run([str(binary), *args], capture_output=True, env=smoke.environment(), timeout=30)
            assert p.returncode == 0, ('native hardware probe', p.returncode, p.stderr)
            bits, cpu = map(int, p.stdout.split())
            assert cpu == selected_cpu and bits == (256 if cpu < 8 else 1024)
            values.append(dict(bits=bits, cpu=cpu, stdout=p.stdout.decode()))
        assert all(smoke.stats()[key] == 0 for key in LEDGERS)
        save(self.evidence / 'hardware-vlen.json', dict(per_cpu=values,
             binding='Managed strict-unready helper: singleton effective mask verified; kernel getcpu; never publishes ready; preference disabled before exit',
             actual_compiler_migration_evidence=False))

    def reference(self, count, label):
        key = (count, label)
        if key in self.references: return self.references[key]
        source, expected = smoke.fixture(count)
        flags = ['-march=rv64gc'] if label == 'scalar' else ['-march=rv64gcv', '-mrvv-vector-bits=scalable']
        path = self.output / f'reference-{count}-{label}.s'
        command = smoke.compile_command(path, flags)
        p = subprocess.run(command, input=source, capture_output=True, env=smoke.environment(), timeout=180)
        (self.evidence / f'reference-{count}-{label}.log').write_bytes(p.stdout + p.stderr)
        assert p.returncode == 0, ('native reference compile', count, label, p.returncode)
        smoke.E = self.evidence
        actual = smoke.check_program(path, flags, expected, f'reference-{count}-{label}')
        record = dict(source_sha256=hashlib.sha256(source).hexdigest(), bytes=len(source), functions=count,
                      flags=flags, expected_stdout=expected, native=actual)
        save(self.evidence / f'reference-{count}-{label}.json', record)
        self.references[key] = source, flags, expected, actual
        return self.references[key]

    def case(self, number, count, category, single_label='scalar'):
        import shutil
        assert shutil.disk_usage(R).free >= 6 * 1024**3
        self.state('running', current_case=dict(number=number, workers=count, category=category))
        directory = self.evidence / f'case-{number:04d}-{count}'
        output = self.output / f'case-{number:04d}-{count}'
        directory.mkdir()
        output.mkdir()
        before = smoke.stats()
        assert all(before[key] == 0 for key in LEDGERS)
        jobs = []
        release = threading.Event()
        trace_active = False
        started = time.monotonic()
        try:
            self.trace.start(directory / 'raw-ack-and-cpu.trace.gz')
            trace_active = True
            for index in range(count):
                functions = 192 if index == 0 else 768
                label = single_label if count == 1 else ('scalar' if index % 2 == 0 else 'rvv')
                source, flags, expected, reference = self.references[(functions, label)]
                assembly = output / f'worker-{index:02d}.s'
                env = smoke.environment()
                env['CHIMERA_BOOTSTRAP_TRACE'] = '1'
                command = [str(R / 'bin/chimera-user'), 'run', '--registry', str(smoke.REGISTRY),
                           '--bootstrap', str(smoke.BOOTSTRAP), '--preference', 'prefer-x100',
                           *smoke.compile_command(assembly, flags)]
                log = (directory / f'worker-{index:02d}.log').open('wb')
                process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=log, stderr=subprocess.STDOUT,
                                           env=env, start_new_session=True)
                job = dict(index=index, label=label, functions=functions, source=source, flags=flags,
                           expected=expected, reference=reference, assembly=assembly, process=process,
                           log=log, samples={}, errors=[], command=command, incomplete_witnesses=0)
                def feed(job=job):
                    try:
                        assert release.wait(180), 'All-ready barrier timed out'
                        job['process'].stdin.write(job['source'])
                        job['process'].stdin.close()
                    except BaseException as error:
                        job['errors'].append(repr(error))
                job['feeder'] = threading.Thread(target=feed, daemon=True)
                job['feeder'].start()
                jobs.append(job)
            all_ready = False
            last_space_check = 0
            while any(job['process'].poll() is None for job in jobs):
                elapsed = time.monotonic() - started
                assert elapsed < 300, 'Concurrent compiler case timed out'
                if elapsed - last_space_check > 5:
                    assert shutil.disk_usage(R).free >= 6 * 1024**3, 'Runtime disk margin reached'
                    assert self.trace.failure is None, self.trace.failure
                    assert not self.kernel.errors and not self.kernel.alerts, ('Kernel evidence or alert', self.kernel.errors, self.kernel.alerts)
                    last_space_check = elapsed
                for job in jobs:
                    p = job['process']
                    if p.poll() is not None:
                        assert all_ready and p.returncode == 0, ('Compiler exited before all-ready or failed', p.pid, p.returncode)
                        continue
                    try:
                        children = (Path('/proc') / str(p.pid) / 'task' / str(p.pid) / 'children').read_text().split()
                        for pid in [p.pid, *map(int, children)]:
                            sample = smoke.status(pid)
                            exe = sample['executable']
                            if exe not in (str(smoke.GCC), str(smoke.CC1)): continue
                            # Capture one complete initialization witness before
                            # releasing input. A signal currently being handled
                            # temporarily masks itself; an exiting process can
                            # clear dispositions. Neither invalidates an earlier
                            # complete witness. Missing/permanently blocked
                            # initialization still fails at the unchanged bound.
                            if exe in job['samples']: continue
                            if not initialization_ready(sample):
                                job['incomplete_witnesses'] += 1
                                job['last_incomplete_witness'] = sample
                                continue
                            if exe not in job['samples']:
                                maps = (Path('/proc') / str(pid) / 'maps').read_text()
                                workspace = R / 'workspaces' / ('xgcc' if exe == str(smoke.GCC) else 'cc1')
                                assert str(workspace / 'artifacts') in maps
                                sample['maps_sha256'] = hashlib.sha256(maps.encode()).hexdigest()
                                sample['workspace_runtime_paths'] = sorted({line.split()[-1] for line in maps.splitlines() if str(workspace / 'artifacts') in line})
                                job['samples'][exe] = sample
                    except (OSError, ProcessLookupError):
                        pass
                if not all_ready and all(set(job['samples']) == {str(smoke.GCC), str(smoke.CC1)} for job in jobs):
                    all_ready = True
                    save(directory / 'all-ready-barrier.json', dict(seconds=time.monotonic() - started,
                         workers=count, drivers=[job['process'].pid for job in jobs],
                         ready=[job['samples'] for job in jobs]))
                    release.set()
                time.sleep(0.02)
            assert all_ready
            for job in jobs:
                job['feeder'].join(timeout=2)
                assert not job['feeder'].is_alive() and not job['errors'], job['errors']
                job['log'].close()
            deadline = time.monotonic() + 2
            after = smoke.stats()
            while any(after[key] != 0 for key in LEDGERS) and time.monotonic() < deadline:
                time.sleep(0.02)
                after = smoke.stats()
            assert all(after[key] == 0 for key in LEDGERS), ('Nonzero accounting', after)
            assert after['prefer_a100_fail_timeout'] == before['prefer_a100_fail_timeout']
            selected = {sample['pid'] for job in jobs for sample in job['samples'].values()}
            capture = self.trace.finish(selected)
            trace_active = False
            assert capture['replay']['capability_ack_count'] >= 2 * count, 'Raw user ACK fields not proven for both initialized programs'
            child_pids = {job['samples'][str(smoke.CC1)]['pid'] for job in jobs}
            child_commits = [record for record in capture['replay']['physical_commits'] if record['tid'] in child_pids]
            outputs = []
            smoke.E = directory
            for job in jobs:
                text = (directory / f'worker-{job["index"]:02d}.log').read_text()
                for exe, workspace in ((smoke.GCC, R / 'workspaces/xgcc'), (smoke.CC1, R / 'workspaces/cc1')):
                    pid = job['samples'][str(exe)]['pid']
                    assert f'initialized pid={pid} executable={exe} workspace={workspace}' in text
                actual = smoke.check_program(job['assembly'], job['flags'], job['expected'], f'worker-{job["index"]:02d}')
                assert actual['assembly_sha256'] == job['reference']['assembly_sha256'], ('Generated assembly differs', job['index'])
                assert actual['executable_sha256'] == job['reference']['executable_sha256'], ('Generated executable differs', job['index'])
                outputs.append(dict(index=job['index'], target=job['label'], functions=job['functions'],
                                    command=job['command'], ready=job['samples'], actual=actual,
                                    incomplete_initialization_samples=job['incomplete_witnesses']))
            value = dict(passed=True, case=number, workers=count, category=category,
                         seconds=time.monotonic() - started, kernel_before=before, kernel_after=after,
                         trace=capture, compiler_child_commits=child_commits, outputs=outputs)
            save(directory / 'result.json', value)
            self.results.append(dict(case=number, workers=count, category=category, passed=True,
                                     seconds=value['seconds'], evidence=str(directory),
                                     child_commits=child_commits))
            # Private reproducible test outputs only; all hashes, stdout and raw
            # migration evidence have already been saved. Keep failed files.
            for job in jobs:
                for path in (job['assembly'], job['assembly'].with_suffix('.exe')):
                    assert path.parent == output and path.resolve().parent == output
                    path.unlink()
            save(self.evidence / 'progress.json', dict(completed_cases=self.results,
                                                      elapsed_seconds=time.monotonic() - self.started))
            self.state('running', last_completed_case=number)
            print(json.dumps(self.results[-1]), flush=True)
        except BaseException as error:
            save(directory / 'failure.json', dict(error=repr(error), processes=[
                dict(pid=j['process'].pid, rc=j['process'].poll(), command=j['command'],
                     samples=j['samples'], feeder_errors=j['errors'],
                     last_incomplete_witness=j.get('last_incomplete_witness')) for j in jobs]))
            raise
        finally:
            for job in jobs:
                p = job['process']
                if p.poll() is None:
                    os.killpg(p.pid, signal.SIGTERM)
                    try: p.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        os.killpg(p.pid, signal.SIGKILL)
                        p.wait(timeout=5)
                if not job['log'].closed: job['log'].close()
            if trace_active:
                try: save(directory / 'failed-trace.json', self.trace.finish(set()))
                except BaseException as error: save(directory / 'trace-error.json', dict(error=repr(error)))

    def run(self):
        self.verify_input()
        assert not self.result.exists()
        self.evidence.mkdir(exist_ok=False)
        self.output.mkdir(exist_ok=False)
        self.state('running', stage=self.stage)
        save(self.evidence / 'input-identities.json', dict(
            profile_sha256=sha(R / 'profile.gcc.toml'), registry_sha256=sha(smoke.REGISTRY),
            bootstrap_sha256=sha(smoke.BOOTSTRAP), elf_sha256={n: sha(R / 'build-gate/gcc' / n) for n in ('xgcc', 'cc1')},
            boot_id=Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
            conditional_scope='assume-scalar-independent'))
        self.hardware()
        for functions in (192, 768):
            for label in ('scalar', 'rvv'): self.reference(functions, label)
        kernel = KernelLog(self.evidence)
        self.kernel = kernel
        kernel.start()
        kernel_result = None
        try:
            self.trace.configure()
            number = 0
            if self.stage == 'matrix':
                for workers, label in [(1, 'scalar'), (1, 'rvv'), (8, 'scalar'), (16, 'scalar'), (24, 'scalar')]:
                    number += 1
                    self.case(number, workers, 'matrix', label)
                for _ in range(10):
                    number += 1
                    self.case(number, 16, 'repeat-16')
            else:
                mixed_started = time.monotonic()
                while time.monotonic() - mixed_started < 7200:
                    workers = (1, 8, 16, 24)[number % 4]
                    number += 1
                    self.case(number, workers, 'two-hour-mixed', 'rvv' if number % 2 else 'scalar')
                assert time.monotonic() - mixed_started >= 7200
                save(self.evidence / 'two-hour-duration.json', dict(seconds=time.monotonic() - mixed_started, minimum=7200))
        finally:
            try:
                self.trace.close()
            finally:
                kernel_result = kernel.finish()
        assert not kernel_result['errors'] and not kernel_result['alerts'], ('Kernel records/alerts', kernel_result)
        commits = [item for case in self.results for item in case['child_commits']]
        by_pid = {}
        for item in commits: by_pid.setdefault(item['tid'], set()).add(item['route'])
        routes = {name: sum(x['route'] == name for x in commits) for name in ('256-to-1024', '1024-to-256')}
        assert all(routes.values()), 'Actual cc1 commits in both directions required'
        assert any(len(values) == 2 for values in by_pid.values()), 'Same compiler child must complete a physical roundtrip'
        assert all(smoke.stats()[key] == 0 for key in LEDGERS)
        value = dict(rc=0, passed=True, stage=self.stage, cases=self.results,
                     child_route_counts=routes, same_tid_roundtrips=[pid for pid, values in by_pid.items() if len(values) == 2],
                     kernel=kernel_result, seconds=time.monotonic() - self.started,
                     conditional_scope='assume-scalar-independent',
                     completed_utc=time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()))
        save(self.result, value)
        self.state('phase_complete', rc=0, evidence=str(self.evidence))
        print(json.dumps(value), flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--stage', choices=('matrix', 'stability'), required=True)
    parser.add_argument('--attempt', type=int, required=True)
    parser.add_argument('--matrix-attempt', type=int, default=3)
    args = parser.parse_args()
    assert args.attempt > 0 and args.matrix_attempt > 0
    runner = Acceptance(args.stage, args.attempt, args.matrix_attempt)
    def terminate(number, frame):
        raise SystemExit(128 + number)
    signal.signal(signal.SIGTERM, terminate)
    try:
        runner.run()
    except BaseException as error:
        save(runner.result, dict(rc=1, passed=False, error=repr(error), evidence=str(runner.evidence),
                                completed_cases=runner.results))
        runner.state('failed', rc=1, error=repr(error), evidence=str(runner.evidence))
        raise
