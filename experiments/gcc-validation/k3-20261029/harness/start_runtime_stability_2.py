"""One-shot resume preflight and bounded background launch; never poll/retry."""
from pathlib import Path
import datetime
import gzip
import hashlib
import json
import os
import re
import shutil
import subprocess

from kernel_event_policy import POLICY, StorageHealth, classify_kernel_record
from runtime_acceptance_v5 import Acceptance

R = Path('/root/chimera-gcc-validation-578ab8321')
E = R / 'provenance/runtime-stability-2-preflight'
UNIT = 'chimera-gcc-runtime-stability-2.service'


def save(name, value):
    (E / name).write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n')


def sha(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(4 * 1024**2), b''):
            digest.update(block)
    return digest.hexdigest()


def run(command):
    p = subprocess.run(command, capture_output=True, text=True)
    assert p.returncode == 0, (command, p.returncode, p.stdout, p.stderr)
    return dict(command=command, stdout=p.stdout, stderr=p.stderr, rc=p.returncode)


assert not E.exists(), 'This launch is one-shot; inspect prior preflight instead of rerunning'
E.mkdir()
for path in (R / 'provenance/runtime-stability-2', R / 'runtime-validation/runtime-stability-2',
             R / 'stage-results/runtime-stability-2.json'):
    assert not path.exists(), ('Attempt2 already exists', str(path))
current = run(['systemctl', 'show', UNIT, '-p', 'LoadState', '-p', 'ActiveState'])
assert 'LoadState=not-found' in current['stdout'] and 'ActiveState=inactive' in current['stdout']
active = run(['systemctl', 'list-units', '--state=active,activating', '--no-legend', '--no-pager', 'chimera-gcc-*'])
assert not active['stdout'].strip(), active

authorization = json.loads((R / 'runtime-kernel-policy-20261029.json').read_text())
assert authorization['user_authorized_exact_known_ufs_status1'] and authorization['policy'] == POLICY
runner = Acceptance('stability', 2, 3, True)
runner.verify_input()
matrix_identity = json.loads((R / 'provenance/runtime-matrix-3/input-identities.json').read_text())
assert Path('/proc/sys/kernel/random/boot_id').read_text().strip() == matrix_identity['boot_id'], 'Boot identity changed; refresh host-bound verification before reuse'

index = json.loads((R / 'provenance/preservation-index-20261029.json').read_text())
identities = []
for entry in index['files']:
    relative = entry['path']
    if entry['kind'] != 'file':
        continue
    if relative.startswith(('workspaces/', 'build-gate/gcc/')) or relative in (
            'profile.gcc.toml', 'runtime-validation/registry.tsv', 'build/runtime/libchimera-bootstrap.so'):
        actual = sha(R / relative)
        assert actual == entry['sha256'], ('Preserved input identity changed', relative)
        identities.append(dict(path=relative, sha256=actual))
save('reused-input-identities.json', identities)

regressions = run([str(R / 'venv/bin/python'), '-m', 'unittest', '-v',
                   'test_kernel_event_policy', 'test_migration_trace', 'test_readiness_probe'])
save('regressions.json', regressions)

# Classify the prior failure without rewriting its strict failure report.
raw = gzip.decompress((R / 'provenance/runtime-stability-1/kernel-continuous.kmsg.gz').read_bytes())
records = []
for line in raw.splitlines(keepends=True):
    if re.match(rb'^\d+,\d+,\d+,[^;\n]*;', line):
        records.append(line)
    else:
        assert records, 'Unframed raw kmsg evidence'
        records[-1] += line
assert b''.join(records) == raw
classifications = [classify_kernel_record(block, True) for block in records]
assert classifications.count('known-ufs-bkops-status1') == 1 and 'alert' not in classifications
assert sha(R / 'stage-results/runtime-stability-1.json') == next(
    row['sha256'] for row in index['files'] if row['path'] == 'stage-results/runtime-stability-1.json')
save('prior-failure-classification.json', dict(
    original_result_unchanged=True, original_result_still_failed=True,
    classifications=classifications, raw_sha256=hashlib.sha256(raw).hexdigest(),
    scope='Offline known-event boundary regression; does not count toward a new stability pass'))
StorageHealth(E).check(force=True)

free_before = shutil.disk_usage(R).free
memory = dict(line.split(':', 1) for line in Path('/proc/meminfo').read_text().splitlines())
available = int(memory['MemAvailable'].split()[0]) * 1024
assert available >= 14 * 1024**3, 'Need12GiB runtime plus2GiB available-memory margin'
assert free_before >= 10 * 1024**3
probe = R / 'tmp/stability-2-capacity-probe'
probe.parent.mkdir(exist_ok=True)
assert probe.parent.resolve() == (R / 'tmp').resolve() and not probe.exists()
descriptor = os.open(probe, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
try:
    os.posix_fallocate(descriptor, 0, 4 * 1024**3)
    os.fsync(descriptor)
    allocated = os.fstat(descriptor).st_blocks * 512
    assert allocated >= 4 * 1024**3
    remaining = shutil.disk_usage(R).free
    assert remaining >= 6 * 1024**3, 'Unchanged6GiB actual reserve unmet'
finally:
    os.close(descriptor)
    assert probe.resolve() == (R / 'tmp/stability-2-capacity-probe').resolve()
    probe.unlink()

sources = {p: sha(R / p) for p in (
    'runtime_acceptance_v5.py', 'kernel_event_policy.py', 'test_kernel_event_policy.py',
    'migration_trace.py', 'readiness_probe.py', 'runtime_smoke.py', 'worker.py',
    'record_cgroup.py', 'watchdog.py', 'runtime-kernel-policy-20261029.json',
    'start_runtime_stability_2.py')}
save('harness-source-sha256.json', sources)
preflight = dict(passed=True, utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
    free_before_bytes=free_before, actual_probe_bytes=4 * 1024**3,
    allocated_probe_bytes=allocated, actual_residual_bytes=remaining,
    minimum_residual_bytes=6 * 1024**3, available_memory_bytes=available,
    memory_max_bytes=12 * 1024**3, swap_max_bytes=0, disk_stop_guard_bytes=3 * 1024**3,
    runtime_max_hours=3, minimum_mixed_monotonic_seconds=7200,
    input_identities_verified=len(identities), regression_count=17,
    original_stability_attempt1_still_failed=True, kernel_event_policy=POLICY)
save('preflight-passed.json', preflight)
(R / 'resumption.json').write_text(json.dumps(dict(
    status='resumed_with_user_authorized_known_event_scope',
    user_instruction=authorization['user_instruction'], policy=POLICY,
    supersedes_pause=True, prior_failure_preserved=True, acceptance_passed=False,
    utc=preflight['utc'], next_unit=UNIT), ensure_ascii=False, indent=2) + '\n')

watchdog = run(['systemd-run', '--unit=chimera-gcc-watchdog', '--on-active=2min',
    '--on-unit-active=2min', '--timer-property=AccuracySec=15s',
    '--property=RuntimeMaxSec=30s', '/usr/bin/python3', str(R / 'watchdog.py')])
command = ['systemd-run', '--unit=' + UNIT, '--service-type=exec',
    '--working-directory=' + str(R), '--property=MemoryHigh=10G', '--property=MemoryMax=12G',
    '--property=MemorySwapMax=0', '--property=OOMPolicy=stop', '--property=RuntimeMaxSec=3h',
    '--property=TimeoutStopSec=30s', '--property=KillMode=control-group',
    '--property=ExecStopPost=/usr/bin/python3 ' + str(R / 'record_cgroup.py') + ' runtime-stability-2',
    '--property=StandardOutput=append:' + str(R / 'logs/runtime-stability-2.log'),
    '--property=StandardError=append:' + str(R / 'logs/runtime-stability-2.log'),
    '--setenv=CHIMERA_USER_CONFIG=' + str(R / 'user.toml'), '--setenv=PYTHONUNBUFFERED=1',
    '/usr/bin/time', '-v', '-o', str(R / 'stage-results/runtime-stability-2.time.txt'),
    str(R / 'venv/bin/python'), str(R / 'runtime_acceptance_v5.py'),
    '--stage', 'stability', '--attempt', '2', '--matrix-attempt', '3',
    '--allow-known-ufs-bkops-status1']
launch = run(command)
save('launch.json', dict(watchdog=watchdog, launch=launch))
print(json.dumps(dict(preflight=preflight, unit=UNIT, launch=launch['stderr']), ensure_ascii=False))
