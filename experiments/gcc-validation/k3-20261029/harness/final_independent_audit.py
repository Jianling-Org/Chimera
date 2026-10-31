"""Fresh in-place audit of current artifacts and every accepted runtime case."""
import collections
import datetime
import gzip
import hashlib
import inspect
import json
import os
from pathlib import Path
import re
import subprocess
import time

from worker import source_imports
import runtime_smoke as smoke
from migration_trace import replay
from readiness_probe import initialization_ready
from kernel_event_policy import POLICY, classify_kernel_record, validate_storage_sample

R = Path('/root/chimera-gcc-validation-578ab8321')
S = R / 'source'
E = R / 'provenance/final-audit-1'
RESULT = R / 'stage-results/final-audit-1.json'
UNIT = 'chimera-gcc-final-audit-1.service'
COMMIT = '578ab8321c0788ab8cba1ad24324f220e1e4a149'
PROFILE_SHA = '1905a136b12c3b4cb71508d546042767b2311780bbf9527c4d218dde6c11ef38'
ELFS = {'xgcc': '88931e9e1309afa31f1e5e056700a8cb1a1684990b9939ea62205f8a31e3a89b',
        'cc1': 'd4e48555d5cd292da07dc820f57eb964df37ffef87723fd799f6a50bb993b7ff'}
LEDGERS = ('policy_a100_assigned_regular', 'policy_a100_assigned_ai',
           'policy_x100_assigned_regular', 'policy_x100_assigned_ai',
           'prefer_assigned_regular', 'prefer_assigned_ai', 'prefer_pending_to_regular',
           'prefer_pending_to_ai', 'prefer_a100_cpu_reservations')
CACHE = {}
EVIDENCE = {}
SECTION = 'initial'


def load(path):
    return json.loads(Path(path).read_text())


def save(path, value):
    Path(path).write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n')


def state(status, **extra):
    value = dict(phase='final_audit', status=status, active_unit=UNIT, commit=COMMIT,
                 updated_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                 section=SECTION, log=str(R / 'logs/final-audit-1.log'), **extra)
    save(R / 'state.json.new', value)
    (R / 'state.json.new').replace(R / 'state.json')
    with (R / 'events.jsonl').open('a') as stream:
        stream.write(json.dumps(value) + '\n')


def sha(path, evidence=False):
    path = Path(path)
    st = path.stat()
    key = (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns)
    if key not in CACHE:
        digest = hashlib.sha256()
        with path.open('rb') as stream:
            for block in iter(lambda: stream.read(4 * 1024**2), b''):
                digest.update(block)
        after = path.stat()
        assert key == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns), str(path)
        CACHE[key] = digest.hexdigest()
    if evidence:
        EVIDENCE[str(path)] = dict(bytes=st.st_size, sha256=CACHE[key])
    return CACHE[key]


def normal_exit(name):
    result = load(R / ('stage-results/' + name + '.json'))
    resource = load(R / ('stage-results/' + name + '.resources.json'))
    assert result['rc'] == 0 and result['passed'] is True, name
    assert [resource[k] for k in ('SERVICE_RESULT', 'EXIT_CODE', 'EXIT_STATUS')] == ['success', 'exited', '0'], resource
    events = dict(line.split() for line in resource.get('memory.events', '').splitlines())
    assert int(events.get('oom', 0)) == 0 and int(events.get('oom_kill', 0)) == 0
    for suffix in ('json', 'resources.json', 'time.txt'):
        path = R / ('stage-results/' + name + '.' + suffix)
        assert path.is_file()
        sha(path, True)
    return result, resource


def identity_numbers(path):
    st = Path(path).stat()
    return [st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns // 10**9,
            st.st_mtime_ns % 10**9, st.st_ctime_ns // 10**9, st.st_ctime_ns % 10**9]


def independent_stdout(count):
    # Recompute the C fixture with modular uint32 arithmetic, independently of
    # the stored reference output and runtime_smoke.fixture's masking loop.
    modulus = 2**32
    word = 0x12345678
    for function in range(count):
        word = (word + function) % modulus
        constant = (0x9e3779b9 * (function + 1)) % modulus
        for iteration in range(64):
            word = (word ^ ((word * 8192) % modulus)) % modulus
            word = (word ^ (word // 131072)) % modulus
            word = (word ^ ((word * 32) % modulus)) % modulus
            word = (word + constant + iteration) % modulus
    for element in range(2048):
        value = (((element * 2654435761) % modulus) * 1664525 + 1013904223) % modulus
        word ^= value
    return f'{word:08x}\n'


def audit_workspace(name, registered):
    from chimera.runtime.validate import verify_workspace
    from chimera.user_config import load_user_settings
    from chimera.workspack import verify_workspace_installation
    from chimera.runtime.manifest import variant_fingerprint
    from chimera.runtime.launcher.run import _search_paths, resolved_module_paths
    from chimera.runtime.preload.bootstrap_launch import bootstrap_tunables
    from elftools.elf.elffile import ELFFile
    assert Path(inspect.getfile(verify_workspace)).resolve().is_relative_to(S)
    program = R / 'build-gate/gcc' / name
    w = R / 'workspaces' / name
    assert w.resolve() == w and sha(program, True) == ELFS[name]
    verify_workspace_installation(w)
    manifest = verify_workspace(w, load_user_settings(), check_host=False)
    mains = [m for m in manifest.modules if m.role == 'main']
    assert len(mains) == 1 and mains[0].sha256 == ELFS[name]
    routes = collections.defaultdict(list)
    for variant in manifest.variants:
        routes[variant.module_id].append([manifest.property_value(variant.variant_id, side, 'vector_vlen_bits')
                                         for side in ('input', 'output')])
    assert len(routes) == len(manifest.modules)
    assert all(sorted(pairs) == [[256, 1024], [1024, 256]] for pairs in routes.values())
    expected = {program.resolve(): ELFS[name]}
    artifacts = []
    for artifact in manifest.artifacts:
        path = w / artifact.path
        assert path.resolve().is_relative_to(w) and not path.is_symlink()
        assert sha(path, True) == artifact.sha256, str(path)
        expected[path.resolve()] = artifact.sha256
        artifacts.append(dict(path=str(path), sha256=artifact.sha256))
    with program.open('rb') as stream:
        loader = next(Path(segment.get_interp_name()) for segment in ELFFile(stream).iter_segments()
                      if segment['p_type'] == 'PT_INTERP')
    resolved = resolved_module_paths(loader, program, _search_paths(w, program), manifest)
    for module in manifest.modules:
        if module.role != 'main':
            path = resolved[module.module_id].resolve()
            assert sha(path, True) == module.sha256, str(path)
            expected[path] = module.sha256
    receipt = w / 'artifacts/verified-files.tsv'
    variants = w / 'artifacts/verified-variants.tsv'
    tables = w / 'artifacts/verified-tables.tsv'
    for path in (variants, w / 'artifacts/modules.tsv'):
        expected[path.resolve()] = sha(path, True)
    rows = {}
    for line in receipt.read_text().splitlines():
        fields = line.split('\t')
        assert len(fields) == 9
        path, digest = Path(fields[0]), fields[1]
        assert path.is_absolute() and path not in rows
        assert list(map(int, fields[2:])) == identity_numbers(path), str(path)
        assert sha(path, True) == digest, str(path)
        rows[path] = digest
    assert rows == expected, ('Receipt set/content mismatch', name, set(rows) ^ set(expected))
    expected_variants = {v.variant_id: variant_fingerprint(manifest, v.variant_id) for v in manifest.variants}
    actual_variants = dict(line.split('\t') for line in variants.read_text().splitlines())
    assert actual_variants == expected_variants
    proof = tables.read_text().split('\t')
    assert proof[0] == 'tables-v1' and list(map(int, proof[1:])) == identity_numbers(receipt)
    receipts_before = {}
    for path in (receipt, variants, tables):
        recorded = registered['receipts'][name][path.name]
        assert sha(path, True) == recorded['sha256']
        receipts_before[path] = (sha(path), identity_numbers(path))
    runtime = next(Path(row[3]) for row in registered['records'] if row[0] == str(program))
    env = smoke.environment()
    env.update(LD_PRELOAD=str(runtime), CHIMERA_WORKSPACE=str(w), CHIMERA_VERIFY_TABLES_ONLY='1',
               GLIBC_TUNABLES=bootstrap_tunables(env.get('GLIBC_TUNABLES', '')))
    # This flag explicitly forces chimera_registry_validate, bypassing the
    # ordinary cached-layout fast path and exits from the runtime constructor.
    process = subprocess.run([str(program)], env=env, capture_output=True, timeout=120)
    path = E / (name + '-native-full-table.log')
    path.write_bytes(process.stdout + process.stderr)
    sha(path, True)
    assert process.returncode == 0, (name, process.returncode, process.stderr)
    for path, before in receipts_before.items():
        assert (sha(path), identity_numbers(path)) == before, 'Audit must not replace receipts'
    value = dict(passed=True, artifacts=artifacts, artifact_count=len(artifacts), modules=len(manifest.modules),
                 routes=dict(routes), receipt_rows=len(rows), variant_receipts=len(actual_variants),
                 official_check_host=False, native_full_table_validation_rc=process.returncode,
                 receipt_content_identity_and_semantics_verified=True, receipts_unchanged=True)
    save(E / (name + '-workspace-audit.json'), value)
    return value


def split_kmsg(raw):
    records = []
    for line in raw.splitlines(keepends=True):
        if re.match(rb'^\d+,\d+,\d+,[^;\n]*;', line):
            records.append(line)
        else:
            assert records, 'Unframed kmsg bytes'
            records[-1] += line
    assert b''.join(records) == raw
    return records


def audit_kernel(stage, result):
    directory = R / 'provenance' / stage
    raw_path = directory / 'kernel-continuous.kmsg.gz'
    sha(raw_path, True)
    raw = gzip.decompress(raw_path.read_bytes())
    audit = load(directory / 'kernel-continuous-audit.json')
    assert audit == result['kernel'] and not audit['errors'] and not audit['alerts']
    assert len(raw) == audit['uncompressed_bytes']
    assert hashlib.sha256(raw).hexdigest() == audit['uncompressed_sha256']
    records = split_kmsg(raw)
    sequences = [int(block.partition(b';')[0].split(b',')[1]) for block in records]
    assert all(b == a + 1 for a, b in zip(sequences, sequences[1:]))
    assert audit['sequence_endpoints'] == ([sequences[0], sequences[-1]] if sequences else [])
    classifications = [classify_kernel_record(block, stage == 'runtime-stability-2') for block in records]
    assert 'alert' not in classifications
    known = [block.decode() for block, kind in zip(records, classifications) if kind == 'known-ufs-bkops-status1']
    if stage == 'runtime-stability-2':
        assert audit['kernel_event_policy'] == POLICY and audit['known_background_events'] == known
        assert audit['known_background_event_count'] == len(known)
        prefix = 'chimera-gcc-validation:' + stage + ':'
        markers = [block.partition(b';')[2].decode().splitlines()[0] for block in records
                   if block.partition(b';')[2].decode().splitlines()[0].startswith(prefix)]
        assert markers == [prefix + 'begin', prefix + 'end']
        assert audit['informational_control_markers'] == ['begin', 'end']
        health_path = directory / 'storage-health.jsonl'
        samples = [json.loads(line) for line in health_path.read_text().splitlines()]
        assert len(samples) == result['storage_health_sample_count'] and len(samples) >= 2
        for sample in samples:
            validate_storage_sample(sample)
        times = [sample['monotonic_seconds'] for sample in samples]
        assert all(b > a for a, b in zip(times, times[1:]))
        sha(health_path, True)
        duration = load(directory / 'two-hour-duration.json')
        assert duration['minimum'] == 7200 and duration['seconds'] >= 7200
        assert times[-1] - times[0] >= duration['seconds']
        sha(directory / 'two-hour-duration.json', True)
        health = dict(samples=len(samples), max_bkops=max(s['bkops_status'] for s in samples),
                      max_critical_health=max(s['critical_health'] for s in samples),
                      maximum_sample_gap_seconds=max(b - a for a, b in zip(times, times[1:])),
                      mixed_seconds=duration['seconds'])
    else:
        assert not known and not records
        assert (directory / 'dmesg-before.txt').read_bytes() == (directory / 'dmesg-after.txt').read_bytes()
        health = None
    for name in ('kernel-continuous-audit.json', 'dmesg-before.txt', 'dmesg-after.txt'):
        sha(directory / name, True)
    return dict(raw_bytes=len(raw), raw_sha256=hashlib.sha256(raw).hexdigest(),
                sequences=sequences, known_background_events=len(known), unexpected_alerts=0, health=health)


def audit_stage(stage, workspaces):
    result, resource = normal_exit(stage)
    directory = R / 'provenance' / stage
    output = R / 'runtime-validation' / stage
    identity = load(directory / 'input-identities.json')
    assert identity['profile_sha256'] == PROFILE_SHA and identity['elf_sha256'] == ELFS
    assert identity['registry_sha256'] == sha(smoke.REGISTRY) and identity['bootstrap_sha256'] == sha(smoke.BOOTSTRAP)
    assert identity['boot_id'] == Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    hardware = load(directory / 'hardware-vlen.json')['per_cpu']
    assert len(hardware) == 16 and {x['cpu']: x['bits'] for x in hardware} == {i: 256 if i < 8 else 1024 for i in range(16)}
    references = {}
    for functions in (192, 768):
        source, _ = smoke.fixture(functions)
        expected = independent_stdout(functions)
        for label in ('scalar', 'rvv'):
            path = directory / f'reference-{functions}-{label}.json'
            reference = load(path)
            assert reference['source_sha256'] == hashlib.sha256(source).hexdigest()
            assert reference['expected_stdout'] == reference['native']['stdout'] == expected
            assembly = output / f'reference-{functions}-{label}.s'
            executable = assembly.with_suffix('.exe')
            assert sha(assembly, True) == reference['native']['assembly_sha256']
            assert sha(executable, True) == reference['native']['executable_sha256']
            native = subprocess.run([str(executable)], env=smoke.environment(), capture_output=True, timeout=30)
            assert native.returncode == 0 and native.stdout.decode() == expected
            references[(functions, label)] = reference
            sha(path, True)
    cases = result['cases']
    assert len(list(directory.glob('case-*'))) == len(cases)
    totals = collections.Counter()
    all_commits = []
    summaries = []
    matrix_plan = [1, 1, 8, 16, 24] + [16] * 10
    for number, case in enumerate(cases, 1):
        assert case['case'] == number and case['passed'] is True
        workers = case['workers']
        assert workers == (matrix_plan[number - 1] if stage == 'runtime-matrix-3' else (1, 8, 16, 24)[(number - 1) % 4])
        case_dir = directory / f'case-{number:04d}-{workers}'
        record = load(case_dir / 'result.json')
        barrier = load(case_dir / 'all-ready-barrier.json')
        assert record['passed'] and record['case'] == number and record['workers'] == workers
        assert 0 < record['seconds'] < 300 and len(record['outputs']) == workers
        assert len(barrier['ready']) == barrier['workers'] == workers
        assert barrier['ready'] == [worker['ready'] for worker in record['outputs']]
        assert barrier['drivers'] == [worker['ready'][str(smoke.GCC)]['pid'] for worker in record['outputs']]
        selected = set()
        children = set()
        for worker in record['outputs']:
            index = worker['index']
            functions = 192 if index == 0 else 768
            assert worker['functions'] == functions
            reference = references[(functions, worker['target'])]
            assert worker['actual'] == reference['native']
            expected_assembly = output / f'case-{number:04d}-{workers}' / f'worker-{index:02d}.s'
            command = [str(R / 'bin/chimera-user'), 'run', '--registry', str(smoke.REGISTRY),
                       '--bootstrap', str(smoke.BOOTSTRAP), '--preference', 'prefer-x100',
                       *smoke.compile_command(expected_assembly, reference['flags'])]
            assert worker['command'] == command
            log = case_dir / f'worker-{index:02d}.log'
            text = log.read_text()
            for program, name in ((smoke.GCC, 'xgcc'), (smoke.CC1, 'cc1')):
                sample = worker['ready'][str(program)]
                assert initialization_ready(sample) and sample['executable'] == str(program)
                assert sample['pid'] not in selected
                selected.add(sample['pid'])
                if name == 'cc1': children.add(sample['pid'])
                workspace = R / 'workspaces' / name
                assert f"initialized pid={sample['pid']} executable={program} workspace={workspace}" in text
                mapped = set(sample['workspace_runtime_paths'])
                assert str(workspace / 'artifacts/runtime/libchimera_inject.so') in mapped
                assert mapped.issubset({entry['path'] for entry in workspaces[name]['artifacts']})
            sha(log, True)
            sha(case_dir / f'worker-{index:02d}-link.log', True)
        raw_path = case_dir / 'raw-ack-and-cpu.trace.gz'
        raw = gzip.decompress(raw_path.read_bytes())
        capture = record['trace']
        assert len(raw) == capture['uncompressed_bytes'] and hashlib.sha256(raw).hexdigest() == capture['uncompressed_sha256']
        fresh = replay(raw.decode().splitlines(), selected)
        assert fresh == capture['replay'] and fresh['capability_ack_count'] >= 2 * workers
        assert len(capture['per_cpu']) == 16 and len(capture['kprobe_profile']) == 2
        for stats in capture['per_cpu'].values():
            rows = dict((key.strip(), value.strip()) for key, _, value in (line.partition(':') for line in stats.splitlines()))
            assert all(int(rows[key]) == 0 for key in ('overrun', 'commit overrun', 'dropped events'))
        assert all(int(line.split()[-1]) == 0 for line in capture['kprobe_profile'])
        child_commits = [item for item in fresh['physical_commits'] if item['tid'] in children]
        assert child_commits == record['compiler_child_commits'] == case['child_commits']
        used = set()
        for item in child_commits:
            ack = item['ack']
            assert ack['action'] == 1 and ack['result'] == 8 and ack['generation'] > 0
            assert ack['enter_time'] <= item['timestamp'] <= ack['return_time']
            assert 0 <= item['src_cpu'] < 16 and 0 <= item['dst_cpu'] < 16
            key = (item['tid'], ack['generation'])
            assert key not in used
            used.add(key)
        assert all(record[boundary][key] == 0 for boundary in ('kernel_before', 'kernel_after') for key in LEDGERS)
        assert record['kernel_before']['prefer_a100_fail_timeout'] == record['kernel_after']['prefer_a100_fail_timeout']
        for path in (raw_path, case_dir / 'result.json', case_dir / 'all-ready-barrier.json'):
            sha(path, True)
        all_commits.extend(child_commits)
        totals['cases'] += 1; totals['compiler_chains'] += workers
        summaries.append(dict(case=number, workers=workers, child_commits=len(child_commits), raw_sha256=capture['uncompressed_sha256']))
    by_tid = collections.defaultdict(set)
    counts = collections.Counter(item['route'] for item in all_commits)
    for item in all_commits: by_tid[item['tid']].add(item['route'])
    roundtrips = sorted(pid for pid, routes in by_tid.items() if len(routes) == 2)
    assert dict(counts) == result['child_route_counts'] and all(counts.values()) and len(counts) == 2
    assert roundtrips and roundtrips == sorted(result['same_tid_roundtrips'])
    if stage == 'runtime-matrix-3': assert len(cases) == 15
    kernel = audit_kernel(stage, result)
    value = dict(passed=True, **dict(totals), child_route_counts=dict(counts), same_tid_roundtrips=len(roundtrips),
                 kernel=kernel, peak_bytes=int(resource['memory.peak']), swap_peak_bytes=int(resource['memory.swap.peak']),
                 actual_exit='success/exited/0', per_case=summaries)
    save(E / (stage + '-audit.json'), value)
    print(json.dumps({k: v for k, v in value.items() if k != 'per_case'}), flush=True)
    return {k: v for k, v in value.items() if k != 'per_case'}


def main():
    global SECTION
    os.umask(0o077)
    assert not RESULT.exists() and not E.exists()
    E.mkdir()
    state('running')
    source_imports()
    assert subprocess.check_output(['git', '-C', str(S), 'rev-parse', 'HEAD'], text=True).strip() == COMMIT
    assert not subprocess.check_output(['git', '-C', str(S), 'status', '--porcelain'], text=True).strip()
    assert os.uname().release == '6.18.3-chimera-d02cd7352'
    assert sha(R / 'profile.gcc.toml', True) == PROFILE_SHA
    assert sha(R / 'plans/gate/decision.json', True) == 'faa49f50b80d0fd83b0e2ad444d250ac4a5ca009649155725613ee037cd8b820'
    gate_names = (R / 'plans/gate/decision.gate_names.txt').read_text().splitlines()
    assert len(set(gate_names)) == len(gate_names) == 3286
    for name, expected in (
        ('xgcc', '2ab178456580cb1b5d6e36c8e527619b9b9c2e425303bcfc7441ae5e4769016b'),
        ('cc1', '91217c45f55e76458ae6f001597a57a1c6caf060eb5e23aa47d487c95d0ca4f2')):
        report = R / ('reports/final-' + name + '.json')
        assert sha(report, True) == expected
        value = load(report)
        assert value['passed'] and value['conditional'] and not value['findings']
        assert value['summary']['pending_proof'] == value['summary']['residual'] == 0
    SECTION = 'current_workspace_artifacts_receipts_and_native_tables'
    state('running')
    registered, _ = normal_exit('bootstrap-register-1')
    assert sha(smoke.REGISTRY, True) == registered['registry_sha256']
    assert sha(smoke.BOOTSTRAP, True) == registered['bootstrap_sha256']
    rows = [line.split('\t') for line in smoke.REGISTRY.read_text().splitlines()[1:]]
    assert rows == registered['records'] and len(rows) == 2
    workspaces = {name: audit_workspace(name, registered) for name in ('xgcc', 'cc1')}
    captured = load(R / 'provenance/runtime-stability-2-preflight/harness-source-sha256.json')
    for relative, digest in captured.items(): assert sha(R / relative, True) == digest
    SECTION = 'independent_full_case_and_raw_trace_replay'
    state('running')
    stages = {name: audit_stage(name, workspaces) for name in ('runtime-matrix-3', 'runtime-stability-2')}
    SECTION = 'preservation_and_final_cleanup'
    state('running')
    preserved = load(R / 'provenance/preservation-index-20261029.json')
    preserved_failures = 0
    for entry in preserved['files']:
        if entry['kind'] == 'file' and entry['path'] in (
            'stage-results/runtime-stability-1.json', 'stage-results/runtime-stability-1.resources.json',
            'stage-results/runtime-matrix-1.json', 'stage-results/runtime-matrix-2.json'):
            assert sha(R / entry['path'], True) == entry['sha256']
            preserved_failures += 1
    assert preserved_failures == 4 and load(R / 'stage-results/runtime-stability-1.json')['passed'] is False
    counters = smoke.stats()
    assert all(counters[key] == 0 for key in LEDGERS)
    assert counters['prefer_a100_fail_timeout'] == 0
    trace_root = Path('/sys/kernel/tracing')
    assert not list((trace_root / 'instances').glob('chimera_gcc_578ab8321_*'))
    assert 'chimera_gcc_578ab8321_' not in (trace_root / 'kprobe_events').read_text()
    assert 'chimera-gcc-validation-578ab8321' not in Path('/proc/swaps').read_text()
    assert not subprocess.check_output(['git', '-C', str(S), 'status', '--porcelain'], text=True).strip()
    save(E / 'evidence-sha256.json', EVIDENCE)
    result = dict(rc=0, passed=True, commit=COMMIT, kernel=os.uname().release,
                  conditional_scope='assume-scalar-independent', kernel_event_policy=POLICY,
                  workspaces={name: {k: v for k, v in value.items() if k != 'artifacts'} for name, value in workspaces.items()},
                  stages=stages, preserved_failed_records=preserved_failures,
                  final_counters=counters, task_trace_and_probes_clean=True, task_swap_absent=True,
                  evidence_file_count=len(EVIDENCE), evidence_manifest_sha256=sha(E / 'evidence-sha256.json'),
                  receipts_republished=False, original_results_modified=False,
                  successful_temporary_worker_outputs='Removed after original execution/hash verification; all recorded digests/stdout audited against retained native baselines; no claim to rehash removed files',
                  completed_utc=datetime.datetime.now(datetime.timezone.utc).isoformat())
    save(RESULT, result)
    state('phase_complete', rc=0, evidence=str(E))
    print(json.dumps(result), flush=True)


if __name__ == '__main__':
    try:
        main()
    except BaseException as error:
        value = dict(rc=1, passed=False, section=SECTION, error=repr(error))
        save(RESULT, value)
        state('failed', rc=1, error=repr(error), evidence=str(E))
        raise
