"""Host-side failure injection for the active verification harnesses."""
import ast
import importlib.util
import json
import math
import os
from pathlib import Path
import re
import shutil
import statistics
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
VERIFY = ROOT / "verify"
LLVM = Path("/opt/homebrew/opt/llvm/bin/clang")


def load(relative):
    path = VERIFY / relative
    name = "opencode_" + relative.replace("/", "_").replace(".", "_")
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def run(cmd, directory):
    return subprocess.run(cmd, cwd=ROOT, text=True, capture_output=True,
                          env={**os.environ, "TMPDIR": str(directory),
                               "PYTHONDONTWRITEBYTECODE": "1"})


def compile_c(directory, source, extra, defines=()):
    compiler = shutil.which("cc")
    if compiler is None:
        pytest.skip("host C compiler unavailable")
    stub = directory / "stub.c"
    stub.write_text(extra)
    binary = directory / "verify-host"
    result = run([compiler, "-std=c11", "-O1", *defines, str(source), str(stub), "-o", str(binary)], directory)
    assert result.returncode == 0, result.stderr
    return binary


@pytest.mark.parametrize("mode", ("good", "input", "gap", "rc"))
def test_caxpy_rejects_input_changes_and_nonzero_return(tmp_path, mode):
    stub = '''int caxpy_k(long n,long p,long q,float ar,float ai,float*x,long ix,float*y,long iy,float*z,long r) {
      for(long i=0;i<n;i++){ long a=2*i*ix,b=2*i*iy;
        float xr=x[a],xi=x[a+1]; y[b]+=ar*xr-ai*xi;y[b+1]+=ar*xi+ai*xr; }
      MUTATION
      return RC;
    }'''.replace("MUTATION", {"good": "", "input": "x[0]+=1;", "gap": "x[2]+=1;", "rc": ""}[mode]).replace("RC", "1" if mode == "rc" else "0")
    binary = compile_c(tmp_path, VERIFY / "caxpy_k/main.c", stub)
    result = run([str(binary)], tmp_path)
    assert (result.returncode == 0) == (mode == "good"), result.stdout


@pytest.mark.parametrize("mutation", ("", "x[-1]=0;", "x[n*ix*2]=0;", "y[-1]=0;", "y[n*iy*2]=0;", "x[2]=0;"))
def test_ccopy_input_and_boundary_guards(tmp_path, mutation):
    stub = '''int ccopy_k(long n,float*x,long ix,float*y,long iy) {
      for(long i=0;i<n;i++){y[2*i*iy]=x[2*i*ix];y[2*i*iy+1]=x[2*i*ix+1];}
      MUTATION return 0;
    }'''.replace("MUTATION", mutation)
    binary = compile_c(tmp_path, VERIFY / "ccopy_k/main.c", stub)
    result = run([str(binary)], tmp_path)
    assert (result.returncode == 0) == (not mutation), result.stdout


@pytest.mark.parametrize("value", ("NAN", "INFINITY", "-INFINITY", "sum"))
def test_ddot_nonfinite_results_fail(tmp_path, value):
    stub = '''#include <math.h>
    double ddot_k(long n,double*x,long ix,double*y,long iy){
      double sum=0;for(long i=0;i<n;i++)sum+=x[i*ix]*y[i*iy];return VALUE;}
    '''.replace("VALUE", value)
    binary = compile_c(tmp_path, VERIFY / "ddot_k/main.c", stub)
    result = run([str(binary)], tmp_path)
    assert (result.returncode == 0) == (value == "sum")


def test_sscal_verified_internal_signature(tmp_path):
    stub = '''int sscal_k(long n,long p,long q,float alpha,float*x,long ix,float*y,long iy,float*d,long d2) {
      if(n!=100||p||q||!x||ix!=2||y||iy||d||d2)return 1;
      for(long i=0;i<n;i++)x[i*ix]*=alpha;return 0;}
    '''
    binary = compile_c(tmp_path, VERIFY / "sscal_k/main.c", stub)
    assert run([str(binary)], tmp_path).returncode == 0
    if not LLVM.exists():
        pytest.skip("RISC-V LLVM backend unavailable")
    text = (VERIFY / "sscal_k/main.c").read_text()
    prototype = re.search(r"extern int sscal_k\([^;]+;", text).group()
    probe = tmp_path / "abi.c"
    probe.write_text(prototype + "\nint probe(float*x){return sscal_k(100,0,0,2.5f,x,2,0,0,0,0);}\n")
    assembly = tmp_path / "abi.s"
    result = run([str(LLVM), "--target=riscv64-unknown-linux-gnu", "-march=rv64gc", "-mabi=lp64d", "-O2", "-fno-optimize-sibling-calls", "-S", str(probe), "-o", str(assembly)], tmp_path)
    assert result.returncode == 0, result.stderr
    output = assembly.read_text()
    assert re.search(r"sd\s+zero,\s*0\(sp\)", output)
    assert re.search(r"mv\s+a3,\s*a0", output)
    assert re.search(r"li\s+a4,\s*2", output)


@pytest.mark.parametrize("correct", (True, False))
def test_vadd_repeated_output_is_detected(tmp_path, correct):
    stub = '#include <stdint.h>\n#include <stddef.h>\nvoid vadd_rvv(int32_t*a,int32_t*b,int32_t*c,size_t n){for(size_t i=0;i<n;i++)c[i]=' + ('a[i]+b[i]' if correct else 'a[0]+b[0]') + ';}'
    binary = compile_c(tmp_path, VERIFY / "vadd_rvv/main.c", stub)
    assert (run([str(binary)], tmp_path).returncode == 0) == correct


@pytest.mark.parametrize("name", ("paired.c", "translated.c"))
def test_q3_partition_rejects_unassigned_row_groups(tmp_path, name):
    text = (VERIFY / "rvv_q3_gemm" / name).read_text()
    start = text.index('    if (m < 8', text.index('int main('))
    end = text.index('    stride =', start)
    guard = text[start:end].replace('    omp_set_dynamic(0);\n', '')
    source = tmp_path / "partition.c"
    source.write_text('#include <stdio.h>\n#include <stdlib.h>\nenum {THREADS=8};\nint main(int c,char**v){int m=32,n=atoi(v[1]),k=256;\n' + guard + '\nreturn 0;}')
    binary = compile_c(tmp_path, source, '')
    for n in (256, 320, 384, 448, 512, 2048, 5632):
        assert (run([str(binary), str(n)], tmp_path).returncode == 0) == (n not in (320, 384, 448))


def test_kde_endpoint_mode_and_insufficient_samples():
    full = load('ime_q3_gemm/summarize_full.py')
    values = [1.0] * 49 + [1000000.0]
    bandwidth = statistics.stdev(values) * len(values) ** -.2
    for scale in (.5, 1, 2):
        assert full.kde_mode(values, bandwidth * scale) == pytest.approx(1.0, abs=.001)
    simple = load('ime_q3_gemm/summarize.py')
    for values in ([], [1.0], [1.0, math.nan]):
        with pytest.raises(ValueError, match='at least two'):
            simple.kde_mode(values)


def valid_record(case, direction, workload):
    profile = workload['paths'][direction]
    source, target = profile['source_vlen_bits'] // 8, profile['target_vlen_bits'] // 8
    workers = [dict(cpu_before=cpu, cpu_after=cpu, vlenb_before=target, vlenb_after=target,
                    frequency_before_khz=profile['frequency_khz'], frequency_after_khz=profile['frequency_khz'])
               for cpu in profile['worker_cpus']]
    return dict(case, validation='PASS', max_abs_error=0, canaries_and_inputs_intact=True,
                translation_state_intact=True, source_vlenb=source, target_vlenb=target,
                source_state_vlenb=[source]*8, threads=8, worker_environment=workers,
                affinity_masks=[1 << cpu for cpu in profile['worker_cpus']], samples=50,
                seconds_per_call=[.001+i*.000001 for i in range(50)])


@pytest.mark.parametrize('optimized', (False, True))
@pytest.mark.parametrize('bad_field', ('validation', 'affinity_masks', 'max_abs_error', None))
def test_summary_rejects_failed_json_under_python_optimization(tmp_path, optimized, bad_field):
    workload = json.loads((VERIFY/'rvv_q3_gemm/workload.json').read_text())
    for case in workload['cases']:
        for direction in ('forward', 'reverse'):
            record = valid_record(case, direction, workload)
            if bad_field is not None:
                record[bad_field] = {'validation':'FAIL','affinity_masks':[], 'max_abs_error':2}[bad_field]
            (tmp_path/f"{case['name']}-{direction}-full.json").write_text(json.dumps(record))
    command = [sys.executable, *(['-O'] if optimized else []), str(VERIFY/'rvv_q3_gemm/summarize.py'), str(tmp_path)]
    result = run(command, tmp_path)
    if bad_field is None:
        assert result.returncode == 0, result.stderr
        assert len(json.loads((tmp_path/'summary.json').read_text())['rows']) == 8
    else:
        assert result.returncode != 0 and 'validation failed' in result.stderr
        assert bad_field in result.stderr and 'NameError' not in result.stderr
        assert not (tmp_path/'summary.json').exists()


@pytest.mark.parametrize('workers', (0, 7, 9))
def test_paired_summary_requires_every_worker(tmp_path, workers):
    workload = json.loads((VERIFY/'rvv_q3_gemm/workload.json').read_text())
    case = workload['cases'][0]
    base = valid_record(case, 'forward', workload)
    sample = dict(validation='PASS', max_abs_error=0, canaries_and_inputs_intact=True,
                  worker_environment=(base['worker_environment']*2)[:workers])
    base.update(case=case['name'], samples=20, state_mode='independent TLS per variant', initial_gate_errors=[0,0],
                source_state_vlenb_baseline=[128]*8, source_state_vlenb_candidate=[128]*8,
                pair_orders=['AB','BA']*10, seconds_per_call_baseline=[.001]*20,
                seconds_per_call_candidate=[.0009]*20,
                pairs=[dict(pair=i, order='AB' if i%2==0 else 'BA', gain=.001/.0009,
                            baseline=dict(sample, seconds_per_call=.001),
                            candidate=dict(sample, seconds_per_call=.0009)) for i in range(20)],
                input_hashes={'w':'hash'})
    (tmp_path/'record.json').write_text(json.dumps(base))
    result = run([sys.executable, '-O', str(VERIFY/'rvv_q3_gemm/summarize_paired.py'), str(tmp_path)], tmp_path)
    assert result.returncode != 0 and 'eight worker' in result.stderr


def test_statecheck_template_drift_is_rejected(monkeypatch):
    checker = load('rvv_q3_gemm/statecheck.py')
    with pytest.raises(ValueError, match='expected one'):
        checker.replace_once('no marker', 'marker missing', 'replacement')
    with pytest.raises(ValueError, match='expected one'):
        checker.replace_once('xx', 'x', 'replacement')
    for direction in ('forward','reverse'):
        generated = checker.c_source([{'command':'vmacc.vx v8, a0, v16'}], direction)
        assert 'input_vstart' in generated and 'actual_vstart' in generated


def test_runner_action_tools_and_quoted_flags(monkeypatch, tmp_path):
    runner = load('run_verify.py')
    monkeypatch.setattr(runner, 'tool_exists', lambda tool: tool == 'cc')
    assert runner.check_server_env(cc='cc') == 0
    assert runner.check_server_env(qemu='qemu') == 1
    commands = []
    monkeypatch.setattr(runner, 'run_cmd', lambda command, cwd: commands.append(command))
    runner.build_case(runner.CASES['vadd_rvv'], 'cc', '-O2 -DNAME="a b"')
    assert commands[0][2] == '-DNAME=a b'
    with pytest.raises(SystemExit, match='invalid --cflags'):
        runner.build_case(runner.CASES['vadd_rvv'], 'cc', '-DNAME="')


def test_codegen_store_metrics_and_profile_identity():
    report = load('rvv256_wide/report_codegen.py')
    text = '\n'.join(('vsll.vi v8, v9, 1','vslideup.vi v8, v9, 1','vse32.v v8, (a0)',
                      'vsseg4e64.v v8, (a0)','vs1r.v v8, (a0)','vsm.v v0, (a0)',
                      'vsoxei32.v v8, (a0), v9','vsoxseg2ei32.v v8, (a0), v10',
                      '# RVV256-WIDE:', '# RVV256-WIDE-MASKED:', '# RVV256-WIDE-MASKED-COMMIT'))
    metrics = report.assembly_metrics(text)
    assert metrics['vector_stores'] == 6
    assert metrics['wide_blocks'] == 1
    runner = load('rvv256_wide/run_verify.py')
    assert not runner.expected_optimization(runner.CASES['vadd_e32_m8'], '# RVV256-NATIVE-MASK')
    for case in runner.CASES.values():
        assembly = runner.translate(runner.AsmParser().parse_string(case.command), init_vtype=case.vtype,
                                    func_name='translated_func', tls_state=False, wide_lmul=case.wide_lmul)
        assert runner.expected_optimization(case, assembly), case.name


def test_ime_stack_checker_covers_failure_branch():
    runner = load('ime_rvv/run_verify.py')
    assembly = 'addi sp, sp, -32\nbnez t0, .Lfail\naddi sp, sp, 32\nret\n.Lfail:\naddi sp, sp, 32\nunimp'
    runner.check_stack_frame(assembly, 32)
    with pytest.raises(ValueError, match='bound'):
        runner.check_stack_frame(assembly, 16)
    with pytest.raises(ValueError, match='unbalanced'):
        runner.check_stack_frame('addi sp, sp, -32\nret', 32)


def test_full_runner_timeout_keeps_partial_output(monkeypatch, tmp_path):
    runner = load('ime_q3_gemm/run_full.py')
    monkeypatch.setattr(runner, 'ROOT', tmp_path)
    monkeypatch.setattr(runner, 'CASES', [('case', 32, 256, 256)])
    monkeypatch.setattr(runner, 'environment', lambda: {})
    def timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired(args[0], 900, output=b'partial stdout', stderr=b'partial stderr')
    monkeypatch.setattr(runner.subprocess, 'run', timeout)
    with pytest.raises(RuntimeError, match='timed out after 900s'):
        runner.main()
    assert (tmp_path/'case-rvv_baseline.stdout').read_bytes() == b'partial stdout'
    assert (tmp_path/'case-rvv_baseline.stderr').read_bytes() == b'partial stderr'
    assert not (tmp_path/'full-done').exists()


def test_full_runner_observer_error_is_not_a_success(monkeypatch, tmp_path):
    import threading
    import time
    runner = load('ime_q3_gemm/run_full.py')
    monkeypatch.setattr(runner, 'ROOT', tmp_path)
    monkeypatch.setattr(runner, 'CASES', [('case', 32, 256, 256)])
    original_event = threading.Event
    class FastEvent:
        def __init__(self): self.event = original_event()
        def set(self): self.event.set()
        def is_set(self): return self.event.is_set()
        def wait(self, timeout=None): return self.event.wait(.001)
    def environment():
        if threading.current_thread() is not threading.main_thread():
            raise OSError('injected cpufreq failure')
        return {}
    def complete(*args, **kwargs):
        time.sleep(.02)
        return subprocess.CompletedProcess(args[0], 0, '{}', '')
    monkeypatch.setattr(runner, 'environment', environment)
    monkeypatch.setattr(runner.threading, 'Event', FastEvent)
    monkeypatch.setattr(runner.subprocess, 'run', complete)
    with pytest.raises(RuntimeError, match='environment sampling failed'):
        runner.main()
    assert 'injected' in (tmp_path/'case-rvv_baseline.environment-errors.json').read_text()
    assert not (tmp_path/'full-done').exists()


def test_prepare_manifest_excludes_previous_outputs(monkeypatch, tmp_path):
    runner = load('rvv_bidirectional_hotspots/prepare.py')
    import rvv_sbt_rvv
    import rvv_sbt_rvv1024
    calls = []
    def translate(function, **options):
        calls.append(options)
        return '.text\nret\n'
    monkeypatch.setattr(rvv_sbt_rvv, 'translate_function', translate)
    monkeypatch.setattr(rvv_sbt_rvv1024, 'translate_function', translate)
    source = tmp_path/'snapshot.json'
    source.write_text(json.dumps({'elf':'fixture','sha256':'fixed', 'functions':{
        name:f'0000000000000000 <{name}>:\n  0: 00008067 ret\n'
        for name in runner.OPERATORS.values()}}))
    output = tmp_path/'payload'
    runner.prepare(source, output, ROOT)
    (output/'stale.o').write_text('not a produced file')
    runner.prepare(source, output, ROOT)
    manifest = json.loads((output/'manifest.json').read_text())
    assert 'stale.o' not in manifest['payload_sha256']
    assert 'manifest.json' not in manifest['payload_sha256']
    assert calls and all(call['strict'] for call in calls)
    import hashlib
    for name, digest in manifest['payload_sha256'].items():
        assert hashlib.sha256((output/name).read_bytes()).hexdigest() == digest


def test_benchmark_numeric_boundary_helpers(tmp_path):
    text = (VERIFY/'rvv_bidirectional_hotspots/bench.c').read_text()
    start = text.index('static void fail(')
    end = text.index('static uint64_t hash_bytes(', start)
    source = tmp_path/'numeric.c'
    source.write_text('#include <errno.h>\n#include <math.h>\n#include <stdio.h>\n#include <stdlib.h>\n' + text[start:end] +
                      '\nint main(int c,char**v){if(v[1][0]==\'i\')integer_argument(v[2],0,100);else sample_duration(v[2]);return 0;}')
    binary = compile_c(tmp_path, source, '')
    for kind, value, valid in [('i','2',True),('i','2x',False),('i','101',False),('i','999999999999999999999',False),
                               ('d','100',True),('d','nan',False),('d','inf',False),('d','0',False),('d','1x',False)]:
        assert (run([str(binary),kind,value],tmp_path).returncode == 0) == valid


def test_board_setup_failure_does_not_launch_benchmark(tmp_path):
    source = (VERIFY/'ime_q3_gemm/run-board.sh').read_text()
    script = tmp_path/'run-board.sh'
    start = source.index('environment() {')
    end = source.index("\nprintf 'environment-before", start)
    source = source[:start] + 'environment() { :; }\n' + source[end:]
    script.write_text(source.replace('printf 0 > /proc/set_ai_thread', 'false'))
    # Only the environment probes run; the measured command must remain unreachable.
    result = subprocess.run(['sh',str(script)],cwd=tmp_path,text=True,capture_output=True,
                            env={**os.environ,'TMPDIR':str(tmp_path)})
    assert result.returncode != 0
    assert (tmp_path/'run-stage.txt').read_text() == 'setup\n'
    assert (tmp_path/'exit-status.txt').read_text().strip() != '0'
    assert (tmp_path/'results.jsonl').read_text() == ''


def test_build_scripts_reject_bad_inputs_before_tools(tmp_path):
    for name, args in [('build.sh', ['/absolute/a','/absolute/b','/absolute/c','0']),
                       ('build_paired.sh',['forward','relative.o','also-relative.o','50'])]:
        script = tmp_path/name
        script.write_text((VERIFY/'rvv_q3_gemm'/name).read_text())
        result = run(['sh',str(script),*args],tmp_path)
        assert result.returncode == 2
        assert ('samples must' if name == 'build.sh' else 'must be absolute') in result.stderr


def test_paired_driver_requires_selected_baseline_module(tmp_path):
    baseline, candidate = tmp_path/'base', tmp_path/'candidate'
    baseline.mkdir();candidate.mkdir()
    result = run([sys.executable,str(VERIFY/'rvv_bidirectional_hotspots/paired.py'),
                  '--baseline',str(baseline),'--candidate',str(candidate),'--direction','forward'],tmp_path)
    assert result.returncode != 0 and 'missing baseline driver' in result.stderr
    (baseline/'run.py').write_text('def command(*args): return ["wrong-binary"]\n')
    for path in (baseline,candidate): (path/'bench-forward').write_text('mock')
    result = run([sys.executable,str(VERIFY/'rvv_bidirectional_hotspots/paired.py'),
                  '--baseline',str(baseline),'--candidate',str(candidate),'--direction','forward'],tmp_path)
    assert result.returncode != 0 and 'exactly once' in result.stderr
    manifest = json.loads((candidate/'paired-manifest.json').read_text())
    assert not manifest['complete']
    assert set(manifest['binary_sha256']) == {'baseline/forward','candidate/forward'}


def test_ime_calibration_bounds_the_slowest_implementation(tmp_path):
    text = (VERIFY/'ime_q3_gemm/bench.c').read_text()
    start = text.index('    if(!rounds) {')
    end = text.index('    printf(', start)
    source = tmp_path/'calibration.c'
    source.write_text('#include <stdint.h>\nstatic uint64_t elapsed;\nstatic uint64_t now(void){return elapsed;}\n'
                      'static void invoke(int impl){const uint64_t costs[]={2,2000,3};elapsed+=costs[impl];}\n'
                      'int main(void){int rounds=0;\n'+text[start:end]+'\nreturn rounds!=1000;}')
    binary = compile_c(tmp_path, source, '')
    assert run([str(binary)], tmp_path).returncode == 0


@pytest.mark.parametrize('corruption', (None, 'array', 'order', 'index', 'gain'))
def test_paired_summary_checks_cross_record_consistency(tmp_path, corruption):
    workload = json.loads((VERIFY/'rvv_q3_gemm/workload.json').read_text())
    case = workload['cases'][0]
    record = valid_record(case, 'forward', workload)
    sample = dict(validation='PASS', max_abs_error=0, canaries_and_inputs_intact=True,
                  worker_environment=record['worker_environment'])
    record.update(case=case['name'], samples=20, state_mode='independent TLS per variant',
                  initial_gate_errors=[0,0], source_state_vlenb_baseline=[128]*8,
                  source_state_vlenb_candidate=[128]*8, pair_orders=['AB','BA']*10,
                  seconds_per_call_baseline=[.001]*20, seconds_per_call_candidate=[.001]*20,
                  pairs=[dict(pair=i, order='AB' if i%2==0 else 'BA', gain=1.0,
                              baseline=dict(sample, seconds_per_call=.001),
                              candidate=dict(sample, seconds_per_call=.001)) for i in range(20)],
                  input_hashes={'w':'hash'})
    if corruption == 'array':
        record['seconds_per_call_candidate'][0] = .0005
        record['pairs'][0]['gain'] = 2.0
    elif corruption == 'order': record['pairs'][0]['order'] = 'BA'
    elif corruption == 'index': record['pairs'][0]['pair'] = 1
    elif corruption == 'gain': record['pairs'][0]['gain'] = 3.0
    (tmp_path/'record.json').write_text(json.dumps(record))
    result = run([sys.executable,'-O',str(VERIFY/'rvv_q3_gemm/summarize_paired.py'),str(tmp_path)],tmp_path)
    if corruption is None:
        assert result.returncode == 0, result.stderr
        summary = json.loads((tmp_path/'summary.json').read_text())
        assert len(summary['rows']) == 1  # A requested case subset remains valid.
        assert summary['rows'][0]['paired_median_time_reduction_percent'] == 0
    else:
        assert result.returncode != 0 and 'pair=0' in result.stderr
        assert not (tmp_path/'summary.json').exists()


def test_paired_summary_rejects_empty_directory(tmp_path):
    result = run([sys.executable,'-O',str(VERIFY/'rvv_q3_gemm/summarize_paired.py'),str(tmp_path)],tmp_path)
    assert result.returncode != 0 and 'no paired measurement records' in result.stderr
    assert not (tmp_path/'summary.json').exists()
