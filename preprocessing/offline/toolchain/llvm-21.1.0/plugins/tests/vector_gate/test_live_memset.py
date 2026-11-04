"""Native K3 check: an RVV value survives compiler-owned fill without a libcall."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import time


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('compiler', 'plugin', 'reference-plugin', 'native-launcher'):
        p.add_argument('--'+name, required=True)
    p.add_argument('--output', required=True, type=Path)
    a = p.parse_args()
    out = a.output
    out.mkdir(exist_ok=False)
    source = Path(__file__).with_name('live-memset.c')
    gate = out/'gate.txt'
    gate.write_text('gated_live_memset\n')
    environment = dict(os.environ, CHIMERA_GATE_LIST=str(gate))
    for key in ('LD_PRELOAD', 'LD_AUDIT', 'LD_PROFILE', 'CHIMERA_BOOTSTRAP',
                'CHIMERA_REGISTRY', 'CHIMERA_AUTOMIGRATE', 'CHIMERA_LAUNCH_PID'):
        environment.pop(key, None)
    commands = []

    def run(argv, name, *, env=environment):
        started = time.monotonic()
        r = subprocess.run(list(map(str, argv)), capture_output=True, env=env, timeout=120)
        (out/(name+'.stdout')).write_bytes(r.stdout)
        (out/(name+'.stderr')).write_bytes(r.stderr)
        row = dict(name=name, argv=list(map(str, argv)), returncode=r.returncode,
                   started_monotonic=started, ended_monotonic=time.monotonic())
        commands.append(row)
        with (out/'commands.jsonl').open('a') as f:
            f.write(json.dumps(row)+'\n')
        if r.returncode:
            raise AssertionError(name+': '+r.stderr.decode(errors='replace'))
        return r.stdout.decode()

    base = [a.compiler, '-O2', '-march=rv64gcv', '-mabi=lp64d', source]
    for name, library in [('original', a.reference_plugin), ('candidate', a.plugin)]:
        run([*base, '-fpass-plugin='+library, '-S', '-o', out/(name+'.s')], name+'-assembly')
    pattern = r'^gated_live_memset:.*?(?=^\s*\.size\s+gated_live_memset)'
    old = re.search(pattern, (out/'original.s').read_text(), re.M | re.S).group(0)
    new = re.search(pattern, (out/'candidate.s').read_text(), re.M | re.S).group(0)
    assert re.search(r'\b(?:call|tail)\s+memset', old), 'Reference did not reproduce the native-call boundary'
    assert not re.search(r'\b(?:call|tail)\s+memset', new), 'Candidate still calls native memset'
    assert 'vle32.v' in new and 'vse32.v' in new, 'Explicit RVV disappeared'
    binary = out/'live-memset'
    run([*base, '-fpass-plugin='+a.plugin, '-o', binary], 'candidate-binary')
    results = []
    for group, width, cpus in [('x100', 32, set(range(8))), ('a100', 128, set(range(8, 16)))]:
        row = json.loads(run([a.native_launcher, group, binary], group+'-execution'))
        assert row['passed'] and row['cases'] == 63 and row['vlenb'] == width and row['cpu'] in cpus
        results.append(dict(group=group, **row))
    (out/'verification.json').write_text(json.dumps(dict(passed=True, commands=commands,
        results=results, binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest()), indent=2)+'\n')
    print('PASS: native-call boundary removed; explicit RVV retained; 63 cases on each VLEN')


if __name__ == '__main__':
    main()
