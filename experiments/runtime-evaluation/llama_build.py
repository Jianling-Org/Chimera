# SPDX-License-Identifier: Apache-2.0
"""Check the effective scalar-control options in a fresh CMake command export."""
import re
import shlex
import argparse
import hashlib
import json
from pathlib import Path

CONTROL_TARGETS = ('llama', 'llama-common', 'llama-common-base', 'cpp-httplib',
                   'llama-perplexity-impl', 'llama-perplexity')


def require_no_autovec(argv, filename):
    # Later -O options have re-enabled vectorization in this toolchain.
    last_optimization = max((i for i, arg in enumerate(argv)
                             if re.fullmatch(r'-O(?:[0-3szg]|fast)', arg)), default=-1)
    for enable, disable in (('-fvectorize', '-fno-vectorize'),
                            ('-fslp-vectorize', '-fno-slp-vectorize')):
        last_enable = max((i for i, arg in enumerate(argv) if arg == enable), default=-1)
        last_disable = max((i for i, arg in enumerate(argv) if arg == disable), default=-1)
        if last_disable <= max(last_enable, last_optimization):
            raise ValueError('Vectorization options are missing or overridden: '+filename)


def audit_scalar_control(commands):
    targets = {}
    vector_rows = 0
    for row in commands:
        argv = row.get('arguments') or shlex.split(row['command'])
        output = row.get('output', '') or (argv[argv.index('-o')+1] if '-o' in argv else '')
        match = re.search(r'CMakeFiles/([^/]+)\.dir/', output)
        if not match:
            continue
        target = match[1]
        marches = [arg for arg in argv if arg.startswith('-march=')]
        if target.startswith('ggml'):
            require_no_autovec(argv, row['file'])
            vector_rows += bool(marches and re.match(r'-march=rv64[^_]*v', marches[-1]))
        if target not in CONTROL_TARGETS:
            continue
        if not marches or marches[-1] != '-march=rv64gc':
            raise ValueError('Control target is not scalar: '+row['file'])
        require_no_autovec(argv, row['file'])
        targets[target] = targets.get(target, 0)+1
    if not {'llama', 'llama-perplexity'} <= targets.keys():
        raise ValueError('Missing compiled llama control targets')
    if not vector_rows:
        raise ValueError('No ggml compilation with RVV enabled')
    return dict(passed=True, control_targets=targets, ggml_rvv_commands=vector_rows)


def scalar_build_record(elf, control, commands, source_commit):
    if not re.fullmatch(r'[0-9a-f]{40}', source_commit):
        raise ValueError('Pin the measured Chimera source commit')
    def digest(path):
        value=hashlib.sha256()
        with Path(path).open('rb') as stream:
            for block in iter(lambda:stream.read(1024**2),b''):
                value.update(block)
        return value.hexdigest()
    audit=audit_scalar_control(json.loads(Path(commands).read_text(encoding='utf-8')))
    return dict(protocol='llama-scalar-retest-v1',source_commit=source_commit,
                elf_sha256=digest(elf),scalar_control_sha256=digest(control),
                compile_commands_sha256=digest(commands),control_compile_audit=audit)


if __name__ == '__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--elf',type=Path,required=True)
    parser.add_argument('--scalar-control',type=Path,required=True)
    parser.add_argument('--compile-commands',type=Path,required=True)
    parser.add_argument('--source-commit',required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    record=scalar_build_record(args.elf,args.scalar_control,args.compile_commands,args.source_commit)
    with args.output.open('x',encoding='utf-8') as stream:
        stream.write(json.dumps(record,indent=2)+'\n')
