#!/usr/bin/env python3
"""One bounded, auditable phase of the authorized GCC validation."""
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import time

R=Path('/root/chimera-gcc-validation-578ab8321')
S=R/'source'
PY=R/'venv/bin/python'
PROFILE=R/'profile.gcc.toml'
GCC_SOURCE=Path('/root/yangzheng/gcc-rebuild/gcc-15-15.2.0/gcc-15.2.0')
OLD=Path('/root/yangzheng/newest-chimera/gcc-validation-20261021-kcpZul')

def sha(path):
    h=hashlib.sha256()
    with Path(path).open('rb') as f:
        for b in iter(lambda:f.read(4*1024*1024),b''):h.update(b)
    return h.hexdigest()

def record(name,obj):
    p=R/name;p.parent.mkdir(parents=True,exist_ok=True)
    p.write_text(json.dumps(obj,indent=2)+'\n')

def run(args,**kw):
    print('COMMAND',shlex.join([str(a) for a in args]),flush=True)
    return subprocess.run([str(a) for a in args],check=True,**kw)

def source_imports():
    sys.path[:0]=[str(S/'cli'),str(S)]
    sys.meta_path[:]=[f for f in sys.meta_path if type(f).__name__!='ScikitBuildRedirectingFinder']

def cli(role,*args):
    return [str(PY),str(S/'tools/run_source_cli.py'),role,*map(str,args)]

def configure_profile():
    # Bootstrap uses native PT_INTERP and actual native dependencies. An empty
    # scalar base avoids substituting a different libc/loader in this experiment.
    (R/'native-scalar-base').mkdir(exist_ok=True)
    text=(S/'examples/platforms/k3/linux-riscv64-rvv-1024-256-bidirectional.toml').read_text()
    text=text.replace('data_root = "~/.chimera/data"',f'data_root = "{R}/data"\nworkspace_root = "{R}/workspaces"')
    text=text.replace('scalar_root = "~/.chimera/scalar"',f'scalar_root = "{R}/native-scalar-base"')
    text=text.replace('../../../preprocessing/',str(S/'preprocessing')+'/')
    text=text.replace('parameters = { min_vlen_bits = 256, compiler_metadata = [] }',
        'parameters = { min_vlen_bits = 256, compiler_metadata = [], unknown_stack_size_policy = "assume-scalar-independent" }')
    assert 'unknown_stack_size_policy' in text and text.count('step = "translate"')==2
    PROFILE.write_text(text)
    (R/'user.toml').write_text(f'[runtime]\nworkspace_root = "{R}/workspaces"\nbpf_map = "/sys/fs/bpf/pid_uprobe_map"\nai_thread_control = "/proc/set_ai_thread"\n')

def preflight():
    assert (R/'setup.done').exists()
    assert subprocess.check_output(['uname','-r'],text=True).strip()=='6.18.3-chimera-d02cd7352'
    if not PY.exists():run(['/usr/bin/python3','-m','venv',R/'venv'])
    run([PY,'-m','pip','install','--disable-pip-version-check','pyelftools==0.33','pytest==9.1.1'])
    configure_profile()
    for name in ('bin','reports','plans','workspaces','tmp','probes','stage-results'):(R/name).mkdir(exist_ok=True)
    for role in ('pkg','user','dev'):
        p=R/'bin'/('chimera-'+role)
        p.write_text('#!/bin/sh\nexec '+shlex.join([str(PY),str(S/'tools/run_source_cli.py'),role])+' "$@"\n')
        p.chmod(0o755)
    for old in (Path('/root/.chimera/elf_registry.json'),Path('/root/.chimera/check_elf/latest.json')):
        backup=R/'provenance'/('shared-before-'+old.name)
        if old.exists() and not backup.exists():shutil.copy2(old,backup)
    run([PY,'-c','import sys,elftools;print(sys.version);print("pyelftools",elftools.__version__)'])
    run([R/'bin/chimera-pkg','--help'])
    run(['cmake','-S',S/'runtime','-B',R/'build/runtime',
         '-DCMAKE_BUILD_TYPE=Release','-DCHIMERA_BUILD_RUNTIME=ON',
         '-DCHIMERA_BUILD_BOOTSTRAP=ON','-DCHIMERA_BUILD_TESTS=OFF',
         '-DCHIMERA_TARGET_OS=linux','-DCHIMERA_TARGET_ARCH=riscv64',
         '-DCHIMERA_TARGET_EXTENSION=rvv','-DCHIMERA_SCENE=linux_riscv64_rvv_v1',
         '-DCMAKE_C_FLAGS=-march=rv64gcv -mabi=lp64d -fno-tree-vectorize'])
    run(['cmake','--build',R/'build/runtime','--parallel','2'])
    # Contract tests use assert(); a Release/NDEBUG test build would erase
    # assertions and also fail their -Werror unused-variable checks.
    run(['cmake','-S',S/'runtime','-B',R/'build/contracts',
         '-DCMAKE_BUILD_TYPE=Debug','-DCHIMERA_BUILD_RUNTIME=OFF',
         '-DCHIMERA_BUILD_BOOTSTRAP=OFF','-DCHIMERA_BUILD_TESTS=ON',
         '-DCMAKE_C_FLAGS=-march=rv64gcv -mabi=lp64d -fno-tree-vectorize'])
    run(['cmake','--build',R/'build/contracts','--parallel','2'])
    run(['ctest','--test-dir',R/'build/contracts','--output-on-failure'])
    tests=['test_bootstrap_exec.py','test_bootstrap_registry.py','test_bootstrap_preference.py',
           'test_compiler_plan.py','test_gate_candidates.py','test_llvm_wrapper.py','test_write_gate_wrapper.py']
    run([PY,'-m','pytest','-q',*[S/'tests'/t for t in tests]],cwd=S)
    tool=R/'toolchain'
    run([tool/'llvm/bin/clang','--version'])
    # Prove compiler/plugin policy on a profitable loop, an ungated control,
    # and explicit RVV which a gate must preserve.
    p=R/'probes'
    code='''void gated(float *restrict a,const float *restrict b,int n){for(int i=0;i<n;i++)a[i]=b[i]+1.0f;}
void open_loop(float *restrict a,const float *restrict b,int n){for(int i=0;i<n;i++)a[i]=b[i]+1.0f;}
void gated_explicit(float *a,const float *b){__asm__ volatile("vsetivli zero,4,e32,m1,ta,ma\\n\\tvle32.v v1,(%1)\\n\\tvse32.v v1,(%0)"::"r"(a),"r"(b):"v1","memory");}
'''
    (p/'gate.c').write_text(code);(p/'gate.txt').write_text('gated\ngated_explicit\n')
    (p/'census.tsv').write_text('')
    probe_env=dict(os.environ,CHIMERA_GATE_LIST=str(p/'gate.txt'),CHIMERA_GATE_STATS=str(p/'census.tsv'))
    run([tool/'llvm/bin/clang','-O2','-march=rv64gcv','-mabi=lp64d',
         '-fpass-plugin='+str(tool/'plugins/lib/chimera/llvm/ChimeraVectorGate.so'),
         '-S',p/'gate.c','-o',p/'gate.s'],env=probe_env)
    asm=(p/'gate.s').read_text()
    def body(name):
        found=re.search(r'^'+name+r':.*?(?=^\s*\.Lfunc_end\d+:)',asm,re.M|re.S)
        assert found,name
        return found[0]
    assert not re.search(r'\bvsetvli\b|\bvsetivli\b',body('gated'))
    assert re.search(r'\bvsetvli\b|\bvsetivli\b',body('open_loop'))
    assert 'vle32.v' in body('gated_explicit')
    census=(p/'census.tsv').read_text()
    assert 'implicit-vector-census\tLV\tgated\tblocked' in census
    assert 'implicit-vector-census\tLV\topen_loop\tformed' in census
    if (p/'stack.c').exists() and not (p/'stack-v1-fixed-array.c').exists():
        shutil.copy2(p/'stack.c',p/'stack-v1-fixed-array.c')
    # A fixed scalar array is not a guaranteed RVV spill. Keep a live RVV
    # value across an opaque call to exercise the documented backend path.
    (p/'stack.c').write_text('''#include <riscv_vector.h>
#include <stddef.h>
extern void opaque(void);
void metadata_probe(float *p,size_t n){size_t vl=__riscv_vsetvl_e32m1(n);vfloat32m1_t v=__riscv_vle32_v_f32m1(p,vl);opaque();__riscv_vse32_v_f32m1(p,v,vl);}
''')
    run([tool/'llvm/bin/clang','-O2','-g','-march=rv64gcv','-mabi=lp64d',
         '-fpass-plugin='+str(tool/'plugins/lib/chimera/llvm/ChimeraStackObject.so'),
         '-c',p/'stack.c','-o',p/'stack.o'])
    sections=subprocess.check_output(['readelf','-SW',str(p/'stack.o')],text=True)
    (p/'stack.sections.txt').write_text(sections)
    assert '.chimera.stackobj' in sections,'Stack-object plugin probe emitted no metadata'
    # Compare production sources to the source tree identified by the prior
    # toolchain record; separately retained tests are not a build identity.
    current=S/'preprocessing/offline/toolchain/llvm-21.1.0'
    previous=Path('/root/yangzheng/newest-chimera/Chimera/preprocessing/offline/toolchain/llvm-21.1.0')
    comparison=[]
    for part in ('plugins/plugins','plugins/common','patches'):
        for path in (current/part).rglob('*'):
            if path.is_file():
                old=previous/path.relative_to(current)
                relative=path.relative_to(current).as_posix()
                comparison.append({'path':relative,'same':old.is_file() and sha(path)==sha(old),
                                   'consumed_by_gate_route':not relative.startswith('plugins/plugins/svf/')})
    record('probes/toolchain-production-source-comparison.json',comparison)
    consumed=[row for row in comparison if row['consumed_by_gate_route']]
    assert consumed and all(row['same'] for row in consumed),'Consumed toolchain production source mismatch'
    # Only stack-object and vector-gate DSOs are present in the reused
    # toolchain. The gate-plan API explicitly rejects any SVF/function-pointer
    # decision, so changed, uninstalled SVF sources are not a reused component.
    record('probes/toolchain-reuse-scope.json',{
        'required_components':['patched LLVM','ChimeraStackObject.so','ChimeraVectorGate.so'],
        'required_sources_identical':len(consumed),
        'not_consumed_differences':[row for row in comparison if not row['same']],
        'svf_guard':'publish_rebuild_plan(stage=gate) and load_rebuild_plan reject function-pointer/SVF decisions'})
    # Preserve actual native dependency paths and contents for the final
    # bootstrap environment, without declaring them scalar by substitution.
    deps={}
    for name in ('xgcc','cc1'):
        program=R/'inputs/metadata'/name
        text=subprocess.check_output(['/lib/ld-linux-riscv64-lp64d.so.1','--list',str(program)],text=True)
        deps[name]={'loader_list':text,'files':[]}
        for path in re.findall(r'(?:=>\s*)?(/[^\s()]+)',text):
            f=Path(path).resolve()
            if f.is_file():deps[name]['files'].append({'path':str(f),'sha256':sha(f)})
    record('native-dependencies.json',deps)
    record('preflight-summary.json',{'passed':True,'scope':'conditional assume-scalar-independent; min_vlen_bits=256',
         'dependencies':'native target-resolved; no scalar substitution','profile_sha256':sha(PROFILE),
         'source_commit':subprocess.check_output(['git','-C',str(S),'rev-parse','HEAD'],text=True).strip()})

def check(program,stage,strict=False):
    elf=R/'inputs/metadata'/program if stage=='metadata' else R/'build-gate/gcc'/program
    report=R/'reports'/f'{stage}-{program}.json'
    inheritance=R/'reports'/f'{stage}-{program}.inheritance.json'
    args=cli('pkg','--debug','check-elf','--profile',PROFILE,'--strategy','gate','--input',elf,
             '--json',report,'--inheritance-report',inheritance)
    if strict:args.append('--strict')
    run(args)
    d=json.loads(report.read_text())
    assert d.get('checks'),'No executed checks in report'
    if strict:assert d.get('passed') is True and not d.get('findings'),(program,d.get('passed'))
    record(f'reports/{stage}-{program}.summary.json',{
        'elf':str(elf),'elf_sha256':sha(elf),'report_sha256':sha(report),
        'passed':d.get('passed'),'findings':len(d.get('findings',[])),
        'conditional':d.get('conditional'),'summary':d.get('summary')})

def gate_plan():
    source_imports()
    from chimera.compiler_plan import publish_rebuild_plan
    plan=R/'plans/gate';plan.mkdir(parents=True,exist_ok=True)
    publish_rebuild_plan(plan,stage='gate',profile=PROFILE,
        reports=[R/'reports/metadata-xgcc.json',R/'reports/metadata-cc1.json'],
        launcher=[str(PY),str(S/'tools/run_source_cli.py'),'pkg'],gate_candidate_objdump='/usr/bin/objdump')

def gate_configure():
    source_imports()
    from chimera.compiler_plan import load_rebuild_plan
    decision,path=load_rebuild_plan(R/'plans/gate')
    record('plans/gate-validated.json',{'decision_sha256':sha(path),'strategy':decision['strategy'],'gate_count':len(decision['gate']['names'])})
    wrappers=R/'wrappers';wrappers.mkdir()
    run([PY,S/'tools/write_gate_wrapper.py','--wrapper-dir',wrappers,'--pkg',R/'bin/chimera-pkg',
         '--decision',path,'--prefix','fixed'])
    for kind in ('cc','cxx'):
        p=wrappers/kind
        body='#!/bin/sh\nset -eu\nprintf "%s  %s\\n" '+shlex.quote(sha(path))+' '+shlex.quote(str(path))+' | sha256sum -c - >/dev/null\nexec '+shlex.quote(str(wrappers/('fixed-'+kind)))+' "$@"\n'
        p.write_text(body);p.chmod(0o755)
    build=R/'build-gate';build.mkdir()
    configure=[GCC_SOURCE/'configure','--prefix='+str(R/'install-gate'),'--enable-languages=c',
         '--disable-bootstrap','--disable-multilib','--with-system-zlib','--enable-checking=release',
         'CC='+str(wrappers/'cc'),'CXX='+str(wrappers/'cxx'),
         'CC_FOR_BUILD=/usr/bin/gcc','CXX_FOR_BUILD=/usr/bin/g++',
         'CFLAGS=-O2 -g -march=rv64gcv -mabi=lp64d','CXXFLAGS=-O2 -g -march=rv64gcv -mabi=lp64d','LDFLAGS=']
    record('gcc-build-configuration.json',{'argv':list(map(str,configure)),'make':['make','-j2','all-gcc']})
    run(configure,cwd=build)

def prepare(name):
    for program in ('xgcc','cc1'):
        summary=json.loads((R/f'reports/final-{program}.summary.json').read_text())
        assert summary['passed'] is True and summary['findings']==0
        assert summary['elf_sha256']==sha(R/'build-gate/gcc'/program)
    run(cli('pkg','prepare','--profile',PROFILE,'--input',R/'build-gate/gcc'/name,
            '--workspace',name,'--workspace-root',R/'workspaces'))

if __name__=='__main__':
    action=sys.argv[1]
    if action=='preflight':preflight()
    elif action.startswith('metadata_'):check(action.split('_',1)[1],'metadata')
    elif action=='gate_plan':gate_plan()
    elif action=='gate_configure':gate_configure()
    elif action=='gate_build':
        run(['make','-j2','all-gcc'],cwd=R/'build-gate')
        record('gate-elf-identities.json',{name:sha(R/'build-gate/gcc'/name) for name in ('xgcc','cc1')})
    elif action.startswith('strict_'):check(action.split('_',1)[1],'final',True)
    elif action.startswith('prepare_'):prepare(action.split('_',1)[1])
    else:raise SystemExit('Unknown action '+action)
