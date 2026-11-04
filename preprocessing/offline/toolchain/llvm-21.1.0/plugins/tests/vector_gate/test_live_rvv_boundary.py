"""Native K3 regression: callback control has no inherited scalable RVV frame."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import time


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('compiler','plugin','reference-plugin','native-launcher'):
        p.add_argument('--'+name,required=True)
    p.add_argument('--output',required=True,type=Path)
    a=p.parse_args();out=a.output;out.mkdir(exist_ok=False)
    source=Path(__file__).with_name('live-rvv-boundary.c')
    gate=out/'gate.txt';gate.write_text('gated_control\n')
    environment=dict(os.environ,CHIMERA_GATE_LIST=str(gate))
    for key in ('LD_PRELOAD','LD_AUDIT','LD_PROFILE','CHIMERA_BOOTSTRAP',
                'CHIMERA_REGISTRY','CHIMERA_AUTOMIGRATE','CHIMERA_LAUNCH_PID'):
        environment.pop(key,None)
    commands=[]

    def run(argv,name,env=environment):
        started=time.monotonic()
        r=subprocess.run(list(map(str,argv)),capture_output=True,env=env,timeout=120)
        (out/(name+'.stdout')).write_bytes(r.stdout);(out/(name+'.stderr')).write_bytes(r.stderr)
        row=dict(name=name,argv=list(map(str,argv)),returncode=r.returncode,
                 started_monotonic=started,ended_monotonic=time.monotonic())
        commands.append(row)
        with (out/'commands.jsonl').open('a') as f:f.write(json.dumps(row)+'\n')
        assert r.returncode==0,(name,r.stderr.decode(errors='replace'))
        return r.stdout.decode()

    base=[a.compiler,'-O2','-march=rv64gcv','-mabi=lp64d',source]
    for name,library in [('original',a.reference_plugin),('candidate',a.plugin)]:
        run([*base,'-fpass-plugin='+library,'-S','-o',out/(name+'.s')],name+'-assembly')
    extract=lambda text,name:re.search(r'^'+name+r':.*?(?=^\s*\.size\s+'+name+r')',text,re.M|re.S).group(0)
    old=extract((out/'original.s').read_text(),'gated_control')
    new=extract((out/'candidate.s').read_text(),'gated_control')
    assert re.search(r'\bcsrr\s+\w+,\s*vlenb',old),'Reference failed to reproduce the scalable control frame'
    assert not re.search(r'\bcsrr\s+\w+,\s*vlenb',new),'Candidate callback control still has a VLEN frame'
    assert re.search(r'\bjalr\b',new),'Callback was removed instead of preserving its boundary'
    assert re.search(r'\b(?:call|tail)\s+vector_leaf',new),'Explicit RVV definition was inlined into control'
    stats=out/'census.tsv';env=dict(environment,CHIMERA_GATE_STATS=str(stats))
    run([*base,'-fpass-plugin='+a.plugin,'-S','-emit-llvm','-o',out/'candidate.ll'],'candidate-ir',env)
    ir=(out/'candidate.ll').read_text()
    leaf=re.search(r'define [^\n]*@vector_leaf\([^\n]* #(\d+)\s*\{',ir)
    assert leaf,'Missing isolated RVV function'
    attrs=re.search(r'attributes #'+leaf[1]+r' = \{([^\n]*)\}',ir)[1]
    assert 'noinline' in attrs and '"chimera-no-vectorize"' in attrs
    assert re.search(r'implicit-vector-census\tSLP\tvector_leaf\tblocked',stats.read_text())
    assembly=(out/'candidate.s').read_text()
    leaf_asm=extract(assembly,'vector_leaf')
    assert 'vle32.v' in leaf_asm and 'vse32.v' in leaf_asm
    assert re.search(r'\bcsrr\s+\w+,\s*vlenb',leaf_asm),'Fixture lost the actual isolated VLEN frame'
    binary=out/'live-rvv-boundary'
    run([*base,'-fpass-plugin='+a.plugin,'-o',binary],'candidate-binary')
    results=[]
    for group,width,cpus in [('x100',32,set(range(8))),('a100',128,set(range(8,16)))]:
        row=json.loads(run([a.native_launcher,group,binary],group+'-execution'))
        assert row['passed'] and row['cases']==row['callbacks']==65 and row['vlenb']==width and row['cpu'] in cpus
        results.append(dict(group=group,**row))
    (out/'verification.json').write_text(json.dumps(dict(passed=True,commands=commands,results=results,
        binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest()),indent=2)+'\n')
    print('PASS: scalable frame stays inside RVV definition; callback and Gate retained; 65 cases per VLEN')


if __name__=='__main__':main()
