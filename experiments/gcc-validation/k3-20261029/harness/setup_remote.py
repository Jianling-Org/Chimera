#!/usr/bin/env python3
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import time
import traceback

ROOT = Path('/root/chimera-gcc-validation-578ab8321')
OLD = Path('/root/yangzheng/newest-chimera')
REUSE = OLD/'gcc-validation-20261021-kcpZul'
BRANCH = 'dev/automigration-subprocess'
COMMIT = '578ab8321c0788ab8cba1ad24324f220e1e4a149'
ARCHIVE = Path('/tmp/gcc-source-578ab8321.tar.gz')
ARCHIVE_SHA = '90b030c44090d82b052176442dc976be1630f3c5ac498c101eb6abb49fe030a5'

def digest(path):
    h=hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda:f.read(4*1024*1024),b''): h.update(chunk)
    return h.hexdigest()

def save(path, value):
    tmp=path.with_name(path.name+'.new')
    tmp.write_text(json.dumps(value,indent=2)+'\n')
    tmp.replace(path)

def state(phase, status='running', **extra):
    value={'phase':phase,'status':status,'updated_utc':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),
           'pid':os.getpid(),'commit':COMMIT,**extra}
    save(ROOT/'state.json',value)
    with (ROOT/'events.jsonl').open('a') as f:f.write(json.dumps(value)+'\n')
    print(json.dumps(value),flush=True)

def run(args, **kw):
    print('COMMAND',args,flush=True)
    return subprocess.run(args,check=True,**kw)

def preserved_copy(src,dst):
    dst.parent.mkdir(parents=True,exist_ok=True)
    shutil.copy2(src,dst)

ROOT.mkdir(mode=0o700,exist_ok=True)
marker=ROOT/'OWNER.json'
if marker.exists():
    assert json.loads(marker.read_text())['commit']==COMMIT
else: save(marker,{'commit':COMMIT,'purpose':'User-authorized current-branch GCC Chimera validation'})

try:
    state('preserve_inputs')
    before=shutil.disk_usage('/').free
    (ROOT/'provenance').mkdir(exist_ok=True)
    identities=[]
    inputs={
      'baseline':{'xgcc':'0e862d054c2e78d13f818290317fde7adc684f89c29a43d0b8b1df569fe7fb9a',
                  'cc1':'1ae8e4b2bf682743103116dc17091613f8f25235604d1764493de140cd866b35'},
      'metadata':{'xgcc':'c8b0d47339d17f9718431bfc393abb1b9d9fd780b2ebb01c36b09c4bff3f7cab',
                  'cc1':'5c9fc54617b00bb385fd38a751642750ec119d7e0b19028a5fdbf2b67e9bcddc'}}
    for phase,programs in inputs.items():
        oldbuild='build-baseline' if phase=='baseline' else 'build-stack'
        for name,expected in programs.items():
            src=REUSE/oldbuild/'gcc'/name
            assert digest(src)==expected,src
            dst=ROOT/'inputs'/phase/name
            if not dst.exists():preserved_copy(src,dst)
            assert digest(dst)==expected,dst
            identities.append({'stage':phase,'program':name,'source':str(src),'path':str(dst),'sha256':expected,'bytes':dst.stat().st_size})
    save(ROOT/'input-identities.json',identities)
    if not (ROOT/'toolchain').exists():shutil.copytree(REUSE/'toolchain',ROOT/'toolchain',symlinks=True)
    toolchain=[]
    for line in (REUSE/'toolchain-inputs.sha256').read_text().splitlines():
        expected,path=line.split(None,1)
        original=Path(path)
        try:relative=original.relative_to(REUSE/'toolchain')
        except ValueError:continue
        copied=ROOT/'toolchain'/relative
        assert digest(copied)==expected,copied
        toolchain.append({'path':str(copied),'source':str(original),'sha256':expected})
    save(ROOT/'toolchain-identities.json',toolchain)
    for name in ('README.md','env.sh','build-baseline.sh','build-stage.sh','profile.gcc.toml','baseline-elf.sha256','stack-elf.sha256','toolchain-inputs.sha256','toolchain-source-comparison.json'):
        src=REUSE/name
        if src.is_file():preserved_copy(src,ROOT/'provenance'/name)

    state('archive_compact_old_evidence')
    suffixes={'.json','.jsonl','.log','.md','.txt','.toml','.sh','.py','.sha256','.patch','.exit','.rc'}
    oldroots=[p for p in OLD.iterdir() if p.is_dir() and (p.name.startswith('gcc-') or p.name.startswith('llamacpp-'))]
    skipped={'venv','.venv','toolchain','build-baseline','build-stack','build-gate','build-gate2','workspaces','verified-workspaces','new-build-output','.git','rebuild-current','rebuild-preserved-baseline'}
    retained=[]
    for parent in oldroots:
        for directory,dirs,files in os.walk(parent):
            dirs[:]=[d for d in dirs if d not in skipped and not d.startswith('build-')]
            for name in files:
                path=Path(directory)/name
                if path.is_symlink() or path.suffix not in suffixes or path.stat().st_size>20*1024**2:continue
                relative=path.relative_to(OLD)
                preserved_copy(path,ROOT/'preserved-evidence'/relative)
                retained.append(str(relative))
    save(ROOT/'preserved-evidence-index.json',retained)

    scratch=[OLD/'gcc-runtime-1024-to-256-20261023-zou7fdnz'/'workspaces'/program/part
             for program in ('xgcc','cc1') for part in ('dump','generated')]
    scratch += [OLD/'gcc-no-relax-validation-20261024-ugm91cfv'/name for name in ('workspaces','new-build-output')]
    builds=[REUSE/'build-baseline',REUSE/'build-stack',
            OLD/'gcc-gate-regression-20261022-s7dzy8k5'/'build-gate',
            OLD/'llamacpp-bidirectional-20261024-4tef3fu6'/'rebuild-current',
            OLD/'llamacpp-bidirectional-20261024-4tef3fu6'/'rebuild-preserved-baseline']
    allroots=[p for p in scratch+builds if p.exists()]
    for path in allroots:
        assert not path.is_symlink(),path
        assert path.resolve().is_relative_to(OLD.resolve()) and path.resolve()!=OLD.resolve(),path
    # Fail before deleting anything if an old job uses the selected directories.
    busy=[]
    for proc in Path('/proc').iterdir():
        if not proc.name.isdigit() or int(proc.name)==os.getpid():continue
        try:
            maps=(proc/'maps').read_text(errors='replace')
            cwd=os.readlink(proc/'cwd')
            for path in allroots:
                prefix=str(path.resolve())+'/'
                if prefix in maps or cwd==str(path) or cwd.startswith(prefix):busy.append({'pid':proc.name,'root':str(path)})
        except (OSError,PermissionError,ProcessLookupError):pass
    assert not busy,busy
    extensions={'.o','.a','.bc','.bca','.gch','.dwo','.gcno','.gcda','.su'}
    removable=[]
    for root in builds:
        if not root.exists():continue
        for directory,dirs,files in os.walk(root,followlinks=False):
            dirs[:]=[d for d in dirs if d!='.git' and not (Path(directory)/d).is_symlink()]
            for name in files:
                path=Path(directory)/name
                if path.suffix in extensions and not path.is_symlink():removable.append(path)
    save(ROOT/'cleanup-plan.json',{
        'scratch_directories':[str(p) for p in scratch if p.exists()],
        'intermediate_roots':[str(p) for p in builds if p.exists()],
        'intermediate_file_count':len(removable),
        'intermediate_paths':[str(p) for p in removable],
        'preserve':'All canonical GCC/Chimera sources, dirty shared worktree, input and final ELF, toolchains, shared models, kernel backup; old published Workspace artifacts/scalar/manifests and paused llama diagnostic evidence remain intact.'})
    state('cleanup_authorized_old_scratch',file_count=len(removable))
    for path in scratch:
        if not path.exists():continue
        assert path.resolve().is_relative_to(OLD.resolve())
        shutil.rmtree(path)
        print('REMOVED_SCRATCH',path,flush=True)
    deleted_bytes=0
    for path in removable:
        try:
            deleted_bytes+=path.stat().st_size
            path.unlink()
        except FileNotFoundError:pass
    after=shutil.disk_usage('/').free
    save(ROOT/'cleanup-result.json',{'before_free_bytes':before,'after_free_bytes':after,
         'net_free_increase_bytes':after-before,'intermediate_logical_bytes':deleted_bytes,
         'files_removed':len(removable),'compact_evidence_files':len(retained)})
    run(['df','-h','/'])
    assert after>=25*1024**3,'Need additional scoped cleanup before large stages'

    state('clean_source_checkout')
    assert digest(ARCHIVE)==ARCHIVE_SHA
    source=ROOT/'source'
    if not source.exists():
        source.mkdir()
        with tarfile.open(ARCHIVE,'r:gz') as archive:
            assert archive.pax_headers.get('comment')==COMMIT,archive.pax_headers
            archive.extractall(source,filter='data')
    agents=list(source.rglob('AGENTS.md'))
    assert not agents,agents
    if not (source/'.git').exists():
        run(['git','init','--initial-branch='+BRANCH,str(source)])
        run(['git','-C',str(source),'remote','add','origin','git@code.ruyicommunity.cn:735522978001541/chimera.git'])
        run(['git','-C',str(source),'config','remote.origin.promisor','true'])
        run(['git','-C',str(source),'config','remote.origin.partialclonefilter','blob:none'])
        env=dict(os.environ,GIT_SSH_COMMAND='ssh -o BatchMode=yes -o ConnectTimeout=20')
        run(['git','-C',str(source),'fetch','--depth=1','--filter=blob:none','--no-tags','origin',BRANCH],env=env)
        run(['git','-C',str(source),'update-ref','refs/heads/'+BRANCH,'FETCH_HEAD'])
        run(['git','-C',str(source),'read-tree','HEAD'])
        run(['git','-C',str(source),'update-index','--refresh'])
    actual=subprocess.check_output(['git','-C',str(source),'rev-parse','HEAD'],text=True).strip()
    assert actual==COMMIT,actual
    status=subprocess.check_output(['git','-C',str(source),'status','--porcelain'],text=True)
    assert not status,status
    save(ROOT/'source-identity.json',{'branch':BRANCH,'commit':actual,'archive_sha256':ARCHIVE_SHA,'clean_status':status})
    (ROOT/'setup.done').write_text(time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime())+'\n')
    state('setup_complete','ready',root_available_bytes=shutil.disk_usage('/').free)
except BaseException as error:
    state('setup_failed','failed',error=repr(error))
    traceback.print_exc()
    raise
