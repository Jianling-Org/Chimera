"""Current identities, exact source and capacity for the corrected j16 comparison."""
import importlib.util, unittest
from perf_common_j16 import *
from performance_round_j16_v2 import full_capacity, platform_settings

def main():
    root=P/'evidence/prelaunch-2';assert not root.exists();root.mkdir()
    state('prelaunch','running','chimera-gcc-j16-prelaunch-2.service')
    verify_authorization();verify_setup();guard();zero_ledgers()
    index=P/'evidence/controller-1-failure.json'
    assert sha(index)=='0746b392f5c74e28c7171fee32ffbbbfd6c7da8eb27853b212f730bda567df34'
    for row in load(index)['files']:assert sha(row['path'])==row['sha256']
    assert sha(BASE/'completion.json')=='b9562014670a5aaed6214cf02459703856a7ca3d208b6e6d2a96314cd853df91'
    assert load(BASE/'completion.json')['performance_completed']
    assert sha(BASE/'final_audit_performance_2.py')=='858a8674483963857cc941d2cdf8dcd2aa77fe84d29b96ac14fa2de06ab871ea'
    prior=load(BASE/'image-plan-v3.json')
    for name,digest in prior['source_sha256'].items():assert sha(BASE/name)==digest,name
    for name in ('config.common','tasks.json','environment.json','platform-settings.json','storage-policy-authorization-attempt2.json','bin/native-launch-image-v3'):
        assert sha(P/name)==sha(BASE/name),name
    assert platform_settings()==load(P/'platform-settings.json')
    available=int(next(line.split()[1] for line in Path('/proc/meminfo').read_text().splitlines() if line.startswith('MemAvailable:')))*1024
    assert available>=12*1024**3,('MemAvailable below phase budget',available)
    verify_previous('preflight-3');verify_previous('preflight-1')
    kernel=KernelLog(root,True);health=StorageHealth(root);kernel.start()
    try:
        health.check(force=True)
        spec=importlib.util.spec_from_file_location('j16_previous_audit',BASE/'final_audit_performance_2.py')
        audit=importlib.util.module_from_spec(spec);spec.loader.exec_module(audit)
        audit.A=root/'current-inputs';audit.A.mkdir()
        source=audit.source_audit();save(root/'current-source.json',source)
        workspaces=audit.workspace_audit();save(root/'current-workspaces.json',workspaces)
        save(root/'current-inputs/evidence-sha256.json',audit.EVIDENCE)
        assert sum(x['receipt_rows'] for x in workspaces.values())==78
        health.check(force=True);zero_ledgers();full_capacity(root)
        source_data=b'#if defined(__GNUC__)\nGCC __GNUC__ __GNUC_MINOR__ __GNUC_PATCHLEVEL__\n#else\nunknown\n#endif\n'
        probes=[];references={}
        commands=[('version',[str(P/'bin/cc-image-v3'),'--version'],None),
          ('macro-version',[str(P/'bin/cc-image-v3'),'-E','-P','-x','c','-'],source_data),
          ('cc-version',[str(S/'scripts/cc-version.sh'),str(P/'bin/cc-image-v3')],None),
          ('as-version',[str(S/'scripts/as-version.sh'),str(P/'bin/cc-image-v3')],None)]
        for mode in ('x100','auto-x100','auto-a100'):
            for name,command,data in commands:
                run=subprocess.run(command,input=data,capture_output=True,env=environment(mode,True),cwd=S,timeout=30)
                row=dict(mode=mode,name=name,command=command,rc=run.returncode,stdout=run.stdout.decode(),stderr=run.stderr.decode())
                save(root/(mode+'-'+name+'.json'),row);assert run.returncode==0 and b'parent_thread_id=' not in run.stdout
                if mode=='x100':references[name]=run.stdout
                else:assert run.stdout==references[name]
                if name=='cc-version':assert run.stdout==b'GCC 150200\n'
                probes.append(row)
            health.check(force=True);zero_ledgers()
        from test_perf_policy_j16 import BoundaryTests
        with (root/'policy-regressions.log').open('w') as log:
            tests=unittest.TextTestRunner(stream=log,verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(BoundaryTests))
        assert tests.wasSuccessful() and tests.testsRun==14 and not tests.skipped
        for name,expected in load(P/'image-plan-j16-attempt2.json')['source_sha256'].items():assert sha(P/name)==expected,name
        health.check(force=True)
    finally:captured=kernel.finish()
    assert not captured['errors'] and not captured['alerts']
    result=dict(passed=True,rc=0,source=source,workspaces=workspaces,receipt_rows=78,mem_available_bytes=available,
      capacity=load(root/'capacity.json'),compiler_probe_cases=len(probes),policy_tests=tests.testsRun,
      same_runtime_and_launcher_as_preflight3=True,actual_preflight_evidence_reused_only_with_unchanged_identity=True,
      original_root_unchanged=True,kernel=captured,health=health.summary(),completed_utc=datetime.datetime.now(datetime.timezone.utc).isoformat())
    save(P/'results/prelaunch-2.json',result)
    state('prelaunch','phase_complete','chimera-gcc-j16-prelaunch-2.service',rc=0)

if __name__=='__main__':
    try:main()
    except BaseException as error:
        save(P/'results/prelaunch-2.json',dict(passed=False,rc=1,error=repr(error)))
        state('prelaunch','failed','chimera-gcc-j16-prelaunch-2.service',error=repr(error));raise
