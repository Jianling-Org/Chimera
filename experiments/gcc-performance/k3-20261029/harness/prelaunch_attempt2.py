"""One bounded untimed identity/capacity/policy check before the new epoch."""
import unittest
from perf_common_v2 import *
from performance_round_v2 import check_receipts, platform_settings, full_capacity

E = P/'evidence/attempt2-prelaunch'
FROZEN = ('performance_controller_v2.py', 'performance_round_v2.py', 'perf_common_v2.py',
          'perf_storage_policy_v2.py', 'perf_common.py', 'native-launch.c', 'bin/native-launch',
          'storage-policy-authorization-attempt2.json')


def main():
    assert not E.exists(); E.mkdir()
    unit = 'chimera-gcc-perf-prelaunch-2.service'
    state('attempt2_prelaunch', 'running', unit)
    verify_authorization(); guard(); verify_setup(); verify_previous('preflight-1'); zero_ledgers()
    active = subprocess.check_output(['systemctl','list-units','--state=active,activating','--type=service','--plain','--no-legend','chimera-gcc-perf-*'], text=True)
    for line in active.splitlines():
        name = line.split()[0]
        assert name in (unit, 'chimera-gcc-perf-watchdog.service'), ('Another performance job is active', name)
    assert not (P/'work/image').exists()
    assert os.uname().release == '6.18.3-chimera-d02cd7352'
    initial = load(P/'evidence/setup-1/inputs.json')
    assert Path('/proc/sys/kernel/random/boot_id').read_text().strip() == initial['boot_id']
    assert subprocess.check_output(['git','-C',str(V/'source'),'rev-parse','HEAD'],text=True).strip() == '578ab8321c0788ab8cba1ad24324f220e1e4a149'
    subprocess.run(['git','-C',str(V/'source'),'diff','--exit-code','--quiet','HEAD'],check=True)
    completion = load(V/'completion.json'); assert completion['acceptance_passed']
    for rel, row in completion['files'].items():
        assert sha(V/rel) == row['sha256'], rel
    for row in load(P/'evidence/controller-1-storage-failure.json')['original_files_unchanged']:
        assert sha(row['path']) == row['sha256'], row['path']
    assert load(P/'results/u24-r2-x100.json')['passed'] is False
    expected = {
        'build-gate/gcc/xgcc':'88931e9e1309afa31f1e5e056700a8cb1a1684990b9939ea62205f8a31e3a89b',
        'build-gate/gcc/cc1':'d4e48555d5cd292da07dc820f57eb964df37ffef87723fd799f6a50bb993b7ff',
        'build/runtime/libchimera-bootstrap.so':'5600ae95e64835ee62211b5b2daa38c79cc8a2568480cc15027a8233511f9c79',
        'runtime-validation/registry.tsv':'3b23ef0f37ffd447e76939d275dfa149a1636785635015f9ca5237b481246467',
        'profile.gcc.toml':'1905a136b12c3b4cb71508d546042767b2311780bbf9527c4d218dde6c11ef38',
    }
    for rel, digest in expected.items():
        assert sha(V/rel) == digest, rel
    check_receipts()
    assert sha(P/'config.common') == '0ecfe62d06dbe0bca2dd1dc1ba61e9cbec26071c9ef3200c782c89459b8e1cf4'
    assert sha(P/'tasks.json') == '720a0fddcbad5973b5e3f779878c837894b43601c54ed4a7bc6e9112e44eca47'
    for task in load(P/'tasks.json'):
        assert sha(task['source']) == task['source_sha256']
    assert platform_settings() == load(P/'platform-settings.json')
    from test_perf_policy_v2 import BoundaryTests
    with (E/'policy-regressions.log').open('w') as stream:
        outcome = unittest.TextTestRunner(stream=stream,verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(BoundaryTests))
    assert outcome.wasSuccessful() and not outcome.skipped
    health = StorageHealth(E); kernel = KernelLog(E,True); kernel.start()
    try:
        health.check(force=True); full_capacity(E); health.check(force=True)
    finally:
        capture = kernel.finish()
    assert not capture['alerts'] and not capture['errors']
    frozen = {name:sha(P/name) for name in FROZEN}
    result = dict(passed=True,rc=0,attempt=2,data_epoch='attempt-2',policy=POLICY,
                  authorization_sha256=sha(P/'storage-policy-authorization-attempt2.json'),
                  frozen_source_sha256=frozen,identity_sha256=expected,receipt_rows=78,
                  same_boot=initial['boot_id'],policy_tests=outcome.testsRun,
                  capacity=load(E/'capacity.json'),health=health.summary(),kernel=capture,
                  old_failure_unchanged=True,prior_attempt_not_pooled=True,
                  completed_utc=datetime.datetime.now(datetime.timezone.utc).isoformat())
    save(E/'result.json',result);save(P/'results/prelaunch-2.json',result)
    state('attempt2_prelaunch','phase_complete',unit,rc=0)
    print(json.dumps(result),flush=True)


if __name__ == '__main__':
    try:
        main()
    except BaseException as error:
        value=dict(passed=False,rc=1,error=repr(error))
        save(P/'results/prelaunch-2.json',value)
        state('attempt2_prelaunch','failed','chimera-gcc-perf-prelaunch-2.service',rc=1,error=repr(error))
        raise
