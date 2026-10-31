# SPDX-License-Identifier: Apache-2.0
"""Device-free checks for the new evaluation protocols, not hardware results."""
from pathlib import Path
import copy
import gzip
import json
import os
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'experiments/runtime-evaluation'))
import evaluation_common as common
import measure_startup as startup
import run_llama_acceptance as llama


def config(kind):
    value=json.loads((ROOT/'experiments/runtime-evaluation'/(kind+'.example.json')).read_text())
    value['source_commit']='a'*40
    value['kernel']='test-kernel'
    for row in value['assets'].values():
        row['sha256']='a'*64
    if kind=='llama':
        value['assets']['model']['sha256']=common.MODEL_SHA
        value['assets']['corpus']['sha256']=common.CORPUS_SHA
    for row in value['workspaces']:
        row['receipt_rows']=1
        row['sha256']={key:'a'*64 for key in row['sha256']}
    for row in value.get('workloads',[]):
        row['argv']=[arg for arg in row['argv'] if 'REPLACE_' not in arg]
    return value


def counters():
    return {key:0 for key in common.LEDGERS+common.MOVES+(common.TIMEOUT,)}


class InputContractTests(unittest.TestCase):
    def test_results_cannot_be_written_inside_measured_sources_or_workspaces(self):
        value=config('llama')
        value['source_tree']=str(ROOT)
        with self.assertRaisesRegex(ValueError,'outside measured'):
            common.check_output_location(value,ROOT/'new-result')
        common.check_output_location(value,ROOT.parent/'independent-result')

    def test_startup_rejects_dependency_output_side_effects(self):
        value=config('startup')
        value['workloads'][1]['argv'].append('-MMD')
        with self.assertRaisesRegex(ValueError,'dependency-file'):
            common.validate_config(value,'startup')

    def test_cli_plan_is_a_device_free_entry_point_for_both_protocols(self):
        for kind,script in (('startup','measure_startup.py'),('llama','run_llama_acceptance.py')):
            with self.subTest(kind=kind),tempfile.TemporaryDirectory() as directory:
                path=Path(directory)/'config.json'
                path.write_text(json.dumps(config(kind)))
                result=subprocess.run([sys.executable,str(ROOT/'experiments/runtime-evaluation'/script),
                    '--config',str(path),'--plan'],capture_output=True,text=True)
                self.assertEqual(result.returncode,0,result.stderr)
                self.assertEqual(json.loads(result.stdout)['protocol'],kind+'-retest-v1')

    def test_inventory_command_pins_files_and_refuses_to_write_inside_its_input(self):
        script=ROOT/'experiments/runtime-evaluation/evaluation_common.py'
        with tempfile.TemporaryDirectory() as directory:
            source=Path(directory)/'source';source.mkdir()
            (source/'fixture.c').write_text('int value;')
            output=Path(directory)/'inventory.json'
            result=subprocess.run([sys.executable,str(script),'--inventory',str(source),str(output)],capture_output=True)
            self.assertEqual(result.returncode,0,result.stderr)
            data=json.loads(output.read_text())
            self.assertEqual(data['files'][0]['sha256'],common.sha(source/'fixture.c'))
            result=subprocess.run([sys.executable,str(script),'--inventory',str(source),str(source/'bad.json')],capture_output=True)
            self.assertNotEqual(result.returncode,0)
            self.assertFalse((source/'bad.json').exists())

    def test_compressed_evidence_identity_is_recomputed_from_stored_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'samples.gz'
            with gzip.open(path,'wb') as stream:stream.write(b'original')
            before=common.gzip_identity(path)
            with gzip.open(path,'wb') as stream:stream.write(b'changed')
            after=common.gzip_identity(path)
            self.assertNotEqual(before['sha256'],after['sha256'])
            self.assertEqual(after['bytes'],7)

    def test_changed_asset_fails_before_any_workload_is_launched(self):
        value=config('llama')
        with tempfile.TemporaryDirectory() as directory:
            asset=Path(directory)/'bootstrap.so';asset.write_bytes(b'changed')
            value['assets']['bootstrap']['path']=str(asset)
            with patch.object(common.platform,'system',return_value='Linux'), \
                 patch.object(common.platform,'machine',return_value='riscv64'), \
                 patch.object(common.platform,'release',return_value=value['kernel']), \
                 patch.object(common.subprocess,'check_output',side_effect=['a'*40+'\n','']):
                with self.assertRaisesRegex(ValueError,'Input SHA mismatch'):
                    common.input_identities(value,'llama')

    def test_examples_require_real_input_identity(self):
        for kind in ('startup','llama'):
            value=json.loads((ROOT/'experiments/runtime-evaluation'/(kind+'.example.json')).read_text())
            with self.subTest(kind=kind),self.assertRaises(ValueError):
                common.validate_config(value,kind)

    def test_valid_plan_never_needs_a_device_or_claims_fixed_historical_rounds(self):
        value=common.validate_config(config('llama'),'llama')
        plan=llama.plan(value)
        self.assertEqual(len(plan['fixed_prefix']),17)
        self.assertEqual([row['threads'] for row in plan['fixed_prefix'][:7]],[2,4,8,12,16,24,32])
        self.assertEqual(plan['mixed_minimum_active_seconds'],7200)
        self.assertIn('not fixed',plan['round_count'])

    def test_reduced_duration_thread_matrix_and_tolerance_are_rejected(self):
        for key,value in (('minimum_mixed_seconds',30),('repeat_16',1),('threads',[16]),('absolute_ppl_tolerance',1.0)):
            current=config('llama');current[key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):
                common.validate_config(current,'llama')

    def test_startup_cannot_silently_use_a_wrapper_or_omit_a_workload(self):
        value=config('startup');value['workloads'][0]['argv'][0]='/bin/sh'
        with self.assertRaisesRegex(ValueError,'compiler directly'):
            common.validate_config(value,'startup')
        value=config('startup');value['workloads'].pop()
        with self.assertRaisesRegex(ValueError,'five startup'):
            common.validate_config(value,'startup')

    def test_source_inventories_and_pinned_workspace_receipts_are_required(self):
        value=config('startup');value['inventories']=[]
        with self.assertRaisesRegex(ValueError,'inventories'):
            common.validate_config(value,'startup')
        value=config('llama');value['workspaces'][0]['sha256'].pop('artifacts/verified-tables.tsv')
        with self.assertRaisesRegex(ValueError,'receipt files'):
            common.validate_config(value,'llama')

    def test_environment_clears_parent_policy_and_preserves_larger_tls_reservation(self):
        value=config('startup')
        with patch.dict(os.environ,{'LD_PRELOAD':'bad.so','CHIMERA_LAUNCH_PID':'123','CHIMERA_AUTOMIGRATE':'1',
                                    'GLIBC_TUNABLES':'glibc.malloc.perturb=1:glibc.rtld.optional_static_tls=131072'}):
            native=common.environment(value)
            boot=common.environment(value,True)
        self.assertNotIn('LD_PRELOAD',native)
        self.assertNotIn('CHIMERA_AUTOMIGRATE',boot)
        self.assertNotIn('CHIMERA_LAUNCH_PID',boot)
        self.assertEqual(native['GLIBC_TUNABLES'],boot['GLIBC_TUNABLES'])
        self.assertIn('=131072',boot['GLIBC_TUNABLES'])
        self.assertIn('glibc.malloc.perturb=1',boot['GLIBC_TUNABLES'])


class TimingAndExitTests(unittest.TestCase):
    def test_stop_post_cleanup_is_scoped_to_its_owned_probe_group(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            unit='chimera-retest-llama-0123456789'
            name=common.trace_name(unit)
            common.save(root/'owner.json',dict(unit=unit))
            common.save(root/'trace-owner.json',dict(unit=unit,name=name))
            events=root/'kprobe_events'
            events.write_text('p:'+name+'/'+name+'_ack_enter func\np:someone_else/event other_func\n')
            capture=Mock(root=root,instance=root/'absent-instance')
            def close():
                self.assertEqual(capture.registered,[name+'_ack_enter'])
                events.write_text('p:someone_else/event other_func\n')
            capture.close.side_effect=close
            module=Mock();module.TraceCapture.return_value=capture
            with patch.object(common,'backend',return_value=module):
                self.assertTrue(common.cleanup_trace(root))
            self.assertIn('someone_else',events.read_text())
            common.save(root/'trace-owner.json',dict(unit=unit,name='someone_else'))
            with patch.object(common,'backend') as backend:
                self.assertFalse(common.cleanup_trace(root))
                backend.assert_not_called()

    def test_short_command_uses_blocking_wait_not_polling_timeout(self):
        process=Mock(pid=123,returncode=0)
        process.wait.return_value=0;process.poll.return_value=0
        with tempfile.TemporaryDirectory() as directory,patch.object(common.subprocess,'Popen',return_value=process), \
             patch.object(common.threading,'Timer'),patch.object(common.time,'monotonic',side_effect=[1.,2.,2.0035]):
            result=common.run_command(['compiler'],Path(directory)/'case',{},directory,20)
        process.wait.assert_called_once_with()
        self.assertAlmostEqual(result['seconds'],0.0035)

    def test_nonzero_process_keeps_real_exit_and_stdout(self):
        with tempfile.TemporaryDirectory() as directory:
            case=Path(directory)/'failed'
            with self.assertRaisesRegex(ValueError,'failed or timed out'):
                common.run_command([sys.executable,'-c','import sys;print("diagnostic");sys.exit(7)'],case,
                                   dict(os.environ),directory,30)
            self.assertEqual(json.loads((case/'exit.json').read_text())['rc'],7)
            self.assertIn('diagnostic',(case/'stdout.log').read_text())

    def test_watchdog_expiration_cannot_be_reported_as_success_with_zero_return_code(self):
        process=Mock(pid=123,returncode=0)
        process.wait.return_value=0;process.poll.return_value=0
        class Timer:
            def __init__(self,seconds,callback):self.callback=callback
            def start(self):self.callback()
            def cancel(self):pass
        with tempfile.TemporaryDirectory() as directory,patch.object(common.subprocess,'Popen',return_value=process), \
             patch.object(common.threading,'Timer',Timer),patch.object(common,'kill_group') as kill:
            with self.assertRaisesRegex(ValueError,'timed out'):
                common.run_command(['compiler'],Path(directory)/'case',{},directory,20)
            kill.assert_called_once_with(process)

    def test_internal_pass_alone_does_not_replace_actual_unit_exit_resources(self):
        resources=dict(SERVICE_RESULT='success',EXIT_CODE='exited',EXIT_STATUS='0',
                       **{'memory.swap.peak':'0','memory.events':'oom 0\noom_kill 0\noom_group_kill 0'})
        self.assertTrue(common.completion_passed(0,{'passed':True},resources))
        for altered in ({},{**resources,'EXIT_CODE':'killed'},
                        {**resources,'memory.swap.peak':'1'},
                        {**resources,'trace_cleanup_passed':False},
                        {**resources,'memory.events':'oom 1\noom_kill 0\noom_group_kill 0'}):
            self.assertFalse(common.completion_passed(0,{'passed':True},altered))
        self.assertFalse(common.completion_passed(0,{'passed':False},resources))
        self.assertFalse(common.completion_passed(1,{'passed':True},resources))


class StartupEvidenceTests(unittest.TestCase):
    def test_complete_startup_workflow_has_ten_untimed_probes_and_thirty_matching_measurements(self):
        value=config('startup')
        suite=Mock();suite.cool.return_value={}
        calls=[]
        def execute(argv,case,env,cwd,timeout,**kwargs):
            case.mkdir()
            calls.append(case.name)
            (case/'stdout.log').write_text('same output')
            if 'CHIMERA_BOOTSTRAP_TRACE' in env:
                log='\n'.join('chimera bootstrap: initialized pid=1 executable='+str(Path(value['assets'][name]['path']).resolve())+' workspace=/workspace'
                    for name in ('gcc','cc1'))+'\n'
            else:
                log=''
            (case/'stderr.log').write_text(log)
            if '-o' in argv:Path(argv[-1]).write_bytes(b'same object')
            return dict(seconds=2 if 'LD_PRELOAD' in env else 1,rc=0)
        with tempfile.TemporaryDirectory() as directory,patch.object(startup,'run_command',side_effect=execute), \
             patch.object(startup,'zero_ledgers',side_effect=counters):
            result=startup.execute(value,Path(directory),suite)
        self.assertEqual(len(calls),40)
        self.assertEqual(sum(name.startswith('probe-') for name in calls),10)
        for row in result['workloads'].values():
            self.assertEqual(row['statistics']['added_percent'],100)
            self.assertEqual(len(row['runs']),6)

    def test_pair_order_and_statistics_keep_all_six_values(self):
        self.assertEqual([startup.pair_order(i) for i in range(3)],
                         [('native','bootstrap'),('bootstrap','native'),('native','bootstrap')])
        rows=[{'mode':mode,'seconds':time} for mode,times in (('native',[1,2,3]),('bootstrap',[2,4,6])) for time in times]
        result=startup.summarize(rows)
        self.assertEqual(result['median_seconds'],{'native':2,'bootstrap':4})
        self.assertEqual(result['added_percent'],100)
        with self.assertRaisesRegex(ValueError,'Incomplete'):
            startup.summarize(rows[:-1])

    def test_preload_without_successful_initialization_is_not_a_witness(self):
        self.assertEqual(startup.initialized_executables('loaded libchimera-bootstrap.so'),set())
        log='chimera bootstrap: initialized pid=31 executable=/gcc/cc1 workspace=/workspace/cc1\n'
        self.assertEqual(startup.initialized_executables(log),{'/gcc/cc1'})

    def test_migration_or_timeout_increment_fails_initialization_only_control(self):
        before=counters()
        for key in common.MOVES+(common.TIMEOUT,):
            after={**before,key:1}
            with self.subTest(key=key),self.assertRaisesRegex(ValueError,'Unexpected migration'):
                common.no_migration(before,after)

    def test_changed_compiler_output_preserves_failure_instead_of_producing_a_median(self):
        value=config('startup');value['workloads']=[value['workloads'][1]]
        suite=Mock();suite.cool.return_value={}
        def execute(argv,case,env,cwd,timeout,**kwargs):
            case.mkdir()
            (case/'stdout.log').write_text('')
            (case/'stderr.log').write_text('')
            Path(argv[-1]).write_bytes(b'boot' if 'LD_PRELOAD' in env else b'native')
            return dict(seconds=1,rc=0)
        with tempfile.TemporaryDirectory() as directory,patch.object(startup,'run_command',side_effect=execute), \
             patch.object(startup,'zero_ledgers',side_effect=counters):
            with self.assertRaisesRegex(ValueError,'output differs'):
                startup.execute(value,Path(directory),suite)
            self.assertEqual((Path(directory)/'tiny-c/output.o').read_bytes(),b'boot')
            self.assertFalse((Path(directory)/'tiny-c/summary.json').exists())


class ModelEvidenceTests(unittest.TestCase):
    def test_two_hour_stage_counts_active_commands_instead_of_rounds_or_idle_time(self):
        value=config('llama')
        state=counters()
        trace=Mock()
        audit=dict(replay=dict(physical_commits=[dict(tid=10),dict(tid=11)],
                              route_counts={'256-to-1024':1,'1024-to-256':1}))
        trace.finish.return_value=audit
        suite=Mock();suite.cool.return_value={'wait_seconds':10000}
        def command(argv,case,env,cwd,timeout,sampler=None,**kwargs):
            case.mkdir()
            (case/'stdout.log').write_text('Final estimate: PPL = 12.7757\n')
            (case/'stderr.log').write_text('')
            threads=int(argv[-1])
            samples=dict(maximum_live_threads=threads,rows=[dict(tid=tid,ready=True) for tid in range(10,10+threads)])
            if '--launch' in argv:
                for key in common.MOVES:state[key]+=1
            return dict(pid=10,rc=0,seconds=2400 if 'mixed' in case.parent.name else 1,samples=samples)
        module=Mock();module.TraceCapture.return_value=trace
        with tempfile.TemporaryDirectory() as directory,patch.object(llama,'backend',return_value=module), \
             patch.object(llama,'run_command',side_effect=command),patch.object(llama,'zero_ledgers',side_effect=lambda:dict(state)):
            common.save(Path(directory)/'owner.json',dict(unit='chimera-retest-llama-0123456789'))
            trace.root=Path(directory)/'tracing';trace.root.mkdir()
            (trace.root/'kprobe_events').write_text('')
            trace.instance=trace.root/'not-created'
            result=llama.execute(value,Path(directory),suite)
        self.assertEqual(result['mixed_rounds'],3)
        self.assertEqual(result['mixed_active_seconds'],7200)
        self.assertEqual(result['rounds'],20)
        self.assertFalse(result['historical_numbers_reproduced'])
        trace.close.assert_called_once_with()

    def evidence(self):
        before=counters();after={**before,common.MOVES[0]:1,common.MOVES[1]:1}
        samples=dict(maximum_live_threads=2,rows=[dict(tid=10,ready=True),dict(tid=11,ready=True)])
        audit=dict(replay=dict(physical_commits=[dict(tid=10),dict(tid=11)],
                              route_counts={'256-to-1024':1,'1024-to-256':1}))
        return samples,audit,before,after

    def test_only_unique_finite_final_ppl_is_accepted(self):
        self.assertEqual(llama.parse_ppl('Final estimate: PPL = 12.7757 +/- 0.1'),12.7757)
        for text in ('progress PPL = 12.7','Final estimate: PPL = nan','Final estimate: PPL = inf',
                     'Final estimate: PPL = 0','Final estimate: PPL = 12\nFinal estimate: PPL = 13'):
            with self.subTest(text=text),self.assertRaises(ValueError):llama.parse_ppl(text)
        with self.assertRaises(ValueError):llama.check_ppl(12.8,12.7757,0.01)

    def test_transient_signal_mask_is_not_a_complete_ready_witness(self):
        status=dict(Hmp_preference='prefer-x100',Hmp_runtime_ready='1',Hmp_exec_requires_ready='1',
                    SigCgt=f'{(1<<4)|(1<<40):x}',SigBlk='0')
        self.assertTrue(llama.initialization_ready(status))
        self.assertFalse(llama.initialization_ready({**status,'SigBlk':f'{1<<40:x}'}))

    def test_real_main_thread_commit_and_counter_agreement_are_required(self):
        samples,audit,before,after=self.evidence()
        llama.validate_migration(samples,audit,2,10,before,after)
        for changes in ('missing-main','wrong-count','not-ready','few-threads'):
            s,a,b,e=copy.deepcopy((samples,audit,before,after))
            if changes=='missing-main':a['replay']['physical_commits']=[dict(tid=11)]
            if changes=='wrong-count':e[common.MOVES[0]]=2
            if changes=='not-ready':s['rows'][1]['ready']=False
            if changes=='few-threads':s['maximum_live_threads']=1
            with self.subTest(changes=changes),self.assertRaises(ValueError):
                llama.validate_migration(s,a,2,10,b,e)

    def test_launcher_registers_preference_before_exec_and_never_publishes_ready(self):
        value=config('llama')
        from unittest.mock import mock_open
        control=mock_open()
        with patch('builtins.open',control),patch.object(llama.Path,'read_text',side_effect=[json.dumps(value),json.dumps({'unit':'owned'})]), \
             patch.object(llama,'cgroup',return_value=Path('/owned.service')),patch.object(llama.os,'getpid',return_value=17), \
             patch.object(llama.os,'execve') as execute:
            llama.launch('/config','/run',['-t','16'])
        control.assert_called_once_with('/proc/prefer_x100','w')
        control().write.assert_called_once_with('inherit:17\n')
        self.assertEqual(execute.call_args.args[1],[value['assets']['elf']['path'],'-t','16'])


if __name__=='__main__':
    unittest.main()
