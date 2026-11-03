"""Versioned 2% criterion retains the original event and application contracts."""
import copy
import unittest
from unittest.mock import patch
import test_runtime_evaluation as baseline
from test_runtime_evaluation import config,common,llama

def version5(scalar=False):
    value=config('llama')
    value.update(protocol='llama-scalar-retest-v5' if scalar else 'llama-retest-v5',
                 relative_ppl_tolerance=.02,application_configuration='original-default')
    value['assets']['policy_authorization']=dict(path='/absolute/authorization.json',sha256='a'*64)
    if scalar:
        value['cpus']=list(range(8,16))
        for key in ('scalar_control','compile_commands','build_record'):
            value['assets'][key]=dict(path='/absolute/'+key,sha256='a'*64)
    return value

class Version5Tests(unittest.TestCase):
    def test_both_builds_use_explicit_two_percent_and_original_arguments(self):
        for scalar in (False,True):
            value=common.validate_config(version5(scalar),'llama')
            plan=llama.plan(value)
            self.assertEqual(plan['ppl_criterion'],dict(relative_tolerance=.02))
            self.assertEqual(plan['automatic_preference'],'prefer-a100')
            self.assertEqual(plan['thread_evidence'],'kernel-lifecycle-v2')
            self.assertEqual(len(plan['fixed_prefix']),17)
            self.assertEqual(plan['mixed_minimum_active_seconds'],7200)
            self.assertEqual(llama.arguments(value,16),llama.arguments(config('llama'),16))

    def test_old_failure_is_only_accepted_under_the_new_criterion(self):
        with self.assertRaises(ValueError):llama.check_ppl(12.6510,12.7928,.01,relative=True)
        llama.check_ppl(12.6510,12.7928,.02,relative=True)
        with self.assertRaises(ValueError):llama.check_ppl(12.5,12.7928,.02,relative=True)
        for version in ('v3','v4'):
            legacy=config('llama');legacy.update(protocol='llama-retest-'+version,relative_ppl_tolerance=.02)
            with self.assertRaises(ValueError):common.validate_config(legacy,'llama')

    def test_new_criterion_cannot_drop_event_or_authorization_inputs(self):
        for key in ('policy_authorization','thread_layout','readiness_contract'):
            value=version5();value['assets'].pop(key)
            with self.subTest(key=key),self.assertRaises(ValueError):common.validate_config(value,'llama')
        value=version5();value['thread_evidence']='periodic-proc-samples'
        with self.assertRaises(ValueError):common.validate_config(value,'llama')

    def test_new_version_rejects_diagnostic_options_or_different_threshold(self):
        for change in ('fa-off','inherited-options','different-threshold','different-application'):
            value=version5()
            if change=='fa-off':value['diagnostic_configuration']=['-fa','off']
            if change=='inherited-options':value['environment']['LLAMA_ARG_FLASH_ATTN']='off'
            if change=='different-threshold':value['relative_ppl_tolerance']=.01
            if change=='different-application':value['application_configuration']='fa-off'
            with self.subTest(change=change),self.assertRaises(ValueError):common.validate_config(value,'llama')

    def test_new_protocol_uses_the_same_six_probe_cleanup(self):
        original_save=common.save
        def owner_version5(path,value):
            if path.name=='owner.json':value=dict(value,protocol='llama-retest-v5')
            original_save(path,value)
        with patch.object(common,'save',side_effect=owner_version5):
            baseline.TimingAndExitTests('test_v4_cleanup_removes_only_its_six_probe_namespace').test_v4_cleanup_removes_only_its_six_probe_namespace()

if __name__=='__main__':unittest.main()
