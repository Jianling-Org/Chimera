from pathlib import Path
import json,unittest
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'experiments/runtime-evaluation'))
import model_thread_trace as trace

def line(tid,timestamp,event):return f' model-{tid} [000] ..... {timestamp:.6f}: {event}\n'
def state(tid,start,event='probe_state_exit',**change):
 row=dict(tid=tid,tgid=10,start=start,enabled=1,prefer_x=0,ready=1,exec_ready=1,blocked=0,handler5=500,handler41=4100);row.update(change)
 return event+': '+' '.join(f'{key}={value}' for key,value in row.items())
def fixture():
 lines=[line(10,1.,'sched_process_exec: filename=/model pid=10 old_pid=10'),line(10,1.1,'task_newtask: pid=11 comm=model clone_flags=10000 oom_score_adj=0'),line(11,1.3,state(11,1100000000)),line(11,1.4,'sched_process_exit: comm=model pid=11 prio=120 group_dead=false'),line(10,1.5,state(10,1000000000)),line(10,1.6,'sched_process_exit: comm=model pid=10 prio=120 group_dead=true')]
 return lines,dict(rows=[dict(tid=10,starttime='100',ready=True)])

class LifecycleTests(unittest.TestCase):
 def test_short_thread_keeps_real_initialization_and_mask_separate(self):
  lines,samples=fixture();lines[2]=line(11,1.3,state(11,1100000000,blocked=trace.REQUIRED));row=trace.lifecycle(lines,10,'/model',samples)
  self.assertEqual(row['owned_tids'],[10,11]);self.assertEqual(row['short_thread_tids'],[11]);self.assertTrue(row['all_threads_ready']);self.assertFalse(row['all_threads_signal_unblocked_observed']);self.assertFalse(row['threads'][1]['kernel_ready_rows']);self.assertTrue(row['threads'][1]['kernel_published_ready_rows'])
 def test_wrong_ownership_missing_birth_or_subprocess_still_fail(self):
  for change in ('wrong-group','missing-birth','subprocess','wrong-elf'):
   lines,samples=fixture()
   if change=='wrong-group':lines[2]=line(11,1.3,state(11,1100000000,tgid=99))
   if change=='missing-birth':lines.pop(1)
   if change=='subprocess':lines[1]=lines[1].replace('10000','0')
   if change=='wrong-elf':lines[0]=lines[0].replace('/model','/other')
   with self.subTest(change=change),self.assertRaises(ValueError):trace.lifecycle(lines,10,'/model',samples)
 def test_missing_published_ready_or_handler_still_fails(self):
  for change in [dict(ready=0),dict(exec_ready=0),dict(handler5=1),dict(handler41=0),dict(prefer_x=1),dict(enabled=0)]:
   lines,samples=fixture();lines[2]=line(11,1.3,state(11,1100000000,**change))
   with self.subTest(change=change),self.assertRaises(ValueError):trace.lifecycle(lines,10,'/model',samples)
 def test_pid_reuse_or_starttime_mismatch_still_fails(self):
  lines,samples=fixture();samples['rows'][0]['starttime']='99'
  with self.assertRaises(ValueError):trace.lifecycle(lines,10,'/model',samples)
  lines,samples=fixture();lines.insert(3,line(11,1.35,state(11,1200000000)))
  with self.assertRaises(ValueError):trace.lifecycle(lines,10,'/model',samples)
 def test_missing_exit_still_fails(self):
  lines,samples=fixture();lines.pop(3)
  with self.assertRaises(ValueError):trace.lifecycle(lines,10,'/model',samples)
 def test_fetches_use_supplied_btf_signal_fields(self):
  names=['pid','tgid','start_boottime','sighand','blocked','prefer_a100','hmp_prefer_x100','hmp_prefer_ready','hmp_exec_requires_ready']
  bits=[12480,12512,14848,17216,17280,58816,58824,58832,58840]
  layout={'types':{'task_struct':{'members':[dict(name=name,bits_offset=value) for name,value in zip(names,bits)]},'sighand_struct':{'members':[dict(name='action',bits_offset=256)]},'k_sigaction':{'size':24,'members':[dict(name='sa',bits_offset=0)]},'sigaction':{'members':[dict(name='sa_handler',bits_offset=0)]}}};text=trace.fields(layout)
  self.assertIn('tid=+1560(%tp):u32',text);self.assertIn('ready=+7354(%tp):u8',text);self.assertIn('handler41=+992(+2152(%tp)):u64',text)
 def test_actual_commit_requires_positive_kernel_check_before_ack(self):
  lines,samples=fixture();own=trace.lifecycle(lines,10,'/model',samples);replay={'physical_commits':[{'tid':11,'route':'256-to-1024','sequence':10,'ack':{'enter_time':1.25}}]}
  for value in ([],[line(99,1.15,state(11,1100000000,event='probe_eligible_enter')),line(99,1.2,'probe_eligible_return: result=0')]):
   with self.assertRaises(ValueError):trace.eligibility(value,10,own,replay)
  checks=[line(99,1.15,state(11,1100000000,event='probe_eligible_enter')),line(99,1.2,'probe_eligible_return: result=1')]
  result=trace.eligibility(checks,10,own,replay);self.assertTrue(result['all_commits_have_positive_kernel_predicate']);self.assertEqual(len(result['commit_witnesses']),1)
 def test_unpaired_or_uninitialized_kernel_check_cannot_prove_commit(self):
  lines,samples=fixture();own=trace.lifecycle(lines,10,'/model',samples);replay={'physical_commits':[{'tid':11,'route':'256-to-1024','sequence':10,'ack':{'enter_time':1.25}}]}
  for changes in [dict(start=1),dict(ready=0),dict(handler41=1)]:
   row=dict(tid=11,start=1100000000);row.update(changes);checks=[line(99,1.15,state(**row,event='probe_eligible_enter')),line(99,1.2,'probe_eligible_return: result=1')]
   with self.subTest(changes=changes),self.assertRaises(ValueError):trace.eligibility(checks,10,own,replay)
  with self.assertRaises(ValueError):trace.eligibility([line(99,1.15,state(11,1100000000,event='probe_eligible_enter'))],10,own,replay)
 def test_entry_mask_and_locked_kernel_return_are_distinct_observations(self):
  lines,samples=fixture();own=trace.lifecycle(lines,10,'/model',samples);checks=[line(99,1.15,state(11,1100000000,event='probe_eligible_enter',blocked=1<<40)),line(99,1.2,'probe_eligible_return: result=1')];replay={'physical_commits':[{'tid':11,'route':'256-to-1024','sequence':10,'ack':{'enter_time':1.25}}]}
  row=trace.eligibility(checks,10,own,replay);self.assertEqual(row['checks'][0]['blocked'],1<<40);self.assertTrue(row['signal41_checked_under_kernel_lock'])

if __name__=='__main__':unittest.main(verbosity=2)
