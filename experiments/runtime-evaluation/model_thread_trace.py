"""Kernel task lifecycle and actual ready-state witnesses for short model threads."""
from pathlib import Path
import gzip,hashlib,json,os,re

REQUIRED=(1<<4)|(1<<40)
STATE_FIELDS=('tid','tgid','start','enabled','prefer_x','ready','exec_ready','blocked','handler5','handler41')

def fields(layout):
    def off(struct,name):
        row=next(row for row in layout['types'][struct]['members'] if row['name']==name)
        if row['bits_offset']%8 or row.get('bitfield_size'):raise ValueError('Unsupported task bitfield')
        return row['bits_offset']//8
    task={name:off('task_struct',name) for name in ('pid','tgid','start_boottime','sighand','blocked','prefer_a100','hmp_prefer_x100','hmp_prefer_ready','hmp_exec_requires_ready')}
    pairs=[('tid','pid','u32'),('tgid','tgid','u32'),('start','start_boottime','u64'),('enabled','prefer_a100','u8'),('prefer_x','hmp_prefer_x100','u8'),('ready','hmp_prefer_ready','u8'),('exec_ready','hmp_exec_requires_ready','u8'),('blocked','blocked','x64')]
    result=[f'{key}=+{task[member]}(%tp):{kind}' for key,member,kind in pairs]
    for sig in (5,41):
        handler=off('sighand_struct','action')+(sig-1)*layout['types']['k_sigaction']['size']+off('k_sigaction','sa')+off('sigaction','sa_handler')
        result.append(f'handler{sig}=+{handler}(+{task["sighand"]}(%tp)):u64')
    return ' '.join(result)

def split_line(line):
    m=re.search(r'-(\d+)\s+\[\d+\].*?\s(\d+\.\d+):\s(.*)',line)
    return (int(m[1]),float(m[2]),m[3]) if m else None

def lifecycle(lines,root_pid,elf,samples,hz=100):
    parsed=[(number,*p) for number,line in enumerate(lines,1) if (p:=split_line(line))]
    states={};births={};exits={};execs=[]
    for seq,caller,stamp,detail in parsed:
        if '_state_ack:' in detail or '_state_exit:' in detail:
            raw=dict(re.findall(r'(\w+)=([^\s]+)',detail))
            if int(raw.get('tgid','-1'),0)!=root_pid:continue
            row={key:int(raw[key],0) for key in STATE_FIELDS}
            if row['tid']!=caller:raise ValueError('Task pointer and trace TID disagree')
            row.update(sequence=seq,timestamp=stamp,point='ack' if '_state_ack:' in detail else 'exit')
            row['published_ready']=(row['enabled']==1 and row['prefer_x']==0 and row['ready']==1 and row['exec_ready']==1 and row['handler5']>1 and row['handler41']>1)
            row['complete_ready']=row['published_ready'] and row['blocked']&REQUIRED==0
            previous=states.setdefault(caller,dict(start=row['start'],rows=[]))
            if previous['start']!=row['start']:raise ValueError('Kernel TID reuse inside case')
            previous['rows'].append(row)
        elif 'task_newtask:' in detail:
            match=re.search(r'pid=(\d+) comm=.* clone_flags=([0-9a-fA-F]+) ',detail)
            if match:
                child=int(match[1])
                if child in births:raise ValueError('Duplicate task birth inside trace')
                births[child]=dict(parent=caller,flags=int(match[2],16),timestamp=stamp,sequence=seq)
        elif 'sched_process_exec:' in detail:
            match=re.search(r'filename=(.*?) pid=(\d+) old_pid=(\d+)',detail)
            if match and int(match[2])==root_pid:execs.append(dict(path=match[1],timestamp=stamp,sequence=seq))
        elif 'sched_process_exit:' in detail:
            match=re.search(r' pid=(\d+) ',detail)
            if match:exits[int(match[1])]=dict(timestamp=stamp,sequence=seq)
    matching=[row for row in execs if row['path']==str(elf)]
    if len(matching)!=1:raise ValueError('Missing unique model exec identity')
    owned={root_pid}
    changed=True
    while changed:
        changed=False
        for child,row in births.items():
            if row['parent'] in owned and child not in owned:
                if not row['flags']&0x10000:raise ValueError('Unexpected model subprocess; not a thread')
                owned.add(child);changed=True
    sampled={row['tid']:row for row in samples['rows']}
    if not set(sampled)<=owned:raise ValueError('Sampled TID lacks kernel lifecycle ownership')
    if set(states)!=owned or not owned<=set(exits):raise ValueError('Missing task state or exit evidence')
    rows=[]
    for tid in sorted(owned):
        state=states[tid];prior=sampled.get(tid)
        if prior and state['start']*hz//10**9!=int(prior['starttime']):raise ValueError('Kernel and proc starttime differ')
        ready=any(row['published_ready'] for row in state['rows']) or bool(prior and prior['ready'])
        if not ready:raise ValueError('Missing published-ready or installed-handler witness for TID '+str(tid))
        rows.append(dict(tid=tid,start_boottime_ns=state['start'],birth=births.get(tid),exit=exits[tid],sampled=prior is not None,proc_ready=bool(prior and prior['ready']),kernel_ready_rows=[row for row in state['rows'] if row['complete_ready']],kernel_published_ready_rows=[row for row in state['rows'] if row['published_ready']],kernel_state_rows=state['rows']))
    return dict(root_pid=root_pid,elf=str(elf),model_exec=matching[0],owned_tids=sorted(owned),sampled_tids=sorted(sampled),short_thread_tids=sorted(owned-set(sampled)),threads=rows,all_threads_ready=True,readiness_contract='Runtime-published initialized readiness; migration eligibility checked separately before each commit',all_threads_signal_unblocked_observed=all(any(row['complete_ready'] for row in state['rows']) or bool(sampled.get(tid,{}).get('ready')) for tid,state in states.items()),hz=hz)

def eligibility(lines,root_pid,own,replay):
    pending={};checks=[];orphans=[]
    for number,line in enumerate(lines,1):
        p=split_line(line)
        if not p:continue
        caller,stamp,detail=p
        if '_eligible_enter:' in detail:
            raw=dict(re.findall(r'(\w+)=([^\s]+)',detail))
            row=None
            if int(raw.get('tgid','-1'),0)==root_pid:
                row={key:int(raw[key],0) for key in STATE_FIELDS};row.update(enter_sequence=number,enter_time=stamp,caller=caller)
            pending.setdefault(caller,[]).append(row)
        elif '_eligible_return:' in detail:
            if not pending.get(caller):orphans.append(dict(caller=caller,sequence=number));continue
            row=pending[caller].pop()
            if row is None:continue
            raw=dict(re.findall(r'(\w+)=([^\s]+)',detail));row.update(result=int(raw['result'],0),return_time=stamp,return_sequence=number)
            if row['result'] not in [0,1]:raise ValueError('Invalid actual kernel readiness return')
            if row['tid'] not in own['owned_tids']:raise ValueError('Kernel predicate target lacks thread ownership')
            identity=next(item for item in own['threads'] if item['tid']==row['tid'])
            if row['start']!=identity['start_boottime_ns']:raise ValueError('Predicate task identity differs')
            # The function reads signal41's mask under sighand->siglock. The
            # entry snapshot precedes that lock and may race a signal return;
            # the actual positive function return is the eligibility witness.
            if row['result']==1 and not (row['enabled']==row['ready']==row['exec_ready']==1 and row['prefer_x']==0 and row['handler5']>1 and row['handler41']>1):
                raise ValueError('Positive kernel predicate lacks initialized task/handlers')
            checks.append(row)
    if any(row is not None for rows in pending.values() for row in rows):raise ValueError('Unclosed owned kernel readiness check')
    witnesses=[]
    for commit in replay['physical_commits']:
        matches=[row for row in checks if row['tid']==commit['tid'] and row['result']==1 and own['model_exec']['timestamp']<=row['enter_time']<=row['return_time']<=commit['ack']['enter_time']]
        if not matches:raise ValueError('Actual commit lacks prior positive kernel readiness witness')
        witnesses.append(dict(tid=commit['tid'],route=commit['route'],commit_sequence=commit['sequence'],kernel_check=max(matches,key=lambda row:row['return_time'])))
    return dict(kernel_predicate='hmp_runtime_ready',signal41_checked_under_kernel_lock=True,checks=checks,commit_witnesses=witnesses,all_commits_have_positive_kernel_predicate=True,unmatched_unattributed_returns=orphans)


def capture_class(base):
    class ModelTraceCapture(base.TraceCapture):
        def __init__(self,name,layout):
            super().__init__(name);self.extra=[];self.layout=layout

        def configure(self):
            if hashlib.sha256(Path('/sys/kernel/btf/vmlinux').read_bytes()).hexdigest()!=self.layout['btf_sha256']:raise ValueError('Kernel BTF changed')
            super().configure()
            try:
                for suffix,symbol in [('state_ack','hmp_prefer_ack_write'),('state_exit','do_exit')]:
                    event=self.name+'_'+suffix
                    base.append_control(self.root/'kprobe_events',f'p:{self.name}/{event} {symbol} '+fields(self.layout));self.extra.append(event)
                    (self.instance/'events'/self.name/event/'enable').write_text('1')
                for suffix,definition in [
                    ('eligible_enter','p:{group}/{event} hmp_runtime_ready '+fields(self.layout).replace('(%tp)','($arg1)')),
                    ('eligible_return','r256:{group}/{event} hmp_runtime_ready result=$retval:u8')]:
                    event=self.name+'_'+suffix
                    base.append_control(self.root/'kprobe_events',definition.format(group=self.name,event=event));self.extra.append(event)
                    (self.instance/'events'/self.name/event/'enable').write_text('1')
                for event in ['task/task_newtask','sched/sched_process_exec','sched/sched_process_exit']:
                    (self.instance/'events'/event/'enable').write_text('1')
            except BaseException:self.close();raise

        def finish_model(self,samples,root_pid,elf):
            row=super().finish(set())
            self.last_base_audit=row
            profiles=[line for line in (self.root/'kprobe_profile').read_text().splitlines() if any(event in line for event in self.extra)]
            if len(profiles)!=4 or any(int(line.split()[-1])!=0 for line in profiles):raise ValueError('Missing or dropped task-state probes')
            with gzip.open(self.path,'rt',encoding='utf-8') as source:lines=list(source)
            own=lifecycle(lines,root_pid,elf,samples,os.sysconf('SC_CLK_TCK'))
            replay=base.replay(lines,set(own['owned_tids']))
            gate=eligibility(lines,root_pid,own,replay)
            row.update(lifecycle=own,replay=replay,migration_eligibility=gate,task_state_probe_profile=profiles,kernel_btf_sha256=self.layout['btf_sha256'])
            return row

        def close(self):
            if self.instance.exists():(self.instance/'tracing_on').write_text('0');(self.instance/'events/enable').write_text('0')
            super().close()
            for event in reversed(self.extra):base.append_control(self.root/'kprobe_events',f'-:{self.name}/{event}')
            self.extra.clear()
    return ModelTraceCapture


def record_layout(destination):
    """Record actual target BTF offsets; no guessed task_struct layout."""
    import subprocess
    destination=Path(destination)
    if destination.exists():raise ValueError('Refuse replacing task layout')
    source=Path('/sys/kernel/btf/vmlinux');raw=source.read_bytes()
    data=json.loads(subprocess.check_output(['bpftool','-j','btf','dump','file',str(source),'format','raw'],text=True))
    types=data['types'] if isinstance(data,dict) else data
    structs={row.get('name'):row for row in types if row.get('kind')=='STRUCT'}
    wanted={'task_struct':['pid','tgid','start_boottime','sighand','blocked','prefer_a100','hmp_prefer_x100','hmp_prefer_ready','hmp_exec_requires_ready'],
            'sighand_struct':['action'],'k_sigaction':['sa'],'sigaction':['sa_handler']}
    result=dict(btf_sha256=hashlib.sha256(raw).hexdigest(),btf_bytes=len(raw),types={})
    for name,members in wanted.items():
        row=structs[name];result['types'][name]=dict(id=row['id'],size=row['size'],members=[item for item in row['members'] if item['name'] in members])
    fields(result)
    destination.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
    return result


def record_contract(destination,chimera_source,kernel_source):
    destination=Path(destination)
    if destination.exists():raise ValueError('Refuse replacing readiness source contract')
    files=[Path(chimera_source)/'runtime/interfaces/uapi/linux/chimera_signal.c',
           Path(chimera_source)/'runtime/runtime/migration/linux_riscv64_rvv_v1/signal_handlers.c',
           Path(kernel_source)/'drivers/soc/spacemit/hmp.c']
    result=dict(files={str(path.resolve()):dict(sha256=hashlib.sha256(path.read_bytes()).hexdigest()) for path in files})
    destination.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
    return result


if __name__=='__main__':
    import argparse
    parser=argparse.ArgumentParser(description='Record target kernel task layout or pinned readiness sources')
    choice=parser.add_mutually_exclusive_group(required=True)
    choice.add_argument('--record-layout',metavar='OUTPUT_JSON')
    choice.add_argument('--record-contract',metavar='OUTPUT_JSON')
    parser.add_argument('--chimera-source');parser.add_argument('--kernel-source');args=parser.parse_args()
    if args.record_layout:record_layout(args.record_layout)
    else:
        if not args.chimera_source or not args.kernel_source:parser.error('Both source directories are required')
        record_contract(args.record_contract,args.chimera_source,args.kernel_source)
