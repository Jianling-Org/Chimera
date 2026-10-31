# SPDX-License-Identifier: Apache-2.0
"""Input-bound thread matrix, ten repeats and two hours of active model runs."""
from pathlib import Path
import gzip
import hashlib
import json
import math
import os
import re
import sys
import threading
import time

from evaluation_common import (LEDGERS, MOVES, TIMEOUT, backend, cgroup_values, counters,
    entry, environment, frequencies, kill_group, no_migration, require, run_command,
    save, temperatures, zero_ledgers, cgroup, gzip_identity, trace_name)


def prefix(config):
    return ([dict(stage='matrix',threads=n) for n in config['threads']]
            +[dict(stage='repeat-16',threads=16) for _ in range(config['repeat_16'])])


def plan(config):
    return dict(protocol=config['protocol'],native_reference_threads=16,fixed_prefix=prefix(config),
        mixed_minimum_active_seconds=7200,mixed_thread_cycle=config['threads'],
        round_count='measured at execution; not fixed to the historical 123 rounds',
        scope='functional acceptance with detailed tracing; elapsed time is not inference throughput')


def arguments(config,threads):
    return ['-m',config['assets']['model']['path'],'-f',config['assets']['corpus']['path'],
            '-c','512','-b','512','-ub','128','--chunks','1','--seed','1234',
            '-t',str(threads),'-tb',str(threads)]


def parse_ppl(text):
    values=re.findall(r'Final estimate:\s*PPL\s*=\s*([^\s]+)',text,re.I)
    require(len(values)==1, 'Expected exactly one final PPL result in this fresh log')
    try:
        value=float(values[0])
    except ValueError:
        raise ValueError('Invalid final PPL value') from None
    require(math.isfinite(value) and value>0, 'PPL must be finite and positive')
    return value


def check_ppl(value,reference,tolerance):
    require(math.isfinite(value) and math.isfinite(reference) and abs(value-reference)<=tolerance,
            'PPL differs from this run\'s native reference')


def initialization_ready(values):
    if values.get('Hmp_preference')!='prefer-x100' or values.get('Hmp_runtime_ready')!='1' or values.get('Hmp_exec_requires_ready')!='1':
        return False
    try:
        required=(1<<4)|(1<<40)
        return int(values['SigCgt'],16)&required==required and int(values['SigBlk'],16)&required==0
    except (KeyError,ValueError):
        return False


class Samples:
    def __init__(self,directory,elf,native,suite):
        self.directory,self.elf,self.native,self.suite=directory,str(Path(elf).resolve()),native,suite
        self.stop=threading.Event()
        self.rows={}
        self.error=None
        self.max_threads=0
        self.digest=hashlib.sha256()
        self.raw_bytes=0
        self.thread=None

    def start(self,process):
        self.process=process
        def collect():
            try:
                with gzip.open(self.directory/'process-samples.jsonl.gz','wb',compresslevel=1) as stream:
                    while not self.stop.is_set():
                        self.suite.check()
                        tasks=[]
                        group=Path('/proc')/str(process.pid)
                        try:
                            if os.readlink(group/'exe')==self.elf:
                                for task in (group/'task').iterdir():
                                    try:
                                        values={key:value.strip() for key,value in
                                            (line.split(':',1) for line in (task/'status').read_text().splitlines() if ':' in line)}
                                        stat=(task/'stat').read_text()
                                        fields=stat[stat.rfind(')')+2:].split()
                                        if fields[0] in ('Z','X','x') or int(fields[6])&4:
                                            continue
                                        tid=int(task.name)
                                        row=dict(tid=tid,starttime=fields[19],cpu=int(fields[36]),state=fields[0],
                                                 allowed_cpus=values['Cpus_allowed_list'],ready=initialization_ready(values),
                                                 preference=values.get('Hmp_preference'),status=values)
                                        prior=self.rows.setdefault(tid,dict(tid=tid,starttime=row['starttime'],cpus=[],ready=False))
                                        require(prior['starttime']==row['starttime'], 'TID reuse inside a case')
                                        if row['cpu'] not in prior['cpus']:
                                            prior['cpus'].append(row['cpu'])
                                        prior['ready'] |= row['ready']
                                        if self.native:
                                            require(row['cpu']<8 and row['preference']=='none' and row['allowed_cpus']=='0-7', 'Native model placement differs')
                                        else:
                                            require(row['preference']=='prefer-x100', 'Automatic thread lost its preference')
                                        tasks.append(row)
                                    except (FileNotFoundError,ProcessLookupError):
                                        continue
                        except (FileNotFoundError,ProcessLookupError):
                            pass
                        self.max_threads=max(self.max_threads,len(tasks))
                        payload=(json.dumps(dict(monotonic=time.monotonic(),tasks=tasks,temperatures=temperatures(),
                            frequencies=frequencies(),cgroup=cgroup_values()),separators=(',',':'))+'\n').encode()
                        self.raw_bytes+=len(payload)
                        require(self.raw_bytes<=256*1024**2, 'Per-case sample budget exceeded')
                        self.digest.update(payload)
                        stream.write(payload)
                        self.stop.wait(0.05)
            except BaseException as error:
                self.error=repr(error)
                kill_group(process)
        self.thread=threading.Thread(target=collect,daemon=True)
        self.thread.start()

    def finish(self):
        self.stop.set()
        self.thread.join(timeout=10)
        require(not self.thread.is_alive(), 'Sampler failed to stop')
        self.thread=None
        value=dict(rows=list(self.rows.values()),maximum_live_threads=self.max_threads,
                   raw_bytes=self.raw_bytes,uncompressed_sha256=self.digest.hexdigest(),error=self.error,
                   period_seconds=0.05)
        save(self.directory/'samples-summary.json',value)
        raw=gzip_identity(self.directory/'process-samples.jsonl.gz')
        require(raw['bytes']==self.raw_bytes and raw['sha256']==self.digest.hexdigest(), 'Raw process samples differ from the collector digest')
        require(self.error is None, 'Sampler failed: '+str(self.error))
        return value


def validate_migration(samples,audit,threads,pid,before,after):
    require(samples['maximum_live_threads']>=threads, 'Requested model threads were not observed')
    rows=samples['rows']
    require(rows and all(row['ready'] for row in rows), 'Missing complete per-thread ready witness')
    require(any(row['tid']==pid for row in rows), 'Missing main-thread identity sample')
    replay=audit['replay']
    require(any(row['tid']==pid for row in replay['physical_commits']), 'Main thread did not actually migrate')
    require(all(after[key]==0 for key in LEDGERS) and after[TIMEOUT]==before[TIMEOUT], 'Ledger or timeout failure')
    for key,route in zip(MOVES,('256-to-1024','1024-to-256')):
        require(after[key]-before[key]==replay['route_counts'][route], 'Global counter delta differs from selected-TID raw ACK/CPU commits')


def execute(config,root,suite):
    trace_module=backend('_retest_trace','experiments/gcc-validation/k3-20261029/harness/migration_trace.py')
    owner=json.loads((root/'owner.json').read_text())
    name=trace_name(owner['unit'])
    trace=trace_module.TraceCapture(name)
    # Prefix is required by the archived private trace backend; no GCC is run.
    require(not trace.instance.exists() and name+'/' not in (trace.root/'kprobe_events').read_text(), 'Owned trace namespace already exists')
    save(root/'trace-owner.json',dict(unit=owner['unit'],name=name))
    trace.configure()
    completed=[]
    native=None
    active_mixed=0.0
    try:
        def run(stage,threads,automatic,index):
            cooling=suite.cool()
            before=zero_ledgers()
            directory=root/f'{index:04d}-{stage}-t{threads}'
            sampler=Samples(directory,config['assets']['elf']['path'],not automatic,suite)
            argv=[config['assets']['elf']['path'],*arguments(config,threads)]
            if automatic:
                argv=[sys.executable,str(Path(__file__).resolve()),'--launch',str(root/'run-config.json'),str(root),*arguments(config,threads)]
            trace_active=False
            try:
                if automatic:
                    # run_command creates its evidence directory before sampling.
                    directory.mkdir()
                    trace.start(directory/'raw-ack-and-cpu.trace.gz')
                    trace_active=True
                    command_directory=directory/'command'
                    sampler.directory=command_directory
                else:
                    command_directory=directory
                row=run_command(argv,command_directory,environment(config,automatic,automatic),
                                root,600,sampler=sampler,check=suite.check)
                after=zero_ledgers()
                text='\n'.join((command_directory/name).read_text(errors='replace') for name in ('stdout.log','stderr.log'))
                ppl=parse_ppl(text)
                audit=None
                if automatic:
                    audit=trace.finish({item['tid'] for item in row['samples']['rows']})
                    trace_active=False
                    save(directory/'trace-summary.json',audit)
                    validate_migration(row['samples'],audit,threads,row['pid'],before,after)
                    check_ppl(ppl,native['ppl'],config['absolute_ppl_tolerance'])
                else:
                    no_migration(before,after)
                    require(row['samples']['maximum_live_threads']>=threads, 'Native reference thread count not observed')
                row.update(stage=stage,threads=threads,ppl=ppl,cooling=cooling,counters_before=before,
                           counters_after=after,trace=audit)
                save(directory/'case.json',row)
                return row
            finally:
                if trace_active:
                    # Preserve raw trace and loss counters even after child failure.
                    try:
                        audit=trace.finish(set(sampler.rows))
                        save(directory/'failed-trace-summary.json',audit)
                    except BaseException as error:
                        save(directory/'trace-failure.json',dict(error=repr(error)))
        native=run('native-reference',16,False,0)
        for index,row in enumerate(prefix(config),1):
            completed.append(run(row['stage'],row['threads'],True,index))
            save(root/'progress.json',dict(completed=len(completed),active_mixed_seconds=active_mixed))
        mixed=0
        while active_mixed<config['minimum_mixed_seconds']:
            threads=config['threads'][mixed%len(config['threads'])]
            row=run('mixed',threads,True,len(completed)+1)
            completed.append(row)
            active_mixed+=row['seconds']
            mixed+=1
            save(root/'progress.json',dict(completed=len(completed),mixed_rounds=mixed,active_mixed_seconds=active_mixed))
        routes={route:sum(row['trace']['replay']['route_counts'][route] for row in completed)
                for route in ('256-to-1024','1024-to-256')}
        require(all(routes.values()), 'Both actual migration directions are required')
        return dict(native_reference=native,cases=completed,rounds=len(completed),mixed_rounds=mixed,
                    mixed_active_seconds=active_mixed,route_counts=routes,measurement=plan(config),
                    historical_numbers_reproduced=False,
                    result_scope='new functional acceptance; not a throughput measurement or replay of historical rounds')
    finally:
        trace.close()


def launch(config_path,root,args):
    config=json.loads(Path(config_path).read_text())
    owner=json.loads((Path(root)/'owner.json').read_text())
    require(owner['unit']+'.service' in str(cgroup()), 'Launcher must run inside its owned unit')
    # Same preference-only opt-in as production launch_bootstrap; readiness is
    # published by the application runtime after exec, never by this helper.
    with open('/proc/prefer_x100','w') as control:
        control.write('inherit:'+str(os.getpid())+'\n')
    elf=config['assets']['elf']['path']
    os.execve(elf,[elf,*args],dict(os.environ))


if __name__=='__main__':
    if len(sys.argv)>4 and sys.argv[1]=='--launch':
        launch(sys.argv[2],sys.argv[3],sys.argv[4:])
    else:
        raise SystemExit(entry('llama',plan,execute))
