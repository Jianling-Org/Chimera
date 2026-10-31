# SPDX-License-Identifier: Apache-2.0
"""Three alternating native/bootstrap pairs for five pinned GCC workloads."""
from pathlib import Path
import json
import re
import shutil
import statistics
import sys

from evaluation_common import (entry, environment, no_migration, require, run_command,
                               save, sha, zero_ledgers)


def pair_order(repeat):
    return ('native','bootstrap') if repeat%2==0 else ('bootstrap','native')


def plan(config):
    return dict(protocol=config['protocol'],workloads=[row['name'] for row in config['workloads']],
                measured_runs=30,initialization_probes=10,repeats=3,
                pair_orders=[pair_order(index) for index in range(3)],
                timed_window='monotonic Popen through blocking waitpid; excludes preparation, hashes, cooling and probes')


def initialized_executables(log):
    return set(re.findall(r'chimera bootstrap: initialized pid=\d+ executable=(\S+) workspace=\S+',log))


def summarize(rows):
    values={mode:[row['seconds'] for row in rows if row['mode']==mode] for mode in ('native','bootstrap')}
    require(all(len(times)==3 for times in values.values()), 'Incomplete startup measurements')
    medians={mode:statistics.median(times) for mode,times in values.items()}
    return dict(raw_seconds=values,median_seconds=medians,
                added_seconds=medians['bootstrap']-medians['native'],
                added_percent=100*(medians['bootstrap']/medians['native']-1))


def execute(config,root,suite):
    results={}
    for workload in config['workloads']:
        directory=root/workload['name']
        directory.mkdir()
        output=directory/'output.o'
        # The compiler sees exactly the same output path in both modes.
        argv=[arg.replace('{output}',str(output)) for arg in workload['argv']]
        stdin=config['assets'][workload['stdin_asset']]['path'] if workload.get('stdin_asset') else None
        expected_stdout=None
        expected_output=None
        expected_stderr=None
        records=[]
        def run(mode,label,probe):
            nonlocal expected_stdout,expected_output,expected_stderr
            cooling=suite.cool()
            before=zero_ledgers()
            if output.exists():
                output.unlink()  # Only this new experiment's known compiler output.
            case=directory/label
            row=run_command(argv,case,environment(config,mode=='bootstrap',probe and mode=='bootstrap'),
                            workload['cwd'],workload['timeout_seconds'],stdin=stdin,check=suite.check)
            after=zero_ledgers()
            no_migration(before,after)
            row.update(mode=mode,probe=probe,cooling=cooling,counters_before=before,counters_after=after)
            stdout_sha=sha(case/'stdout.log')
            stderr_sha=sha(case/'stderr.log')
            output_sha=sha(output) if output.is_file() else None
            if workload['name']!='cc1-version':
                require(output_sha is not None, 'Compiler did not produce its owned output')
                shutil.copyfile(output,case/'output.o')
            if expected_stdout is None:
                expected_stdout,expected_output=stdout_sha,output_sha
                expected_stderr=stderr_sha
            require(stdout_sha==expected_stdout and output_sha==expected_output, 'Native/bootstrap output differs')
            if not (mode=='bootstrap' and probe):
                require(stderr_sha==expected_stderr, 'Compiler stderr differs; inspect bootstrap/loader diagnostics')
            if mode=='bootstrap' and probe:
                witnesses=initialized_executables((case/'stderr.log').read_text(errors='replace'))
                expected={str(Path(config['assets'][name]['path']).resolve()) for name in workload['initialized_assets']}
                require(expected <= witnesses, 'Bootstrap was loaded but initialization was not proven')
                row['initialized_executables']=sorted(witnesses)
            row.update(stdout_sha256=stdout_sha,stderr_sha256=stderr_sha,output_sha256=output_sha)
            save(case/'result.json',row)
            return row
        probes=[run(mode,'probe-'+mode,True) for mode in ('native','bootstrap')]
        for repeat in range(3):
            for mode in pair_order(repeat):
                records.append(run(mode,f'r{repeat+1}-'+mode,False))
        value=dict(probes=probes,runs=records,statistics=summarize(records))
        save(directory/'summary.json',value)
        results[workload['name']]=value
        save(root/'progress.json',dict(completed=list(results),total=5))
    return dict(workloads=results,measurement=plan(config),
                historical_numbers_reproduced=False,
                result_scope='new input-bound measurements; compare with historical values only after examining actual results')


if __name__=='__main__':
    raise SystemExit(entry('startup',plan,execute))
