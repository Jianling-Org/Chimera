"""Private tracefs capture and replay of actual ACK commits and CPU transitions."""
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import select
import threading
import time


def append_control(path, command):
    # Python text append seeks to EOF; seq_lseek rejects SEEK_END on tracefs.
    # Use the native control protocol and never O_TRUNC (which clears all probes).
    descriptor = os.open(path, os.O_WRONLY | os.O_APPEND)
    try:
        payload = (command + '\n').encode('ascii')
        assert os.write(descriptor, payload) == len(payload)
    finally:
        os.close(descriptor)


def replay(lines, selected_pids):
    pending = {}
    acknowledgments = []
    commits = []
    capabilities = []
    unmatched = []
    sequence = 0
    for line in lines:
        sequence += 1
        prefix = re.search(r'-(\d+)\s+\[\d+\].*?\s(\d+\.\d+):\s(.*)', line)
        if not prefix:
            continue
        tid, timestamp, detail = int(prefix[1]), float(prefix[2]), prefix[3]
        if 'ack_enter:' in detail:
            fields = dict(re.findall(r'(generation|action)=([^\s]+)', detail))
            if len(fields) != 2:
                raise ValueError('Missing raw ACK fields: ' + line)
            row = dict(tid=tid, generation=int(fields['generation'], 0), action=int(fields['action'], 0),
                       enter_time=timestamp, enter_sequence=sequence)
            pending.setdefault(tid, []).append(row)
        elif 'ack_return:' in detail:
            value = re.search(r'result=(-?(?:0x[0-9a-f]+|\d+))', detail)
            if not value:
                raise ValueError('Missing ACK return: ' + line)
            if not pending.get(tid):
                unmatched.append(dict(tid=tid, kind='return_without_entry', line=line))
                continue
            row = pending[tid].pop()
            row.update(return_time=timestamp, return_sequence=sequence, result=int(value[1], 0))
            if row['action'] == 1 and row['result'] == 8:
                acknowledgments.append(row)
            if row['action'] == 7 and row['result'] == 8:
                capabilities.append(row)
        elif 'sched_prefer_a100_migrate:' in detail:
            values = re.search(r'pid=(\d+) src_cpu=(\d+) dst_cpu=(\d+) reason=(\S+)', detail)
            if values:
                commits.append(dict(tid=int(values[1]), src_cpu=int(values[2]), dst_cpu=int(values[3]),
                                    reason=values[4], timestamp=timestamp, sequence=sequence))
    physical = []
    for commit in commits:
        if commit['tid'] not in selected_pids:
            continue
        source, target = commit['src_cpu'], commit['dst_cpu']
        if source < 8 <= target:
            route = '256-to-1024'
        elif target < 8 <= source:
            route = '1024-to-256'
        else:
            continue
        matching = [ack for ack in acknowledgments if ack['tid'] == commit['tid']
                    and ack['enter_time'] <= commit['timestamp'] <= ack['return_time']]
        if len(matching) != 1:
            raise ValueError('CPU commit lacks exactly one accepted raw ACK: ' + repr(commit))
        physical.append({**commit, 'route': route, 'ack': matching[0]})
    selected_unmatched = [x for x in unmatched if x['tid'] in selected_pids]
    selected_pending = {pid: rows for pid, rows in pending.items() if pid in selected_pids and rows}
    if selected_unmatched or selected_pending:
        raise ValueError('Incomplete selected-TID ACK trace')
    by_pid = {}
    for item in physical:
        by_pid.setdefault(str(item['tid']), set()).add(item['route'])
    return dict(physical_commits=physical,
                route_counts={route: sum(x['route'] == route for x in physical)
                              for route in ('256-to-1024', '1024-to-256')},
                both_route_tids=[int(pid) for pid, routes in by_pid.items() if len(routes) == 2],
                raw_accepted_ack_count=sum(x['tid'] in selected_pids for x in acknowledgments),
                capability_ack_count=sum(x['tid'] in selected_pids for x in capabilities))


class TraceCapture:
    def __init__(self, name):
        assert re.fullmatch(r'chimera_gcc_[a-z0-9_]+', name)
        self.name = name
        self.root = Path('/sys/kernel/tracing')
        self.instance = self.root / 'instances' / name
        self.registered = []
        self.thread = None
        self.fd = None
        self.stop_event = threading.Event()
        self.failure = None

    def configure(self):
        assert not self.instance.exists(), 'Private instance already exists; inspect rather than replacing it'
        prior = (self.root / 'kprobe_events').read_text()
        assert self.name + '/' not in prior
        self.entry_event = self.name + '_ack_enter'
        self.return_event = self.name + '_ack_return'
        definitions = [
            (self.entry_event, f'p:{self.name}/{self.entry_event} hmp_prefer_ack_write generation=+u0($arg2):u32 action=+u4($arg2):u32'),
            (self.return_event, f'r256:{self.name}/{self.return_event} hmp_prefer_ack_write result=$retval:s64'),
        ]
        try:
            for event, definition in definitions:
                append_control(self.root / 'kprobe_events', definition)
                self.registered.append(event)
            self.instance.mkdir()
            (self.instance / 'tracing_on').write_text('0')
            (self.instance / 'buffer_size_kb').write_text('1024')
            (self.instance / 'trace_clock').write_text('mono')
            for event in (self.entry_event, self.return_event):
                (self.instance / 'events' / self.name / event / 'enable').write_text('1')
            (self.instance / 'events/sched/sched_prefer_a100_migrate/enable').write_text('1')
        except BaseException:
            self.close()
            raise

    def start(self, path):
        assert self.thread is None
        self.path = Path(path)
        self.stop_event.clear()
        self.failure = None
        self.digest = hashlib.sha256()
        self.raw_bytes = 0
        (self.instance / 'trace').write_text('')
        self.fd = os.open(self.instance / 'trace_pipe', os.O_RDONLY | os.O_NONBLOCK)
        def collect():
            try:
                with gzip.open(self.path, 'wb', compresslevel=1) as output:
                    drained = 0
                    while True:
                        ready, _, _ = select.select([self.fd], [], [], 0.1)
                        if not ready:
                            if self.stop_event.is_set():
                                drained += 1
                                if drained >= 3:
                                    break
                            continue
                        try:
                            block = os.read(self.fd, 1024 * 1024)
                        except BlockingIOError:
                            continue
                        if block:
                            drained = 0
                            self.raw_bytes += len(block)
                            assert self.raw_bytes <= 2 * 1024**3, 'Trace budget exceeded; preserve and stop'
                            self.digest.update(block)
                            output.write(block)
            except BaseException as error:
                self.failure = repr(error)
        self.thread = threading.Thread(target=collect, daemon=True)
        self.thread.start()
        (self.instance / 'tracing_on').write_text('1')

    def finish(self, selected_pids):
        (self.instance / 'tracing_on').write_text('0')
        self.stop_event.set()
        self.thread.join(timeout=10)
        assert not self.thread.is_alive(), 'Trace collector failed to stop'
        self.thread = None
        os.close(self.fd)
        self.fd = None
        assert self.failure is None, self.failure
        per_cpu = {}
        for p in sorted((self.instance / 'per_cpu').glob('cpu*/stats')):
            text = p.read_text()
            per_cpu[p.parent.name] = text
            for line in text.splitlines():
                key, _, value = line.partition(':')
                if key.strip() in ('overrun', 'commit overrun', 'dropped events'):
                    assert int(value.strip()) == 0, ('Lost trace events', str(p), text)
        profile = (self.root / 'kprobe_profile').read_text()
        own_profile = [line for line in profile.splitlines() if any(name in line for name in self.registered)]
        assert len(own_profile) == 2, ('Missing kprobe accounting', own_profile)
        assert all(int(line.split()[-1]) == 0 for line in own_profile), ('Missed probes', own_profile)
        digest = hashlib.sha256()
        with gzip.open(self.path, 'rb') as source:
            for block in iter(lambda: source.read(1024 * 1024), b''):
                digest.update(block)
        assert digest.hexdigest() == self.digest.hexdigest()
        with gzip.open(self.path, 'rt', encoding='utf-8') as source:
            audit = replay(source, set(selected_pids))
        return dict(raw_trace=str(self.path), uncompressed_sha256=self.digest.hexdigest(),
                    uncompressed_bytes=self.raw_bytes, per_cpu=per_cpu, kprobe_profile=own_profile,
                    replay=audit)

    def close(self):
        if self.instance.exists():
            (self.instance / 'tracing_on').write_text('0')
        if self.thread is not None:
            self.stop_event.set()
            self.thread.join(timeout=10)
            self.thread = None
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None
        if self.instance.exists():
            (self.instance / 'events/enable').write_text('0')
            self.instance.rmdir()
        for event in reversed(self.registered):
            append_control(self.root / 'kprobe_events', f'-:{self.name}/{event}')
        self.registered.clear()
