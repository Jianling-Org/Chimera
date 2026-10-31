"""Experiment-only authorization: record BKOPS1/2 maintenance, keep real faults fatal."""
import collections
import gzip
import hashlib
import json
import os
from pathlib import Path
import select
import subprocess
import threading
import time

ROOT = Path('/root/chimera-gcc-performance-578ab8321-20261029')
MESSAGE_PREFIX = ('ufshcd-spacemit-k3 c0e00000.ufshc: '
                  'ufshcd_bkops_exception_event_handler: device raised urgent BKOPS exception for bkops status ')
CONTEXT = {' SUBSYSTEM=platform', ' DEVICE=+platform:c0e00000.ufshc'}
POLICY = {
    'name': 'explicit-user-authorized-performance-attempt2-bkops-maintenance',
    'controller': 'c0e00000.ufshc',
    'actual_bkops_admitted_states': [0, 1, 2],
    'known_maintenance_log_states': [1, 2],
    'known_maintenance_message_prefix': MESSAGE_PREFIX,
    'known_maintenance_priority': 3,
    'retain_all_original_bytes_sequences_timestamps_hashes_counts': True,
    'bkops2_performance_impact_disclosed': True,
    'actual_status3_or_unknown_and_nonzero_critical_health_fail': True,
    'io_errors_other_warning_error_and_missing_evidence_fail': True,
    'prior_failed_attempt_not_reclassified_or_pooled': True,
}


def save(path, value):
    Path(path).write_text(json.dumps(value, indent=2) + '\n')


def verify_authorization():
    value = json.loads((ROOT / 'storage-policy-authorization-attempt2.json').read_text())
    assert value['attempt'] == 2 and value['data_epoch'] == 'attempt-2'
    assert value['allowed_actual_bkops_states'] == [0, 1, 2]
    assert value['allowed_maintenance_log_states'] == [1, 2]
    assert value['controller'] == 'c0e00000.ufshc'
    assert value['exact_message_prefix'] == MESSAGE_PREFIX and value['log_priority'] == 3
    assert value['critical_health_must_equal'] == 0
    assert value['performance_impact_must_be_disclosed'] is True
    assert value['other_io_errors_unknown_logs_and_safety_checks_unchanged'] is True
    assert value['fresh_full_108_rounds'] is True and value['pool_attempt1_and_attempt2'] is False
    return value


def classify_kernel_record(block, allow_known=False):
    header, separator, body = block.partition(b';')
    if not separator:
        raise ValueError('Malformed kmsg record')
    fields = header.decode('ascii').split(',')
    if len(fields) != 4:
        raise ValueError('Malformed kmsg header')
    priority, sequence, timestamp = map(int, fields[:3])
    if not 0 <= priority <= 191 or sequence < 0 or timestamp < 0:
        raise ValueError('Invalid kmsg header values')
    lines = body.decode('utf-8', errors='strict').splitlines()
    if not lines:
        raise ValueError('Empty kmsg body')
    if priority & 7 > 4:
        return 'informational'
    if (allow_known and priority == 3 and fields[3] == '-'
            and len(lines[1:]) == len(set(lines[1:]))
            and set(lines[1:]).issubset(CONTEXT)):
        for status in (1, 2):
            if lines[0] == MESSAGE_PREFIX + str(status):
                return 'known-ufs-bkops-status' + str(status)
    return 'alert'


def validate_storage_sample(sample):
    bkops = sample['bkops_status']
    critical = sample['critical_health']
    if type(bkops) is not int or bkops not in (0, 1, 2):
        raise AssertionError(('UFS actual BKOPS critical or unknown', sample))
    if type(critical) is not int or critical != 0:
        raise AssertionError(('UFS critical health is not zero', sample))


class StorageHealth:
    def __init__(self, directory):
        self.directory = directory
        self.last = None
        self.counts = collections.Counter()
        self.status2_samples = []

    def check(self, force=False):
        now = time.monotonic()
        if not force and self.last is not None and now - self.last < 30:
            return
        root = Path('/sys/bus/platform/devices/c0e00000.ufshc')
        sample = {
            'utc': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
            'monotonic_seconds': now,
            'bkops_status': int((root / 'attributes/bkops_status').read_text().strip(), 0),
            'critical_health': int((root / 'critical_health').read_text().strip(), 0),
        }
        with (self.directory / 'storage-health.jsonl').open('a') as stream:
            stream.write(json.dumps(sample) + '\n')
        validate_storage_sample(sample)
        self.counts[sample['bkops_status']] += 1
        if sample['bkops_status'] == 2:
            self.status2_samples.append(sample)
        self.last = now

    def summary(self):
        return {
            'sample_counts_by_bkops_status': dict(self.counts),
            'status2_samples': self.status2_samples,
            'status2_performance_environment_observed': bool(self.status2_samples),
            'sampling_period_seconds': 30,
            'limitation': 'Discrete read-only samples; do not infer event duration or exact performance impact.',
            'policy': POLICY,
        }


class KernelLog:
    def __init__(self, directory, allow_known_ufs=False):
        self.directory = directory
        self.stop = threading.Event()
        self.errors = []
        self.alerts = []
        self.allow_known_ufs = allow_known_ufs
        self.known_background_events = []
        self.sequence = []
        self.raw_bytes = 0
        self.digest = hashlib.sha256()
        self.marker_prefix = 'chimera-gcc-validation:' + directory.name + ':'
        self.markers_seen = []

    def marker(self, name):
        # Informational control messages prove that a quiet kernel log reader
        # is live and bracket this measurement; they do not change runtime or
        # scheduler state. Never write a warning or clear existing kernel logs.
        payload = ('<6>' + self.marker_prefix + name + '\n').encode()
        descriptor = os.open('/dev/kmsg', os.O_WRONLY | os.O_CLOEXEC)
        try:
            assert os.write(descriptor, payload) == len(payload)
        finally:
            os.close(descriptor)

    def start(self):
        (self.directory / 'dmesg-before.txt').write_bytes(subprocess.check_output(['dmesg', '--raw']))
        self.fd = os.open('/dev/kmsg', os.O_RDONLY | os.O_NONBLOCK)
        os.lseek(self.fd, 0, os.SEEK_END)
        def collect():
            last_sequence = None
            try:
                with gzip.open(self.directory / 'kernel-continuous.kmsg.gz', 'wb', compresslevel=1) as output:
                    drained = 0
                    while True:
                        ready, _, _ = select.select([self.fd], [], [], 0.1)
                        if not ready:
                            if self.stop.is_set():
                                drained += 1
                                if drained >= 3: break
                            continue
                        try:
                            block = os.read(self.fd, 1024 * 1024)
                        except BlockingIOError:
                            continue
                        if not block: continue
                        drained = 0
                        self.raw_bytes += len(block)
                        assert self.raw_bytes < 512 * 1024**2, 'Kernel evidence budget exceeded'
                        self.digest.update(block)
                        output.write(block)
                        header, _, body = block.partition(b';')
                        priority, seq, _, _ = header.decode().split(',', 3)
                        seq = int(seq)
                        if last_sequence is not None:
                            assert seq == last_sequence + 1, 'Kernel log sequence gap'
                        if not self.sequence: self.sequence.append(seq)
                        last_sequence = seq
                        message = body.decode(errors='replace')
                        for marker in ('begin', 'end'):
                            if self.marker_prefix + marker in message:
                                self.markers_seen.append(marker)
                        classification = classify_kernel_record(block, self.allow_known_ufs)
                        if classification in ('known-ufs-bkops-status1','known-ufs-bkops-status2'):
                            self.known_background_events.append(block.decode())
                        elif classification == 'alert':
                            self.alerts.append(block.decode(errors='replace'))
                    if last_sequence is not None: self.sequence.append(last_sequence)
            except BaseException as error:
                self.errors.append(repr(error))
        self.thread = threading.Thread(target=collect, daemon=True)
        self.thread.start()
        self.marker('begin')

    def finish(self):
        self.marker('end')
        self.stop.set()
        self.thread.join(timeout=10)
        os.close(self.fd)
        assert not self.thread.is_alive(), 'Kernel collector did not stop'
        (self.directory / 'dmesg-after.txt').write_bytes(subprocess.check_output(['dmesg', '--raw']))
        if self.markers_seen != ['begin', 'end']:
            self.errors.append('Kernel log control markers missing or out of order')
        value = dict(sequence_endpoints=self.sequence, errors=self.errors, alerts=self.alerts,
                     kernel_event_policy=POLICY if self.allow_known_ufs else None,
                     known_background_events=self.known_background_events,
                     known_background_event_count=len(self.known_background_events),
                     informational_control_markers=self.markers_seen,
                     uncompressed_bytes=self.raw_bytes, uncompressed_sha256=self.digest.hexdigest())
        save(self.directory / 'kernel-continuous-audit.json', value)
        return value

