"""Explicit, exact known-event boundary; retain every original kernel byte."""
import json
from pathlib import Path
import time

KNOWN_MESSAGE = ('ufshcd-spacemit-k3 c0e00000.ufshc: '
                 'ufshcd_bkops_exception_event_handler: device raised urgent BKOPS exception for bkops status 1')
KNOWN_CONTEXT = {' SUBSYSTEM=platform', ' DEVICE=+platform:c0e00000.ufshc'}
POLICY = {
    'name': 'user-authorized-exact-c0e00000-ufs-bkops-status1',
    'message': KNOWN_MESSAGE,
    'priority': 3,
    'retain_raw_bytes_sequence_hash_and_count': True,
    'all_other_warning_or_error_records_fail': True,
    'storage_status_2_or_3_and_critical_health_fail': True,
    'source_user_url': 'https://lkml.org/lkml/2026/10/2/188#1',
    'source_mail_mirror': 'https://lore-kernel.gnuweeb.org/spacemit/20261002-08-k3-ufs-support-v7-1-bb39007ff9ae%40kernel.org/T/',
}


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
    if (allow_known and priority == 3 and fields[3] == '-' and lines[0] == KNOWN_MESSAGE
            and len(lines[1:]) == len(set(lines[1:]))
            and set(lines[1:]).issubset(KNOWN_CONTEXT)):
        return 'known-ufs-bkops-status1'
    return 'alert'


def validate_storage_sample(sample):
    # An exact status1 log is the sole admitted background event. Actual
    # performance-impact/critical BKOPS states and health errors still fail.
    bkops = sample['bkops_status']
    critical = sample['critical_health']
    if type(bkops) is not int or bkops not in (0, 1):
        raise AssertionError(('UFS BKOPS status outside admitted 0/1', sample))
    if type(critical) is not int or critical != 0:
        raise AssertionError(('UFS critical health is not zero', sample))


class StorageHealth:
    def __init__(self, directory):
        self.directory = directory
        self.last = None
        self.count = 0

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
        with (self.directory / 'storage-health.jsonl').open('a') as output:
            output.write(json.dumps(sample) + '\n')
        validate_storage_sample(sample)
        self.last = now
        self.count += 1
