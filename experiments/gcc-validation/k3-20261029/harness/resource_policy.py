"""Task-owned temporary swap for the diagnosed large cc1 analysis stages."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import time

ROOT = Path('/root/chimera-gcc-validation-578ab8321')
SWAP = ROOT / 'resources/cc1-analysis.swap'
OWNER = SWAP.with_suffix('.owner.json')
CAPACITY_PROBE = ROOT / 'resources/prepare-workspace-capacity.probe'
GIB = 1024 ** 3
LARGE_PHASES = frozenset(('metadata_cc1', 'strict_cc1', 'prepare_cc1'))


def policy(phase):
    if phase in LARGE_PHASES:
        settings = {'memory_high': '12G', 'memory_max': '13G', 'swap_max': '16G',
                    'swap_bytes': 16 * GIB, 'runtime_max': '6h'}
        if phase == 'prepare_cc1':
            # The interrupted run already held 15.9 GB before the second
            # translated dump, offset maps, and linker/patch copies completed.
            # Reserve both routes' complete growth plus temporary files and
            # a separate margin; the existing 3 GiB stop guard stays intact.
            # Attempt 1 took 4h50 before the second route and offset-map /
            # patch publication completed. A six-hour phase limit would risk
            # another predictable interruption. Keep a finite 18-hour bound
            # for this phase only; memory, swap and safety limits are intact.
            settings.update(runtime_max='18h', workspace_budget_bytes=28 * GIB,
                            disk_margin_bytes=6 * GIB,
                            required_free_bytes=50 * GIB)
        return settings
    return {'memory_high': '11G', 'memory_max': '12G', 'swap_max': '0',
            'swap_bytes': 0, 'runtime_max': '6h'}


def active_swap():
    return {line.split()[0] for line in Path('/proc/swaps').read_text().splitlines()[1:]}


def record(record_id, action, **fields):
    entry = {'utc': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
             'record_id': record_id, 'action': action, **fields}
    with (ROOT / 'resource-events.jsonl').open('a') as output:
        output.write(json.dumps(entry) + '\n')


def check_path():
    assert ROOT.resolve() == ROOT
    assert not SWAP.parent.is_symlink() and not SWAP.is_symlink()
    assert SWAP.resolve() == SWAP and SWAP.parent == ROOT / 'resources'


def enable(record_id, settings):
    check_path()
    if not settings['swap_bytes']:
        if SWAP.exists() or str(SWAP) in active_swap():
            raise RuntimeError('Unexpected task swap remains before a no-swap phase')
        return
    # Keep six GiB free for reports plus the existing three-GiB disk guard.
    free = shutil.disk_usage(ROOT).free
    required = settings.get('required_free_bytes', settings['swap_bytes'] + 9 * GIB)
    if free < required:
        raise RuntimeError(f'Insufficient disk before allocation: free={free}, required={required}')
    SWAP.parent.mkdir(exist_ok=True, mode=0o700)
    if SWAP.exists() or OWNER.exists() or CAPACITY_PROBE.exists() or str(SWAP) in active_swap():
        raise RuntimeError('Task swap already exists; inspect ownership before recovery')
    descriptor = os.open(SWAP, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    os.close(descriptor)
    OWNER.write_text(json.dumps({'record_id': record_id, 'path': str(SWAP)}) + '\n')
    try:
        subprocess.run(['fallocate', '-l', str(settings['swap_bytes']), str(SWAP)], check=True)
        workspace_budget = settings.get('workspace_budget_bytes', 0)
        if workspace_budget:
            # Prove ext4 can allocate swap + the full working budget together.
            # Release only the private probe before running the real pipeline.
            assert CAPACITY_PROBE.resolve() == CAPACITY_PROBE
            descriptor = os.open(CAPACITY_PROBE, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            os.close(descriptor)
            try:
                subprocess.run(['fallocate', '-l', str(workspace_budget), str(CAPACITY_PROBE)], check=True)
                assert CAPACITY_PROBE.stat().st_blocks * 512 >= workspace_budget
                remaining = shutil.disk_usage(ROOT).free
                if remaining < settings['disk_margin_bytes']:
                    raise RuntimeError(f'Full disk capacity probe left insufficient margin: {remaining}')
                record(record_id, 'disk_capacity_verified', working_bytes=workspace_budget,
                       swap_bytes=settings['swap_bytes'], margin_free_bytes=remaining)
            finally:
                assert CAPACITY_PROBE.is_file() and not CAPACITY_PROBE.is_symlink()
                assert CAPACITY_PROBE.stat().st_uid == os.geteuid()
                CAPACITY_PROBE.unlink()
        subprocess.run(['mkswap', str(SWAP)], check=True)
        subprocess.run(['swapon', '--priority', '10', str(SWAP)], check=True)
        assert str(SWAP) in active_swap()
        record(record_id, 'swap_enabled', path=str(SWAP), free_before=free,
               free_after=shutil.disk_usage(ROOT).free, policy=settings)
    except BaseException:
        disable(record_id)
        raise


def disable(record_id):
    check_path()
    if SWAP.exists() or str(SWAP) in active_swap():
        if not OWNER.is_file() or OWNER.is_symlink():
            raise RuntimeError('Refusing to remove swap without its task ownership record')
        assert json.loads(OWNER.read_text()) == {'record_id': record_id, 'path': str(SWAP)}
    if str(SWAP) in active_swap():
        subprocess.run(['swapoff', str(SWAP)], check=True)
    if SWAP.exists():
        assert SWAP.is_file() and SWAP.stat().st_uid == 0
        SWAP.unlink()
        record(record_id, 'swap_removed', path=str(SWAP), free_after=shutil.disk_usage(ROOT).free)
    if OWNER.exists():
        OWNER.unlink()


if __name__ == '__main__':
    # Exercise actual ext4/kernel swap support without an analysis retry.
    enable('resource-smoke', policy('metadata_cc1'))
    try:
        assert str(SWAP) in active_swap()
    finally:
        disable('resource-smoke')
