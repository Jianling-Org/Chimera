"""Fail closed on systemd stop signals and unpublished preparation output."""
import json
from pathlib import Path
import signal


def classify(root: Path, phase: str, attempt: int, unit: str, reported_rc: int):
    resource_path = root / 'stage-results' / f'{phase}-{attempt}.resources.json'
    try:
        resource = json.loads(resource_path.read_text())
    except (OSError, ValueError) as error:
        return reported_rc or 125, {'reason': 'missing_or_invalid_exit_evidence', 'error': repr(error)}
    observed = {key: resource.get(key) for key in ('SERVICE_RESULT', 'EXIT_CODE', 'EXIT_STATUS')}
    guard_path = root / 'DISK_GUARD_TRIGGERED.json'
    if guard_path.is_file():
        try:
            guard = json.loads(guard_path.read_text())
        except ValueError:
            return reported_rc or 125, {'reason': 'invalid_disk_guard_evidence', **observed}
        if guard.get('unit') == unit:
            return 28, {'reason': 'disk_guard_stopped_phase', 'guard': guard, **observed}
    if reported_rc:
        return reported_rc, {'reason': 'runner_nonzero_exit', **observed}
    if observed != {'SERVICE_RESULT': 'success', 'EXIT_CODE': 'exited', 'EXIT_STATUS': '0'}:
        code = 125
        if resource.get('EXIT_CODE') in ('killed', 'dumped'):
            number = getattr(signal, 'SIG' + str(resource.get('EXIT_STATUS')), None)
            if number is not None:
                code = 128 + int(number)
        return code, {'reason': 'phase_did_not_exit_normally_with_zero', **observed}
    if phase.startswith('prepare_'):
        workspace = root / 'workspaces' / phase.removeprefix('prepare_')
        required = (workspace / 'workspace.json', workspace / 'artifacts/modules.tsv')
        if workspace.is_symlink() or not all(p.is_file() and not p.is_symlink() for p in required):
            return 125, {'reason': 'prepare_did_not_publish_workspace', 'workspace': str(workspace), **observed}
    return 0, {'reason': 'normal_zero_exit_and_required_publication', **observed}
