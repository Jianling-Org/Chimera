"""An initialization witness must be complete; transient handler masks are retried."""


def initialization_ready(sample):
    if (sample.get('ready') != '1' or sample.get('exec_requires_ready') != '1'
            or sample.get('preference') != 'prefer-x100'):
        return False
    try:
        caught = int(sample['SigCgt'], 16)
        blocked = int(sample['SigBlk'], 16)
    except (KeyError, ValueError, TypeError):
        return False
    required = (1 << (5 - 1)) | (1 << (41 - 1))
    return caught & required == required and blocked & required == 0
