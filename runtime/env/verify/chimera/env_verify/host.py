"""Validate host-side BPF and migration-control capabilities."""

from __future__ import annotations

import os
from pathlib import Path

from chimera.preprocess.offline.config import BaseConfig
from chimera.runtime.bpf.registry import PinnedUprobeMap


def verify_host(settings: BaseConfig) -> None:
    with PinnedUprobeMap(settings.bpf_map):
        pass
    control = Path(settings.ai_thread_control)
    if not control.exists():
        raise RuntimeError(f"migration control is missing: {control}")
    if not os.access(control, os.W_OK):
        raise RuntimeError(f"migration control is not writable: {control}")
