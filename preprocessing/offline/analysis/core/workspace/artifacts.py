"""Artifact hashing owned by immutable workspace publication."""

from __future__ import annotations

from hashlib import sha256
from pathlib import Path


def sha256_file(path: Path) -> str:
    from chimera.runtime.manifest.file_identity import cached_sha256
    return cached_sha256(path)
