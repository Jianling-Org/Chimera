"""Artifact hashing owned by immutable workspace publication."""

from __future__ import annotations

from hashlib import sha256
from pathlib import Path


def sha256_file(path: Path) -> str:
    return sha256(path.read_bytes()).hexdigest()
