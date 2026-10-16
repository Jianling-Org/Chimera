"""Small validation helpers shared by the configuration parser."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import PurePath
from typing import Any


def require_table(value: object, *, name: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise TypeError(f"{name} must be a TOML table")
    return value


def reject_unknown(table: Mapping[str, Any], allowed: set[str], *, name: str) -> None:
    unknown = sorted(set(table) - allowed)
    if unknown:
        raise ValueError(f"unknown {name} key(s): {', '.join(unknown)}")


def validate_workspace_name(value: object) -> str:
    if not isinstance(value, str) or not value:
        raise TypeError("workspace_name must be a non-empty string")
    if value != "auto":
        path = PurePath(value)
        if path.name != value or value in {".", ".."} or any(c in value for c in "/\\\t\r\n"):
            raise ValueError("workspace_name must be 'auto' or a relative basename")
    return value
