"""Bounded, redacted, single-line rendering for debug monitor events."""

from __future__ import annotations

from collections.abc import Mapping, Sequence, Set
from dataclasses import fields, is_dataclass
from enum import Enum
import json
from pathlib import Path
from typing import Any


MAX_DEPTH = 3
MAX_ITEMS = 8
MAX_STRING = 256
MAX_LINE = 2048
_SENSITIVE_PARTS = ("password", "token", "secret", "credential")


def _sensitive(name: str) -> bool:
    lowered = name.lower().replace("-", "_")
    return any(part in lowered for part in _SENSITIVE_PARTS)


def _short_text(value: str) -> str:
    normalized = value.replace("\r", "\\r").replace("\n", "\\n")
    if len(normalized) <= MAX_STRING:
        return normalized
    return normalized[: MAX_STRING - 14] + "<truncated>"


def _redact_command(values: Sequence[Any]) -> list[Any]:
    result: list[Any] = []
    redact_next = False
    for value in values:
        if redact_next:
            result.append("<redacted>")
            redact_next = False
            continue
        if isinstance(value, str) and value.startswith("--"):
            option, separator, option_value = value.partition("=")
            if _sensitive(option):
                if separator:
                    result.append(f"{option}=<redacted>")
                else:
                    result.append(value)
                    redact_next = True
                continue
        result.append(value)
    return result


def summarize(
    value: Any,
    *,
    label: str = "value",
    _depth: int = 0,
    _seen: set[int] | None = None,
) -> Any:
    if _sensitive(label):
        return "<redacted>"
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        return _short_text(value)
    if isinstance(value, Path):
        return _short_text(str(value))
    if isinstance(value, bytes):
        return f"<bytes:{len(value)}>"
    if isinstance(value, Enum):
        return summarize(value.value, label=label, _depth=_depth, _seen=_seen)
    if _depth >= MAX_DEPTH:
        return f"<{type(value).__name__}>"

    seen = set() if _seen is None else _seen
    identity = id(value)
    if identity in seen:
        return f"<{type(value).__name__}:cycle>"
    seen.add(identity)
    try:
        if is_dataclass(value) and not isinstance(value, type):
            result: dict[str, Any] = {}
            for item in fields(value)[:MAX_ITEMS]:
                result[item.name] = summarize(
                    getattr(value, item.name),
                    label=item.name,
                    _depth=_depth + 1,
                    _seen=seen,
                )
            if len(fields(value)) > MAX_ITEMS:
                result["..."] = f"{len(fields(value)) - MAX_ITEMS} more fields"
            return result
        if isinstance(value, Mapping):
            ordered = sorted(value.items(), key=lambda item: str(item[0]))
            result = {
                _short_text(str(key)): summarize(
                    item,
                    label=str(key),
                    _depth=_depth + 1,
                    _seen=seen,
                )
                for key, item in ordered[:MAX_ITEMS]
            }
            if len(ordered) > MAX_ITEMS:
                result["..."] = f"{len(ordered) - MAX_ITEMS} more items"
            return result
        if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
            selected = (
                _redact_command(value)
                if label.lower() in {"command", "commands"}
                else list(value)
            )
            result = [
                summarize(
                    item,
                    label=label,
                    _depth=_depth + 1,
                    _seen=seen,
                )
                for item in selected[:MAX_ITEMS]
            ]
            if len(selected) > MAX_ITEMS:
                result.append(f"<{len(selected) - MAX_ITEMS} more items>")
            return result
        if isinstance(value, Set):
            selected = sorted(value, key=lambda item: repr(item))
            result = [
                summarize(
                    item,
                    label=label,
                    _depth=_depth + 1,
                    _seen=seen,
                )
                for item in selected[:MAX_ITEMS]
            ]
            if len(selected) > MAX_ITEMS:
                result.append(f"<{len(selected) - MAX_ITEMS} more items>")
            return result
        return f"<{type(value).__name__}>"
    finally:
        seen.discard(identity)


def render_line(event: str, values: Mapping[str, Any]) -> str:
    parts = ["[DEBUG]", event]
    for label, value in values.items():
        rendered = summarize(value, label=label)
        encoded = json.dumps(
            rendered,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        parts.append(f"{label}={encoded}")
    line = " ".join(parts)
    if len(line) > MAX_LINE:
        line = line[: MAX_LINE - len("<truncated>")] + "<truncated>"
    return line


__all__ = ["MAX_DEPTH", "MAX_ITEMS", "MAX_LINE", "MAX_STRING", "render_line", "summarize"]
