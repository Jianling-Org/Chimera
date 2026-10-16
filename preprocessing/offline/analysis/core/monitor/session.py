"""Context-local monitor activation and output destination."""

from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
import sys
from typing import Iterator, TextIO


@dataclass(frozen=True)
class MonitorSession:
    enabled: bool
    stream: TextIO | None


_SESSION: ContextVar[MonitorSession] = ContextVar(
    "chimera_monitor_session",
    default=MonitorSession(False, None),
)


def current_session() -> MonitorSession:
    return _SESSION.get()


@contextmanager
def monitoring(
    *,
    enabled: bool,
    stream: TextIO | None = None,
) -> Iterator[None]:
    selected_stream = (sys.stdout if stream is None else stream) if enabled else None
    token = _SESSION.set(MonitorSession(bool(enabled), selected_stream))
    try:
        yield
    finally:
        _SESSION.reset(token)


__all__ = ["MonitorSession", "current_session", "monitoring"]
