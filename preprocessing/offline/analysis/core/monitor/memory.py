"""Resident-memory accounting and progress lines for long analyses.

A whole-program safety check can run for a long time and retain a lot of
per-instruction state, so it needs to be observable while it runs: which phase
it is in, how much resident memory it holds, how far it has progressed, and
which single function suddenly costs much more than its neighbours.

Design constraints:

* every probe is failure-tolerant — an unreadable ``/proc`` entry, a missing
  platform counter, or a closed stream simply omits the line and never
  propagates into the analysis it observes;
* nothing here walks the object graph.  Progress reports count the *retained
  sparse entries* the analysis hands over explicitly; there is deliberately no
  "measure the size of these objects" mode, which would be far more expensive
  than the analyses themselves;
* lines are emitted through the existing opt-in monitor session (``--debug``),
  so a normal run produces no extra output at all.
"""

from __future__ import annotations

from dataclasses import dataclass
import sys
from time import perf_counter
from typing import Any

from .render import render_line
from .session import current_session

_MIB = 1024 * 1024

#: Emit a cumulative progress line every this many completed functions.
PROGRESS_INTERVAL = 100

#: Report a single function that took at least this long.
SLOW_FUNCTION_SECONDS = 5.0

#: Report a single function whose completion grew RSS by at least this much.
RSS_GROWTH_LIMIT_BYTES = 64 * _MIB

_PROC_STATUS_PATH = "/proc/self/status"


@dataclass(frozen=True)
class MemorySample:
    """One point-in-time resident-memory sample.  ``None`` means unknown."""

    rss_bytes: int | None = None
    peak_rss_bytes: int | None = None
    swap_bytes: int | None = None

    def fields(self) -> dict[str, float]:
        """Render as MiB-valued monitor fields, omitting unknown components."""

        result: dict[str, float] = {}
        if self.rss_bytes is not None:
            result["rss_mib"] = round(self.rss_bytes / _MIB, 1)
        if self.peak_rss_bytes is not None:
            result["peak_rss_mib"] = round(self.peak_rss_bytes / _MIB, 1)
        if self.swap_bytes is not None:
            result["swap_mib"] = round(self.swap_bytes / _MIB, 1)
        return result


def _read_proc_status() -> MemorySample | None:
    try:
        rss = peak = swap = None
        with open(_PROC_STATUS_PATH, encoding="ascii") as status:
            for line in status:
                name, _, rest = line.partition(":")
                if name == "VmRSS":
                    rss = int(rest.split()[0]) * 1024
                elif name == "VmHWM":
                    peak = int(rest.split()[0]) * 1024
                elif name == "VmSwap":
                    swap = int(rest.split()[0]) * 1024
                if rss is not None and peak is not None and swap is not None:
                    break
    except (OSError, ValueError, IndexError):
        return None
    if rss is None and peak is None and swap is None:
        return None
    return MemorySample(rss, peak, swap)


def _read_windows_counters() -> MemorySample | None:
    """Working set / peak working set / pagefile usage via ``GetProcessMemoryInfo``."""

    try:
        import ctypes
        from ctypes import wintypes

        class _ProcessMemoryCounters(ctypes.Structure):
            _fields_ = [
                ("cb", wintypes.DWORD),
                ("PageFaultCount", wintypes.DWORD),
                ("PeakWorkingSetSize", ctypes.c_size_t),
                ("WorkingSetSize", ctypes.c_size_t),
                ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                ("PagefileUsage", ctypes.c_size_t),
                ("PeakPagefileUsage", ctypes.c_size_t),
            ]

        counters = _ProcessMemoryCounters()
        counters.cb = ctypes.sizeof(_ProcessMemoryCounters)
        psapi = ctypes.windll.psapi
        kernel32 = ctypes.windll.kernel32
        psapi.GetProcessMemoryInfo.restype = wintypes.BOOL
        psapi.GetProcessMemoryInfo.argtypes = [
            wintypes.HANDLE,
            ctypes.POINTER(_ProcessMemoryCounters),
            wintypes.DWORD,
        ]
        kernel32.GetCurrentProcess.restype = wintypes.HANDLE
        if not psapi.GetProcessMemoryInfo(
            kernel32.GetCurrentProcess(), ctypes.byref(counters), counters.cb
        ):
            return None
        return MemorySample(
            rss_bytes=int(counters.WorkingSetSize),
            peak_rss_bytes=int(counters.PeakWorkingSetSize),
            swap_bytes=int(counters.PagefileUsage),
        )
    except BaseException:
        return None


def read_memory() -> MemorySample | None:
    """Sample RSS / peak RSS / swap; ``None`` when unavailable on this host."""

    if sys.platform == "win32":
        return _read_windows_counters()
    return _read_proc_status()


def _emit(event: str, values: dict[str, Any]) -> None:
    session = current_session()
    if not session.enabled or session.stream is None:
        return
    try:
        print(render_line(event, values), file=session.stream, flush=True)
    except BaseException:
        return


def _sample_fields(sample: MemorySample | None) -> dict[str, float]:
    return {} if sample is None else sample.fields()


class _Item:
    """One in-flight unit of work (normally one function)."""

    __slots__ = ("_monitor", "name", "address", "instructions", "started", "before")

    def __init__(
        self,
        monitor: "PhaseMemoryMonitor",
        name: str,
        address: int | None,
        instructions: int,
        started: float,
        before: MemorySample | None,
    ) -> None:
        self._monitor = monitor
        self.name = name
        self.address = address
        self.instructions = instructions
        self.started = started
        self.before = before

    def end(self, *, retained: int = 0) -> None:
        self._monitor._finish_item(self, retained)


class _NullItem:
    """No-op item used whenever monitoring is disabled."""

    __slots__ = ()

    def end(self, *, retained: int = 0) -> None:
        return None


_NULL_ITEM = _NullItem()


class PhaseMemoryMonitor:
    """Memory and progress accounting for one analysis phase.

    One instance corresponds to exactly one phase invocation, so its counters
    never outlive the phase they describe.
    """

    def __init__(
        self,
        event: str,
        *,
        progress_interval: int = PROGRESS_INTERVAL,
        slow_seconds: float = SLOW_FUNCTION_SECONDS,
        growth_limit_bytes: int = RSS_GROWTH_LIMIT_BYTES,
    ) -> None:
        self._event = event
        self._progress_interval = max(1, int(progress_interval))
        self._slow_seconds = float(slow_seconds)
        self._growth_limit_bytes = int(growth_limit_bytes)
        self._completed = 0
        self._retained_total = 0

    @property
    def event(self) -> str:
        return self._event

    @staticmethod
    def _active() -> bool:
        session = current_session()
        return bool(session.enabled and session.stream is not None)

    def begin(self, **fields: Any) -> None:
        """Record the phase boundary and its current memory footprint."""

        if not self._active():
            return
        self._completed = 0
        self._retained_total = 0
        _emit(f"{self._event}.start", {**fields, **_sample_fields(read_memory())})

    def end(self, **fields: Any) -> None:
        """Record the phase end, flushing immediately."""

        if not self._active():
            return
        values: dict[str, Any] = {
            **fields,
            "completed": self._completed,
            "retained_states": self._retained_total,
        }
        values.update(_sample_fields(read_memory()))
        _emit(f"{self._event}.finish", values)

    def begin_item(
        self,
        name: str,
        address: int | None = None,
        instructions: int = 0,
    ) -> _Item | _NullItem:
        """Start timing one function; returns a no-op item when disabled."""

        if not self._active():
            return _NULL_ITEM
        return _Item(self, name, address, instructions, perf_counter(), read_memory())

    def _finish_item(self, item: _Item, retained: int) -> None:
        elapsed = perf_counter() - item.started
        after = read_memory()
        self._completed += 1
        self._retained_total += retained

        grew = 0
        if item.before is not None and after is not None:
            before_rss = item.before.rss_bytes
            after_rss = after.rss_bytes
            if before_rss is not None and after_rss is not None:
                grew = after_rss - before_rss
        if elapsed >= self._slow_seconds or grew >= self._growth_limit_bytes:
            values: dict[str, Any] = {
                "function": item.name,
                "function_start": item.address,
                "instructions": item.instructions,
                "retained_states": retained,
                "elapsed_ms": int(elapsed * 1000),
                "rss_growth_mib": round(grew / _MIB, 1),
            }
            values.update(
                {
                    f"before_{key}": value
                    for key, value in _sample_fields(item.before).items()
                }
            )
            values.update(
                {f"after_{key}": value for key, value in _sample_fields(after).items()}
            )
            _emit(f"{self._event}.slow", values)

        if self._completed % self._progress_interval == 0:
            values = {
                "completed": self._completed,
                "retained_states": self._retained_total,
            }
            values.update(_sample_fields(after))
            _emit(f"{self._event}.progress", values)


__all__ = [
    "PROGRESS_INTERVAL",
    "RSS_GROWTH_LIMIT_BYTES",
    "SLOW_FUNCTION_SECONDS",
    "MemorySample",
    "PhaseMemoryMonitor",
    "read_memory",
]
