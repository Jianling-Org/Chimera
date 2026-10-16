"""Low-overhead monitoring decorator with explicit variable allowlists."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from functools import wraps
import inspect
from time import perf_counter_ns
import sys
from typing import Any, TypeVar, cast

from .model import WatchedValue
from .render import render_line
from .session import current_session


Function = TypeVar("Function", bound=Callable[..., Any])
_MISSING = object()


def _path_value(value: Any, path: tuple[str, ...]) -> Any:
    current = value
    for component in path:
        if isinstance(current, Mapping) and component in current:
            current = current[component]
        else:
            current = getattr(current, component)
    return current


def _probe_value(
    probe: WatchedValue,
    *,
    arguments: Mapping[str, Any],
    local_values: Mapping[str, Any],
    result: Any = _MISSING,
) -> Any:
    if probe.source == "argument":
        value = arguments.get(cast(str, probe.name), _MISSING)
    elif probe.source == "local":
        value = local_values.get(cast(str, probe.name), _MISSING)
    else:
        value = result
    if value is _MISSING:
        return _MISSING
    value = _path_value(value, probe.path)
    return probe.transform(value) if probe.transform is not None else value


def _collect(
    probes: Sequence[WatchedValue],
    *,
    source: str,
    arguments: Mapping[str, Any],
    local_values: Mapping[str, Any],
    result: Any = _MISSING,
) -> dict[str, Any]:
    collected: dict[str, Any] = {}
    for probe in probes:
        if probe.source != source:
            continue
        try:
            value = _probe_value(
                probe,
                arguments=arguments,
                local_values=local_values,
                result=result,
            )
        except BaseException:
            continue
        if value is not _MISSING:
            collected[probe.label] = value
    return collected


def _emit(event: str, values: Mapping[str, Any]) -> None:
    session = current_session()
    if not session.enabled or session.stream is None:
        return
    try:
        print(render_line(event, values), file=session.stream, flush=True)
    except BaseException:
        return


def monitored(
    event: str,
    *,
    variables: tuple[WatchedValue, ...] = (),
) -> Callable[[Function], Function]:
    if not event:
        raise ValueError("monitor event cannot be empty")

    def decorate(function: Function) -> Function:
        signature = inspect.signature(function)
        qualified_name = f"{function.__module__}.{function.__qualname__}"
        needs_locals = any(item.source == "local" for item in variables)

        @wraps(function)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            session = current_session()
            if not session.enabled:
                return function(*args, **kwargs)

            try:
                bound = signature.bind_partial(*args, **kwargs)
                bound.apply_defaults()
                arguments = dict(bound.arguments)
            except BaseException:
                arguments = {}
            start_values: dict[str, Any] = {"function": qualified_name}
            start_values.update(
                _collect(
                    variables,
                    source="argument",
                    arguments=arguments,
                    local_values={},
                )
            )
            _emit(f"{event}.start", start_values)

            captured_locals: dict[str, Any] = {}
            previous_trace = sys.gettrace()

            def trace(frame, trace_event, trace_argument):
                if frame.f_code is function.__code__:
                    if trace_event in {"return", "exception"}:
                        captured_locals.clear()
                        captured_locals.update(frame.f_locals)
                    return trace
                if previous_trace is not None:
                    return previous_trace(frame, trace_event, trace_argument)
                return None

            started = perf_counter_ns()
            if needs_locals:
                sys.settrace(trace)
            try:
                result = function(*args, **kwargs)
            except BaseException:
                raise
            finally:
                if needs_locals:
                    sys.settrace(previous_trace)

            finish_values: dict[str, Any] = {
                "function": qualified_name,
                "duration_ms": (perf_counter_ns() - started) // 1_000_000,
            }
            finish_values.update(
                _collect(
                    variables,
                    source="local",
                    arguments=arguments,
                    local_values=captured_locals,
                    result=result,
                )
            )
            finish_values.update(
                _collect(
                    variables,
                    source="return",
                    arguments=arguments,
                    local_values=captured_locals,
                    result=result,
                )
            )
            _emit(f"{event}.finish", finish_values)
            return result

        return cast(Function, wrapper)

    return decorate


__all__ = ["monitored"]
