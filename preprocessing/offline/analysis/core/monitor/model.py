"""Declarative descriptions of values captured by monitoring decorators."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Literal


ValueTransform = Callable[[Any], Any]
ValueSource = Literal["argument", "local", "return"]


@dataclass(frozen=True)
class WatchedValue:
    """One explicitly allowed argument, local, or return value."""

    label: str
    source: ValueSource
    name: str | None = None
    path: tuple[str, ...] = ()
    transform: ValueTransform | None = None

    def __post_init__(self) -> None:
        if not self.label:
            raise ValueError("monitored value label cannot be empty")
        if self.source != "return" and not self.name:
            raise ValueError(f"{self.source} monitored values require a name")


def argument(
    name: str,
    *,
    label: str | None = None,
    path: tuple[str, ...] = (),
    transform: ValueTransform | None = None,
) -> WatchedValue:
    return WatchedValue(label or name, "argument", name, tuple(path), transform)


def local(
    name: str,
    *,
    label: str | None = None,
    path: tuple[str, ...] = (),
    transform: ValueTransform | None = None,
) -> WatchedValue:
    return WatchedValue(label or name, "local", name, tuple(path), transform)


def returned(
    *,
    label: str = "result",
    path: tuple[str, ...] = (),
    transform: ValueTransform | None = None,
) -> WatchedValue:
    return WatchedValue(label, "return", None, tuple(path), transform)


__all__ = ["WatchedValue", "argument", "local", "returned"]
