"""Read the loader's own answer to "what will this launch load?".

``ld.so --list`` prints the set of objects it resolved, and it does so using the
very search rules that will apply to the launch -- ``DT_RPATH``, then the
command-line search path, then ``DT_RUNPATH``, then the cache.  Re-implementing
those rules would be a second, permanently lagging copy of the loader; asking
the loader is both cheaper and authoritative.

The output is meant for humans, so parsing it is deliberately strict: any shape
this module does not recognise is a hard failure rather than a skipped line.
Silently ignoring an unrecognised line is how a library ends up unverified.

Two modes, never combined: ``--list`` prints the object set and exits 0;
``--verify`` prints nothing and exits with a status describing whether the
loader can load the program at all.  glibc stores the mode in a single variable,
so a later option overwrites an earlier one -- the two must be separate calls.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path, PurePosixPath


# ``name => path (address)`` for a resolved dependency, ``path (address)`` for
# an object given by absolute path, and ``name (address)`` for one with no file
# behind it.  ``name => not found`` carries no address and is matched first, so
# an unresolvable dependency can never be mistaken for a plain name.
_UNRESOLVED = re.compile(r"^(?P<name>.+?) => not found$")
_LINE = re.compile(
    r"^(?P<name>.+?)"
    r"(?: => (?P<target>.+?))?"
    r" \(0x[0-9a-fA-F]+\)$"
)


class LoaderReportError(RuntimeError):
    """The loader's output could not be read, or it rejected the program."""


@dataclass(frozen=True)
class LoadedObject:
    #: Basename the loader reports (or the absolute path when it prints one).
    name: str
    #: Absolute path the loader resolved, or ``None`` for objects with no file
    #: behind them (``linux-vdso.so.1``).
    path: Path | None


def _is_absolute(value: str) -> bool:
    # The loader's own output is POSIX even when we happen to be parsing it on
    # a development host that is not Linux.
    return PurePosixPath(value).is_absolute()


def parse_loader_list(output: str) -> tuple[LoadedObject, ...]:
    """Parse ``ld.so --list`` output.

    Raises :class:`LoaderReportError` on any line that is not one of the three
    recognised shapes, and on a dependency the loader could not resolve.
    """

    objects: list[LoadedObject] = []
    for number, raw in enumerate(output.splitlines(), start=1):
        line = raw.strip()
        if not line:
            continue
        unresolved = _UNRESOLVED.match(line)
        if unresolved is not None:
            raise LoaderReportError(
                f"loader could not resolve {unresolved.group('name')}: {raw!r}"
            )
        match = _LINE.match(line)
        if match is None:
            raise LoaderReportError(
                f"unrecognised loader output on line {number}: {raw!r}"
            )
        name = match.group("name").strip()
        target = match.group("target")
        if target is not None:
            target = target.strip()
            if target == "not found":
                raise LoaderReportError(f"loader could not resolve {name}: {raw!r}")
            if not _is_absolute(target):
                raise LoaderReportError(
                    f"loader resolved {name} to a non-absolute path: {raw!r}"
                )
            objects.append(LoadedObject(Path(name).name, Path(target)))
        elif _is_absolute(name):
            # An object given by absolute path (``LD_PRELOAD``); the loader
            # prints it directly because there is no name to resolve.
            objects.append(LoadedObject(Path(name).name, Path(name)))
        else:
            # No file behind it -- linux-vdso.so.1, typically.
            objects.append(LoadedObject(Path(name).name, None))
    return tuple(objects)


__all__ = ["LoadedObject", "LoaderReportError", "parse_loader_list"]
