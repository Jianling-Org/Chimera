"""Resolve target ELF dependencies without executing host ``ldd``."""

from __future__ import annotations

from collections import deque
from pathlib import Path

from .elf import interpreter


def needed_libraries(path: Path) -> tuple[str, ...]:
    from elftools.elf.elffile import ELFFile

    with path.open("rb") as stream:
        elf = ELFFile(stream)
        for segment in elf.iter_segments():
            if segment.header.p_type == "PT_DYNAMIC":
                return tuple(
                    str(tag.needed)
                    for tag in segment.iter_tags()
                    if tag.entry.d_tag == "DT_NEEDED"
                )
        return ()


def _find_library(name: str, roots: tuple[Path, ...]) -> Path:
    if Path(name).name != name:
        raise ValueError(f"ELF dependency is not a basename: {name!r}")
    for root in roots:
        candidate = root / name
        if candidate.is_file():
            return candidate
    raise FileNotFoundError(
        f"target ELF dependency not found in configured library roots: {name}"
    )


def collect_dependencies(
    input_elf: Path, library_roots: tuple[Path, ...]
) -> tuple[Path, ...]:
    """Return main, interpreter, and recursive ``DT_NEEDED`` dependencies."""

    source = input_elf.resolve()
    roots = (source.parent, *tuple(root.resolve() for root in library_roots))
    selected: list[Path] = [source]
    by_name: dict[str, Path] = {source.name: source}
    pending = deque(needed_libraries(source))
    dynamic_interpreter = interpreter(source)
    if dynamic_interpreter:
        pending.appendleft(Path(dynamic_interpreter).name)

    while pending:
        name = pending.popleft()
        if name in by_name:
            continue
        library = _find_library(name, roots)
        previous = by_name.setdefault(library.name, library)
        if previous != library:
            raise ValueError(f"dependency basename collision: {previous} and {library}")
        selected.append(library)
        pending.extend(needed_libraries(library))
    return tuple(selected)
