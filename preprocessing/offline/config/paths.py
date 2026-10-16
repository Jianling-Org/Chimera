"""Path and executable references relative to a selected profile file."""

from __future__ import annotations

from pathlib import Path


def resolve_path(value: object, *, source: Path, field: str) -> Path:
    if not isinstance(value, str) or not value:
        raise TypeError(f"{field} must be a non-empty path string")
    candidate = Path(value).expanduser()
    return candidate.resolve() if candidate.is_absolute() else (source.parent / candidate).resolve()


def executable_reference(value: object, *, source: Path, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise TypeError(f"{field} must be a non-empty executable string")
    if "/" in value or "\\" in value:
        return str(resolve_path(value, source=source, field=field))
    return value


def translator_reference(value: object, *, source: Path, field: str) -> Path:
    """Resolve source-layout example references in an installed wheel.

    Bundled examples retain their repository-relative paths. Older saved
    profiles can also contain the resulting absolute ``chimera/preprocessing``
    path. Only relocate known built-in scripts to the sibling package layout;
    existing source files and arbitrary custom translators retain their paths.
    """
    path = resolve_path(value, source=source, field=field)
    if path.is_file():
        return path
    if path.name in {"rvv_sbt_rvv.py", "rvv_sbt_rvv1024.py"}:
        # Wheels expose the namespace as ``chimera.preprocess`` while older
        # generated profiles recorded ``chimera/preprocessing``.  Locate the
        # package component instead of relying on a fixed number of parent
        # directories (virtualenv/site-packages prefixes vary).
        parts = path.parts
        for index, part in enumerate(parts[:-1]):
            if part != "chimera" or index + 1 >= len(parts) or parts[index + 1] != "preprocessing":
                continue
            installed = Path(*parts[: index + 1], "preprocess", *parts[index + 2 :])
            if installed.is_file():
                return installed.resolve()
    return path
