"""Locate the runtime CMake source bundle across install layouts."""

from __future__ import annotations

import importlib.resources
from pathlib import Path


def runtime_source_root() -> Path:
    # The Chimera runtime C sources are reachable through the package resource
    # finder in two layouts:
    #   * a source checkout / editable install (scikit-build-core) exposes the
    #     repository root as one of the finder paths, so ``runtime/`` (which
    #     holds CMakeLists.txt) is directly traversable;
    #   * a built wheel ships the CMake install tree under ``runtime_source/``
    #     (runtime/CMakeLists.txt installs to chimera/runtime_source).
    # Prefer the live checkout when present, then fall back to the installed copy.
    root = importlib.resources.files("chimera")
    candidates = ["runtime_source", "runtime"]
    package_root = Path(str(root)).resolve()
    # Source-tree invocations keep CMake under the repository root rather
    # than under ``cli/chimera``.  Restrict this fallback to the real source
    # package so installed wheels and resource-location tests still report a
    # missing bundle instead of reaching into an unrelated checkout.
    source_root = Path(__file__).resolve().parents[4]
    if package_root == source_root / "cli" / "chimera":
        candidates.append(str(source_root / "runtime"))
    for candidate in candidates:
        candidate_path = (
            Path(candidate).resolve()
            if Path(candidate).is_absolute()
            else Path(str(root.joinpath(candidate))).resolve()
        )
        if candidate_path.joinpath("CMakeLists.txt").is_file():
            return candidate_path
    raise FileNotFoundError("the Chimera runtime source bundle is not installed")


__all__ = ["runtime_source_root"]
