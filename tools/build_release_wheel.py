"""Source-tree entrypoint for ``make wheel``."""

from __future__ import annotations

import sys
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "cli"))

import chimera  # noqa: E402


def _alias(name: str, paths: list[Path]) -> None:
    module = types.ModuleType(name)
    module.__path__ = [str(path) for path in paths]
    sys.modules[name] = module
    parent_name, _, child_name = name.rpartition(".")
    if parent_name and parent_name in sys.modules:
        setattr(sys.modules[parent_name], child_name, module)


_alias("chimera.preprocess", [ROOT / "preprocessing"])
_alias("chimera.preprocess.offline", [ROOT / "preprocessing" / "offline"])
_alias("chimera.runtime", [
    ROOT / "runtime" / "artifacts" / "manifest" / "chimera",
    ROOT / "runtime" / "artifacts" / "scene_contracts" / "chimera",
    ROOT / "runtime" / "artifacts" / "validate" / "chimera",
    ROOT / "runtime" / "bpf" / "loader" / "chimera",
    ROOT / "runtime" / "env" / "verify" / "chimera",
    ROOT / "runtime" / "launcher" / "run" / "chimera",
    ROOT / "runtime" / "launcher" / "preload" / "chimera",
])

from chimera.release_wheel import main  # noqa: E402


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
