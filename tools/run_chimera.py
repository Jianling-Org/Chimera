"""Run the source-tree CLI with the same package layout as a wheel."""

from __future__ import annotations

import sys
import types
import os
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "cli"))
# The source-tree launcher aliases the Python package directories below, but
# those aliases do not give ``importlib.resources`` a package-owned
# toolchain_source directory.  Point the toolchain resolver at the checked-in
# patch/plugin bundle explicitly so component builds requested by ``make
# wheel`` can bootstrap from a source checkout as well as an installed wheel.
os.environ.setdefault(
    "CHIMERA_TOOLCHAIN_SOURCE_ROOT",
    str(ROOT / "preprocessing" / "offline" / "toolchain" / "llvm-21.1.0"),
)

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

_role = os.environ.get("CHIMERA_ROLE", "pkg")
if _role not in {"pkg", "user", "dev"}:
    raise SystemExit(f"unknown CHIMERA_ROLE: {_role}")
main = __import__(f"chimera.{_role}", fromlist=["main"]).main  # noqa: E402


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
