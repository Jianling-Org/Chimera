#!/usr/bin/env python3
"""Run this checkout's CLI without replacing an existing editable installation."""
from pathlib import Path
import importlib
import sys

root = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(root / "cli"), str(root)]
sys.meta_path[:] = [finder for finder in sys.meta_path
                   if type(finder).__name__ != "ScikitBuildRedirectingFinder"]
if len(sys.argv) < 2 or sys.argv[1] not in {"user", "pkg", "dev"}:
    raise SystemExit("usage: run_source_cli.py {user|pkg|dev} CLI arguments")
role = sys.argv.pop(1)
module = importlib.import_module("chimera." + role)
Path(module.__file__).resolve().relative_to(root)
sys.argv[0] = "chimera-" + role
raise SystemExit(module.main())
