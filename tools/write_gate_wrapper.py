#!/usr/bin/env python3
"""Write the compiler wrapper scripts of one build stage.

The wrapper is what GCC's ``configure`` is handed as ``CC``/``CXX``: a two-line
``sh`` script that execs ``chimera-pkg llvm`` with a *fixed* decision file, so
the build can never pick up a strategy from the global "latest check" pointer.

This used to be an inline heredoc inside the K3 driver script.  A heredoc
cannot be tested, and an ``import`` missing from it only shows up hours into a
rebuild -- which is exactly what happened (``sys`` was used but not imported).
It is a program now: arguments in, files out, exit code, and a test.

Nothing here runs a compiler, writes a decision or touches a check credential:
the decision file is read by ``chimera-pkg llvm`` at build time, not here.

Usage:
    python tools/write_gate_wrapper.py \
        --wrapper-dir /run/wrappers --pkg /venv/bin/chimera-pkg \
        --decision /run/decisions/gate3.decision.json [--prefix gate3]
"""

from __future__ import annotations

import argparse
import shlex
import sys
from pathlib import Path

EXIT_OK = 0
EXIT_BAD_INPUT = 3

#: The two flavours: a plain compiler wrapper and one that adds ``--cxx``.
FLAVOURS = (
    ("cc", ()),
    ("cxx", ("--cxx",)),
)


def wrapper_body(pkg: str, decision: str, extra: tuple[str, ...]) -> str:
    """The text of one wrapper script.

    ``--`` keeps a source file named like an option from being parsed as one,
    and ``"$@"`` forwards the rest of the compiler command line unchanged.
    """

    args = [pkg, "llvm", *extra, "--list", decision, "--"]
    return "#!/bin/sh\nexec " + shlex.join(args) + ' "$@"\n'


def write_wrappers(
    wrapper_dir: Path, pkg: str, decision: str, prefix: str = "gate3"
) -> list[Path]:
    if not pkg:
        raise ValueError("the chimera-pkg path must not be empty")
    decision_path = Path(decision)
    if not decision_path.is_file():
        raise FileNotFoundError(f"decision file does not exist: {decision_path}")
    wrapper_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for suffix, extra in FLAVOURS:
        path = wrapper_dir / f"{prefix}-{suffix}"
        path.write_text(wrapper_body(pkg, str(decision_path), extra), encoding="utf-8")
        path.chmod(0o755)
        written.append(path)
    return written


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wrapper-dir", type=Path, required=True)
    parser.add_argument("--pkg", required=True)
    parser.add_argument("--decision", type=Path, required=True)
    parser.add_argument("--prefix", default="gate3")
    args = parser.parse_args(argv)
    try:
        written = write_wrappers(
            args.wrapper_dir, args.pkg, args.decision, args.prefix
        )
    except (ValueError, OSError) as error:
        print(f"input error: {error}", file=sys.stderr)
        return EXIT_BAD_INPUT
    for path in written:
        print(f"wrapper: {path}")
    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
