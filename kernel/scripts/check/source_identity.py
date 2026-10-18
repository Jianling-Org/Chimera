#!/usr/bin/env python3
"""Read-only identity check for the exact vendor base or reconstructed freeze."""

import argparse
import json
import subprocess
from pathlib import Path

EXPECTED_BASE = "b1944b2fc1cd68ade89219eb2773fbccc74a66f0"
EXPECTED_TREE = "a1817d0ca2ffe426c8a5448c5d35f5fee5ed17f5"


def git_output(source: Path, *arguments: str) -> str:
    return subprocess.check_output(
        ["git", "-C", str(source), *arguments], text=True
    ).strip()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("--expect", choices=["base", "frozen"], required=True)
    args = parser.parse_args()

    head = git_output(args.source, "rev-parse", "HEAD")
    tree = git_output(args.source, "rev-parse", "HEAD^{tree}")
    clean = not git_output(args.source, "status", "--porcelain")
    identity_matches = (
        head == EXPECTED_BASE if args.expect == "base" else tree == EXPECTED_TREE
    )
    passed = clean and identity_matches
    print(json.dumps({
        "source": str(args.source.resolve()),
        "expect": args.expect,
        "head": head,
        "tree": tree,
        "clean": clean,
        "passed": passed,
        "build_or_boot": False,
    }))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
