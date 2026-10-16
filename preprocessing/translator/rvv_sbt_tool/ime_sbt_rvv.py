#!/usr/bin/env python3
"""Expand A100 integer matrix and data-layout IME into native RVV1024."""

import argparse
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

from riscv.extensions.spacemit_ime.translation import translate_assembly


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="pre-expanded symbolic .s file (not objdump)")
    parser.add_argument("-o", "--output", type=Path)
    args = parser.parse_args()
    try:
        output = translate_assembly(args.input.read_text(encoding="utf-8"))
    except (ValueError, RuntimeError, OSError) as exc:
        parser.exit(2, f"{exc}\n")
    try:
        if args.output:
            args.output.write_text(output, encoding="utf-8")
        else:
            sys.stdout.write(output)
    except (OSError, UnicodeError) as exc:
        parser.exit(2, f"{args.output or '<stdout>'}: {exc}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
