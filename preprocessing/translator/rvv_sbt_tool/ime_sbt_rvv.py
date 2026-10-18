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
        output = translate_assembly(args.input.read_text())
    except (ValueError, RuntimeError) as exc:
        parser.exit(2, f"{exc}\n")
    if args.output:
        args.output.write_text(output)
    else:
        sys.stdout.write(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
