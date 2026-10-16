#!/usr/bin/env python3
"""CLI for the read-only layout / metadata-mode diagnosis.

Runs the existing gate-2 ``layout`` fixture under the forced metadata states
(no section, section present with zero records, and a synthetic complete
coverage) and prints the comparison.  Forcing a metadata state is diagnostic
only and is never a safety pass.  This tool writes to stdout (or
``--json-out``) and nothing else: no ELF, no decision, no check credential, no
safety criterion.

Usage:
    python tools/diagnose_layout_metadata_mode.py
    python tools/diagnose_layout_metadata_mode.py --json-out /tmp/diag.json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "cli"))
sys.path.insert(0, str(ROOT / "tests"))

import layout_mode_diagnosis as diag  # noqa: E402
import xgcc_stack_fixture as fixture  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--json-out",
        type=Path,
        default=None,
        help="optional path for the machine-readable comparison",
    )
    parser.add_argument(
        "--function",
        default=fixture.FIXED_FRAME_FUNCTIONS[2],
        help="function name to diagnose (default: the layout constructor)",
    )
    args = parser.parse_args(argv)

    program = fixture.load_program()
    function = fixture.function(program, args.function)
    comparison = diag.diagnose_function(program, function)

    print(diag.format_comparison(comparison))
    print()
    print(
        "Forced metadata mode is a diagnostic control, not a safety pass. "
        "A degradation warning and a propagatable degradation object are "
        "reported as separate facts."
    )

    if args.json_out is not None:
        args.json_out.write_text(
            json.dumps(diag.comparison_to_json(comparison), indent=2),
            encoding="utf-8",
        )
        print(f"wrote {args.json_out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
