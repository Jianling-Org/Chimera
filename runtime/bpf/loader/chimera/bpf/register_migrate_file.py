#!/usr/bin/env python3
"""Register one ELF as migratable through the Chimera uprobe queue map."""

from __future__ import annotations

import argparse
import sys

from .registry import ChimeraRegistry, RegistrationError


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--map", required=True, dest="map_path")
    parser.add_argument("--elf", required=True, help="migratable ELF file")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)

    try:
        with ChimeraRegistry(args.map_path, dry_run=args.dry_run) as registry:
            registry.register_migratable_file(args.elf)
    except (OSError, ValueError, RegistrationError) as error:
        print(f"migrate-file registration failed: {error}", file=sys.stderr)
        return 1

    print("registered_migratable_file=1")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
