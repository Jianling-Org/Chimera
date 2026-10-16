"""Packaging and deployment command entry point."""

from .cli import main as _main


def main(argv=None) -> int:
    return _main(argv, command_group="pkg", prog="chimera-pkg")


if __name__ == "__main__":
    raise SystemExit(main())
