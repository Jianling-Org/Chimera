"""Runtime user-facing Chimera command entry point."""

from .cli import main as _main


def main(argv=None) -> int:
    return _main(argv, command_group="user", prog="chimera-user")


if __name__ == "__main__":
    raise SystemExit(main())
