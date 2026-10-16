"""Small, injectable subprocess boundary."""

from __future__ import annotations

from pathlib import Path
import subprocess
from typing import Sequence

from ...core.monitor import argument, monitored, returned


class CommandError(RuntimeError):
    """An external tool failed or could not be started."""


class CommandRunner:
    @monitored(
        "tool.command",
        variables=(
            argument("command"),
            argument("stdout_path"),
            returned(label="returncode", path=("returncode",)),
        ),
    )
    def run(
        self,
        command: Sequence[str],
        *,
        stdout_path: Path | None = None,
    ) -> subprocess.CompletedProcess[str]:
        try:
            if stdout_path is None:
                return subprocess.run(
                    list(command),
                    check=True,
                    capture_output=True,
                    text=True,
                )
            stdout_path.parent.mkdir(parents=True, exist_ok=True)
            with stdout_path.open("w", encoding="utf-8", newline="\n") as output:
                return subprocess.run(
                    list(command),
                    check=True,
                    stdout=output,
                    stderr=subprocess.PIPE,
                    text=True,
                )
        except (OSError, subprocess.CalledProcessError) as error:
            stderr = getattr(error, "stderr", None)
            detail = f": {stderr.strip()}" if stderr else ""
            raise CommandError(f"command failed: {' '.join(command)}{detail}") from error
