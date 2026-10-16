"""GCC-compatible shared-library compiler adapter."""

from __future__ import annotations

from pathlib import Path
import shlex
from typing import Sequence


class GccCompiler:
    def __init__(
        self,
        executable: str,
        *,
        extra_flags: Sequence[str] = (),
        linker_flags: Sequence[str] = (),
    ) -> None:
        self._command = tuple(shlex.split(executable))
        if not self._command:
            raise ValueError("config.tools.cc cannot be empty")
        self._extra_flags = tuple(extra_flags)
        self._linker_flags = tuple(linker_flags)

    def compile(
        self, sources: Sequence[Path], output: Path, *,
        flags: Sequence[str] = ("-fPIC", "-shared"),
    ) -> Sequence[str]:
        return [
            *self._command,
            *flags,
            *self._linker_flags,
            *self._extra_flags,
            *(str(source) for source in sources),
            "-o", str(output),
        ]
