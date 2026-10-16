"""Dynamic-symbol inspection through nm."""

from pathlib import Path
from typing import Sequence


class NmInspector:
    def __init__(self, executable: str) -> None:
        self._executable = executable

    def exported_symbols(self, library: Path) -> Sequence[str]:
        return [self._executable, "-D", "--defined-only", str(library)]
