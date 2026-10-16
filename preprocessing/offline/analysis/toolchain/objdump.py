"""GNU objdump command and text-format description."""

from __future__ import annotations

from pathlib import Path
from typing import Sequence

from ..core.contracts import DisassemblyFormat


class LinuxObjdump:
    def __init__(self, executable: str) -> None:
        self._executable = executable
        self._format = DisassemblyFormat(
            instruction_pattern=(
                r"^\s*([0-9a-f]+):\s+([0-9a-f]+)\s+([\w.]+)\s*(.*)$"
            ),
            function_pattern=r"^([0-9a-f]+)\s+<([^>]+)>:",
            field_map={
                "address": 1, "machine_code": 2, "opcode": 3, "operand": 4,
            },
            dump_label_pattern=r"([0-9a-fA-F]+)\s+<([^>]+)>",
        )

    @property
    def parse_format(self) -> DisassemblyFormat:
        return self._format

    def command(self, binary: Path) -> Sequence[str]:
        return [self._executable, "-d", str(binary)]

    @staticmethod
    def is_external_trampoline(name: str) -> bool:
        """Return the GNU objdump fact for an external linkage trampoline."""
        return name.endswith("@plt")
