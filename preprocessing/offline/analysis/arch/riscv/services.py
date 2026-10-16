"""Base RISC-V services composed with one selected extension service."""

from __future__ import annotations

from .control_flow import build_cfg


class RiscvServices:
    def __init__(self, extension) -> None:
        self._extension = extension

    @property
    def extension(self):
        return self._extension

    @staticmethod
    def build_cfg(program):
        return build_cfg(program)
