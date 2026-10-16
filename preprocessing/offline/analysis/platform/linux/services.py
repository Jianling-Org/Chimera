"""Linux implementation of platform capabilities used by offline analysis.

Implements both ``PlatformServices`` (validate_capabilities + runner) and
the optional ``ElfModuleServices`` capability (interpreter, load layout,
dependencies).
"""

from __future__ import annotations

from pathlib import Path

from .dependencies import collect_dependencies
from .elf import (
    dynamic_search_paths,
    interpreter,
    load_base,
    load_segments,
    virtual_to_file_offset,
)
from .capabilities import validate_offline_capabilities
from .process import CommandRunner


class LinuxServices:
    # Implements: PlatformServices, ElfModuleServices

    def __init__(self, runner: CommandRunner | None = None) -> None:
        self._runner = runner or CommandRunner()

    @staticmethod
    def dependencies(
        module_path: Path, library_roots: tuple[Path, ...]
    ) -> tuple[Path, ...]:
        return collect_dependencies(module_path, library_roots)

    @staticmethod
    def interpreter(path: Path) -> str | None:
        return interpreter(path)

    @staticmethod
    def load_base(path: Path) -> int:
        return load_base(path)

    @staticmethod
    def load_segments(path: Path) -> tuple[tuple[int, int, int], ...]:
        return load_segments(path)

    @staticmethod
    def virtual_to_file_offset(
        segments: tuple[tuple[int, int, int], ...], address: int
    ) -> int:
        return virtual_to_file_offset(segments, address)

    @staticmethod
    def dynamic_search_paths(path: Path) -> dict[str, tuple[str, ...]]:
        return dynamic_search_paths(path)

    @staticmethod
    def validate_capabilities(config) -> dict[str, str]:
        return validate_offline_capabilities(config)

    @property
    def runner(self) -> CommandRunner:
        return self._runner
