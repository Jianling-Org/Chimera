"""CMake command construction without process execution."""

from __future__ import annotations

from pathlib import Path
from typing import Mapping, Sequence


class CmakeToolchain:
    def __init__(self, executable: str) -> None:
        self._executable = executable

    def configure(
        self, source: Path, build: Path, *, defines: Mapping[str, str],
        install_prefix: Path, toolchain_file: Path | None,
        system_name: str, processor: str, compiler: str,
        sysroot: Path | None,
    ) -> Sequence[str]:
        command = [
            self._executable, "-S", str(source), "-B", str(build),
            "-DCMAKE_BUILD_TYPE=Release",
            f"-DCMAKE_INSTALL_PREFIX={install_prefix}",
            *(f"-D{name}={value}" for name, value in defines.items()),
        ]
        if toolchain_file is not None:
            command.append(f"-DCMAKE_TOOLCHAIN_FILE={toolchain_file}")
        else:
            command.extend((
                f"-DCMAKE_SYSTEM_NAME={system_name}",
                f"-DCMAKE_SYSTEM_PROCESSOR={processor}",
                f"-DCMAKE_C_COMPILER={compiler}",
            ))
            if sysroot is not None:
                command.append(f"-DCMAKE_SYSROOT={sysroot}")
        return command

    def build(self, build: Path, *, target: str) -> Sequence[str]:
        return [
            self._executable, "--build", str(build), "--config", "Release",
            "--target", target,
        ]

    def install(self, build: Path) -> Sequence[str]:
        return [self._executable, "--install", str(build), "--config", "Release"]
