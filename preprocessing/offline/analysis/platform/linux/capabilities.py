"""Validate Linux-hosted tools required by the offline workflow."""

from __future__ import annotations

import platform
import shlex
import shutil


def validate_offline_capabilities(config) -> dict[str, str]:
    if platform.system().lower() != "linux":
        raise RuntimeError("offline prepare is supported only on Linux hosts")
    commands = {
        "python": config.tools.python,
        "cc": shlex.split(config.tools.cc)[0] if config.tools.cc else "",
        "objdump": config.tools.objdump,
        "nm": config.tools.nm,
        "cmake": config.tools.cmake,
    }
    missing = [name for name, command in commands.items() if shutil.which(command) is None]
    if missing:
        raise FileNotFoundError("required executable(s) not found: " + ", ".join(missing))
    return commands


__all__ = ["validate_offline_capabilities"]
