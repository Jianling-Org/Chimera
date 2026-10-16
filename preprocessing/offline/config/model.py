"""Immutable in-memory representation of a complete Chimera TOML file."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import re
from types import MappingProxyType
from typing import Any, Mapping


_ENDPOINT_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]*$")


@dataclass(frozen=True, order=True)
class TranslationEndpoint:
    architecture: str
    extension: str
    specification: str

    @classmethod
    def parse(cls, value: object, *, field: str) -> "TranslationEndpoint":
        if not isinstance(value, str):
            raise TypeError(f"{field} must be a translation endpoint string")
        if any(character.isspace() for character in value):
            raise ValueError(f"{field} cannot contain whitespace")
        parts = value.split(";")
        if len(parts) != 3 or any(not part for part in parts):
            raise ValueError(
                f"{field} must have exactly three non-empty ';'-separated fields"
            )
        architecture, extension, specification = parts
        if not _ENDPOINT_IDENTIFIER.fullmatch(architecture):
            raise ValueError(f"{field} has invalid architecture: {architecture!r}")
        if not _ENDPOINT_IDENTIFIER.fullmatch(extension):
            raise ValueError(f"{field} has invalid extension: {extension!r}")
        return cls(architecture, extension, specification)

    @property
    def canonical(self) -> str:
        return ";".join((self.architecture, self.extension, self.specification))


@dataclass(frozen=True, order=True)
class TranslationRoute:
    source: TranslationEndpoint
    target: TranslationEndpoint


@dataclass(frozen=True)
class TranslatorBinding:
    source: TranslationEndpoint
    target: TranslationEndpoint
    translator_path: Path

    @property
    def route(self) -> TranslationRoute:
        return TranslationRoute(self.source, self.target)


@dataclass(frozen=True)
class ToolConfig:
    python: str = ""
    cc: str = ""
    cc_flags: tuple[str, ...] = ()
    objdump: str = ""
    nm: str = ""
    cmake: str = ""


@dataclass(frozen=True)
class TargetFilesConfig:
    sysroot: Path | None = None
    library_roots: tuple[Path, ...] = ()
    cmake_toolchain_file: Path | None = None


@dataclass(frozen=True)
class RuntimeConfig:
    bpf_map: Path = Path("/sys/fs/bpf/pid_uprobe_map")
    ai_thread_control: Path = Path("/proc/set_ai_thread")


@dataclass(frozen=True)
class BaseConfig:
    data_root: Path
    workspace_root: Path
    scalar_root: Path
    workspace_name: str = "auto"
    translators: tuple[TranslatorBinding, ...] = ()
    tools: ToolConfig = field(default_factory=ToolConfig)
    target_files: TargetFilesConfig = field(default_factory=TargetFilesConfig)
    runtime: RuntimeConfig = field(default_factory=RuntimeConfig)
    source: Path | None = None

    def translator_for(
        self, source: TranslationEndpoint, target: TranslationEndpoint
    ) -> Path:
        route = TranslationRoute(source, target)
        matches = [
            binding.translator_path
            for binding in self.translators
            if binding.route == route
        ]
        if len(matches) == 1:
            return matches[0]
        label = f"{source.canonical} -> {target.canonical}"
        if not matches:
            raise ValueError(
                f"no translator binding for route: {label}; "
                "add [[config.translators]]"
            )
        raise ValueError(f"multiple translator bindings for route: {label}")

    @property
    def compiler(self) -> str:
        return self.tools.cc

    @property
    def objdump(self) -> str:
        return self.tools.objdump

    @property
    def nm(self) -> str:
        return self.tools.nm


    @property
    def bpf_map(self) -> str:
        return str(self.runtime.bpf_map)

    @property
    def ai_thread_control(self) -> str:
        return str(self.runtime.ai_thread_control)


@dataclass(frozen=True)
class WorkflowStepConfig:
    """One user-declared step. IDs are deliberately generated later."""

    step: str
    parameters: Mapping[str, Any] = field(default_factory=lambda: MappingProxyType({}))


@dataclass(frozen=True)
class WorkflowConfig:
    steps: tuple[WorkflowStepConfig, ...]


@dataclass(frozen=True)
class ProfileConfig:
    name: str
    target_os: str
    target_arch: str
    target_arch_extension: str
    runtime_scene: str
    runtime_abi: int
    workflow: WorkflowConfig
    source: Path | None = None


@dataclass(frozen=True)
class ChimeraConfiguration:
    base: BaseConfig
    profile: ProfileConfig
    source: Path
