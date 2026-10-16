"""Immutable execution state shared by materialized analysis steps."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from pathlib import Path
from types import MappingProxyType
from typing import Any, Mapping


@dataclass(frozen=True)
class AnalysisContext:
    input_elf: Path
    stage: Path | None
    config: Any
    target_os: str
    target_arch: str
    target_arch_extension: str
    runtime_scene: str
    runtime_abi: int
    services: Any
    target_bundle: Any | None = None
    debug_enabled: bool = False
    global_results: Mapping[str, Any] = field(default_factory=lambda: MappingProxyType({}))
    parameters: Mapping[str, Any] = field(default_factory=lambda: MappingProxyType({}))

    @property
    def architecture(self):
        return self.services.architecture

    @property
    def platform(self):
        return self.services.platform

    @property
    def toolchain(self):
        return self.services.toolchain

    def with_stage(self, stage: Path) -> "AnalysisContext":
        return replace(self, stage=stage)

    def put_global(self, name: str, value: Any) -> "AnalysisContext":
        if not name:
            raise ValueError("analysis context key cannot be empty")
        updated = dict(self.global_results)
        updated[name] = value
        return replace(self, global_results=MappingProxyType(updated))

    def require_global(self, name: str) -> Any:
        try:
            return self.global_results[name]
        except KeyError as error:
            raise RuntimeError(f"global analysis input is missing: {name}") from error

    def drop_global(self, name: str) -> "AnalysisContext":
        """Return a context without *name*, releasing its memory for collection."""

        if name not in self.global_results:
            return self
        updated = dict(self.global_results)
        del updated[name]
        return replace(self, global_results=MappingProxyType(updated))

    def put_parameter(self, name: str, value: Any) -> "AnalysisContext":
        updated = dict(self.parameters)
        updated[name] = value
        return replace(self, parameters=MappingProxyType(updated))
