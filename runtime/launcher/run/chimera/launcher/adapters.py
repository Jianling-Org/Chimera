"""Scene-selected launch environment adapters."""

from __future__ import annotations

from dataclasses import dataclass

from chimera.runtime.preload import runtime_environment


SceneKey = tuple[str, str, str, str]


@dataclass(frozen=True)
class LaunchAdapter:
    key: SceneKey
    environment_factory: object

    def environment(self, workspace, manifest) -> dict[str, str]:
        return self.environment_factory(workspace, manifest)


class LaunchAdapterCatalog:
    def __init__(self, adapters=()) -> None:
        self._adapters = {}
        for adapter in adapters:
            if adapter.key in self._adapters:
                raise ValueError(f"duplicate launch adapter: {adapter.key}")
            self._adapters[adapter.key] = adapter

    def select(self, key: SceneKey) -> LaunchAdapter:
        try:
            return self._adapters[key]
        except KeyError as error:
            raise RuntimeError(
                "launch is unsupported for scene/target: " + "/".join(key)
            ) from error


def registered_launch_adapters() -> LaunchAdapterCatalog:
    return LaunchAdapterCatalog((LaunchAdapter(
        ("linux", "riscv64", "rvv", "linux_riscv64_rvv_v1"),
        runtime_environment,
    ),))


__all__ = [
    "LaunchAdapter", "LaunchAdapterCatalog", "registered_launch_adapters",
]
