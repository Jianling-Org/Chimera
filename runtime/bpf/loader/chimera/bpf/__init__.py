"""Pinned-map registration and ABI helpers."""

import platform
from dataclasses import dataclass

from chimera.preprocess.offline.analysis.core.monitor import (
    argument,
    monitored,
    returned,
)
from .registry import ChimeraRegistry, RegistrationError, UprobeInfo
from .transaction import PreparationRegistrar, RegistrationSummary


SceneKey = tuple[str, str, str, str]


@dataclass(frozen=True)
class SceneRegistrar:
    key: SceneKey
    factory: object
    supported_hosts: frozenset[tuple[str, str]]


class RegistrarCatalog:
    def __init__(self, registrars=()) -> None:
        self._registrars = {}
        for registrar in registrars:
            if registrar.key in self._registrars:
                raise ValueError(f"duplicate scene registrar: {registrar.key}")
            self._registrars[registrar.key] = registrar

    def select(self, key: SceneKey) -> SceneRegistrar:
        try:
            return self._registrars[key]
        except KeyError as error:
            raise RuntimeError(
                "registration is unsupported for scene/target: " + "/".join(key)
            ) from error


def registered_registrars() -> RegistrarCatalog:
    return RegistrarCatalog((SceneRegistrar(
        ("linux", "riscv64", "rvv", "linux_riscv64_rvv_v1"),
        PreparationRegistrar,
        frozenset({("linux", "riscv64"), ("linux", "riscv")}),
    ),))


@monitored(
    "runtime.register",
    variables=(
        argument("workspace"),
        argument("manifest", label="artifacts", path=("artifacts",), transform=len),
        argument("map_path"),
        returned(label="map_keys", path=("map_keys",)),
    ),
)
def register_workspace(
    workspace, manifest, *, map_path: str, resolved_paths=None
) -> RegistrationSummary:
    """Register one verified published workspace with the pinned BPF map."""
    key = (
        manifest.target_os, manifest.target_arch,
        manifest.target_arch_extension, manifest.runtime_scene,
    )
    adapter = registered_registrars().select(key)
    host = (platform.system().lower(), platform.machine().lower())
    if host not in adapter.supported_hosts:
        raise RuntimeError(
            f"BPF registration for {'/'.join(key)} is unsupported on {host[0]}/{host[1]}"
        )
    return adapter.factory(map_path).register_workspace(
        workspace,
        manifest,
        resolved_paths=resolved_paths,
    )

__all__ = [
    "ChimeraRegistry",
    "PreparationRegistrar",
    "RegistrationSummary",
    "RegistrationError",
    "UprobeInfo",
    "register_workspace",
    "RegistrarCatalog",
    "SceneRegistrar",
    "registered_registrars",
]
