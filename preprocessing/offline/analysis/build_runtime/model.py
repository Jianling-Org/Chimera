"""Immutable result of one Workspace-local runtime build."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from chimera.runtime.scene_contracts import (
    RuntimeArtifactContract,
    registered_runtime_artifact_contracts,
)

RUNTIME_LIBRARY = "runtime/libchimera_inject.so"


@dataclass(frozen=True)
class RuntimeArtifact:
    library: Path
    manifest_path: str
    target_os: str
    target_arch: str
    extension: str
    scene: str
    sha256: str


def validate_runtime_elf(
    path: Path, *, expected_machine: int, target: tuple[str, str, str],
    contract: RuntimeArtifactContract | None = None,
) -> None:
    # Compatibility helper for direct callers; BuildRuntimeStep uses the
    # bundle's immutable contract directly.
    if contract is not None:
        if contract.key[:3] != target or contract.elf_machine != expected_machine:
            raise ValueError(
                "runtime artifact contract does not match the requested target or machine"
            )
        contract.validate_elf(path)
        return
    contracts = registered_runtime_artifact_contracts().contracts()
    matches = [
        contract for key, contract in contracts.items()
        if key[:3] == target and contract.elf_machine == expected_machine
    ]
    if len(matches) != 1:
        raise ValueError(
            "no unique runtime scene contract for target "
            + "/".join(target)
        )
    matches[0].validate_elf(path)


def required_runtime_symbols(scene: str) -> frozenset[str]:
    matches = [
        contract for contract in
        registered_runtime_artifact_contracts().contracts().values()
        if contract.runtime_scene == scene
    ]
    if len(matches) != 1:
        raise ValueError(f"unsupported runtime scene: {scene}")
    return matches[0].required_symbols


__all__ = [
    "RUNTIME_LIBRARY", "RuntimeArtifact",
    "required_runtime_symbols", "validate_runtime_elf",
]
