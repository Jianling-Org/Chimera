"""Small, shared contracts for scene-owned runtime artifacts.

The contract model is target independent.  A scene registers the concrete
ELF and symbol requirements that its Runtime DSO exposes; offline builders and
Python verifiers consume the same immutable value.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import struct
from types import MappingProxyType
from typing import Iterable, Mapping


SceneKey = tuple[str, str, str, str]


@dataclass(frozen=True)
class RuntimeArtifactContract:
    target_os: str
    target_arch: str
    target_arch_extension: str
    runtime_scene: str
    runtime_abi: int
    elf_machine: int
    required_symbols: frozenset[str]
    representation: str = "elf"
    elf_class: int = 2
    elf_data: int = 1

    def __post_init__(self) -> None:
        # A frozen dataclass prevents rebinding, while normalizing this
        # collection also prevents callers from mutating the contract through
        # an input ``set`` after construction.
        object.__setattr__(self, "required_symbols", frozenset(self.required_symbols))

    @property
    def key(self) -> SceneKey:
        return (
            self.target_os,
            self.target_arch,
            self.target_arch_extension,
            self.runtime_scene,
        )

    def missing_symbols(self, exported: Iterable[str]) -> frozenset[str]:
        return self.required_symbols.difference(exported)

    def validate_elf(self, path: Path) -> None:
        if self.representation != "elf":
            raise ValueError(
                "runtime artifact contract does not describe an ELF "
                f"representation: {self.representation}"
            )
        data = path.read_bytes()
        header_size = {1: 52, 2: 64}.get(self.elf_class)
        if header_size is None:
            raise ValueError(f"unsupported ELF class in scene contract: {self.elf_class}")
        if len(data) < header_size or data[:4] != b"\x7fELF":
            raise ValueError(f"runtime artifact is not an ELF file: {path}")
        if data[4] != self.elf_class or data[5] != self.elf_data:
            raise ValueError(
                "runtime artifact must be an ELF with the scene's "
                f"class/data ({self.elf_class}/{self.elf_data})"
            )
        if self.elf_data not in (1, 2):
            raise ValueError(f"unsupported ELF data encoding in scene contract: {self.elf_data}")
        if data[6] != 1:
            raise ValueError("runtime ELF identification version is not current")
        order = "<" if self.elf_data == 1 else ">"
        e_type, machine, version = struct.unpack_from(order + "HHI", data, 16)
        if version != 1:
            raise ValueError("runtime ELF version is not current")
        if e_type != 3:
            raise ValueError("runtime artifact is not an ET_DYN DSO")
        # e_ehsize is at offset 40 in ELF32 and offset 52 in ELF64.  The
        # latter follows the 32-bit e_flags field in the 64-bit header; offset 40 is
        # the beginning of e_shoff and must never be used for this check.
        ehsize_offset = 40 if self.elf_class == 1 else 52
        actual_header_size = struct.unpack_from(order + "H", data, ehsize_offset)[0]
        if actual_header_size != header_size:
            raise ValueError(
                f"runtime ELF header size {actual_header_size} does not match "
                f"class requirement {header_size}"
            )
        if machine != self.elf_machine:
            raise ValueError(
                f"runtime ELF machine {machine} does not match "
                f"scene target {self.target_arch}"
            )


class RuntimeArtifactContractCatalog:
    def __init__(self, contracts: Iterable[RuntimeArtifactContract] = ()) -> None:
        values: dict[SceneKey, RuntimeArtifactContract] = {}
        for contract in contracts:
            if contract.key in values:
                raise ValueError(f"duplicate runtime scene contract: {contract.key}")
            values[contract.key] = contract
        self._contracts = MappingProxyType(values)

    def select(self, key: SceneKey) -> RuntimeArtifactContract:
        # TargetKey is the canonical key object used by the offline profile.
        # Accepting its tuple-shaped ``key`` property here keeps this small
        # package independent from the profile model while allowing callers
        # to pass either representation.
        if hasattr(key, "key"):
            lookup = key.key
        elif all(hasattr(key, name) for name in (
            "target_os", "target_arch", "target_arch_extension", "runtime_scene"
        )):
            lookup = (
                key.target_os,
                key.target_arch,
                key.target_arch_extension,
                key.runtime_scene,
            )
        else:
            lookup = key
        try:
            return self._contracts[lookup]
        except KeyError as error:
            raise ValueError(
                "unsupported runtime scene contract: " + "/".join(lookup)
            ) from error

    def contracts(self) -> Mapping[SceneKey, RuntimeArtifactContract]:
        return self._contracts


def registered_runtime_artifact_contracts() -> RuntimeArtifactContractCatalog:
    """Compatibility access to the repository's current scene catalog.

    New code should import a scene-owned catalog explicitly.  The lazy import
    keeps older callers working without making this generic package import the
    offline pipeline or verifier implementation at module load time.
    """
    from .composition import registered_runtime_artifact_contracts as register
    return register()


__all__ = [
    "RuntimeArtifactContract",
    "RuntimeArtifactContractCatalog",
    "SceneKey",
    "registered_runtime_artifact_contracts",
]
