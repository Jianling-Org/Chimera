"""Composition root for runtime artifact contracts."""

from __future__ import annotations

from . import RuntimeArtifactContractCatalog
from .linux_riscv64_rvv_v1 import RVV_RUNTIME_ARTIFACT_CONTRACT


def registered_runtime_artifact_contracts() -> RuntimeArtifactContractCatalog:
    """Return contracts for scenes enabled by this runtime distribution."""
    return RuntimeArtifactContractCatalog((RVV_RUNTIME_ARTIFACT_CONTRACT,))


__all__ = ["registered_runtime_artifact_contracts"]
