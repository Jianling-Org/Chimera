"""Runtime artifact contract owned by the Linux/RISC-V/RVV scene."""

from __future__ import annotations

from . import RuntimeArtifactContract, RuntimeArtifactContractCatalog


RVV_RUNTIME_REQUIRED_SYMBOLS = frozenset({
    "chimera_runtime_abi_v1",
    "chimera_runtime_scene_linux_riscv64_rvv_v1",
    "query_original_translated_map",
    "simulated_cpu_state_riscv64_rvv_1024_riscv64_rvv_256",
    "simulated_cpu_state_riscv64_rvv_256_riscv64_rvv_1024",
    "get_simulated_cpu_state_addr_riscv64_rvv_1024_riscv64_rvv_256",
    "get_simulated_cpu_state_addr_riscv64_rvv_256_riscv64_rvv_1024",
})


RVV_RUNTIME_ARTIFACT_CONTRACT = RuntimeArtifactContract(
    target_os="linux",
    target_arch="riscv64",
    target_arch_extension="rvv",
    runtime_scene="linux_riscv64_rvv_v1",
    runtime_abi=1,
    elf_machine=243,
    required_symbols=RVV_RUNTIME_REQUIRED_SYMBOLS,
)


def registered_runtime_artifact_contracts() -> RuntimeArtifactContractCatalog:
    """Compatibility forwarder to the distribution composition root."""
    from .composition import registered_runtime_artifact_contracts
    return registered_runtime_artifact_contracts()


__all__ = [
    "RVV_RUNTIME_ARTIFACT_CONTRACT",
    "RVV_RUNTIME_REQUIRED_SYMBOLS",
    "registered_runtime_artifact_contracts",
]
