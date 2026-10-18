"""Concrete external-tool adapters selected by the composition root."""

from .cmake import CmakeToolchain
from .compiler import GccCompiler
from .objdump import LinuxObjdump
from .nm import NmInspector
from .translator import ExternalTranslator
from .artifact_emitter import GnuArtifactEmitter
from ..core.contracts import ToolchainServices


def build_toolchain_services(
    config, *, artifact_emitter=None, linker_flags=()
) -> ToolchainServices:
    return ToolchainServices(
        code_builder=CmakeToolchain(config.tools.cmake),
        disassembler=LinuxObjdump(config.tools.objdump),
        translator=ExternalTranslator(python=config.tools.python),
        compiler=GccCompiler(
            config.tools.cc,
            extra_flags=config.tools.cc_flags,
            linker_flags=linker_flags,
        ),
        symbols=NmInspector(config.tools.nm),
        # Emitters are target/toolchain capabilities.  Keep the field
        # genuinely optional so a target that has not supplied syntax rules
        # fails at the producer boundary instead of silently using GNU text.
        artifact_emitter=artifact_emitter,
    )


__all__ = [
    "CmakeToolchain", "ExternalTranslator", "GccCompiler", "LinuxObjdump",
    "NmInspector", "GnuArtifactEmitter",
    "build_toolchain_services",
]
