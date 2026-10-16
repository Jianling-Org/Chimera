"""Assembler spelling retained by the RVV scene's artifact ABI."""

from __future__ import annotations

from ....toolchain.artifact_emitter import GnuArtifactEmitter


class RvvArtifactEmitter(GnuArtifactEmitter):
    def __init__(self) -> None:
        # Keep the established RVV textual output and therefore the generated
        # object layout and exported symbol contract unchanged.
        super().__init__(word_directive=".dword")


__all__ = ["RvvArtifactEmitter"]
