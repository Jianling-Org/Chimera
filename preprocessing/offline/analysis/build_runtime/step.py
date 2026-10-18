"""Offline step that builds one immutable Workspace runtime DSO."""

from __future__ import annotations

import shlex
import shutil

from chimera.runtime.manifest import ArtifactRecord

from ..core.contracts import AnalysisContext
from ..core.monitor import local, monitored, returned
from ..core.workspace import sha256_file
from .model import (
    RUNTIME_LIBRARY, RuntimeArtifact,
    validate_runtime_elf,
)
from .source import runtime_source_root


def _artifact_summary(context: AnalysisContext) -> dict[str, object]:
    artifact = context.require_global("runtime_artifact")
    return {
        "library": artifact.library,
        "scene": artifact.scene,
        "target": [artifact.target_os, artifact.target_arch, artifact.extension],
        "sha256": artifact.sha256,
    }


class BuildRuntimeStep:
    name = "build-runtime"

    @monitored(
        "offline.build-runtime",
        variables=(
            local("source"),
            local("build"),
            local("target"),
            local("defines"),
            local("commands"),
            local("library"),
            returned(label="runtime_artifact", transform=_artifact_summary),
        ),
    )
    def run(self, context: AnalysisContext) -> AnalysisContext:
        if context.stage is None:
            raise RuntimeError("build-runtime requires a staging workspace")
        capabilities = context.global_results.get("capabilities")
        if capabilities is None:
            capabilities = context.platform.validate_capabilities(context.config)
            context = context.put_global("capabilities", capabilities)

        source = runtime_source_root()
        build = context.stage / ".build" / "runtime"
        target = (
            context.target_os,
            context.target_arch,
            context.target_arch_extension,
        )
        try:
            if context.target_bundle is None:
                raise RuntimeError("build-runtime requires a selected target bundle")
            runtime = context.target_bundle.runtime
            contract = getattr(runtime, "artifact_contract", None)
            if contract is None:
                raise ValueError(
                    "target bundle must provide a RuntimeArtifactContract for "
                    "build-runtime"
                )
            if runtime.abi != contract.runtime_abi:
                raise ValueError(
                    "runtime ABI mismatch between target bundle and scene contract"
                )
            if contract.representation != "elf":
                raise ValueError(
                    "build-runtime currently requires an ELF runtime artifact"
                )
            expected_key = (
                context.target_os,
                context.target_arch,
                context.target_arch_extension,
                context.runtime_scene,
            )
            if contract.key != expected_key:
                raise ValueError(
                    "runtime artifact contract does not match the selected target "
                    f"({contract.key!r} != {expected_key!r})"
                )
            if context.runtime_abi != contract.runtime_abi:
                raise ValueError(
                    "runtime ABI mismatch between profile and scene contract"
                )
            compiler = shlex.split(context.config.tools.cc)
            toolchain_file = context.config.target_files.cmake_toolchain_file
            if toolchain_file is None and len(compiler) != 1:
                raise ValueError(
                    "config.tools.cc must be one executable when no "
                    "cmake_toolchain_file is configured"
                )
            builder = context.toolchain.code_builder
            defines = {
                "CHIMERA_BUILD_RUNTIME": "ON",
                "CHIMERA_INSTALL_RUNTIME_SOURCE": "OFF",
                "CHIMERA_BUILD_TESTS": "OFF",
                "CHIMERA_SCENE": context.runtime_scene,
                "CHIMERA_TARGET_OS": context.target_os,
                "CHIMERA_TARGET_ARCH": context.target_arch,
                "CHIMERA_TARGET_EXTENSION": context.target_arch_extension,
                "CHIMERA_DEBUG": "ON" if context.debug_enabled else "OFF",
            }
            commands = (
                builder.configure(
                    source, build, defines=defines, install_prefix=context.stage,
                    toolchain_file=toolchain_file,
                    system_name=runtime.system_name,
                    processor=runtime.system_processor,
                    compiler=compiler[0] if compiler else "",
                    sysroot=context.config.target_files.sysroot,
                ),
                builder.build(build, target="chimera_inject"),
                builder.install(build),
            )
            for command in commands:
                context.platform.runner.run(command)
            library = context.stage / "artifacts" / RUNTIME_LIBRARY
            if not library.is_file():
                raise FileNotFoundError(
                    f"CMake did not install the runtime DSO: {library}"
                )
            validate_runtime_elf(
                library,
                expected_machine=runtime.elf_machine,
                target=target,
                contract=contract,
            )
            symbols = context.platform.runner.run(
                context.toolchain.symbols.exported_symbols(library)
            ).stdout
            exported = {
                fields[-1] for line in symbols.splitlines() if (fields := line.split())
            }
            missing = sorted(contract.missing_symbols(exported))
            if missing:
                raise ValueError(
                    "runtime DSO is missing exported symbols: " + ", ".join(missing)
                )
            artifact = RuntimeArtifact(
                library=library,
                manifest_path=RUNTIME_LIBRARY,
                target_os=target[0],
                target_arch=target[1],
                extension=target[2],
                scene=context.runtime_scene,
                sha256=sha256_file(library),
            )
            session = context.require_global("workspace_session")
            session.registry.register_artifact(ArtifactRecord(
                artifact_id="runtime",
                owner_kind="workspace",
                owner_id="root",
                capability="runtime",
                representation="elf",
                abi=contract.runtime_abi,
                required_by=frozenset({"runtime"}),
                path=library.relative_to(context.stage).as_posix(),
                sha256=artifact.sha256,
            ))
            return context.put_global("runtime_artifact", artifact)
        finally:
            build_root = context.stage / ".build"
            if build_root.is_dir():
                shutil.rmtree(build_root)


__all__ = ["BuildRuntimeStep"]
