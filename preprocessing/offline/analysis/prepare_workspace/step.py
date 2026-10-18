"""Allocate a workspace when needed and materialise its selected modules.

Two things changed shape here, and both of them remove a way for the artifacts
to describe something other than what runs:

* **A module has one file.**  Analysis reads each module's *selected* file
  directly -- the scalar build for package-delivered modules, the application's
  own file for target-resolved ones.  There is no staging copy of a module any
  more, so "what was analysed" and "what is delivered" cannot drift apart, and
  the application's ELF is never duplicated into the package.
* **Nothing rewrites an ELF.**  The old flow edited each `PT_INTERP` to point at
  a loader inside the package, which meant the bytes that were analysed were not
  the bytes the application ships with.  `run` invokes the loader explicitly
  instead, so prepare can leave every input file untouched.

Each module's file is anchored as it is read (see ``core.workspace.anchor``) and
re-checked before the publication is committed.
"""

from __future__ import annotations

import shutil
from pathlib import Path

from chimera.runtime.manifest import ModuleRecord, PACKAGE_MODULE_DIR

from ..core.data_model import DELIVERY_PACKAGE, AnalysisModule
from ..core.contracts import AnalysisContext, ElfModuleServices
from ..core.monitor import local, monitored, returned
from ..core.workspace import (
    WORKSPACE_METADATA,
    WorkspaceRepository,
    WorkspaceSession,
    anchor_modules,
    identity_digest,
    update_workspace_metadata,
    write_workspace_metadata,
)
from .checks import reject_target_loader_redirection
from .selection import prepare_input_fingerprint, select_modules, target_label


def _module_summary(modules) -> dict[str, object]:
    return {
        "count": len(modules),
        "module_ids": [item.module_id for item in modules],
        "packaged": sum(1 for item in modules if item.is_packaged),
    }


def _anchor_summary(anchors) -> dict[str, object]:
    return {
        "count": len(anchors),
        "modules": sorted(anchors),
    }


def _result_keys(context: AnalysisContext) -> list[str]:
    return sorted(context.global_results)


class PrepareWorkspaceStep:
    name = "prepare-workspace"

    def __init__(self, workspace_repository: WorkspaceRepository | None = None):
        self.workspace_repository = workspace_repository

    def _start_session(
        self, context: AnalysisContext
    ) -> tuple[AnalysisContext, WorkspaceSession]:
        if self.workspace_repository is None:
            raise RuntimeError("prepare-workspace requires a workspace repository")
        configured_name = context.config.workspace_name
        selected_name = context.parameters.get("requested_workspace")
        if selected_name is None and configured_name != "auto":
            selected_name = configured_name
        session = self.workspace_repository.start(
            context.input_elf, workspace=selected_name
        )
        try:
            updated = (
                context.with_stage(session.stage)
                .put_global("publication_path", session.destination)
                .put_global("workspace_session", session)
            )
        except BaseException:
            # The repository has already allocated staging at this point;
            # make the helper itself exception-safe in case context
            # construction is extended with a fallible operation later.
            session.abort()
            raise
        return updated, session

    @monitored(
        "offline.prepare-workspace",
        variables=(
            local("created_here"),
            local("scalar_dir"),
            local("session", label="staging", path=("stage",)),
            local("session", label="publication", path=("destination",)),
            local("modules", transform=_module_summary),
            local("anchors", transform=_anchor_summary),
            returned(label="results", transform=_result_keys),
        ),
    )
    def run(self, context: AnalysisContext) -> AnalysisContext:
        if not isinstance(context.platform, ElfModuleServices):
            raise TypeError(
                "prepare-workspace requires an ElfModuleServices platform "
                f"(got {type(context.platform).__name__})"
            )
        # Validate host/tool capabilities before allocating a staging session.
        # A failed probe must not leave a session that a caller can forget to
        # abort.  The capability result is reused by disassemble/build-runtime.
        if "capabilities" not in context.global_results:
            validate_capabilities = getattr(
                context.platform, "validate_capabilities", None
            )
            if not callable(validate_capabilities):
                raise TypeError(
                    "prepare-workspace requires platform.validate_capabilities"
                )
            context = context.put_global(
                "capabilities", validate_capabilities(context.config)
            )
        session = context.global_results.get("workspace_session")
        created_here = session is None

        try:
            if session is None:
                context, session = self._start_session(context)
            if not isinstance(session, WorkspaceSession):
                raise TypeError("workspace_session must be a WorkspaceSession")
            if context.stage is None:
                raise RuntimeError("prepare-workspace requires a staging directory")
            scalar_dir = context.stage / PACKAGE_MODULE_DIR
            scalar_dir.mkdir(parents=True, exist_ok=True)
            chosen = select_modules(
                context.input_elf,
                context.platform.dependencies(
                    context.input_elf,
                    context.config.target_files.library_roots,
                ),
                context.config.scalar_root,
            )
            # A file we cannot point the loader at is not something a digest can
            # detect later, so the verdict has to be reached here.
            reject_target_loader_redirection(context.platform, chosen)
            modules = [
                self._materialize(item, scalar_dir) for item in chosen
            ]
            anchors = anchor_modules(modules)
            _verify_packaged_copies(chosen, modules, anchors)
            if not (context.stage / WORKSPACE_METADATA).is_file():
                write_workspace_metadata(
                    context.stage,
                    workspace_id=session.destination.name,
                    input_elf=context.input_elf,
                )
            # Record what this run actually consumed, so a later prepare can
            # tell a reusable Workspace from a stale one even when the input
            # ELF itself is untouched.
            update_workspace_metadata(
                context.stage,
                input_fingerprint=prepare_input_fingerprint(
                    context.input_elf,
                    chosen,
                    target_label(
                        context.target_os,
                        context.target_arch,
                        context.target_arch_extension,
                        context.runtime_scene,
                        context.runtime_abi,
                    ),
                ),
            )
            session.anchors = tuple(anchors.values())
            for module in modules:
                session.registry.register_module(ModuleRecord(
                    module_id=module.module_id,
                    role="main" if module.is_main else "dependency",
                    runtime_name=module.selected_path.name,
                    selected_kind="scalar" if module.is_scalar else "original",
                    delivery=module.delivery,
                    sha256=anchors[module.module_id].sha256,
                ))
            return context.put_global("modules", tuple(modules))
        except BaseException:
            if created_here and session is not None:
                session.abort()
            raise

    @staticmethod
    def _materialize(item, scalar_dir: Path) -> AnalysisModule:
        """Return the module record for *item*, staging its file if it ships.

        Package-delivered files are copied into the staging workspace because
        that copy *is* the payload; target-resolved files stay exactly where the
        application installed them, because their location is what makes the
        application's own path derivation keep working.
        """

        selected = item.selected_path
        if item.delivery == DELIVERY_PACKAGE:
            staged = scalar_dir / selected.name
            shutil.copy2(selected, staged, follow_symlinks=True)
            selected = staged
        return AnalysisModule(
            module_id=item.module_id,
            source=item.source,
            selected_path=selected,
            is_scalar=item.is_scalar,
            is_main=item.is_main,
            delivery=item.delivery,
        )


def _verify_packaged_copies(chosen, modules, anchors) -> None:
    """Prove a staged payload is byte-identical to the file it was selected from.

    Without this the fingerprint would describe the source while the artifacts
    described the copy, and nothing would connect the two.
    """

    for item, module in zip(chosen, modules):
        if module.delivery != DELIVERY_PACKAGE:
            continue
        source_digest = identity_digest(item.selected_path)
        if anchors[module.module_id].digest != source_digest:
            raise ValueError(
                "staged module payload does not match the file it was selected "
                f"from: {module.selected_path} != {item.selected_path}"
            )
