"""Transactional runtime-side BPF registration for published workspaces.

Registration is limited to migratable-file announcements (the zero-offset
form of ``struct uprobe_info``).  Safety points are no longer registered as
uprobes: the prepare pipeline's ``patch-safepoints`` step rewrites them into
ebreak traps inside the translated DSO image, so any artifact still marked
``required_by={"register"}`` is rejected as a stale contract.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from chimera.runtime.manifest import PACKAGE_MODULE_DIR, WorkspaceManifest
from chimera.preprocess.offline.analysis.core.monitor import (
    argument,
    monitored,
    returned,
)

from .registry import (
    ChimeraRegistry,
    RegistrationError,
    RegistrationKeyNotFound,
)


@dataclass(frozen=True)
class RegistrationSummary:
    workspace: Path
    map_keys: int


@dataclass(frozen=True)
class RollbackSummary:
    rolled_back: tuple[int, ...]
    failures: tuple[Exception, ...]


class PreparationRegistrar:
    def __init__(self, map_path: str, *, dry_run: bool = False):
        self.registry = ChimeraRegistry(map_path, dry_run=dry_run)
        self._keys: list[int] = []

    def close(self) -> None:
        self.registry.close()

    def register(
        self,
        stage: Path,
        manifest: WorkspaceManifest,
        *,
        resolved_paths: dict[str, Path] | None = None,
    ) -> None:
        """Announce every module file as migratable.

        Package-delivered modules are announced by their path inside the
        Workspace.  Target-resolved ones have no file there at all -- they live
        wherever the application is installed -- so the caller must supply the
        path this machine resolved them to.  Refusing to guess keeps a stale
        Workspace from announcing an inode that is no longer the application.
        """

        for artifact in manifest.artifacts:
            if "register" in artifact.required_by:
                raise RegistrationError(
                    "unsupported required capability for register: "
                    f"{artifact.capability}/{artifact.representation}"
                )
        for module in manifest.modules:
            if getattr(module, "delivery", "package") == "package":
                path = Path(stage) / PACKAGE_MODULE_DIR / module.runtime_name
            else:
                resolved = (resolved_paths or {}).get(module.module_id)
                if resolved is None:
                    raise RegistrationError(
                        "target-resolved module needs a resolved path to "
                        f"register: {module.module_id} (run register with "
                        "--input)"
                    )
                path = Path(resolved)
            self._keys.append(self.registry.register_migratable_file(path))

    @monitored(
        "runtime.register.transaction",
        variables=(
            argument("workspace"),
            argument("manifest", label="artifacts", path=("artifacts",), transform=len),
            returned(label="map_keys", path=("map_keys",)),
        ),
    )
    def register_workspace(
        self,
        workspace: Path,
        manifest: WorkspaceManifest,
        *,
        resolved_paths: dict[str, Path] | None = None,
    ) -> RegistrationSummary:
        # Registration state lives only in the kernel map and is lost on
        # reboot, so no "already registered" marker is persisted: re-running
        # register simply upserts the same deterministic keys (BPF_ANY).
        primary_error: BaseException | None = None
        try:
            self.register(workspace, manifest, resolved_paths=resolved_paths)
            return RegistrationSummary(
                workspace=workspace,
                map_keys=len(self._keys),
            )
        except BaseException as error:
            primary_error = error
            try:
                self.rollback()
            except BaseException as rollback_error:
                primary_error = rollback_error
                raise
            raise
        finally:
            try:
                self.close()
            except BaseException as close_error:
                if primary_error is None:
                    raise
                primary_error.add_note(f"closing the BPF map also failed: {close_error}")

    @monitored(
        "runtime.bpf.rollback",
        variables=(
            argument("self", label="key_count", path=("_keys",), transform=len),
            returned(label="rolled_back", path=("rolled_back",)),
            returned(label="failures", path=("failures",), transform=len),
        ),
    )
    def _rollback(self) -> RollbackSummary:
        errors: list[Exception] = []
        rolled_back = tuple(reversed(self._keys))
        for key in rolled_back:
            try:
                self.registry.queue.delete(key)
            except RegistrationKeyNotFound:
                pass
            except Exception as error:
                errors.append(error)
        self._keys.clear()
        return RollbackSummary(rolled_back, tuple(errors))

    def rollback(self) -> None:
        summary = self._rollback()
        if summary.failures:
            raise RuntimeError(
                "BPF rollback failed for "
                f"{len(summary.failures)} map key(s): {summary.failures[0]}"
            ) from summary.failures[0]


__all__ = [
    "PreparationRegistrar",
    "RollbackSummary",
    "RegistrationSummary",
]
