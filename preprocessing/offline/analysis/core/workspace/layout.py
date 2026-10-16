"""Canonical paths inside one staging workspace."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from chimera.runtime.manifest import PACKAGE_MODULE_DIR


@dataclass(frozen=True)
class WorkspaceLayout:
    #: Layout of one staging Workspace.  ``scalar`` holds exactly the module
    #: files that ship with the package; the application and its own libraries
    #: are not copied here -- they are resolved on the target machine, which is
    #: what keeps their path derivation working.
    root: Path

    @property
    def scalar(self) -> Path:
        return self.root / PACKAGE_MODULE_DIR

    @property
    def artifacts(self) -> Path:
        return self.root / "artifacts"

    @property
    def generated(self) -> Path:
        return self.root / "generated"

    @property
    def runtime_artifacts(self) -> Path:
        return self.artifacts / "runtime"

    @property
    def dumps(self) -> Path:
        return self.root / "dump"

    @property
    def logs(self) -> Path:
        return self.root / "log"

    def create(self) -> "WorkspaceLayout":
        for directory in (
            self.scalar,
            self.artifacts,
            self.runtime_artifacts,
            self.generated,
            self.dumps,
            self.logs,
        ):
            directory.mkdir(parents=True, exist_ok=True)
        return self
