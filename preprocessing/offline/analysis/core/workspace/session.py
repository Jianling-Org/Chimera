"""Recoverable workspace session used by the workflow pipeline."""

from __future__ import annotations

import os
from pathlib import Path
import shutil
from typing import TYPE_CHECKING
from uuid import uuid4
import logging

from .registry import WorkspaceRegistry

if TYPE_CHECKING:  # pragma: no cover - import cycle guard
    from .anchor import FileAnchor


_LOG = logging.getLogger(__name__)


class WorkspaceSession:
    def __init__(
        self, *, root: Path, stage: Path, destination: Path,
        published_manifest=None,
    ):
        self.root = root
        self.stage = stage
        self.destination = destination
        # Rebuild inspection uses the exact manifest validated before staging.
        self.published_manifest = published_manifest
        #: Identity of every module file this publication analysed, recorded by
        #: ``prepare`` and re-checked before the publication is committed.  The
        #: session owns it because "what did this publication consume" is a
        #: property of the publication, not of any single step's context.
        self.anchors: tuple["FileAnchor", ...] = ()
        self._finished = False
        self.registry = WorkspaceRegistry(stage, is_open=lambda: not self._finished)
        self._validators: dict[str, object] = {}

    def require_open(self) -> None:
        """Reject operations after completion or when staging was removed."""

        if self._finished:
            raise RuntimeError("workspace staging session is already finished")
        if not self.stage.is_dir():
            raise RuntimeError(
                f"workspace staging session is not open: staging directory is missing: {self.stage}"
            )

    def register_validator(self, identifier: str, validator) -> None:
        if self._finished:
            raise RuntimeError("workspace staging session is already finished")
        if not identifier:
            raise ValueError("publication validator ID cannot be empty")
        if identifier in self._validators:
            raise ValueError(f"duplicate publication validator: {identifier}")
        self._validators[identifier] = validator

    def freeze(self, **headers):
        manifest = self.registry.freeze(**headers)
        for identifier in sorted(self._validators):
            self._validators[identifier](manifest)
        return manifest

    def verify_inputs_unchanged(self) -> None:
        """Fail unless every analysed module file is still the file that was read.

        Called immediately before publication.  Every analysis step opened its
        input by path again, so this is the last point at which "the artifacts
        describe files that are still there" can be established at all.
        """

        from .anchor import verify_anchors

        verify_anchors(self.anchors)

    def commit(self) -> Path:
        if self._finished:
            raise RuntimeError("workspace staging session is already finished")
        if self.destination.exists():
            # Rebuild publishes over an existing workspace by moving the old
            # directory aside, renaming the stage into place, then discarding
            # the old tree after the new directory is installed.
            backup = self.destination.with_name(
                f".{self.destination.name}.old-{uuid4().hex}"
            )
            backup_display = backup.absolute()
            os.replace(self.destination, backup)
            try:
                os.replace(self.stage, self.destination)
            except BaseException as publish_error:
                try:
                    os.replace(backup, self.destination)
                except BaseException as restore_error:
                    raise RuntimeError(
                        "workspace publish failed and restoring the previous "
                        "workspace also failed; backup retained at "
                        f"{backup_display}: "
                        f"publish={publish_error}; restore={restore_error}"
                    ) from publish_error
                # A successful restore puts the old workspace back in its
                # original location.  There is no backup left to clean up,
                # and attempting to remove it here can race with callers
                # inspecting the rollback path.
                raise
            self._finished = True
            try:
                shutil.rmtree(backup)
            except Exception as cleanup_error:
                _LOG.warning(
                    "previous workspace backup could not be removed after a "
                    "successful publish (%s): %s",
                    backup_display,
                    cleanup_error,
                )
            return self.destination
        else:
            os.replace(self.stage, self.destination)
        self._finished = True
        return self.destination

    def abort(self) -> None:
        if self._finished:
            return
        if self.stage.exists() and self.stage.parent == self.root:
            shutil.rmtree(self.stage)
        self._finished = True
