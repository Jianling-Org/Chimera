"""Pin the bytes an analysis consumed, and re-check them before publishing.

``prepare`` must analyse the very bytes it recorded.  Nothing else in the
pipeline can prove that on its own: every later step opens the selected file
*by path* again (``objdump``, ``ChimeraMetadata.from_elf``, the disassembler),
so a package manager, an operator script or a concurrent build can replace that
file between two of those opens.  The result is an artifact set computed for
bytes that are no longer there -- this project's worst failure mode, because it
is silent mis-computation rather than a crash.

An anchor therefore records, at the moment the bytes are read:

* the **identity digest** and the whole-file **SHA-256**, both computed from
  the *same descriptor* the region bytes were read through, so "hashed" and
  "read" cannot refer to different content;
* the file's stat identity ``(st_dev, st_ino, st_size, st_mtime_ns)``, which is
  free to check again later (see :data:`_SIGNATURE_FIELDS` for why ``st_ctime``
  is excluded).

Re-checking that stat identity before publishing closes the window between
reading a file and recording the artifacts derived from it.  It does **not**
close the window between publishing and running -- that is the separate
runtime-consistency question, which this stage deliberately does not pursue.

All five stat fields are compared on purpose: ``st_mtime`` alone can be
restored by the writer, and ``st_ino`` alone misses an in-place overwrite.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
from pathlib import Path

from .identity import compute_identity_digest, scan_identity_inputs

#: Compared to decide whether a file is still the one that was read.
#:
#: ``st_ctime_ns`` is deliberately **not** in here.  On POSIX it is the last
#: metadata change, which nothing in this window changes; on Windows it is the
#: creation time, and the filesystem keeps adjusting it for a moment after the
#: file is written -- observed reporting a *smaller* value on a later stat of a
#: file nobody touched.  A check that fires when nothing changed is worse than
#: no check, because it teaches people to ignore it.
#:
#: What remains still catches both replacement shapes: a rename-over changes
#: ``st_ino``, and an in-place rewrite changes ``st_size`` or ``st_mtime_ns``.
_SIGNATURE_FIELDS = ("st_dev", "st_ino", "st_size", "st_mtime_ns")
#: Recorded for diagnostics, never compared.
_DIAGNOSTIC_FIELDS = ("st_ctime_ns",)


@dataclass(frozen=True)
class FileAnchor:
    """The identity of one file at the moment its bytes were read."""

    path: Path
    #: Identity digest -- the same value that addresses a Workspace.
    digest: str
    #: Whole-file SHA-256, recorded for the Manifest (Stage 3).
    sha256: str
    st_dev: int
    st_ino: int
    st_size: int
    st_mtime_ns: int
    st_ctime_ns: int

    def signature(self) -> tuple[int, ...]:
        """The fields that decide whether this is still the same file."""

        return tuple(getattr(self, name) for name in _SIGNATURE_FIELDS)

    def describe_change(self, current) -> str:
        return _describe_difference(self, current)


def anchor_file(path: str | Path) -> FileAnchor:
    """Read *path* once and return the identity of the bytes that were read."""

    target = Path(path)
    with target.open("rb") as stream:
        before = os.fstat(stream.fileno())
        inputs = scan_identity_inputs(stream)
        digest = compute_identity_digest(inputs, stream)
        stream.seek(0)
        sha256 = hashlib.file_digest(stream, "sha256").hexdigest()
        after = os.fstat(stream.fileno())
    if _signature(before) != _signature(after):
        raise ValueError(
            f"{target} changed while it was being read; refusing to analyse a "
            "file that is being rewritten: "
            + _describe_difference(before, after)
        )
    return FileAnchor(
        path=target,
        digest=digest,
        sha256=sha256,
        st_dev=int(after.st_dev),
        st_ino=int(after.st_ino),
        st_size=int(after.st_size),
        st_mtime_ns=int(after.st_mtime_ns),
        st_ctime_ns=int(after.st_ctime_ns),
    )


def anchor_modules(modules) -> dict[str, FileAnchor]:
    """Anchor every module's selected file, keyed by module ID."""

    return {module.module_id: anchor_file(module.selected_path) for module in modules}


def verify_anchor(anchor: FileAnchor) -> None:
    """Fail unless *anchor*'s file still is the file that was read."""

    try:
        current = os.stat(anchor.path)
    except OSError as error:
        raise ValueError(
            f"{anchor.path} disappeared after it was analysed: {error}"
        ) from error
    observed = _signature(current)
    if observed != anchor.signature():
        raise ValueError(
            f"{anchor.path} changed after it was analysed; the recorded "
            "artifacts no longer describe the file on disk: "
            + _describe_difference(anchor, current)
        )


def verify_anchors(anchors) -> None:
    """Verify a collection of anchors, reporting every changed file at once."""

    failures: list[str] = []
    for anchor in anchors:
        try:
            verify_anchor(anchor)
        except ValueError as error:
            failures.append(str(error))
    if failures:
        raise ValueError(
            "workspace inputs changed while the workspace was being built:\n  "
            + "\n  ".join(failures)
        )


def _signature(stat_result) -> tuple[int, ...]:
    return tuple(int(getattr(stat_result, name)) for name in _SIGNATURE_FIELDS)


def _describe_difference(before, after) -> str:
    return ", ".join(
        f"{name}: {int(getattr(before, name))} -> {int(getattr(after, name))}"
        for name in _SIGNATURE_FIELDS
        if int(getattr(before, name)) != int(getattr(after, name))
    )


__all__ = [
    "FileAnchor",
    "anchor_file",
    "anchor_modules",
    "verify_anchor",
    "verify_anchors",
]
