"""Prove a publication describes the bytes it actually read.

These tests cover the window that a content digest cannot: every analysis step
re-opens its input *by path*, so "the digest matched" says nothing about the
file that is on disk when the artifacts are published.  The anchor is the only
thing standing between a replaced file and a silently wrong Workspace.
"""

from __future__ import annotations

import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from elf_fixture import build_elf

from chimera.preprocess.offline.analysis.core.workspace import (
    anchor_file,
    identity_digest,
    verify_anchor,
    verify_anchors,
)
from chimera.preprocess.offline.analysis.platform.linux.elf import (
    dynamic_search_paths,
)
from chimera.preprocess.offline.analysis.prepare_workspace.checks import (
    reject_target_loader_redirection,
)
from chimera.preprocess.offline.analysis.prepare_workspace.selection import (
    SelectedModule,
)

_ANCHOR_MODULE = "chimera.preprocess.offline.analysis.core.workspace.anchor"


def _selected(path: Path, delivery: str) -> SelectedModule:
    return SelectedModule(
        module_id=path.stem,
        source=path,
        selected_path=path,
        is_scalar=delivery == "package",
        is_main=False,
        delivery=delivery,
    )


class DynamicSearchPathTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def test_rpath_and_runpath_are_reported_separately(self) -> None:
        path = build_elf(
            self.root / "both.so",
            dynamic=(("DT_RPATH", "/opt/legacy/lib"), ("DT_RUNPATH", "$ORIGIN/lib")),
        )

        self.assertEqual(
            dynamic_search_paths(path),
            {"DT_RPATH": ("/opt/legacy/lib",), "DT_RUNPATH": ("$ORIGIN/lib",)},
        )

    def test_file_without_dynamic_tags_reports_nothing(self) -> None:
        path = build_elf(self.root / "plain.so")

        self.assertEqual(dynamic_search_paths(path), {})


class TargetLoaderRedirectionTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def test_target_module_with_rpath_is_rejected(self) -> None:
        path = build_elf(
            self.root / "app", dynamic=(("DT_RPATH", "/opt/legacy/lib"),)
        )
        platform = _StubPlatform()

        with self.assertRaisesRegex(ValueError, "DT_RPATH") as raised:
            reject_target_loader_redirection(
                platform, (_selected(path, "target"),)
            )

        self.assertIn("/opt/legacy/lib", str(raised.exception))
        self.assertIn(str(path), str(raised.exception))

    def test_target_module_with_runpath_is_accepted(self) -> None:
        # DT_RUNPATH is searched *after* --library-path, so the launch still
        # decides which file loads.  Rejecting it too would fail builds that
        # are in fact safe.
        path = build_elf(
            self.root / "app", dynamic=(("DT_RUNPATH", "$ORIGIN/../lib"),)
        )

        reject_target_loader_redirection(
            _StubPlatform(), (_selected(path, "target"),)
        )

    def test_package_module_with_rpath_is_not_checked_here(self) -> None:
        # Its bytes are rewritten into a flat directory at packing time, where
        # workspack verifies the search paths instead.
        path = build_elf(
            self.root / "libdep.so", dynamic=(("DT_RPATH", "/opt/legacy/lib"),)
        )
        platform = _StubPlatform()

        reject_target_loader_redirection(
            platform, (_selected(path, "package"),)
        )

        self.assertEqual([], platform.checked)


class _StubPlatform:
    def __init__(self) -> None:
        self.checked: list[Path] = []

    def dynamic_search_paths(self, path: Path) -> dict[str, tuple[str, ...]]:
        self.checked.append(path)
        return dynamic_search_paths(path)


class FileAnchorTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def _elf(self, name: str, *, data: bytes = b"\xaa" * 32) -> Path:
        return build_elf(self.root / name, data=data)

    def test_anchor_matches_independently_computed_digests(self) -> None:
        path = self._elf("app.so")

        anchor = anchor_file(path)

        payload = path.read_bytes()
        self.assertEqual(anchor.digest, identity_digest(path))
        self.assertEqual(anchor.sha256, __import__("hashlib").sha256(payload).hexdigest())
        self.assertEqual(anchor.st_size, len(payload))

    def test_same_file_anchors_to_the_same_digest(self) -> None:
        first = anchor_file(self._elf("a.so"))
        second = anchor_file(self._elf("b.so"))

        self.assertEqual(first.digest, second.digest)

    def test_change_during_the_read_is_detected(self) -> None:
        path = self._elf("app.so")
        original = _ANCHOR_MODULE + ".scan_identity_inputs"
        real = __import__(
            _ANCHOR_MODULE, fromlist=["scan_identity_inputs"]
        ).scan_identity_inputs

        def replace_then_scan(stream):
            inputs = real(stream)
            # Somebody else rewrites the file between the parse and the read.
            with path.open("ab") as writer:
                writer.write(b"\x00" * 4096)
            return inputs

        with patch(original, side_effect=replace_then_scan):
            with self.assertRaisesRegex(ValueError, "changed while it was being read"):
                anchor_file(path)

    def test_verify_accepts_an_unchanged_file(self) -> None:
        anchor = anchor_file(self._elf("app.so"))

        verify_anchor(anchor)
        verify_anchors([anchor])

    def test_verify_rejects_in_place_rewrite(self) -> None:
        path = self._elf("app.so")
        anchor = anchor_file(path)
        path.write_bytes(path.read_bytes() + b"\x00" * 64)

        with self.assertRaisesRegex(ValueError, "changed after it was analysed"):
            verify_anchor(anchor)

    def test_verify_rejects_replacement_through_rename(self) -> None:
        # What a package manager does: write a new file, rename over the old.
        path = self._elf("app.so")
        anchor = anchor_file(path)
        replacement = self._elf("replacement.so", data=b"\xbb" * 96)
        os.replace(replacement, path)

        with self.assertRaisesRegex(ValueError, "changed after it was analysed"):
            verify_anchor(anchor)

    def test_verify_reports_every_changed_file(self) -> None:
        first = self._elf("one.so")
        second = self._elf("two.so")
        anchors = [anchor_file(first), anchor_file(second)]
        first.write_bytes(first.read_bytes() + b"\x00" * 32)
        second.write_bytes(second.read_bytes() + b"\x00" * 96)

        with self.assertRaises(ValueError) as raised:
            verify_anchors(anchors)

        message = str(raised.exception)
        self.assertIn(str(first), message)
        self.assertIn(str(second), message)

    def test_verify_rejects_a_file_that_disappeared(self) -> None:
        path = self._elf("app.so")
        anchor = anchor_file(path)
        path.unlink()

        with self.assertRaisesRegex(ValueError, "disappeared"):
            verify_anchor(anchor)


if __name__ == "__main__":
    unittest.main()
