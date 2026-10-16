"""Identity digest and prepare-input fingerprint tests.

The ELF builder below is intentionally minimal but structurally complete: real
program headers, a real section header table and a real ``.shstrtab``, so the
tests exercise the same parsing path (pyelftools) that production uses.
"""

from __future__ import annotations

from contextlib import closing
from pathlib import Path
import tempfile
import unittest

from elf_fixture import (
    BUILD_ID,
    DEFAULT_LOADER,
    OTHER_BUILD_ID,
    PT_GNU_STACK,
    PT_NOTE,
    PF_R,
    PF_W,
    build_elf,
    write_header_only_elf,
)
from chimera.preprocess.offline.analysis.core.workspace.identity import (
    ANALYSIS_SECTIONS,
    LoadRegion,
    SectionRegion,
    compute_identity_digest,
    identity_digest,
    scan_identity_inputs,
)
from chimera.preprocess.offline.analysis.core.workspace.fingerprint import (
    input_fingerprint,
)
from chimera.preprocess.offline.analysis.prepare_workspace.selection import (
    prepare_input_fingerprint,
    select_modules,
    target_label,
)

class IdentityDigestTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def _elf(self, name: str = "a.so", **kwargs) -> Path:
        return build_elf(self.root / name, **kwargs)

    def test_identical_content_has_one_identity(self) -> None:
        first = self._elf("one/app.so")
        second = self._elf("two/app.so")

        self.assertEqual(identity_digest(first), identity_digest(second))
        self.assertRegex(identity_digest(first), r"^[0-9a-f]{64}$")

    def test_section_table_rewrites_are_tolerated(self) -> None:
        # strip / debug-split rewrite the section table: e_shoff, e_shnum and
        # the non-allocated contents move or disappear.  None of that is read.
        described = self._elf("described.so", comment=b"GCC: (GNU) 15.2.0")
        stripped = self._elf("stripped.so")

        self.assertEqual(identity_digest(stripped), identity_digest(described))

    def test_build_id_payload_is_tolerated(self) -> None:
        first = self._elf("a.so", note=BUILD_ID)
        second = self._elf("b.so", note=OTHER_BUILD_ID)

        self.assertEqual(identity_digest(second), identity_digest(first))

    def test_program_header_order_and_unread_fields_are_tolerated(self) -> None:
        # Same entry count, so nothing after the table moves: only ordering and
        # non-consumed field values differ.
        plain = self._elf(
            "p.so", extra_programs=((PT_GNU_STACK, PF_R), (PT_NOTE, PF_R))
        )
        reordered = self._elf(
            "r.so", extra_programs=((PT_NOTE, PF_R), (PT_GNU_STACK, PF_R | PF_W))
        )

        self.assertEqual(identity_digest(reordered), identity_digest(plain))

    def test_program_header_count_change_is_not_tolerated(self) -> None:
        # Recorded deliberately: an extra entry moves every byte after the
        # table, so the loaded content really is different.  Do not "fix" this
        # by widening the exclusions.
        plain = self._elf("p.so")
        extra = self._elf("e.so", extra_programs=((PT_GNU_STACK, PF_R),))

        self.assertNotEqual(identity_digest(extra), identity_digest(plain))

    def test_loaded_bytes_change_identity(self) -> None:
        baseline = self._elf("base.so")
        changed_data = self._elf("data.so", data=b"\xbb" * 32)
        changed_code = self._elf(
            "code.so", code=b"\x13\x05\x00\x00" * 7 + b"\x00\x00\x00\x00"
        )

        digest = identity_digest(baseline)
        self.assertNotEqual(identity_digest(changed_data), digest)
        self.assertNotEqual(identity_digest(changed_code), digest)

    def test_virtual_address_change_identity(self) -> None:
        baseline = self._elf("base.so")
        moved = self._elf("moved.so", load1_vaddr=0x4000)

        self.assertNotEqual(identity_digest(moved), identity_digest(baseline))

    def test_payload_basename_decides_identity(self) -> None:
        # The payload sits outside every PT_LOAD here (interp_original is
        # pinned), so only the basename item can see these differences.
        baseline = self._elf(
            "base.so", interp_original=DEFAULT_LOADER, interp_payload=DEFAULT_LOADER
        )
        relocated = self._elf(
            "relocated.so",
            interp_original=DEFAULT_LOADER,
            interp_payload="/usr/lib/" + Path(DEFAULT_LOADER).name,
        )
        repointed = self._elf(
            "repointed.so",
            interp_original=DEFAULT_LOADER,
            interp_payload="/root/build/local/" + Path(DEFAULT_LOADER).name,
        )
        other_loader = self._elf(
            "other.so",
            interp_original=DEFAULT_LOADER,
            interp_payload="/lib/ld-linux-riscv64.so.1",
        )

        digest = identity_digest(baseline)
        self.assertEqual(identity_digest(relocated), digest)
        self.assertEqual(identity_digest(repointed), digest)
        self.assertNotEqual(identity_digest(other_loader), digest)

    def test_interpreter_moved_out_of_loads_is_tolerated(self) -> None:
        # reserve_interpreter_slot: keep the original in-load bytes, append a
        # copy at EOF, repoint PT_INTERP.  No PT_LOAD byte or p_vaddr changes,
        # and the basename is unchanged.
        baseline = self._elf("base.so", interp_payload=DEFAULT_LOADER)
        reserved = self._elf(
            "reserved.so",
            interp_original=DEFAULT_LOADER,
            interp_payload="/root/build/workspace/local/" + Path(DEFAULT_LOADER).name,
        )

        self.assertEqual(identity_digest(reserved), identity_digest(baseline))

    def test_in_load_interpreter_bytes_are_part_of_the_identity(self) -> None:
        # The linked string sits inside the first PT_LOAD, so a file carrying a
        # different one is genuinely a different file.
        baseline = self._elf("base.so", interp_payload=DEFAULT_LOADER)
        relinked = self._elf("relinked.so", interp_payload="/opt/loader/" + Path(DEFAULT_LOADER).name)

        self.assertNotEqual(identity_digest(relinked), identity_digest(baseline))

    def test_analysis_section_content_and_presence_change_identity(self) -> None:
        baseline = self._elf("base.so")
        with_map = self._elf(
            "map.so", sections=((".chimera.stackobj_map", b"\x01\x02", False),)
        )
        other_map = self._elf(
            "other.so", sections=((".chimera.stackobj_map", b"\x01\x03", False),)
        )
        pointer = self._elf(
            "fp.so", sections=((".chimera.function_pointer", b"\x01\x02", False),)
        )

        digest = identity_digest(baseline)
        self.assertNotEqual(identity_digest(with_map), digest)
        self.assertNotEqual(identity_digest(other_map), identity_digest(with_map))
        self.assertNotEqual(identity_digest(pointer), identity_digest(with_map))

    def test_allocated_analysis_section_is_not_counted_twice(self) -> None:
        content = b"\x07\x00\x00\x00"
        baseline = self._elf("base.so")
        allocated = self._elf(
            "alloc.so", sections=((".chimera.stackobj_map", content, True),)
        )

        with closing(allocated.open("rb")) as stream:
            inputs = scan_identity_inputs(stream)

        self.assertEqual(inputs.sections, ())
        self.assertNotEqual(identity_digest(allocated), identity_digest(baseline))

    def test_regions_are_reported_in_file_offset_order(self) -> None:
        path = self._elf(
            "ordered.so",
            interp_payload=DEFAULT_LOADER,
            sections=(
                (".chimera.function_pointer", b"\x09", False),
                (".chimera.stackobj_map", b"\x08", False),
            ),
        )

        with closing(path.open("rb")) as stream:
            inputs = scan_identity_inputs(stream)

        self.assertEqual(len(inputs.loads), 2)
        self.assertEqual(
            [load.offset for load in inputs.loads],
            sorted(load.offset for load in inputs.loads),
        )
        self.assertEqual(
            [section.offset for section in inputs.sections],
            sorted(section.offset for section in inputs.sections),
        )
        self.assertEqual(
            sorted(section.name for section in inputs.sections),
            sorted(ANALYSIS_SECTIONS),
        )
        self.assertEqual(inputs.interpreter_basename, "ld-linux-riscv64-lp64d.so.1")

    def test_consumed_header_fields_change_identity(self) -> None:
        baseline = self._elf("base.so")
        other_entry = self._elf("entry.so", entry=0x2000)
        other_flags = self._elf("flags.so", flags=0x5)

        digest = identity_digest(baseline)
        self.assertNotEqual(identity_digest(other_entry), digest)
        self.assertNotEqual(identity_digest(other_flags), digest)

    def test_elf_without_load_segments_is_rejected(self) -> None:
        header_only = write_header_only_elf(self.root / "header.so")

        with self.assertRaisesRegex(ValueError, "no PT_LOAD"):
            identity_digest(header_only)

    def test_digest_reuses_a_single_open_stream(self) -> None:
        path = self._elf("single.so", interp_payload=DEFAULT_LOADER)

        with closing(path.open("rb")) as stream:
            inputs = scan_identity_inputs(stream)
            from_stream = compute_identity_digest(inputs, stream)

        self.assertEqual(from_stream, identity_digest(path))
        self.assertEqual(
            inputs.loads[0],
            LoadRegion(
                virtual_address=0x1000, offset=0, size=inputs.loads[0].size
            ),
        )
        self.assertEqual(inputs.sections, ())

    def test_analysis_section_names_are_the_documented_ones(self) -> None:
        self.assertEqual(
            ANALYSIS_SECTIONS,
            (".chimera.stackobj_map", ".chimera.function_pointer"),
        )
        self.assertNotIn(SectionRegion(".comment", 0, 0).name, ANALYSIS_SECTIONS)


class InputFingerprintTests(unittest.TestCase):
    def test_result_is_order_independent(self) -> None:
        items = [("module:b", "22"), ("input-elf", "11")]
        self.assertEqual(
            input_fingerprint(items),
            input_fingerprint(reversed(items)),
        )

    def test_any_input_change_changes_the_fingerprint(self) -> None:
        baseline = [("input-elf", "11"), ("module:a", "22")]
        dependency_upgraded = [("input-elf", "11"), ("module:a", "33")]

        self.assertNotEqual(
            input_fingerprint(baseline), input_fingerprint(dependency_upgraded)
        )

    def test_duplicate_labels_are_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "duplicate fingerprint label"):
            input_fingerprint([("module:a", "11"), ("module:a", "22")])

    def test_blank_labels_and_values_are_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "non-empty string"):
            input_fingerprint([("", "11")])
        with self.assertRaisesRegex(ValueError, "non-empty string"):
            input_fingerprint([("module:a", "")])
        with self.assertRaisesRegex(ValueError, "non-empty string"):
            input_fingerprint([(None, "11")])


class PrepareInputFingerprintTests(unittest.TestCase):
    """The cache-validity half: identity alone must not authorise reuse."""

    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def _fingerprint(self, *, dependency_payload: bytes = b"\xaa" * 32) -> str:
        app = build_elf(self.root / "app", data=b"\x11" * 16)
        dependency = build_elf(self.root / "libdemo.so", data=dependency_payload)
        scalar_root = self.root / "scalar"
        scalar_root.mkdir(exist_ok=True)
        modules = select_modules(app, (app, dependency), scalar_root)
        return prepare_input_fingerprint(
            app,
            modules,
            target_label("linux", "riscv64", "rvv", "linux_riscv64_rvv_v1", 1),
        )

    def test_dependency_change_invalidates_an_unchanged_input_elf(self) -> None:
        baseline = self._fingerprint()
        upgraded = self._fingerprint(dependency_payload=b"\xbb" * 32)

        self.assertNotEqual(baseline, upgraded)

    def test_stable_when_nothing_changed(self) -> None:
        self.assertEqual(self._fingerprint(), self._fingerprint())

    def test_target_change_invalidates(self) -> None:
        app = build_elf(self.root / "app", data=b"\x11" * 16)
        modules = select_modules(app, (app,), self.root / "scalar")
        first = prepare_input_fingerprint(
            app, modules, target_label("linux", "riscv64", "rvv", "scene-v1", 1)
        )
        second = prepare_input_fingerprint(
            app, modules, target_label("linux", "riscv64", "rvv", "scene-v1", 2)
        )

        self.assertNotEqual(first, second)


if __name__ == "__main__":
    unittest.main()
