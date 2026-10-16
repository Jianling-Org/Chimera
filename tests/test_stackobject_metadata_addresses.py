"""Address contract of the compiler-provided metadata sections.

``.chimera.stackobj_map`` records are ``[u64 LinkedVA][u32 SOID]``: the address is
the *linked* virtual address of the vector stack access, i.e. exactly the value a
disassembler prints and the value the stack analysis keys its per-instruction maps
on.  Rebasing those records by the ELF load base shifts every entry away from the
instruction it describes; in metadata mode the intersection with the VLEN-sensitive
access set then becomes empty and stack accesses go silently unchecked.

These tests pin the no-rebasing contract down through the real
``ChimeraMetadata.from_elf`` read path (a structurally complete ELF with program
headers and a metadata section), not through a hand-built metadata object.
"""

from __future__ import annotations

from pathlib import Path
import struct
import tempfile
import unittest
from types import SimpleNamespace

from elf_fixture import ET_DYN, ET_EXEC, build_elf

from chimera.preprocess.offline.analysis.arch.riscv.rvv.services import (
    RiscvStackSemantics,
)
from chimera.preprocess.offline.analysis.core.data_model.program import (
    Function,
    Instruction,
    Program,
)
from chimera.preprocess.offline.analysis.safety.stack_liveness.analyzer import (
    StackLivenessAnalyzer,
)
from chimera.preprocess.offline.analysis.safety.stack_liveness.model import (
    CallTargetEntry,
    ChimeraMetadata,
    MetadataFormatError,
    StackAccessKind,
    StackObjectId,
)

STACKOBJ_SECTION = ".chimera.stackobj_map"
FUNCTION_POINTER_SECTION = ".chimera.function_pointer"

_STACKOBJ_RECORD = struct.Struct("<QI")
_FUNCTION_POINTER_HEADER = struct.Struct("<QI")

#: Linked address used by the ``ET_EXEC`` case; rebasing by the 0x10000 load base
#: would move it to 0x263de and detach it from the instruction it describes.
EXEC_LINKED_ADDRESS = 0x163DE
EXEC_LOAD_BASE = 0x10000
EXEC_OBJECT_ID = 2147483657


def _stackobj_payload(*records: tuple[int, int]) -> bytes:
    return b"".join(
        _STACKOBJ_RECORD.pack(address, object_id)
        for address, object_id in records
    )


def _function_pointer_payload(*entries: tuple[int, tuple[int, ...]]) -> bytes:
    payload = bytearray()
    for call_site, targets in entries:
        payload += _FUNCTION_POINTER_HEADER.pack(call_site, len(targets))
        for target in targets:
            payload += struct.pack("<Q", target)
    return bytes(payload)


def _elf_with_metadata(
    path: Path,
    *,
    elf_type: int = ET_DYN,
    load_vaddr: int = 0x1000,
    stackobj: bytes | None = None,
    function_pointer: bytes | None = None,
) -> Path:
    """Write a minimal ELF carrying the given metadata section payloads.

    ``stackobj=None`` omits the section entirely, which is a different mode from
    an empty payload: an empty ``.chimera.stackobj_map`` still selects the
    compiler-metadata mode with an empty mapping.
    """

    sections: list[tuple[str, bytes, bool]] = []
    if stackobj is not None:
        sections.append((STACKOBJ_SECTION, stackobj, False))
    if function_pointer is not None:
        sections.append((FUNCTION_POINTER_SECTION, function_pointer, False))
    return build_elf(
        path,
        elf_type=elf_type,
        load0_vaddr=load_vaddr,
        load1_vaddr=load_vaddr + 0x2000,
        sections=tuple(sections),
    )


def _vector_access_function(start: int) -> Function:
    """A function whose whole-register accesses are the VLEN-sensitive set U."""

    specs = (
        ("vs1r.v", ["v8", "(sp)"]),
        ("vl1r.v", ["v8", "(sp)"]),
        ("ret", []),
    )
    instructions = [
        Instruction(
            start + index * 4,
            4,
            op,
            list(args),
            f"{op} " + ",".join(args),
        )
        for index, (op, args) in enumerate(specs)
    ]
    for current, following in zip(instructions, instructions[1:]):
        current.succ.add(following.addr)
    return Function("fixture", start, instructions)


def _program(function: Function) -> Program:
    return Program(
        dump_lines=[],
        functions=[function],
        instructions=function.insts,
        instruction_by_address={
            instruction.addr: instruction for instruction in function.insts
        },
    )


def _config_result():
    return SimpleNamespace(at=lambda _address: frozenset())


def _analyze(program: Program, metadata: ChimeraMetadata):
    return StackLivenessAnalyzer(
        min_vlen_bits=256,
        semantics=RiscvStackSemantics(),
        emit_warnings=False,
    ).analyze_program(
        program,
        metadata=metadata,
        config_results={program.functions[0].start: _config_result()},
    )


class StackObjectMetadataAddressTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def test_exec_linked_address_is_not_rebased(self) -> None:
        path = _elf_with_metadata(
            self.root / "exec.elf",
            elf_type=ET_EXEC,
            load_vaddr=EXEC_LOAD_BASE,
            stackobj=_stackobj_payload((EXEC_LINKED_ADDRESS, EXEC_OBJECT_ID)),
        )

        metadata = ChimeraMetadata.from_elf(path)

        self.assertEqual(metadata.stack_ids, {EXEC_LINKED_ADDRESS: EXEC_OBJECT_ID})
        self.assertNotIn(
            EXEC_LOAD_BASE + EXEC_LINKED_ADDRESS, metadata.stack_ids
        )
        self.assertTrue(metadata.has_stackobj_map_section)
        self.assertEqual(metadata.capabilities, frozenset({"stack_access_ids"}))

    def test_dyn_linked_addresses_survive_zero_and_nonzero_load_bases(self) -> None:
        records = ((0x163DE, EXEC_OBJECT_ID), (0x1A004, 7))
        for load_base in (0, 0x1000, 0x400000):
            with self.subTest(load_base=hex(load_base)):
                path = _elf_with_metadata(
                    self.root / f"dyn-{load_base:x}.elf",
                    elf_type=ET_DYN,
                    load_vaddr=load_base,
                    stackobj=_stackobj_payload(*records),
                )

                metadata = ChimeraMetadata.from_elf(path)

                self.assertEqual(metadata.stack_ids, dict(records))

    def test_missing_and_empty_metadata_sections_keep_distinct_modes(self) -> None:
        missing = ChimeraMetadata.from_elf(
            _elf_with_metadata(self.root / "missing.elf")
        )
        empty = ChimeraMetadata.from_elf(
            _elf_with_metadata(self.root / "empty.elf", stackobj=b"")
        )

        self.assertFalse(missing.has_stackobj_map_section)
        self.assertEqual(missing.stack_ids, {})
        self.assertEqual(missing.capabilities, frozenset())

        self.assertTrue(empty.has_stackobj_map_section)
        self.assertEqual(empty.stack_ids, {})
        self.assertEqual(empty.capabilities, frozenset({"stack_access_ids"}))

    def test_function_pointer_only_elf_does_not_select_stackobj_mode(self) -> None:
        metadata = ChimeraMetadata.from_elf(
            _elf_with_metadata(
                self.root / "fp-only.elf",
                function_pointer=_function_pointer_payload((0x2000, (0x3000,))),
            )
        )

        self.assertFalse(metadata.has_stackobj_map_section)
        self.assertTrue(metadata.has_function_pointer_section)
        self.assertEqual(metadata.capabilities, frozenset({"function_pointer"}))

    def test_malformed_stackobj_records_are_rejected(self) -> None:
        # Six payload bytes: not a whole number of 12-byte records.
        self.assertRaises(
            MetadataFormatError,
            ChimeraMetadata.from_elf,
            _elf_with_metadata(self.root / "short.elf", stackobj=b"\x00" * 6),
        )
        # Same linked address with two different object IDs.
        self.assertRaises(
            MetadataFormatError,
            ChimeraMetadata.from_elf,
            _elf_with_metadata(
                self.root / "conflict.elf",
                stackobj=_stackobj_payload(
                    (EXEC_LINKED_ADDRESS, EXEC_OBJECT_ID),
                    (EXEC_LINKED_ADDRESS, 5),
                ),
            ),
        )
        # Identical duplicates stay accepted (no conflicting record).
        duplicates = ChimeraMetadata.from_elf(
            _elf_with_metadata(
                self.root / "duplicate.elf",
                stackobj=_stackobj_payload(
                    (EXEC_LINKED_ADDRESS, EXEC_OBJECT_ID),
                    (EXEC_LINKED_ADDRESS, EXEC_OBJECT_ID),
                ),
            )
        )
        self.assertEqual(
            duplicates.stack_ids, {EXEC_LINKED_ADDRESS: EXEC_OBJECT_ID}
        )

    def test_function_pointer_conversion_is_unchanged(self) -> None:
        """The function-pointer section keeps its own (base-applied) conversion.

        This fix deliberately only touches ``.chimera.stackobj_map``; the
        function-pointer reader, its record layout and its validation are out of
        scope.  The assertions below therefore describe the existing behaviour,
        and the stackobj part of the same ELF is the only thing that changed.
        """

        load_base = 0x4000
        call_site = 0x2000
        targets = (0x3000, 0x3200)
        stackobj_address = 0x2100
        path = _elf_with_metadata(
            self.root / "combined.elf",
            load_vaddr=load_base,
            stackobj=_stackobj_payload((stackobj_address, 9)),
            function_pointer=_function_pointer_payload((call_site, targets)),
        )

        metadata = ChimeraMetadata.from_elf(path)

        self.assertEqual(metadata.stack_ids, {stackobj_address: 9})
        self.assertEqual(
            metadata.function_pointer,
            {
                load_base + call_site: CallTargetEntry(
                    callsite_rva=load_base + call_site,
                    targets=tuple(load_base + target for target in targets),
                )
            },
        )
        self.assertEqual(
            metadata.capabilities,
            frozenset({"stack_access_ids", "function_pointer"}),
        )

    def test_analysis_detects_the_same_accesses_as_hand_built_metadata(self) -> None:
        """Regression: ELF-read metadata must not lose the stack accesses.

        The fixture function's accesses sit at their own linked addresses, which
        is what the record payload contains and what the disassembler would
        report.  Under the rebasing bug the intersection with U is empty, so the
        metadata-mode analysis sees *no* stack access at all.
        """

        function = _vector_access_function(0x1000)
        program = _program(function)
        expected = {0x1000: 11, 0x1004: 12}
        path = _elf_with_metadata(
            self.root / "accesses.elf",
            load_vaddr=0x1000,
            stackobj=_stackobj_payload(*sorted(expected.items())),
        )

        from_elf = _analyze(program, ChimeraMetadata.from_elf(path))
        manual = _analyze(
            program,
            ChimeraMetadata(stack_ids=dict(expected)),
        )

        elf_entry = from_elf.by_function[function.start]
        manual_entry = manual.by_function[function.start]

        self.assertEqual(sorted(elf_entry.accesses), [0x1000, 0x1004])
        self.assertEqual(
            elf_entry.accesses[0x1000].kind, StackAccessKind.STORE
        )
        self.assertEqual(elf_entry.accesses[0x1004].kind, StackAccessKind.LOAD)
        self.assertEqual(
            elf_entry.accesses[0x1000].stack_id, StackObjectId("compiler", 11)
        )
        self.assertEqual(
            elf_entry.accesses[0x1004].stack_id, StackObjectId("compiler", 12)
        )
        self.assertEqual(
            {access.source for access in elf_entry.accesses.values()},
            {"compiler"},
        )
        self.assertEqual(elf_entry.accesses, manual_entry.accesses)
        self.assertEqual(
            dict(from_elf.live_before), dict(manual.live_before)
        )


if __name__ == "__main__":
    unittest.main()
