#!/usr/bin/env python3

import importlib.util
import pathlib
import struct
import tempfile
import unittest


CHECKER_PATH = pathlib.Path(__file__).with_name("check_stackobj_map.py")
SPEC = importlib.util.spec_from_file_location("check_stackobj_map", CHECKER_PATH)
CHECKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECKER)


def align(value, alignment):
    return (value + alignment - 1) & -alignment


def make_elf64(path, records, endian="little", with_relocation=False,
               malformed_payload=None):
    prefix = "<" if endian == "little" else ">"
    ident = bytearray(b"\x7fELF")
    ident.extend((2, 1 if endian == "little" else 2, 1, 0, 0))
    ident.extend(b"\x00" * 7)

    shstrtab = b"\x00.shstrtab\x00.chimera.stackobj_map\x00.rela.chimera.stackobj_map\x00"
    shstr_name = shstrtab.index(b".shstrtab")
    map_name = shstrtab.index(b".chimera.stackobj_map")
    rela_name = shstrtab.index(b".rela.chimera.stackobj_map")

    if malformed_payload is None:
        payload = b"".join(
            struct.pack(prefix + "QI", linked_va, soid)
            for linked_va, soid in records
        )
    else:
        payload = malformed_payload

    elf_header_size = 64
    section_header_size = 64
    shstr_offset = elf_header_size
    map_offset = align(shstr_offset + len(shstrtab), 8)
    rela_payload = struct.pack(prefix + "QQq", 0, 0, 0) if with_relocation else b""
    rela_offset = align(map_offset + len(payload), 8)
    section_count = 4 if with_relocation else 3
    section_table_offset = align(rela_offset + len(rela_payload), 8)

    header = struct.pack(
        prefix + "16sHHIQQQIHHHHHH",
        bytes(ident),
        1,
        243,
        1,
        0,
        0,
        section_table_offset,
        0,
        elf_header_size,
        0,
        0,
        section_header_size,
        section_count,
        1,
    )

    def section(name, section_type, flags, offset, size, link=0, info=0,
                alignment=1, entry_size=0):
        return struct.pack(
            prefix + "IIQQQQIIQQ",
            name,
            section_type,
            flags,
            0,
            offset,
            size,
            link,
            info,
            alignment,
            entry_size,
        )

    sections = [bytes(section_header_size)]
    sections.append(section(shstr_name, 3, 0, shstr_offset, len(shstrtab)))
    sections.append(section(map_name, 1, 2, map_offset, len(payload), alignment=1))
    if with_relocation:
        sections.append(
            section(
                rela_name,
                4,
                0,
                rela_offset,
                len(rela_payload),
                info=2,
                alignment=8,
                entry_size=24,
            )
        )

    image = bytearray(header)
    image.extend(shstrtab)
    image.extend(b"\x00" * (map_offset - len(image)))
    image.extend(payload)
    image.extend(b"\x00" * (rela_offset - len(image)))
    image.extend(rela_payload)
    image.extend(b"\x00" * (section_table_offset - len(image)))
    image.extend(b"".join(sections))
    path.write_bytes(image)


class StackObjectMapCheckerTests(unittest.TestCase):
    def test_parses_little_endian_records_without_order_dependency(self):
        with tempfile.TemporaryDirectory() as tmp:
            elf_path = pathlib.Path(tmp) / "little.elf"
            make_elf64(elf_path, [(0x11230, 2), (0x11200, 0)])

            elf = CHECKER.parse_elf(elf_path)

            self.assertEqual(
                {(0x11200, 0), (0x11230, 2)},
                set(elf.stackobj_records()),
            )
            elf.assert_records([(0x11200, 0), (0x11230, 2)])
            elf.assert_no_relocations()

    def test_parses_big_endian_records(self):
        with tempfile.TemporaryDirectory() as tmp:
            elf_path = pathlib.Path(tmp) / "big.elf"
            make_elf64(elf_path, [(0x1020304050607080, 0xA0B0C0D0)], "big")

            elf = CHECKER.parse_elf(elf_path)

            self.assertEqual(
                [(0x1020304050607080, 0xA0B0C0D0)],
                elf.stackobj_records(),
            )

    def test_rejects_non_12_byte_payload(self):
        with tempfile.TemporaryDirectory() as tmp:
            elf_path = pathlib.Path(tmp) / "malformed.elf"
            make_elf64(elf_path, [], malformed_payload=b"\x00" * 13)

            elf = CHECKER.parse_elf(elf_path)

            with self.assertRaisesRegex(ValueError, "multiple of 12"):
                elf.stackobj_records()

    def test_detects_relocation_section_targeting_map(self):
        with tempfile.TemporaryDirectory() as tmp:
            elf_path = pathlib.Path(tmp) / "relocated.elf"
            make_elf64(elf_path, [(0x11200, 0)], with_relocation=True)

            elf = CHECKER.parse_elf(elf_path)

            with self.assertRaisesRegex(AssertionError, "relocation"):
                elf.assert_no_relocations()

    def test_rejects_rv32_elf(self):
        with tempfile.TemporaryDirectory() as tmp:
            elf_path = pathlib.Path(tmp) / "elf32"
            elf_path.write_bytes(b"\x7fELF\x01" + b"\x00" * 59)

            with self.assertRaisesRegex(ValueError, "ELF64"):
                CHECKER.parse_elf(elf_path)


if __name__ == "__main__":
    unittest.main()
