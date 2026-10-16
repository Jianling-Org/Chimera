#!/usr/bin/env python3

import argparse
from collections import Counter
from dataclasses import dataclass
import pathlib
import struct


ELF_MAGIC = b"\x7fELF"
ELFCLASS64 = 2
ELFDATA2LSB = 1
ELFDATA2MSB = 2
EM_RISCV = 243
SHT_RELA = 4
SHT_REL = 9
STACKOBJ_SECTION = ".chimera.stackobj_map"
STACKOBJ_RECORD_SIZE = 12


@dataclass(frozen=True)
class Section:
    index: int
    name: str
    section_type: int
    offset: int
    size: int
    info: int


class ELFFile:
    def __init__(self, data, endian, sections):
        self._data = data
        self.endian = endian
        self.sections = sections

    def section(self, name):
        matches = [section for section in self.sections if section.name == name]
        if len(matches) != 1:
            raise ValueError(
                f"expected exactly one {name} section, found {len(matches)}"
            )
        return matches[0]

    def section_data(self, name):
        section = self.section(name)
        end = section.offset + section.size
        if end > len(self._data):
            raise ValueError(f"section {name} extends past end of file")
        return self._data[section.offset:end]

    def stackobj_records(self, section_name=STACKOBJ_SECTION):
        payload = self.section_data(section_name)
        if len(payload) % STACKOBJ_RECORD_SIZE:
            raise ValueError(
                f"{section_name} size {len(payload)} is not a multiple of 12"
            )
        return [
            struct.unpack_from(self.endian + "QI", payload, offset)
            for offset in range(0, len(payload), STACKOBJ_RECORD_SIZE)
        ]

    def assert_records(self, expected, section_name=STACKOBJ_SECTION):
        actual = Counter(self.stackobj_records(section_name))
        wanted = Counter(expected)
        if actual != wanted:
            raise AssertionError(
                f"unexpected {section_name} records:\n"
                f"  actual:   {actual}\n"
                f"  expected: {wanted}"
            )

    def assert_no_relocations(self, section_name=STACKOBJ_SECTION):
        target = self.section(section_name)
        relocations = [
            section
            for section in self.sections
            if section.section_type in (SHT_REL, SHT_RELA)
            and section.info == target.index
            and section.size != 0
        ]
        if relocations:
            names = ", ".join(section.name for section in relocations)
            raise AssertionError(
                f"relocation section(s) target {section_name}: {names}"
            )


def _unpack_from(fmt, data, offset, description):
    size = struct.calcsize(fmt)
    if offset < 0 or offset + size > len(data):
        raise ValueError(f"truncated {description}")
    return struct.unpack_from(fmt, data, offset)


def _cstring(data, offset):
    if offset < 0 or offset >= len(data):
        raise ValueError("section name offset is outside .shstrtab")
    end = data.find(b"\x00", offset)
    if end < 0:
        raise ValueError("unterminated section name")
    return data[offset:end].decode("utf-8")


def parse_elf(path):
    data = pathlib.Path(path).read_bytes()
    if len(data) < 16 or data[:4] != ELF_MAGIC:
        raise ValueError("not an ELF file")
    if data[4] != ELFCLASS64:
        raise ValueError("Chimera StackObject maps require ELF64")
    if data[5] == ELFDATA2LSB:
        endian = "<"
    elif data[5] == ELFDATA2MSB:
        endian = ">"
    else:
        raise ValueError("unsupported ELF data encoding")

    header = _unpack_from(
        endian + "16sHHIQQQIHHHHHH", data, 0, "ELF64 header"
    )
    machine = header[2]
    section_offset = header[6]
    section_entry_size = header[11]
    section_count = header[12]
    shstr_index = header[13]

    if machine != EM_RISCV:
        raise ValueError(f"Chimera StackObject maps require RISC-V ELF, got {machine}")
    if section_entry_size < 64:
        raise ValueError("invalid ELF64 section-header size")
    if not section_count or shstr_index >= section_count:
        raise ValueError("invalid ELF64 section table")

    raw_sections = []
    for index in range(section_count):
        values = _unpack_from(
            endian + "IIQQQQIIQQ",
            data,
            section_offset + index * section_entry_size,
            f"section header {index}",
        )
        raw_sections.append(values)

    shstr = raw_sections[shstr_index]
    shstr_offset, shstr_size = shstr[4], shstr[5]
    if shstr_offset + shstr_size > len(data):
        raise ValueError(".shstrtab extends past end of file")
    names = data[shstr_offset:shstr_offset + shstr_size]

    sections = [
        Section(
            index=index,
            name=_cstring(names, values[0]),
            section_type=values[1],
            offset=values[4],
            size=values[5],
            info=values[7],
        )
        for index, values in enumerate(raw_sections)
    ]
    return ELFFile(data, endian, sections)


def parse_expected_record(text):
    try:
        linked_va, soid = text.split(":", 1)
        return int(linked_va, 0), int(soid, 0)
    except ValueError as error:
        raise argparse.ArgumentTypeError(
            f"expected VA:SOID with integers, got {text!r}"
        ) from error


def main():
    parser = argparse.ArgumentParser(
        description="Check Chimera's RV64 .chimera.stackobj_map wire format"
    )
    parser.add_argument("elf", type=pathlib.Path)
    parser.add_argument(
        "--expect-record",
        action="append",
        default=[],
        type=parse_expected_record,
        metavar="VA:SOID",
    )
    parser.add_argument("--require-no-relocations", action="store_true")
    args = parser.parse_args()

    elf = parse_elf(args.elf)
    records = elf.stackobj_records()
    if args.expect_record:
        elf.assert_records(args.expect_record)
    if args.require_no_relocations:
        elf.assert_no_relocations()

    for linked_va, soid in records:
        print(f"0x{linked_va:x}:0x{soid:x}")


if __name__ == "__main__":
    main()
