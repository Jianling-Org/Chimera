"""Synthetic ELF fixtures shared by the workspace tests.

``build_elf`` writes a structurally complete ELF64 -- real program headers, a
real section header table, a real ``.shstrtab`` -- so tests exercise the same
pyelftools parsing path production uses.  ``write_elf`` is the shortcut for
tests that only need "a valid ELF with distinguishable content".
"""

from __future__ import annotations

from pathlib import Path
import struct

EHDR = struct.Struct("<16sHHIQQQIHHHHHH")
PHDR = struct.Struct("<IIQQQQQQ")
SHDR = struct.Struct("<IIQQQQIIQQ")

ET_EXEC = 2
ET_DYN = 3
EM_RISCV = 243

PT_LOAD = 1
PT_DYNAMIC = 2
PT_INTERP = 3
PT_NOTE = 4
PT_GNU_STACK = 0x6474E551

PF_R = 4
PF_W = 2
PF_X = 1

#: ``d_tag`` values for the dynamic entries this fixture can emit.
DT_NULL = 0
DT_NEEDED = 1
DT_STRTAB = 5
DT_RPATH = 15
DT_RUNPATH = 29
_DYNAMIC_TAGS = {"DT_NEEDED": DT_NEEDED, "DT_RPATH": DT_RPATH, "DT_RUNPATH": DT_RUNPATH}
_DYNAMIC_ENTRY = struct.Struct("<QQ")

SHT_PROGBITS = 1
SHT_STRTAB = 3

SHF_WRITE = 0x1
SHF_ALLOC = 0x2

DEFAULT_LOADER = "/lib/ld-linux-riscv64-lp64d.so.1"
BUILD_ID = b"\x04\x00\x00\x00\x10\x00\x00\x00GNU\x00" + b"\x11" * 20
OTHER_BUILD_ID = b"\x04\x00\x00\x00\x10\x00\x00\x00GNU\x00" + b"\x22" * 20


def write_header_only_elf(path: Path) -> Path:
    """Write a valid ELF64 header with no program and no section headers."""

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(
        EHDR.pack(
            b"\x7fELF" + bytes((2, 1, 1)) + bytes(9),
            ET_DYN,
            EM_RISCV,
            1,
            0,
            64,
            0,
            0,
            64,
            PHDR.size,
            0,
            SHDR.size,
            0,
            0,
        )
    )
    return path


def write_elf(path: Path, payload: bytes = b"\xaa" * 16) -> Path:
    """Write a valid ELF whose loaded data is *payload*."""

    return build_elf(path, data=payload)


def build_elf(
    path: Path,
    *,
    code: bytes = b"\x13\x05\x00\x00" * 8,
    data: bytes = b"\xaa" * 32,
    note: bytes | None = None,
    interp_payload: str | None = None,
    interp_original: str | None = None,
    load0_vaddr: int = 0x1000,
    load1_vaddr: int = 0x3000,
    entry: int = 0,
    flags: int = 0,
    elf_type: int = ET_DYN,
    sections: tuple[tuple[str, bytes, bool], ...] = (),
    extra_programs: tuple[tuple[int, int], ...] = (),
    comment: bytes | None = None,
    dynamic: tuple[tuple[str, str], ...] = (),
) -> Path:
    """Write a two-PT_LOAD ELF64 covering every shape the identity cares about.

    * ``code`` / ``data`` fill the two loaded segments; ``note`` becomes a
      ``PT_NOTE`` payload inside the first one (a build id, in practice).
    * ``interp_original`` is the PT_INTERP string stored *inside* the first
      PT_LOAD, i.e. part of the covered bytes (defaults to ``interp_payload``).
    * ``interp_payload`` is the string ``PT_INTERP`` actually points at.  When
      it differs from ``interp_original`` the payload is appended past every
      PT_LOAD and the header is repointed -- what a patchelf-style
      reserve-and-repoint does.
    * ``sections`` are ``(name, content, alloc)``; allocated ones sit inside
      the second PT_LOAD, the rest past it.
    * ``dynamic`` is ``(tag, value)`` with ``tag`` one of ``DT_NEEDED``,
      ``DT_RPATH``, ``DT_RUNPATH``.  It produces a real ``PT_DYNAMIC`` whose
      string table lives inside the second ``PT_LOAD`` -- the layout pyelftools
      needs, since it resolves those tags through ``DT_STRTAB``.
    * ``elf_type`` selects ``e_type`` (``ET_DYN`` by default, ``ET_EXEC`` for
      absolutely linked images); ``load0_vaddr`` is the lowest ``PT_LOAD``
      ``p_vaddr`` and therefore the load base metadata consumers derive.
    """

    path.parent.mkdir(parents=True, exist_ok=True)
    has_interp = interp_payload is not None
    has_dynamic = bool(dynamic)
    if interp_original is None:
        interp_original = interp_payload
    interp_in_load = (
        interp_original.encode("utf-8") + b"\x00" if has_interp else None
    )
    payload_outside = has_interp and interp_payload != interp_original

    program_count = (
        2 + (1 if has_interp else 0) + (1 if note is not None else 0)
        + (1 if has_dynamic else 0) + len(extra_programs)
    )
    body_offset = _align(64 + PHDR.size * program_count, 16)
    note_offset = body_offset
    code_offset = note_offset + (len(note) if note is not None else 0)
    interp_offset = code_offset + len(code)
    load0_end = interp_offset + (len(interp_in_load) if interp_in_load else 0)

    data_offset = _align(load0_end, 16)
    data_image = bytearray(data)
    allocated: list[tuple[str, int, int]] = []
    for name, content, alloc in sections:
        if alloc:
            allocated.append((name, data_offset + len(data_image), len(content)))
            data_image.extend(content)

    # Dynamic table: a string table, then the (tag, value) array pointing at
    # it.  Both live inside the second PT_LOAD so DT_STRTAB resolves through
    # program headers, which is how pyelftools reads RPATH/RUNPATH/NEEDED.
    dynamic_header: tuple[int, int, int, int, int, int, int, int] | None = None
    if has_dynamic:
        strings = bytearray(b"\x00")
        entries: list[tuple[int, int]] = []
        for tag, value in dynamic:
            if tag not in _DYNAMIC_TAGS:
                raise ValueError(f"unsupported dynamic tag for fixtures: {tag!r}")
            entries.append((_DYNAMIC_TAGS[tag], len(strings)))
            strings.extend(value.encode("utf-8") + b"\x00")
        strings_offset = data_offset + _align(len(data_image), 8)
        data_image.extend(b"\x00" * (strings_offset - data_offset - len(data_image)))
        data_image.extend(strings)
        array = bytearray(
            _DYNAMIC_ENTRY.pack(DT_STRTAB, load1_vaddr + (strings_offset - data_offset))
        )
        for tag, value in entries:
            array.extend(_DYNAMIC_ENTRY.pack(tag, value))
        array.extend(_DYNAMIC_ENTRY.pack(DT_NULL, 0))
        array_offset = data_offset + _align(len(data_image), 8)
        data_image.extend(b"\x00" * (array_offset - data_offset - len(data_image)))
        data_image.extend(array)
        dynamic_header = (
            PT_DYNAMIC,
            PF_R,
            array_offset,
            load1_vaddr + (array_offset - data_offset),
            load1_vaddr + (array_offset - data_offset),
            len(array),
            len(array),
            8,
        )
    load1_end = data_offset + len(data_image)

    blob = bytearray()
    blob_start = load1_end

    def place(content: bytes) -> int:
        offset = blob_start + len(blob)
        blob.extend(content)
        return offset

    outside_offset = (
        place(interp_payload.encode("utf-8") + b"\x00") if payload_outside else None
    )

    non_allocated: list[tuple[str, int, int]] = []
    for name, content, alloc in sections:
        if not alloc:
            non_allocated.append((name, place(content), len(content)))
    comment_offset = place(comment) if comment is not None else 0

    names = [".shstrtab"]
    names.extend(name for name, _content, _alloc in sections)
    if comment is not None:
        names.append(".comment")
    name_offsets: dict[str, int] = {}
    shstrtab = bytearray(b"\x00")
    for name in names:
        name_offsets[name] = len(shstrtab)
        shstrtab.extend(name.encode("utf-8") + b"\x00")
    shstrtab_offset = place(bytes(shstrtab))

    # (sh_name, sh_type, sh_flags, sh_offset, sh_size)
    section_entries: list[tuple[int, int, int, int, int]] = [
        (name_offsets[".shstrtab"], SHT_STRTAB, 0, shstrtab_offset, len(shstrtab))
    ]
    for name, offset, size in allocated:
        section_entries.append(
            (name_offsets[name], SHT_PROGBITS, SHF_ALLOC | SHF_WRITE, offset, size)
        )
    for name, offset, size in non_allocated:
        section_entries.append((name_offsets[name], SHT_PROGBITS, 0, offset, size))
    if comment is not None:
        section_entries.append(
            (name_offsets[".comment"], SHT_PROGBITS, 0, comment_offset, len(comment))
        )

    section_count = 1 + len(section_entries)
    section_offset = _align(blob_start + len(blob), 8)
    image = bytearray(section_offset + SHDR.size * section_count)

    image[0:64] = EHDR.pack(
        b"\x7fELF" + bytes((2, 1, 1)) + bytes(9),
        elf_type,
        EM_RISCV,
        1,
        entry,
        64,
        section_offset,
        flags,
        64,
        PHDR.size,
        program_count,
        SHDR.size,
        section_count,
        1,
    )

    headers: list[tuple[int, int, int, int, int, int, int, int]] = [
        (PT_LOAD, PF_R | PF_X, 0, load0_vaddr, load0_vaddr, load0_end, load0_end, 0x1000),
        (
            PT_LOAD,
            PF_R | PF_W,
            data_offset,
            load1_vaddr,
            load1_vaddr,
            len(data_image),
            len(data_image),
            0x1000,
        ),
    ]
    if note is not None:
        headers.append((PT_NOTE, PF_R, note_offset, 0, 0, len(note), len(note), 4))
    if has_interp:
        if payload_outside:
            assert outside_offset is not None
            size = len(interp_payload.encode("utf-8")) + 1
            headers.append((PT_INTERP, PF_R, outside_offset, 0, 0, size, size, 1))
        else:
            assert interp_in_load is not None
            headers.append(
                (
                    PT_INTERP,
                    PF_R,
                    interp_offset,
                    0,
                    0,
                    len(interp_in_load),
                    len(interp_in_load),
                    1,
                )
            )
    if has_dynamic:
        assert dynamic_header is not None
        headers.append(dynamic_header)
    headers.extend(
        (program_type, program_flags, 0, 0, 0, 0, 0, 0)
        for program_type, program_flags in extra_programs
    )

    program_offset = 64
    for header in headers:
        image[program_offset : program_offset + PHDR.size] = PHDR.pack(*header)
        program_offset += PHDR.size

    image[code_offset : code_offset + len(code)] = code
    if note is not None:
        image[note_offset : note_offset + len(note)] = note
    if interp_in_load is not None:
        image[interp_offset : interp_offset + len(interp_in_load)] = interp_in_load
    image[data_offset:load1_end] = data_image
    image[blob_start : blob_start + len(blob)] = blob

    # Section 0 is the mandatory SHT_NULL; leave it zeroed.
    entry_offset = section_offset + SHDR.size
    for name_offset, section_type, section_flags, offset, size in section_entries:
        image[entry_offset : entry_offset + SHDR.size] = SHDR.pack(
            name_offset, section_type, section_flags, 0, offset, size, 0, 0, 1, 0
        )
        entry_offset += SHDR.size

    path.write_bytes(bytes(image))
    return path


def _align(value: int, alignment: int) -> int:
    return (value + alignment - 1) // alignment * alignment


__all__ = [
    "BUILD_ID",
    "DEFAULT_LOADER",
    "DT_NEEDED",
    "DT_RPATH",
    "DT_RUNPATH",
    "ET_DYN",
    "ET_EXEC",
    "OTHER_BUILD_ID",
    "PT_DYNAMIC",
    "PT_GNU_STACK",
    "PT_INTERP",
    "PT_LOAD",
    "PT_NOTE",
    "PF_R",
    "PF_W",
    "PF_X",
    "build_elf",
    "write_elf",
    "write_header_only_elf",
]
