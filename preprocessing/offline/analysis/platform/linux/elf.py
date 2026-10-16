"""Minimal ELF program-header reader used for RVA normalization."""

from __future__ import annotations

from pathlib import Path
import struct


def _program_headers(path: Path) -> tuple[bytes, list[tuple[int, ...]], int, int]:
    data = path.read_bytes()
    if data[:4] != b"\x7fELF" or len(data) < 52:
        raise ValueError(f"not an ELF file: {path}")
    elf_class = data[4]
    byte_order = data[5]
    if byte_order != 1:
        raise ValueError(f"only little-endian ELF is supported: {path}")
    if elf_class == 2:
        if len(data) < 64:
            raise ValueError(f"truncated ELF header: {path}")
        phoff = struct.unpack_from("<Q", data, 32)[0]
        phentsize, phnum = struct.unpack_from("<HH", data, 54)
        header = struct.Struct("<IIQQQQQQ")
        file_offset_index = 2
        virtual_index = 3
    elif elf_class == 1:
        phoff = struct.unpack_from("<I", data, 28)[0]
        phentsize, phnum = struct.unpack_from("<HH", data, 42)
        header = struct.Struct("<IIIIIIII")
        file_offset_index = 1
        virtual_index = 2
    else:
        raise ValueError(f"unsupported ELF class {elf_class}: {path}")
    headers: list[tuple[int, ...]] = []
    for index in range(phnum):
        offset = phoff + index * phentsize
        if offset + header.size > len(data):
            raise ValueError(f"truncated ELF program headers: {path}")
        headers.append(header.unpack_from(data, offset))
    return data, headers, file_offset_index, virtual_index


def load_base(path: Path) -> int:
    _data, headers, _file_offset_index, virtual_index = _program_headers(path)
    bases = [int(fields[virtual_index]) for fields in headers if fields[0] == 1]
    if not bases:
        raise ValueError(f"ELF contains no PT_LOAD segments: {path}")
    return min(bases)


def load_segments(path: Path) -> tuple[tuple[int, int, int], ...]:
    """Return (file_offset, virtual_address, file_size) for each PT_LOAD."""

    data, headers, file_offset_index, virtual_index = _program_headers(path)
    file_size_index = 5 if data[4] == 2 else 4
    segments = tuple(
        (
            int(fields[file_offset_index]),
            int(fields[virtual_index]),
            int(fields[file_size_index]),
        )
        for fields in headers
        if fields[0] == 1 and int(fields[file_size_index])
    )
    if not segments:
        raise ValueError(f"ELF contains no PT_LOAD segments: {path}")
    return segments


def virtual_to_file_offset(
    segments: tuple[tuple[int, int, int], ...],
    address: int,
) -> int:
    """Map a virtual address onto its ELF file offset via PT_LOAD segments."""

    for file_offset, virtual_address, file_size in segments:
        if virtual_address <= address < virtual_address + file_size:
            return file_offset + (address - virtual_address)
    raise ValueError(
        f"virtual address 0x{address:x} is not backed by a PT_LOAD file range"
    )


def interpreter(path: Path) -> str | None:
    data, headers, file_offset_index, _virtual_index = _program_headers(path)
    for fields in headers:
        if fields[0] != 3:
            continue
        offset = int(fields[file_offset_index])
        size = int(fields[5] if data[4] == 2 else fields[4])
        raw = data[offset : offset + size]
        if len(raw) != size:
            raise ValueError(f"truncated PT_INTERP segment: {path}")
        return raw.split(b"\0", 1)[0].decode("utf-8")
    return None


#: Dynamic tags that add directories to the loader's search path.  The two are
#: not interchangeable: ``DT_RPATH`` is consulted *before* ``--library-path``,
#: ``DT_RUNPATH`` *after* it (see the ld.so search order).
SEARCH_PATH_TAGS = ("DT_RPATH", "DT_RUNPATH")


def dynamic_search_paths(path: Path) -> dict[str, tuple[str, ...]]:
    """Return the search directories an ELF declares itself.

    Only tags actually present are included, so an empty result means "this
    file does not redirect the loader at all".
    """

    from elftools.elf.elffile import ELFFile

    found: dict[str, list[str]] = {}
    with Path(path).open("rb") as stream:
        elf = ELFFile(stream)
        for segment in elf.iter_segments():
            if segment.header.p_type != "PT_DYNAMIC":
                continue
            for tag in segment.iter_tags():
                name = tag.entry.d_tag
                if name not in SEARCH_PATH_TAGS:
                    continue
                value = tag.rpath if name == "DT_RPATH" else tag.runpath
                found.setdefault(name, []).extend(
                    part for part in str(value).split(":") if part
                )
    return {name: tuple(values) for name, values in found.items()}

