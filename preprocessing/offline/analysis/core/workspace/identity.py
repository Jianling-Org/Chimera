"""Content identity of an input ELF.

An ELF's identity answers exactly one question: *is this the file the analysis
artifacts were produced for?*  The criterion is **every quantity the prepare
pipeline reads**, whether that quantity is raw file bytes or a value derived
from ELF structure:

=================================  ==========================================
quantity read                      where it comes from
=================================  ==========================================
mapped bytes                       each ``PT_LOAD``'s ``[p_offset, p_offset +
                                   p_filesz)``, minus the header region below
load base                          ``PT_LOAD`` ``p_vaddr`` (``min`` decides
                                   the RVA origin)
header identity                    ``e_type`` / ``e_machine`` / ``e_version``
                                   / ``e_entry`` / ``e_flags``
analysis metadata                  ``.chimera.stackobj_map`` and
                                   ``.chimera.function_pointer`` section bytes
loader selection                   basename parsed out of ``PT_INTERP``
=================================  ==========================================

Two kinds of file range are **excluded** from the mapped bytes, because they
carry layout or descriptive metadata that no analysis here reads:

* the ELF header ``[0, e_ehsize)`` and the program header table
  ``[e_phoff, e_phoff + e_phentsize * e_phnum)``;
* every ``PT_NOTE`` payload (build id and similar).

The header regions sit inside the first ``PT_LOAD``, so without that exclusion
any change to the section header table's location would change the identity --
which is precisely what ``strip`` and debug-split do.  The *consumed* header
fields are absorbed explicitly instead, so the identity tracks meaning rather
than layout.

Everything else is excluded on purpose as well:

* program-header fields other than the three consumed ones -- ``p_memsz``,
  ``p_flags``, ``p_align``, table order, ``PT_GNU_STACK``;
* non-allocated metadata that never enters memory and that no analysis in this
  pipeline reads: ``.comment``, ``.symtab``, debug sections;
* file offsets and inode -- they only decide *where* the covered bytes live,
  and build-machine paths are provenance, not cross-machine identity.

Properties the encoding guarantees, each covered by a test:

* **injective** -- every item is absorbed with a length prefix, so no two
  different inputs produce the same byte stream;
* **layout independent** -- item order is fixed by file offset within each
  kind, so the digest does not follow program-header order.

Maintenance rule: a new analysis input means a new entry in this module.
Forgetting one silently maps two different inputs onto one identity.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
from pathlib import Path
from pathlib import PurePosixPath
import struct
from typing import BinaryIO

#: Sections the safety analysis reads directly.  ``.chimera.stackobj_map`` is
#: the local-analysis mode switch, so its presence matters as much as its bytes.
ANALYSIS_SECTIONS = (".chimera.stackobj_map", ".chimera.function_pointer")

_ABSORB_HEADER = struct.Struct("<Q")
#: Canonical encoding of the consumed header fields.  ``e_entry`` is widened to
#: 64 bits for both ELF classes so the same logical value encodes identically.
_HEADER_FIELDS = struct.Struct("<HHQII")
_INTERP_BASENAME_MARKER = b"\x01"


@dataclass(frozen=True)
class LoadRegion:
    """One ``PT_LOAD``: its ``p_vaddr`` plus the file bytes it covers."""

    virtual_address: int
    offset: int
    size: int


@dataclass(frozen=True)
class SectionRegion:
    """One analysis-read section that no ``PT_LOAD`` already covers."""

    name: str
    offset: int
    size: int


@dataclass(frozen=True)
class HeaderIdentity:
    """The consumed part of the ELF header.

    Everything else in the header is either an offset/size pointing at a
    structure that has its own item, or unused.
    """

    e_type: int
    e_machine: int
    e_version: int
    e_entry: int
    e_flags: int

    def encode(self) -> bytes:
        return _HEADER_FIELDS.pack(
            self.e_type,
            self.e_machine,
            self.e_version,
            self.e_entry,
            self.e_flags,
        )


@dataclass(frozen=True)
class IdentityInputs:
    """Everything the identity digest is computed from.

    Exposed so callers can inspect the selection independently of hashing, and
    so a caller may fingerprint a file once and reuse the result.
    """

    header: HeaderIdentity
    #: Ranges dropped from every ``PT_LOAD`` before hashing: header, program
    #: header table and note payloads.  All layout or descriptive metadata.
    excluded_ranges: tuple[tuple[int, int], ...]
    loads: tuple[LoadRegion, ...]
    sections: tuple[SectionRegion, ...]
    interpreter_basename: str | None


def identity_digest(path: str | Path) -> str:
    """Return the identity digest of *path* as 64 lowercase hex characters."""

    with Path(path).open("rb") as stream:
        return compute_identity_digest(scan_identity_inputs(stream), stream)


def scan_identity_inputs(stream: BinaryIO) -> IdentityInputs:
    """Read the identity-defining structure of an ELF from *stream*.

    The stream is left positioned arbitrarily; callers that then read region
    bytes must seek explicitly, which :func:`compute_identity_digest` does.
    """

    try:
        from elftools.elf.elffile import ELFFile
    except ImportError as error:  # pragma: no cover - declared dependency
        raise ValueError("reading ELF identity requires pyelftools") from error

    elf = ELFFile(stream)
    header = _header_identity(stream, elf)
    excluded = _excluded_ranges(elf)

    loads: list[LoadRegion] = []
    interpreter_basename: str | None = None
    for segment in elf.iter_segments():
        segment_header = segment.header
        kind = segment_header.p_type
        if kind == "PT_LOAD":
            loads.append(
                LoadRegion(
                    virtual_address=int(segment_header.p_vaddr),
                    offset=int(segment_header.p_offset),
                    size=int(segment_header.p_filesz),
                )
            )
        elif kind == "PT_NOTE":
            excluded.append(
                (int(segment_header.p_offset), int(segment_header.p_filesz))
            )
        elif kind == "PT_INTERP" and interpreter_basename is None:
            raw = _read_at(
                stream, int(segment_header.p_offset), int(segment_header.p_filesz)
            )
            interpreter_basename = _interpreter_basename(raw)
    if not loads:
        raise ValueError("ELF contains no PT_LOAD segments; cannot derive identity")

    # File-offset order keeps the digest independent of program-header order.
    loads.sort(key=lambda item: (item.offset, item.virtual_address))
    excluded_ranges = tuple(sorted(item for item in excluded if item[1]))

    sections: list[SectionRegion] = []
    for name in ANALYSIS_SECTIONS:
        section = elf.get_section_by_name(name)
        if section is None:
            continue
        offset = int(section["sh_offset"])
        size = int(section["sh_size"])
        # An allocated section is covered byte for byte by the PT_LOAD mapping
        # it.  Only what no loaded segment carries has to be added separately,
        # which is exactly the non-allocated case; an empty section cannot
        # switch the analysis mode (see stack_liveness).
        if any(_covers(load, offset, size) for load in loads):
            continue
        sections.append(SectionRegion(name=name, offset=offset, size=size))
    sections.sort(key=lambda item: (item.offset, item.name))

    return IdentityInputs(
        header=header,
        excluded_ranges=excluded_ranges,
        loads=tuple(loads),
        sections=tuple(sections),
        interpreter_basename=interpreter_basename,
    )


def compute_identity_digest(inputs: IdentityInputs, stream: BinaryIO) -> str:
    """Hash *inputs* using region bytes read from *stream*.

    Taking an already-open stream keeps a caller free to anchor the file with a
    single descriptor and read the very bytes it hashed, instead of re-opening
    the path and racing a replacement.
    """

    digest = hashlib.sha256()
    _absorb(digest, inputs.header.encode())
    for load in inputs.loads:
        _absorb(digest, load.virtual_address.to_bytes(8, "little"))
        for offset, size in _pieces(load.offset, load.size, inputs.excluded_ranges):
            _absorb(digest, _read_at(stream, offset, size))
    for section in inputs.sections:
        _absorb(
            digest,
            section.name.encode("utf-8")
            + b"\x00"
            + _read_at(stream, section.offset, section.size),
        )
    # An absent PT_INTERP must not collide with an empty basename.
    if inputs.interpreter_basename is None:
        _absorb(digest, b"")
    else:
        _absorb(
            digest,
            _INTERP_BASENAME_MARKER + inputs.interpreter_basename.encode("utf-8"),
        )
    return digest.hexdigest()


def _header_identity(stream: BinaryIO, elf) -> HeaderIdentity:
    """Read the consumed header fields as integers.

    pyelftools reports ``e_type``/``e_machine``/``e_version`` as symbolic names,
    which would make the digest depend on its mapping tables rather than on the
    file, so the raw header bytes are decoded here.
    """

    size = 64 if elf.elfclass == 64 else 52
    raw = _read_at(stream, 0, size)
    order = "<" if elf.little_endian else ">"
    e_type, e_machine, e_version = struct.unpack_from(order + "HHI", raw, 16)
    if elf.elfclass == 64:
        e_entry = struct.unpack_from(order + "Q", raw, 24)[0]
        e_flags = struct.unpack_from(order + "I", raw, 48)[0]
    else:
        e_entry = struct.unpack_from(order + "I", raw, 24)[0]
        e_flags = struct.unpack_from(order + "I", raw, 36)[0]
    return HeaderIdentity(
        e_type=e_type,
        e_machine=e_machine,
        e_version=e_version,
        e_entry=e_entry,
        e_flags=e_flags,
    )


def _excluded_ranges(elf) -> list[tuple[int, int]]:
    """Return the layout ranges every ``PT_LOAD`` drops before hashing."""

    ranges: list[tuple[int, int]] = []
    ehsize = int(elf["e_ehsize"])
    if ehsize:
        ranges.append((0, ehsize))
    phoff = int(elf["e_phoff"])
    phentsize = int(elf["e_phentsize"])
    phnum = int(elf["e_phnum"])
    if phoff and phentsize and phnum:
        ranges.append((phoff, phentsize * phnum))
    return ranges


def _pieces(
    offset: int, size: int, exclusions: tuple[tuple[int, int], ...]
) -> tuple[tuple[int, int], ...]:
    """Split ``[offset, offset + size)`` around *exclusions*, in order."""

    pieces: list[tuple[int, int]] = []
    cursor = offset
    end = offset + size
    for excluded_offset, excluded_size in sorted(exclusions):
        excluded_end = excluded_offset + excluded_size
        if excluded_end <= cursor or excluded_offset >= end:
            continue
        if excluded_offset > cursor:
            pieces.append((cursor, excluded_offset - cursor))
        cursor = max(cursor, excluded_end)
    if cursor < end:
        pieces.append((cursor, end - cursor))
    return tuple(pieces)


def _absorb(digest: "hashlib._Hash", payload: bytes) -> None:
    """Mix one item in, length-prefixed so concatenation stays injective."""

    digest.update(_ABSORB_HEADER.pack(len(payload)))
    digest.update(payload)


def _read_at(stream: BinaryIO, offset: int, size: int) -> bytes:
    if offset < 0 or size < 0:
        raise ValueError(f"negative ELF region: offset={offset} size={size}")
    stream.seek(offset)
    data = stream.read(size)
    if len(data) != size:
        raise ValueError(
            f"ELF region is truncated: wanted {size} bytes at {offset}, "
            f"got {len(data)}"
        )
    return data


def _covers(load: LoadRegion, offset: int, size: int) -> bool:
    return offset >= load.offset and offset + size <= load.offset + load.size


def _interpreter_basename(raw: bytes) -> str | None:
    """Return the basename of a PT_INTERP payload, or ``None`` when empty.

    Only the basename takes part in the identity: loader selection looks the
    name up in ``scalar_root``, so a differing directory part describes the
    build machine rather than this file.
    """

    text = raw.split(b"\x00", 1)[0].decode("utf-8", "strict")
    if not text:
        return None
    return PurePosixPath(text).name


__all__ = [
    "ANALYSIS_SECTIONS",
    "HeaderIdentity",
    "IdentityInputs",
    "LoadRegion",
    "SectionRegion",
    "compute_identity_digest",
    "identity_digest",
    "scan_identity_inputs",
]
