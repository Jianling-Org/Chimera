"""ELF-side binding for scalar leaf proofs (standard RV64 PLT only)."""
from __future__ import annotations

from pathlib import Path
import struct
import subprocess

from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection

from .external_leaf import (
    MEMCPY_NO_CALLBACK_BASIS, ExternalLeafBindings, disassemble_leaf,
    file_sha256, verify_scalar_leaf,
)


def _version(elf, index):
    versions = elf.get_section_by_name(".gnu.version")
    if versions is None:
        return None, False
    value = versions.get_symbol(index)["ndx"]
    if not isinstance(value, int) or (value & 0x7fff) <= 1:
        return None, False
    hidden, value = bool(value & 0x8000), value & 0x7fff
    definitions = elf.get_section_by_name(".gnu.version_d")
    if definitions:
        for version, auxiliaries in definitions.iter_versions():
            if version["vd_ndx"] == value:
                return next(auxiliaries).name, hidden
    needs = elf.get_section_by_name(".gnu.version_r")
    if needs:
        for _need, auxiliaries in needs.iter_versions():
            for auxiliary in auxiliaries:
                if (auxiliary["vna_other"] & 0x7fff) == value:
                    return auxiliary.name, hidden
    raise ValueError("unresolved-symbol-version")


def dynamic_definitions(path: Path, names) -> dict[str, list[dict]]:
    found = {name: [] for name in names}
    with Path(path).open("rb") as stream:
        elf = ELFFile(stream)
        if elf.elfclass != 64 or not elf.little_endian or elf["e_machine"] != "EM_RISCV":
            raise ValueError("scalar leaf binding requires little-endian RV64 ELF")
        dynamic = elf.get_section_by_name(".dynamic")
        if dynamic is not None and any(tag.entry.d_tag in {
                "DT_AUDIT", "DT_DEPAUDIT", "DT_FILTER", "DT_AUXILIARY",
                0x6ffffefc, 0x6ffffefb, 0x7fffffff, 0x7ffffffd,
        } for tag in dynamic.iter_tags()):
            raise ValueError("scalar leaf binding cannot cover an ELF loader hook")
        symbols = elf.get_section_by_name(".dynsym")
        if symbols is None:
            return found
        for index, symbol in enumerate(symbols.iter_symbols()):
            if (symbol.name not in found or symbol["st_shndx"] == "SHN_UNDEF"
                    or symbol["st_info"]["bind"] == "STB_LOCAL"
                    or symbol["st_other"]["visibility"] in {"STV_HIDDEN", "STV_INTERNAL"}):
                continue
            version, hidden = _version(elf, index)
            found[symbol.name].append({"value": symbol["st_value"], "size": symbol["st_size"],
                "type": symbol["st_info"]["type"], "binding": symbol["st_info"]["bind"],
                "section": symbol["st_shndx"],
                "version": version, "hidden_version": hidden})
    return found


def _read_code(elf, address, size):
    for section in elf.iter_sections():
        start, extent = section["sh_addr"], section["sh_size"]
        if (section["sh_flags"] & 4 and section["sh_type"] == "SHT_PROGBITS"
                and start <= address and address + size <= start + extent):
            return section.data()[address - start:address - start + size]
    raise ValueError("symbol-code-not-backed-by-executable-section")


def _signed(value, bits):
    return value - (1 << bits) if value & (1 << (bits - 1)) else value


def plt_import(elf, target):
    """Validate instructions and GOT relocation; the printed PLT name is unused."""
    auipc, load, jump, nop = struct.unpack("<IIII", _read_code(elf, target, 16))
    if (auipc & 0xfff != (28 << 7) | 0x17
            or load & 0xfffff != (28 << 15) | (3 << 12) | (28 << 7) | 0x03
            or jump != (28 << 15) | (6 << 7) | 0x67 or nop != 0x13):
        raise ValueError("unsupported-plt-shape")
    got = target + _signed(auipc & 0xfffff000, 32) + _signed(load >> 20, 12)
    found = []
    for section in elf.iter_sections():
        if not isinstance(section, RelocationSection):
            continue
        symbols = elf.get_section(section["sh_link"])
        for relocation in section.iter_relocations():
            if relocation["r_offset"] != got:
                continue
            if relocation["r_info_type"] != 5 or symbols.name != ".dynsym":
                raise ValueError("plt-got-not-a-jump-slot")
            index = relocation["r_info_sym"]
            symbol = symbols.get_symbol(index)
            if symbol["st_shndx"] != "SHN_UNDEF" or relocation.entry.get("r_addend", 0):
                raise ValueError("plt-import-is-not-an-ordinary-undefined-symbol")
            version, hidden = _version(elf, index)
            found.append({"symbol": symbol.name, "version": version, "got": got})
    if len(found) != 1:
        raise ValueError("missing-or-ambiguous-jump-slot")
    return found[0]


def bind_leaves(elf_path, program, modules, contracts, objdump):
    requests = {item["symbol"]: item for item in contracts}
    names = set(requests) | {"memcpy"}
    definitions, digests, module_errors = {}, {}, {}
    for module in modules:
        path = Path(module.selected_path)
        try:
            digests[module.module_id] = file_sha256(path)
            definitions[module.module_id] = dynamic_definitions(path, names)
        except (OSError, ValueError) as error:
            module_errors[module.module_id] = type(error).__name__ + ":" + str(error)
            definitions[module.module_id] = {name: [] for name in names}
    if module_errors and contracts:
        # Preserve the explicit leaf contract's former fail-fast behavior.
        # The automatic memcpy interface has no user contract to trust, so its
        # incomplete scan is recorded below as an open boundary instead.
        raise ValueError(next(iter(module_errors.values())))
    proofs, rejections, interfaces, interface_rejections, cached = [], [], [], [], {}
    with elf_path.open("rb") as stream:
        elf = ELFFile(stream)
        if elf.elfclass != 64 or not elf.little_endian or elf["e_machine"] != "EM_RISCV":
            raise ValueError("external leaf binding requires little-endian RV64 ELF")
        for function in program.functions:
            if not function.is_external_trampoline:
                continue
            # The name only limits requested work; GOT/ELF checks below are
            # what establishes identity. An unrequested boundary stays open.
            requested_name = function.name.removesuffix("@plt")
            if requested_name not in requests and requested_name != "memcpy":
                continue
            try:
                imported = plt_import(elf, function.start)
                name = imported["symbol"]
                if name != requested_name:
                    raise ValueError("plt-name-and-relocation-disagree")
                if name == "memcpy":
                    if module_errors:
                        raise ValueError("selected-module-symbol-scan-incomplete")
                    candidates = [(module, definition) for module in modules
                        for definition in definitions[module.module_id][name]
                        if not definition["hidden_version"]]
                    if len(candidates) != 1:
                        raise ValueError("missing-or-interposed-memcpy-provider")
                    module, definition = candidates[0]
                    library = Path(module.selected_path).name
                    if library != "libc.so.6" or module_errors:
                        raise ValueError("memcpy-provider-is-not-the-selected-libc")
                    if (definition["type"] not in {"STT_FUNC", "STT_LOOS", "STT_GNU_IFUNC"}
                            or not isinstance(definition["section"], int)
                            or definition["binding"] not in {"STB_GLOBAL", "STB_WEAK"}):
                        raise ValueError("memcpy-provider-symbol-kind-is-not-supported")
                    if (imported["version"] is not None
                            and imported["version"] != definition["version"]):
                        raise ValueError("memcpy-symbol-version-mismatch")
                    interfaces.append({
                        "target": function.start,
                        "symbol": "memcpy",
                        "provider_module": module.module_id,
                        "provider_library": library,
                        "provider_sha256": digests[module.module_id],
                        "provider_address": definition["value"],
                        "provider_size": definition["size"],
                        "provider_type": definition["type"],
                        "provider_version": definition["version"],
                        "imported_version": imported["version"],
                        "got": imported["got"],
                        "status": "bound-standard-interface-no-application-callback",
                        "semantic_basis": MEMCPY_NO_CALLBACK_BASIS,
                    })
                    continue
                if module_errors:
                    raise ValueError("selected-module-symbol-scan-incomplete: "
                                     + ";".join(sorted(module_errors.values())))
                request = requests[name]
                candidates = [(module, definition) for module in modules
                    for definition in definitions[module.module_id][name]]
                if len(candidates) != 1:
                    raise ValueError("missing-or-interposed-scalar-provider")
                module, definition = candidates[0]
                if not module.is_scalar or Path(module.selected_path).name != request["library"]:
                    raise ValueError("provider-is-not-the-requested-scalar-module")
                if digests[module.module_id] != request["sha256"]:
                    raise ValueError("scalar-provider-hash-mismatch")
                if (definition["type"] != "STT_FUNC" or definition["hidden_version"]
                        or not isinstance(definition["section"], int)
                        or definition["binding"] not in {"STB_GLOBAL", "STB_WEAK"}):
                    raise ValueError("provider-is-not-an-ordinary-default-function")
                if imported["version"] is not None and imported["version"] != definition["version"]:
                    raise ValueError("scalar-provider-symbol-version-mismatch")
                start, size = definition["value"], definition["size"]
                if not 0 < size <= 4096:
                    raise ValueError("invalid-scalar-leaf-symbol-size")
                key = (module.module_id, start, size)
                if key not in cached:
                    with Path(module.selected_path).open("rb") as provider:
                        code = _read_code(ELFFile(provider), start, size)
                    body = disassemble_leaf(Path(module.selected_path), name, start, size, objdump)
                    problems = verify_scalar_leaf(body, size, code)
                    if problems:
                        raise ValueError(";".join(problems))
                    import hashlib
                    cached[key] = hashlib.sha256(code).hexdigest()
                proofs.append({"target": function.start, **request,
                    "provider_module": module.module_id, "provider_address": start,
                    "size": size, "code_sha256": cached[key], "version": definition["version"],
                    "got": imported["got"], "status": "verified-scalar-leaf"})
            except (OSError, ValueError, struct.error, subprocess.TimeoutExpired) as error:
                # A malformed or unproved boundary never becomes a proof.
                item = {"target": function.start, "reason": str(error)}
                if requested_name == "memcpy":
                    interface_rejections.append(item)
                else:
                    rejections.append(item)
    for module in modules:
        try:
            unchanged = file_sha256(Path(module.selected_path)) == digests[module.module_id]
        except (OSError, KeyError):
            unchanged = False
        if not unchanged:
            error = {"reason": "module-changed-during-leaf-binding",
                     "module": module.module_id}
            return ExternalLeafBindings((), (error,) if contracts else (), (),
                                        (error,) if any(f.name.removesuffix("@plt") == "memcpy"
                                                        for f in program.functions) else ())
    return ExternalLeafBindings(tuple(proofs), tuple(rejections),
                                tuple(interfaces), tuple(interface_rejections))
