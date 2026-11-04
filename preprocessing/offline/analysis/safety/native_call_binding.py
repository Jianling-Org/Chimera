"""ELF-bound, machine-verified native scalar call closures.

Unlike an interface/name assumption, every reachable body is decoded and its
ABI return checked. Immutable object and TLS references are bound through real
relocations. Any missing target, interposer, loader hook or budget gap stays open.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import io
from pathlib import Path
import struct
import subprocess
import time

from elftools.dwarf.callframe import FDE
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
from elftools.common.exceptions import ELFError, DWARFError

from .external_leaf import disassemble_leaf, file_sha256
from .external_leaf_binding import _read_code, _version, plt_import
from .native_call_closure import ClosureRefusal, NativeCallClosure


NATIVE_CLOSURE_FORMAT = 'chimera-native-scalar-call-closure-v1'
NATIVE_CLOSURE_STATUS = 'verified-native-scalar-call-closure'


@dataclass
class Snapshot:
    module: object
    data: bytes
    digest: str
    elf: ELFFile
    definitions: dict
    relocations: dict
    extents: dict


class NativeClosureEnvironment:
    def __init__(self, main_path, modules, objdump, *, disassemble=disassemble_leaf):
        self.main_path = Path(main_path).resolve()
        self.modules = tuple(modules)
        self.objdump, self.disassemble = objdump, disassemble
        self.snapshots = {}
        self.objects = {}
        self.deadline = 0

    def _initialize(self):
        if self.snapshots:
            return
        snapshots = {}
        total = 0
        for module in self.modules:
            path = Path(module.selected_path)
            size = path.stat().st_size
            total += size
            if total > 256*1024**2:
                raise ClosureRefusal('selected-native-module-byte-budget-exhausted')
            data = path.read_bytes()
            elf = ELFFile(io.BytesIO(data))
            if (elf.elfclass != 64 or not elf.little_endian or elf['e_machine'] != 'EM_RISCV'
                    or elf['e_flags'] & 6 != 4):
                # The proof tracks 64-bit callee-saved FP registers. A different
                # FLEN/ABI must not reuse that preservation argument.
                raise ClosureRefusal('native-closure-requires-little-endian-rv64-lp64d')
            dynamic = elf.get_section_by_name('.dynamic')
            if dynamic is not None and any(tag.entry.d_tag in {
                    'DT_AUDIT', 'DT_DEPAUDIT', 'DT_FILTER', 'DT_AUXILIARY',
                    0x6ffffefc, 0x6ffffefb, 0x7fffffff, 0x7ffffffd,
            } for tag in dynamic.iter_tags()):
                raise ClosureRefusal('native-provider-has-loader-hooks')
            definitions, relocations = {}, {}
            symbols = elf.get_section_by_name('.dynsym')
            if symbols:
                for index, symbol in enumerate(symbols.iter_symbols()):
                    if (symbol['st_shndx'] == 'SHN_UNDEF'
                            or symbol['st_info']['bind'] == 'STB_LOCAL'
                            or symbol['st_other']['visibility'] in {'STV_HIDDEN', 'STV_INTERNAL'}):
                        continue
                    version, hidden = _version(elf, index)
                    definitions.setdefault(symbol.name, []).append(dict(
                        value=symbol['st_value'], size=symbol['st_size'],
                        type=symbol['st_info']['type'], binding=symbol['st_info']['bind'],
                        section=symbol['st_shndx'], version=version, hidden_version=hidden))
            for section in elf.iter_sections():
                if isinstance(section, RelocationSection):
                    symtab = elf.get_section(section['sh_link'])
                    for relocation in section.iter_relocations():
                        address = relocation['r_offset']
                        if address in relocations:
                            raise ClosureRefusal('overlapping-native-relocations')
                        index = relocation['r_info_sym']
                        symbol = symtab.get_symbol(index)
                        version = _version(elf, index)[0] if symtab.name == '.dynsym' else None
                        relocations[address] = dict(kind=relocation['r_info_type'], symbol=symbol.name,
                            version=version, addend=relocation.entry.get('r_addend', 0),
                            defined=symbol['st_shndx'] != 'SHN_UNDEF', value=symbol['st_value'],
                            symbol_type=symbol['st_info']['type'], size=symbol['st_size'])
            snapshots[module.module_id] = Snapshot(module, data,
                hashlib.sha256(data).hexdigest(), elf, definitions, relocations, {})
        main = [s for s in snapshots.values()
                if Path(s.module.selected_path).resolve() == self.main_path]
        if len(main) != 1:
            raise ClosureRefusal('missing-or-ambiguous-native-main-module')
        self.main_id = main[0].module.module_id
        self.snapshots = snapshots

    def resolve_symbol(self, name, version, kind):
        candidates = [(mid, definition) for mid, snapshot in self.snapshots.items()
                      for definition in snapshot.definitions.get(name, ())
                      if not definition['hidden_version']]
        if len(candidates) != 1:
            raise ClosureRefusal('missing-or-interposed-native-symbol:'+name)
        mid, definition = candidates[0]
        if (definition['type'] != kind or not isinstance(definition['section'], int)
                or definition['binding'] not in {'STB_GLOBAL', 'STB_WEAK'}
                or definition['size'] <= 0
                or version is not None and version != definition['version']):
            raise ClosureRefusal('unsupported-native-symbol-definition:'+name)
        if kind == 'STT_TLS':
            elf = self.snapshots[mid].elf
            section = elf.get_section(definition['section'])
            tls = [segment for segment in elf.iter_segments() if segment['p_type'] == 'PT_TLS']
            if (len(tls) != 1 or not section['sh_flags'] & 0x400
                    or definition['value'] < 0
                    or definition['value']+definition['size'] > tls[0]['p_memsz']
                    or not section['sh_addr'] <= tls[0]['p_vaddr']+definition['value']
                    or tls[0]['p_vaddr']+definition['value']+definition['size'] > section['sh_addr']+section['sh_size']):
                raise ClosureRefusal('native-tls-symbol-outside-loader-tls-layout')
        return mid, definition

    def code_bytes(self, mid, address, size):
        snapshot = self.snapshots[mid]
        code = _read_code(snapshot.elf, address, size)
        candidates = []
        for segment in snapshot.elf.iter_segments():
            if segment['p_type'] != 'PT_LOAD':
                continue
            start = segment['p_vaddr']
            if (segment['p_flags'] & 2 and (start & ~4095) < address+size
                    and address < ((start+segment['p_memsz']+4095) & ~4095)):
                raise ClosureRefusal('native-code-overlaps-writable-load-page')
            if (segment['p_flags'] & 1 and not segment['p_flags'] & 2
                    and start <= address and address+size <= start+segment['p_filesz']):
                offset = segment['p_offset']+address-start
                candidates.append(snapshot.data[offset:offset+size])
        if len(candidates) != 1 or candidates[0] != code:
            raise ClosureRefusal('native-code-not-bound-to-immutable-executable-load')
        if any(start < address+size and address < start+8 for start in snapshot.relocations):
            raise ClosureRefusal('native-code-has-loader-relocation')
        return code

    def root(self, target):
        self._initialize()
        self.code_bytes(self.main_id, target, 16)
        imported = plt_import(self.snapshots[self.main_id].elf, target)
        mid, definition = self.resolve_symbol(imported['symbol'], imported['version'], 'STT_FUNC')
        if mid == self.main_id:
            raise ClosureRefusal('native-root-resolves-back-into-application')
        return imported, mid, definition

    def _extents(self, mid):
        snapshot = self.snapshots[mid]
        if not snapshot.extents:
            # Exact function entries only; never infer an internal helper's
            # extent from the next printed objdump label or a nearby symbol.
            ranges = {}
            entries = (snapshot.elf.get_dwarf_info().EH_CFI_entries()
                       if snapshot.elf.get_section_by_name('.eh_frame') else ())
            for entry in entries:
                if isinstance(entry, FDE):
                    start, size = entry['initial_location'], entry['address_range']
                    if start in ranges and ranges[start] != size:
                        raise ClosureRefusal('ambiguous-native-unwind-extent')
                    ranges[start] = size
            for definitions in snapshot.definitions.values():
                for definition in definitions:
                    if definition['type'] != 'STT_FUNC' or not definition['size']:
                        continue
                    start, size = definition['value'], definition['size']
                    if start in ranges and ranges[start] != size:
                        raise ClosureRefusal('native-symbol-and-unwind-extents-disagree')
                    ranges[start] = size
            snapshot.extents = ranges
        return snapshot.extents

    def body(self, key):
        if time.monotonic() > self.deadline:
            raise ClosureRefusal('native-call-wall-time-budget-exhausted')
        mid, address = key
        snapshot = self.snapshots[mid]
        size = self._extents(mid).get(address)
        if size is None or not 0 < size <= 4096:
            raise ClosureRefusal('missing-or-oversized-native-function-extent')
        code = self.code_bytes(mid, address, size)
        function = self.disassemble(Path(snapshot.module.selected_path),
                                    'native', address, size, self.objdump)
        return function, code

    def target(self, source, address):
        if address is None:
            raise ClosureRefusal('unresolved-native-target')
        mid = source[0]
        snapshot = self.snapshots[mid]
        if address in self._extents(mid):
            return mid, address
        try:
            self.code_bytes(mid, address, 16)
            imported = plt_import(snapshot.elf, address)
        except (ValueError, OSError) as error:
            raise ClosureRefusal('native-target-has-no-body-or-proven-plt') from error
        provider, definition = self.resolve_symbol(imported['symbol'], imported['version'], 'STT_FUNC')
        if provider == self.main_id:
            raise ClosureRefusal('native-closure-calls-application')
        return provider, definition['value']

    def immutable(self, mid, address, size):
        elf = self.snapshots[mid].elf
        segments = tuple(elf.iter_segments())
        # RELRO can protect part of an otherwise writable load segment.
        for segment in segments:
            start, end = segment['p_vaddr'], segment['p_vaddr']+segment['p_memsz']
            if (segment['p_type'] == 'PT_GNU_RELRO' and start <= address
                    and address+size <= (end & ~4095)):
                return True
        if any(segment['p_type'] == 'PT_LOAD' and segment['p_flags'] & 2
               and (segment['p_vaddr'] & ~4095) < address+size
               and address < ((segment['p_vaddr']+segment['p_memsz']+4095) & ~4095)
               for segment in segments):
            return False
        for segment in segments:
            start, end = segment['p_vaddr'], segment['p_vaddr']+segment['p_memsz']
            if segment['p_type'] == 'PT_LOAD' and not segment['p_flags'] & 2 and start <= address and address+size <= end:
                return True
        return False

    def load(self, key, address, size):
        if address[0] != 'address' or size > 8:
            return None
        _, mid, offset = address
        if not self.immutable(mid, offset, size):
            return None
        snapshot = self.snapshots[mid]
        # A partial/overlapping relocation is never read as ordinary data.
        for start in snapshot.relocations:
            if start < offset+size and offset < start+8 and start != offset:
                return None
        relocation = snapshot.relocations.get(offset)
        if relocation is None:
            # The loader may initialize RELRO data (e.g. stack canaries).
            # Equal immutable loads are stable, not equal to initial file bytes.
            return ('immutable', mid, offset, size)
        if size != 8 or relocation['addend']:
            return None
        kind = relocation['kind']
        if kind not in {2, 11}:
            return None
        expected = 'STT_OBJECT' if kind == 2 else 'STT_TLS'
        provider, definition = self.resolve_symbol(relocation['symbol'], relocation['version'], expected)
        record = dict(source_module=mid, source_address=offset,
            symbol=relocation['symbol'], imported_version=relocation['version'], relocation_type=kind,
            provider_module=provider, **definition)
        self.objects[mid, offset] = record
        if kind == 11:
            return ('tls-offset', provider, relocation['symbol'], definition['size'])
        return ('address', provider, definition['value'])

    def tls_write(self, address, size):
        if address[0] != 'tls-address':
            return False
        _, _provider, _symbol, extent, offset = address
        return 0 <= offset and offset+size <= extent

    def prove_root(self, target):
        self.deadline = time.monotonic()+60
        self.objects = {}
        imported, mid, definition = self.root(target)
        key = (mid, definition['value'])
        solver = NativeCallClosure(self)
        solver.prove(key)
        reachable, pending = set(), [key]
        while pending:
            node = pending.pop()
            if node in reachable:
                continue
            reachable.add(node)
            pending.extend(solver.memo[node]['callees'])
        for snapshot in self.snapshots.values():
            if file_sha256(Path(snapshot.module.selected_path)) != snapshot.digest:
                raise ClosureRefusal('native-module-changed-during-proof')
        return dict(format=NATIVE_CLOSURE_FORMAT, status=NATIVE_CLOSURE_STATUS,
            target=target, symbol=imported['symbol'], got=imported['got'],
            imported_version=imported['version'], provider_module=mid,
            provider_address=definition['value'], provider_definition=definition,
            modules={name: value.digest for name, value in self.snapshots.items()},
            object_bindings=list(self.objects.values()),
            functions=[dict(module=name, **solver.memo[name, address])
                       for name, address in sorted(reachable)])


class NativeClosureBindings:
    """Lazy proof work is limited to actual active external targets."""
    def __init__(self, main_path, modules, objdump, *, excluded_targets=()):
        self.environment = NativeClosureEnvironment(main_path, modules, objdump)
        self.excluded_targets = frozenset(excluded_targets)
        self.attempted = set()
        self.proofs = []
        self.rejections = []

    def resolve(self, targets):
        deadline = time.monotonic()+120
        for target in sorted(set(targets)-self.attempted-self.excluded_targets):
            self.attempted.add(target)
            if len(self.attempted) > 32 or time.monotonic() > deadline:
                self.rejections.append(dict(target=target, reason='native-root-proof-budget-exhausted'))
                continue
            try:
                self.environment.objects = {}
                self.proofs.append(self.environment.prove_root(target))
            except (ValueError, OSError, struct.error, subprocess.TimeoutExpired, ELFError, DWARFError) as error:
                self.rejections.append(dict(target=target, reason=str(error)))
