"""Target-independent service contracts consumed by analysis steps.

This module declares the *generic skeleton* of services consumed by the
offline pipeline and the *optional* capability protocols an extension or
platform may additionally implement. The split is intentional:

- ``StackSemantics``, ``PlatformServices``, ``ArchitectureExtensionServices``
  cover what every architecture/platform must provide to be reachable from
  the workflow. They must not mention vector semantics, VLEN, RISC-V, or any
  extension-specific concept.
- ``VectorStackSemantics``, ``VectorExtensionServices`` add vector analysis
  surface. A step that genuinely needs vector analysis (e.g. ``safety``)
  ``isinstance``-checks against these protocols and fails fast when an
  extension does not implement them, so a non-vector extension can still run
  steps that do not need them.
- ``ElfModuleServices`` is the ELF-only platform surface (``interpreter``,
  ``load_base``, ``load_segments``, ``dependencies``,
  ``dynamic_search_paths``). ``PlatformServices`` itself only requires
  ``validate_capabilities`` and ``runner``.

Nothing in the pipeline rewrites an input ELF: ``run`` invokes the loader
explicitly, so the toolchain needs no patcher.  Every artifact is derived from
the selected files as the application ships them.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Protocol, Sequence, Iterable, runtime_checkable


class StackSemantics(Protocol):
    """Scalar stack semantics: required from every architecture extension."""

    @property
    def symbolic(self) -> Any: ...
    def written_scalar_registers(self, instruction) -> set[str]: ...
    def read_scalar_registers(self, instruction) -> set[str]: ...
    def is_call_instruction(self, instruction) -> bool: ...
    def is_tail_call_instruction(self, instruction, function) -> bool: ...
    def stack_access_kind(self, instruction) -> str: ...


@dataclass(frozen=True, slots=True)
class ScalarWidthInstruction:
    """Scalar read/write and memory roles for hardware-width value liveness."""

    reads: frozenset[str] = frozenset()
    writes: frozenset[str] = frozenset()
    source_kind: str | None = None
    memory: tuple[str, int, int] | None = None
    load: bool = False
    store: bool = False
    stored_value: str | None = None
    unstable_write: bool = False
    call: bool = False
    returns: bool = False
    unmodelled: bool = False
    vector_data_write: bool = False
    call_value_reads: frozenset[str] = frozenset()
    vector_reads: frozenset[int] = frozenset()
    # Vector registers consumed as data. `vector_reads` remains the combined
    # compatibility set, including mask and indexed-address operands.
    vector_value_reads: frozenset[int] = frozenset()
    vector_writes: frozenset[int] = frozenset()
    vector_must_writes: frozenset[int] = frozenset()
    vector_address_reads: frozenset[str] = frozenset()
    vector_memory_kind: str | None = None
    vector_restart_unproven: bool = False
    vector_memory: tuple[str, int] | None = None
    # Upper byte extent as (constant, VLENB coefficient). Only a complete
    # unmasked whole-register store can also use it as a covering definition.
    vector_memory_span: tuple[int, int] | None = None
    vector_store_complete: bool = False
    vector_store_values: frozenset[int] = frozenset()
    vector_mask_reads: frozenset[int] = frozenset()
    vector_memory_address_vectors: frozenset[int] = frozenset()
    # Positive, complete integer register-only effect coverage. Absence is
    # never a no-memory certificate; return/operand shapes must also be valid.
    register_only: bool = False
    call_target_reads: frozenset[str] = frozenset()


class VectorStackSemantics(StackSemantics, Protocol):
    """Optional vector-extension surface on top of scalar stack semantics."""

    def vector_memory_operand(self, instruction) -> str | None: ...
    def is_whole_register_access(self, instruction) -> bool: ...
    def is_vlen_sensitive_config(
        self, config, *, min_vlen_bits: int
    ) -> bool: ...
    def config_at(self, result, address: int) -> frozenset[object]: ...
    def scalar_width_facts(self, instruction, configs=()) -> ScalarWidthInstruction: ...
    def scalar_width_cache_reads(
        self, instruction, incoming_expressions, width_registers
    ) -> set[str]: ...


class PlatformServices(Protocol):
    """Platform surface required from every supported platform."""

    def validate_capabilities(self, config) -> dict[str, str]: ...

    @property
    def runner(self): ...


@runtime_checkable
class ElfModuleServices(Protocol):
    """ELF-only platform surface (interpreter, load layout, dependencies)."""

    def dependencies(
        self, module_path: Path, library_roots: tuple[Path, ...]
    ) -> tuple[Path, ...]: ...
    def interpreter(self, path: Path) -> str | None: ...
    def load_base(self, path: Path) -> int: ...
    def load_segments(self, path: Path) -> tuple[tuple[int, int, int], ...]: ...
    def virtual_to_file_offset(
        self, segments: tuple[tuple[int, int, int], ...], address: int
    ) -> int: ...
    def dynamic_search_paths(self, path: Path) -> dict[str, tuple[str, ...]]: ...


class ArchitectureExtensionServices(Protocol):
    """Minimal extension contract required from every architecture extension."""

    @property
    def name(self) -> str: ...
    @property
    def stack_semantics(self) -> StackSemantics: ...


@runtime_checkable
class VectorExtensionServices(ArchitectureExtensionServices, Protocol):
    """Optional vector extension contract.

    Steps that consume vector analysis (``safety``) gate themselves on
    ``isinstance(extension, VectorExtensionServices)``; extensions without
    vector analysis intentionally do not implement this protocol.
    """

    @property
    def stack_semantics(self) -> VectorStackSemantics: ...
    def vector_configs(self, program): ...
    def vector_liveness(self, program): ...
    def vtype_annotations(self, program, configs): ...
    def classify_vector_liveness(self, vector_live) -> tuple[str, ...]: ...


@runtime_checkable
class TranslationSemantics(Protocol):
    """Scene-owned route and production naming contract.

    Generic translation and offset-map steps only consume this protocol.  A
    scene decides how endpoints become typed manifest properties, variant IDs,
    symbol namespaces and intermediate paths.
    """

    def validate_route(self, source, target): ...
    def production_spec(self, module_id: str, source, target, stage): ...
    def endpoint_from_properties(self, registry, variant_id: str, side: str): ...


@runtime_checkable
class TrapPatchServices(Protocol):
    """Optional target hook for size-preserving trap patching."""

    @property
    def max_instruction_bytes(self) -> int: ...

    def trap_for_instruction(
        self, instruction_bytes: bytes
    ) -> tuple[int, bytes]: ...


@runtime_checkable
class ArtifactEmitter(Protocol):
    """Target/toolchain capability for assembly-backed ABI artifacts."""

    def emit_u64_table(
        self, output_path: Path,
        tables: Iterable[tuple[str, Iterable[object]]],
    ) -> None: ...

    def emit_translation_provenance(
        self,
        output_path: Path,
        *,
        symbol_namespace: str,
        fingerprint: str,
    ) -> None: ...


class ArchitectureServices(Protocol):
    @property
    def extension(self) -> ArchitectureExtensionServices: ...
    def build_cfg(self, program): ...


@dataclass(frozen=True)
class DisassemblyFormat:
    instruction_pattern: str
    function_pattern: str
    field_map: Mapping[str, int]
    dump_label_pattern: str


@dataclass(frozen=True)
class TranslatorFormat:
    target_label_prefix: str
    entry_label_suffix: str
    label_pattern: str


class BuildToolchain(Protocol):
    def configure(
        self, source: Path, build: Path, *, defines: Mapping[str, str],
        install_prefix: Path, toolchain_file: Path | None,
        system_name: str, processor: str, compiler: str,
        sysroot: Path | None,
    ) -> Sequence[str]: ...
    def build(self, build: Path, *, target: str) -> Sequence[str]: ...
    def install(self, build: Path) -> Sequence[str]: ...


class DisassembleToolchain(Protocol):
    @property
    def parse_format(self) -> DisassemblyFormat: ...
    def command(self, binary: Path) -> Sequence[str]: ...
    def is_external_trampoline(self, name: str) -> bool: ...


class TranslateToolchain(Protocol):
    @property
    def format(self) -> TranslatorFormat: ...
    def command(self, request: Any) -> Sequence[str]: ...


class Compiler(Protocol):
    def compile(
        self, sources: Sequence[Path], output: Path, *,
        flags: Sequence[str] = ("-fPIC", "-shared"),
    ) -> Sequence[str]: ...


class SymbolInspector(Protocol):
    def exported_symbols(self, library: Path) -> Sequence[str]: ...


@dataclass(frozen=True)
class ToolchainServices:
    code_builder: BuildToolchain
    disassembler: DisassembleToolchain
    translator: TranslateToolchain
    compiler: Compiler
    symbols: SymbolInspector
    # Optional syntax emitter for assembly-backed ABI artifacts.  Kept after
    # the pre-existing fields so positional construction remains compatible.
    artifact_emitter: ArtifactEmitter | None = None


@dataclass(frozen=True)
class AnalysisServices:
    architecture: ArchitectureServices
    platform: PlatformServices
    toolchain: ToolchainServices
