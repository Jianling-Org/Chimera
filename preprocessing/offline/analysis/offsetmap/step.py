"""Generate RVA-normalized forward and reverse offset-map inputs."""

from __future__ import annotations

from chimera.runtime.manifest import ArtifactRecord
from ..core.contracts import AnalysisContext, ElfModuleServices
from ..core.monitor import local, monitored, returned
from ..core.workspace import sha256_file
from .model import OffsetMapArtifact
from ..translation.model import ensure_production_outputs_are_writable
from .codegen import (
    OFFSET_MAP_ABI_VERSION,
    export_asm,
    export_json,
    parse_asm_source,
    parse_translated_dump,
)


def _mapping_summary(context: AnalysisContext) -> dict[str, object]:
    mappings = context.require_global("offset_maps")
    return {
        "variants": len(mappings),
        "entries": sum(len(item.mapping) for item in mappings.values()),
        "outputs": [item.document for item in mappings.values()],
    }


class OffsetMapStep:
    name = "offset-map"

    @monitored(
        "offline.offset-map",
        variables=(
            local("generated"),
            local("mappings", label="translation_variants", transform=len),
            returned(label="offset_maps", transform=_mapping_summary),
        ),
    )
    def run(self, context: AnalysisContext) -> AnalysisContext:
        if not isinstance(context.platform, ElfModuleServices):
            raise TypeError(
                "offset-map requires ElfModuleServices for ELF artifacts"
            )
        emitter = getattr(context.toolchain, "artifact_emitter", None)
        if emitter is None or not callable(getattr(emitter, "emit_u64_table", None)):
            raise TypeError(
                "offset-map requires toolchain ArtifactEmitter capability "
                "before invoking the compiler"
            )
        generated = context.stage / "generated"
        artifacts = context.stage / "artifacts"
        generated.mkdir(parents=True, exist_ok=True)
        artifacts.mkdir(parents=True, exist_ok=True)
        mappings = {}
        modules = {
            module.module_id: module for module in context.require_global("modules")
        }
        module_paths = frozenset(item.selected_path for item in modules.values())
        translator_format = context.toolchain.translator.format
        disassembly_format = context.toolchain.disassembler.parse_format
        for key, translated in sorted(context.require_global("translations").items()):
            module = modules[key.module_id]
            spec = getattr(translated, "spec", None)
            if spec is None:
                raise ValueError(
                    "offset-map requires a TranslationProductionSpec for each "
                    f"route ({key.canonical_route[0]} -> {key.canonical_route[1]})"
                )
            ensure_production_outputs_are_writable(
                spec, context.stage, module_paths
            )
            labels = parse_asm_source(translated.assembly, translator_format)
            absolute = parse_translated_dump(
                translated.translated_dump,
                labels,
                translator_format,
                disassembly_format,
            )
            original_base = context.platform.load_base(module.selected_path)
            translated_base = context.platform.load_base(translated.library)
            mapping = {
                original - original_base: target - translated_base
                for original, target in absolute.items()
                if original >= original_base and target >= translated_base
            }
            table = (
                context.stage / spec.offset_map_assembly_path
            )
            document = (
                context.stage / spec.offset_map_document_path
            )
            library = (
                context.stage / spec.offset_map_library_path
            )
            for output in (table, document, library):
                output.parent.mkdir(parents=True, exist_ok=True)
            symbol_namespace = (
                spec.symbol_namespace
            )
            export_asm(mapping, table, symbol_namespace, emitter=emitter)
            export_json(mapping, document)
            context.platform.runner.run(
                context.toolchain.compiler.compile([table], library)
            )
            mappings[key] = OffsetMapArtifact(
                key=key,
                mapping=mapping,
                assembly=table,
                document=document,
                library=library,
                original_base=original_base,
            )
            owner_id = (
                spec.variant_id
            )
            session = context.require_global("workspace_session")
            session.registry.register_artifact(ArtifactRecord(
                artifact_id=spec.offset_map_artifact_id,
                owner_kind="variant",
                owner_id=owner_id,
                capability="offset-map",
                representation="elf",
                abi=OFFSET_MAP_ABI_VERSION,
                required_by=frozenset({"runtime"}),
                path=library.relative_to(context.stage).as_posix(),
                sha256=sha256_file(library),
            ))
            # The offset-map JSON stays a prepare-internal product (consumed
            # by patch-safepoints via the in-memory mapping and by rebuild
            # replay); it is not published as a manifest artifact.
        return context.put_global("offset_maps", mappings)
