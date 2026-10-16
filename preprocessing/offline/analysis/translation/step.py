"""Materialize translation-variant requests through an adapter."""

from __future__ import annotations

from pathlib import Path
import shutil

from chimera.preprocess.offline.config import TranslationEndpoint
from chimera.runtime.manifest import (
    ArtifactRecord,
    VariantPropertyRecord,
    VariantRecord,
    canonical_property_value,
    variant_records_fingerprint,
)
from ..core.contracts import AnalysisContext, ElfModuleServices
from ..core.workspace import sha256_file
from ..core.monitor import argument, local, monitored, returned
from .model import (
    TranslatedModule,
    TranslationKey,
    TranslationRequest,
    TranslationProductionSpec,
    ensure_production_outputs_are_writable,
)


def _translation_summary(context: AnalysisContext) -> dict[str, object]:
    translations = context.require_global("translations")
    return {
        "count": len(translations),
        "libraries": [item.library for item in translations.values()],
    }


class TranslationStep:
    name = "translate"

    def __init__(
        self,
        *,
        source_endpoint: TranslationEndpoint,
        target_endpoint: TranslationEndpoint,
        translator_path: Path,
        semantics=None,
    ) -> None:
        self.source_endpoint = source_endpoint
        self.target_endpoint = target_endpoint
        self.translator_path = translator_path
        self.semantics = semantics

    @monitored(
        "offline.translate",
        variables=(
            argument("self", label="source_endpoint", path=("source_endpoint",)),
            argument("self", label="target_endpoint", path=("target_endpoint",)),
            local("production_spec"),
            local("request"),
            returned(label="translations", transform=_translation_summary),
        ),
    )
    def run(self, context: AnalysisContext) -> AnalysisContext:
        if context.stage is None:
            raise RuntimeError("translate requires a staging workspace")
        if not isinstance(context.platform, ElfModuleServices):
            raise TypeError(
                "translate currently produces ELF artifacts and requires "
                "ElfModuleServices"
            )
        emitter = getattr(context.toolchain, "artifact_emitter", None)
        if emitter is None or not callable(
            getattr(emitter, "emit_translation_provenance", None)
        ):
            raise TypeError(
                "translate requires toolchain ArtifactEmitter capability "
                "before invoking the translator"
            )
        semantics = (
            self.semantics
            if self.semantics is not None
            else getattr(context.target_bundle, "translation_semantics", None)
        )
        production_spec: TranslationProductionSpec | None = None
        if semantics is None or not all(
            callable(getattr(semantics, name, None))
            for name in ("validate_route", "production_spec")
        ):
            raise TypeError(
                "translate requires target translation route/production semantics"
            )
        semantics.validate_route(self.source_endpoint, self.target_endpoint)
        dump_dir = context.stage / "dump"
        generated_dir = context.stage / "generated"
        artifact_dir = context.stage / "artifacts"
        for directory in (dump_dir, generated_dir, artifact_dir):
            directory.mkdir(parents=True, exist_ok=True)
        translated = dict(context.global_results.get("translations", {}))
        native_dumps = context.require_global("native_dumps")
        modules = tuple(context.require_global("modules"))
        module_paths = frozenset(item.selected_path for item in modules)
        for module in modules:
            spec = semantics.production_spec(
                module.module_id,
                self.source_endpoint,
                self.target_endpoint,
                context.stage,
            )
            production_spec = spec
            ensure_production_outputs_are_writable(
                spec, context.stage, module_paths,
            )
            namespace = spec.symbol_namespace
            input_properties = dict(spec.input_properties)
            output_properties = dict(spec.output_properties)
            assembly_output = context.stage / spec.assembly_path
            library_output = context.stage / spec.library_path
            translated_dump_output = context.stage / spec.translated_dump_path
            provenance_output = context.stage / spec.provenance_path
            for output in (
                assembly_output, library_output, translated_dump_output,
                provenance_output,
            ):
                output.parent.mkdir(parents=True, exist_ok=True)
            if spec.unpatched_library_path is not None:
                (context.stage / spec.unpatched_library_path).parent.mkdir(
                    parents=True, exist_ok=True
                )
            if spec.unpatched_library_sha256_path is not None:
                (context.stage / spec.unpatched_library_sha256_path).parent.mkdir(
                    parents=True, exist_ok=True
                )
            request = TranslationRequest(
                module=module,
                source_endpoint=self.source_endpoint,
                target_endpoint=self.target_endpoint,
                translator_path=self.translator_path,
                native_dump=native_dumps[module.module_id],
                assembly_output=assembly_output,
                library_output=library_output,
                translated_dump_output=translated_dump_output,
                symbol_namespace=namespace,
                input_properties=input_properties,
                output_properties=output_properties,
            )
            key = TranslationKey(
                module.module_id,
                self.source_endpoint,
                self.target_endpoint,
            )
            if key in translated:
                raise ValueError(f"duplicate translation result: {key}")
            context.platform.runner.run(
                context.toolchain.translator.command(request)
            )
            if not request.assembly_output.is_file():
                raise FileNotFoundError(
                    f"translator did not create assembly: {request.assembly_output}"
                )
            identifier = spec.owner_id
            variant = VariantRecord(identifier, module.module_id)
            def property_record(side: str, name: str, value):
                kinds = (
                    spec.input_property_kinds if side == "input"
                    else spec.output_property_kinds
                )
                kind = (
                    kinds.get(name) if kinds is not None and name in kinds
                    else ("u64" if isinstance(value, int) and not isinstance(value, bool) else "token")
                )
                return VariantPropertyRecord(
                    identifier, side, name, kind,
                    canonical_property_value(kind, value),
                )
            properties = tuple(
                property_record(side, name, value)
                for side, values in (("input", input_properties), ("output", output_properties))
                for name, value in values.items()
            )
            fingerprint = variant_records_fingerprint(variant, properties)
            emitter.emit_translation_provenance(
                provenance_output,
                symbol_namespace=spec.symbol_namespace,
                fingerprint=fingerprint,
            )
            context.platform.runner.run(
                context.toolchain.compiler.compile(
                    [request.assembly_output, provenance_output], request.library_output
                )
            )
            if not request.library_output.is_file():
                raise FileNotFoundError(
                    f"compiler did not create translated library: {request.library_output}"
                )
            if spec.unpatched_library_path is not None:
                unpatched = context.stage / spec.unpatched_library_path
                shutil.copy2(request.library_output, unpatched)
                checksum_path = spec.unpatched_library_sha256_path
                if checksum_path is None:
                    raise ValueError(
                        "translation production spec omitted unpatched library checksum path"
                    )
                (context.stage / checksum_path).write_text(
                    f"{sha256_file(unpatched)}\n", encoding="ascii"
                )
            context.platform.runner.run(
                context.toolchain.disassembler.command(request.library_output),
                stdout_path=request.translated_dump_output,
            )
            translated[key] = TranslatedModule(
                key=key,
                assembly=request.assembly_output,
                library=request.library_output,
                native_dump=request.native_dump,
                translated_dump=request.translated_dump_output,
                symbol_namespace=request.symbol_namespace,
                fingerprint=fingerprint,
                spec=spec,
            )
            session = context.require_global("workspace_session")
            session.registry.register_variant(variant)
            for property_record in properties:
                session.registry.register_variant_property(property_record)
            session.registry.register_artifact(ArtifactRecord(
                artifact_id=spec.artifact_id,
                owner_kind="variant",
                owner_id=identifier,
                capability="translated-code",
                representation="elf",
                abi=1,
                required_by=frozenset({"runtime"}),
                path=request.library_output.relative_to(context.stage).as_posix(),
                sha256=sha256_file(request.library_output),
            ))
        return context.put_global("translations", translated)
