"""Replay callbacks registered by workflow steps.

The rebuild engine only invokes a step's declared callback.  Keeping the
format-specific reconstruction here makes replay an extension point instead
of a name-based switch in the engine itself.
"""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path
from typing import Any, Mapping

from chimera.preprocess.offline.analysis.build_runtime.model import RuntimeArtifact
from chimera.preprocess.offline.analysis.offsetmap.codegen import (
    parse_asm_source,
    parse_translated_dump,
)
from chimera.preprocess.offline.analysis.offsetmap.model import OffsetMapArtifact
from chimera.preprocess.offline.analysis.program_model.parser import parse_dump
from chimera.preprocess.offline.analysis.safety.classifier import (
    SafetyAnalysisResult,
    SafetyRecord,
)
from chimera.preprocess.offline.analysis.safety.stack_liveness.model import (
    ScopeExclusion,
)
from chimera.preprocess.offline.analysis.safety.stack_liveness.scope import (
    CONSERVATIVE,
    assumption_for_policy,
    is_conditional_policy,
    normalize_unknown_stack_size_policy,
)
from chimera.preprocess.offline.analysis.safety.result import SafetyPipelineResult
from chimera.preprocess.offline.analysis.translation.model import (
    TranslatedModule,
    TranslationKey,
)
from chimera.preprocess.offline.analysis.core.contracts import ElfModuleServices
from chimera.runtime.manifest import variant_records_fingerprint
from .errors import BuildReplayPropertyError, RebuildMissingUpstream


def replay_disassemble(_parameters: Mapping[str, Any], context):
    dump_dir = context.stage / "dump"
    dumps = {}
    for module in context.require_global("modules"):
        candidate = dump_dir / f"{module.module_id}.dump"
        if not candidate.is_file():
            raise RebuildMissingUpstream(
                f"disassemble replay missing native dump: {candidate}"
            )
        dumps[module.module_id] = candidate
    return context.put_global("native_dumps", dumps)


def replay_program_model(_parameters: Mapping[str, Any], context):
    native_dumps = context.require_global("native_dumps")
    programs = {
        module_id: context.architecture.build_cfg(
            parse_dump(
                path,
                context.toolchain.disassembler.parse_format,
                is_external_trampoline=getattr(
                    context.toolchain.disassembler,
                    "is_external_trampoline",
                    None,
                ),
                # Match BuildProgramModelStep: dump_lines has no consumer
                # once the CFG exists; keep the single streamed copy.
                retain_dump_lines=False,
            )
        )
        for module_id, path in native_dumps.items()
    }
    return context.put_global("programs", programs)


def replay_translate(parameters: Mapping[str, Any], context):
    session = context.require_global("workspace_session")
    translated = dict(context.global_results.get("translations", {}))
    requested_source = parameters.get("source")
    requested_target = parameters.get("target")
    matched = False
    semantics = getattr(context.target_bundle, "translation_semantics", None)
    if semantics is None:
        raise RebuildMissingUpstream(
            "translate replay requires target translation semantics"
        )
    for artifact in session.registry.artifacts.values():
        if (
            artifact.capability != "translated-code"
            or artifact.owner_kind != "variant"
            or artifact.representation != "elf"
            or artifact.abi != 1
        ):
            continue
        variant = session.registry.variants.get(artifact.owner_id)
        if variant is None:
            raise RebuildMissingUpstream(
                f"translated-code artifact {artifact.artifact_id} has no variant"
            )
        source_endpoint = semantics.endpoint_from_properties(
            session.registry, variant.variant_id, "input"
        )
        target_endpoint = semantics.endpoint_from_properties(
            session.registry, variant.variant_id, "output"
        )
        semantics.validate_route(source_endpoint, target_endpoint)
        spec = semantics.production_spec(
            variant.module_id, source_endpoint, target_endpoint, context.stage
        )
        if artifact.artifact_id != spec.artifact_id:
            raise RebuildMissingUpstream(
                "translated-code artifact ID does not match the scene "
                f"production spec for {variant.variant_id}: "
                f"{artifact.artifact_id} != {spec.artifact_id}"
            )
        if (
            requested_source is not None
            and requested_target is not None
            and (
                source_endpoint.canonical,
                target_endpoint.canonical,
            )
            != (
                getattr(requested_source, "canonical", requested_source),
                getattr(requested_target, "canonical", requested_target),
            )
        ):
            continue
        matched = True
        # The manifest artifact path is authoritative for published products.
        library = (context.stage / artifact.path).resolve()
        assembly = context.stage / spec.assembly_path
        translated_dump = context.stage / spec.translated_dump_path
        native_dump = context.stage / "dump" / f"{variant.module_id}.dump"
        for path in (assembly, library, translated_dump, native_dump):
            if not path.is_file():
                raise RebuildMissingUpstream(f"translate replay missing {path}")
        key = TranslationKey(variant.module_id, source_endpoint, target_endpoint)
        # Preserve the manifest's published path if it differs from the
        # scene's default naming (for example after a workspace migration).
        spec = replace(spec, library_path=Path(artifact.path))
        properties = tuple(
            item for item in session.registry.variant_properties.values()
            if item.variant_id == variant.variant_id
        )
        translated[key] = TranslatedModule(
            key=key,
            assembly=assembly,
            library=library,
            native_dump=native_dump,
            translated_dump=translated_dump,
            symbol_namespace=spec.symbol_namespace,
            fingerprint=variant_records_fingerprint(variant, properties),
            spec=spec,
        )
    if requested_source is not None and requested_target is not None and not matched:
        source_text = getattr(requested_source, "canonical", str(requested_source))
        target_text = getattr(requested_target, "canonical", str(requested_target))
        raise RebuildMissingUpstream(
            "translate replay found no published artifact for route "
            f"{source_text} -> {target_text}"
        )
    return context.put_global("translations", translated)


def replay_offset_map(_parameters: Mapping[str, Any], context):
    if not isinstance(context.platform, ElfModuleServices):
        raise RebuildMissingUpstream(
            "offset-map replay requires ElfModuleServices for ELF artifacts"
        )
    modules = {item.module_id: item for item in context.require_global("modules")}
    translator_format = context.toolchain.translator.format
    disassembly_format = context.toolchain.disassembler.parse_format
    translations = context.require_global("translations")
    mappings = {}
    for key, translated in translations.items():
        module = modules[key.module_id]
        spec = getattr(translated, "spec", None)
        if spec is None:
            raise RebuildMissingUpstream(
                "offset-map replay requires a TranslationProductionSpec for "
                f"route ({key.canonical_route[0]} -> {key.canonical_route[1]})"
            )
        labels = parse_asm_source(translated.assembly, translator_format)
        absolute = parse_translated_dump(
            translated.translated_dump, labels, translator_format, disassembly_format
        )
        original_base = context.platform.load_base(module.selected_path)
        translated_base = context.platform.load_base(translated.library)
        mapping = {
            original - original_base: target - translated_base
            for original, target in absolute.items()
            if original >= original_base and target >= translated_base
        }
        assembly = context.stage / spec.offset_map_assembly_path
        document = context.stage / spec.offset_map_document_path
        offset_records = [
            item for item in context.require_global("workspace_session").registry.artifacts.values()
            if item.artifact_id == spec.offset_map_artifact_id
            and item.owner_kind == "variant"
            and item.owner_id == spec.owner_id
            and item.capability == "offset-map"
            and item.representation == "elf"
            and item.abi == 1
        ]
        if len(offset_records) != 1:
            raise RebuildMissingUpstream(
                f"offset-map replay requires one artifact for {spec.owner_id}"
            )
        for path in (assembly, document):
            if not path.is_file():
                raise RebuildMissingUpstream(f"offset-map replay missing {path}")
        # Published artifact paths are authoritative during rebuild.
        library = (context.stage / offset_records[0].path).resolve()
        if not library.is_file():
            raise RebuildMissingUpstream(f"offset-map replay missing {library}")
        mappings[key] = OffsetMapArtifact(
            key=key,
            mapping=mapping,
            assembly=assembly,
            document=document,
            library=library,
            original_base=original_base,
        )
    return context.put_global("offset_maps", mappings)


def replay_build_runtime(_parameters: Mapping[str, Any], context):
    session = context.require_global("workspace_session")
    for artifact in session.registry.artifacts.values():
        if (
            artifact.capability != "runtime"
            or artifact.owner_kind != "workspace"
            or artifact.owner_id != "root"
            or artifact.representation != "elf"
            or artifact.abi != context.runtime_abi
        ):
            continue
        library = (context.stage / artifact.path).resolve()
        if not library.is_file():
            raise RebuildMissingUpstream(f"build-runtime replay missing {library}")
        runtime_artifact = RuntimeArtifact(
            library=library,
            manifest_path=artifact.path,
            target_os=context.target_os,
            target_arch=context.target_arch,
            extension=context.target_arch_extension,
            scene=context.runtime_scene,
            sha256=artifact.sha256,
        )
        return context.put_global("runtime_artifact", runtime_artifact)
    raise RebuildMissingUpstream("no runtime artifact in workspace manifest")


def replay_safety(_parameters: Mapping[str, Any], context):
    if _parameters.get("external_scalar_leaf_contracts"):
        raise RebuildMissingUpstream(
            "external scalar leaf contracts require fresh binding and safety analysis")
    main = next(
        module for module in context.require_global("modules") if module.is_main
    )
    document_path = context.stage / "generated" / f"{main.module_id}.safety.json"
    if not document_path.is_file():
        raise RebuildMissingUpstream(
            f"safety replay missing document: {document_path}"
        )
    try:
        document = json.loads(document_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise RebuildMissingUpstream(
            f"safety replay cannot read document {document_path}: {error}"
        ) from error
    if not isinstance(document, dict):
        raise RebuildMissingUpstream(
            f"safety replay document root must be an object: {document_path}"
        )
    if document.get("format") != "chimera-safety-v1":
        raise RebuildMissingUpstream(
            f"safety replay unsupported format in {document_path}"
        )
    try:
        saved_policy = normalize_unknown_stack_size_policy(
            document.get("unknown_stack_size_policy", CONSERVATIVE)
        )
        requested_policy = normalize_unknown_stack_size_policy(
            _parameters.get("unknown_stack_size_policy", CONSERVATIVE)
        )
    except (TypeError, ValueError) as error:
        raise RebuildMissingUpstream(
            f"safety replay has an invalid unknown stack-size policy: {error}"
        ) from error
    if saved_policy != requested_policy:
        raise RebuildMissingUpstream(
            "safety replay policy does not match the current workflow parameters"
        )
    assumption = document.get("assumption", assumption_for_policy(saved_policy))
    conditional = document.get("conditional", is_conditional_policy(saved_policy))
    if (
        not isinstance(assumption, str)
        or assumption != assumption_for_policy(saved_policy)
        or not isinstance(conditional, bool)
        or conditional != is_conditional_policy(saved_policy)
    ):
        raise RebuildMissingUpstream(
            "safety replay scope description is inconsistent with its policy"
        )
    raw_exclusions = document.get("scope_exclusions", [])
    if not isinstance(raw_exclusions, list):
        raise RebuildMissingUpstream("safety replay scope_exclusions must be an array")
    exclusions = []
    for index, item in enumerate(raw_exclusions):
        if (
            not isinstance(item, dict)
            or item.get("dependency") != "unknown"
            or item.get("disposition") != "assumption"
            or item.get("assumption") != assumption
            or not isinstance(item.get("function_start"), int)
            or isinstance(item.get("function_start"), bool)
            or item.get("function_start", -1) < 0
            or not isinstance(item.get("adjustment"), int)
            or isinstance(item.get("adjustment"), bool)
            or item.get("adjustment", -1) < 0
            or (
                item.get("size_register") is not None
                and not isinstance(item.get("size_register"), str)
            )
            or not isinstance(item.get("gaps", []), list)
            or not all(isinstance(gap, str) for gap in item.get("gaps", []))
        ):
            raise RebuildMissingUpstream(
                f"safety replay scope exclusion {index} is invalid"
            )
        exclusions.append(
            ScopeExclusion(
                source=str(item.get("source", "vlen_stack_frame")),
                function_start=item["function_start"],
                adjustment=item["adjustment"],
                dependency="unknown",
                size_register=item.get("size_register"),
                disposition="assumption",
                assumption=assumption,
                proof=item.get("proof"),
                gaps=tuple(item.get("gaps", ())),
            )
        )
    if saved_policy == CONSERVATIVE and exclusions:
        raise RebuildMissingUpstream(
            "conservative safety replay cannot contain scoped exclusions"
        )
    if document.get("scope_exclusion_count", len(exclusions)) != len(exclusions):
        raise RebuildMissingUpstream("safety replay scope exclusion count is inconsistent")
    entries = document.get("entries")
    if not isinstance(entries, list):
        raise RebuildMissingUpstream(
            f"safety replay document entries must be an array: {document_path}"
        )
    records = {}
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise RebuildMissingUpstream(
                f"safety replay entry {index} must be an object"
            )
        address = entry.get("address")
        if (
            not isinstance(address, int)
            or isinstance(address, bool)
            or address < 0
        ):
            raise RebuildMissingUpstream(
                f"safety replay entry {index} has an invalid address"
            )
        if address in records:
            raise RebuildMissingUpstream(
                f"safety replay has duplicate address {address:#x}"
            )
        safe = entry.get("safe")
        if not isinstance(safe, bool):
            raise RebuildMissingUpstream(
                f"safety replay entry {index} has a non-boolean safe flag"
            )
        reasons = entry.get("unsafe_reasons", [])
        if (
            not isinstance(reasons, list)
            or not all(isinstance(reason, str) for reason in reasons)
        ):
            raise RebuildMissingUpstream(
                f"safety replay entry {index} has invalid unsafe_reasons"
            )
        records[address] = SafetyRecord(
            address,
            safe,
            frozenset(),
            frozenset(),
            tuple(reasons),
        )
    result = SafetyPipelineResult(
        module_id=main.module_id,
        vector_configs=None,
        vector_liveness=None,
        stack_liveness=None,
        safety=SafetyAnalysisResult(
            records=records,
            vector=None,
            stack=None,
            unknown_stack_size_policy=saved_policy,
            assumption=assumption,
            conditional=conditional,
            scope_exclusions=tuple(exclusions),
        ),
        warnings=(),
        summary={
            "unknown_stack_size_policy": saved_policy,
            "assumption": assumption,
            "conditional": conditional,
            "scope_exclusion_count": len(exclusions),
        },
    )
    return context.put_global("safety_analysis", result)


__all__ = [
    "BuildReplayPropertyError",
    "RebuildMissingUpstream",
    "replay_build_runtime",
    "replay_disassemble",
    "replay_offset_map",
    "replay_program_model",
    "replay_safety",
    "replay_translate",
]
