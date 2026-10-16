"""Patch translated safety points into scene-defined traps inside the DSO image.

Each safe original instruction maps (via the offset-map) to the first
translated instruction of its translation sequence.  This step overwrites
that instruction in the translated DSO with the equal-sized trap encoding
provided by the target scene.  Executing the trap raises the signal selected
by that scene, which the runtime can use for its exit-translation path.

The patch is size-preserving, so the offset-map and disassembly dumps stay
valid.  Each run starts from the validated unpatched translation copy and
applies exactly the traps required by the current Safety result; reducing the
Safety set therefore restores the original instruction bytes before publish.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

from chimera.runtime.manifest import ArtifactRecord

from ..core.contracts import AnalysisContext, ElfModuleServices, TrapPatchServices
from ..core.monitor import local, monitored, returned
from ..core.workspace import sha256_file


def _patch_summary(context: AnalysisContext) -> dict[str, object]:
    patched = context.require_global("patched_safepoints")
    return {
        "variants": len(patched),
        "safepoints": sum(patched.values()),
    }


def _unpatched_copy_valid(stage: Path, spec) -> bool:
    library_path = getattr(spec, "unpatched_library_path", None)
    checksum_path = getattr(spec, "unpatched_library_sha256_path", None)
    if library_path is None or checksum_path is None:
        return False
    library = stage / library_path
    checksum = stage / checksum_path
    if not library.is_file() or not checksum.is_file():
        return False
    try:
        fields = checksum.read_text(encoding="ascii").strip().split()
        expected = fields[0]
        if not re.fullmatch(r"[0-9a-fA-F]{64}", expected):
            return False
        return sha256_file(library).lower() == expected.lower()
    except (OSError, UnicodeError, IndexError, ValueError):
        return False


def check_unpatched_productions(inspection, iter_productions) -> frozenset[str]:
    """Return exact producer identifiers whose original copy is unavailable.

    ``iter_productions`` is supplied by the workflow/target composition root;
    this checker deliberately knows nothing about producer names or parameter
    shapes.  It only validates the production specification's offline copy and
    its SHA-256 sidecar.
    """
    missing: set[str] = set()
    for identifier, spec in iter_productions(inspection):
        if not isinstance(identifier, str):
            raise TypeError("translation production identifier must be a string")
        if not _unpatched_copy_valid(inspection.stage, spec):
            missing.add(identifier)
    return frozenset(missing)


def unpatched_copy_preflight(_parameters, inspection) -> frozenset[str]:
    """Compatibility hook for custom composition roots.

    A target/workflow adapter must expose ``iter_productions`` on the
    inspection object when using this historical hook directly.  Built-in
    registration supplies its own adapter and calls the generic checker.
    """
    iterator = getattr(inspection, "iter_productions", None)
    if not callable(iterator):
        raise TypeError(
            "unpatched_copy_preflight requires a workflow production adapter"
        )
    return check_unpatched_productions(inspection, iterator)


class PatchSafepointsStep:
    name = "patch-safepoints"

    @monitored(
        "offline.patch-safepoints",
        variables=(
            local("safe_rvas", label="safe_points", transform=len),
            returned(label="patched", transform=_patch_summary),
        ),
    )
    def run(self, context: AnalysisContext) -> AnalysisContext:
        if context.stage is None:
            raise RuntimeError("patch-safepoints requires a staging workspace")
        if not isinstance(context.platform, ElfModuleServices):
            raise TypeError(
                "patch-safepoints requires ElfModuleServices for ELF artifacts"
            )
        result = context.require_global("safety_analysis")
        translations = context.require_global("translations")
        offset_maps = context.require_global("offset_maps")
        modules = {
            module.module_id: module
            for module in context.require_global("modules")
        }
        main = modules[result.module_id]
        original_base = context.platform.load_base(main.selected_path)
        safe_rvas = frozenset(
            address - original_base
            for address, record in result.safety.records.items()
            if record.safe and address >= original_base
        )
        session = context.require_global("workspace_session")
        trap_services = getattr(
            context.target_bundle, "trap_patch_services", None
        ) if context.target_bundle is not None else None
        if not isinstance(trap_services, TrapPatchServices):
            raise TypeError(
                "patch-safepoints requires target TrapPatchServices capability"
            )
        patched: dict[object, int] = {}
        for key, offset_map in sorted(offset_maps.items()):
            if key.module_id != result.module_id:
                continue
            translated = translations[key]
            spec = getattr(translated, "spec", None)
            if spec is None:
                raise ValueError(
                    "patch-safepoints requires a TranslationProductionSpec for "
                    f"route ({key.canonical_route[0]} -> {key.canonical_route[1]})"
                )
            if (
                spec.unpatched_library_path is None
                or spec.unpatched_library_sha256_path is None
            ):
                raise ValueError(
                    "patch-safepoints requires an unpatched translation library "
                    f"for {spec.owner_id}"
                )
            unpatched = context.stage / spec.unpatched_library_path
            checksum = context.stage / spec.unpatched_library_sha256_path
            self._validate_unpatched_library(unpatched, checksum)
            rvas = sorted({
                offset_map.mapping[original_rva]
                for original_rva in safe_rvas
                if original_rva in offset_map.mapping
            })
            patched[key] = self._patch_library(
                context,
                translated.library,
                rvas,
                trap_services,
                unpatched_library=unpatched,
            )
            identifier = spec.variant_id
            artifact_id = spec.artifact_id
            session.registry.register_artifact(ArtifactRecord(
                artifact_id=artifact_id,
                owner_kind="variant",
                owner_id=identifier,
                capability="translated-code",
                representation="elf",
                abi=1,
                required_by=frozenset({"runtime"}),
                path=translated.library.relative_to(context.stage).as_posix(),
                sha256=sha256_file(translated.library),
            ))
        return context.put_global("patched_safepoints", patched)

    @staticmethod
    def _patch_library(
        context: AnalysisContext,
        library: Path,
        rvas: list[int],
        trap_services,
        *,
        unpatched_library: Path | None = None,
    ) -> int:
        # Full workflow calls provide a validated private copy.  Retain the
        # optional argument for older direct integrations and unit fixtures.
        source = library if unpatched_library is None else Path(unpatched_library)
        data = bytearray(source.read_bytes())
        base = context.platform.load_base(source)
        segments = context.platform.load_segments(source)
        if not isinstance(trap_services, TrapPatchServices):
            raise TypeError(
                "patch-safepoints requires target TrapPatchServices capability"
            )
        max_bytes = trap_services.max_instruction_bytes
        if (
            isinstance(max_bytes, bool)
            or not isinstance(max_bytes, int)
            or max_bytes <= 0
        ):
            raise ValueError(
                "trap-patch service max_instruction_bytes must be a positive integer"
            )
        for rva in rvas:
            address = base + rva
            offset = context.platform.virtual_to_file_offset(segments, address)
            segment_start = None
            segment_end = None
            for file_offset, virtual_address, file_size in segments:
                if virtual_address <= address < virtual_address + file_size:
                    segment_start = file_offset
                    segment_end = file_offset + file_size
                    break
            if (
                segment_start is None
                or segment_end is None
                or offset < segment_start
                or offset >= segment_end
                or offset >= len(data)
            ):
                raise ValueError(f"safepoint patch offset is outside the image: {offset}")
            available = min(max_bytes, segment_end - offset, len(data) - offset)
            if available <= 0:
                raise ValueError(
                    f"safepoint patch has no bytes available at file offset {offset}"
                )
            slot_width, trap = trap_services.trap_for_instruction(
                bytes(data[offset:offset + available])
            )
            if (
                isinstance(slot_width, bool)
                or not isinstance(slot_width, int)
                or slot_width <= 0
            ):
                raise ValueError(
                    "trap-patch service returned an invalid slot width "
                    f"{slot_width}"
                )
            if slot_width > available:
                raise ValueError(
                    "trap-patch slot is incomplete in the ELF image: "
                    f"width={slot_width}, available={available}"
                )
            try:
                trap = bytes(trap)
            except (TypeError, ValueError) as error:
                raise ValueError(
                    "trap-patch service returned non-byte trap encoding"
                ) from error
            if len(trap) != slot_width:
                raise ValueError(
                    "trap-patch encoding length does not match its slot width: "
                    f"{len(trap)} != {slot_width}"
                )
            if offset + slot_width > len(data) or offset + slot_width > segment_end:
                raise ValueError(
                    "trap-patch slot extends beyond the ELF image segment"
                )
            data[offset:offset + slot_width] = trap
        # Write-then-replace keeps a reopened (hard-linked) staging copy from
        # modifying the published workspace through the shared inode.
        temporary = library.with_name(f".{library.name}.patching")
        temporary.parent.mkdir(parents=True, exist_ok=True)
        temporary.write_bytes(bytes(data))
        os.replace(temporary, library)
        return len(rvas)

    @staticmethod
    def _validate_unpatched_library(library: Path, checksum_path: Path) -> None:
        if not library.is_file():
            raise FileNotFoundError(
                f"unpatched translation library is missing: {library}"
            )
        if not checksum_path.is_file():
            raise FileNotFoundError(
                f"unpatched translation checksum is missing: {checksum_path}"
            )
        try:
            fields = checksum_path.read_text(encoding="ascii").strip().split()
            expected = fields[0]
        except (OSError, UnicodeError, IndexError) as error:
            raise ValueError(
                f"cannot read unpatched translation checksum: {checksum_path}"
            ) from error
        if re.fullmatch(r"[0-9a-fA-F]{64}", expected) is None:
            raise ValueError(
                f"invalid unpatched translation checksum: {checksum_path}"
            )
        actual = sha256_file(library)
        if actual.lower() != expected.lower():
            raise ValueError(
                f"unpatched translation checksum mismatch: {library}"
            )


__all__ = [
    "PatchSafepointsStep", "check_unpatched_productions",
    "unpatched_copy_preflight",
]
