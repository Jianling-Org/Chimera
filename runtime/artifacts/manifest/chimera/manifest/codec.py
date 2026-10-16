"""Deterministic TSV codec for Chimera Workspace Manifest v2.

v2 adds ``delivery`` and ``sha256`` to the module record: a module no longer
implicitly lives inside the Workspace, and its identity is the thing a run has
to match rather than a name it can look up.
"""

from __future__ import annotations

import os
from pathlib import Path
import re
import tempfile

from .model import (
    ArtifactRecord, ModuleRecord, VariantPropertyRecord, VariantRecord,
    WorkspaceManifest,
)


MANIFEST_MAGIC = "# chimera-workspace-manifest-v2"
RUNTIME_ABI_PREFIX = "# runtime_abi="
TARGET_OS_PREFIX = "# target_os="
TARGET_ARCH_PREFIX = "# target_arch="
TARGET_ARCH_EXTENSION_PREFIX = "# target_arch_extension="
RUNTIME_SCENE_PREFIX = "# runtime_scene="


def _parse_positive_u64(value: str, label: str) -> int:
    if not re.fullmatch(r"[1-9][0-9]*", value):
        raise ValueError(f"{label} must be a canonical positive u64")
    parsed = int(value)
    if parsed >= 2**64:
        raise ValueError(f"{label} must be a canonical positive u64")
    return parsed


def _header_value(line: str, prefix: str, label: str) -> str:
    if not line.startswith(prefix) or not line[len(prefix):]:
        raise ValueError(f"manifest {label} header is missing or empty")
    return line[len(prefix):]


def _parse_record(line: str, line_number: int):
    fields = line.split("\t")
    kind = fields[0]
    try:
        if kind == "module" and len(fields) == 7:
            return kind, ModuleRecord(*fields[1:])
        if kind == "variant" and len(fields) == 3:
            return kind, VariantRecord(*fields[1:])
        if kind == "variant-property" and len(fields) == 6:
            return kind, VariantPropertyRecord(*fields[1:])
        if kind == "artifact" and len(fields) == 10:
            consumers = frozenset() if fields[7] == "-" else frozenset(fields[7].split(","))
            if fields[7] != "-" and fields[7] != ",".join(sorted(consumers)):
                raise ValueError("required_by must be a sorted set or '-'")
            return kind, ArtifactRecord(
                fields[1], fields[2], fields[3], fields[4], fields[5],
                _parse_positive_u64(fields[6], "artifact ABI"),
                consumers, fields[8], fields[9],
            )
    except ValueError as error:
        raise ValueError(f"line {line_number}: {error}") from error
    expected = {"module": 7, "variant": 3, "variant-property": 6, "artifact": 10}.get(kind)
    if expected is None:
        raise ValueError(f"line {line_number}: unknown record kind {kind!r}")
    raise ValueError(
        f"line {line_number}: {kind} record expects {expected} fields, got {len(fields)}"
    )


def read_manifest(path: str | Path, *, workspace_root: str | Path | None = None) -> WorkspaceManifest:
    source = Path(path)
    lines = source.read_text(encoding="utf-8").splitlines()
    if len(lines) < 6 or lines[0] != MANIFEST_MAGIC:
        raise ValueError(
            "unsupported Chimera Workspace Manifest; run prepare again to create v2"
        )
    runtime_abi = _parse_positive_u64(
        _header_value(lines[1], RUNTIME_ABI_PREFIX, "runtime ABI"),
        "manifest runtime ABI",
    )
    modules: list[ModuleRecord] = []
    variants: list[VariantRecord] = []
    properties: list[VariantPropertyRecord] = []
    artifacts: list[ArtifactRecord] = []
    destinations = {
        "module": modules, "variant": variants,
        "variant-property": properties, "artifact": artifacts,
    }
    for line_number, line in enumerate(lines[6:], start=7):
        if not line or line.startswith("#"):
            continue
        kind, record = _parse_record(line, line_number)
        destinations[kind].append(record)
    manifest = WorkspaceManifest(
        runtime_abi=runtime_abi,
        target_os=_header_value(lines[2], TARGET_OS_PREFIX, "target OS"),
        target_arch=_header_value(lines[3], TARGET_ARCH_PREFIX, "target architecture"),
        target_arch_extension=_header_value(
            lines[4], TARGET_ARCH_EXTENSION_PREFIX, "target architecture extension"
        ),
        runtime_scene=_header_value(lines[5], RUNTIME_SCENE_PREFIX, "runtime scene"),
        modules=tuple(modules), variants=tuple(variants),
        variant_properties=tuple(properties), artifacts=tuple(artifacts),
    )
    manifest.validate(workspace_root=workspace_root)
    return manifest


def _record_lines(manifest: WorkspaceManifest) -> list[str]:
    lines = [
        "\t".join((
            "module", item.module_id, item.role, item.runtime_name,
            item.selected_kind, item.delivery, item.sha256,
        ))
        for item in sorted(manifest.modules)
    ]
    lines.extend(
        "\t".join(("variant", item.variant_id, item.module_id))
        for item in sorted(manifest.variants)
    )
    lines.extend(
        "\t".join((
            "variant-property", item.variant_id, item.side, item.name,
            item.value_kind, item.value,
        ))
        for item in sorted(
            manifest.variant_properties,
            key=lambda value: (value.variant_id, value.side, value.name),
        )
    )
    lines.extend(
        "\t".join((
            "artifact", item.artifact_id, item.owner_kind, item.owner_id,
            item.capability, item.representation, str(item.abi),
            ",".join(sorted(item.required_by)) if item.required_by else "-",
            item.path, item.sha256,
        ))
        for item in sorted(manifest.artifacts, key=lambda value: value.artifact_id)
    )
    return lines


def write_manifest(manifest: WorkspaceManifest, path: str | Path) -> None:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    workspace_root = destination.parent.parent
    manifest.validate(workspace_root=workspace_root)
    content = "\n".join((
        MANIFEST_MAGIC,
        f"{RUNTIME_ABI_PREFIX}{manifest.runtime_abi}",
        f"{TARGET_OS_PREFIX}{manifest.target_os}",
        f"{TARGET_ARCH_PREFIX}{manifest.target_arch}",
        f"{TARGET_ARCH_EXTENSION_PREFIX}{manifest.target_arch_extension}",
        f"{RUNTIME_SCENE_PREFIX}{manifest.runtime_scene}",
        *_record_lines(manifest),
        "",
    ))
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.", suffix=".tmp", dir=destination.parent
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as output:
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary_name, destination)
    except BaseException:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
        raise
