"""Generic value types for Chimera Workspace Manifest v1."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path, PurePosixPath
import re


IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]*$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
VALID_ROLES = frozenset({"main", "dependency"})
VALID_SELECTED_KINDS = frozenset({"original", "scalar"})
#: Where a module's file comes from at run time.  ``package`` means the file
#: travels inside the Workspace; ``target`` means the target machine resolves it
#: from the application's own installation.  It is recorded rather than derived
#: from ``selected_kind``: the two happen to coincide today, but "which build was
#: selected" and "does the file ship" are different questions.
VALID_DELIVERIES = frozenset({"package", "target"})
VALID_OWNER_KINDS = frozenset({"workspace", "module", "variant"})
VALID_PROPERTY_SIDES = frozenset({"input", "output"})
VALID_PROPERTY_KINDS = frozenset({"u64", "i64", "bool", "token"})
MANIFEST_TEXT_CAPACITY = 256
MANIFEST_SHORT_TEXT_CAPACITY = 32

#: Directory inside a Workspace holding the module files that ship with it.
#: It is *not* a copy of the application: the application and its own libraries
#: are resolved on the target machine, which is what keeps their path
#: derivation intact.
PACKAGE_MODULE_DIR = "scalar"


def _require_utf8_capacity(value: str, label: str, capacity: int) -> None:
    if len(value.encode("utf-8")) >= capacity:
        raise ValueError(
            f"{label} must encode to at most {capacity - 1} UTF-8 bytes "
            f"for C char[{capacity}]"
        )


def _require_identifier(
    value: str,
    label: str,
    capacity: int = MANIFEST_TEXT_CAPACITY,
) -> None:
    if not isinstance(value, str) or not IDENTIFIER_RE.fullmatch(value):
        raise ValueError(f"invalid {label}: {value!r}")
    _require_utf8_capacity(value, label, capacity)


def _artifact_path(value: str) -> PurePosixPath:
    if not isinstance(value, str) or not value or any(
        character in value for character in ("\\", "\x00")
    ):
        raise ValueError(f"artifact path must be safe workspace-relative POSIX text: {value!r}")
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or path.as_posix() != value
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise ValueError(f"artifact path must be safe workspace-relative POSIX text: {value!r}")
    return path


def canonical_property_value(kind: str, value: object) -> str:
    if kind == "u64":
        if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value < 2**64:
            raise ValueError("u64 property value is out of range")
        return str(value)
    if kind == "i64":
        if not isinstance(value, int) or isinstance(value, bool) or not -(2**63) <= value < 2**63:
            raise ValueError("i64 property value is out of range")
        return str(value)
    if kind == "bool":
        if not isinstance(value, bool):
            raise ValueError("bool property value must be a boolean")
        return "true" if value else "false"
    if kind == "token":
        _require_identifier(value, "token property value")
        return value
    raise ValueError(f"invalid variant property kind: {kind!r}")


def parse_property_value(kind: str, value: str) -> object:
    if kind == "u64":
        parsed: object = int(value) if re.fullmatch(r"0|[1-9][0-9]*", value) else None
    elif kind == "i64":
        parsed = int(value) if re.fullmatch(r"0|-?[1-9][0-9]*", value) else None
    elif kind == "bool":
        parsed = {"true": True, "false": False}.get(value)
    elif kind == "token":
        parsed = value if IDENTIFIER_RE.fullmatch(value) else None
    else:
        raise ValueError(f"invalid variant property kind: {kind!r}")
    if parsed is None or canonical_property_value(kind, parsed) != value:
        raise ValueError(f"non-canonical {kind} property value: {value!r}")
    return parsed


@dataclass(frozen=True, order=True)
class ModuleRecord:
    module_id: str
    role: str
    runtime_name: str
    selected_kind: str
    #: ``package`` or ``target``; see :data:`VALID_DELIVERIES`.  Only
    #: ``package`` modules have a file inside the Workspace -- and only those
    #: are checked against the filesystem here.
    delivery: str
    #: SHA-256 of the file every artifact in this Workspace was derived from.
    #: Recorded so a run can prove the file it resolved is the file that was
    #: analysed; a basename or a SONAME cannot do that.
    sha256: str

    def validate(self) -> None:
        _require_identifier(self.module_id, "module_id")
        if self.role not in VALID_ROLES:
            raise ValueError(f"invalid module role: {self.role!r}")
        if (
            not isinstance(self.runtime_name, str)
            or not self.runtime_name
            or self.runtime_name in {".", ".."}
            or Path(self.runtime_name).name != self.runtime_name
            or any(character in self.runtime_name for character in "/\\\t\r\n\x00")
        ):
            raise ValueError("runtime_name must be a non-empty basename")
        _require_utf8_capacity(
            self.runtime_name, "module runtime_name", MANIFEST_TEXT_CAPACITY
        )
        if self.selected_kind not in VALID_SELECTED_KINDS:
            raise ValueError(f"invalid selected kind: {self.selected_kind!r}")
        if self.delivery not in VALID_DELIVERIES:
            raise ValueError(f"invalid module delivery: {self.delivery!r}")
        if not isinstance(self.sha256, str) or not SHA256_RE.fullmatch(self.sha256):
            raise ValueError("module SHA-256 must be lowercase hexadecimal")


@dataclass(frozen=True, order=True)
class VariantRecord:
    variant_id: str
    module_id: str

    def validate(self) -> None:
        _require_identifier(self.variant_id, "variant_id")
        _require_identifier(self.module_id, "variant module_id")


@dataclass(frozen=True, order=True)
class VariantPropertyRecord:
    variant_id: str
    side: str
    name: str
    value_kind: str
    value: str

    def validate(self) -> None:
        _require_identifier(self.variant_id, "property variant_id")
        if self.side not in VALID_PROPERTY_SIDES:
            raise ValueError(f"invalid variant property side: {self.side!r}")
        _require_identifier(self.name, "variant property name")
        if self.value_kind not in VALID_PROPERTY_KINDS:
            raise ValueError(f"invalid variant property kind: {self.value_kind!r}")
        if not isinstance(self.value, str) or any(c in self.value for c in "\t\r\n"):
            raise ValueError("variant property value must be one TSV-safe string")
        _require_utf8_capacity(
            self.value, "variant property value", MANIFEST_TEXT_CAPACITY
        )
        parse_property_value(self.value_kind, self.value)


@dataclass(frozen=True, order=True)
class ArtifactRecord:
    artifact_id: str
    owner_kind: str
    owner_id: str
    capability: str
    representation: str
    abi: int
    required_by: frozenset[str]
    path: str
    sha256: str

    def validate(self) -> None:
        _require_identifier(self.artifact_id, "artifact_id")
        if self.owner_kind not in VALID_OWNER_KINDS:
            raise ValueError(f"invalid artifact owner kind: {self.owner_kind!r}")
        _require_identifier(self.owner_id, "artifact owner_id")
        _require_identifier(self.capability, "artifact capability")
        _require_identifier(
            self.representation,
            "artifact representation",
            MANIFEST_SHORT_TEXT_CAPACITY,
        )
        if (
            not isinstance(self.abi, int) or isinstance(self.abi, bool)
            or not 0 < self.abi < 2**64
        ):
            raise ValueError("artifact ABI must be a positive u64")
        if not isinstance(self.required_by, frozenset):
            raise TypeError("artifact required_by must be a frozenset")
        for consumer in self.required_by:
            _require_identifier(consumer, "artifact consumer")
        serialized_consumers = (
            ",".join(sorted(self.required_by)) if self.required_by else "-"
        )
        _require_utf8_capacity(
            serialized_consumers,
            "artifact required_by",
            MANIFEST_TEXT_CAPACITY,
        )
        _artifact_path(self.path)
        _require_utf8_capacity(
            self.path, "artifact path", MANIFEST_TEXT_CAPACITY
        )
        if not isinstance(self.sha256, str) or not SHA256_RE.fullmatch(self.sha256):
            raise ValueError("artifact SHA-256 must be lowercase hexadecimal")


@dataclass(frozen=True)
class WorkspaceManifest:
    runtime_abi: int
    target_os: str
    target_arch: str
    target_arch_extension: str
    runtime_scene: str
    modules: tuple[ModuleRecord, ...]
    variants: tuple[VariantRecord, ...]
    variant_properties: tuple[VariantPropertyRecord, ...]
    artifacts: tuple[ArtifactRecord, ...]

    def properties_for(self, variant_id: str) -> tuple[VariantPropertyRecord, ...]:
        return tuple(
            item for item in self.variant_properties if item.variant_id == variant_id
        )

    def property_value(self, variant_id: str, side: str, name: str) -> object:
        record = self.property_record(variant_id, side, name)
        return parse_property_value(record.value_kind, record.value)

    def property_record(
        self, variant_id: str, side: str, name: str
    ) -> VariantPropertyRecord:
        matches = [
            item for item in self.variant_properties
            if (item.variant_id, item.side, item.name) == (variant_id, side, name)
        ]
        if len(matches) != 1:
            raise ValueError(
                f"variant {variant_id} requires exactly one {side}.{name} property"
            )
        return matches[0]

    def validate(self, *, workspace_root: str | Path | None = None) -> None:
        if (
            not isinstance(self.runtime_abi, int) or isinstance(self.runtime_abi, bool)
            or not 0 < self.runtime_abi < 2**64
        ):
            raise ValueError("runtime ABI must be a positive u64")
        for value, label in (
            (self.target_os, "target_os"),
            (self.target_arch, "target_arch"),
            (self.target_arch_extension, "target_arch_extension"),
        ):
            _require_identifier(value, label, MANIFEST_SHORT_TEXT_CAPACITY)
        _require_identifier(self.runtime_scene, "runtime_scene")

        module_ids: set[str] = set()
        runtime_names: set[str] = set()
        for module in self.modules:
            module.validate()
            if module.module_id in module_ids:
                raise ValueError(f"duplicate module ID: {module.module_id}")
            if module.runtime_name in runtime_names:
                raise ValueError(f"duplicate module runtime_name: {module.runtime_name}")
            if module.role == "main" and module.delivery != "target":
                raise ValueError("the main module is resolved on the target machine")
            module_ids.add(module.module_id)
            runtime_names.add(module.runtime_name)
        if sum(module.role == "main" for module in self.modules) != 1:
            raise ValueError("manifest must describe exactly one main module")

        variant_ids: set[str] = set()
        for variant in self.variants:
            variant.validate()
            if variant.variant_id in variant_ids:
                raise ValueError(f"duplicate variant ID: {variant.variant_id}")
            if variant.module_id not in module_ids:
                raise ValueError(f"variant has unknown module owner: {variant.module_id}")
            variant_ids.add(variant.variant_id)

        property_keys: set[tuple[str, str, str]] = set()
        for item in self.variant_properties:
            item.validate()
            if item.variant_id not in variant_ids:
                raise ValueError(f"property has unknown variant owner: {item.variant_id}")
            key = (item.variant_id, item.side, item.name)
            if key in property_keys:
                raise ValueError(f"duplicate variant property: {key}")
            property_keys.add(key)

        artifact_ids: set[str] = set()
        artifact_paths: set[str] = set()
        # Only package-delivered modules occupy a path inside the Workspace;
        # target-resolved ones live wherever the application installed them.
        module_paths = {
            PurePosixPath(PACKAGE_MODULE_DIR) / module.runtime_name
            for module in self.modules
            if module.delivery == "package"
        }
        root = Path(workspace_root).resolve() if workspace_root is not None else None
        for artifact in self.artifacts:
            artifact.validate()
            if artifact.artifact_id in artifact_ids:
                raise ValueError(f"duplicate artifact ID: {artifact.artifact_id}")
            if artifact.path in artifact_paths:
                raise ValueError(f"duplicate artifact path: {artifact.path}")
            artifact_ids.add(artifact.artifact_id)
            artifact_paths.add(artifact.path)
            if _artifact_path(artifact.path) in module_paths:
                raise ValueError(
                    "artifact path cannot replace a manifest module input: "
                    f"{artifact.path}"
                )
            if artifact.owner_kind == "workspace" and artifact.owner_id != "root":
                raise ValueError("workspace artifact owner must be 'root'")
            if artifact.owner_kind == "module" and artifact.owner_id not in module_ids:
                raise ValueError(f"artifact has unknown module owner: {artifact.owner_id}")
            if artifact.owner_kind == "variant" and artifact.owner_id not in variant_ids:
                raise ValueError(f"artifact has unknown variant owner: {artifact.owner_id}")
            if root is not None:
                relative = _artifact_path(artifact.path)
                candidate = (root / Path(*relative.parts)).resolve()
                if not candidate.is_relative_to(root) or not candidate.is_file():
                    raise ValueError(f"artifact is missing or escapes workspace: {artifact.path}")
                actual = sha256(candidate.read_bytes()).hexdigest()
                if actual != artifact.sha256:
                    raise ValueError(f"artifact SHA-256 mismatch: {artifact.path}")


def variant_records_fingerprint(
    variant: VariantRecord,
    properties: tuple[VariantPropertyRecord, ...],
) -> str:
    lines = [f"variant\t{variant.variant_id}\t{variant.module_id}"]
    for item in sorted(properties, key=lambda x: (x.side, x.name)):
        if item.variant_id != variant.variant_id:
            raise ValueError("fingerprint property belongs to another variant")
        item.validate()
        lines.append(
            "\t".join((
                "variant-property", item.variant_id, item.side, item.name,
                item.value_kind, item.value,
            ))
        )
    return sha256(("\n".join(lines) + "\n").encode("utf-8")).hexdigest()


def variant_fingerprint(manifest: WorkspaceManifest, variant_id: str) -> str:
    variants = [item for item in manifest.variants if item.variant_id == variant_id]
    if len(variants) != 1:
        raise ValueError(f"unknown or duplicate variant ID: {variant_id}")
    return variant_records_fingerprint(
        variants[0], manifest.properties_for(variant_id)
    )
