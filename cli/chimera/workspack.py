"""Portable packaging and installation for prepared Chimera Workspaces.

The package format deliberately keeps the existing Workspace Manifest intact.
Only the source-machine metadata is rewritten during installation; generated
ELF code and mapping artifacts are copied byte-for-byte.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import tempfile
import zipfile

from chimera.preprocess.offline.analysis.core.workspace import (
    parse_workspace_metadata,
)
from chimera.runtime.manifest import PACKAGE_MODULE_DIR

try:
    from elftools.elf.elffile import ELFFile
except ImportError:  # pragma: no cover - dependency is declared by the package
    ELFFile = None


def _manifest_identity(root: Path) -> dict[str, object]:
    try:
        from chimera.runtime.manifest import read_manifest
        manifest = read_manifest(root / "artifacts" / "modules.tsv", workspace_root=root)
    except Exception:
        return {}
    return {
        "target_os": manifest.target_os,
        "target_arch": manifest.target_arch,
        "target_arch_extension": manifest.target_arch_extension,
        "runtime_scene": manifest.runtime_scene,
        "runtime_abi": manifest.runtime_abi,
    }


def _minimal_manifest_for_pack(root: Path) -> tuple[dict[str, object], tuple[str, ...]]:
    """Read the portable header when the source-tree runtime alias is absent.

    The installed package always uses the full Manifest codec.  This small
    fallback keeps the standalone ``PYTHONPATH=cli`` tooling useful for
    packaging simple fixtures without weakening the archive's required target
    identity or artifact path checks.
    """
    path = root / "artifacts" / "modules.tsv"
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as error:
        raise WorkspackError(f"Workspace Manifest is unreadable: {path}") from error
    prefixes = (
        "# runtime_abi=", "# target_os=", "# target_arch=",
        "# target_arch_extension=", "# runtime_scene=",
    )
    if len(lines) < 6 or lines[0] != "# chimera-workspace-manifest-v1":
        raise WorkspackError("Workspace Manifest is invalid: unsupported Manifest magic")
    values: list[str] = []
    for line, prefix in zip(lines[1:6], prefixes):
        if not line.startswith(prefix) or not line[len(prefix):]:
            raise WorkspackError(f"Workspace Manifest is invalid: missing {prefix[2:-1]}")
        values.append(line[len(prefix):])
    try:
        runtime_abi = int(values[0])
    except ValueError as error:
        raise WorkspackError("Workspace Manifest is invalid: runtime ABI is not an integer") from error
    if runtime_abi <= 0:
        raise WorkspackError("Workspace Manifest is invalid: runtime ABI must be positive")
    artifacts: list[str] = []
    for line in lines[6:]:
        if not line or line.startswith("#"):
            continue
        fields = line.split("\t")
        if fields[0] == "artifact":
            if len(fields) != 10:
                raise WorkspackError("Workspace Manifest is invalid: artifact record is malformed")
            relative = fields[8]
            _member_name(relative)
            artifacts.append(relative)
    return {
        "runtime_abi": runtime_abi,
        "target_os": values[1],
        "target_arch": values[2],
        "target_arch_extension": values[3],
        "runtime_scene": values[4],
    }, tuple(artifacts)


WORKSPACK_FORMAT = "chimera-workspack"
WORKSPACK_VERSION = 1
WORKSPACE_EXTENSION = ".workspace"
_PACKAGE_MANIFEST = "workspack.json"
_INSTALL_MARKER = ".workspack-install.json"
# These trees are useful while preparing or debugging a Workspace but are not
# runtime inputs.  Omitting them keeps delivery archives small and avoids
# accidentally shipping build products or offline analysis state.
_NON_RUNTIME_TOP_LEVEL = frozenset({"dump", "log", "generated", "build", "cache", "toolchain"})
_RUNTIME_TOP_LEVEL = frozenset({
    "workspace.json", PACKAGE_MODULE_DIR, "artifacts", "resources", _INSTALL_MARKER
})


class WorkspackError(RuntimeError):
    """A Workspack is malformed, unsafe, or incompatible."""


@dataclass(frozen=True)
class ResourceSpec:
    source: Path
    relative: str


def _configured_workspace_root() -> Path:
    """Resolve the runtime root without requiring an offline Profile."""
    configured = os.environ.get("CHIMERA_WORKSPACE_ROOT")
    if configured:
        # Keep the spelling until install performs its symlink safety check.
        return Path(configured).expanduser()
    try:
        from .user_config import load_user_settings
        return load_user_settings().workspace_root
    except (ImportError, OSError, RuntimeError, ValueError):
        return Path.home() / ".chimera" / "workspaces"


def _reject_symlink_components(path: Path, *, label: str) -> None:
    """Reject a user supplied path that would cross a symbolic link."""
    candidate = path if path.is_absolute() else Path.cwd() / path
    current = Path(candidate.anchor)
    for component in candidate.parts:
        if component == candidate.anchor or component == ".":
            continue
        if component == "..":
            if current.is_symlink():
                raise WorkspackError(f"{label} contains a symlink: {current}")
            current = current.parent
            continue
        current = current / component
        if current.is_symlink():
            raise WorkspackError(f"{label} contains a symlink: {current}")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _member_name(value: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or "\\" in value
        or ":" in value
        or "\x00" in value
    ):
        raise WorkspackError(f"unsafe archive member: {value!r}")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise WorkspackError(f"archive member must be relative: {value!r}")
    normalized = path.as_posix()
    if normalized != value:
        raise WorkspackError(f"archive member is not canonical: {value!r}")
    return normalized


def _workspace_identifier(value: object) -> str:
    if (
        not isinstance(value, str)
        or value in {".", ".."}
        or not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]*", value)
    ):
        raise WorkspackError(f"unsafe Workspace ID: {value!r}")
    return value


def _workspace_id(root: Path) -> str:
    metadata = root / "workspace.json"
    try:
        document = json.loads(metadata.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise WorkspackError(f"Workspace metadata is invalid: {metadata}") from error
    if not isinstance(document, dict):
        raise WorkspackError(f"Workspace metadata must contain an object: {metadata}")
    try:
        values = parse_workspace_metadata(document)
    except ValueError as error:
        raise WorkspackError(f"Workspace metadata is invalid: {error}") from error
    value = values.workspace_id
    if value != root.name:
        raise WorkspackError("Workspace metadata ID does not match its directory")
    _workspace_identifier(value)
    return value


def _iter_files(root: Path, *, top_levels: frozenset[str] | None = None):
    for current, dirs, files in os.walk(root):
        if top_levels is not None and Path(current) == root:
            # Build and analysis trees may contain arbitrary links and
            # scratch files.  They are intentionally omitted from a package,
            # so do not descend into them just to inspect files that will not
            # be delivered.
            dirs[:] = [name for name in dirs if name in top_levels]
            files = [name for name in files if name in top_levels]
        safe_dirs = []
        for name in dirs:
            if name.startswith(".staging-"):
                continue
            directory = Path(current) / name
            if directory.is_symlink():
                raise WorkspackError(f"Workspace contains a symlink directory: {directory.relative_to(root)}")
            safe_dirs.append(name)
        dirs[:] = sorted(safe_dirs)
        for name in sorted(files):
            if name.startswith(".staging-"):
                continue
            path = Path(current) / name
            relative = path.relative_to(root).as_posix()
            _member_name(relative)
            if path.is_symlink():
                raise WorkspackError(f"Workspace contains a symlink: {relative}")
            if not path.is_file():
                raise WorkspackError(f"Workspace member is not a regular file: {relative}")
            yield relative, path


def _parse_resources(resources) -> tuple[ResourceSpec, ...]:
    parsed: list[ResourceSpec] = []
    for item in resources or ():
        if isinstance(item, ResourceSpec):
            value = item
        else:
            try:
                source, relative = item
            except (TypeError, ValueError) as error:
                raise WorkspackError("resource must be (source, relative_path)") from error
            value = ResourceSpec(Path(source).expanduser(), str(relative))
        relative = _member_name(value.relative)
        source = value.source.expanduser()
        if source.is_symlink():
            raise WorkspackError(f"resource is not a regular file: {source}")
        source = source.resolve()
        if not source.is_file():
            raise WorkspackError(f"resource is not a regular file: {source}")
        parsed.append(ResourceSpec(source, relative))
    names = [item.relative for item in parsed]
    if len(names) != len(set(names)):
        raise WorkspackError("duplicate explicit resource path")
    return tuple(parsed)


def _missing_local_dependencies(package_files: dict[str, tuple[Path, str]]) -> list[str]:
    """Return unresolved DT_NEEDED names and reject ambiguous basenames.

    Runtime modules normally live below ``scalar/``; translated/runtime ELF
    artifacts and explicitly supplied plugins may live elsewhere.  Scan every
    package member so an ELF referenced by the Manifest cannot smuggle an
    unresolved dependency past packing.  Non-ELF resources remain opaque.
    """
    if ELFFile is None:
        for name, (path, _member) in package_files.items():
            if path.read_bytes()[:4] == b"\x7fELF":
                raise WorkspackError(
                    "pyelftools is required to inspect ELF dependencies"
                )
        return []
    by_basename: dict[str, list[tuple[str, Path]]] = {}
    for name, (path, _member) in package_files.items():
        by_basename.setdefault(Path(name).name, []).append((name, path))
    missing: set[str] = set()
    for name, (path, _member) in package_files.items():
        try:
            with path.open("rb") as stream:
                elf = ELFFile(stream)
                if not any(segment.header.p_type == "PT_DYNAMIC" for segment in elf.iter_segments()):
                    continue
                for segment in elf.iter_segments():
                    if segment.header.p_type != "PT_DYNAMIC":
                        continue
                    for tag in segment.iter_tags():
                        if tag.entry.d_tag != "DT_NEEDED":
                            continue
                        dependency = str(tag.needed)
                        matches = by_basename.get(dependency, [])
                        if not matches:
                            missing.add(dependency)
                        elif len({
                            _sha256(candidate)
                            for _member_name, candidate in matches
                        }) > 1:
                            locations = ", ".join(item for item, _candidate in matches)
                            raise WorkspackError(
                                f"ELF dependency basename collision for {dependency}: {locations}"
                            )
        except Exception as error:
            # Non-ELF resources are opaque and are validated by the runtime
            # resource shape checks after installation.
            if path.read_bytes()[:4] == b"\x7fELF":
                if isinstance(error, WorkspackError):
                    raise
                raise WorkspackError(f"cannot parse ELF dependencies for {name}") from error
            continue
    return sorted(missing)


def _absolute_rpaths(package_files: dict[str, tuple[Path, str]]) -> list[str]:
    if ELFFile is None:
        return []
    invalid: list[str] = []
    for name, (path, _member) in package_files.items():
        try:
            with path.open("rb") as stream:
                elf = ELFFile(stream)
                dynamic = next((s for s in elf.iter_segments() if s.header.p_type == "PT_DYNAMIC"), None)
                if dynamic is None:
                    continue
                for tag in dynamic.iter_tags():
                    if tag.entry.d_tag in {"DT_RPATH", "DT_RUNPATH"}:
                        value = str(tag.rpath if tag.entry.d_tag == "DT_RPATH" else tag.runpath)
                        parts = [part for part in value.split(":") if part]
                        if any(
                            part.startswith("/")
                            or ("$ORIGIN" not in part and "${ORIGIN}" not in part)
                            for part in parts
                        ):
                            invalid.append(f"{name}: {value}")
        except Exception as error:
            if path.read_bytes()[:4] == b"\x7fELF":
                raise WorkspackError(f"cannot parse ELF RPATH/RUNPATH for {name}") from error
            continue
    return invalid


def _needed_names(path: Path) -> tuple[str, ...] | None:
    """Read DT_NEEDED names, returning ``None`` for a non-ELF payload."""
    if ELFFile is None:
        return ()
    try:
        with path.open("rb") as stream:
            elf = ELFFile(stream)
            for segment in elf.iter_segments():
                if segment.header.p_type != "PT_DYNAMIC":
                    continue
                return tuple(
                    str(tag.needed)
                    for tag in segment.iter_tags()
                    if tag.entry.d_tag == "DT_NEEDED"
                )
    except Exception as error:
        if path.read_bytes()[:4] == b"\x7fELF":
            raise WorkspackError(f"cannot parse ELF dependencies for {path}") from error
        return None
    return ()


def _augment_resource_dependencies(
    package_files: dict[str, tuple[Path, str]],
) -> None:
    """Include resolvable plugin dependencies next to explicit resources.

    Explicit resource paths are often supplied from a small plugin directory.
    When a DT_NEEDED basename is found beside that plugin, carry it into the
    same Workspack resource subtree and continue recursively.  Dependencies
    already present in ``scalar/`` or ``resources/`` are reused; unresolved
    names are left for the common dependency check to report clearly.
    """
    if ELFFile is None:
        return
    known: dict[str, Path] = {}
    for member, (path, _member) in package_files.items():
        if member.startswith((PACKAGE_MODULE_DIR + "/", "resources/")):
            basename = Path(member).name
            prior = known.get(basename)
            if prior is not None and _sha256(prior) != _sha256(path):
                raise WorkspackError(f"dependency basename collision: {prior} and {path}")
            known[basename] = path
    pending = [
        (member, path)
        for member, (path, _member) in package_files.items()
        if member.startswith("resources/")
    ]
    seen: set[tuple[str, str]] = set()
    while pending:
        member, path = pending.pop()
        key = (member, str(path))
        if key in seen:
            continue
        seen.add(key)
        needed = _needed_names(path)
        if not needed:
            continue
        parent = PurePosixPath(member).relative_to("resources").parent
        for dependency in needed:
            if dependency in known:
                continue
            candidate = path.parent / dependency
            if not candidate.is_file() or candidate.is_symlink():
                continue
            destination = (
                f"resources/{parent.as_posix()}/{dependency}"
                if str(parent) != "."
                else f"resources/{dependency}"
            )
            _member_name(destination)
            prior_entry = package_files.get(destination)
            if prior_entry is not None and _sha256(prior_entry[0]) != _sha256(candidate):
                raise WorkspackError(
                    f"dependency basename collision at {destination}: {prior_entry[0]} and {candidate}"
                )
            if prior_entry is None:
                package_files[destination] = (candidate, destination)
                pending.append((destination, candidate))
            known[dependency] = candidate


def pack_workspack(
    workspace: str | Path,
    output: str | Path,
    *,
    resources=(),
) -> Path:
    """Create a deterministic Workspack archive from one published Workspace."""

    destination_input = Path(output).expanduser()
    _reject_symlink_components(destination_input, label="Workspace package output")
    if destination_input.is_symlink():
        raise WorkspackError(
            f"Workspace package output is a symlink: {destination_input}"
        )
    destination = destination_input.resolve()
    if destination.suffix != WORKSPACE_EXTENSION:
        raise WorkspackError(
            f"Workspace package output must use {WORKSPACE_EXTENSION}: {destination}"
        )

    root = Path(workspace).expanduser()
    if not root.is_absolute() and len(root.parts) == 1:
        _workspace_identifier(root.name)
        root = _configured_workspace_root() / root
    _reject_symlink_components(root, label="Workspace path")
    root = root.resolve()
    if not root.is_dir():
        raise WorkspackError(f"Workspace does not exist: {root}")
    workspace_id = _workspace_id(root)
    if destination == root or root in destination.parents:
        raise WorkspackError("Workspack output must be outside the Workspace")
    all_children = list(root.iterdir())
    unexpected = sorted(
        child.name for child in all_children
        if child.name not in _RUNTIME_TOP_LEVEL
        and child.name not in _NON_RUNTIME_TOP_LEVEL
        and not child.name.startswith(".staging-")
    )
    if unexpected:
        raise WorkspackError(
            "Workspace contains unsupported top-level runtime members: "
            + ", ".join(unexpected)
        )
    for managed in (PACKAGE_MODULE_DIR, "artifacts", "resources"):
        candidate = root / managed
        if candidate.is_symlink() or (candidate.exists() and not candidate.is_dir()):
            raise WorkspackError(
                f"Workspace managed member must be a directory: {managed}"
            )
    metadata_member = root / "workspace.json"
    if metadata_member.is_symlink() or (
        metadata_member.exists() and not metadata_member.is_file()
    ):
        raise WorkspackError("Workspace metadata must be a regular file: workspace.json")
    all_files = list(_iter_files(root, top_levels=_RUNTIME_TOP_LEVEL))
    files = [
        (name, path)
        for name, path in all_files
        if name.split("/", 1)[0] in _RUNTIME_TOP_LEVEL
        and name.split("/", 1)[0] != "resources"
    ]
    if not any(name == "artifacts/modules.tsv" for name, _ in files):
        raise WorkspackError("Workspace has no artifacts/modules.tsv Manifest")
    if not (root / PACKAGE_MODULE_DIR).is_dir():
        raise WorkspackError(
            f"Workspace has no {PACKAGE_MODULE_DIR} module directory"
        )
    explicit = _parse_resources(resources)
    existing_resources = {
        name for name, _path in all_files
        if name.startswith("resources/")
    }
    existing_resource_files = {
        name: path for name, path in all_files
        if name.startswith("resources/")
    }
    declared_resources = {f"resources/{item.relative}" for item in explicit}
    undeclared_resources = sorted(existing_resources - declared_resources)
    if undeclared_resources:
        raise WorkspackError(
            "Workspace resources must be declared with --resource: "
            + ", ".join(undeclared_resources)
        )
    package_files: dict[str, tuple[Path, str]] = {
        name: (path, name) for name, path in files if name != _INSTALL_MARKER
    }
    # A valid Manifest is the runtime's authoritative artifact inventory.
    # Verify that every referenced path is present in the archive selection;
    # an invalid Manifest cannot describe a portable runtime package.
    try:
        from chimera.runtime.manifest import read_manifest
    except ModuleNotFoundError as error:
        if error.name not in {"chimera.runtime", "chimera.runtime.manifest"}:
            raise
        manifest = None
        identity, artifact_paths = _minimal_manifest_for_pack(root)
    else:
        try:
            manifest = read_manifest(root / "artifacts" / "modules.tsv", workspace_root=root)
            identity = _manifest_identity(root)
            artifact_paths = tuple(artifact.path for artifact in manifest.artifacts)
        except (OSError, ValueError) as error:
            raise WorkspackError(f"Workspace Manifest is invalid: {error}") from error
    if manifest is not None:
        scalar_root = (root / PACKAGE_MODULE_DIR).resolve()
        for module in manifest.modules:
            module_path = root / PACKAGE_MODULE_DIR / module.runtime_name
            packaged = getattr(module, "delivery", "package") == "package"
            if not packaged:
                if not module_path.is_symlink() and module_path.is_file():
                    raise WorkspackError(
                        "Workspace packages a target-resolved module: "
                        f"{module.runtime_name} is resolved on the target "
                        "machine and must not ship inside the package"
                    )
                continue
            if (
                module_path.is_symlink()
                or not module_path.is_file()
                or module_path.resolve().parent != scalar_root
            ):
                raise WorkspackError(
                    f"Workspace Manifest module is missing or escapes "
                    f"{PACKAGE_MODULE_DIR}/: {module.runtime_name}"
                )
    if not identity:
        raise WorkspackError(
            "Workspace Manifest lacks target compatibility metadata"
        )
    if identity:
        try:
            from chimera.runtime.scene_contracts import registered_runtime_artifact_contracts
            contract = registered_runtime_artifact_contracts().select(
                tuple(identity[field] for field in (
                    "target_os", "target_arch", "target_arch_extension", "runtime_scene",
                ))
            )
        except (ImportError, OSError, RuntimeError, ValueError) as error:
            # The standalone source-tree fallback has no scene catalog; the
            # installed package validates this against the registered catalog.
            if manifest is not None:
                raise WorkspackError(
                    f"Workspace target scene is unsupported: {error}"
                ) from error
        else:
            runtime_abi = manifest.runtime_abi if manifest is not None else identity["runtime_abi"]
            if contract.runtime_abi != runtime_abi:
                raise WorkspackError(
                    "Workspace runtime ABI does not match its target scene: "
                    f"manifest={runtime_abi}, contract={contract.runtime_abi}"
                )
    missing_artifacts = sorted(
        artifact_path for artifact_path in artifact_paths
        if artifact_path not in package_files
    )
    if missing_artifacts:
        raise WorkspackError(
            "Manifest references files omitted from Workspack: "
            + ", ".join(missing_artifacts)
        )
    for item in explicit:
        member = f"resources/{item.relative}"
        _member_name(member)
        if member in package_files:
            raise WorkspackError(f"resource collides with Workspace member: {member}")
        existing = existing_resource_files.get(member)
        if existing is not None:
            # A resource already published in the Workspace must be declared
            # explicitly as well.  Reusing an identical file is safe; silently
            # replacing it with a different source would make a package's
            # declared resource depend on the caller's command line.
            if _sha256(existing) != _sha256(item.source):
                raise WorkspackError(
                    f"resource collides with an existing Workspace resource: {member}"
                )
            package_files[member] = (existing, member)
        else:
            package_files[member] = (item.source, member)
    _augment_resource_dependencies(package_files)
    missing_dependencies = _missing_local_dependencies(package_files)
    if missing_dependencies:
        raise WorkspackError(
            "ELF dependencies are not included in Workspace: "
            + ", ".join(missing_dependencies)
        )
    absolute_rpaths = _absolute_rpaths(package_files)
    if absolute_rpaths:
        raise WorkspackError(
            "ELF contains non-relocatable absolute RPATH/RUNPATH: "
            + ", ".join(absolute_rpaths)
        )

    metadata_path = root / "workspace.json"
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    if not isinstance(metadata, dict):
        raise WorkspackError("Workspace metadata must contain an object")
    if manifest is not None:
        main_modules = [
            module.runtime_name
            for module in manifest.modules
            if module.role == "main"
        ]
        if len(main_modules) == 1 and metadata.get("input_elf_name") != main_modules[0]:
            raise WorkspackError(
                "Workspace metadata input ELF does not match the Manifest main module"
            )
    # The source inode is a local binding and is never part of the document,
    # so installation rewrites only the Workspace ID.
    metadata["workspace_id"] = workspace_id
    metadata_bytes = (json.dumps(metadata, sort_keys=True) + "\n").encode("utf-8")
    package_files["workspace.json"] = (metadata_path, "workspace.json")

    entries = [
        {
            "path": name,
            "sha256": _sha256(path),
            "size": path.stat().st_size,
            "mode": stat.S_IMODE(path.stat().st_mode),
        }
        for name, (path, _member) in sorted(package_files.items())
        if name != "workspace.json"
    ]
    entries.append({
        "path": "workspace.json",
        "sha256": hashlib.sha256(metadata_bytes).hexdigest(),
        "size": len(metadata_bytes),
        "mode": stat.S_IMODE(metadata_path.stat().st_mode),
    })
    manifest = {
        "format": WORKSPACK_FORMAT,
        "version": WORKSPACK_VERSION,
        "workspace_id": workspace_id,
        "files": sorted(entries, key=lambda value: value["path"]),
        "resources": sorted(
            name for name in package_files if name.startswith("resources/")
        ),
    }
    manifest.update(identity)
    manifest_bytes = (json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    destination.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.", suffix=".tmp", dir=str(destination.parent)
    )
    os.close(fd)
    temporary = Path(temporary_name)
    try:
        with zipfile.ZipFile(temporary, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
            info = zipfile.ZipInfo(_PACKAGE_MANIFEST)
            info.date_time = (1980, 1, 1, 0, 0, 0)
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, manifest_bytes)
            for name, (path, _member) in sorted(package_files.items()):
                info = zipfile.ZipInfo(name)
                info.date_time = (1980, 1, 1, 0, 0, 0)
                info.compress_type = zipfile.ZIP_DEFLATED
                mode = next(item["mode"] for item in entries if item["path"] == name)
                info.external_attr = (stat.S_IFREG | mode) << 16
                if name == "workspace.json":
                    archive.writestr(info, metadata_bytes)
                else:
                    archive.writestr(info, path.read_bytes())
        os.replace(temporary, destination)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise
    return destination


def _validate_archive(archive: zipfile.ZipFile) -> tuple[dict, dict[str, bytes]]:
    names = archive.namelist()
    if len(names) != len(set(names)):
        raise WorkspackError("archive contains duplicate members")
    if os.name == "nt":
        folded: dict[str, str] = {}
        for name in names:
            key = name.casefold()
            prior = folded.get(key)
            if prior is not None and prior != name:
                raise WorkspackError(
                    f"archive members collide on a case-insensitive filesystem: {prior}, {name}"
                )
            folded[key] = name
    for name in names:
        _member_name(name)
        info = archive.getinfo(name)
        # ZIP external attributes can encode a symbolic link even when the
        # member name itself is safe.  Workspack installs only regular files.
        mode = (info.external_attr >> 16) & 0o170000
        if mode == 0o120000:
            raise WorkspackError(f"archive member is a symlink: {name}")
        if mode not in (0, stat.S_IFREG):
            raise WorkspackError(f"archive member is not a regular file: {name}")
    if _PACKAGE_MANIFEST not in names:
        raise WorkspackError("archive has no workspack.json")
    try:
        manifest = json.loads(archive.read(_PACKAGE_MANIFEST).decode("utf-8"))
    except (OSError, ValueError, UnicodeDecodeError) as error:
        raise WorkspackError("invalid workspack.json") from error
    if not isinstance(manifest, dict):
        raise WorkspackError("workspack.json must contain an object")
    if (
        manifest.get("format") != WORKSPACK_FORMAT
        or manifest.get("version") != WORKSPACK_VERSION
        or not isinstance(manifest.get("workspace_id"), str)
    ):
        raise WorkspackError("unsupported Workspack format or version")
    _workspace_identifier(manifest["workspace_id"])
    if len(PurePosixPath(manifest["workspace_id"]).parts) != 1:
        raise WorkspackError("Workspace ID must be a single path component")
    target_fields = (
        "target_os", "target_arch", "target_arch_extension",
        "runtime_scene", "runtime_abi",
    )
    present = [field in manifest for field in target_fields]
    if not all(present):
        raise WorkspackError("Workspack target compatibility fields are incomplete")
    if any(not isinstance(manifest[field], str) or not manifest[field] for field in target_fields[:-1]):
        raise WorkspackError("invalid Workspack target compatibility fields")
    if not isinstance(manifest["runtime_abi"], int) or manifest["runtime_abi"] <= 0:
        raise WorkspackError("invalid Workspack runtime ABI")
    try:
        from chimera.runtime.scene_contracts import registered_runtime_artifact_contracts
        contract = registered_runtime_artifact_contracts().select(tuple(manifest[field] for field in target_fields[:-1]))
        if contract.runtime_abi != manifest["runtime_abi"]:
            raise WorkspackError("Workspack runtime ABI does not match its target scene")
    except ModuleNotFoundError as error:
        # The source-tree ``PYTHONPATH=cli`` fallback has no runtime
        # package alias.  Installed packages always include the catalog,
        # so target compatibility is enforced there.
        if error.name not in {"chimera.runtime", "chimera.runtime.scene_contracts"}:
            raise WorkspackError(f"unsupported Workspack target scene: {error}") from error
    except WorkspackError:
        raise
    except Exception as error:
        raise WorkspackError(f"unsupported Workspack target scene: {error}") from error
    entries = manifest.get("files")
    if not isinstance(entries, list):
        raise WorkspackError("Workspack files must be an array")
    expected: dict[str, dict] = {}
    for item in entries:
        if not isinstance(item, dict) or not isinstance(item.get("path"), str):
            raise WorkspackError("invalid Workspack file entry")
        path = _member_name(item["path"])
        if path in expected or path == _PACKAGE_MANIFEST:
            raise WorkspackError(f"invalid or duplicate Workspack file: {path}")
        if (
            not isinstance(item.get("sha256"), str)
            or len(item["sha256"]) != 64
            or any(character not in "0123456789abcdef" for character in item["sha256"])
        ):
            raise WorkspackError(f"invalid Workspack hash: {path}")
        if (
            not isinstance(item.get("size"), int)
            or isinstance(item["size"], bool)
            or item["size"] < 0
        ):
            raise WorkspackError(f"invalid Workspack file size: {path}")
        if (
            not isinstance(item.get("mode"), int)
            or isinstance(item["mode"], bool)
            or not 0 <= item["mode"] <= 0o777
        ):
            raise WorkspackError(f"invalid Workspack file mode: {path}")
        top_level = path.split("/", 1)[0]
        if top_level not in {
            "workspace.json", PACKAGE_MODULE_DIR, "artifacts", "resources"
        }:
            raise WorkspackError(
                f"Workspack contains unsupported runtime member: {path}"
            )
        if top_level == "workspace.json" and path != "workspace.json":
            raise WorkspackError("Workspack workspace.json must be a file")
        if top_level != "workspace.json" and "/" not in path:
            raise WorkspackError(
                f"Workspack runtime member must be below a managed directory: {path}"
            )
        expected[path] = item
    required = {"workspace.json", "artifacts/modules.tsv"}
    if not required.issubset(expected):
        raise WorkspackError("Workspack is missing workspace metadata or Manifest")
    if _INSTALL_MARKER in expected:
        raise WorkspackError("Workspack must not contain an installation marker")
    actual_names = set(names) - {_PACKAGE_MANIFEST}
    if actual_names != set(expected):
        raise WorkspackError("Workspack file list does not match archive members")
    payload = {name: archive.read(name) for name in actual_names}
    for name, data in payload.items():
        item = expected[name]
        if hashlib.sha256(data).hexdigest() != item["sha256"] or len(data) != item.get("size"):
            raise WorkspackError(f"Workspack file integrity check failed: {name}")
    try:
        metadata = json.loads(payload["workspace.json"].decode("utf-8"))
        values = parse_workspace_metadata(metadata)
    except (UnicodeDecodeError, ValueError) as error:
        raise WorkspackError(
            f"Workspack workspace metadata is invalid: {error}"
        ) from error
    input_name = values.input_elf_name
    if (
        values.workspace_id != manifest["workspace_id"]
        or not input_name
        or Path(input_name).name != input_name
        or any(character in input_name for character in ("/", chr(92), chr(0)))
    ):
        raise WorkspackError("Workspack workspace metadata lacks stable identity fields")
    resources = manifest.get("resources", [])
    if not isinstance(resources, list):
        raise WorkspackError("Workspack resources must be an array")
    if any(not isinstance(resource, str) for resource in resources):
        raise WorkspackError("invalid Workspack resource path")
    if len(resources) != len(set(resources)):
        raise WorkspackError("Workspack resources contain duplicates")
    for resource in resources:
        if not resource.startswith("resources/"):
            raise WorkspackError("invalid Workspack resource path")
        _member_name(resource)
        if resource not in payload:
            raise WorkspackError(f"Workspack resource is missing from payload: {resource}")
    payload_resources = {name for name in payload if name.startswith("resources/")}
    if payload_resources != set(resources):
        raise WorkspackError("Workspack contains resources that are not declared")
    return manifest, payload


def install_workspack(
    package: str | Path,
    workspace_root: str | Path | None = None,
    *,
    name: str | None = None,
) -> Path:
    """Safely install a Workspack and return its published Workspace path."""

    source_input = Path(package).expanduser()
    if source_input.suffix != WORKSPACE_EXTENSION:
        raise WorkspackError(
            f"Workspace package input must use {WORKSPACE_EXTENSION}: {source_input}"
        )
    _reject_symlink_components(source_input, label="Workspace package input")
    source = source_input.resolve()
    if not source.is_file():
        raise WorkspackError(f"Workspace package does not exist: {source}")
    root_argument = (
        Path(workspace_root).expanduser()
        if workspace_root is not None
        else _configured_workspace_root()
    )
    _reject_symlink_components(root_argument, label="Workspace root")
    root = root_argument.resolve()
    try:
        root.mkdir(parents=True, exist_ok=True)
    except OSError as error:
        raise WorkspackError(f"Workspace root cannot be created: {root}") from error
    try:
        with zipfile.ZipFile(source) as archive:
            _reject_trailing_archive_data(source, archive)
            manifest, payload = _validate_archive(archive)
    except zipfile.BadZipFile as error:
        raise WorkspackError(f"invalid Workspack archive: {source}") from error
    workspace_id = name or manifest["workspace_id"]
    _workspace_identifier(workspace_id)
    if len(PurePosixPath(workspace_id).parts) != 1:
        raise WorkspackError("Workspace ID must be a single path component")
    destination = root / workspace_id
    if destination.is_symlink():
        raise WorkspackError(f"Workspace destination is a symlink: {destination}")
    package_hash = _sha256(source)
    marker = destination / _INSTALL_MARKER
    if destination.exists():
        if marker.is_file():
            try:
                prior = json.loads(marker.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                prior = {}
            if prior.get("package_sha256") == package_hash:
                try:
                    verify_workspack_installation(destination)
                except WorkspackError as error:
                    raise WorkspackError(
                        f"existing Workspace for this package failed integrity verification: {destination}"
                    ) from error
                return destination
        raise WorkspackError(f"Workspace already exists with a different package: {destination}")

    staging = Path(tempfile.mkdtemp(prefix=f".{workspace_id}.staging-", dir=str(root)))
    try:
        for member, data in payload.items():
            target = staging / Path(*PurePosixPath(member).parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
            mode = next(item["mode"] for item in manifest["files"] if item["path"] == member)
            target.chmod(mode)
        metadata_path = staging / "workspace.json"
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        metadata["workspace_id"] = workspace_id
        metadata_path.write_text(json.dumps(metadata, sort_keys=True) + "\n", encoding="utf-8")
        installed_files = {
            relative: _sha256(path)
            for relative, path in _iter_files(staging)
        }
        # The marker is written last and is deliberately excluded from its
        # own digest map.
        (staging / _INSTALL_MARKER).write_text(
            json.dumps({
                "package_sha256": package_hash,
                "workspace_id": workspace_id,
                "installed_files": installed_files,
            }, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        os.replace(staging, destination)
        try:
            verify_workspack_installation(destination)
        except BaseException:
            # A post-publish integrity failure must not leave a partially
            # installed Workspace available to the runtime.
            shutil.rmtree(destination, ignore_errors=True)
            raise
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    return destination


def _reject_trailing_archive_data(source: Path, archive: zipfile.ZipFile) -> None:
    """Reject bytes appended after the ZIP end record.

    ``zipfile.ZipFile`` intentionally tolerates a self-extracting prefix and
    trailing data.  Workspack is a signed-by-digest delivery artifact, so
    silently ignoring trailing bytes would let a damaged or concatenated file
    pass validation.  Our writer emits a classic EOCD record with no comment;
    retain support for a normal ZIP comment while requiring the record to end
    exactly at EOF.
    """
    data = source.read_bytes()
    marker = b"PK\x05\x06"
    offset = data.rfind(marker)
    if offset < 0 or offset + 22 > len(data):
        raise WorkspackError("Workspack has no valid ZIP end record")
    comment_length = int.from_bytes(data[offset + 20:offset + 22], "little")
    end = offset + 22 + comment_length
    if end != len(data):
        raise WorkspackError("Workspack contains trailing data after ZIP end record")


def verify_workspack_installation(workspace: str | Path) -> None:
    """Validate the post-install file digest record, if this is an install."""
    root = Path(workspace).expanduser().resolve()
    marker = root / _INSTALL_MARKER
    if marker.is_symlink():
        raise WorkspackError(f"installed Workspack marker is a symlink: {marker}")
    if not marker.is_file():
        return
    try:
        document = json.loads(marker.read_text(encoding="utf-8"))
        if not isinstance(document, dict):
            raise ValueError("marker must contain an object")
        if document.get("workspace_id") != root.name:
            raise WorkspackError("installed Workspack marker ID does not match directory")
        if (
            not isinstance(document.get("package_sha256"), str)
            or len(document["package_sha256"]) != 64
            or any(character not in "0123456789abcdef" for character in document["package_sha256"])
        ):
            raise WorkspackError("installed Workspack marker has an invalid package hash")
        files = document["installed_files"]
        if not isinstance(files, dict):
            raise ValueError("installed_files is not an object")
        for relative, expected in files.items():
            _member_name(relative)
            if relative == _INSTALL_MARKER:
                raise WorkspackError("installed file map contains its own marker")
            if (
                not isinstance(expected, str)
                or len(expected) != 64
                or any(character not in "0123456789abcdef" for character in expected)
            ):
                raise WorkspackError(f"installed file map has an invalid hash: {relative}")
            path = root / Path(*PurePosixPath(relative).parts)
            if any(parent.is_symlink() for parent in path.parents if parent != root):
                raise WorkspackError(f"installed Workspack path escapes root: {relative}")
            if not path.is_file() or path.is_symlink() or _sha256(path) != expected:
                raise WorkspackError(f"installed Workspack file integrity check failed: {relative}")
        actual = {
            relative
            for relative, _path in _iter_files(root)
            if relative != _INSTALL_MARKER
        }
        if actual != set(files):
            extra = sorted(actual - set(files))
            missing = sorted(set(files) - actual)
            details = []
            if extra:
                details.append("unexpected=" + ",".join(extra))
            if missing:
                details.append("missing=" + ",".join(missing))
            raise WorkspackError(
                "installed Workspack file set changed" + (": " + "; ".join(details) if details else "")
            )
    except (OSError, ValueError, KeyError, TypeError) as error:
        if isinstance(error, WorkspackError):
            raise
        raise WorkspackError(f"invalid Workspack installation marker: {marker}") from error


def pack_workspace(workspace: str | Path, output: str | Path, *, resources=()) -> Path:
    """Create a public ``.workspace`` package."""
    return pack_workspack(workspace, output, resources=resources)


def install_workspace(
    package: str | Path,
    workspace_root: str | Path | None = None,
    *,
    name: str | None = None,
) -> Path:
    """Install a public ``.workspace`` package."""
    return install_workspack(package, workspace_root, name=name)


# Public spelling for the renamed package interface.  The historical helper
# remains available inside this module because the archive protocol still uses
# the ``workspack`` format identifier.
verify_workspace_installation = verify_workspack_installation


__all__ = [
    "ResourceSpec", "WorkspackError", "WORKSPACK_FORMAT", "WORKSPACK_VERSION",
    "WORKSPACE_EXTENSION", "install_workspack", "pack_workspack",
    "pack_workspace", "install_workspace", "verify_workspack_installation",
    "verify_workspace_installation",
]
