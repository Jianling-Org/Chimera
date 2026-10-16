"""Preflight and staging helpers for platform-specific release wheels."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys
from typing import Callable, Iterable, Mapping

try:
    from .preprocess.offline.config import load_configuration, selected_profile
except ModuleNotFoundError:  # source-tree invocation from Makefile
    from preprocessing.offline.config import load_configuration, selected_profile


@dataclass(frozen=True)
class MissingArtifact:
    component: str
    reason: str
    path: Path | None = None


@dataclass(frozen=True)
class ArtifactInspection:
    ready: bool
    missing: tuple[MissingArtifact, ...]
    found: tuple[tuple[str, Path], ...] = ()


@dataclass(frozen=True)
class ToolchainArtifacts:
    """Usable installation prefixes discovered from one user-supplied path."""

    llvm_root: Path | None
    plugins_root: Path | None
    issues: tuple[str, ...] = ()


_REQUIRED_ARTIFACTS = (
    ("toolchain/llvm/bin/clang", "patched LLVM compiler"),
    ("toolchain/llvm/bin/clang++", "patched LLVM C++ compiler"),
    ("toolchain/plugins/lib/chimera/llvm/ChimeraStackObject.so", "StackObject plugin"),
    ("toolchain/plugins/lib/chimera/llvm/ChimeraVectorGate.so", "VectorGate plugin"),
)


def artifact_requirements() -> tuple[str, ...]:
    return tuple(relative for relative, _ in _REQUIRED_ARTIFACTS)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _usable_binary(path: Path, *, executable: bool = False) -> bool:
    """Return whether a release input is a readable regular file.

    ``Path.is_file`` follows links, which is intentional: installed LLVM
    prefixes commonly expose ``clang -> clang-21``.  Executability is checked
    on POSIX hosts, while Windows uses the normal executable association.
    """

    if not path.is_file():
        return False
    try:
        with path.open("rb") as stream:
            stream.read(1)
    except OSError:
        return False
    return not executable or os.name == "nt" or os.access(path, os.X_OK)


def discover_toolchain_artifacts(path: Path) -> ToolchainArtifacts:
    """Discover LLVM and Chimera plugin prefixes from an install or bundle root.

    A bundle root contains ``llvm/`` and/or ``plugins/``.  An individual
    install prefix contains either ``bin/clang`` plus ``bin/clang++`` or
    ``lib/chimera/llvm/`` with one or both Chimera plugins.  The returned paths are
    read-only sources; callers decide where to copy the selected trees.
    """

    candidate = path.expanduser().resolve()
    if not candidate.is_dir():
        return ToolchainArtifacts(
            None,
            None,
            (f"toolchain path is not a directory: {candidate}",),
        )

    # Accept both a toolchain root and a release root containing
    # ``toolchain/{llvm,plugins}``; the latter is useful when reusing a saved
    # release directory without making the user locate its child first.
    bases = [candidate]
    if (candidate / "toolchain").is_dir():
        bases.insert(0, candidate / "toolchain")

    llvm_root: Path | None = None
    for base in bases:
        for root in (base / "llvm", base):
            if root.is_dir() and all(
                _usable_binary(root / "bin" / name, executable=True)
                for name in ("clang", "clang++")
            ):
                llvm_root = root.resolve()
                break
        if llvm_root is not None:
            break

    plugins_root: Path | None = None
    for base in bases:
        for root in (base / "plugins", base):
            plugin_dir = root / "lib" / "chimera" / "llvm"
            if root.is_dir() and any(
                _usable_binary(plugin_dir / name)
                for name in ("ChimeraStackObject.so", "ChimeraVectorGate.so")
            ):
                plugins_root = root.resolve()
                break
        if plugins_root is not None:
            break

    issues: list[str] = []
    if llvm_root is None:
        issues.append(
            f"LLVM installation missing executable bin/clang and bin/clang++: {candidate}"
        )
    if plugins_root is None:
        issues.append(
            "plugin installation has no usable file under "
            "lib/chimera/llvm/ (expected ChimeraStackObject.so or ChimeraVectorGate.so): "
            f"{candidate}"
        )
    return ToolchainArtifacts(llvm_root, plugins_root, tuple(issues))


def _copy_managed_tree(
    source: Path, destination: Path, *, merge_existing: bool = False
) -> None:
    """Copy one selected install tree without deleting its source."""

    source = source.expanduser().resolve()
    # ``resolve`` would follow a pre-existing destination symlink and could
    # make a staging operation write outside the managed release tree.  Keep
    # the final destination lexical and reject such a link explicitly.
    destination = Path(os.path.abspath(destination.expanduser()))
    if not source.is_dir():
        raise ValueError(f"selected toolchain prefix is not a directory: {source}")
    if destination.is_symlink():
        raise ValueError(f"release destination is a symlink: {destination}")
    if source == destination.resolve(strict=False):
        return
    try:
        source.relative_to(destination)
        destination_overlap = True
    except ValueError:
        destination_overlap = False
    try:
        destination.resolve(strict=False).relative_to(source)
        source_overlap = True
    except ValueError:
        source_overlap = False
    if destination_overlap or source_overlap:
        raise ValueError(
            f"selected toolchain prefix overlaps release destination: {source} -> {destination}"
        )

    temporary = destination.parent / f".{destination.name}.chimera-{os.getpid()}"
    backup = destination.parent / f".{destination.name}.chimera-{os.getpid()}.old"
    if temporary.exists() or temporary.is_symlink():
        if temporary.is_dir() and not temporary.is_symlink():
            shutil.rmtree(temporary)
        else:
            temporary.unlink()
    if backup.exists() or backup.is_symlink():
        if backup.is_dir() and not backup.is_symlink():
            shutil.rmtree(backup)
        else:
            backup.unlink()
    committed = False
    try:
        if merge_existing and destination.is_dir() and not destination.is_symlink():
            shutil.copytree(destination, temporary, symlinks=True)
            shutil.copytree(source, temporary, symlinks=True, dirs_exist_ok=True)
        else:
            shutil.copytree(source, temporary, symlinks=True)
        # Do not package links that escape the selected install prefix.  This
        # also catches broken links before replacing an existing good tree.
        for link in temporary.rglob("*"):
            if not link.is_symlink():
                continue
            target = link.resolve(strict=False)
            if not target.exists():
                raise ValueError(
                    f"selected toolchain contains an external or dangling link: {link}"
                )
            try:
                target.relative_to(temporary.resolve())
            except ValueError as error:
                raise ValueError(
                    f"selected toolchain contains an external or dangling link: {link}"
                ) from error
        if destination.exists() or destination.is_symlink():
            os.replace(destination, backup)
        try:
            os.replace(temporary, destination)
        except BaseException:
            if backup.exists() or backup.is_symlink():
                # Keep the previous tree if replacing the staged copy fails.
                # If restoration itself fails, leave the backup in place so a
                # later explicit cleanup can recover it; never delete the only
                # known-good cache from this error path.
                try:
                    os.replace(backup, destination)
                except OSError:
                    pass
            raise
        committed = True
    finally:
        if temporary.exists() or temporary.is_symlink():
            if temporary.is_dir() and not temporary.is_symlink():
                shutil.rmtree(temporary, ignore_errors=True)
            else:
                temporary.unlink(missing_ok=True)
        if committed and (backup.exists() or backup.is_symlink()):
            if backup.is_dir() and not backup.is_symlink():
                shutil.rmtree(backup, ignore_errors=True)
            else:
                backup.unlink(missing_ok=True)


def _validate_internal_toolchain_links(root: Path) -> None:
    """Reject broken or external links in the staged toolchain prefixes."""

    if not root.exists():
        return
    resolved_root = root.resolve()
    for link in root.rglob("*"):
        if not link.is_symlink():
            continue
        target = link.resolve(strict=False)
        if not target.exists():
            raise ValueError(
                f"staged toolchain contains an external or dangling link: {link}"
            )
        try:
            target.relative_to(resolved_root)
        except ValueError as error:
            raise ValueError(
                f"staged toolchain contains an external or dangling link: {link}"
            ) from error


def _release_elf_dependency_issue(path: Path) -> str | None:
    """Return a reason when an ELF still needs a build-tree llama library."""

    try:
        with path.open("rb") as stream:
            if stream.read(4) != b"\x7fELF":
                return None
    except OSError:
        return None
    readelf = shutil.which("readelf") or shutil.which("llvm-readelf")
    if readelf is None:
        return None
    try:
        result = subprocess.run(
            [readelf, "-d", str(path)], capture_output=True, text=True, check=False
        )
    except OSError as error:
        return f"unable to inspect ELF dependencies ({readelf}): {error}"
    if result.returncode:
        return f"unable to inspect ELF dependencies ({readelf})"
    needed = re.findall(
        r"\(NEEDED\).*?\[([^]]+)\]", getattr(result, "stdout", "") or ""
    )
    forbidden = sorted({name for name in needed if name.startswith(("libllama", "libggml"))})
    if forbidden:
        return "depends on build-tree libraries: " + ", ".join(forbidden)
    return None


def inspect_artifacts(root: Path, *, profile: Path | None = None) -> ArtifactInspection:
    """Inspect the explicit release files without requiring a release manifest.

    A release manifest is an optional provenance record, never a prerequisite
    for reusing an already-installed compiler or ELF.  Packaging receives the
    concrete files selected by the caller and creates its own metadata.
    """

    root = root.expanduser().resolve()
    missing: list[MissingArtifact] = []
    found: list[tuple[str, Path]] = []
    for relative, component in _REQUIRED_ARTIFACTS:
        path = root / relative
        is_compiler = relative.endswith("/clang") or relative.endswith("/clang++")
        if not _usable_binary(path, executable=is_compiler):
            missing.append(MissingArtifact(component, "file is missing", path))
            continue
        if relative.startswith("examples/"):
            dependency_issue = _release_elf_dependency_issue(path)
            if dependency_issue:
                missing.append(MissingArtifact(component, dependency_issue, path))
                continue
        found.append((relative, path))
    return ArtifactInspection(not missing, tuple(missing), tuple(found))


def profile_build_tag(profile: Path) -> str:
    configuration = load_configuration(selected_profile(profile))
    p = configuration.profile
    safe = re.sub(r"[^A-Za-z0-9_]+", "_", p.name).strip("_") or "profile"
    digest = hashlib.sha256(
        json.dumps(
            {
                "os": p.target_os,
                "arch": p.target_arch,
                "extension": p.target_arch_extension,
                "scene": p.runtime_scene,
                "abi": p.runtime_abi,
                "workflow": [
                    {"step": step.step, "parameters": dict(step.parameters)}
                    for step in p.workflow.steps
                ],
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()[:12]
    # Wheel build tags must begin with a digit according to PEP 427.
    scene = re.sub(r"[^A-Za-z0-9_]+", "_", p.runtime_scene).strip("_") or "scene"
    return f"1{p.target_os}_{p.target_arch}_{p.target_arch_extension}_{scene}_{safe}_{digest}"


def write_manifest(root: Path, *, profile: Path, metadata: dict[str, object] | None = None) -> Path:
    root = root.expanduser().resolve()
    root.mkdir(parents=True, exist_ok=True)
    files = {
        str(path.relative_to(root)).replace(os.sep, "/"): _sha256(path)
        for path in root.rglob("*")
        if path.is_file() and path.name != "manifest.json"
    }
    payload = {
        "schema_version": 1,
        "profile": profile_build_tag(profile),
        "profile_build_tag": profile_build_tag(profile),
        "files": files,
        **(metadata or {}),
    }
    destination = root / "manifest.json"
    temporary = destination.with_suffix(".json.tmp")
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    os.replace(temporary, destination)
    return destination


def release_artifact_root() -> Path:
    return Path(os.environ.get("CHIMERA_RELEASE_ARTIFACT_ROOT", Path.home() / ".chimera" / "release-artifacts"))


def discover_example_artifacts(
    *,
    roots: Iterable[Path],
    source_root: Path | None = None,
    profile: Path | None = None,
) -> dict[str, Path]:
    """Find explicit system/remediated llama.cpp outputs.

    The ordered candidates cover the user delivery tree, its prebuilt export,
    and ordinary source build directories.  Only exact paths are considered;
    arbitrary ``build*`` directories are never swept into a release.
    """

    candidates: dict[str, list[Path]] = {"system": [], "remediated": []}
    for raw_root in roots:
        root = raw_root.expanduser().resolve()
        # A source checkout passed as a root keeps CMake trees below its
        # nested ``llama.cpp`` directory. Include that exact directory too;
        # do not sweep arbitrary build directories.
        search_roots = [root]
        nested_checkout = root / "llama.cpp"
        if nested_checkout.is_dir():
            search_roots.append(nested_checkout)
        for search_root in search_roots:
            for kind in candidates:
                build_name = "build-vanilla" if kind == "system" else "build-remediated"
                paths = [
                    search_root / "prebuilt" / kind / "llama-perplexity",
                    search_root / kind / "llama-perplexity",
                    search_root / build_name / "bin" / "llama-perplexity",
                ]
                # ``build_llamacpp`` publishes the selected final face under
                # ``main/``.  That location is a managed delivery output,
                # and is therefore a known remediated candidate even though
                # it is not a CMake build tree.  A system baseline remains
                # explicit under ``prebuilt/system`` so a final face is never
                # silently treated as both roles.
                if kind == "remediated":
                    paths.append(search_root / "main" / "llama-perplexity")
                candidates[kind].extend(paths)
    if source_root is not None:
        source = source_root.expanduser().resolve()
        for kind in candidates:
            candidates[kind].append(source / f"build-{kind}" / "bin" / "llama-perplexity")
        candidates["system"].append(source / "build-vanilla" / "bin" / "llama-perplexity")
        candidates["remediated"].append(source / "build-remediated" / "bin" / "llama-perplexity")
    result: dict[str, Path] = {}
    for kind, paths in candidates.items():
        for path in paths:
            if not _usable_binary(path):
                continue
            if profile is not None:
                try:
                    validate_elf(path, profile=profile)
                except (OSError, ValueError):
                    continue
            result[kind] = path
            break
    return result


def validate_elf(path: Path, *, profile: Path | None = None) -> None:
    """Validate an explicitly selected ELF and its target machine."""

    path = path.expanduser().resolve()
    if not _usable_binary(path):
        raise ValueError(f"binary is missing or unreadable: {path}")
    with path.open("rb") as stream:
        header = stream.read(20)
    if header[:4] != b"\x7fELF":
        raise ValueError(f"input is not an ELF file: {path}")
    if len(header) < 20 or header[4] not in (1, 2) or header[5] not in (1, 2):
        raise ValueError(f"input has an invalid ELF header: {path}")
    endian = "<" if header[5] == 1 else ">"
    machine = struct.unpack(endian + "H", header[18:20])[0]
    expected = None
    if profile is not None:
        configuration = load_configuration(selected_profile(profile))
        if configuration.profile.target_arch in {"riscv64", "riscv"}:
            expected = 243
    if expected is not None and machine != expected:
        raise ValueError(
            f"input ELF architecture mismatch: expected RISC-V (machine {expected}), got {machine}: {path}"
        )


def stage_existing_artifacts(root: Path, *, toolchain_root: Path | None = None,
                             example_root: Path | None = None,
                             example_paths: dict[str, Path] | None = None,
                             toolchain_sources: Mapping[str, Path] | None = None) -> Path:
    """Collect already-built user artifacts into the deterministic release tree."""

    root = root.expanduser().resolve()
    managed_toolchain_dir = root / "toolchain"
    if managed_toolchain_dir.is_symlink():
        raise ValueError(
            f"release toolchain destination is a symlink: {managed_toolchain_dir}"
        )
    if toolchain_sources is None:
        toolchain_root = Path(
            toolchain_root
            or os.environ.get("CHIMERA_TOOLCHAIN_BUILD", Path.home() / ".chimera" / "toolchain_build")
        ).expanduser().resolve()
        discovered = discover_toolchain_artifacts(toolchain_root)
        toolchain_sources = {
            name: source
            for name, source in {
                "llvm": discovered.llvm_root,
                "plugins": discovered.plugins_root,
            }.items()
            if source is not None
        }
    for name, source in toolchain_sources.items():
        if name not in {"llvm", "plugins"}:
            raise ValueError(f"unknown toolchain source: {name}")
        destination = root / "toolchain" / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        _copy_managed_tree(
            Path(source), destination, merge_existing=name == "plugins"
        )
    if toolchain_sources:
        _validate_internal_toolchain_links(root / "toolchain")
    if example_paths is None and example_root is not None:
        example_paths = discover_example_artifacts(roots=(example_root,))
    if example_paths:
        destination = root / "examples" / "llamacpp"
        for kind, source_file in example_paths.items():
            target = destination / kind / "llama-perplexity"
            target.parent.mkdir(parents=True, exist_ok=True)
            source = Path(source_file).expanduser().resolve()
            if source != target.resolve(strict=False):
                shutil.copy2(source, target)
    return root


def ensure_release_artifacts(
    profile: Path | None = None,
    *,
    root: Path | None = None,
    builder: Callable[..., int] | None = None,
    input_fn: Callable[[str], str] = input,
) -> Path:
    profile = selected_profile(profile)
    root = (root or release_artifact_root()).expanduser().resolve()
    inspection = inspect_artifacts(root, profile=profile)
    if not inspection.ready:
        print("Release wheel 缺少以下必需二进制：", file=sys.stderr)
        for item in inspection.missing:
            location = f" ({item.path})" if item.path is not None else ""
            print(
                f"  - {item.component}: {item.reason}{location}",
                file=sys.stderr,
            )
        if not sys.stdin.isatty() and input_fn is input:
            raise RuntimeError("release artifacts are incomplete; refusing to build in non-interactive mode")
        try:
            answer = input_fn("是否构建这些组件？[y/N] ")
        except EOFError as error:
            raise RuntimeError("no confirmation received; wheel was not built") from error
        if answer.strip().lower() not in {"y", "yes"}:
            raise RuntimeError("release artifact build declined; wheel was not built")
        # A release builder receives the exact missing set.  Keep the
        # zero-argument callback form for callers written against the old
        # helper, but never fall back to the full example workflow here: that
        # workflow creates workspaces and runs prepare/runtime rebuilds.
        if builder is None:
            raise RuntimeError(
                "release artifacts are incomplete; no component builder was supplied"
            )
        try:
            import inspect

            parameters = inspect.signature(builder).parameters
            accepts_missing = any(
                parameter.kind in (parameter.POSITIONAL_ONLY,
                                   parameter.POSITIONAL_OR_KEYWORD,
                                   parameter.VAR_POSITIONAL)
                for parameter in parameters.values()
            )
        except (TypeError, ValueError):
            accepts_missing = False
        status = (
            builder(tuple(item.component for item in inspection.missing))
            if accepts_missing
            else builder()
        )
        if status != 0:
            raise RuntimeError(f"release artifact build failed with exit code {status}")
        inspection = inspect_artifacts(root, profile=profile)
        if not inspection.ready:
            raise RuntimeError("build completed but release artifacts are still incomplete")
    return root


__all__ = [
    "ArtifactInspection",
    "MissingArtifact",
    "ToolchainArtifacts",
    "artifact_requirements",
    "discover_example_artifacts",
    "discover_toolchain_artifacts",
    "ensure_release_artifacts",
    "inspect_artifacts",
    "profile_build_tag",
    "release_artifact_root",
    "stage_existing_artifacts",
    "validate_elf",
    "write_manifest",
]
