"""Command used by ``make wheel`` to validate and build a release wheel."""

from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile
from typing import Callable

from .release import (
    discover_toolchain_artifacts,
    inspect_artifacts,
    stage_existing_artifacts,
)
def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _retag_wheel_platform(source: Path, platform_tag: str) -> None:
    """Make the archive metadata agree with its platform-specific filename.

    scikit-build-core may emit a pure-Python ``any`` wheel because the Python
    modules themselves are pure.  A release wheel carries native ELF files,
    so both ``WHEEL`` and ``RECORD`` must be rewritten before the archive is
    renamed.  The operation is performed in a sibling temporary archive and
    replaces the source atomically.
    """

    with zipfile.ZipFile(source, "r") as archive:
        infos = archive.infolist()
        payloads = {info.filename: archive.read(info.filename) for info in infos}
    wheel_name = next(
        (name for name in payloads if name.endswith(".dist-info/WHEEL")), None
    )
    record_name = next(
        (name for name in payloads if name.endswith(".dist-info/RECORD")), None
    )
    if wheel_name is None or record_name is None:
        raise RuntimeError(f"wheel is missing WHEEL or RECORD metadata: {source.name}")

    original = payloads[wheel_name].decode("utf-8")
    lines = original.splitlines()
    rewritten: list[str] = []
    tag_seen = False
    purelib_seen = False
    for line in lines:
        if line.startswith("Root-Is-Purelib:"):
            rewritten.append("Root-Is-Purelib: false")
            purelib_seen = True
            continue
        if line.startswith("Tag:"):
            value = line.split(":", 1)[1].strip()
            fields = value.split("-")


            if len(fields) >= 3:
                rewritten.append(f"Tag: {fields[0]}-{fields[1]}-{platform_tag}")
                tag_seen = True
                continue
        rewritten.append(line)
    if not tag_seen:
        rewritten.append(f"Tag: py3-none-{platform_tag}")
    if not purelib_seen:
        rewritten.insert(2, "Root-Is-Purelib: false")
    payloads[wheel_name] = ("\n".join(rewritten) + "\n").encode("utf-8")

    rows: list[list[str]] = []
    for name in payloads:
        if name == record_name:
            continue
        digest = hashlib.sha256(payloads[name]).digest()
        encoded = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
        rows.append([name, f"sha256={encoded}", str(len(payloads[name]))])
    rows.append([record_name, "", ""])
    record_buffer = io.StringIO(newline="")
    csv.writer(record_buffer, lineterminator="\n").writerows(rows)
    payloads[record_name] = record_buffer.getvalue().encode("utf-8")

    temporary_file = tempfile.NamedTemporaryFile(
        prefix=f".{source.name}.", suffix=".tmp", dir=source.parent, delete=False
    )
    temporary = Path(temporary_file.name)
    temporary_file.close()
    try:
        with zipfile.ZipFile(temporary, "w") as archive:
            for info in infos:
                archive.writestr(info, payloads[info.filename])
        os.replace(temporary, source)
    finally:
        temporary.unlink(missing_ok=True)


def _make_package_staging(root: Path) -> Path:
    """Create a clean release payload from the explicit artifact tree.

    ``root`` is a reusable user cache and may contain an old manifest or
    diagnostic files.  Only the toolchain and release configuration are copied
    into this temporary payload, so CMake cannot accidentally package a
    Workspace or intermediate build directory.
    """

    staging = Path(
        tempfile.mkdtemp(prefix=f".{root.name}.wheel-", dir=str(root.parent))
    )
    try:
        # The reusable cache may contain diagnostics, old workspaces, or
        # intermediate toolchain trees alongside the install prefixes.  Copy
        # only the two published prefixes and the release configuration.
        source_toolchain = root / "toolchain"
        _copy_release_toolchain(source_toolchain, staging / "toolchain")
        _copy_release_plugins(source_toolchain, staging / "toolchain")
        source = root / "release-config.json"
        if source.exists() or source.is_symlink():
            shutil.copy2(source, staging / "release-config.json", follow_symlinks=False)
        # CMake's install step preserves source permissions, but a release
        # cache may have been populated by a zip/wheel extractor that dropped
        # executable bits.  Normalize only the files that users execute in
        # this isolated staging tree; the installer repeats the repair after
        # pip extraction for older archives.
        if os.name != "nt":
            staging_root = staging.resolve()
            executable_paths = []
            bin_dir = staging / "toolchain" / "llvm" / "bin"
            if bin_dir.is_dir():
                executable_paths.extend(
                    path for path in bin_dir.iterdir()
                    if path.is_file() or path.is_symlink()
                )
            seen: set[Path] = set()
            for path in executable_paths:
                if not (path.is_file() or path.is_symlink()):
                    continue
                try:
                    resolved = path.resolve(strict=True)
                    resolved.relative_to(staging_root)
                    if resolved in seen:
                        continue
                    seen.add(resolved)
                    resolved.chmod(resolved.stat().st_mode | 0o111)
                except (OSError, RuntimeError, ValueError) as error:
                    raise RuntimeError(
                        f"unable to normalize release executable permissions: {path}"
                    ) from error
        _validate_staged_links(staging)
        return staging
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise


def _regular_tool(path: Path, *, root: Path | None = None) -> Path | None:
    """Resolve a tool entry while keeping the selected source read-only."""

    if not (path.is_file() or path.is_symlink()):

        return None

    try:
        resolved = path.resolve(strict=True)
    except (OSError, RuntimeError):
        return None
    if not resolved.is_file():
        return None
    if root is not None:
        try:
            resolved.relative_to(root.resolve())
        except ValueError as error:
            raise RuntimeError(f"toolchain executable link escapes its LLVM prefix: {path}") from error
    return resolved


def _toolchain_layout(source: Path) -> tuple[dict[str, Path], dict[str, str]]:
    """Return one compiler/lld payload and the aliases restored on install.

    Release caches are intentionally allowed to contain a complete LLVM
    installation.  The wheel only needs the executable compiler and linker,
    their resource directory, and the two Chimera plugins.  Alias entries are
    represented as links so a wheel never stores several 130 MB copies of
    clang.
    """

    bin_dir = source / "llvm" / "bin"
    selected: dict[str, Path] = {}
    for role, candidates in {
        "clang": ("clang-21", "clang"),
        "lld": ("ld.lld", "lld", "lld-21"),
    }.items():
        chosen = None
        for name in candidates:
            chosen = _regular_tool(bin_dir / name, root=bin_dir)
            if chosen is not None:
                selected[role] = chosen
                break
    if not selected:
        return {}, {}
    links: dict[str, str] = {}
    clang_target = selected.get("clang")
    if clang_target is not None:
        target_name = clang_target.name
        for alias in ("clang", "clang++"):
            if alias != target_name:
                links[f"toolchain/llvm/bin/{alias}"] = target_name
    lld_target = selected.get("lld")
    if lld_target is not None:
        target_name = lld_target.name
        for alias in ("ld.lld", "lld"):
            if alias != target_name:
                links[f"toolchain/llvm/bin/{alias}"] = target_name
    return selected, links


def _copy_release_toolchain(source: Path, destination: Path) -> dict[str, str]:
    """Copy the runtime subset of an LLVM installation into wheel staging."""

    selected, links = _toolchain_layout(source)
    if not selected:
        return links
    llvm_source = source / "llvm"
    llvm_destination = destination / "llvm"
    bin_destination = llvm_destination / "bin"
    bin_destination.mkdir(parents=True, exist_ok=True)
    for path in selected.values():
        target = bin_destination / path.name
        if target.exists() or target.is_symlink():
            target.unlink()
        shutil.copy2(path, target, follow_symlinks=True)
    for relative, target_name in links.items():
        link = destination.parent / relative
        link.parent.mkdir(parents=True, exist_ok=True)
        if link.exists() or link.is_symlink():
            link.unlink()
        try:
            link.symlink_to(target_name)
        except OSError:
            # Linux release wheels preserve these links.  Keep packaging
            # usable on development hosts where symlink creation is disabled;
            # installation will recreate them on the supported target host.
            continue

    # Clang discovers builtin headers and target runtimes relative to this
    # directory.  It is the only large LLVM subtree required at runtime.
    resource_source = llvm_source / "lib" / "clang"
    if resource_source.is_dir():
        shutil.copytree(resource_source, llvm_destination / "lib" / "clang", symlinks=True)
    # A dynamically linked plugin/compiler may need LLVM shared objects.  Do
    # not copy static development archives, CMake metadata, or compiler tools.
    lib_source = llvm_source / "lib"
    lib_destination = llvm_destination / "lib"
    if lib_source.is_dir():
        lib_destination.mkdir(parents=True, exist_ok=True)
        candidates = {
            item.name: item
            for item in lib_source.iterdir()
            if item.name != "clang"
            and item.name.startswith(("libLLVM", "libclang", "liblld"))

            and ".so" in item.name
            and (item.is_file() or item.is_symlink())

        }
        # Include plugin files as roots when an ELF inspector is available.
        # If it is not, retaining all LLVM shared objects is the safe fallback
        # for non-Linux development hosts; the supported release host always
        # has readelf or llvm-readelf.
        plugin_roots = [
            source / "plugins" / "lib" / "chimera" / "llvm" / name
            for name in ("ChimeraStackObject.so", "ChimeraVectorGate.so")
        ]
        seeds = [*selected.values(), *(path for path in plugin_roots if path.is_file())]
        readelf = shutil.which("readelf") or shutil.which("llvm-readelf")
        required: set[Path]
        if readelf is None:
            required = set(candidates.values())
        else:
            required = set()
            pending = list(seeds)
            visited: set[Path] = set()
            while pending:
                current = pending.pop()
                try:
                    resolved_current = current.resolve(strict=True)
                except (OSError, RuntimeError) as error:
                    raise RuntimeError(
                        f"unable to resolve toolchain dependency root: {current}"
                    ) from error
                if resolved_current in visited:
                    continue
                visited.add(resolved_current)
                try:
                    with resolved_current.open("rb") as stream:
                        if stream.read(4) != b"\x7fELF":
                            continue
                except OSError as error:
                    raise RuntimeError(
                        f"unable to read toolchain dependency root: {resolved_current}"
                    ) from error
                try:
                    result = subprocess.run(
                        [readelf, "-d", str(resolved_current)],
                        capture_output=True,
                        text=True,
                        check=False,
                    )
                except OSError as error:
                    raise RuntimeError(
                        f"unable to inspect toolchain dependencies ({readelf}): {resolved_current}"
                    ) from error
                if result.returncode:
                    raise RuntimeError(
                        f"unable to inspect toolchain dependencies ({readelf}): {resolved_current}"
                    )
                needed_names = re.findall(
                    r"\(NEEDED\).*?\[([^]]+)\]", getattr(result, "stdout", "") or ""
                )
                for name in needed_names:
                    dependency = candidates.get(name)
                    if dependency is None:
                        # These are normal host-provided dependencies and are
                        # deliberately not copied into a platform wheel.
                        if name.startswith(
                            (
                                "libc", "libm", "libdl", "libpthread", "librt",
                                "libgcc", "libstdc++", "libz", "libzstd", "libssl",
                                "libcrypto", "libunwind", "libtinfo", "libxml2",
                                "libffi", "libedit", "libncurses", "ld-linux",
                                "linux-vdso",
                            )
                        ):
                            continue
                        if name.startswith(("libLLVM", "libclang", "liblld")):
                            raise RuntimeError(
                                "toolchain dependency is not present in the selected LLVM prefix: "
                                f"{name} (needed by {resolved_current})"
                            )
                        continue
                    required.add(dependency)
                    pending.append(dependency)
                    try:
                        target = dependency.resolve(strict=True)
                    except (OSError, RuntimeError) as error:
                        raise RuntimeError(
                            f"unable to resolve toolchain shared library link: {dependency}"
                        ) from error
                    if target != dependency and target.name in candidates:
                        required.add(candidates[target.name])
                        pending.append(candidates[target.name])
        for item in sorted(required, key=lambda path: path.name):
            target = lib_destination / item.name
            if target.exists() or target.is_symlink():
                target.unlink()
            shutil.copy2(item, target, follow_symlinks=False)
    return links


def _copy_release_plugins(source: Path, destination: Path) -> None:
    """Copy only the two plugins loaded by the published RVV workflow."""


    source_dir = source / "plugins" / "lib" / "chimera" / "llvm"
    if not source_dir.is_dir():

        return
    destination_dir = destination / "plugins" / "lib" / "chimera" / "llvm"
    for name in ("ChimeraStackObject.so", "ChimeraVectorGate.so"):
        item = source_dir / name
        if not (item.is_file() or item.is_symlink()):
            continue
        try:
            resolved = item.resolve(strict=True)
            resolved.relative_to(source_dir.resolve())
        except (OSError, RuntimeError, ValueError) as error:
            raise RuntimeError(
                f"release plugin link escapes the managed plugin prefix: {item}"
            ) from error
        target = destination_dir / name
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists() or target.is_symlink():
            target.unlink()
        if item.is_symlink():
            target.symlink_to(os.readlink(item))
            # The resolved target is copied under the same relative path so
            # the link is relocatable inside the wheel payload.
            resolved_target = destination_dir / resolved.relative_to(source_dir.resolve())
            resolved_target.parent.mkdir(parents=True, exist_ok=True)
            if not resolved_target.exists():
                shutil.copy2(resolved, resolved_target, follow_symlinks=True)
        else:
            shutil.copy2(item, target, follow_symlinks=False)


def _validate_staged_links(root: Path) -> None:
    """Ensure every staged symlink is relocatable inside the wheel payload."""

    resolved_root = root.resolve()
    for path in root.rglob("*"):
        if not path.is_symlink():
            continue
        try:
            target = path.resolve(strict=False)
            if not target.exists():
                raise ValueError("dangling symlink")
            target.relative_to(resolved_root)
        except (OSError, RuntimeError, ValueError) as error:
            raise RuntimeError(
                f"release payload contains an unsafe or dangling symlink: {path}"
            ) from error


def _payload_stats(root: Path) -> tuple[int, int]:
    """Return (file count, uncompressed bytes), following only regular files."""

    count = 0
    size = 0

    for path in root.rglob("*"):
        if path.is_file() and not path.is_symlink():
            count += 1
            size += path.stat().st_size

    return count, size


def _validate_wheel_payload(wheel: Path) -> None:
    """Guard the final archive against accidental model/development payloads."""

    forbidden_tools = {"opt", "llc", "llvm-tblgen", "llvm-objdump"}
    with zipfile.ZipFile(wheel) as archive:
        names = archive.namelist()
    violations: list[str] = []
    for name in names:
        normalized = name.replace("\\", "/")
        if normalized.lower().endswith(".gguf"):
            violations.append(name)
        if normalized.startswith("chimera/toolchain_source/"):
            violations.append(name)
        marker = "/release/toolchain/llvm/lib/"
        if marker in normalized:
            relative_lib = normalized.split(marker, 1)[1]
            # Compiler-rt archives under lib/clang/<version>/lib/linux are
            # runtime inputs; only reject top-level LLVM development archives.
            if "/" not in relative_lib and relative_lib.lower().endswith(".a"):
                violations.append(name)
        if "/release/toolchain/llvm/bin/" in normalized:
            basename = Path(normalized).name
            if basename in forbidden_tools or any(
                basename.startswith(f"{tool}-") for tool in forbidden_tools
            ):
                violations.append(name)
    if violations:
        raise RuntimeError(
            "release wheel contains excluded payloads: "
            + ", ".join(sorted(set(violations)))
        )


def _validate_existing_release_inputs(root: Path) -> None:
    """Validate the system payload without reading an application Profile."""

    inspected = inspect_artifacts(root)
    if not inspected.ready:
        details = ", ".join(
            f"{item.component}: {item.path or item.reason}" for item in inspected.missing
        )
        raise RuntimeError(f"missing release artifacts ({details})")


def _collect_toolchain_sources(
    root: Path,
    toolchain_root: Path,
    *,
    input_fn: Callable[[str], str] | None = None,
) -> dict[str, Path]:
    """Discover and interactively select missing LLVM/plugin install trees."""

    if input_fn is None:
        input_fn = input
    root = root.expanduser().resolve()
    toolchain_root = toolchain_root.expanduser().resolve()
    discovered = discover_toolchain_artifacts(toolchain_root)
    sources: dict[str, Path] = {
        name: source
        for name, source in {
            "llvm": discovered.llvm_root,
            "plugins": discovered.plugins_root,
        }.items()
        if source is not None
    }
    if sources:
        stage_existing_artifacts(root, toolchain_sources=sources)

    def missing_kinds() -> tuple[str, ...]:
        inspection = inspect_artifacts(root)
        missing = {item.component for item in inspection.missing}
        kinds: list[str] = []
        if {
            "patched LLVM compiler",
            "patched LLVM C++ compiler",
        } & missing:
            kinds.append("llvm")
        if {"StackObject plugin", "VectorGate plugin"} & missing:
            kinds.append("plugins")
        return tuple(kinds)

    skipped: set[str] = set()
    reported_missing = False
    while (pending := tuple(kind for kind in missing_kinds() if kind not in skipped)):
        # The normal publisher remains non-interactive when stdin is not a
        # terminal; _validate_existing_release_inputs will then reject the incomplete
        # set without creating a wheel.  Tests and embedders may provide an
        # explicit input function and still exercise this flow.
        if input_fn is input and not sys.stdin.isatty():
            break

        if not reported_missing:
            missing = inspect_artifacts(root).missing
            print("Release wheel 缺少以下工具链产物：", file=sys.stderr)
            for item in missing:
                if item.component in {

                    "patched LLVM compiler",
                    "patched LLVM C++ compiler",
                    "StackObject plugin",
                    "VectorGate plugin",
                }:
                    print(
                        f"  - {item.component}: {item.reason} ({item.path})",
                        file=sys.stderr,
                    )
            reported_missing = True
        kind = pending[0]
        if kind == "llvm":
            prompt = "请指定 patched LLVM 安装目录或工具链根目录（留空后续构建）："
        else:
            prompt = "请指定 Chimera 插件安装目录或工具链根目录（留空后续构建）："
        try:
            value = input_fn(prompt).strip()
        except EOFError as error:
            raise RuntimeError("未收到工具链路径选择，wheel 未构建") from error
        if not value:
            skipped.add(kind)
            continue
        candidate = Path(value).expanduser()
        try:
            selection = discover_toolchain_artifacts(candidate)
        except (OSError, RuntimeError) as error:
            print(f"无效的工具链路径：{error}", file=sys.stderr)
            continue
        selected = selection.llvm_root if kind == "llvm" else selection.plugins_root
        # An overall bundle may contain one usable tree while the tree asked
        # for is incomplete.  Keep the usable side instead of discarding it;
        # the next iteration then asks only for the still-missing component.
        available: dict[str, Path] = {}
        if selection.llvm_root is not None:
            available["llvm"] = selection.llvm_root
        if selection.plugins_root is not None:
            available["plugins"] = selection.plugins_root
        if selected is None:
            detail = next(
                (
                    issue
                    for issue in selection.issues
                    if (kind == "llvm" and "LLVM" in issue)
                    or (kind == "plugins" and "plugin" in issue)
                ),
                selection.issues[0] if selection.issues else f"无法找到 {kind} 安装内容",
            )
            print(f"无效的工具链路径：{detail}", file=sys.stderr)
            if available:
                previous_sources = dict(sources)
                try:
                    sources.update(available)
                    stage_existing_artifacts(root, toolchain_sources=available)
                except (OSError, ValueError, RuntimeError) as error:
                    print(f"无法复用工具链路径：{error}", file=sys.stderr)
                    sources.clear()
                    sources.update(previous_sources)
                else:
                    for name, source in available.items():
                        label = "patched LLVM" if name == "llvm" else "Chimera 插件"
                        print(f"复用用户指定的 {label}: {source}")
            continue
        # An overall root can satisfy both prompts at once.  Keep each
        # selected tree independently so a later ELF prompt never recopies it.
        previous_sources = dict(sources)
        sources.update(available)
        try:
            stage_existing_artifacts(root, toolchain_sources={kind: selected, **{
                name: source
                for name, source in sources.items()
                if name != kind and source is not None
            }})
        except (OSError, ValueError, RuntimeError) as error:
            print(f"无法复用工具链路径：{error}", file=sys.stderr)
            sources.clear()
            sources.update(previous_sources)
            continue
        print(
            f"复用用户指定的 {'patched LLVM' if kind == 'llvm' else 'Chimera 插件'}: {selected}"
        )
    return sources


def _build_system_wheel(argv: list[str] | None = None) -> int:
    """Build a Chimera system wheel from already-built release artifacts.

    应用 Profile 和应用交付物属于部署流程；此发布器只验证可复用的工具链
    产物，并让 scikit-build-core 打包 Runtime 及这些系统资源。
    """

    parser = argparse.ArgumentParser(prog="chimera-dev wheel")
    parser.add_argument("--wheel-dir", type=Path, default=Path("dist"))
    parser.add_argument("--artifact-root", type=Path)
    parser.add_argument("--target-os")
    parser.add_argument("--target-arch")
    parser.add_argument("--target-extension")
    parser.add_argument("--scene")
    args = parser.parse_args(argv)

    repository_root = Path(__file__).resolve().parents[2]
    root = (args.artifact_root or Path(os.environ.get(
        "CHIMERA_RELEASE_ARTIFACT_ROOT",
        Path.home() / ".chimera" / "release-artifacts",
    ))).expanduser().resolve()
    toolchain_root = Path(os.environ.get(
        "CHIMERA_TOOLCHAIN_BUILD", Path.home() / ".chimera" / "toolchain_build"
    )).expanduser().resolve()
    try:
        # A previously staged release root is already a valid input.  Only
        # consult the developer toolchain cache when the reusable release
        # payload is incomplete; this keeps wheel publication independent of
        # a local build tree after artifacts have been collected once.
        if not inspect_artifacts(root).ready:
            discovered = discover_toolchain_artifacts(toolchain_root)
            if discovered.issues:
                raise RuntimeError("; ".join(discovered.issues))
            stage_existing_artifacts(
                root,
                toolchain_sources={"llvm": discovered.llvm_root, "plugins": discovered.plugins_root},
            )
        _validate_existing_release_inputs(root)
    except (OSError, ValueError, RuntimeError) as error:
        print(
            f"chimera-dev wheel: release artifacts are missing or invalid: {error}\n"
            "请先运行 chimera-dev toolchain build patched-llvm 和 "
            "chimera-dev toolchain build llvm-plugin",
            file=sys.stderr,
        )
        return 1
    system = (args.target_os or __import__("platform").system()).lower().replace("-", "_")
    arch = (args.target_arch or __import__("platform").machine()).lower().replace("-", "_")
    extension = args.target_extension or "generic"
    scene = args.scene or "generic"
    try:
        from chimera.preprocess.offline.analysis_profile.target import (
            TargetKey, registered_target_catalog,
        )
        registered_target_catalog().select(TargetKey(system, arch, extension, scene))
    except (ImportError, RuntimeError, ValueError) as error:
        print(
            "chimera-dev wheel: unsupported target/scene; use a registered "
            f"target implementation ({error})",
            file=sys.stderr,
        )
        return 1
    config = {
        "schema_version": 1,
        "target_os": system,
        "target_arch": arch,
        "target_arch_extension": extension,
        "runtime_scene": scene,
        "toolchain_files": [relative for relative, _ in inspect_artifacts(root).found],
    }
    root.mkdir(parents=True, exist_ok=True)
    (root / "release-config.json").write_text(
        json.dumps(config, indent=2, sort_keys=True), encoding="utf-8"
    )
    package_root = _make_package_staging(root)
    wheel_dir = args.wheel_dir.expanduser().resolve()
    wheel_dir.mkdir(parents=True, exist_ok=True)
    try:
        existing = {p: p.stat().st_mtime_ns for p in wheel_dir.glob("chimera-*.whl")}
        environment = os.environ.copy()
        environment["CHIMERA_RELEASE_ARTIFACT_ROOT"] = str(package_root)
        command = [
            sys.executable, "-m", "pip", "wheel", ".", "--no-deps",
            "--wheel-dir", str(wheel_dir),
            f"--config-settings=cmake.define.CHIMERA_RELEASE_ARTIFACT_ROOT={package_root}",
            "--config-settings=cmake.define.CHIMERA_INSTALL_EXAMPLES=OFF",
            "--config-settings=cmake.define.CHIMERA_INSTALL_TOOLCHAIN_SOURCE=OFF",
        ]
        result = subprocess.run(command, cwd=repository_root, env=environment, check=False)
        if result.returncode:
            return result.returncode
        wheels = sorted(
            (p for p in wheel_dir.glob("chimera-*.whl")
             if p.is_file() and (p not in existing or p.stat().st_mtime_ns > existing[p])),
            key=lambda p: p.stat().st_mtime_ns,
        )
        if not wheels:
            raise RuntimeError("pip wheel completed without producing a Chimera wheel")
        source = wheels[-1]
        _validate_wheel_payload(source)
        platform_tag = f"{system}_{arch}"
        _retag_wheel_platform(source, platform_tag)
        print(f"chimera-dev wheel: {source}")
        return 0
    except (OSError, RuntimeError, ValueError) as error:
        print(f"chimera-dev wheel: {error}", file=sys.stderr)
        return 1

    finally:
        shutil.rmtree(package_root, ignore_errors=True)


def main(argv: list[str] | None = None) -> int:
    return _build_system_wheel(argv)
if __name__ == "__main__":
    raise SystemExit(main())
