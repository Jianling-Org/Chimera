"""First-run installation of resources shipped inside a release wheel."""

from __future__ import annotations

import importlib.resources
import filecmp
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import time
from types import SimpleNamespace
import urllib.request

from . import __version__
from .example_capabilities import detect_host_capabilities, profile_compatibility
from .model import (
    MODEL_FILENAME,
    MODEL_LICENSE,
    MODEL_REPOSITORY,
    MODEL_REVISION,
    MODEL_SIZE,
    MODEL_SHA256,
    MODEL_URL,
)


def _model_cache_path() -> Path:
    return Path.home() / ".chimera" / "models" / MODEL_SHA256 / MODEL_FILENAME


def _model_is_valid(path: Path) -> bool:
    try:
        if path.is_symlink():
            return False
        if path.stat().st_size != MODEL_SIZE:
            return False
        with path.open("rb") as stream:
            if stream.read(4) != b"GGUF":
                return False
            digest = hashlib.sha256()
            stream.seek(0)
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest() == MODEL_SHA256
    except (OSError, ValueError):
        return False


def _download_model() -> Path:
    """Download the pinned model atomically, preserving any old cache."""

    destination = _model_cache_path()
    if _model_is_valid(destination):
        return destination
    destination.parent.mkdir(parents=True, exist_ok=True)
    lock = _acquire_install_lock(destination.parents[1] / ".download.lock")
    temporary: Path | None = None
    try:
        if _model_is_valid(destination):
            return destination
        with urllib.request.urlopen(MODEL_URL, timeout=60) as response:
            with tempfile.NamedTemporaryFile(
                mode="wb",
                prefix=f".{MODEL_FILENAME}.",
                suffix=".tmp",
                dir=str(destination.parent),
                delete=False,
            ) as stream:
                temporary = Path(stream.name)
                digest = hashlib.sha256()
                size = 0
                first = b""
                while True:
                    chunk = response.read(1024 * 1024)
                    if not chunk:
                        break
                    if not first:
                        first = chunk[:4]
                    size += len(chunk)
                    if size > MODEL_SIZE:
                        raise RuntimeError(
                            f"model download is larger than expected ({size} > {MODEL_SIZE} bytes)"
                        )
                    stream.write(chunk)
                    digest.update(chunk)
                stream.flush()
                os.fsync(stream.fileno())
        if size != MODEL_SIZE:
            raise RuntimeError(
                f"model download size mismatch: expected {MODEL_SIZE}, got {size}"
            )
        if first != b"GGUF":
            raise RuntimeError("model download is not a GGUF file")
        if digest.hexdigest() != MODEL_SHA256:
            raise RuntimeError("model download SHA-256 mismatch")
        os.replace(temporary, destination)
        temporary = None
        return destination
    except Exception as error:
        if isinstance(error, RuntimeError):
            raise
        raise RuntimeError(f"model download failed: {error}") from error
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
        lock.close()


def _install_local_model(source: Path) -> Path:
    """Copy and validate a user-provided model into the managed cache."""

    source = source.expanduser()
    try:
        if not source.is_file():
            raise RuntimeError(f"local model path is not a readable file: {source}")
        source_resolved = source.resolve(strict=True)
    except (OSError, RuntimeError, ValueError) as error:
        if isinstance(error, RuntimeError) and str(error).startswith("local model path"):
            raise
        raise RuntimeError(f"local model path is not readable: {source}: {error}") from error

    destination = _model_cache_path()
    destination.parent.mkdir(parents=True, exist_ok=True)
    lock = _acquire_install_lock(destination.parents[1] / ".download.lock")
    temporary: Path | None = None
    try:
        if _model_is_valid(destination):
            return destination
        try:
            if source_resolved == destination.resolve(strict=False):
                raise RuntimeError("local model path is the managed cache path but is invalid")
        except OSError:
            pass
        with source_resolved.open("rb") as input_stream:
            with tempfile.NamedTemporaryFile(
                mode="wb",
                prefix=f".{MODEL_FILENAME}.",
                suffix=".tmp",
                dir=str(destination.parent),
                delete=False,
            ) as output_stream:
                temporary = Path(output_stream.name)
                digest = hashlib.sha256()
                size = 0
                first = b""
                while True:
                    chunk = input_stream.read(1024 * 1024)
                    if not chunk:
                        break
                    if not first:
                        first = chunk[:4]
                    size += len(chunk)
                    if size > MODEL_SIZE:
                        raise RuntimeError(
                            f"local model is larger than expected ({size} > {MODEL_SIZE} bytes)"
                        )
                    output_stream.write(chunk)
                    digest.update(chunk)
                output_stream.flush()
                os.fsync(output_stream.fileno())
        if size != MODEL_SIZE:
            raise RuntimeError(
                f"local model size mismatch: expected {MODEL_SIZE}, got {size}"
            )
        if first != b"GGUF":
            raise RuntimeError("local model is not a GGUF file")
        if digest.hexdigest() != MODEL_SHA256:
            raise RuntimeError("local model SHA-256 mismatch")
        os.replace(temporary, destination)
        temporary = None
        return destination
    except RuntimeError:
        raise
    except OSError as error:
        raise RuntimeError(f"local model copy failed: {error}") from error
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
        lock.close()


def _maybe_download_model() -> Path | None:
    destination = _model_cache_path()
    if _model_is_valid(destination):
        print(f"复用样例模型: {destination}")
        return destination
    if not sys.stdin.isatty():
        print(
            "样例模型不会由 Chimera 安装流程自动下载。"
        )
        return None
    try:
        local_path = input("请指定本地样例模型路径（留空表示没有）：").strip()
    except EOFError:
        return None
    if local_path:
        installed = _install_local_model(Path(local_path))
        print(f"已复制并校验本地样例模型: {installed}")
        return installed
    print(
        "样例模型缺失："
        f" {MODEL_REPOSITORY}@{MODEL_REVISION}，约 {MODEL_SIZE / 1_000_000:.0f} MB，"
        f"将保存到 {destination}"
    )
    try:
        answer = input("是否下载样例模型？[y/N] ")
    except EOFError:
        return None
    if answer.strip().lower() not in {"y", "yes"}:
        print("跳过样例模型下载；核心资源仍已初始化")
        return None
    downloaded = _download_model()
    print(f"样例模型已下载: {downloaded}")
    return downloaded


def _release_resource():
    try:
        resource = importlib.resources.files("chimera").joinpath("release")
        # Release metadata is optional for reuse; the presence of the bundled
        # toolchain or ELF resources is the authoritative package marker.
        markers = (
            resource.joinpath("release-config.json"),
            resource.joinpath("toolchain/llvm/bin/clang"),
        )
        return resource if any(marker.is_file() for marker in markers) else None
    except (ModuleNotFoundError, TypeError, ValueError, OSError):
        return None


def _release_target(resource) -> dict[str, str]:
    """Read target metadata without treating it as a binary provenance file."""

    defaults = {
        "target_os": "linux",
        "target_arch": "riscv64",
        "target_arch_extension": "rvv",
    }
    config = resource.joinpath("release-config.json")
    try:
        document = json.loads(config.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return defaults
    except json.JSONDecodeError as error:
        raise RuntimeError(f"release-config.json is invalid: {error}") from error
    except OSError as error:
        raise RuntimeError(f"unable to read release-config.json: {error}") from error
    if not isinstance(document, dict):
        raise RuntimeError("release-config.json must contain a JSON object")
    return {
        key: str(document.get(key, defaults[key]))
        for key in defaults
    }


def _check_release_compatibility(resource, host=None) -> None:
    """Reject a wheel before it creates user state on an incompatible host."""

    target = _release_target(resource)
    host = detect_host_capabilities() if host is None else host
    requirement = SimpleNamespace(**target)
    result = profile_compatibility(requirement, host)
    if result.status == "supported":
        return
    detail = "; ".join(result.reasons)
    if result.status == "unknown":
        raise RuntimeError(
            "无法确认当前系统的 RVV 能力，未初始化 wheel；请检查内核硬件能力信息后重试"
            + (f"（{detail}）" if detail else "")
        )
    raise RuntimeError(
        "此 wheel 与当前系统／架构／RVV 能力不匹配，请安装对应的发布包"
        + (f"（{detail}）" if detail else "")
    )


def _release_identity(resource) -> str:
    config = resource.joinpath("release-config.json")
    try:
        return hashlib.sha256(config.read_bytes()).hexdigest()[:24]
    except (FileNotFoundError, OSError):
        return "legacy-linux-riscv64-rvv"


def _marker_matches(marker: Path, identity: str) -> bool:
    try:
        return f"identity={identity}" in marker.read_text(encoding="utf-8").splitlines()
    except (FileNotFoundError, OSError):
        return False


def _release_marker(resource) -> Path:
    """Return the identity-scoped completion marker for a bundled release."""

    return Path.home() / ".chimera" / "releases" / _release_identity(resource) / ".installed"


def release_initialized() -> bool:
    """Return whether the bundled release has been completely deployed.

    This is deliberately read-only.  Internal release checks may use it to
    decide whether a payload is ready; it must never deploy files as a side effect.
    """

    resource = _release_resource()
    if resource is None:
        return True
    marker = _release_marker(resource)
    if not _marker_matches(marker, _release_identity(resource)):
        return False
    home_root = Path.home() / ".chimera"
    toolchain = home_root / "toolchain_build"
    for relative in (
        "llvm/bin/clang",
        "llvm/bin/clang++",
        "plugins/lib/chimera/llvm/ChimeraStackObject.so",
        "plugins/lib/chimera/llvm/ChimeraVectorGate.so",
    ):
        path = toolchain / relative
        if not path.is_file():
            return False
        if os.name != "nt" and relative.endswith(("clang", "clang++")) and not os.access(path, os.X_OK):
            return False
    # Newer release configs declare every file copied from LLVM's bin
    # directory.  Check those declarations as well so a damaged auxiliary
    # tool cannot leave the installation marked complete.  Unknown/legacy
    # configs still use the fixed required-file checks above.
    try:
        config = json.loads(resource.joinpath("release-config.json").read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError, json.JSONDecodeError):
        config = {}
    declared = config.get("executable_files") if isinstance(config, dict) else None
    if isinstance(declared, list):
        installed_root = home_root / "releases" / _release_identity(resource)
        for item in declared:
            if not isinstance(item, str):
                continue
            package_path = installed_root / item
            if item.startswith("toolchain/"):
                user_path = toolchain / item[len("toolchain/") :]
            else:
                user_path = package_path
            for path in (package_path, user_path):
                if not path.is_file():
                    return False
                if os.name != "nt" and not os.access(path, os.X_OK):
                    return False
    if os.name != "nt":
        for name in ("clang", "clang++"):
            shim = home_root / "bin" / name
            if not shim.is_file() or not os.access(shim, os.X_OK):
                return False
    return True


def _repair_executable_modes(
    root: Path,
    *,
    config: dict[str, object] | None = None,
    scan_bin: bool = True,
    executable_paths: set[Path] | None = None,
) -> None:
    """Restore executable bits lost by wheel/CMake extraction.

    Only files in the release payload's known executable locations are
    touched.  Symlinks are followed only when their resolved target remains
    inside the deployed release tree.
    """

    relative: set[str] = set()
    declared = (config or {}).get("executable_files")
    if isinstance(declared, list):
        relative.update(str(item) for item in declared if isinstance(item, str))
    if executable_paths:
        for path in executable_paths:
            try:
                relative.add(path.relative_to(root).as_posix())
            except ValueError:
                continue
    # The package-owned release tree may scan its complete LLVM bin directory
    # because every entry came from the wheel.  The flattened user toolchain
    # must never be scanned wholesale: it can contain user-owned compilers and
    # helpers that a release is required to preserve.
    if scan_bin:
        relative.update(
            path.relative_to(root).as_posix()
            for directory in (
                root / "toolchain" / "llvm" / "bin",
                root / "llvm" / "bin",
            )
            if directory.is_dir()
            for path in directory.iterdir()
            if path.is_file() or path.is_symlink()
        )
    elif executable_paths is None:
        # Direct callers that opt out of a complete bin scan still get the
        # two stable compiler entry points repaired.  The installer passes an
        # explicit managed set, so it does not touch conflicting user files.
        relative.update({"llvm/bin/clang", "llvm/bin/clang++"})
    # Keep executable modes repairable for legacy wheels that still carry the
    # removed samples.  Current wheels do not ship or require these files.
    relative.update(
        f"examples/llamacpp/{kind}/llama-perplexity"
        for kind in ("system", "remediated")
    )
    seen_targets: set[Path] = set()
    for item in sorted(relative):
        path = root / item
        if not (path.is_file() or path.is_symlink()) and item.startswith("toolchain/"):
            # The release config records paths relative to the package release
            # root.  When repairing the separately deployed toolchain, strip
            # that payload prefix while keeping all other paths untouched.
            item = item[len("toolchain/") :]
            path = root / item
        if not (path.is_file() or path.is_symlink()):
            continue
        try:
            resolved = path.resolve(strict=True)
            resolved.relative_to(root.resolve())
            if resolved in seen_targets:
                continue
            seen_targets.add(resolved)
            if os.name != "nt":
                resolved.chmod(resolved.stat().st_mode | 0o111)
        except (OSError, RuntimeError, ValueError) as error:
            raise RuntimeError(f"无法修复 release 可执行文件权限：{path}: {error}") from error


def _copy_missing_tree(source: Path, destination: Path) -> set[Path]:
    """Add missing managed files without replacing an existing user toolchain."""

    managed: set[Path] = set()
    destination.mkdir(parents=True, exist_ok=True)
    for item in source.rglob("*"):
        relative = item.relative_to(source)
        target = destination / relative
        if target.is_symlink() and not target.exists():
            target.unlink()
        elif target.exists() or target.is_symlink():
            conflict = False
            if item.is_symlink() != target.is_symlink():
                conflict = True
            elif item.is_symlink() and target.is_symlink():
                conflict = os.readlink(item) != os.readlink(target)
                if not conflict:
                    # Matching links are only managed when their resolved
                    # target also matches.  This prevents a
                    # ``clang -> clang-21`` link from making us chmod a
                    # conflicting user-owned target.
                    try:
                        source_target = item.resolve(strict=True)
                        destination_target = target.resolve(strict=True)
                        if source_target.is_file() and destination_target.is_file():
                            conflict = not filecmp.cmp(
                                source_target, destination_target, shallow=False
                            )
                    except (OSError, RuntimeError):
                        conflict = True
            elif item.is_file() and target.is_file():
                try:
                    # Size alone is not a provenance check: a user-owned
                    # compiler can have exactly the same length as the
                    # bundled one.  Preserve it and report a conflict unless
                    # the bytes really match.
                    conflict = not filecmp.cmp(item, target, shallow=False)
                except OSError:
                    conflict = True
            if conflict:
                print(
                    "保留现有用户工具链文件，未覆盖冲突路径："
                    f" {target}",
                    file=sys.stderr,
                )
            elif item.is_symlink() or item.is_file():
                managed.add(target)
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        if item.is_symlink():
            target.symlink_to(os.readlink(item), target_is_directory=item.is_dir())
            managed.add(target)
        elif item.is_dir():
            target.mkdir()
            shutil.copystat(item, target, follow_symlinks=False)
        else:
            shutil.copy2(item, target, follow_symlinks=False)
            managed.add(target)
    return managed


def _sync_managed_release_tree(
    source, destination: Path, *, config: dict[str, object] | None = None
) -> None:
    """Restore missing files in the identity-scoped release payload.

    The identity marker is intentionally cheap metadata, so a user can delete
    a managed file (or leave a dangling symlink) without changing the marker.
    Re-running the resource deployment helper must repair those exact payload entries while
    keeping the separately managed user toolchain conflict-safe.  Release
    wheels are installed from a filesystem by pip; if a resource backend does
    not expose a real path, the normal atomic copy path below will report the
    actionable error instead of silently claiming success.
    """

    try:
        source_path = Path(str(source))
    except (TypeError, ValueError):
        return
    if not source_path.is_dir():
        return
    # Some archive/extraction implementations flatten file symlinks.  The
    # release config records the original link text so the identity-scoped
    # copy can restore links after missing payload files are synchronized.
    links = (config or {}).get("links")
    relative: set[Path] = {
        Path("release-config.json"),
        Path("toolchain/llvm/bin/clang"),
        Path("toolchain/llvm/bin/clang++"),
        Path("toolchain/plugins/lib/chimera/llvm/ChimeraStackObject.so"),
        Path("toolchain/plugins/lib/chimera/llvm/ChimeraVectorGate.so"),
        # Optional entries retained only so upgrades can repair legacy wheels;
        # they are not part of the current release requirements.
        Path("examples/llamacpp/system/llama-perplexity"),
        Path("examples/llamacpp/remediated/llama-perplexity"),
    }
    # Include versioned clang targets (for example clang-21) so a dangling
    # ``clang -> clang-21`` link can be repaired without traversing the whole
    # LLVM payload on every repeated init.
    bin_dir = source_path / "toolchain" / "llvm" / "bin"
    if bin_dir.is_dir():
        relative.update(
            path.relative_to(source_path)
            for path in bin_dir.iterdir()
            if path.is_file() or path.is_symlink()
        )
    for item in sorted(relative):
        item_source = source_path / item
        target = destination / item
        if not (item_source.is_file() or item_source.is_symlink()):
            continue
        if target.is_symlink():
            # The identity-scoped tree is package-owned.  A damaged or
            # hand-edited link must never be allowed to redirect a managed
            # payload entry outside this release directory.  Replace it with
            # the bundled file/link; user toolchain conflicts are handled
            # separately by the non-destructive copy below.
            try:
                target.resolve(strict=False).relative_to(destination.resolve())
                link_is_safe = True
            except (OSError, RuntimeError, ValueError):
                link_is_safe = False
            if (
                not link_is_safe
                or not item_source.is_symlink()
                or os.readlink(item_source) != os.readlink(target)
            ):
                target.unlink()
        if target.exists() or target.is_symlink():
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        if item_source.is_symlink():
            target.symlink_to(
                os.readlink(item_source), target_is_directory=item_source.is_dir()
            )
        else:
            shutil.copy2(item_source, target, follow_symlinks=False)
    # Apply declared link metadata after the regular missing-file pass.  This
    # order matters when a wheel extractor flattened ``clang -> clang-21``:
    # copying the flattened entry first must not overwrite the restored link.
    if isinstance(links, dict):
        destination_root = destination.resolve()
        for raw_relative, raw_target in links.items():
            if not isinstance(raw_relative, str) or not isinstance(raw_target, str):
                continue
            link_relative = Path(raw_relative)
            if link_relative.is_absolute() or ".." in link_relative.parts:
                raise RuntimeError(f"release config contains an unsafe link path: {raw_relative}")
            target_relative = Path(raw_target)
            if target_relative.is_absolute() or ".." in target_relative.parts:
                raise RuntimeError(
                    f"release config contains an unsafe link target: {raw_relative} -> {raw_target}"
                )
            link = destination / link_relative
            target = (link.parent / target_relative).resolve(strict=False)
            try:
                target.relative_to(destination_root)
            except ValueError as error:
                raise RuntimeError(
                    f"release config link target escapes managed tree: {raw_relative} -> {raw_target}"
                ) from error
            if link.exists() and not link.is_symlink():
                link.unlink()
            if link.is_symlink() and os.readlink(link) == raw_target:
                continue
            if link.is_symlink():
                link.unlink()
            link.parent.mkdir(parents=True, exist_ok=True)
            link.symlink_to(raw_target, target_is_directory=False)


def require_user_layout() -> None:
    """Compatibility no-op; wheel resources are usable after pip install."""
    return None


def _acquire_install_lock(lock: Path):
    """Hold an OS advisory lock so a killed process cannot leave a stale lock."""

    descriptor = lock.open("a+", encoding="utf-8")
    try:
        import fcntl
    except ImportError:
        # Windows development hosts do not publish release wheels.  Keep the
        # lock file open for the duration of the operation as a best effort.
        return descriptor
    for _ in range(200):
        try:
            fcntl.flock(descriptor.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            return descriptor
        except BlockingIOError:
            time.sleep(0.05)
    descriptor.close()
    raise RuntimeError(f"timed out waiting for Chimera release installation lock: {lock}")


def ensure_user_layout() -> bool:
    """Deploy release resources once; return whether a release was present."""

    resource = _release_resource()
    if resource is None:
        return False
    _check_release_compatibility(resource)
    identity = _release_identity(resource)
    home_root = Path.home() / ".chimera"
    config_root = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / "chimera"
    home_root.mkdir(parents=True, exist_ok=True)
    config_root.mkdir(parents=True, exist_ok=True)
    lock = home_root / ".release-install.lock"
    marker = _release_marker(resource)
    descriptor = _acquire_install_lock(lock)
    try:
        config_document: dict[str, object] = {}
        config_path = resource.joinpath("release-config.json")
        try:
            loaded = json.loads(config_path.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                config_document = loaded
        except (FileNotFoundError, OSError, json.JSONDecodeError):
            pass
        if not _marker_matches(marker, identity):
            destination = marker.parent
            if destination.is_symlink():
                raise RuntimeError(f"refusing to replace symlinked release directory: {destination}")
            if destination.exists() and not destination.is_dir():
                raise RuntimeError(f"refusing to replace non-directory release path: {destination}")
            destination.parent.mkdir(parents=True, exist_ok=True)
            temporary = Path(tempfile.mkdtemp(prefix=f".{__version__}.", dir=str(destination.parent)))
            try:
                for child in resource.iterdir():
                    target = temporary / child.name
                    if child.is_dir():
                        shutil.copytree(str(child), target, symlinks=True)
                    else:
                        # File symlinks (notably clang -> clang-21) are part of
                        # the published toolchain layout.  Do not dereference
                        # them while making the identity-scoped install copy.
                        shutil.copy2(str(child), target, follow_symlinks=False)
                if destination.exists():
                    shutil.rmtree(destination)
                os.replace(temporary, destination)
            finally:
                if temporary.exists():
                    shutil.rmtree(temporary, ignore_errors=True)
        installed_root = marker.parent
        # A matching marker does not prove that every managed payload file is
        # still present.  Repair only missing files/dangling links in the
        # identity-scoped copy; user-owned ``toolchain_build`` is handled by
        # the conflict-preserving copy below.
        _sync_managed_release_tree(
            resource, installed_root, config=config_document
        )
        _repair_executable_modes(installed_root, config=config_document)
        bundled_toolchain = installed_root / "toolchain"
        toolchain_root = home_root / "toolchain_build"
        if toolchain_root.is_symlink():
            raise RuntimeError(f"refusing to deploy through symlinked toolchain directory: {toolchain_root}")
        if bundled_toolchain.is_dir() and not toolchain_root.exists():
            shutil.copytree(bundled_toolchain, toolchain_root, symlinks=True)
        if bundled_toolchain.is_dir() and toolchain_root.exists():
            # Existing user toolchains are never replaced.  Repair only the
            # exact files/links that match the bundled release; unmanaged
            # entries are absent from ``managed`` and remain untouched.
            managed = _copy_missing_tree(bundled_toolchain, toolchain_root)
            llvm_bin = toolchain_root / "llvm" / "bin"
            managed_executables = {
                path for path in managed if path.parent == llvm_bin
            }
            _repair_executable_modes(
                toolchain_root, scan_bin=False, executable_paths=managed_executables
            )
        shim_dir = home_root / "bin"
        shim_dir.mkdir(parents=True, exist_ok=True)
        for name, option in (("clang", ""), ("clang++", "--cxx")):
            shim = shim_dir / name
            expected_shim = (
                "#!/usr/bin/env bash\n"
                f'exec "{os.environ.get("PYTHON", "python3")}" -m chimera.pkg llvm {option} -- "$@"\n'
            )
            if shim.is_symlink() and not shim.exists():
                # A failed or hand-edited release install can leave a
                # dangling managed shim.  Remove only that exact entry before
                # recreating it; valid user-owned shims are preserved below.
                shim.unlink()
            if not shim.exists():
                shim.write_text(expected_shim, encoding="utf-8")
                shim.chmod(0o755)
            elif os.name != "nt":
                try:
                    target = shim
                    if shim.is_symlink():
                        resolved = shim.resolve(strict=True)
                        resolved.relative_to(shim_dir.resolve())
                        text = resolved.read_text(encoding="utf-8", errors="replace")
                        target = resolved
                    else:
                        text = shim.read_text(encoding="utf-8", errors="replace")
                    managed = text.startswith("#!/usr/bin/env bash\n") and (
                        "-m chimera.pkg llvm" in text
                        or "-m chimera llvm" in text
                    )
                    if not managed:
                        if not os.access(shim, os.X_OK):
                            raise RuntimeError(
                                f"compiler shim conflicts with a non-executable user file: {shim}"
                            )
                        print(
                            "保留现有用户 compiler shim，未覆盖冲突路径："
                            f" {shim}",
                            file=sys.stderr,
                        )
                        continue
                    # Rewrite shims generated by the removed ``chimera``
                    # entry point so an upgrade does not leave a broken
                    # compiler wrapper behind.
                    if "-m chimera llvm" in text and "-m chimera.pkg llvm" not in text:
                        target.write_text(expected_shim, encoding="utf-8")
                    shim.chmod(shim.stat().st_mode | 0o111)
                except OSError as error:
                    raise RuntimeError(f"无法修复 compiler shim 权限：{shim}: {error}") from error
                except (RuntimeError, ValueError) as error:
                    raise RuntimeError(f"compiler shim 路径冲突：{shim}: {error}") from error
        required = (
            installed_root / "toolchain" / "llvm" / "bin" / "clang",
            installed_root / "toolchain" / "llvm" / "bin" / "clang++",
            installed_root / "toolchain" / "plugins" / "lib" / "chimera" / "llvm" / "ChimeraStackObject.so",
            installed_root / "toolchain" / "plugins" / "lib" / "chimera" / "llvm" / "ChimeraVectorGate.so",
        )
        user_required = (
            toolchain_root / "llvm" / "bin" / "clang",
            toolchain_root / "llvm" / "bin" / "clang++",
            toolchain_root / "plugins" / "lib" / "chimera" / "llvm" / "ChimeraStackObject.so",
            toolchain_root / "plugins" / "lib" / "chimera" / "llvm" / "ChimeraVectorGate.so",
        )
        executable_required = {
            required[0],
            required[1],
            user_required[0],
            user_required[1],
        }
        missing: list[str] = []
        for path in (*required, *user_required):
            if not path.is_file():
                missing.append(str(path))
            elif (
                os.name != "nt"
                and path in executable_required
                and not os.access(path, os.X_OK)
            ):
                missing.append(f"{path} (not executable)")
        if missing:
            raise RuntimeError("release resources are incomplete after deployment: " + ", ".join(missing))
        # The completion marker is deliberately written last.  A failed
        # resource copy or shim deployment must be retried on
        # the next invocation rather than being mistaken for a complete
        # installation.
        marker.parent.mkdir(parents=True, exist_ok=True)
        marker_temporary = marker.with_name(f".{marker.name}.{os.getpid()}.tmp")
        try:
            marker_temporary.write_text(
                f"schema_version=1\nidentity={identity}\n", encoding="utf-8"
            )
            os.replace(marker_temporary, marker)
        finally:
            marker_temporary.unlink(missing_ok=True)
    finally:
        descriptor.close()
    return True


__all__ = [
    "MODEL_FILENAME",
    "MODEL_LICENSE",
    "MODEL_REPOSITORY",
    "MODEL_REVISION",
    "MODEL_SIZE",
    "MODEL_SHA256",
    "MODEL_URL",
    "ensure_user_layout",
    "release_initialized",
    "require_user_layout",
]
