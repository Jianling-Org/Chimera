"""First-class dispatch for the repository's end-to-end examples."""

from __future__ import annotations

from dataclasses import dataclass
from contextlib import contextmanager
import importlib.resources
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10 source-test fallback
    import tomli as tomllib

from chimera import __version__
from chimera.example_capabilities import (
    Compatibility,
    detect_host_capabilities,
    profile_compatibility,
)
from chimera.preprocess.offline.config import load_configuration
from chimera.installation import require_user_layout


SOURCE_BINDING = Path(".chimera") / "examples" / "source.json"
SOURCE_ENV = "CHIMERA_EXAMPLE_SOURCE_ROOT"
DISPATCH_ENV = "CHIMERA_EXAMPLE_DISPATCH_ROOT"


@dataclass(frozen=True)
class ExampleSpec:
    action: str
    script: str
    description: str
    accepts_args: bool = False
    profiles: tuple[str, ...] = ()
    release_supported: bool = True
    run_script: str | None = None


@dataclass(frozen=True)
class ExampleAvailability:
    name: str
    action: str
    description: str
    status: str
    reasons: tuple[str, ...] = ()


EXAMPLE_CATALOG: dict[str, ExampleSpec] = {
    "hello_world": ExampleSpec(
        "build",
        "examples/scripts/build/build_hello_world.sh",
        "build a small vector-enabled Hello World Workspace",
        profiles=("hello-world.toml",),
        run_script="examples/scripts/run/run_hello_world.sh",
    ),
    "build_llamacpp": ExampleSpec(
        "build",
        "examples/scripts/build/build_llamacpp.sh",
        "build, analyze, remediate and prepare all llama.cpp faces",
        profiles=(
            "linux-riscv64-rvv-1024-to-256.toml",
            "linux-riscv64-rvv-256-to-1024.toml",
            "linux-riscv64-rvv-1024-256-bidirectional.toml",
        ),
    ),
    "build_llamacpp_stats": ExampleSpec(
        "build",
        "examples/scripts/build/build_llamacpp_stats.sh",
        "build the single-face implicit-vector census",
        profiles=("linux-riscv64-rvv-1024-256-bidirectional.toml",),
    ),
    "run_llamacpp_1024_to_256": ExampleSpec(
        "run",
        "examples/scripts/run/run_llamacpp_1024_to_256.sh",
        "run with one 1024-to-256 migration",
        profiles=("linux-riscv64-rvv-1024-to-256.toml",),
    ),
    "run_llamacpp_256_to_1024": ExampleSpec(
        "run",
        "examples/scripts/run/run_llamacpp_256_to_1024.sh",
        "run with one 256-to-1024 migration",
        profiles=("linux-riscv64-rvv-256-to-1024.toml",),
    ),
    "run_llamacpp_1024_256_bidirectional": ExampleSpec(
        "run",
        "examples/scripts/run/run_llamacpp_1024_256_bidirectional.sh",
        "run bidirectional migration",
        profiles=("linux-riscv64-rvv-1024-256-bidirectional.toml",),
    ),
    "run_llamacpp_scheduler": ExampleSpec(
        "run",
        "examples/scripts/run/run_llamacpp_scheduler.sh",
        "run the no-migration scheduler baseline",
        profiles=("linux-riscv64-rvv-1024-256-bidirectional.toml",),
    ),
    "run_llamacpp_benchmark": ExampleSpec(
        "run",
        "examples/scripts/run/run_llamacpp_benchmark.sh",
        "repeat five llama.cpp scenarios and average performance/PPL",
        True,
        ("linux-riscv64-rvv-1024-256-bidirectional.toml",),
    ),
}

_STATIC_FILES = (
    "examples/scripts/build/_common.sh",
    "examples/scripts/build/install_llamacpp_scalar.py",
    "examples/scripts/build/vector_census_report.py",
    "examples/scripts/build/build_llamacpp.sh",
    "examples/scripts/build/build_llamacpp_stats.sh",
    "examples/scripts/build/build_hello_world.sh",
    "examples/scripts/run/run_llamacpp_1024_to_256.sh",
    "examples/scripts/run/run_llamacpp_256_to_1024.sh",
    "examples/scripts/run/run_llamacpp_1024_256_bidirectional.sh",
    "examples/scripts/run/run_llamacpp_scheduler.sh",
    "examples/scripts/run/run_llamacpp_benchmark.sh",
    "examples/scripts/run/_common.sh",
    "examples/scripts/run/run_hello_world.sh",
    "examples/applications/hello-world/hello_world.c",
    "examples/platforms/k3/hello-world.toml",
    "examples/platforms/k3/linux-riscv64-rvv-1024-to-256.toml",
    "examples/platforms/k3/linux-riscv64-rvv-256-to-1024.toml",
    "examples/platforms/k3/linux-riscv64-rvv-1024-256-bidirectional.toml",
    "examples/applications/llama-cpp/prompt/file.txt",
    "examples/applications/llama-cpp/patch/0001-llama.cpp-rvv-vlen1024-compatible-with-vlen256.patch",
    "examples/applications/llama-cpp/patch/llama-cpp-rvv-vlen1024-q5-fix-4fc4ec554.patch",
    "examples/applications/llama-cpp/scalar/ld-linux-riscv64-lp64d.so.1",
    "examples/applications/llama-cpp/scalar/libc.so.6",
    "examples/applications/llama-cpp/scalar/libgcc_s.so.1",
    "examples/applications/llama-cpp/scalar/libgomp.so.1",
    "examples/applications/llama-cpp/scalar/libm.so.6",
    "examples/applications/llama-cpp/scalar/libstdc++.so.6",
)

_SUBMODULE_PATHS = (
    "examples/applications/llama-cpp/llama.cpp",
    "third_party/llvm",
    "third_party/SVF",
)

_EXAMPLE_BUILD_DIRS = {
    "build_llamacpp": (
        "examples/applications/llama-cpp/llama.cpp/build-vanilla",
        "examples/applications/llama-cpp/llama.cpp/build-remediated",
    ),
    "build_llamacpp_stats": (
        "examples/applications/llama-cpp/llama.cpp/build-stats-discovery",
        "examples/applications/llama-cpp/llama.cpp/build-stats-gate",
    ),
}
_EXAMPLE_TEMP_FILES = {
    "build_llamacpp": (),
    "build_llamacpp_stats": (
        "examples/applications/llama-cpp/llama.cpp/build-stats.mock-seed.json",
        "examples/applications/llama-cpp/llama.cpp/build-stats.decision.json",
        "examples/applications/llama-cpp/llama.cpp/build-stats.decision.gate_names.txt",
        "examples/applications/llama-cpp/llama.cpp/build-stats.decision.gate_names.implicit_vector_census.tsv",
    ),
}


@contextmanager
def _example_operation_lock():
    """Serialize llama.cpp source mutation and cleanup operations."""

    lock_path = Path(
        os.environ.get(
            "CHIMERA_EXAMPLE_LOCK_PATH",
            Path.home() / ".chimera" / ".llamacpp-source.lock",
        )
    ).expanduser()
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = lock_path.open("a+b")
    unlock = None
    try:
        try:
            import fcntl
        except ImportError:
            # Release wheels target Linux.  Keeping the descriptor open is a
            # best-effort fallback for development on Windows.
            pass
        else:
            try:
                fcntl.flock(descriptor.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except (BlockingIOError, OSError) as error:
                raise ValueError(
                    "another Chimera llama.cpp operation is using the source; "
                    "wait for it to finish and retry"
                ) from error
            unlock = fcntl.flock
        yield
    finally:
        if unlock is not None:
            try:
                unlock(descriptor.fileno(), fcntl.LOCK_UN)
            except OSError:
                pass
        descriptor.close()


def _git_submodule_commit(root: Path, relative: str) -> str:
    completed = subprocess.run(
        ["git", "-c", f"safe.directory={root.as_posix()}", "-C", str(root),
         "ls-tree", "HEAD", "--", relative],
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        raise ValueError(f"unable to inspect source gitlink: {relative}")
    for line in completed.stdout.splitlines():
        fields = line.split()
        if len(fields) >= 4 and fields[0] == "160000" and fields[-1] == relative:
            return fields[2]
    raise ValueError(f"source checkout has no recorded gitlink: {relative}")


def _git_metadata_file(checkout: Path, name: str) -> Path | None:
    completed = subprocess.run(
        ["git", "-C", str(checkout), "rev-parse", "--path-format=absolute", "--git-path", name],
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        completed = subprocess.run(
            ["git", "-C", str(checkout), "rev-parse", "--git-path", name],
            capture_output=True,
            text=True,
            check=False,
        )
    if completed.returncode != 0 or not completed.stdout.strip():
        return None
    path = Path(completed.stdout.strip())
    return path if path.is_absolute() else checkout / path


def _release_llama_commit() -> str:
    """Return the fixed llama.cpp commit recorded in a release package."""

    try:
        resource = importlib.resources.files("chimera").joinpath("release/release-config.json")
        document = json.loads(resource.read_text(encoding="utf-8"))
    except FileNotFoundError:
        # Wheels produced before release-config.json was introduced still
        # shipped the same pinned llama.cpp payload. Keep their cleanup and
        # source bootstrap compatible without treating the old manifest as a
        # binary reuse credential.
        return "4fc4ec554"
    except (ModuleNotFoundError, TypeError, ValueError, OSError, json.JSONDecodeError) as error:
        raise ValueError(f"release configuration is unavailable: {error}") from error
    commit = document.get("llama_commit") if isinstance(document, dict) else None
    if not isinstance(commit, str) or not commit:
        raise ValueError("release configuration does not declare llama_commit")
    return commit


def _packaged_artifact_root() -> Path:
    """Return a release-stable user directory for example outputs.

    A wheel may be installed into different virtual environments on the same
    host.  Hashing the site-packages path would move the user's ELF, reports,
    and stats every time that happens, so packaged examples use the release
    configuration identity instead.  Legacy wheels without that file retain a
    fixed compatibility bucket.
    """

    identity = "legacy-linux-riscv64-rvv"
    try:
        resource = importlib.resources.files("chimera").joinpath(
            "release/release-config.json"
        )
        identity = hashlib.sha256(resource.read_bytes()).hexdigest()
    except (ModuleNotFoundError, TypeError, ValueError, OSError):
        pass
    return Path.home() / ".chimera" / "examples" / identity / "llamacpp"


def clean_example(name: str) -> None:
    """Restore llama.cpp and remove only the named example build trees."""

    build_dirs = _EXAMPLE_BUILD_DIRS.get(name)
    if build_dirs is None:
        raise ValueError(
            f"unknown cleanable example {name!r}; use build_llamacpp or "
            "build_llamacpp_stats"
        )
    with _example_operation_lock():
        _clean_example_locked(name, build_dirs)


def _clean_example_locked(name: str, build_dirs: tuple[str, ...]) -> None:
    packaged = _packaged_release_present()
    root = resolve_source_root()
    if packaged:
        # A packaged build that consumed a prebuilt input keeps its temporary
        # CMake trees outside the source checkout so a passing input does not
        # trigger a clone.  The state file is deliberately in the same
        # managed directory; Workspace cleanup removes it after an interrupted
        # run so the next build can retry.
        package_build_root = Path(
            os.environ.get(
                "CHIMERA_EXAMPLE_BUILD_ROOT",
                Path.home() / ".chimera" / "example-build" / "llamacpp",
            )
        ).expanduser().resolve()
        package_root = (Path.home() / ".chimera").resolve()
        try:
            package_build_root.relative_to(package_root)
        except ValueError as error:
            raise ValueError(
                f"refusing to remove packaged example build outside {package_root}: "
                f"{package_build_root}"
            ) from error
        if name == "build_llamacpp":
            package_build_dirs = ("vanilla", "remediated")
        else:
            package_build_dirs = ()
        for directory in package_build_dirs:
            build = package_build_root / directory
            if build == package_build_root or build == package_root:
                raise ValueError(f"refusing to remove unsafe example build directory: {build}")
            if build.is_symlink():
                raise ValueError(f"refusing to remove symlinked example build directory: {build}")
            if build.exists():
                if not build.is_dir():
                    raise ValueError(f"refusing to remove non-directory example build path: {build}")
                shutil.rmtree(build)
        (package_build_root / ".chimera-example-state.json").unlink(missing_ok=True)
        try:
            package_build_root.rmdir()
        except OSError:
            # Keep a custom/user-added file in the managed parent intact.
            pass
        if not (Path.home() / ".chimera" / "example-source" / "llama.cpp").exists():
            print(f"cleaned example {name}: removed packaged build directories")
            return
        # Release examples clone their fixed source revision under the user's
        # writable directory; package resources and site-packages stay intact.
        llama = (Path.home() / ".chimera" / "example-source" / "llama.cpp").resolve()
        if not llama.exists():
            print(f"cleaned example {name}: no release source checkout to clean")
            return
        expected = _release_llama_commit()
    else:
        _validate_source_root(root, version=__version__)
        relative = "examples/applications/llama-cpp/llama.cpp"
        llama = (root / relative).resolve()
        expected = _git_submodule_commit(root, relative)
    if not llama.is_dir() or not (llama / ".git").exists():
        raise ValueError(f"llama.cpp source is not a Git checkout: {llama}")
    for relative_build in build_dirs:
        build_path = llama / Path(relative_build).name
        build = build_path.resolve(strict=False)
        if build in {llama, llama / ".git"}:
            raise ValueError(f"refusing to remove unsafe example build directory: {build}")
        if build_path.exists() or build_path.is_symlink():
            if build_path.is_symlink():
                raise ValueError(f"refusing to remove symlinked example build directory: {build_path}")
            shutil.rmtree(build_path)
    completed = subprocess.run(
        ["git", "-C", str(llama), "reset", "--hard", expected],
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        raise ValueError(f"failed to restore llama.cpp to recorded commit {expected}")
    state = _git_metadata_file(llama, "chimera-example-state.json")
    if state is not None:
        state.unlink(missing_ok=True)
    for pattern in ("*.decision.json", "*.check.json"):
        for report in llama.glob(pattern):
            report.unlink(missing_ok=True)
    for relative_temp in _EXAMPLE_TEMP_FILES[name]:
        (llama / Path(relative_temp).name).unlink(missing_ok=True)
    print(f"cleaned example {name}: restored {llama} and removed build directories")

_REBIND_HINT = "run the project-specific example setup documented by the example package"


def _binding_path() -> Path:
    return Path.home() / SOURCE_BINDING


def _validate_source_root(root: Path, *, version: str | None = None) -> None:
    if not root.is_dir():
        raise ValueError(f"example source root is not a directory: {root}; {_REBIND_HINT}")
    if not (root / ".git").exists():
        raise ValueError(f"example source root is not a Git checkout: {root}; {_REBIND_HINT}")
    pyproject = root / "pyproject.toml"
    if not pyproject.is_file():
        raise ValueError(f"example source root is missing pyproject.toml: {root}; {_REBIND_HINT}")
    with pyproject.open("rb") as stream:
        project = tomllib.load(stream).get("project", {})
    if not isinstance(project, dict):
        raise ValueError(f"example source root has an invalid [project] table: {root}; {_REBIND_HINT}")
    if project.get("name") != "chimera":
        raise ValueError(f"example source root is not the Chimera project: {root}; {_REBIND_HINT}")
    if version and not version.startswith("0+") and project.get("version") != version:
        raise ValueError(
            "example source and installed Chimera versions differ: "
            f"source={project.get('version')!r} installed={version!r}; {_REBIND_HINT}"
        )
    gitmodules = root / ".gitmodules"
    if not gitmodules.is_file():
        raise ValueError(f"example source root is missing .gitmodules: {root}; {_REBIND_HINT}")
    gitmodules_text = gitmodules.read_text(encoding="utf-8")
    missing_gitlinks = [
        path for path in _SUBMODULE_PATHS if f"path = {path}" not in gitmodules_text
    ]
    if missing_gitlinks:
        raise ValueError(
            "example source root is missing recorded submodules: "
            + ", ".join(missing_gitlinks)
            + f"; {_REBIND_HINT}"
        )
    recorded = _recorded_gitlink_paths(root)
    missing_gitlinks = [path for path in _SUBMODULE_PATHS if path not in recorded]
    if missing_gitlinks:
        raise ValueError(
            "example source root does not record the required gitlinks: "
            + ", ".join(missing_gitlinks)
            + f"; {_REBIND_HINT}"
        )
    missing = [relative for relative in _STATIC_FILES if not (root / relative).is_file()]
    if missing:
        raise ValueError(
            "example source root is missing example files:\n  "
            + "\n  ".join(str(root / relative) for relative in missing)
            + f"\n{_REBIND_HINT}"
        )


def _recorded_gitlink_paths(root: Path) -> set[str]:
    """Return submodule paths recorded as mode-160000 entries in HEAD."""

    try:
        completed = subprocess.run(
            [
                "git",
                "-c",
                f"safe.directory={root.as_posix()}",
                "-C",
                str(root),
                "ls-tree",
                "-z",
                "HEAD",
                "--",
                *_SUBMODULE_PATHS,
            ],
            capture_output=True,
            check=False,
        )
    except FileNotFoundError as error:
        raise ValueError(f"git is required to inspect the source checkout; {_REBIND_HINT}") from error
    if completed.returncode != 0:
        detail = completed.stderr.decode(errors="replace").strip()
        raise ValueError(
            "unable to inspect Chimera superproject gitlinks: "
            f"{detail or 'git ls-tree failed'}; {_REBIND_HINT}"
        )
    recorded: set[str] = set()
    for entry in completed.stdout.split(b"\0"):
        if not entry:
            continue
        header, separator, path = entry.partition(b"\t")
        if not separator:
            continue
        mode = header.split(maxsplit=1)[0]
        if mode == b"160000":
            recorded.add(path.decode())
    return recorded


def configure_source_root(source_root: str | Path, *, version: str | None = None) -> Path:
    """Validate and atomically persist the checkout used by examples."""

    root = Path(source_root).expanduser().resolve()
    binding_version = __version__ if version is None else version
    _validate_source_root(root, version=binding_version)
    destination = _binding_path()
    destination.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema_version": 1,
        "source_root": str(root),
        "chimera_version": binding_version,
    }
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=destination.parent, delete=False
    ) as stream:
        json.dump(payload, stream, indent=2, sort_keys=True)
        stream.write("\n")
        temporary = Path(stream.name)
    try:
        os.replace(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)
    return destination


def resolve_source_root() -> Path:
    """Return the configured checkout; validation happens at dispatch time."""

    override = os.environ.get(SOURCE_ENV)
    if override:
        return Path(override).expanduser().resolve()
    # A release wheel owns its bundled scripts.  A stale source binding from a
    # previous checkout must not redirect release commands into site-packages
    # or the publisher's repository.  An explicit environment override still
    # wins for development and migration testing.
    if _packaged_release_present():
        try:
            packaged = Path(str(importlib.resources.files("chimera")))
            if (packaged / "examples" / "scripts").is_dir():
                return packaged
        except (ModuleNotFoundError, TypeError, ValueError, OSError):
            pass
    binding = _binding_path()
    if not binding.is_file():
        try:
            packaged = Path(str(importlib.resources.files("chimera")))
            if (packaged / "examples" / "scripts").is_dir():
                return packaged
        except (ModuleNotFoundError, TypeError, ValueError, OSError):
            pass
        raise ValueError(
            "no Chimera example checkout is configured; run "
            "the example package setup command"
        )
    try:
        document = json.loads(binding.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(
            f"invalid example source binding {binding}: {error}; {_REBIND_HINT}"
        ) from error
    if (
        not isinstance(document, dict)
        or document.get("schema_version") != 1
        or not isinstance(document.get("source_root"), str)
        or not isinstance(document.get("chimera_version"), str)
    ):
        raise ValueError(f"unsupported example source binding: {binding}; {_REBIND_HINT}")
    return Path(document["source_root"]).expanduser().resolve()


def _bundled_profile(name: str) -> Path | None:
    candidates = [
        Path(__file__).resolve().parents[2] / "examples" / "platforms" / "k3" / name,
    ]
    try:
        candidates.insert(
            0,
            Path(str(importlib.resources.files("chimera").joinpath("examples/platforms/k3", name))),
        )
    except (ModuleNotFoundError, TypeError, ValueError):
        pass
    return next((candidate for candidate in candidates if candidate.is_file()), None)


def _packaged_release_present() -> bool:
    try:
        resource = importlib.resources.files("chimera").joinpath("release")
        return any(
            resource.joinpath(marker).is_file()
            for marker in (
                "release-config.json",
                "toolchain/llvm/bin/clang",
                "examples/llamacpp/system/llama-perplexity",
            )
        )
    except (ModuleNotFoundError, TypeError, ValueError, OSError):
        return False


def example_availability(
    *, profile: Path | None = None, host=None
) -> list[ExampleAvailability]:
    """Return availability for every registered example using one host snapshot."""

    host = detect_host_capabilities() if host is None else host
    # ``profile`` selects the configuration used by a later build/run.  The
    # hardware admission comparison uses the explicit sample profile only;
    # there is no implicit system Profile to search or merge here.
    result: list[ExampleAvailability] = []
    for name, spec in EXAMPLE_CATALOG.items():
        statuses: list[Compatibility] = []
        try:
            packaged_release = _packaged_release_present()
        except (ModuleNotFoundError, TypeError, ValueError):
            packaged_release = False
        if packaged_release and not spec.release_supported:
            statuses.append(Compatibility("unsupported", ("this example is not bundled in the release wheel",)))
        for filename in spec.profiles:
            candidate = _bundled_profile(filename)
            if candidate is None:
                statuses.append(Compatibility("unknown", (f"missing example Profile: {filename}",)))
                continue
            requirement = load_configuration(candidate).profile
            statuses.append(profile_compatibility(requirement, host))
        reasons = tuple(dict.fromkeys(reason for item in statuses for reason in item.reasons))
        if any(item.status == "unsupported" for item in statuses):
            status = "unsupported"
        elif any(item.status == "unknown" for item in statuses):
            status = "unknown"
        else:
            status = "supported"
        result.append(ExampleAvailability(name, spec.action, spec.description, status, reasons))
    return result


def require_example_supported(name: str, *, profile: Path | None = None) -> None:
    availability = {item.name: item for item in example_availability(profile=profile)}
    item = availability.get(name)
    if item is None:
        raise ValueError(f"unknown example {name!r}; use the example package documentation to see valid names")
    if item.status != "supported":
        detail = "; ".join(item.reasons) or item.status
        raise ValueError(f"example {name!r} is not supported by the current host: {detail}")


def list_examples(*, profile: Path | None = None, all_examples: bool = False) -> list[ExampleAvailability]:
    entries = example_availability(profile=profile)
    print("action\tname\tstatus\tdescription")
    for item in entries:
        if not all_examples and item.status != "supported":
            continue
        print(f"{item.action}\t{item.name}\t{item.status}\t{item.description}")
        if all_examples and item.reasons:
            print(f"\t\treason: {'; '.join(item.reasons)}")
    if not all_examples and not any(item.status == "supported" for item in entries):
        print("no examples match the current host; consult the example package documentation for details")
    return [item for item in entries if all_examples or item.status == "supported"]


def execute_example(
    name: str, *, action: str | None = None, args: list[str] | None = None,
    input_elf: str | None = None, profile: Path | None = None,
    workspace: str | Path | None = None,
) -> int:
    """Run one fixed example script and return its shell-compatible status."""

    spec = EXAMPLE_CATALOG.get(name)
    if spec is None:
        raise ValueError(
            f"unknown example {name!r}; use the example package documentation to see valid names"
        )
    if action is not None and spec.action != action and not (name == "hello_world" and action == "run" and spec.run_script):
        raise ValueError(
            f"example {name!r} is a {spec.action} example, not a {action} example"
        )
    root = resolve_source_root()
    packaged_input = False
    packaged_root = _packaged_release_present()
    if packaged_root and name != "hello_world":
        require_user_layout()
    if input_elf is not None:
        if input_elf in {"system", "remediated"}:
            relative = f"release/examples/llamacpp/{input_elf}/llama-perplexity"
            try:
                packaged_path = Path(str(importlib.resources.files("chimera").joinpath(relative)))
            except (ModuleNotFoundError, TypeError, ValueError) as error:
                raise ValueError(f"release input {input_elf!r} is unavailable") from error
            if not packaged_path.is_file():
                raise ValueError(f"release input {input_elf!r} is unavailable: {packaged_path}")
            input_elf = str(packaged_path)
            packaged_input = True
        else:
            input_elf = str(Path(input_elf).expanduser().resolve())
    if not packaged_input and not packaged_root:
        _validate_source_root(root, version=__version__)
    # Gate every build/run before touching its script.  Configuration and
    # cleanup commands dispatch elsewhere and therefore remain unrestricted.
    if spec.profiles:
        require_example_supported(name, profile=profile)
    if packaged_root and not spec.release_supported:
        raise ValueError(f"example {name!r} is not bundled in the release wheel")
    if packaged_root and name == "build_llamacpp" and action == "build" and input_elf is None:
        raise ValueError(
            "release wheel example builds require --input system, --input remediated, or an ELF path"
        )
    script = root / (spec.run_script if action == "run" and spec.run_script else spec.script)
    if not script.is_file():
        raise ValueError(f"example script is missing: {script}")
    environment = os.environ.copy()
    environment[DISPATCH_ENV] = str(root)
    if packaged_root and "CHIMERA_EXAMPLE_ARTIFACT_ROOT" not in environment:
        environment["CHIMERA_EXAMPLE_ARTIFACT_ROOT"] = str(
            _packaged_artifact_root()
        )
    if input_elf is not None:
        environment["CHIMERA_EXAMPLE_INPUT"] = input_elf
    if workspace is not None:
        # Preserve a single-component Workspace ID for chimera-user, which
        # resolves IDs under its runtime configuration root.  Explicit paths
        # are normalized so scripts receive a stable absolute location.
        workspace_value = Path(workspace).expanduser()
        if not workspace_value.is_absolute() and len(workspace_value.parts) == 1:
            environment["CHIMERA_EXAMPLE_WORKSPACE"] = workspace_value.name
        else:
            environment["CHIMERA_EXAMPLE_WORKSPACE"] = str(workspace_value.resolve())
    if packaged_input or packaged_root:
        environment["CHIMERA_EXAMPLE_PACKAGED"] = "1"
        try:
            config_path = Path(str(importlib.resources.files("chimera").joinpath("release/release-config.json")))
            config = json.loads(config_path.read_text(encoding="utf-8"))
            if isinstance(config, dict):
                if isinstance(config.get("llama_repository"), str):
                    environment["CHIMERA_LLAMA_REPOSITORY"] = config["llama_repository"]
                if isinstance(config.get("llama_commit"), str):
                    environment["CHIMERA_LLAMA_COMMIT"] = config["llama_commit"]
        except (OSError, ValueError, json.JSONDecodeError):
            pass
    command = ["bash", str(script), *(args or [])]
    try:
        completed = subprocess.run(command, cwd=root, env=environment)
    except FileNotFoundError as error:
        raise ValueError("bash is required to run Chimera examples") from error
    if completed.returncode < 0:
        return 128 - completed.returncode
    return completed.returncode


__all__ = [
    "DISPATCH_ENV",
    "EXAMPLE_CATALOG",
    "SOURCE_ENV",
    "configure_source_root",
    "clean_example",
    "execute_example",
    "example_availability",
    "require_example_supported",
    "list_examples",
    "resolve_source_root",
]
