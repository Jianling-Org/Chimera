"""Verify a workspace and replace the current process with the application.

The application is **not** copied into the Workspace: it runs from wherever it
is installed, started by invoking the package's own loader explicitly.  That
inversion is what keeps the application's path derivation intact, and it also
means the loader is a file we control rather than whatever ``PT_INTERP`` points
at on this machine.

Because the application now comes from outside the package, "which files will
this launch actually use" is no longer something the package can assert.  It is
asked of the loader, and every answer is checked against the Manifest by hash.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
import subprocess
from typing import NoReturn, Sequence

from chimera.preprocess.offline.analysis.core.monitor import (
    argument,
    monitored,
    returned,
)
from chimera.preprocess.offline.analysis.platform.linux.elf import interpreter
from chimera.preprocess.offline.config import BaseConfig
from chimera.runtime.manifest import PACKAGE_MODULE_DIR, read_manifest
from chimera.runtime.validate import verify_workspace
from .adapters import registered_launch_adapters
from .precheck import LoaderReportError, parse_loader_list
from .external_leaf import leaf_artifacts, reject_leaf_interposers, validate_leaf_launch


class LaunchError(RuntimeError):
    """A Workspace or application cannot be launched as recorded."""


@dataclass(frozen=True)
class ResolvedModules:
    manifest: object
    #: Module ID -> the file this machine resolves it to.
    resolved: dict[str, Path]


@dataclass(frozen=True)
class LaunchRequest:
    loader: Path
    program: Path
    argv: tuple[str, ...]
    library_paths: tuple[str, ...]
    #: Where each Manifest module actually resolves on this machine, keyed by
    #: module ID.  Only what the loader reported, so it never invents a path.
    resolved: dict[str, Path]
    environment: dict[str, str]


_LD_SO_CONF = Path("/etc/ld.so.conf")


def _machine_library_paths() -> tuple[str, ...]:
    """Directories ``ldconfig`` indexes, i.e. where *this* machine keeps libs.

    A dependency the package deliberately leaves on the machine (D2) can only
    be resolved if the search path reaches the directory the machine actually
    keeps it in.  Multiarch directories like ``/usr/lib/riscv64-linux-gnu`` are
    **not** part of the loader's built-in defaults -- ``ldconfig`` adds them to
    the cache, and they are otherwise invisible to a launch that supplies its
    own search path.  Listing them explicitly is what makes "resolved on the
    machine" mean something.
    """

    if not _LD_SO_CONF.is_file():
        return ()
    pending = [_LD_SO_CONF]
    found: list[str] = []
    while pending:
        current = pending.pop()
        try:
            lines = current.read_text(
                encoding="utf-8", errors="replace"
            ).splitlines()
        except OSError:
            continue
        for line in lines:
            entry = line.split("#", 1)[0].strip()
            if not entry:
                continue
            if entry.startswith("include "):
                pattern = entry[len("include "):].strip().lstrip("/")
                if pattern:
                    pending.extend(sorted(Path("/").glob(pattern)))
                continue
            if entry.startswith("/") and Path(entry).is_dir():
                found.append(entry)
    ordered: list[str] = []
    for candidate in found:
        if candidate not in ordered:
            ordered.append(candidate)
    return tuple(ordered)


def _search_paths(root: Path, program: Path) -> tuple[str, ...]:
    """Everything the package controls, then the machine's own directories.

    Order is the whole point: the package's base, artifacts and the
    application's own directory come first, so appending the machine's library
    directories can never shadow a file the package ships -- it only lets a
    dependency the package left on the machine be found.  Whatever the loader
    picks is still checked against the Manifest by hash.
    """

    ordered: list[str] = []
    for candidate in (
        str(root / PACKAGE_MODULE_DIR),
        str(root / "artifacts"),
        str(root / "artifacts" / "runtime"),
        str(program.parent),
        *_machine_library_paths(),
    ):
        if candidate not in ordered:
            ordered.append(candidate)
    return tuple(ordered)


def _module_path(root: Path, module) -> Path | None:
    if getattr(module, "delivery", "package") == "package":
        return root / PACKAGE_MODULE_DIR / module.runtime_name
    return None


def _require_file(path: Path, what: str) -> Path:
    if not path.is_file() or path.is_symlink():
        raise LaunchError(f"{what} is missing or not a regular file: {path}")
    return path


def _resolve_main(program: Path, manifest, root: Path):
    """Check that *program* really is the main module this Workspace describes.

    The main module is the one file the package does not deliver, so nothing
    but this check ties the Workspace to the file it was prepared for.  Both
    launching and registering need it: registration announces an inode, and
    announcing the wrong one is worse than refusing.
    """

    main = next(
        (module for module in manifest.modules if module.role == "main"), None
    )
    if main is None:
        raise LaunchError(f"{root} publishes no main module")
    if getattr(main, "delivery", "package") != "target":
        raise LaunchError(
            "the main module must be resolved on the target machine; this "
            "Workspace packages it, which is not a supported layout"
        )
    if program.name != main.runtime_name:
        raise LaunchError(
            f"{program} is not the application this Workspace was prepared "
            f"for ({main.runtime_name})"
        )
    if sha256(program.read_bytes()).hexdigest() != main.sha256:
        raise LaunchError(
            f"{program} does not match the file this Workspace was prepared "
            "from; re-run prepare or install the recorded build"
        )
    return main


def _select_loader(root: Path, program: Path, manifest) -> Path:
    """Pick the loader the Manifest ships for this program.

    The program's own ``PT_INTERP`` names a loader that lives on *this* machine
    and is paired with *this* machine's libc; using it to load the package's
    libc would combine two builds nobody verified together.  So the name only
    selects among the modules the package delivers (D10-alpha).
    """

    declared = interpreter(program)
    if not declared:
        raise LaunchError(f"{program} has no PT_INTERP; it cannot be launched")
    basename = Path(declared).name
    for module in manifest.modules:
        if module.runtime_name != basename:
            continue
        if getattr(module, "delivery", "package") != "package":
            raise LaunchError(
                f"loader {basename} is not delivered by the Workspace; "
                "the package loader must be used with the package libc"
            )
        return _require_file(
            root / PACKAGE_MODULE_DIR / basename, "package loader"
        )
    raise LaunchError(
        f"Workspace does not deliver the loader {basename} that {program} needs"
    )


def _run_loader(
    loader: Path, arguments: Sequence[str]
) -> tuple[int, str, str]:
    """Run the loader and return ``(status, stdout, stderr)``.

    The loader writes its *reasons* to stderr -- an unresolvable library, a
    wrong architecture, an unreadable file.  Dropping them turns every failure
    into an opaque exit status, so they are returned rather than discarded.
    """

    try:
        completed = subprocess.run(
            [str(loader), *arguments],
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError as error:
        raise LaunchError(f"cannot execute the package loader: {error}") from error
    return completed.returncode, completed.stdout, completed.stderr


def _why(stderr: str) -> str:
    """Render the loader's stderr as a suffix for a failure message."""

    lines = [line.strip() for line in stderr.splitlines() if line.strip()]
    if not lines:
        return ""
    if len(lines) == 1:
        return f" -- {lines[0]}"
    return " -- " + "; ".join(lines[:3]) + ("; ..." if len(lines) > 3 else "")


def resolved_module_paths(
    loader: Path,
    program: Path,
    library_paths: Sequence[str],
    manifest,
) -> dict[str, Path]:
    """Ask the loader where each Manifest **dependency** actually lives.

    Only modules the loader reports are returned; a module it never mentions
    stays unresolved rather than being guessed from a search path.

    The main module is deliberately *not* here: ``--list`` lists dependencies
    only, never the program it was asked about.  Callers add it themselves
    from the path they were handed (see :func:`with_main_module`).
    """

    search = os.pathsep.join(library_paths)
    common = ("--library-path", search, str(program))
    code, output, errors = _run_loader(loader, ("--list", *common))
    if code != 0:
        raise LaunchError(
            f"package loader could not resolve {program} "
            f"(--list exit {code}){_why(errors)}\n"
            f"  searched: {search}"
        )
    try:
        loaded = parse_loader_list(output)
    except LoaderReportError as error:
        raise LaunchError(str(error)) from error
    by_name = {module.runtime_name: module for module in manifest.modules}
    resolved: dict[str, Path] = {}
    for item in loaded:
        if item.path is None:
            continue
        module = by_name.get(item.name)
        if module is None:
            if leaf_artifacts(manifest):
                raise LaunchError("unrecorded loaded module under scalar leaf contracts: " + str(item.path))
            # Not a recorded module -- the preloaded runtime, for one.  There
            # is nothing in the Manifest to key it by.
            continue
        resolved[module.module_id] = item.path
    return resolved


def with_main_module(
    resolved: dict[str, Path], program: Path, main
) -> dict[str, Path]:
    """Add the main module to a resolution.

    ``--list`` never names the program, so the main module has to come from the
    path the caller was handed.  It is safe to add unconditionally here because
    :func:`_resolve_main` already proved that path is the recorded main module.
    """

    return {**resolved, main.module_id: program}


def _precheck(
    loader: Path, program: Path, library_paths: Sequence[str], manifest, root: Path,
    main,
) -> dict[str, Path]:
    """Ask the loader what it will load, and check every answer by hash.

    This is the only place the package can still be wrong: ``--library-path``
    does not guarantee a library comes from a directory we listed
    (``DT_RPATH`` outranks it), and the application's own dependencies are
    resolved from this machine.  Hashing what the loader reports turns both
    into a detectable failure instead of a silently different file.

    Two calls, never one: ``--verify`` and ``--list`` are separate modes in the
    loader, and combining them silently drops one of the two checks.
    """

    search = os.pathsep.join(library_paths)
    code, _, errors = _run_loader(
        loader, ("--verify", "--library-path", search, str(program))
    )
    if code not in (0, 2):
        raise LaunchError(
            f"package loader rejects {program} "
            f"(--verify exit {code}){_why(errors)}"
        )
    resolved = with_main_module(
        resolved_module_paths(loader, program, library_paths, manifest),
        program,
        main,
    )
    expected = {module.module_id: module for module in manifest.modules}
    for module_id, path in sorted(resolved.items()):
        module = expected[module_id]
        actual = sha256(path.read_bytes()).hexdigest()
        if actual != module.sha256:
            raise LaunchError(
                f"module {module.runtime_name} resolves to {path}, whose "
                "content does not match the Manifest; refusing to launch"
            )
    if not resolved:
        raise LaunchError(
            "loader reported no module the Manifest describes; refusing to "
            f"launch {program} from {root}"
        )
    return resolved


@monitored(
    "runtime.run.prepare",
    variables=(
        argument("workspace"),
        argument("input_elf", label="input_elf"),
        argument("arguments", label="application_args"),
        returned(label="program", path=("program",)),
        returned(label="loader", path=("loader",)),
        returned(label="argv", path=("argv",)),
        returned(label="library_path", path=("library_paths",)),
        returned(
            label="workspace_environment",
            path=("environment", "CHIMERA_WORKSPACE"),
        ),
        returned(label="preload", path=("environment", "LD_PRELOAD")),
    ),
)
def prepare_launch(
    workspace: Path,
    input_elf: Path,
    arguments: Sequence[str],
    settings: BaseConfig,
    *,
    verify: bool = True,
) -> LaunchRequest:
    """Resolve everything a launch needs without executing the application."""

    root = Path(workspace).resolve()
    program = Path(input_elf).resolve()
    if not program.is_file():
        raise LaunchError(f"application does not exist: {program}")
    manifest = (
        verify_workspace(root, settings)
        if verify
        else read_manifest(root / "artifacts" / "modules.tsv", workspace_root=root)
    )
    main = _resolve_main(program, manifest, root)

    try:
        reject_leaf_interposers(manifest)
    except ValueError as error:
        raise LaunchError(str(error)) from error

    loader = _select_loader(root, program, manifest)
    library_paths = _search_paths(root, program)
    key = (
        manifest.target_os, manifest.target_arch,
        manifest.target_arch_extension, manifest.runtime_scene,
    )
    environment = registered_launch_adapters().select(key).environment(
        root, manifest
    )
    resolved = _precheck(loader, program, library_paths, manifest, root, main)
    try:
        if validate_leaf_launch(root, manifest, resolved):
            # Bind ordinary GOT slots before application callbacks/dlopen.
            environment["LD_BIND_NOW"] = "1"
    except (OSError, ValueError, KeyError) as error:
        raise LaunchError(str(error)) from error
    argv = (str(program), *arguments)
    return LaunchRequest(
        loader, program, argv, library_paths, resolved, environment
    )


@monitored(
    "runtime.run.resolve",
    variables=(
        argument("workspace"),
        argument("input_elf", label="input_elf"),
        returned(label="manifest", path=("manifest",)),
        returned(label="resolved", path=("resolved",), transform=len),
    ),
)
def resolve_modules(
    workspace: Path,
    input_elf: Path,
    settings: BaseConfig,
    *,
    verify: bool = True,
) -> "ResolvedModules":
    """Return the Manifest and where each module resolves on this machine.

    Registration needs the same answer the launcher needs -- which file on this
    machine is the module the Manifest describes -- so both go through the
    loader instead of through two different guesses.
    """

    root = Path(workspace).resolve()
    program = Path(input_elf).resolve()
    if not program.is_file():
        raise LaunchError(f"application does not exist: {program}")
    manifest = (
        verify_workspace(root, settings)
        if verify
        else read_manifest(root / "artifacts" / "modules.tsv", workspace_root=root)
    )
    # Registration announces inodes, so it needs the same identity proof the
    # launcher has: without it, any ELF could be registered against any
    # Workspace and the kernel would be told the wrong file is migratable.
    main = _resolve_main(program, manifest, root)
    try:
        reject_leaf_interposers(manifest)
    except ValueError as error:
        raise LaunchError(str(error)) from error
    loader = _select_loader(root, program, manifest)
    paths = _search_paths(root, program)
    resolved = with_main_module(resolved_module_paths(loader, program, paths, manifest), program, main)
    try:
        validate_leaf_launch(root, manifest, resolved)
    except (OSError, ValueError, KeyError) as error:
        raise LaunchError(str(error)) from error
    return ResolvedModules(manifest=manifest, resolved=resolved)


@monitored(
    "runtime.run.exec",
    variables=(
        argument("request", label="loader", path=("loader",)),
        argument("request", label="program", path=("program",)),
        argument("request", label="argv", path=("argv",)),
    ),
)
def _execve(request: LaunchRequest) -> NoReturn:
    command = [
        str(request.loader),
        "--library-path",
        os.pathsep.join(request.library_paths),
        *request.argv,
    ]
    os.execve(str(request.loader), command, request.environment)
    raise AssertionError("os.execve returned unexpectedly")


def launch(
    workspace: Path,
    input_elf: Path,
    arguments: Sequence[str],
    settings: BaseConfig,
    *,
    verify: bool = True,
) -> NoReturn:
    _execve(
        prepare_launch(workspace, input_elf, arguments, settings, verify=verify)
    )


__all__ = [
    "LaunchError",
    "LaunchRequest",
    "ResolvedModules",
    "launch",
    "prepare_launch",
    "resolve_modules",
]
