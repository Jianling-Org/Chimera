"""Unified Chimera lifecycle command."""

from __future__ import annotations

import argparse
from dataclasses import replace
import os
from pathlib import Path
import shutil
import sys

from chimera import __version__
from chimera.preprocess.offline.analysis_profile import (
    PreparePipeline,
    RebuildPipeline,
    build_check_plan,
    build_execution_plan,
    check_admission,
)
from chimera.preprocess.offline.config import load_configuration, load_toml
from chimera.preprocess.offline.analysis.core.workspace import (
    WorkspaceError,
    WorkspaceRepository,
    read_workspace_metadata,
    resolve_clean_target,
    resolve_workspace_by_elf,
    resolve_workspace_reference,
    resolve_workspace_id,
)
from chimera.preprocess.offline.analysis.prepare_workspace.selection import (
    prepare_input_fingerprint,
    select_modules,
    target_label,
)
from chimera.preprocess.offline.analysis.core.monitor import monitoring
from chimera.runtime.bpf import register_workspace
from chimera.runtime.launcher import (
    launch, registered_migration_adapters, resolve_modules,
)
from chimera.runtime.manifest import read_manifest
from chimera.runtime.validate import verify_workspace
from chimera.toolchain import (
    ALL_PLUGINS,
    build_llvm_plugin,
    build_patched_llvm,
    clean_patched_llvm,
    build_svf,
    resolve_build_root,
    resolve_llvm_src,
    resolve_svf_src,
    toolchain_build_root,
    svf_build_dir,
    plugin_build_dir,
    toolchain_source_root,
)
from .check_elf import (
    DEFAULT_TEXT_THRESHOLD,
    now_stamp,
    write_check_report,
    write_latest_pointer,
)
from .elf_state import (
    CHECKED,
    PROBLEMATIC,
    REMEDIATED,
    UNCHECKED,
    ElfStateRegistry,
    sha256_of,
)
from .llvm_wrapper import run_llvm_wrapper
from .user_config import load_user_settings
from .workspace import (
    install_workspace,
    pack_workspace,
    verify_workspace_installation,
)


def _default_workspace_root() -> Path:
    # Keep the lexical path until an operation performs its own symlink and
    # boundary checks.  Resolving here would hide a symlink supplied through
    # CHIMERA_WORKSPACE_ROOT from workspace install/clean validation.
    return Path(os.environ.get(
        "CHIMERA_WORKSPACE_ROOT",
        str(Path.home() / ".chimera" / "workspaces"),
    )).expanduser()



def _runtime_workspace_root() -> Path:
    """Use the runtime settings root when present, otherwise the shared default."""
    if os.environ.get("CHIMERA_WORKSPACE_ROOT"):
        return _default_workspace_root()
    try:
        return load_user_settings().workspace_root.resolve()
    except (OSError, RuntimeError, ValueError):
        return _default_workspace_root()


def _workspace_cleanup_root(value: str | Path | None) -> Path:
    """Resolve a cleanup root without following a user supplied symlink."""
    raw = (
        Path(value).expanduser()
        if value is not None
        else Path(os.environ.get(
            "CHIMERA_WORKSPACE_ROOT",
            str(Path.home() / ".chimera" / "workspaces"),
        )).expanduser()
    )
    # Check lexical components before resolving.  Iterating ``raw.parents``
    # alone misses a symlink hidden before a ``..`` component (``link/../x``).
    candidate = raw if raw.is_absolute() else Path.cwd() / raw
    current = Path(candidate.anchor)
    for component in candidate.parts:
        if component == candidate.anchor or component == ".":
            continue
        if component == "..":
            if current.is_symlink():
                raise WorkspaceError(f"Workspace root contains a symlink: {current}")
            current = current.parent
            continue
        current = current / component
        if current.is_symlink():
            raise WorkspaceError(f"Workspace root contains a symlink: {current}")
    root = raw.resolve()
    protected = {
        Path(root.anchor).resolve(),
        Path.home().resolve(),
        Path.cwd().resolve(),
    }
    if root in protected:
        raise WorkspaceError(f"refusing to clean unsafe Workspace root: {root}")
    return root


def _validate_cleanup_tree(root: Path) -> None:
    """Reject links anywhere in a tree before a destructive cleanup.

    ``shutil.rmtree`` does not follow directory links, but accepting a link
    inside a managed Workspace would still make the cleanup contract depend
    on the platform's traversal details.  Validate the complete tree first so
    a failed boundary check never results in a partially cleaned root.
    """
    if not root.exists():
        return
    if root.is_symlink():
        raise WorkspaceError(f"cleanup root is a symlink: {root}")
    if not root.is_dir():
        raise WorkspaceError(f"cleanup root is not a directory: {root}")
    for current, directories, files in os.walk(root, followlinks=False):
        current_path = Path(current)
        for name in (*directories, *files):
            path = current_path / name
            if path.is_symlink():
                raise WorkspaceError(
                    f"cleanup tree contains a symlink: {path.relative_to(root)}"
                )


_COMMAND_GROUPS = {
    "dev": {"rebuild", "toolchain", "wheel"},
    "pkg": {"check-elf", "prepare", "llvm", "workspace", "status", "build-bundle"},
    "user": {"list", "verify", "register", "run", "migrate"},
}


# Public parser for the three role-specific entry points.
def build_parser(command_group: str | None = None, *, prog: str | None = None) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog=prog or "chimera")

    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("--debug", action="store_true", help="输出离线和运行时诊断")
    commands = parser.add_subparsers(dest="command", required=True)

    def profile_arg(command, *, required=True):
        command.add_argument("--profile", type=Path, required=required,
                             help="应用配置及 workflow 的 TOML 文件")

    prepare = commands.add_parser("prepare", help="根据应用 Profile 构建 Workspace")
    profile_arg(prepare)
    prepare.add_argument("--input", type=Path, required=True, dest="input_elf")
    prepare.add_argument("--workspace")
    prepare.add_argument("--workspace-root", type=Path)
    prepare.add_argument("--allow-problematic", action="store_true")

    check_elf = commands.add_parser("check-elf", help="检查 ELF 并生成编译决策")
    profile_arg(check_elf)
    check_elf.add_argument(
        "--input", type=Path, required=True, action="append", dest="input_elf",
        help="待检查的 ELF；可重复指定，按顺序检查同一项目的多个产物",
    )
    check_elf.add_argument("--strategy", choices=("auto", "gate", "svf"), default="auto")
    check_elf.add_argument("--min-vlen-bits", type=int, default=None)
    check_elf.add_argument("--text-threshold", type=int, default=DEFAULT_TEXT_THRESHOLD)
    check_elf.add_argument("--objdump")
    check_elf.add_argument("--json", type=Path, help="单输入的报告文件，或多输入的报告目录")
    check_elf.add_argument(
        "--inheritance-report",
        type=Path,
        default=None,
        metavar="PATH",
        help="单输入的继承报告文件，或多输入的报告目录（复用分析结果）",
    )
    check_elf.add_argument("--strict", action="store_true")
    check_elf.add_argument(
        "--rebuild-stage", choices=("metadata", "gate"),
        help="生成下一轮编译入口：metadata 仅插桩；gate 保留插桩并应用名单",
    )
    check_elf.add_argument(
        "--rebuild-dir", type=Path,
        help="新的编译计划目录；全部检查正常完成后发布 cc/cxx，不覆盖现有目录",
    )

    status = commands.add_parser("status", help="查询 ELF 检查状态")
    status.add_argument("--input", type=Path, required=True, dest="input_elf")
    status.add_argument("--profile", type=Path)

    llvm = commands.add_parser("llvm", help="调用带 Chimera 插件的 LLVM 编译器")
    llvm.add_argument("--cxx", action="store_true")
    llvm_decision = llvm.add_mutually_exclusive_group()
    llvm_decision.add_argument("--list", type=Path, dest="list_path")
    llvm_decision.add_argument("--build-plan", type=Path, help="消费固定的 Chimera 编译计划")
    llvm.add_argument("--no-gate", action="store_true")
    llvm.add_argument("--registry", type=Path)
    llvm.add_argument("llvm_params", nargs=argparse.REMAINDER)

    bundle = commands.add_parser("build-bundle", help="打包或解包 ELF 构建脚本与说明")
    bundle_commands = bundle.add_subparsers(dest="bundle_action", required=True)
    bundle_pack = bundle_commands.add_parser("pack", help="打包指定的 Profile、脚本和使用说明")
    profile_arg(bundle_pack)
    bundle_pack.add_argument("--script", type=Path, required=True)
    bundle_pack.add_argument("--instructions", type=Path, required=True)
    bundle_pack.add_argument("--require-env", action="append", default=[], metavar="NAME[=DESCRIPTION]",
                             help="声明脚本必需的环境变量；可重复指定，不打包变量值")
    bundle_pack.add_argument("--output", type=Path, required=True)
    bundle_unpack = bundle_commands.add_parser("unpack", help="解包到新目录并打印使用说明及环境变量")
    bundle_unpack.add_argument("--input", type=Path, required=True)
    bundle_unpack.add_argument("--output-dir", type=Path, required=True)

    workspace = commands.add_parser("workspace", help="管理 Workspace 交付包")
    workspace_commands = workspace.add_subparsers(dest="workspace_action", required=True)
    pack = workspace_commands.add_parser("pack", help="创建 .workspace 包")
    pack.add_argument("--workspace", required=True)
    pack.add_argument("--output", type=Path, required=True)
    pack.add_argument("--resource", action="append", default=[], metavar="SOURCE=RELATIVE_PATH")
    install = workspace_commands.add_parser("install", help="安装 .workspace 包")
    install.add_argument("--input", type=Path, required=True)
    install.add_argument("--name")
    install.add_argument("--workspace-root", type=Path)
    remove = workspace_commands.add_parser("remove", help="删除指定 Workspace")
    remove.add_argument("--workspace", required=True)
    clean_workspace = workspace_commands.add_parser("clean", help="清空 Workspace 根目录")
    clean_workspace.add_argument("--workspace-root", type=Path)

    list_command = commands.add_parser("list", help="列出已发布 Workspace")
    _ = list_command
    verify = commands.add_parser("verify", help="验证 Workspace 和主机契约")
    verify.add_argument("--workspace", required=True)
    verify.add_argument("--input", type=Path, dest="input_elf")
    register = commands.add_parser("register", help="向内核注册 Workspace")
    register.add_argument("--input", type=Path, required=True, dest="input_elf")
    register.add_argument("--workspace")
    run = commands.add_parser("run", help="以 Workspace 运行指定的应用")
    run.add_argument("--input", type=Path, required=True, dest="input_elf")
    run.add_argument("--workspace")
    run.add_argument("application_args", nargs=argparse.REMAINDER)
    migrate = commands.add_parser("migrate", help="选择线程执行迁移")
    migrate.add_argument(
        "--workspace",
        help="显式指定 Workspace；省略时从目标进程的 CHIMERA_WORKSPACE 获取",
    )
    migrate.add_argument("--parent-thread", type=int)
    migrate.add_argument("--migration-count", type=int)
    migrate.add_argument("--threads", type=int, nargs="+")
    migrate.add_argument(
        "--direction",
        required=True,
        help="由目标 scene 解释的迁移 route",
    )

    rebuild = commands.add_parser("rebuild", help="使用开发测试 Profile 重建 Workspace 步骤")
    profile_arg(rebuild)
    # Keep the input optional at parse time so an installed Workspace produces
    # the actionable "development intermediates are unavailable" error from
    # ``_rebuild`` instead of a generic argparse failure.  Rebuilding still
    # requires the original ELF once execution starts.
    rebuild.add_argument("--input", type=Path, dest="input_elf")
    rebuild.add_argument("--workspace", required=True)
    rebuild.add_argument("--workspace-root", type=Path)
    rebuild.add_argument("--steps", required=True)

    toolchain = commands.add_parser("toolchain", help="构建或清理开发工具链")
    toolchain_commands = toolchain.add_subparsers(dest="toolchain_action", required=True)
    for action in ("build", "clean"):
        target_parser = toolchain_commands.add_parser(action)
        target_parser.add_argument("target", choices=("patched-llvm", "llvm-plugin", "svf"))
        target_parser.add_argument("--llvm-src", type=Path)
        target_parser.add_argument("--build-root", type=Path)
        target_parser.add_argument("--svf-dir", type=Path)
        target_parser.add_argument("--toolchain-build", type=Path)
        target_parser.add_argument("--plugins", nargs="+", choices=("stackobject", "function-pointer", "vector-gate"))
        target_parser.add_argument("--full", action="store_true")
    wheel = commands.add_parser("wheel", help="构建 Chimera 系统 wheel")
    wheel.add_argument("--wheel-dir", type=Path, default=Path("dist"))
    wheel.add_argument("--artifact-root", type=Path)
    wheel.add_argument("--target-os")
    wheel.add_argument("--target-arch")
    wheel.add_argument("--target-extension")
    wheel.add_argument("--scene")

    if command_group is not None:
        if command_group not in _COMMAND_GROUPS:
            raise ValueError(f"unknown command group: {command_group}")
        allowed = _COMMAND_GROUPS[command_group]
        for name in list(commands.choices):
            if name not in allowed:
                del commands.choices[name]
        commands._choices_actions[:] = [a for a in commands._choices_actions if a.dest in allowed]
    return parser


def _selected_profile(arguments: argparse.Namespace) -> Path:
    profile = getattr(arguments, "profile", None)
    if profile is None:
        raise ValueError("--profile is required for this command")
    return Path(profile).expanduser().resolve()


def _base_config(arguments: argparse.Namespace):
    return _configuration(arguments).base


def _prepare_input_fingerprint(plan, input_elf: Path) -> str:
    """Fingerprint the inputs a prepare run would select for *input_elf*.

    The selection rule and the digest live in ``prepare_workspace.selection``,
    so the reuse decision here and the prepare step cannot drift apart.
    """

    base = plan.base
    profile = plan.profile
    modules = select_modules(
        input_elf,
        plan.services.platform.dependencies(
            input_elf, base.target_files.library_roots
        ),
        base.scalar_root,
    )
    return prepare_input_fingerprint(
        input_elf,
        modules,
        target_label(
            profile.target_os,
            profile.target_arch,
            profile.target_arch_extension,
            profile.runtime_scene,
            profile.runtime_abi,
        ),
    )


def _configuration(arguments: argparse.Namespace):
    profile_path = _selected_profile(arguments)
    configuration = load_configuration(profile_path)
    workspace_root = getattr(arguments, "workspace_root", None)
    # ``config.workspace_root`` belonged to the old system-profile based
    # layout. It is no longer an output selector; report the migration
    # whenever the legacy field is present, including ``status --profile``.
    # Profiles that omit it stay quiet, and an explicit command-line root
    # always wins.
    try:
        config_table = load_toml(profile_path).get("config", {})
    except (OSError, ValueError, TypeError):
        config_table = {}
    if isinstance(config_table, dict) and "workspace_root" in config_table:
        print(
            "warning: Profile 中的 config.workspace_root 已忽略；"
            "请在 prepare 中使用 --workspace-root 指定 Workspace 根目录",
            file=sys.stderr,
        )
    if getattr(arguments, "command", None) in {"prepare", "rebuild", "check-elf"}:
        if workspace_root is None:
            workspace_root = _default_workspace_root()
    if workspace_root is None:
        return configuration
    base = replace(
        configuration.base,
        workspace_root=Path(workspace_root).expanduser().resolve(),
    )
    return replace(configuration, base=base)


def _thread_group(tid: int) -> tuple[int, list[int]]:
    status = Path("/proc") / str(tid) / "status"
    if tid <= 0 or not status.is_file():
        raise FileNotFoundError(f"thread does not exist: {tid}")
    values = dict(
        line.split(":", 1)
        for line in status.read_text(encoding="utf-8").splitlines()
        if ":" in line
    )
    tgid = int(values["Tgid"].strip())
    task_root = Path("/proc") / str(tgid) / "task"
    return tgid, sorted(
        int(path.name) for path in task_root.iterdir() if path.name.isdigit()
    )


def _select_migration_tids(
    available: list[int], main_tid: int, count: int
) -> list[int]:
    """Pick up to ``count`` tids from the tail (newest first), skipping the
    thread-group leader unless forced.

    tid 按创建序递增：组内低 tid 是运行时早期诞生的辅助线程（注入/分词
    辅助），常驻睡眠态——对它们发起迁移会先进入翻译态，而反向迁移又会
    在其翻译态中再次迁移（翻译态不允许迁移）。因此从尾部（最新的计算
    worker 波）往前选。主线程仅在 count 超过非主线程数时兜底纳入。
    """

    non_main = sorted(tid for tid in available if tid != main_tid)
    if count <= len(non_main):
        return non_main[-count:]
    extra = count - 1
    tail = non_main[-extra:] if extra > 0 else []
    return [main_tid, *tail]


def _process_workspace(tgid: int, settings) -> Path:
    """Read the Workspace selected at launch from the target group's environment.

    Never use this command's environment or cwd as the target's configuration.
    A missing/unreadable/ambiguous launch identity needs an explicit argument.
    """
    environment_path = Path("/proc") / str(tgid) / "environ"
    hint = "supply --workspace with the Workspace used to launch this process"
    try:
        environment = environment_path.read_bytes()
    except OSError as error:
        raise RuntimeError(
            f"cannot read process {tgid} environment: {environment_path}; {hint}"
        ) from error
    prefix = b"CHIMERA_WORKSPACE="
    values = [
        item[len(prefix):]
        for item in environment.split(b"\0") if item.startswith(prefix)
    ]
    if len(values) != 1 or not values[0]:
        raise ValueError(
            f"process {tgid} has no unique non-empty CHIMERA_WORKSPACE; {hint}"
        )
    reference = Path(os.fsdecode(values[0]))
    if not reference.is_absolute():
        raise ValueError(f"process {tgid} CHIMERA_WORKSPACE is not absolute; {hint}")
    return resolve_workspace_reference(settings.workspace_root.resolve(), reference)


def _migrate(arguments: argparse.Namespace, settings, *, workspace=None) -> int:
    parent_mode = (
        arguments.parent_thread is not None or arguments.migration_count is not None
    )
    if parent_mode and arguments.threads:
        raise ValueError(
            "--threads cannot be combined with --parent-thread/--migration-count"
        )
    if parent_mode:
        if (
            arguments.parent_thread is None
            or arguments.migration_count is None
            or arguments.migration_count <= 0
        ):
            raise ValueError(
                "--parent-thread and positive --migration-count must be supplied together"
            )
        tgid, available = _thread_group(arguments.parent_thread)
        selected = _select_migration_tids(
            available, tgid, arguments.migration_count
        )
    else:

        if not arguments.threads:
            raise ValueError(
                "supply --threads or --parent-thread with --migration-count"
            )
        selected = arguments.threads
        groups = {_thread_group(tid)[0] for tid in selected}
        if len(groups) != 1:
            raise ValueError("all --threads values must belong to one thread group")
        tgid = next(iter(groups))
    control = settings.runtime.ai_thread_control
    if not control.exists():
        raise FileNotFoundError(f"migration control is missing: {control}")

    if workspace is None:
        workspace = (
            _workspace(arguments, settings)
            if getattr(arguments, "workspace", None)
            else _process_workspace(tgid, settings)
        )
    verify_workspace_installation(workspace)
    manifest = read_manifest(
        Path(workspace) / "artifacts" / "modules.tsv",
        workspace_root=workspace,
    )
    key = (
        manifest.target_os, manifest.target_arch,
        manifest.target_arch_extension, manifest.runtime_scene,
    )
    adapter = registered_migration_adapters().select(key)
    requests = [(tid, adapter.encode(arguments.direction, tid)) for tid in selected]
    # Validate the whole selection before the first control write. Launch's
    # PID and Workspace environment precede Runtime signal installation.
    adapter.require_ready(tgid, selected, proc_root=Path("/proc"))
    for _tid, value in requests:
        control.write_text(f"{value}\n", encoding="ascii")
    print(f"selected_threads={len(selected)}")
    origin = (
        f"tgid={arguments.parent_thread}"
        if arguments.parent_thread is not None
        else "--threads"
    )
    print(
        f"migrated_tids[{arguments.direction}] via {origin}: "
        + " ".join(str(value) for _tid, value in sorted(requests))
    )
    return 0


def _workspace(arguments: argparse.Namespace, settings) -> Path:
    reference = getattr(arguments, "workspace", None)
    if reference:
        return resolve_workspace_reference(settings.workspace_root.resolve(), reference)
    input_elf = getattr(arguments, "input_elf", None)
    if input_elf is None:
        raise ValueError("--workspace is required")
    return resolve_workspace_by_elf(settings.workspace_root.resolve(), input_elf)


def _rebuild(arguments: argparse.Namespace, settings) -> int:
    steps = {name.strip() for name in arguments.steps.split(",") if name.strip()}
    if not steps:
        raise ValueError("no steps supplied to --rebuild")
    if "prepare-workspace" in steps:
        raise ValueError(
            "prepare-workspace cannot be re-run: it copies the input ELF into the "
            "workspace local copy and establishes its content identity"
        )
    configuration = _configuration(arguments)
    # Admission must happen before reopening the workspace: ``reopen``
    # allocates staging state and must not let a newly added or changed Safety
    # requirement bypass its binary preflight.
    check_plan = build_check_plan(configuration)
    if not arguments.input_elf:
        raise ValueError(
            "rebuild requires --input on the build machine; installed Workspace "
            "does not contain development intermediates"
        )
    check_admission(Path(arguments.input_elf), check_plan)
    workspace_path = _workspace(arguments, settings)
    repository = WorkspaceRepository(settings.workspace_root.resolve())
    session = repository.reopen(workspace_path)
    try:
        plan = build_execution_plan(configuration)
        pipeline = RebuildPipeline(plan)
        execution_plan = pipeline.make_rebuild_plan(steps, session=session)
        print("rebuild execution: " + ", ".join(execution_plan.execution))
        published = pipeline.prepare(
            arguments.input_elf,
            session=session, steps=steps,
            execution_plan=execution_plan,
        )
    except BaseException:
        # The reopened session owns a staging tree with hard links only for
        # Manifest module inputs; clean it if plan construction fails before
        # RebuildPipeline can take over cleanup.
        session.abort()
        raise
    print(published)
    return 0


def _list(settings) -> int:
    root = settings.workspace_root.resolve()
    if not root.is_dir():
        return 0
    records = []
    for child in root.iterdir():

        if child.is_dir() and not child.name.startswith("."):
            metadata = read_workspace_metadata(child)
            records.append(metadata)
    for metadata in sorted(records, key=lambda item: item.created_at, reverse=True):
        print(
            f"{Path(metadata.input_elf_name).stem}\t{metadata.workspace_id}\t"
            f"{metadata.created_at}\t{metadata.input_elf_name}"
        )
    return 0


def _check_elf_outputs(arguments, inputs, rebuild_dir):
    """Resolve all output paths before an analysis can overwrite an input."""
    multiple = len(inputs) > 1
    protected = set(inputs)
    profile = getattr(arguments, "profile", None)
    if profile is not None:
        protected.add(Path(profile).expanduser().resolve())
    outputs = []
    used = set()
    reserved = {
        rebuild_dir / name
        for name in ("cc", "cxx", "decision.json", "build-plan.json", "profile.snapshot.toml")
    } if rebuild_dir is not None else set()
    for index, elf in enumerate(inputs, 1):
        label = f"{index:04d}-{elf.name}"
        json_option = getattr(arguments, "json", None)
        inheritance_option = getattr(arguments, "inheritance_report", None)
        if json_option is not None:
            report = Path(json_option).expanduser()
            if multiple:
                if report.exists() and not report.is_dir():
                    raise ValueError("multiple --input values require --json to name a directory")
                report /= label + ".check.json"
        elif rebuild_dir is not None:
            report = rebuild_dir / "reports" / (label + ".check.json")
        else:
            report = Path(str(elf) + ".check.json")
        if inheritance_option is not None:
            inheritance = Path(inheritance_option).expanduser()
            if multiple:
                if inheritance.exists() and not inheritance.is_dir():
                    raise ValueError("multiple --input values require --inheritance-report to name a directory")
                inheritance /= label + ".inheritance.json"
        elif rebuild_dir is not None:
            inheritance = rebuild_dir / "reports" / (label + ".inheritance.json")
        else:
            inheritance = None
        resolved = []
        for path in (report, inheritance):
            if path is None:
                resolved.append(None)
                continue
            path = path.resolve()
            # Both report exporters atomically replace a .tmp sibling. That
            # intermediate file must not alias another output or an input.
            for write_path in (path, path.with_suffix(path.suffix + ".tmp").resolve()):
                if write_path in protected or any(
                    write_path.exists() and write_path.samefile(source) for source in protected
                ):
                    raise ValueError(f"check output would overwrite an input or profile: {write_path}")
                if write_path in used or write_path == rebuild_dir or any(
                    write_path in other.parents or other in write_path.parents for other in used
                ):
                    raise ValueError(f"check output paths collide: {write_path}")
                if write_path in reserved or any(owned in write_path.parents for owned in reserved) or (
                    rebuild_dir is not None and write_path == rebuild_dir / "reports"
                ):
                    raise ValueError(f"check output uses a reserved compiler plan path: {write_path}")
                if write_path.is_dir():
                    raise ValueError(f"check output must be a file: {write_path}")
                used.add(write_path)
            resolved.append(path)
        outputs.append(tuple(resolved))
    return outputs


def _check_elf(arguments: argparse.Namespace) -> int:
    """Check inputs sequentially; publish a compiler plan only after success."""
    raw_inputs = arguments.input_elf
    if not isinstance(raw_inputs, (tuple, list)):
        raw_inputs = [raw_inputs]  # compatibility for programmatic callers
    inputs = [Path(path).expanduser().resolve() for path in raw_inputs]
    if not inputs or len(set(inputs)) != len(inputs):
        raise ValueError("--input must contain distinct ELF paths")
    for elf in inputs:
        if not elf.is_file():
            raise FileNotFoundError(f"input ELF does not exist: {elf}")
    stage = getattr(arguments, "rebuild_stage", None)
    raw_dir = getattr(arguments, "rebuild_dir", None)
    if bool(stage) != (raw_dir is not None):
        raise ValueError("--rebuild-stage and --rebuild-dir must be supplied together")
    rebuild_dir = None
    if raw_dir is not None:
        raw_dir = Path(raw_dir).expanduser()
        if raw_dir.exists() or raw_dir.is_symlink():
            raise ValueError(f"rebuild directory already exists; choose a new directory: {raw_dir}")
        rebuild_dir = raw_dir.resolve()
    outputs = _check_elf_outputs(arguments, inputs, rebuild_dir)
    profile = getattr(arguments, "profile", None)
    if profile is not None:
        profile = Path(profile).expanduser().resolve()
    profile_hash = sha256_of(profile) if rebuild_dir is not None else None
    configuration = _configuration(arguments)
    if rebuild_dir is not None and sha256_of(profile) != profile_hash:
        raise RuntimeError("profile changed while loading configuration; re-run with a fixed profile")
    plan = build_check_plan(configuration)
    if rebuild_dir is not None and not plan.requests:
        raise ValueError("cannot publish compiler entries without workflow binary checks")
    # ``--min-vlen-bits`` predates workflow declarations.  It remains a
    # compatibility check, but may not silently create a credential whose
    # Safety assumptions differ from the workflow that prepare will run.
    if arguments.min_vlen_bits is not None:
        for request in plan.requests:
            if "min_vlen_bits" not in request.parameters:
                continue
            step_value = request.parameters.get("min_vlen_bits")
            if step_value is not None and arguments.min_vlen_bits != step_value:
                raise ValueError(
                    "--min-vlen-bits does not match the Safety workflow step: "
                    f"override={arguments.min_vlen_bits}, step={step_value}"
                )
    if rebuild_dir is not None:
        rebuild_dir.mkdir(parents=True, exist_ok=False)
    reports = []
    all_passed = True
    try:
        for elf, (report, inheritance) in zip(inputs, outputs):
            single = argparse.Namespace(**vars(arguments))
            single.input_elf = elf
            single.json = report
            single.inheritance_report = inheritance
            passed, report_path = _check_elf_one(single, configuration, plan)
            all_passed = all_passed and passed
            reports.append(report_path)
        if rebuild_dir is not None:
            if sha256_of(profile) != profile_hash:
                raise RuntimeError("profile changed during check-elf; re-run with a fixed profile")
            from .compiler_plan import publish_rebuild_plan

            manifest = publish_rebuild_plan(
                rebuild_dir, stage=stage, profile=profile, reports=reports,
                launcher=[sys.executable, "-I", "-m", "chimera.pkg"],
                gate_candidate_objdump=(
                    arguments.objdump or configuration.base.tools.objdump
                    if stage == "gate" else None
                ),
            )
            print(f"rebuild plan: {manifest}")
            print(f"C compiler: {rebuild_dir / 'cc'}")
            print(f"C++ compiler: {rebuild_dir / 'cxx'}")
    except BaseException:
        # Keep completed reports; an interrupted batch never publishes entries.
        if rebuild_dir is not None:
            print(f"check-elf incomplete; evidence retained in {rebuild_dir}", file=sys.stderr)
        raise
    return 1 if arguments.strict and not all_passed else 0


def _check_elf_one(arguments, configuration, plan):
    """Save one report and credential without retaining the analysis model."""
    elf_path = Path(arguments.input_elf).resolve()
    content_hash = sha256_of(elf_path)
    objdump = arguments.objdump
    if plan.requests and objdump is None:
        objdump = getattr(
            getattr(getattr(configuration, "base", None), "tools", None),
            "objdump",
            None,
        )
    result = plan.run(
        arguments.input_elf,
        objdump_cmd=objdump,
        overrides={
            "strategy": arguments.strategy,
            "text_threshold": arguments.text_threshold,
            "inheritance_report": getattr(arguments, "inheritance_report", None),
        },
    )
    json_path = (
        arguments.json
        if arguments.json is not None
        else Path(str(arguments.input_elf.resolve()) + ".check.json")
    )
    if sha256_of(elf_path) != content_hash:
        raise RuntimeError(f"input ELF changed during analysis: {elf_path}")
    report_path = write_check_report(
        plan,
        result,
        json_path,
        elf_identity={"path": str(elf_path), "content_sha256": content_hash},
    )

    status = CHECKED if result.passed else PROBLEMATIC
    ElfStateRegistry().set_status(
        elf_path,
        status,
        decision_ref=str(report_path),
        check_fingerprint=plan.fingerprint(content_hash),
        check_scope=plan.scope,
        require_file=True,
    )
    latest_counts = {
        "checks": len(result.outcomes),
        "failed": sum(
            1 for _request, outcome in result.outcomes if not outcome.passed
        ),
    }
    strategy_reason = "workflow:no-binary-checks"
    for _request, outcome in result.outcomes:
        summary = outcome.diagnostics.get("summary")
        if isinstance(summary, dict):
            latest_counts.update(summary)
        if outcome.diagnostics.get("strategy_reason"):
            strategy_reason = outcome.diagnostics["strategy_reason"]
    write_latest_pointer({
        "elf_path": str(elf_path),
        "decision_path": str(report_path),
        "strategy": result.decision.get("strategy", "none"),
        "stack_object": bool(result.decision.get("stack_object_plugin", False)),
        "strategy_reason": strategy_reason,
        "check_scope": plan.scope,
        "check_fingerprint": plan.fingerprint(content_hash),
        "exported_at": now_stamp(),
        "counts": latest_counts,
    })
    if not plan.requests:
        print("chimera-pkg check-elf: current workflow has no binary checks; passed")
    else:
        print(
            "chimera-pkg check-elf: checks="
            + ", ".join(request.check_id for request in plan.requests)
        )
        for request, outcome in result.outcomes:
            print(
                f"chimera-pkg check-elf: {request.check_id}="
                f"{'passed' if outcome.passed else 'failed'}"
                + (f" ({outcome.message})" if outcome.message else "")
            )
    print(f"chimera-pkg check-elf: elf state -> {status}")
    print(f"report: {report_path}")
    return bool(result.passed), report_path


def _elf_status(arguments: argparse.Namespace) -> int:
    registry = ElfStateRegistry()
    resolved = Path(arguments.input_elf).resolve()
    state, record = registry.effective_status(resolved)
    suffix = ""
    if record is not None:
        suffix = f" (updated {record.updated_at})"
        if state == UNCHECKED:
            suffix += "; binary changed since this record"
    print(f"{resolved}: {state}{suffix}")
    # Status is also useful for diagnosing why a valid-looking historical
    # state cannot satisfy the currently selected workflow.  This is a pure
    # declaration check: it never invokes objdump or any analysis tool.
    if getattr(arguments, "profile", None) is None:
        check_plan = None
    else:
        # An explicitly requested Profile is part of the status query; report
        # malformed or missing files instead of silently dropping the check.
        check_plan = build_check_plan(_configuration(arguments))
    if check_plan is not None and check_plan.requests and record is not None:
        if state == UNCHECKED and resolved.is_file():
            if sha256_of(resolved) != record.content_hash:
                print("note: ELF changed since the recorded check")
        elif resolved.is_file() and record.check_fingerprint != check_plan.fingerprint(sha256_of(resolved)):
            print("note: check conditions do not match the selected workflow")
    elif check_plan is not None and check_plan.requests and record is None:
        print("note: selected workflow requires binary checks")
    if state == UNCHECKED and record is None:
        print("hint: run 'chimera-pkg check-elf --profile <PROFILE> --input <ELF>' to analyze it")
    elif state == PROBLEMATIC:
        print("hint: rebuild via 'chimera-pkg llvm' to apply the decision file")
    elif state == REMEDIATED:
        print("note: rebuilt under a decision file but not re-verified")
    return 0


def _build_toolchain(arguments: argparse.Namespace) -> int:
    toolchain_build = toolchain_build_root(arguments.toolchain_build)
    build_root = resolve_build_root(arguments.build_root)
    llvm_prefix = toolchain_build / "llvm"
    if arguments.target != "llvm-plugin" and arguments.plugins is not None:
        raise ValueError("--plugins only applies to the llvm-plugin target")
    if arguments.target == "patched-llvm":
        try:
            llvm_src = resolve_llvm_src(arguments.llvm_src)
        except FileNotFoundError as error:
            raise ValueError(
                f"{error}; pass --llvm-src or set CHIMERA_LLVM_SRC"
            ) from error
        build_patched_llvm(
            llvm_src, llvm_prefix, build_root=build_root, full=arguments.full

        )
    elif arguments.full:
        raise ValueError("--full only applies to the patched-llvm target")
    elif arguments.target == "llvm-plugin":
        selected = (
            tuple(arguments.plugins) if arguments.plugins is not None else ALL_PLUGINS
        )
        build_llvm_plugin(
            llvm_prefix,
            toolchain_build / "svf",
            toolchain_build / "plugins",
            selected,
            build_root=build_root,
        )
    else:
        try:
            svf_src = resolve_svf_src(arguments.svf_dir)
        except FileNotFoundError as error:
            raise ValueError(
                f"{error}; pass --svf-dir or set CHIMERA_SVF_DIR"
            ) from error
        build_svf(
            svf_src, llvm_prefix, toolchain_build / "svf", build_root=build_root
        )
    return 0


def _clean_toolchain(arguments: argparse.Namespace) -> int:
    build_root = resolve_build_root(arguments.build_root)
    if arguments.target == "patched-llvm":
        try:
            llvm_src = resolve_llvm_src(arguments.llvm_src)
        except FileNotFoundError as error:
            raise ValueError(f"{error}; pass --llvm-src or set CHIMERA_LLVM_SRC") from error
        clean_patched_llvm(llvm_src, build_root=build_root)
        return 0
    if arguments.target == "svf":
        try:
            source = resolve_svf_src(arguments.svf_dir)
        except FileNotFoundError:
            source = None
        target = (
            svf_build_dir(build_root, source)
            if source is not None
            else (build_root / "svf" if build_root is not None else None)
        )
    else:
        # An explicit build root fully determines the plugin build tree; do
        # not require the source bundle merely to clean that tree.  The
        # source-local fallback is used only when no build root was supplied.
        if build_root is not None:
            target = build_root / "plugins"
        else:
            source = toolchain_source_root()
            target = plugin_build_dir(None, source)
    if target is not None and target.exists():
        resolved = target.expanduser().resolve()
        if resolved == Path(resolved.anchor) or resolved == Path.home().resolve():
            raise ValueError(f"refusing unsafe toolchain cleanup target: {resolved}")
        shutil.rmtree(resolved)
    return 0


def main(argv: list[str] | None = None, *, command_group: str | None = None,
         prog: str | None = None) -> int:
    parser = build_parser(command_group, prog=prog)
    arguments = parser.parse_args(argv)
    with monitoring(enabled=arguments.debug):
        try:
            if arguments.command == "build-bundle":
                from .build_bundle import (
                    pack_build_bundle, render_build_bundle_usage, unpack_build_bundle,
                )
                if arguments.bundle_action == "pack":
                    print(pack_build_bundle(
                        arguments.profile, arguments.script, arguments.instructions,
                        arguments.output, required_env=arguments.require_env,
                    ))
                else:
                    directory = unpack_build_bundle(arguments.input, arguments.output_dir)
                    print(render_build_bundle_usage(directory))
                return 0
            if arguments.command == "workspace":
                if arguments.workspace_action == "pack":
                    resources = []
                    for item in arguments.resource:
                        if "=" not in item:
                            raise ValueError("--resource must be SOURCE=RELATIVE_PATH")
                        source, relative = item.split("=", 1)
                        if not source or not relative:
                            raise ValueError("--resource must be SOURCE=RELATIVE_PATH")
                        resources.append((source, relative))
                    workspace_ref = Path(arguments.workspace).expanduser()
                    # A single path component is an ID under the shared
                    # default root; paths containing separators are resolved
                    # directly from the caller's working directory.
                    if (
                        not workspace_ref.is_absolute()
                        and len(workspace_ref.parts) == 1
                        and workspace_ref.name not in {".", ".."}
                    ):
                        workspace_ref = _runtime_workspace_root() / workspace_ref
                    print(pack_workspace(workspace_ref, arguments.output, resources=resources))
                    return 0
                if arguments.workspace_action == "install":
                    install_root = arguments.workspace_root or _runtime_workspace_root()
                    print(install_workspace(arguments.input, install_root, name=arguments.name))
                    return 0
                if arguments.workspace_action == "remove":
                    reference = Path(arguments.workspace).expanduser()
                    if (
                        reference.is_absolute()
                        or len(reference.parts) != 1
                        or reference.name in {".", ".."}
                    ):
                        if reference.is_symlink():
                            raise WorkspaceError(f"Workspace target is a symlink: {reference}")
                        root = _workspace_cleanup_root(reference.parent)
                        target = resolve_workspace_reference(root, reference)
                    else:
                        root = _workspace_cleanup_root(_runtime_workspace_root())
                        target = resolve_workspace_reference(root, arguments.workspace)
                    _validate_cleanup_tree(target)
                    shutil.rmtree(resolve_clean_target(root, target))
                    return 0
                if arguments.workspace_action == "clean":
                    root = _workspace_cleanup_root(
                        arguments.workspace_root or _runtime_workspace_root()
                    )
                    if root.exists():
                        _validate_cleanup_tree(root)
                        # Validate every child before deleting any of them so
                        # a symlink or escaping entry cannot leave a partially
                        # cleaned root behind.
                        targets = [
                            resolve_clean_target(root, child)
                            for child in list(root.iterdir())
                        ]
                        for target in targets:
                            if target.is_dir():
                                shutil.rmtree(target)
                            else:
                                target.unlink()
                    return 0
            if arguments.command == "prepare":
                configuration = _configuration(arguments)
                registry = ElfStateRegistry()
                check_plan = build_check_plan(configuration)
                check_admission(
                    Path(arguments.input_elf),
                    check_plan,
                    registry=registry,
                    allow_problematic=arguments.allow_problematic,
                )
                state, _record = registry.effective_status(
                    Path(arguments.input_elf).resolve()
                )
                if check_plan.requests and state == PROBLEMATIC and arguments.allow_problematic:
                    print(
                        "chimera-pkg prepare: note: ELF state is PROBLEMATIC "
                        "(--allow-problematic); preparing a control face "
                        "for comparison runs",
                        file=sys.stderr,
                    )
                plan = build_execution_plan(configuration)
                # 同一 ELF 内容已 prepare 过 → 直接复用既有 Workspace，
                # 不重跑 dump/translate；内容变化时按名刷新陈旧产物。
                workspace_root = Path(plan.base.workspace_root).resolve()
                try:
                    existing = resolve_workspace_by_elf(
                        workspace_root,
                        Path(arguments.input_elf).resolve(),
                    )
                except WorkspaceError:
                    existing = None
                # An explicitly named Workspace may have been copied beside a
                # new input ELF, or be looked up under its own ID.
                if arguments.workspace:
                    try:
                        requested = resolve_workspace_id(workspace_root, arguments.workspace)
                    except WorkspaceError:
                        requested = None
                    if requested is not None and requested.is_dir():
                        existing = requested
                if existing is not None:
                    metadata = None
                    expected_fingerprint = ""
                    try:
                        metadata = read_workspace_metadata(existing)
                        expected_fingerprint = _prepare_input_fingerprint(
                            plan, Path(arguments.input_elf).resolve()
                        )
                    except (OSError, ValueError, WorkspaceError):
                        metadata = None
                    # Reuse needs both halves: the same input identity *and* the
                    # same set of selected inputs.  The input ELF can be
                    # untouched while a dependency or the scalar base changed,
                    # and then the recorded artifacts describe inputs that no
                    # longer exist.
                    if (
                        metadata is not None
                        and metadata.input_fingerprint == expected_fingerprint
                    ):
                        print(f"workspace already prepared, reusing: {existing}")
                        return 0
                    # A Workspace from another format, or one whose inputs
                    # changed, cannot be packaged safely. Remove that stale
                    # publication so one normal prepare rebuilds it.
                    print(f"workspace metadata is stale; re-preparing: {existing}")
                    shutil.rmtree(resolve_clean_target(workspace_root, existing))
                pipeline = PreparePipeline(plan)
                workspace = pipeline.prepare(
                    arguments.input_elf, workspace=arguments.workspace
                )
                print(workspace)
                return 0
            if arguments.command == "toolchain":
                if arguments.toolchain_action == "build":
                    return _build_toolchain(arguments)
                return _clean_toolchain(arguments)
            if arguments.command == "wheel":
                from .release_wheel import main as build_wheel
                wheel_args = ["--wheel-dir", str(arguments.wheel_dir)]
                if arguments.artifact_root:
                    wheel_args += ["--artifact-root", str(arguments.artifact_root)]
                for option, value in (("--target-os", arguments.target_os),
                                      ("--target-arch", arguments.target_arch),
                                      ("--target-extension", arguments.target_extension),
                                      ("--scene", arguments.scene)):
                    if value:
                        wheel_args += [option, value]
                return build_wheel(wheel_args)
            if arguments.command == "check-elf":
                return _check_elf(arguments)
            if arguments.command == "llvm":
                return run_llvm_wrapper(arguments)
            if arguments.command == "status":
                return _elf_status(arguments)
            if command_group == "user":
                settings = load_user_settings()
            elif arguments.command in {"check-elf", "prepare", "rebuild"}:
                settings = _base_config(arguments)
            else:

                settings = load_user_settings()
            if arguments.command == "rebuild":
                return _rebuild(arguments, settings)
            if arguments.command == "list":
                return _list(settings)
            if arguments.command == "verify":
                workspace = _workspace(arguments, settings)
                verify_workspace_installation(workspace)
                verify_workspace(workspace, settings)
                print("workspace verification passed")
                return 0
            if arguments.command == "run":
                application_args = list(arguments.application_args)
                if application_args and application_args[0] == "--":
                    application_args.pop(0)
                workspace = _workspace(arguments, settings)
                verify_workspace_installation(workspace)
                launch(
                    workspace,
                    Path(arguments.input_elf).resolve(),
                    application_args,
                    settings,
                )
                return 0
            if arguments.command == "register":
                workspace = _workspace(arguments, settings)
                verify_workspace_installation(workspace)
                resolved = resolve_modules(
                    workspace, Path(arguments.input_elf).resolve(), settings
                )
                register_workspace(
                    workspace,
                    resolved.manifest,
                    map_path=settings.bpf_map,
                    resolved_paths=resolved.resolved,
                )
                print(f"registered_workspace={workspace.name}")
                return 0
            if arguments.command == "migrate":
                return _migrate(arguments, settings)
            parser.error(f"unsupported command: {arguments.command}")
        except KeyboardInterrupt:
            print(f"{prog or 'chimera'}: interrupted", file=sys.stderr)
            return 130
        except (OSError, RuntimeError, TypeError, ValueError) as error:
            print(f"{prog or 'chimera'}: error: {error}", file=sys.stderr)
            return 2
    return 0


__all__ = ["build_parser", "main"]
