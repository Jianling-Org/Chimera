"""chimera-pkg llvm — decision-driven wrapper around the patched clang.

The wrapper is deliberately policy-free towards the user: there are no
plugin switches.  Everything that should be injected is written by
``chimera-pkg check-elf`` into a decision file referenced from the ELF state
registry; the wrapper applies that decision to matching invocations:

* compile mode (``-c``): optionally add ``-fpass-plugin=ChimeraStackObject.so``;
  when the decision enables the vector gate, also add
  ``-fpass-plugin=ChimeraVectorGate.so`` — under ``-flto`` auto-vectorization
  happens in each TU's pre-link pipeline, so the gate attribute must be
  stamped at compile time (stamping at link time is too late); without
  ``-flto`` this is the only vectorization point, so compile-time stamping
  is complete on its own
* link mode (``-o`` target registered as PROBLEMATIC): load
  ChimeraFunctionPointer.so / ChimeraVectorGate.so and hand the gate list to
  the VectorGate pass via the ``CHIMERA_GATE_LIST`` / ``CHIMERA_GATE_STATS``
  environment variables (lld parses ``-mllvm`` before loading pass plugins,
  so the plugin's cl::opt flags are unusable at link time).  A gate-only
  decision on a non-LTO link is a pure passthrough: LTO is an enabling
  requirement of the SVF/function-pointer route only, and a plain link runs
  no LLVM passes

* probe invocations (``-E``, or a ``conftest.*`` input) get **no** decision at
  all: autoconf judges its header checks by the preprocessor's stderr, so any
  diagnostic printed there turns a present header into a reported "no" (see
  ``_is_probe``)

Everything else is forwarded verbatim to the patched clang.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

from chimera.toolchain import toolchain_build_root
import importlib.resources
from .check_elf import load_latest_pointer
from .elf_state import (
    PROBLEMATIC,
    REMEDIATED,
    ElfStateRegistry,
)


class _Mode:
    COMPILE = "compile"
    LINK = "link"
    PASSTHROUGH = "passthrough"


def _detect_mode(params: list[str]) -> str:
    if any(item in ("-c", "-S", "-E") for item in params):
        return _Mode.COMPILE
    # 一步构建（clang a.c b.c -o app -flto）没有 .o 中间产物，
    # 只要带 -o 且不是纯预处理/汇编输出，就按链接对待。
    if "-o" in params:
        return _Mode.LINK
    return _Mode.PASSTHROUGH


_PROBE_SOURCE_PREFIX = "conftest."


def _is_probe(params: list[str]) -> bool:
    """True for autoconf / config.status probe invocations.

    Probes are not deliverables, and — critically — some of them are judged by
    the *contents of the compiler's stderr*, not by its exit status.
    ``AC_PREPROC_IFELSE`` (which backs every ``AC_CHECK_HEADER`` header test in
    autoconf 2.69) runs ``$CPP conftest.c`` and treats a non-empty
    ``conftest.err`` as failure.

    So an injected diagnostic line is not merely noise there: it silently
    converts a present header into a reported ``no``.  Measured on K3, while
    rebuilding GCC with ``chimera-pkg llvm`` as ``CC``: libiberty's
    ``limits.h`` / ``fcntl.h`` / ``malloc.h`` / ``alloca.h`` probes all logged

        configure:5751: /usr/local/bin/chimera-clang -E  conftest.c
        chimera-pkg llvm: applied decision (mode=compile, flags=2); ...
        configure:5751: $? = 0
        configure:5751: result: no

    while the ``-c`` probes (judged by exit status) passed with the very same
    stderr line.  ``HAVE_LIMITS_H`` / ``HAVE_FCNTL_H`` therefore ended up
    undefined in ``libiberty/config.h`` and the build died with
    ``use of undeclared identifier 'LONG_MIN'`` — a symptom that looks like a
    clang/GCC incompatibility but is entirely ours.

    Probes are detected by shape, because injection frequency must not depend
    on which project is being built: ``-E``, or an input file named
    ``conftest.*`` (autoconf and ``config.status`` always use that name, for
    compile, link and run probes alike).
    """

    if "-E" in params:
        return True
    for item in params:
        if item.startswith("-"):
            continue
        if Path(item).name.startswith(_PROBE_SOURCE_PREFIX):
            return True
    return False


def _output_target(params: list[str]) -> Path | None:
    for index, item in enumerate(params):
        if item == "-o" and index + 1 < len(params):
            return Path(params[index + 1])
        if item.startswith("-o") and len(item) > 2 and item[2] not in "0123456789":
            # -o<path> glued form
            return Path(item[2:])
    return None


def _has_flag(params: list[str], flag: str) -> bool:
    return any(item == flag or item.startswith(flag + "=") for item in params)


def _load_decisions(path: str | None) -> dict:
    if not path:
        return {}
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise RuntimeError(
            f"decision file unreadable: {path} ({error})"
        ) from error
    # 报告 v1 把决策放在 decision（单数）键下；兼容历史的
    # decisions 键与"gate 平铺在顶层"的旧嵌套写法。
    block = data.get("decision")
    if not isinstance(block, dict):
        block = data.get("decisions", {})
    if isinstance(block, dict) and "gate" not in block:
        legacy_gate = data.get("gate")
        if isinstance(legacy_gate, dict):
            block = {**block, "gate": legacy_gate}
    return block if isinstance(block, dict) else {}


def _resolve_decisions(arguments, registry, target: Path | None, mode: str):
    """Return (decisions, decision_path) for this invocation.

    A fixed build plan is authoritative for every invocation (including a
    configure probe); it never falls back to the registry or latest pointer.
    Legacy link mode resolves through the registry entry of the
    output path; compile mode has no output ELF yet, so it falls back to
    the latest check-elf export (explicit --list always wins).
    """

    build_plan = getattr(arguments, "build_plan", None)
    if build_plan is not None:
        if arguments.list_path or arguments.no_gate:
            raise ValueError("--build-plan cannot be combined with --list or --no-gate")
        from .compiler_plan import load_rebuild_plan

        decisions, path = load_rebuild_plan(Path(build_plan).expanduser())
        return decisions, str(path)
    if arguments.list_path:
        path = str(Path(arguments.list_path).expanduser())
        return _load_decisions(path), path
    if mode == _Mode.LINK and target is not None:
        status, record = registry.effective_status(target)
        if record is not None and record.decision_ref:
            # 仅 PROBLEMATIC 注入；CHECKED/REMEDIATED 不重复应用决策。
            if status == PROBLEMATIC:
                return _load_decisions(record.decision_ref), record.decision_ref
            return {}, None
        # 目标尚未登记或已被删除（clean 后重链场景）：回退到最新导出，
        # 且仅当其记录的 elf 路径与当前目标一致时才采用。
        latest = load_latest_pointer()
        if (
            latest
            and latest.get("decision_path")
            and latest.get("elf_path")
            and Path(latest["elf_path"]).resolve() == target.resolve()
        ):
            return _load_decisions(latest["decision_path"]), latest["decision_path"]
        return {}, None
    latest = load_latest_pointer()
    if latest and latest.get("decision_path"):
        return _load_decisions(latest["decision_path"]), latest["decision_path"]
    return {}, None


def _write_gate_names(decision_path: str, decisions: dict) -> Path:
    gate = decisions.get("gate") or {}
    names = sorted(gate.get("names") or [])
    target = Path(decision_path).with_suffix(".gate_names.txt")
    contents = "\n".join(names) + ("\n" if names else "")
    target.parent.mkdir(parents=True, exist_ok=True)

    try:
        if target.read_text(encoding="utf-8") == contents:
            return target
    except OSError:
        pass

    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=target.parent,
            prefix=f".{target.name}.",
            delete=False,
        ) as stream:
            stream.write(contents)
            temporary = Path(stream.name)
        os.replace(temporary, target)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    return target


def _toolchain_paths() -> tuple[Path, Path]:
    explicit = os.environ.get("CHIMERA_TOOLCHAIN_BUILD")
    if explicit:
        root = Path(explicit).expanduser().resolve()
    else:
        try:
            packaged = Path(str(importlib.resources.files("chimera").joinpath("release", "toolchain")))
        except (ModuleNotFoundError, TypeError, ValueError):
            packaged = Path()
        root = packaged if packaged.is_dir() else toolchain_build_root(None)
    bin_dir = root / "llvm" / "bin"
    plugins = root / "plugins" / "lib" / "chimera" / "llvm"
    return bin_dir, plugins


def _inject_vector_gate(decisions, decision_path, gate_env, notes):
    """Shared VectorGate wiring for compile and link modes.

    Writes the gate-names file next to the decision file and points the
    plugin's environment fallback at it.  The build orchestrator owns
    truncation so compile and full-LTO decisions share one complete stream.
    """

    names_path = _write_gate_names(decision_path, decisions)
    stats_path = names_path.with_suffix(".implicit_vector_census.tsv")
    stats_path.parent.mkdir(parents=True, exist_ok=True)
    gate_env["CHIMERA_GATE_LIST"] = str(names_path)
    gate_env["CHIMERA_GATE_STATS"] = str(stats_path)
    names = (decisions.get("gate") or {}).get("names") or []
    notes.append(f"gate list: {len(names)} function(s)")
    return stats_path


def run_llvm_wrapper(arguments) -> int:
    params = list(arguments.llvm_params)
    if params and params[0] == "--":
        params.pop(0)

    mode = _detect_mode(params)
    registry = ElfStateRegistry(arguments.registry)

    target: Path | None = None
    if mode == _Mode.LINK:
        raw_target = _output_target(params)
        if raw_target is not None:
            # 注册表查询用解析后的路径；用户命令行保持原样不动。
            target = raw_target.expanduser().resolve()
    bound_decision = None
    if getattr(arguments, "build_plan", None) is not None:
        # Even a probe must reject a damaged plan; probes still inject nothing.
        bound_decision = _resolve_decisions(arguments, registry, target, mode)
    if _is_probe(params):
        # 探针拿不到决策：既不注入插件，也不碰 stderr（见 _is_probe 的推导）。
        # decisions 为空会让下面所有注入分支与状态转移自动短路。
        decisions: dict = {}
        decision_path: str | None = None
    elif bound_decision is not None:
        decisions, decision_path = bound_decision
    else:
        decisions, decision_path = _resolve_decisions(
            arguments, registry, target, mode
        )

    bin_dir, plugins_dir = _toolchain_paths()
    clang = bin_dir / ("clang++" if arguments.cxx else "clang")
    if not clang.is_file():
        raise FileNotFoundError(
            f"patched clang not found: {clang}; "
            "run 'chimera-dev toolchain build patched-llvm' first"
        )

    stack_object_so = plugins_dir / "ChimeraStackObject.so"
    function_pointer_so = plugins_dir / "ChimeraFunctionPointer.so"
    vector_gate_so = plugins_dir / "ChimeraVectorGate.so"

    injected: list[str] = []
    notes: list[str] = []
    gate_env: dict[str, str] = {}

    if mode == _Mode.COMPILE:
        if decisions.get("stack_object_plugin"):
            if not stack_object_so.is_file():
                raise FileNotFoundError(
                    f"StackObject plugin missing: {stack_object_so}; "
                    "run 'chimera-dev toolchain build llvm-plugin "
                    "--plugins stackobject'"
                )
            if _has_flag(params, "-fpass-plugin"):
                raise ValueError(
                    "refusing to inject StackObject: <llvm_params> already "
                    "contains -fpass-plugin"
                )
            # -fpass-plugin 是 joined-only 选项（只认 = 形式，分离两项
            # 会被 clang 拒收）
            injected += [f"-fpass-plugin={stack_object_so}"]

        # -flto 下向量化发生在每个 TU 的编译期（pre-link 管线含 Loop/SLP
        # 向量化器），链接期再打属性为时已晚——门控必须在编译期注入，
        # 让 GateMarkPass 在 per-TU PipelineStartEP 打上 chimera-no-vectorize。
        compile_gate = decisions.get("gate") or {}
        if decisions and compile_gate.get("enabled") and not arguments.no_gate:
            if not vector_gate_so.is_file():
                raise FileNotFoundError(
                    f"VectorGate plugin missing: {vector_gate_so}; "
                    "run 'chimera-dev toolchain build llvm-plugin "
                    "--plugins vector-gate'"
                )
            if not decision_path:
                raise RuntimeError("gate enabled but no decision file reference")
            if _has_flag(params, "-fpass-plugin"):
                raise ValueError(
                    "refusing to inject VectorGate: <llvm_params> already "
                    "contains -fpass-plugin"
                )
            injected += [f"-fpass-plugin={vector_gate_so}"]  # joined-only
            _inject_vector_gate(decisions, decision_path, gate_env, notes)

    if mode == _Mode.LINK and decisions and not arguments.no_gate:
        gate = decisions.get("gate") or {}
        gate_enabled = bool(gate.get("enabled"))
        fp_enabled = bool(decisions.get("function_pointer_plugin"))
        has_lto = _has_flag(params, "-flto")

        # LTO 只 是 SVF/function_pointer 的使用需求：指针分析需要链接期
        # 合并模块才能解析间接调用目标。gate 是纯编译期门控（per-TU 打
        # 属性），非 LTO 链接不运行任何 LLVM pass，链接期无事可做。
        if fp_enabled and not has_lto:
            raise ValueError(
                "the decision file selects the function-pointer (SVF) "
                "remediation, which requires an LTO link, but "
                "<llvm_params> lacks -flto; add -flto or rebuild without "
                "the decision (--no-gate)"
            )

        if gate_enabled and not has_lto:
            # gate-only + 非 LTO：编译期注入已完成全部门控，链接期原样
            # 透传（不加载 pass 插件、不写 stats）。
            pass
        else:
            if fp_enabled:
                if not function_pointer_so.is_file():
                    raise FileNotFoundError(
                        f"FunctionPointer plugin missing: {function_pointer_so}; "
                        "run 'chimera-dev toolchain build svf' and "
                        "'chimera-dev toolchain build llvm-plugin "
                        "--plugins function-pointer'"
                    )
                if _has_flag(params, "--load-pass-plugin") or _has_flag(
                    params, "-load-pass-plugin"
                ):
                    raise ValueError(
                        "refusing to inject FunctionPointer: <llvm_params> "
                        "already contains --load-pass-plugin"
                    )
                injected += [
                    "-Wl,--load-pass-plugin",
                    str(function_pointer_so),
                ]

            if gate_enabled:
                if not vector_gate_so.is_file():
                    raise FileNotFoundError(
                        f"VectorGate plugin missing: {vector_gate_so}; "
                        "run 'chimera-dev toolchain build llvm-plugin "
                        "--plugins vector-gate'"
                    )
                if not decision_path:
                    raise RuntimeError(
                        "gate enabled but no decision file reference"
                    )
                injected += [
                    "-Wl,--load-pass-plugin",
                    str(vector_gate_so),
                ]
                # lld 在加载 pass 插件之前就解析 -mllvm，插件的 cl::opt 此刻
                # 尚未注册，-chimera-gate-list/-stats 必然 "Unknown command
                # line argument"（实测）。改走插件的环境变量回退通道，插件在
                # pass 运行时读取，与 lld 的解析时序无关。
                _inject_vector_gate(decisions, decision_path, gate_env, notes)

    argv = [str(clang)] + injected + params
    env = os.environ.copy()
    env.update(gate_env)
    completed = subprocess.run(argv, check=False, env=env)
    return_code = completed.returncode

    if return_code == 0 and injected:
        message = f"chimera-pkg llvm: applied decision (mode={mode}, flags={len(injected)})"
        if notes:
            message += "; " + "; ".join(notes)
        # Diagnostics go to stderr: this process stands in for the compiler, and
        # build systems (libtool, autoconf probes) capture a compiler's stdout
        # and splice it back into command lines.  Anything on stdout becomes a
        # bogus argument there -- an earlier build died with
        # `bash: syntax error near unexpected token '('` because this very line
        # was captured by libtool and turned into an argument.
        print(message, file=sys.stderr)

    if (
        return_code == 0
        and mode == _Mode.LINK
        and target is not None
        and decisions
    ):
        # REMEDIATED 的判定依据是产物本身：链接成功的 ELF 必须携带
        # chimera 元数据节（stackobj_map / function_pointer 任一），
        # 否则说明决策没有真正生效，状态保持 PROBLEMATIC。
        sections = _chimera_sections(target)
        if sections:
            # The rebuilt bytes no longer carry the old check credential.
            # Keep the remediation state for diagnostics, but require an
            # explicit workflow-driven check-elf before prepare admission.
            registry.set_status(
                target,
                REMEDIATED,
                check_fingerprint=None,
                check_scope=None,
            )
            print(
                f"chimera-pkg llvm: elf state -> REMEDIATED ({target}); "
                f"metadata sections: {', '.join(sections)} "
                "(未经复检；跑一次 chimera-pkg check-elf 可升级为 CHECKED)",
                file=sys.stderr,
            )
        else:
            print(
                "chimera-pkg llvm: warning: decision applied but the output "
                f"carries no chimera metadata sections: {target}; state "
                "stays PROBLEMATIC",
                file=sys.stderr,
            )
    return return_code


def _chimera_sections(elf_path: Path) -> list[str]:
    """Chimera metadata section names present in ``elf_path``.

    Byte-level scan on purpose: section names appear verbatim in the
    section-header string table of any linked ELF, and this keeps the
    check independent from an ELF parser dependency at wrapper time.
    """

    known = (
        ".chimera.stackobj_map",
        ".chimera.function_pointer",
        ".chimera.pcsections",
    )
    try:
        blob = Path(elf_path).read_bytes()
    except OSError:
        return []
    return [name for name in known if name.encode() in blob]
