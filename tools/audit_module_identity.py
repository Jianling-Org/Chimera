#!/usr/bin/env python3
"""Prove that the audit executes the code that was reviewed.

The K3 audit runs ``python -I -m chimera.gate_source_audit``, i.e. the module
*installed* into the venv, while the repository checkout may already have moved
on.  Recording the source revision alone therefore describes the wrong code: a
fresh audit module paired with a stale analyzer would still be reported as "the
reviewed revision", and every conclusion would inherit the stale analysis.
Recording hashes without comparing them has the same hole - an operator reading
"7 modules listed, all inside the venv" would reasonably conclude the modules
were checked.

So this script does the comparison, for **every** module whose decisions reach
the output, against the matching file in the source tree:

* the imported path must be inside the venv (otherwise the "installed" copy is
  not the one the deployment owns);
* the source file must exist (a module with no counterpart cannot be reviewed);
* the two file digests must be equal.

Any mismatch is a hard failure with a non-zero exit; the transcript names the
module, both paths and both digests, so the failure can be acted on rather than
guessed at.

Exit codes: 0 = every recorded module matches its source; 1 = at least one
mismatch; 2 = the check could not be performed (usage, import or I/O error).
Nothing here audits the application, and exit 0 does not mean the application
is safe - it means the code that will run is the code that was read.

Outputs (under ``--out-dir``):

* ``audit-module.txt``      human-readable transcript (also printed to stdout)
* ``installed-modules.tsv`` one row per module: name, installed path, installed
                            digest, source path, source digest, match
* ``module-identity.txt``   the verdict, plus the remediation steps on failure
"""

from __future__ import annotations

import argparse
import hashlib
import importlib
import sys
from pathlib import Path

#: (dotted module, path relative to the source root) for every module whose
#: decisions reach the audit output.  Order matters only for readability: the
#: audit module first, then the analyses it consumes.
DEFAULT_MODULES: tuple[tuple[str, str], ...] = (
    (
        "chimera.preprocess.offline.analysis.safety.stack_liveness.scalar_width",
        "preprocessing/offline/analysis/safety/stack_liveness/scalar_width.py",
    ),
    (
        "chimera.preprocess.offline.analysis.arch.riscv.scalar_width_facts",
        "preprocessing/offline/analysis/arch/riscv/scalar_width_facts.py",
    ),
    (
        "chimera.preprocess.offline.analysis.arch.riscv.scalar_width_vectors",
        "preprocessing/offline/analysis/arch/riscv/scalar_width_vectors.py",
    ),
    (
        "chimera.preprocess.offline.analysis.arch.riscv.stack_semantics",
        "preprocessing/offline/analysis/arch/riscv/stack_semantics.py",
    ),
    (
        "chimera.preprocess.offline.analysis.core.contracts.services",
        "preprocessing/offline/analysis/core/contracts/services.py",
    ),
    ("chimera.gate_source_audit", "cli/chimera/gate_source_audit.py"),
    (
        "chimera.preprocess.offline.analysis.safety.stack_liveness.analyzer",
        "preprocessing/offline/analysis/safety/stack_liveness/analyzer.py",
    ),
    (
        "chimera.preprocess.offline.analysis.safety.stack_liveness.frame_liveness",
        "preprocessing/offline/analysis/safety/stack_liveness/frame_liveness.py",
    ),
    (
        "chimera.preprocess.offline.analysis.safety.stack_liveness.liveness",
        "preprocessing/offline/analysis/safety/stack_liveness/liveness.py",
    ),
    (
        "chimera.preprocess.offline.analysis.safety.stack_liveness.origins",
        "preprocessing/offline/analysis/safety/stack_liveness/origins.py",
    ),
    (
        "chimera.preprocess.offline.analysis.arch.riscv.control_flow",
        "preprocessing/offline/analysis/arch/riscv/control_flow.py",
    ),
    (
        "chimera.preprocess.offline.analysis.program_model.parser",
        "preprocessing/offline/analysis/program_model/parser.py",
    ),
)

EXIT_OK = 0
EXIT_MISMATCH = 1
EXIT_CANNOT_CHECK = 2

_TRANSCRIPT = "audit-module.txt"
_VERDICT = "module-identity.txt"
_TABLE = "installed-modules.tsv"


def digest(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def parse_module_spec(spec: str) -> tuple[str, str]:
    """``"name=relative/path.py"`` -> ``("name", "relative/path.py")``."""

    name, separator, relative = spec.partition("=")
    name = name.strip()
    relative = relative.strip()
    if not separator or not name or not relative:
        raise ValueError(
            f"--module 需要 NAME=相对源码根路径 形式，收到 {spec!r}"
        )
    return name, relative


def resolve_source(source_root: Path, relative: str) -> Path:
    """Resolve a declared source path, refusing to escape the source root."""

    candidate = Path(relative)
    resolved = (
        candidate.resolve()
        if candidate.is_absolute()
        else (source_root / candidate).resolve()
    )
    if not resolved.is_relative_to(source_root):
        raise ValueError(f"源码路径越出源码根：{relative!r}")
    return resolved


def build_rows(
    modules, source_root: Path, venv: Path
) -> tuple[list[dict], list[str]]:
    """Import each module and compare it with its declared source file.

    Import failures and unreadable files are *collected*, not raised, so the
    transcript reports every problem in one pass instead of only the first.
    """

    rows: list[dict] = []
    problems: list[str] = []
    for name, relative in modules:
        source = resolve_source(source_root, relative)
        try:
            module = importlib.import_module(name)
            installed = Path(module.__file__).resolve()
        except Exception as exc:  # noqa: BLE001 - any import failure is fatal
            problems.append(f"无法导入 {name}：{type(exc).__name__}: {exc}")
            continue
        row = {
            "module": name,
            "installed_path": str(installed),
            "installed_sha256": None,
            "source_path": str(source),
            "source_sha256": None,
            "inside_venv": installed.is_relative_to(venv),
            "source_exists": source.is_file(),
            "matches": False,
        }
        try:
            row["installed_sha256"] = digest(installed)
        except OSError as exc:
            problems.append(f"无法读取已安装模块 {name}：{exc}")
        if not row["source_exists"]:
            problems.append(f"源码树中不存在 {relative}（无法核对 {name}）")
        else:
            try:
                row["source_sha256"] = digest(source)
            except OSError as exc:
                problems.append(f"无法读取源码文件 {source}：{exc}")
        row["matches"] = (
            row["installed_sha256"] is not None
            and row["source_sha256"] is not None
            and row["installed_sha256"] == row["source_sha256"]
        )
        rows.append(row)
    return rows, problems


def render_transcript(
    rows: list[dict], problems: list[str], venv: Path, version: str | None
) -> str:
    lines: list[str] = []
    lines.append(f"chimera_version={version or '<unknown>'}")
    lines.append(f"venv={venv}")
    lines.append(f"python={sys.executable}")
    lines.append("modules=")
    width = max((len(row["module"]) for row in rows), default=1)
    for row in rows:
        lines.append(
            f"  {row['module']:<{width}} "
            f"inside_venv={row['inside_venv']} "
            f"matches_source={row['matches']} "
            f"installed={row['installed_path']}@{row['installed_sha256'] or '?'} "
            f"source={row['source_path']}@{row['source_sha256'] or '?'}"
        )
    for problem in problems:
        lines.append(f"problem={problem}")
    lines.append(
        "all_modules_match_source="
        f"{bool(rows) and not problems and all(r['matches'] for r in rows)}"
    )
    lines.append(
        "all_modules_inside_venv="
        f"{bool(rows) and all(r['inside_venv'] for r in rows)}"
    )
    return "\n".join(lines) + "\n"


def render_table(rows: list[dict]) -> str:
    header = (
        "module\tinstalled_path\tinstalled_sha256\t"
        "source_path\tsource_sha256\tinside_venv\tmatches_source"
    )
    body = [
        "\t".join(
            [
                row["module"],
                row["installed_path"],
                row["installed_sha256"] or "",
                row["source_path"],
                row["source_sha256"] or "",
                str(row["inside_venv"]),
                str(row["matches"]),
            ]
        )
        for row in rows
    ]
    return "\n".join([header, *body]) + "\n"


def render_verdict(
    rows: list[dict], problems: list[str], source_root: Path, venv: Path
) -> tuple[str, bool]:
    """Render the verdict and say whether it is a pass."""

    mismatched = [row for row in rows if not row["matches"]]
    outside = [row for row in rows if not row["inside_venv"]]
    ok = bool(rows) and not problems and not mismatched and not outside
    lines: list[str] = []
    if ok:
        lines.append(
            f"audit module identity verified: {len(rows)} deciding modules, "
            "every installed copy equals its source-tree file and lives inside "
            f"{venv}"
        )
        for row in rows:
            lines.append(f"  {row['module']} {row['installed_sha256']}")
        return "\n".join(lines) + "\n", True

    lines.append("STOP: the code that would run is NOT the code in the checkout.")
    lines.append(f"source_root={source_root}")
    lines.append(f"venv={venv}")
    for problem in problems:
        lines.append(f"problem: {problem}")
    for row in mismatched:
        lines.append(f"mismatch: {row['module']}")
        lines.append(f"  installed={row['installed_path']} {row['installed_sha256']}")
        lines.append(f"  source   ={row['source_path']} {row['source_sha256']}")
    for row in outside:
        lines.append(
            f"outside_venv: {row['module']} imported from {row['installed_path']}"
        )
    lines.append("")
    lines.append(
        "Rebuild the wheel (tools/build_release_wheel.py) and reinstall the "
        "package into the venv so every deciding module matches this checkout, "
        "then rerun.  An audit whose decisions come from unreviewed code "
        "describes nobody's revision."
    )
    return "\n".join(lines) + "\n", False


def _write(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="audit-module-identity",
        description=(
            "Verify that every module deciding the audit output is the "
            "source-tree revision of that module."
        ),
    )
    parser.add_argument(
        "--out-dir",
        required=True,
        help="目录：写入 audit-module.txt / installed-modules.tsv / module-identity.txt",
    )
    parser.add_argument(
        "--source-root",
        required=True,
        help="源码树根目录（--module 的相对路径以此为基准）",
    )
    parser.add_argument(
        "--venv",
        default=None,
        help="期望已安装模块所在的虚拟环境目录；缺省用 sys.prefix",
    )
    parser.add_argument(
        "--module",
        action="append",
        default=None,
        metavar="NAME=RELATIVE_PATH",
        help=(
            "参与判定的模块及其源码路径，可重复；"
            "缺省使用本脚本内置的模块清单（含标量宽度分析及其适配器契约）"
        ),
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    # The transcript quotes Chinese problem texts; make the streams UTF-8 so a
    # narrow console encoding can never turn a report into an exception (or,
    # worse, into a different exit code than the check deserves).
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, OSError):  # pragma: no cover - stream is a pipe
            pass

    arguments = _build_parser().parse_args(argv)
    out_dir = Path(arguments.out_dir)
    source_root = Path(arguments.source_root).resolve()
    venv = (
        Path(sys.prefix).resolve()
        if arguments.venv is None
        else Path(arguments.venv).resolve()
    )

    if not source_root.is_dir():
        print(f"STOP: 源码根目录不存在：{source_root}", file=sys.stderr)
        return EXIT_CANNOT_CHECK
    try:
        out_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        print(f"STOP: 无法创建输出目录 {out_dir}：{exc}", file=sys.stderr)
        return EXIT_CANNOT_CHECK

    try:
        modules = (
            DEFAULT_MODULES
            if arguments.module is None
            else tuple(parse_module_spec(spec) for spec in arguments.module)
        )
        # Resolve every source path up front: a spec that escapes the source
        # root is a usage error, not an identity mismatch, and must not be
        # reported as one.
        for name, relative in modules:
            resolve_source(source_root, relative)
    except ValueError as exc:
        print(f"STOP: {exc}", file=sys.stderr)
        return EXIT_CANNOT_CHECK

    version = None
    try:
        import chimera

        version = getattr(chimera, "__version__", None)
    except Exception:  # noqa: BLE001 - the version is informational only
        version = None

    rows, problems = build_rows(modules, source_root, venv)
    transcript = render_transcript(rows, problems, venv, version)
    verdict, ok = render_verdict(rows, problems, source_root, venv)

    try:
        _write(out_dir / _TRANSCRIPT, transcript)
        _write(out_dir / _TABLE, render_table(rows))
        _write(out_dir / _VERDICT, verdict)
    except OSError as exc:
        print(f"STOP: 无法写出身份核对结果：{exc}", file=sys.stderr)
        print(transcript, file=sys.stderr)
        return EXIT_CANNOT_CHECK

    print(transcript, end="")
    if not ok:
        print(verdict, file=sys.stderr)
        return EXIT_MISMATCH
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
