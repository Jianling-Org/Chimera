"""程序级本地跳转的对象级范围修正。

本模块属于翻译器本身，不放在 ``offline`` 层。它不参与 emitter 的底层
纯文本发射；程序模式的正常 CLI 流程会默认调用它，并使用生产 RISC-V
编译器和 ``readelf`` 执行两轮对象检查：第一轮保留短跳并输出 site 标签，
后续轮次只把对象确认越界的源地址交给 emitter 的长跳路径。
"""

from __future__ import annotations

import re
import os
import selectors
import signal
import shlex
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable, Iterator, Sequence


# JAL 的 21 位有符号立即数按 2 字节对齐编码，字节距离范围为
# [-2^20, 2^20-2]。C.J、B 型分支也在这里检查，避免第二轮代码膨胀后
# 产生新的未报告的短跳/条件分支溢出；条件分支仍属于本次修复范围之外，
# 一旦越界就明确失败，而不是把它误认为已经修复。
JAL_MIN_DISTANCE = -(1 << 20)
JAL_MAX_DISTANCE = (1 << 20) - 2
RVC_JUMP_MIN_DISTANCE = -(1 << 11)
RVC_JUMP_MAX_DISTANCE = (1 << 11) - 2
BRANCH_MIN_DISTANCE = -(1 << 12)
BRANCH_MAX_DISTANCE = (1 << 12) - 2
RVC_BRANCH_MIN_DISTANCE = -(1 << 8)
RVC_BRANCH_MAX_DISTANCE = (1 << 8) - 2

_RELOCATION_LIMITS = {
    "R_RISCV_JAL": (JAL_MIN_DISTANCE, JAL_MAX_DISTANCE),
    "R_RISCV_RVC_JUMP": (RVC_JUMP_MIN_DISTANCE, RVC_JUMP_MAX_DISTANCE),
    "R_RISCV_BRANCH": (BRANCH_MIN_DISTANCE, BRANCH_MAX_DISTANCE),
    "R_RISCV_RVC_BRANCH": (RVC_BRANCH_MIN_DISTANCE, RVC_BRANCH_MAX_DISTANCE),
}
_DIRECT_RELOCATION_TYPES = frozenset(_RELOCATION_LIMITS)
_SITE_LABEL = re.compile(r"^chimera_j_site_([0-9a-fA-F]+)$")
# Large program compilation can take hours; callers may set a tighter tool budget.
DEFAULT_COMMAND_TIMEOUT = 6 * 60 * 60


class JalRangeFixupError(RuntimeError):
    """对象范围修正无法安全完成。"""


@dataclass(frozen=True)
class RelocationIssue:
    """一条无法编码的直接控制流重定位。"""

    relocation_type: str
    place: int
    target: str
    target_value: int | None
    site: int | None
    delta: int | None

    def describe(self) -> str:
        site_text = (
            f"site=0x{self.site:x}" if self.site is not None else "site=unknown"
        )
        target_text = (
            f"target=0x{self.target_value:x}"
            if self.target_value is not None
            else "target=undefined"
        )
        delta_text = (
            f"delta={self.delta:+#x}" if self.delta is not None else "delta=unknown"
        )
        return (
            f"{self.relocation_type} at 0x{self.place:x}, {site_text}, "
            f"{self.target} ({target_text}, {delta_text})"
        )


@dataclass(frozen=True)
class RelocationReport:
    """一次对象范围检查的结果。"""

    out_of_range_sites: frozenset[int]
    unclassified_issues: tuple[RelocationIssue, ...]
    branch_issues: tuple[RelocationIssue, ...]


def _command_parts(command: str | Sequence[str]) -> list[str]:
    """把可执行文件字符串或参数序列规范化为安全的参数列表。"""

    if isinstance(command, str):
        parts = shlex.split(command)
    else:
        parts = [str(item) for item in command]
    if not parts:
        raise ValueError("工具命令不能为空")
    return parts


def _run(command: Sequence[str], *, timeout: float | None = None) -> str:
    """运行对象工具，并保留完整错误上下文。"""

    output: list[str] = []
    try:
        output.extend(_run_lines(command, timeout=timeout))
    except JalRangeFixupError as exc:
        if output:
            raise JalRangeFixupError(f"{exc}\n{''.join(output).strip()}") from exc
        raise
    return "".join(output)


def _run_lines(command: Sequence[str], *, timeout: float | None = None) -> Iterator[str]:
    """Stream output under one deadline and reap our process group on cancellation."""
    budget = DEFAULT_COMMAND_TIMEOUT if timeout is None else timeout
    if not 0 < budget < float("inf"):
        raise ValueError("工具超时必须为正数")
    deadline = time.monotonic() + budget
    with tempfile.TemporaryFile(mode="w+t") as errors:
        with subprocess.Popen(
            list(command), stdout=subprocess.PIPE, stderr=errors, text=True,
            start_new_session=True,
        ) as process:
            assert process.stdout is not None
            completed = False
            try:
                with selectors.DefaultSelector() as selector:
                    selector.register(process.stdout, selectors.EVENT_READ)
                    pending = b""
                    while True:
                        remaining = deadline - time.monotonic()
                        if remaining <= 0 or not selector.select(remaining):
                            raise subprocess.TimeoutExpired(command, budget)
                        chunk = os.read(process.stdout.fileno(), 65536)
                        if not chunk:
                            if pending:
                                yield pending.decode(process.stdout.encoding)
                            break
                        lines = (pending + chunk).split(b"\n")
                        pending = lines.pop()
                        for line in lines:
                            yield line.decode(process.stdout.encoding) + "\n"
                process.wait(timeout=max(0, deadline - time.monotonic()))
                completed = True
                if process.returncode != 0:
                    errors.seek(0)
                    raise JalRangeFixupError(
                        f"命令失败（退出码 {process.returncode}）: {' '.join(command)}\n"
                        f"{errors.read().strip()}"
                    )
            except subprocess.TimeoutExpired as exc:
                errors.seek(0)
                raise JalRangeFixupError(
                    f"命令超时（{budget:g}s）: {' '.join(command)}\n{errors.read().strip()}"
                ) from exc
            finally:
                # Closing a partially consumed iterator must not leave a compiler
                # or a pipe-holding descendant running after the caller exits.
                if not completed:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                process.wait()


def _parse_symbols(
    readelf_output: str | Iterable[str],
    *,
    targets: set[str] | None = None,
) -> dict[str, int]:
    """解析 ``readelf -sW`` 的符号值。"""

    symbols: dict[str, int] = {}
    for line in readelf_output.splitlines() if isinstance(readelf_output, str) else readelf_output:
        fields = line.split()
        if len(fields) < 8 or not fields[0].rstrip(":").isdigit():
            continue
        if targets is not None and fields[7] not in targets and not _SITE_LABEL.fullmatch(fields[7]):
            continue
        try:
            value = int(fields[1], 16)
        except ValueError:
            continue
        symbols[fields[7]] = value
    return symbols


def _parse_relocations(
    readelf_output: str | Iterable[str],
) -> list[tuple[int, str, str, int]]:
    """解析 JAL、RVC jump 和 B 型分支重定位。"""

    relocations: list[tuple[int, str, str, int]] = []
    for line in readelf_output.splitlines() if isinstance(readelf_output, str) else readelf_output:
        fields = line.split()
        if not fields or not re.fullmatch(r"[0-9a-fA-F]+", fields[0]):
            continue
        type_index = next(
            (
                index
                for index, field in enumerate(fields)
                if field in _DIRECT_RELOCATION_TYPES
            ),
            None,
        )
        if type_index is None:
            continue
        if type_index + 2 >= len(fields):
            raise JalRangeFixupError(f"无法解析重定位行（缺少目标符号）: {line.strip()}")

        target = fields[type_index + 2]
        addend_index = type_index + 3
        if addend_index + 2 != len(fields) or fields[addend_index] not in {"+", "-"}:
            raise JalRangeFixupError(f"无法解析重定位 addend: {line.strip()}")
        raw_addend = fields[addend_index + 1]
        if re.fullmatch(r"(?:0[xX])?[0-9a-fA-F]+", raw_addend) is None:
            raise JalRangeFixupError(f"无法解析重定位 addend: {line.strip()}")
        addend = int(raw_addend, 16)
        if fields[addend_index] == "-":
            addend = -addend

        relocations.append(
            (
                int(fields[0], 16),
                fields[type_index],
                target,
                addend,
            )
        )
    return relocations


def _is_out_of_range(relocation_type: str, delta: int) -> bool:
    """判断某种直接控制流重定位是否能编码该字节距离。"""

    minimum, maximum = _RELOCATION_LIMITS[relocation_type]
    return delta % 2 != 0 or not minimum <= delta <= maximum


def inspect_object(
    object_path: Path,
    *,
    readelf: str | Sequence[str] = "readelf",
) -> RelocationReport:
    """检查对象并把可定位的越界跳转映射回源指令地址。"""

    readelf_command = _command_parts(readelf)
    relocations = _parse_relocations(
        _run_lines([*readelf_command, "-rW", str(object_path)])
    )
    symbols = _parse_symbols(
        _run_lines([*readelf_command, "-sW", str(object_path)]),
        targets={target for _, _, target, _ in relocations},
    )
    site_by_value: dict[int, int] = {}
    for name, value in symbols.items():
        match = _SITE_LABEL.match(name)
        if match:
            site_by_value[value] = int(match.group(1), 16)

    sites: set[int] = set()
    unclassified: list[RelocationIssue] = []
    branch_issues: list[RelocationIssue] = []

    for place, relocation_type, target, addend in relocations:
        target_value = symbols.get(target)
        site = site_by_value.get(place)
        if target_value is None:
            issue = RelocationIssue(
                relocation_type=relocation_type,
                place=place,
                target=target,
                target_value=None,
                site=site,
                delta=None,
            )
            if relocation_type in {"R_RISCV_BRANCH", "R_RISCV_RVC_BRANCH"}:
                branch_issues.append(issue)
            else:
                unclassified.append(issue)
            continue

        delta = target_value + addend - place
        if not _is_out_of_range(relocation_type, delta):
            continue

        issue = RelocationIssue(
            relocation_type=relocation_type,
            place=place,
            target=target,
            target_value=target_value,
            site=site,
            delta=delta,
        )
        if relocation_type in {"R_RISCV_BRANCH", "R_RISCV_RVC_BRANCH"}:
            branch_issues.append(issue)
        elif issue.site is None:
            unclassified.append(issue)
        else:
            sites.add(issue.site)

    return RelocationReport(
        out_of_range_sites=frozenset(sites),
        unclassified_issues=tuple(unclassified),
        branch_issues=tuple(branch_issues),
    )


def _compile_object(
    *,
    compiler: str | Sequence[str],
    source_path: Path,
    object_path: Path,
    compiler_args: Sequence[str],
) -> None:
    """合并同名代码节后检查范围，保留重定位供最终共享对象链接。"""

    command = [
        *_command_parts(compiler),
        *compiler_args,
        "-nostdlib",
        "-r",
        str(source_path),
        "-o",
        str(object_path),
    ]
    _run(command)


def _raise_report_errors(report: RelocationReport, *, prefix: str) -> None:
    """把本次修复范围之外的重定位问题转换为明确错误。"""

    if report.branch_issues:
        details = "\n".join(issue.describe() for issue in report.branch_issues)
        raise JalRangeFixupError(
            f"{prefix}发现超范围 R_RISCV_BRANCH/R_RISCV_RVC_BRANCH；"
            f"本次只修复本地 j：\n{details}"
        )
    if report.unclassified_issues:
        details = "\n".join(issue.describe() for issue in report.unclassified_issues)
        raise JalRangeFixupError(
            f"{prefix}发现无法映射回 emitter 本地 j 的超范围直接跳转：\n{details}"
        )


def _write_source(path: Path, source: str | Iterable[str], *, final: bool = False) -> None:
    """Write one round without materializing the program's complete assembly."""
    if isinstance(source, str):
        if final and re.search(r"(?m)^chimera_j_site_[0-9a-fA-F]+:", source):
            raise JalRangeFixupError("正式输出仍包含范围探测标签")
        path.write_text(source, encoding="utf-8")
        return
    with path.open("w", encoding="utf-8") as output:
        for index, line in enumerate(source):
            if final and re.search(r"(?m)^chimera_j_site_[0-9a-fA-F]+:", line):
                raise JalRangeFixupError("正式输出仍包含范围探测标签")
            if index:
                output.write("\n")
            output.write(line)


def resolve_jal_ranges(
    *,
    translate_round: Callable[[frozenset[int], bool], str | Iterable[str]],
    compiler: str | Sequence[str],
    readelf: str | Sequence[str] = "readelf",
    compiler_args: Sequence[str] = ("-fPIC",),
    max_iterations: int = 8,
    output_path: str | Path | None = None,
) -> tuple[str | None, frozenset[int]]:
    """反复生成并检查对象，只为已确认越界的本地 j 发射长跳。

    ``translate_round(sites, emit_markers)`` 是翻译器内部回调。探测轮要求
    ``emit_markers=True`` 且只使用传入的显式长跳集合；正式轮关闭标记，
    因而输出不会泄漏 ``chimera_j_site_*``。对象级检查放在翻译器目录内，
    但编译器和 ``readelf`` 仍必须由调用方提供与生产环境一致的工具。
    """

    if max_iterations <= 0:
        raise ValueError("max_iterations 必须为正数")

    sites: set[int] = set()
    with tempfile.TemporaryDirectory(prefix="chimera-jal-fixup-") as temporary:
        temporary_path = Path(temporary)
        for iteration in range(max_iterations):
            probe_source = temporary_path / f"probe_{iteration}.s"
            probe_object = temporary_path / f"probe_{iteration}.o"
            _write_source(
                probe_source,
                translate_round(frozenset(sites), True),
            )
            _compile_object(
                compiler=compiler,
                source_path=probe_source,
                object_path=probe_object,
                compiler_args=compiler_args,
            )
            report = inspect_object(probe_object, readelf=readelf)
            _raise_report_errors(report, prefix=f"第 {iteration + 1} 轮：")

            still_out_of_range = report.out_of_range_sites & sites
            if still_out_of_range:
                addresses = ", ".join(
                    f"0x{site:x}" for site in sorted(still_out_of_range)
                )
                raise JalRangeFixupError(
                    "已标记为长跳的 site 仍产生超范围直接跳转：" + addresses
                )

            new_sites = set(report.out_of_range_sites) - sites
            if new_sites:
                sites.update(new_sites)
                continue

            final_source = translate_round(frozenset(sites), False)
            final_source_path = temporary_path / "final.s"
            final_object = temporary_path / "final.o"
            _write_source(final_source_path, final_source, final=True)
            _compile_object(
                compiler=compiler,
                source_path=final_source_path,
                object_path=final_object,
                compiler_args=compiler_args,
            )
            final_report = inspect_object(final_object, readelf=readelf)
            _raise_report_errors(final_report, prefix="正式输出：")
            if final_report.out_of_range_sites:
                addresses = ", ".join(
                    f"0x{site:x}" for site in sorted(final_report.out_of_range_sites)
                )
                raise JalRangeFixupError(
                    "正式输出仍包含未修复的本地直接跳转：" + addresses
                )
            if output_path is not None:
                shutil.copyfile(final_source_path, output_path)
                return None, frozenset(sites)
            return final_source_path.read_text(encoding="utf-8"), frozenset(sites)

    addresses = ", ".join(f"0x{site:x}" for site in sorted(sites))
    raise JalRangeFixupError(
        f"本地 j 范围修正超过 {max_iterations} 轮仍未收敛；已标记 site: {addresses}"
    )


__all__ = [
    "BRANCH_MAX_DISTANCE",
    "BRANCH_MIN_DISTANCE",
    "JAL_MAX_DISTANCE",
    "JAL_MIN_DISTANCE",
    "JalRangeFixupError",
    "RelocationIssue",
    "RelocationReport",
    "inspect_object",
    "resolve_jal_ranges",
]
