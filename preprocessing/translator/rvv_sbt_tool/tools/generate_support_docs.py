#!/usr/bin/env python3
"""从三个后端 registry 生成指令支持文档。

普通运行会原子更新 ``doc/developer/translator/supported-instructions.md``；``--check`` 只比较
当前文件，适合 Makefile/CI 门禁。脚本只读取本仓库 Python 规格，不联网。
"""

from __future__ import annotations

import argparse
import os
import stat
from pathlib import Path
import sys
import uuid


TOOL_ROOT = Path(__file__).resolve().parents[1]
DOC_PATH = TOOL_ROOT.parents[2] / "doc/developer/translator/supported-instructions.md"
if str(TOOL_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(TOOL_ROOT / "src"))

from riscv.extensions.rvv.backends.rvv1024_transition.specs import TRANSITION_REGISTRY  # noqa: E402
from riscv.extensions.rvv.backends.rvv256.specs import build_rvv256_registry  # noqa: E402
from riscv.extensions.rvv.backends.scalar.specs import build_scalar_registry  # noqa: E402
from riscv.extensions.rvv.translation.contracts import InstructionSpec  # noqa: E402
from riscv.extensions.rvv.translation.specs import HandlerRegistry  # noqa: E402


def _escape(value: object) -> str:
    """转义 Markdown 表格中的特殊字符。"""

    return str(value).replace("|", "\\|").replace("\n", " ")


def _format_sews(values: frozenset[int]) -> str:
    if not values:
        return "指令内决定/不依赖"
    return "/".join(f"e{value}" for value in sorted(values))


def _format_lmul(value: float) -> str:
    names = {
        0.125: "mf8",
        0.25: "mf4",
        0.5: "mf2",
        1.0: "m1",
        2.0: "m2",
        4.0: "m4",
        8.0: "m8",
    }
    return names.get(float(value), f"{value:g}")


def _format_lmuls(values: frozenset[float]) -> str:
    if not values:
        return "指令内决定/不依赖"
    return "/".join(_format_lmul(value) for value in sorted(values))


def _counts(registry: HandlerRegistry) -> str:
    return ", ".join(
        f"{category}={len(registry.by_category(category))}"
        for category in registry.categories()
    )


def _render_registry(
    lines: list[str],
    *,
    title: str,
    registry: HandlerRegistry,
    note: str,
    conservative_registry: HandlerRegistry | None = None,
) -> None:
    """输出一个后端的完整结构化能力表。"""

    lines.extend((
        f"## {title}",
        "",
        note,
        "",
        f"注册总数：**{len(registry)}**。分类计数：{_counts(registry)}。",
        "",
    ))
    for category in registry.categories():
        specs = tuple(sorted(registry.by_category(category).values(), key=lambda item: item.opcode))
        lines.extend((
            f"### `{category}`（{len(specs)}）",
            "",
        ))
        if conservative_registry is None:
            lines.extend((
                "| opcode | 合法 operand form | SEW | LMUL | mask | tail | vstart | 旧 vd | vtype 无关 | 目标 mnemonic | 有符号性 | 舍入 |",
                "|---|---|---|---|---|---|---|---:|---:|---|---|---|",
            ))
        else:
            lines.extend((
                "| opcode | 合法 operand form | SEW | LMUL | mask（宽/保守） | tail | vstart | 旧 vd | vtype 无关 | 目标 mnemonic | 有符号性 | 舍入 |",
                "|---|---|---|---|---|---|---|---:|---:|---|---|---|",
            ))
        for spec in specs:
            forms = "<br>".join(f"`{_escape(form)}`" for form in spec.operand_forms)
            mask_text = spec.mask_policy.value
            if conservative_registry is not None:
                conservative = conservative_registry.require(spec.opcode)
                mask_text = f"{spec.mask_policy.value} / {conservative.mask_policy.value}"
            target = spec.target_mnemonic or spec.opcode
            row = (
                f"| `{spec.opcode}` | {forms} | {_format_sews(spec.supported_sews)} | "
                f"{_format_lmuls(spec.supported_lmuls)} | `{mask_text}` | "
                f"`{spec.tail_policy.value}` | `{spec.vstart_policy.value}` | "
                f"{'是' if spec.reads_old_vd else '否'} | "
                f"{'是' if spec.vtype_independent else '否'} | `{_escape(target)}` | "
                f"`{_escape(spec.signedness)}` | `{_escape(spec.rounding_policy)}` |"
            )
            lines.append(row)
        lines.append("")


def render() -> str:
    """返回完全由当前 registry 决定的 Markdown。"""

    scalar = build_scalar_registry()
    rvv256_wide = build_rvv256_registry(wide_lmul=True)
    rvv256_conservative = build_rvv256_registry(wide_lmul=False)
    transition = TRANSITION_REGISTRY
    if set(rvv256_wide.snapshot()) != set(rvv256_conservative.snapshot()):
        raise RuntimeError("RVV256 宽/保守 profile 的 opcode 集合不一致")

    lines = [
        "<!-- 此文件由 tools/generate_support_docs.py 生成，请勿手工编辑。 -->",
        "# 后端注册能力",
        "",
        "本文件只描述当前 `InstructionSpec` registry 中的**已注册能力与结构限制**。",
        "它不是目标机语义验证报告；注册、生成汇编和目标机差分验证仍是不同层级。",
        "",
        "重新生成：",
        "",
        "```bash",
        "python3 tools/generate_support_docs.py",
        "python3 tools/generate_support_docs.py --check",
        "```",
        "",
        "| 后端/profile | 注册数 | fallback | 说明 |",
        "|---|---:|---|---|",
        f"| 标量 RV64 | {len(scalar)} | 抛出异常，CLI 失败 | `rvv_sbt.py` |",
        f"| RVV256 宽 profile | {len(rvv256_wide)} | 诊断 + `ebreak` | `rvv_sbt_rvv.py` 默认 |",
        f"| RVV256 保守 profile | {len(rvv256_conservative)} | 诊断 + `ebreak` | `rvv_sbt_rvv.py --conservative` |",
        f"| RVV256→RVV1024 过渡 | {len(transition)} | 诊断 + `ebreak` | `rvv_sbt_rvv1024.py` |",
        "",
    ]
    _render_registry(
        lines,
        title="标量 RV64 后端",
        registry=scalar,
        note="逐元素在 RV64 上执行；未注册 opcode 通过公共 `UnsupportedInstructionError` 失败。",
    )
    _render_registry(
        lines,
        title="RVV256 后端",
        registry=rvv256_wide,
        conservative_registry=rvv256_conservative,
        note=(
            "源语义 VLEN=1024，目标 VLEN=256。表中 mask 按“默认宽 profile / "
            "`--conservative`”排列；具体寄存器组形状仍由纯 validator 与 planner 检查。"
            "`vle8ff.v` 按最多 32 字节分块执行，没有额外的 `VL <= 256` 容量上限；"
            "后续分块的首元素 fault 仍可能错误触发异常，该边界尚未修复。"
            "运行期限制见[已知限制](limitations.md)。"
        ),
    )
    _render_registry(
        lines,
        title="RVV256→RVV1024 过渡后端",
        registry=transition,
        note=(
            "该实验路径仍在写出正式汇编前完成 CFG/vtype 预检；可由单条 ebreak"
            " 安全表示的未知入口或未验证 form 会保留诊断并生成 fallback。"
        ),
    )
    lines.extend((
        "## 证据边界",
        "",
        "- 本表证明 opcode 已注册、静态 form/能力字段存在且 dispatcher 可找到结构化 lowerer。",
        "- pytest 与目标汇编器通过，只能分别证明主机结构/流程回归和目标汇编语法可接受。",
        "- 算术、mask、tail、`vstart`、迁移状态和性能必须由相应 RISC-V/QEMU/真机差分验证证明。",
        "",
    ))
    return "\n".join(lines)


def _write_atomic(path: Path, content: str) -> None:
    """同目录临时文件写完并 fsync 后原子替换。"""

    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o666)
    try:
        if path.exists():
            os.fchmod(descriptor, stat.S_IMODE(path.stat().st_mode))
        stream = os.fdopen(descriptor, "w", encoding="utf-8", newline="\n")
        descriptor = None
        with stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        temporary.unlink(missing_ok=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="只检查已提交文档是否与当前 registry 一致",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DOC_PATH,
        help="输出路径；默认写入 doc/developer/translator/supported-instructions.md",
    )
    args = parser.parse_args(argv)
    expected = render()
    output = args.output.resolve()
    if args.check:
        actual = output.read_text(encoding="utf-8") if output.exists() else None
        if actual != expected:
            print(
                f"支持文档已过期: {output}\n"
                "请运行 python3 tools/generate_support_docs.py",
                file=sys.stderr,
            )
            return 1
        print(f"支持文档与 registry 一致: {output}")
        return 0
    _write_atomic(output, expected)
    print(f"已生成支持文档: {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
