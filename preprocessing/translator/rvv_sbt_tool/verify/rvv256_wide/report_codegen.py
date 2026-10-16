#!/usr/bin/env python3
"""比较 fixture 或完整 objdump 的 legacy 与宽路径静态代码生成指标。"""

from __future__ import annotations

import argparse
import filecmp
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile


HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parent.parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "src"))

from riscv.extensions.rvv.instruction import is_vector_instruction
from riscv.frontend.parser import AsmParser  # noqa: E402
from riscv.extensions.rvv.instruction import peek_mask_operand  # noqa: E402
from rvv_sbt_rvv import translate_program  # noqa: E402


FIXTURE_DIR = REPO_ROOT / "tests" / "fixtures" / "objdump"
DEFAULT_LLVM_MATTR = (
    "+m,+a,+f,+d,+c,+v,+zba,+zbb,+zbc,+zbs,+zfa,+zfh,+zicond,+zicsr,"
    "+zifencei,+zihintpause,+zihpm,+zkt,+zvbb,+zvbc,+zve32f,+zve32x,"
    "+zve64d,+zve64f,+zve64x,+zvfh,+zvfhmin,+zvkb,+zvkg,+zvkned,"
    "+zvknha,+zvknhb,+zvksed,+zvksh,+zvkt,+zicbop"
)


def assembly_metrics(text: str) -> dict[str, int]:
    """提取可稳定用于版本间比较的静态汇编指标。"""
    return {
        "source_bytes": len(text.encode("utf-8")),
        # Exact base markers, disjoint from masked/commit/reduction markers.
        "wide_blocks": text.count("RVV256-WIDE:"),
        # native whole-register 传输现已同时服务默认/宽 profile。为避免旧 JSON
        # 消费方把新 marker 误读为“没有 whole 优化”，兼容字段也统计新 marker；
        # ``native_whole_blocks`` 保留更准确的、与 profile 无关的名称。
        "wide_whole_blocks": text.count("RVV256-NATIVE-WHOLE"),
        "native_whole_blocks": text.count("RVV256-NATIVE-WHOLE"),
        "wide_masked_blocks": text.count("RVV256-WIDE-MASKED:") + text.count(
            "RVV256-WIDE-MASKED-REDUCTION"
        ),
        "masked_commit_blocks": text.count("RVV256-WIDE-MASKED-COMMIT"),
        "default_direct_mask_chunks": text.count(
            "Direct byte-aligned mask chunk into v0"
        ),
        "native_mask_blocks": text.count("RVV256-NATIVE-MASK"),
        "native_reduction_blocks": text.count("RVV256-WIDE-REDUCTION") + text.count(
            "RVV256-WIDE-MASKED-REDUCTION"
        ),
        "vset": len(re.findall(r"(?m)^\s*vset(?:i?vli|vl)\s+", text)),
        "vector_loads": len(re.findall(r"(?m)^\s*vl[a-z0-9.]*\s+v", text)),
        "vector_stores": len(re.findall(r"(?m)^\s*(?:vse\d+|vsse\d+|vs[ou]xei\d+|vs(?:s|[ou]x)?seg[2-8]e(?:i)?\d+|vs[1248]r|vsm)\.v\s+v\d+,\s*\(", text)),
        "loop_backedges": len(re.findall(r"(?m)^\s*bnez\s+[^,]+,\s*\.L_", text)),
        "scalar_tail_labels": text.count("尾部标量回退"),
        "gpr_spills": len(re.findall(r"(?m)^\s*sd\s+\w+,\s*\d+\(sp\)$", text)),
        "fpr_spills": len(re.findall(r"(?m)^\s*fsd\s+\w+,\s*\d+\(sp\)$", text)),
        "ebreaks": len(re.findall(r"(?m)^\s*ebreak\s*$", text)),
        "unsupported_fallbacks": (
            text.count("Unsupported RVV instruction lowered to ebreak")
            + text.count("# UNIMPLEMENTED:")
        ),
    }


def _find_llvm_tool(name: str) -> str | None:
    discovered = shutil.which(name)
    if discovered:
        return discovered
    homebrew = Path("/opt/homebrew/opt/llvm/bin") / name
    return str(homebrew) if homebrew.exists() else None


def _assemble_and_measure_text_size(
    source: Path,
    obj: Path,
    *,
    llvm_mc: str,
    llvm_size: str,
    llvm_mattr: str,
) -> int:
    """汇编已写入磁盘的大型程序结果，并返回 `.text` 字节数。

    完整 objdump 中会原样保留非 RVV 指令，因此 `llvm_mattr` 必须与
    输入二进制的 ISA profile（指令集配置）匹配，不能一律假定为纯 RV64GCV。
    """
    subprocess.run(
        [
            llvm_mc,
            "-triple=riscv64-unknown-linux-gnu",
            f"-mattr={llvm_mattr}",
            "-filetype=obj",
            str(source),
            "-o",
            str(obj),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    output = subprocess.run(
        [llvm_size, "-A", str(obj)],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    match = re.search(r"(?m)^\.text\s+(\d+)\s+", output)
    if match is None:
        raise RuntimeError(f"无法从 llvm-size 输出读取 {source.name} 的 .text 大小")
    return int(match.group(1))


def _measure_text_size(
    text: str,
    name: str,
    directory: Path,
    llvm_mc: str,
    llvm_size: str,
    llvm_mattr: str,
) -> int:
    source = directory / f"{name}.s"
    obj = directory / f"{name}.o"
    source.write_text(text, encoding="utf-8")
    return _assemble_and_measure_text_size(
        source,
        obj,
        llvm_mc=llvm_mc,
        llvm_size=llvm_size,
        llvm_mattr=llvm_mattr,
    )


def collect_report(
    *,
    with_object_size: bool = False,
    llvm_mattr: str = DEFAULT_LLVM_MATTR,
) -> dict:
    parser = AsmParser()
    cases: dict[str, dict] = {}
    totals = {"legacy": {}, "wide": {}}
    llvm_mc = _find_llvm_tool("llvm-mc") if with_object_size else None
    llvm_size = _find_llvm_tool("llvm-size") if with_object_size else None
    if with_object_size and (llvm_mc is None or llvm_size is None):
        raise RuntimeError("--with-object-size 需要 llvm-mc 和 llvm-size")

    with tempfile.TemporaryDirectory(prefix="chimera-rvv256-report-") as temp_name:
        temp_dir = Path(temp_name)
        for fixture in sorted(FIXTURE_DIR.glob("*.objdump.s")):
            program = parser.parse_file_program(str(fixture))
            legacy = translate_program(
                program,
                source_file=str(fixture),
                lib_name="fixture",
                wide_lmul=False,
            )
            wide = translate_program(
                program,
                source_file=str(fixture),
                lib_name="fixture",
                wide_lmul=True,
            )
            legacy_metrics = assembly_metrics(legacy)
            wide_metrics = assembly_metrics(wide)
            if with_object_size:
                assert llvm_mc is not None and llvm_size is not None
                legacy_metrics["text_bytes"] = _measure_text_size(
                    legacy,
                    f"{fixture.stem}.legacy",
                    temp_dir,
                    llvm_mc,
                    llvm_size,
                    llvm_mattr,
                )
                wide_metrics["text_bytes"] = _measure_text_size(
                    wide,
                    f"{fixture.stem}.wide",
                    temp_dir,
                    llvm_mc,
                    llvm_size,
                    llvm_mattr,
                )
            if legacy_metrics["ebreaks"] != wide_metrics["ebreaks"]:
                raise RuntimeError(f"{fixture.name}: 宽路径改变了 ebreak/fallback 数量")
            cases[fixture.name] = {"legacy": legacy_metrics, "wide": wide_metrics}
            for mode, metrics in (("legacy", legacy_metrics), ("wide", wide_metrics)):
                for key, value in metrics.items():
                    totals[mode][key] = totals[mode].get(key, 0) + value
    return {"fixture_count": len(cases), "cases": cases, "totals": totals}


def collect_program_report(
    input_path: Path,
    *,
    lib_name: str,
    with_object_size: bool = False,
    llvm_mattr: str = DEFAULT_LLVM_MATTR,
) -> dict:
    """
    对一个接近部署规模的完整 objdump 做 legacy/wide 对照。

    该入口与微型 fixture 的职责不同：它主要暴露程序级解析、控制流重写、
    地址映射和目标汇编问题。报告同时给出真实 RVV 指令数，防止把不含 RVV
    的大型共享库误当成宽 LMUL/masked 语义覆盖证据。
    """
    parser = AsmParser()
    program = parser.parse_file_program(str(input_path))
    functions = program.functions
    instruction_count = sum(len(function.instructions) for function in functions)
    vector_instruction_count = sum(
        is_vector_instruction(insn)
        for function in functions
        for insn in function.instructions
    )
    masked_vector_instruction_count = sum(
        is_vector_instruction(insn) and peek_mask_operand(insn) is not None
        for function in functions
        for insn in function.instructions
    )
    llvm_mc = _find_llvm_tool("llvm-mc") if with_object_size else None
    llvm_size = _find_llvm_tool("llvm-size") if with_object_size else None
    if with_object_size and (llvm_mc is None or llvm_size is None):
        raise RuntimeError("--with-object-size 需要 llvm-mc 和 llvm-size")

    # llama 级别的输入会产生数百 MiB 汇编。顺序生成并将两种模式
    # 落盘后再比较，避免同时保留 legacy/wide 两份巨型 Python 字符串。
    with tempfile.TemporaryDirectory(prefix="chimera-rvv256-program-report-") as temp_name:
        temp_dir = Path(temp_name)
        legacy_source = temp_dir / "representative.legacy.s"
        wide_source = temp_dir / "representative.wide.s"

        legacy = translate_program(
            program,
            source_file=str(input_path),
            lib_name=lib_name,
            wide_lmul=False,
        )
        legacy_metrics = assembly_metrics(legacy)
        legacy_source.write_text(legacy, encoding="utf-8")
        del legacy

        wide = translate_program(
            program,
            source_file=str(input_path),
            lib_name=lib_name,
            wide_lmul=True,
        )
        wide_metrics = assembly_metrics(wide)
        wide_source.write_text(wide, encoding="utf-8")
        del wide

        legacy_wide_identical = filecmp.cmp(legacy_source, wide_source, shallow=False)
        if with_object_size:
            assert llvm_mc is not None and llvm_size is not None
            legacy_metrics["text_bytes"] = _assemble_and_measure_text_size(
                legacy_source,
                temp_dir / "representative.legacy.o",
                llvm_mc=llvm_mc,
                llvm_size=llvm_size,
                llvm_mattr=llvm_mattr,
            )
            wide_metrics["text_bytes"] = _assemble_and_measure_text_size(
                wide_source,
                temp_dir / "representative.wide.o",
                llvm_mc=llvm_mc,
                llvm_size=llvm_size,
                llvm_mattr=llvm_mattr,
            )

    return {
        "input": str(input_path),
        "lib_name": lib_name,
        "function_count": len(functions),
        "instruction_count": instruction_count,
        "vector_instruction_count": vector_instruction_count,
        "masked_vector_instruction_count": masked_vector_instruction_count,
        "legacy_wide_identical": legacy_wide_identical,
        "legacy": legacy_metrics,
        "wide": wide_metrics,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="输出机器可读 JSON")
    parser.add_argument(
        "--with-object-size",
        action="store_true",
        help="调用 LLVM RISC-V 汇编器并统计真实 .text 字节数",
    )
    parser.add_argument(
        "--program-input",
        type=Path,
        help="完整 objdump 路径；提供后改做代表性全程序 legacy/wide 对照",
    )
    parser.add_argument(
        "--lib-name",
        default="representative",
        help="--program-input 模式下用于原始基址符号的库名",
    )
    parser.add_argument(
        "--llvm-mattr",
        default=DEFAULT_LLVM_MATTR,
        help=(
            "LLVM 汇编时启用的 ISA 扩展；完整程序必须与原二进制配置匹配 "
            f"(默认: {DEFAULT_LLVM_MATTR})"
        ),
    )
    args = parser.parse_args()
    if args.program_input is not None:
        report = collect_program_report(
            args.program_input,
            lib_name=args.lib_name,
            with_object_size=args.with_object_size,
            llvm_mattr=args.llvm_mattr,
        )
        if args.json:
            print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
            return 0
        print(f"input: {report['input']}")
        print(f"functions: {report['function_count']}")
        print(f"instructions: {report['instruction_count']}")
        print(f"vector_instructions: {report['vector_instruction_count']}")
        print(f"masked_vector_instructions: {report['masked_vector_instruction_count']}")
        print(f"legacy_wide_identical: {report['legacy_wide_identical']}")
        for key in report["legacy"]:
            legacy = report["legacy"][key]
            wide = report["wide"][key]
            delta = wide - legacy
            print(f"{key:20s} legacy={legacy:7d} wide={wide:7d} delta={delta:+7d}")
        return 0

    report = collect_report(
        with_object_size=args.with_object_size,
        llvm_mattr=args.llvm_mattr,
    )
    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
        return 0

    print(f"fixtures: {report['fixture_count']}")
    for key in report["totals"]["legacy"]:
        legacy = report["totals"]["legacy"][key]
        wide = report["totals"]["wide"][key]
        delta = wide - legacy
        print(f"{key:20s} legacy={legacy:7d} wide={wide:7d} delta={delta:+7d}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
