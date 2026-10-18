#!/usr/bin/env python3
"""RVV256 原生状态到 RVV1024 临时执行的过渡翻译器。

这不是把 RVV256 客体永久重写为另一份 RVV1024 程序。它生成的是迁移期间
可从任意 ``branch_j_target_<offset>`` 进入的完整过渡实现：每条源 V 指令
从紧凑 RVV256 state 读取、使用 RVV1024 临时寄存器执行、立即写回同一布局。
直接恢复、probe 和离开过渡区的跳转由目录外组件负责。
"""

from __future__ import annotations

import argparse
import sys

from pathlib import Path

# The public scripts also run directly from the bundled source tree.
sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

from riscv.extensions.rvv.translation.emitter import ProgramEmitter
from riscv.extensions.rvv.runtime.access import StateAccessEmitter
from riscv.extensions.rvv.translation.pipeline import EmissionOptions, TranslationPipeline
from riscv.extensions.rvv.runtime.contract import RVV256_TO_RVV1024
from riscv.frontend.parser import AsmParser
from riscv.extensions.rvv.runtime.layout import SimulatedStateLayout
from riscv.extensions.rvv.runtime.geometry import RVV256_TO_RVV1024_GEOMETRY
from riscv.extensions.rvv.analysis.config import StateTracker
from riscv.frontend.model import RVFunction, RVProgram
from riscv.extensions.rvv.backends.rvv1024_transition.backend import RVV1024Dispatcher
from riscv.extensions.rvv.backends.rvv1024_transition.backend import make_transition_profile
from riscv.extensions.rvv.backends.rvv1024_transition.preflight import (
    TransitionPreflightError,
    preflight_instruction_stream,
    preflight_program,
)


# 方向几何的单一权威位于 riscv.extensions.rvv.runtime.geometry；本入口只引用，不重复定义
# 32/128 字面量。过渡路径的 state_view/handlers 中的 SOURCE_VLENB 同样
# 由几何对象派生。
SOURCE_VLENB = RVV256_TO_RVV1024_GEOMETRY.source_vlenb
TARGET_VLENB = RVV256_TO_RVV1024_GEOMETRY.target_vlenb


def _make_emitter(*, state_base_mode: str = "initial-exec") -> ProgramEmitter:
    """构造 256→1024 过渡发射器，并固定紧凑源状态 ABI。

    ``ProgramEmitter`` 的宽度参数传入源端 32B，避免任何保留的标量 CSR 路径泄漏
    目标 RVV1024 的 128B。状态缓冲区总尺寸仍由固定 0x1040 布局决定；
    profile=2 只用于反向地址映射，不能与 1024→256 路径混用。
    """

    return ProgramEmitter(
        vlenb=SOURCE_VLENB,
        state_base_mode=state_base_mode,
        state_symbol=RVV256_TO_RVV1024.state_symbol,
        lookup_profile=RVV256_TO_RVV1024.lookup_profile,
    )


def translate(
    insn_list,
    *,
    source_vlenb: int = SOURCE_VLENB,
    target_vlenb: int = TARGET_VLENB,
    source_file: str = "input.s",
    text_only: bool = False,
    init_vtype: str | None = None,
    raw: bool = False,
    func_name: str | None = None,
    tls_state: bool = True,
    state_base_mode: str = "initial-exec",
) -> str:
    """翻译一段 RVV256 客体指令；不可降低的指令生成 ebreak 回退。

    ``source_file`` is retained for API compatibility and currently does not affect
    emitted output.
    """
    function_name = func_name or "translated_func"
    function = RVFunction(
        name=function_name,
        start_addr=insn_list[0].address if insn_list else 0,
        instructions=list(insn_list),
    )
    return translate_function(
        function,
        source_vlenb=source_vlenb,
        target_vlenb=target_vlenb,
        text_only=text_only,
        init_vtype=init_vtype,
        raw=raw,
        tls_state=tls_state,
        state_base_mode=state_base_mode,
    )


def translate_function(
    function: RVFunction,
    *,
    source_vlenb: int = SOURCE_VLENB,
    target_vlenb: int = TARGET_VLENB,
    source_file: str = "input.s",
    text_only: bool = False,
    init_vtype: str | None = None,
    raw: bool = False,
    tls_state: bool = True,
    state_base_mode: str = "initial-exec",
) -> str:
    """翻译单个 ``RVFunction``；无法确定入口 vtype 时生成安全 fallback。"""
    if not isinstance(function, RVFunction):
        raise TypeError("translate_function() 需要 RVFunction；片段请使用 translate()")
    profile = make_transition_profile(
        source_vlenb=source_vlenb,
        target_vlenb=target_vlenb,
    )

    def run_preflight(prepared_program: RVProgram, prepared_analysis):
        prepared_function = prepared_program.functions[0]
        function_analysis = prepared_analysis.for_function(
            prepared_function.start_addr
        )
        if function_analysis is None:
            raise ValueError("过渡预检缺少当前函数的 CFG/vtype 分析")
        return preflight_instruction_stream(
            prepared_function.instructions,
            analysis=function_analysis,
            dispatcher_factory=RVV1024Dispatcher,
            source_vlenb=source_vlenb,
            init_vtype=init_vtype,
            allow_ebreak_fallback=(profile.fallback_policy == "ebreak"),
        )

    pipeline = TranslationPipeline(
        _make_emitter(state_base_mode=state_base_mode),
        preflight_planner=run_preflight,
    )

    prepared = pipeline.prepare(
        RVProgram(functions=[function]),
        backend_profile=profile,
        init_vtype=init_vtype,
    )
    return pipeline.emit_function(
        prepared,
        state_factory=lambda: StateTracker(vlenb=source_vlenb),
        # SimulatedStateLayout 的总大小/CSR offset 仍是 simulated_cpu_state ABI 权威；
        # 过渡 payload 的 32B 紧凑解释继续由 state_view 独占。
        allocator_factory=SimulatedStateLayout,
        dispatcher_factory=RVV1024Dispatcher,
        emission_options=EmissionOptions(),
        func_name=function.name or "translated_func",
        text_only=text_only,
        raw=raw,
        tls_state=tls_state,
    )


def translate_program(
    program: RVProgram,
    *,
    source_vlenb: int = SOURCE_VLENB,
    target_vlenb: int = TARGET_VLENB,
    source_file: str = "input.s",
    text_only: bool = False,
    init_vtype: str | None = None,
    lib_name: str = "main",
    state_base_mode: str = "initial-exec",
    runtime_vtype_guard: bool = True,
) -> str:
    """翻译完整 objdump 输入，并保持现有 offset-map/地址标签合同。"""
    if not isinstance(program, RVProgram):
        raise TypeError("translate_program() 需要 RVProgram；请先构造统一程序对象")
    profile = make_transition_profile(
        source_vlenb=source_vlenb,
        target_vlenb=target_vlenb,
        runtime_vtype_guard=runtime_vtype_guard,
    )

    def run_preflight(prepared_program: RVProgram, prepared_analysis):
        return preflight_program(
            prepared_program,
            analysis=prepared_analysis,
            dispatcher_factory=RVV1024Dispatcher,
            source_vlenb=source_vlenb,
            init_vtype=init_vtype,
            allow_mixed_unknown_vtype=(
                profile.preflight_policy == "mixed-unknown-runtime-guard"
            ),
            allow_ebreak_fallback=(profile.fallback_policy == "ebreak"),
        )

    pipeline = TranslationPipeline(
        _make_emitter(state_base_mode=state_base_mode),
        preflight_planner=run_preflight,
    )

    prepared = pipeline.prepare(
        program,
        backend_profile=profile,
        init_vtype=init_vtype,
    )
    return pipeline.emit_program(
        prepared,
        state_factory=lambda: StateTracker(vlenb=source_vlenb),
        allocator_factory=SimulatedStateLayout,
        dispatcher_factory=RVV1024Dispatcher,
        emission_options=EmissionOptions(),
        text_only=text_only,
        lib_name=lib_name,
    )


def main() -> None:
    """命令行入口；只在整文件预检和生成均成功后才打开输出文件。"""
    parser = argparse.ArgumentParser(
        description="RVV256 原生状态 → RVV1024 迁移过渡汇编翻译器"
    )
    parser.add_argument("input", nargs="?", help="输入汇编或 objdump 文本")
    parser.add_argument(
        "lib_name",
        nargs="?",
        help="可选库名；提供后启用完整 objdump 程序级翻译模式",
    )
    parser.add_argument("-c", "--command", help="单条或片段汇编文本")
    parser.add_argument("-o", "--output", help="输出文件；失败时不会创建或覆盖")
    parser.add_argument("--source-vlenb", type=int, default=SOURCE_VLENB)
    parser.add_argument("--target-vlenb", type=int, default=TARGET_VLENB)
    parser.add_argument("--text-only", action="store_true")
    parser.add_argument("--init-vtype", help="单函数/片段的初始源 vtype")
    parser.add_argument("--raw", action="store_true", help="只输出翻译块正文")
    parser.add_argument("--func-name", help="单函数输出符号名")
    parser.add_argument(
        "--state-base-mode",
        choices=StateAccessEmitter.STATE_BASE_MODES,
        default="initial-exec",
        help="状态基址获取方式：initial-exec 或 helper",
    )
    args = parser.parse_args()
    if not args.input and not args.command:
        parser.error("Need input file or -c/--command")

    source_label = args.input or "<command>"
    try:
        asm_parser = AsmParser()
        if args.command:
            instructions = asm_parser.parse_string(args.command)
            result = translate(
                instructions,
                source_vlenb=args.source_vlenb,
                target_vlenb=args.target_vlenb,
                source_file=source_label,
                text_only=args.text_only,
                init_vtype=args.init_vtype,
                raw=args.raw,
                func_name=args.func_name,
                state_base_mode=args.state_base_mode,
            )
        elif args.lib_name:
            program = asm_parser.parse_file_program(args.input)
            result = translate_program(
                program,
                source_vlenb=args.source_vlenb,
                target_vlenb=args.target_vlenb,
                source_file=source_label,
                text_only=args.text_only,
                init_vtype=args.init_vtype,
                lib_name=args.lib_name,
                state_base_mode=args.state_base_mode,
            )
        else:
            instructions = asm_parser.parse_file(args.input)
            result = translate(
                instructions,
                source_vlenb=args.source_vlenb,
                target_vlenb=args.target_vlenb,
                source_file=source_label,
                text_only=args.text_only,
                init_vtype=args.init_vtype,
                raw=args.raw,
                func_name=args.func_name,
                state_base_mode=args.state_base_mode,
            )
    except (TransitionPreflightError, ValueError, FileNotFoundError) as exc:
        print(f"翻译失败: {exc}", file=sys.stderr)
        raise SystemExit(1)
    except Exception as exc:
        # 其他异常表示翻译器内部错误，仍不得在 -o 路径留下半成品。
        print(f"翻译器内部错误: {exc}", file=sys.stderr)
        raise SystemExit(1)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as output:
            output.write(result)
        print(f"已翻译: {source_label} -> {args.output}")
    else:
        print(result)


if __name__ == "__main__":
    main()
