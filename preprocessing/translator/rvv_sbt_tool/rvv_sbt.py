# rvv_sbt.py
"""
RVV-to-Scalar Static Binary Translator

单一入口模块：接收 List[RVInstruction]，输出翻译后的标量汇编代码。
当前按“单函数 objdump 片段”作为主输入假设；片段、函数与程序入口都先经
``TranslationPipeline.prepare()``，再选择兼容函数包装或程序包装发射。

Usage:
    # As module:
    from rvv_sbt import translate
    result = translate(insn_list)

    # As CLI:
    python3 rvv_sbt.py input.s -o output.s
"""
import sys
import argparse
from typing import List

from pathlib import Path

# The public scripts also run directly from the bundled source tree.
sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

from riscv.frontend.model import RVFunction, RVInstruction, RVProgram
from riscv.frontend.parser import AsmParser
from riscv.extensions.rvv.translation.pipeline import EmissionOptions, TranslationPipeline
from riscv.extensions.rvv.analysis.config import StateTracker
from riscv.extensions.rvv.runtime.layout import SimulatedStateLayout
from riscv.extensions.rvv.backends.scalar.backend import ScalarDispatcher
from riscv.extensions.rvv.translation.contracts import UnsupportedInstructionError
from riscv.extensions.rvv.backends.scalar.backend import make_scalar_profile
from riscv.extensions.rvv.translation.emitter import ProgramEmitter
from riscv.extensions.rvv.runtime.access import StateAccessEmitter


def translate(
    insn_list: List[RVInstruction],
    vlenb: int = 128,
    source_file: str = "input.s",
    text_only: bool = False,
    init_vtype: str | None = None,
    raw: bool = False,
    func_name: str | None = None,
    state_base_mode: str = "initial-exec",
) -> str:
    """
    兼容入口：在单函数模式下委托给 translate_function()

    :param insn_list: RVInstruction 列表（来自 asm_parser 或其他工具）
    :param vlenb: VLEN/8，默认 128 (VLEN=1024)
    :param source_file: Retained for API compatibility; currently does not affect output.
    :param text_only: 是否只保留 `.text` 与正文，去掉 `.globl/.type/.size/.comm`
    :param raw: 仅输出纯翻译块（无函数包装）
    :param func_name: 自定义函数名
    :param state_base_mode: 状态基址模式，默认 ``initial-exec``；可回退为 ``helper``
    :return: 翻译后的汇编代码字符串
    """
    if func_name is None:
        func_name = "translated_func"
        for insn in insn_list:
            if insn.label and not insn.label.startswith('.') and not insn.label.isdigit():
                func_name = insn.label
                break

    function = RVFunction(
        name=func_name,
        start_addr=insn_list[0].address if insn_list else 0,
        instructions=list(insn_list),
    )
    return translate_function(
        function=function,
        vlenb=vlenb,
        text_only=text_only,
        init_vtype=init_vtype,
        raw=raw,
        state_base_mode=state_base_mode,
    )


def translate_function(
    function: RVFunction,
    func_name: str | None = None,
    vlenb: int = 128,
    source_file: str = "input.s",
    text_only: bool = False,
    init_vtype: str | None = None,
    raw: bool = False,
    state_base_mode: str = "initial-exec",
) -> str:
    """
    翻译为单个函数（带函数标签和 .globl）

    :param function: 单函数源程序对象
    :param func_name: 可选的输出函数名；缺省使用 ``function.name``
    :param vlenb: VLEN/8
    :param source_file: Retained for API compatibility; currently does not affect output.
    :param text_only: 是否只保留 `.text` 与正文，去掉 `.globl/.type/.size/.comm`
    :param raw: 仅输出纯翻译块（无函数包装）
    :param state_base_mode: 状态基址模式，默认使用无调用的 Initial-Exec TLS
    :return: 翻译后的汇编代码字符串
    """
    if not isinstance(function, RVFunction):
        raise TypeError("translate_function() 需要 RVFunction；片段请使用 translate()")
    output_name = func_name or function.name or "translated_func"
    pipeline = TranslationPipeline(
        ProgramEmitter(vlenb=vlenb, state_base_mode=state_base_mode)
    )
    prepared = pipeline.prepare(
        RVProgram(functions=[function]),
        backend_profile=make_scalar_profile(vlenb=vlenb),
        init_vtype=init_vtype,
    )
    return pipeline.emit_function(
        prepared,
        state_factory=lambda: StateTracker(vlenb=vlenb),
        allocator_factory=lambda: SimulatedStateLayout(vlenb=vlenb),
        dispatcher_factory=ScalarDispatcher,
        emission_options=EmissionOptions(),
        func_name=output_name,
        text_only=text_only,
        raw=raw,
    )


def translate_program(
    program: RVProgram,
    vlenb: int = 128,
    source_file: str = "input.s",
    text_only: bool = False,
    init_vtype: str | None = None,
    lib_name: str = "main",
    state_base_mode: str = "initial-exec",
) -> str:
    """程序级标量翻译入口，并在内部执行 CFG/vtype 分析。"""

    if not isinstance(program, RVProgram):
        raise TypeError("translate_program() 需要 RVProgram；请先构造统一程序对象")
    pipeline = TranslationPipeline(
        ProgramEmitter(vlenb=vlenb, state_base_mode=state_base_mode)
    )
    prepared = pipeline.prepare(
        program,
        backend_profile=make_scalar_profile(vlenb=vlenb),
        init_vtype=init_vtype,
    )
    return pipeline.emit_program(
        prepared,
        state_factory=lambda: StateTracker(vlenb=vlenb),
        allocator_factory=lambda: SimulatedStateLayout(vlenb=vlenb),
        dispatcher_factory=ScalarDispatcher,
        emission_options=EmissionOptions(),
        text_only=text_only,
        lib_name=lib_name,
    )


__all__ = ['translate', 'translate_function', 'translate_program']


def main():
    """命令行入口"""
    parser = argparse.ArgumentParser(
        description='RVV-to-Scalar Static Binary Translator'
    )
    parser.add_argument(
        'input',
        nargs='?',
        help='Input .s file with RVV instructions'
    )
    parser.add_argument(
        'lib_name',
        nargs='?',
        help='Optional library/program name; enables whole-objdump translation mode'
    )
    parser.add_argument(
        '-c', '--command',
        type=str,
        default=None,
        help='Inline RVV instruction string (e.g. "vfmacc.vv v8,v8,v12")'
    )
    parser.add_argument(
        '-o', '--output',
        help='Output file (default: stdout)',
        default=None
    )
    parser.add_argument(
        '--vlenb',
        type=int,
        default=128,
        help='VLEN/8 (default: 128, for VLEN=1024)'
    )
    parser.add_argument(
        '--text-only',
        action='store_true',
        help='只保留 .text 与正文，去掉 .globl/.type/.size/.comm 等包装字段'
    )
    parser.add_argument(
        '--init-vtype',
        type=str,
        default=None,
        help='为 StateTracker 播种 vtype 值，不产生输出'
            '（原始数值如 0xDA，或语义形式如 sew=32,lmul=2,ta,ma；省略策略使用 tu,mu）'
    )
    parser.add_argument(
        '--raw',
        action='store_true',
        help='仅输出纯翻译块（无函数标签/ret/.comm，仅状态基址装载 + handler 输出）'
    )
    parser.add_argument(
        '--func-name',
        type=str,
        default=None,
        help='自定义函数名 (默认: translated_func)'
    )
    parser.add_argument(
        '--state-base-mode',
        choices=StateAccessEmitter.STATE_BASE_MODES,
        default='initial-exec',
        help='状态基址获取方式：initial-exec（默认，无函数调用）或 helper（兼容回退）'
    )

    args = parser.parse_args()
    if args.command and (args.input or args.lib_name):
        parser.error("-c/--command 不能与输入文件或 lib_name 同时使用")

    # 必须提供 input 文件或 -c 命令
    if not args.input and not args.command:
        parser.error("必须提供 input 文件或 -c/--command 参数")

    # 解析输入
    asm_parser = AsmParser()
    source_label = args.input or "<command>"
    try:
        if args.command:
            insn_list = asm_parser.parse_string(args.command)
        elif args.lib_name:
            program = asm_parser.parse_file_program(args.input)
            insn_list = None
        else:
            insn_list = asm_parser.parse_file(args.input)
    except FileNotFoundError:
        print(f"Error: Input file not found: {args.input}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error parsing input: {e}", file=sys.stderr)
        sys.exit(1)

    # 翻译
    try:
        if args.lib_name:
            result = translate_program(
                program,
                vlenb=args.vlenb,
                source_file=source_label,
                text_only=args.text_only,
                init_vtype=args.init_vtype,
                lib_name=args.lib_name,
                state_base_mode=args.state_base_mode,
            )
        else:
            result = translate(
                insn_list,
                vlenb=args.vlenb,
                source_file=source_label,
                text_only=args.text_only,
                init_vtype=args.init_vtype,
                raw=args.raw,
                func_name=args.func_name,
                state_base_mode=args.state_base_mode,
            )
    except UnsupportedInstructionError as e:
        print(f"Translation error: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:  # noqa: BLE001 - CLI 顶层兜底，避免留下半成品输出
        print(f"Translator internal error: {e}", file=sys.stderr)
        sys.exit(1)

    # 输出。生成文本含非 ASCII 注释，必须显式 UTF-8，不能依赖 locale。
    if args.output:
        with open(args.output, 'w', encoding='utf-8') as f:
            f.write(result)
        print(f"Translated: {source_label} -> {args.output}")
    else:
        print(result)


if __name__ == '__main__':
    main()
