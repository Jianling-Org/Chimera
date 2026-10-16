#!/usr/bin/env python3
"""
RVV 1024-bit to 256-bit Translator

将 VLEN=1024（模拟状态）的 RVV 指令翻译为 VLEN=256 的实际 RVV 指令，
使用 strip-mining 将 1024-bit 的向量操作分解为多个 256-bit 块。

Usage:
    python3 rvv_sbt_rvv.py input.s -o output.s
    python3 rvv_sbt_rvv.py -c "vfmacc.vf v8, fa0, v16" --init-vtype sew=64,lmul=1 --text-only
"""

import sys
from dataclasses import replace
import argparse
import gc
import tempfile
from typing import Iterable, Iterator, Sequence

from pathlib import Path

# The public scripts also run directly from the bundled source tree.
sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

from riscv.frontend.model import RVFunction, RVProgram
from riscv.frontend.parser import AsmParser
from riscv.extensions.rvv.translation.pipeline import EmissionOptions, PreparedTranslation, TranslationPipeline
from riscv.extensions.rvv.analysis.config import StateTracker
from riscv.extensions.rvv.runtime.layout import SimulatedStateLayout
from riscv.extensions.rvv.translation.emitter import ProgramEmitter
from riscv.extensions.rvv.runtime.access import StateAccessEmitter
from riscv.extensions.rvv.runtime.contract import RVV1024_TO_RVV256
from riscv.extensions.rvv.backends.rvv256.backend import RVV256Dispatcher
from riscv.extensions.rvv.translation.contracts import UnsupportedInstructionError
from riscv.extensions.rvv.backends.rvv256.backend import make_rvv256_profile


# 程序模式的正常入口必须先完成对象级范围探测，再输出正式汇编。
# 目标机 CLI 默认使用本机 ``gcc``，因为测试命令在 RISC-V 真机上直接调用
# 它完成最终共享对象构建。探测阶段必须使用与最终共享对象相同的 ISA（指令集
# 架构）参数；否则含有半精度浮点指令（例如 ``fadd.h``）的输入会在探测阶段
# 先因缺少 ``zfh`` 扩展而失败。这里与 preprocessing/offline/config 中的默认
# Linux RVV profile 保持一致，调用方仍可通过 CLI/API 显式传入另一套参数。
DEFAULT_PROGRAM_CLI_JAL_RANGE_FIXUP_COMPILER = "gcc"
DEFAULT_API_JAL_RANGE_FIXUP_COMPILER = "riscv64-unknown-linux-gnu-gcc"
DEFAULT_JAL_RANGE_FIXUP_COMPILER_ARGS = (
    "-fPIC",
    "-march=rv64imafdc_zba_zbb_zbc_zbs_zfa_zfh_zicond_zicsr_zifencei_"
    "zihintpause_zihpm_zkt_zvbb_zvbc_zve32f_zve32x_zve64d_zve64f_zve64x_"
    "zvfh_zvfhmin_zvkb_zvkg_zvkned_zvknha_zvknhb_zvksed_zvksh_zvkt_zicbop_"
    "zihintntl",
    "-mabi=lp64d",
)


def _make_emitter(
    *, vlenb: int = 128, state_base_mode: str = "initial-exec"
) -> ProgramEmitter:
    """构造 1024→256 发射器，并固定跨运行时的状态 ABI 参数。

    入口不再通过继承覆写通用 emitter。模拟状态仍按每个逻辑 vreg 128 字节
    解释；profile=1 同时写入 ret/jalr/jr 的地址查表调用，不能与反向过渡
    后端的状态符号或 lookup profile 混用。
    """

    return ProgramEmitter(
        vlenb=vlenb,
        state_base_mode=state_base_mode,
        state_symbol=RVV1024_TO_RVV256.state_symbol,
        lookup_profile=RVV1024_TO_RVV256.lookup_profile,
    )

# ============================================================================
# 翻译入口
# ============================================================================

def translate(
    insn_list,
    vlenb=128,
    source_file="input.s",
    text_only=False,
    init_vtype=None,
    raw=False,
    func_name=None,
    tls_state=True,
    state_base_mode="initial-exec",
    wide_lmul=True,
):
    """
    将指令列表翻译为 256-bit RVV 汇编

    :param insn_list: RVInstruction 列表
    :param vlenb: VLEN/8 (默认 128，对应 1024-bit 模拟状态)
    :param source_file: Retained for API compatibility; currently does not affect output.
    :param text_only: 是否只保留正文
    :param init_vtype: 初始 vtype 字符串 (如 'sew=64,lmul=1')
    :param raw: 是否只输出纯翻译块
    :param func_name: 自定义函数名 (默认 'translated_func')
    :param tls_state: 是否通过 TLS 访问 simulated_cpu_state
    :param state_base_mode: 状态基址模式，默认 ``initial-exec``；可回退为 ``helper``
    :param wide_lmul: 是否使用 RVV256 宽 LMUL 性能 profile，默认启用；传入
        ``False`` 可选择原有的保守 profile。
    :return: 汇编代码字符串
    """
    # 函数名：显式传入 > 自动检测 > 默认值。片段入口仍接受列表，
    # 但内部立即封装成 RVFunction，避免 emitter 看到平行的源程序表示。
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
        function,
        vlenb=vlenb,
        text_only=text_only,
        init_vtype=init_vtype,
        raw=raw,
        tls_state=tls_state,
        state_base_mode=state_base_mode,
        wide_lmul=wide_lmul,
    )


def translate_function(
    function: RVFunction,
    vlenb=128,
    source_file="input.s",
    text_only=False,
    init_vtype=None,
    raw=False,
    tls_state=True,
    state_base_mode="initial-exec",
    wide_lmul=True,
    *,
    strict: bool = False,
):
    """翻译单个函数；strict=True 在不支持的形态处拒绝生成输出。"""
    if not isinstance(function, RVFunction):
        raise TypeError("translate_function() 需要 RVFunction；片段请使用 translate()")

    profile = make_rvv256_profile(wide_lmul=wide_lmul, source_vlenb=vlenb)
    if strict:
        profile = replace(profile, fallback_policy="raise")
    pipeline = TranslationPipeline(
        _make_emitter(vlenb=vlenb, state_base_mode=state_base_mode)
    )
    prepared = pipeline.prepare(
        RVProgram(functions=[function]),
        backend_profile=profile,
        init_vtype=init_vtype,
    )
    return pipeline.emit_function(
        prepared,
        state_factory=lambda: StateTracker(vlenb=vlenb),
        allocator_factory=lambda: SimulatedStateLayout(vlenb=vlenb),
        dispatcher_factory=lambda: RVV256Dispatcher(wide_lmul=wide_lmul),
        emission_options=EmissionOptions(),
        func_name=function.name or "translated_func",
        text_only=text_only,
        raw=raw,
        tls_state=tls_state,
    )


def _prepare_program_translation(
    program: RVProgram,
    *,
    vlenb: int,
    init_vtype: str | None,
    state_base_mode: str,
    wide_lmul: bool,
) -> tuple[TranslationPipeline, PreparedTranslation]:
    """建立可供普通发射和多轮 JAL 探测共同复用的准备结果。"""

    if not isinstance(program, RVProgram):
        raise TypeError("程序级翻译需要 RVProgram；请先构造统一程序对象")
    pipeline = TranslationPipeline(
        _make_emitter(vlenb=vlenb, state_base_mode=state_base_mode)
    )
    prepared = pipeline.prepare(
        program,
        backend_profile=make_rvv256_profile(
            wide_lmul=wide_lmul, source_vlenb=vlenb
        ),
        init_vtype=init_vtype,
    )
    return pipeline, prepared


def _emit_prepared_program(
    pipeline: TranslationPipeline,
    prepared: PreparedTranslation,
    *,
    vlenb: int,
    text_only: bool,
    lib_name: str,
    wide_lmul: bool,
    long_jump_sites: Iterable[int] = (),
    emit_jump_site_markers: bool = False,
    stream: bool = False,
    program_context=None,
) -> str | Iterator[str]:
    """仅执行一轮发射；该函数不得重新分析 ``prepared.program``。"""

    options = dict(
        state_factory=lambda: StateTracker(vlenb=vlenb),
        allocator_factory=lambda: SimulatedStateLayout(vlenb=vlenb),
        dispatcher_factory=lambda: RVV256Dispatcher(wide_lmul=wide_lmul),
        emission_options=EmissionOptions(
            long_jump_sites=long_jump_sites,  # type: ignore[arg-type]
            emit_jump_site_markers=emit_jump_site_markers,
        ),
        text_only=text_only,
        lib_name=lib_name,
    )
    if stream:
        return pipeline.iter_emit_program(prepared, program_context=program_context, **options)
    return pipeline.emit_program(prepared, **options)


def translate_program(
    program: RVProgram,
    vlenb=128,
    source_file="input.s",
    text_only=False,
    init_vtype=None,
    lib_name="main",
    state_base_mode="initial-exec",
    wide_lmul=True,
    long_jump_sites: Iterable[int] = (),
    emit_jump_site_markers: bool = False,
):
    """
    将完整 objdump 的函数列表翻译为程序级汇编。

    每个源函数输出为 `<func>_translated`，每条源指令前输出
    `# 原偏移` 注释，供离线 offset map 生成器消费。

    :param state_base_mode: 状态基址模式，默认使用无调用的 Initial-Exec TLS
    :param wide_lmul: 是否使用 RVV256 宽 LMUL 性能 profile，默认启用；传入
        ``False`` 可选择原有的保守 profile。
    :param long_jump_sites: 显式选择需要发射本地长跳的源 ``j`` 指令地址集合。
        正常情况下由对象级范围检查得到；集合之外的本地 ``j`` 保持短跳。
    :param emit_jump_site_markers: 是否输出供对象级范围探测使用的内部标签。
    """
    pipeline, prepared = _prepare_program_translation(
        program,
        vlenb=vlenb,
        init_vtype=init_vtype,
        state_base_mode=state_base_mode,
        wide_lmul=wide_lmul,
    )
    return _emit_prepared_program(
        pipeline,
        prepared,
        vlenb=vlenb,
        text_only=text_only,
        lib_name=lib_name,
        wide_lmul=wide_lmul,
        long_jump_sites=long_jump_sites,
        emit_jump_site_markers=emit_jump_site_markers,
    )


def translate_program_with_jal_range_fixup(
    program: RVProgram,
    vlenb=128,
    source_file="input.s",
    text_only=False,
    init_vtype=None,
    lib_name="main",
    state_base_mode="initial-exec",
    wide_lmul=True,
    compiler: str | Sequence[str] = DEFAULT_API_JAL_RANGE_FIXUP_COMPILER,
    readelf: str | Sequence[str] = "readelf",
    compiler_args: Sequence[str] = DEFAULT_JAL_RANGE_FIXUP_COMPILER_ARGS,
    max_iterations: int = 8,
    output_path: str | Path | None = None,
) -> tuple[str | None, frozenset[int]]:
    """生成只对对象确认越界 site 使用长跳的程序汇编。

    该入口仍位于翻译器目录内。每一轮先由本模块生成短 ``j`` 探测汇编，
    再使用调用方提供的生产 RISC-V 编译器生成对象，并读取 JAL/RVC jump
    重定位；只有对象中实际越界且能通过 ``chimera_j_site_*`` 映射回源地址
    的 site 才进入下一轮长跳集合。最终返回正式汇编和已修正的源地址集合。

    该入口是程序模式的正常生成流程。底层 ``translate_program()`` 仍然保留
    纯文本发射能力，供单元测试和第一轮探测使用；用户通过 CLI 进行完整程序
    翻译时会默认调用本入口，范围修正不是可关闭的兼容选项。
    compiler/readelf/``-march`` 参数必须与最终构建环境一致。
    """

    if not isinstance(program, RVProgram):
        raise TypeError("translate_program_with_jal_range_fixup() 需要 RVProgram")

    pipeline, prepared = _prepare_program_translation(
        program,
        vlenb=vlenb,
        init_vtype=init_vtype,
        state_base_mode=state_base_mode,
        wide_lmul=wide_lmul,
    )
    return _resolve_prepared_program(
        pipeline, prepared, vlenb=vlenb, text_only=text_only,
        lib_name=lib_name, wide_lmul=wide_lmul, compiler=compiler, readelf=readelf,
        compiler_args=compiler_args, max_iterations=max_iterations,
        output_path=output_path, stream=output_path is not None,
    )


def _prepare_stored_file(input_path, stream, *, vlenb, init_vtype, state_base_mode, wide_lmul):
    from riscv.extensions.rvv.translation.program_store import PreparedProgramStore

    program = AsmParser(retain_raw_lines=False).parse_file_program(str(input_path))
    pipeline, prepared = _prepare_program_translation(
        program, vlenb=vlenb, init_vtype=init_vtype,
        state_base_mode=state_base_mode, wide_lmul=wide_lmul,
    )
    program_context = pipeline.emitter.control_flow.build_program_context(
        [function for function in program.functions if "@plt" not in function.name]
    )
    store = PreparedProgramStore(stream, program, prepared.analysis, program_context)
    stored_program, stored_analysis = store.views()
    stored = PreparedTranslation._from_pipeline(
        program=stored_program, analysis=stored_analysis,
        backend_profile=prepared.backend_profile, init_vtype=prepared.init_vtype,
        preflight_plans=prepared.preflight_plans,
    )
    AsmParser._objdump_operands.cache_clear()
    AsmParser._objdump_encoding.cache_clear()
    return pipeline, stored, store.program_context


def translate_file_with_jal_range_fixup(
    input_path: str | Path,
    vlenb=128,
    source_file="input.s",
    text_only=False,
    init_vtype=None,
    lib_name="main",
    state_base_mode="initial-exec",
    wide_lmul=True,
    compiler: str | Sequence[str] = DEFAULT_API_JAL_RANGE_FIXUP_COMPILER,
    readelf: str | Sequence[str] = "readelf",
    compiler_args: Sequence[str] = DEFAULT_JAL_RANGE_FIXUP_COMPILER_ARGS,
    max_iterations: int = 8,
    output_path: str | Path | None = None,
) -> tuple[str | None, frozenset[int]]:
    """Analyze once, then release the whole-program IR before object tools run."""
    with tempfile.TemporaryFile(prefix="chimera-prepared-") as storage:
        pipeline, prepared, program_context = _prepare_stored_file(
            input_path, storage, vlenb=vlenb, init_vtype=init_vtype,
            state_base_mode=state_base_mode, wide_lmul=wide_lmul,
        )
        gc.collect()
        return _resolve_prepared_program(
            pipeline, prepared, vlenb=vlenb, text_only=text_only,
            lib_name=lib_name, wide_lmul=wide_lmul, compiler=compiler, readelf=readelf,
            compiler_args=compiler_args, max_iterations=max_iterations,
            output_path=output_path, stream=True, program_context=program_context,
        )


def _resolve_prepared_program(
    pipeline, prepared, *, vlenb, text_only, lib_name, wide_lmul,
    compiler, readelf, compiler_args, max_iterations, output_path,
    stream, program_context=None,
):
    from riscv.codegen.jal_range_fixup import resolve_jal_ranges

    def translate_round(sites: frozenset[int], emit_markers: bool) -> str | Iterator[str]:
        return _emit_prepared_program(
            pipeline,
            prepared,
            vlenb=vlenb,
            text_only=text_only,
            lib_name=lib_name,
            wide_lmul=wide_lmul,
            long_jump_sites=sites,
            emit_jump_site_markers=emit_markers,
            stream=stream,
            program_context=program_context,
        )

    return resolve_jal_ranges(
        translate_round=translate_round,
        compiler=compiler,
        readelf=readelf,
        compiler_args=compiler_args,
        max_iterations=max_iterations,
        output_path=output_path,
    )


# ============================================================================
# CLI 入口
# ============================================================================

def _read_long_jump_sites_file(path: str) -> tuple[int, ...]:
    """读取诊断/兼容模式使用的源 ``j`` 地址列表。"""

    sites: list[int] = []
    with open(path, "r", encoding="utf-8") as source:
        for line_number, raw_line in enumerate(source, start=1):
            token = raw_line.split("#", 1)[0].strip()
            if not token:
                continue
            try:
                # 允许 ``0x55f88`` 和不带前缀的 ``55f88`` 两种写法。
                value = int(token, 0)
            except ValueError:
                try:
                    value = int(token, 16)
                except ValueError as exc:
                    raise ValueError(
                        f"范围修正地址文件第 {line_number} 行不是合法整数: {token!r}"
                    ) from exc
            if value < 0:
                raise ValueError(
                    f"范围修正地址文件第 {line_number} 行包含负数地址: {value}"
                )
            sites.append(value)
    return tuple(sites)


def main():
    """命令行入口"""
    parser = argparse.ArgumentParser(
        description='RVV 1024->256-bit Translator',
        # 已删除的兼容参数不能通过 argparse 的长选项前缀匹配到仍有效的
        # JAL 工具参数；关闭缩写后，旧参数会稳定地产生明确错误。
        allow_abbrev=False,
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
        help='Inline instruction string (e.g. "vfmacc.vf v8, fa0, v16")'
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
        help=(
            'VLEN/8 for sim state (default: 128, for VLEN=1024). '
            '本路径只支持 128；其他值会按未登记的翻译方向拒绝'
        )
    )
    parser.add_argument(
        '--text-only',
        action='store_true',
        help='Only emit .text and instruction body'
    )
    parser.add_argument(
        '--init-vtype',
        type=str,
        default=None,
        help='Seed StateTracker with vtype (e.g. "sew=64,lmul=1")'
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
    parser.add_argument(
        '--long-jump-sites-file',
        type=str,
        default=None,
        help='程序模式本地 j 长跳源地址文件，每行一个十六进制或十进制地址',
    )
    parser.add_argument(
        '--emit-jump-site-markers',
        action='store_true',
        help='输出供 R_RISCV_JAL 范围探测使用的内部 site 标签',
    )
    parser.add_argument(
        '--jal-range-fixup-compiler',
        type=str,
        default=DEFAULT_PROGRAM_CLI_JAL_RANGE_FIXUP_COMPILER,
        help=(
            '程序模式默认范围修正使用的 RISC-V 编译器命令；'
            '需与最终构建工具链一致（默认: gcc）'
        ),
    )
    parser.add_argument(
        '--jal-range-fixup-readelf',
        type=str,
        default='readelf',
        help='JAL 范围修正使用的 readelf 命令（默认: readelf）',
    )
    parser.add_argument(
        '--jal-range-fixup-compiler-arg',
        action='append',
        default=[],
        help='替换默认编译器参数（仍保留 -fPIC），可重复使用；必须给出完整 ISA/ABI，例如 -march=rv64gcv 和 -mabi=lp64d',
    )
    parser.add_argument(
        '--jal-range-fixup-max-iterations',
        type=int,
        default=8,
        help='JAL 范围修正最大轮数（默认: 8）',
    )
    parser.add_argument(
        '--conservative',
        dest='wide_lmul',
        action='store_false',
        default=True,
        help='使用原有保守 RVV256 profile（禁用宽 LMUL 热点路径）'
    )
    args = parser.parse_args()
    if args.command and (args.input or args.lib_name):
        parser.error("-c/--command 不能与输入文件或 lib_name 同时使用")

    # 必须提供 input 文件或 -c 命令
    if not args.input and not args.command:
        parser.error("Need input file or -c/--command")

    long_jump_sites = ()
    manual_jump_probe = bool(args.long_jump_sites_file or args.emit_jump_site_markers)
    if args.long_jump_sites_file or args.emit_jump_site_markers:
        if not args.lib_name:
            parser.error("本地 j 范围修正选项只适用于程序模式（需要提供 lib_name）")
        if args.long_jump_sites_file:
            long_jump_sites = _read_long_jump_sites_file(args.long_jump_sites_file)

    # 解析输入
    # Program emission uses parsed fields and original addresses, not raw text.
    asm_parser = AsmParser(retain_raw_lines=not bool(args.lib_name))
    source_label = args.input or "<command>"
    try:
        if args.command:
            insn_list = asm_parser.parse_string(args.command)
        elif args.lib_name:
            program = asm_parser.parse_file_program(args.input) if manual_jump_probe else None
            insn_list = None
        else:
            insn_list = asm_parser.parse_file(args.input)
    except FileNotFoundError as e:
        message = (
            f"Error: Input file not found: {args.input}"
            if e.filename == args.input
            else f"Translator internal error: {e}"
        )
        print(message, file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error parsing: {e}", file=sys.stderr)
        sys.exit(1)

    # 翻译
    try:
        if args.lib_name:
            # 完整程序翻译默认执行对象级范围修正。手工 site 文件和探测标签
            # 是调试/测试接口：一旦显式要求它们，就只发射对应的探测文本，
            # 避免在探测轮中递归再次调用范围修正器。
            if not manual_jump_probe:
                result, fixed_sites = translate_file_with_jal_range_fixup(
                    args.input,
                    vlenb=args.vlenb,
                    source_file=source_label,
                    text_only=args.text_only,
                    init_vtype=args.init_vtype,
                    lib_name=args.lib_name,
                    state_base_mode=args.state_base_mode,
                    wide_lmul=args.wide_lmul,
                    compiler=args.jal_range_fixup_compiler,
                    readelf=args.jal_range_fixup_readelf,
                    compiler_args=(
                        ("-fPIC", *tuple(args.jal_range_fixup_compiler_arg))
                        if args.jal_range_fixup_compiler_arg
                        else DEFAULT_JAL_RANGE_FIXUP_COMPILER_ARGS
                    ),
                    max_iterations=args.jal_range_fixup_max_iterations,
                    output_path=args.output,
                )
                print(
                    f"JAL range fixup: {len(fixed_sites)} local site(s) use long jump",
                    file=sys.stderr,
                )
            else:
                result = translate_program(
                    program,
                    vlenb=args.vlenb,
                    source_file=source_label,
                    text_only=args.text_only,
                    init_vtype=args.init_vtype,
                    lib_name=args.lib_name,
                    state_base_mode=args.state_base_mode,
                    wide_lmul=args.wide_lmul,
                    long_jump_sites=long_jump_sites,
                    emit_jump_site_markers=args.emit_jump_site_markers,
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
                wide_lmul=args.wide_lmul,
            )
    except FileNotFoundError as e:
        message = (
            f"Error: Input file not found: {args.input}"
            if e.filename == args.input
            else f"Translator internal error: {e}"
        )
        print(message, file=sys.stderr)
        sys.exit(1)
    except UnsupportedInstructionError as e:
        # 输入包含未注册/未实现形态：这是输入问题，不是翻译器缺陷。
        print(f"Translation error: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:  # noqa: BLE001 - CLI 顶层兜底，避免留下半成品输出
        print(f"Translator internal error: {e}", file=sys.stderr)
        sys.exit(1)

    # 输出。生成文本含非 ASCII 注释，必须显式 UTF-8，
    # 不能依赖目标机 locale（LANG=C 会触发 UnicodeEncodeError）。
    if args.output:
        if result is not None:
            with open(args.output, 'w', encoding='utf-8') as f:
                f.write(result)
        print(f"Translated: {source_label} -> {args.output}")
    else:
        print(result)


if __name__ == '__main__':
    main()
