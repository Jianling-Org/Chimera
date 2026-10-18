#!/usr/bin/env python3
"""Program-level translator contract tests."""
import os
import re
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from riscv.frontend.parser import AsmParser
import riscv.extensions.rvv.translation.pipeline as pipeline_module
import riscv.codegen.jal_range_fixup as jal_fixup_module
import riscv.frontend.analysis as cfg_pipeline_module
from riscv.extensions.rvv.translation.pipeline import TranslationPipeline
from riscv.extensions.rvv.translation.contracts import BackendProfile
from riscv.extensions.rvv.translation.pipeline import analyze_program
from riscv.extensions.rvv.runtime.contract import RVV1024_TO_RVV256
from riscv.frontend.model import RVProgram
import rvv_sbt_rvv
import rvv_sbt
import rvv_sbt_rvv1024
from rvv_sbt_rvv import translate_program as _translate_program


def translate_program(functions, **kwargs):
    """测试辅助：把解析结果封装为正式 RVProgram 后再调用入口。"""

    return _translate_program(RVProgram(functions=list(functions)), **kwargs)


def _instruction_block(output, address):
    """取出一个源地址对应的发射片段，避免被跳板内部的同名 j 干扰。"""

    marker = f"# 原偏移: 0x{address:x}"
    start = output.index(marker)
    end = output.find("# 原偏移:", start + len(marker))
    return output[start:] if end < 0 else output[start:end]


def _context_program():
    return AsmParser().parse_string_program(
        """
0000000000001000 <foo>:
    1000: 0d0577d7             vsetvli a5, a0, e32, m1, ta, ma
    1004: 02050457             vadd.vv v8, v8, v16
    1008: 8082                 ret
"""
    )


def _profile():
    return BackendProfile(
        name="test",
        source_vlenb=128,
        target_vlenb=32,
        fallback_policy="ebreak",
        preflight_policy="none",
    )


def test_pipeline_prepare_requires_unified_program():
    pipeline = TranslationPipeline(object())
    with pytest.raises(TypeError, match="需要 RVProgram"):
        pipeline.prepare([], backend_profile=_profile())


def test_pipeline_does_not_accept_external_analysis():
    program = _context_program()
    pipeline = TranslationPipeline(object())
    with pytest.raises(TypeError, match="unexpected keyword argument 'analysis'"):
        pipeline.prepare(
            program,
            backend_profile=_profile(),
            analysis=analyze_program(program),
        )


def test_pipeline_rejects_missing_vector_instruction_analysis(monkeypatch):
    program = _context_program()
    analysis = analyze_program(program)
    function_analysis = analysis.functions[0x1000]
    function_analysis.instructions.pop(0x1004)
    monkeypatch.setattr(pipeline_module, "analyze_program", lambda _program: analysis)
    pipeline = TranslationPipeline(object())
    with pytest.raises(ValueError, match="缺少 InstructionAnalysis"):
        pipeline.prepare(program, backend_profile=_profile())


def test_pipeline_enforces_profile_preflight_policy():
    """preflight 回调与 profile 必须一一对应，禁止展示字段与真实行为漂移。"""

    program = _context_program()
    strict_profile = BackendProfile(
        name="strict-test",
        source_vlenb=32,
        target_vlenb=128,
        fallback_policy="reject",
        preflight_policy="strict",
        runtime_vtype_dispatch=False,
    )
    pipeline = TranslationPipeline(object())
    with pytest.raises(ValueError, match="要求提供预检器"):
        pipeline.prepare(program, backend_profile=strict_profile)

    strict_pipeline = TranslationPipeline(
        object(), preflight_planner=lambda _program, _analysis: ()
    )
    prepared = strict_pipeline.prepare(program, backend_profile=strict_profile)
    assert prepared.backend_profile is strict_profile

    with pytest.raises(ValueError, match="不得注入额外预检器"):
        strict_pipeline.prepare(program, backend_profile=_profile())


@pytest.mark.parametrize(
    "translator",
    (rvv_sbt, rvv_sbt_rvv, rvv_sbt_rvv1024),
)
def test_public_fragment_apis_prepare_exactly_once(monkeypatch, translator):
    """三条公开片段 API 都必须先完成一次 CFG/vtype 准备。"""

    calls = 0
    original = pipeline_module.analyze_program

    def counted(program, **kwargs):
        nonlocal calls
        calls += 1
        return original(program, **kwargs)

    monkeypatch.setattr(pipeline_module, "analyze_program", counted)
    output = translator.translate(
        AsmParser().parse_string("vadd.vv v8, v16, v24"),
        init_vtype="sew=32,lmul=1",
        raw=True,
    )

    assert output
    assert calls == 1


@pytest.mark.parametrize(
    "translator",
    (rvv_sbt, rvv_sbt_rvv, rvv_sbt_rvv1024),
)
def test_public_fragment_source_file_is_compatibility_only(translator):
    """公开 source_file 参数仍可调用，但不改变片段输出。"""

    default_output = translator.translate(
        AsmParser().parse_string("vadd.vv v8, v16, v24"),
        init_vtype="sew=32,lmul=1",
        raw=True,
    )
    custom_output = translator.translate(
        AsmParser().parse_string("vadd.vv v8, v16, v24"),
        source_file="custom-input.s",
        init_vtype="sew=32,lmul=1",
        raw=True,
    )

    assert custom_output == default_output


def test_jal_probe_rounds_reuse_single_preparation(monkeypatch):
    """两轮探测和最终输出只能分析、计算指纹、结构校验各一次。"""

    counts = {"analysis": 0, "fingerprint": 0, "validation": 0}
    original_analysis = pipeline_module.analyze_program
    original_fingerprint = cfg_pipeline_module.compute_program_fingerprint
    original_validation = pipeline_module._validate_analyzed_program

    def counted_analysis(program):
        counts["analysis"] += 1
        return original_analysis(program)

    def counted_fingerprint(program):
        counts["fingerprint"] += 1
        return original_fingerprint(program)

    def counted_validation(program, analysis):
        counts["validation"] += 1
        return original_validation(program, analysis)

    def fake_resolve_jal_ranges(*, translate_round, **_kwargs):
        translate_round(frozenset(), True)
        final = translate_round(frozenset({0x1000}), False)
        return final, frozenset({0x1000})

    monkeypatch.setattr(pipeline_module, "analyze_program", counted_analysis)
    monkeypatch.setattr(
        cfg_pipeline_module, "compute_program_fingerprint", counted_fingerprint
    )
    monkeypatch.setattr(
        pipeline_module, "_validate_analyzed_program", counted_validation
    )
    monkeypatch.setattr(
        jal_fixup_module, "resolve_jal_ranges", fake_resolve_jal_ranges
    )

    program = AsmParser().parse_string_program(
        """
0000000000001000 <foo>:
    1000: 0080006f             j       1008
    1004: 8082                 ret
0000000000001008 <.Ltarget>:
    1008: 8082                 ret
"""
    )
    output, sites = rvv_sbt_rvv.translate_program_with_jal_range_fixup(program)

    assert sites == frozenset({0x1000})
    assert "branch_j_target_1008:" in output
    assert counts == {"analysis": 1, "fingerprint": 1, "validation": 1}


def test_repeated_emission_resets_session_label_allocation():
    """同一 PreparedTranslation 的多轮发射必须产生完全相同的局部标签。"""

    program = AsmParser().parse_string_program(
        """
0000000000001000 <foo>:
    1000: c119                 beqz    a0, 1010
    1004: 0c0577d7             vsetvli a5, a0, e16, m1, ta, ma
    1008: a011                 j       1014
    1010: 0d0577d7             vsetvli a5, a0, e32, m1, ta, ma
    1014: 02050457             vadd.vv v8, v16, v24
    1018: 8082                 ret
"""
    )
    pipeline, prepared = rvv_sbt_rvv._prepare_program_translation(
        program,
        vlenb=128,
        init_vtype=None,
        state_base_mode="initial-exec",
        wide_lmul=True,
    )

    def emit_once():
        return rvv_sbt_rvv._emit_prepared_program(
            pipeline,
            prepared,
            vlenb=128,
            text_only=False,
            lib_name="session_labels",
            wide_lmul=True,
        )

    first = emit_once()
    second = emit_once()
    assert "runtime vtype dispatch" in first
    assert first == second


def test_parse_functions_and_emit_program_contract():
    asm = """
0000000000001000 <foo>:
    1000: 0505                 addi    a0, a0, 1
    1002: c119                 beqz    a0, 1008 <.L0>
0000000000001008 <.L0>:
    1008: 8082                 ret

0000000000002000 <bar>:
    2000: 0505                 addi    a0, a0, 1
    2002: c119                 beqz    a0, 2008 <.L0>
0000000000002008 <.L0>:
    2008: 8082                 ret
"""
    parser = AsmParser()
    functions = parser.parse_string_functions(asm)

    assert [fn.name for fn in functions] == ["foo", "bar"]
    assert [fn.start_addr for fn in functions] == [0x1000, 0x2000]
    assert len(functions[0].instructions) == 3
    assert functions[0].instructions[1].operands == ["a0", ".L0"]

    output = translate_program(functions, source_file="contract.objdump.s")

    assert ".globl  foo_translated" in output
    assert "foo_translated:" in output
    assert ".globl  bar_translated" in output
    assert "bar_translated:" in output
    assert "# 原偏移: 0x1000" in output
    assert "# 原偏移: 0x1002" in output
    assert "# 原偏移: 0x2000" in output
    assert ".Lchimera_foo__L0_1008:" in output
    assert ".Lchimera_bar__L0_2008:" in output
    assert "branch_j_target_1008:" in output
    assert "branch_j_target_2008:" in output
    assert "beqz     a0, branch_j_target_1008" in output
    assert "beqz     a0, branch_j_target_2008" in output
    assert ".globl main_original_base_addr" in output


def test_program_mode_keeps_handler_labels_unique():
    asm = """
0000000000001000 <foo>:
    1000: 0d0577d7             vsetvli a5, a0, e32, m1, ta, ma
    1004: 8082                 ret

0000000000002000 <bar>:
    2000: 0d0577d7             vsetvli a5, a0, e32, m1, ta, ma
    2004: 8082                 ret
"""
    functions = AsmParser().parse_string_functions(asm)
    output = translate_program(functions, source_file="handler_labels.objdump.s")

    assert ".L_rvv256_vsetvli_skip_0:" in output
    assert ".L_rvv256_vsetvli_skip_1:" in output


def test_program_mode_stage1_remaining_contracts():
    asm = """
0000000000003000 <baz>:
    3000: c2202573             csrr    a0, vlenb
    3004: 0d0577d7             vsetvli a5, a0, e32, m1, ta, ma
    3008: deadbeef             vunknown.vv v1, v2, v3
    300c: 8082                 ret
"""
    functions = AsmParser().parse_string_functions(asm)
    output = translate_program(
        functions,
        source_file="stage1_remaining.objdump.s",
    )

    assert re.search(r"li\s+(\w+), 128\n\s+mv\s+a0, \1", output)
    assert "fallback to ebreak" in output
    assert "    ebreak" in output
    assert f"la.tls.ie t6, {RVV1024_TO_RVV256.state_symbol}" in output
    assert "add     t6, t6, tp" in output
    assert "get_simulated_cpu_state_addr@plt" not in output
    assert ".globl main_original_base_addr" in output
    assert ".comm   simulated_cpu_state" not in output


def test_program_mode_vfwredusum_ambiguous_vtype_uses_runtime_dispatch():
    asm = """
0000000000400000 <softmax_tail>:
  400000: 00050663             beqz a0, 40000c
  400004: cd00f057             vsetivli zero, 1, e16, m1, ta, ma
  400008: 0080006f             j 400010
  40000c: cd00f057             vsetivli zero, 1, e32, m1, ta, ma
  400010: c6241457             vfwredusum.vs v8, v2, v8
  400014: 8082                 ret
"""
    functions = AsmParser().parse_string_functions(asm)
    output = translate_program(
        functions,
        source_file="vfwred_dynamic.objdump.s",
    )

    assert "runtime vtype dispatch" in output
    assert "dispatch on simulated CSR.vtype" in output
    assert "vfwredusum.vs v25, v24, v25" in output
    assert "Unsupported RVV instruction lowered to ebreak: vfwredusum.vs" not in output
    assert "e16->e32" in output and "e32->e64" in output


def test_program_mode_vfwredusum_known_e64_is_rejected():
    source = """
0000000000400000 <invalid_widening>:
  400000: cd80f057             vsetivli zero, 1, e64, m1, ta, ma
  400004: c6241457             vfwredusum.vs v8, v2, v8
  400008: 8082                 ret
"""
    output = translate_program(AsmParser().parse_string_functions(source))
    assert "runtime vtype dispatch" not in output
    assert "vfwredusum.vs does not support SEW=64" in output
    assert "fallback to ebreak" in output


def test_program_mode_control_flow_and_base_delta_contracts():
    asm = """
0000000000001000 <foo>:
    1000: 00000517             auipc   a0, 0x0
    1004: c119                 beqz    a0, 1010 <.L0>
    1008: 0100006f             j       1014
0000000000001010 <.L0>:
    1010: 020000ef             jal     2000 <bar>
    1014: 000780e7             jalr    ra, 0(a5)
    1018: 8082                 ret

0000000000002000 <bar>:
    2000: 8082                 ret
"""
    functions = AsmParser().parse_string_functions(asm)
    output = translate_program(
        functions,
        source_file="control.objdump.s",
        lib_name="demo",
    )

    assert "branch_j_target_1000:" in output
    assert "beqz     a0, branch_j_target_1010" in output
    assert re.search(r"\bj\s+branch_j_target_1014\b", output)
    local_j_block = _instruction_block(output, 0x1008)
    assert ".Lchimera_pcrel_j_1008:" not in local_j_block
    assert re.search(r"\bj\s+branch_j_target_1014\b", local_j_block)
    assert "call    bar_translated" in output
    assert "demo_original_base_addr" in output
    assert "call    query_original_translated_map@plt" in output
    assert "li      a0, 1" in output
    assert "# jalr target remap" in output
    assert "# ret target remap" in output


def test_program_mode_local_j_long_jump_veneer_preserves_contract():
    """被范围修正标记的本地 j 使用 t0 保留跳板且不新增迁移入口。"""

    asm = """
0000000000001000 <foo>:
   1000: 0100006f             j       1008
   1004: 8082                 ret
0000000000001008 <.Ltarget>:
   1008: 8082                 ret
"""
    functions = AsmParser().parse_string_functions(asm)

    output = translate_program(
        functions,
        source_file="local_j_veneer.objdump.s",
        long_jump_sites={0x1000},
    )

    assert "addi    sp, sp, -16" in output
    assert "sd      t0, 0(sp)" in output
    assert "auipc   t0, %pcrel_hi(.Lchimera_veneer_" in output
    assert ".Lchimera_pcrel_j_1000:" in output
    assert "jalr    x0, %pcrel_lo(.Lchimera_pcrel_j_1000)(t0)" in output
    assert "ld      t0, 0(sp)" in output
    assert "addi    sp, sp, 16" in output
    assert "branch_j_target_1008:" in output
    assert len(re.findall(r"(?m)^branch_j_target_1008:$", output)) == 1
    assert "chimera_j_site_1000:" not in output


def test_program_mode_local_j_probe_marker_is_not_migration_label():
    """范围探测标签只在探测轮输出，且不取代 branch_j_target。"""

    asm = """
0000000000002000 <foo>:
   2000: 0100006f             j       2008
   2004: 8082                 ret
0000000000002008 <.Ltarget>:
   2008: 8082                 ret
"""
    functions = AsmParser().parse_string_functions(asm)

    output = translate_program(
        functions,
        source_file="local_j_probe.objdump.s",
        emit_jump_site_markers=True,
    )

    assert "chimera_j_site_2000:" in output
    assert "branch_j_target_2008:" in output
    assert len(re.findall(r"(?m)^branch_j_target_2008:$", output)) == 1
    # 观察轮显式关闭自动长跳，才能保留可供外部检查的 R_RISCV_JAL。
    assert re.search(r"\bj\s+branch_j_target_2008\b", _instruction_block(output, 0x2000))


def test_program_mode_local_j_defaults_to_short_jump():
    """底层纯文本 emitter 保持短 j；正常 CLI 另行负责对象级范围修正。"""

    asm = """
0000000000002400 <foo>:
   2400: 0100006f             j       2408
   2404: 8082                 ret
0000000000002408 <.Ltarget>:
   2408: 8082                 ret
"""
    functions = AsmParser().parse_string_functions(asm)

    output = translate_program(
        functions,
        source_file="local_j_default_short_jump.objdump.s",
    )
    block = _instruction_block(output, 0x2400)

    assert ".Lchimera_pcrel_j_2400:" not in block
    assert re.search(r"\bj\s+branch_j_target_2408\b", block)
    assert "chimera_j_site_2400:" not in output


def test_program_cli_enables_jal_range_fixup_by_default(monkeypatch, tmp_path):
    """程序模式的正常 CLI 不需要开关即可执行选择性长跳流程。"""

    input_path = tmp_path / "program.objdump.s"
    output_path = tmp_path / "translated.s"
    input_path.write_text(
        "0000000000001000 <foo>:\n"
        "   1000: 8082                 ret\n",
        encoding="utf-8",
    )
    calls = []

    def fake_fixup(program, **kwargs):
        calls.append((program, kwargs))
        return "fixed-output\n", frozenset({0x1000})

    monkeypatch.setattr(rvv_sbt_rvv, "translate_file_with_jal_range_fixup", fake_fixup)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "rvv_sbt_rvv.py",
            str(input_path),
            "demo",
            "-o",
            str(output_path),
        ],
    )

    rvv_sbt_rvv.main()

    assert output_path.read_text(encoding="utf-8") == "fixed-output\n"
    assert len(calls) == 1
    _program, options = calls[0]
    assert _program == str(input_path)
    assert options["compiler"] == "gcc"
    assert options["compiler_args"] == rvv_sbt_rvv.DEFAULT_JAL_RANGE_FIXUP_COMPILER_ARGS
    assert any("_zfh" in option for option in options["compiler_args"])


def test_program_mode_local_j_reuses_one_veneer_per_target():
    """多个超范围 site 指向同一目标时只生成一个共享跳板。"""

    asm = """
0000000000003000 <foo>:
   3000: 0100006f             j       3010
   3004: 0100006f             j       3010
   3008: 8082                 ret
0000000000003010 <.Ltarget>:
   3010: 8082                 ret
"""
    functions = AsmParser().parse_string_functions(asm)

    output = translate_program(
        functions,
        source_file="local_j_shared_veneer.objdump.s",
        long_jump_sites={0x3000, 0x3004},
    )

    assert output.count(".Lchimera_veneer_foo_translated_branch_j_target_3010:") == 1
    assert output.count("auipc   t0, %pcrel_hi(.Lchimera_veneer_") == 2


def test_program_mode_local_j_only_selected_site_uses_shared_veneer():
    """同一目标存在多个本地 j 时，未选中的 site 仍保持短跳。"""

    asm = """
0000000000003200 <foo>:
   3200: 0100006f             j       3210
   3204: 0100006f             j       3210
   3208: 8082                 ret
0000000000003210 <.Ltarget>:
   3210: 8082                 ret
"""
    functions = AsmParser().parse_string_functions(asm)

    output = translate_program(
        functions,
        source_file="local_j_selective_shared_veneer.objdump.s",
        long_jump_sites={0x3200},
    )

    selected_block = _instruction_block(output, 0x3200)
    unselected_block = _instruction_block(output, 0x3204)
    assert "auipc   t0, %pcrel_hi(.Lchimera_veneer_" in selected_block
    assert ".Lchimera_pcrel_j_3200:" in selected_block
    assert ".Lchimera_pcrel_j_3204:" not in unselected_block
    assert re.search(r"\bj\s+branch_j_target_3210\b", unselected_block)
    assert output.count(".Lchimera_veneer_foo_translated_branch_j_target_3210:") == 1


def test_program_mode_jr_offset_operand_uses_address_parse_helper():
    asm = """
0000000000001000 <foo>:
   1000: 5a030067             jr      1442(t1)
"""
    functions = AsmParser().parse_string_functions(asm)
    output = translate_program(
        functions,
        source_file="jr_offset_operand.objdump.s",
    )

    assert "# jr target remap" in output
    assert "ld      a1, 16(sp)" in output
    assert "addi    a1, a1, 1442" in output
    assert "mv      a1, 1442(t1)" not in output
    assert "ld      1442(t1), 128(sp)" not in output
    assert "ld      t1, 16(sp)" in output
    assert re.search(r"\bjr\s+1442\(t1\)", output)
    assert "chimera_jump_mapped_v1" not in output
    assert "bne     a0, t0, .Lchimera_indirect_reject_1000" in output
    assert "Unsupported no-link indirect target remap\n    ebreak" in output


def test_parser_preserves_objdump_control_flow_target_address():
    asm = """
00000000000436b0 <foo>:
    436b0: c71f40ef             jal     38320 <memset@plt>
"""
    functions = AsmParser().parse_string_functions(asm)
    insn = functions[0].instructions[0]

    assert insn.operands == ["memset@plt"]
    assert insn.target_address == 0x38320
    assert insn.target_symbol == "memset@plt"


def test_program_mode_rewrites_jal_by_objdump_target_address():
    asm = """
0000000000038320 <memset@plt>:
   38320: 00573e17             auipc   t3,0x573
   38324: 000e0367             jalr    t1,t3

00000000000436b0 <foo>:
   436b0: c71f40ef             jal     38320 <memset@plt>
   436b4: 8082                 ret
"""
    functions = AsmParser().parse_string_functions(asm)
    output = translate_program(
        functions,
        source_file="jal_target_address.objdump.s",
    )

    assert "memset_plt_translated" not in output
    assert "%got_pcrel_hi(memset)" in output
    assert "    jalr    ra, 0(t1)" in output
    assert "    call    memset@plt" not in output
    assert "jal      memset_plt_translated" not in output


def test_program_mode_rewrites_objdump_function_offset_targets():
    asm = """
0000000000038ccc <foo>:
   38ccc: 1141                 addi    sp,sp,-16
   38cce: 00090663             beqz    s2,38cda <foo+0xe>
   38cd2: a021                 j       38ce2 <foo+0x16>
   38cda: 4501                 li      a0,0
   38ce2: 8082                 ret
"""
    functions = AsmParser().parse_string_functions(asm)
    output = translate_program(
        functions,
        source_file="function_offset_targets.objdump.s",
    )

    assert "beqz     s2, branch_j_target_38cda" in output
    assert re.search(r"\bj\s+branch_j_target_38ce2\b", output)
    local_j_block = _instruction_block(output, 0x38CD2)
    assert ".Lchimera_pcrel_j_38cd2:" not in local_j_block
    assert re.search(r"\bj\s+branch_j_target_38ce2\b", local_j_block)


def test_program_mode_branch_to_function_start_uses_address_label():
    asm = """
00000000000436b0 <foo>:
   436b0: 872a                 mv      a4,a0
   436b2: f77d                 bnez    a4,436b0 <foo>
   436b4: 8082                 ret
"""
    functions = AsmParser().parse_string_functions(asm)
    output = translate_program(
        functions,
        source_file="branch_to_function_start.objdump.s",
    )

    assert "bnez     a4, branch_j_target_436b0" in output
    assert "bnez     a4, foo_translated" not in output


@pytest.mark.parametrize("translator", (rvv_sbt, rvv_sbt_rvv, rvv_sbt_rvv1024))
@pytest.mark.parametrize("jump", ("j", "jal x0,", "jal zero,"))
@pytest.mark.parametrize("target", ("2000 <bar>", "2004 <bar+0x4>"), ids=("entry", "interior"))
def test_program_mode_cross_function_jump_preserves_registers(translator, jump, target):
    program = AsmParser().parse_string_program(
        f"""
0000000000001000 <foo>:
   1000: 0100006f             {jump} {target}
   1004: 8082                 ret

0000000000002000 <bar>:
   2000: 1141                 addi    sp,sp,-16
   2002: 0001                 nop
   2004: 8082                 ret
"""
    )
    output = translator.translate_program(program)
    jump_block = _instruction_block(output, 0x1000)
    target_address = int(target.split()[0], 16)

    assert not re.search(r"\b(?:call|tail|t1)\b", jump_block)
    assert re.search(r"addi\s+sp, sp, -16", jump_block)
    assert re.search(r"sd\s+t0, 0\(sp\)", jump_block)
    pcrel = re.search(r"auipc\s+t0, %pcrel_hi\(([^)]+)\)", jump_block)
    assert pcrel is not None
    assert re.search(r"jalr\s+x0, %pcrel_lo\([^)]+\)\(t0\)", jump_block)
    assert re.search(
        re.escape(pcrel.group(1))
        + r":\n\s+ld\s+t0, 0\(sp\)\n\s+addi\s+sp, sp, 16\n"
        + rf"\s+j\s+branch_j_target_{target_address:x}\b",
        output,
    )
    assert "chimera_j_site_1000:" not in output


@pytest.mark.parametrize("translator", (rvv_sbt, rvv_sbt_rvv, rvv_sbt_rvv1024))
@pytest.mark.parametrize("instruction, emitted", (("call", "call"), ("jal ra,", "call"), ("tail", "tail")))
def test_program_mode_explicit_calls_keep_calling_convention(translator, instruction, emitted):
    program = AsmParser().parse_string_program(
        f"00001000 <foo>:\n 1000: 000000ef {instruction} 2000 <bar>\n"
        "00002000 <bar>:\n 2000: 00008067 ret\n"
    )
    output = translator.translate_program(program)
    call_block = _instruction_block(output, 0x1000)
    assert re.search(rf"\b{emitted}\s+bar_translated\b", call_block)
    assert "%pcrel_hi" not in call_block


def test_program_mode_jal_ra_to_other_function_interior_uses_call_exact_target():
    """写入 ra 的跨函数内部入口必须保留 call/返回地址语义。"""
    asm = """
0000000000001000 <foo>:
   1000: 000000ef             jal     ra, 2004 <bar+0x4>
   1004: 8082                 ret

0000000000002000 <bar>:
   2000: 1141                 addi    sp,sp,-16
   2002: 0001                 nop
   2004: 8082                 ret
"""
    functions = AsmParser().parse_string_functions(asm)
    output = translate_program(
        functions,
        source_file="jal_ra_to_other_function_interior.objdump.s",
    )

    assert re.search(r"\bcall\s+branch_j_target_2004\b", output)
    assert not re.search(r"\btail\s+branch_j_target_2004\b", output)
    assert not re.search(r"\bj\s+branch_j_target_2004\b", output)


def test_program_mode_j_to_plt_uses_tail():
    asm = """
0000000000038320 <memset@plt>:
   38320: 00573e17             auipc   t3,0x573
   38324: 000e0367             jalr    t1,t3

00000000000436b0 <foo>:
   436b0: bfd5                 j       38320 <memset@plt>
   436b2: 8082                 ret
"""
    functions = AsmParser().parse_string_functions(asm)
    output = translate_program(
        functions,
        source_file="jump_to_plt.objdump.s",
    )

    assert "%got_pcrel_hi(memset)" in output
    assert "    jalr    x0, 0(t1)" in output
    assert not re.search(r"\btail\s+memset@plt\b", output)
    assert not re.search(r"\bj\s+memset@plt\b", output)


def test_program_mode_jal_x0_to_plt_uses_tail():
    asm = """
0000000000038320 <memset@plt>:
   38320: 00573e17             auipc   t3,0x573
   38324: 000e0367             jalr    t1,t3

00000000000436b0 <foo>:
   436b0: 000000ef             jal     x0, 38320 <memset@plt>
   436b4: 8082                 ret
"""
    functions = AsmParser().parse_string_functions(asm)
    output = translate_program(
        functions,
        source_file="jal_x0_to_plt.objdump.s",
    )

    assert "%got_pcrel_hi(memset)" in output
    assert "    jalr    x0, 0(t1)" in output
    assert not re.search(r"\btail\s+memset@plt\b", output)
    assert not re.search(r"\bcall\s+memset@plt\b", output)


def test_program_mode_explicit_jal_rd_keeps_link_register():
    asm = """
0000000000001000 <foo>:
   1000: 000002ef             jal     t0, 1010 <bar>
   1004: 8082                 ret

0000000000001010 <bar>:
   1010: 8082                 ret
"""
    functions = AsmParser().parse_string_functions(asm)
    output = translate_program(
        functions,
        source_file="jal_t0_to_other_function.objdump.s",
    )

    assert "jal      t0, bar_translated" in output
    assert "jal      bar_translated, bar_translated" not in output


def test_program_mode_explicit_jal_rd_to_plt_falls_back_to_ebreak():
    asm = """
0000000000038320 <memset@plt>:
   38320: 00573e17             auipc   t3,0x573
   38324: 000e0367             jalr    t1,t3

00000000000436b0 <foo>:
   436b0: 000002ef             jal     t0, 38320 <memset@plt>
   436b4: 8082                 ret
"""
    functions = AsmParser().parse_string_functions(asm)
    output = translate_program(
        functions,
        source_file="jal_t0_to_plt.objdump.s",
    )

    assert "Unsupported scalar instruction lowered to ebreak" in output
    assert "custom link-register direct calls to @plt are not supported" in output
    assert "    ebreak" in output
    assert "call    memset@plt" not in output
