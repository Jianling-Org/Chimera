#!/usr/bin/env python3
"""RVV256→RVV1024 过渡路径的结构与合同测试。

这些测试只验证翻译期接口、紧凑状态寻址、预检和程序级 emitter 合同；它们
不能替代 VLEN=1024 目标机上的参考/候选全状态差分。尤其 Pack/Unpack 的最终
算术与掩码正确性仍应由目标环境验证器覆盖。
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest


sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from riscv.frontend.parser import AsmParser
from riscv.extensions.rvv.translation.pipeline import analyze_program
from riscv.frontend.model import RVFunction, RVProgram
from riscv.extensions.rvv.analysis.model import parse_init_vtype
from riscv.extensions.rvv.backends.rvv1024_transition.backend import RVV1024Dispatcher
from riscv.extensions.rvv.backends.rvv1024_transition.state_view import (
    SOURCE_VLENB,
    TARGET_VLENB,
    emit_source_vreg_address,
    source_group_byte_size,
    transfer_lmul_for_bytes,
)
from riscv.extensions.rvv.backends.rvv1024_transition.temp_regs import VRegTempAllocator
from riscv.extensions.rvv.backends.rvv1024_transition.preflight import (
    TransitionPreflightError,
    preflight_instruction_stream,
    preflight_program,
)
from riscv.extensions.rvv.backends.rvv1024_transition.backend import make_transition_profile
from rvv_sbt_rvv1024 import translate, translate_program


def _translate_program(functions, **kwargs):
    """测试辅助：程序入口只接收统一 RVProgram。"""

    return translate_program(RVProgram(functions=list(functions)), **kwargs)


def _instructions(asm: str):
    """用与 CLI 相同的 parser 构造测试输入。"""
    return AsmParser().parse_string(asm)


def test_preflight_builds_plans_without_calling_lowerer(monkeypatch):
    """预检只能运行纯 validator，不能生成再丢弃汇编。"""

    def forbidden_lower(*_args, **_kwargs):
        raise AssertionError("preflight 不得调用 lowerer")

    monkeypatch.setattr(RVV1024Dispatcher, "lower", forbidden_lower)
    instructions = _instructions("vadd.vv v8, v16, v24")
    function = RVFunction("preflight", 0, instructions)
    analysis = analyze_program(
        RVProgram(functions=[function]),
        initial_vtype=parse_init_vtype("sew=32,lmul=1"),
    ).for_function(function.start_addr)
    assert analysis is not None
    plans = preflight_instruction_stream(
        instructions,
        analysis=analysis,
        dispatcher_factory=RVV1024Dispatcher,
        init_vtype="sew=32,lmul=1",
    )

    assert len(plans) == 1
    assert plans[0].instruction.opcode == "vadd.vv"
    assert plans[0].normalized_operands == ("v8", "v16", "v24")


def test_transition_profile_uses_ebreak_for_instruction_failures():
    assert make_transition_profile().fallback_policy == "ebreak"


def test_preflight_remains_strict_without_ebreak_opt_in():
    """底层预检默认仍可用于需要完整计划的调用方。"""
    instructions = _instructions("vdiv.vv v8, v16, v24")
    function = RVFunction("strict-preflight", 0, instructions)
    analysis = analyze_program(
        RVProgram(functions=[function]),
        initial_vtype=parse_init_vtype("sew=32,lmul=1"),
    ).for_function(function.start_addr)
    assert analysis is not None

    with pytest.raises(TransitionPreflightError, match="后端未注册 opcode: vdiv.vv"):
        preflight_instruction_stream(
            instructions,
            analysis=analysis,
            dispatcher_factory=RVV1024Dispatcher,
            init_vtype="sew=32,lmul=1",
        )


def test_program_preflight_skips_empty_function_records():
    """只有函数头而没有指令的符号不应阻断程序级预检。"""
    program = RVProgram(
        functions=[RVFunction("empty", 0x2463D2, instructions=[])],
    )
    analysis = analyze_program(program)

    assert preflight_program(
        program,
        analysis=analysis,
        dispatcher_factory=RVV1024Dispatcher,
        allow_ebreak_fallback=True,
    ) == ()


def test_vmv_v_i_validates_and_lowers_in_transition_backend():
    """vmv.v.i 的立即数与目的寄存器组均通过后应进入正常 lowering。"""
    output = translate(
        _instructions("vmv.v.i v8, 0"),
        init_vtype="sew=64,lmul=1",
        raw=True,
    )

    assert "RVV1024 fallback" not in output
    assert "vmv.v.i" in output


def test_vmv_v_i_rejects_misaligned_destination_group():
    """vmv.v.i 仍需遵守源端 LMUL 的目的寄存器组对齐规则。"""
    output = translate(
        _instructions("vmv.v.i v9, 0"),
        init_vtype="sew=64,lmul=8",
        raw=True,
    )

    assert "RVV1024 fallback" in output
    assert "不是 m8 组对齐起点" in output
    assert "未知 validation kind" not in output
    assert "    ebreak" in output


@pytest.mark.parametrize(
    ("instruction", "vtype"),
    (
        ("vmv.s.x v9, a0", "sew=32,lmul=8"),
        ("vmv.x.s a0, v9", "sew=32,lmul=8"),
        ("vfmv.s.f v9, fa0", "sew=32,lmul=8"),
        ("vfmv.f.s fa0, v9", "sew=32,lmul=8"),
    ),
)
def test_scalar_element_moves_use_m1_physical_groups(
    instruction: str, vtype: str
):
    """.s move 只触及 element 0，不能按当前 LMUL 要求源寄存器组对齐。"""
    output = translate(_instructions(instruction), init_vtype=vtype, raw=True)

    assert "RVV1024 fallback" not in output
    assert "vsetivli zero, 1, e32, m1, tu, mu" in output


def test_program_emission_reuses_preflight_plans(monkeypatch):
    """程序发射不得为同一指令/candidate 再次调用 validator。"""

    counts = {"plan": 0, "lower": 0}
    original_plan = RVV1024Dispatcher.plan
    original_lower = RVV1024Dispatcher.lower

    def counted_plan(self, *args, **kwargs):
        counts["plan"] += 1
        return original_plan(self, *args, **kwargs)

    def counted_lower(self, *args, **kwargs):
        counts["lower"] += 1
        return original_lower(self, *args, **kwargs)

    monkeypatch.setattr(RVV1024Dispatcher, "plan", counted_plan)
    monkeypatch.setattr(RVV1024Dispatcher, "lower", counted_lower)
    program = AsmParser().parse_string_program(
        """
0000000000001000 <foo>:
    1000: 0d0577d7             vsetvli a5, a0, e32, m1, ta, ma
    1004: 02050457             vadd.vv v8, v8, v16
    1008: 8082                 ret
"""
    )

    output = translate_program(program)

    assert "vadd.vv" in output
    assert counts == {"plan": 2, "lower": 2}


def test_compact_source_layout_and_target_temp_groups():
    """源 vN 必须按 N*32B，而非旧 SimulatedStateLayout 的 128B 槽位寻址。"""
    assert SOURCE_VLENB == 32
    assert TARGET_VLENB == 128
    assert source_group_byte_size("mf8") == 4
    assert source_group_byte_size("m1") == 32
    assert source_group_byte_size("m8") == 256
    assert transfer_lmul_for_bytes(32) == "m1"
    assert transfer_lmul_for_bytes(256) == "m2"

    lines: list[str] = []
    emit_source_vreg_address(lines, "t0", "v31")
    assert lines == ["    addi    t0, t6, 992  # CHIMERA_STATE_BASE"]

    allocator = VRegTempAllocator()
    assert allocator.alloc_vreg_group(8) == "v8"
    assert allocator.alloc_vreg_group(8) == "v16"
    assert allocator.alloc_vreg_group(8) == "v24"


def test_vadd_packs_raw_32b_offsets_before_writing_back():
    """别名安全的 vadd 先读全量源组，再以源 VL 在目标临时组执行。"""
    output = translate(
        _instructions("vadd.vv v8, v16, v24"),
        init_vtype="sew=32,lmul=1",
        raw=True,
    )

    # v8/v16/v24 的源端起点分别是 8/16/24 * 32B，不得变成 128B 槽位。
    assert "addi    t1, t6, 256  # CHIMERA_STATE_BASE" in output
    assert "addi    t1, t6, 512  # CHIMERA_STATE_BASE" in output
    assert "addi    t1, t6, 768  # CHIMERA_STATE_BASE" in output
    assert "vsetvli zero, t0, e32, m1, tu, mu" in output
    assert "vadd.vv    v8, v9, v10" in output
    assert output.index("vle8.v  v9") < output.index("vadd.vv    v8, v9, v10")
    assert output.index("vle8.v  v10") < output.index("vadd.vv    v8, v9, v10")
    assert "源 CSR.vstart = 0" in output


def test_source_config_and_vlenb_csr_keep_rvv256_semantics():
    """vset* 与 csrr vlenb 观察源端 VLENB=32，而非目标硬件 128。"""
    output = translate(
        _instructions("\n".join([
            "vsetvli a0, a1, e8, m8, ta, ma",
            "csrr a2, vlenb",
        ])),
        raw=True,
    )

    assert "VLMAX=256" in output
    assert "li      a2, 32" in output
    assert "真实 RVV1024 硬件 VLENB" in output  # profile guard 仍需检查目标环境。


def test_unit_load_uses_eew_emul_for_compact_payload():
    """EEW 与 SEW 不同时，load 仍按源 EMUL 校验并只提交活动元素。"""
    output = translate(
        _instructions("vle64.v v8, (a0)"),
        init_vtype="sew=32,lmul=1",
        raw=True,
    )

    assert "EEW=e64, 源 SEW=e32, 源 LMUL=m1, EMUL=2" in output
    assert "Pack 源组有效字节数" not in output
    assert "Unpack 源组有效字节数" not in output
    assert "vsetvli zero, t0, e32, m1, tu, mu" in output
    assert "vle64.v   v8, (a0)" in output
    assert "vse64.v   v8, (t1)" in output


def test_whole_register_move_is_vtype_independent_and_copies_256b():
    """vmv8r.v 没有前置 vset* 仍可按固定 8*32B 物理字节复制。"""
    output = translate(_instructions("vmv8r.v v8, v16"), raw=True)

    assert "复制 8 个 RVV256 物理寄存器" in output
    assert "li      t1, 256             # Pack 源组有效字节数" in output
    assert "vsetvli zero, t1, e8, m2, tu, mu" in output
    assert "vle8.v  v8" in output and "vse8.v  v8" in output


def test_preflight_maps_unsupported_masked_form_to_ebreak():
    """未注册 opcode 仍保留诊断，但反向入口按 profile 输出单条 ebreak。"""
    output = translate(
        # vadd 的基础 v0.t 已在批次 2 接通；选择仍未注册的除法 form，
        # 验证 fallback 诊断而非冻结已支持集合。
        _instructions("vdiv.vv v8, v16, v24, v0.t"),
        init_vtype="sew=32,lmul=1",
        raw=True,
    )
    assert "RVV1024 fallback" in output
    assert "后端未注册 opcode: vdiv.vv" in output
    assert "fallback to ebreak" in output
    assert "    ebreak" in output


def test_cli_writes_ebreak_fallback_over_existing_output(tmp_path):
    """可恢复的 lowering 失败由 CLI 正常写出带诊断的 ebreak。"""
    output_path = tmp_path / "must_keep.s"
    output_path.write_text("用户已有内容\n", encoding="utf-8")
    entry = os.path.join(os.path.dirname(os.path.dirname(__file__)), "rvv_sbt_rvv1024.py")
    result = subprocess.run(
        [
            sys.executable,
            entry,
            "-c",
            "vdiv.vv v8, v16, v24, v0.t",
            "--init-vtype",
            "sew=32,lmul=1",
            "-o",
            str(output_path),
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    generated = output_path.read_text(encoding="utf-8")
    assert "用户已有内容" not in generated
    assert "RVV1024 fallback" in generated
    assert "后端未注册 opcode: vdiv.vv" in generated
    assert "    ebreak" in generated


def test_profile_guard_rejects_nonzero_vstart_and_normal_path_has_no_fallback():
    """每个向量入口都检查 vstart；支持 form 不生成 emitter 的未支持回退。"""
    output = translate(
        _instructions("vadd.vv v8, v16, v24"),
        init_vtype="sew=32,lmul=1",
        raw=True,
    )

    assert "一期不支持陷阱重启" in output
    assert "profile 或 vstart 不满足迁移前提" in output
    assert "Unsupported RVV instruction lowered to ebreak" not in output
    assert "未实现 opcode" not in output


def test_program_mode_preserves_existing_address_label_contract():
    """新后端复用程序级 `<func>_translated` 与地址标签，不碰目录外跳转逻辑。"""
    functions = AsmParser().parse_string_functions(
        """
0000000000001000 <foo>:
    1000: 0d0577d7             vsetvli a5, a0, e32, m1, ta, ma
    1004: 02050457             vadd.vv v8, v8, v16 # source: <e32,m1,ta,ma>
    1008: 8082                 ret
"""
    )
    output = _translate_program(functions, source_file="transition.objdump.s")

    assert ".globl  foo_translated" in output
    assert "branch_j_target_1000:" in output
    assert "branch_j_target_1004:" in output
    assert "# 原偏移: 0x1004" in output
    assert "Unsupported RVV instruction lowered to ebreak" not in output


def test_program_mode_uses_internal_cfg_for_arbitrary_branch_entry():
    """内部 CFG 应保留两个真实前驱 vtype，并生成运行时分发。"""
    functions = AsmParser().parse_string_functions(
        """
0000000000001000 <foo>:
    1000: 0d0577d7             vsetvli a5, a0, e8, m1, ta, ma
    1004: 00050463             beq a0, zero, 100c <foo+0xc>
    1008: 0d0577d7             vsetvli a5, a0, e64, m1, ta, ma
    100c: 02050457             vadd.vv v8, v8, v16
    1010: 8082                 ret
"""
    )

    output = _translate_program(functions, source_file="ambiguous-entry.objdump.s")
    vadd = functions[0].instructions[3]
    from riscv.extensions.rvv.translation.pipeline import analyze_program
    from riscv.frontend.model import RVProgram
    analysis = analyze_program(RVProgram(functions=functions))
    assert {candidate.sew for candidate in analysis.for_function(functions[0].start_addr).at(vadd.address).possible_vtypes} == {8, 64}
    assert "runtime vtype dispatch" in output
    assert "Unsupported RVV instruction lowered to ebreak" not in output


def _mixed_unknown_program():
    """构造一个已知前驱与无 vtype 次级入口汇合的程序。"""
    functions = AsmParser().parse_string_functions(
        """
0000000000001000 <foo>:
    1000: 0d0577d7             vsetvli a5, a0, e8, m1, ta, ma
    1004: 00050463             beq a0, zero, 100c <foo+0xc>
    1008: 0d0577d7             vsetvli a5, a0, e64, m1, ta, ma
    100c: 02050457             vadd.vv v8, v8, v16
    1010: 8082                   ret
0000000000001014 <.Lsecondary>:
    1014: a011                   j 100c <foo+0xc>
"""
    )
    return list(functions)


def test_program_mode_can_opt_out_of_mixed_unknown_runtime_guard():
    """关闭 runtime guard 时，混合候选仍以反向后端 fallback 收口。"""
    output = _translate_program(
        _mixed_unknown_program(),
        runtime_vtype_guard=False,
    )
    assert "RVV1024 fallback" in output
    assert "backend profile disables runtime vtype dispatch" in output
    assert "fallback to ebreak" in output


def test_program_mode_runtime_guard_is_default_for_known_mixed_case():
    """默认读取 source vtype；未命中已知候选时 fail-fast。"""
    output = _translate_program(_mixed_unknown_program())
    assert "runtime vtype dispatch for vadd.vv" in output
    assert "No analyzed vtype case matched at runtime" in output
    assert "Unsupported RVV instruction lowered to ebreak" not in output


@pytest.mark.parametrize("raw_vtype", ("0x100", "0x8000000000000000", "0x24"))
def test_raw_init_vtype_rejects_reserved_or_unsupported_shape(raw_vtype: str):
    """新路径不能沿用通用 StateTracker 对 raw vtype 的宽松默认解码。"""
    with pytest.raises(ValueError):
        translate(
            _instructions("vadd.vv v8, v16, v24"),
            init_vtype=raw_vtype,
            raw=True,
        )


def test_dynamic_vsetvl_checks_reserved_vtype_high_bits_before_state_write():
    """运行时 rs2 的保留高位必须走 vill/vl=0 路径，不能低 8 位截断。"""
    # x0,x0 同时会调用“旧 vtype 的 VLMAX”辅助计算，故可覆盖 rs2 和旧 CSR
    # 两条高位保留检查路径。
    output = translate(_instructions("vsetvl zero, zero, a2"), raw=True)
    assert "输入 vtype 保留位非零" in output
    assert output.count("vtype 保留位非零") >= 2


def test_dispatcher_marks_vector_csr_as_vtype_independent():
    """孤立的 csrr vlenb 不需要虚构前置 vset*。"""
    dispatcher = RVV1024Dispatcher()
    insn = _instructions("csrr a0, vlenb")[0]
    assert dispatcher.handles_scalar_instruction(insn)
    assert dispatcher.is_vtype_independent_instruction(insn)


@pytest.mark.parametrize(
    "instruction",
    (
        "csrwi vxrm, 1",
        "csrw vcsr, a0",
        "csrs vxrm, a0",
        "csrsi vxsat, 1",
        "csrc vcsr, a0",
        "csrci vxrm, 1",
        "csrrw a1, vstart, a2",
        "csrrsi a1, vxsat, 1",
    ),
)
def test_writable_vector_csr_write_or_rmw_updates_source_state_only(instruction: str):
    """可写 CSR 只更新 source state，不能透传到真实 RVV1024 CSR。"""
    dispatcher = RVV1024Dispatcher()
    insn = _instructions(instruction)[0]
    assert dispatcher.handles_scalar_instruction(insn)
    output = translate(_instructions(instruction), raw=True)
    code = _assembly_code_without_comments(output)
    assert "模拟源 RVV256 CSR" in output
    assert "源 CSR.vcsr" in output or "源 CSR.vstart" in output
    # 仅 profile guard 会读取目标 vlenb；绝不能把客体 CSR 写原样输出。
    assert not re.search(r"^\s*csr(?:w|wi|s|si|c|ci)\s+(?:vstart|vxsat|vxrm|vcsr)\b", code, re.MULTILINE)


@pytest.mark.parametrize(
    "instruction",
    (
        "csrw vl, a0",
        "csrwi vtype, 1",
        "csrrw a1, vlenb, a2",
    ),
)
def test_vector_csr_actual_write_to_read_only_csr_falls_back(instruction: str):
    """vl/vtype/vlenb 不可被伪造；当前反向 profile 用 ebreak 明确收口。"""
    output = translate(_instructions(instruction), raw=True)
    assert "RVV1024 fallback" in output
    assert "不允许写只读 vector CSR" in output
    assert "    ebreak" in output


def test_zero_mask_rmw_on_read_only_csr_is_a_safe_read_not_a_write():
    """CSRRSI zimm=0 读取 source vlenb，不能被误判成只读 CSR 写入。"""
    output = translate(_instructions("csrrsi a1, vlenb, 0"), raw=True)
    code = _assembly_code_without_comments(output)
    assert re.search(r"^\s*li\s+a1,\s+32\b", code, re.MULTILINE)
    assert "不允许写只读" not in output


def test_csr_rmw_same_rd_rs1_survives_helper_state_base_call():
    """csrrw a0,...,a0 必须先恢复原 a0，再在 state 写回后提交旧 CSR。"""
    output = translate(
        _instructions("csrrw a0, vxrm, a0"), raw=True, state_base_mode="helper"
    )
    assert "恢复 TLS helper 可能破坏的原始标量输入" in output
    assert re.search(r"^\s*ld\s+a0,\s+\d+\(sp\)$", output, re.MULTILINE)
    assert output.index("源 CSR.vcsr") < output.rindex("rd = CSR 旧值")
    restore_tail = output[output.index("# 恢复 RVV 翻译块现场"):]
    assert "ld      a0," not in restore_tail


def test_csr_rmw_x31_preserves_input_and_commits_output_after_state_write():
    """x31/t6 既作 rs1 又作 rd 时，state-base 与旧 CSR 结果不能互相覆盖。"""
    output = translate(
        _instructions("csrrw x31, vxrm, x31"), raw=True, state_base_mode="helper"
    )
    assert "恢复源指令作为输入使用的原始 t6" in output
    state_write = output.index("源 CSR.vcsr")
    result_write = output.index("mv      x31,")
    assert state_write < result_write
    restore_tail = output[output.index("# 恢复 RVV 翻译块现场"):]
    assert "ld      t6," not in restore_tail


@pytest.mark.parametrize(
    ("instruction", "native_opcode"),
    (
        ("vmv.x.s t6, v1", "vmv.x.s"),
        ("vfirst.m t6, v1", "vfirst.m"),
        ("vcpop.m t6, v1", "vcpop.m"),
    ),
)
def test_scalar_result_t6_is_delayed_until_after_state_postamble(
    instruction: str,
    native_opcode: str,
):
    """t6 作为语义输出时，vcsr/vstart 写回不能再把结果当状态基址。"""
    output = translate(
        _instructions(instruction), init_vtype="sew=8,lmul=1", raw=True
    )
    native_match = re.search(
        rf"^\s*{re.escape(native_opcode)}\s+t6,\s+v8$", output, re.MULTILINE
    )
    assert native_match is not None
    native_index = native_match.start()

    assert output.index("源 CSR.vcsr") < native_index
    assert output.index("源 CSR.vstart = 0") < native_index
    # wrapper 把 t6 识别为语义输出，不能在尾部 reload 旧值覆盖新结果。
    restore_tail = output[output.index("# 恢复 RVV 翻译块现场"):]
    assert "ld      t6," not in restore_tail


@pytest.mark.parametrize(
    "instruction",
    (
        "vmv.x.s sp, v1",
        "vfirst.m sp, v1",
        "vcpop.m x2, v1",
        "vsetivli sp, 1, e8, m1, ta, ma",
        "csrr sp, vl",
        "csrrw x2, vxrm, a0",
    ),
)
def test_scalar_result_sp_falls_back_until_wrapper_has_commit_protocol(
    instruction: str,
):
    """避免 wrapper 的临时栈帧覆盖客户结果，未安全支持时输出 ebreak。"""
    output = translate(
        _instructions(instruction), init_vtype="sew=8,lmul=1", raw=True
    )
    assert "RVV1024 fallback" in output
    assert "rd=sp/x2" in output
    assert "    ebreak" in output


def _assembly_code_without_comments(output: str) -> str:
    """去除测试输入回显注释，只观察真正会执行的寄存器拼写。"""
    return "\n".join(line.split("#", 1)[0] for line in output.splitlines())


def test_x31_scalar_input_is_preserved_as_semantic_t6_not_state_base():
    """客户以 x31 拼写 t6 时，native .vx 操作数必须使用保存的别名。"""
    output = translate(
        _instructions("vadd.vx v8, v9, x31"), init_vtype="sew=8,lmul=1", raw=True
    )
    code = _assembly_code_without_comments(output)
    native = re.search(r"^\s*vadd\.vx\s+v8,\s+v9,\s+(\w+)$", code, re.MULTILINE)
    assert native is not None
    assert native.group(1) not in {"t6", "x31"}
    assert "恢复源指令作为输入使用的原始 t6" in output


def test_x31_vector_memory_base_is_preserved_as_semantic_t6_not_state_base():
    """(x31) 访存基址也必须使用原客户 t6，而不能读取 simulated state。"""
    output = translate(
        _instructions("vle8.v v8, (x31)"), init_vtype="sew=8,lmul=1", raw=True
    )
    code = _assembly_code_without_comments(output)
    native_bases = re.findall(
        r"^\s*vle8\.v\s+v8,\s+\((\w+)\)$", code, re.MULTILINE
    )
    assert native_bases
    assert native_bases[-1] not in {"t6", "x31"}


def test_x2_stack_alias_is_preserved_for_vector_memory_and_config_input():
    """客户以 x2 拼写 sp 时，wrapper 的临时帧不能改变其观察到的基址/AVL。"""
    memory_output = translate(
        _instructions("vle8.v v8, (x2)"), init_vtype="sew=8,lmul=1", raw=True
    )
    config_output = translate(
        _instructions("vsetvli a0, x2, e8, m1, ta, ma"), raw=True
    )
    memory_code = _assembly_code_without_comments(memory_output)
    config_code = _assembly_code_without_comments(config_output)

    memory_bases = re.findall(
        r"^\s*vle8\.v\s+v8,\s+\((\w+)\)$", memory_code, re.MULTILINE
    )
    assert memory_bases and memory_bases[-1] not in {"sp", "x2"}
    assert "保留原程序 sp 作为向量访存基址" in memory_output
    assert not re.search(r"(?<![A-Za-z0-9_.])x2(?![A-Za-z0-9_.])", config_code)
    assert "保留原程序 sp 作为向量访存基址" in config_output


def test_preflight_maps_stale_static_shape_after_dynamic_vsetvl_to_ebreak():
    """动态 vsetvl 后不能沿用旧形状，无法解释时生成 ebreak。"""
    output = translate(
        _instructions("\n".join([
            "vsetvli zero, a0, e32, m1, ta, ma",
            "vsetvl zero, a1, a2",
            "vadd.vv v8, v16, v24",
        ])),
        raw=True,
    )
    assert "RVV1024 fallback" in output
    assert "source vtype analysis contains only unknown entries" in output
    assert "    ebreak" in output


@pytest.mark.parametrize(
    "annotation",
    [
        "# source: unknown",
        "# source: e8,m1,ta,ma; e32,m2,tu,mu",
    ],
)
def test_config_does_not_use_incoming_cfg_vtype_annotation(annotation: str):
    """配置指令的入站 unknown 不能变成 emitter 的普通 ebreak fallback。

    ``vset*`` 的输出 vtype 由本指令字面量或 rs2 决定，不依赖 CFG 标注的
    到达状态。过渡路径先通过整文件预检后，必须直接交给配置 handler，而非
    生成一个永远不属于客户语义的运行时 vtype 分派和 fallback。
    """
    output = translate(
        _instructions(f"vsetvli a5, a0, e32, m1, ta, ma {annotation}"),
        raw=True,
    )

    assert "源 RVV256 vsetvli" in output
    assert "Unsupported RVV instruction lowered to ebreak" not in output
    assert "runtime vtype dispatch" not in output


def test_vtype_independent_whole_move_bypasses_multi_candidate_dispatch():
    """固定 32B raw move 不应因入站 CFG 多候选产生 runtime fallback。"""
    output = translate(
        _instructions(
            "vmv1r.v v8, v16 # source: <e8,m1,ta,ma>; <e16,m2,tu,mu>"
        ),
        raw=True,
    )

    assert "复制 1 个 RVV256 物理寄存器" in output
    assert "runtime vtype dispatch" not in output
    assert "Unsupported RVV instruction lowered to ebreak" not in output


@pytest.mark.parametrize(
    ("instruction", "native", "packed_bytes", "is_load"),
    [
        ("vlse8.v v8, (a0), a1", "vlse8.v  v8, (a0), a1", 8, True),
        ("vlse16.v v8, (a0), a1", "vlse16.v  v8, (a0), a1", 16, True),
        ("vlse32.v v8, (a0), a1", "vlse32.v  v8, (a0), a1", 32, True),
        ("vlse64.v v8, (a0), a1", "vlse64.v  v8, (a0), a1", 64, True),
        ("vsse8.v v8, (a0), a1", "vsse8.v  v8, (a0), a1", 8, False),
        ("vsse16.v v8, (a0), a1", "vsse16.v  v8, (a0), a1", 16, False),
        ("vsse32.v v8, (a0), a1", "vsse32.v  v8, (a0), a1", 32, False),
        ("vsse64.v v8, (a0), a1", "vsse64.v  v8, (a0), a1", 64, False),
    ],
)
def test_unmasked_strided_memory_uses_exact_emul_pack(
    instruction: str,
    native: str,
    packed_bytes: int,
    is_load: bool,
):
    """strided form 与 unit-stride 一样必须按 EEW 推导 EMUL。"""
    output = translate(
        _instructions(instruction),
        init_vtype="sew=32,lmul=1",
        raw=True,
    )

    # v8 在 RVV256 raw payload 中是 8*32B，而不是旧 ABI 的 0x400。
    assert "addi    t1, t6, 256  # CHIMERA_STATE_BASE" in output
    assert f"li      t2, {packed_bytes}             # Pack 源组有效字节数" in output
    assert "vsetvli zero, t0, e32, m1, tu, mu" in output
    assert native in output
    assert "# ERROR:" not in output
    if is_load:
        assert "# 写回紧凑 RVV256 物理组" in output
    else:
        assert "store 不写回紧凑 RVV256 state" in output


def test_strided_wide_eew_uses_m8_source_group_and_m2_transfer():
    """e32,m4 的 vlse64 目的 EMUL=m8，必须覆盖完整 256B 源物理组。"""
    output = translate(
        _instructions("vlse64.v v8, (a0), a1"),
        init_vtype="sew=32,lmul=4",
        raw=True,
    )

    assert "EMUL=8" in output
    assert "li      t2, 256             # Pack 源组有效字节数" in output
    assert "vsetvli zero, t2, e8, m2, tu, mu" in output
    assert "vlse64.v  v8, (a0), a1" in output


@pytest.mark.parametrize(
    ("instruction", "vtype", "native"),
    (
        ("vlse64.v v8, (a0), a1, v0.t", "sew=64,lmul=1", "vlse64.v"),
        ("vsse32.v v8, (a0), a1, v0.t", "sew=32,lmul=1", "vsse32.v"),
        ("vsse64.v v8, (a0), a1, v0.t", "sew=64,lmul=1", "vsse64.v"),
    ),
)
def test_selected_masked_strided_memory_forms_pack_source_v0(
    instruction: str, vtype: str, native: str
):
    """已声明支持的 strided masked form 必须在访存前装载源 v0。"""
    output = translate(_instructions(instruction), init_vtype=vtype, raw=True)

    native_match = re.search(
        rf"^\s+{re.escape(native)}\s+.*v0\.t$", output, re.MULTILINE
    )
    assert native_match is not None
    assert output.index("载入源 v0.t 执行掩码") < native_match.start()
    assert "RVV1024 fallback" not in output


def test_strided_memory_maps_masked_and_misaligned_m8_forms_to_ebreak():
    """未建模 form 与非法 EMUL 组都保留诊断并生成 ebreak。"""
    masked_output = translate(
        _instructions("vlse32.v v8, (a0), a1, v0.t"),
        init_vtype="sew=32,lmul=1",
        raw=True,
    )
    assert "RVV1024 fallback" in masked_output
    assert "未验证的 v0.t 掩码 form" in masked_output
    assert "    ebreak" in masked_output

    alignment_output = translate(
        _instructions("vlse64.v v4, (a0), a1"),
        init_vtype="sew=32,lmul=4",
        raw=True,
    )
    assert "RVV1024 fallback" in alignment_output
    assert "不是 m8 组对齐起点" in alignment_output
    assert "    ebreak" in alignment_output


def test_vsm_uses_source_vl_without_requiring_static_vtype():
    """mask store 的有效长度是 ceil(VL/8)，可只由保存的 source VL 决定。"""
    output = translate(_instructions("vsm.v v3, (a0)"), raw=True)

    # v3 的 raw 起点为 96B；m2/e8 在目标 VLEN=1024 上给出 VLMAX=256，
    # 覆盖源机任何合法 vtype 的最大 VL，实际写 byte 数由原生 vsm.v 定义。
    assert "addi    t1, t6, 96  # CHIMERA_STATE_BASE" in output
    assert "li      t2, 32             # Pack 源组有效字节数" in output
    assert "vsetvli zero, t0, e8, m2, tu, mu" in output
    assert "vsm.v     v8, (a0)" in output
    assert "写回紧凑 RVV256 物理组" not in output
    assert "# ERROR:" not in output


@pytest.mark.parametrize(
    ("instruction", "factor", "is_load"),
    [
        ("vl2re32.v v8, (a0)", 2, True),
        ("vl4r.v v8, (a0)", 4, True),
        ("vs2r.v v8, (a0)", 2, False),
        ("vs8r.v v8, (a0)", 8, False),
    ],
)
def test_whole_register_memory_uses_fixed_compact_raw_bytes(
    instruction: str,
    factor: int,
    is_load: bool,
):
    """whole-register memory 不依赖 vtype，且每个源寄存器只能搬 32B。"""
    output = translate(_instructions(instruction), raw=True)
    total_bytes = factor * 32

    assert f"固定搬运 {factor} * 32B = {total_bytes}B" in output
    assert "不发射同名目标 whole-register 指令" in output
    assert "addi    t0, t6, 256  # CHIMERA_STATE_BASE" in output
    if is_load:
        assert f"li      t1, {total_bytes}             # whole-register 源字节数" in output
        assert "读取 RVV256 whole-register bytes" in output
        assert "写回紧凑 RVV256 物理组" in output
    else:
        assert f"li      t1, {total_bytes}             # Pack 源组有效字节数" in output
        assert "写出 RVV256 whole-register bytes" in output


def test_whole_register_memory_maps_illegal_source_group_alignment_to_ebreak():
    """固定字节搬运仍遵守整组对齐规则，非法 form 以 ebreak 收口。"""
    output = translate(_instructions("vl2r.v v9, (a0)"), raw=True)
    assert "RVV1024 fallback" in output
    assert "不是 m2 组对齐起点" in output
    assert "    ebreak" in output


@pytest.mark.parametrize(
    ("instruction", "index_eew", "index_bytes", "native"),
    [
        ("vluxei16.v v8, (a0), v16", 16, 16, "vluxei16.v  v8, (a0), v9"),
        ("vluxei64.v v8, (a0), v16", 64, 64, "vluxei64.v  v8, (a0), v10"),
    ],
)
def test_unordered_indexed_load_uses_index_eew_emul(
    instruction: str,
    index_eew: int,
    index_bytes: int,
    native: str,
):
    """indexed offsets 的 raw 组宽度必须由 index EEW，而非 data EEW 决定。"""
    output = translate(
        _instructions(instruction),
        init_vtype="sew=32,lmul=1",
        raw=True,
    )

    assert f"index EEW=e{index_eew}" in output
    assert f"li      t2, {index_bytes}             # Pack 源组有效字节数" in output
    assert native in output
    assert "写回紧凑 RVV256 物理组" in output


def test_indexed_load_maps_masked_form_to_ebreak_before_generation():
    """未验证的 indexed `v0.t` form 不会被静默去掩码，而是生成 ebreak。"""
    output = translate(
        _instructions("vluxei16.v v8, (a0), v16, v0.t"),
        init_vtype="sew=32,lmul=1",
        raw=True,
    )
    assert "RVV1024 fallback" in output
    assert "未验证的 v0.t 掩码 form" in output
    assert "    ebreak" in output


@pytest.mark.parametrize(
    ("instruction", "vtype", "native", "field_bytes", "is_load"),
    [
        ("vlseg2e32.v v8, (a0)", "sew=32,lmul=1", "vlseg2e32.v     v8, (a0)", 32, True),
        ("vsseg2e64.v v8, (a0)", "sew=64,lmul=2", "vsseg2e64.v     v8, (a0)", 64, False),
        ("vsseg4e64.v v8, (a0)", "sew=64,lmul=2", "vsseg4e64.v     v8, (a0)", 64, False),
        ("vlsseg2e64.v v8, (a0), a1", "sew=64,lmul=2", "vlsseg2e64.v    v8, (a0), a1", 64, True),
        ("vssseg2e32.v v8, (a0), a1", "sew=32,lmul=1", "vssseg2e32.v    v8, (a0), a1", 32, False),
    ],
)
def test_segment_memory_packs_every_field_before_native_access(
    instruction: str,
    vtype: str,
    native: str,
    field_bytes: int,
    is_load: bool,
):
    """segment field groups 必须连续、独立 Pack，load 才会逐 field Unpack。"""
    output = translate(_instructions(instruction), init_vtype=vtype, raw=True)

    assert f"field EMUL=" in output
    assert native in output
    assert output.count(f"li      t2, {field_bytes}             # Pack 源组有效字节数") >= (
        2 if "seg2" in instruction else 4
    )
    if is_load:
        assert output.count(f"li      t2, {field_bytes}             # Unpack 源组有效字节数") >= 2
    else:
        assert "segment store 不写回紧凑 RVV256 state" in output


def test_segment_memory_maps_masked_and_overwide_field_groups_to_ebreak():
    """无掩码契约与 NF×EMUL 上限生效；未实现 form 生成 ebreak。"""
    masked_output = translate(
        _instructions("vlseg2e32.v v8, (a0), v0.t"),
        init_vtype="sew=32,lmul=1",
        raw=True,
    )
    assert "RVV1024 fallback" in masked_output
    assert "未验证的 v0.t 掩码 form" in masked_output
    assert "    ebreak" in masked_output

    size_output = translate(
        _instructions("vsseg4e64.v v8, (a0)"),
        init_vtype="sew=64,lmul=4",
        raw=True,
    )
    assert "RVV1024 fallback" in size_output
    assert "segment 上限" in size_output
    assert "    ebreak" in size_output


def test_batch5_strided_and_mask_store_output_is_accepted_by_llvm_mc(tmp_path: Path):
    """代表性 Batch 5 输出必须能被真实 RV64GCV 汇编器接受。

    汇编成功只验证编码、临时组对齐和汇编文本；完整的访存/异常语义仍需要
    VLEN=1024 目标机上的参考/候选状态差分验证。
    """
    llvm_mc = shutil.which("llvm-mc")
    if llvm_mc is None:
        homebrew_llvm_mc = Path("/opt/homebrew/opt/llvm/bin/llvm-mc")
        llvm_mc = str(homebrew_llvm_mc) if homebrew_llvm_mc.exists() else None
    if llvm_mc is None:
        pytest.skip("未找到带 RISC-V target 的 llvm-mc")

    for index, instruction in enumerate((
        "vlse64.v v8, (a0), a1",
        "vsse8.v v8, (a0), a1",
        "vsm.v v3, (a0)",
        "vl2re32.v v8, (a0)",
        "vs8r.v v8, (a0)",
        "vluxei16.v v8, (a0), v16",
        "vluxei64.v v8, (a0), v16",
        "vlseg2e32.v v8, (a0)",
        "vsseg4e64.v v8, (a0)",
        "vlsseg2e64.v v8, (a0), a1",
    )):
        source = tmp_path / f"rvv1024_batch5_{index}.s"
        obj = tmp_path / f"rvv1024_batch5_{index}.o"
        source.write_text(
            ".text\n" + translate(
                _instructions(instruction),
                init_vtype="sew=32,lmul=1",
                raw=True,
            ),
            encoding="utf-8",
        )
        subprocess.run(
            [
                llvm_mc,
                "-triple=riscv64-unknown-linux-gnu",
                "-mattr=+m,+a,+f,+d,+c,+v,+zicsr",
                "-filetype=obj",
                str(source),
                "-o",
                str(obj),
            ],
            check=True,
            capture_output=True,
            text=True,
        )
