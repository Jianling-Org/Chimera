"""RVV256 宽 LMUL 路径的规划、代码形状和回退合同测试。"""

from fractions import Fraction
from pathlib import Path
import re
import shutil
import subprocess
import sys

import pytest

from riscv.frontend.parser import AsmParser
from riscv.extensions.rvv.backends.rvv256.specs import RVV256_SAME_WIDTH_OPCODES
from riscv.extensions.rvv.backends.rvv256.planning import WideVRegGroupAllocator, plan_wide_chunk, plan_wide_operands
from riscv.frontend.model import RVInstruction, RVProgram
from rvv_sbt_rvv import translate
from rvv_sbt_rvv import translate_program


def _translate(command: str, vtype: str, *, wide: bool) -> str:
    instructions = AsmParser().parse_string(command)
    return translate(
        instructions,
        init_vtype=vtype,
        raw=True,
        wide_lmul=wide,
    )


def _same_width_test_command(opcode: str) -> str:
    """根据首期同宽 opcode 的操作数形式构造最小合法测试指令。"""

    if opcode in {"vnot.v", "vfabs.v", "vfneg.v"}:
        return f"{opcode} v8, v16"
    if opcode.endswith(".vv"):
        return f"{opcode} v8, v16, v24"
    if opcode.endswith(".vi"):
        return f"{opcode} v8, v16, 3"
    if opcode.endswith(".vf"):
        return f"{opcode} v8, v16, fa0"
    if opcode.endswith(".vx"):
        return f"{opcode} v8, v16, a0"
    raise AssertionError(f"测试表未覆盖同宽 opcode 形式: {opcode}")


@pytest.mark.parametrize("opcode", sorted(RVV256_SAME_WIDTH_OPCODES))
def test_all_first_batch_same_width_unmasked_ops_use_wide_path(opcode):
    """首期 33 条无掩码同宽指令均应进入 RVV256 宽 LMUL emitter。"""

    output = _translate(
        _same_width_test_command(opcode),
        "sew=32,lmul=8",
        wide=True,
    )
    assert f"# RVV256-WIDE: {opcode}" in output
    assert f"# UNIMPLEMENTED: {opcode}" not in output
    assert "尾部标量回退" not in output
    if opcode == "vandn.vv":
        assert "vxor.vi" in output
        assert "vand.vv" in output
        assert "vandn.vv v" not in output
    elif opcode == "vnot.v":
        assert "vxor.vi" in output
        assert "vnot.v v" not in output
    else:
        assert f"{opcode} " in output


@pytest.mark.parametrize("opcode", sorted(RVV256_SAME_WIDTH_OPCODES))
def test_first_batch_conservative_profile_keeps_legacy_path(opcode):
    """首期扩展不能改变 --conservative 的旧 m1 strip-mining 基线。"""

    output = _translate(
        _same_width_test_command(opcode),
        "sew=32,lmul=8",
        wide=False,
    )
    assert f"# RVV256-WIDE: {opcode}" not in output
    assert f"# UNIMPLEMENTED: {opcode}" not in output
    assert f"{opcode} " in output


def test_first_batch_e8_uses_register_avl_for_wide_chunk():
    """e8 的 32 元素目标块不能错误地使用 5-bit vsetivli 立即数。"""

    output = _translate("vand.vv v8, v12, v16", "sew=8,lmul=1", wide=True)
    assert "# RVV256-WIDE: vand.vv" in output
    assert re.search(r"vsetvli zero, \w+, e8, m4, ta, ma", output)
    assert "vsetivli zero, 32, e8" not in output


@pytest.mark.parametrize("wide", [True, False])
def test_wide_path_reports_clobbered_vregs(wide):
    """宽/保守 profile 必须同样报告被破坏的目标向量临时寄存器组。

    ``LoweringResult.clobbered_vregs`` 是结构化合同的一部分；宽路径的
    ``WideVRegGroupAllocator`` 曾经漏记 clobber，导致两个 profile 在同一
    合同上不对称。
    """

    from riscv.extensions.rvv.runtime.layout import SimulatedStateLayout
    from riscv.extensions.rvv.analysis.config import StateTracker
    from riscv.extensions.rvv.backends.rvv256.backend import RVV256Dispatcher

    insn = AsmParser().parse_string("vadd.vv v8, v16, v24")[0]
    state = StateTracker(vlenb=128)
    state.apply_init_vtype("sew=32,lmul=4")
    dispatcher = RVV256Dispatcher(wide_lmul=wide)
    context = dispatcher.make_context(insn, state, SimulatedStateLayout(vlenb=128))
    result = dispatcher.lower(context, dispatcher.plan(context))

    assert result.is_lowered
    assert result.clobbered_vregs, (
        f"wide_lmul={wide} 必须报告 clobbered_vregs，实际为空"
    )
    # 每个报告的寄存器都应是真实的目标硬件临时组编号 (v0-v31)。
    for register in result.clobbered_vregs:
        assert re.fullmatch(r"v(?:[0-9]|[12][0-9]|3[01])", register)


@pytest.mark.parametrize(
    ("command", "target_operation"),
    [
        ("vdiv.vx v8, v16, a0", "vdiv.vx v8, v8, a0"),
        ("vfsub.vf v8, v16, fa0", "vfsub.vf v8, v8, fa0"),
        ("vfrsub.vf v8, v16, fa0", "vfrsub.vf v8, v8, fa0"),
    ],
)
def test_first_batch_scalar_operand_order_is_preserved(command, target_operation):
    """vx/vf 形式必须保持 GNU RVV 的向量源和标量源位置。"""

    output = _translate(command, "sew=32,lmul=1", wide=True)
    assert target_operation in output


@pytest.mark.parametrize(
    "command",
    [
        "vand.vv v8, v8, v16",
        "vsub.vv v8, v16, v8",
        "vsll.vv v8, v16, v16",
        "vnot.v v8, v8",
    ],
)
def test_first_batch_aliases_load_sources_before_writing_destination(command):
    """vd 与输入别名时，宽路径必须先加载所有源值再提交结果。"""

    output = _translate(command, "sew=32,lmul=1", wide=True)
    opcode = command.split()[0]
    assert f"# RVV256-WIDE: {opcode}" in output
    target_opcode = "vxor.vi" if opcode == "vnot.v" else opcode
    operation_index = output.index(f"{target_opcode} ")
    prefix = output[:operation_index]
    assert "vle32.v" in prefix
    assert "vse32.v" not in prefix


@pytest.mark.parametrize("opcode", sorted(RVV256_SAME_WIDTH_OPCODES))
def test_first_batch_masked_form_does_not_expand_masked_whitelist(opcode):
    """首期无掩码实现不能把任何尚未验收的 v0.t 形式静默升级为宽路径。"""

    output = _translate(
        f"{_same_width_test_command(opcode)}, v0.t",
        "sew=32,lmul=8",
        wide=True,
    )
    assert f"# RVV256-WIDE: {opcode}" not in output
    assert (
        opcode in output
        or "# ERROR: RVV256 masked form is not implemented yet:" in output
        or "# ERROR: RVV256 wide masked form is not available for this shape:" in output
    )


def test_first_batch_invalid_source_group_fails_closed():
    """非法源寄存器组必须 fail-fast，不能生成看似可运行的宽汇编。"""

    output = _translate("vand.vv v14, v16, v24", "sew=64,lmul=8", wide=True)
    assert "# RVV256-WIDE: vand.vv" not in output
    assert "# RVV256 fallback:" in output
    assert "vand.vv" in output
    assert re.search(r"(?m)^\s*ebreak\s*$", output)


def test_first_batch_all_unmasked_ops_assemble_with_llvm(tmp_path):
    """33 条首期宽路径都必须能被真实 LLVM RISC-V 汇编器接受。"""

    llvm_mc = shutil.which("llvm-mc")
    if llvm_mc is None:
        homebrew_llvm_mc = Path("/opt/homebrew/opt/llvm/bin/llvm-mc")
        llvm_mc = str(homebrew_llvm_mc) if homebrew_llvm_mc.exists() else None
    if llvm_mc is None:
        pytest.skip("未找到带 RISC-V target 的 llvm-mc")

    float_ops = {
        "vfabs.v",
        "vfadd.vf",
        "vfadd.vv",
        "vfdiv.vv",
        "vfmax.vv",
        "vfmin.vv",
        "vfmul.vv",
        "vfneg.v",
        "vfrsub.vf",
        "vfsub.vf",
        "vfsub.vv",
    }
    cases = []
    for opcode in sorted(RVV256_SAME_WIDTH_OPCODES):
        cases.append((opcode, "sew=32,lmul=8"))
        cases.append((opcode, "sew=64,lmul=4"))
        if opcode not in float_ops:
            cases.append((opcode, "sew=8,lmul=1"))

    for index, (opcode, vtype) in enumerate(cases):
        assembly = _translate(_same_width_test_command(opcode), vtype, wide=True)
        source = tmp_path / f"first_batch_{index}.s"
        obj = tmp_path / f"first_batch_{index}.o"
        source.write_text(".text\n" + assembly, encoding="utf-8")
        subprocess.run(
            [
                llvm_mc,
                "-triple=riscv64-unknown-linux-gnu",
                "-mattr=+m,+a,+f,+d,+c,+v,+zfh,+zvfh,+zvfhmin",
                "-filetype=obj",
                str(source),
                "-o",
                str(obj),
            ],
            check=True,
            capture_output=True,
            text=True,
        )


def test_public_api_defaults_to_wide_profile_and_can_select_conservative():
    """公共 Python API 默认走宽 profile，显式 False 保留旧的保守基线。"""
    instructions = AsmParser().parse_string("vadd.vv v8, v16, v24")
    default_output = translate(
        instructions,
        init_vtype="sew=32,lmul=8",
        raw=True,
    )
    conservative_output = translate(
        instructions,
        init_vtype="sew=32,lmul=8",
        raw=True,
        wide_lmul=False,
    )
    assert "RVV256-WIDE: vadd.vv" in default_output
    assert "RVV256-WIDE" not in conservative_output
    assert "尾部标量回退" in conservative_output


def test_cli_defaults_to_wide_profile_and_rejects_removed_aliases(tmp_path):
    """默认使用宽路径；已失效的兼容参数必须由 argparse 明确拒绝。"""
    translator = Path(__file__).parents[1] / "rvv_sbt_rvv.py"
    common = [
        sys.executable,
        str(translator),
        "-c",
        "vadd.vv v8, v16, v24",
        "--init-vtype",
        "sew=32,lmul=8",
        "--raw",
    ]
    default_output = tmp_path / "default.s"
    conservative_output = tmp_path / "conservative.s"

    subprocess.run([*common, "-o", str(default_output)], check=True, text=True)
    subprocess.run(
        [*common, "--conservative", "-o", str(conservative_output)],
        check=True,
        text=True,
    )
    removed = {}
    for option in ("--wide-lmul", "--conservative-lmul", "--jal-range-fixup"):
        removed[option] = subprocess.run(
            [*common, option, "-o", str(tmp_path / f"invalid-{option[2:]}.s")],
            capture_output=True,
            text=True,
        )

    assert "RVV256-WIDE: vadd.vv" in default_output.read_text(encoding="utf-8")
    assert "RVV256-WIDE" not in conservative_output.read_text(encoding="utf-8")
    for option, result in removed.items():
        assert result.returncode != 0
        assert "unrecognized arguments" in result.stderr
        assert option in result.stderr


@pytest.mark.parametrize(
    ("source_lmul", "target_lmul", "one_shot"),
    [
        (Fraction(1, 8), Fraction(1, 2), True),
        (Fraction(1, 4), Fraction(1), True),
        (Fraction(1, 2), Fraction(2), True),
        (Fraction(1), Fraction(4), True),
        (Fraction(2), Fraction(8), True),
        (Fraction(4), Fraction(8), False),
        (Fraction(8), Fraction(8), False),
    ],
)
def test_wide_planner_uses_saturating_lmul_mapping(source_lmul, target_lmul, one_shot):
    plan = plan_wide_chunk(
        source_lmul=source_lmul,
        source_sew=32,
        data_sew=32,
        source_regs=("v8",),
        target_group_count=1,
    )
    assert plan is not None
    assert plan.target_lmul == target_lmul
    assert plan.one_shot is one_shot


def test_wide_allocator_fits_three_m8_groups_without_v0():
    groups = WideVRegGroupAllocator().allocate((Fraction(8),) * 3)
    assert groups == ("v8", "v16", "v24")


def test_memory_emul_uses_eew_over_source_sew():
    plan = plan_wide_chunk(
        source_lmul=1,
        source_sew=32,
        data_sew=64,
        source_regs=("v8",),
        target_group_count=1,
    )
    assert plan is not None
    assert plan.source_operand_emuls == (Fraction(2),)
    assert plan.target_lmul == Fraction(8)
    assert plan.one_shot


def test_heterogeneous_planner_accounts_for_wide_and_narrow_groups():
    plan = plan_wide_operands(
        source_lmul=1,
        source_sew=16,
        source_operands=(("v8", 32), ("v16", 16)),
        target_vtype_sew=16,
        target_operand_eews=(32, 16),
    )
    assert plan is not None
    assert plan.source_operand_emuls == (Fraction(2), Fraction(1))
    assert plan.target_lmul == Fraction(4)
    assert plan.target_operand_emuls == (Fraction(8), Fraction(4))
    assert plan.one_shot


def test_illegal_source_group_fails_before_codegen():
    with pytest.raises(ValueError, match="组对齐"):
        plan_wide_chunk(
            source_lmul=4,
            source_sew=32,
            data_sew=32,
            source_regs=("v2",),
            target_group_count=1,
        )


def test_wide_switch_is_explicit_and_default_stays_legacy():
    legacy = _translate("vadd.vv v8, v16, v24", "sew=32,lmul=8", wide=False)
    wide = _translate("vadd.vv v8, v16, v24", "sew=32,lmul=8", wide=True)
    assert "RVV256-WIDE" not in legacy
    assert "尾部标量回退" in legacy
    assert "RVV256-WIDE: vadd.vv" in wide
    assert "尾部标量回退" not in wide
    assert "e32, m8" in wide


def test_m1_wide_arithmetic_is_one_shot_m4():
    output = _translate("vadd.vv v8, v12, v16", "sew=32,lmul=1", wide=True)
    assert "target=m4" in output
    assert output.count("vsetvli zero") == 1
    assert "_full_" not in output


def test_wide_vfmul_preserves_gnu_operand_order():
    output = _translate("vfmul.vf v8, v16, fa0", "sew=32,lmul=2", wide=True)
    assert re.search(r"(?m)^\s*vfmul\.vf\s+v8,\s+v8,\s+fa0$", output)


def test_m8_wide_full_loop_configures_vtype_outside_backedge():
    output = _translate("vfmacc.vv v8, v16, v24", "sew=64,lmul=8", wide=True)
    loop_match = re.search(r"(?m)^(\.L_rvv256_wide_vfmacc_vv_full_\d+):$", output)
    assert loop_match is not None
    first_vset = output.index("vsetvli zero")
    assert first_vset < loop_match.start()
    loop_body = output[loop_match.start():output.index("_after_full_", loop_match.end())]
    assert "vsetvli" not in loop_body
    assert "尾部标量回退" not in output
    assert "v8" in output and "v16" in output and "v24" in output


def test_wide_memory_uses_eew_vtype_and_vector_tail():
    output = _translate("vlse64.v v8, (a0), a1", "sew=32,lmul=4", wide=True)
    assert "RVV256-WIDE: vlse64.v" in output
    assert "target=e64,m8" in output
    assert "vlse64.v v8" in output
    assert "尾部标量回退" not in output
    assert len(re.findall(r"(?m)^\s*mul\s+", output)) == 1


@pytest.mark.parametrize(
    ("wide", "vtype"),
    [
        (True, "sew=64,lmul=1"),
        (True, "sew=64,lmul=8"),
        (False, "sew=64,lmul=1"),
    ],
)
def test_vsse64_is_supported_in_both_rvv256_profiles(wide, vtype):
    """
    ``vsse64.v`` 不能再从 RVV256 dispatcher 落入未实现回退。

    宽 profile 检查目标 e64/m4 或 e64/m8 的原生 strided store；保守
    profile 检查同一通用 handler 的 e64/m1 分块路径。两者都必须保留
    源 ``vl``，并在翻译块结束时清零模拟 CSR.vstart。
    """
    output = _translate("vsse64.v v8, (a0), a1", vtype, wide=wide)

    assert "# UNIMPLEMENTED: vsse64.v" not in output
    assert "fallback to ebreak" not in output
    assert "vsse64.v" in output
    assert "CSR.vstart = 0 after vector completion" in output
    if wide:
        assert "RVV256-WIDE: vsse64.v" in output
    else:
        assert "RVV256-WIDE: vsse64.v" not in output


def test_wide_vsse64_uses_eew_vtype_and_byte_stride_progress():
    """宽路径必须按 64-bit EEW 建立 vtype，并按元素数乘 byte stride 前进。"""
    output = _translate("vsse64.v v8, (a0), a1", "sew=64,lmul=8", wide=True)

    assert "RVV256-WIDE: vsse64.v" in output
    assert "target=e64,m8" in output
    assert "chunk=32 elements" in output
    assert re.search(r"(?m)^\s*vsse64\.v\s+v8,\s+\(\w+\),\s+a1$", output)
    assert len(re.findall(r"(?m)^\s*mul\s+", output)) == 1
    assert re.search(r"(?m)^\s*addi\s+\w+,\s+\w+,\s+256$", output)


def test_vsse64_accepts_the_user_example_v14_in_a_legal_source_group():
    """用户示例的 v14 在合法 e64,m2 源状态下应进入真实宽路径。"""
    output = _translate(
        "vsse64.v v14, (a5), s2",
        "sew=64,lmul=2",
        wide=True,
    )

    assert "RVV256-WIDE: vsse64.v" in output
    assert "# UNIMPLEMENTED: vsse64.v" not in output
    assert "fallback" not in output
    assert all("unsupported nonzero source vstart" in line
               for line in output.splitlines() if "ebreak" in line)
    assert re.search(r"(?m)^\s*vsse64\.v\s+v8,\s+\(a5\),\s+s2$", output)


def test_masked_wide_vsse64_loads_v0_and_preserves_mask_form():
    """显式 v0.t 的 64-bit strided store 不能被静默当成无掩码。"""
    output = _translate(
        "vsse64.v v8, (a0), a1, v0.t",
        "sew=64,lmul=1",
        wide=True,
    )

    assert "RVV256-WIDE-MASKED: vsse64.v" in output
    assert "vlm.v   v0" in output
    assert re.search(r"(?m)^\s*vsse64\.v\s+v8,\s+\(a0\),\s+a1,\s+v0\.t$", output)
    assert "# UNIMPLEMENTED: vsse64.v" not in output
    assert "fallback" not in output
    assert all("unsupported nonzero source vstart" in line
               for line in output.splitlines() if "ebreak" in line)


def test_program_mode_vsse64_no_longer_emits_unimplemented_branch_fallback():
    """程序模式的 branch_j_target 入口也必须发射真实 vsse64.v。"""
    fixture = Path(__file__).parent / "fixtures" / "objdump" / "daxpy_k.objdump.s"
    program = RVProgram(functions=AsmParser().parse_file_functions(str(fixture)))
    output = translate_program(
        program,
        source_file=str(fixture),
        lib_name="fixture",
        wide_lmul=True,
    )

    assert "# UNIMPLEMENTED: vsse64.v" not in output
    assert "vsse64.v" in output
    assert "branch_j_target_" in output


def test_masked_vadd_commits_only_active_lanes_without_old_destination_load():
    output = _translate("vadd.vv v8, v16, v24, v0.t", "sew=32,lmul=8", wide=True)
    assert "RVV256-WIDE-MASKED: vadd.vv" in output
    assert "RVV256-WIDE-MASKED-COMMIT" in output
    assert "e32, m8, ta, ma" in output
    assert "vlm.v   v0" in output
    assert "vadd.vv v8, v8, v16, v0.t" in output
    # 非累加指令无需为了 mu 预装旧 vd；只将命中 lane 提交到状态块。
    assert "vle32.v v8, (t0)" not in output
    assert "vse32.v v8, (t0), v0.t" in output
    assert re.search(r"(?m)^\s*addi\s+\w+,\s+\w+,\s+8$", output)


def test_masked_one_shot_does_not_advance_mask_pointer():
    output = _translate("vadd.vv v8, v12, v16, v0.t", "sew=32,lmul=1", wide=True)
    assert "RVV256-WIDE-MASKED: vadd.vv" in output
    assert "target=m4" in output
    assert output.count("vlm.v") == 1
    assert "_full_" not in output


def test_masked_vfmul_uses_source_group_and_masked_state_commit():
    output = _translate("vfmul.vf v8, v16, fa0, v0.t", "sew=32,lmul=2", wide=True)
    assert "RVV256-WIDE-MASKED: vfmul.vf" in output
    assert "RVV256-WIDE-MASKED-COMMIT" in output
    operation = output.index("vfmul.vf v8, v8, fa0, v0.t")
    prefix = output[:operation]
    assert "vle32.v v8, (t1)" in prefix
    assert "vle32.v v8, (t0)" not in prefix
    assert "vse32.v v8, (t0), v0.t" in output


@pytest.mark.parametrize(
    ("command", "vtype", "operation"),
    [
        ("vle32.v v8, (a0), v0.t", "sew=32,lmul=8", "vle32.v v8, (t1), v0.t"),
        ("vse32.v v8, (a0), v0.t", "sew=32,lmul=8", "vse32.v v8, (t1), v0.t"),
        ("vlse64.v v8, (a0), a1, v0.t", "sew=32,lmul=4", "vlse64.v v8, (t1), a1, v0.t"),
        ("vsse32.v v8, (a0), a1, v0.t", "sew=32,lmul=8", "vsse32.v v8, (t1), a1, v0.t"),
    ],
)
def test_masked_memory_uses_wide_target_mask(command, vtype, operation):
    output = _translate(command, vtype, wide=True)
    assert "RVV256-WIDE-MASKED" in output
    assert "vlm.v   v0" in output
    assert operation in output


def test_non_v0_mask_is_rejected_before_codegen():
    output = _translate("vadd.vv v8, v16, v24, v1.t", "sew=32,lmul=8", wide=True)
    assert "only supports explicit v0.t mask" in output
    assert "ebreak" in output
    assert "RVV256-WIDE" not in output


def test_wide_only_masked_shape_never_falls_through_as_unmasked():
    output = _translate("vfnmsac.vf v8, fa0, v16, v0.t", "sew=16,lmul=1", wide=True)
    assert "wide masked form is not available for this shape" in output
    assert "ebreak" in output
    assert "vfnmsac.vf v24" not in output


@pytest.mark.parametrize("wide", [False, True])
def test_whole_register_move_uses_vl8r_vs8r_without_vtype_setup(wide):
    output = _translate("vmv4r.v v8, v16", "sew=32,lmul=1", wide=wide)
    temp_group = "v8" if wide else "v24"
    assert "RVV256-NATIVE-WHOLE: vmv4r.v" in output
    assert "vsetvli" not in output
    assert len(re.findall(rf"(?m)^\s*vl8r\.v\s+{temp_group},", output)) == 2
    assert len(re.findall(rf"(?m)^\s*vs8r\.v\s+{temp_group},", output)) == 2
    assert ".L_rvv256_wide_vmv" not in output


@pytest.mark.parametrize(
    ("command", "marker", "load_op", "store_op", "chunks"),
    [
        ("vl4re32.v v8, (a0)", "vl4re32.v", "vl8re32.v", "vs8r.v", 2),
        ("vs8r.v v16, (a0)", "vs8r.v", "vl8r.v", "vs8r.v", 4),
    ],
)
@pytest.mark.parametrize("wide", [False, True])
def test_whole_register_memory_uses_native_transfer_without_vtype(command, marker, load_op, store_op, chunks, wide):
    output = _translate(command, "sew=32,lmul=1", wide=wide)
    temp_group = "v8" if wide else "v24"
    assert f"RVV256-NATIVE-WHOLE-MEM: {marker}" in output
    assert "vsetvli" not in output
    assert len(re.findall(rf"(?m)^\s*{re.escape(load_op)}\s+{temp_group},", output)) == chunks
    assert len(re.findall(rf"(?m)^\s*{re.escape(store_op)}\s+{temp_group},", output)) == chunks


@pytest.mark.parametrize(
    ("command", "vtype", "operation"),
    [
        ("vfwmul.vf v10, v12, fa5", "sew=16,lmul=1", "vfwmul.vf"),
        ("vwadd.wv v8, v10, v12", "sew=16,lmul=1", "vwadd.wv"),
        ("vsseg4e64.v v24, (a1)", "sew=64,lmul=2", "vsseg4e64.v"),
    ],
)
def test_real_llama_missing_opcodes_have_default_handlers(command, vtype, operation):
    output = _translate(command, vtype, wide=False)
    assert f"UNIMPLEMENTED: {operation}" not in output
    assert "fallback to ebreak" not in output
    assert re.search(rf"(?m)^\s*{re.escape(operation)}\s+", output)
    assert "CSR.vstart = 0 after vector completion" in output


@pytest.mark.parametrize(
    ("command", "vtype"),
    [
        ("vfwmul.vf v8, v12, fa0", "sew=16,lmul=2"),
        ("vwadd.wv v8, v16, v24", "sew=32,lmul=8"),
    ],
)
@pytest.mark.parametrize("wide", [False, True])
def test_new_widening_handlers_reject_unverified_shapes(command, vtype, wide):
    """拒绝浮点工作负载边界和整数 widening 的非法 EMUL。"""
    output = _translate(command, vtype, wide=wide)
    assert "does not support LMUL" in output
    assert not re.search(r"(?m)^\s+(?:vfwmul\.vf|vwadd\.wv)\s+", output)


def test_unknown_vtype_whole_register_bypasses_only_vtype_independent_gate():
    # 所有由 native whole emitter 接受的 load 形态都必须同步进入 emitter
    # 的 vtype-independent 白名单；否则 unknown 分析结果时会在真正
    # dispatcher 前错误 ebreak。
    whole_cases = (
        ("vl1re16.v", "v8", "vl4re16.v"),
        ("vl2re64.v", "v8", "vl8re64.v"),
        ("vl8r.v", "v8", "vl8r.v"),
        ("vl8re16.v", "v8", "vl8re16.v"),
    )
    normal = RVInstruction(
        4,
        "vadd.vv",
        operands=["v8", "v4", "v0"],
        op_str="vadd.vv v8, v4, v0",
    )
    normal_output = translate([normal], raw=True)
    for opcode, vd, native_load in whole_cases:
        whole = RVInstruction(
            0,
            opcode,
            operands=[vd, "(a0)"],
            op_str=f"{opcode} {vd}, (a0)",
        )
        whole_output = translate([whole], raw=True)
        assert "source vtype analysis contains only unknown entries" not in whole_output
        assert native_load in whole_output
    assert "source vtype analysis contains only unknown entries" in normal_output


@pytest.mark.parametrize(
    ("command", "vtype", "accumulator"),
    [
        ("vwmacc.vx v8, a1, v6, v0.t", "sew=16,lmul=1,ta,mu", True),
        ("vadd.vi v8, v16, -1, v0.t", "sew=8,lmul=2,ta,mu", False),
        ("vadd.vx v8, v16, a1, v0.t", "sew=8,lmul=2,ta,mu", False),
        ("vrsub.vi v8, v16, 3, v0.t", "sew=8,lmul=2,ta,mu", False),
        ("vor.vx v8, v16, a1, v0.t", "sew=8,lmul=2,ta,mu", False),
    ],
)
def test_hot_masked_ops_distinguish_accumulator_from_masked_commit(command, vtype, accumulator):
    output = _translate(command, vtype, wide=True)
    opcode = command.split()[0]
    assert f"RVV256-WIDE-MASKED: {opcode}" in output
    assert "vlm.v   v0" in output
    assert re.search(rf"(?m)^\s*{re.escape(opcode)}\s+.*v0\.t$", output)
    if accumulator:
        assert "ta, mu" in output
        assert not re.search(r"(?m)^\s*vse(?:8|16|32|64)\.v.*v0\.t$", output)
    else:
        assert "RVV256-WIDE-MASKED-COMMIT" in output
        assert "ta, ma" in output
        assert re.search(r"(?m)^\s*vse(?:8|16|32|64)\.v.*v0\.t$", output)


def test_native_vwredsum_removes_stack_spill_and_scalar_element_loop():
    output = _translate(
        "vwredsum.vs v8, v16, v2, v0.t",
        "sew=16,lmul=1,ta,mu",
        wide=True,
    )
    assert "RVV256-WIDE-MASKED-REDUCTION" in output
    assert "vwredsum.vs" in output and "v0.t" in output
    assert "CHIMERA_INTERNAL_STACK" not in output
    assert "vl=0 时 vd 保持不变" in output
    assert re.search(r"(?m)^\s*vse32\.v\s+\w+,\s*\(\w+\)$", output)


@pytest.mark.parametrize(
    ("command", "marker", "native_operation"),
    [
        ("vmseq.vi v1, v2, -1", "vmseq.vi", "vsm.v"),
        ("vmor.mm v1, v2, v3", "vmor.mm", "vmor.mm"),
        ("vfirst.m a0, v1", "vfirst.m", "vfirst.m"),
        ("vcpop.m a0, v1", "vcpop.m", "vcpop.m"),
    ],
)
def test_native_mask_hotpaths_replace_scalar_bit_loops(command, marker, native_operation):
    output = _translate(command, "sew=8,lmul=1", wide=True)
    assert f"RVV256-NATIVE-MASK: {marker}" in output
    assert re.search(rf"(?m)^\s*{re.escape(native_operation)}\s+", output)
    assert "CSR.vstart = 0 after vector completion" in output
    assert "load next mask byte" not in output


@pytest.mark.parametrize(
    ("command", "native_operation"),
    [
        ("vmseq.vi v1, v2, -1", "vmseq.vi"),
        ("vmor.mm v1, v2, v3", "vmor.mm"),
        ("vfirst.m a0, v1", "vfirst.m"),
        ("vcpop.m a0, v1", "vcpop.m"),
    ],
)
def test_default_native_mask_profile_uses_m1_temp_pool(command, native_operation):
    """保守路径也走真实 mask 指令，但不触及宽 profile 的 v8-v23 临时池。"""
    output = _translate(command, "sew=8,lmul=1", wide=False)
    assert "RVV256-NATIVE-MASK" in output
    assert "(default)" in output
    assert "e8, m1" in output
    assert re.search(rf"(?m)^\s*{re.escape(native_operation)}\s+", output)
    assert "CSR.vstart = 0 after vector completion" in output
    # 保守 profile 的数据/输出临时量来自既有池；v0 仍只作 execution mask。
    assert re.search(r"(?m)^\s*(?:vlm\.v|vle8\.v|vmseq\.vi|vmor\.mm|vfirst\.m|vcpop\.m)\s+v(?:2[4-9]|3[01])", output)


def test_conservative_vmseq_e64_promotes_to_byte_aligned_m2_chunks():
    """e64,m1 每块 4 bit 会错位；保守 native 路径必须提升到 e64,m2。"""
    output = _translate("vmseq.vi v1, v2, -1", "sew=64,lmul=1", wide=False)
    assert "RVV256-NATIVE-MASK" in output
    assert "e64, m2" in output
    # 每个 e64,m2 块恰好产生 8 bit，mask 状态指针必须前进一个字节；这比
    # 仅检查没有 addi ...,0 更能防止下一块覆盖前一块的输出。
    match = re.search(
        r"(?ms)^\s*vsm\.v\s+\w+,\s*\((\w+)\)\n.*?^\s*addi\s+\1,\s+\1,\s+1$",
        output,
    )
    assert match is not None


@pytest.mark.parametrize(
    ("command", "expected_vlm"),
    [
        ("vmor.mm v1, v2, v3", 2),
        ("vmor.mm v2, v2, v3", 2),
        ("vmor.mm v1, v2, v2", 1),
    ],
)
def test_native_vmor_elides_output_preload_and_reuses_alias_input(command, expected_vlm):
    output = _translate(command, "sew=8,lmul=1", wide=False)
    assert output.count("vlm.v") == expected_vlm
    assert "vsm.v" in output
    assert "vmor.mm" in output


def test_native_vmseq_rejects_output_inside_unread_source_group():
    """不能让 mask 输出覆盖 source m4 组中后续尚未读取的 v9 状态槽。"""
    output = _translate("vmseq.vi v9, v8, -1", "sew=8,lmul=4", wide=False)
    assert "RVV256-NATIVE-MASK" not in output
    assert "Illegal overlapping vector groups: v9, v8" in output


@pytest.mark.parametrize(
    ("command", "vtype"),
    [
        ("vadd.vi v8, v16, -1, v0.t", "sew=8,lmul=1"),
        ("vadd.vx v8, v16, a1, v0.t", "sew=32,lmul=1"),
        ("vrsub.vi v8, v16, 3, v0.t", "sew=8,lmul=1"),
        ("vor.vx v8, v16, a1, v0.t", "sew=16,lmul=1"),
        ("vle16.v v8, (a0), v0.t", "sew=16,lmul=1"),
        ("vlse32.v v8, (a0), a1, v0.t", "sew=32,lmul=1"),
        ("vsse32.v v8, (a0), a1, v0.t", "sew=32,lmul=1"),
    ],
)
def test_default_aligned_mask_chunks_use_direct_vlm_after_vset(command, vtype):
    """默认 e8/e16/e32,m1 完整块不再经 GPR 位移和 vmv.v.x 装载掩码。"""
    output = _translate(command, vtype, wide=False)
    assert "Direct byte-aligned mask chunk into v0" in output
    assert "vlm.v   v0" in output
    assert "vmv.v.x v0" not in output
    first_vset = min(match.start() for match in re.finditer(r"(?m)^\s*vset", output))
    first_vlm = output.index("vlm.v   v0")
    assert first_vset < first_vlm
    assert "CSR.vstart = 0 after vector completion" in output


def test_default_e64_mask_chunk_keeps_shift_repack_fallback():
    for command in ("vle64.v v8, (a0), v0.t", "vrsub.vi v8, v16, 3, v0.t"):
        output = _translate(command, "sew=64,lmul=1", wide=False)
        assert "Direct byte-aligned mask chunk into v0" not in output
        assert "vmv.v.x v0" in output
        assert "v0.t" in output


@pytest.mark.parametrize(
    "command",
    [
        "vluxei16.v v8, (a0), v16, v0.t",
        "vfmacc.vv v8, v16, v24, v0.t",
        "vwmul.vx v8, a0, v16, v0.t",
        "vl1re16.v v8, (a0), v0.t",
    ],
)
def test_unimplemented_masked_forms_fail_fast_instead_of_ignoring_v0(command):
    output = _translate(command, "sew=32,lmul=1", wide=False)
    assert "ebreak" in output
    assert "v0.t" not in "\n".join(
        line for line in output.splitlines() if line.lstrip().startswith(("vle", "vse", "vfmacc", "vwmul"))
    )


@pytest.mark.parametrize("command", ["vfirst.m a0, v1", "vcpop.m a0, v1"])
def test_native_mask_scalar_result_survives_wrapper_restore(command):
    """a0 是受保护 scratch；标量结果不能在 wrapper 尾部被旧值覆盖。"""
    output = _translate(command, "sew=8,lmul=1", wide=True)
    assert not re.search(r"(?m)^\s*sd\s+a0,", output)
    assert not re.search(r"(?m)^\s*ld\s+a0,", output)
    assert re.search(r"(?m)^\s*(?:li|add)\s+a0,", output)


@pytest.mark.parametrize("opcode", ["vfirst.m", "vcpop.m", "vmv.x.s"])
@pytest.mark.parametrize("rd", ["t6", "x31"])
@pytest.mark.parametrize("wide", [False, True])
def test_scalar_t6_result_clears_vstart_before_overwriting_state_base(opcode, rd, wide):
    """t6/x31 既是状态基址也可作标量 rd，写回顺序必须明确受控。"""
    output = _translate(f"{opcode} {rd}, v1", "sew=8,lmul=1", wide=wide)
    clear_index = output.index("CSR.vstart = 0 after vector completion")
    result_index = output.rindex(f"mv      {rd},")
    assert clear_index < result_index


@pytest.mark.parametrize("opcode", ["vfirst.m", "vcpop.m"])
def test_native_mask_sp_result_fails_fast_until_wrapper_supports_stack_output(opcode):
    output = _translate(f"{opcode} sp, v1", "sew=8,lmul=1", wide=False)
    assert "暂不支持把标量结果写入 sp/x2" in output
    assert "ebreak" in output


def test_new_native_hotpaths_are_accepted_by_llvm(tmp_path):
    llvm_mc = shutil.which("llvm-mc")
    if llvm_mc is None:
        homebrew_llvm_mc = Path("/opt/homebrew/opt/llvm/bin/llvm-mc")
        llvm_mc = str(homebrew_llvm_mc) if homebrew_llvm_mc.exists() else None
    if llvm_mc is None:
        pytest.skip("未找到带 RISC-V target 的 llvm-mc")

    cases = (
        ("vfwmul.vf v10, v12, fa5", "sew=16,lmul=1"),
        ("vwadd.wv v8, v10, v12", "sew=16,lmul=1"),
        ("vsseg4e64.v v24, (a1)", "sew=64,lmul=2"),
        ("vwredsum.vs v8, v16, v2, v0.t", "sew=16,lmul=1,ta,mu"),
        ("vmseq.vi v1, v2, -1", "sew=8,lmul=1"),
        ("vmor.mm v1, v2, v3", "sew=8,lmul=1"),
        ("vfirst.m a0, v1", "sew=8,lmul=1"),
        ("vcpop.m a0, v1", "sew=8,lmul=1"),
    )
    for index, (command, vtype) in enumerate(cases):
        source = tmp_path / f"native_hotpath_{index}.s"
        obj = tmp_path / f"native_hotpath_{index}.o"
        source.write_text(".text\n" + _translate(command, vtype, wide=True), encoding="utf-8")
        subprocess.run(
            [
                llvm_mc,
                "-triple=riscv64-unknown-linux-gnu",
                "-mattr=+m,+a,+f,+d,+c,+v,+zfh,+zvfh,+zvfhmin",
                "-filetype=obj",
                str(source),
                "-o",
                str(obj),
            ],
            check=True,
            capture_output=True,
            text=True,
        )


def test_default_optimized_hotpaths_are_accepted_by_llvm(tmp_path):
    """
    保守 profile 的新路径也必须经过真实 LLVM RISC-V 汇编器。

    这里刻意使用保守 profile：覆盖 v24-v31 whole-register 临时组、
    m1/m2 native mask、以及 e8/e16/e32 直接 ``vlm.v`` 装载。它是静态语法和
    寄存器组门禁，不替代外部 RVV256 机器上的 C-reference 语义测试。
    """
    llvm_mc = shutil.which("llvm-mc")
    if llvm_mc is None:
        homebrew_llvm_mc = Path("/opt/homebrew/opt/llvm/bin/llvm-mc")
        llvm_mc = str(homebrew_llvm_mc) if homebrew_llvm_mc.exists() else None
    if llvm_mc is None:
        pytest.skip("未找到带 RISC-V target 的 llvm-mc")

    cases = (
        # conservative native mask：含 e64,m1 自动提升 m2，以及 alias/标量结果。
        ("vmseq.vi v1, v2, -1", "sew=64,lmul=1"),
        ("vmor.mm v1, v1, v2", "sew=8,lmul=1"),
        ("vfirst.m a0, v1", "sew=8,lmul=1"),
        ("vcpop.m a0, v1", "sew=8,lmul=1"),
        ("vfirst.m t6, v1", "sew=8,lmul=1"),
        # conservative whole transfer：临时组必须是 legacy 池中的对齐 v24-v31。
        ("vmv4r.v v8, v16", "sew=32,lmul=1"),
        ("vl4re32.v v8, (a0)", "sew=32,lmul=1"),
        ("vs8r.v v16, (a0)", "sew=32,lmul=1"),
        # conservative direct-vlm：等宽、unit/strided memory 与新补齐 vrsub。
        ("vadd.vi v8, v16, -1, v0.t", "sew=8,lmul=1"),
        ("vrsub.vi v8, v16, 3, v0.t", "sew=8,lmul=1"),
        ("vle16.v v8, (a0), v0.t", "sew=16,lmul=1"),
        ("vlse32.v v8, (a0), a1, v0.t", "sew=32,lmul=1"),
        ("vsse32.v v8, (a0), a1, v0.t", "sew=32,lmul=1"),
    )
    for index, (command, vtype) in enumerate(cases):
        source = tmp_path / f"default_optimized_hotpath_{index}.s"
        obj = tmp_path / f"default_optimized_hotpath_{index}.o"
        source.write_text(".text\n" + _translate(command, vtype, wide=False), encoding="utf-8")
        subprocess.run(
            [
                llvm_mc,
                "-triple=riscv64-unknown-linux-gnu",
                "-mattr=+m,+a,+f,+d,+c,+v,+zfh,+zvfh,+zvfhmin",
                "-filetype=obj",
                str(source),
                "-o",
                str(obj),
            ],
            check=True,
            capture_output=True,
            text=True,
        )


def test_legacy_e8_vadd_keeps_avl_scratch_separate_from_vs1_pointer():
    output = _translate("vadd.vv v8, v16, v24", "sew=8,lmul=1", wide=False)
    match = re.search(
        r"li\s+(\w+),\s+0x800\s*\n\s*add\s+\1,\s+t6,\s+\1",
        output,
    )
    assert match is not None
    vs1_pointer = match.group(1)
    assert f"li      {vs1_pointer}, 32" not in output
    assert f"vle8.v v25, ({vs1_pointer})" in output


def test_legacy_unmasked_hot_loop_hoists_vset_and_stride_multiply():
    output = _translate("vlse32.v v8, (a0), a1", "sew=32,lmul=1", wide=False)
    loop = re.search(r"(?m)^(\.L_rvv256_vlse_main_\d+):$", output)
    assert loop is not None
    assert output.index("vsetivli zero") < loop.start()
    assert len(re.findall(r"(?m)^\s*mul\s+", output)) == 1
    loop_body = output[loop.start():output.index("vlse_after", loop.end())]
    assert "vset" not in loop_body
    assert not re.search(r"(?m)^\s*mul\s+", loop_body)


def test_all_objdump_fixtures_preserve_fallback_count_and_program_labels(tmp_path):
    fixture_dir = Path(__file__).parent / "fixtures" / "objdump"
    parser = AsmParser()
    wide_blocks = 0
    llvm_mc = shutil.which("llvm-mc")
    if llvm_mc is None:
        homebrew_llvm_mc = Path("/opt/homebrew/opt/llvm/bin/llvm-mc")
        llvm_mc = str(homebrew_llvm_mc) if homebrew_llvm_mc.exists() else None
    for fixture in sorted(fixture_dir.glob("*.objdump.s")):
        functions = parser.parse_file_functions(str(fixture))
        program = RVProgram(functions=functions)
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
        actual_legacy_ebreaks = len(re.findall(r"(?m)^\s*ebreak\s*$", legacy))
        actual_wide_ebreaks = len(re.findall(r"(?m)^\s*ebreak\s*$", wide))
        assert actual_wide_ebreaks == actual_legacy_ebreaks, fixture.name
        assert wide.count("branch_j_target_") == legacy.count("branch_j_target_")
        assert wide.count("# 原偏移:") == legacy.count("# 原偏移:")
        for segment in re.split(r"(?m)^branch_j_target_[0-9a-f]+:\s*$", wide):
            if any(
                marker in segment
                for marker in ("RVV256-WIDE", "RVV256-NATIVE-MASK", "RVV256-NATIVE-WHOLE")
            ):
                assert "CSR.vstart = 0 after vector completion" in segment
        if llvm_mc is not None:
            source = tmp_path / f"{fixture.stem}.wide.s"
            obj = tmp_path / f"{fixture.stem}.wide.o"
            source.write_text(wide, encoding="utf-8")
            subprocess.run(
                [
                    llvm_mc,
                    "-triple=riscv64-unknown-linux-gnu",
                    "-mattr=+m,+a,+f,+d,+c,+v",
                    "-filetype=obj",
                    str(source),
                    "-o",
                    str(obj),
                ],
                check=True,
                capture_output=True,
                text=True,
            )
        wide_blocks += wide.count("RVV256-WIDE")
    assert wide_blocks > 0


@pytest.mark.parametrize("command, last_vreg, vstart_policy", (
    ("vmacc.vx v8, s1, v16", 16, "architectural"),
    ("vwmacc.vv v8, v16, v24", 24, "require-zero"),
))
@pytest.mark.parametrize("wide", (False, True))
def test_q3_mac_wide_reports_complete_groups_and_old_destination(command, last_vreg, vstart_policy, wide):
    from riscv.extensions.rvv.analysis.config import StateTracker
    from riscv.extensions.rvv.backends.rvv256.backend import RVV256Dispatcher
    from riscv.extensions.rvv.runtime.layout import SimulatedStateLayout

    state = StateTracker(vlenb=128)
    state.apply_init_vtype("sew=16,lmul=1")
    dispatcher = RVV256Dispatcher(wide_lmul=wide)
    context = dispatcher.make_context(
        AsmParser().parse_string(command)[0], state, SimulatedStateLayout(vlenb=128),
    )
    plan = dispatcher.plan(context)
    result = dispatcher.lower(context, plan)
    assert result.is_lowered
    assert result.clobbered_vregs == frozenset(f"v{i}" for i in range(8, last_vreg))
    assert plan.spec.reads_old_vd
    assert plan.spec.vstart_policy.value == vstart_policy


def test_vmacc_vx_wide_keeps_restart_skip_offset_and_shared_source_pointer():
    output = _translate("vmacc.vx v8, a0, v8", "sew=16,lmul=1", wide=True)
    skip = re.search(r"bgeu\s+(\w+),\s*(\w+),\s*(\S+)", output)
    assert skip is not None
    start, remaining, end = skip.groups()
    assert re.search(rf"sub\s+{remaining},\s*{remaining},\s*{start}", output)
    assert re.search(rf"slli\s+{start},\s*{start},\s*1", output)
    loads = list(re.finditer(r"vle16\.v\s+v(?:8|12),\s*\((\w+)\)", output))
    assert len(loads) == 2 and loads[0][1] == loads[1][1]
    assert skip.start() < loads[0].start()
    pointer = loads[0][1]
    assert len(re.findall(rf"add\s+{pointer},\s*{pointer},\s*{start}", output)) == 1
    assert re.search(rf"vsetvli zero, {remaining}, e16, m4, ta, ma", output)
    assert output.count("vmacc.vx v8, a0, v12") == 1
    assert output.index(f"{end}:") < output.index("CSR.vstart = 0 after vector completion")


@pytest.mark.parametrize("scalar", ("ra", "a0", "t6", "x31", "sp"))
def test_vmacc_vx_wide_preserves_scalar_inputs_and_marked_vstart_address(scalar):
    output = _translate(f"vmacc.vx v8, {scalar}, v16", "sew=16,lmul=1", wide=True)
    operation = re.search(r"(?m)^\s*vmacc\.vx v8, (\w+), v12$", output)
    assert operation is not None
    operand = operation[1]
    if scalar in ("t6", "x31", "sp"):
        assert operand not in ("t6", "x31", "sp")
        if scalar == "sp":
            assert re.search(rf"addi\s+{operand},\s*sp,\s*\d+", output)
        else:
            assert re.search(rf"ld\s+{operand},\s*\d+\(sp\)", output)
    else:
        assert operand == scalar
    assert re.search(
        r"li\s+(\w+),\s*0x1000\n\s*add\s+\1,\s*t6,\s*\1\s+# CHIMERA_STATE_BASE",
        output,
    )


@pytest.mark.parametrize("rhs", (16, 24))
def test_vwmacc_vv_wide_loads_old_destination_and_inputs_before_commit(rhs):
    output = _translate(f"vwmacc.vv v8, v16, v{rhs}", "sew=16,lmul=1", wide=True)
    operation = output.index("vwmacc.vv v8, v16, v20")
    assert "target=m4" in output
    assert output.index("vle32.v v8,") < operation
    assert output.index("vle16.v v16,") < operation
    assert output.index("vle16.v v20,") < operation
    assert "vse32.v" not in output[:operation]
    assert output.index("vse32.v v8,") > operation
    assert "尾部标量回退" not in output


@pytest.mark.parametrize("command", ("vmacc.vx v8, t6, v16", "vwmacc.vv v8, v16, v24"))
@pytest.mark.parametrize("vtype, wide, mask", (
    ("sew=8,lmul=1", True, ""),
    ("sew=32,lmul=1", True, ""),
    ("sew=16,lmul=2", True, ""),
    ("sew=16,lmul=1", True, ", v0.t"),
))
def test_q3_mac_primary_scope_keeps_other_forms_and_mask_rejection(command, vtype, wide, mask):
    output = _translate(command + mask, vtype, wide=wide)
    assert f"# RVV256-WIDE: {command.split()[0]}" not in output
    if mask:
        assert "ebreak" in output
    else:
        assert "fallback" not in output


@pytest.mark.parametrize("command", ("vmacc.vx v8, t6, v16", "vwmacc.vv v8, v16, v24"))
def test_q3_mac_uses_the_same_primary_lowering_in_both_profiles(command):
    assert _translate(command, "sew=16,lmul=1", wide=False) == _translate(
        command, "sew=16,lmul=1", wide=True,
    )
