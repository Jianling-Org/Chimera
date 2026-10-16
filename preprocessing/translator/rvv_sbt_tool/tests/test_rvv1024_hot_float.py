"""RVV256→RVV1024 过渡路径的批次 3 浮点热点结构回归。

这些测试只验证生成器的 Pack/operand-order/组宽度合同，不能替代 VLEN=1024
目标机上的 reference/candidate 全状态差分。尤其是浮点异常标志和舍入边界，
仍需在真实目标环境中单独验收。
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

from riscv.frontend.parser import AsmParser
from rvv_sbt_rvv1024 import translate


def _translate(source: str, vtype: str) -> str:
    """以显式源端 vtype 生成一个裸翻译块，避免默认状态掩盖入口依赖。"""
    instructions = AsmParser().parse_string(source)
    return translate(instructions, init_vtype=vtype, raw=True)


def test_vfmacc_vf_preserves_fma_operand_order_and_raw_alias_reads():
    """FMA .vf 必须是 ``vd, rs1, vs2``，且 vd==vs2 时两个输入都先 Pack。"""
    output = _translate("vfmacc.vf v8, fa0, v8", "sew=32,lmul=1")

    # 旧累加器和 vs2 都来自源 v8 的 raw 偏移 8*32=256，却必须使用不同的
    # RVV1024 临时寄存器，随后才执行 fused instruction。
    assert output.count("addi    t1, t6, 256") >= 2
    assert re.search(r"vle8\.v\s+v8,\s+\(t1\)", output)
    assert re.search(r"vle8\.v\s+v9,\s+\(t1\)", output)
    assert re.search(r"vfmacc\.vf\s+v8,\s+fa0,\s+v9", output)


def test_vfmacc_vv_m8_uses_three_disjoint_target_groups():
    """m8 FMA 恰好占用 v8-v31，不能把源客体寄存器名当作硬件占用。"""
    output = _translate("vfmacc.vv v8, v16, v24", "sew=64,lmul=8")

    assert "addi    t1, t6, 256" in output
    assert "addi    t1, t6, 512" in output
    assert "addi    t1, t6, 768" in output
    assert re.search(r"vfmacc\.vv\s+v8,\s+v16,\s+v24", output)
    assert "vsetvli zero, t0, e64, m8, tu, mu" in output


@pytest.mark.parametrize(
    ("instruction", "expected"),
    [
        ("vfmul.vf v8, v16, ft0", r"vfmul\.vf\s+v8,\s+v9,\s+ft0"),
        ("vfadd.vv v8, v16, v24", r"vfadd\.vv\s+v8,\s+v9,\s+v10"),
        ("vfsub.vf v8, v16, fa1", r"vfsub\.vf\s+v8,\s+v9,\s+fa1"),
        ("vfnmsac.vf v8, fa0, v16", r"vfnmsac\.vf\s+v8,\s+fa0,\s+v9"),
        ("vfdiv.vv v8, v16, v24", r"vfdiv\.vv\s+v8,\s+v9,\s+v10"),
        ("vfrsub.vf v8, v16, fa0", r"vfrsub\.vf\s+v8,\s+v9,\s+fa0"),
        ("vfmax.vv v8, v16, v24", r"vfmax\.vv\s+v8,\s+v9,\s+v10"),
        ("vfmin.vv v8, v16, v24", r"vfmin\.vv\s+v8,\s+v9,\s+v10"),
        ("vfmadd.vf v8, fa0, v16", r"vfmadd\.vf\s+v8,\s+fa0,\s+v9"),
        ("vfmsub.vv v8, v16, v24", r"vfmsub\.vv\s+v8,\s+v9,\s+v10"),
    ],
)
def test_float_hot_forms_keep_native_operand_roles(instruction: str, expected: str):
    """普通 .vf 与 FMA .vf 的 scalar 位置不同，生成器必须逐类保持原编码。"""
    output = _translate(instruction, "sew=32,lmul=1")
    assert re.search(expected, output)
    assert "# ERROR:" not in output


@pytest.mark.parametrize(
    ("instruction", "expected"),
    (
        ("vfmul.vf v8, v16, fa0, v0.t", r"vfmul\.vf\s+v8,\s+v9,\s+fa0, v0\.t"),
        ("vfadd.vv v8, v16, v24, v0.t", r"vfadd\.vv\s+v8,\s+v9,\s+v10, v0\.t"),
        ("vfcvt.f.x.v v8, v16, v0.t", r"vfcvt\.f\.x\.v\s+v8,\s+v9, v0\.t"),
        ("vfcvt.x.f.v v8, v16, v0.t", r"vfcvt\.x\.f\.v\s+v8,\s+v9, v0\.t"),
        ("vfneg.v v8, v16, v0.t", r"vfneg\.v\s+v8,\s+v9, v0\.t"),
    ),
)
def test_selected_masked_float_forms_pack_source_v0_before_execution(
    instruction: str, expected: str
):
    """已声明支持的 masked 浮点 form 必须真正装载源 v0，而非只放行后缀。"""
    output = _translate(instruction, "sew=32,lmul=1")

    native = re.search(expected, output)
    assert native is not None
    assert output.index("载入源 v0.t 执行掩码") < native.start()
    assert "RVV1024 fallback" not in output


def test_equal_width_vfcvt_uses_same_compact_group_shape():
    """等宽转换按当前 LMUL Pack 源/目的，并在同一源 vtype 下执行。"""
    output = _translate("vfcvt.xu.f.v v8, v16", "sew=64,lmul=2")

    # m2 的源物理组是 64B；v8/v16 分别位于 0x100/0x200。
    assert "addi    t1, t6, 256" in output
    assert "addi    t1, t6, 512" in output
    assert output.count("li      t2, 64") >= 3
    assert re.search(r"vfcvt\.xu\.f\.v\s+v8,\s+v10", output)
    assert "vsetvli zero, t0, e64, m2, tu, mu" in output


def test_widening_vfwcvt_uses_double_destination_lmul():
    """扩宽 conversion 的 vd 必须按 2*LMUL（此处 m4）读写，而 vs2 保持 m2。"""
    output = _translate("vfwcvt.f.x.v v8, v4", "sew=32,lmul=2")

    # vd=v8 的 m4 raw 组为 128B，vs2=v4 的 m2 raw 组为 64B；临时组也分别
    # 为 m4(v8) 与 m2(v12)。
    assert "addi    t1, t6, 256" in output
    assert "addi    t1, t6, 128" in output
    assert output.count("li      t2, 128") >= 2
    assert "li      t2, 64" in output
    assert re.search(r"vfwcvt\.f\.x\.v\s+v8,\s+v12", output)
    assert "vsetvli zero, t0, e32, m2, tu, mu" in output


@pytest.mark.parametrize(
    ("instruction", "vtype", "reason"),
    [
        ("vfsub.vf v8, v16, fa0, v0.t", "sew=32,lmul=1", "掩码"),
        ("vfcvt.f.x.v v8, v16", "sew=8,lmul=1", "浮点"),
        ("vfwcvt.f.f.v v8, v4", "sew=32,lmul=8", "LMUL=16"),
    ],
)
def test_float_forms_that_exceed_current_contract_fall_back(
    instruction: str,
    vtype: str,
    reason: str,
):
    """未验证掩码、非法浮点宽度和 m16 目的组生成诊断 + ebreak。"""
    instructions = AsmParser().parse_string(instruction)
    output = translate(instructions, init_vtype=vtype, raw=True)
    assert "RVV1024 fallback" in output
    assert reason in output
    assert "fallback to ebreak" in output


def test_hot_float_output_is_accepted_by_llvm_mc(tmp_path: Path):
    """用真实 RISC-V 汇编器检查 operand 顺序和临时组编码。

    这是静态汇编门禁：它只证明生成文本可被 RV64GCV 汇编器接受，不证明
    VLEN=1024 实机上的浮点结果、异常标志或完整 state 差分已经正确。
    """
    llvm_mc = shutil.which("llvm-mc")
    if llvm_mc is None:
        homebrew_llvm_mc = Path("/opt/homebrew/opt/llvm/bin/llvm-mc")
        llvm_mc = str(homebrew_llvm_mc) if homebrew_llvm_mc.exists() else None
    if llvm_mc is None:
        pytest.skip("未找到带 RISC-V target 的 llvm-mc")

    cases = (
        ("vfmacc.vf v8, fa0, v16", "sew=32,lmul=1"),
        ("vfmacc.vv v8, v16, v24", "sew=64,lmul=8"),
        ("vfnmsac.vf v8, fa1, v16", "sew=64,lmul=2"),
        ("vfmadd.vf v8, fa0, v16", "sew=32,lmul=1"),
        ("vfmsac.vv v8, v16, v24", "sew=32,lmul=2"),
        ("vfdiv.vv v8, v16, v24", "sew=32,lmul=1"),
        ("vfsub.vv v8, v16, v24", "sew=32,lmul=2"),
        ("vfcvt.xu.f.v v8, v16", "sew=32,lmul=2"),
        ("vfwcvt.f.x.v v8, v4", "sew=32,lmul=2"),
    )
    for index, (instruction, vtype) in enumerate(cases):
        source = tmp_path / f"rvv1024_hot_float_{index}.s"
        obj = tmp_path / f"rvv1024_hot_float_{index}.o"
        source.write_text(".text\n" + _translate(instruction, vtype), encoding="utf-8")
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
