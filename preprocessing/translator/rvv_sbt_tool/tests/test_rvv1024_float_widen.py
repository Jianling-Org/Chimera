"""RVV256→RVV1024 无掩码浮点宽化乘法的结构与汇编检查。"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

from riscv.frontend.parser import AsmParser
from rvv_sbt_rvv1024 import translate


def _translate(source: str, vtype: str) -> str:
    """以显式 source vtype 生成单条裸过渡块。"""
    return translate(AsmParser().parse_string(source), init_vtype=vtype, raw=True)


def test_vfwmacc_packs_wide_accumulator_and_all_narrow_sources_before_writeback():
    """宽 FMA 在 m2 时 vd=m4，两个窄输入仍为 m2，且顺序保持 ``vs1,vs2``。"""
    output = _translate("vfwmacc.vv v8, v4, v12", "sew=32,lmul=2")

    # 源紧凑 layout: 宽 vd=v8,m4 为 128B；窄 vs1=v4,m2 和 vs2=v12,m2 各
    # 64B。三者均在 native FMA 与首次 Unpack 前完成 Pack。
    assert "addi    t1, t6, 256" in output
    assert "addi    t1, t6, 128" in output
    assert "addi    t1, t6, 384" in output
    assert "li      t2, 128             # Pack 源组有效字节数" in output
    assert output.count("li      t2, 64             # Pack 源组有效字节数") == 2
    native = re.search(r"^\s*vfwmacc\.vv\s+v8,\s+v12,\s+v14$", output, re.M)
    assert native is not None
    # 三个真实 Pack load 必须在 native FMA 前完成，避免 vd/vs 别名时提前
    # Unpack 覆盖仍待读取的窄输入。
    assert output[:native.start()].count("vle8.v") == 3
    assert output.find("vse8.v", native.end()) >= native.end()
    assert "vsetvli zero, t0, e32, m2, tu, mu" in output


def test_vfwmul_vf_uses_wide_destination_but_keeps_vector_scalar_operand_order():
    """``vfwmul.vf`` 必须发射为 ``vd, vs2, rs1``，不能误用 FMA .vf 顺序。"""
    output = _translate("vfwmul.vf v8, v4, fa0", "sew=16,lmul=4")

    # vd=v8,m8 占 256B，vs2=v4,m4 占 128B；scalar 不访问紧凑 vector state。
    assert "addi    t1, t6, 256" in output
    assert "addi    t1, t6, 128" in output
    assert "li      t2, 256             # Pack 源组有效字节数" in output
    assert "li      t2, 128             # Pack 源组有效字节数" in output
    assert re.search(r"vfwmul\.vf\s+v8,\s+v16,\s+fa0", output)
    assert "vsetvli zero, t0, e16, m4, tu, mu" in output


@pytest.mark.parametrize(
    ("instruction", "vtype", "reason"),
    [
        ("vfwmacc.vv v8, v4, v12, v0.t", "sew=32,lmul=2", "掩码"),
        ("vfwmul.vf v8, v4, fa0", "sew=64,lmul=1", "e64"),
        ("vfwmacc.vv v8, v8, v16", "sew=32,lmul=8", "EMUL=16"),
    ],
)
def test_float_widen_forms_outside_safe_subset_fall_back(
    instruction: str,
    vtype: str,
    reason: str,
):
    """未验证 mask、e128 和非法 m16 宽目的组生成诊断 + ebreak。"""
    output = _translate(instruction, vtype)
    assert "RVV1024 fallback" in output
    assert reason in output
    assert "    ebreak" in output


def test_float_widen_output_is_accepted_by_llvm_mc(tmp_path: Path):
    """确认 target 汇编器接受组宽与 operand-order；不是机器语义差分。"""
    llvm_mc = shutil.which("llvm-mc")
    if llvm_mc is None:
        homebrew_llvm_mc = Path("/opt/homebrew/opt/llvm/bin/llvm-mc")
        llvm_mc = str(homebrew_llvm_mc) if homebrew_llvm_mc.exists() else None
    if llvm_mc is None:
        pytest.skip("未找到带 RISC-V target 的 llvm-mc")

    cases = (
        ("vfwmacc.vv v8, v4, v12", "sew=16,lmul=4"),
        ("vfwmacc.vv v8, v4, v12", "sew=32,lmul=2"),
        ("vfwmul.vf v8, v4, fa0", "sew=16,lmul=4"),
        ("vfwmul.vf v8, v4, fa0", "sew=32,lmul=2"),
    )
    for index, (instruction, vtype) in enumerate(cases):
        source = tmp_path / f"rvv1024_float_widen_{index}.s"
        obj = tmp_path / f"rvv1024_float_widen_{index}.o"
        source.write_text(".text\n" + _translate(instruction, vtype), encoding="utf-8")
        subprocess.run(
            [
                llvm_mc,
                "-triple=riscv64-unknown-linux-gnu",
                "-mattr=+m,+a,+f,+d,+c,+v,+zfh,+zvfh,+zvfhmin,+zicsr",
                "-filetype=obj",
                str(source),
                "-o",
                str(obj),
            ],
            check=True,
            capture_output=True,
            text=True,
        )
