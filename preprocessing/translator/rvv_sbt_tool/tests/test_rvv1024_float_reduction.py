"""RVV256→RVV1024 浮点归约过渡路径的结构与汇编门禁。

这些用例验证的是生成器的 state-layout、寄存器组和 operand-order 合同；它们
不是 VLEN=1024 目标机上的语义差分。特别是非确定浮点归约允许的归约树、NaN
处理和异常标志，仍需在真实目标环境以同初始状态进行完整参考/候选比较。
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
    """以显式源端 vtype 生成单条裸过渡块，便于检查 raw state 访问。"""
    instructions = AsmParser().parse_string(source)
    return translate(instructions, init_vtype=vtype, raw=True)


def test_vfredusum_m8_packs_single_register_result_seed_and_group_vs2():
    """同宽归约在 m8 时仍只为 vd/vs1 读写 32B，vs2 才使用 256B。"""
    output = _translate("vfredusum.vs v5, v16, v7", "sew=32,lmul=8")

    # 紧凑 RVV256 raw 偏移必须是寄存器编号乘 32，而非旧 128B state 槽位：
    # v5=160、v16=512、v7=224。三次 Pack 都在任何 Unpack 前完成。
    assert "addi    t1, t6, 160" in output
    assert "addi    t1, t6, 512" in output
    assert "addi    t1, t6, 224" in output
    assert output.count("li      t2, 32             # Pack 源组有效字节数") == 2
    assert "li      t2, 256             # Pack 源组有效字节数" in output
    native = re.search(r"^\s*vfredusum\.vs\s+v8,\s+v16,\s+v9$", output, re.M)
    assert native is not None
    # 不用文件头的注释作为证据：必须是三次真实 Pack load 都出现在 native
    # reduction 前，而第一次 Unpack store 出现在其后。
    assert output[:native.start()].count("vle8.v") == 3
    assert output.find("vse8.v", native.end()) >= native.end()

    # m8 只施加给被归约向量 vs2；v8/v9 是两个 m1 的目标临时组，分别保存
    # result 与 seed，避免 vd/vs1 在源端可合法的非 m8 对齐而被错误拒绝。
    assert native
    assert "vsetvli zero, t0, e32, m8, tu, mu" in output
    assert "# ERROR:" not in output


@pytest.mark.parametrize(
    ("opcode", "expected"),
    [
        ("vfredmax.vs", r"vfredmax\.vs\s+v8,\s+v12,\s+v9"),
        ("vfredmin.vs", r"vfredmin\.vs\s+v8,\s+v12,\s+v9"),
    ],
)
def test_vfred_minmax_keep_single_register_seed_with_m4_source(
    opcode: str, expected: str
):
    """min/max 在 m4 源输入下也不能把 result/seed 当作 m4 组。"""
    output = _translate(f"{opcode} v3, v8, v5", "sew=64,lmul=4")

    # v3=96 (vd), v8=256 (vs2 m4), v5=160 (vs1 seed)。只出现两次 32B
    # Pack，证明 vd/vs1 没有错误按照 128B 的 m4 物理组解释。
    assert "addi    t1, t6, 96" in output
    assert "addi    t1, t6, 256" in output
    assert "addi    t1, t6, 160" in output
    assert output.count("li      t2, 32             # Pack 源组有效字节数") == 2
    assert "li      t2, 128             # Pack 源组有效字节数" in output
    assert re.search(expected, output)
    assert "vsetvli zero, t0, e64, m4, tu, mu" in output


def test_vfwredusum_uses_wide_single_register_seed_result_not_double_lmul_group():
    """宽化 reduction 的宽 element 不意味着 vd/vs1 变为 2*LMUL raw 组。"""
    output = _translate("vfwredusum.vs v3, v8, v5", "sew=32,lmul=4")

    # 若把 vd/vs1 错当成 m8，生成器会尝试各搬运 256B 并要求组对齐；正确行为
    # 是 v3 和 v5 各 32B，vs2=v8 才按 m4 搬运 128B。
    assert output.count("li      t2, 32             # Pack 源组有效字节数") == 2
    assert "li      t2, 128             # Pack 源组有效字节数" in output
    assert output.count("li      t2, 32             # Unpack 源组有效字节数") == 1
    assert re.search(r"vfwredusum\.vs\s+v8,\s+v12,\s+v9", output)
    assert "vsetvli zero, t0, e32, m4, tu, mu" in output


def test_vfwredosum_keeps_ordered_opcode_and_wide_scalar_seed_layout():
    """有序宽化归约不能退化为 unordered opcode，也不能扩大 seed/result 组。"""
    output = _translate("vfwredosum.vs v3, v8, v5", "sew=32,lmul=4")

    assert output.count("li      t2, 32             # Pack 源组有效字节数") == 2
    assert "li      t2, 128             # Pack 源组有效字节数" in output
    assert re.search(r"vfwredosum\.vs\s+v8,\s+v12,\s+v9", output)
    assert "vfwredusum.vs" not in output


@pytest.mark.parametrize(
    ("instruction", "vtype", "reason"),
    [
        ("vfredusum.vs v8, v16, v1, v0.t", "sew=32,lmul=1", "掩码"),
        ("vfwredusum.vs v8, v16, v1", "sew=64,lmul=1", "e64"),
        ("vfwredusum.vs v8, v16, v1", "sew=8,lmul=1", "浮点"),
    ],
)
def test_float_reduction_forms_outside_safe_subset_fall_back(
    instruction: str,
    vtype: str,
    reason: str,
):
    """masked、e64→e128 与 e8 浮点 form 生成诊断 + ebreak。"""
    instructions = AsmParser().parse_string(instruction)
    output = translate(instructions, init_vtype=vtype, raw=True)
    assert "RVV1024 fallback" in output
    assert reason in output
    assert "    ebreak" in output


def test_float_reduction_output_is_accepted_by_llvm_mc(tmp_path: Path):
    """真实 RV64GCV 汇编器接受所生成的 reduction operand/group 编码。

这是静态汇编检查，不等价于目标 VLEN=1024 环境的浮点语义、异常状态或完整
state 差分验证。
    """
    llvm_mc = shutil.which("llvm-mc")
    if llvm_mc is None:
        homebrew_llvm_mc = Path("/opt/homebrew/opt/llvm/bin/llvm-mc")
        llvm_mc = str(homebrew_llvm_mc) if homebrew_llvm_mc.exists() else None
    if llvm_mc is None:
        pytest.skip("未找到带 RISC-V target 的 llvm-mc")

    cases = (
        ("vfredusum.vs v5, v16, v7", "sew=32,lmul=8"),
        ("vfredmax.vs v3, v8, v5", "sew=64,lmul=4"),
        ("vfredmin.vs v3, v8, v5", "sew=16,lmul=4"),
        ("vfwredusum.vs v3, v8, v5", "sew=16,lmul=8"),
        ("vfwredusum.vs v3, v8, v5", "sew=32,lmul=4"),
        ("vfwredosum.vs v3, v8, v5", "sew=32,lmul=4"),
    )
    for index, (instruction, vtype) in enumerate(cases):
        source = tmp_path / f"rvv1024_float_reduce_{index}.s"
        obj = tmp_path / f"rvv1024_float_reduce_{index}.o"
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
