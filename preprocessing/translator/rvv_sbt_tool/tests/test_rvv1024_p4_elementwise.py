"""RVV256→RVV1024 过渡路径的批次 4 逐元素与归约结构回归。

本文件刻意不覆盖 ``vrgather``、``vslide`` 等需要显式限制源 VLMAX 的指令。
断言只验证紧凑 state 的 Pack/Unpack、原生 operand 顺序和静态汇编可接受性；
真实目标机的全状态差分仍是后续语义验收门槛。
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
    """用显式 RVV256 源 vtype 生成裸过渡块。"""
    return translate(AsmParser().parse_string(source), init_vtype=vtype, raw=True)


def test_integer_accumulator_forms_preserve_nonstandard_operand_order():
    """vmacc.vx 的 scalar 位于 vs2 前，vmacc/vmadd .vv 都保留旧 vd。"""
    vv = _translate("vmacc.vv v8, v16, v24", "sew=32,lmul=2")
    assert re.search(r"vmacc\.vv\s+v8,\s+v10,\s+v12", vv)
    old_destination = re.search(r"vle32\.v\s+v8,", vv)
    accumulation = re.search(r"vmacc\.vv\s+v8,\s+v10,\s+v12", vv)
    assert old_destination is not None and accumulation is not None
    assert old_destination.start() < accumulation.start() < vv.index("vse32.v")

    vx = _translate("vmacc.vx v8, a0, v16", "sew=32,lmul=2")
    assert re.search(r"vmacc\.vx\s+v8,\s+a0,\s+v10", vx)

    vmadd = _translate("vmadd.vv v8, v16, v24", "sew=32,lmul=1")
    assert re.search(r"vmadd\.vv\s+v8,\s+v9,\s+v10", vmadd)


def test_vdiv_vx_keeps_semantic_t6_separate_from_state_base():
    """客户把 t6 当 rs1 时，emitter 必须别名保存它，state 基址仍为 t6。"""
    output = _translate("vdiv.vx v8, v16, t6", "sew=32,lmul=1")
    match = re.search(r"vdiv\.vx\s+v8,\s+v9,\s+(\w+)", output)
    assert match is not None
    assert match.group(1) != "t6"
    assert "CHIMERA_STATE_BASE" in output


@pytest.mark.parametrize(
    ("instruction", "expected"),
    [
        ("vdiv.vx v8, v16, a0", r"vdiv\.vx\s+v8,\s+v9,\s+a0"),
        ("vrsub.vi v8, v16, 0x1f", r"vrsub\.vi\s+v8,\s+v9,\s+-1"),
        ("vmax.vv v8, v16, v24", r"vmax\.vv\s+v8,\s+v9,\s+v10"),
        ("vmaxu.vv v8, v16, v24", r"vmaxu\.vv\s+v8,\s+v9,\s+v10"),
        ("vid.v v8", r"vid\.v\s+v8"),
        ("vfabs.v v8, v16", r"vfabs\.v\s+v8,\s+v9"),
        ("vfneg.v v8, v16", r"vfneg\.v\s+v8,\s+v9"),
    ],
)
def test_elementwise_native_forms_use_source_vl_and_tu_mu(
    instruction: str,
    expected: str,
):
    """不依赖源 VLMAX 的 form 必须在同一源 VL 下直接于目标硬件执行。"""
    output = _translate(instruction, "sew=32,lmul=1")
    assert "vsetvli zero, t0, e32, m1, tu, mu" in output
    assert re.search(expected, output)
    assert "# ERROR:" not in output


def test_vandn_and_vnot_lower_without_zvkb_requirement():
    """vandn/vnot 只使用基础 V 的 vxor.vi、vand.vv，不依赖可选 Zvkb。"""
    vandn = _translate("vandn.vv v8, v16, v24", "sew=32,lmul=1")
    assert "vandn.vv       " not in vandn
    assert re.search(r"vxor\.vi\s+v10,\s+v10,\s+-1", vandn)
    assert re.search(r"vand\.vv\s+v8,\s+v9,\s+v10", vandn)

    vnot = _translate("vnot.v v8, v16", "sew=32,lmul=1")
    assert re.search(r"vxor\.vi\s+v8,\s+v9,\s+-1", vnot)


def test_vandn_m8_reuses_packed_source_group_instead_of_needing_a_fourth_group():
    """m8 三操作数组已占满 v8-v31；vandn lowering 必须原地改写 vs1 临时组。"""
    output = _translate("vandn.vv v8, v16, v24", "sew=32,lmul=8")
    assert re.search(r"vxor\.vi\s+v24,\s+v24,\s+-1", output)
    assert re.search(r"vand\.vv\s+v8,\s+v16,\s+v24", output)


def test_masked_vrsub_vi_uses_common_v0_pack_then_native_form():
    """workload 中的 `vrsub.vi ..., v0.t` 必须保留关闭 lane 的旧目的值。"""
    output = _translate("vrsub.vi v8, v16, -3, v0.t", "sew=32,lmul=1")

    native = re.search(r"vrsub\.vi\s+v8,\s+v9,\s+-3, v0\.t", output)
    assert native is not None
    assert output.index("载入源 v0.t 执行掩码") < native.start()
    assert "写回紧凑 RVV256 物理组" in output


@pytest.mark.parametrize("opcode", ("vredsum.vs", "vredor.vs", "vredmaxu.vs"))
def test_integer_reduction_uses_m1_seed_and_destination_when_source_is_m8(opcode: str):
    """归约的 vd/vs1 恒为 m1，而 vs2 才是当前 m8 源组。"""
    output = _translate(f"{opcode} v3, v8, v5", "sew=32,lmul=8")

    # v3/v5 是单 32B raw 物理寄存器；v8 m8 才需要完整 256B Pack。
    assert "addi    t1, t6, 96" in output
    assert "addi    t1, t6, 160" in output
    assert "addi    t1, t6, 256" in output
    assert "li      t2, 256" in output
    assert output.count("li      t2, 32") >= 3
    assert re.search(rf"{re.escape(opcode)}\s+v8,\s+v16,\s+v9", output)
    assert "vsetvli zero, t0, e32, m8, tu, mu" in output


@pytest.mark.parametrize(
    "instruction",
    (
        "vmacc.vv v8, v16, v24, v0.t",
        "vredsum.vs v3, v8, v5, v0.t",
        "vfabs.v v8, v16, v0.t",
    ),
)
def test_p4_masked_forms_fall_back_until_verified(instruction: str):
    """尚未声明支持的 masked form 不能把 v0.t 悄悄当作无掩码执行。"""
    output = _translate(instruction, "sew=32,lmul=1")
    assert "RVV1024 fallback" in output
    assert "未验证" in output
    assert "    ebreak" in output


def test_p4_output_is_accepted_by_base_rv64gcv_assembler(tmp_path: Path):
    """静态检查：vandn lowering 不要求 Zvkb，所有 P4 文本能被基础 RV64GCV 接受。"""
    llvm_mc = shutil.which("llvm-mc")
    if llvm_mc is None:
        homebrew_llvm_mc = Path("/opt/homebrew/opt/llvm/bin/llvm-mc")
        llvm_mc = str(homebrew_llvm_mc) if homebrew_llvm_mc.exists() else None
    if llvm_mc is None:
        pytest.skip("未找到带 RISC-V target 的 llvm-mc")

    cases = (
        ("vmacc.vv v8, v16, v24", "sew=64,lmul=8"),
        ("vmacc.vx v8, a0, v16", "sew=32,lmul=2"),
        ("vmadd.vv v8, v16, v24", "sew=32,lmul=2"),
        ("vdiv.vx v8, v16, a0", "sew=32,lmul=1"),
        ("vrsub.vi v8, v16, -3", "sew=16,lmul=1"),
        ("vrsub.vi v8, v16, -3, v0.t", "sew=16,lmul=1"),
        ("vandn.vv v8, v16, v24", "sew=32,lmul=8"),
        ("vnot.v v8, v16", "sew=32,lmul=1"),
        ("vid.v v8", "sew=32,lmul=1"),
        ("vfabs.v v8, v16", "sew=32,lmul=1"),
        ("vredsum.vs v3, v8, v5", "sew=32,lmul=8"),
        ("vredor.vs v3, v8, v5", "sew=32,lmul=8"),
        ("vredmaxu.vs v3, v8, v5", "sew=32,lmul=8"),
    )
    for index, (instruction, vtype) in enumerate(cases):
        source = tmp_path / f"rvv1024_p4_{index}.s"
        obj = tmp_path / f"rvv1024_p4_{index}.o"
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
