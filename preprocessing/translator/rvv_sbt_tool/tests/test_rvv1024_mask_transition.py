#!/usr/bin/env python3
"""RVV256→RVV1024 批次 2 掩码与 FOF 的结构合同测试。

这些断言验证的是翻译器生成的 Pack/执行/Unpack 顺序、紧凑 32B state
寻址以及 FOF 的 ``vl`` 回写，不代替 VLEN=1024 目标机上的参考/候选完整
状态差分。特别是 mask tail、异常和真实访存故障仍需在目标环境验收。
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import re

import pytest


sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from riscv.frontend.parser import AsmParser
from rvv_sbt_rvv1024 import translate


def _translate(source: str, vtype: str = "sew=32,lmul=1") -> str:
    """按显式源端 vtype 翻译单条/片段，避免默认状态掩盖迁移入口合同。"""
    return translate(AsmParser().parse_string(source), init_vtype=vtype, raw=True)


@pytest.mark.parametrize(
    ("instruction", "native"),
    [
        ("vlm.v v1, (a0)", "vlm.v     v8, (a0)"),
        ("vmseq.vi v1, v2, -1", "vmseq.vi   v8, v9, -1"),
        ("vmsne.vv v1, v2, v3", "vmsne.vv   v8, v9, v10"),
        ("vmor.mm v1, v2, v3", "vmor.mm    v8, v9, v10"),
        ("vmand.mm v1, v2, v3", "vmand.mm   v8, v9, v10"),
        ("vmnot.m v1, v2", "vmnot.m    v8, v9"),
    ],
)
def test_mask_result_and_logic_use_raw_32b_pack_then_unpack(
    instruction: str, native: str
):
    """mask 指令应在临时 RVV1024 寄存器运行，而非访问旧 128B 槽位。"""
    output = _translate(instruction)

    # v1/v2/v3 分别从 N*32B=32/64/96 的源端 raw payload 读取。
    assert "addi    t1, t6, 32  # CHIMERA_STATE_BASE" in output
    assert "vsetvli zero, t0, e32, m1, tu, mu" in output
    assert native in output
    assert "# 写回紧凑 RVV256 物理组" in output
    assert "# ERROR:" not in output


@pytest.mark.parametrize(
    ("instruction", "native"),
    [
        ("vfirst.m a0, v1", "vfirst.m   a0, v8"),
        ("vcpop.m a0, v1", "vcpop.m    a0, v8"),
    ],
)
def test_mask_scans_only_pack_source_and_write_scalar(
    instruction: str, native: str
):
    """vfirst/vcpop 不应伪造向量目的写回，只观察 source mask 与源 VL。"""
    output = _translate(instruction)

    assert native in output
    assert "addi    t1, t6, 32  # CHIMERA_STATE_BASE" in output
    assert "# 写回紧凑 RVV256 物理组" not in output


@pytest.mark.parametrize(
    ("instruction", "native"),
    [
        ("vmsgtu.vi v1, v2, -1", "vmsgtu.vi v8, v9, -1"),
        ("vmsgtu.vx v1, v2, a0", "vmsgtu.vx v8, v9, a0"),
        ("vmsle.vi v1, v2, -3", "vmsle.vi v8, v9, -3"),
        ("vmsleu.vi v1, v2, 3", "vmsleu.vi v8, v9, 3"),
        ("vmsltu.vx v1, v2, a0", "vmsltu.vx v8, v9, a0"),
        ("vmfgt.vf v1, v2, fa0", "vmfgt.vf v8, v9, fa0"),
        ("vmfle.vf v1, v2, fa0", "vmfle.vf v8, v9, fa0"),
    ],
)
def test_additional_mask_compares_keep_source_vl_and_bitpacked_result(
    instruction: str, native: str
):
    """新增比较 form 必须走已有 mask Pack/Unpack 闭环，不能退化成标量路径。"""
    output = _translate(instruction)

    # handler 为 opcode 保留固定列宽，具体空格数不属于语义合同。
    assert " ".join(native.split()) in " ".join(output.split())
    assert "vsetvli zero, t0, e32, m1, tu, mu" in output
    assert "# 写回紧凑 RVV256 物理组" in output
    assert "# ERROR:" not in output


@pytest.mark.parametrize(
    ("instruction", "native"),
    [
        ("vmerge.vvm v8, v16, v24, v0", "vmerge.vvm v8, v9, v10, v0"),
        ("vmerge.vxm v8, v16, a0, v0", "vmerge.vxm v8, v9, a0, v0"),
        ("vmerge.vim v8, v16, -3, v0", "vmerge.vim v8, v9, -3, v0"),
    ],
)
def test_vmerge_packs_v0_selector_before_target_execution(
    instruction: str, native: str
):
    """vmerge 的 selector 必须来自 source raw v0，而不是残留目标硬件 v0。"""
    output = _translate(instruction)

    selector_load = output.index("vmv1r.v v0")
    execute = output.index(native)
    writeback = output.index("# 写回紧凑 RVV256 物理组")
    assert selector_load < execute < writeback
    # source v0 的 raw 起点正是 state 基址本身。
    assert "mv      t1, t6  # CHIMERA_STATE_BASE" in output


@pytest.mark.parametrize(
    "instruction",
    [
        "vadd.vv v0, v0, v8, v0.t",
        "vle32.v v0, (a0), v0.t",
        "vse32.v v0, (a0), v0.t",
    ],
)
def test_masked_data_forms_reject_illegal_v0_overlap(
    instruction: str,
):
    """数据目的不得覆盖 v0，数据源也不能同时以 EEW=1 作为 mask 读取。"""
    output = _translate(instruction)
    assert "fallback" in output
    assert "v0" in output
    assert not re.search(r"^\s*(?:vle|vse|vlm)", output, re.M)


def test_fof_keeps_source_vtype_and_writes_back_actual_vl():
    """FOF 的 EEW 只影响目的 EMUL；VL 语义仍来自原始 SEW/LMUL。"""
    output = _translate("vle8ff.v v8, (a0)")

    # e32,m1 源状态下 e8 目的为 mf4（8B），但执行 vtype 仍是 e32,m1。
    assert "目的 EMUL=0.25；执行 vtype 仍是源 e32,m1" in output
    assert "li      t3, 8             # Pack 源组有效字节数" in output
    assert "vsetvli zero, t0, e32, m1, tu, mu" in output
    assert "vle8ff.v  v8, (a0)" in output
    assert "# FOF 实际加载元素数" in output
    assert "源 CSR.vl" in output
    assert output.index("# FOF 实际加载元素数") < output.index("# FOF 已把缩短后的 VL")


def test_unverified_masked_fof_falls_back():
    """没有明确建模的 masked FOF 不能落入普通 load handler，改由 ebreak 收口。"""
    output = _translate("vle8ff.v v8, (a0), v0.t")
    assert "RVV1024 fallback" in output
    assert "未验证的 v0.t 掩码 form" in output
    assert "    ebreak" in output


def test_mask_and_fof_output_is_accepted_by_llvm_mc(tmp_path: Path):
    """静态汇编检查代表性 mask/FOF 输出。

    这一步只证明生成的 RV64GCV 文本、临时组和 ``v0`` 编码能被真实汇编器
    接受；它不证明 VLEN=1024 实机上的 mask tail、FOF fault 或完整 state
    差分正确性。
    """
    llvm_mc = shutil.which("llvm-mc")
    if llvm_mc is None:
        homebrew_llvm_mc = Path("/opt/homebrew/opt/llvm/bin/llvm-mc")
        llvm_mc = str(homebrew_llvm_mc) if homebrew_llvm_mc.exists() else None
    if llvm_mc is None:
        pytest.skip("未找到带 RISC-V target 的 llvm-mc")

    cases = (
        "vmseq.vi v1, v2, -1",
        "vmor.mm v1, v2, v3",
        "vmsgtu.vi v1, v2, -1",
        "vmfgt.vf v1, v2, fa0",
        "vmerge.vvm v8, v16, v24, v0",
        "vadd.vv v0, v0, v8, v0.t",
        "vle8ff.v v8, (a0)",
    )
    for index, instruction in enumerate(cases):
        source = tmp_path / f"rvv1024_mask_{index}.s"
        obj = tmp_path / f"rvv1024_mask_{index}.o"
        source.write_text(".text\n" + _translate(instruction), encoding="utf-8")
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
