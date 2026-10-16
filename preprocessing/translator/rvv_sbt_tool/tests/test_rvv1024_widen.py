#!/usr/bin/env python3
"""RVV256→RVV1024 宽化整数闭环的翻译期测试。"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest


sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from riscv.frontend.parser import AsmParser
from rvv_sbt_rvv1024 import translate


def _translate(command: str, init_vtype: str = "sew=32,lmul=1") -> str:
    return translate(
        AsmParser().parse_string(command), init_vtype=init_vtype, raw=True
    )


def test_vwmacc_vx_uses_wide_destination_and_narrow_source_groups():
    """vwmacc.vx 的 vd 为 2*LMUL，而 vs2 仍按源 LMUL Pack。"""
    output = _translate("vwmacc.vx v8, a0, v16")

    assert "目的 EMUL=2" in output
    assert "li      t2, 64             # Pack 源组有效字节数" in output
    assert "li      t2, 32             # Pack 源组有效字节数" in output
    assert "vwmacc.vx    v8, a0, v10" in output
    assert "写回紧凑 RVV256 物理组" in output


def test_wide_narrow_and_reduction_keep_per_operand_emul():
    """wide+narrow 与宽化归约必须使用各自规定的物理组宽度。"""
    output = _translate(
        "\n".join([
            "vwadd.wv v8, v16, v24",
            "vwredsum.vs v8, v16, v24",
        ])
    )

    assert "vwadd.wv" in output
    assert "vwredsum.vs" in output
    # ``vwadd.wv`` 的 vd/vs2 是宽 m2 组，所以至少有两次 64B Pack；
    # ``vwredsum.vs`` 则是特殊的 widening reduction：vd/vs1 均为单
    # 物理寄存器的宽标量，只能按 32B Pack，不能错误要求 m2 对齐。
    assert output.count("li      t2, 64             # Pack 源组有效字节数") >= 2
    assert output.count("li      t2, 32             # Pack 源组有效字节数") >= 4


def test_vwsll_vi_uses_wide_destination_and_unsigned_shift_immediate():
    """vwsll.vi 的 vd 是 2*LMUL，并以基础 RVV lowering 避免 Zvbb 依赖。"""
    output = _translate("vwsll.vi v8, v16, 31", "sew=32,lmul=1")

    assert "宽化左移" in output
    assert "vwcvtu + vsll" in output
    assert "li      t2, 64             # Pack 源组有效字节数" in output
    assert "li      t2, 32             # Pack 源组有效字节数" in output
    assert "vwcvtu.x.x.v  v8, v10" in output
    assert "vsll.vi       v8, v8, 31" in output
    assert "    vwsll.vi" not in output
    assert "写回紧凑 RVV256 物理组" in output


def test_vwsll_vi_maps_e64_widening_to_ebreak():
    """e64→e128 不在一期 profile 内，不能生成假语义，改由 ebreak 收口。"""
    output = _translate("vwsll.vi v8, v16, 1", "sew=64,lmul=1")
    assert "RVV1024 fallback" in output
    assert "e8/e16/e32" in output
    assert "    ebreak" in output


def test_widening_reduction_accepts_unaligned_single_register_seed_and_result():
    """合法的 ``vwredsum`` seed/result 不是 2*LMUL 向量组。"""
    output = _translate("vwredsum.vs v4, v4, v5", "sew=8,lmul=1")

    assert "宽 seed/result 均为单物理寄存器" in output
    assert "addi    t1, t6, 128  # CHIMERA_STATE_BASE" in output  # vd/vs2 = v4
    assert "addi    t1, t6, 160  # CHIMERA_STATE_BASE" in output  # vs1 = v5
    assert "vwredsum.vs  v8, v9, v10" in output


def test_widening_m8_maps_illegal_m16_destination_to_ebreak():
    """m8 宽化需要非法 m16 目的组，当前以诊断 + ebreak 收口。"""
    output = _translate("vwmul.vv v8, v16, v24", "sew=32,lmul=8")
    assert "RVV1024 fallback" in output
    assert "超出 m8" in output
    assert "    ebreak" in output


def test_masked_widening_hotspots_pack_source_v0_after_all_data_sources():
    """vwmacc/vwredsum 的 v0.t 不能覆盖尚未 Pack 的宽/窄源组。"""
    output = _translate(
        "\n".join([
            "vwmacc.vx v8, a0, v16, v0.t",
            "vwredsum.vs v8, v16, v24, v0.t",
        ])
    )
    first_wmac = output.index("vwmacc.vx    v8, a0, v10, v0.t")
    first_mask = output.index("vmv1r.v v0", output.index("vwmacc.vx v8"))
    assert first_mask < first_wmac
    assert output.count("载入源 v0.t 执行掩码") == 2


def _llvm_mc_path() -> str | None:
    """沿用项目的 Homebrew LLVM 探测约定，仅做静态汇编门禁。"""
    found = shutil.which("llvm-mc")
    if found:
        return found
    candidate = Path("/opt/homebrew/opt/llvm/bin/llvm-mc")
    return str(candidate) if candidate.exists() else None


@pytest.mark.skipif(_llvm_mc_path() is None, reason="缺少带 RISC-V 后端的 llvm-mc")
def test_widening_output_assembles_as_rv64gcv(tmp_path):
    """宽化输出必须先通过目标汇编器；这不是目标机语义差分结论。"""
    asm = _translate(
        "\n".join([
            "vwmul.vv v8, v16, v24",
            "vwmacc.vx v8, a0, v16",
            "vwmulu.vx v8, v16, a1",
            "vwadd.wv v8, v16, v24",
            "vwsll.vi v8, v16, 3",
            "vwredsum.vs v8, v16, v24",
        ])
    )
    source = tmp_path / "widen.s"
    output = tmp_path / "widen.o"
    source.write_text(asm, encoding="utf-8")
    subprocess.run(
        [
            _llvm_mc_path(),
            "-triple=riscv64-unknown-linux-gnu",
            "-mattr=+v,+zicsr",
            "-filetype=obj",
            str(source),
            "-o",
            str(output),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    assert output.exists()
