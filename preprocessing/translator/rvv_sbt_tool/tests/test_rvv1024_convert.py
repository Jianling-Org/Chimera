#!/usr/bin/env python3
"""RVV256→RVV1024 宽窄转换路径的结构与目标汇编测试。"""

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
from rvv_sbt_rvv1024 import translate


def _translate(command: str, init_vtype: str) -> str:
    return translate(
        AsmParser().parse_string(command), init_vtype=init_vtype, raw=True
    )


def test_extend_uses_fractional_source_emul():
    """vzext.vf2 在 e16,m4 下必须把 vs2 当 e8,m2 组读取。"""
    output = _translate("vzext.vf2 v12, v20", "sew=16,lmul=4")

    assert "e8->e16 扩展，vs2 EMUL=2" in output
    assert "li      t2, 128             # Pack 源组有效字节数" in output
    assert "li      t2, 64             # Pack 源组有效字节数" in output
    assert "vzext.vf2      v8, v12" in output


def test_narrowing_uses_double_source_emul_and_preserves_vcsr_path():
    """宽源为 2*LMUL；两条指令恢复 vcsr，只有饱和 vnclip 需要回读。"""
    output = _translate(
        "\n".join([
            "vnsrl.wi v4, v8, 0",
            "vnclip.wi v4, v8, 3",
        ]),
        "sew=8,lmul=2",
    )

    assert output.count("e16->e8 窄化，vs2 EMUL=4") == 2
    assert output.count("li      t2, 128             # Pack 源组有效字节数") >= 2
    assert "vnsrl.wi       v8, v12, 0" in output
    assert "vnclip.wi      v8, v12, 3" in output
    assert output.count("csrw    vcsr,") == 2
    assert output.count("捕获目标执行后的 vcsr") == 1


def test_integer_widen_and_float_narrowing_shapes_are_distinct():
    """整数扩宽与 f32→i16 窄化应各自使用正确的 raw 组宽。"""
    widen_output = _translate("vwcvtu.x.x.v v10, v9", "sew=8,lmul=0.5")
    narrow_output = _translate("vfncvt.x.f.w v8, v8", "sew=16,lmul=4")

    assert "vwcvtu.x.x.v" in widen_output
    assert "vfncvt.x.f.w" in narrow_output
    assert "整数扩宽转换" in widen_output
    assert "e32->e16 窄化" in narrow_output


def test_masked_float_narrowing_packs_source_v0_before_execution():
    """vfncvt.f.f.w 的 masked form 必须保留窄目的的旧值和源 v0。"""
    output = _translate(
        "vfncvt.f.f.w v8, v16, v0.t",
        "sew=16,lmul=1",
    )

    native_match = re.search(
        r"^\s+vfncvt\.f\.f\.w\s+v8,\s+v10, v0\.t$",
        output,
        re.MULTILINE,
    )
    assert native_match is not None
    assert "载入源 v0.t 执行掩码" in output
    assert output.index("载入源 v0.t 执行掩码") < native_match.start()
    assert "vfncvt.f.f.w   v8, v10, v0.t" in output
    assert "RVV1024 fallback" not in output


def test_invalid_narrowing_e64_falls_back():
    """e64 目的要求 e128 宽源，当前一期不生成该 form，改由 ebreak 收口。"""
    output = _translate("vnsrl.wi v8, v16, 0", "sew=64,lmul=1")
    assert "RVV1024 fallback" in output
    assert "目的 SEW=e8/e16/e32" in output
    assert "    ebreak" in output


def _llvm_mc_path() -> str | None:
    found = shutil.which("llvm-mc")
    if found:
        return found
    candidate = Path("/opt/homebrew/opt/llvm/bin/llvm-mc")
    return str(candidate) if candidate.exists() else None


@pytest.mark.skipif(_llvm_mc_path() is None, reason="缺少带 RISC-V 后端的 llvm-mc")
def test_convert_output_assembles_as_rv64gcv(tmp_path):
    """目标汇编门禁仅验证编码合法，不能替代 VLEN=1024 语义差分。"""
    asm = _translate(
        "\n".join([
            "vzext.vf2 v12, v20",
            "vsext.vf2 v8, v4",
            "vnsrl.wi v4, v8, 0",
            "vwcvtu.x.x.v v8, v4",
            "vfncvt.x.f.w v8, v8",
        ]),
        "sew=16,lmul=1",
    )
    source = tmp_path / "convert.s"
    object_file = tmp_path / "convert.o"
    source.write_text(asm, encoding="utf-8")
    subprocess.run(
        [
            _llvm_mc_path(),
            "-triple=riscv64-unknown-linux-gnu",
            "-mattr=+v,+zicsr",
            "-filetype=obj",
            str(source),
            "-o",
            str(object_file),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    assert object_file.exists()
