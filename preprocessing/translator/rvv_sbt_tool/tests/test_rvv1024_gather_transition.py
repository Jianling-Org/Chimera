"""RVV256→RVV1024 ``vrgather`` 过渡路径回归。

这些测试验证两个互补层次：

* 生成文本确实先零扩展 target ``vs2``，再 Pack 源 raw payload，并在 source
  ``vl`` 下执行原生 gather；
* 一个独立的小型值模型验证该零扩展技巧对所有 source-VLMAX 越界索引给出零。

后者不是 RVV 真机差分验证，不能替代 VLEN=1024 目标环境上的完整状态测试；它
只把本 handler 的关键边界不变量固定下来，避免后续“简化”为直接 target gather。
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
    """以显式 RVV256 source vtype 生成裸过渡块。"""
    return translate(AsmParser().parse_string(source), init_vtype=vtype, raw=True)


def _source_gather(values: list[int], indices: list[int]) -> list[int]:
    """RVV 源语义模型：index >= source VLMAX 必须返回零。"""
    return [values[index] if 0 <= index < len(values) else 0 for index in indices]


def _target_gather_after_zero_extension(
    source_values: list[int], indices: list[int], target_vlmax: int
) -> list[int]:
    """建模本 handler 的 target gather 输入：低位源值，高位全零。"""
    assert len(source_values) <= target_vlmax
    target_values = source_values + [0] * (target_vlmax - len(source_values))
    return [target_values[index] if 0 <= index < target_vlmax else 0 for index in indices]


@pytest.mark.parametrize(
    "source_vlmax",
    (1, 2, 8, 32, 64, 256),
)
def test_zero_extended_target_vs2_preserves_source_vlmax_out_of_range_rule(
    source_vlmax: int,
):
    """四倍 target VLMAX 不得让 source 越界 index 读到真实临时寄存器内容。"""
    source_values = [0x1000 + index for index in range(source_vlmax)]
    indices = [
        0,
        source_vlmax - 1,
        source_vlmax,
        source_vlmax + 1,
        4 * source_vlmax - 1,
        4 * source_vlmax,
        0xFFFF,
    ]
    expected = _source_gather(source_values, indices)
    actual = _target_gather_after_zero_extension(
        source_values, indices, target_vlmax=4 * source_vlmax
    )
    assert actual == expected


def test_vrgather_vv_zeros_target_expansion_before_packing_all_aliasable_sources():
    """普通 gather 必须零扩展 vs2，且 vd/vs2/vs1 全部 Pack 后才 Unpack。"""
    output = _translate("vrgather.vv v8, v16, v16", "sew=32,lmul=1")

    zero = output.index("vmv.v.i v9, 0")
    packed_vs2 = output.index("vle8.v  v9, (t1)")
    native = output.index("vrgather.vv        v8, v9, v10")
    unpack = output.index("vse8.v  v8, (t1)")

    assert zero < packed_vs2 < native < unpack
    assert "source VLMAX=8" in output
    assert re.search(r"vsetvli zero, \w+, e32, m1, tu, mu", output)
    assert output.count("vsetvli zero,") >= 2
    # 两个 source 可以互相别名，但 gather 的目的组不能与 source 重叠。
    assert output.count("addi    t1, t6, 512") == 2


def test_vrgather_rejects_destination_source_overlap():
    output = _translate("vrgather.vv v8, v8, v16", "sew=32,lmul=1")
    assert "Illegal overlapping vector groups" in output
    assert "fallback" in output


def test_vrgatherei16_uses_e16_index_emul_not_data_lmul():
    """source e8,m1 时 e16 index 必须按 m2（64B）Pack。"""
    output = _translate("vrgatherei16.vv v8, v16, v24", "sew=8,lmul=1")

    assert "index EMUL=2" in output
    assert "li      t2, 64             # Pack 源组有效字节数" in output
    assert re.search(r"vrgatherei16\.vv\s+v8, v9, v10", output)
    assert "vsetvli zero, t0, e8, m1, tu, mu" in output


def test_vrgather_m8_uses_all_three_temp_groups_and_raw_256b_transfer():
    """m8 gather 正好占满 v8--v31；扩展清零仍只能修改 vs2 临时组。"""
    output = _translate("vrgather.vv v8, v16, v24", "sew=8,lmul=8")

    assert "vmv.v.i v16, 0" in output
    assert re.search(r"vrgather\.vv\s+v8, v16, v24", output)
    assert output.count("li      t2, 256             # Pack 源组有效字节数") == 3
    assert "vsetvli zero, t0, e8, m8, tu, mu" in output


def test_vrgather_fractional_lmul_uses_exact_raw_bytes_not_128b_slot():
    """mf8 只有 4B source payload；不能因目标临时寄存器是 128B 而多 Pack。"""
    output = _translate("vrgather.vv v8, v16, v24", "sew=8,lmul=0.125")

    assert "source VLMAX=4" in output
    assert output.count("li      t2, 4             # Pack 源组有效字节数") == 3
    assert "vsetvli zero, t0, e8, mf8, tu, mu" in output


def test_vrgatherei16_maps_illegal_m16_index_group_to_ebreak():
    """source e8,m8 的 e16 index 是 m16，当前 form 以 ebreak 收口。"""
    output = _translate("vrgatherei16.vv v8, v16, v24", "sew=8,lmul=8")
    assert "RVV1024 fallback" in output
    assert "index EMUL=16" in output
    assert "    ebreak" in output


@pytest.mark.parametrize(
    "instruction",
    (
        "vrgather.vv v8, v16, v24, v0.t",
        "vrgatherei16.vv v8, v16, v24, v0.t",
    ),
)
def test_masked_gather_forms_fall_back_until_verified(instruction: str):
    """本实现还没有 mask-undisturbed 差分证据，不能无声放开 ``v0.t``。"""
    output = _translate(instruction, "sew=32,lmul=1")
    assert "RVV1024 fallback" in output
    assert "未验证" in output
    assert "    ebreak" in output


def _llvm_mc_path() -> str | None:
    """沿用项目的本地 LLVM 探测约定，仅做 RV64GCV 静态汇编门禁。"""
    discovered = shutil.which("llvm-mc")
    if discovered:
        return discovered
    candidate = Path("/opt/homebrew/opt/llvm/bin/llvm-mc")
    return str(candidate) if candidate.exists() else None


@pytest.mark.skipif(_llvm_mc_path() is None, reason="缺少带 RISC-V 后端的 llvm-mc")
@pytest.mark.parametrize(
    ("instruction", "vtype"),
    (
        ("vrgather.vv v8, v16, v24", "sew=32,lmul=1"),
        ("vrgather.vv v8, v16, v24", "sew=8,lmul=0.125"),
        ("vrgather.vv v8, v16, v24", "sew=8,lmul=8"),
        ("vrgatherei16.vv v8, v16, v24", "sew=8,lmul=1"),
        ("vrgatherei16.vv v8, v16, v24", "sew=32,lmul=0.5"),
        ("vrgatherei16.vv v8, v16, v24", "sew=8,lmul=4"),
        ("vrgatherei16.vv v8, v16, v24", "sew=64,lmul=8"),
    ),
)
def test_gather_output_is_accepted_by_base_rv64gcv_assembler(
    tmp_path: Path,
    instruction: str,
    vtype: str,
):
    """静态门禁只证明编码可汇编，不宣称已完成目标机语义差分。"""
    source = tmp_path / "gather.s"
    output = tmp_path / "gather.o"
    source.write_text(".text\n" + _translate(instruction, vtype), encoding="utf-8")
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
