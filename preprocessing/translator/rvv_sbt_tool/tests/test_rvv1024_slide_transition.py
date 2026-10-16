"""RVV256→RVV1024 过渡路径 slide 指令回归。

这些用例固定两条容易在“直接复用 RVV1024 指令”时丢失的架构约束：

* ``vslidedown`` 的 source 读取边界是 source RVV256 的 VLMAX，而不是当前 VL，
  也不是目标 RVV1024 的更大 VLMAX；
* ``vslideup`` 和 ``vslide1up`` 的 source/destination 组重叠在 RVV 中是保留
  编码，迁移器必须 fail-closed。

本文件的纯 Python 值模型只验证上述边界构造，不能替代 VLEN=1024 真机上的完整
reference/candidate 状态差分。
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


def _source_slidedown(values: list[int], vl: int, offset: int) -> list[int]:
    """按 RVV source VLMAX 规则建模无掩码 active destination lane。"""
    return [
        values[index + offset] if index + offset < len(values) else 0
        for index in range(vl)
    ]


def _target_slidedown_after_zero_extension(
    source_values: list[int],
    vl: int,
    offset: int,
) -> list[int]:
    """建模 handler：低 source VLMAX 为原值，目标扩展 lane 清零。"""
    target_values = source_values + [0] * (3 * len(source_values))
    return [
        target_values[index + offset]
        if index + offset < len(target_values)
        else 0
        for index in range(vl)
    ]


@pytest.mark.parametrize("source_vlmax", (1, 2, 8, 32, 64, 256))
def test_slidedown_zero_extension_preserves_source_vlmax_not_current_vl(
    source_vlmax: int,
):
    """即使 source tail 可读，也不得把 target 扩展区误当作可读 source。"""
    values = [0x5000 + index for index in range(source_vlmax)]
    for vl in {0, 1, max(1, source_vlmax // 2), source_vlmax}:
        for offset in {
            0,
            max(0, vl - 1),
            vl,
            max(0, source_vlmax - 1),
            source_vlmax,
            source_vlmax + 1,
            4 * source_vlmax - 1,
            4 * source_vlmax,
        }:
            assert _target_slidedown_after_zero_extension(values, vl, offset) == (
                _source_slidedown(values, vl, offset)
            )


def test_slidedown_vi_clears_complete_target_expansion_before_packing_aliasable_sources():
    """in-place slide-down 要先清零 vs2 temp，再 Pack old vd 和 vs2。"""
    output = _translate("vslidedown.vi v8, v8, 8", "sew=32,lmul=1")

    zero = output.index("vmv.v.i v9, 0")
    pack_vd = output.index("vle8.v  v8, (t1)")
    pack_vs2 = output.index("vle8.v  v9, (t1)")
    native_match = re.search(r"vslidedown\.vi\s+v8,\s+v9,\s+8", output)
    assert native_match is not None
    native = native_match.start()
    unpack = output.index("vse8.v  v8, (t1)")

    assert zero < pack_vd < pack_vs2 < native < unpack
    assert "source VLMAX=8" in output
    assert "target VLMAX = 4 * source VLMAX" in output
    # 原生执行严格以保存的 source VL 设置 target VL，而非 target VLMAX。
    assert "vsetvli zero, t0, e32, m1, tu, mu" in output
    # 同一 raw v8 必须被完整读取为 old-vd 与 source，两次 Pack 均在写回前。
    assert output.count("addi    t1, t6, 256") >= 3


def test_slidedown_reads_source_tail_when_offset_crosses_current_vl():
    """回归：offset>=VL 不等于零；只在 offset 到达 source VLMAX 后才为零。"""
    values = list(range(8))
    assert _source_slidedown(values, vl=2, offset=4) == [4, 5]
    assert _target_slidedown_after_zero_extension(values, vl=2, offset=4) == [4, 5]
    assert _source_slidedown(values, vl=2, offset=8) == [0, 0]


def test_slide1down_uses_saved_source_vl_for_scalar_position_not_target_vlmax():
    """``vslide1down`` 的标量位置是 ``VL-1``，故 native 前必须恢复 source VL。"""
    source_vlmax = 8
    source_values = list(range(source_vlmax))
    source_vl = source_vlmax
    scalar = 0x7F

    # RVV 规范：前 VL-1 lane 向下滑动，最后一个 *active* lane 写入 scalar。
    expected = source_values[1:source_vl] + [scalar]
    target_values = source_values + [0] * (3 * source_vlmax)
    actual = target_values[1:source_vl] + [scalar]
    assert actual == expected

    output = _translate("vslide1down.vx v8, v8, a0", "sew=32,lmul=1")
    native_match = re.search(r"^\s+vslide1down\.vx\s+", output, re.MULTILINE)
    assert native_match is not None
    native = native_match.start()
    # target full-VLMAX 初始化只属于 vslidedown 边界修补；slide1down 不能
    # 使用它，否则将把 scalar 错放到 target VLMAX-1。
    assert "请求完整 RVV1024 VLMAX" not in output
    assert output.rfind("vsetvli zero, t0, e32, m1, tu, mu", 0, native) != -1


def test_slidedown_vx_preserves_semantic_t6_through_emitter_aliasing():
    """客户 rs1 为 t6 时，t6 仍必须先被 wrapper 改名保存，不能变成 state 基址。"""
    output = _translate("vslidedown.vx v8, v16, t6", "sew=16,lmul=4")
    native = re.search(r"vslidedown\.vx\s+v8,\s+v12,\s+(\w+)", output)
    assert native is not None
    assert native.group(1) != "t6"
    assert "CHIMERA_STATE_BASE" in output


@pytest.mark.parametrize(
    ("instruction", "native"),
    (
        ("vslideup.vi v8, v16, 7", r"vslideup\.vi\s+v8,\s+v9,\s+7"),
        ("vslide1up.vx v8, v16, a0", r"vslide1up\.vx\s+v8,\s+v9,\s+a0"),
        # slide1down 明确允许 vd==vs2；两个临时组仍需先后 Pack 才能安全。
        ("vslide1down.vx v8, v8, zero", r"vslide1down\.vx\s+v8,\s+v9,\s+zero"),
    ),
)
def test_other_slide_forms_pack_all_inputs_then_execute_at_source_vl(
    instruction: str,
    native: str,
):
    """slide-up / slide1 只在 source VL 下执行，并保留 old vd 的 tu 值。"""
    output = _translate(instruction, "sew=32,lmul=1")
    assert re.search(native, output)
    assert "vsetvli zero, t0, e32, m1, tu, mu" in output
    assert output.index("vle8.v  v8, (t1)") < re.search(native, output).start()
    assert output.index("vle8.v  v9, (t1)") < re.search(native, output).start()
    assert "target VLMAX = 4 * source VLMAX" not in output


@pytest.mark.parametrize(
    "instruction",
    (
        "vslideup.vi v8, v8, 1",
        "vslide1up.vx v8, v8, zero",
        # m2 同起点会覆盖完整 source 组；该 form 同样是保留编码。
        "vslideup.vi v16, v16, 1",
    ),
)
def test_slideup_and_slide1up_overlap_falls_back(instruction: str):
    """规范保留的 source/destination overlap 不应被静默赋义。"""
    vtype = "sew=32,lmul=2" if instruction == "vslideup.vi v16, v16, 1" else "sew=32,lmul=1"
    output = _translate(instruction, vtype)
    assert "RVV1024 fallback" in output
    assert "重叠" in output
    assert "保留" in output
    assert "    ebreak" in output


@pytest.mark.parametrize(
    "instruction",
    (
        "vslideup.vi v8, v16, 1, v0.t",
        "vslide1up.vx v8, v16, zero, v0.t",
        "vslide1down.vx v8, v16, zero, v0.t",
    ),
)
def test_unverified_masked_slide_forms_fall_back_until_verified(instruction: str):
    """尚未声明支持的 masked slide 不能把关闭 lane 当作普通写入。"""
    output = _translate(instruction, "sew=32,lmul=1")
    assert "RVV1024 fallback" in output
    assert "未验证" in output
    assert "    ebreak" in output


def test_masked_slidedown_vi_packs_source_v0_before_native_execution():
    """已接通的 vslidedown.vi masked form 必须在原生指令前装载源 v0。"""
    output = _translate("vslidedown.vi v8, v16, 1, v0.t", "sew=32,lmul=1")

    native = re.search(r"vslidedown\.vi\s+v8,\s+v9,\s+1, v0\.t", output)
    assert native is not None
    assert output.index("载入源 v0.t 执行掩码") < native.start()
    assert "RVV1024 fallback" not in output


@pytest.mark.parametrize(
    ("instruction", "vtype"),
    (
        ("vslidedown.vi v8, v16, 31", "sew=32,lmul=1"),
        ("vslidedown.vx v8, v16, a0", "sew=32,lmul=1"),
        ("vslideup.vi v8, v16, 7", "sew=32,lmul=1"),
        ("vslide1up.vx v8, v16, a0", "sew=32,lmul=1"),
        ("vslide1down.vx v8, v8, zero", "sew=32,lmul=1"),
        # m8 时两个临时组恰好占用 v8--v23；仍必须在 Pack 后安全执行。
        ("vslidedown.vi v8, v16, 31", "sew=16,lmul=8"),
    ),
)
def test_slide_output_is_accepted_by_base_rv64gcv_assembler(
    tmp_path: Path,
    instruction: str,
    vtype: str,
):
    """静态汇编门禁只验证编码，不替代 VLEN=1024 真机语义差分。"""
    llvm_mc = shutil.which("llvm-mc")
    if llvm_mc is None:
        candidate = Path("/opt/homebrew/opt/llvm/bin/llvm-mc")
        llvm_mc = str(candidate) if candidate.exists() else None
    if llvm_mc is None:
        pytest.skip("缺少带 RISC-V 后端的 llvm-mc")

    source = tmp_path / "slide.s"
    output = tmp_path / "slide.o"
    source.write_text(".text\n" + _translate(instruction, vtype), encoding="utf-8")
    subprocess.run(
        [
            llvm_mc,
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
