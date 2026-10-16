"""五条新增 RVV 指令的两条模式结构回归。

这些测试验证的是当前翻译器已经承诺的证据层：dispatcher 可达、生成的
Pack/执行/Unpack 或 RVV256 分块文本完整、操作数顺序正确，以及整寄存器
搬运的固定字节数正确。它们不把主机上的文本检查冒充成目标 RISC-V 真机
上的算术/掩码差分验证；真实语义仍需在具备对应 RVV 硬件或 QEMU 的环境
中继续验收。
"""

from __future__ import annotations

import re

import pytest

from riscv.frontend.parser import AsmParser
from rvv_sbt_rvv import translate as translate_rvv256
from rvv_sbt_rvv1024 import translate as translate_rvv1024


def _instructions(source: str):
    """使用统一 parser，确保测试覆盖真实 operand DTO 而不是手造字符串。"""
    return AsmParser().parse_string(source)


@pytest.mark.parametrize("wide_lmul", (True, False))
@pytest.mark.parametrize(
    ("instruction", "vtype", "expected"),
    [
        (
            "vmfne.vf v1, v2, fa0",
            "sew=32,lmul=1",
            "feq.s",
        ),
        (
            "vwaddu.vx v8, v16, a0",
            "sew=8,lmul=1",
            "vwaddu.vx",
        ),
        (
            "vmadd.vx v8, a0, v16",
            "sew=32,lmul=1",
            "vmadd.vx",
        ),
        (
            "vmclr.m v1",
            "sew=32,lmul=1",
            "sb      zero",
        ),
        (
            "vl8r.v v8, (a0)",
            None,
            "vl8r.v",
        ),
    ],
)
def test_rvv256_requested_opcodes_are_reachable_in_both_profiles(
    instruction: str,
    vtype: str | None,
    expected: str,
    wide_lmul: bool,
):
    """RVV256 默认宽 profile 与保守 profile 都不能把新增 opcode 落到 ebreak。"""
    output = translate_rvv256(
        _instructions(instruction),
        init_vtype=vtype,
        raw=True,
        wide_lmul=wide_lmul,
    )

    assert "# ERROR:" not in output
    assert "# UNIMPLEMENTED:" not in output
    assert expected in output

    if instruction.startswith("vmadd.vx"):
        # vmadd.vx 的 scalar 必须位于 vs2 前；只检查原生临时寄存器形态，
        # 不绑定 allocator 的具体 v24/v25 编号。
        assert re.search(r"vmadd\.vx\s+v\d+,\s+a0,\s+v\d+", output)
    if instruction.startswith("vwaddu.vx"):
        assert "vle8.v" in output and "vse16.v" in output
    if instruction.startswith("vl8r.v"):
        assert "vl8r.v" in output


@pytest.mark.parametrize(
    ("instruction", "vtype", "expected"),
    [
        ("vmfne.vf v1, v2, fa0", "sew=32,lmul=1", "vmfne.vf"),
        ("vwaddu.vx v8, v16, a0", "sew=16,lmul=1", "vwaddu.vx"),
        ("vmadd.vx v8, a0, v16", "sew=32,lmul=1", "vmadd.vx"),
        ("vmclr.m v1", "sew=32,lmul=1", "vmxor.mm"),
        ("vl8r.v v8, (a0)", None, "固定搬运 8 * 32B = 256B"),
    ],
)
def test_rvv1024_requested_opcodes_use_compact_state_contract(
    instruction: str,
    vtype: str | None,
    expected: str,
):
    """RVV1024 过渡路径必须经过紧凑 32B state 的正确闭环。"""
    output = translate_rvv1024(
        _instructions(instruction),
        init_vtype=vtype,
        raw=True,
    )

    assert "# ERROR:" not in output
    assert expected in output
    assert "RVV256→RVV1024 迁移 profile guard" in output

    if instruction.startswith("vmadd.vx"):
        assert re.search(r"vmadd\.vx\s+v\d+,\s+a0,\s+v\d+", output)
        assert "写回紧凑 RVV256 物理组" in output
    if instruction.startswith("vmclr.m"):
        assert "# vmclr.m" in output
        assert "写回紧凑 RVV256 物理组" in output
    if instruction.startswith("vl8r.v"):
        # whole-register load 与当前源 vtype 无关，固定使用 e8,m2 覆盖 256B。
        assert "vsetvli zero, t1, e8, m2, tu, mu" in output


def test_new_masked_forms_do_not_silently_drop_v0_t():
    """当前只接通无掩码形态；v0.t 必须继续显式 fallback。"""
    rvv256_output = translate_rvv256(
        _instructions("vmadd.vx v8, a0, v16, v0.t"),
        init_vtype="sew=32,lmul=1",
        raw=True,
    )
    assert "RVV256 masked form is not implemented yet" in rvv256_output
    assert "    ebreak" in rvv256_output

    transition_output = translate_rvv1024(
        _instructions("vwaddu.vx v8, v16, a0, v0.t"),
        init_vtype="sew=16,lmul=1",
        raw=True,
    )
    assert "RVV1024 fallback" in transition_output
    assert "未验证的 v0.t 掩码 form" in transition_output
    assert "    ebreak" in transition_output
