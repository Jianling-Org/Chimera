"""共享 vtype 解码发射器的跨后端一致性测试。"""

import pytest

from riscv.extensions.rvv.translation.vtype_decode import emit_vlmax_from_vtype
from riscv.frontend.model import RVInstruction


class _LabelDispatcher:
    """测试用最小标签分配器，模拟正式 dispatcher 的编号行为。"""

    def __init__(self, prefix: str):
        self._prefix = prefix
        self._counter = 0

    def get_loop_label(self, prefix: str = "loop") -> str:
        label = f".L_{self._prefix}_{prefix}_{self._counter}"
        self._counter += 1
        return label


def _emit(source_vlenb: int) -> list[str]:
    lines: list[str] = []
    # 使用与 source_vlenb 无关的固定前缀，保证两次输出只有 li base 一行
    # 因几何参数而不同，标签必须逐行一致。
    dispatcher = _LabelDispatcher("decode")
    emit_vlmax_from_vtype(
        lines,
        vtype_reg="t0",
        out_reg="t1",
        sew_reg="t2",
        base_reg="t3",
        lmul_reg="t4",
        tmp_reg="t5",
        source_vlenb=source_vlenb,
        invalid_label=".L_invalid",
        new_label=dispatcher.get_loop_label,
        prefix="test",
    )
    return lines


def test_decode_emits_full_rvv_validity_checks():
    code = "\n".join(_emit(128))
    # RVV 1.0 的三项硬性检查必须都在场。
    assert "bltz    t0, .L_invalid" in code          # vill
    assert "vtype 保留位非零" in code                  # vtype[62:8]
    assert "e8..e64" in code                          # vsew 范围
    assert "100 为保留编码" in code                    # vlmul=0b100


def test_decode_parameterizes_source_vlenb_only():
    """两个后端只应因源 VLENB 不同而不同，检查逻辑必须逐行一致。"""

    narrow = _emit(32)
    wide = _emit(128)
    assert len(narrow) == len(wide)
    differences = [
        (a, b)
        for a, b in zip(narrow, wide)
        if a != b
    ]
    assert len(differences) == 1, f"期望仅一行 (li base) 不同: {differences}"
    assert "li      t3, 32" in differences[0][0]
    assert "li      t3, 128" in differences[0][1]


def test_integer_and_fractional_lmul_branches_both_emitted():
    code = "\n".join(_emit(128))
    assert "# 整数 LMUL" in code
    assert "# 分数 LMUL" in code


def test_rvv256_and_transition_configs_share_decoder():
    """两个后端的 vsetvl builder 都必须引用共享实现，不再各自维护副本。"""

    import riscv.extensions.rvv.backends.rvv256.handlers.config as rvv256_config
    import riscv.extensions.rvv.backends.rvv1024_transition.handlers.config as transition_config
    import riscv.extensions.rvv.translation.vtype_decode as shared

    assert rvv256_config.emit_vlmax_from_vtype is shared.emit_vlmax_from_vtype
    assert (
        transition_config.emit_vlmax_from_vtype
        is shared.emit_vlmax_from_vtype
    )
