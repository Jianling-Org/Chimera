"""翻译方向几何单一权威的合同测试。"""

from fractions import Fraction

import pytest

from riscv.extensions.rvv.analysis.model import LEGAL_LMULS, LMUL_TOKENS
from riscv.extensions.rvv.runtime.geometry import RVV1024_TO_RVV256_GEOMETRY, RVV256_TO_RVV1024_GEOMETRY, TranslationGeometry, geometry_for_direction, validate_state_layout_compatibility


class TestDirectionRegistry:
    def test_registered_directions(self):
        assert RVV1024_TO_RVV256_GEOMETRY.source_vlenb == 128
        assert RVV1024_TO_RVV256_GEOMETRY.target_vlenb == 32
        assert RVV256_TO_RVV1024_GEOMETRY.source_vlenb == 32
        assert RVV256_TO_RVV1024_GEOMETRY.target_vlenb == 128

    def test_registry_lookup_returns_registered_object(self):
        geometry = geometry_for_direction(128, 32)
        assert geometry is RVV1024_TO_RVV256_GEOMETRY
        assert geometry_for_direction(32, 128) is RVV256_TO_RVV1024_GEOMETRY

    def test_unregistered_direction_fails_closed(self):
        with pytest.raises(ValueError, match="未支持的翻译方向"):
            geometry_for_direction(64, 32)
        with pytest.raises(ValueError, match="未支持的翻译方向"):
            geometry_for_direction(128, 128)

    def test_geometry_validates_slot_coverage(self):
        # 源 VLENB 必须整除固定 128B 槽，否则紧凑布局无法解释。
        with pytest.raises(ValueError, match="不能整除"):
            TranslationGeometry(source_vlenb=48, target_vlenb=32)

    def test_geometry_rejects_non_power_of_two_target(self):
        with pytest.raises(ValueError, match="2 的幂"):
            TranslationGeometry(source_vlenb=128, target_vlenb=24)


class TestDerivations:
    def test_wide_ratio_matches_state_slot(self):
        # 128B 槽 / 32B 目标 = 4，这正是 strip-mining 的方向常数。
        assert RVV1024_TO_RVV256_GEOMETRY.ratio == 4

    def test_elements_per_chunk(self):
        geometry = RVV1024_TO_RVV256_GEOMETRY
        assert geometry.elements_per_chunk(8) == 32
        assert geometry.elements_per_chunk(32) == 8
        assert geometry.elements_per_chunk(64) == 4
        with pytest.raises(ValueError):
            geometry.elements_per_chunk(24)

    def test_chunk_bytes_equals_target_vlenb(self):
        assert RVV1024_TO_RVV256_GEOMETRY.chunk_bytes() == 32

    def test_source_vlmax(self):
        geometry = RVV1024_TO_RVV256_GEOMETRY
        assert geometry.source_vlmax(8, 8.0) == 1024
        assert geometry.source_vlmax(64, 1.0) == 16
        assert geometry.source_vlmax(32, 0.5) == 16

    def test_whole_register_transfer(self):
        geometry = RVV1024_TO_RVV256_GEOMETRY
        assert geometry.whole_register_transfer_lmul(32) == 1
        assert geometry.whole_register_transfer_lmul(64) == 2
        assert geometry.whole_register_transfer_lmul(128) == 4
        assert geometry.whole_register_transfer_lmul(256) == 8
        with pytest.raises(ValueError):
            geometry.whole_register_transfer_lmul(48)
        with pytest.raises(ValueError):
            geometry.whole_register_transfer_lmul(32 * 16)

    def test_reverse_direction_has_no_strip_ratio(self):
        # 32→128 是加宽方向；strip-mining 常数未定义，不得静默返回 0。
        with pytest.raises(ValueError):
            _ = RVV256_TO_RVV1024_GEOMETRY.ratio


class TestLmulFacts:
    def test_legal_lmul_set_matches_rvv_encoding(self):
        assert LEGAL_LMULS == (0.125, 0.25, 0.5, 1.0, 2.0, 4.0, 8.0)

    def test_lmul_tokens_are_complete(self):
        assert set(LMUL_TOKENS) == set(LEGAL_LMULS)
        assert LMUL_TOKENS[0.125] == "mf8"
        assert LMUL_TOKENS[8.0] == "m8"


def test_layout_compatibility_check_passes_for_both_directions():
    for geometry in (RVV1024_TO_RVV256_GEOMETRY, RVV256_TO_RVV1024_GEOMETRY):
        layout = validate_state_layout_compatibility(geometry)
        assert layout.get_total_size() == 0x1040


def test_wide_planner_uses_geometry_ratio_not_literal():
    """宽路径规划器的放大倍数必须来自几何，而非内联 4。"""

    from riscv.extensions.rvv.backends.rvv256.planning import plan_wide_chunk

    plan = plan_wide_chunk(
        source_lmul=1.0,
        source_sew=32,
        data_sew=32,
        source_regs=("v8", "v16", "v24"),
        target_group_count=2,
    )
    assert plan is not None
    # 128→32 的理想放大是 4：e32,m1 源应规划到 m4 目标。
    assert plan.target_lmul == Fraction(4)
