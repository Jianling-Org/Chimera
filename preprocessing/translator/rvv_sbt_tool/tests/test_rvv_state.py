#!/usr/bin/env python3
"""
RVV 状态布局与配置跟踪测试
"""

import sys
import os

# 添加项目根目录到 sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from riscv.extensions.rvv.runtime.layout import SimulatedStateLayout
from riscv.extensions.rvv.runtime.layout import CSR_OFFSETS, VREG_SIZE
from riscv.extensions.rvv.analysis.config import StateTracker
from riscv.frontend.model import RVInstruction


def test_state_layout_offsets():
    """测试模拟状态布局的偏移量计算"""

    allocator = SimulatedStateLayout(vlenb=128)

    # 测试向量寄存器偏移量
    assert allocator.get_offset('v0') == 0x0000, f"v0 offset error: {allocator.get_offset('v0')}"
    assert allocator.get_offset('v1') == 0x0080, f"v1 offset error: {allocator.get_offset('v1')}"
    assert allocator.get_offset('v16') == 0x0800, f"v16 offset error: {allocator.get_offset('v16')}"
    assert allocator.get_offset('v31') == 0x0F80, f"v31 offset error: {allocator.get_offset('v31')}"

    # 测试 CSR 偏移量
    assert allocator.get_offset('vstart') == 0x1000, f"vstart offset error"
    assert allocator.get_offset('vxsat') == 0x1008, f"vxsat offset error"
    assert allocator.get_offset('vxrm') == 0x1010, f"vxrm offset error"
    assert allocator.get_offset('vcsr') == 0x1018, f"vcsr offset error"
    assert allocator.get_offset('vl') == 0x1020, f"vl offset error"
    assert allocator.get_offset('vtype') == 0x1028, f"vtype offset error"
    assert allocator.get_offset('vlenb') == 0x1030, f"vlenb offset error"

    # 测试总大小
    total_size = allocator.get_total_size()
    expected_size = 32 * 128 + 0x40  # 4096 + 64 = 4160
    assert total_size == expected_size, f"Total size error: {total_size} != {expected_size}"

    # 测试向量寄存器范围
    start, end = allocator.get_vreg_range('v16')
    assert start == 0x0800 and end == 0x0880, f"vreg range error: ({start}, {end})"

    # 测试大小写不敏感
    assert allocator.get_offset('V16') == 0x0800, f"Case insensitive error"
    assert allocator.get_offset('VL') == 0x1020, f"Case insensitive error for CSR"

    # 测试无效寄存器
    try:
        allocator.get_offset('v32')
        assert False, "Should raise ValueError for v32"
    except ValueError as e:
        pass

    try:
        allocator.get_offset('unknown')
        assert False, "Should raise ValueError for unknown register"
    except ValueError as e:
        pass



def test_state_tracker_daxpy():
    """测试 StateTracker 解析 daxpy 风格的 m8 配置"""

    tracker = StateTracker(vlenb=128)  # VLEN = 128

    # 初始状态检查
    assert tracker.sew == 64, f"Initial SEW error: {tracker.sew}"
    assert tracker.lmul == 1.0, f"Initial LMUL error: {tracker.lmul}"
    assert tracker.vl == 0, f"Initial VL error: {tracker.vl}"

    # 创建 vsetvli a5, a0, e64, m8, ta, ma 指令
    insn = RVInstruction(
        address=0x34,
        opcode='vsetvli',
        op_str='a5, a0, e64, m8, ta, ma',
        operands=['a5', 'a0', 'e64', 'm8', 'ta', 'ma']
    )

    # 更新状态
    result = tracker.update(insn)
    assert result == True, "update() should return True for config instruction"

    # 验证解析结果
    assert tracker.sew == 64, f"SEW error: {tracker.sew}"
    assert tracker.lmul == 8.0, f"LMUL error: {tracker.lmul}"

    # 验证 VLMAX 计算: VLEN * LMUL / SEW = 1024 * 8 / 64 = 128
    # (vlenb=128 -> VLEN=1024 bits)
    vlmax = tracker.get_vlmax()
    assert vlmax == 128, f"VLMAX error: {vlmax}"

    # 验证状态字符串
    state_str = tracker.get_state_str()
    assert "SEW=64" in state_str, f"State string missing SEW: {state_str}"
    assert "LMUL=8.0" in state_str, f"State string missing LMUL: {state_str}"
    assert "VLMAX=128" in state_str, f"State string missing VLMAX: {state_str}"



def test_state_tracker_fractional():
    """测试 StateTracker 解析分数 LMUL (mf2)"""

    tracker = StateTracker(vlenb=128)  # VLEN = 128

    # 创建 vsetvli a0, a1, e64, mf2, ta, ma 指令
    insn = RVInstruction(
        address=0x100,
        opcode='vsetvli',
        op_str='a0, a1, e64, mf2, ta, ma',
        operands=['a0', 'a1', 'e64', 'mf2', 'ta', 'ma']
    )

    # 更新状态
    tracker.update(insn)

    # 验证解析结果
    assert tracker.sew == 64, f"SEW error: {tracker.sew}"
    assert tracker.lmul == 0.5, f"LMUL error: {tracker.lmul}"

    # 验证 VLMAX 计算: VLEN * LMUL / SEW = 1024 * 0.5 / 64 = 8
    # (vlenb=128 -> VLEN=1024 bits, mf2 -> LMUL=0.5)
    vlmax = tracker.get_vlmax()
    assert vlmax == 8, f"VLMAX error: {vlmax}"

    # 验证状态字符串
    state_str = tracker.get_state_str()
    assert "LMUL=0.5" in state_str, f"State string missing fractional LMUL: {state_str}"



def test_state_tracker_vsetivli():
    """测试 StateTracker 解析 vsetivli (立即数版本)"""

    tracker = StateTracker(vlenb=128)

    # 创建 vsetivli a0, 4, e32, m2, ta, ma 指令
    insn = RVInstruction(
        address=0x200,
        opcode='vsetivli',
        op_str='a0, 4, e32, m2, ta, ma',
        operands=['a0', '4', 'e32', 'm2', 'ta', 'ma']
    )

    # 更新状态
    tracker.update(insn)

    # 验证解析结果
    assert tracker.sew == 32, f"SEW error: {tracker.sew}"
    assert tracker.lmul == 2.0, f"LMUL error: {tracker.lmul}"

    # 验证 VLMAX 计算: VLEN * LMUL / SEW = 1024 * 2 / 32 = 64
    # (vlenb=128 -> VLEN=1024 bits, m2 -> LMUL=2)
    vlmax = tracker.get_vlmax()
    assert vlmax == 64, f"VLMAX error: {vlmax}"



def test_state_tracker_vsetvli_mu():
    """测试 StateTracker 解析 `mu` 时不会误判为 LMUL"""

    tracker = StateTracker(vlenb=128)

    insn = RVInstruction(
        address=0x220,
        opcode='vsetvli',
        op_str='a5, a0, e32, m4, ta, mu',
        operands=['a5', 'a0', 'e32', 'm4', 'ta', 'mu']
    )

    tracker.update(insn)

    assert tracker.sew == 32, f"SEW error: {tracker.sew}"
    assert tracker.lmul == 4.0, f"LMUL error: {tracker.lmul}"
    assert tracker.vta == 1, f"vta error: {tracker.vta}"
    assert tracker.vma == 0, f"vma error: {tracker.vma}"
    assert tracker.get_vtype_value() == 0b01010010, (
        f"vtype error: {tracker.get_vtype_value():#x}"
    )



def test_state_tracker_vsetivli_mu():
    """测试 StateTracker 解析 `vsetivli ... mu` 时不会崩溃"""

    tracker = StateTracker(vlenb=128)

    insn = RVInstruction(
        address=0x240,
        opcode='vsetivli',
        op_str='a0, 4, e32, m2, tu, mu',
        operands=['a0', '4', 'e32', 'm2', 'tu', 'mu']
    )

    tracker.update(insn)

    assert tracker.sew == 32, f"SEW error: {tracker.sew}"
    assert tracker.lmul == 2.0, f"LMUL error: {tracker.lmul}"
    assert tracker.vta == 0, f"vta error: {tracker.vta}"
    assert tracker.vma == 0, f"vma error: {tracker.vma}"
    assert tracker.get_vtype_value() == 0b00010001, (
        f"vtype error: {tracker.get_vtype_value():#x}"
    )



def test_state_tracker_non_config():
    """测试 StateTracker 对非配置指令的处理"""

    tracker = StateTracker(vlenb=128)

    # 先设置一个已知状态
    config_insn = RVInstruction(
        address=0x34,
        opcode='vsetvli',
        op_str='a5, a0, e64, m8, ta, ma',
        operands=['a5', 'a0', 'e64', 'm8', 'ta', 'ma']
    )
    tracker.update(config_insn)

    # 保存当前状态
    saved_sew = tracker.sew
    saved_lmul = tracker.lmul

    # 创建一个向量指令 (非配置指令)
    vector_insn = RVInstruction(
        address=0x38,
        opcode='vfmacc.vv',
        op_str='v4, v28, v16',
        operands=['v4', 'v28', 'v16']
    )

    # 更新状态 - 应该不改变任何状态
    result = tracker.update(vector_insn)
    assert result == False, "update() should return False for non-config instruction"
    assert tracker.sew == saved_sew, "SEW should not change"
    assert tracker.lmul == saved_lmul, "LMUL should not change"



def test_state_dict():
    """测试 StateTracker.get_state_dict()"""

    tracker = StateTracker(vlenb=128)

    insn = RVInstruction(
        address=0x34,
        opcode='vsetvli',
        op_str='a5, a0, e64, m4, ta, ma',
        operands=['a5', 'a0', 'e64', 'm4', 'ta', 'ma']
    )
    tracker.update(insn)

    state = tracker.get_state_dict()

    assert state['sew'] == 64, f"SEW error in dict: {state['sew']}"
    assert state['lmul'] == 4.0, f"LMUL error in dict: {state['lmul']}"
    # vlenb=128 -> VLEN=1024 bits, m4 -> LMUL=4
    # VLMAX = 1024 * 4 / 64 = 64
    assert state['vlmax'] == 64, f"VLMAX error in dict: {state['vlmax']}"
    assert state['vlen'] == 1024, f"VLEN error in dict: {state['vlen']}"
    assert state['config_str'] == 'a5, a0, e64, m4, ta, ma', f"config_str error"



def test_vtype_encoding_matches_rvv_layout():
    """测试 vtype 编码遵循 RVV 1.0 的真实位布局"""

    tracker = StateTracker(vlenb=128)
    insn = RVInstruction(
        address=0x300,
        opcode='vsetvli',
        op_str='a5, a0, e64, m8, ta, ma',
        operands=['a5', 'a0', 'e64', 'm8', 'ta', 'ma']
    )
    tracker.update(insn)

    # RVV 1.0:
    # - vlmul(m8) = 0b011
    # - vsew(e64) = 0b011
    # - vta = 1 -> bit6
    # - vma = 1 -> bit7
    expected = 0b11011011
    assert tracker.get_vtype_value() == expected, (
        f"vtype encoding mismatch: {tracker.get_vtype_value():#x} != {expected:#x}"
    )



def test_vtype_fractional_lmul_encoding():
    """测试分数 LMUL 的 vlmul 字段使用 RVV signed 编码"""

    cases = [
        ("mf8", 0.125, 0b11000101),
        ("mf4", 0.25, 0b11000110),
        ("mf2", 0.5, 0b11000111),
    ]

    for lmul_token, expected_lmul, expected_vtype in cases:
        tracker = StateTracker(vlenb=128)
        insn = RVInstruction(
            address=0x320,
            opcode='vsetvli',
            op_str=f'a5, a0, e8, {lmul_token}, ta, ma',
            operands=['a5', 'a0', 'e8', lmul_token, 'ta', 'ma']
        )
        tracker.update(insn)

        assert tracker.lmul == expected_lmul, (
            f"LMUL error for {lmul_token}: {tracker.lmul}"
        )
        assert tracker.get_vtype_value() == expected_vtype, (
            f"vtype error for {lmul_token}: "
            f"{tracker.get_vtype_value():#x} != {expected_vtype:#x}"
        )
