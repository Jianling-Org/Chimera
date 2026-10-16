#!/usr/bin/env python3
"""
--init-vtype 参数测试（修订版）
仅验证 StateTracker 内部状态播种，不检查输出代码。
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from riscv.extensions.rvv.analysis.config import StateTracker
from riscv.extensions.rvv.runtime.layout import SimulatedStateLayout
from riscv.extensions.rvv.translation.emitter import ProgramEmitter
from riscv.extensions.rvv.backends.scalar.backend import ScalarDispatcher
from riscv.frontend.model import RVInstruction


def test_apply_init_vtype_raw_hex():
    """原始十六进制值"""
    s = StateTracker(vlenb=128)
    s.apply_init_vtype('0xDA')
    assert s.vtype == 0  # vtype 字段不直接设置，由 get_vtype_value() 计算
    assert s.sew == 64   # vsew=3 -> 64
    assert s.lmul == 4.0 # vlmul=3 -> 8.0... wait, 0xDA: bits[2:0]=010=2 -> 4.0


def test_apply_init_vtype_raw_decimal():
    """原始十进制值"""
    s = StateTracker(vlenb=128)
    s.apply_init_vtype('218')  # 0xDA
    assert s.sew == 64
    assert s.lmul == 4.0


def test_apply_init_vtype_raw_fractional_lmul():
    """原始 vtype 值中的分数 LMUL 使用 RVV signed vlmul 编码"""
    cases = [
        ('0xC5', 0.125),  # e8,mf8,ta,ma
        ('0xC6', 0.25),   # e8,mf4,ta,ma
        ('0xC7', 0.5),    # e8,mf2,ta,ma
    ]

    for raw_vtype, expected_lmul in cases:
        s = StateTracker(vlenb=128)
        s.apply_init_vtype(raw_vtype)
        assert s.sew == 8
        assert s.lmul == expected_lmul, (
            f"{raw_vtype}: lmul={s.lmul}, expected={expected_lmul}"
        )
        assert s.vta == 1
        assert s.vma == 1



def test_apply_init_vtype_semantic_minimal():
    """语义形式 - 最小必填字段"""
    s = StateTracker(vlenb=128)
    s.apply_init_vtype('sew=32,lmul=2')
    assert s.sew == 32
    assert s.lmul == 2.0
    assert s.vta == 0  # 缺省 tu
    assert s.vma == 0  # 缺省 mu


def test_apply_init_vtype_semantic_full():
    """语义形式 - 带策略字段"""
    s = StateTracker(vlenb=128)
    s.apply_init_vtype('sew=64,lmul=1,ta,ma')
    assert s.sew == 64
    assert s.lmul == 1.0
    assert s.vta == 1
    assert s.vma == 1


def test_apply_init_vtype_missing_sew():
    """缺少必填字段 sew"""
    s = StateTracker(vlenb=128)
    try:
        s.apply_init_vtype('lmul=2')
        assert False, "Should have raised ValueError"
    except ValueError as e:
        assert 'sew' in str(e)


def test_apply_init_vtype_missing_lmul():
    """缺少必填字段 lmul"""
    s = StateTracker(vlenb=128)
    try:
        s.apply_init_vtype('sew=32')
        assert False, "Should have raised ValueError"
    except ValueError as e:
        assert 'lmul' in str(e)


def test_emitter_with_init_vtype():
    """emitter 播种 StateTracker，但不产生 init 代码"""
    insns = [
        RVInstruction(address=0, opcode='add', operands=['a0', 'a0', 'a1'],
                       op_str='add a0, a0, a1')
    ]
    state = StateTracker(vlenb=128)
    alloc = SimulatedStateLayout()
    disp = ScalarDispatcher()
    emitter = ProgramEmitter()

    result = emitter._emit_function_assembly(
        insns, state, alloc, disp,
        init_vtype='sew=32,lmul=2'
    )

    # StateTracker 已播种
    assert state.sew == 32
    assert state.lmul == 2.0
    # 输出中不含 init 代码
    assert '--init-vtype' not in result
    assert 'CSR.vtype' not in result
    assert 'CSR.vl' not in result


def test_emitter_without_init_vtype():
    """不传 init_vtype 时行为不变"""
    insns = [
        RVInstruction(address=0, opcode='add', operands=['a0', 'a0', 'a1'],
                       op_str='add a0, a0, a1')
    ]
    state = StateTracker(vlenb=128)
    alloc = SimulatedStateLayout()
    disp = ScalarDispatcher()
    emitter = ProgramEmitter()

    result = emitter._emit_function_assembly(insns, state, alloc, disp)
    assert '--init-vtype' not in result
    assert '.text' in result


def test_backward_compatible_translate():
    """向后兼容 - translate() 不传 init_vtype"""
    from rvv_sbt import translate
    insns = [
        RVInstruction(address=0, opcode='add', operands=['a0', 'a0', 'a1'],
                       op_str='add a0, a0, a1')
    ]
    result = translate(insns)
    assert '.text' in result
    assert 'add' in result
