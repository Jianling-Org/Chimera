#!/usr/bin/env python3
"""
后端单元测试
测试 dispatcher.py, rvv_config.py 和 rvv_arithmetic.py
"""

import sys
import os
import re

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from riscv.extensions.rvv.backends.scalar.backend import ScalarDispatcher
from riscv.extensions.rvv.translation.contracts import (
    InstructionValidationError,
    UnsupportedInstructionError,
)
from riscv.extensions.rvv.translation.emitter import ProgramEmitter
from riscv.extensions.rvv.translation.contracts import LoweringResult
from riscv.extensions.rvv.analysis.config import StateTracker
from riscv.extensions.rvv.runtime.layout import SimulatedStateLayout
from riscv.extensions.rvv.instruction import peek_mask_operand, uses_explicit_v0_mask
from riscv.frontend.model import RVInstruction


def _lower(dispatcher, insn, state, allocator):
    """测试只通过正式的 context/plan/lower 协议调用标量后端。

    与生产链路 ``VTypeDispatchEmitter._dispatch_with_state`` 保持一致：
    plan 和 lower 两个阶段的结构化校验失败都按标量 ``raise`` 策略收敛为
    ``UnsupportedInstructionError``，而不是只在 plan 阶段包装。
    """

    context = dispatcher.make_context(insn, state, allocator)
    try:
        plan = dispatcher.plan(context)
        return dispatcher.lower(context, plan)
    except InstructionValidationError as exc:
        raise UnsupportedInstructionError(insn, detail=exc.detail) from exc


def test_dispatcher_init():
    """dispatcher 只从唯一 registry 暴露能力分类。"""

    dispatcher = ScalarDispatcher()
    arithmetic = dispatcher.registry.by_category("arithmetic")
    config = dispatcher.registry.by_category("config")
    memory = {
        spec.opcode: spec
        for spec in dispatcher.registry
        if spec.category.startswith("memory-")
    }

    # 检查由规格类别派生的算术能力。
    for opcode in (
        'vfmacc.vf', 'vfnmsac.vf', 'vfmacc.vv', 'vfwmacc.vv',
        'vadd.vv', 'vfmv.v.f', 'vfmv.f.s', 'vmv4r.v', 'vmv.v.i',
        'vmv.s.x', 'vfredusum.vs', 'vfmul.vf',
    ):
        assert opcode in arithmetic

    assert 'vsetvli' in config
    assert 'vsetivli' in config

    # 检查循环计数器是实例变量
    assert hasattr(dispatcher, '_loop_counter')
    assert dispatcher._loop_counter == 0

    # 检查 stride 32-bit 内存指令映射
    for opcode in (
        'vlse32.v', 'vsse32.v', 'vlseg2e32.v', 'vsseg2e32.v',
        'vlsseg2e32.v', 'vssseg2e32.v', 'vlseg2e64.v', 'vsseg2e64.v',
        'vlsseg2e64.v', 'vssseg2e64.v',
    ):
        assert opcode in memory



def test_dispatch_vsetvli():
    """测试 vsetvli 指令分发 - 应该生成 CSR 更新代码"""

    dispatcher = ScalarDispatcher()
    state = StateTracker(vlenb=128)
    allocator = SimulatedStateLayout(vlenb=128)

    # 创建 vsetvli 指令
    insn = RVInstruction(
        address=0x34,
        opcode='vsetvli',
        op_str='a5, a0, e64, m8, ta, ma',
        operands=['a5', 'a0', 'e64', 'm8', 'ta', 'ma']
    )

    # 分发指令
    result = _lower(dispatcher, insn, state, allocator)

    output = '\n'.join(result.assembly_lines)

    # 验证生成了 CSR 更新代码
    assert '# vsetvli' in output
    assert 't6' in output  # 使用 t6 作为 CSR 基地址寄存器
    assert 'sd' in output  # 应该有 store 指令写入 CSR

    # 验证注释包含状态信息
    assert 'VLMAX' in output or 'vl' in output.lower()



def test_dispatch_vsetivli():
    """测试 vsetivli 指令分发"""

    dispatcher = ScalarDispatcher()
    state = StateTracker(vlenb=128)
    allocator = SimulatedStateLayout(vlenb=128)

    # 创建 vsetivli 指令
    insn = RVInstruction(
        address=0xda,
        opcode='vsetivli',
        op_str='zero, 0x1, e64, m1, ta, ma',
        operands=['zero', '0x1', 'e64', 'm1', 'ta', 'ma']
    )

    result = _lower(dispatcher, insn, state, allocator)
    output = '\n'.join(result.assembly_lines)

    # 验证生成了代码
    assert 'vsetivli' in output or '# ' in output  # 有注释输出
    assert 't6' in output  # 使用 t6 作为 CSR 基地址寄存器



def test_dispatch_vsetvli_t6_still_initializes_state_base():
    """测试 vsetvli 写回 t6 时仍会先初始化 simulated_cpu_state 基址"""

    dispatcher = ScalarDispatcher()
    state = StateTracker(vlenb=128)
    allocator = SimulatedStateLayout(vlenb=128)

    insn = RVInstruction(
        address=0x40,
        opcode='vsetvli',
        op_str='t6, a0, e64, m1, ta, ma',
        operands=['t6', 'a0', 'e64', 'm1', 'ta', 'ma']
    )

    translated = _lower(dispatcher, insn, state, allocator)
    emitter = ProgramEmitter(vlenb=128)
    wrapped = emitter.vector_block.wrap(insn, translated)
    output = '\n'.join(wrapped)

    assert 'la.tls.ie t6, simulated_cpu_state_ptr' in output
    assert 'add     t6, t6, tp' in output
    assert 'get_simulated_cpu_state_addr@plt' not in output
    assert 'ld      t6,' not in output



def test_initial_exec_state_base_keeps_gpr_inputs_live_without_early_reload():
    """测试 IE TLS 取址不破坏 GPR 输入，因此只需在块尾恢复现场。"""

    insn = RVInstruction(
        address=0x44,
        opcode='vle16.v',
        op_str='vle16.v v4, (a0)',
        operands=['v4', '(a0)'],
    )

    translated = [
        "    li      t0, 0x200",
        "    add     t4, t6, t0",
        "    mv      t3, a0",
    ]
    emitter = ProgramEmitter(vlenb=128)
    result = LoweringResult.lowered(
        translated,
        clobbered_gprs=frozenset({"t0", "t3", "t4"}),
        semantic_inputs=frozenset({"a0"}),
        state_reads=frozenset({"vreg"}),
    )
    wrapped = emitter.vector_block.wrap(insn, result)
    output = '\n'.join(wrapped)

    use_idx = output.index('mv      t3, a0')
    state_base_idx = output.index('la.tls.ie t6, simulated_cpu_state_ptr')

    assert state_base_idx < use_idx
    pre_body = output[:use_idx]
    assert 'ld      a0,' not in pre_body
    assert 'sd      a0,' not in output
    assert 'ld      a0,' not in output
    assert 'ld      t0,' not in pre_body
    assert 'ld      t1,' not in pre_body
    assert 'get_simulated_cpu_state_addr@plt' not in output



def test_initial_exec_state_base_keeps_fpr_inputs_live_without_early_reload():
    """测试 IE TLS 取址不破坏 FPR 输入，因此只需在块尾恢复现场。"""

    insn = RVInstruction(
        address=0x48,
        opcode='vfmacc.vf',
        op_str='vfmacc.vf v8, fa0, v16',
        operands=['v8', 'fa0', 'v16'],
    )

    translated = [
        "    li      t0, 0x200",
        "    add     t1, t6, t0",
        "    fmv.d   ft0, fa0",
    ]
    emitter = ProgramEmitter(vlenb=128)
    result = LoweringResult.lowered(
        translated,
        clobbered_gprs=frozenset({"t0", "t1"}),
        clobbered_fprs=frozenset({"ft0"}),
        semantic_inputs=frozenset({"fa0"}),
        state_reads=frozenset({"vreg"}),
    )
    wrapped = emitter.vector_block.wrap(insn, result)
    output = '\n'.join(wrapped)

    use_idx = output.index('fmv.d   ft0, fa0')
    state_base_idx = output.index('la.tls.ie t6, simulated_cpu_state_ptr')

    assert state_base_idx < use_idx
    assert 'fsd     fa0,' not in output
    assert 'fld     fa0,' not in output
    assert 'get_simulated_cpu_state_addr@plt' not in output



def test_vfmv_f_s_fa0_output_still_skips_restore():
    """测试 vfmv.f.s 写回 fa0 时不会把结果寄存器错误恢复。"""

    insn = RVInstruction(
        address=0x4c,
        opcode='vfmv.f.s',
        op_str='fa0, v1',
        operands=['fa0', 'v1'],
    )

    translated = [
        "    li      t0, 0x200",
        "    add     t0, t6, t0",
        "    fld     fa0, 0(t0)",
    ]
    emitter = ProgramEmitter(vlenb=128)
    result = LoweringResult.lowered(
        translated,
        clobbered_gprs=frozenset({"t0"}),
        clobbered_fprs=frozenset({"fa0"}),
        semantic_outputs=frozenset({"fa0"}),
        state_reads=frozenset({"vreg"}),
    )
    wrapped = emitter.vector_block.wrap(insn, result)
    output = '\n'.join(wrapped)

    assert 'fsd     fa0,' not in output
    assert re.search(r"fld\s+fa0,\s+\d+\(sp\)", output) is None



def test_initial_exec_state_base_avoids_unused_call_clobbered_fpr_spills():
    """测试无调用 IE 取址不会保存正文未使用的 caller-saved FPR。"""

    insn = RVInstruction(
        address=0x50,
        opcode='vle16.v',
        op_str='vle16.v v4, (a0)',
        operands=['v4', '(a0)'],
    )

    translated = [
        "    li      t0, 0x200",
        "    add     t1, t6, t0",
        "    mv      t3, a0",
    ]
    emitter = ProgramEmitter(vlenb=128)
    result = LoweringResult.lowered(
        translated,
        clobbered_gprs=frozenset({"t0", "t1", "t3"}),
        semantic_inputs=frozenset({"a0"}),
        state_reads=frozenset({"vreg"}),
    )
    wrapped = emitter.vector_block.wrap(insn, result)
    output = '\n'.join(wrapped)

    assert 'la.tls.ie t6, simulated_cpu_state_ptr' in output
    assert 'get_simulated_cpu_state_addr@plt' not in output
    assert 'fsd     fa0,' not in output
    assert 'fsd     ft11,' not in output
    assert re.search(r"fld\s+fa0,\s+\d+\(sp\)", output) is None
    assert re.search(r"fld\s+ft11,\s+\d+\(sp\)", output) is None



def test_helper_state_base_mode_preserves_all_call_clobbered_registers():
    """测试兼容 helper 回退仍按普通调用 ABI 保存全部 caller-saved 现场。"""
    insn = RVInstruction(
        address=0x54,
        opcode='vle16.v',
        op_str='vle16.v v4, (a0)',
        operands=['v4', '(a0)'],
    )
    translated = [
        "    li      t0, 0x200",
        "    add     t1, t6, t0",
        "    mv      t3, a0",
    ]

    result = LoweringResult.lowered(
        translated,
        clobbered_gprs=frozenset({"t0", "t1", "t3"}),
        semantic_inputs=frozenset({"a0"}),
        state_reads=frozenset({"vreg"}),
    )
    emitter = ProgramEmitter(vlenb=128, state_base_mode='helper')
    output = '\n'.join(emitter.vector_block.wrap(insn, result))

    assert 'call    get_simulated_cpu_state_addr@plt' in output
    assert 'mv      t6, a0' in output
    assert 'fsd     fa0,' in output
    assert 'fsd     ft11,' in output
    assert re.search(r"fld\s+fa0,\s+\d+\(sp\)", output) is not None
    assert re.search(r"fld\s+ft11,\s+\d+\(sp\)", output) is not None


def test_vsetvli_rs1_zero_rd_not_zero():
    """测试 vsetvli rs1=zero, rd!=zero 场景 (应设置 vl=VLMAX)"""

    dispatcher = ScalarDispatcher()
    state = StateTracker(vlenb=128)
    allocator = SimulatedStateLayout(vlenb=128)

    # vsetvli a6, zero, e64, m4, ta, ma
    # 语义: rs1=zero, rd=a6!=zero -> vl = VLMAX
    insn = RVInstruction(
        address=0x04,
        opcode='vsetvli',
        op_str='a6, zero, e64, m4, ta, ma',
        operands=['a6', 'zero', 'e64', 'm4', 'ta', 'ma']
    )

    result = _lower(dispatcher, insn, state, allocator)
    output = '\n'.join(result.assembly_lines)

    # 验证生成了正确的语义注释
    assert 'rs1=zero, rd!=zero' in output or 'VLMAX' in output
    # 不应该出现 "min" 因为是直接设置 VLMAX
    assert 'vl = VLMAX' in output or 't3 = VLMAX' in output or 'li      t3, 8' in output
    # 应该有返回 vl 到 rd
    assert 'mv      a6, t3' in output or 'a6 = vl' in output



def test_vsetvli_rs1_zero_rd_zero():
    """测试 vsetvli rs1=zero, rd=zero 场景 (应保持 vl 不变)"""

    dispatcher = ScalarDispatcher()
    state = StateTracker(vlenb=128)
    allocator = SimulatedStateLayout(vlenb=128)

    # vsetvli zero, zero, e64, m4, ta, ma
    # 语义: rs1=zero, rd=zero -> 保持 vl 不变
    insn = RVInstruction(
        address=0x08,
        opcode='vsetvli',
        op_str='zero, zero, e64, m4, ta, ma',
        operands=['zero', 'zero', 'e64', 'm4', 'ta', 'ma']
    )

    result = _lower(dispatcher, insn, state, allocator)
    output = '\n'.join(result.assembly_lines)

    # 验证生成了正确的语义注释
    assert 'rs1=zero, rd=zero' in output or '保持 vl 不变' in output
    # 不应该有 sd 指令写入 vl (因为保持不变)
    assert 'sd      t3, 4128(t0)' not in output or '跳过 CSR vl 写入' in output



def test_dispatch_vfmacc_vf():
    """测试 vfmacc.vf 指令分发 - 应该从 CSR 读取 vl"""

    dispatcher = ScalarDispatcher()
    state = StateTracker(vlenb=128)
    allocator = SimulatedStateLayout(vlenb=128)

    # 设置状态: e64, m8
    config_insn = RVInstruction(
        address=0x34,
        opcode='vsetvli',
        op_str='a5, a0, e64, m8, ta, ma',
        operands=['a5', 'a0', 'e64', 'm8', 'ta', 'ma']
    )
    state.update(config_insn)

    # 创建 vfmacc.vf 指令
    insn = RVInstruction(
        address=0x38,
        opcode='vfmacc.vf',
        op_str='v8, fa0, v16',
        operands=['v8', 'fa0', 'v16']
    )

    # 分发指令
    result = _lower(dispatcher, insn, state, allocator)


    output = '\n'.join(result.assembly_lines)

    # 验证从 CSR 加载 vl
    assert 't6' in output  # 使用 t6 作为 CSR 基地址寄存器
    assert 'ld' in output  # 应该有 load 指令
    assert '# 从 CSR 加载 vl' in output or 'vl' in output

    # 验证循环结构
    assert '.L_vfmacc_loop_' in output
    assert 'beqz' in output
    assert 'fmadd.d' in output

    # 零开销: 不需要 prologue/epilogue (t 寄存器是 caller-saved)
    # 这是静态翻译的优化



def test_dispatch_vfmacc_vv():
    """测试 vfmacc.vv 指令分发"""

    dispatcher = ScalarDispatcher()
    state = StateTracker(vlenb=128)
    allocator = SimulatedStateLayout(vlenb=128)

    # 设置状态: e64, m4
    config_insn = RVInstruction(
        address=0x04,
        opcode='vsetvli',
        op_str='a6, zero, e64, m4, ta, ma',
        operands=['a6', 'zero', 'e64', 'm4', 'ta', 'ma']
    )
    state.update(config_insn)

    # 创建 vfmacc.vv 指令
    insn = RVInstruction(
        address=0x08,
        opcode='vfmacc.vv',
        op_str='v4, v28, v16',
        operands=['v4', 'v28', 'v16']
    )

    result = _lower(dispatcher, insn, state, allocator)
    output = '\n'.join(result.assembly_lines)


    # 验证从 CSR 加载 vl
    assert 't6' in output
    assert 'ld' in output



def test_dispatch_vfwmacc_vv():
    """测试 vfwmacc.vv 指令分发 - 应该执行 e32 -> e64 widening 乘加"""

    dispatcher = ScalarDispatcher()
    state = StateTracker(vlenb=128)
    allocator = SimulatedStateLayout(vlenb=128)

    # 这里模拟 sdot_k 中的关键配置：源为 e32，目的 widening 到 e64。
    config_insn = RVInstruction(
        address=0x1c,
        opcode='vsetvli',
        op_str='a5, a0, e32, m4, tu, ma',
        operands=['a5', 'a0', 'e32', 'm4', 'tu', 'ma']
    )
    state.update(config_insn)

    insn = RVInstruction(
        address=0x20,
        opcode='vfwmacc.vv',
        op_str='v16, v8, v4',
        operands=['v16', 'v8', 'v4']
    )

    result = _lower(dispatcher, insn, state, allocator)
    output = '\n'.join(result.assembly_lines)


    assert 't6' in output
    assert '.L_vfwmacc_vv_loop_' in output
    assert 'flw' in output, "源元素应按 float32 读取"
    assert 'fcvt.d.s' in output, "应将 float32 源元素提升为 float64"
    assert 'fld' in output, "widened 目标元素应按 float64 读取"
    assert 'fmadd.d' in output, "widening 乘加应使用双精度 FMA"
    assert 'fsd' in output, "widened 目标元素应按 float64 写回"



def test_dispatch_vfwmacc_vv_unsupported_width():
    """测试 vfwmacc.vv 在未覆盖宽度下应走统一的 unsupported error 路径"""

    dispatcher = ScalarDispatcher()
    state = StateTracker(vlenb=128)
    allocator = SimulatedStateLayout(vlenb=128)

    # 这里故意构造一个当前未实现的 widening 形式：e16 -> e32。
    config_insn = RVInstruction(
        address=0x28,
        opcode='vsetvli',
        op_str='a5, a0, e16, m4, ta, ma',
        operands=['a5', 'a0', 'e16', 'm4', 'ta', 'ma']
    )
    state.update(config_insn)

    insn = RVInstruction(
        address=0x2c,
        opcode='vfwmacc.vv',
        op_str='v16, v8, v4',
        operands=['v16', 'v8', 'v4']
    )

    try:
        _lower(dispatcher, insn, state, allocator)
        raise AssertionError("Expected UnsupportedInstructionError")
    except UnsupportedInstructionError as exc:
        message = str(exc)
        assert 'vfwmacc.vv' in message
        assert 'SEW=32' in message or 'SEW=16' in message



def test_dispatch_vfmul_vf():
    """测试 vfmul.vf 指令分发 - 应该按 CSR 中的 vl 逐元素做浮点乘法"""

    dispatcher = ScalarDispatcher()
    state = StateTracker(vlenb=128)
    allocator = SimulatedStateLayout(vlenb=128)

    config_insn = RVInstruction(
        address=0x10,
        opcode='vsetvli',
        op_str='a5, a0, e32, m8, ta, ma',
        operands=['a5', 'a0', 'e32', 'm8', 'ta', 'ma']
    )
    state.update(config_insn)

    insn = RVInstruction(
        address=0x14,
        opcode='vfmul.vf',
        op_str='v8, v16, fa0',
        operands=['v8', 'v16', 'fa0']
    )

    result = _lower(dispatcher, insn, state, allocator)
    output = '\n'.join(result.assembly_lines)


    assert 't6' in output
    assert 'ld' in output
    assert '.L_vfmul_vf_loop_' in output
    assert 'flw' in output
    assert 'fmul.s' in output
    assert 'fsw' in output



def test_mask_operand_helper():
    """测试 mask helper 只接受显式的 `v0.t` 形式"""

    masked_insn = RVInstruction(
        address=0x18,
        opcode='vadd.vv',
        op_str='v8, v4, v16, v0.t',
        operands=['v8', 'v4', 'v16', 'v0.t']
    )
    assert peek_mask_operand(masked_insn) == 'v0.t'
    assert uses_explicit_v0_mask(masked_insn) is True

    unmasked_insn = RVInstruction(
        address=0x1c,
        opcode='vadd.vv',
        op_str='v8, v4, v0',
        operands=['v8', 'v4', 'v0']
    )
    assert peek_mask_operand(unmasked_insn) is None
    assert uses_explicit_v0_mask(unmasked_insn) is False

    invalid_mask_insn = RVInstruction(
        address=0x20,
        opcode='vadd.vv',
        op_str='v8, v4, v0, v8.t',
        operands=['v8', 'v4', 'v0', 'v8.t']
    )
    try:
        uses_explicit_v0_mask(invalid_mask_insn)
        raise AssertionError("Expected ValueError for non-v0 mask operand")
    except ValueError as exc:
        assert 'v8.t' in str(exc)



def test_dispatch_vadd_vv_masked_form():
    """测试 `vadd.vv ..., v0.t` 会生成显式的 v0 mask guard"""

    dispatcher = ScalarDispatcher()
    state = StateTracker(vlenb=128)
    allocator = SimulatedStateLayout(vlenb=128)

    config_insn = RVInstruction(
        address=0x24,
        opcode='vsetvli',
        op_str='a5, a0, e32, m1, ta, mu',
        operands=['a5', 'a0', 'e32', 'm1', 'ta', 'mu']
    )
    state.update(config_insn)

    insn = RVInstruction(
        address=0x28,
        opcode='vadd.vv',
        op_str='v8, v4, v16, v0.t',
        operands=['v8', 'v4', 'v16', 'v0.t']
    )

    result = _lower(dispatcher, insn, state, allocator)
    output = '\n'.join(result.assembly_lines)

    assert '# masked form:' in output
    assert '.L_vadd_vv_mask_skip_loop_' in output
    assert 'srli' in output
    assert 'andi' in output
    assert 'beqz' in output



def test_dispatch_masked_form_rejects_non_v0_mask():
    """测试非 `v0.t` 的 masked form 会被显式拒绝"""

    dispatcher = ScalarDispatcher()
    state = StateTracker(vlenb=128)
    allocator = SimulatedStateLayout(vlenb=128)

    config_insn = RVInstruction(
        address=0x2c,
        opcode='vsetvli',
        op_str='a5, a0, e32, m1, ta, mu',
        operands=['a5', 'a0', 'e32', 'm1', 'ta', 'mu']
    )
    state.update(config_insn)

    insn = RVInstruction(
        address=0x30,
        opcode='vadd.vv',
        op_str='v8, v4, v0, v8.t',
        operands=['v8', 'v4', 'v0', 'v8.t']
    )

    try:
        _lower(dispatcher, insn, state, allocator)
        raise AssertionError("Expected UnsupportedInstructionError")
    except UnsupportedInstructionError as exc:
        assert 'v8.t' in str(exc)



def test_dispatch_masked_form_rejects_unsupported_opcode():
    """测试尚未纳入 masked 白名单的 opcode 会在 dispatcher 层 fail-fast"""

    dispatcher = ScalarDispatcher()
    state = StateTracker(vlenb=128)
    allocator = SimulatedStateLayout(vlenb=128)

    config_insn = RVInstruction(
        address=0x34,
        opcode='vsetvli',
        op_str='a5, a0, e32, m1, ta, mu',
        operands=['a5', 'a0', 'e32', 'm1', 'ta', 'mu']
    )
    state.update(config_insn)

    insn = RVInstruction(
        address=0x38,
        opcode='vfmv.v.f',
        op_str='v8, fa0, v0.t',
        operands=['v8', 'fa0', 'v0.t']
    )

    try:
        _lower(dispatcher, insn, state, allocator)
        raise AssertionError("Expected UnsupportedInstructionError")
    except UnsupportedInstructionError as exc:
        message = str(exc)
        assert 'vfmv.v.f' in message
        assert 'masked form' in message



def test_dispatch_vfnmsac_vf():
    """测试 vfnmsac.vf 指令分发 - 应该生成负乘积再累加的 fused 路径"""

    dispatcher = ScalarDispatcher()
    state = StateTracker(vlenb=128)
    allocator = SimulatedStateLayout(vlenb=128)

    config_insn = RVInstruction(
        address=0x14,
        opcode='vsetvli',
        op_str='a5, a0, e32, m4, ta, ma',
        operands=['a5', 'a0', 'e32', 'm4', 'ta', 'ma']
    )
    state.update(config_insn)

    insn = RVInstruction(
        address=0x18,
        opcode='vfnmsac.vf',
        op_str='v4, fa1, v20',
        operands=['v4', 'fa1', 'v20']
    )

    result = _lower(dispatcher, insn, state, allocator)
    output = '\n'.join(result.assembly_lines)

    assert '.L_vfnmsac_vf_loop_' in output
    assert 'fnmsub.s' in output
    assert '-(fa1 * v20[i]) + v4[i]' in output



def test_dispatch_vmv_v_i():
    """测试 vmv.v.i 指令分发 - 应该用有符号 5-bit 立即数填满整个向量"""

    dispatcher = ScalarDispatcher()
    state = StateTracker(vlenb=128)
    allocator = SimulatedStateLayout(vlenb=128)

    config_insn = RVInstruction(
        address=0x18,
        opcode='vsetvli',
        op_str='a5, a0, e32, m8, ta, ma',
        operands=['a5', 'a0', 'e32', 'm8', 'ta', 'ma']
    )
    state.update(config_insn)

    insn = RVInstruction(
        address=0x1c,
        opcode='vmv.v.i',
        op_str='v8, 0x0',
        operands=['v8', '0x0']
    )

    result = _lower(dispatcher, insn, state, allocator)
    output = '\n'.join(result.assembly_lines)

    assert 't6' in output
    assert '.L_vmv_v_i_loop_' in output
    assert 'li      t4, 0' in output
    assert 'sw' in output



def test_dispatch_vfmv_f_s():
    """测试 vfmv.f.s 指令分发 - 应该直接读取向量寄存器第 0 个元素"""

    dispatcher = ScalarDispatcher()
    state = StateTracker(vlenb=128)
    allocator = SimulatedStateLayout(vlenb=128)

    config_insn = RVInstruction(
        address=0x20,
        opcode='vsetvli',
        op_str='a6, zero, e64, m1, ta, ma',
        operands=['a6', 'zero', 'e64', 'm1', 'ta', 'ma']
    )
    state.update(config_insn)

    insn = RVInstruction(
        address=0x24,
        opcode='vfmv.f.s',
        op_str='fa0, v1',
        operands=['fa0', 'v1']
    )

    result = _lower(dispatcher, insn, state, allocator)
    output = '\n'.join(result.assembly_lines)

    assert 't6' in output
    assert 'v1[0]' in output
    assert 'fld' in output
    assert 'fa0' in output
    assert all(line.startswith('.L_vstart_zero_loop_')
               for line in output.splitlines() if line.startswith('.L_'))
    assert 'unsupported nonzero source vstart' in output
    assert '0x1020' not in output, "vfmv.f.s 不应该依赖 vl"



def test_dispatch_vmv4r_v():
    """测试 vmv4r.v 指令分发 - 应该执行 whole-register block copy"""

    dispatcher = ScalarDispatcher()
    state = StateTracker(vlenb=128)
    allocator = SimulatedStateLayout(vlenb=128)

    insn = RVInstruction(
        address=0x24,
        opcode='vmv4r.v',
        op_str='v4, v8',
        operands=['v4', 'v8']
    )

    result = _lower(dispatcher, insn, state, allocator)
    output = '\n'.join(result.assembly_lines)

    assert '.L_vmv4r_v_loop_' in output
    assert 'whole-register move' in output
    assert 'li      t0, 512' in output
    assert 'ld      t2, 0(t1)' in output
    assert 'sd      t2, 0(t3)' in output



def test_dispatch_unknown_instruction():
    """测试未知指令分发应明确报错"""

    dispatcher = ScalarDispatcher()
    state = StateTracker(vlenb=128)
    allocator = SimulatedStateLayout(vlenb=128)

    # 创建一个未知指令
    insn = RVInstruction(
        address=0x100,
        opcode='vunknown.xyz',
        op_str='v0, v1, v2',
        operands=['v0', 'v1', 'v2']
    )

    try:
        _lower(dispatcher, insn, state, allocator)
        raise AssertionError("Expected UnsupportedInstructionError")
    except UnsupportedInstructionError as exc:
        message = str(exc)
        assert 'Unsupported instruction' in message
        assert 'vunknown.xyz' in message
        assert '0x0100' in message



def test_dispatch_vlse32_vsse32():
    """测试 32-bit stride 加载/存储指令分发"""

    dispatcher = ScalarDispatcher()
    state = StateTracker(vlenb=128)
    allocator = SimulatedStateLayout(vlenb=128)

    config_insn = RVInstruction(
        address=0x00,
        opcode='vsetvli',
        op_str='a0, a1, e32, m8, ta, ma',
        operands=['a0', 'a1', 'e32', 'm8', 'ta', 'ma']
    )
    state.update(config_insn)

    vlse_insn = RVInstruction(
        address=0x04,
        opcode='vlse32.v',
        op_str='v8, (a5), a6',
        operands=['v8', '(a5)', 'a6']
    )
    vlse_output = '\n'.join(
        _lower(dispatcher, vlse_insn, state, allocator).assembly_lines
    )
    assert 'mem[a5 + a6 * i]' in vlse_output
    assert 'lw' in vlse_output
    assert 'sw' in vlse_output
    assert '.L_vlse32_v_loop_' in vlse_output

    vsse_insn = RVInstruction(
        address=0x08,
        opcode='vsse32.v',
        op_str='v8, (a5), a6',
        operands=['v8', '(a5)', 'a6']
    )
    vsse_output = '\n'.join(
        _lower(dispatcher, vsse_insn, state, allocator).assembly_lines
    )
    assert 'mem[a5 + a6 * i] = v8' in vsse_output
    assert 'lw' in vsse_output
    assert 'sw' in vsse_output
    assert '.L_vsse32_v_loop_' in vsse_output



def test_dispatch_vlseg2e32_vsseg2e32():
    """测试 32-bit segmented unit-stride load/store 指令分发"""

    dispatcher = ScalarDispatcher()
    state = StateTracker(vlenb=128)
    allocator = SimulatedStateLayout(vlenb=128)

    config_insn = RVInstruction(
        address=0x00,
        opcode='vsetvli',
        op_str='a0, a1, e32, m4, ta, ma',
        operands=['a0', 'a1', 'e32', 'm4', 'ta', 'ma']
    )
    state.update(config_insn)

    vlseg_insn = RVInstruction(
        address=0x04,
        opcode='vlseg2e32.v',
        op_str='v8, (a5)',
        operands=['v8', '(a5)']
    )
    vlseg_output = '\n'.join(
        _lower(dispatcher, vlseg_insn, state, allocator).assembly_lines
    )
    assert '.L_vlseg2e32_v_loop_' in vlseg_output
    assert 'segmented load' in vlseg_output
    assert '1536' in vlseg_output, "第二个 segment 应落到 v12 组首"
    assert 'lw' in vlseg_output
    assert 'sw' in vlseg_output

    vsseg_insn = RVInstruction(
        address=0x08,
        opcode='vsseg2e32.v',
        op_str='v8, (a5)',
        operands=['v8', '(a5)']
    )
    vsseg_output = '\n'.join(
        _lower(dispatcher, vsseg_insn, state, allocator).assembly_lines
    )
    assert '.L_vsseg2e32_v_loop_' in vsseg_output
    assert 'segmented store' in vsseg_output
    assert re.search(r"sw\s+t[0-5],\s+0\(t3\)", vsseg_output), "segment 0 应写回 tuple 的第 0 个槽位"
    assert re.search(r"sw\s+t[0-5],\s+4\(t3\)", vsseg_output), "segment 1 应写回 tuple 的第 1 个槽位"



def test_dispatch_vlsseg2e64_vssseg2e64():
    """测试 64-bit segmented stride load/store 指令分发"""

    dispatcher = ScalarDispatcher()
    state = StateTracker(vlenb=128)
    allocator = SimulatedStateLayout(vlenb=128)

    config_insn = RVInstruction(
        address=0x10,
        opcode='vsetvli',
        op_str='a0, a1, e64, m4, ta, ma',
        operands=['a0', 'a1', 'e64', 'm4', 'ta', 'ma']
    )
    state.update(config_insn)

    vlsseg_insn = RVInstruction(
        address=0x14,
        opcode='vlsseg2e64.v',
        op_str='v16, (a3), a4',
        operands=['v16', '(a3)', 'a4']
    )
    vlsseg_output = '\n'.join(
        _lower(dispatcher, vlsseg_insn, state, allocator).assembly_lines
    )
    assert '.L_vlsseg2e64_v_loop_' in vlsseg_output
    assert 'i * a4' in vlsseg_output
    assert 'ld' in vlsseg_output
    assert 'sd' in vlsseg_output

    vssseg_insn = RVInstruction(
        address=0x18,
        opcode='vssseg2e64.v',
        op_str='v16, (a3), a4',
        operands=['v16', '(a3)', 'a4']
    )
    vssseg_output = '\n'.join(
        _lower(dispatcher, vssseg_insn, state, allocator).assembly_lines
    )
    assert '.L_vssseg2e64_v_loop_' in vssseg_output
    assert 'i * a4' in vssseg_output
    assert re.search(r"sd\s+t[0-5],\s+0\(t3\)", vssseg_output), "segment 0 应写回 tuple 的第 0 个槽位"
    assert re.search(r"sd\s+t[0-5],\s+8\(t3\)", vssseg_output), "segment 1 应写回 tuple 的第 1 个槽位"



def test_element_size_handling():
    """测试不同元素大小的处理"""

    dispatcher = ScalarDispatcher()
    allocator = SimulatedStateLayout(vlenb=128)

    # 测试 e32 (32-bit)
    state_32 = StateTracker(vlenb=128)
    config_32 = RVInstruction(
        address=0x00,
        opcode='vsetvli',
        op_str='a0, a1, e32, m4, ta, ma',
        operands=['a0', 'a1', 'e32', 'm4', 'ta', 'ma']
    )
    state_32.update(config_32)

    insn = RVInstruction(
        address=0x04,
        opcode='vfmacc.vf',
        op_str='v8, fa0, v16',
        operands=['v8', 'fa0', 'v16']
    )

    result_32 = _lower(dispatcher, insn, state_32, allocator)
    output_32 = '\n'.join(result_32.assembly_lines)

    # 32-bit 元素: slli t2, t2, 2
    assert 'slli    t2, t2, 2' in output_32
    # 32-bit 浮点指令
    assert 'flw' in output_32
    assert 'fsw' in output_32
    assert 'fmadd.s' in output_32

    # 测试 e64 (64-bit)
    state_64 = StateTracker(vlenb=128)
    config_64 = RVInstruction(
        address=0x00,
        opcode='vsetvli',
        op_str='a0, a1, e64, m4, ta, ma',
        operands=['a0', 'a1', 'e64', 'm4', 'ta', 'ma']
    )
    state_64.update(config_64)

    result_64 = _lower(dispatcher, insn, state_64, allocator)
    output_64 = '\n'.join(result_64.assembly_lines)

    # 64-bit 元素: slli t2, t2, 3
    assert 'slli    t2, t2, 3' in output_64
    # 64-bit 浮点指令
    assert 'fld' in output_64
    assert 'fsd' in output_64
    assert 'fmadd.d' in output_64



def test_loop_counter_instance():
    """测试循环计数器是实例变量"""

    dispatcher1 = ScalarDispatcher()
    dispatcher2 = ScalarDispatcher()

    label1 = dispatcher1.get_loop_label("test")
    label2 = dispatcher2.get_loop_label("test")

    # 两个分发器应该生成相同的标签 (各自独立计数)
    assert label1 == ".L_test_loop_0"
    assert label2 == ".L_test_loop_0"

    label1_2 = dispatcher1.get_loop_label("test")
    assert label1_2 == ".L_test_loop_1"

    # dispatcher2 的计数器不受影响
    label2_2 = dispatcher2.get_loop_label("test")
    assert label2_2 == ".L_test_loop_1"
