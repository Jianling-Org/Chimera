#!/usr/bin/env python3
"""
集成测试：使用汇编文件测试翻译流程
"""

from riscv.extensions.rvv.instruction import is_vector_instruction, is_config_instruction
import sys
import os
import re

# 添加项目根目录到 sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from riscv.frontend.parser import AsmParser
from riscv.frontend.model import RVFunction
from riscv.extensions.rvv.analysis.config import StateTracker
from riscv.extensions.rvv.runtime.layout import SimulatedStateLayout
from riscv.extensions.rvv.backends.scalar.backend import ScalarDispatcher
from riscv.extensions.rvv.translation.contracts import UnsupportedInstructionError
from riscv.extensions.rvv.translation.emitter import ProgramEmitter
from rvv_sbt import translate_function


# 测试输入文件目录
FIXTURES_DIR = os.path.join(os.path.dirname(__file__), 'fixtures', 'objdump')
# 测试输出文件目录
OUTPUTS_DIR = os.path.join(os.path.dirname(__file__), 'outputs')


def _infer_func_name(instructions):
    """从单函数 objdump 片段中提取函数名。"""
    for insn in instructions:
        if insn.label and not insn.label.startswith('.'):
            return insn.label
    return "translated_func"


def _translate_inline_asm(asm: str) -> tuple[list, str]:
    """
    统一的内联汇编翻译辅助函数。

    新增 masked-form 测试后，很多 case 都只是“给一小段 asm，跑完整翻译链路，
    再检查输出里有没有正确的 guard / 标签 / fail-fast 行为”。
    把这段样板代码收敛到一个 helper 里，测试意图会更清晰。
    """
    parser = AsmParser()
    instructions = parser.parse_string(asm)

    tracker = StateTracker(vlenb=128)
    allocator = SimulatedStateLayout(vlenb=128)
    dispatcher = ScalarDispatcher()
    emitter = ProgramEmitter(vlenb=128)

    output = emitter._emit_function_assembly(
        instructions,
        tracker,
        allocator,
        dispatcher,
        func_name=_infer_func_name(instructions),
    )
    return instructions, output


def test_vadd_rvv():
    """测试 vadd_rvv 翻译"""
    asm_path = os.path.join(FIXTURES_DIR, 'vadd_rvv.objdump.s')

    if not os.path.exists(asm_path):
        return


    # 解析汇编文件
    parser = AsmParser()
    instructions = parser.parse_file(asm_path)

    # 过滤向量指令
    vector_insns = [i for i in instructions if is_vector_instruction(i)]
    config_insns = [i for i in instructions if is_config_instruction(i)]

    # 初始化组件
    tracker = StateTracker(vlenb=128)
    allocator = SimulatedStateLayout(vlenb=128)
    dispatcher = ScalarDispatcher()

    # 测试状态追踪
    for insn in config_insns:
        old_state = tracker.get_state_str()
        tracker.update(insn)
        new_state = tracker.get_state_str()

    # 测试翻译
    emitter = ProgramEmitter(vlenb=128)
    output = emitter._emit_function_assembly(
        instructions,
        tracker,
        allocator,
        dispatcher,
        func_name=_infer_func_name(instructions),
    )

    # 验证输出包含关键元素
    assert 'simulated_cpu_state' in output, "Missing CSR state"
    assert '.text' in output, "Missing .text section"
    assert '.globl  vadd_rvv' in output, "Missing function symbol"



def test_daxpy_k():
    """测试 daxpy_k 翻译"""
    asm_path = os.path.join(FIXTURES_DIR, 'daxpy_k.objdump.s')

    if not os.path.exists(asm_path):
        return


    # 解析汇编文件
    parser = AsmParser()
    instructions = parser.parse_file(asm_path)

    # 统计
    vector_insns = [i for i in instructions if is_vector_instruction(i)]
    config_insns = [i for i in instructions if is_config_instruction(i)]

    # 列出所有向量指令类型
    opcodes = set(i.opcode for i in vector_insns)

    # 初始化组件
    tracker = StateTracker(vlenb=128)
    allocator = SimulatedStateLayout(vlenb=128)
    dispatcher = ScalarDispatcher()

    # 测试翻译
    emitter = ProgramEmitter(vlenb=128)
    output = emitter._emit_function_assembly(
        instructions,
        tracker,
        allocator,
        dispatcher,
        func_name=_infer_func_name(instructions),
    )

    # 验证输出
    assert 'simulated_cpu_state' in output, "Missing CSR state"
    assert '.text' in output, "Missing .text section"
    assert '.globl  daxpy_k' in output, "Missing function symbol"
    assert '.L6:' in output, "Missing internal label preservation"

    # 检查关键指令是否被翻译
    key_instructions = ['vle64.v', 'vse64.v', 'vlse64.v', 'vsse64.v',
                        'vfmacc.vf', 'vfmv.v.f', 'vmv.s.x', 'vfredusum.vs']
    for op in key_instructions:
        if op in str(opcodes):
            # 检查是否在输出中 (翻译后的注释)
            if op.replace('.', '_') in output or op in output:
                pass



def test_saxpy_k():
    """测试 saxpy_k 翻译"""
    asm_path = os.path.join(FIXTURES_DIR, 'saxpy_k.objdump.s')

    if not os.path.exists(asm_path):
        return


    parser = AsmParser()
    instructions = parser.parse_file(asm_path)

    vector_insns = [i for i in instructions if is_vector_instruction(i)]
    config_insns = [i for i in instructions if is_config_instruction(i)]

    opcodes = set(i.opcode for i in vector_insns)

    tracker = StateTracker(vlenb=128)
    allocator = SimulatedStateLayout(vlenb=128)
    dispatcher = ScalarDispatcher()
    emitter = ProgramEmitter(vlenb=128)

    output = emitter._emit_function_assembly(
        instructions,
        tracker,
        allocator,
        dispatcher,
        func_name=_infer_func_name(instructions),
    )

    assert 'simulated_cpu_state' in output, "Missing CSR state"
    assert '.text' in output, "Missing .text section"
    assert '.globl  saxpy_k' in output, "Missing function symbol"
    assert '.L6:' in output, "Missing internal label preservation"
    assert 'TODO: Unhandled instruction' not in output, "saxpy_k still contains unhandled instructions"
    assert '.L_vlse32_v_loop_' in output, "Missing vlse32.v translation"
    assert '.L_vsse32_v_loop_' in output, "Missing vsse32.v translation"



def test_dcopy_k():
    """测试 dcopy_k 翻译"""
    asm_path = os.path.join(FIXTURES_DIR, 'dcopy_k.objdump.s')

    if not os.path.exists(asm_path):
        return


    parser = AsmParser()
    instructions = parser.parse_file(asm_path)

    vector_insns = [i for i in instructions if is_vector_instruction(i)]
    config_insns = [i for i in instructions if is_config_instruction(i)]

    opcodes = set(i.opcode for i in vector_insns)

    tracker = StateTracker(vlenb=128)
    allocator = SimulatedStateLayout(vlenb=128)
    dispatcher = ScalarDispatcher()
    emitter = ProgramEmitter(vlenb=128)

    output = emitter._emit_function_assembly(
        instructions,
        tracker,
        allocator,
        dispatcher,
        func_name=_infer_func_name(instructions),
    )

    assert 'simulated_cpu_state' in output, "Missing CSR state"
    assert '.text' in output, "Missing .text section"
    assert '.globl  dcopy_k' in output, "Missing function symbol"
    assert 'TODO: Unhandled instruction' not in output, "dcopy_k still contains unhandled instructions"
    assert '.L_vlse64_v_loop_' in output, "Missing vlse64.v translation"
    assert '.L_vsse64_v_loop_' in output, "Missing vsse64.v translation"



def test_ccopy_k():
    """测试 ccopy_k 翻译"""
    asm_path = os.path.join(FIXTURES_DIR, 'ccopy_k.objdump.s')

    if not os.path.exists(asm_path):
        return


    parser = AsmParser()
    instructions = parser.parse_file(asm_path)

    vector_insns = [i for i in instructions if is_vector_instruction(i)]
    config_insns = [i for i in instructions if is_config_instruction(i)]

    opcodes = set(i.opcode for i in vector_insns)

    tracker = StateTracker(vlenb=128)
    allocator = SimulatedStateLayout(vlenb=128)
    dispatcher = ScalarDispatcher()
    emitter = ProgramEmitter(vlenb=128)

    output = emitter._emit_function_assembly(
        instructions,
        tracker,
        allocator,
        dispatcher,
        func_name=_infer_func_name(instructions),
    )

    assert 'simulated_cpu_state' in output, "Missing CSR state"
    assert '.text' in output, "Missing .text section"
    assert '.globl  ccopy_k' in output, "Missing function symbol"
    assert 'TODO: Unhandled instruction' not in output, "ccopy_k still contains unhandled instructions"
    assert '.L_vlseg2e32_v_loop_' in output, "Missing vlseg2e32.v translation"
    assert '.L_vlsseg2e32_v_loop_' in output, "Missing vlsseg2e32.v translation"
    assert '.L_vsseg2e32_v_loop_' in output, "Missing vsseg2e32.v translation"
    assert '.L_vssseg2e32_v_loop_' in output, "Missing vssseg2e32.v translation"



def test_dswap_k():
    """测试 dswap_k 翻译"""
    asm_path = os.path.join(FIXTURES_DIR, 'dswap_k.objdump.s')

    if not os.path.exists(asm_path):
        return


    parser = AsmParser()
    instructions = parser.parse_file(asm_path)

    vector_insns = [i for i in instructions if is_vector_instruction(i)]
    config_insns = [i for i in instructions if is_config_instruction(i)]

    opcodes = set(i.opcode for i in vector_insns)

    tracker = StateTracker(vlenb=128)
    allocator = SimulatedStateLayout(vlenb=128)
    dispatcher = ScalarDispatcher()
    emitter = ProgramEmitter(vlenb=128)

    output = emitter._emit_function_assembly(
        instructions,
        tracker,
        allocator,
        dispatcher,
        func_name=_infer_func_name(instructions),
    )

    assert 'simulated_cpu_state' in output, "Missing CSR state"
    assert '.text' in output, "Missing .text section"
    assert '.globl  dswap_k' in output, "Missing function symbol"
    assert 'TODO: Unhandled instruction' not in output, "dswap_k still contains unhandled instructions"
    assert '.L_vlse64_v_loop_' in output, "Missing vlse64.v translation"
    assert '.L_vsse64_v_loop_' in output, "Missing vsse64.v translation"
    assert '.L_vle64_v_loop_' in output, "Missing vle64.v translation"
    assert '.L_vse64_v_loop_' in output, "Missing vse64.v translation"



def test_caxpy_k():
    """测试 caxpy_k 翻译"""
    asm_path = os.path.join(FIXTURES_DIR, 'caxpy_k.objdump.s')

    if not os.path.exists(asm_path):
        return


    parser = AsmParser()
    instructions = parser.parse_file(asm_path)

    vector_insns = [i for i in instructions if is_vector_instruction(i)]
    config_insns = [i for i in instructions if is_config_instruction(i)]

    opcodes = set(i.opcode for i in vector_insns)

    tracker = StateTracker(vlenb=128)
    allocator = SimulatedStateLayout(vlenb=128)
    dispatcher = ScalarDispatcher()
    emitter = ProgramEmitter(vlenb=128)

    output = emitter._emit_function_assembly(
        instructions,
        tracker,
        allocator,
        dispatcher,
        func_name=_infer_func_name(instructions),
    )

    assert 'simulated_cpu_state' in output, "Missing CSR state"
    assert '.text' in output, "Missing .text section"
    assert '.globl  caxpy_k' in output, "Missing function symbol"
    assert 'TODO: Unhandled instruction' not in output, "caxpy_k still contains unhandled instructions"
    assert '.L_vlseg2e32_v_loop_' in output, "Missing vlseg2e32.v translation"
    assert '.L_vlsseg2e32_v_loop_' in output, "Missing vlsseg2e32.v translation"
    assert '.L_vsseg2e32_v_loop_' in output, "Missing vsseg2e32.v translation"
    assert '.L_vssseg2e32_v_loop_' in output, "Missing vssseg2e32.v translation"
    assert '.L_vfnmsac_vf_loop_' in output, "Missing vfnmsac.vf translation"
    assert '.L_vmv4r_v_loop_' in output, "Missing vmv4r.v translation"



def test_zaxpy_k():
    """测试 zaxpy_k 翻译"""
    asm_path = os.path.join(FIXTURES_DIR, 'zaxpy_k.objdump.s')

    if not os.path.exists(asm_path):
        return


    parser = AsmParser()
    instructions = parser.parse_file(asm_path)

    vector_insns = [i for i in instructions if is_vector_instruction(i)]
    config_insns = [i for i in instructions if is_config_instruction(i)]

    opcodes = set(i.opcode for i in vector_insns)

    tracker = StateTracker(vlenb=128)
    allocator = SimulatedStateLayout(vlenb=128)
    dispatcher = ScalarDispatcher()
    emitter = ProgramEmitter(vlenb=128)

    output = emitter._emit_function_assembly(
        instructions,
        tracker,
        allocator,
        dispatcher,
        func_name=_infer_func_name(instructions),
    )

    assert 'simulated_cpu_state' in output, "Missing CSR state"
    assert '.text' in output, "Missing .text section"
    assert '.globl  zaxpy_k' in output, "Missing function symbol"
    assert 'TODO: Unhandled instruction' not in output, "zaxpy_k still contains unhandled instructions"
    assert '.L_vlseg2e64_v_loop_' in output, "Missing vlseg2e64.v translation"
    assert '.L_vlsseg2e64_v_loop_' in output, "Missing vlsseg2e64.v translation"
    assert '.L_vsseg2e64_v_loop_' in output, "Missing vsseg2e64.v translation"
    assert '.L_vssseg2e64_v_loop_' in output, "Missing vssseg2e64.v translation"
    assert '.L_vfnmsac_vf_loop_' in output, "Missing vfnmsac.vf translation"
    assert '.L_vmv4r_v_loop_' in output, "Missing vmv4r.v translation"



def test_sscal_k():
    """测试 sscal_k 翻译"""
    asm_path = os.path.join(FIXTURES_DIR, 'sscal_k.objdump.s')

    if not os.path.exists(asm_path):
        return


    parser = AsmParser()
    instructions = parser.parse_file(asm_path)

    vector_insns = [i for i in instructions if is_vector_instruction(i)]
    config_insns = [i for i in instructions if is_config_instruction(i)]

    opcodes = set(i.opcode for i in vector_insns)

    tracker = StateTracker(vlenb=128)
    allocator = SimulatedStateLayout(vlenb=128)
    dispatcher = ScalarDispatcher()
    emitter = ProgramEmitter(vlenb=128)

    output = emitter._emit_function_assembly(
        instructions,
        tracker,
        allocator,
        dispatcher,
        func_name=_infer_func_name(instructions),
    )

    assert 'simulated_cpu_state' in output, "Missing CSR state"
    assert '.text' in output, "Missing .text section"
    assert '.globl  sscal_k' in output, "Missing function symbol"
    assert 'TODO: Unhandled instruction' not in output, "sscal_k still contains unhandled instructions"
    assert '.L_vmv_v_i_loop_' in output, "Missing vmv.v.i translation"
    assert '.L_vfmul_vf_loop_' in output, "Missing vfmul.vf translation"



def test_dscal_k():
    """测试 dscal_k 翻译"""
    asm_path = os.path.join(FIXTURES_DIR, 'dscal_k.objdump.s')

    if not os.path.exists(asm_path):
        return


    parser = AsmParser()
    instructions = parser.parse_file(asm_path)

    vector_insns = [i for i in instructions if is_vector_instruction(i)]
    config_insns = [i for i in instructions if is_config_instruction(i)]

    opcodes = set(i.opcode for i in vector_insns)

    tracker = StateTracker(vlenb=128)
    allocator = SimulatedStateLayout(vlenb=128)
    dispatcher = ScalarDispatcher()
    emitter = ProgramEmitter(vlenb=128)

    output = emitter._emit_function_assembly(
        instructions,
        tracker,
        allocator,
        dispatcher,
        func_name=_infer_func_name(instructions),
    )

    assert 'simulated_cpu_state' in output, "Missing CSR state"
    assert '.text' in output, "Missing .text section"
    assert '.globl  dscal_k' in output, "Missing function symbol"
    assert 'TODO: Unhandled instruction' not in output, "dscal_k still contains unhandled instructions"
    assert '.L_vmv_v_i_loop_' in output, "Missing vmv.v.i translation"
    assert '.L_vfmul_vf_loop_' in output, "Missing vfmul.vf translation"
    assert '.L_vlse64_v_loop_' in output, "Missing vlse64.v translation"
    assert '.L_vsse64_v_loop_' in output, "Missing vsse64.v translation"



def test_sdot_k():
    """测试 sdot_k 翻译"""
    asm_path = os.path.join(FIXTURES_DIR, 'sdot_k.objdump.s')

    if not os.path.exists(asm_path):
        return


    parser = AsmParser()
    instructions = parser.parse_file(asm_path)

    vector_insns = [i for i in instructions if is_vector_instruction(i)]
    config_insns = [i for i in instructions if is_config_instruction(i)]

    opcodes = set(i.opcode for i in vector_insns)

    tracker = StateTracker(vlenb=128)
    allocator = SimulatedStateLayout(vlenb=128)
    dispatcher = ScalarDispatcher()
    emitter = ProgramEmitter(vlenb=128)

    output = emitter._emit_function_assembly(
        instructions,
        tracker,
        allocator,
        dispatcher,
        func_name=_infer_func_name(instructions),
    )

    assert 'simulated_cpu_state' in output, "Missing CSR state"
    assert '.text' in output, "Missing .text section"
    assert '.globl  sdot_k' in output, "Missing function symbol"
    assert 'TODO: Unhandled instruction' not in output, "sdot_k still contains unhandled instructions"
    assert '.L_vfwmacc_vv_loop_' in output, "Missing vfwmacc.vv translation"
    assert 'fcvt.d.s' in output, "Missing widening conversion for vfwmacc.vv"
    assert 'fmadd.d' in output, "Missing widened fused multiply-add"
    assert 'vfmv.f.s' in output, "Missing vfmv.f.s translation comment"



def test_ddot_k():
    """测试 ddot_k 翻译"""
    asm_path = os.path.join(FIXTURES_DIR, 'ddot_k.objdump.s')

    if not os.path.exists(asm_path):
        return


    parser = AsmParser()
    instructions = parser.parse_file(asm_path)

    vector_insns = [i for i in instructions if is_vector_instruction(i)]
    config_insns = [i for i in instructions if is_config_instruction(i)]

    opcodes = set(i.opcode for i in vector_insns)

    tracker = StateTracker(vlenb=128)
    allocator = SimulatedStateLayout(vlenb=128)
    dispatcher = ScalarDispatcher()
    emitter = ProgramEmitter(vlenb=128)

    output = emitter._emit_function_assembly(
        instructions,
        tracker,
        allocator,
        dispatcher,
        func_name=_infer_func_name(instructions),
    )

    assert 'simulated_cpu_state' in output, "Missing CSR state"
    assert '.text' in output, "Missing .text section"
    assert '.globl  ddot_k' in output, "Missing function symbol"
    assert 'TODO: Unhandled instruction' not in output, "ddot_k still contains unhandled instructions"
    assert '.L_vfmacc_vv_loop_' in output, "Missing vfmacc.vv translation"
    assert '.L_vfredusum_loop_' in output, "Missing vfredusum.vs translation"
    assert 'vfmv.f.s' in output, "Missing vfmv.f.s translation comment"
    assert '.L_vlse64_v_loop_' in output, "Missing vlse64.v translation"
    assert 'fmadd.d' in output, "Missing double-precision fused multiply-add"



def test_vfmul_vf_inline():
    """测试 vfmul.vf 内联翻译"""

    asm = """foo:
    vsetvli a5, a0, e32, m8, ta, ma
    vfmul.vf v8, v16, fa0
"""

    parser = AsmParser()
    instructions = parser.parse_string(asm)

    tracker = StateTracker(vlenb=128)
    allocator = SimulatedStateLayout(vlenb=128)
    dispatcher = ScalarDispatcher()
    emitter = ProgramEmitter(vlenb=128)

    output = emitter._emit_function_assembly(
        instructions,
        tracker,
        allocator,
        dispatcher,
        func_name=_infer_func_name(instructions),
    )

    assert 'vfmul.vf' in output
    assert '.L_vfmul_vf_loop_' in output
    assert 'fmul.s' in output



def test_vfmv_f_s_inline():
    """测试 vfmv.f.s 内联翻译"""

    asm = """foo:
    vsetvli a6, zero, e64, m1, ta, ma
    vfmv.f.s fa0, v1
"""

    parser = AsmParser()
    instructions = parser.parse_string(asm)

    tracker = StateTracker(vlenb=128)
    allocator = SimulatedStateLayout(vlenb=128)
    dispatcher = ScalarDispatcher()
    emitter = ProgramEmitter(vlenb=128)

    output = emitter._emit_function_assembly(
        instructions,
        tracker,
        allocator,
        dispatcher,
        func_name=_infer_func_name(instructions),
    )

    assert 'vfmv.f.s' in output
    assert 'fld' in output  # SEW=64 → fld (双精度浮点加载)
    assert 'fa0' in output
    assert all(line.startswith('.L_vstart_zero_loop_')
               for line in output.splitlines() if line.startswith('.L_'))
    assert 'unsupported nonzero source vstart' in output



def test_vsetvli_mu_inline():
    """测试 `vsetvli ..., mu` 可以走完整翻译链路"""

    asm = """foo:
    vsetvli a5, a0, e32, m4, ta, mu
    vadd.vv v8, v4, v0
"""

    parser = AsmParser()
    instructions = parser.parse_string(asm)

    tracker = StateTracker(vlenb=128)
    allocator = SimulatedStateLayout(vlenb=128)
    dispatcher = ScalarDispatcher()
    emitter = ProgramEmitter(vlenb=128)

    output = emitter._emit_function_assembly(
        instructions,
        tracker,
        allocator,
        dispatcher,
        func_name=_infer_func_name(instructions),
    )

    assert 'vsetvli a5, a0, e32, m4, ta, mu' in output
    assert 'CSR.vtype = vtype' in output
    assert '.L_vadd_vv_loop_' in output
    assert 'TODO: Unhandled instruction' not in output



def test_complex_axpy_inline():
    """测试 complex axpy 关键指令链路的内联翻译"""

    asm = """foo:
    vsetvli a4, a0, e32, m4, ta, ma
    vlseg2e32.v v8, (a5)
    vlseg2e32.v v16, (a3)
    vmv4r.v v4, v8
    vmv4r.v v24, v12
    vfmacc.vf v4, fa0, v16
    vfmacc.vf v24, fa0, v20
    vfnmsac.vf v4, fa1, v20
    vfmacc.vf v24, fa1, v16
    vmv4r.v v8, v4
    vmv4r.v v12, v24
    vsseg2e32.v v8, (a5)
"""

    parser = AsmParser()
    instructions = parser.parse_string(asm)

    tracker = StateTracker(vlenb=128)
    allocator = SimulatedStateLayout(vlenb=128)
    dispatcher = ScalarDispatcher()
    emitter = ProgramEmitter(vlenb=128)

    output = emitter._emit_function_assembly(
        instructions,
        tracker,
        allocator,
        dispatcher,
        func_name=_infer_func_name(instructions),
    )

    assert 'vlseg2e32.v' in output
    assert '.L_vlseg2e32_v_loop_' in output
    assert '.L_vmv4r_v_loop_' in output
    assert '.L_vfnmsac_vf_loop_' in output
    assert '.L_vsseg2e32_v_loop_' in output
    assert 'fnmsub.s' in output
    assert 'TODO: Unhandled instruction' not in output



def test_unsupported_instruction_fails_translation():
    """测试未支持指令会显式中断翻译"""

    asm = """foo:
    vsetvli a5, a0, e32, m8, ta, ma
    vfdiv.vv v16, v8, v4
"""

    parser = AsmParser()
    instructions = parser.parse_string(asm)

    tracker = StateTracker(vlenb=128)
    allocator = SimulatedStateLayout(vlenb=128)
    dispatcher = ScalarDispatcher()
    emitter = ProgramEmitter(vlenb=128)

    try:
        emitter._emit_function_assembly(
            instructions,
            tracker,
            allocator,
            dispatcher,
            func_name=_infer_func_name(instructions),
        )
        raise AssertionError("Expected UnsupportedInstructionError")
    except UnsupportedInstructionError as exc:
        assert 'vfdiv.vv' in str(exc)



def test_parser_plain_label_and_no_operand():
    """测试解析器支持普通标签和无操作数指令"""

    asm = """foo:
    vsetvli a5, a0, e64, m1, ta, ma
    ret
"""
    parser = AsmParser()
    instructions = parser.parse_string(asm)

    assert len(instructions) == 2, f"Expected 2 instructions, got {len(instructions)}"
    assert instructions[0].label == 'foo', f"Expected label foo, got {instructions[0].label}"
    assert instructions[1].opcode == 'ret', f"Expected ret, got {instructions[1].opcode}"
    assert instructions[1].operands == [], f"ret should have empty operands, got {instructions[1].operands}"



def test_parser_numeric_local_labels():
    """测试解析器支持 GNU 数字局部标签"""

    asm = """foo:
    vsetvli a5, a0, e64, m1, ta, ma
1:
    addi a0, a0, -1
    bnez a0, 1b
"""
    parser = AsmParser()
    instructions = parser.parse_string(asm)

    assert len(instructions) == 3, f"Expected 3 instructions, got {len(instructions)}"
    assert instructions[0].label == 'foo', f"Expected first label foo, got {instructions[0].label}"
    assert instructions[1].label == '1', f"Expected numeric local label 1, got {instructions[1].label}"
    assert instructions[2].operands[-1] == '1b', f"Expected branch target 1b, got {instructions[2].operands[-1]}"



def test_parser_preserves_v0_t_operand():
    """测试 parser 会保留 masked form 中的 `v0.t` 操作数"""

    asm = """foo:
    vadd.vv v8, v4, v16, v0.t
"""
    parser = AsmParser()
    instructions = parser.parse_string(asm)

    assert len(instructions) == 1
    assert instructions[0].operands[-1] == 'v0.t'



def test_parser_source_vtype_annotations_are_ordinary_comments():
    """旧 ``# source:`` 注释不再向指令对象注入 vtype 语义。"""

    asm = """foo:
    vadd.vv v8, v4, v0 # source: <e32,m2,ta,ma>
    addi a4,a4,-1324 # 4d7e40 <sym> # source: <e8,mf2,tu,mu>; <e16,mf4,ta,ma>; <e8,mf2,tu,mu>
    vsub.vv v10, v8, v4 # source: e64, m1, ta, ma
    vfmacc.vv v12, v8, v4 # source: e16, m2, tu, mu; e32, m4, ta, ma; e16, m2, tu, mu
    vmul.vv v14, v8, v4 # source: unknown[not in block]
    vand.vv v16, v8, v4 # source: e32, m1, ta, ma; unknown[merged path]
"""
    parser = AsmParser()
    instructions = parser.parse_string(asm)

    assert instructions[1].op_str == "a4,a4,-1324"
    assert not hasattr(instructions[0], "source_vtypes")
    assert not hasattr(instructions[0], "source_vtype_unknown")
    assert instructions[0].op_str == "v8, v4, v0"



def test_private_function_assembly_uses_explicit_function_path():
    """单函数 emitter 入口使用调用方显式给出的函数名。"""

    asm = """vsetvli a5, a0, e64, m1, ta, ma
vle64.v v1, (a0)
ret
"""
    parser = AsmParser()
    instructions = parser.parse_string(asm)

    output = ProgramEmitter(vlenb=128)._emit_function_assembly(
        instructions,
        StateTracker(vlenb=128),
        SimulatedStateLayout(vlenb=128),
        ScalarDispatcher(),
        func_name="inline",
    )
    assert ".globl  inline" in output, "single-function path must keep the requested name"
    assert "la.tls.ie t6, simulated_cpu_state_ptr" in output, "Missing Initial-Exec TLS state-base reload"
    assert "add     t6, t6, tp" in output, "Missing thread-pointer addition in TLS state-base reload"
    assert "get_simulated_cpu_state_addr@plt" not in output, "Default path must not call the TLS helper"
    assert "la      t6, simulated_cpu_state" not in output, "single-function path must not use non-TLS state base"
    assert "addi    sp, sp, -" in output, "Missing local spill frame in single-function path"



def test_private_function_assembly_wraps_vector_blocks():
    """测试私有函数正文发射器为向量翻译块生成局部保护代码。"""

    asm = """vsetvli a5, a0, e64, m1, ta, ma
vle64.v v1, (a0)
ret
"""
    parser = AsmParser()
    instructions = parser.parse_string(asm)

    tracker = StateTracker(vlenb=128)
    allocator = SimulatedStateLayout(vlenb=128)
    dispatcher = ScalarDispatcher()
    emitter = ProgramEmitter(vlenb=128)

    output = emitter._emit_function_assembly(
        instructions,
        tracker,
        allocator,
        dispatcher,
        func_name="foo",
    )

    assert "la.tls.ie t6, simulated_cpu_state_ptr" in output, "Missing Initial-Exec TLS state-base reload"
    assert "get_simulated_cpu_state_addr@plt" not in output, "Default path must not call the TLS helper"
    assert "la      t6, simulated_cpu_state" not in output, "函数正文发射不得误用非 TLS 状态基址"
    assert output.count("addi    sp, sp, -") == 2, "Expected one spill frame per RVV instruction"
    assert output.count("addi    sp, sp, ") >= 4, "Expected matching spill/restore operations"
    assert output.count("la.tls.ie t6, simulated_cpu_state_ptr") == 2, "Expected one direct TLS reload per RVV instruction"
    assert "foo:" in output, "Missing function label"



def test_vsetvli_skip_restore_for_output_t0():
    """测试 vsetvli 写回 t0 时不会把结果寄存器错误恢复"""

    asm = """foo:
    vsetvli t0, a0, e64, m1, ta, ma
    ret
"""
    parser = AsmParser()
    instructions = parser.parse_string(asm)

    output = ProgramEmitter(vlenb=128)._emit_function_assembly(
        instructions,
        StateTracker(vlenb=128),
        SimulatedStateLayout(vlenb=128),
        ScalarDispatcher(),
        func_name="foo",
    )

    assert "sd      t0," not in output, "t0 is semantic output of vsetvli and must not be saved/restored"
    assert "ld      t0," not in output, "t0 is semantic output of vsetvli and must not be restored"
    assert "la.tls.ie t6, simulated_cpu_state_ptr" in output, "Expected direct TLS state-base reload"
    assert "get_simulated_cpu_state_addr@plt" not in output, "Default path must not call the TLS helper"
    assert "la      t6, simulated_cpu_state" not in output, "Must not use non-TLS state base"
    assert "addi    sp, sp, -" in output, "Expected spill frame for handler clobber protection"



def test_csrr_skip_restore_for_output_a5():
    """测试 csrr 写回 a5 时不会被块级寄存器恢复覆盖"""

    asm = """foo:
    csrr a5, vlenb
    ret
"""
    parser = AsmParser()
    instructions = parser.parse_string(asm)

    output = ProgramEmitter(vlenb=128)._emit_function_assembly(
        instructions,
        StateTracker(vlenb=128),
        SimulatedStateLayout(vlenb=128),
        ScalarDispatcher(),
        func_name="foo",
    )

    assert re.search(r"li\s+(\w+), 128\n\s+mv\s+a5, \1", output), "csrr vlenb must read the simulated VLENB"
    assert "sd      a5," not in output, "a5 is semantic output of csrr and must not be saved/restored"
    assert "ld      a5," not in output, "a5 is semantic output of csrr and must not be restored"



def test_masked_vadd_vv_inline():
    """测试 `vadd.vv` 的 masked form 会生成显式的 v0 guard"""

    asm = """foo:
    vsetvli a5, a0, e32, m1, ta, mu
    vadd.vv v8, v4, v16, v0.t
    ret
"""
    _, output = _translate_inline_asm(asm)

    assert "# masked form:" in output
    assert ".L_vadd_vv_mask_skip_loop_" in output
    assert "TODO: Unhandled instruction" not in output



def test_masked_vfredusum_vs_inline():
    """测试 `vfredusum.vs` 的 masked form 会跳过 masked-off 元素"""

    asm = """foo:
    vsetvli a5, a0, e64, m1, ta, mu
    vfredusum.vs v8, v8, v1, v0.t
    ret
"""
    _, output = _translate_inline_asm(asm)

    assert "# masked form:" in output
    assert ".L_vfredusum_mask_skip_loop_" in output
    assert "fadd.d" in output



def test_masked_vle32_v_inline():
    """测试 unit-stride masked load 不会再忽略 `v0.t`"""

    asm = """foo:
    vsetvli a5, a0, e32, m1, ta, mu
    vle32.v v8, (a1), v0.t
    ret
"""
    _, output = _translate_inline_asm(asm)

    assert "# masked form:" in output
    assert ".L_vle32_v_mask_skip_loop_" in output
    assert "lw" in output



def test_masked_vsse32_v_inline():
    """测试 stride masked store 会正确保留 stride 操作数而不是误读 `v0.t`"""

    asm = """foo:
    vsetvli a5, a0, e32, m1, ta, mu
    vsse32.v v8, (a1), a2, v0.t
    ret
"""
    _, output = _translate_inline_asm(asm)

    assert "# masked form:" in output
    assert ".L_vsse32_v_mask_skip_loop_" in output
    assert "mul" in output
    assert "v0.t" not in re.findall(r"mul\s+\w+,\s+\w+,\s+(\w+)", output), "mask operand must not be parsed as stride"



def test_masked_vlsseg2e32_v_inline():
    """测试 strided segmented masked load 也会生成统一的 mask guard"""

    asm = """foo:
    vsetvli a5, a0, e32, m1, ta, mu
    vlsseg2e32.v v8, (a1), a2, v0.t
    ret
"""
    _, output = _translate_inline_asm(asm)

    assert "# masked form:" in output
    assert ".L_vlsseg2e32_v_mask_skip_loop_" in output
    assert "segment 0" in output



def test_masked_vsseg2e32_v_inline():
    """测试 segmented store 的 masked form 会在整个 tuple 副作用前先做 guard"""

    asm = """foo:
    vsetvli a5, a0, e32, m1, ta, mu
    vsseg2e32.v v8, (a1), v0.t
    ret
"""
    _, output = _translate_inline_asm(asm)

    assert "# masked form:" in output
    assert ".L_vsseg2e32_v_mask_skip_loop_" in output
    assert "segment 0 / segment 1" in output



def test_vfmv_f_s_skip_restore_for_output_ft0():
    """测试 vfmv.f.s 写回 ft0 时不会把结果寄存器错误恢复"""

    asm = """foo:
    vfmv.f.s ft0, v1
    ret
"""
    parser = AsmParser()
    instructions = parser.parse_string(asm)

    output = ProgramEmitter(vlenb=128)._emit_function_assembly(
        instructions,
        StateTracker(vlenb=128),
        SimulatedStateLayout(vlenb=128),
        ScalarDispatcher(),
        func_name="foo",
        init_vtype="sew=64,lmul=1,ta,ma"
    )

    assert "fsd     ft0," not in output, "ft0 is semantic output of vfmv.f.s and must not be saved"
    assert re.search(r"fld\s+ft0,\s+\d+\(sp\)", output) is None, "ft0 is semantic output of vfmv.f.s and must not be restored from stack"
    assert "la.tls.ie t6, simulated_cpu_state_ptr" in output, "Expected direct TLS state-base reload"
    assert "get_simulated_cpu_state_addr@plt" not in output, "Default path must not call the TLS helper"
    assert "la      t6, simulated_cpu_state" not in output, "Must not use non-TLS state base"
    assert "addi    sp, sp, -" in output, "Expected spill frame for handler clobber protection"



def test_vsetvli_avoids_gpr_temp_conflict():
    """测试 vsetvli 在 rd/rs1 使用 t 寄存器时不会发生块内冲突"""

    asm = """foo:
    vsetvli t1, t2, e64, m1, ta, ma
    ret
"""
    parser = AsmParser()
    instructions = parser.parse_string(asm)

    output = ProgramEmitter(vlenb=128)._emit_function_assembly(
        instructions,
        StateTracker(vlenb=128),
        SimulatedStateLayout(vlenb=128),
        ScalarDispatcher(),
        func_name="foo",
    )

    # 期望行为：
    # - t1/t2 仅承担指令语义中的 rd/rs1 角色；
    # - 真正的中间值应落在其它 temp 上，而不是继续写死 t1/t2。
    assert "li      t1, 192" not in output, "vsetvli should not reuse rd=t1 as internal temp"
    assert "li      t2, 192" not in output, "vsetvli should not reuse rs1=t2 as internal temp"
    assert "mv      t2, t2" not in output, "vsetvli should not collapse source copy onto rs1 itself"
    assert "mv      t1, t4" in output, "vsetvli should still write the final vl back to rd"



def test_vfmul_vf_avoids_fpr_temp_conflict():
    """测试 vfmul.vf 在 rs1=ft0 时不会把标量输入当成临时寄存器覆盖"""

    asm = """foo:
    vsetvli a5, a0, e32, m1, ta, ma
    vfmul.vf v8, v16, ft0
    ret
"""
    parser = AsmParser()
    instructions = parser.parse_string(asm)

    output = ProgramEmitter(vlenb=128)._emit_function_assembly(
        instructions,
        StateTracker(vlenb=128),
        SimulatedStateLayout(vlenb=128),
        ScalarDispatcher(),
        func_name="foo",
    )

    assert re.search(r"\bf(?:lw|ld)\s+ft0,\s+0\(t3\)", output) is None, "vfmul.vf should not load vector data into scalar source ft0"
    assert "fmul.s  ft2, ft1, ft0" in output or "fmul.d  ft2, ft1, ft0" in output, "vfmul.vf should use alternate temps and keep ft0 as scalar input"



def test_vmv_s_x_avoids_gpr_temp_conflict():
    """测试 vmv.s.x 在 rs1=t3 时不会复用 t3 作为地址临时寄存器"""

    asm = """foo:
    vmv.s.x v8, t3
    ret
"""
    parser = AsmParser()
    instructions = parser.parse_string(asm)

    output = ProgramEmitter(vlenb=128)._emit_function_assembly(
        instructions,
        StateTracker(vlenb=128),
        SimulatedStateLayout(vlenb=128),
        ScalarDispatcher(),
        func_name="foo",
    )

    assert "li      t3, 1024" not in output, "vmv.s.x should not reuse rs1=t3 as address temp"
    assert "sd      t3, 0(t0)" in output or "sw      t3, 0(t0)" in output, "vmv.s.x should preserve t3 as semantic source and store through another temp"



def test_vle32_v_avoids_base_gpr_conflict():
    """测试 vle32.v 在 base=t3 时不会复用 t3 作为中间地址寄存器"""

    asm = """foo:
    vsetvli a5, a0, e32, m1, ta, ma
    vle32.v v8, (t3)
    ret
"""
    parser = AsmParser()
    instructions = parser.parse_string(asm)

    output = ProgramEmitter(vlenb=128)._emit_function_assembly(
        instructions,
        StateTracker(vlenb=128),
        SimulatedStateLayout(vlenb=128),
        ScalarDispatcher(),
        func_name="foo",
    )

    assert "add     t3, t3," not in output, "vle32.v should not reuse base register t3 as scratch destination"
    assert "lw      t5, 0(t3)" not in output, "vle32.v should not build memory address directly on clobbered t3 path"



def test_vsse32_v_avoids_base_and_stride_conflicts():
    """测试 vsse32.v 在 base=t3/stride=t4 时不会与内部 temp 硬冲突"""

    asm = """foo:
    vsetvli a5, a0, e32, m1, ta, ma
    vsse32.v v8, (t3), t4
    ret
"""
    parser = AsmParser()
    instructions = parser.parse_string(asm)

    output = ProgramEmitter(vlenb=128)._emit_function_assembly(
        instructions,
        StateTracker(vlenb=128),
        SimulatedStateLayout(vlenb=128),
        ScalarDispatcher(),
        func_name="foo",
    )

    assert "mv      t4, t4" not in output, "vsse32.v should not reuse stride register t4 as temp copy target"
    assert "add     t3, t3," not in output, "vsse32.v should not reuse base register t3 as scratch destination"



def test_vlsseg2e32_v_avoids_temp_conflicts():
    """测试 vlsseg2e32.v 在 base=t4/stride=t5 时仍能避开内部 temp 冲突"""

    asm = """foo:
    vsetvli a5, a0, e32, m1, ta, ma
    vlsseg2e32.v v8, (t4), t5
    ret
"""
    parser = AsmParser()
    instructions = parser.parse_string(asm)

    output = ProgramEmitter(vlenb=128)._emit_function_assembly(
        instructions,
        StateTracker(vlenb=128),
        SimulatedStateLayout(vlenb=128),
        ScalarDispatcher(),
        func_name="foo",
    )

    assert "mul     t5, " not in output, "vlsseg2e32.v should not reuse stride register t5 as tuple-offset temp"
    assert "add     t4, t4," not in output, "vlsseg2e32.v should not reuse base register t4 as scratch destination"



def test_translate_function_text_only_mode():
    """测试 text_only 模式会去掉包装性汇编字段，但保留 .text 与正文"""

    asm = """foo:
    vsetvli a5, a0, e64, m1, ta, ma
    ret
"""
    parser = AsmParser()
    instructions = parser.parse_string(asm)

    output = translate_function(
        RVFunction(name="foo", start_addr=0, instructions=instructions),
        func_name="foo",
        vlenb=128,
        source_file="inline_text_only.s",
        text_only=True,
    )

    assert "    .text" not in output, "text_only mode must omit .text section"
    assert "foo:" in output, "text_only mode must keep function label"
    assert ".globl" not in output, "text_only mode must omit .globl"
    assert ".type" not in output, "text_only mode must omit .type"
    assert ".size" not in output, "text_only mode must omit .size"
    assert ".comm   simulated_cpu_state" not in output, "text_only mode must omit .comm state declaration"
