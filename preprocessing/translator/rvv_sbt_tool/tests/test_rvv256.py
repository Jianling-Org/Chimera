#!/usr/bin/env python3
"""256-bit RVV mode tests"""
import sys, os, re
import pytest
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from riscv.extensions.rvv.analysis.model import InstructionAnalysis
from riscv.frontend.model import RVInstruction
from riscv.extensions.rvv.analysis.model import VTypeSpec
from riscv.extensions.rvv.analysis.model import VTypeCandidate
from riscv.extensions.rvv.analysis.config import StateTracker
from riscv.extensions.rvv.runtime.layout import SimulatedStateLayout
from riscv.extensions.rvv.translation.contracts import HandlerContext, InstructionValidationError, LoweringPlan
from riscv.frontend.parser import AsmParser
from riscv.extensions.rvv.backends.rvv256.temp_regs import VRegTempAllocator
from riscv.extensions.rvv.translation.temps import TempRegisterAllocator
from riscv.extensions.rvv.backends.rvv256.handlers.arithmetic.floating_multiply import _build_vfmacc_vf_lines, _build_vfmacc_vv_lines
from riscv.extensions.rvv.backends.rvv256.handlers.memory import _build_vle64_v_lines, _build_vse64_v_lines
from riscv.extensions.rvv.backends.rvv256.handlers.config import _build_vsetvli_lines, _build_vsetivli_lines, _build_vsetvl_lines
from riscv.extensions.rvv.backends.rvv256.specs import build_rvv256_registry


@pytest.fixture(autouse=True)
def _use_conservative_profile_for_legacy_shape_tests(monkeypatch):
    """让本模块继续锁定原有保守代码形状，避免默认 profile 反转后失去回归基线。

    本文件的大多数断言检查 v24-v31 临时寄存器、逐块循环和标量尾部等历史
    发射形状，而非公共 API 的默认策略。将导入到测试函数内的 ``translate``
    替换为显式 ``wide_lmul=False`` 的包装器，能够保留这组基线；默认宽 profile
    的 API/CLI 合同由 ``test_rvv256_wide.py`` 单独验证。
    """
    import rvv_sbt_rvv

    original_translate = rvv_sbt_rvv.translate

    def conservative_translate(*args, **kwargs):
        kwargs.setdefault("wide_lmul", False)
        return original_translate(*args, **kwargs)

    monkeypatch.setattr(rvv_sbt_rvv, "translate", conservative_translate)

class FakeDisp:
    _c = 0
    def get_loop_label(self, p):
        FakeDisp._c += 1; return f'.L_t_{p}_{FakeDisp._c}'


def _invoke_builder(builder, insn, state, allocator, dispatcher=None):
    """按结构化 handler 合同调用内部 builder。

    这些断言有意检查保守实现的逐行形状，所以不经过可能选择宽路径的
    ``RVV256Lowerer``；但上下文和计划仍来自真实 registry，不再复活旧的
    ``(insn, state, allocator, dispatcher)`` 兼容调用约定。
    """

    registry = build_rvv256_registry(wide_lmul=False)
    spec = registry.get(insn.opcode)
    assert spec is not None
    context = HandlerContext(
        instruction=insn,
        state=state,
        new_label=(dispatcher or FakeDisp()).get_loop_label,
        layout=allocator,
        temp_register_allocator=TempRegisterAllocator(
            insn, reserved_gprs=("t6",)
        ),
        spec=spec,
    )
    plan = LoweringPlan(
        instruction=insn,
        spec=spec,
        normalized_operands=tuple(str(item).strip() for item in insn.operands),
    )
    return builder(context)


def _analysis_for(address, specs=(), *, unknown=False):
    """为发射器单元测试构造内部分析事实，不再模拟旧 source 注释字段。"""

    return InstructionAnalysis(
        address=address,
        possible_vtypes=frozenset(
            VTypeCandidate.from_spec(spec) for spec in specs
        ),
        vtype_unknown=unknown,
    )


def _translate_cfg_fixture(source: str) -> str:
    """通过真实 parser/CFG 产生多入口 vtype，不向指令注入旧分析对象。"""

    from rvv_sbt_rvv import translate

    functions = AsmParser().parse_string_functions(source)
    assert len(functions) == 1
    return translate(functions[0].instructions, raw=True)

def test_vreg_alloc():
    insn = RVInstruction(0, 'vfmacc.vf', operands=['v8','fa0','v16'], op_str='vfmacc.vf v8, fa0, v16')
    a = VRegTempAllocator(insn)
    assert a.alloc_vreg() == 'v24'

def test_vreg_alloc_all8():
    insn = RVInstruction(0, 'vfmacc.vf', operands=['v8','fa0','v16'], op_str='vfmacc.vf v8, fa0, v16')
    a = VRegTempAllocator(insn)
    regs = [a.alloc_vreg() for _ in range(8)]
    assert regs == [f'v{i}' for i in range(24,32)]

def test_vreg_group_alloc_reserves_contiguous_members():
    insn = RVInstruction(0, 'vfncvt.f.f.w', operands=['v1','v1'], op_str='vfncvt.f.f.w v1, v1')
    a = VRegTempAllocator(insn)
    assert a.alloc_vreg_group(2) == 'v24'
    assert a.alloc_vreg() == 'v26'

def test_vreg_group_alloc_honors_alignment():
    insn = RVInstruction(0, 'vfncvt.f.f.w', operands=['v1','v1'], op_str='vfncvt.f.f.w v1, v1')
    a = VRegTempAllocator(insn, reserved_vregs=(24,))
    assert a.alloc_vreg_group(2) == 'v26'

def test_vfmacc_vf():
    state = StateTracker(vlenb=128); state.sew = 64
    alloc = SimulatedStateLayout()
    insn = RVInstruction(0, 'vfmacc.vf', operands=['v8','fa0','v16'], op_str='vfmacc.vf v8, fa0, v16', )
    lines = _invoke_builder(_build_vfmacc_vf_lines, insn, state, alloc)
    code = '\n'.join(lines)
    assert 'vle64.v' in code and 'vfmacc.vf' in code and 'vse64.v' in code

def test_vfmacc_vv():
    state = StateTracker(vlenb=128); state.sew = 64
    alloc = SimulatedStateLayout()
    insn = RVInstruction(0, 'vfmacc.vv', operands=['v8','v16','v24'], op_str='vfmacc.vv v8, v16, v24', )
    lines = _invoke_builder(_build_vfmacc_vv_lines, insn, state, alloc)
    code = '\n'.join(lines)
    assert 'vle64.v' in code and 'vfmacc.vv' in code

def test_vle64_v():
    state = StateTracker(vlenb=128); state.sew = 64
    alloc = SimulatedStateLayout()
    insn = RVInstruction(0, 'vle64.v', operands=['v8','(a0)'], op_str='vle64.v v8, (a0)', )
    lines = _invoke_builder(_build_vle64_v_lines, insn, state, alloc)
    code = '\n'.join(lines)
    assert 'vle64.v' in code

def test_vse64_v():
    state = StateTracker(vlenb=128); state.sew = 64
    alloc = SimulatedStateLayout()
    insn = RVInstruction(0, 'vse64.v', operands=['v8','(a0)'], op_str='vse64.v v8, (a0)', )
    lines = _invoke_builder(_build_vse64_v_lines, insn, state, alloc)
    code = '\n'.join(lines)
    assert 'vse64.v' in code

def test_vsetvli():
    insn = RVInstruction(0, 'vsetvli', operands=['a4','a0','e64','m8','ta','ma'],
                          op_str='vsetvli a4, a0, e64, m8, ta, ma', )
    state = StateTracker(vlenb=128); alloc = SimulatedStateLayout()
    lines = _invoke_builder(_build_vsetvli_lines, insn, state, alloc)
    assert state.sew == 64 and state.lmul == 8.0

def test_end_to_end():
    from rvv_sbt_rvv import translate
    insn = RVInstruction(0, 'vfmacc.vf', operands=['v8','fa0','v16'], op_str='vfmacc.vf v8, fa0, v16', )
    result = translate([insn], init_vtype='sew=64,lmul=1')
    assert 'vle64.v' in result and 'vfmacc.vf' in result
    assert 'simulated_cpu_state' in result

def test_e8_chunk_uses_register_avl():
    from rvv_sbt_rvv import translate
    insn = RVInstruction(0, 'vid.v', operands=['v2'], op_str='vid.v v2', )
    result = translate([insn], init_vtype='199', raw=True)
    assert 'vsetivli zero, 32' not in result
    assert re.search(
        r"li\s+(\w+), 32\s*\n\s+vsetvli zero, \1, e8, m1, ta, ma",
        result,
    )
    assert 'addi    sp, sp, -16' not in result
    assert 'CHIMERA_INTERNAL_STACK' not in result

def test_vmfgt_vf_tail_uses_int_store_and_avoids_ft0_conflict():
    from rvv_sbt_rvv import translate
    insn = RVInstruction(0, 'vmfgt.vf', operands=['v12','v18','ft0'], op_str='vmfgt.vf v12, v18, ft0', )
    result = translate([insn], init_vtype='sew=32,lmul=1')
    assert 'RVV1.0 bit-packed mask' in result
    assert 'vse32.v' not in result
    assert 'sw       t' not in result
    assert 'sb      ' in result
    assert 'flw      ft0,' not in result
    assert 'flt.s    t5, ft0, ft0' not in result

def test_vmfle_vf_writes_bitpacked_mask():
    from rvv_sbt_rvv import translate
    cases = [
        ('sew=32,lmul=1', 'fle.s', 'vse32.v'),
        ('sew=64,lmul=1', 'fle.d', 'vse64.v'),
    ]
    for init_vtype, cmp_instr, forbidden_store in cases:
        insn = RVInstruction(0, 'vmfle.vf', operands=['v8','v10','fa0'], op_str='vmfle.vf v8, v10, fa0', )
        result = translate([insn], init_vtype=init_vtype)
        assert 'vmfle.vf v8, v10, fa0' in result
        assert 'RVV1.0 bit-packed mask' in result
        assert cmp_instr in result
        assert '<= fa0' in result
        assert forbidden_store not in result
        assert 'sb      ' in result

def test_vadd_vv_tail_is_integer():
    from rvv_sbt_rvv import translate
    insn = RVInstruction(0, 'vadd.vv', operands=['v4','v2','v3'], op_str='vadd.vv v4, v2, v3', )
    result = translate([insn], init_vtype='sew=32,lmul=1', raw=True)
    assert '整数标量尾部回退' in result
    assert 'fadd.s' not in result and 'fadd.d' not in result
    assert 'lwu' in result and 'sw' in result

def test_vsub_vv_path():
    from rvv_sbt_rvv import translate
    insn = RVInstruction(0, 'vsub.vv', operands=['v4','v2','v3'], op_str='vsub.vv v4, v2, v3', )
    result = translate([insn], init_vtype='sew=32,lmul=1', raw=True)
    assert 'vsub.vv v26, v24, v25' in result
    assert 'v4[i] = v2[i] - v3[i]' in result
    assert '尾部 RVV chunk' in result
    assert 'vsetvli zero,' in result

def test_vslidedown_zero_fills_suffix_without_fallthrough():
    from rvv_sbt_rvv import translate
    insn = RVInstruction(0, 'vslidedown.vi', operands=['v4','v2','3'], op_str='vslidedown.vi v4, v2, 3', )
    result = translate([insn], init_vtype='sew=32,lmul=1', raw=True)
    assert 'vslidedown_copy_limit' in result
    assert 'vslidedown_zero_all' in result
    assert 'vslidedown_done' in result

def test_vrgather_vv_scalar_cross_chunk_path():
    from rvv_sbt_rvv import translate
    insn = RVInstruction(0, 'vrgather.vv', operands=['v4','v2','v3'], op_str='vrgather.vv v4, v2, v3', )
    result = translate([insn], init_vtype='sew=32,lmul=1', raw=True)
    assert 'vrgather.vv v4, v2, v3' in result
    assert 'scalar cross-chunk gather' in result
    assert 'VLMAX=32' in result
    assert 'bgeu' in result and 'index >= VLMAX => 0' in result
    assert 'lwu     ' in result and 'sw      ' in result
    assert 'slli' in result and 'byte offset = index * 4' in result
    assert 'Active element count comes from vl' in result

def test_vrgatherei16_vv_scalar_index_path():
    from rvv_sbt_rvv import translate
    insn = RVInstruction(0, 'vrgatherei16.vv', operands=['v4','v2','v3'], op_str='vrgatherei16.vv v4, v2, v3', )
    result = translate([insn], init_vtype='sew=32,lmul=1', raw=True)
    assert 'vrgatherei16.vv v4, v2, v3' in result
    assert 'scalar e16-index gather' in result
    assert 'lhu' in result and 'index = u16(v3[i])' in result
    assert 'VLMAX=32' in result
    assert 'index >= VLMAX => 0' in result
    assert 'byte offset = index * 4' in result

def test_vwmul_vx_tail_sign_extends_scalar_sew():
    from rvv_sbt_rvv import translate
    insn = RVInstruction(0, 'vwmul.vx', operands=['v4','v2','a1'], op_str='vwmul.vx v4, v2, a1', )
    result = translate([insn], init_vtype='sew=32,lmul=1', raw=True)
    assert 'scalar low e32 bits' in result
    assert 'sign-extend scalar to XLEN' in result
    assert 'sext(low e32 a1)' in result

def test_widening_integer_vv_and_acc_vx_paths():
    from rvv_sbt_rvv import translate
    cases = [
        RVInstruction(0, 'vwmul.vv', operands=['v4','v2','v3'], op_str='vwmul.vv v4, v2, v3', ),
        RVInstruction(0, 'vwmacc.vv', operands=['v10','v2','v4'], op_str='vwmacc.vv v10, v2, v4', ),
        RVInstruction(0, 'vwmacc.vx', operands=['v8','a1','v6'], op_str='vwmacc.vx v8, a1, v6', ),
    ]
    result = translate(cases, init_vtype='sew=32,lmul=1', raw=True)
    assert 'vwmul.vv v26, v24, v25' in result
    assert 'vwmacc.vv v26, v24, v25' in result
    assert 'vwmacc.vx v25,' in result
    assert 'e32 -> e64' in result
    assert 'vle32.v' in result and 'vse64.v' in result
    assert 'widening signed multiply' in result
    assert 'widening signed multiply-accumulate' in result
    assert 'sign-extend scalar to XLEN' in result
    assert 'vsetvli zero, t2, e32, mf2, ta, ma' in result
    assert '尾部标量回退' in result

def test_vwmul_vv_supports_e8_e16_e32():
    from rvv_sbt_rvv import translate
    insn = RVInstruction(0, 'vwmul.vv', operands=['v4','v2','v3'], op_str='vwmul.vv v4, v2, v3', )
    cases = [
        ('sew=8,lmul=1', 'vle8.v v24', 'vle8.v v25', 'vse16.v v26', 'e8 -> e16', 'vsetivli zero, 16, e8, mf2, ta, ma'),
        ('sew=16,lmul=1', 'vle16.v v24', 'vle16.v v25', 'vse32.v v26', 'e16 -> e32', 'vsetivli zero, 8, e16, mf2, ta, ma'),
        ('sew=32,lmul=1', 'vle32.v v24', 'vle32.v v25', 'vse64.v v26', 'e32 -> e64', 'vsetivli zero, 4, e32, mf2, ta, ma'),
    ]

    for init_vtype, load_vs2, load_vs1, store_vd, width_note, chunk_vset in cases:
        result = translate([insn], init_vtype=init_vtype, raw=True)
        assert 'vwmul.vv v26, v24, v25' in result
        assert load_vs2 in result
        assert load_vs1 in result
        assert store_vd in result
        assert width_note in result
        assert chunk_vset in result
        assert 'widening signed multiply' in result
        assert '尾部标量回退' in result


def test_vwmacc_vv_supports_e8_e16_e32():
    from rvv_sbt_rvv import translate
    insn = RVInstruction(0, 'vwmacc.vv', operands=['v4','v2','v3'], op_str='vwmacc.vv v4, v2, v3', )
    cases = [
        ('sew=8,lmul=1', 'vle8.v v24', 'vle8.v v25', 'vle16.v v26', 'vse16.v v26', 'e8 -> e16', 'vsetivli zero, 16, e8, mf2, ta, ma'),
        ('sew=16,lmul=1', 'vle16.v v24', 'vle16.v v25', 'vle32.v v26', 'vse32.v v26', 'e16 -> e32', 'vsetivli zero, 8, e16, mf2, ta, ma'),
        ('sew=32,lmul=1', 'vle32.v v24', 'vle32.v v25', 'vle64.v v26', 'vse64.v v26', 'e32 -> e64', 'vsetivli zero, 4, e32, mf2, ta, ma'),
    ]

    for init_vtype, load_vs1, load_vs2, load_acc, store_vd, width_note, chunk_vset in cases:
        result = translate([insn], init_vtype=init_vtype, raw=True)
        if init_vtype == 'sew=16,lmul=1':
            assert result == translate([insn], init_vtype=init_vtype, raw=True, wide_lmul=False)
            assert 'vwmacc.vv v8, v16, v20' in result
            assert 'vle32.v v8,' in result and 'vse32.v v8,' in result
            assert 'vle16.v v16,' in result and 'vle16.v v20,' in result
            assert 'target=m4' in result
            assert '尾部标量回退' not in result
            continue
        assert 'vwmacc.vv v26, v24, v25' in result
        assert load_vs1 in result
        assert load_vs2 in result
        assert load_acc in result
        assert store_vd in result
        assert width_note in result
        assert chunk_vset in result
        assert 'widening signed multiply-accumulate' in result
        assert '尾部标量回退' in result

    invalid = translate([insn], init_vtype='sew=64,lmul=1', raw=True)
    assert 'does not support SEW=64' in invalid
    assert 'fallback to ebreak' in invalid

def test_vnsrl_wi_narrows_unsigned_shift():
    from rvv_sbt_rvv import translate
    insn = RVInstruction(0, 'vnsrl.wi', operands=['v4','v2','7'], op_str='vnsrl.wi v4, v2, 7', )
    result = translate([insn], init_vtype='sew=32,lmul=1', raw=True)
    assert 'vnsrl.wi v26, v24, 7' in result
    assert 'vle64.v v24' in result
    assert 'vse32.v v26' in result
    assert 'lwu' not in result
    assert 'e64 -> e32' in result

def test_vnsra_wi_narrows_signed_shift():
    from rvv_sbt_rvv import translate
    insn = RVInstruction(0, 'vnsra.wi', operands=['v4','v2','7'], op_str='vnsra.wi v4, v2, 7', )
    result = translate([insn], init_vtype='sew=16,lmul=1', raw=True)
    assert 'vnsra.wi v26, v24, 7' in result
    assert 'vle32.v v24' in result
    assert 'vse16.v v26' in result
    
    assert 'e32 -> e16' in result

def test_vnclip_wi_uses_native_rounding_and_saturation():
    from rvv_sbt_rvv import translate
    insn = RVInstruction(0, 'vnclip.wi', operands=['v4','v2','7'], op_str='vnclip.wi v4, v2, 7', )
    result = translate([insn], init_vtype='sew=32,lmul=1', raw=True)
    assert 'vnclip.wi v26, v24, 7' in result
    assert 'vle64.v v24' in result
    assert 'vse32.v v26' in result
    assert 'csrw    vxrm' in result
    assert 'csrr    ' in result and ', vxsat' in result
    assert 'CSR.vcsr |= hardware vxsat' in result
    assert '尾部 RVV chunk' in result
    assert '尾部标量回退' not in result
    assert 'e64 -> e32' in result

def test_vfcvt_equal_width_paths():
    from rvv_sbt_rvv import translate
    cases = [
        RVInstruction(0, 'vfcvt.x.f.v', operands=['v4','v2'], op_str='vfcvt.x.f.v v4, v2', ),
        RVInstruction(0, 'vfcvt.f.xu.v', operands=['v6','v4'], op_str='vfcvt.f.xu.v v6, v4', ),
    ]
    result = translate(cases, init_vtype='sew=32,lmul=1', raw=True)
    assert 'vfcvt.x.f.v v25, v24' in result
    assert 'vfcvt.f.xu.v v25, v24' in result
    assert 'v4[i] = int(v2[i])' in result
    assert 'v6[i] = float_unsigned(v4[i])' in result
    assert '尾部 RVV chunk' in result
    assert 'vsetvli zero,' in result

def test_vfncvt_narrowing_paths_avoid_illegal_overlap():
    from rvv_sbt_rvv import translate
    cases = [
        ('vfncvt.f.f.w', 'vfncvt.f.f.w v26, v24', 'e64 -> e32'),
        ('vfncvt.f.xu.w', 'vfncvt.f.xu.w v26, v24', 'e64 -> e32'),
        ('vfncvt.x.f.w', 'vfncvt.x.f.w v26, v24', 'e64 float -> e32 int'),
    ]

    for opcode, emitted, note in cases:
        insn = RVInstruction(0, opcode, operands=['v4','v2'], op_str=f'{opcode} v4, v2', )
        result = translate([insn], init_vtype='sew=32,lmul=1', raw=True)
        assert emitted in result
        assert 'v25, v24' not in result
        assert note in result


def test_vfwcvt_f_f_v_supports_e16_and_e32():
    from rvv_sbt_rvv import translate
    insn = RVInstruction(0, 'vfwcvt.f.f.v', operands=['v4','v2'], op_str='vfwcvt.f.f.v v4, v2', )
    cases = [
        ('sew=16,lmul=1', 'vle16.v v24', 'vse32.v v25', 'e16 -> e32', 'vsetivli zero, 8, e16, mf2, ta, ma'),
        ('sew=32,lmul=1', 'vle32.v v24', 'vse64.v v25', 'e32 -> e64', 'vsetivli zero, 4, e32, mf2, ta, ma'),
    ]

    for init_vtype, load_text, store_text, width_note, chunk_vset in cases:
        result = translate([insn], init_vtype=init_vtype, raw=True)
        assert 'vfwcvt.f.f.v v25, v24' in result
        assert load_text in result
        assert store_text in result
        assert width_note in result
        assert chunk_vset in result
        assert '尾部 RVV widening chunk' in result
        assert '尾部标量回退' not in result

    invalid_result = translate([insn], init_vtype='sew=64,lmul=1', raw=True)
    assert 'does not support SEW=64' in invalid_result
    assert 'fallback to ebreak' in invalid_result

def test_vfwcvt_f_x_v_supports_e16_and_e32():
    from rvv_sbt_rvv import translate
    insn = RVInstruction(0, 'vfwcvt.f.x.v', operands=['v4','v2'], op_str='vfwcvt.f.x.v v4, v2', )
    cases = [
        ('sew=16,lmul=1', 'vle16.v v24', 'vse32.v v25', 'e16 -> e32', 'vsetivli zero, 8, e16, mf2, ta, ma'),
        ('sew=32,lmul=1', 'vle32.v v24', 'vse64.v v25', 'e32 -> e64', 'vsetivli zero, 4, e32, mf2, ta, ma'),
    ]

    for init_vtype, load_text, store_text, width_note, chunk_vset in cases:
        result = translate([insn], init_vtype=init_vtype, raw=True)
        assert 'vfwcvt.f.x.v v25, v24' in result
        assert load_text in result
        assert store_text in result
        assert width_note in result
        assert chunk_vset in result
        assert 'signed int -> widened float' in result
        assert '尾部 RVV widening convert chunk' in result

    invalid_result = translate([insn], init_vtype='sew=64,lmul=1', raw=True)
    assert 'does not support SEW=64' in invalid_result
    assert 'fallback to ebreak' in invalid_result

def test_vext_vf_family_paths():
    from rvv_sbt_rvv import translate
    cases = [
        ('vzext.vf2', 'sew=16,lmul=1', 'e8 -> e16', 'LMUL=mf2'),
        ('vzext.vf4', 'sew=32,lmul=1', 'e8 -> e32', 'LMUL=mf4'),
        ('vsext.vf4', 'sew=32,lmul=1', 'e8 -> e32', 'sign-extend'),
        ('vsext.vf2', 'sew=64,lmul=1', 'e32 -> e64', 'LMUL=mf2'),
        ('vzext.vf8', 'sew=64,lmul=1', 'e8 -> e64', 'LMUL=mf8'),
    ]
    for opcode, init_vtype, width_note, marker in cases:
        insn = RVInstruction(0, opcode, operands=['v4','v2'], op_str=f'{opcode} v4, v2', )
        result = translate([insn], init_vtype=init_vtype, raw=True)
        assert f'{opcode} v26, v24' in result
        assert width_note in result
        assert marker in result
        assert '尾部 RVV extension chunk' in result
        assert '尾部标量回退' not in result
    invalid = RVInstruction(0, 'vzext.vf8', operands=['v4','v2'], op_str='vzext.vf8 v4, v2', )
    invalid_result = translate([invalid], init_vtype='sew=32,lmul=1', raw=True)
    assert 'does not support SEW=32' in invalid_result
    assert 'fallback to ebreak' in invalid_result

def test_vsetvl_x0_x0_preserves_vl():
    state = StateTracker(vlenb=128)
    alloc = SimulatedStateLayout()
    insn = RVInstruction(0, 'vsetvl', operands=['zero','zero','a0'], op_str='vsetvl zero, zero, a0', )
    lines = _invoke_builder(_build_vsetvl_lines, insn, state, alloc)
    code = '\n'.join(lines)
    assert 'vl unchanged' in code
    assert 'x0,x0 requires unchanged VLMAX' in code
    assert 'CSR.vl = VL' not in code
    assert 'CSR.vtype = a0' in code

def test_vsetvl_fractional_lmul_vlmax_shift():
    state = StateTracker(vlenb=128)
    alloc = SimulatedStateLayout()
    insn = RVInstruction(0, 'vsetvl', operands=['zero','zero','a0'], op_str='vsetvl zero, zero, a0', )
    lines = _invoke_builder(_build_vsetvl_lines, insn, state, alloc)
    code = '\n'.join(lines)
    # 分数 LMUL 分支来自共享 vtype_decode 发射器。
    assert '# 分数 LMUL' in code
    assert 'lmul_enc-4' not in code
    assert 'lmul_enc - 4' not in code


def test_vsetvl_reserved_bits_route_to_vill_path():
    """vtype[62:8] 保留位非零必须进入 vill 收尾，而不是截取低 8 位继续。

    RVV 1.0 要求保留位非零的 vtype 视为非法（vill=1, vl=0）。RVV256 后端
    旧实现缺少该检查，会把 corrupted raw vtype 按低 8 位解码出的形状
    继续执行；统一共享发射器后两种行为必须一致。
    """
    state = StateTracker(vlenb=128)
    alloc = SimulatedStateLayout()
    insn = RVInstruction(0, 'vsetvl', operands=['zero','zero','a0'], op_str='vsetvl zero, zero, a0', )
    lines = _invoke_builder(_build_vsetvl_lines, insn, state, alloc)
    code = '\n'.join(lines)
    assert 'vtype 保留位非零' in code
    # vill 收尾必须写 vill 位并把 vl 清零。
    assert 'vill bit for RV64' in code
    assert 'CSR.vl = 0' in code

def test_vsetvli_x0_x0_keeps_vl_without_static_vlmax_reject():
    state = StateTracker(vlenb=128); state.sew = 64; state.lmul = 1.0
    alloc = SimulatedStateLayout()
    insn = RVInstruction(0, 'vsetvli', operands=['zero','zero','e32','m1','ta','ma'],
                          op_str='vsetvli zero, zero, e32, m1, ta, ma', )
    lines = _invoke_builder(_build_vsetvli_lines, insn, state, alloc)
    code = '\n'.join(lines)
    assert '# vl unchanged' in code
    assert '# ERROR' not in code
    assert 'runtime check: vsetvli x0,x0 requires unchanged VLMAX' in code
    assert 'old CSR.vtype for x0,x0 VLMAX check' in code
    assert 'new VLMAX' in code
    assert 'ebreak' in code
    assert 'CSR.vtype = vtype' in code
    assert 'CSR.vl = VLMAX' not in code
    assert 'CSR.vl = VL' not in code
    assert state.sew == 32 and state.lmul == 1.0

def test_vsetvli_x0_x0_fractional_lmul_equal_vlmax():
    state = StateTracker(vlenb=128); state.sew = 8; state.lmul = 0.5
    alloc = SimulatedStateLayout()
    insn = RVInstruction(0, 'vsetvli', operands=['zero','zero','e16','m1','ta','mu'],
                          op_str='vsetvli zero, zero, e16, m1, ta, mu', )
    lines = _invoke_builder(_build_vsetvli_lines, insn, state, alloc)
    code = '\n'.join(lines)
    assert '# ERROR' not in code
    assert 'runtime check: vsetvli x0,x0 requires unchanged VLMAX' in code
    # 分数 LMUL 走右移分支（共享 vtype_decode 发射器）。
    assert '# 分数 LMUL' in code
    assert 'new VLMAX' in code and ', 64' in code
    assert 'lmul-4' not in code
    assert 'lmul_enc-4' not in code
    assert 'lmul_enc - 4' not in code
    assert '# vl unchanged' in code

def test_vsetvli_x0_x0_translate_honors_init_vtype():
    from rvv_sbt_rvv import translate
    insn = RVInstruction(0, 'vsetvli', operands=['zero','zero','e32','mf2','ta','ma'],
                          op_str='vsetvli zero, zero, e32, mf2, ta, ma', )

    result = translate([insn], init_vtype='0', raw=True)
    assert '# vl unchanged' in result
    assert '# ERROR' not in result
    assert 'runtime check: vsetvli x0,x0 requires unchanged VLMAX' in result
    assert 'old CSR.vtype for x0,x0 VLMAX check' in result
    assert 'CSR.vtype = vtype' in result

def test_single_function_tls_state_base_load():
    from rvv_sbt_rvv import translate
    from riscv.extensions.rvv.runtime.contract import RVV1024_TO_RVV256
    insn = RVInstruction(0, 'vsetvli', operands=['a5','a4','e32','mf2','ta','ma'],
                          op_str='vsetvli a5, a4, e32, mf2, ta, ma', )
    result = translate([insn], init_vtype='0xd7', text_only=True, tls_state=True)
    assert f'la.tls.ie t6, {RVV1024_TO_RVV256.state_symbol}' in result
    assert 'add     t6, t6, tp' in result
    assert 'get_simulated_cpu_state_addr@plt' not in result
    assert 'la      t6, simulated_cpu_state_ptr' not in result

def test_t6_scalar_input_is_aliased_from_state_base():
    from rvv_sbt_rvv import translate
    insn = RVInstruction(0, 'vlse16.v', operands=['v18','(a4)','t6'],
                          op_str='vlse16.v v18, (a4), t6', )
    result = translate([insn], init_vtype='sew=16,lmul=1', text_only=True)
    match = re.search(r"vlse16\.v v24, \(t3\), (\w+)", result)
    assert match is not None
    stride_alias = match.group(1)
    assert stride_alias != 't6'
    assert f'ld      {stride_alias}, ' in result
    assert f'mul     t5, t5, {stride_alias}' in result
    assert 'add     t1, t6, t1' in result


def test_fast_state_pointer_keeps_tls_base_when_t6_is_semantic_input():
    """whole-register 快路径不能把状态槽地址错改成源程序的 t6 基址。"""
    from rvv_sbt_rvv import translate

    insn = RVInstruction(
        0,
        'vl1r.v',
        operands=['v8', '(t6)'],
        op_str='vl1r.v v8, (t6)',
    )
    result = translate([insn], init_vtype='sew=8,lmul=1', text_only=True)

    # wrapper 为源语义 t6 保存别名；客体访存必须使用该别名。
    # 保守 profile 的 whole-register 临时组固定为既有 legacy 池 v24-v31。
    match = re.search(r"^\s*vl4r\.v\s+v24,\s*\((\w+)\)", result, re.MULTILINE)
    assert match is not None
    semantic_t6_alias = match.group(1)
    assert semantic_t6_alias != 't6'

    # 状态 v8 的偏移是 0x400，故 store 的基址计算必须继续引用 TLS state
    # base t6，而不能引用上面的源程序 t6 别名。
    assert re.search(
        r"^\s*addi\s+\w+,\s*t6,\s*1024\s+# CHIMERA_STATE_BASE$",
        result,
        re.MULTILINE,
    )
    assert not re.search(
        rf"^\s*addi\s+\w+,\s*{semantic_t6_alias},\s*1024\b",
        result,
        re.MULTILINE,
    )

def test_t6_config_input_output_keeps_new_output():
    from rvv_sbt_rvv import translate
    insn = RVInstruction(0, 'vsetvli', operands=['t6','t6','e32','m1','ta','ma'],
                          op_str='vsetvli t6, t6, e32, m1, ta, ma', )
    result = translate([insn], init_vtype='sew=32,lmul=1', text_only=True)
    assert 'mv      t6,' in result
    assert 'ld      t6,' not in result
    assert re.search(r"bltu\s+\w+,\s+(?!t6)\w+,", result) is not None

def test_vsetivli_rejects_unsupported_static_vtype():
    state = StateTracker(vlenb=128); state.sew = 64
    alloc = SimulatedStateLayout()
    insn = RVInstruction(0, 'vsetivli', operands=['a0','1','e128','m1','ta','ma'],
                          op_str='vsetivli a0, 1, e128, m1, ta, ma', )
    with pytest.raises(InstructionValidationError, match='supports SEW=8/16/32/64 only'):
        _invoke_builder(_build_vsetivli_lines, insn, state, alloc)
    assert state.sew == 64

def test_vector_completion_clears_vstart():
    from rvv_sbt_rvv import translate
    insn = RVInstruction(0, 'vmul.vx', operands=['v4','v2','a1'], op_str='vmul.vx v4, v2, a1', )
    result = translate([insn], init_vtype='sew=32,lmul=1', raw=True)
    assert 'CSR.vstart = 0 after vector completion' in result

def test_rvv256_emitter_preserves_temps_not_scalar_output():
    from rvv_sbt_rvv import translate
    insn = RVInstruction(0, 'vfirst.m', operands=['a4','v1'], op_str='vfirst.m a4, v1', )
    result = translate([insn], init_vtype='sew=32,lmul=1')
    assert '保存 RVV 翻译块现场: vfirst.m' in result
    assert '恢复 RVV 翻译块现场: vfirst.m' in result
    assert 'sd      t0,' in result and 'ld      t0,' in result
    assert 'sd      a4,' not in result
    assert 'ld      a4,' not in result
    assert re.search(r"(?m)^\s*(?:li|add)\s+a4,", result)

def test_rvv256_emitter_preserves_original_sp_for_stack_memory_operand():
    from rvv_sbt_rvv import translate
    insn = RVInstruction(0, 'vse64.v', operands=['v1','(sp)'], op_str='vse64.v v1, (sp)', )
    result = translate([insn], init_vtype='sew=64,lmul=1')
    assert '保留原程序 sp 作为向量访存基址' in result
    assert 'mv      t3, sp' not in result
    assert 'mv      t3, t5' in result
    assert 'addi    t5, sp,' in result
    assert 'sd      t5,' in result and 'ld      t5,' in result

def test_rvv256_masked_form_fails_fast():
    from rvv_sbt_rvv import translate
    insn = RVInstruction(0, 'vadd.vv', operands=['v4','v2','v3','v0.t'],
                         op_str='vadd.vv v4, v2, v3, v0.t', )
    result = translate([insn], init_vtype='sew=32,lmul=1', raw=True)
    assert 'vmv.v.x' in result
    assert 'vadd.vv' in result
    assert 'v0.t' in result
    assert ', v0.t' in result # Make sure suffix is correctly added
    assert 'vse32.v' in result and ', v0.t' in result # Assert writeback has mask

def test_next_batch_rvv256_dispatch():
    from riscv.extensions.rvv.backends.rvv256.backend import RVV256Dispatcher
    disp = RVV256Dispatcher()
    for opcode in ['vlm.v', 'vmsne.vv', 'vmsne.vi', 'vmseq.vi',
                   'vmsle.vi', 'vmsleu.vi', 'vmsleu.vv', 'vmsltu.vv', 'vmor.mm',
                   'vfirst.m', 'vmerge.vvm', 'vle8ff.v',
                   'vmul.vx', 'vrsub.vi', 'vlse16.v', 'vlse32.v', 'vlse64.v',
                   'vsseg2e32.v', 'vmsgtu.vi', 'vwmul.vv', 'vwmacc.vx', 'vsub.vx',
                   'vmaxu.vv', 'vand.vx', 'vfwcvt.f.x.v', 'vredmaxu.vs',
                   'vwmacc.vv', 'vsra.vi', 'vmacc.vx',
                   'vluxei16.v', 'vmv4r.v', 'vwmulu.vx', 'vwmulu.vv',
                   'vsrl.vv', 'vwcvt.x.x.v',
                   'vslidedown.vx', 'vl2r.v', 'vfmadd.vf', 'vwmulsu.vv',
                   'vl4re16.v', 'vl4re32.v',
                   'vmv.v.v', 'vmsgtu.vx', 'vmnot.m', 'vdiv.vx', 'vwadd.vv',
                   'vslideup.vi', 'vl4re64.v', 'vmv8r.v', 'vmacc.vv', 'vlse8.v',
                   'vmsltu.vx', 'vmand.mm', 'vl8re64.v', 'vslide1up.vx',
                   'vslide1down.vx', 'vl8re32.v']:
        assert disp.registry.get(opcode) is not None, f"{opcode} not registered"

def test_vlm_v_bitpacked_mask_load():
    from rvv_sbt_rvv import translate
    insn = RVInstruction(0, 'vlm.v', operands=['v1','(a0)'], op_str='vlm.v v1, (a0)', )
    result = translate([insn], init_vtype='sew=8,lmul=1', raw=True)
    assert 'ceil(vl / 8)' in result
    assert 'lbu' in result and 'sb' in result

def test_mask_compare_logic_and_first():
    from rvv_sbt_rvv import translate
    cases = [
        RVInstruction(0, 'vmsne.vv', operands=['v1','v2','v3'], op_str='vmsne.vv v1, v2, v3', ),
        RVInstruction(0, 'vmsne.vi', operands=['v1','v2','7'], op_str='vmsne.vi v1, v2, 7', ),
        RVInstruction(0, 'vmseq.vi', operands=['v1','v2','-1'], op_str='vmseq.vi v1, v2, -1', ),
        RVInstruction(0, 'vmsle.vi', operands=['v1','v2','-3'], op_str='vmsle.vi v1, v2, -3', ),
        RVInstruction(0, 'vmsleu.vi', operands=['v1','v2','-1'], op_str='vmsleu.vi v1, v2, -1', ),
        RVInstruction(0, 'vmsgtu.vi', operands=['v1','v2','3'], op_str='vmsgtu.vi v1, v2, 3', ),
        RVInstruction(0, 'vmsleu.vv', operands=['v1','v2','v3'], op_str='vmsleu.vv v1, v2, v3', ),
        RVInstruction(0, 'vmsltu.vv', operands=['v1','v2','v3'], op_str='vmsltu.vv v1, v2, v3', ),
        RVInstruction(0, 'vmor.mm', operands=['v1','v2','v3'], op_str='vmor.mm v1, v2, v3', ),
        RVInstruction(0, 'vfirst.m', operands=['a0','v1'], op_str='vfirst.m a0, v1', ),
    ]
    result = translate(cases, init_vtype='sew=8,lmul=1', raw=True)
    assert 'RVV1.0 bit-packed mask' in result
    assert 'snez' in result and 'seqz' in result
    assert 'vmsne.vi' in result and '!= 7' in result
    assert 'vmsle.vi' in result and 'slt     ' in result
    assert 'vmsleu.vi' in result and 'sltu' in result
    assert 'vmsgtu.vi' in result and '> unsigned(3)' in result
    assert 'vmsleu.vv' in result and '< v2[i]) unsigned' in result
    assert 'vmsltu.vv' in result and 'unsigned(v2[i]) < unsigned(v3[i])' in result
    assert 'or      ' in result
    assert 'li      a0, -1' in result
    assert '255' in result  # vi -1 sign-extended to e8 bit pattern

def test_vmerge_vvm_uses_v0_selector():
    from rvv_sbt_rvv import translate
    insn = RVInstruction(0, 'vmerge.vvm', operands=['v4','v2','v3','v0'], op_str='vmerge.vvm v4, v2, v3, v0', )
    result = translate([insn], init_vtype='sew=32,lmul=1', raw=True)
    assert 'v0.mask[i] ? v3[i] : v2[i]' in result
    assert 'selector true: vs1' in result
    assert 'selector false: vs2' in result

def test_vmerge_vxm_and_vim_use_v0_selector():
    from rvv_sbt_rvv import translate
    cases = [
        RVInstruction(0, 'vmerge.vxm', operands=['v4','v2','a0','v0'], op_str='vmerge.vxm v4, v2, a0, v0', ),
        RVInstruction(0, 'vmerge.vim', operands=['v6','v4','-3','v0'], op_str='vmerge.vim v6, v4, -3, v0', ),
    ]
    result = translate(cases, init_vtype='sew=32,lmul=1', raw=True)
    assert 'vmerge.vxm v4, v2, a0, v0' in result
    assert 'vmerge.vim v6, v4, -3, v0' in result
    assert 'v0.mask[i] ? scalar a0 : v2[i]' in result
    assert 'v0.mask[i] ? imm -3 : v4[i]' in result
    assert 'selector true: scalar' in result
    assert 'selector true: imm' in result
    assert 'selector false: vs2' in result

def test_vle8ff_v_fault_only_first_chunk_path():
    from rvv_sbt_rvv import translate
    insn = RVInstruction(0, 'vle8ff.v', operands=['v8','(a0)'], op_str='vle8ff.v v8, (a0)', )
    result = translate([insn], init_vtype='sew=8,lmul=1', raw=True)
    assert 'RVV1.0 fault-only-first' in result
    assert 'vle8ff.v' in result and 'vse8.v' in result
    assert 'csrr' in result and 'CSR.vl = loaded count after FOF trim' in result

def test_integer_vx_vi_next_batch():
    from rvv_sbt_rvv import translate
    cases = [
        RVInstruction(0, 'vmul.vv', operands=['v8','v2','v3'], op_str='vmul.vv v8, v2, v3', ),
        RVInstruction(0, 'vmadd.vv', operands=['v10','v8','v2'], op_str='vmadd.vv v10, v8, v2', ),
        RVInstruction(0, 'vmacc.vx', operands=['v12','a1','v10'], op_str='vmacc.vx v12, a1, v10', ),
        RVInstruction(0, 'vmul.vx', operands=['v4','v2','a1'], op_str='vmul.vx v4, v2, a1', ),
        RVInstruction(0, 'vsub.vx', operands=['v6','v4','a2'], op_str='vsub.vx v6, v4, a2', ),
        RVInstruction(0, 'vrsub.vi', operands=['v6','v4','3'], op_str='vrsub.vi v6, v4, 3', ),
    ]
    result = translate(cases, init_vtype='sew=32,lmul=1', raw=True)
    assert 'vmul.vv v26, v24, v25' in result
    assert 'vmadd.vv v24, v25, v26' in result
    assert 'old v10[i] * v8[i] + v2[i]' in result
    assert 'vmacc.vx v24, a1, v25' in result
    assert 'a1 * v10[i] + old v12[i]' in result
    assert 'vmul.vx' in result and 'mul     ' in result
    assert 'vsub.vx' in result and '- a2' in result
    assert 'vrsub.vi' in result and 'sub     ' in result
    assert '尾部 RVV chunk' in result

def test_vand_vv_and_vi_paths():
    from rvv_sbt_rvv import translate
    cases = [
        RVInstruction(0, 'vand.vv', operands=['v4','v2','v3'], op_str='vand.vv v4, v2, v3', ),
        RVInstruction(0, 'vand.vi', operands=['v6','v4','-16'], op_str='vand.vi v6, v4, -16', ),
        RVInstruction(0, 'vand.vx', operands=['v14','v12','a1'], op_str='vand.vx v14, v12, a1', ),
        RVInstruction(0, 'vandn.vv', operands=['v8','v6','v2'], op_str='vandn.vv v8, v6, v2', ),
        RVInstruction(0, 'vor.vv', operands=['v10','v8','v4'], op_str='vor.vv v10, v8, v4', ),
        RVInstruction(0, 'vnot.v', operands=['v12','v10'], op_str='vnot.v v12, v10', ),
    ]
    result = translate(cases, init_vtype='sew=32,lmul=1', raw=True)
    assert 'vand.vv v26, v24, v25' in result
    assert 'vand.vi v25, v24, -16' in result
    assert 'vand.vx v25, v24, a1' in result
    assert 'vxor.vi v25, v25, -1' in result
    assert 'vandn.vv v26, v24, v25' not in result
    assert 'vor.vv  v26, v24, v25' in result
    assert 'vxor.vi v25, v24, -1' in result
    assert 'v8[i] = v6[i] & ~v2[i]' in result
    assert 'v12[i] = ~v10[i]' in result
    assert '尾部 RVV chunk' in result
    assert 'vsetvli zero,' in result
    assert 'sign_extend(-16)' in result

def test_vmax_vv_path():
    from rvv_sbt_rvv import translate
    cases = [
        RVInstruction(0, 'vmax.vv', operands=['v4','v2','v3'], op_str='vmax.vv v4, v2, v3', ),
        RVInstruction(0, 'vmaxu.vv', operands=['v6','v4','v5'], op_str='vmaxu.vv v6, v4, v5', ),
    ]
    result = translate(cases, init_vtype='sew=32,lmul=1', raw=True)
    assert 'vmax.vv v26, v24, v25' in result
    assert 'vmaxu.vv v26, v24, v25' in result
    assert 'max_signed(v2[i], v3[i])' in result
    assert 'max_unsigned(v4[i], v5[i])' in result
    assert '尾部 RVV chunk' in result
    assert 'vsetvli zero,' in result

def test_vector_shift_vv_vx_paths():
    from rvv_sbt_rvv import translate
    cases = [
        RVInstruction(0, 'vsll.vv', operands=['v4','v2','v3'], op_str='vsll.vv v4, v2, v3', ),
        RVInstruction(0, 'vsll.vx', operands=['v6','v4','a1'], op_str='vsll.vx v6, v4, a1', ),
        RVInstruction(0, 'vsrl.vx', operands=['v8','v6','a2'], op_str='vsrl.vx v8, v6, a2', ),
        RVInstruction(0, 'vsra.vi', operands=['v10','v8','3'], op_str='vsra.vi v10, v8, 3', ),
    ]
    result = translate(cases, init_vtype='sew=32,lmul=1', raw=True)
    assert 'vsll.vv v26, v24, v25' in result
    assert 'vsll.vx v25, v24' in result
    assert 'vsrl.vx v25, v24' in result
    assert 'vsra.vi v25, v24, 3' in result
    assert 'signed(v8[i]) >> 3' in result
    assert 'RVV 指令按 SEW 自动取低位' in result
    assert '尾部 RVV chunk' in result
    assert 'vsetvli zero,' in result

def test_vwsll_vi_widening_shift_path():
    from rvv_sbt_rvv import translate
    insn = RVInstruction(0, 'vwsll.vi', operands=['v4','v2','3'], op_str='vwsll.vi v4, v2, 3', )
    result = translate([insn], init_vtype='sew=16,lmul=1', raw=True)
    assert 'vwsll.vi v26, v24, 3' in result
    assert 'vle16.v v24' in result
    assert 'vse32.v v26' in result
    assert 'e16 -> e32' in result
    assert 'LMUL=mf2' in result
    assert '尾部 RVV widening chunk' in result
    assert '尾部标量回退' not in result

def test_vwaddu_wv_widening_add_path():
    from rvv_sbt_rvv import translate
    insn = RVInstruction(0, 'vwaddu.wv', operands=['v4','v2','v6'], op_str='vwaddu.wv v4, v2, v6', )
    result = translate([insn], init_vtype='sew=16,lmul=1', raw=True)
    assert 'vwaddu.wv v26, v24, v25' in result
    assert 'vle32.v v24' in result
    assert 'vle16.v v25' in result
    assert 'vse32.v v26' in result
    assert 'e16 -> e32' in result
    assert 'wide + zext(narrow)' in result
    assert '尾部 RVV widening add chunk' in result

def test_vfadd_vf_and_vfmadd_vv_paths():
    from rvv_sbt_rvv import translate
    cases = [
        RVInstruction(0, 'vfadd.vf', operands=['v4','v2','fa0'], op_str='vfadd.vf v4, v2, fa0', ),
        RVInstruction(0, 'vfsub.vf', operands=['v8','v4','fa1'], op_str='vfsub.vf v8, v4, fa1', ),
        RVInstruction(0, 'vfmadd.vv', operands=['v6','v4','v8'], op_str='vfmadd.vv v6, v4, v8', ),
        RVInstruction(0, 'vfmsub.vv', operands=['v10','v6','v4'], op_str='vfmsub.vv v10, v6, v4', ),
    ]
    result = translate(cases, init_vtype='sew=32,lmul=1', raw=True)
    assert 'vfadd.vf v25, v24, fa0' in result
    assert 'vfsub.vf v25, v24, fa1' in result
    assert 'vfmadd.vv v24, v25, v26' in result
    assert 'vfmsub.vv v24, v25, v26' in result
    assert 'v8[i] = v4[i] - fa1' in result
    assert 'old v6[i] * v4[i] + v8[i]' in result
    assert 'old v10[i] * v6[i] - v4[i]' in result
    assert '尾部 RVV chunk' in result
    assert 'vsetvli zero,' in result

def test_vfmax_min_vv_paths():
    from rvv_sbt_rvv import translate
    cases = [
        RVInstruction(0, 'vfmax.vv', operands=['v4','v2','v3'], op_str='vfmax.vv v4, v2, v3', ),
        RVInstruction(0, 'vfmin.vv', operands=['v6','v4','v8'], op_str='vfmin.vv v6, v4, v8', ),
    ]
    result = translate(cases, init_vtype='sew=32,lmul=1', raw=True)
    assert 'vfmax.vv v26, v24, v25' in result
    assert 'vfmin.vv v26, v24, v25' in result
    assert 'v4[i] = maxNum(v2[i], v3[i])' in result
    assert 'v6[i] = minNum(v4[i], v8[i])' in result
    assert '尾部 RVV chunk' in result
    assert 'vsetvli zero,' in result

def test_vfmv_s_f_writes_element_zero_when_vl_nonzero():
    from rvv_sbt_rvv import translate
    insn = RVInstruction(0, 'vfmv.s.f', operands=['v4','fa0'], op_str='vfmv.s.f v4, fa0', )
    result = translate([insn], init_vtype='sew=32,lmul=1', raw=True)
    assert 'vfmv.s.f v24, fa0' in result
    assert 'vl=0' in result and '不更新目标' in result
    assert 'vsetivli zero, 1, e32, m1, ta, ma' in result
    assert '只写回 element 0' in result

def test_vfdiv_vv_path():
    from rvv_sbt_rvv import translate
    insn = RVInstruction(0, 'vfdiv.vv', operands=['v16','v8','v4'], op_str='vfdiv.vv v16, v8, v4', )
    result = translate([insn], init_vtype='sew=32,lmul=1', raw=True)
    assert 'vfdiv.vv v26, v24, v25' in result
    assert 'v16[i] = v8[i] / v4[i]' in result
    assert '尾部 RVV chunk' in result
    assert 'vsetvli zero,' in result

def test_vfmsac_vv_path():
    from rvv_sbt_rvv import translate
    insn = RVInstruction(0, 'vfmsac.vv', operands=['v6','v4','v8'], op_str='vfmsac.vv v6, v4, v8', )
    result = translate([insn], init_vtype='sew=32,lmul=1', raw=True)
    assert 'vfmsac.vv v24, v25, v26' in result
    assert 'v6[i] = v4[i] * v8[i] - old v6[i]' in result
    assert 'subtrahend' in result
    assert '尾部 RVV chunk' in result

def test_vfredmax_min_vs_paths():
    from rvv_sbt_rvv import translate
    cases = [
        RVInstruction(0, 'vfredmax.vs', operands=['v8','v16','v1'], op_str='vfredmax.vs v8, v16, v1', ),
        RVInstruction(0, 'vfredmin.vs', operands=['v10','v18','v3'], op_str='vfredmin.vs v10, v18, v3', ),
    ]
    result = translate(cases, init_vtype='sew=32,lmul=1', raw=True)
    assert 'vfredmax.vs v25, v24, v25' in result
    assert 'vfredmin.vs v25, v24, v25' in result
    assert 'fredmax(v16[0:vl], v1[0])' in result
    assert 'fredmin(v18[0:vl], v3[0])' in result
    assert '尾部 RVV reduction chunk' in result

def test_vfwred_ordered_unordered_sum_paths():
    from rvv_sbt_rvv import translate
    cases = [
        RVInstruction(0, 'vfwredosum.vs', operands=['v8','v16','v1'], op_str='vfwredosum.vs v8, v16, v1', ),
        RVInstruction(0, 'vfwredusum.vs', operands=['v10','v18','v3'], op_str='vfwredusum.vs v10, v18, v3', ),
    ]
    result = translate(cases, init_vtype='sew=32,lmul=1', raw=True)
    assert 'vfwredosum.vs v25, v24, v25' in result
    assert 'vfwredusum.vs v25, v24, v25' in result
    assert 'widen-reduce-ordered-sum(v16[0:vl], v1[0])' in result
    assert 'widen-reduce-unordered-sum(v18[0:vl], v3[0])' in result
    assert 'e32->e64' in result
    assert '尾部 RVV widening reduction chunk' in result
    
    result_e16 = translate(cases, init_vtype='sew=16,lmul=1', raw=True)
    assert 'vfwredosum.vs v25, v24, v25' in result_e16
    assert 'widen-reduce-ordered-sum(v16[0:vl], v1[0])' in result_e16
    assert 'e16->e32' in result_e16
    assert 'vsetivli zero, 1, e32, m1, ta, ma' in result_e16
    assert 'vfmv.s.f v25, ft0' in result_e16
    assert 'vfmv.f.s ft0, v25' in result_e16

    result_ambiguous = translate(
        [RVInstruction(0, 'vfwredusum.vs', operands=['v8','v2','v8'],
                       op_str='vfwredusum.vs v8, v2, v8', )],
        init_vtype='sew=64,lmul=1',
        raw=True,
    )
    assert 'runtime vtype dispatch' not in result_ambiguous
    assert 'vfwredusum.vs does not support SEW=64' in result_ambiguous
    assert 'fallback to ebreak' in result_ambiguous

def test_vwredsum_vs_supports_e8_e16_e32():
    from rvv_sbt_rvv import translate
    cases = [
        ('sew=8,lmul=1', 'lh', 'sh', 'e8 -> e16'),
        ('sew=16,lmul=1', 'lw', 'sw', 'e16 -> e32'),
        ('sew=32,lmul=1', 'ld', 'sd', 'e32 -> e64'),
    ]
    for init_vtype, seed_load, result_store, width_note in cases:
        insn = RVInstruction(0, 'vwredsum.vs', operands=['v8','v16','v1'],
                             op_str='vwredsum.vs v8, v16, v1', )
        result = translate([insn], init_vtype=init_vtype, raw=True)
        assert 'vwredsum.vs v8, v16, v1' in result
        assert width_note in result
        assert seed_load in result
        assert result_store in result
        if init_vtype.startswith('sew=8'):
            assert 'CHIMERA_INTERNAL_STACK' in result
            assert 'addi    sp, sp, -32              # CHIMERA_INTERNAL_STACK' in result
            assert 'addi    sp, sp, 32               # CHIMERA_INTERNAL_STACK release' in result
            assert '保留原程序 sp' not in result

def test_vwredsum_vs_rejects_e64():
    from rvv_sbt_rvv import translate
    insn = RVInstruction(0, 'vwredsum.vs', operands=['v8','v16','v1'],
                         op_str='vwredsum.vs v8, v16, v1', )
    result = translate([insn], init_vtype='sew=64,lmul=1', raw=True)
    assert '# RVV256 fallback:' in result
    assert 'does not support SEW=64' in result
    assert 'ebreak' in result

def test_vredsum_and_vredor_vs_paths():
    from rvv_sbt_rvv import translate
    cases = [
        RVInstruction(0, 'vredsum.vs', operands=['v8','v16','v1'], op_str='vredsum.vs v8, v16, v1', ),
        RVInstruction(0, 'vredor.vs', operands=['v10','v18','v3'], op_str='vredor.vs v10, v18, v3', ),
        RVInstruction(0, 'vredmaxu.vs', operands=['v12','v20','v5'], op_str='vredmaxu.vs v12, v20, v5', ),
    ]
    result = translate(cases, init_vtype='sew=32,lmul=1', raw=True)
    assert 'vredsum.vs v25, v24, v25' in result
    assert 'vredor.vs v25, v24, v25' in result
    assert 'vredmaxu.vs v25, v24, v25' in result
    assert 'redsum(v16[0:vl], v1[0])' in result
    assert 'redor(v18[0:vl], v3[0])' in result
    assert 'redmax_unsigned(v20[0:vl], v5[0])' in result
    assert 'vmv.s.x' in result and 'vmv.x.s' in result
    assert '尾部 RVV integer reduction chunk' in result

def test_whole_register_move_and_store_paths():
    from rvv_sbt_rvv import translate
    cases = [
        RVInstruction(0, 'vmv1r.v', operands=['v8','v16'], op_str='vmv1r.v v8, v16', ),
        RVInstruction(0, 'vmv2r.v', operands=['v10','v18'], op_str='vmv2r.v v10, v18', ),
        RVInstruction(0, 'vs1r.v', operands=['v8','(a0)'], op_str='vs1r.v v8, (a0)', ),
        RVInstruction(0, 'vs2r.v', operands=['v2','(a4)'], op_str='vs2r.v v2, (a4)', ),
        RVInstruction(0, 'vs4r.v', operands=['v4','(a5)'], op_str='vs4r.v v4, (a5)', ),
        RVInstruction(0, 'vs8r.v', operands=['v8','(a6)'], op_str='vs8r.v v8, (a6)', ),
    ]
    result = translate(cases, init_vtype='sew=32,lmul=1', raw=True)
    assert result.count('RVV256-NATIVE-WHOLE:') == 2
    assert result.count('RVV256-NATIVE-WHOLE-MEM:') == 4
    assert 'UNIMPLEMENTED: vs2r.v' not in result
    assert 'vsetvli' not in result
    assert 'vle32.v' not in result and 'vse32.v' not in result
    assert 'vl4r.v v24' in result and 'vs4r.v v24' in result
    assert 'vl8r.v v24' in result and 'vs8r.v v24' in result

def test_whole_register_1r_load_paths():
    from rvv_sbt_rvv import translate
    cases = [
        RVInstruction(0, 'vl1r.v', operands=['v8','(a0)'], op_str='vl1r.v v8, (a0)', ),
        RVInstruction(0, 'vl1re16.v', operands=['v9','(a1)'], op_str='vl1re16.v v9, (a1)', ),
        RVInstruction(0, 'vl1re64.v', operands=['v10','(a2)'], op_str='vl1re64.v v10, (a2)', ),
    ]
    result = translate(cases, init_vtype='sew=32,lmul=1', raw=True)
    assert result.count('RVV256-NATIVE-WHOLE-MEM:') == 3
    assert 'vsetvli' not in result
    # re16/re64 不是纯布局注释；目标 load 保留相同 EEW 以避免改变对齐异常。
    assert 'vl4r.v v24, (a0)' in result
    assert 'vl4re16.v v24, (a1)' in result
    assert 'vl4re64.v v24, (a2)' in result
    assert len(re.findall(r'(?m)^\s*vs4r\.v\s+v24,', result)) == 3


def test_whole_register_next_load_paths():
    from rvv_sbt_rvv import translate
    cases = [
        RVInstruction(0, 'vl1re32.v', operands=['v3','(sp)'], op_str='vl1re32.v v3, (sp)', ),
        RVInstruction(4, 'vl2r.v', operands=['v8','(s4)'], op_str='vl2r.v v8, (s4)', ),
        RVInstruction(8, 'vl2re16.v', operands=['v12','(s0)'], op_str='vl2re16.v v12, (s0)', ),
        RVInstruction(12, 'vl4re16.v', operands=['v4','(a4)'], op_str='vl4re16.v v4, (a4)', ),
        RVInstruction(16, 'vl4re32.v', operands=['v8','(t6)'], op_str='vl4re32.v v8, (t6)', ),
    ]
    result = translate(cases, init_vtype='sew=32,lmul=1', raw=True)
    assert 'UNIMPLEMENTED:' not in result
    assert result.count('RVV256-NATIVE-WHOLE-MEM:') == 5
    assert 'vsetvli' not in result
    assert re.search(r'(?m)^\s*vl4re32\.v\s+v24,', result)
    assert 'vl8r.v v24, (s4)' in result
    assert 'vl8re16.v v24, (s0)' in result
    assert len(re.findall(r'(?m)^\s*vl8re16\.v\s+v24,', result)) == 3
    assert len(re.findall(r'(?m)^\s*vl8re32\.v\s+v24,', result)) == 2


def test_llama_fragment_fallback_opcodes():
    from rvv_sbt_rvv import translate
    cases = [
        RVInstruction(0, 'vl2re32.v', operands=['v2','(a1)'], op_str='vl2re32.v v2, (a1)', ),
        RVInstruction(4, 'vmseq.vx', operands=['v1','v1','a2'], op_str='vmseq.vx v1, v1, a2', ),
        RVInstruction(8, 'vsm.v', operands=['v1','(a3)'], op_str='vsm.v v1, (a3)', ),
        RVInstruction(12, 'vsub.vx', operands=['v1','v2','a5','v0.t'], op_str='vsub.vx v1, v2, a5, v0.t', ),
    ]
    result = translate(cases, init_vtype='sew=32,lmul=1', raw=True)
    assert 'UNIMPLEMENTED:' not in result
    assert 'RVV256 masked form is not implemented yet' not in result
    assert 'RVV256-NATIVE-WHOLE-MEM: vl2re32.v' in result
    assert 'vl8re32.v v24, (a1)' in result
    assert 'vmseq.vx v1, v1, a2' in result
    assert 'mask bit = (v1[i] == a2)' in result
    assert 'vsm.v v1, (a3)' in result
    assert 'store ceil(vl / 8) mask bytes from v1 to mem[a3]' in result
    assert 'vsub.vx v25, v24,' in result and ', v0.t' in result
    assert 'vmv.v.x v0' in result


def test_llama_first_batch_fallback_opcodes():
    from rvv_sbt_rvv import translate
    cases = [
        RVInstruction(0, 'vluxei16.v', operands=['v8','(a0)','v2'], op_str='vluxei16.v v8, (a0), v2', ),
        RVInstruction(4, 'vmv4r.v', operands=['v4','v8'], op_str='vmv4r.v v4, v8', ),
        RVInstruction(8, 'vwmulu.vx', operands=['v12','v10','a1'], op_str='vwmulu.vx v12, v10, a1', ),
        RVInstruction(12, 'vwmulu.vv', operands=['v16','v12','v14'], op_str='vwmulu.vv v16, v12, v14', ),
        RVInstruction(16, 'vsrl.vv', operands=['v20','v16','v18'], op_str='vsrl.vv v20, v16, v18', ),
        RVInstruction(20, 'vwcvt.x.x.v', operands=['v22','v20'], op_str='vwcvt.x.x.v v22, v20', ),
    ]
    result = translate(cases, init_vtype='sew=32,lmul=1', raw=True)
    assert 'UNIMPLEMENTED:' not in result
    assert 'vluxei16.v v8, (a0), v2' in result
    assert 'index EEW=16' in result and 'byte offset = u16(v2[i])' in result
    assert 'RVV256-NATIVE-WHOLE: vmv4r.v' in result
    assert len(re.findall(r'(?m)^\s*vl8r\.v\s+v24,', result)) >= 2
    assert 'vwmulu.vx' in result and 'zero-extend scalar to XLEN' in result
    assert 'vwmulu.vv' in result and 'unsigned widening multiply' in result
    assert 'vsrl.vv' in result and '>>' in result
    assert 'vwcvt.x.x.v' in result and 'sign_extend' in result


def test_llama_second_batch_fallback_opcodes():
    from rvv_sbt_rvv import translate
    cases = [
        RVInstruction(0, 'vslidedown.vx', operands=['v4','v4','a5'], op_str='vslidedown.vx v4, v4, a5', ),
        RVInstruction(4, 'vl2r.v', operands=['v24','(s1)'], op_str='vl2r.v v24, (s1)', ),
        RVInstruction(8, 'vfmadd.vf', operands=['v8','fa5','v16'], op_str='vfmadd.vf v8, fa5, v16', ),
        RVInstruction(12, 'vwmulsu.vv', operands=['v28','v14','v18'], op_str='vwmulsu.vv v28, v14, v18', ),
        RVInstruction(16, 'vl4re16.v', operands=['v20','(s1)'], op_str='vl4re16.v v20, (s1)', ),
        RVInstruction(20, 'vl4re32.v', operands=['v4','(a4)'], op_str='vl4re32.v v4, (a4)', ),
    ]
    result = translate(cases, init_vtype='sew=32,lmul=1', raw=True)
    assert 'UNIMPLEMENTED:' not in result
    assert 'vslidedown.vx v4, v4, a5' in result
    assert 'runtime slide offset in elements' in result
    assert 'offset >= VLMAX: zero-fill all active elements' in result
    assert 'RVV256-NATIVE-WHOLE-MEM: vl2r.v' in result
    assert 'vl8r.v v24, (s1)' in result
    assert 'vfmadd.vf v8, fa5, v16' in result
    assert 'old v8[i] * fa5 + v16[i]' in result
    assert 'vwmulsu.vv v28, v14, v18' in result
    assert 'signed * unsigned widening multiply' in result
    assert 'RVV256-NATIVE-WHOLE-MEM: vl4re16.v' in result
    assert 'RVV256-NATIVE-WHOLE-MEM: vl4re32.v' in result
    assert len(re.findall(r'(?m)^\s*vl8re16\.v\s+v24,', result)) == 2
    assert len(re.findall(r'(?m)^\s*vl8re32\.v\s+v24,', result)) == 2


def test_llama_third_batch_fallback_opcodes():
    from rvv_sbt_rvv import translate
    cases = [
        RVInstruction(0, 'vmv.v.v', operands=['v8','v4'], op_str='vmv.v.v v8, v4', ),
        RVInstruction(4, 'vmsgtu.vx', operands=['v13','v1','t3'], op_str='vmsgtu.vx v13, v1, t3', ),
        RVInstruction(8, 'vmnot.m', operands=['v20','v1'], op_str='vmnot.m v20, v1', ),
        RVInstruction(12, 'vdiv.vx', operands=['v10','v10','a7'], op_str='vdiv.vx v10, v10, a7', ),
        RVInstruction(16, 'vwadd.vv', operands=['v8','v6','v4'], op_str='vwadd.vv v8, v6, v4', ),
        RVInstruction(20, 'vslideup.vi', operands=['v2','v3','1'], op_str='vslideup.vi v2, v3, 1', ),
        RVInstruction(24, 'vl4re64.v', operands=['v12','(sp)'], op_str='vl4re64.v v12, (sp)', ),
        RVInstruction(28, 'vmv8r.v', operands=['v24','v8'], op_str='vmv8r.v v24, v8', ),
        RVInstruction(32, 'vmacc.vv', operands=['v4','v8','v16'], op_str='vmacc.vv v4, v8, v16', ),
        RVInstruction(36, 'vlse8.v', operands=['v2','(a6)','zero'], op_str='vlse8.v v2, (a6), zero', ),
        RVInstruction(40, 'vmsltu.vx', operands=['v3','v4','a7'], op_str='vmsltu.vx v3, v4, a7', ),
        RVInstruction(44, 'vmand.mm', operands=['v21','v21','v1'], op_str='vmand.mm v21, v21, v1', ),
        RVInstruction(48, 'vl8re64.v', operands=['v8','(t6)'], op_str='vl8re64.v v8, (t6)', ),
        RVInstruction(52, 'vslide1up.vx', operands=['v5','v4','zero'], op_str='vslide1up.vx v5, v4, zero', ),
        RVInstruction(56, 'vslide1down.vx', operands=['v1','v1','zero'], op_str='vslide1down.vx v1, v1, zero', ),
        RVInstruction(60, 'vl8re32.v', operands=['v8','(s2)'], op_str='vl8re32.v v8, (s2)', ),
    ]
    result = translate(cases, init_vtype='sew=32,lmul=1', raw=True)
    assert 'UNIMPLEMENTED:' not in result
    assert '# ERROR' not in result
    assert 'vmv.v.v v8, v4' in result and 'active elements' in result
    assert 'vmsgtu.vx v13, v1, t3' in result and 'unsigned(v1[i]) > unsigned(t3)' in result
    assert 'vmnot.m v20, v1' in result and 'bit-packed mask' in result
    assert 'vdiv.vx v10, v10, a7' in result and 'signed(v10[i]) / signed(a7)' in result
    assert 'vwadd.vv v8, v6, v4' in result and 'sext(v6[i]) + sext(v4[i])' in result
    assert 'vslideup.vi v2, v3, 1' in result and 'prefix undisturbed' in result
    assert 'RVV256-NATIVE-WHOLE-MEM: vl4re64.v' in result
    assert 'RVV256-NATIVE-WHOLE: vmv8r.v' in result
    assert 'vmacc.vv v4, v8, v16' in result and 'v4[i] += v8[i] * v16[i]' in result
    assert 'vlse8.v' in result and 'mem[a6 + zero * i]' in result
    assert 'vmsltu.vx v3, v4, a7' in result and 'unsigned(v4[i]) < unsigned(a7)' in result
    assert 'vmand.mm v21, v21, v1' in result
    assert 'RVV256-NATIVE-WHOLE-MEM: vl8re64.v' in result
    assert 'vslide1up.vx v5, v4, zero' in result and 'v5[0] = zero' in result
    assert 'vslide1down.vx v1, v1, zero' in result and 'v1[vl-1] = zero' in result
    assert 'RVV256-NATIVE-WHOLE-MEM: vl8re32.v' in result
    assert 'start at v1[1]' in result
    for opcode, operands in (("vslide1up.vx", ["v1", "v1", "zero"]),
                             ("vslideup.vi", ["v4", "v4", "16"]),
                             ("vwadd.vv", ["v5", "v6", "v4"])):
        invalid = translate([RVInstruction(0, opcode, operands=operands,
                                           op_str=", ".join(operands))],
                            init_vtype='sew=32,lmul=1', raw=True)
        assert 'fallback to ebreak' in invalid
        assert opcode in invalid


def test_vlse16_32_64_paths():
    from rvv_sbt_rvv import translate
    cases = [
        ('vlse16.v', 'sew=16,lmul=1', 'vlse16.v v24, (', 'vse16.v v24, ('),
        ('vlse32.v', 'sew=32,lmul=1', 'vlse32.v v24, (', 'vse32.v v24, ('),
        ('vlse64.v', 'sew=64,lmul=1', 'vlse64.v v24, (', 'vse64.v v24, ('),
    ]
    for opcode, init_vtype, load_text, store_text in cases:
        insn = RVInstruction(
            0,
            opcode,
            operands=['v8', '(a0)', 'a1'],
            op_str=f'{opcode} v8, (a0), a1',
        )
        result = translate([insn], init_vtype=init_vtype, raw=True)
        assert load_text in result
        assert store_text in result
        assert 'mem[a0 + a1 * i]' in result
        assert 'chunk_n * stride' in result
        assert '尾部 RVV strided load chunk' in result


def test_vlse32_and_vlseg2e32_paths():
    from rvv_sbt_rvv import translate
    cases = [
        RVInstruction(0, 'vlse32.v', operands=['v8','(a0)','a1'], op_str='vlse32.v v8, (a0), a1', ),
        RVInstruction(0, 'vsse32.v', operands=['v8','(a0)','a1'], op_str='vsse32.v v8, (a0), a1', ),
        RVInstruction(0, 'vlseg2e32.v', operands=['v10','(a2)'], op_str='vlseg2e32.v v10, (a2)', ),
    ]
    result = translate(cases, init_vtype='sew=32,lmul=1', raw=True)
    assert 'vlse32.v v24, (' in result
    assert 'mem[a0 + a1 * i]' in result
    assert 'chunk_n * stride' in result
    assert '尾部 RVV strided load chunk' in result
    assert 'vsse32.v v24, (' in result
    assert 'mem[a0 + a1 * i] = v8[i]' in result
    assert '尾部 RVV strided store chunk' in result
    assert 'vlseg2e32.v v24, (' in result
    assert 'NF=2: segment 0 -> v10, segment 1 -> v11' in result
    assert 'segment 0 到 sim_state' in result
    assert 'segment 1 到 sim_state' in result

def test_segmented_memory_uses_start_vreg_syntax():
    from rvv_sbt_rvv import translate
    cases = [
        RVInstruction(0, 'vlseg2e32.v', operands=['v2','(a2)'], op_str='vlseg2e32.v v2, (a2)', ),
        RVInstruction(0, 'vsseg2e32.v', operands=['v2','(a2)'], op_str='vsseg2e32.v v2, (a2)', ),
        RVInstruction(0, 'vlsseg2e32.v', operands=['v2','(a2)','a3'], op_str='vlsseg2e32.v v2, (a2), a3', ),
        RVInstruction(0, 'vssseg2e32.v', operands=['v2','(a2)','a3'], op_str='vssseg2e32.v v2, (a2), a3', ),
    ]
    result = translate(cases, init_vtype='sew=32,lmul=1', raw=True)
    assert '{v' not in result
    assert 'vlseg2e32.v v24, (' in result
    assert 'vsseg2e32.v v24, (' in result
    assert 'vlsseg2e32.v v24, (' in result
    assert 'vssseg2e32.v v24, (' in result

def test_vluxei64_v_scalar_indexed_load_path():
    from rvv_sbt_rvv import translate
    insn = RVInstruction(0, 'vluxei64.v', operands=['v4','(a0)','v2'], op_str='vluxei64.v v4, (a0), v2', )
    result = translate([insn], init_vtype='sew=32,lmul=1', raw=True)
    assert 'vluxei64.v v4, (a0), v2' in result
    assert 'scalar indexed load' in result
    assert 'index EEW=64' in result
    assert 'byte offset = u64(v2[i])' in result
    assert 'lw' in result and 'sw' in result

def test_vluxei16_v_scalar_indexed_load_path():
    from rvv_sbt_rvv import translate
    insn = RVInstruction(0, 'vluxei16.v', operands=['v4','(a0)','v2'], op_str='vluxei16.v v4, (a0), v2', )
    result = translate([insn], init_vtype='sew=16,lmul=1', raw=True)
    assert 'vluxei16.v v4, (a0), v2' in result
    assert 'scalar indexed load' in result
    assert 'index EEW=16' in result
    assert 'byte offset = u16(v2[i])' in result
    assert 'lhu' in result and 'sh' in result

def test_masked_memory_instructions():
    from rvv_sbt_rvv import translate
    insn_vle = RVInstruction(0, 'vle8.v', operands=['v4', '(a0)', 'v0.t'],
                             op_str='vle8.v v4, (a0), v0.t', )
    insn_vse = RVInstruction(4, 'vse32.v', operands=['v8', '(a1)', 'v0.t'],
                             op_str='vse32.v v8, (a1), v0.t', )
    insn_vlse = RVInstruction(8, 'vlse16.v', operands=['v12', '(a2)', 'a3', 'v0.t'],
                              op_str='vlse16.v v12, (a2), a3, v0.t', )
    
    res_vle = translate([insn_vle], init_vtype='sew=8,lmul=1', raw=True)
    assert 'vle8.v v24, (' in res_vle and ', v0.t' in res_vle
    assert 'vse8.v v24, (' in res_vle and ', v0.t' in res_vle
    assert 'Direct byte-aligned mask chunk into v0' in res_vle
    assert 'vlm.v   v0' in res_vle
    assert 'vmv.v.x v0' not in res_vle
    
    res_vse = translate([insn_vse], init_vtype='sew=32,lmul=1', raw=True)
    assert 'vle32.v v24, (' in res_vse and ', v0.t' in res_vse
    assert 'vse32.v v24, (' in res_vse and ', v0.t' in res_vse
    assert 'Direct byte-aligned mask chunk into v0' in res_vse
    assert 'vlm.v   v0' in res_vse
    assert 'vmv.v.x v0' not in res_vse

    res_vlse = translate([insn_vlse], init_vtype='sew=16,lmul=1', raw=True)
    assert 'vlse16.v v24, (' in res_vlse and ', v0.t' in res_vlse
    assert 'vse16.v v24, (' in res_vlse and ', v0.t' in res_vlse
    assert 'Direct byte-aligned mask chunk into v0' in res_vlse
    assert 'vlm.v   v0' in res_vlse
    assert 'vmv.v.x v0' not in res_vlse
    

def test_rvv256_masked_forms():
    from rvv_sbt_rvv import translate

    # Representative masked opcodes should not crash or silently drop masking.
    test_opcodes = [
        ('vadd.vv', ['v4', 'v2', 'v3', 'v0.t']),
        ('vfadd.vf', ['v4', 'v2', 'fa1', 'v0.t']),
        ('vfsub.vv', ['v4', 'v2', 'v3', 'v0.t']),
        ('vwmacc.vx', ['v4', 'a1', 'v3', 'v0.t']),
        ('vnsrl.wi', ['v4', 'v2', '3', 'v0.t']),
        ('vsll.vv', ['v4', 'v2', 'v3', 'v0.t']),
        ('vsll.vi', ['v4', 'v2', '3', 'v0.t']),
        ('vor.vi', ['v4', 'v2', '7', 'v0.t']),
        ('vor.vx', ['v4', 'v2', 'a1', 'v0.t']),
        ('vfrsub.vf', ['v4', 'v2', 'fa1', 'v0.t']),
        ('vwredsum.vs', ['v4', 'v2', 'v3', 'v0.t']),
    ]

    for opcode, operands in test_opcodes:
        op_str = f"{opcode} {', '.join(operands)}"
        insn = RVInstruction(0, opcode, operands=operands, op_str=op_str, )
        result = translate([insn], init_vtype='sew=32,lmul=1', raw=True)
        if "ERROR: RVV256 masked form is not implemented yet" in result:
            raise AssertionError(f"Masked form unexpectedly not implemented for: {op_str}")

        assert f"{opcode}" in result, f"Base instruction missing in {opcode}"
        if opcode != 'vwredsum.vs':
            if opcode == 'vor.vx':
                # e32,m1 完整块已改为在正确 vtype 后直接 vlm.v。
                assert 'Direct byte-aligned mask chunk into v0' in result
                assert 'vlm.v   v0' in result
                assert 'vmv.v.x' not in result
            else:
                assert 'vmv.v.x' in result, f"Mask extraction missing in {opcode}"
            assert ', v0.t' in result, f"Mask suffix missing from instruction in {opcode}"
        else:
            assert 'red_skip_' in result, f"Mask skip label missing in {opcode}"
            assert 'mask byte address' in result, f"Scalar mask byte load missing in {opcode}"

        if opcode != 'vwredsum.vs' and 'vse' in result:
            vse_lines = [
                l for l in result.split('\n')
                if ('vse8.v' in l or 'vse16.v' in l or 'vse32.v' in l or 'vse64.v' in l)
                and 'sp' not in l
                and '溢出' not in l
            ]
            for line in vse_lines:
                assert ', v0.t' in line, f"Writeback missing mask suffix in {opcode}: {line}"


def test_vor_vx_masked_preserves_scalar_input():
    from rvv_sbt_rvv import translate
    insn = RVInstruction(
        0,
        'vor.vx',
        operands=['v4', 'v2', 't0', 'v0.t'],
        op_str='vor.vx v4, v2, t0, v0.t',
    )
    result = translate([insn], init_vtype='sew=32,lmul=1', raw=True)
    assert "vor.vx" in result and ", t0, v0.t" in result
    assert "    li      t0," not in result
    assert "    mv      t0," not in result

def test_masked_vadd_tail_paths_guard_each_tail_element():
    from rvv_sbt_rvv import translate

    for opcode, operands in (
        ('vadd.vi', ['v1', 'v1', '-4', 'v0.t']),
        ('vadd.vx', ['v4', 'v2', 'a1', 'v0.t']),
    ):
        op_str = f"{opcode} {', '.join(operands)}"
        insn = RVInstruction(0, opcode, operands=operands, op_str=op_str, )
        result = translate([insn], init_vtype='sew=16,lmul=1', raw=True)
        tail_prefix = opcode.replace('.', '_')

        assert f"{tail_prefix}_tail" in result
        assert "If mask is 0, skip element" in result
        assert re.search(
            rf"\.L_rvv256_{tail_prefix}_tail_\d+_skip:\n\s+addi\s+\w+,\s+\w+,\s+1",
            result,
        ), f"masked tail must advance mask index after skip label in {opcode}"


def test_masked_vadd_vx_keeps_scalar_out_of_mask_temps():
    from rvv_sbt_rvv import translate

    insn = RVInstruction(
        0,
        'vadd.vx',
        operands=['v4', 'v2', 'a1', 'v0.t'],
        op_str='vadd.vx v4, v2, a1, v0.t',
    )
    result = translate([insn], init_vtype='sew=16,lmul=1', raw=True)

    scalar_match = re.search(r"^\s*mv\s+(\w+),\s+a1\s+# \1 = a1", result, re.MULTILINE)
    assert scalar_match, "masked vadd.vx must copy rs1 into a dedicated scalar temp"
    scalar_reg = scalar_match.group(1)

    assert re.search(
        rf"\bvadd\.vx\s+\w+,\s+\w+,\s+{scalar_reg},\s+v0\.t",
        result,
    ), "masked vadd.vx must use the saved scalar temp after mask extraction"
    assert not re.search(
        rf"^\s+(srli|andi|srl)\s+{scalar_reg},",
        result,
        re.MULTILINE,
    ), "saved scalar temp must not be reused by mask extraction"


def _assert_masked_tail_chunk_preserves_tail_count(result: str, modulo_mask: int) -> None:
    tail_match = re.search(
        rf"^\s*andi\s+(\w+),\s+\w+,\s+{modulo_mask}\s+# \1 = vl %",
        result,
        re.MULTILINE,
    )
    assert tail_match, "test could not identify tail_count register"
    tail_reg = tail_match.group(1)

    tail_pos = result.find("# --- 尾部 RVV")
    assert tail_pos >= 0, "test expects a tail RVV chunk"
    tail_section = result[tail_pos:]
    vset_marker = f"vsetvli zero, {tail_reg},"
    assert vset_marker in tail_section, "tail chunk must use tail_count as AVL"
    before_vset = tail_section.split(vset_marker, 1)[0]

    assert not re.search(
        rf"^\s+(srli|andi|srl|add|li|mv|lbu|lhu|lwu|ld)\s+{tail_reg}\b",
        before_vset,
        re.MULTILINE,
    ), "mask extraction must not clobber tail_count before vsetvli"

def test_masked_tail_rvv_chunks_preserve_tail_count():
    from rvv_sbt_rvv import translate

    cases = [
        ('vwmacc.vx', ['v2', 't6', 'v5', 'v0.t'], 'sew=16,lmul=1', 7, False),
        ('vsll.vi', ['v4', 'v2', '3', 'v0.t'], 'sew=16,lmul=1', 15, True),
        ('vnsrl.wi', ['v4', 'v2', '3', 'v0.t'], 'sew=16,lmul=1', 7, True),
        ('vlse16.v', ['v12', '(a2)', 'a3', 'v0.t'], 'sew=16,lmul=1', 15, True),
    ]
    for opcode, operands, init_vtype, modulo_mask, raw in cases:
        insn = RVInstruction(
            0,
            opcode,
            operands=operands,
            op_str=f"{opcode} {', '.join(operands)}",
        )
        result = translate([insn], init_vtype=init_vtype, raw=raw, text_only=not raw)
        _assert_masked_tail_chunk_preserves_tail_count(result, modulo_mask)


def test_masked_vwmacc_vx_mask_and_t6_paths():
    from rvv_sbt_rvv import translate

    insn = RVInstruction(
        0,
        'vwmacc.vx',
        operands=['v2', 't6', 'v5', 'v0.t'],
        op_str='vwmacc.vx v2, t6, v5, v0.t',
    )
    result = translate([insn], init_vtype='sew=16,lmul=1', text_only=True, raw=False)

    mask_idx_match = re.search(
        r"^\s*li\s+(\w+),\s+0\s+# 初始化全局元素掩码索引",
        result,
        re.MULTILINE,
    )
    assert mask_idx_match, "masked vwmacc.vx must initialize mask index"
    mask_idx = mask_idx_match.group(1)

    assert result.count("# --- Mask Setup ---") == 1
    assert result.count("# --- Extract mask chunk into v0 ---") == 2
    assert len(re.findall(rf"^\s*addi\s+{mask_idx},\s+{mask_idx},\s+8\b", result, re.MULTILINE)) == 1
    assert "恢复源指令作为输入使用的原始 t6" in result
    assert "get_simulated_cpu_state_addr@plt" not in result
    assert re.search(r"^\s*ld\s+\w+,\s+48\(sp\)", result, re.MULTILINE)
    assert not re.search(r"^\s*vwmacc\.vx\s+\w+,\s+t6,", result, re.MULTILINE)


def test_vf_tail_avoids_fpr_scalar_input_conflicts():
    from rvv_sbt_rvv import translate
    cases = [
        (
            'vfmul.vf',
            ['v8', 'v16', 'ft0'],
            'v8, v16, ft0',
            r"fmul\.s\s+\w+,\s+\w+,\s+ft0",
        ),
        (
            'vfmacc.vf',
            ['v8', 'ft0', 'v16'],
            'v8, ft0, v16',
            r"fmadd\.s\s+\w+,\s+\w+,\s+ft0,\s+\w+",
        ),
        (
            'vfnmsac.vf',
            ['v8', 'ft0', 'v16'],
            'v8, ft0, v16',
            r"fnmsub\.s\s+\w+,\s+\w+,\s+ft0,\s+\w+",
        ),
    ]
    for opcode, operands, op_str, op_pattern in cases:
        insn = RVInstruction(0, opcode, operands=operands, op_str=op_str, )
        result = translate([insn], init_vtype='sew=32,lmul=1', raw=True)
        assert '# ERROR' not in result, f"{opcode} generated an error path"
        assert '.word 0x0' not in result, f"{opcode} generated an illegal placeholder"
        assert not re.search(r"\bflw\s+ft0,\s+0\(", result), (
            f"{opcode} tail path overwrote scalar input ft0"
        )
        assert re.search(op_pattern, result), f"{opcode} tail path did not use ft0 as scalar input"

def test_vmacc_vx_preserves_t6_scalar_input():
    from rvv_sbt_rvv import translate
    insn = RVInstruction(
        0,
        'vmacc.vx',
        operands=['v0', 't6', 'v8'],
        op_str='vmacc.vx v0, t6, v8',
    )
    result = translate([insn], init_vtype='sew=32,lmul=1', text_only=True, raw=False)
    assert 'vmacc.vx v24, a0, v25' in result
    assert 'ld      a0, 48(sp)' in result
    assert 'vmacc.vx v24, t6, v25' not in result

def test_csrr_vector_csr_reads_simulated_state():
    from rvv_sbt_rvv import translate
    insn = RVInstruction(0, 'csrr', operands=['a4', 'vl'], op_str='a4, vl')
    result = translate([insn], raw=True)
    assert 'simulated CSR.vl' in result
    assert 'li      t0, 0x1020' in result
    assert 'ld      t1, 0(t0)' in result
    assert 'mv      a4, t2' in result
    assert '\n    csrr     a4, vl' not in result
    assert not re.search(r"\n\s+ld\s+a4,\s+\d+\(sp\)", result)

def test_csrr_vector_csr_numeric_aliases():
    from rvv_sbt_rvv import translate
    cases = [
        ('0xc20', '0x1020'),
        ('0x0c21', '0x1028'),
        ('10', '0x1018'),
    ]
    for csr, offset in cases:
        insn = RVInstruction(0, 'csrr', operands=['a5', csr], op_str=f'a5, {csr}')
        result = translate([insn], raw=True)
        assert f'li      t0, {offset}' in result
        assert 'ld      t1, 0(t0)' in result
        assert 'mv      a5, t2' in result
        assert f'\n    csrr     a5, {csr}' not in result

def test_csrr_vlenb_uses_translator_vlenb_constant():
    from rvv_sbt_rvv import translate
    insn = RVInstruction(0, 'csrr', operands=['a5', '0xc22'], op_str='a5, 0xc22')
    # guest 可见 vlenb 常数来自已登记方向几何（128B 槽 = VLEN=1024）；
    # 非 128 的 vlenb 属于未登记方向，会在 profile 构造期被拒绝。
    result = translate([insn], vlenb=128, raw=True)
    assert 'simulated CSR.vlenb' in result
    assert re.search(r'li\s+(\w+), 128\n\s+mv\s+a5, \1', result)
    assert '0x1030' not in result


def test_csrr_vlenb_rejects_unregistered_direction():
    from rvv_sbt_rvv import translate
    insn = RVInstruction(0, 'csrr', operands=['a5', '0xc22'], op_str='a5, 0xc22')
    # vlenb=64 对应 512-bit 源，从未被 chunking/状态槽布局支持；
    # 必须在生成任何汇编前 fail-fast，而不是静默产出越界布局。
    try:
        translate([insn], vlenb=64, raw=True)
    except ValueError as exc:
        assert '未支持的翻译方向' in str(exc)
    else:
        raise AssertionError("Expected ValueError for unregistered direction")

def test_csrr_non_vector_csr_passes_through():
    from rvv_sbt_rvv import translate
    insn = RVInstruction(0, 'csrr', operands=['a0', 'cycle'], op_str='a0, cycle')
    result = translate([insn], raw=True)
    assert result.strip() == 'csrr     a0, cycle'
    assert 'get_simulated_cpu_state_addr@plt' not in result
    assert 'la.tls.ie t6, simulated_cpu_state_ptr' not in result
    assert 'read simulated RVV CSR' not in result

def test_caller_injected_analysis_cannot_override_prepared_cfg_state():
    from rvv_sbt_rvv import translate
    linear_config = RVInstruction(
        0,
        'vsetivli',
        operands=['zero', '0', 'e64', 'm1', 'ta', 'ma'],
        op_str='zero, 0, e64, m1, ta, ma',
    )
    annotated_vadd = RVInstruction(
        4,
        'vadd.vv',
        operands=['v8', 'v4', 'v0'],
        op_str='v8, v4, v0',
    )
    annotated_vadd.analysis = _analysis_for(
            4,
            [VTypeSpec(sew=32, lmul=2.0, vta=1, vma=1)],
    )

    result = translate([linear_config, annotated_vadd], raw=True)

    assert 'vadd.vv v8, v4, v0' in result
    assert 'SEW=64' in result
    assert 'Semantic: v8[i] = v4[i] + v0[i], SEW=32' not in result

def test_source_vtype_runtime_dispatch_cases():
    result = _translate_cfg_fixture(
        """
0000000000001000 <dispatch>:
    1000: 0c0577d7             vsetvli a5, a0, e16, m1, ta, ma
    1004: 00050663             beq     a0, zero, 1010
    1008: 0d0577d7             vsetvli a5, a0, e32, m1, ta, ma
    100c: 0040006f             j       1010
    1010: 02050457             vadd.vv v8, v4, v0
"""
    )

    assert 'runtime vtype dispatch for vadd.vv v8, v4, v0' in result
    assert 'li      t0, 0x1028' in result
    assert 'dispatch on simulated CSR.vtype' in result
    assert result.count('beq') >= 2
    assert 'No analyzed vtype case matched at runtime' in result
    assert 'SEW=16' in result
    assert 'SEW=32' in result

def test_source_vtype_runtime_dispatch_fallback_is_per_case():
    result = _translate_cfg_fixture(
        """
0000000000002000 <dispatch_fallback>:
    2000: 0d0577d7             vsetvli a5, a0, e32, m1, ta, ma
    2004: 00050663             beq     a0, zero, 2010
    2008: 0d8577d7             vsetvli a5, a0, e64, m1, ta, ma
    200c: 0040006f             j       2010
    2010: c2051457             vfwmacc.vv v8, v4, v0
"""
    )

    assert 'runtime vtype dispatch for vfwmacc.vv v8, v4, v0' in result
    assert '# RVV256-WIDE: vfwmacc.vv' in result
    assert 'vfwmacc.vv v8, v16, v20' in result
    assert 'vle64.v v8,' in result and 'vse64.v v8,' in result
    assert '尾部标量回退' not in result
    # e64 候选失败使用后端统一的 RVV256 fallback 文案。
    assert 'RVV256 fallback: vtype case e64,m1,ta,ma' in result
    assert 'vtype case e64,m1,ta,ma' in result

def test_source_vtype_unknown_only_falls_back():
    from rvv_sbt_rvv import translate
    insn = RVInstruction(
        0,
        'vadd.vv',
        operands=['v8', 'v4', 'v0'],
        op_str='v8, v4, v0',
    )
    insn.analysis = _analysis_for(0, unknown=True)

    result = translate([insn], raw=True)

    # ebreak 文案统一由 RVV256 后端 fallback_result 生产（与 CLI 合同一致），
    # 不再依赖 core 的通用模板文本。unknown-only 情形没有候选可列，
    # 正文只保留 fallback 标记和原因。
    assert 'RVV256 fallback' in result
    assert 'source vtype analysis contains only unknown entries' in result
    assert 'dispatch on simulated CSR.vtype' not in result

def test_source_vtype_mixed_unknown_dispatches_known_cases():
    result = _translate_cfg_fixture(
        """
0000000000003000 <mixed_unknown>:
    3000: 00050663             beq     a0, zero, 300c
    3004: 0d0577d7             vsetvli a5, a0, e32, m1, ta, ma
    3008: 0040006f             j       300c
    300c: 02050457             vadd.vv v8, v4, v0
"""
    )

    assert 'runtime vtype dispatch for vadd.vv v8, v4, v0' in result
    assert 'dispatch on simulated CSR.vtype' in result
    assert 'No analyzed vtype case matched at runtime' in result
    assert 'Semantic: v8[i] = v4[i] + v0[i], SEW=32' in result
    assert 'Semantic: v8[i] = v4[i] + v0[i], SEW=64' not in result

def test_multi_source_literal_config_syncs_following_legacy_state():
    from rvv_sbt_rvv import translate
    annotated_config = RVInstruction(
        0,
        'vsetivli',
        operands=['zero', '1', 'e32', 'm1', 'ta', 'ma'],
        op_str='zero, 1, e32, m1, ta, ma',
    )
    annotated_config.analysis = _analysis_for(0, [
            VTypeSpec(sew=16, lmul=1.0, vta=1, vma=1),
            VTypeSpec(sew=64, lmul=1.0, vta=1, vma=1),
    ])
    legacy_vadd = RVInstruction(
        4,
        'vadd.vv',
        operands=['v8', 'v4', 'v0'],
        op_str='v8, v4, v0',
    )

    result = translate([annotated_config, legacy_vadd], init_vtype='sew=64,lmul=1,ta,ma', raw=True)

    # vsetivli 的输出 vtype 在指令本身确定，不应使用其“进入前”的
    # 候选集合生成无意义的运行时分支；后续线性状态应更新为 e32。
    assert 'runtime vtype dispatch for vsetivli zero, 1, e32, m1, ta, ma' not in result
    assert 'Semantic: v8[i] = v4[i] + v0[i], SEW=32' in result
    assert 'Semantic: v8[i] = v4[i] + v0[i], SEW=64' not in result

def test_vsetvli_zero_zero_no_longer_requires_source_vtype():
    from rvv_sbt_rvv import translate
    linear_config = RVInstruction(
        0,
        'vsetivli',
        operands=['zero', '0', 'e32', 'm1', 'ta', 'ma'],
        op_str='zero, 0, e32, m1, ta, ma',
    )
    vset_insn = RVInstruction(
        4,
        'vsetvli',
        operands=['zero', 'zero', 'e32', 'mf2', 'ta', 'ma'],
        op_str='zero, zero, e32, mf2, ta, ma',
    )

    result = translate([linear_config, vset_insn], raw=True)

    assert '# ERROR' not in result
    assert 'runtime check: vsetvli x0,x0 requires unchanged VLMAX' in result
    assert '# vl unchanged' in result
    assert 'vsetvli zero, zero, e32, mf2, ta, ma' in result

def test_scalar_unaffected():
    from rvv_sbt import translate
    insn = RVInstruction(0, 'add', operands=['a0','a0','a1'], op_str='add a0, a0, a1')
    result = translate([insn])
    assert '.text' in result
