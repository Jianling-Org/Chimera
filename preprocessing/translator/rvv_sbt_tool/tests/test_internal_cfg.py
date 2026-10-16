"""内部 CFG/vtype 分析的语义回归测试。"""

from __future__ import annotations

from riscv.frontend.parser import AsmParser
from riscv.extensions.rvv.translation.pipeline import analyze_program
from riscv.frontend.model import CallEdgeKind
from riscv.frontend.model import CFGEdgeKind
from riscv.frontend.model import RVProgram
from riscv.extensions.rvv.analysis.model import AVLKind, parse_init_vtype


def _parse(asm: str):
    return AsmParser().parse_string_functions(asm)


def analyze_functions(functions):
    """测试辅助函数：每次都通过统一 RVProgram 入口执行内部分析。"""

    return analyze_program(RVProgram(functions=list(functions)))


def test_explicit_init_vtype_seeds_primary_cfg_entry_only():
    """片段 API 的显式入口配置必须进入 prepare 分析，而非只播种 emitter。"""

    functions = _parse(
        """
0000000000000500 <seeded>:
    0500: 02050457             vadd.vv v8, v8, v16
    0504: 8082                 ret
"""
    )
    analysis = analyze_program(
        RVProgram(functions=list(functions)),
        initial_vtype=parse_init_vtype("sew=32,lmul=2,ta,mu"),
    )
    instruction = analysis.functions[0x500].at(0x500)

    assert instruction.vtype_unknown is False
    assert instruction.provenance == "internal-cfg:explicit-initial-vtype"
    assert instruction.known_specs()[0].sew == 32
    assert instruction.known_specs()[0].lmul == 2.0
    assert instruction.known_specs()[0].vta == 1
    assert instruction.known_specs()[0].vma == 0


def test_internal_cfg_handles_loop_and_preserves_tail_mask_policy():
    functions = _parse(
        """
0000000000001000 <loop>:
    1000: 00400513             li      a0, 4
    1004: 0d0575d7             vsetvli a1, a0, e32, m1, tu, mu
    1008: 00050463             beq     a0, zero, 1010 <.Ldone>
    100c: 02050457             vadd.vv v8, v8, v16
0000000000001010 <.Ldone>:
    1010: 8082                 ret
"""
    )
    analysis = analyze_functions(functions)
    function = functions[0]
    vadd = function.instructions[3]

    assert function.cfg is not None
    assert function.cfg.unknown_exit is False
    assert analysis.for_function(function.start_addr).at(vadd.address) is not None
    assert analysis.for_function(function.start_addr).at(vadd.address).definite_vtype is not None
    assert analysis.for_function(function.start_addr).at(vadd.address).definite_vtype.vta == 0
    assert analysis.for_function(function.start_addr).at(vadd.address).definite_vtype.vma == 0
    assert analysis.for_function(function.start_addr).at(vadd.address).known_specs()[0].vta == 0
    assert analysis.for_function(function.start_addr).at(vadd.address).known_specs()[0].vma == 0
    assert analysis.for_function(function.start_addr) is analysis.for_function(function.start_addr)


def test_internal_cfg_merges_multiple_predecessor_vtypes_without_guessing():
    functions = _parse(
        """
0000000000002000 <merge>:
    2000: 00050463             beq     a0, zero, 200c <.Lright>
    2004: 0d0577d7             vsetvli a5, a0, e8, m1, ta, ma
    2008: 0000006f             j       2010 <.Ljoin>
000000000000200c <.Lright>:
    200c: 0d0577d7             vsetvli a5, a0, e64, m1, tu, mu
0000000000002010 <.Ljoin>:
    2010: 02050457             vadd.vv v8, v8, v16
    2014: 8082                 ret
"""
    )
    analysis = analyze_functions(functions)
    vadd = functions[0].instructions[4]

    assert analysis.for_function(functions[0].start_addr).at(vadd.address) is not None
    assert {candidate.sew for candidate in analysis.for_function(functions[0].start_addr).at(vadd.address).possible_vtypes} == {8, 64}
    assert analysis.for_function(functions[0].start_addr).at(vadd.address).vtype_unknown is False
    assert {spec.sew for spec in analysis.for_function(functions[0].start_addr).at(vadd.address).known_specs()} == {8, 64}
    assert {spec.vta for spec in analysis.for_function(functions[0].start_addr).at(vadd.address).known_specs()} == {0, 1}
    assert {spec.vma for spec in analysis.for_function(functions[0].start_addr).at(vadd.address).known_specs()} == {0, 1}


def test_vsetvl_keeps_dynamic_vtype_unknown_and_preserves_avl_information():
    functions = _parse(
        """
0000000000003000 <dynamic>:
    3000: 00000557             vsetvl a0, a1, a2
    3004: 02050457             vadd.vv v8, v8, v16
    3008: 8082                 ret
"""
    )
    analysis = analyze_functions(functions)
    vsetvl, vadd, _ = functions[0].instructions

    candidate = next(iter(analysis.for_function(functions[0].start_addr).at(vadd.address).possible_vtypes))
    assert candidate.sew is None
    assert candidate.lmul is None
    assert candidate.vta is None
    assert candidate.vma is None
    assert candidate.avl.kind is AVLKind.UNKNOWN
    assert analysis.for_function(functions[0].start_addr).at(vadd.address).known_specs() == ()
    assert analysis.for_function(functions[0].start_addr).at(vadd.address).has_unknown_candidate() is True
    assert analysis.for_function(functions[0].start_addr).at(vsetvl.address) is not None


def test_vsetvli_reads_old_rs1_before_rd_writeback_for_avl_constant():
    functions = _parse(
        """
0000000000004000 <same>:
    4000: 00400513             li      a0, 4
    4004: 0d057557             vsetvli a0, a0, e32, m1, ta, ma
    4008: 02050457             vadd.vv v8, v8, v16
    400c: 8082                 ret
"""
    )
    analysis = analyze_functions(functions)
    candidate = next(iter(analysis.for_function(functions[0].start_addr).at(functions[0].instructions[2].address).possible_vtypes))
    assert candidate.avl.kind is AVLKind.CONSTANT
    assert candidate.avl.value == 4


def test_equivalent_vtype_join_keeps_origin_and_drops_conflicting_constants():
    functions = _parse(
        "00001000 <joined>:\n"
        " 1000: 00050463 beq a0,zero,1010 <joined+0x10>\n"
        " 1004: 00400293 li t0,4\n"
        " 1008: 0d027057 vsetivli zero,4,e32,m1,tu,mu\n"
        " 100c: 0000006f j 101c <joined+0x1c>\n"
        " 1010: 00800293 li t0,8\n"
        " 1014: 0d027057 vsetivli zero,4,e32,m1,tu,mu\n"
        " 1018: 00000013 nop\n"
        " 101c: 02050457 vadd.vv v8,v8,v16\n"
        " 1020: 0d02f057 vsetvli zero,t0,e32,m1,tu,mu\n"
        " 1024: 02050457 vadd.vv v8,v8,v16\n"
        " 1028: 00008067 ret\n"
    )
    analysis = analyze_functions(functions).for_function(0x1000)
    candidate, = analysis.at(0x101C).possible_vtypes
    assert candidate.source_instruction == 0x1008
    assert candidate.avl.kind is AVLKind.CONSTANT
    assert candidate.avl.value == 4
    later, = analysis.at(0x1024).possible_vtypes
    assert later.avl.kind is not AVLKind.CONSTANT


def test_internal_cfg_analyzes_secondary_entry_with_local_vset():
    """函数范围内的冷代码/次级入口不应因主入口不可达而整体 unknown。"""

    functions = _parse(
        """
0000000000006000 <fragmented>:
    6000: 0d057557             vsetvli a0, a0, e32, m1, ta, ma
    6004: 02050457             vadd.vv v8, v8, v16
    6008: 8082                 ret
000000000000600c <.Lcold>:
    600c: 0d0575d7             vsetvli a1, a0, e64, m2, tu, mu
    6010: 02050457             vadd.vv v8, v8, v16
    6014: 8082                 ret
"""
    )

    analysis = analyze_functions(functions)
    function = functions[0]
    cold_vadd = function.instructions[4]

    assert function.cfg is not None
    assert function.cfg.entry_addresses == (0x6000, 0x600C)
    assert function.cfg.secondary_entry_addresses == (0x600C,)
    assert analysis.for_function(function.start_addr) is not None
    assert analysis.for_function(function.start_addr).structure.unreachable_addresses == frozenset()
    assert analysis.for_function(function.start_addr).at(cold_vadd.address) is not None
    assert analysis.for_function(function.start_addr).at(cold_vadd.address).vtype_unknown is False
    assert analysis.for_function(function.start_addr).at(cold_vadd.address).provenance == "internal-cfg:secondary-entry"
    assert analysis.for_function(function.start_addr).at(cold_vadd.address).known_specs()[0].sew == 64
    assert analysis.for_function(function.start_addr).at(cold_vadd.address).known_specs()[0].lmul == 2.0
    assert analysis.for_function(function.start_addr).at(cold_vadd.address).known_specs()[0].vta == 0
    assert analysis.for_function(function.start_addr).at(cold_vadd.address).known_specs()[0].vma == 0


def test_secondary_entry_without_local_vset_remains_explicitly_unknown():
    """扩展入口只扩大覆盖范围，不得把缺少 vset 的路径猜成已知配置。"""

    functions = _parse(
        """
0000000000007000 <fragmented_unknown>:
    7000: 0d057557             vsetvli a0, a0, e32, m1, ta, ma
    7004: 8082                 ret
0000000000007008 <.Lentry_without_config>:
    7008: 02050457             vadd.vv v8, v8, v16
    700c: 8082                 ret
"""
    )

    analysis = analyze_functions(functions)
    function = functions[0]
    vadd = function.instructions[2]

    assert analysis.for_function(function.start_addr).at(vadd.address) is not None
    assert analysis.for_function(function.start_addr).at(vadd.address).vtype_unknown is True
    candidate = next(iter(analysis.for_function(function.start_addr).at(vadd.address).possible_vtypes))
    assert candidate.unknown_reason == (
        "possible secondary entry without incoming vtype"
    )
    assert analysis.for_function(function.start_addr).at(vadd.address).known_specs() == ()
    assert analysis.for_function(function.start_addr).at(vadd.address).has_unknown_candidate() is True


def test_isolated_cycle_is_reported_as_unrecognized_cfg_entry():
    """没有任何入口的孤立环不能被误报为次级入口或动态 vtype。"""

    functions = _parse(
        """
0000000000009000 <orphan_cycle>:
    9000: 8082                 ret
0000000000009004 <.Lorphan_loop>:
    9004: 02050457             vadd.vv v8, v8, v16
    9008: 0000006f             j       9004 <.Lorphan_loop>
"""
    )

    analysis = analyze_functions(functions)
    function = functions[0]
    vadd = function.instructions[1]

    assert analysis.for_function(function.start_addr) is not None
    assert analysis.for_function(function.start_addr).structure.secondary_entry_addresses == ()
    assert analysis.for_function(function.start_addr).structure.unreachable_addresses == frozenset({0x9004, 0x9008})
    assert analysis.for_function(function.start_addr).at(vadd.address) is not None
    assert analysis.for_function(function.start_addr).at(vadd.address).provenance == "internal-cfg:unreachable"
    candidate = next(iter(analysis.for_function(function.start_addr).at(vadd.address).possible_vtypes))
    assert candidate.unknown_reason == "no recognized CFG entry"


def test_indirect_call_keeps_fallthrough_and_invalidates_vtype():
    """jalr 调用的返回落点要继续分析，但不能沿用调用前 vtype。"""

    functions = _parse(
        """
0000000000008000 <indirect_call>:
    8000: 0d057557             vsetvli a0, a0, e32, m1, ta, ma
    8004: 000500e7             jalr    ra, 0(a0)
    8008: 02050457             vadd.vv v8, v8, v16
    800c: 8082                 ret
"""
    )

    analysis = analyze_functions(functions)
    function = functions[0]
    call = function.instructions[1]
    vadd = function.instructions[2]

    assert call.successors == (0x8008,)
    assert function.cfg.unknown_exit is True
    assert analysis.for_function(function.start_addr).at(vadd.address) is not None
    assert analysis.for_function(function.start_addr).at(vadd.address).vtype_unknown is True
    candidate = next(iter(analysis.for_function(function.start_addr).at(vadd.address).possible_vtypes))
    assert candidate.unknown_reason == (
        "call may change vtype in an unanalyzed callee"
    )


def test_indirect_call_target_address_is_not_promoted_to_direct_summary():
    """jalr 行上的附带地址不能绕过间接调用的保守边界。"""

    functions = _parse(
        """
0000000000008100 <callee>:
    8100: 8082                 ret
0000000000008200 <indirect_with_text_target>:
    8200: 0d057557             vsetvli a0, a0, e32, m1, ta, ma
    8204: 000500e7             jalr    ra, 0(a0)  # 8100 <callee>
    8208: 02050457             vadd.vv v8, v8, v16
    820c: 8082                 ret
"""
    )
    # 手工补充 objdump 可能附带的目标地址，验证调用图不会把它当成
    # jal/call 直接目标。文本地址仍然保留在指令对象本身。
    functions[1].instructions[1].target_address = 0x8100
    functions[1].instructions[1].target_symbol = "callee"

    analysis = analyze_functions(functions)
    edge = analysis.structure.call_graph.edge_for_call(0x8204)
    vadd = functions[1].instructions[2]

    assert edge is not None
    assert edge.kind is CallEdgeKind.INDIRECT_CALL
    assert edge.target_address == 0x8100
    assert edge.target_function_start is None
    assert edge.target_is_function_entry is False
    assert edge.resolved is False
    assert edge.provenance == "text:unresolved-indirect"
    assert functions[1].instructions[1].target_address == 0x8100
    assert analysis.for_function(functions[1].start_addr).at(vadd.address).vtype_unknown is True


def test_program_call_summary_preserves_vtype_for_direct_call():
    """文本可解析的叶函数没有 vset 时，调用后保留入口 vtype。"""

    functions = _parse(
        """
0000000000001000 <leaf>:
    1000: 8082                 ret
0000000000002000 <caller>:
    2000: 0d057557             vsetvli a0, a0, e32, m1, tu, mu
    2004: 00000097             call    leaf
    2008: 02050457             vadd.vv v8, v8, v16
    200c: 8082                 ret
"""
    )

    analysis = analyze_functions(functions)
    caller = functions[1]
    vadd = caller.instructions[2]

    assert analysis.structure.call_graph is not None
    edge = analysis.structure.call_graph.edge_for_call(0x2004)
    assert edge is not None
    assert edge.kind is CallEdgeKind.DIRECT_CALL
    assert edge.resolved is True
    assert analysis.function_summaries[0x1000].display() == "preserve-input"
    assert analysis.for_function(caller.start_addr).at(vadd.address).vtype_unknown is False
    assert analysis.for_function(caller.start_addr).at(vadd.address).known_specs()[0].sew == 32
    assert analysis.for_function(caller.start_addr).at(vadd.address).known_specs()[0].vta == 0
    assert analysis.for_function(caller.start_addr).at(vadd.address).known_specs()[0].vma == 0


def test_program_call_summary_propagates_constant_vtype():
    """被调函数固定 vset 后，调用者使用被调函数的完整配置。"""

    functions = _parse(
        """
0000000000003000 <set_e64>:
    3000: 0d007057             vsetivli zero, 1, e64, m2, tu, mu
    3004: 8082                 ret
0000000000004000 <caller_set>:
    4000: 0d057557             vsetvli a0, a0, e32, m1, ta, ma
    4004: 00000097             call    set_e64
    4008: 02050457             vadd.vv v8, v8, v16
    400c: 8082                 ret
"""
    )

    analysis = analyze_functions(functions)
    vadd = functions[1].instructions[2]
    summary = analysis.function_summaries[0x3000]

    assert summary.display() == "e64,m2,tu,mu"
    assert analysis.for_function(functions[1].start_addr).at(vadd.address).vtype_unknown is False
    assert analysis.for_function(functions[1].start_addr).at(vadd.address).known_specs()[0].sew == 64
    assert analysis.for_function(functions[1].start_addr).at(vadd.address).known_specs()[0].lmul == 2.0
    assert analysis.for_function(functions[1].start_addr).at(vadd.address).known_specs()[0].vta == 0
    assert analysis.for_function(functions[1].start_addr).at(vadd.address).known_specs()[0].vma == 0


def test_interior_direct_call_does_not_apply_function_entry_summary():
    """函数内部目标不能套用从函数头开始计算的摘要。"""

    functions = _parse(
        """
0000000000003000 <callee>:
    3000: 0d007057             vsetivli zero, 1, e64, m2, tu, mu
    3004: 8082                 ret
0000000000004000 <caller_interior>:
    4000: 0d057557             vsetvli a0, a0, e32, m1, ta, ma
    4004: 00000097             call    3004 <callee+0x4>
    4008: 02050457             vadd.vv v8, v8, v16
    400c: 8082                 ret
"""
    )

    analysis = analyze_functions(functions)
    edge = analysis.structure.call_graph.edge_for_call(0x4004)
    vadd = functions[1].instructions[2]

    assert edge is not None
    assert edge.resolved is True
    assert edge.target_function_start == 0x3000
    assert edge.target_is_function_entry is False
    assert edge.provenance == "text:direct-target-interior"
    assert analysis.for_function(functions[1].start_addr).at(vadd.address).vtype_unknown is True
    candidate = next(iter(analysis.for_function(functions[1].start_addr).at(vadd.address).possible_vtypes))
    assert "interior function address" in (candidate.unknown_reason or "")


def test_plt_stub_is_not_used_as_an_internal_vtype_summary():
    """dump 中的 @plt 桩不能被误当成已分析的内部函数。"""

    functions = _parse(
        """
0000000000005000 <memset@plt>:
    5000: 00000097             auipc   ra, 0
    5004: 000080e7             jalr    ra, 0(ra)
0000000000006000 <caller_plt>:
    6000: 0d057557             vsetvli a0, a0, e32, m1, ta, ma
    6004: 00000097             call    5000 <memset@plt>
    6008: 02050457             vadd.vv v8, v8, v16
    600c: 8082                 ret
"""
    )

    analysis = analyze_functions(functions)
    edge = analysis.structure.call_graph.edge_for_call(0x6004)
    vadd = functions[1].instructions[2]

    assert edge is not None
    assert edge.resolved is False
    assert edge.target_function_start is None
    assert edge.provenance == "text:external-stub"
    assert analysis.for_function(functions[1].start_addr).at(vadd.address).vtype_unknown is True
    candidate = next(iter(analysis.for_function(functions[1].start_addr).at(vadd.address).possible_vtypes))
    assert candidate.unknown_reason == "call target is external or unresolved"


def test_function_without_explicit_return_has_unknown_summary():
    """普通指令结束的函数不能被摘要为隐式正常返回。"""

    functions = _parse(
        """
0000000000007000 <truncated_callee>:
    7000: 0d007057             vsetivli zero, 1, e64, m2, tu, mu
0000000000008000 <caller_truncated>:
    8000: 00000097             call    truncated_callee
    8004: 02050457             vadd.vv v8, v8, v16
    8008: 8082                 ret
"""
    )

    analysis = analyze_functions(functions)
    summary = analysis.function_summaries[0x7000]
    vadd = functions[1].instructions[1]

    assert summary.normal_return is False
    assert summary.has_unknown_effect is True
    assert analysis.for_function(functions[1].start_addr).at(vadd.address).vtype_unknown is True


def test_program_call_summary_merges_multiple_return_effects():
    """不同返回路径的完整配置取并集，不猜测单一路径。"""

    functions = _parse(
        """
0000000000005000 <choose_vtype>:
    5000: 00050463             beq     a0, zero, 500c <.Lright>
    5004: 0d057557             vsetvli a0, a0, e32, m1, ta, ma
    5008: 8082                 ret
000000000000500c <.Lright>:
    500c: 0d0575d7             vsetvli a1, a0, e64, m1, tu, mu
    5010: 8082                 ret
0000000000006000 <caller_choose>:
    6000: 00000097             call    choose_vtype
    6004: 02050457             vadd.vv v8, v8, v16
    6008: 8082                 ret
"""
    )

    analysis = analyze_functions(functions)
    vadd = functions[1].instructions[1]
    summary = analysis.function_summaries[0x5000]

    assert summary.has_unknown_effect is False
    assert {candidate.sew for candidate in analysis.for_function(functions[1].start_addr).at(vadd.address).possible_vtypes} == {32, 64}
    assert {candidate.vta for candidate in analysis.for_function(functions[1].start_addr).at(vadd.address).possible_vtypes} == {0, 1}
    assert {candidate.vma for candidate in analysis.for_function(functions[1].start_addr).at(vadd.address).possible_vtypes} == {0, 1}
    assert analysis.for_function(functions[1].start_addr).at(vadd.address).vtype_unknown is False


def test_function_summary_composes_prior_vset_with_preserving_callee():
    """调用保持型叶函数时，调用者此前的 vset 效果必须继续保留。"""

    functions = _parse(
        """
0000000000005000 <preserve_leaf>:
    5000: 8082                 ret
0000000000006000 <wrapper>:
    6000: 0d057557             vsetvli a0, a0, e32, m1, ta, ma
    6004: 00000097             call    preserve_leaf
    6008: 8082                 ret
0000000000007000 <caller_wrapper>:
    7000: 0d0575d7             vsetvli a0, a0, e64, m2, tu, mu
    7004: 00000097             call    wrapper
    7008: 02050457             vadd.vv v8, v8, v16
    700c: 8082                 ret
"""
    )

    analysis = analyze_functions(functions)
    wrapper_summary = analysis.function_summaries[0x6000]
    vadd = functions[2].instructions[2]

    assert wrapper_summary.display() == "e32,m1,ta,ma"
    assert analysis.for_function(functions[2].start_addr).at(vadd.address).vtype_unknown is False
    assert analysis.for_function(functions[2].start_addr).at(vadd.address).known_specs()[0].sew == 32
    assert analysis.for_function(functions[2].start_addr).at(vadd.address).known_specs()[0].lmul == 1.0
    assert analysis.for_function(functions[2].start_addr).at(vadd.address).known_specs()[0].vta == 1
    assert analysis.for_function(functions[2].start_addr).at(vadd.address).known_specs()[0].vma == 1


def test_external_direct_call_is_explicitly_unknown():
    """dump 中没有外部函数体时，不根据 ABI 猜测其 vtype 效果。"""

    functions = _parse(
        """
0000000000007000 <caller_external>:
    7000: 0d057557             vsetvli a0, a0, e32, m1, ta, ma
    7004: 00000097             call    external_function
    7008: 02050457             vadd.vv v8, v8, v16
    700c: 8082                 ret
"""
    )

    analysis = analyze_functions(functions)
    vadd = functions[0].instructions[2]
    edge = analysis.structure.call_graph.edge_for_call(0x7004)

    assert edge is not None
    assert edge.resolved is False
    assert analysis.for_function(functions[0].start_addr).at(vadd.address).vtype_unknown is True
    candidate = next(iter(analysis.for_function(functions[0].start_addr).at(vadd.address).possible_vtypes))
    assert candidate.unknown_reason == "call target is external or unresolved"


def test_recursive_call_summary_is_conservative():
    """递归 SCC 内部不使用尚未稳定的 vtype 摘要。"""

    functions = _parse(
        """
0000000000008000 <recursive>:
    8000: 00000097             call    recursive
    8004: 02050457             vadd.vv v8, v8, v16
    8008: 8082                 ret
"""
    )

    analysis = analyze_functions(functions)
    vadd = functions[0].instructions[1]
    summary = analysis.function_summaries[0x8000]

    assert summary.has_unknown_effect is True
    assert analysis.for_function(functions[0].start_addr).at(vadd.address).vtype_unknown is True
    candidate = next(iter(analysis.for_function(functions[0].start_addr).at(vadd.address).possible_vtypes))
    assert "recursive" in (candidate.unknown_reason or "")


def test_cross_function_tail_call_is_not_a_local_fallthrough():
    """文本可解析的 tail 目标进入调用图，但不污染当前函数 CFG。"""

    functions = _parse(
        """
0000000000009000 <tail_target>:
    9000: 8082                 ret
000000000000a000 <tail_caller>:
    a000: 00000097             tail    tail_target
"""
    )

    analysis = analyze_functions(functions)
    caller = functions[1]
    edge = analysis.structure.call_graph.edge_for_call(0xa000)

    assert edge is not None
    assert edge.kind is CallEdgeKind.TAIL_CALL
    assert edge.resolved is True
    assert caller.instructions[0].successors == ()
    assert caller.cfg.unknown_exit is False


def test_cfg_records_direct_edges_without_adding_unconditional_fallthrough():
    """边审计信息与旧 block 后继同时保持正确。"""

    functions = _parse(
        """
000000000000b000 <direct_edges>:
    b000: 0000006f             j       b008 <.Ltarget>
    b004: 02050457             vadd.vv v8, v8, v16
000000000000b008 <.Ltarget>:
    b008: 8082                 ret
"""
    )

    analysis = analyze_functions(functions)
    function = functions[0]
    jump = function.instructions[0]
    edge_kinds = {
        edge.kind
        for edge in function.cfg.edges
        if edge.source_address == jump.address
    }

    assert jump.successors == (0xB008,)
    assert CFGEdgeKind.UNCONDITIONAL_JUMP in edge_kinds
    assert CFGEdgeKind.FALLTHROUGH not in edge_kinds
    assert analysis.structure.metrics.direct_edge_count >= 1
    assert analysis.metrics.unknown_vector_count == 1


def test_source_comment_is_ignored_by_parser_and_analysis():
    """旧 ``# source:`` 注释不能覆盖内部 CFG/vtype 分析结果。"""

    plain = _parse(
        """
0000000000005000 <commented>:
    5000: 0d057557             vsetvli a0, a0, e32, m1, tu, mu
    5004: 02050457             vadd.vv v8, v8, v16 # source: <e64,m8,ta,ma>
    5008: 8082                 ret
"""
    )
    result = analyze_functions(plain)
    instruction = plain[0].instructions[1]
    assert result.for_function(plain[0].start_addr).at(instruction.address).known_specs()[0].sew == 32
    assert result.structure.input_fingerprint
