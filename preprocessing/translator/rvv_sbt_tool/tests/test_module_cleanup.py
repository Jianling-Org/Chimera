"""Data-flow and dependency checks for the module and dead-code cleanup."""

import ast
from dataclasses import fields, replace
from pathlib import Path

import pytest

from riscv.frontend.analysis import analyze_structure, validate_structure
from riscv.frontend.cfg import CFGBuilder
from riscv.frontend.model import CFGEdgeKind, ControlFlowEdge, RVFunction, RVInstruction, RVProgram
from riscv.frontend.parser import AsmParser
from riscv.frontend.text_index import TextProgramIndex
from riscv.extensions.rvv.analysis.config import StateTracker
from riscv.extensions.rvv.backends.scalar.backend import ScalarDispatcher
from riscv.extensions.rvv.backends.rvv256.backend import RVV256Dispatcher
from riscv.extensions.rvv.backends.rvv1024_transition.backend import RVV1024Dispatcher
from riscv.extensions.rvv.backends.rvv256.handlers.arithmetic.floating import _build_vfnmsac_vf_lines
from riscv.extensions.rvv.translation.contracts import HandlerContext, InstructionValidationError, LoweringResult
from riscv.extensions.rvv.translation.specs import HandlerRegistry
from riscv.extensions.rvv.translation.temps import capture_clobbers
from riscv.extensions.rvv.runtime.layout import SimulatedStateLayout


ROOT = Path(__file__).resolve().parents[1] / 'src'


def test_normalized_operands_reach_lowering_without_changing_source_instruction():
    backend = ScalarDispatcher()
    source = RVInstruction(0x40, 'vadd.vv', 'original operands', operands=['original'])
    state = StateTracker(vlenb=128)
    context = backend.make_context(source, state, SimulatedStateLayout())
    spec = backend.registry.get('vadd.vv')

    def lower(bound, plan):
        assert bound.instruction is not source
        assert bound.instruction.address == source.address
        assert bound.instruction.op_str == 'original operands'
        assert bound.instruction.operands == ['v8', 'v16', 'v24']
        assert plan.instruction is source
        return LoweringResult.lowered(('    nop',))

    registry = HandlerRegistry()
    registry.register(replace(spec, validator=lambda _: ('v8', 'v16', 'v24'), lowerer=lower))
    result = registry.lower(context, registry.plan(context))
    assert result.is_lowered
    assert source.operands == ['original']


def test_handler_context_contains_only_instruction_local_dependencies():
    assert {f.name for f in fields(HandlerContext)} == {
        'instruction', 'state', 'layout', 'new_label', 'temp_register_allocator', 'spec',
    }


def test_transition_guard_remains_inside_lowering_clobber_capture():
    backend = RVV1024Dispatcher()
    source = RVInstruction(0x20, 'vadd.vv', 'v8, v16, v24', operands=['v8', 'v16', 'v24'])
    state = StateTracker(vlenb=32)
    state.apply_init_vtype('sew=32,lmul=1')
    context = backend.make_context(source, state, SimulatedStateLayout(vlenb=32))
    with capture_clobbers() as outer:
        result = backend.lower(context, backend.plan(context))
    assert not outer.gprs
    assert {'t0', 't1', 't2'} <= result.clobbered_gprs
    assembly = '\n'.join(result.assembly_lines)
    assert assembly.index('bne') < assembly.index('vadd.vv v')
    assert 'csrw    vcsr' in assembly
    assert '源 CSR.vstart = 0' in assembly
    assert not hasattr(backend, '_emit_guarded_block')


def test_conservative_masked_vfnmsac_rejects_before_using_unallocated_mask_temps():
    backend = RVV256Dispatcher(wide_lmul=False)
    source = RVInstruction(0, 'vfnmsac.vf', 'v8, fa0, v16, v0.t', operands=['v8', 'fa0', 'v16', 'v0.t'])
    state = StateTracker(vlenb=128)
    context = backend.make_context(source, state, SimulatedStateLayout())
    with pytest.raises(InstructionValidationError, match='does not support masked'):
        _build_vfnmsac_vf_lines(context)


def test_source_modules_have_no_import_cycles_or_validation_handler_dependencies():
    modules = {'.'.join(p.relative_to(ROOT).with_suffix('').parts).removesuffix('.__init__'): p
               for p in ROOT.rglob('*.py')}
    graph = {name: set() for name in modules}
    for name, path in modules.items():
        for node in ast.walk(ast.parse(path.read_text())):
            dependencies = []
            if isinstance(node, ast.ImportFrom):
                base = node.module or ''
                if node.level:
                    base = '.'.join(name.split('.')[:-node.level] + ([base] if base else []))
                dependencies = [base, *(base + '.' + n.name for n in node.names)]
            elif isinstance(node, ast.Import):
                dependencies = [n.name for n in node.names]
            for dependency in dependencies:
                if path.stem in {'operands', 'validation'}:
                    assert '.handlers' not in dependency, (path, dependency)
                if name.startswith('riscv.extensions.rvv.analysis'):
                    assert not dependency.startswith(('riscv.extensions.rvv.runtime', 'riscv.extensions.rvv.translation', 'riscv.extensions.rvv.backends'))
                if name.endswith('translation.dispatch'):
                    assert dependency != 'riscv.extensions.rvv.translation.pipeline'
                if dependency in modules:
                    graph[name].add(dependency)
    visited, active = set(), set()

    def visit(name):
        assert name not in active, name
        if name in visited:
            return
        active.add(name)
        for dependency in graph[name]:
            visit(dependency)
        active.remove(name)
        visited.add(name)

    for name in modules:
        visit(name)


def test_structure_analysis_shares_one_index_and_standalone_cfg_still_works(monkeypatch):
    program = AsmParser().parse_string_program(
        "0000000000001000 <caller>:\n"
        "    1000: 000000ef call 2000 <callee>\n"
        "    1004: 8082 ret\n"
        "0000000000002000 <callee>:\n"
        "    2000: 8082 ret\n"
    )
    original_build = TextProgramIndex.build
    built = []

    def counted_build(cls, source):
        result = original_build(source)
        built.append(result)
        return result

    monkeypatch.setattr(TextProgramIndex, 'build', classmethod(counted_build))
    structure = analyze_structure(program)
    assert len(built) == 1
    call = structure.call_graph.edge_for_call(0x1000)
    assert call.resolved
    assert call.target_function_start == 0x2000

    built.clear()
    standalone = CFGBuilder().build_program_cfg(program)
    assert len(built) == 1
    assert standalone.functions == {
        start: function.cfg for start, function in structure.functions.items()
    }


@pytest.mark.parametrize('target', [None, 0x9000])
def test_structure_validation_rejects_missing_declared_target_but_allows_external(target):
    program = RVProgram(functions=[RVFunction(
        'caller', 0x1000, [RVInstruction(0x1000, 'ret', '', operands=[])],
    )])
    structure = analyze_structure(program)
    function = structure.functions[0x1000]
    edge = ControlFlowEdge(
        source_address=0x1000,
        target_address=target,
        kind=CFGEdgeKind.DIRECT_CALL,
        resolved=True,
    )
    structure = replace(structure, functions={
        0x1000: replace(function, cfg=replace(function.cfg, edges=(edge,))),
    })
    if target is None:
        with pytest.raises(ValueError, match='控制流边缺少已声明目标'):
            validate_structure(program, structure)
    else:
        validate_structure(program, structure)


def test_duplicate_function_names_keep_distinct_address_based_targets():
    from rvv_sbt_rvv import translate_program

    program = RVProgram(functions=[
        RVFunction('same', 0x1000, [RVInstruction(
            0x1000, 'j', '2000', operands=['2000'], target_address=0x2000,
        )]),
        RVFunction('same', 0x2000, [RVInstruction(0x2000, 'ret', '', operands=[])]),
    ])
    output = translate_program(program, text_only=True)
    assert 'same_1000_translated:' in output
    assert 'same_2000_translated:' in output
    assert 'j       branch_j_target_2000' in output
    assert 'tail    same_2000_translated' not in output


@pytest.mark.parametrize('entry', ['translate', 'translate_function', 'translate_program'])
def test_transition_public_entries_validate_direction_once(monkeypatch, entry):
    import rvv_sbt_rvv1024 as translator
    import riscv.extensions.rvv.backends.rvv1024_transition.backend as backend

    original_lookup = backend.geometry_for_direction
    directions = []

    def counted_lookup(source, target):
        directions.append((source, target))
        return original_lookup(source, target)

    monkeypatch.setattr(backend, 'geometry_for_direction', counted_lookup)
    instructions = AsmParser().parse_string('vadd.vv v8, v16, v24')
    function = RVFunction('vector', 0, instructions)
    source = {
        'translate': instructions,
        'translate_function': function,
        'translate_program': RVProgram(functions=[function]),
    }[entry]
    translate = getattr(translator, entry)
    output = translate(source, init_vtype='sew=32,lmul=1')
    assert 'vadd.vv' in output
    assert directions == [(32, 128)]

    directions.clear()
    with pytest.raises(ValueError):
        translate(source, source_vlenb=64, target_vlenb=128)
    assert directions == [(64, 128)]
