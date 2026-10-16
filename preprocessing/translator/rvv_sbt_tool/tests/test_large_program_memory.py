"""Large-input regressions for compact analysis and streamed program output."""

import hashlib
import io
import json
import sys
import tempfile
import weakref

import pytest

from riscv.codegen import jal_range_fixup
from riscv.codegen.control_flow import ControlFlowEmitter
from riscv.frontend.analysis import analyze_structure
from riscv.frontend.call_graph import bottom_up_sccs
from riscv.frontend.model import CallEdge, CallEdgeKind, CallGraph
from riscv.frontend.model import CFGEdgeKind, InstructionBlockMap, RVFunction, RVInstruction, RVProgram, compute_program_fingerprint
from riscv.frontend.parser import AsmParser
from riscv.extensions.rvv.translation.pipeline import analyze_program
import rvv_sbt_rvv


def test_large_call_graph_orders_each_callee_before_its_callers():
    count = 10000
    edges = {
        caller: tuple(
            CallEdge(caller, caller * 16 + index, callee, None,
                     CallEdgeKind.DIRECT_CALL, callee, True, True)
            for index, callee in enumerate((0, caller - 1) if caller > 1 else (0,))
        )
        for caller in range(1, count)
    }
    # Start Tarjan at the leaf so the graph can be large without a deep DFS.
    graph = CallGraph(edges, {})
    components = bottom_up_sccs(graph, range(count))
    assert components == tuple(frozenset({vertex}) for vertex in range(count))


def test_compact_block_map_does_not_accept_addresses_between_instructions():
    expected = {0x1004: 0x1000, 0x1000: 0x1000, 2**64 - 4: 2**64 - 4}
    blocks = InstructionBlockMap(expected)
    assert dict(blocks) == expected
    assert blocks.get(0x1002) is None
    assert blocks.get(2**64) is None
    assert blocks.get(-1) is None
    assert len(InstructionBlockMap({})) == 0


def test_straight_line_cfg_uses_one_block_and_preserves_instruction_edges():
    instructions = [RVInstruction(i * 4, "nop", "") for i in range(4096)]
    instructions.append(RVInstruction(4096 * 4, "ret", ""))
    function = RVFunction("straight", 0, instructions)
    structure = analyze_structure(RVProgram([function]))
    cfg = structure.functions[0].cfg

    assert len(cfg.blocks) == 1
    assert len(cfg.edges) == 1
    assert cfg.reachable_addresses() == {insn.address for insn in instructions}
    for instruction, successor in zip(instructions, instructions[1:]):
        assert cfg.successors_for(instruction.address) == (successor.address,)
        edge, = cfg.edges_for_source(instruction.address)
        assert edge.kind is CFGEdgeKind.FALLTHROUGH
        assert edge.target_address == successor.address
    assert cfg.edges_for_source(instructions[-1].address)[0].kind is CFGEdgeKind.RETURN


def test_interior_call_target_starts_a_block():
    program = AsmParser().parse_string_program(
        "00001000 <entry>:\n"
        " 1000: 008000ef jal 1008 <entry+0x8>\n"
        " 1004: 00000013 nop\n"
        " 1008: 00000013 nop\n"
        " 100c: 00008067 ret\n"
    )
    cfg = analyze_structure(program).functions[0x1000].cfg
    assert set(cfg.blocks) == {0x1000, 0x1004, 0x1008}


def test_file_parser_consumes_an_iterator_without_readlines(monkeypatch):
    class Source(io.StringIO):
        def readlines(self, *args):
            raise AssertionError("whole input buffered")

    monkeypatch.setattr("builtins.open", lambda *args, **kwargs: Source(
        "00001000 <entry>:\n 1000: 00008067 ret\n"
    ))
    assert AsmParser().parse_file_program("input.dump").functions[0].instructions[0].opcode == "ret"


def test_shared_objdump_fields_keep_instruction_operands_independent():
    source = "00001000 <entry>:\n 1000: 00400513 li a0,4\n 1004: 00400513 li a0,4\n"
    first, second = AsmParser().parse_string_program(source).functions[0].instructions
    assert first.raw_bytes == second.raw_bytes == bytes.fromhex("00400513")
    assert first.op_str == second.op_str == "a0,4"
    assert first.raw_line != second.raw_line
    first.operands[0] = "a1"
    assert second.operands == ["a0", "4"]


def test_program_cli_can_discard_raw_lines_without_changing_semantics():
    source = "00001000 <entry>:\n 1000: 00400513 li a0,4\n 1004: 00008067 ret\n"
    retained = AsmParser().parse_string_program(source)
    compact = AsmParser(retain_raw_lines=False).parse_string_program(source)
    assert retained.functions[0].instructions[0].raw_line
    assert not compact.functions[0].instructions[0].raw_line
    assert compute_program_fingerprint(retained) == compute_program_fingerprint(compact)
    assert rvv_sbt_rvv.translate_program(retained) == rvv_sbt_rvv.translate_program(compact)


@pytest.mark.parametrize("empty", [False, True])
def test_incremental_fingerprint_matches_canonical_json(empty):
    program = AsmParser().parse_string_program(
        "00001000 <entry>:\n 1000: 0000006f j 2000 <callee>\n"
        "00002000 <callee>:\n 2000: 00008067 ret\n"
    ) if not empty else RVProgram()
    payload = [
        {"name": f.name, "start_addr": f.start_addr, "instructions": [
            {"address": i.address, "opcode": i.opcode,
             "operands": [str(o) for o in i.operands],
             "target_address": i.target_address, "target_symbol": i.target_symbol}
            for i in f.instructions
        ]}
        for f in program.functions
    ]
    expected = hashlib.sha256(json.dumps(
        payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
    ).encode("utf-8")).hexdigest()
    assert compute_program_fingerprint(program) == expected


def test_sparse_vtype_results_preserve_scalar_avl_propagation():
    program = AsmParser().parse_string_program(
        "00001000 <entry>:\n"
        " 1000: 00400513 li a0,4\n"
        " 1004: 0d0575d7 vsetvli a1,a0,e32,m1,tu,mu\n"
        " 1008: 02050457 vadd.vv v8,v8,v16\n"
        " 100c: 00008067 ret\n"
    )
    analysis = analyze_program(program).functions[0x1000]
    assert set(analysis.instructions) == {0x1004, 0x1008}
    candidate, = analysis.at(0x1008).possible_vtypes
    assert candidate.avl.value == 4
    assert candidate.vta == 0
    assert candidate.vma == 0


def test_lazy_address_labels_keep_membership_and_spelling():
    function = RVFunction("entry", 0x1000, [RVInstruction(0x1000, "ret", "")])
    labels = ControlFlowEmitter(lookup_profile=1).build_program_context([function])["address_labels"]
    assert dict(labels) == {0x1000: "branch_j_target_1000"}
    assert labels.get(0x1004) is None
    with pytest.raises(KeyError):
        labels[0x1004]


def test_streamed_fixup_preserves_output_and_publishes_after_validation(monkeypatch, tmp_path):
    program = AsmParser().parse_string_program("00001000 <entry>:\n 1000: 00008067 ret\n")
    output = tmp_path / "output.s"
    output.write_text("old output")
    compiled = []

    def compile_object(**kwargs):
        assert output.read_text() == "old output"
        compiled.append(kwargs["source_path"].read_text())

    monkeypatch.setattr(jal_range_fixup, "_compile_object", compile_object)
    monkeypatch.setattr(jal_range_fixup, "inspect_object", lambda *args, **kwargs:
        jal_range_fixup.RelocationReport(frozenset(), (), ()))
    result, sites = rvv_sbt_rvv.translate_program_with_jal_range_fixup(program, output_path=output)
    assert result is None
    assert sites == frozenset()
    assert output.read_text() == rvv_sbt_rvv.translate_program(program)
    assert len(compiled) == 2


def test_readelf_stream_reports_child_failure():
    with pytest.raises(jal_range_fixup.JalRangeFixupError, match="readelf failed"):
        list(jal_range_fixup._run_lines([
            sys.executable, "-c", "import sys; print('readelf failed', file=sys.stderr); sys.exit(3)",
        ]))


def test_file_translation_releases_full_ir_and_prepares_once(monkeypatch, tmp_path):
    source = tmp_path / "source.dump"
    source.write_text(
        "00001000 <foo>:\n"
        " 1000: 00400513 li a0,4\n"
        " 1004: 0d0575d7 vsetvli a1,a0,e32,m1,tu,mu\n"
        " 1008: 0080006f j 1010\n"
        " 100c: 02050457 vadd.vv v8,v8,v16\n"
        " 1010: 00008067 ret\n"
        "00002000 <bar>:\n"
        " 2000: 000000ef call 1000 <foo>\n"
        " 2004: 00008067 ret\n"
    )
    references = []
    original_prepare = rvv_sbt_rvv._prepare_program_translation

    def prepare(program, **kwargs):
        references.append(weakref.ref(program))
        return original_prepare(program, **kwargs)

    compiled = []
    def compile_object(**kwargs):
        assert all(reference() is None for reference in references)
        compiled.append(kwargs["source_path"].read_text())

    reports = iter([
        jal_range_fixup.RelocationReport(frozenset({0x1008}), (), ()),
        jal_range_fixup.RelocationReport(frozenset(), (), ()),
        jal_range_fixup.RelocationReport(frozenset(), (), ()),
    ])
    monkeypatch.setattr(rvv_sbt_rvv, "_prepare_program_translation", prepare)
    monkeypatch.setattr(jal_range_fixup, "_compile_object", compile_object)
    monkeypatch.setattr(jal_range_fixup, "inspect_object", lambda *a, **kw: next(reports))
    output = tmp_path / "translated.s"
    result, sites = rvv_sbt_rvv.translate_file_with_jal_range_fixup(source, output_path=output)
    assert result is None
    assert sites == frozenset({0x1008})
    assert len(references) == 1
    assert len(compiled) == 3
    expected = rvv_sbt_rvv.translate_program(
        AsmParser().parse_file_program(str(source)), long_jump_sites=sites,
    )
    assert output.read_text() == expected


def test_stored_program_preserves_order_fingerprint_and_cfg_identity(tmp_path):
    source = tmp_path / "aliases.dump"
    source.write_text(
        "00001000 <empty_alias>:\n"
        "00001000 <foo>:\n 1000: 00008067 ret\n"
        "00002000 <bar>:\n 2000: 00008067 ret\n"
    )
    with tempfile.TemporaryFile() as storage:
        _, prepared, _ = rvv_sbt_rvv._prepare_stored_file(
            source, storage, vlenb=128, init_vtype=None,
            state_base_mode="initial-exec", wide_lmul=True,
        )
        assert [f.name for f in prepared.program.functions] == ["empty_alias", "foo", "bar"]
        assert compute_program_fingerprint(prepared.program) == prepared.analysis.structure.input_fingerprint
        function = prepared.program.functions[-1]
        assert function.cfg is prepared.analysis.for_function(function.start_addr).structure.cfg


def test_missing_compiler_is_not_reported_as_missing_input(monkeypatch, tmp_path, capsys):
    source = tmp_path / "source.dump"
    source.write_text("00001000 <foo>:\n 1000: 00008067 ret\n")
    compiler = tmp_path / "missing-compiler"
    monkeypatch.setattr(sys, "argv", [
        "rvv_sbt_rvv.py", str(source), "demo", "-o", str(tmp_path / "out.s"),
        "--jal-range-fixup-compiler", str(compiler),
    ])
    with pytest.raises(SystemExit) as error:
        rvv_sbt_rvv.main()
    assert error.value.code == 1
    stderr = capsys.readouterr().err
    assert str(compiler) in stderr
    assert "Input file not found" not in stderr
