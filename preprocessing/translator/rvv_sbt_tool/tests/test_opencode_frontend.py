"""Source provenance, control-flow parsing, and scalar fact regressions."""

from typing import get_type_hints

import pytest

from riscv.codegen.control_flow import ControlFlowEmitter
from riscv.extensions.rvv.analysis.dataflow import VectorConfigAnalyzer
from riscv.extensions.rvv.analysis.model import AVLKind, VTypeSpec, parse_init_vtype
from riscv.extensions.rvv.translation.pipeline import analyze_program
from riscv.frontend.model import RVFunction, RVInstruction, RVProgram, compute_program_fingerprint
from riscv.frontend.parser import AsmParser
from riscv.frontend.text_index import TextProgramIndex
from test_control_flow_review_fixes import _execute


def test_public_analysis_annotations_resolve():
    assert get_type_hints(VectorConfigAnalyzer.analyze_program)["initial_vtype"] == VTypeSpec | None
    assert get_type_hints(compute_program_fingerprint)["program"] is RVProgram


@pytest.mark.parametrize("call", [
    "call callee", "jal callee", "jal ra,callee", "jal x1,callee", "jalr ra,a5,0",
])
def test_calls_clear_alias_constants_but_keep_callee_saved_values(call):
    instructions = AsmParser().parse_string(
        f"li x10,5\nli x8,7\naddi fp,s0,1\n{call}\n"
        "vsetvli zero,x10,e32,m1,tu,mu\nvadd.vv v8,v16,v24\n"
        "vsetvli zero,fp,e32,m1,tu,mu\nvadd.vv v8,v16,v24\nret"
    )
    callee = RVFunction("callee", 0x1000, [RVInstruction(0x1000, "ret", "")])
    analysis = analyze_program(RVProgram([RVFunction("caller", 0, instructions), callee]))
    caller = analysis.for_function(0)
    clobbered, = caller.at(20).possible_vtypes
    preserved, = caller.at(28).possible_vtypes
    assert clobbered.avl.kind is AVLKind.UNKNOWN
    assert preserved.avl.kind is AVLKind.CONSTANT and preserved.avl.value == 8


@pytest.mark.parametrize("jump", ["j next", "jal zero,next", "jal x0,next"])
def test_no_link_jumps_preserve_scalar_constants(jump):
    instructions = AsmParser().parse_string(
        f"li x10,5\n{jump}\nnext:\nvsetvli zero,a0,e32,m1,tu,mu\nvadd.vv v8,v16,v24"
    )
    analysis = analyze_program(RVProgram([RVFunction("caller", 0, instructions)]))
    candidate, = analysis.for_function(0).at(12).possible_vtypes
    assert candidate.avl.kind is AVLKind.CONSTANT and candidate.avl.value == 5


def test_section_names_do_not_accept_text_substrings():
    source = "\n".join(
        f"Disassembly of section {section}:\n{address:x} <{name}>:\n {address:x}: 00000013 nop"
        for section, address, name in [
            (".text", 0x1000, "code"), (".rela.text", 0x2000, "relocations"),
            (".textual", 0x3000, "data"), (".text.hot", 0x4000, "hot_code"),
            (".plt.sec", 0x5000, "callee@plt"),
        ]
    )
    parser = AsmParser()
    assert [i.address for i in parser.parse_string(source)] == [0x1000, 0x4000]
    assert [f.name for f in parser.parse_string_program(source).functions] == [
        "code", "hot_code", "callee@plt",
    ]


@pytest.mark.parametrize("name", ["abc", "add", "dead"])
def test_undefined_hex_like_symbols_are_not_addresses(name):
    plain = AsmParser().parse_string(f"call {name}")[0]
    program = RVProgram([RVFunction("caller", 0, [plain])])
    assert TextProgramIndex.build(program).resolve_target(plain) is None
    program.symbols[name] = 0x2000
    assert TextProgramIndex.build(program).resolve_target(plain) == 0x2000
    dump = AsmParser().parse_string(f"1000: 000000ef jal {name}")[0]
    assert TextProgramIndex.build([]).resolve_target(dump) == int(name, 16)


def test_explicit_global_label_wins_during_index_construction():
    instruction = RVInstruction(0x1000, "nop", "", label="shared")
    program = RVProgram([RVFunction("caller", 0x1000, [instruction])],
                        global_labels={"shared": 0x2000})
    assert TextProgramIndex.build(program).label_to_address["shared"] == 0x2000


@pytest.mark.parametrize("text,disassembled,immediate", [
    ("4096", False, 4096), ("4096", True, 0x4096),
    ("01", False, 1), ("010", False, 8), ("0b1", False, 1),
    ("524288", False, 0x80000), ("80000", True, 0x80000), ("-1", False, -1),
])
def test_auipc_emission_and_plt_index_use_the_same_source_semantics(
    tmp_path, text, disassembled, immediate,
):
    instruction = AsmParser().parse_string(f"auipc a0,{text}")[0]
    instruction.address = 0x80001000
    if disassembled:
        instruction.raw_bytes_hex = f"{((immediate & 0xfffff) << 12) | 0x517:08x}"
    displacement = (immediate & 0xfffff) << 12
    if displacement & 0x80000000:
        displacement -= 1 << 32
    target = instruction.address + displacement
    jump = RVInstruction(instruction.address + 4, "jalr", "ra,0(a0)", operands=["ra", "0(a0)"])
    stub = RVFunction("callee@plt", target, [RVInstruction(target, "nop", "")])
    program = RVProgram([RVFunction("caller", instruction.address, [instruction, jump]), stub])
    assert TextProgramIndex.build(program).plt_call_candidates()[jump.address].address == target
    body = "\n".join(ControlFlowEmitter(lookup_profile=1).emit_program_scalar(
        instruction, instruction.operands, "original_base", context=None,
        active_long_jump_veneers={},
    ))
    _execute(tmp_path, f"""
.option norelax
.text
.globl _start
_start:
    la sp,stack_end
    la t0,fail
    csrw mtvec,t0
{body}
    li t1,{0x10000000 + target}
    bne a0,t1,fail
    li t0,0x100000
    li t1,0x5555
    sw t1,0(t0)
1:  j 1b
.balign 4
fail:
    li t0,0x100000
    li t1,0x13333
    sw t1,0(t0)
2:  j 2b
.data
.balign 8
original_base:
    .dword 0x10000000
.bss
.balign 16
    .skip 4096
stack_end:
""")


@pytest.mark.parametrize("command", [
    "jalr ra,08(a0)", "jalr ra,a0,08", "jalr ra,09(a0)", "jalr ra,a0,09",
    "jalr ra,bad(a0)", "jalr ra,a0,bad", "jr bad(a0)", "jalr",
])
def test_invalid_jalr_has_instruction_context(command):
    instruction = AsmParser().parse_string(command)[0]
    instruction.address = 0x124
    with pytest.raises(ValueError, match=r"Invalid .* at 0x124"):
        ControlFlowEmitter(lookup_profile=1).emit_program_scalar(
            instruction, instruction.operands, "original_base", context=None,
            active_long_jump_veneers={},
        )


@pytest.mark.parametrize("operand", ["16(a0)", "0x10(a0)", "0X10(a0)", "020(a0)", "0b10000(a0)"])
def test_jalr_valid_offsets_keep_the_remap_path(operand):
    instruction = AsmParser().parse_string(f"jalr ra,{operand}")[0]
    output = "\n".join(ControlFlowEmitter(lookup_profile=1).emit_program_scalar(
        instruction, instruction.operands, "original_base", context=None,
        active_long_jump_veneers={},
    ))
    assert "query_original_translated_map" in output
    assert "addi    a1, a1, 16" in output


def test_init_vtype_documented_defaults_are_tu_mu():
    spec = parse_init_vtype("sew=32,lmul=2")
    assert (spec.vta, spec.vma) == (0, 0)


@pytest.mark.parametrize("token,expected", [("010", 8), ("0b1000", 8), ("0X10", 16)])
def test_symbolic_numeric_target_uses_source_radix(token, expected):
    instruction = AsmParser().parse_string(f"j {token}")[0]
    assert TextProgramIndex.build([]).resolve_target(instruction) == expected
