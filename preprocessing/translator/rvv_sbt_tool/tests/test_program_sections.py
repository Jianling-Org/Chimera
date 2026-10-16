"""Program section partitioning and object-level range checks."""

import shutil

import pytest

import rvv_sbt_rvv
from riscv.codegen.jal_range_fixup import _compile_object, inspect_object
from riscv.extensions.rvv.translation import emitter
from riscv.frontend.parser import AsmParser


def _program():
    return AsmParser().parse_string_program(
        "00001000 <first>:\n 1000: 00000013 nop\n 1004: 00008067 ret\n"
        "00002000 <second>:\n 2000: 00000013 nop\n 2004: 00008067 ret\n"
        "00003000 <third>:\n 3000: 00000013 nop\n 3004: 00008067 ret\n"
        "00004000 <fourth>:\n 4000: 00000013 nop\n 4004: 00008067 ret\n"
        "00005000 <fifth>:\n 5000: 00000013 nop\n 5004: 00008067 ret\n"
    )


def test_program_partitions_only_between_complete_functions(monkeypatch):
    original = rvv_sbt_rvv.translate_program(_program())
    monkeypatch.setattr(emitter, "_PROGRAM_SECTION_INSTRUCTIONS", 3)
    partitioned = rvv_sbt_rvv.translate_program(_program())

    directives = [line for line in partitioned.splitlines() if "@progbits,unique," in line]
    assert directives == [
        '    .section .text,"ax",@progbits,unique,1',
        '    .section .text,"ax",@progbits,unique,2',
    ]
    assert partitioned.index(directives[0]) > partitioned.index(".size   second_translated")
    assert partitioned.index(directives[0]) < partitioned.index(".globl  third_translated")
    assert partitioned.index(directives[1]) > partitioned.index(".size   fourth_translated")
    for directive in directives:
        partitioned = partitioned.replace(directive + "\n", "")
    assert partitioned == original


def test_text_only_program_keeps_its_section_contract(monkeypatch):
    monkeypatch.setattr(emitter, "_PROGRAM_SECTION_INSTRUCTIONS", 1)
    output = rvv_sbt_rvv.translate_program(_program(), text_only=True)
    assert ".section" not in output
    assert "branch_j_target_5004:" in output


# The raw section offset fits; the preceding four-byte jump makes it overflow.
@pytest.mark.parametrize("distance,out_of_range", [(0xFFFFC, True), (0x100, False)])
def test_range_checks_use_merged_section_addresses(tmp_path, distance, out_of_range):
    compiler = shutil.which("riscv64-elf-gcc")
    readelf = shutil.which("riscv64-elf-readelf")
    if compiler is None or readelf is None:
        pytest.skip("RISC-V GNU compiler and readelf are required")
    source = tmp_path / "sections.s"
    source.write_text(
        "    .text\n    .option norvc\n"
        "chimera_j_site_1000:\n    j branch_j_target_2000\n"
        '    .section .text,"ax",@progbits,unique,1\n'
        f"    .space {distance}\n"
        "branch_j_target_2000:\n    nop\n"
    )
    obj = tmp_path / "sections.o"
    _compile_object(
        compiler=compiler, source_path=source, object_path=obj,
        compiler_args=("-march=rv64gc", "-mabi=lp64d"),
    )
    report = inspect_object(obj, readelf=readelf)
    assert report.out_of_range_sites == (frozenset({0x1000}) if out_of_range else frozenset())
    assert not report.unclassified_issues
    assert not report.branch_issues
