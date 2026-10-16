"""Keep accepted immediates consistent with the source assembler."""

import pytest

from riscv.extensions.rvv.analysis.dataflow import VectorConfigAnalyzer
from riscv.extensions.rvv.runtime.contract import RVV1024_TO_RVV256
from riscv.frontend.literals import parse_integer_literal
from riscv.frontend.parser import AsmParser
from test_review_arithmetic_execution import _compare
from test_review_reverse_state import _check
from test_rvv256_vstart import riscv_tools


@pytest.mark.parametrize("literal,value", [("01", 1), ("010", 8), ("037", 31),
                                          ("0X1", 1), ("0b1", 1), ("-010", -8)])
def test_literal_value_and_analysis_agree(literal, value):
    assert parse_integer_literal(literal) == value
    assert VectorConfigAnalyzer._parse_integer(literal) == value


@pytest.mark.parametrize("literal", ["08", "09", "0o10", "1_0", "0b2", "dead", "--1"])
def test_non_assembler_integer_is_not_accepted(literal):
    with pytest.raises(ValueError):
        parse_integer_literal(literal)


@pytest.mark.parametrize("literal", ["01", "010", "0X1", "0b1"])
@pytest.mark.parametrize("backend", ["scalar", "conservative", "wide"])
def test_vsetivli_literal_matches_source_execution(tmp_path, riscv_tools, literal, backend):
    symbol = ("simulated_cpu_state" if backend == "scalar"
              else RVV1024_TO_RVV256.non_tls_state_symbol)
    command = (f"vsetivli a0,{literal},e32,m1,tu,mu\ncsrr t1,vl\n"
               f"la t0,{symbol}\nli t2,0x1020\nadd t0,t0,t2\nsd t1,0(t0)")
    _compare(tmp_path, riscv_tools, command, backend=backend, lengths=[1, 9])


@pytest.mark.parametrize("literal,value", [("01", 1), ("010", 8), ("0X1", 1), ("0b1", 1)])
def test_reverse_vsetivli_literal_matches_source(tmp_path, riscv_tools, literal, value):
    _check(tmp_path, riscv_tools, f"vsetivli a0,{literal},e32,m1,tu,mu\ncsrr a1,vstart",
           expected=f"*(uint64_t*)(want+0x1020)={value};",
           observed=f"observed[0]=={value} && observed[1]==0")


@pytest.mark.parametrize("opcode", ["vslidedown.vi", "vsll.vi", "vsrl.vi"])
@pytest.mark.parametrize("backend", ["wide", "conservative"])
def test_octal_vector_immediate_matches_source(tmp_path, riscv_tools, opcode, backend):
    _compare(tmp_path, riscv_tools, f"{opcode} v8,v16,010", backend=backend,
             lengths=[1, 9, 32])
