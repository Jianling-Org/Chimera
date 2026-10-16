"""Regressions for shared input, state and emission review findings."""

import pytest

from riscv.extensions.rvv.translation.contracts import UnsupportedInstructionError
from riscv.extensions.rvv.translation.temps import TempRegisterAllocator
from riscv.extensions.rvv.backends.rvv1024_transition.preflight import TransitionPreflightError
from riscv.extensions.spacemit_ime.translation import parse_source
from riscv.frontend.parser import AsmParser
from riscv.frontend.model import RVFunction
from rvv_sbt import translate as scalar_translate
from rvv_sbt_rvv import translate
from test_review_arithmetic_execution import _compare
from test_rvv256_vstart import riscv_tools


@pytest.mark.parametrize("sew", [8, 16, 32, 64])
@pytest.mark.parametrize("register", ["t6", "x31"])
def test_scalar_insert_reads_guest_t6(tmp_path, riscv_tools, sew, register):
    _compare(tmp_path, riscv_tools, f"vmv.s.x v8,{register}", sew=sew,
             backend="scalar", setup="li t6,123", lengths=[0, 1])


@pytest.mark.parametrize("mask", ["v0.t", "V0.t", "V0.T"])
def test_scalar_mask_spelling_does_not_bypass_overlap(mask):
    with pytest.raises(UnsupportedInstructionError, match="must not overlap v0"):
        scalar_translate(AsmParser().parse_string(f"vadd.vv v0,v1,v2,{mask}"),
                         init_vtype="sew=32,lmul=1,tu,mu", raw=True)


@pytest.mark.parametrize("value", ["-1", "32", "bad"])
def test_scalar_vsetivli_rejects_invalid_immediate(value):
    with pytest.raises(UnsupportedInstructionError, match="0..31"):
        scalar_translate(AsmParser().parse_string(f"vsetivli a0,{value},e32,m1,tu,mu"),
                         raw=True)


def test_scalar_vsetivli_uppercase_hex_is_not_zero():
    output = scalar_translate(AsmParser().parse_string("vsetivli a0,0X1,e32,m1,tu,mu"),
                              raw=True)
    assert "imm=1," in output
    assert "imm=0," not in output


@pytest.mark.parametrize("operands,index", [("v8,v16,a0", 3), ("v8,a1,v24", 2),
                                           ("a0,a1,a2", 1)])
def test_bad_reduction_operand_has_a_source_diagnostic(operands, index):
    output = translate(AsmParser().parse_string("vredsum.vs " + operands),
                       init_vtype="sew=32,lmul=1,tu,mu", raw=True)
    assert f"Operand {index} must be a vector register" in output
    assert "fallback" in output


def test_reserved_register_aliases_are_not_allocated():
    allocator = TempRegisterAllocator(None, reserved_gprs=("x5",), reserved_fprs=("f0",))
    assert allocator.alloc_gpr() == "t1"
    assert allocator.alloc_fpr() == "ft1"


def test_early_return_does_not_remove_fragment_terminator():
    output = scalar_translate(AsmParser().parse_string("beqz a0,.Lend\nret\n.Lend:\nnop"))
    assert sum(line.strip() == "ret" for line in output.splitlines()) == 2


@pytest.mark.parametrize("header", ["file format elf64-littleriscv",
                                    "Disassembly of section .rodata:",
                                    "demo.o:     file format elf64-littleriscv"])
def test_ime_rejects_headers_before_plan_addresses_drift(header):
    with pytest.raises(ValueError, match="not objdump"):
        parse_source(header + "\nadd a0,a1,a2\n")


@pytest.mark.parametrize("label", ["1", "f", "dead"])
def test_ime_accepts_hex_like_inline_labels(label):
    program, lines = parse_source(f"{label}: add a0,a1,a2\n")
    assert [insn.opcode for insn in program.instructions] == ["add"]
    assert lines[0].address == 0


@pytest.mark.parametrize("direction", ["forward", "reverse"])
def test_strict_function_entry_rejects_unsupported_opcode(direction):
    from rvv_sbt_rvv import translate_function as forward
    from rvv_sbt_rvv1024 import translate_function as reverse

    function = RVFunction("unknown", 0, AsmParser().parse_string("vunknown.vv v8,v16,v24"))
    entry = forward if direction == "forward" else reverse
    with pytest.raises((UnsupportedInstructionError, TransitionPreflightError), match="vunknown"):
        entry(function, init_vtype="sew=32,lmul=1,tu,mu", strict=True)


@pytest.mark.parametrize("entry", ["rvv_sbt.py", "rvv_sbt_rvv.py"])
def test_conflicting_cli_modes_do_not_create_output(tmp_path, entry):
    import subprocess
    import sys
    from pathlib import Path

    output = tmp_path / "result.s"
    result = subprocess.run([sys.executable, str(Path(__file__).parents[1] / entry),
                             "unused", "library", "-c", "nop", "-o", str(output)],
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 2
    assert "不能" in result.stderr
    assert not output.exists()


def test_reverse_atomic_output_keeps_existing_file_on_replace_error(tmp_path, monkeypatch):
    import sys
    from pathlib import Path
    import rvv_sbt_rvv1024

    output = tmp_path / "old.s"
    output.write_text("old output")
    monkeypatch.setattr(sys, "argv", ["rvv_sbt_rvv1024.py", "-c", "nop", "-o", str(output)])
    monkeypatch.setattr(rvv_sbt_rvv1024, "translate", lambda *args, **kwargs: "new output")

    def fail_replace(self, destination):
        raise OSError("simulated publication failure")

    monkeypatch.setattr(Path, "replace", fail_replace)
    with pytest.raises(SystemExit) as error:
        rvv_sbt_rvv1024.main()
    assert error.value.code == 1
    assert output.read_text() == "old output"
    assert list(tmp_path.iterdir()) == [output]


@pytest.mark.parametrize("existing", [False, True])
def test_reverse_atomic_output_preserves_creation_permissions(tmp_path, monkeypatch, existing):
    import stat
    import sys
    import rvv_sbt_rvv1024

    output = tmp_path / "result.s"
    reference = tmp_path / "reference.s"
    reference.write_text("reference")
    expected_mode = stat.S_IMODE(reference.stat().st_mode)
    if existing:
        output.write_text("old")
        output.chmod(0o640)
        expected_mode = 0o640
    monkeypatch.setattr(sys, "argv", ["rvv_sbt_rvv1024.py", "-c", "nop", "-o", str(output)])
    monkeypatch.setattr(rvv_sbt_rvv1024, "translate", lambda *args, **kwargs: "new")
    rvv_sbt_rvv1024.main()
    assert output.read_text() == "new"
    assert stat.S_IMODE(output.stat().st_mode) == expected_mode


def test_reverse_internal_error_keeps_traceback(tmp_path, monkeypatch, capsys):
    import sys
    import rvv_sbt_rvv1024

    output = tmp_path / "out.s"
    monkeypatch.setattr(sys, "argv", ["rvv_sbt_rvv1024.py", "-c", "nop", "-o", str(output)])

    def fail_translate(*args, **kwargs):
        raise RuntimeError("internal-probe")

    monkeypatch.setattr(rvv_sbt_rvv1024, "translate", fail_translate)
    with pytest.raises(SystemExit):
        rvv_sbt_rvv1024.main()
    error = capsys.readouterr().err
    assert "Traceback" in error and "RuntimeError: internal-probe" in error
    assert not output.exists()


def test_ime_missing_input_has_cli_diagnostic(tmp_path, monkeypatch, capsys):
    import sys
    import ime_sbt_rvv

    missing = tmp_path / "missing.s"
    monkeypatch.setattr(sys, "argv", ["ime_sbt_rvv.py", str(missing)])
    with pytest.raises(SystemExit) as error:
        ime_sbt_rvv.main()
    assert error.value.code == 2
    diagnostic = capsys.readouterr().err
    assert str(missing) in diagnostic and "Traceback" not in diagnostic
