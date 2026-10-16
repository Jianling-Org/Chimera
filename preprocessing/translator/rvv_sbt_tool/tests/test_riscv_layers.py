"""Exercise the common layer without loading any RVV implementation."""

import os
from pathlib import Path
import subprocess
import sys

from riscv.frontend.analysis import analyze_structure
from riscv.frontend.parser import AsmParser
from riscv.frontend.model import RVProgram, RVFunction
from riscv.extensions.rvv.analysis.dataflow import VectorConfigAnalyzer
from riscv.extensions.rvv.instruction import is_vector_instruction, is_config_instruction


ROOT = Path(__file__).resolve().parents[1]


def test_common_analysis_and_codegen_work_when_extension_imports_are_blocked():
    script = '''
import importlib.abc
import sys
class NoExtensions(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname.startswith("riscv.extensions"):
            raise AssertionError(fullname)
sys.meta_path.insert(0, NoExtensions())
from riscv.frontend.parser import AsmParser
from riscv.frontend.model import RVProgram, RVFunction
from riscv.frontend.analysis import analyze_structure
from riscv.codegen.control_flow import ControlFlowEmitter
from riscv.codegen.control_flow import ControlFlowContext, EmissionOptions
program = RVProgram(functions=[RVFunction("scalar", 0, AsmParser().parse_string("addi a0, a0, 1\\nret"))])
structure = analyze_structure(program)
assert structure.functions
assert structure.input_fingerprint
context = ControlFlowContext(structure, EmissionOptions())
emitter = ControlFlowEmitter(lookup_profile=0)
assert "addi" in emitter.emit_scalar_instruction(program.instructions[0])[0]
assert "riscv.extensions.rvv" not in sys.modules
'''
    env = dict(os.environ, PYTHONPATH=str(ROOT / 'src'), PYTHONDONTWRITEBYTECODE='1')
    result = subprocess.run([sys.executable, '-c', script], cwd=ROOT.parent,
                            env=env, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr


def test_rvv_consumes_existing_structure_without_mutating_it_or_source_models():
    program = RVProgram(functions=[RVFunction('vector', 0, AsmParser().parse_string('vsetivli zero, 4, e32, m1, ta, ma\nvadd.vv v8, v16, v24\nret'))])
    structure = analyze_structure(program)
    before = repr(structure)
    analysis = VectorConfigAnalyzer().analyze_program(program, structure)
    assert analysis.structure is structure
    assert repr(structure) == before
    function = program.functions[0]
    assert analysis.for_function(function.start_addr).at(program.instructions[1].address).known_specs()[0].sew == 32
    assert not hasattr(program, 'analysis')
    assert not hasattr(function, 'analysis')
    assert all(not hasattr(instruction, 'analysis') for instruction in program.instructions)


def test_extension_classification_does_not_depend_on_backend_support():
    instruction = AsmParser().parse_string('vfuture.vv v1, v2, v3')[0]
    assert is_vector_instruction(instruction)
    assert not is_config_instruction(instruction)
    assert 'is_vector' not in instruction.__dataclass_fields__
    config = AsmParser().parse_string('vsetvl a0, a1, a2')[0]
    assert is_config_instruction(config)


def test_old_implementation_directories_are_removed():
    for name in ('core', 'models', 'backends'):
        assert not (ROOT / name).exists()
