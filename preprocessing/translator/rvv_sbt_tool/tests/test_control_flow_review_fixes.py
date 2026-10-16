"""Execution regressions for numeric labels and scalar control-flow state."""

import re
import shutil
import subprocess

import pytest

import rvv_sbt_rvv
import rvv_sbt_rvv1024
from riscv.codegen.control_flow import ControlFlowEmitter
from riscv.extensions.rvv.translation.pipeline import TranslationPipeline, analyze_program
from riscv.extensions.rvv.translation.emitter import ProgramEmitter
from riscv.extensions.rvv.analysis.config import StateTracker
from riscv.extensions.rvv.backends.scalar.backend import ScalarDispatcher, make_scalar_profile
from riscv.extensions.rvv.runtime.layout import SimulatedStateLayout
from riscv.frontend.analysis import analyze_structure
from riscv.frontend.model import CFGEdgeKind, RVFunction, RVProgram
from riscv.frontend.parser import AsmParser
from riscv.frontend.text_index import TextProgramIndex
from riscv.extensions.rvv.runtime.contract import RVV1024_TO_RVV256, RVV256_TO_RVV1024
from riscv.registers import CALL_CLOBBERED_FPRS, CALL_CLOBBERED_GPRS


def _program(source):
    instructions = AsmParser().parse_string(source)
    return RVProgram(functions=[RVFunction("probe", 0, instructions)])


def _tool(name):
    path = shutil.which(name)
    if path is None:
        pytest.skip(f"requires {name}")
    return path


def _execute(tmp_path, source, *, march="rv64gc", cpu=None):
    assembly, obj, elf = (tmp_path / name for name in ("probe.S", "probe.o", "probe.elf"))
    assembly.write_text(source)
    subprocess.run([
        _tool("riscv64-elf-as"), f"-march={march}", "-mabi=lp64d",
        "-o", str(obj), str(assembly),
    ], check=True, capture_output=True, text=True)
    subprocess.run([
        _tool("riscv64-elf-ld"), "-Ttext=0x80000000", "-e", "_start",
        "-o", str(elf), str(obj),
    ], check=True, capture_output=True, text=True)
    cpu_options = ["-cpu", cpu] if cpu else []
    result = subprocess.run([
        _tool("qemu-system-riscv64"), "-machine", "virt", "-m", "128M",
        *cpu_options,
        "-bios", "none", "-kernel", str(elf), "-nographic",
        "-monitor", "none", "-serial", "none",
    ], capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, f"exit={result.returncode}: {result.stderr}"


def test_numeric_labels_resolve_nearest_direction_and_missing_stays_unknown():
    program = _program("""
1:
    beqz a0, 1f
    j 1b
1:
    bnez a0, 1b
    j 1f
1:
    j 2f
""")
    index = TextProgramIndex.build(program)
    instructions = program.functions[0].instructions
    assert [index.resolve_target(insn) for insn in instructions] == [8, 0, 8, 16, None]
    structure = analyze_structure(program)
    last_edges = structure.functions[0].cfg.edges_for_source(16)
    assert any(edge.target_address is None and not edge.resolved for edge in last_edges)


def test_numeric_local_reference_does_not_override_objdump_absolute_address():
    program = AsmParser().parse_string_program("""
0000 <probe>:
    0: 0000006f j 1b
    4: 0000006f j 1f <target>
""")
    index = TextProgramIndex.build(program)
    assert [index.resolve_target(insn) for insn in program.functions[0].instructions] == [27, 31]


def test_scalar_numeric_loop_cannot_bind_to_handler_internal_labels(tmp_path):
    program = _program("""
    li a0, 2
1:
    addi a0, a0, -1
    vsetivli zero, 4, e32, m1, tu, mu
    bnez a0, 1b
""")
    pipeline = TranslationPipeline(ProgramEmitter())
    prepared = pipeline.prepare(program, backend_profile=make_scalar_profile())
    body = pipeline.emit_function(
        prepared, state_factory=lambda: StateTracker(128), allocator_factory=SimulatedStateLayout,
        dispatcher_factory=ScalarDispatcher, raw=True, tls_state=False,
    )
    _execute(tmp_path, f"""
.option norelax
.option norvc
.text
.globl _start
_start:
    la sp, stack_end
    la t0, fail
    csrw mtvec, t0
{body}
    bnez a0, fail
    li t0, 0x100000
    li t1, 0x5555
    sw t1, 0(t0)
1:  j 1b
.balign 4
fail:
    li t0, 0x100000
    li t1, 0x13333
    sw t1, 0(t0)
2:  j 2b
.bss
.balign 128
simulated_cpu_state:
    .skip 0x1040
.balign 16
    .skip 4096
stack_end:
""")


@pytest.mark.parametrize("translator", [rvv_sbt_rvv, rvv_sbt_rvv1024])
def test_numeric_loop_preserves_vtype_backedge_and_unique_program_labels(translator):
    program = _program("""
    li a0, 2
    vsetivli zero, 4, e32, m1, tu, mu
1:
    vadd.vv v8, v8, v16
    vsetivli zero, 4, e64, m1, tu, mu
    addi a0, a0, -1
    bnez a0, 1b
    j 1f
1:
    ebreak
""")
    analysis = analyze_program(program)
    assert {spec.sew for spec in analysis.for_function(0).at(8).known_specs()} == {32, 64}
    cfg = program.functions[0].cfg
    assert any(
        edge.target_address == 8 and edge.kind is CFGEdgeKind.CONDITIONAL_BRANCH
        for edge in cfg.edges_for_source(20)
    )
    output = translator.translate_program(program, lib_name="numeric")
    assert re.search(r"bnez\s+a0, branch_j_target_8", output)
    labels = re.findall(r"(?m)^(\.Lchimera_probe_fn_1_\w+):", output)
    assert len(labels) == len(set(labels)) == 2


@pytest.mark.parametrize("native", [True, False], ids=["source", "translated"])
@pytest.mark.parametrize("source_bytes", [128, 32], ids=["forward", "reverse"])
def test_numeric_loop_executes_both_analyzed_vtypes(tmp_path, native, source_bytes):
    source = """
    li a0, 2
    vsetivli zero, 4, e32, m1, tu, mu
1:
    vadd.vv v8, v8, v16
    vsetivli zero, 4, e64, m1, tu, mu
    addi a0, a0, -1
    bnez a0, 1b
    j 1f
1:
    nop
"""
    translator = rvv_sbt_rvv if source_bytes == 128 else rvv_sbt_rvv1024
    contract = RVV1024_TO_RVV256 if source_bytes == 128 else RVV256_TO_RVV1024
    state_symbol = contract.non_tls_state_symbol
    if native:
        body = f"""
    la t0, {state_symbol} + {8 * source_bytes}
    vl1re8.v v8, (t0)
    la t0, {state_symbol} + {16 * source_bytes}
    vl1re8.v v16, (t0)
{source}
    la t0, {state_symbol} + {8 * source_bytes}
    vs1r.v v8, (t0)
"""
        vlen = source_bytes * 8
    else:
        body = translator.translate(
            AsmParser().parse_string(source), raw=True, tls_state=False,
        )
        vlen = 256 if source_bytes == 128 else 1024
    expected = [0xA00000003, 0xD00000004, 0xA00000003, 0xC00000008]
    expected.extend([0] * (source_bytes // 8 - len(expected)))
    expected_words = "\n".join(f"    .quad {value}" for value in expected)
    _execute(tmp_path, f"""
.option norelax
.option norvc
.text
.globl _start
_start:
    la sp, stack_end
    la t0, fail
    csrw mtvec, t0
    li t0, 0x6600
    csrs mstatus, t0
    call probe
    la t0, {state_symbol} + {8 * source_bytes}
    la t1, expected
    li t2, {len(expected)}
check:
    ld t3, 0(t0)
    ld t4, 0(t1)
    bne t3, t4, fail
    addi t0, t0, 8
    addi t1, t1, 8
    addi t2, t2, -1
    bnez t2, check
    li t0, 0x100000
    li t1, 0x5555
    sw t1, 0(t0)
1:  j 1b
.balign 4
fail:
    li t0, 0x100000
    li t1, 0x13333
    sw t1, 0(t0)
2:  j 2b
probe:
{body}
    ret
.data
.balign 128
{state_symbol}:
    .zero {8 * source_bytes}
    .word 0xffffffff, 0, 0xfffffffe, 1, 0xffffffff, 2, 3, 4
    .zero {8 * source_bytes - 32}
    .word 2, 5, 3, 6, 4, 7, 5, 8
    .zero {0x1030 - 16 * source_bytes - 32}
    .quad {source_bytes}
    .zero 8
.balign 8
expected:
{expected_words}
.bss
.balign 16
    .skip 8192
stack_end:
""", march="rv64gcv", cpu=f"rv64,v=true,vlen={vlen},elen=64")


@pytest.mark.parametrize("destination", ["sp", "x2", "t0", "t1", "a0"])
@pytest.mark.parametrize("immediate", ["0x1", "0xfffff"])
def test_auipc_commits_sp_after_restoring_temporaries(tmp_path, destination, immediate):
    insn = AsmParser().parse_string(f"auipc {destination}, {immediate}")[0]
    insn.address = 0x1000
    body = "\n".join(ControlFlowEmitter(lookup_profile=1).emit_program_scalar(
        insn, insn.operands, "original_base", context=None, active_long_jump_veneers={},
    ))
    offset = 4096 if immediate == "0x1" else -4096
    checks = "\n".join(
        f"    li t4, {value}\n    bne {register}, t4, fail"
        for register, value in (("t0", 123), ("t1", 456), ("a0", 789))
        if register != destination
    )
    _execute(tmp_path, f"""
.option norelax
.option norvc
.text
.globl _start
_start:
    la sp, stack_end
    la t0, fail
    csrw mtvec, t0
    li t0, 123
    li t1, 456
    li a0, 789
source_site:
{body}
    mv t3, {destination}
    la sp, stack_end
    la t4, source_site
    li t5, {offset}
    add t4, t4, t5
    bne t3, t4, fail
{checks}
    li t0, 0x100000
    li t1, 0x5555
    sw t1, 0(t0)
1:  j 1b
.balign 4
fail:
    li t0, 0x100000
    li t1, 0x13333
    sw t1, 0(t0)
2:  j 2b
.data
.balign 8
original_base:
    .quad source_site - 0x1000
.bss
.balign 16
    .skip 4096
stack_end:
""")


@pytest.mark.parametrize("remapped", [False, True], ids=["identity", "remapped"])
@pytest.mark.parametrize("command,base,number,offset", [
    ("ret", "ra", 1, 0),
    ("jr t0", "t0", 5, 0),
    ("jr a1", "a1", 11, 0),
    ("jr s1", "s1", 9, 0),
    ("jr sp", "sp", 2, 0),
    ("jalr zero, 8(t0)", "t0", 5, 8),
    ("jalr x0, -8(a1)", "a1", 11, -8),
    ("jalr x0, 8(sp)", "sp", 2, 8),
])
def test_no_link_lookup_preserves_all_registers_on_identity_or_rejection(
    tmp_path, remapped, command, base, number, offset,
):
    insn = AsmParser().parse_string(command)[0]
    insn.address = 0x1000
    body = "\n".join(ControlFlowEmitter(lookup_profile=1).emit_program_scalar(
        insn, insn.operands, "original_base", context=None, active_long_jump_veneers={},
    ))
    assert "chimera_jump_mapped_v1" not in body
    assert "Unsupported no-link indirect target remap" in body
    initialize = "\n".join(
        f"    li x{reg}, {0x100 + reg}" for reg in range(1, 32) if reg != 2
    )
    save = "\n".join(f"    sd x{reg}, {reg * 8}(sp)" for reg in range(1, 32) if reg != 2)
    poison = "\n".join(
        f"    li {register}, -1" for register in CALL_CLOBBERED_GPRS
        if register not in {"ra", "a0"}
    )
    fp_initialize = "\n".join(f"    fmv.d.x {register}, t0" for register in CALL_CLOBBERED_FPRS)
    fp_poison = "\n".join(f"    fmv.d.x {register}, zero" for register in CALL_CLOBBERED_FPRS)
    fp_check = "\n".join(
        f"    fmv.x.d t0, {register}\n    bne t0, t1, fail" for register in CALL_CLOBBERED_FPRS
    )
    base_value = "stack_end" if base == "sp" else f"destination + 1 - ({offset})"
    setup_base = f"    la {base}, {base_value}"
    expected = {reg: str(0x100 + reg) for reg in range(1, 32)}
    expected[2] = "stack_end"
    expected[number] = base_value
    expected_words = "\n".join(f"    .quad {expected[reg]}" for reg in range(1, 32))
    target = "stack_end" + (f" + {offset}" if offset else "") if base == "sp" else "destination"
    expected_pc = f"    la t1, {'wrapper_end - 4' if remapped else target}\n    bne t0, t1, fail"
    query_return = "    la a0, remapped_destination" if remapped else "    mv a0, a1"
    _execute(tmp_path, f"""
.option norelax
.option norvc
.text
.globl _start
_start:
    la t0, trap
    csrw mtvec, t0
    la t0, saved
    csrw mscratch, t0
    li t0, 0x6000
    csrs mstatus, t0
    li t0, 0x65
    fscsr t0
    li t0, 0x1234
{fp_initialize}
    la sp, stack_end
{initialize}
{setup_base}
    j wrapper
wrapper:
{body}
wrapper_end:
    j fail
destination:
    ebreak
remapped_destination:
    j fail
.balign 4
trap:
    csrrw sp, mscratch, sp
{save}
    csrr t0, mscratch
    sd t0, 16(sp)
    csrr t0, mcause
    li t1, 3
    bne t0, t1, fail
    csrr t0, mepc
{expected_pc}
    la t0, saved + 8
    la t1, expected
    li t2, 31
check_register:
    ld t3, 0(t0)
    ld t4, 0(t1)
    bne t3, t4, fail
    addi t0, t0, 8
    addi t1, t1, 8
    addi t2, t2, -1
    bnez t2, check_register
    frcsr t0
    li t1, 0x65
    bne t0, t1, fail
    li t1, 0x1234
{fp_check}
    li t0, 0x100000
    li t1, 0x5555
    sw t1, 0(t0)
1:  j 1b
fail:
    li t0, 0x100000
    li t1, 0x13333
    sw t1, 0(t0)
2:  j 2b
query_original_translated_map:
{query_return}
{poison}
{fp_poison}
    fscsr zero
    ret
.balign 16
    .skip 8192
stack_end:
    ebreak
    nop
    ebreak
.data
.balign 8
expected:
{expected_words}
.bss
.balign 16
saved:
    .skip 256
""")
