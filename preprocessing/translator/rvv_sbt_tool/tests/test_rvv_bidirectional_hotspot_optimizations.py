"""Regression contracts for hardware-measured per-instruction optimizations."""

from fractions import Fraction

import re

import pytest

from riscv.frontend.parser import AsmParser
from riscv.extensions.rvv.backends.rvv256.planning import plan_wide_chunk, plan_wide_operands
from riscv.extensions.rvv.backends.rvv1024_transition.state_view import (
    SOURCE_VLENB, TARGET_VLENB, emit_load_csr, emit_store_csr,
)
from riscv.extensions.rvv.runtime.access import STATE_BASE_MARKER
from riscv.extensions.rvv.backends.rvv1024_transition.specs import build_transition_registry
from rvv_sbt_rvv import translate as forward
from rvv_sbt_rvv1024 import translate as reverse


@pytest.mark.parametrize("command", (
    "vadd.vv v8, v16, v24", "vle32.v v8, (a0)",
    "vfmacc.vv v8, v16, v24", "vfwmacc.vv v8, v16, v24",
    "vmv.x.s t6, v8", "vfmv.f.s fa0, v8",
))
def test_reverse_non_saturating_instructions_restore_but_do_not_recapture_vcsr(command):
    output = reverse(AsmParser().parse_string(command), init_vtype="sew=32,lmul=1", raw=True)
    assert "csrw    vcsr," in output
    assert len(re.findall(r"csrr\s+\w+,\s*vcsr", output)) == 1
    assert "源 CSR.vstart = 0" in output
    assert "vcsr" not in build_transition_registry().require(command.split()[0]).state_writes


def test_reverse_saturating_clip_keeps_rounding_and_saturation_writeback():
    spec = build_transition_registry().require("vnclip.wi")
    assert "vcsr" in spec.state_writes
    output = reverse(AsmParser().parse_string("vnclip.wi v8, v16, 1"),
                     init_vtype="sew=16,lmul=1", raw=True)
    assert "csrw    vcsr," in output
    assert re.search(r"csrr\s+\w+,\s*vcsr", output)
    assert "捕获目标执行后的 vcsr" in output


@pytest.mark.parametrize("sew", (16, 32))
def test_forward_widening_fma_loads_all_inputs_before_committing_active_elements(sew):
    output = forward(AsmParser().parse_string("vfwmacc.vv v8, v16, v24"),
                     init_vtype=f"sew={sew},lmul=1", raw=True)
    assert "target=m4" in output
    operation = re.search(r"^\s*vfwmacc\.vv v8, v16, v20$", output, re.M)
    assert operation is not None
    prefix = output[:operation.start()]
    assert f"vle{sew * 2}.v v8," in prefix
    assert f"vle{sew}.v v16," in prefix
    assert f"vle{sew}.v v20," in prefix
    assert f"vse{sew * 2}.v" not in prefix
    assert "尾部标量回退" not in output


def test_forward_duplicate_sources_advance_the_shared_pointer_once_per_chunk():
    output = forward(AsmParser().parse_string("vfwmacc.vv v8, v16, v16"),
                     init_vtype="sew=16,lmul=4", raw=True)
    lhs = re.search(r"vle16\.v v16, \((\w+)\)", output).group(1)
    rhs = re.search(r"vle16\.v v20, \((\w+)\)", output).group(1)
    assert lhs == rhs
    assert output.count(f"addi    {lhs}, {lhs}, 128") == 1


@pytest.mark.parametrize("sew", (16, 32))
def test_forward_widening_fma_uses_the_same_primary_lowering_in_both_profiles(sew):
    instructions = AsmParser().parse_string("vfwmacc.vv v8, v16, v24")
    kwargs = dict(init_vtype=f"sew={sew},lmul=1", raw=True)
    output = forward(instructions, **kwargs)
    assert output == forward(instructions, wide_lmul=False, **kwargs)
    assert "RVV256-WIDE" in output
    assert "尾部标量回退" not in output


@pytest.mark.parametrize("command, target", (
    ("vfmacc.vv v8, v16, v24", "target=m4"),
    ("vfmacc.vv v8, v8, v8", "target=m4"),
    ("vle32.v v8, (a0)", "target=e32,m4"),
))
def test_forward_f32_hotspots_use_m4_for_unmasked_e32_m8(command, target):
    output = forward(AsmParser().parse_string(command),
                     init_vtype="sew=32,lmul=8", raw=True)
    assert "RVV256-WIDE" in output
    assert f"{target}, chunk=32 elements" in output
    assert "fallback" not in output.lower()


@pytest.mark.parametrize("command, vtype, target", (
    ("vfmacc.vv v8, v16, v24, v0.t", "sew=32,lmul=8", "target=m8"),
    ("vle32.v v8, (a0), v0.t", "sew=32,lmul=8", "target=e32,m8"),
    ("vse32.v v8, (a0)", "sew=32,lmul=8", "target=e32,m8"),
    ("vlse32.v v8, (a0), a1", "sew=32,lmul=8", "target=e32,m8"),
    ("vfmacc.vf v8, fa0, v16", "sew=32,lmul=8", "target=m8"),
    ("vadd.vv v8, v16, v24", "sew=32,lmul=8", "target=m8"),
    ("vfmacc.vv v8, v16, v24", "sew=64,lmul=8", "target=m8"),
    ("vfmacc.vv v8, v16, v24", "sew=32,lmul=4", "target=m8"),
    ("vle32.v v8, (a0)", "sew=32,lmul=4", "target=e32,m8"),
))
def test_forward_f32_limit_preserves_other_wide_forms(command, vtype, target):
    output = forward(AsmParser().parse_string(command), init_vtype=vtype, raw=True)
    assert "RVV256-WIDE" in output
    assert target in output
    assert "fallback" not in output.lower()


def test_forward_f32_limit_is_selected_by_callers_and_keeps_default_planner():
    kwargs = dict(source_lmul=8, source_sew=32, data_sew=32,
                  source_regs=("v8", "v16", "v24"), target_group_count=3)
    default = plan_wide_chunk(**kwargs)
    generic = plan_wide_operands(
        source_lmul=8, source_sew=32,
        source_operands=(("v8", 32), ("v16", 32), ("v24", 32)),
        target_vtype_sew=32, target_operand_eews=(32, 32, 32),
    )
    limited = plan_wide_chunk(**kwargs, max_target_lmul=4)
    assert default is not None and generic == default
    assert default.target_lmul == Fraction(8)
    assert default.elements_per_chunk == 64
    assert limited is not None
    assert limited.target_lmul == Fraction(4)
    assert limited.elements_per_chunk == 32


@pytest.mark.parametrize("command", (
    "vfmacc.vv v8, v16, v24", "vle32.v v8, (a0)",
))
def test_forward_f32_hotspots_use_the_same_primary_lowering_in_both_profiles(command):
    instructions = AsmParser().parse_string(command)
    kwargs = dict(init_vtype="sew=32,lmul=8", raw=True)
    output = forward(instructions, **kwargs)
    assert output == forward(instructions, wide_lmul=False, **kwargs)
    assert "target=m4" in output or "target=e32,m4" in output
    assert "fallback" not in output.lower()


_CSR_ABI_SLOTS = (
    ("vstart", 0x1000), ("vxsat", 0x1008), ("vxrm", 0x1010),
    ("vcsr", 0x1018), ("vl", 0x1020), ("vtype", 0x1028),
    ("vlenb", 0x1030),
)


def _csr_slot_offset(lines, opcode):
    assert len(lines) == 3
    constant = re.fullmatch(r"\s*li\s+(\w+),\s*(0x[0-9a-f]+|\d+)", lines[0])
    assert constant is not None
    address_reg, base_offset = constant.groups()
    assert re.fullmatch(
        rf"\s*add\s+{address_reg},\s*t6,\s*{address_reg}\s+# {STATE_BASE_MARKER}",
        lines[1],
    )
    memory = re.fullmatch(
        rf"\s*{opcode}\s+t0,\s*(\d+)\({address_reg}\)\s+#.*", lines[2],
    )
    assert memory is not None
    if opcode == "sd":
        assert address_reg != "t0"
    return int(base_offset, 0) + int(memory.group(1))


@pytest.mark.parametrize("csr, expected_offset", _CSR_ABI_SLOTS)
def test_reverse_csr_loads_keep_abi_addresses_with_aliased_destination(csr, expected_offset):
    lines = []
    emit_load_csr(lines, "t0", "t0", csr)
    assert _csr_slot_offset(lines, "ld") == expected_offset


@pytest.mark.parametrize("csr, expected_offset", _CSR_ABI_SLOTS)
def test_reverse_csr_stores_keep_abi_addresses_and_source_register(csr, expected_offset):
    lines = []
    emit_store_csr(lines, "t0", "t1", csr)
    assert _csr_slot_offset(lines, "sd") == expected_offset


@pytest.mark.parametrize("eew,sew,lmul", ((8, 32, 1), (16, 16, 1), (32, 32, 1), (64, 32, 1)))
def test_reverse_unmasked_unit_load_commits_with_the_source_active_vl(eew, sew, lmul):
    output = reverse(AsmParser().parse_string(f"vle{eew}.v v24, (a0)"),
                     init_vtype=f"sew={sew},lmul={lmul}", raw=True)
    assert "fallback" not in output.lower()
    load = re.search(rf"^\s*vle{eew}\.v\s+(v\d+),\s*\(a0\)$", output, re.M)
    store = re.search(rf"^\s*vse{eew}\.v\s+(v\d+),\s*\((\w+)\)$", output, re.M)
    source_vl = re.search(r"^\s*ld\s+(\w+),.*# 源 CSR.vl$", output, re.M)
    assert load is not None and store is not None and source_vl is not None
    assert load.group(1) == store.group(1)
    assert source_vl.start() < load.start() < store.start()
    assert re.search(rf"vsetvli\s+zero,\s*{source_vl.group(1)},\s*e{sew},\s*m1,\s*tu,\s*mu",
                     output[:load.start()])
    assert "vsetvli" not in output[load.end():store.start()]
    assert re.search(rf"addi\s+{store.group(2)},\s*t6,\s*768\b", output)
    assert len(re.findall(r"^\s*vle\d+\.v\s", output, re.M)) == 1
    assert "csrw    vcsr," in output
    assert not re.search(r"^\s*csrw\s+vstart,", output, re.M)
    assert "源 CSR.vstart = 0" in output


@pytest.mark.parametrize("eew,lmul,byte_count", ((64, 1, 64), (32, 8, 256)))
def test_reverse_masked_unit_load_keeps_the_old_destination_and_source_layout(eew, lmul, byte_count):
    output = reverse(AsmParser().parse_string(f"vle{eew}.v v24, (a0), v0.t"),
                     init_vtype=f"sew=32,lmul={lmul}", raw=True)
    operation = re.search(rf"^\s*vle{eew}\.v\s+v8,\s*\(a0\),\s*v0\.t$", output, re.M)
    assert operation is not None
    prefix, suffix = output[:operation.start()], output[operation.end():]
    assert re.search(r"^\s*vle8\.v\s+v8,", prefix, re.M)
    assert re.search(rf"li\s+\w+,\s*{byte_count}\s+# Pack", prefix)
    assert "vmv1r.v v0," in prefix
    assert re.search(rf"vsetvli\s+zero,\s*\w+,\s*e32,\s*m{lmul},\s*tu,\s*mu", prefix)
    assert re.search(rf"li\s+\w+,\s*{byte_count}\s+# Unpack", suffix)
    assert re.search(r"^\s*vse8\.v\s+v8,", suffix, re.M)
    assert not re.search(rf"^\s*vse{eew}\.v\s", suffix, re.M)


@pytest.mark.parametrize("command,diagnostic", (
    ("vle64.v v8, (a0)", "EMUL=16"),
    ("vle32.v v10, (a0)", "不是 m8 组对齐起点"),
    ("vle8.v v9, (a0)", "不是 m2 组对齐起点"),
))
def test_reverse_tight_load_still_validates_the_source_emul(command, diagnostic):
    output = reverse(AsmParser().parse_string(command), init_vtype="sew=32,lmul=8", raw=True)
    assert "RVV1024 fallback" in output
    assert diagnostic in output
    assert "ebreak" in output
    assert not re.search(r"^\s*v(?:le|se)\d+\.v\s", output, re.M)


@pytest.mark.parametrize("eew,sew,lmul,target_lmul", (
    (8, 32, 8, "m2"), (16, 32, 8, "m2"), (32, 32, 8, "m2"),
    (32, 32, 4, "m4"), (16, 16, 8, "m8"),
))
def test_reverse_unit_load_tightens_only_the_proven_source_profile(eew, sew, lmul, target_lmul):
    output = reverse(AsmParser().parse_string(f"vle{eew}.v v24, (a0)"),
                     init_vtype=f"sew={sew},lmul={lmul}", raw=True)
    assert "fallback" not in output.lower()
    configurations = re.findall(r"^\s*vsetvli\s+zero,\s*\w+,\s*e(\d+),\s*(m\d+),", output, re.M)
    assert configurations == [(str(sew), target_lmul)]
    assert f"源 LMUL=m{lmul}" in output


def test_reverse_tight_load_does_not_change_source_vtype_vl_or_vlenb():
    output = reverse(AsmParser().parse_string(
        "vsetvli a0, zero, e32, m8, tu, mu\n"
        "vle32.v v24, (a1)\ncsrr a2, vlenb"), raw=True)
    assert "fallback" not in output.lower()
    assert re.search(r"li\s+\w+,\s*0x13\s+# 源 CSR.vtype", output)
    assert re.search(r"li\s+\w+,\s*64\s+# VL = VLMAX", output)
    assert re.search(r"vsetvli\s+zero,\s*\w+,\s*e32,\s*m2,", output)
    assert re.search(r"li\s+a2,\s*32\b", output)


@pytest.mark.parametrize("address", ("t6", "x31"))
def test_reverse_direct_load_preserves_the_guest_t6_address_and_commits_to_state(address):
    output = reverse(AsmParser().parse_string(f"vle32.v v24, ({address})"),
                     init_vtype="sew=32,lmul=8", raw=True, tls_state=False)
    saved = re.search(r"^\s*sd\s+t6,\s*(\d+)\(sp\)$", output, re.M)
    load = re.search(r"^\s*vle32\.v\s+(v\d+),\s*\((\w+)\)$", output, re.M)
    store = re.search(r"^\s*vse32\.v\s+(v\d+),\s*\((\w+)\)$", output, re.M)
    assert saved is not None and load is not None and store is not None
    assert load.group(2) not in {"t6", "x31"}
    assert re.search(rf"ld\s+{load.group(2)},\s*{saved.group(1)}\(sp\)", output[:load.start()])
    assert load.group(1) == store.group(1)
    assert re.search(rf"addi\s+{store.group(2)},\s*t6,\s*768\b", output[load.end():store.start()])
    restore = output.rsplit("# 恢复 RVV 翻译块现场:", 1)[1]
    assert re.search(rf"ld\s+t6,\s*{saved.group(1)}\(sp\)", restore)


def test_reverse_load_then_scalar_t6_result_commits_state_before_the_output():
    output = reverse(AsmParser().parse_string("vle32.v v24, (t6)\nvmv.x.s t6, v24"),
                     init_vtype="sew=32,lmul=8", raw=True, tls_state=False)
    result = re.search(r"^\s*vmv\.x\.s\s+t6,\s*v8$", output, re.M)
    assert result is not None
    assert output.rfind("源 CSR.vstart = 0", 0, result.start()) >= 0
    restore = output[result.end():]
    assert not re.search(r"^\s*ld\s+t6,", restore, re.M)


STATE_BASE = 0x100000000


def translated(command):
    assembly = forward(
        AsmParser().parse_string(command), raw=True, tls_state=False,
        init_vtype="sew=32,lmul=8,tu,mu",
    )
    assert "fallback" not in assembly.lower()
    return assembly


def initialized_addresses(assembly):
    start = assembly.index("# RVV256-WIDE: vfmacc.vv")
    prefix = assembly[start:].split("= vl (from simulated CSR)", 1)[0]
    values = {"t6": STATE_BASE}
    for line in prefix.splitlines():
        instruction = line.split("#", 1)[0].strip()
        if not instruction:
            continue
        opcode, operands = instruction.split(None, 1)
        operands = [item.strip() for item in operands.split(",")]
        if opcode == "li":
            values[operands[0]] = int(operands[1], 0)
        elif opcode == "addi":
            values[operands[0]] = values[operands[1]] + int(operands[2], 0)
        elif opcode == "add":
            values[operands[0]] = values[operands[1]] + values[operands[2]]
        elif opcode == "mv":
            values[operands[0]] = values[operands[1]]
        elif opcode == "ld":
            break
        else:
            raise AssertionError(instruction)
    assert values["t6"] == STATE_BASE
    return values


def loaded_source_addresses(assembly):
    values = initialized_addresses(assembly)
    loads = re.findall(r"vle32\.v\s+(v\d+),\s*\((\w+)\)", assembly)[:3]
    assert len(loads) == 3
    return [values[pointer] for _group, pointer in loads], [pointer for _group, pointer in loads]


def assert_gpr_frame_preserved(assembly):
    saves = re.findall(r"(?m)^\s*sd\s+(\w+),\s*(\d+)\(sp\)", assembly)
    restores = re.findall(r"(?m)^\s*ld\s+(\w+),\s*(\d+)\(sp\)", assembly)
    assert saves == restores
    assert any(register == "t6" for register, _offset in saves)
    assert assembly.index("CSR.vstart = 0") < assembly.index("# 恢复 RVV 翻译块现场")


def test_typical_three_groups_derive_from_state_base_and_keep_gpr_frame():
    assembly = translated("vfmacc.vv v8, v16, v24")
    addresses, _pointers = loaded_source_addresses(assembly)
    assert addresses == [STATE_BASE + 0x800, STATE_BASE + 0xC00, STATE_BASE + 0x400]
    assert "addi    t1, t0, 1024" in assembly
    assert "addi    t2, t1, 1024" in assembly
    assert_gpr_frame_preserved(assembly)


def test_negative_relative_offset_and_small_absolute_offset_are_exact():
    assembly = translated("vfmacc.vv v24, v16, v8")
    addresses, _pointers = loaded_source_addresses(assembly)
    assert addresses == [STATE_BASE + 0x800, STATE_BASE + 0x400, STATE_BASE + 0xC00]
    assert "addi    t1, t0, -1024" in assembly
    assert "addi    t2, t6, 1024  # CHIMERA_STATE_BASE" in assembly
    assert_gpr_frame_preserved(assembly)


@pytest.mark.parametrize("command, expected_offsets, alias_pair", (
    ("vfmacc.vv v8, v16, v16", (0x800, 0x800, 0x400), (0, 1)),
    ("vfmacc.vv v16, v16, v24", (0x800, 0xC00, 0x800), (0, 2)),
))
def test_aliased_source_addresses_advance_once_after_all_reads(command, expected_offsets, alias_pair):
    assembly = translated(command)
    addresses, pointers = loaded_source_addresses(assembly)
    assert addresses == [STATE_BASE + offset for offset in expected_offsets]
    left, right = alias_pair
    assert pointers[left] == pointers[right]
    pointer = pointers[left]
    assert assembly.count(f"addi    {pointer}, {pointer}, 128") == 1
    assert assembly.index("vfmacc.vv v8, v12, v16") < assembly.index("vse32.v")
    assert_gpr_frame_preserved(assembly)


def _state_vector_accesses(output, mnemonic):
    accesses = []
    for operation in re.finditer(rf"^\s*{re.escape(mnemonic)}\s+(v\d+),\s*\((\w+)\)$", output, re.M):
        address = operation.group(2)
        pointers = re.findall(rf"^\s*(?:addi\s+{address},\s*t6,\s*(\d+)|mv\s+{address},\s*t6)\s+# CHIMERA_STATE_BASE$",
                              output[:operation.start()], re.M)
        assert pointers
        accesses.append((operation.group(1), int(pointers[-1]) if pointers[-1] else 0))
    return accesses


@pytest.mark.parametrize("command,expected_offsets,maximum_loads", (
    ("vand.vv v8, v16, v24", {512, 768}, 2),
    ("vand.vv v8, v8, v24", {256, 768}, 2),
    ("vand.vv v8, v16, v16", {512}, 2),
    ("vadd.vi v8, v8, 1", {256}, 1),
))
def test_reverse_non_accumulator_reads_only_its_semantic_vector_inputs(command, expected_offsets, maximum_loads):
    output = reverse(AsmParser().parse_string(command), init_vtype="sew=32,lmul=2", raw=True)
    operation = re.search(r"^\s*" + re.escape(command.split()[0]) + r"\s+.*$", output, re.M)
    assert operation is not None
    inputs = _state_vector_accesses(output[:operation.start()], "vle32.v")
    assert {offset for _, offset in inputs} == expected_offsets
    assert len(inputs) <= maximum_loads
    assert len(_state_vector_accesses(output, "vse32.v")) == 1


@pytest.mark.parametrize("command", ("vfmacc.vv v8, v16, v24", "vmacc.vv v8, v8, v24"))
def test_reverse_accumulator_loads_the_old_destination_before_arithmetic(command):
    output = reverse(AsmParser().parse_string(command), init_vtype="sew=32,lmul=2", raw=True)
    operation = re.search(r"^\s*" + re.escape(command.split()[0]) + r"\s+(v\d+),.*$", output, re.M)
    assert operation is not None
    inputs = _state_vector_accesses(output[:operation.start()], "vle32.v")
    assert (operation.group(1), 256) in inputs
    assert 768 in {offset for _, offset in inputs}
    if command.startswith("vfmacc"):
        assert 512 in {offset for _, offset in inputs}
    assert "vse32.v" not in output[:operation.start()]


@pytest.mark.parametrize("command,lmul", (
    ("vfmacc.vv v8, v16, v24", 2), ("vmacc.vv v8, v16, v24", 2), ("vadd.vi v8, v16, 1", 2),
))
def test_reverse_arithmetic_commits_with_the_same_source_active_vl(command, lmul):
    output = reverse(AsmParser().parse_string(command), init_vtype=f"sew=32,lmul={lmul}", raw=True)
    source_vl = re.search(r"^\s*ld\s+(\w+),.*# 源 CSR.vl$", output, re.M)
    configuration = re.search(r"^\s*vsetvli\s+zero,\s*(\w+),\s*e32,", output, re.M)
    operation = re.search(r"^\s*" + re.escape(command.split()[0]) + r"\s+(v\d+),.*$", output, re.M)
    assert source_vl is not None and configuration is not None and operation is not None
    assert source_vl.group(1) == configuration.group(1)
    assert source_vl.start() < configuration.start() < operation.start()
    assert len(re.findall(r"^\s*vsetvli\s", output, re.M)) == 1
    store = re.search(rf"^\s*vse32\.v\s+{operation.group(1)},\s*\(\w+\)$", output, re.M)
    assert store is not None and operation.start() < store.start()
    assert "vsetvli" not in output[configuration.end():store.start()]
    assert "csrw    vcsr," in output
    assert not re.search(r"^\s*csrw\s+vstart,", output, re.M)
    assert "源 CSR.vstart = 0" in output


@pytest.mark.parametrize("command,sew,lmul", (
    ("vand.vv v8, v16, v24, v0.t", 32, 1),
    ("vadd.vv v8, v16, v24", 32, 1),
    ("vfredusum.vs v8, v16, v24", 32, 1),
    ("vfwmacc.vv v8, v16, v24", 32, 1),
    ("vfmacc.vv v8, v16, v24", 32, 8),
    ("vand.vv v8, v16, v24", 16, 2),
    ("vand.vv v8, v16, v24", 32, 1),
    ("vfwmacc.vv v8, v16, v24", 16, 1),
))
def test_reverse_mask_and_other_source_profiles_keep_raw_state_transfers(command, sew, lmul):
    output = reverse(AsmParser().parse_string(command), init_vtype=f"sew={sew},lmul={lmul}", raw=True)
    operation = re.search(r"^\s*" + re.escape(command.split()[0]) + r"\s+.*$", output, re.M)
    assert operation is not None
    assert "vle8.v" in output[:operation.start()]
    assert "vse8.v" in output[operation.end():]
    assert "vse32.v" not in output[operation.end():]
    if "v0.t" in command:
        assert "vlm.v v0," in output[:operation.start()]
        assert operation[0].endswith("v0.t")


@pytest.mark.parametrize("scalar", ("t6", "x31"))
def test_reverse_active_arithmetic_preserves_the_guest_t6_and_state_base(scalar):
    output = reverse(AsmParser().parse_string(f"vadd.vx v0, v8, {scalar}"),
                     init_vtype="sew=32,lmul=2", raw=True, tls_state=False)
    saved = re.search(r"^\s*sd\s+t6,\s*(\d+)\(sp\)$", output, re.M)
    operation = re.search(r"^\s*vadd\.vx\s+(v\d+),\s*v\d+,\s*(\w+)$", output, re.M)
    assert saved is not None and operation is not None
    assert operation.group(2) not in {"t6", "x31"}
    assert re.search(rf"ld\s+{operation.group(2)},\s*{saved.group(1)}\(sp\)", output[:operation.start()])
    assert {offset for _, offset in _state_vector_accesses(output[:operation.start()], "vle32.v")} == {256}
    assert _state_vector_accesses(output[operation.end():], "vse32.v") == [(operation.group(1), 0)]
    restore = output.rsplit("# 恢复 RVV 翻译块现场:", 1)[1]
    assert re.search(rf"ld\s+t6,\s*{saved.group(1)}\(sp\)", restore)
    assert "csrw    vcsr," in output
    assert "源 CSR.vstart = 0" in output


@pytest.mark.parametrize("command, vtype", (
    ("vand.vv v8, v16, v24", "sew=8,lmul=2"),
    ("vand.vv v8, v16, v24", "sew=16,lmul=2"),
    ("vand.vv v8, v16, v24", "sew=64,lmul=2"),
    ("vand.vv v8, v16, v24", "sew=32,lmul=1"),
    ("vand.vv v8, v16, v24", "sew=32,lmul=0.5"),
    ("vand.vv v8, v16, v24", "sew=32,lmul=4"),
    ("vand.vv v8, v16, v24, v0.t", "sew=32,lmul=2"),
    ("vsub.vv v8, v16, v24", "sew=32,lmul=2"),
    ("vfmacc.vv v8, v16, v24", "sew=32,lmul=8"),
    ("vfadd.vv v8, v8, v9", "sew=32,lmul=1"),
    ("vfwmacc.vv v8, v10, v11", "sew=16,lmul=1"),
))
def test_reverse_other_shapes_keep_complete_raw_pack_and_unpack(command, vtype):
    output = reverse(AsmParser().parse_string(command), init_vtype=vtype, raw=True)
    assert "Pack 源组有效字节数" in output
    assert "Unpack 源组有效字节数" in output
    assert "fallback" not in output.lower()


@pytest.mark.parametrize("command, sew, source_lmul, target_lmul, operand_eews", (
    ("vfmacc.vv v8, v16, v24", 32, Fraction(8), Fraction(2), (32, 32, 32)),
    ("vmacc.vv v8, v16, v24", 32, Fraction(2), Fraction(1, 2), (32, 32, 32)),
    ("vfwmacc.vv v8, v10, v11", 16, Fraction(1), Fraction(1, 4), (32, 16, 16)),
))
def test_reverse_tight_execution_matches_source_capacity_and_retains_source_csrs(
    command, sew, source_lmul, target_lmul, operand_eews,
):
    output = reverse(AsmParser().parse_string(command),
                     init_vtype=f"sew={sew},lmul={source_lmul}", raw=True)
    execution = re.search(
        rf"vsetvli\s+zero,\s*\w+,\s*e{sew},\s*(m[1248]|mf[248]),\s*tu,\s*mu"
        r"\s+# 以源 VL 在 RVV1024 临时组执行", output,
    )
    assert execution is not None
    token = execution.group(1)
    emitted_lmul = Fraction(1, int(token[2:])) if token.startswith("mf") else Fraction(int(token[1:]))
    assert emitted_lmul == target_lmul
    assert SOURCE_VLENB * 8 * source_lmul / sew == TARGET_VLENB * 8 * emitted_lmul / sew
    assert sew <= 64 * emitted_lmul
    for eew in operand_eews:
        target_emul = emitted_lmul * eew / sew
        assert Fraction(1, 8) <= target_emul <= 8
        assert SOURCE_VLENB * source_lmul * eew / sew == TARGET_VLENB * target_emul
    assert "csrw    vcsr," in output
    assert len(re.findall(r"csrr\s+\w+,\s*vcsr", output)) == 1
    assert "源 CSR.vstart = 0" in output
    assert not re.search(r"\bsd\s+[^\n]*# (?:源 )?CSR\.(?:vl|vtype|vlenb|vcsr)\b", output)
    writes = build_transition_registry().require(command.split()[0]).state_writes
    assert not ({"vl", "vtype", "vlenb", "vcsr"} & set(writes))


def test_reverse_q3_mac_passes_the_spec_accumulator_contract(monkeypatch):
    from dataclasses import replace
    from types import SimpleNamespace
    from riscv.extensions.rvv.analysis.config import StateTracker
    from riscv.extensions.rvv.backends.rvv1024_transition.handlers import arithmetic

    spec = build_transition_registry().require("vmacc.vx")
    assert spec.reads_old_vd
    assert not ({"vl", "vtype", "vlenb", "vcsr"} & set(spec.state_writes))
    state = StateTracker(32)
    state.apply_init_vtype("sew=16,lmul=1")
    instruction = AsmParser().parse_string("vmacc.vx v8, a0, v16")[0]
    observed = []

    def capture(_instruction, _state, **options):
        observed.append(options["reads_old_vd"])
        return []

    monkeypatch.setattr(arithmetic, "_emit_packed_vector_write", capture)
    for reads_old_vd in (True, False):
        context = SimpleNamespace(instruction=instruction, state=state,
                                  spec=replace(spec, reads_old_vd=reads_old_vd))
        arithmetic.build_with_opcode(context, emitter=arithmetic._emit_integer_accumulate_vx)
    assert observed == [True, False]


@pytest.mark.parametrize("command, destination, source", (
    ("vmacc.vx v8, a0, v16", 256, 512),
    ("vmacc.vx v0, a0, v0", 0, 0),
))
def test_reverse_q3_active_mac_reads_old_vd_even_when_the_input_aliases(command, destination, source):
    output = reverse(AsmParser().parse_string(command), init_vtype="sew=16,lmul=1", raw=True)
    operation = re.search(r"^\s*vmacc\.vx\s+(v\d+),\s*\w+,\s*(v\d+)$", output, re.M)
    assert operation is not None
    inputs = _state_vector_accesses(output[:operation.start()], "vle16.v")
    assert inputs == [(operation[1], destination), (operation[2], source)]
    assert _state_vector_accesses(output, "vse16.v") == [(operation[1], destination)]
    assert not re.search(r"^\s*v(?:le|se)8\.v\s", output, re.M)


def test_reverse_q3_active_mac_uses_one_capacity_matched_vtype_through_commit():
    output = reverse(AsmParser().parse_string("vmacc.vx v31, a0, v31"),
                     init_vtype="sew=16,lmul=1,ta,ma", raw=True)
    source_vl = re.search(r"^\s*ld\s+(\w+),.*# 源 CSR.vl$", output, re.M)
    configuration = re.search(r"^\s*vsetvli\s+zero,\s*(\w+),\s*e16,\s*mf4,\s*tu,\s*mu", output, re.M)
    store = re.search(r"^\s*vse16\.v\s+v\d+,\s*\(\w+\)$", output, re.M)
    assert source_vl is not None and configuration is not None and store is not None
    assert source_vl[1] == configuration[1]
    assert SOURCE_VLENB * 8 / 16 == TARGET_VLENB * 8 * Fraction(1, 4) / 16 == 16
    assert len(re.findall(r"^\s*vsetvli\s", output, re.M)) == 1
    assert "vsetvli" not in output[configuration.end():store.start()]
    assert "csrw    vcsr," in output
    assert not re.search(r"^\s*csrw\s+vstart,", output, re.M)
    assert "Guarded zero source vstart remains zero" in output
    assert not re.search(r"\bsd\s+[^\n]*# (?:源 )?CSR\.(?:vl|vtype|vlenb|vcsr)\b", output)


@pytest.mark.parametrize("scalar", ("t6", "x31"))
def test_reverse_q3_active_mac_preserves_guest_t6_scalar_and_state_base(scalar):
    output = reverse(AsmParser().parse_string(f"vmacc.vx v0, {scalar}, v31"),
                     init_vtype="sew=16,lmul=1", raw=True, tls_state=False)
    saved = re.search(r"^\s*sd\s+t6,\s*(\d+)\(sp\)$", output, re.M)
    operation = re.search(r"^\s*vmacc\.vx\s+(v\d+),\s*(\w+),\s*v\d+$", output, re.M)
    assert saved is not None and operation is not None
    assert operation[2] not in {"t6", "x31"}
    assert re.search(rf"ld\s+{operation[2]},\s*{saved[1]}\(sp\)", output[:operation.start()])
    assert {offset for _, offset in _state_vector_accesses(output[:operation.start()], "vle16.v")} == {0, 992}
    assert _state_vector_accesses(output, "vse16.v") == [(operation[1], 0)]
    restore = output.rsplit("# 恢复 RVV 翻译块现场:", 1)[1]
    saves = re.findall(r"^\s*sd\s+(\w+),\s*(\d+)\(sp\)$", output, re.M)
    restores = re.findall(r"^\s*ld\s+(\w+),\s*(\d+)\(sp\)$", restore, re.M)
    assert saves == restores
    assert output.index("Guarded zero source vstart remains zero") < output.index("# 恢复 RVV 翻译块现场")


def test_reverse_q3_widening_mac_tightens_execution_but_keeps_source_emul_transfers():
    output = reverse(AsmParser().parse_string("vwmacc.vv v8, v9, v16"),
                     init_vtype="sew=16,lmul=1", raw=True)
    operation = re.search(r"^\s*vwmacc\.vv\s+(v\d+),\s*(v\d+),\s*(v\d+)$", output, re.M)
    assert operation is not None
    prefix, suffix = output[:operation.start()], output[operation.end():]
    assert re.search(r"vsetvli\s+zero,\s*\w+,\s*e16,\s*mf4,\s*tu,\s*mu", prefix)
    assert re.findall(r"li\s+\w+,\s*(\d+)\s+# Pack 源组有效字节数", prefix) == ["64", "32", "32"]
    assert re.findall(r"li\s+\w+,\s*(\d+)\s+# Unpack 源组有效字节数", suffix) == ["64"]
    assert len(re.findall(r"^\s*vle8\.v\s", prefix, re.M)) == 3
    assert len(re.findall(r"^\s*vse8\.v\s", suffix, re.M)) == 1
    assert "vse32.v" not in output
    assert SOURCE_VLENB * 2 == TARGET_VLENB * Fraction(1, 2) == 64
    assert not re.search(r"\bsd\s+[^\n]*# (?:源 )?CSR\.(?:vl|vtype|vlenb|vcsr)\b", output)


@pytest.mark.parametrize("command, vtype, diagnostic", (
    ("vwmacc.vv v9, v16, v24", "sew=16,lmul=1", "对齐"),
    ("vmacc.vx v9, a0, v16", "sew=16,lmul=2", "对齐"),
    ("vwmacc.vv v8, v16, v24", "sew=16,lmul=8", "EMUL=16"),
))
def test_reverse_q3_tight_mac_still_rejects_invalid_source_groups(command, vtype, diagnostic):
    output = reverse(AsmParser().parse_string(command), init_vtype=vtype, raw=True)
    assert "RVV1024 fallback" in output and diagnostic in output and "ebreak" in output
    assert not re.search(r"^\s*(?:v(?:le|se)\d+\.v|vmacc\.vx|vwmacc\.vv)\s", output, re.M)


@pytest.mark.parametrize("command, sew, lmul, packs", (
    ("vmacc.vx v8, a0, v16", 8, 1, 2),
    ("vmacc.vx v8, a0, v16", 16, 2, 2),
    ("vmadd.vx v8, a0, v16", 16, 1, 2),
    ("vwmacc.vv v8, v16, v24", 32, 1, 3),
    ("vwmacc.vv v8, v16, v24, v0.t", 16, 1, 4),
))
def test_reverse_q3_mac_other_shapes_and_mask_keep_raw_state_transfers(command, sew, lmul, packs):
    output = reverse(AsmParser().parse_string(command),
                     init_vtype=f"sew={sew},lmul={lmul}", raw=True)
    operation = re.search(r"^\s*" + re.escape(command.split()[0]) + r"\s+.*$", output, re.M)
    assert operation is not None and "fallback" not in output.lower()
    prefix, suffix = output[:operation.start()], output[operation.end():]
    assert len(re.findall(r"^\s*vle8\.v\s", prefix, re.M)) == packs
    assert len(re.findall(r"^\s*vse8\.v\s", suffix, re.M)) == 1
    assert re.search(rf"vsetvli\s+zero,\s*\w+,\s*e{sew},\s*m{lmul},\s*tu,\s*mu", prefix)
    assert not re.search(r"^\s*vse(?:16|32)\.v\s", suffix, re.M)
    if "v0.t" in command:
        assert "vmv1r.v v0," in prefix and operation[0].endswith("v0.t")

@pytest.mark.parametrize("command", ("vand.vi v8, v16, 15", "vsrl.vx v8, v8, a1"))
def test_q3_byte_overwrite_uses_only_semantic_inputs_and_partial_commit(command):
    output=reverse(AsmParser().parse_string(command),init_vtype="sew=8,lmul=0.5",raw=True)
    native=re.search(r"^\s*(?:vand\.vi|vsrl\.vx)\s+(v\d+),\s*(v\d+),",output,re.M)
    assert native is not None
    inputs=_state_vector_accesses(output[:native.start()], 'vle8.v')
    assert inputs==[(native[2],512 if 'v16' in command else 256)]
    assert _state_vector_accesses(output[native.end():],'vse8.v')==[(native[1],256)]
    assert build_transition_registry().require(command.split()[0]).reads_old_vd is False
    assert len(re.findall(r'^\s*vsetvli\s',output,re.M))==1
    assert re.search(r'vsetvli\s+zero,\s*\w+,\s*e8,\s*mf8,\s*tu,\s*mu',output)


@pytest.mark.parametrize("command", ('vand.vi v8, v16, 15','vsrl.vx v8, v16, a1','vle8.v v8, (a0)'))
def test_q3_guard_reuses_only_dead_comparison_value_and_vset_clears_start(command):
    output=reverse(AsmParser().parse_string(command),init_vtype='sew=8,lmul=0.5',raw=True)
    value=re.search(r'ld\s+(\w+),\s*48\((\w+)\).*CSR.vlenb',output)
    assert value is not None
    assert re.search(rf'csrr\s+{value[1]},\s*vlenb',output)
    assert re.search(rf'ld\s+{value[1]},\s*0\({value[2]}\).*CSR.vstart',output)
    assert 'csrw    vcsr,' in output and '源 CSR.vstart = 0' in output
    assert not re.search(r'^\s*csrw\s+vstart,',output,re.M)
    assert re.search(r'^\s*vsetvli\s',output,re.M)


@pytest.mark.parametrize('command,vtype', (
    ('vand.vi v8, v16, 15, v0.t','sew=8,lmul=0.5'),
    ('vsrl.vx v8, v16, a1, v0.t','sew=8,lmul=0.5'),
    ('vle8.v v8, (a0), v0.t','sew=16,lmul=1'),
    ('vand.vi v8, v16, 15','sew=16,lmul=1'),
    ('vsrl.vx v8, v16, a1','sew=32,lmul=1'),
    ('vle8.v v8, (a0)','sew=32,lmul=1'),
))
def test_reverse_first_vset_clears_hardware_start_for_other_forms(command,vtype):
    output=reverse(AsmParser().parse_string(command),init_vtype=vtype,raw=True)
    assert not re.search(r'^\s*csrw\s+vstart,', output, re.M)
    first = next(line.strip().split()[0] for line in output.splitlines()
                 if line.lstrip().startswith('v'))
    assert first in {'vsetvli', 'vsetivli', 'vsetvl'}


@pytest.mark.parametrize("command", ("vadd.vv v8, v16, v24", "vnclip.wi v8, v16, 1", "vmv.x.s t6, v8"))
def test_reverse_vcsr_equal_branch_uses_distinct_live_values_and_keeps_writeback(command):
    output = reverse(AsmParser().parse_string(command), init_vtype="sew=16,lmul=1", raw=True)
    source = re.search(r"ld\s+(\w+),\s*24\((\w+)\).*CSR.vcsr", output)
    actual = re.search(r"csrr\s+(\w+),\s*vcsr", output)
    branch = re.search(r"beq\s+(\w+),\s*(\w+),\s*(\.L_rvv1024_vcsr_equal_\d+)", output)
    assert source and actual and branch
    assert actual[1] == source[2] and actual[1] != source[1]
    assert (branch[1], branch[2]) == (actual[1], source[1])
    assert output.index("源 CSR.vstart") < actual.start()
    assert output.index("csrw    vcsr,") < output.index(branch[3] + ":")
    assert "源 CSR.vstart = 0" in output
    if command.startswith("vnclip"):
        assert "捕获目标执行后的 vcsr" in output
    if command.startswith("vmv.x.s"):
        result = re.search(r"^\s*vmv\.x\.s\s+t6,", output, re.M)
        assert result and output.index("源 CSR.vstart = 0") < result.start()


@pytest.mark.parametrize('command, expected_loads', (
    ('vadd.vi v8, v8, -4, v0.t', 1),
    ('vadd.vi v8, v16, -4, v0.t', 2),
))
def test_reverse_masked_halfword_add_keeps_inactive_lanes_and_reuses_alias_snapshot(command, expected_loads):
    output = reverse(AsmParser().parse_string(command), init_vtype='sew=16,lmul=1', raw=True)
    operation = re.search(r'^\s*vadd\.vi\s+(v\d+),\s*(v\d+),\s*-4,\s*v0\.t$', output, re.M)
    assert operation is not None
    loads = _state_vector_accesses(output[:operation.start()], 'vle16.v')
    assert len(loads) == expected_loads
    assert (operation[1], 256) in loads
    assert len(_state_vector_accesses(output[operation.end():], 'vse16.v')) == 1
    assert len(re.findall(r'^\s*vsetvli\s', output, re.M)) == 1
    assert re.search(r'vsetvli\s+zero,\s*\w+,\s*e16,\s*mf4,\s*tu,\s*mu', output)
    assert re.search(r'^\s*vlm\.v\s+v0,', output, re.M)
    assert not re.search(r'^\s*(?:vle8\.v|vse8\.v|vmv1r\.v)\s', output, re.M)
    assert operation[1] == operation[2] if expected_loads == 1 else operation[1] != operation[2]
    assert len(re.findall(r'^\s*sd\s+\w+,\s*\d+\(sp\)', output, re.M)) == 3
    assert output.index('源 CSR.vstart = 0') < output.index('# 恢复 RVV 翻译块现场')


@pytest.mark.parametrize('vd, vs', (('v8', 'v16'), ('v0', 'v31'), ('v31', 'v1')))
def test_reverse_halfword_zero_extend_commits_only_active_bytes(vd, vs):
    output = reverse(AsmParser().parse_string(f'vzext.vf2 {vd}, {vs}'), init_vtype='sew=16,lmul=1', raw=True)
    operation = re.search(r'^\s*vzext\.vf2\s+(v\d+),\s*(v\d+)$', output, re.M)
    assert operation is not None
    assert _state_vector_accesses(output[:operation.start()], 'vle8.v') == [(operation[2], int(vs[1:])*32)]
    assert _state_vector_accesses(output[operation.end():], 'vse16.v') == [(operation[1], int(vd[1:])*32)]
    assert not re.search(r'^\s*vse8\.v\s', output, re.M)
    assert len(re.findall(r'^\s*vsetvli\s', output, re.M)) == 1
    assert re.search(r'vsetvli\s+zero,\s*\w+,\s*e16,\s*mf4,\s*tu,\s*mu', output)
    assert SOURCE_VLENB*Fraction(1,2) == TARGET_VLENB*Fraction(1,8) == 16
    assert len(re.findall(r'^\s*sd\s+\w+,\s*\d+\(sp\)', output, re.M)) == 3
    assert not re.search(r'^\s*sd\s+[^\n]*# (?:源 )?CSR\.(?:vl|vtype|vlenb|vcsr)\b', output, re.M)


@pytest.mark.parametrize('command, vtype', (
    ('vadd.vi v8, v16, -4, v0.t', 'sew=8,lmul=1'),
    ('vadd.vi v8, v16, -4, v0.t', 'sew=16,lmul=2'),
    ('vadd.vi v8, v16, -4', 'sew=16,lmul=1'),
    ('vzext.vf2 v8, v16', 'sew=16,lmul=2'),
    ('vzext.vf2 v8, v16', 'sew=32,lmul=1'),
    ('vsext.vf2 v8, v16', 'sew=16,lmul=1'),
))
def test_reverse_mask_extend_optimizations_keep_other_forms_on_existing_transfers(command, vtype):
    output = reverse(AsmParser().parse_string(command), init_vtype=vtype, raw=True)
    assert 'fallback' not in output.lower()
    assert re.search(r'^\s*vse8\.v\s', output, re.M)
    assert bool(re.search(r'^\s*vlm\.v\s', output, re.M)) == ('v0.t' in command)


def test_reverse_active_mac_does_not_borrow_unused_transfer_gpr():
    output = reverse(AsmParser().parse_string('vmacc.vx v8, a1, v16'), init_vtype='sew=16,lmul=1', raw=True)
    spills = re.findall(r'^\s*sd\s+(\w+),\s*\d+\(sp\)', output, re.M)
    assert spills == ['t0', 't1', 't6']
    assert len(re.findall(r'^\s*vsetvli\s', output, re.M)) == 1
    assert len(_state_vector_accesses(output, 'vle16.v')) == 2
    assert len(_state_vector_accesses(output, 'vse16.v')) == 1


@pytest.mark.parametrize('scalar', ('a1', 't0', 't1', 't2', 't6', 'x31'))
def test_reverse_mac_preserves_guarded_zero_vstart_without_rewriting_csr_page(scalar):
    output = reverse(AsmParser().parse_string(f'vmacc.vx v8, {scalar}, v16'),
                     init_vtype='sew=16,lmul=1', raw=True, tls_state=False)
    guard = re.search(r'ld\s+(\w+),\s*0\(\w+\).*CSR.vstart', output)
    operation = re.search(r'^\s*vmacc\.vx\s+', output, re.M)
    sync = re.search(r'^\s*csrr\s+\w+,\s*vcsr', output, re.M)
    assert guard and operation and sync and guard.start() < sync.start() < operation.start()
    assert 'Guarded zero source vstart remains zero' in output
    assert not re.search(r'^\s*sd\s+zero,\s*0\(\w+\).*CSR.vstart', output, re.M)
    assert 'Source VL from the live guard CSR page' not in output
    assert re.search(r'ld\s+\w+,\s*32\(\w+\).*CSR.vl', output)
    assert len(re.findall(r'^\s*vsetvli\s', output, re.M)) == 1
    assert len(_state_vector_accesses(output, 'vle16.v')) == 2
    assert len(_state_vector_accesses(output, 'vse16.v')) == 1
    assert output.count('ebreak') == 1


@pytest.mark.parametrize('command,vtype', (
    ('vmacc.vx v8, a1, v16', 'sew=8,lmul=1'),
    ('vmacc.vx v8, a1, v16', 'sew=16,lmul=2'),
    ('vmacc.vx v8, a1, v16', 'sew=32,lmul=1'),
    ('vmadd.vx v8, a1, v16', 'sew=16,lmul=1'),
    ('vwmacc.vv v8, v16, v24', 'sew=16,lmul=1'),
    ('vse16.v v8, (a0)', 'sew=16,lmul=1'),
))
def test_reverse_mac_zero_vstart_fold_keeps_other_forms_and_external_stores_conservative(command, vtype):
    output = reverse(AsmParser().parse_string(command), init_vtype=vtype, raw=True)
    assert '源 CSR.vstart = 0' in output
    assert 'Guarded zero source vstart remains zero' not in output
    assert re.search(r'^\s*sd\s+zero,\s*0\(\w+\).*CSR.vstart', output, re.M)


@pytest.mark.parametrize('scalar', ('a0', 't0', 't1', 't2', 't6', 'x31'))
def test_reverse_mac_retains_vd_address_in_dead_vl_temp_through_commit(scalar):
    output = reverse(AsmParser().parse_string(f'vmacc.vx v8, {scalar}, v16'),
                     init_vtype='sew=16,lmul=1', raw=True, tls_state=False)
    source_vl = re.search(r'^\s*ld\s+(\w+),.*# 源 CSR.vl$', output, re.M)
    config = re.search(r'^\s*vsetvli\s+zero,\s*(\w+),\s*e16,\s*mf4,', output, re.M)
    operation = re.search(r'^\s*vmacc\.vx\s+(v\d+),\s*\w+,\s*(v\d+)$', output, re.M)
    assert source_vl and config and operation and source_vl[1] == config[1]
    vd_load = re.search(r'^\s*vle16\.v\s+'+operation[1]+r',\s*\((\w+)\)$', output, re.M)
    source_load = re.search(r'^\s*vle16\.v\s+'+operation[2]+r',\s*\((\w+)\)$', output, re.M)
    commit = re.search(r'^\s*vse16\.v\s+'+operation[1]+r',\s*\((\w+)\)$', output, re.M)
    assert vd_load and source_load and commit
    assert vd_load[1] == commit[1] == source_vl[1]
    assert source_load[1] != vd_load[1]
    assert config.start() < vd_load.start() < source_load.start() < operation.start() < commit.start()
    assert len(re.findall(r'^\s*addi\s+'+vd_load[1]+r',\s*t6,\s*256\s+# CHIMERA_STATE_BASE$',output,re.M)) == 1
    assert _state_vector_accesses(output,'vse16.v') == [(operation[1],256)]
    assert output.index('csrw    vcsr,') < operation.start()
    assert 'Guarded zero source vstart remains zero' in output


@pytest.mark.parametrize('command,vtype', (
    ('vmacc.vx v8, a0, v16','sew=8,lmul=1'),
    ('vmacc.vx v8, a0, v16','sew=16,lmul=2'),
    ('vmadd.vx v8, a0, v16','sew=16,lmul=1'),
))
def test_reverse_mac_address_retention_keeps_raw_transfer_controls(command,vtype):
    output = reverse(AsmParser().parse_string(command),init_vtype=vtype,raw=True)
    assert re.search(r'^\s*vse8\.v\s',output,re.M)
    assert 'Guarded zero source vstart remains zero' not in output
