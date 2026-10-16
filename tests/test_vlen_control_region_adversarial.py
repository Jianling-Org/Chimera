"""Production parser/CFG regressions for known VLEN control regions."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from chimera.preprocess.offline.analysis.arch.riscv.rvv.services import RvvServices
from chimera.preprocess.offline.analysis.arch.riscv.services import RiscvServices
from chimera.preprocess.offline.analysis.program_model.parser import parse_dump
from chimera.preprocess.offline.analysis.safety.stack_liveness.analyzer import (
    StackLivenessAnalyzer,
)
from chimera.preprocess.offline.analysis.safety.stack_liveness.dependencies import (
    analyze_register_dependencies,
)
from chimera.preprocess.offline.analysis.safety.stack_liveness.model import (
    ChimeraMetadata,
)
from chimera.preprocess.offline.analysis.toolchain.objdump import LinuxObjdump


def _dump(name: str, body: list[tuple[str, str]]) -> tuple[str, int]:
    """Render labeled RISC-V instructions with addresses derived from position."""
    labels: dict[str, int] = {}
    address = 0x1000
    for op, operands in body:
        if op == "label":
            labels[operands] = address
        else:
            address += 4

    lines = [f"0000000000001000 <{name}>:"]
    address = 0x1000
    adjustment = None
    for op, operands in body:
        if op == "label":
            continue
        for label, target in labels.items():
            operands = operands.replace("@" + label, hex(target))
        lines.append(f"{address:x}: 00000013 {op} {operands}".rstrip())
        if op == "sub" and operands == "sp,sp,a0":
            adjustment = address
        address += 4
    if adjustment is None:
        raise AssertionError("scenario must contain the stack adjustment")
    return "\n".join(lines) + "\n", adjustment


_GUARD = [("csrr", "t0,vlenb"), ("li", "t1,8"), ("bltu", "t0,t1,@left")]
_NOOP_ARMS = [
    ("nop", ""), ("j", "@join"), ("label", "left"), ("nop", ""),
    ("label", "join"),
]
_SELECT_ARMS = [
    ("li", "a0,16"), ("j", "@join"), ("label", "left"),
    ("li", "a0,32"), ("label", "join"),
]
_END = [("sub", "sp,sp,a0"), ("ret", "")]

_CASES = (
    ("noop_join_unknown", _GUARD + _NOOP_ARMS + _END, False),
    ("noop_join_constant_write", _GUARD + _NOOP_ARMS + [("li", "a0,16")] + _END, False),
    ("noop_join_external_call", _GUARD + _NOOP_ARMS + [("jal", "0x9000")] + _END, False),
    ("selected_size_survives_join", _GUARD + _SELECT_ARMS + _END, True),
    ("selected_size_survives_unrelated_write", _GUARD + _SELECT_ARMS + [("li", "a1,64")] + _END, True),
    ("selected_size_overwritten_after_join", _GUARD + _SELECT_ARMS + [("li", "a0,64")] + _END, False),
    ("selected_size_used_by_later_guard", _GUARD + _SELECT_ARMS + [
        ("beqz", "a0,@other"), ("li", "a0,48"), ("j", "@later"),
        ("label", "other"), ("li", "a0,80"), ("label", "later"),
    ] + _END, True),
    ("nested_join_still_in_outer_arm", _GUARD + [
        ("beqz", "a2,@inner"), ("nop", ""), ("j", "@innerjoin"),
        ("label", "inner"), ("nop", ""), ("label", "innerjoin"),
        ("li", "a0,16"), ("j", "@join"), ("label", "left"),
        ("li", "a0,32"), ("label", "join"),
    ] + _END, True),
    ("call_inside_known_guard", _GUARD + [
        ("jal", "0x9000"), ("j", "@join"), ("label", "left"),
        ("li", "a0,32"), ("label", "join"),
    ] + _END, True),
    ("multiple_exits_controlled_allocation", _GUARD + _END + [
        ("label", "left"), ("ret", ""),
    ], True),
    ("unknown_jump_not_fake_reconvergence", _GUARD + [
        ("jr", "t2"), ("label", "left"),
    ] + _END, True),
    ("nonexit_scc_not_fake_reconvergence", _GUARD + [
        ("label", "spin"), ("j", "@spin"), ("label", "left"),
    ] + _END, True),
    ("partial_exit_path_not_fake_reconvergence", _GUARD + [
        ("beqz", "a2,@spin"), ("j", "@join"), ("label", "spin"),
        ("j", "@spin"), ("label", "left"), ("nop", ""), ("label", "join"),
    ] + _END, True),
    ("unknown_guard_not_known_vlen", [("beqz", "a2,@left")] + _SELECT_ARMS + _END, False),
    ("unknown_incomplete_guard_not_known_vlen", [("beqz", "a2,0x9000")] + _END, False),
    ("known_incomplete_guard_retained", [("csrr", "t0,vlenb"), ("beqz", "t0,0x9000")] + _END, True),
    ("unreachable_vlen_guard_ignored", [
        ("j", "@join"), ("csrr", "t0,vlenb"), ("li", "t1,8"),
        ("bltu", "t0,t1,@left"), ("li", "a0,16"), ("label", "left"),
        ("li", "a0,32"), ("label", "join"),
    ] + _END, False),
    ("selected_value_loop_carried", _GUARD + _SELECT_ARMS + [
        ("li", "t2,3"), ("label", "loop"), ("addi", "t2,t2,-1"),
        ("bnez", "t2,@loop"),
    ] + _END, True),
    ("genuine_vlen_size", [
        ("csrr", "a0,vlenb"), ("li", "t1,10"), ("mul", "a0,a0,t1"),
    ] + _END, True),
    ("known_guard_arm_contains_bset", _GUARD + [
        ("bset", "a3,a4,a5"), ("j", "@join"), ("label", "left"),
        ("nop", ""), ("label", "join"),
    ] + _END, False),
    ("linear_bset_is_not_a_guard", [
        ("csrr", "t0,vlenb"), ("bset", "a3,t0,a5"),
    ] + _END, False),
)


class VlenControlRegionAdversarialTests(unittest.TestCase):
    def test_production_parser_cfg_and_frame_flow_cover_adversarial_cases(self):
        self.assertEqual(len(_CASES), 21)
        rvv = RvvServices()
        semantics = rvv.stack_semantics
        adapter = LinuxObjdump("objdump")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name, body, expected_retained in _CASES:
                with self.subTest(case=name):
                    dump, adjustment = _dump(name, body)
                    source = root / f"{name}.dump"
                    source.write_text(dump, encoding="utf-8")
                    parsed = parse_dump(
                        source,
                        adapter.parse_format,
                        is_external_trampoline=adapter.is_external_trampoline,
                        retain_dump_lines=False,
                    )
                    program = RiscvServices(rvv).build_cfg(parsed)
                    function, = program.functions
                    dependencies = analyze_register_dependencies(
                        function,
                        semantics,
                        capture_known_vlen_control=True,
                    )
                    result = StackLivenessAnalyzer(
                        semantics=semantics,
                        emit_warnings=False,
                        unknown_stack_size_policy="assume-scalar-independent",
                    ).analyze_program(
                        program,
                        metadata=ChimeraMetadata.empty(),
                        config_results=rvv.vector_configs(program),
                    )
                    local = result.by_function[function.start]
                    origin = next(
                        (
                            item
                            for item in local.frame_origins
                            if item.adjustment == adjustment
                            and item.dependency != "proven"
                        ),
                        None,
                    )
                    self.assertEqual(origin is not None, expected_retained)
                    if name in {"unknown_incomplete_guard_not_known_vlen", "unknown_guard_not_known_vlen"}:
                        self.assertFalse(dependencies.vlen_controlled_before(adjustment, "a0"))
                    if name == "known_incomplete_guard_retained":
                        self.assertTrue(dependencies.known_control_fallback)


if __name__ == "__main__":
    unittest.main()
