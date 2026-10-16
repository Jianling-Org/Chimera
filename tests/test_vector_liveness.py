"""Vector-state (vtype/vl) liveness coverage for the RVV safety analysis."""

from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from chimera.preprocess.offline.analysis.arch.riscv.rvv.liveness import (
    VECTOR_STATE_REGISTER,
    VectorLivenessAnalyzer,
    instruction_use_def,
)
from chimera.preprocess.offline.analysis.core.data_model import (
    Function,
    Instruction,
    Program,
)
from chimera.preprocess.offline.analysis.safety.classifier import SafetyRecord
from chimera.preprocess.offline.analysis.safety.exporters import export_json


def _instruction(address: int, op: str, args: list[str]) -> Instruction:
    return Instruction(address, 4, op, list(args), f"{op} " + ",".join(args))


def _function(*specs: tuple[str, list[str]], start: int = 0x1000) -> Function:
    instructions = [
        _instruction(start + 4 * index, op, args)
        for index, (op, args) in enumerate(specs)
    ]
    for current, following in zip(instructions, instructions[1:]):
        current.succ.add(following.addr)
    return Function("fixture", start, instructions)


def _analyze(function: Function):
    return VectorLivenessAnalyzer().analyze_function(function)


class VectorStateUseDefTests(unittest.TestCase):
    def test_vset_defines_virtual_state_register(self) -> None:
        uses, definitions = instruction_use_def(
            _instruction(0, "vsetvli", ["a0", "a1", "e32", "m1"])
        )
        self.assertEqual(uses, set())
        self.assertEqual(definitions, {VECTOR_STATE_REGISTER})

    def test_vsetivli_defines_without_use(self) -> None:
        uses, definitions = instruction_use_def(
            _instruction(0, "vsetivli", ["a0", "5", "e32", "m1"])
        )
        self.assertEqual(uses, set())
        self.assertEqual(definitions, {VECTOR_STATE_REGISTER})

    def test_keep_vl_vset_form_observes_previous_state(self) -> None:
        # rd=x0, rs1=x0 keeps the current vl: the instruction observes the
        # previous vector state, so it must use as well as define.
        for spellings in (("zero", "zero"), ("x0", "x0")):
            uses, definitions = instruction_use_def(
                _instruction(0, "vsetvli", [*spellings, "e32", "m1"])
            )
            self.assertEqual(uses, {VECTOR_STATE_REGISTER})
            self.assertEqual(definitions, {VECTOR_STATE_REGISTER})

    def test_vector_instruction_uses_state_register(self) -> None:
        uses, definitions = instruction_use_def(
            _instruction(0, "vadd.vv", ["v1", "v2", "v3"])
        )
        self.assertEqual(uses, {2, 3, VECTOR_STATE_REGISTER})
        self.assertEqual(definitions, {1})

    def test_vector_store_uses_state_register(self) -> None:
        uses, definitions = instruction_use_def(
            _instruction(0, "vse32.v", ["v1", "0(a0)"])
        )
        self.assertEqual(uses, {1, VECTOR_STATE_REGISTER})
        self.assertEqual(definitions, set())

    def test_csr_read_of_vtype_or_vl_uses_state(self) -> None:
        for op, args in (
            ("csrr", ["a0", "vtype"]),
            ("csrrs", ["a0", "vl", "zero"]),
        ):
            uses, definitions = instruction_use_def(_instruction(0, op, args))
            self.assertEqual(uses, {VECTOR_STATE_REGISTER})
            self.assertEqual(definitions, set())

    def test_csr_on_unrelated_state_does_not_use(self) -> None:
        for args in (["a0", "vlenb"], ["a1", "vstart", "a0"]):
            uses, definitions = instruction_use_def(
                _instruction(0, "csrrw", args)
            )
            self.assertEqual(uses, set())
            self.assertEqual(definitions, set())

    def test_call_kills_state_register(self) -> None:
        uses, definitions = instruction_use_def(_instruction(0, "call", ["foo"]))
        self.assertEqual(uses, set())
        self.assertIn(VECTOR_STATE_REGISTER, definitions)
        self.assertEqual(definitions, set(range(VECTOR_STATE_REGISTER + 1)))


class VectorStateLivenessTests(unittest.TestCase):
    def test_interval_between_vset_and_first_vector_op_is_unsafe(self) -> None:
        function = _function(
            ("vsetvli", ["a0", "a1", "e32", "m1"]),
            ("addi", ["a0", "a0", "1"]),
            ("vadd.vv", ["v1", "v2", "v3"]),
        )
        result = _analyze(function)
        self.assertIn(VECTOR_STATE_REGISTER, result.live_before[0x1004])
        # The vsetvli itself defines the state: it is not live before it.
        self.assertNotIn(VECTOR_STATE_REGISTER, result.live_before[0x1000])

    def test_state_dies_after_last_vector_use(self) -> None:
        function = _function(
            ("vsetvli", ["a0", "a1", "e32", "m1"]),
            ("vadd.vv", ["v1", "v2", "v3"]),
            ("addi", ["a0", "a0", "1"]),
            ("addi", ["a1", "a1", "1"]),
        )
        result = _analyze(function)
        self.assertNotIn(VECTOR_STATE_REGISTER, result.live_before[0x1008])
        self.assertNotIn(VECTOR_STATE_REGISTER, result.live_before[0x100C])

    def test_keep_vl_form_keeps_interval_unsafe(self) -> None:
        function = _function(
            ("vadd.vv", ["v1", "v2", "v3"]),
            ("vsetvli", ["zero", "zero", "e16", "m1"]),
            ("vadd.vv", ["v4", "v5", "v6"]),
        )
        result = _analyze(function)
        self.assertIn(VECTOR_STATE_REGISTER, result.live_before[0x1004])
        # A plain vsetvli at the same spot would not have the state live-in.
        plain = _function(
            ("vadd.vv", ["v1", "v2", "v3"]),
            ("vsetvli", ["a0", "a1", "e16", "m1"]),
            ("vadd.vv", ["v4", "v5", "v6"]),
        )
        plain_result = _analyze(plain)
        self.assertNotIn(VECTOR_STATE_REGISTER, plain_result.live_before[0x1004])

    def test_call_ends_state_lifetime(self) -> None:
        function = _function(
            ("vsetvli", ["a0", "a1", "e32", "m1"]),
            ("call", ["foo"]),
            ("ret", []),
        )
        result = _analyze(function)
        self.assertNotIn(VECTOR_STATE_REGISTER, result.live_before[0x1004])

    def test_csr_read_marks_preceding_point_unsafe(self) -> None:
        function = _function(
            ("vsetvli", ["a0", "a1", "e32", "m1"]),
            ("csrr", ["a0", "vtype"]),
        )
        result = _analyze(function)
        self.assertIn(VECTOR_STATE_REGISTER, result.live_before[0x1004])


class VectorStatePresentationTests(unittest.TestCase):
    def test_reasons_distinguish_state_from_registers(self) -> None:
        state_only = SafetyRecord(
            0x10, False, frozenset({VECTOR_STATE_REGISTER}), frozenset(),
            ("live_vector_state",),
        )
        self.assertEqual(state_only.reasons, ("live_vector_state",))
        mixed = SafetyRecord(
            0x10, False, frozenset({8, VECTOR_STATE_REGISTER}), frozenset(),
            ("live_vector_registers", "live_vector_state"),
        )
        self.assertEqual(mixed.reasons, ("live_vector_registers", "live_vector_state"))
        registers_only = SafetyRecord(
            0x10, False, frozenset({8}), frozenset(),
            ("live_vector_registers",),
        )
        self.assertEqual(registers_only.reasons, ("live_vector_registers",))

    def test_export_json_labels_state_register(self) -> None:
        records = {
            0x10: SafetyRecord(
                0x10, False, frozenset({8, VECTOR_STATE_REGISTER}), frozenset(),
                ("live_vector_registers", "live_vector_state"),
            ),
        }
        result = type(
            "Result", (), {"records": records}
        )()
        program = Program(
            dump_lines=[],
            functions=[],
            instructions=[],
            instruction_by_address={},
            source_path=Path("fixture.dump"),
        )
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "safety.json"
            export_json(program, result, output)
            document = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(document["unknown_stack_size_policy"], "conservative")
        self.assertFalse(document["conditional"])
        self.assertEqual(
            document["assumption"],
            "Unknown scalar stack allocation sizes remain conservatively VLEN-sensitive.",
        )
        self.assertEqual(document["scope_exclusion_count"], 0)
        self.assertEqual(document["entries"][0]["vector_live"], [8, VECTOR_STATE_REGISTER])
        self.assertEqual(
            document["entries"][0]["unsafe_reasons"],
            ["live_vector_registers", "live_vector_state"],
        )


if __name__ == "__main__":
    unittest.main()
