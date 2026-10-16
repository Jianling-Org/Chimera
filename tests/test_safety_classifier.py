from __future__ import annotations

from io import StringIO
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from chimera.preprocess.offline.analysis.core.data_model import (
    Function,
    Instruction,
    Program,
)
from chimera.preprocess.offline.analysis.core.monitor import monitoring
from chimera.preprocess.offline.analysis.safety.classifier import (
    SafetyAnalysisResult,
    SafetyRecord,
    classify_liveness,
)
from chimera.preprocess.offline.analysis.safety.stack_liveness.model import (
    StackObjectId,
)
from chimera.preprocess.offline.analysis.safety.stack_liveness.frame_liveness import (
    VLEN_STACK_FRAME,
    VLEN_STACK_SETUP,
)
from chimera.preprocess.offline.analysis.safety.step import _compute_summary


class _FunctionResult:
    def __init__(self, live_before):
        self.live_before = live_before


class _FlatteningForbidden:
    def __init__(self, by_function):
        self.by_function = by_function

    @property
    def live_before(self):
        raise AssertionError("classifier must not flatten all function results")


def _instruction(address: int) -> Instruction:
    return Instruction(address, 4, "addi", ["a0", "a0", "1"], "addi a0,a0,1")


def _program_fixture():
    vector_instruction = _instruction(0x20)
    stack_instruction = _instruction(0x24)
    missing_instruction = _instruction(0x10)
    orphan_instruction = _instruction(0x30)
    first = Function("first", 0x20, [vector_instruction, stack_instruction])
    second = Function("second", 0x10, [missing_instruction])
    instructions = [vector_instruction, stack_instruction, missing_instruction, orphan_instruction]
    program = Program(
        dump_lines=[],
        functions=[first, second],
        instructions=instructions,
        instruction_by_address={item.addr: item for item in instructions},
        source_path=Path("fixture.dump"),
    )
    stack_object = StackObjectId("stack", "slot")
    vector = _FlatteningForbidden(
        {first.start: _FunctionResult({vector_instruction.addr: frozenset({8})})}
    )
    stack = _FlatteningForbidden(
        {first.start: _FunctionResult({stack_instruction.addr: frozenset({stack_object})})}
    )
    return program, vector, stack


class SafetyClassifierTests(unittest.TestCase):
    def test_vlen_stack_markers_have_distinct_reasons(self) -> None:
        function = Function("frame", 0x40, [_instruction(0x40)])
        program = Program(
            dump_lines=[],
            functions=[function],
            instructions=function.insts,
            instruction_by_address={0x40: function.insts[0]},
            source_path=Path("fixture.dump"),
        )
        vector = _FlatteningForbidden({})
        stack = _FlatteningForbidden(
            {
                function.start: _FunctionResult(
                    {
                        0x40: frozenset({VLEN_STACK_FRAME, VLEN_STACK_SETUP})
                    }
                )
            }
        )

        result = classify_liveness(program, vector, stack)

        self.assertEqual(
            result.records[0x40].reasons,
            ("live_vlen_stack_frame", "live_vlen_stack_setup"),
        )

    def test_classification_uses_per_function_liveness_without_flattening(self) -> None:
        program, vector, stack = _program_fixture()

        result = classify_liveness(program, vector, stack)

        self.assertFalse(result.records[0x20].safe)
        self.assertEqual(result.records[0x20].vector_live, frozenset({8}))
        self.assertFalse(result.records[0x24].safe)
        self.assertEqual(
            result.records[0x24].stack_live,
            frozenset({StackObjectId("stack", "slot")}),
        )

    def test_missing_function_and_orphan_instruction_default_to_safe(self) -> None:
        program, vector, stack = _program_fixture()

        result = classify_liveness(program, vector, stack)

        self.assertTrue(result.records[0x10].safe)
        self.assertTrue(result.records[0x30].safe)
        self.assertEqual(result.safe_addresses, [0x10, 0x30])

    def test_debug_counts_do_not_sort_safe_addresses(self) -> None:
        program, vector, stack = _program_fixture()
        output = StringIO()

        with (
            patch.object(
                SafetyAnalysisResult,
                "safe_addresses",
                new_callable=unittest.mock.PropertyMock,
                side_effect=AssertionError("safe-address sorting is forbidden"),
            ),
            monitoring(enabled=True, stream=output),
        ):
            classify_liveness(program, vector, stack)

        text = output.getvalue()
        self.assertIn("[DEBUG] safety.classify.finish", text)
        self.assertIn("safe=2", text)
        self.assertIn("unsafe=2", text)

    def test_safety_summary_reports_counts_and_warning_categories(self) -> None:
        records = {
            0x10: SafetyRecord(0x10, True, frozenset(), frozenset()),
            0x20: SafetyRecord(0x20, False, frozenset({1}), frozenset()),
        }
        warning = SimpleNamespace(code="irreducible-loop")

        summary = _compute_summary(
            module_id="app",
            config_functions=1,
            vector=SimpleNamespace(by_function={0x10: object()}),
            stack=SimpleNamespace(
                by_function={0x10: object()},
                inherited_functions=frozenset({0x20}),
                unresolved_live_calls=(0x30, 0x40),
                inheritance_trace=SimpleNamespace(
                    seed_edges=(object(),),
                    max_depth=2,
                ),
            ),
            safety=SimpleNamespace(records=records),
            warnings=(warning, warning),
        )

        self.assertEqual(
            summary["instructions"],
            {"total": 2, "safe": 1, "unsafe": 1},
        )
        self.assertEqual(
            summary["calls"],
            {
                "inherited_functions": 1,
                "unresolved_active_calls": 2,
                "active_external_calls": 0,
                "closed_external_calls": 0,
                "seed_edges": 1,
                "max_inheritance_depth": 2,
            },
        )
        self.assertEqual(
            summary["warnings"],
            {"total": 2, "by_code": {"irreducible-loop": 2}},
        )


if __name__ == "__main__":
    unittest.main()
