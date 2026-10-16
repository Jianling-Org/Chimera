"""Stack-analysis warning emission (safety step stderr output).

``unresolved-active-indirect-call`` sites must be printed with their owning
function name plus one aggregate remedy line; previously they lived only in
memory and were lost when prepare exited.
"""

from __future__ import annotations

import io
import unittest
from contextlib import redirect_stderr

from chimera.preprocess.offline.analysis.core.data_model.program import (
    Function,
    Instruction,
)
from chimera.preprocess.offline.analysis.safety.stack_liveness.liveness import (
    _CallerStackContextPropagator,
)
from chimera.preprocess.offline.analysis.safety.stack_liveness.model import (
    ORIGIN_INHERITED,
    ORIGIN_VECTOR_DATA,
)
from chimera.preprocess.offline.analysis.safety.stack_liveness.model import (
    AnalysisWarning,
    StackAccess,
    StackAccessKind,
    StackFunctionLiveness,
    StackObjectId,
)
from chimera.preprocess.offline.analysis.safety.step import _emit_stack_warnings


def _warning(code: str, function_start: int = 0x1000) -> AnalysisWarning:
    return AnalysisWarning(
        code=code,
        message=(
            f"active indirect call at {0x2000:#x} has no usable complete "
            "internal target set; inherited stack state was not propagated"
        ),
        function_start=function_start,
        addresses=(0x2000,),
    )


class EmitStackWarningsTests(unittest.TestCase):
    def test_unresolved_sites_print_function_names_and_aggregate(self) -> None:
        warnings = [
            _warning("unresolved-active-indirect-call", function_start=0x1000),
            _warning("unresolved-active-indirect-call", function_start=0x3000),
        ]
        buffer = io.StringIO()
        with redirect_stderr(buffer):
            _emit_stack_warnings(warnings, {0x1000: "foo", 0x3000: "bar"})
        output = buffer.getvalue()
        self.assertIn("[unresolved-active-indirect-call]", output)
        self.assertIn("function=foo", output)
        self.assertIn("function=bar", output)
        self.assertIn("2 active indirect call(s)", output)
        self.assertIn("svf/full", output)
        self.assertNotIn("chimera: error", output)

    def test_unknown_function_start_falls_back(self) -> None:
        buffer = io.StringIO()
        with redirect_stderr(buffer):
            _emit_stack_warnings(
                [_warning("unresolved-active-indirect-call")], {}
            )
        self.assertIn("function=<unknown>", buffer.getvalue())

    def test_empty_call_target_set_prints_as_error(self) -> None:
        buffer = io.StringIO()
        with redirect_stderr(buffer):
            _emit_stack_warnings([_warning("empty-call-target-set")], {})
        output = buffer.getvalue()
        self.assertIn("chimera: error: [empty-call-target-set]", output)
        self.assertNotIn("active indirect call(s)", output)

    def test_unrelated_warnings_are_not_printed(self) -> None:
        buffer = io.StringIO()
        with redirect_stderr(buffer):
            _emit_stack_warnings([_warning("irreducible-loop-degraded")], {})
        self.assertEqual(buffer.getvalue(), "")

    def test_details_are_printed_below_the_warning(self) -> None:
        warning = AnalysisWarning(
            code="unresolved-active-indirect-call",
            message="active indirect call at 0x2000 has no usable complete "
            "internal target set; inherited stack state was not propagated",
            function_start=0x1000,
            addresses=(0x2000,),
            details=(
                "live stack object compiler:3: vector stack write(s) at "
                "0x1010 `vs1r.v v8, (sp)`; read back at 0x1080 `vl1r.v v8, (sp)`",
            ),
        )
        buffer = io.StringIO()
        with redirect_stderr(buffer):
            _emit_stack_warnings([warning], {0x1000: "foo"})
        output = buffer.getvalue()
        self.assertIn("stack-active because: live stack object compiler:3", output)
        self.assertIn("0x1010 `vs1r.v v8, (sp)`", output)


class ExplainActivityTests(unittest.TestCase):
    @staticmethod
    def _instruction(addr: int, text: str) -> Instruction:
        return Instruction(addr=addr, size=4, op=text.split()[0], args=[], text=text)

    def test_live_object_lists_vector_stack_write_and_read(self) -> None:
        obj = StackObjectId("compiler", 3)
        function = Function(
            name="foo",
            start=0x1000,
            insts=[
                self._instruction(0x1010, "vs1r.v v8, (sp)"),
                self._instruction(0x2000, "jalr ra, t1, 0"),
                self._instruction(0x1080, "vl1r.v v8, (sp)"),
            ],
        )
        local = StackFunctionLiveness(
            function_start=0x1000,
            live_before={0x2000: frozenset({obj})},
            accesses={
                0x1010: StackAccess(
                    instruction_addr=0x1010,
                    kind=StackAccessKind.STORE,
                    stack_id=obj,
                    config=frozenset(),
                    source="compiler",
                ),
                0x1080: StackAccess(
                    instruction_addr=0x1080,
                    kind=StackAccessKind.LOAD,
                    stack_id=obj,
                    config=frozenset(),
                    source="compiler",
                ),
            },
        )
        details, origins = _CallerStackContextPropagator._explain_activity(
            function, local, 0x2000, caller_live=False
        )
        self.assertEqual(len(details), 1)
        self.assertIn("vector stack write(s) at 0x1010 `vs1r.v v8, (sp)`", details[0])
        self.assertIn("read back at 0x1080 `vl1r.v v8, (sp)`", details[0])
        # The structured record carries the same verdict, so classification
        # never has to read the prose.
        self.assertEqual(len(origins), 1)
        self.assertEqual(origins[0].origin, ORIGIN_VECTOR_DATA)
        self.assertEqual(origins[0].object_id, str(obj))
        self.assertEqual(origins[0].detail, details[0])

    def test_caller_live_marker_explains_inheritance(self) -> None:
        function = Function(
            name="foo",
            start=0x1000,
            insts=[self._instruction(0x2000, "jalr ra, t1, 0")],
        )
        local = StackFunctionLiveness(
            function_start=0x1000,
            live_before={0x2000: frozenset()},
            accesses={},
        )
        details, origins = _CallerStackContextPropagator._explain_activity(
            function, local, 0x2000, caller_live=True
        )
        self.assertIn("caller-inherited stack data", details[0])
        self.assertEqual(
            [origin.origin for origin in origins], [ORIGIN_INHERITED]
        )


if __name__ == "__main__":
    unittest.main()
