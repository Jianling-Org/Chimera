from __future__ import annotations

from contextlib import redirect_stdout
from collections.abc import Mapping
from io import StringIO
import sys
import unittest

from chimera.preprocess.offline.analysis.core.monitor import (
    argument,
    local,
    monitored,
    monitoring,
    returned,
)


class MonitorTests(unittest.TestCase):
    def test_disabled_monitor_is_silent_and_preserves_result(self) -> None:
        @monitored(
            "sample",
            variables=(argument("value"), local("doubled"), returned()),
        )
        def sample(value: int) -> int:
            doubled = value * 2
            return doubled

        output = StringIO()
        with redirect_stdout(output):
            result = sample(4)

        self.assertEqual(result, 8)
        self.assertEqual(output.getvalue(), "")

    def test_enabled_monitor_prints_argument_local_and_return_snapshots(self) -> None:
        @monitored(
            "sample",
            variables=(
                argument("value"),
                local("doubled"),
                returned(label="answer"),
            ),
        )
        def sample(value: int) -> int:
            unlisted_secret = "must-not-appear"
            doubled = value * 2
            return doubled

        output = StringIO()
        with monitoring(enabled=True, stream=output):
            result = sample(4)

        self.assertEqual(result, 8)
        lines = output.getvalue().splitlines()
        self.assertEqual(len(lines), 2)
        self.assertTrue(lines[0].startswith("[DEBUG] sample.start "))
        self.assertIn("value=4", lines[0])
        self.assertTrue(lines[1].startswith("[DEBUG] sample.finish "))
        self.assertIn("doubled=8", lines[1])
        self.assertIn("answer=8", lines[1])
        self.assertIn("duration_ms=", lines[1])
        self.assertNotIn("unlisted_secret", output.getvalue())
        self.assertNotIn("must-not-appear", output.getvalue())

    def test_attribute_paths_and_transforms_are_declarative(self) -> None:
        class Payload:
            def __init__(self) -> None:
                self.values = {"first": 1, "second": 2}

        @monitored(
            "paths",
            variables=(
                argument(
                    "payload",
                    label="value_count",
                    path=("values",),
                    transform=len,
                ),
                returned(label="result_count", transform=len),
            ),
        )
        def inspect_payload(payload: Payload) -> list[int]:
            return list(payload.values.values())

        output = StringIO()
        with monitoring(enabled=True, stream=output):
            inspect_payload(Payload())

        text = output.getvalue()
        self.assertIn("value_count=2", text)
        self.assertIn("result_count=2", text)

    def test_nested_monitors_restore_existing_trace_function(self) -> None:
        @monitored("inner", variables=(local("inner_value"),))
        def inner(value: int) -> int:
            inner_value = value + 1
            return inner_value

        @monitored("outer", variables=(local("outer_value"),))
        def outer(value: int) -> int:
            outer_value = inner(value) + 1
            return outer_value

        def sentinel(frame, event, arg):
            return sentinel

        previous = sys.gettrace()
        output = StringIO()
        sys.settrace(sentinel)
        try:
            with monitoring(enabled=True, stream=output):
                self.assertEqual(outer(1), 3)
            self.assertIs(sys.gettrace(), sentinel)
        finally:
            sys.settrace(previous)

        lines = output.getvalue().splitlines()
        self.assertEqual(len(lines), 4)
        self.assertTrue(all(line.startswith("[DEBUG] ") for line in lines))
        self.assertIn("inner_value=2", output.getvalue())
        self.assertIn("outer_value=3", output.getvalue())

    def test_exception_is_unchanged_and_does_not_emit_finish(self) -> None:
        failure = RuntimeError("original failure")

        @monitored("failure", variables=(argument("value"), local("computed")))
        def explode(value: int) -> None:
            computed = value + 1
            raise failure

        previous = sys.gettrace()
        output = StringIO()
        with monitoring(enabled=True, stream=output):
            with self.assertRaises(RuntimeError) as raised:
                explode(2)

        self.assertIs(raised.exception, failure)
        self.assertIs(sys.gettrace(), previous)
        lines = output.getvalue().splitlines()
        self.assertEqual(len(lines), 1)
        self.assertTrue(lines[0].startswith("[DEBUG] failure.start "))
        self.assertNotIn("failure.finish", output.getvalue())
        self.assertNotIn("Traceback", output.getvalue())
        self.assertNotIn("computed", output.getvalue())

    def test_rendering_is_bounded_single_line_and_redacts_sensitive_values(self) -> None:
        payload = {
            "password": "visible-password",
            "nested": {"api_token": "visible-token"},
            "text": "x" * 600,
            "items": list(range(30)),
            "blob": b"secret bytes",
            "command": ["tool", "--credential", "visible-credential"],
        }

        @monitored("bounded", variables=(argument("payload"),))
        def consume(payload):
            return payload

        output = StringIO()
        with monitoring(enabled=True, stream=output):
            consume(payload)

        lines = output.getvalue().splitlines()
        self.assertEqual(len(lines), 2)
        self.assertTrue(all(line.startswith("[DEBUG] ") for line in lines))
        self.assertTrue(all(len(line) <= 2048 for line in lines))
        self.assertIn("<redacted>", lines[0])
        self.assertIn("<bytes:12>", lines[0])
        self.assertNotIn("visible-password", lines[0])
        self.assertNotIn("visible-token", lines[0])
        self.assertNotIn("visible-credential", lines[0])
        self.assertNotIn("\n", lines[0])

    def test_probe_failure_never_changes_the_monitored_function(self) -> None:
        def broken_transform(_value):
            raise ValueError("monitor transform failed")

        @monitored(
            "resilient",
            variables=(
                argument("value", label="broken", transform=broken_transform),
                returned(label="answer"),
            ),
        )
        def identity(value: int) -> int:
            return value

        output = StringIO()
        with monitoring(enabled=True, stream=output):
            result = identity(7)

        self.assertEqual(result, 7)
        self.assertNotIn("broken=", output.getvalue())
        self.assertIn("answer=7", output.getvalue())

    def test_renderer_and_output_failures_never_change_the_function(self) -> None:
        class BrokenMapping(Mapping):
            def __getitem__(self, key):
                raise RuntimeError("broken mapping")

            def __iter__(self):
                raise RuntimeError("broken mapping")

            def __len__(self):
                return 1

        class BrokenStream:
            def write(self, _text):
                raise OSError("broken stream")

            def flush(self):
                raise OSError("broken stream")

        @monitored("resilient-output", variables=(argument("value"),))
        def identity(value):
            return value

        payload = BrokenMapping()
        with monitoring(enabled=True, stream=StringIO()):
            self.assertIs(identity(payload), payload)
        with monitoring(enabled=True, stream=BrokenStream()):
            self.assertEqual(identity(9), 9)

    def test_default_stream_is_resolved_when_monitoring_starts(self) -> None:
        @monitored("redirected", variables=(returned(),))
        def value() -> int:
            return 3

        output = StringIO()
        with redirect_stdout(output), monitoring(enabled=True):
            value()

        self.assertIn("[DEBUG] redirected.finish", output.getvalue())


if __name__ == "__main__":
    unittest.main()
