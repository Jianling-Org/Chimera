from __future__ import annotations

import unittest

from chimera.cli import build_parser


class ExampleCliRemovedTests(unittest.TestCase):
    """Examples are delivered as Workspace packages, not CLI subcommands."""

    def test_example_commands_are_absent_from_all_roles(self) -> None:
        for role in ("dev", "pkg", "user"):
            parser = build_parser(role, prog=f"chimera-{role}")
            commands = set(parser._subparsers._group_actions[0].choices)
            self.assertNotIn("example", commands)
            self.assertNotIn("clean-example", commands)

    def test_removed_example_tokens_are_rejected(self) -> None:
        parser = build_parser("pkg", prog="chimera-pkg")
        for argv in (("example", "list"), ("clean-example", "--name", "demo")):
            with self.assertRaises(SystemExit):
                parser.parse_args(list(argv))


if __name__ == "__main__":
    unittest.main()
