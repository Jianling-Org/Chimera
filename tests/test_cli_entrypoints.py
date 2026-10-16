from __future__ import annotations

import unittest

from chimera.cli import build_parser


class CliEntrypointTests(unittest.TestCase):
    def test_pkg_parser_exposes_packaging_commands_only(self) -> None:
        parser = build_parser(command_group="pkg", prog="chimera-pkg")
        commands = set(parser._subparsers._group_actions[0].choices)
        self.assertIn("prepare", commands)
        self.assertIn("workspace", commands)
        self.assertNotIn("register", commands)
        self.assertNotIn("run", commands)

    def test_user_parser_exposes_runtime_commands_only(self) -> None:
        parser = build_parser(command_group="user", prog="chimera-user")
        commands = set(parser._subparsers._group_actions[0].choices)
        self.assertIn("register", commands)
        self.assertIn("run", commands)
        self.assertNotIn("prepare", commands)
        self.assertNotIn("toolchain", commands)

    def test_dev_parser_has_rebuild(self) -> None:
        parser = build_parser(command_group="dev", prog="chimera-dev")
        commands = set(parser._subparsers._group_actions[0].choices)
        self.assertEqual(commands, {"rebuild", "toolchain", "wheel"})
