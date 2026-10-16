from __future__ import annotations

import unittest

from chimera.cli import build_parser


class CommandRoleContractTests(unittest.TestCase):
    def test_dev_exposes_only_developer_commands(self) -> None:
        parser = build_parser("dev", prog="chimera-dev")
        self.assertEqual(
            set(parser._subparsers._group_actions[0].choices),
            {"rebuild", "toolchain", "wheel"},
        )
        parser.parse_args(["toolchain", "build", "patched-llvm"])
        parser.parse_args(["toolchain", "clean", "patched-llvm"])
        parser.parse_args(["wheel"])

    def test_pkg_exposes_packaging_commands(self) -> None:
        parser = build_parser("pkg", prog="chimera-pkg")
        self.assertEqual(
            set(parser._subparsers._group_actions[0].choices),
            {"check-elf", "prepare", "llvm", "workspace", "status", "build-bundle"},
        )
        parser.parse_args(["check-elf", "--profile", "p.toml", "--input", "app"])
        parser.parse_args(["prepare", "--profile", "p.toml", "--input", "app"])
        parser.parse_args(["workspace", "pack", "--workspace", "demo", "--output", "demo.workspace"])
        parser.parse_args(["workspace", "install", "--input", "demo.workspace"])
        parser.parse_args(["workspace", "remove", "--workspace", "demo"])
        parser.parse_args(["workspace", "clean"])
        parser.parse_args(["build-bundle", "pack", "--profile", "p.toml", "--script", "build.sh", "--instructions", "BUILD.md", "--output", "bundle.zip"])
        parser.parse_args(["build-bundle", "unpack", "--input", "bundle.zip", "--output-dir", "received"])

    def test_user_has_no_init_or_example_commands(self) -> None:
        parser = build_parser("user", prog="chimera-user")
        self.assertEqual(
            set(parser._subparsers._group_actions[0].choices),
            {"list", "verify", "register", "run", "migrate"},
        )

    def test_removed_entry_commands_are_rejected(self) -> None:
        parser = build_parser("pkg", prog="chimera-pkg")
        for argv in (["init"], ["example", "list"], ["workspack", "pack"]):
            with self.assertRaises(SystemExit):
                parser.parse_args(argv)

    def test_offline_commands_require_an_explicit_profile(self) -> None:
        parser = build_parser("pkg", prog="chimera-pkg")
        with self.assertRaises(SystemExit):
            parser.parse_args(["prepare", "--input", "app"])
        parser = build_parser("dev", prog="chimera-dev")
        with self.assertRaises(SystemExit):
            parser.parse_args(["rebuild", "--steps", "s"])


if __name__ == "__main__":
    unittest.main()
