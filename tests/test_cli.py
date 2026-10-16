from __future__ import annotations

import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
import tomllib

from chimera import __version__
from chimera.cli import _select_migration_tids, build_parser


class CliTests(unittest.TestCase):
    def test_release_package_version_is_1_0_0(self) -> None:
        project = Path(__file__).resolve().parents[1] / "pyproject.toml"
        with project.open("rb") as source:
            self.assertEqual(tomllib.load(source)["project"]["version"], "1.0.0")

    def test_prepare_rejects_translator_override(self) -> None:
        parser = build_parser()
        with self.assertRaises(SystemExit) as raised:
            parser.parse_args(
                ["prepare", "--input", "app", "--translator", "translator.py"]
            )
        self.assertEqual(raised.exception.code, 2)

    def test_prepare_allow_problematic_flag_parses(self) -> None:
        parser = build_parser()
        namespace = parser.parse_args(
            ["prepare", "--profile", "profile.toml", "--input", "app", "--allow-problematic"]
        )
        self.assertTrue(namespace.allow_problematic)
        namespace = parser.parse_args(["prepare", "--profile", "profile.toml", "--input", "app"])
        self.assertFalse(namespace.allow_problematic)

    def test_global_version_prints_package_version(self) -> None:
        parser = build_parser()
        output = StringIO()
        with redirect_stdout(output), self.assertRaises(SystemExit) as raised:
            parser.parse_args(["--version"])
        self.assertEqual(raised.exception.code, 0)
        self.assertEqual(output.getvalue().strip(), f"chimera {__version__}")

    def test_lifecycle_commands_are_exposed(self) -> None:
        self.assertEqual(
            set(build_parser("pkg")._subparsers._group_actions[0].choices),
            {"check-elf", "prepare", "llvm", "workspace", "status", "build-bundle"},
        )
        self.assertEqual(
            set(build_parser("user")._subparsers._group_actions[0].choices),
            {"list", "verify", "register", "run", "migrate"},
        )

    def test_migration_explicit_threads_are_parsed(self) -> None:
        parser = build_parser()
        namespace = parser.parse_args(
            ["migrate", "--workspace", "demo", "--direction", "ROUTE", "--threads", "2", "3"]
        )
        self.assertEqual(namespace.threads, [2, 3])

    def test_migration_selection_excludes_main_thread_when_possible(self) -> None:
        available = [10, 11, 12, 13]  # 10 is the thread-group leader
        # 从尾部（最新创建）往前选：主线程排除，取最新的 count 个
        selected = _select_migration_tids(available, 10, 2)
        self.assertEqual(selected, [12, 13])

    def test_migration_selection_skips_early_sleeper_threads(self) -> None:
        # 低 tid 是运行时早期诞生的辅助线程，常驻睡眠态；翻译态不允许
        # 二次迁移，因此迁移选择必须跳过它们、只落最新的 worker 波。
        available = [10, 11, 12, 13, 14, 15]  # 11 是早期辅助线程
        self.assertEqual(_select_migration_tids(available, 10, 2), [14, 15])
        self.assertEqual(_select_migration_tids(available, 10, 3), [13, 14, 15])
        self.assertNotIn(11, _select_migration_tids(available, 10, 4))

    def test_migration_selection_includes_main_thread_only_when_forced(self) -> None:
        available = [10, 11, 12]
        # count == non-main count: main still excluded
        self.assertNotIn(10, _select_migration_tids(available, 10, 2))
        # count beyond non-main count: main must be included
        selected = _select_migration_tids(available, 10, 3)
        self.assertEqual(len(selected), 3)
        self.assertIn(10, selected)
        # count beyond the whole group: everything is selected, main included
        selected = _select_migration_tids(available, 10, 99)
        self.assertEqual(sorted(selected), available)

    def test_migration_selection_handles_single_threaded_group(self) -> None:
        self.assertEqual(_select_migration_tids([10], 10, 1), [10])

if __name__ == "__main__":
    unittest.main()
