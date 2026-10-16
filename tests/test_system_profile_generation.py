from __future__ import annotations

import contextlib
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from chimera.preprocess.offline.config import load_configuration
from chimera.preprocess.offline.config import system_profile as sp


def _which_all_found(name: str) -> str:
    return f"/usr/bin/{name}"


def _which_none(_name: str) -> None:
    return None


def _which_cross_environment(name: str) -> str | None:
    """Bare gcc/objdump/nm absent, prefixed toolchain and host tools present."""
    if name.startswith("riscv64-linux-gnu-") or name == "cmake":
        return f"/usr/bin/{name}"
    return None


class HostDetectionTests(unittest.TestCase):
    def test_unsupported_host_aborts_before_tool_detection(self) -> None:
        which = mock.Mock(return_value="/usr/bin/gcc")
        with (
            mock.patch.object(sp.platform, "system", return_value="Windows"),
            mock.patch.object(sp.platform, "machine", return_value="AMD64"),
            mock.patch.object(sp.shutil, "which", which),
        ):
            with self.assertRaisesRegex(
                ValueError, r"linux/riscv64.*windows/amd64"
            ):
                sp.generate_profile_document()
        which.assert_not_called()


class ToolDetectionTests(unittest.TestCase):
    def _generate(self, which) -> tuple[str, list[str]]:
        with contextlib.ExitStack() as stack:
            stack.enter_context(
                mock.patch.object(sp.platform, "system", return_value="Linux")
            )
            stack.enter_context(
                mock.patch.object(sp.platform, "machine", return_value="riscv64")
            )
            stack.enter_context(
                mock.patch.object(sp.shutil, "which", side_effect=which)
            )
            stack.enter_context(
                mock.patch.object(sp, "_bundled_translator_directory")
            )
            return sp.generate_profile_document()

    def test_bare_tools_preferred_with_native_cc_flags(self) -> None:
        document, warnings = self._generate(_which_all_found)
        self.assertEqual(warnings, [])
        self.assertIn('cc = "gcc"', document)
        self.assertIn('objdump = "objdump"', document)
        self.assertIn('nm = "nm"', document)
        self.assertIn("-march=rv64", document)
        self.assertIn('"-mabi=lp64d"', document)

    def test_prefixed_fallback_clears_cc_flags(self) -> None:
        document, warnings = self._generate(_which_cross_environment)
        self.assertEqual(warnings, [])
        self.assertIn('cc = "riscv64-linux-gnu-gcc"', document)
        self.assertIn('objdump = "riscv64-linux-gnu-objdump"', document)
        self.assertIn("cc_flags = []", document)

    def test_missing_tools_degrade_with_warnings(self) -> None:
        document, warnings = self._generate(_which_none)
        self.assertEqual(len(warnings), 4)
        self.assertIn('cc = "gcc"', document)
        self.assertIn("-march=rv64", document)


class GeneratedDocumentTests(unittest.TestCase):
    def test_document_round_trips_through_loader(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary) / "home"
            home.mkdir()
            translators = home / "translators"
            translators.mkdir()
            for script in ("rvv_sbt_rvv.py", "rvv_sbt_rvv1024.py"):
                (translators / script).write_text("# stub\n", encoding="utf-8")
            with contextlib.ExitStack() as stack:
                stack.enter_context(
                    mock.patch.object(sp.platform, "system", return_value="Linux")
                )
                stack.enter_context(
                    mock.patch.object(sp.platform, "machine", return_value="riscv64")
                )
                stack.enter_context(
                    mock.patch.object(sp.shutil, "which", side_effect=_which_all_found)
                )
                stack.enter_context(
                    mock.patch("pathlib.Path.home", return_value=home)
                )
                stack.enter_context(
                    mock.patch.object(
                        sp, "_bundled_translator_directory", return_value=translators
                    )
                )
                document, warnings = sp.generate_profile_document()
            self.assertEqual(warnings, [])
            profile_path = Path(temporary) / "generated.toml"
            profile_path.write_text(document, encoding="utf-8")
            configuration = load_configuration(profile_path)
        self.assertEqual(
            configuration.profile.name,
            "linux-riscv64-rvv-1024-256-bidirectional",
        )
        self.assertEqual(len(configuration.base.translators), 2)
        routes = {
            (binding.source.canonical, binding.target.canonical)
            for binding in configuration.base.translators
        }
        self.assertEqual(
            routes,
            {
                ("riscv64;rvv;vlen=1024", "riscv64;rvv;vlen=256"),
                ("riscv64;rvv;vlen=256", "riscv64;rvv;vlen=1024"),
            },
        )
        self.assertEqual(
            [step.step for step in configuration.profile.workflow.steps],
            [
                "prepare-workspace", "build-runtime", "disassemble",
                "build-program-model", "safety", "translate", "translate",
                "offset-map", "patch-safepoints", "finalize-workspace",
            ],
        )
        self.assertEqual(
            configuration.base.workspace_root, (home / ".chimera" / "workspaces").resolve()
        )
        self.assertEqual(configuration.base.tools.cc, "gcc")


class InstallAutoProfileTests(unittest.TestCase):
    def _install(self, *, force: bool, existing: bool):
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary) / "home"
            home.mkdir()
            translators = home / "translators"
            translators.mkdir()
            for script in ("rvv_sbt_rvv.py", "rvv_sbt_rvv1024.py"):
                (translators / script).write_text("# stub\n", encoding="utf-8")
            destination = Path(temporary) / "profile" / "system-profile.toml"
            destination.parent.mkdir()
            if existing:
                destination.write_text("# user-edited\n", encoding="utf-8")
            with contextlib.ExitStack() as stack:
                stack.enter_context(
                    mock.patch.object(sp.platform, "system", return_value="Linux")
                )
                stack.enter_context(
                    mock.patch.object(sp.platform, "machine", return_value="riscv64")
                )
                stack.enter_context(
                    mock.patch.object(sp.shutil, "which", side_effect=_which_all_found)
                )
                stack.enter_context(
                    mock.patch("pathlib.Path.home", return_value=home)
                )
                stack.enter_context(
                    mock.patch.object(
                        sp, "_bundled_translator_directory", return_value=translators
                    )
                )
                stack.enter_context(
                    mock.patch.object(
                        sp, "system_profile_path", return_value=destination
                    )
                )
                installed = sp.install_auto_profile(force=force)
            if existing and not force:
                self.assertIsNone(installed)
                self.assertEqual(
                    destination.read_text(encoding="utf-8"), "# user-edited\n"
                )
            else:
                self.assertEqual(installed, destination)
                configuration = load_configuration(destination)
                self.assertEqual(len(configuration.base.translators), 2)

    def test_existing_profile_is_kept_without_force(self) -> None:
        self._install(force=False, existing=True)

    def test_force_regenerates_existing_profile(self) -> None:
        self._install(force=True, existing=True)

    def test_missing_profile_is_created(self) -> None:
        self._install(force=False, existing=False)


if __name__ == "__main__":
    unittest.main()
