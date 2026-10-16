from __future__ import annotations

from pathlib import Path
import tempfile
import tomllib
import unittest

from chimera.preprocess.offline.analysis.toolchain.compiler import GccCompiler
from chimera.preprocess.offline.analysis.toolchain import build_toolchain_services
from chimera.preprocess.offline.config.loader import load_configuration, parse_base_config
from chimera.preprocess.offline.config.model import (
    ChimeraConfiguration,
    ProfileConfig,
    WorkflowConfig,
)
from chimera.preprocess.offline.config.system_profile import _serialize


MARCH = (
    "-march=rv64imafdc_zba_zbb_zbc_zbs_zfa_zfh_zicond_zicsr_"
    "zifencei_zihintpause_zihpm_zkt_zvbb_zvbc_zve32f_zve32x_"
    "zve64d_zve64f_zve64x_zvfh_zvfhmin_zvkb_zvkg_zvkned_"
    "zvknha_zvknhb_zvksed_zvksh_zvkt_zicbop_zihintntl"
)


class CompilerFlagsTests(unittest.TestCase):
    def _configuration(self, source: Path) -> ChimeraConfiguration:
        base = parse_base_config(
            {
                "tools": {
                    "cc": "gcc",
                    "cc_flags": [MARCH, "-mabi=lp64d"],
                }
            },
            source=source,
        )
        profile = ProfileConfig(
            name="test",
            target_os="linux",
            target_arch="riscv64",
            target_arch_extension="rvv",
            runtime_scene="linux_riscv64_rvv_v1",
            runtime_abi=1,
            workflow=WorkflowConfig(()),
            source=source,
        )
        return ChimeraConfiguration(base=base, profile=profile, source=source)

    def test_base_config_preserves_compiler_flags_as_argv_tokens(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "profile.toml"
            configuration = self._configuration(source)

        self.assertEqual(configuration.base.tools.cc_flags, (MARCH, "-mabi=lp64d"))

    def test_compiler_appends_configured_flags_before_sources(self) -> None:
        compiler = GccCompiler("gcc", extra_flags=(MARCH, "-mabi=lp64d"))

        command = compiler.compile([Path("translated.S")], Path("translated.so"))

        self.assertEqual(
            command,
            [
                "gcc",
                "-fPIC",
                "-shared",
                MARCH,
                "-mabi=lp64d",
                "translated.S",
                "-o",
                "translated.so",
            ],
        )

    def test_compiler_accepts_target_linker_flags(self) -> None:
        compiler = GccCompiler(
            "gcc",
            extra_flags=(MARCH, "-mabi=lp64d"),
            linker_flags=("-Wl,--relax",),
        )

        command = compiler.compile([Path("translated.S")], Path("translated.so"))

        self.assertEqual(command[3:6], ["-Wl,--relax", MARCH, "-mabi=lp64d"])

    def test_toolchain_services_pass_configured_flags_to_compiler(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "profile.toml"
            configuration = self._configuration(source)
            services = build_toolchain_services(configuration.base)

        command = services.compiler.compile([Path("metadata.S")], Path("metadata.so"))
        self.assertEqual(command[3:5], [MARCH, "-mabi=lp64d"])
        self.assertNotIn("-Wl,--relax", command)

    def test_system_profile_serialization_preserves_compiler_flags(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "profile.toml"
            configuration = self._configuration(source)
            serialized = _serialize(configuration)
            installed = Path(temporary) / "installed.toml"
            installed.write_text(serialized, encoding="utf-8")
            reloaded = load_configuration(installed)

        document = tomllib.loads(serialized)
        self.assertEqual(document["config"]["tools"]["cc_flags"], [MARCH, "-mabi=lp64d"])
        self.assertEqual(reloaded.base.tools.cc_flags, (MARCH, "-mabi=lp64d"))
        self.assertNotIn("translator_command", document["config"]["tools"])

    def test_compiler_flags_require_non_empty_string_array_items(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "profile.toml"
            for invalid in ("-march=rv64gc", [""], [1]):
                with self.subTest(invalid=invalid):
                    with self.assertRaises((TypeError, ValueError)):
                        parse_base_config(
                            {"tools": {"cc_flags": invalid}},
                            source=source,
                        )

    def test_translator_command_is_rejected_with_migration_message(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "profile.toml"
            for invalid in ("python translator.py", [], [""], [1]):
                with self.subTest(invalid=invalid):
                    with self.assertRaisesRegex(ValueError, "config.translators"):
                        parse_base_config(
                            {"tools": {"translator_command": invalid}},
                            source=source,
                        )


if __name__ == "__main__":
    unittest.main()
