from __future__ import annotations

from pathlib import Path
from pathlib import PurePosixPath
import tempfile
import tomllib
import unittest

from chimera.preprocess.offline.config import load_configuration, load_toml
from chimera.preprocess.offline.config.loader import parse_base_config, parse_profile_config
from chimera.preprocess.offline.config.system_profile import _serialize, _toml_value
from chimera.preprocess.offline.config.paths import resolve_path


def _profile_table() -> dict[str, object]:
    return {
        "name": "linux-riscv64-rvv",
        "target_os": "linux",
        "target_arch": "riscv64",
        "target_arch_extension": "rvv",
        "runtime_scene": "linux_riscv64_rvv_v1",
        "runtime_abi": 1,
        "workflow": {"steps": []},
    }


class ProfileConfigTests(unittest.TestCase):
    def test_installed_example_resolves_source_layout_translator(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            package = Path(temporary) / "site-packages" / "chimera"
            profile = package / "examples" / "platforms" / "k3" / "profile.toml"
            for name in ("rvv_sbt_rvv.py", "rvv_sbt_rvv1024.py"):
                installed = package / "preprocess" / "translator" / "rvv_sbt_tool" / name
                installed.parent.mkdir(parents=True, exist_ok=True)
                installed.write_text("# translator", encoding="utf-8")
                legacy = package / "preprocessing" / "translator" / "rvv_sbt_tool" / name
                for reference in (str(legacy), f"../../../preprocessing/translator/rvv_sbt_tool/{name}"):
                    with self.subTest(reference=reference):
                        config = parse_base_config({"translators": [{
                            "source": "riscv64;rvv;vlen=1024",
                            "target": "riscv64;rvv;vlen=256",
                            "translator_path": reference,
                        }]}, source=profile)
                        self.assertEqual(config.translators[0].translator_path, installed.resolve())

    def test_existing_source_layout_translator_is_preserved(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            package = Path(temporary) / "chimera"
            legacy = package / "preprocessing/translator/rvv_sbt_tool/rvv_sbt_rvv.py"
            legacy.parent.mkdir(parents=True)
            legacy.write_text("# source", encoding="utf-8")
            config = parse_base_config({"translators": [{
                "source": "riscv64;rvv;vlen=1024", "target": "riscv64;rvv;vlen=256",
                "translator_path": str(legacy),
            }]}, source=package / "profile.toml")
            self.assertEqual(config.translators[0].translator_path, legacy.resolve())

    def test_missing_custom_or_uninstalled_translator_still_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            package = Path(temporary) / "chimera"
            for name in ("custom.py", "rvv_sbt_rvv.py"):
                with self.subTest(name=name):
                    installed = package / "preprocess/translator/rvv_sbt_tool" / name
                    if name == "custom.py":
                        installed.parent.mkdir(parents=True, exist_ok=True)
                        installed.write_text("# custom", encoding="utf-8")
                    missing = package / "preprocessing/translator/rvv_sbt_tool" / name
                    with self.assertRaises(FileNotFoundError):
                        parse_base_config({"translators": [{
                            "source": "riscv64;rvv;vlen=1024",
                            "target": "riscv64;rvv;vlen=256",
                            "translator_path": str(missing),
                        }]}, source=package / "profile.toml")

    def test_profile_rejects_legacy_safety_fields_with_migration_hint(self) -> None:
        table = _profile_table()
        table["min_vlen_bits"] = 256
        table["compiler_metadata"] = []

        with self.assertRaisesRegex(
            ValueError,
            r"min_vlen_bits.*safety.*parameters",
        ):
            parse_profile_config(table, source=Path("profile.toml"))

    def test_profile_rejects_legacy_metadata_abi(self) -> None:
        table = _profile_table()
        table["metadata_abi"] = 2

        with self.assertRaisesRegex(ValueError, "unknown.*metadata_abi"):
            parse_profile_config(table, source=Path("profile.toml"))

    def test_document_requires_both_domain_tables(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "broken.toml"
            path.write_text("[config]\nworkspace_name = 'auto'\n", encoding="utf-8")

            with self.assertRaisesRegex(ValueError, r"missing \[profile\]"):
                load_toml(path)

    def test_profile_rejects_path_keys_from_config_domain(self) -> None:
        table = _profile_table()
        table["workspace_root"] = "workspaces"

        with self.assertRaisesRegex(ValueError, r"unknown \[profile\] key"):
            parse_profile_config(table, source=Path("profile.toml"))

    def test_current_example_profile_references_external_translator(self) -> None:
        source = Path("examples/platforms/k3/linux-riscv64-rvv-1024-to-256.toml")
        document = tomllib.loads(source.read_text(encoding="utf-8"))

        self.assertEqual(document["profile"]["runtime_abi"], 1)
        translator = document["config"]["translators"][0]
        self.assertEqual(translator["source"], "riscv64;rvv;vlen=1024")
        self.assertEqual(translator["target"], "riscv64;rvv;vlen=256")
        self.assertEqual(
            translator["translator_path"],
            "/path/to/chimera-translator/rvv_sbt_rvv.py",
        )
        self.assertTrue(PurePosixPath(translator["translator_path"]).is_absolute())
        self.assertNotIn("preprocessing/translator", translator["translator_path"])
        self.assertEqual(
            [step["step"] for step in document["profile"]["workflow"]["steps"]],
            [
                "prepare-workspace", "build-runtime", "disassemble",
                "build-program-model", "safety", "translate", "offset-map",
                "patch-safepoints", "finalize-workspace",
            ],
        )

    def test_k3_example_profiles_share_user_chimera_roots(self) -> None:
        for source in Path("examples/platforms/k3").glob("*.toml"):
            with self.subTest(profile=source.name):
                config = tomllib.loads(source.read_text(encoding="utf-8"))["config"]
                self.assertEqual(config["data_root"], "~/.chimera/data")
                self.assertEqual(config["workspace_root"], "~/.chimera/workspaces")
                self.assertEqual(config["scalar_root"], "~/.chimera/scalar")

    def test_tilde_paths_expand_before_profile_relative_resolution(self) -> None:
        profile = Path.cwd() / "profile.toml"
        self.assertEqual(
            resolve_path("~/.chimera/data", source=profile, field="config.data_root"),
            Path("~/.chimera/data").expanduser().resolve(),
        )

    def test_toml_value_serializes_lists(self) -> None:
        self.assertEqual(_toml_value([]), "[]")
        self.assertEqual(_toml_value(["a", "b"]), '["a", "b"]')
        self.assertEqual(_toml_value([1, 2]), "[1, 2]")

    def test_serialize_round_trips_list_step_parameters(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            translator = root / "translator.py"
            translator.write_text("# translator stub\n", encoding="utf-8")
            source = root / "profile.toml"
            source.write_text(
                f"""\
[config]
data_root = '{root / 'data'}'
workspace_root = '{root / 'workspaces'}'
scalar_root = '{root / 'scalar'}'

[[config.translators]]
source = "riscv64;rvv;vlen=1024"
target = "riscv64;rvv;vlen=256"
translator_path = '{translator}'

[config.tools]
python = "python3"
cc = "gcc"

[profile]
name = "test"
target_os = "linux"
target_arch = "riscv64"
target_arch_extension = "rvv"
runtime_scene = "linux_riscv64_rvv_v1"
runtime_abi = 1

[[profile.workflow.steps]]
step = "safety"
parameters = {{ min_vlen_bits = 256, compiler_metadata = [] }}
""",
                encoding="utf-8",
            )

            first = load_configuration(source)
            serialized = _serialize(first)
            self.assertIn("compiler_metadata = []", serialized)

            roundtrip = root / "roundtrip.toml"
            roundtrip.write_text(serialized, encoding="utf-8")
            second = load_configuration(roundtrip)
            safety = next(
                step for step in second.profile.workflow.steps if step.step == "safety"
            )
            self.assertEqual(safety.parameters["min_vlen_bits"], 256)
            self.assertEqual(safety.parameters["compiler_metadata"], [])


if __name__ == "__main__":
    unittest.main()
