from __future__ import annotations

from pathlib import Path
from types import MappingProxyType
import tempfile
import tomllib
import unittest
from unittest.mock import patch

from chimera.preprocess.offline.analysis.core.workspace import WorkspaceRepository
from chimera.preprocess.offline.analysis_profile import build_execution_plan
from chimera.preprocess.offline.config.loader import parse_base_config
from chimera.preprocess.offline.config.model import (
    BaseConfig,
    ChimeraConfiguration,
    ProfileConfig,
    ToolConfig,
    TranslationEndpoint,
    TranslatorBinding,
    WorkflowConfig,
    WorkflowStepConfig,
)
from chimera.preprocess.offline.config.system_profile import _serialize


ROUTE_CASES = (
    (1024, 256, True),
    (256, 1024, True),
    (1024, 512, False),
    (512, 256, False),
    (256, 256, False),
    (1024, 1024, False),
)


def _step(name: str, parameters: dict[str, object] | None = None) -> WorkflowStepConfig:
    return WorkflowStepConfig(name, MappingProxyType(parameters or {}))


class TranslatorRoutingConfigTests(unittest.TestCase):
    def test_parses_ordered_request_to_translator_bindings(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "profile.toml"
            first = root / "rvv_sbt_rvv.py"
            second = root / "rvv_sbt_rvv1024.py"
            first.write_text("# external translator\n", encoding="utf-8")
            second.write_text("# external translator\n", encoding="utf-8")

            config = parse_base_config(
                {
                    "translators": [
                        {
                            "source": "riscv64;rvv;vlen=1024",
                            "target": "riscv64;rvv;vlen=256",
                            "translator_path": first.name,
                        },
                        {
                            "source": "riscv64;rvv;vlen=256",
                            "target": "riscv64;rvv;vlen=1024",
                            "translator_path": second.name,
                        },
                    ]
                },
                source=source,
            )

        self.assertEqual(
            [binding.source.canonical for binding in config.translators],
            ["riscv64;rvv;vlen=1024", "riscv64;rvv;vlen=256"],
        )
        self.assertEqual(
            [binding.translator_path for binding in config.translators],
            [first.resolve(), second.resolve()],
        )

    def test_rejects_missing_file_duplicate_route_and_legacy_fields(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "profile.toml"
            translator = root / "translator.py"
            translator.write_text("# external\n", encoding="utf-8")
            route = {
                "source": "riscv64;rvv;vlen=1024",
                "target": "riscv64;rvv;vlen=256",
                "translator_path": translator.name,
            }
            with self.assertRaisesRegex(FileNotFoundError, "existing file"):
                parse_base_config(
                    {"translators": [{**route, "translator_path": "missing.py"}]},
                    source=source,
                )
            with self.assertRaisesRegex(ValueError, "duplicate translator route"):
                parse_base_config(
                    {"translators": [route, route]}, source=source
                )
            with self.assertRaisesRegex(ValueError, "endpoints must be distinct"):
                parse_base_config(
                    {"translators": [{**route, "target": route["source"]}]},
                    source=source,
                )
            with self.assertRaisesRegex(ValueError, r"\[\[config.translators\]\]"):
                parse_base_config({"translator": translator.name}, source=source)
            with self.assertRaisesRegex(ValueError, "config.translators"):
                parse_base_config(
                    {"tools": {"translator_command": ["{python}"]}},
                    source=source,
                )

    def test_system_profile_serializes_bindings_in_order_with_absolute_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "profile.toml"
            translator = root / "shared.py"
            translator.write_text("# external\n", encoding="utf-8")
            base = parse_base_config(
                {"translators": [
                    {
                        "source": "riscv64;rvv;vlen=1024",
                        "target": "riscv64;rvv;vlen=256",
                        "translator_path": translator.name,
                    },
                    {
                        "source": "riscv64;rvv;vlen=256",
                        "target": "riscv64;rvv;vlen=1024",
                        "translator_path": translator.name,
                    },
                ]},
                source=source,
            )
            profile = ProfileConfig(
                name="test", target_os="linux", target_arch="riscv64",
                target_arch_extension="rvv",
                runtime_scene="linux_riscv64_rvv_v1", runtime_abi=1,
                workflow=WorkflowConfig(()), source=source,
            )
            serialized = _serialize(ChimeraConfiguration(base, profile, source))

        bindings = tomllib.loads(serialized)["config"]["translators"]
        self.assertEqual(
            [item["source"] for item in bindings],
            ["riscv64;rvv;vlen=1024", "riscv64;rvv;vlen=256"],
        )
        self.assertEqual(
            [item["translator_path"] for item in bindings],
            [str(translator.resolve()), str(translator.resolve())],
        )

    def test_endpoint_syntax_requires_three_nonempty_whitespace_free_fields(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source_path = root / "profile.toml"
            translator = root / "translator.py"
            translator.write_text("# external\n", encoding="utf-8")
            for endpoint in (
                "riscv64;rvv", "riscv64;rvv;", ";rvv;vlen=1",
                "riscv64;rvv;vlen=1;extra", "riscv64; rvv;vlen=1",
            ):
                with self.subTest(endpoint=endpoint):
                    with self.assertRaises((TypeError, ValueError)):
                        parse_base_config({"translators": [{
                            "source": endpoint,
                            "target": "riscv64;rvv;vlen=2",
                            "translator_path": translator.name,
                        }]}, source=source_path)

    def test_planner_accepts_only_supported_rvv_routes_before_staging(self) -> None:
        for source_vlen, target_vlen, supported in ROUTE_CASES:
            with self.subTest(source=source_vlen, target=target_vlen):
                with tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    source = TranslationEndpoint.parse(
                        f"riscv64;rvv;vlen={source_vlen}", field="source"
                    )
                    target = TranslationEndpoint.parse(
                        f"riscv64;rvv;vlen={target_vlen}", field="target"
                    )
                    translator = root / "translator.py"
                    translator.write_text("# external\n", encoding="utf-8")
                    profile_source = root / "profile.toml"
                    configuration = ChimeraConfiguration(
                        BaseConfig(
                            data_root=root / "data",
                            workspace_root=root / "workspaces",
                            scalar_root=root / "scalar",
                            tools=ToolConfig(cc="gcc"),
                            translators=(TranslatorBinding(
                                source, target, translator,
                            ),),
                        ),
                        ProfileConfig(
                            name="route-matrix",
                            target_os="linux",
                            target_arch="riscv64",
                            target_arch_extension="rvv",
                            runtime_scene="linux_riscv64_rvv_v1",
                            runtime_abi=1,
                            workflow=WorkflowConfig((
                                _step("prepare-workspace"),
                                _step("build-runtime"),
                                _step("disassemble"),
                                _step("translate", {
                                    "source": source.canonical,
                                    "target": target.canonical,
                                }),
                                _step("offset-map"),
                                _step("finalize-workspace"),
                            )),
                            source=profile_source,
                        ),
                        profile_source,
                    )
                    with patch.object(
                        WorkspaceRepository, "start", autospec=True
                    ) as start:
                        if supported:
                            build_execution_plan(configuration)
                        else:
                            with self.assertRaisesRegex(
                                ValueError, "unsupported RVV translation route"
                            ):
                                build_execution_plan(configuration)
                        start.assert_not_called()


if __name__ == "__main__":
    unittest.main()
