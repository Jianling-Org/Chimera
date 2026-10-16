from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from types import MappingProxyType
import tempfile
import unittest

from chimera.preprocess.offline.analysis_profile import build_execution_plan
from chimera.preprocess.offline.config import (
    BaseConfig,
    ChimeraConfiguration,
    ProfileConfig,
    ToolConfig,
    WorkflowConfig,
    WorkflowStepConfig,
    TranslationEndpoint,
    TranslatorBinding,
)


def _step(
    name: str,
    parameters: dict[str, object] | None = None,
) -> WorkflowStepConfig:
    return WorkflowStepConfig(name, MappingProxyType(parameters or {}))


class ExecutionPlanDependencyTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.down_translator = self.root / "rvv_sbt_rvv.py"
        self.up_translator = self.root / "rvv_sbt_rvv1024.py"
        self.down_translator.write_text("# external\n", encoding="utf-8")
        self.up_translator.write_text("# external\n", encoding="utf-8")

    @staticmethod
    def route(source: int, target: int) -> dict[str, str]:
        return {
            "source": f"riscv64;rvv;vlen={source}",
            "target": f"riscv64;rvv;vlen={target}",
        }

    def configuration(self, *steps: WorkflowStepConfig) -> ChimeraConfiguration:
        source = self.root / "profile.toml"
        return ChimeraConfiguration(
            base=BaseConfig(
                data_root=self.root / "data",
                workspace_root=self.root / "workspaces",
                scalar_root=self.root / "scalar",
                tools=ToolConfig(cc="gcc"),
                translators=(
                    TranslatorBinding(
                        TranslationEndpoint.parse(
                            "riscv64;rvv;vlen=1024", field="source"
                        ),
                        TranslationEndpoint.parse(
                            "riscv64;rvv;vlen=256", field="target"
                        ),
                        self.down_translator,
                    ),
                    TranslatorBinding(
                        TranslationEndpoint.parse(
                            "riscv64;rvv;vlen=256", field="source"
                        ),
                        TranslationEndpoint.parse(
                            "riscv64;rvv;vlen=1024", field="target"
                        ),
                        self.up_translator,
                    ),
                ),
            ),
            profile=ProfileConfig(
                name="test",
                target_os="linux",
                target_arch="riscv64",
                target_arch_extension="rvv",
                runtime_scene="linux_riscv64_rvv_v1",
                runtime_abi=1,
                workflow=WorkflowConfig(steps),
                source=source,
            ),
            source=source,
        )

    def test_consumer_must_follow_every_producer(self) -> None:
        configuration = self.configuration(
            _step("prepare-workspace"),
            _step("disassemble"),
            _step("translate", self.route(1024, 256)),
            _step("offset-map"),
            _step("translate", self.route(256, 1024)),
            _step("build-runtime"),
            _step("finalize-workspace"),
        )

        with self.assertRaisesRegex(
            ValueError,
            r"offset-map.*translations.*later producer",
        ):
            build_execution_plan(configuration)

    def test_minimal_profile_omits_program_model_and_safety(self) -> None:
        configuration = self.configuration(
            _step("prepare-workspace"),
            _step("build-runtime"),
            _step("disassemble"),
            _step("translate", self.route(1024, 256)),
            _step("offset-map"),
            _step("finalize-workspace"),
        )

        plan = build_execution_plan(configuration)

        self.assertEqual(
            [step.name for step in plan.steps],
            [
                "prepare-workspace",
                "build-runtime",
                "disassemble",
                "translate",
                "offset-map",
                "finalize-workspace",
            ],
        )

    def test_safety_requires_programs_but_not_translation(self) -> None:
        configuration = self.configuration(
            _step("prepare-workspace"),
            _step("disassemble"),
            _step("safety", {"min_vlen_bits": 256}),
            _step("build-runtime"),
            _step("translate", self.route(1024, 256)),
            _step("offset-map"),
            _step("finalize-workspace"),
        )

        with self.assertRaisesRegex(ValueError, r"safety.*programs.*no producer"):
            build_execution_plan(configuration)

    def test_declaration_order_is_preserved(self) -> None:
        configuration = self.configuration(
            _step("prepare-workspace"),
            _step("disassemble"),
            _step("build-runtime"),
            _step("translate", self.route(1024, 256)),
            _step("offset-map"),
            _step("finalize-workspace"),
        )

        plan = build_execution_plan(configuration)

        self.assertEqual(
            [step.name for step in plan.steps],
            [
                "prepare-workspace",
                "disassemble",
                "build-runtime",
                "translate",
                "offset-map",
                "finalize-workspace",
            ],
        )

    def test_tmp_vtype_is_unknown(self) -> None:
        configuration = self.configuration(_step("tmp-vtype"))

        with self.assertRaisesRegex(ValueError, r"unknown workflow step 'tmp-vtype'"):
            build_execution_plan(configuration)

    def test_context_mutation_pseudo_step_is_unknown(self) -> None:
        configuration = self.configuration(_step(".modify-context-info"))

        with self.assertRaisesRegex(
            ValueError, r"unknown workflow step '\.modify-context-info'"
        ):
            build_execution_plan(configuration)

    def test_two_directions_select_two_exact_translator_scripts(self) -> None:
        configuration = self.configuration(
            _step("prepare-workspace"),
            _step("build-runtime"),
            _step("disassemble"),
            _step("translate", self.route(1024, 256)),
            _step("translate", self.route(256, 1024)),
            _step("offset-map"),
            _step("finalize-workspace"),
        )

        plan = build_execution_plan(configuration)
        translations = [step.implementation for step in plan.steps if step.name == "translate"]

        self.assertEqual(
            [step.translator_path for step in translations],
            [self.down_translator, self.up_translator],
        )

    def test_missing_route_fails_during_plan_construction(self) -> None:
        configuration = self.configuration(
            _step("prepare-workspace"),
            _step("build-runtime"),
            _step("disassemble"),
            _step("translate", self.route(1024, 256)),
            _step("offset-map"),
            _step("finalize-workspace"),
        )
        configuration = replace(
            configuration, base=replace(configuration.base, translators=())
        )

        with self.assertRaisesRegex(ValueError, "no translator binding.*1024.*256"):
            build_execution_plan(configuration)
        self.assertFalse(configuration.base.workspace_root.exists())

    def test_runtime_abi_mismatch_fails_before_staging(self) -> None:
        configuration = self.configuration(
            _step("prepare-workspace"),
            _step("build-runtime"),
            _step("disassemble"),
            _step("translate", self.route(1024, 256)),
            _step("offset-map"),
            _step("finalize-workspace"),
        )
        configuration = replace(
            configuration,
            profile=replace(configuration.profile, runtime_abi=2),
        )

        with self.assertRaisesRegex(ValueError, "runtime ABI.*profile=2.*bundle=1"):
            build_execution_plan(configuration)
        self.assertFalse(configuration.base.workspace_root.exists())

    def test_rejects_legacy_and_noncanonical_rvv_requests(self) -> None:
        legacy = self.configuration(_step("translate", {
            "source_vlen_bits": 1024, "target_vlen_bits": 256,
        }))
        with self.assertRaisesRegex(ValueError, "legacy translate parameter"):
            build_execution_plan(legacy)

        invalid_sources = (
            "RISCV64;rvv;vlen=1024",
            "riscv64;RVV;vlen=1024",
            "riscv64;rvv;vlen=01024",
            "riscv64;rvv;vlen=0",
            "riscv64;rvv;vlen=18446744073709551616",
            "riscv64;rvv;vlen=1024;extra",
            "riscv64;rvv;vlen =1024",
        )
        for source in invalid_sources:
            with self.subTest(source=source):
                configuration = self.configuration(_step("translate", {
                    "source": source,
                    "target": "riscv64;rvv;vlen=256",
                }))
                with self.assertRaises((TypeError, ValueError)):
                    build_execution_plan(configuration)

    def test_rejects_same_endpoint_and_duplicate_source_selector(self) -> None:
        same = self.configuration(_step("translate", {
            "source": "riscv64;rvv;vlen=1024",
            "target": "riscv64;rvv;vlen=1024",
        }))
        with self.assertRaisesRegex(ValueError, "endpoints must be distinct"):
            build_execution_plan(same)

        duplicate = self.configuration(
            _step("translate", self.route(1024, 256)),
            _step("translate", self.route(1024, 512)),
        )
        with self.assertRaisesRegex(ValueError, "source endpoint.*more than once"):
            build_execution_plan(duplicate)


if __name__ == "__main__":
    unittest.main()
