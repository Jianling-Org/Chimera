from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from types import MappingProxyType, SimpleNamespace
import tempfile
import unittest

from chimera.preprocess.offline.analysis import AnalysisContext
from chimera.preprocess.offline.analysis_profile.pipeline import (
    PreparePipeline,
    StepContractError,
)
from chimera.preprocess.offline.analysis_profile.rebuild import (
    BuildReplayPropertyError as RebuildPropertyError,
    RebuildMissingUpstream,
    RebuildExecutionPlan,
    RebuildPipeline,
)
from chimera.preprocess.offline.analysis_profile.plan import (
    ExecutionPlan,
    PlannedStep,
)
from chimera.preprocess.offline.analysis.core.workspace import WorkspaceSession
from chimera.preprocess.offline.analysis_profile.registry import (
    ParameterSpec,
    StepCatalog,
    StepDefinition,
    rvv_step_definitions,
)
from chimera.runtime.manifest import ArtifactRecord, ModuleRecord


class _NoResultStep:
    name = "missing-result"

    def run(self, context):
        return context


class StepCatalogContractTests(unittest.TestCase):
    def test_safety_policy_defaults_to_conservative_and_accepts_explicit_scope(self) -> None:
        definition = next(
            item for item in rvv_step_definitions() if item.name == "safety"
        )
        self.assertIn("unknown_stack_size_policy", definition.parameters)

        conservative = definition.normalize_parameters(
            {"min_vlen_bits": 256, "compiler_metadata": ()}
        )
        scoped = definition.normalize_parameters(
            {
                "min_vlen_bits": 256,
                "compiler_metadata": (),
                "unknown_stack_size_policy": "assume-scalar-independent",
            }
        )

        self.assertEqual(conservative["unknown_stack_size_policy"], "conservative")
        self.assertEqual(
            scoped["unknown_stack_size_policy"], "assume-scalar-independent"
        )
        with self.assertRaisesRegex(ValueError, "unknown_stack_size_policy"):
            definition.normalize_parameters(
                {
                    "min_vlen_bits": 256,
                    "compiler_metadata": (),
                    "unknown_stack_size_policy": "guess",
                }
            )

    def test_safety_replay_preserves_scope_and_rejects_cross_policy_artifacts(self) -> None:
        import json
        from chimera.preprocess.offline.analysis_profile.errors import RebuildMissingUpstream
        from chimera.preprocess.offline.analysis_profile.replay import replay_safety
        from chimera.preprocess.offline.analysis.safety.stack_liveness.scope import (
            assumption_for_policy,
        )

        with tempfile.TemporaryDirectory() as temporary:
            stage = Path(temporary)
            generated = stage / "generated"
            generated.mkdir()
            document = {
                "format": "chimera-safety-v1",
                "unknown_stack_size_policy": "assume-scalar-independent",
                "assumption": assumption_for_policy("assume-scalar-independent"),
                "conditional": True,
                "scope_exclusion_count": 1,
                "scope_exclusions": [{
                    "source": "vlen_stack_frame",
                    "function_start": 0x1000,
                    "adjustment": 0x1004,
                    "dependency": "unknown",
                    "size_register": "a0",
                    "disposition": "assumption",
                    "assumption": assumption_for_policy("assume-scalar-independent"),
                    "proof": "p0",
                    "gaps": ["external-callee"],
                }],
                "entries": [],
            }
            (generated / "main.safety.json").write_text(
                json.dumps(document), encoding="utf-8"
            )
            main = SimpleNamespace(module_id="main", is_main=True)

            class Context:
                def __init__(self):
                    self.stage = stage
                    self.result = None

                def require_global(self, name):
                    self.assertions = name
                    return [main]

                def put_global(self, name, result):
                    self.result = result
                    return result

            context = Context()
            result = replay_safety(
                {"unknown_stack_size_policy": "assume-scalar-independent"},
                context,
            )
            self.assertTrue(result.safety.conditional)
            self.assertEqual(len(result.safety.scope_exclusions), 1)
            self.assertEqual(
                result.safety.unknown_stack_size_policy,
                "assume-scalar-independent",
            )
            with self.assertRaisesRegex(RebuildMissingUpstream, "does not match"):
                replay_safety(
                    {"unknown_stack_size_policy": "conservative"}, Context()
                )

    def test_rebuild_exception_imports_remain_compatible(self) -> None:
        from chimera.preprocess.offline.analysis_profile.errors import (
            BuildReplayPropertyError,
            RebuildMissingUpstream,
        )
        from chimera.preprocess.offline.analysis_profile.replay import (
            BuildReplayPropertyError as ReplayPropertyError,
            RebuildMissingUpstream as ReplayMissingUpstream,
        )

        self.assertIs(RebuildMissingUpstream, ReplayMissingUpstream)
        self.assertIs(RebuildPropertyError, BuildReplayPropertyError)
        self.assertIs(RebuildPropertyError, ReplayPropertyError)

    def test_catalog_rejects_duplicate_registration(self) -> None:
        definition = StepDefinition(
            name="example",
            parameters={},
            requires=frozenset(),
            provides=frozenset({"example_result"}),
            repeatable=False,
            factory=lambda _p, _c, _r: _NoResultStep(),
        )
        catalog = StepCatalog((definition,))

        with self.assertRaisesRegex(ValueError, "duplicate workflow step.*example"):
            catalog.register(definition)

    def test_parameter_defaults_are_normalized_by_definition(self) -> None:
        definition = StepDefinition(
            name="example",
            parameters={
                "limit": ParameterSpec(int),
                "labels": ParameterSpec(
                    list,
                    default=[],
                    normalize=lambda value: tuple(value),
                ),
            },
            requires=frozenset(),
            provides=frozenset(),
            repeatable=False,
            factory=lambda _p, _c, _r: _NoResultStep(),
        )

        normalized = definition.normalize_parameters({"limit": 4})

        self.assertEqual(normalized, {"limit": 4, "labels": ()})

    def test_executor_rejects_an_unfulfilled_provide(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "input"
            source.write_bytes(b"input")
            definition = StepDefinition(
                name="missing-result",
                parameters={},
                requires=frozenset(),
                provides=frozenset({"expected_result"}),
                repeatable=False,
                factory=lambda _p, _c, _r: _NoResultStep(),
            )
            profile = SimpleNamespace(
                target_os="linux",
                target_arch="riscv64",
                target_arch_extension="rvv",
                runtime_scene="linux_riscv64_rvv_v1",
                runtime_abi=1,
            )
            plan = ExecutionPlan(
                SimpleNamespace(base=SimpleNamespace(), profile=profile),
                SimpleNamespace(),
                (
                    PlannedStep(
                        "001:missing-result",
                        "missing-result",
                        _NoResultStep(),
                        MappingProxyType({}),
                        definition,
                    ),
                ),
            )

            with self.assertRaisesRegex(
                StepContractError,
                "001:missing-result.*expected_result",
            ):
                PreparePipeline(plan).prepare(source)

    def test_executor_aborts_new_session_when_post_step_registration_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "input"
            source.write_bytes(b"input")
            stage = root / ".ready.staging-test"
            stage.mkdir()
            destination = root / "ready"

            class CreateSession:
                def run(self, context):
                    session = WorkspaceSession(
                        root=root, stage=stage, destination=destination
                    )
                    session.register_validator("duplicate", lambda _manifest: None)
                    return context.with_stage(stage).put_global(
                        "workspace_session", session
                    )

            definition = StepDefinition(
                name="create-session",
                parameters={},
                requires=frozenset(),
                provides=frozenset({"workspace_session"}),
                repeatable=False,
                factory=lambda _p, _c, _r: CreateSession(),
                publication_validators=(("duplicate", lambda _manifest: None),),
            )
            profile = SimpleNamespace(
                target_os="linux",
                target_arch="riscv64",
                target_arch_extension="rvv",
                runtime_scene="linux_riscv64_rvv_v1",
                runtime_abi=1,
            )
            plan = ExecutionPlan(
                SimpleNamespace(base=SimpleNamespace(), profile=profile),
                SimpleNamespace(),
                (
                    PlannedStep(
                        "001:create-session",
                        "create-session",
                        CreateSession(),
                        MappingProxyType({}),
                        definition,
                    ),
                ),
                SimpleNamespace(publication_validators=()),
            )

            with self.assertRaisesRegex(ValueError, "duplicate publication validator"):
                PreparePipeline(plan).prepare(source)

            self.assertFalse(stage.exists())

    def test_safety_publication_does_not_require_dependency_analysis(self) -> None:
        definition = next(
            item for item in rvv_step_definitions() if item.name == "safety"
        )
        validator = definition.publication_validators[0][1]
        artifacts = (
            ArtifactRecord(
                "safety-main-elf", "module", "main", "safety",
                "elf", 1, frozenset(), "artifacts/safety.elf",
                "0" * 64,
            ),
        )
        manifest = SimpleNamespace(
            modules=(
                ModuleRecord("main", "main", "app", "original", "target", "0" * 64),
                ModuleRecord("dep", "dependency", "libdep.so", "original", "target", "0" * 64),
            ),
            artifacts=artifacts,
        )

        validator(manifest)

    def test_patch_safepoints_is_registered_after_offset_map(self) -> None:
        definitions = {item.name: item for item in rvv_step_definitions()}

        patch = definitions["patch-safepoints"]

        self.assertIn("safety_analysis", patch.requires)
        self.assertIn("offset_maps", patch.requires)
        self.assertIn("translations", patch.requires)
        self.assertIn("patched_safepoints", patch.provides)
        self.assertTrue(patch.rebuild_execute)

    def test_rebuild_uses_declared_replay_callback(self) -> None:
        calls = []
        definition = StepDefinition(
            name="custom",
            parameters={},
            requires=frozenset(),
            provides=frozenset(),
            repeatable=False,
            factory=lambda _p, _c, _r: _NoResultStep(),
            replay=lambda parameters, context: calls.append((parameters, context)) or context,
        )
        planned = PlannedStep(
            "001:custom", "custom", _NoResultStep(), MappingProxyType({}), definition
        )
        pipeline = RebuildPipeline.__new__(RebuildPipeline)
        context = AnalysisContext(
            input_elf=Path("input"),
            stage=None,
            config=SimpleNamespace(),
            target_os="test-os",
            target_arch="test-arch",
            target_arch_extension="test-ext",
            runtime_scene="test-scene",
            runtime_abi=1,
            services=SimpleNamespace(),
        )

        pipeline._record_contribution = lambda value, _planned: value
        self.assertIs(pipeline._replay_step(planned, context), context)
        self.assertEqual(calls, [({}, context)])

    def test_rebuild_rejects_custom_step_without_replay(self) -> None:
        definition = StepDefinition(
            name="custom",
            parameters={},
            requires=frozenset(),
            provides=frozenset(),
            repeatable=False,
            factory=lambda _p, _c, _r: _NoResultStep(),
        )
        planned = PlannedStep(
            "001:custom", "custom", _NoResultStep(), MappingProxyType({}), definition
        )
        pipeline = RebuildPipeline.__new__(RebuildPipeline)
        with self.assertRaisesRegex(RebuildMissingUpstream, "no replay callback"):
            pipeline._replay_step(planned, SimpleNamespace(global_results={}))

    def test_rebuild_preflight_can_add_custom_step_identifier(self) -> None:
        stage = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(stage))
        producer_definition = StepDefinition(
            name="custom-producer",
            parameters={},
            requires=frozenset(),
            provides=frozenset({"custom_output"}),
            repeatable=False,
            factory=lambda _p, _c, _r: _NoResultStep(),
            replay=lambda _p, context: context.put_global("custom_output", True),
        )
        finalizer_definition = StepDefinition(
            name="finalize-workspace",
            parameters={},
            requires=frozenset({"custom_output"}),
            provides=frozenset({"published_workspace"}),
            repeatable=False,
            factory=lambda _p, _c, _r: _NoResultStep(),
            rebuild_execute=True,
        )
        hook_definition = StepDefinition(
            name="custom-check",
            parameters={},
            requires=frozenset(),
            provides=frozenset(),
            repeatable=False,
            factory=lambda _p, _c, _r: _NoResultStep(),
            rebuild_preflight=lambda _p, inspection: frozenset(
                {"001:custom-producer"}
            ),
        )
        plan = ExecutionPlan(
            SimpleNamespace(base=SimpleNamespace(), profile=SimpleNamespace()),
            SimpleNamespace(),
            (
                PlannedStep("001:custom-producer", "custom-producer", _NoResultStep(), {}, producer_definition),
                PlannedStep("002:custom-check", "custom-check", _NoResultStep(), {}, hook_definition),
                PlannedStep("003:finalize-workspace", "finalize-workspace", _NoResultStep(), {}, finalizer_definition),
            ),
            SimpleNamespace(),
        )
        pipeline = RebuildPipeline(plan)
        session = WorkspaceSession(
            root=stage, stage=stage / "staging", destination=stage / "ready"
        )
        session.stage.mkdir()

        execution = pipeline.rebuild_execution_list(set(), session=session)

        self.assertEqual(
            execution,
            ("001:custom-producer", "003:finalize-workspace"),
        )

    def _preflight_validation_pipeline(self, result):
        stage_root = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(stage_root))
        prepare = StepDefinition(
            name="prepare-workspace", parameters={}, requires=frozenset(),
            provides=frozenset(), repeatable=False,
            factory=lambda _p, _c, _r: _NoResultStep(),
        )
        hook = StepDefinition(
            name="custom-check", parameters={}, requires=frozenset(),
            provides=frozenset(), repeatable=False,
            factory=lambda _p, _c, _r: _NoResultStep(),
            rebuild_preflight=lambda _p, _inspection: result,
        )
        plan = ExecutionPlan(
            SimpleNamespace(base=SimpleNamespace(), profile=SimpleNamespace()),
            SimpleNamespace(),
            (
                PlannedStep("001:prepare-workspace", "prepare-workspace", _NoResultStep(), {}, prepare),
                PlannedStep("002:custom-check", "custom-check", _NoResultStep(), {}, hook),
            ),
            SimpleNamespace(),
        )
        pipeline = RebuildPipeline(plan)
        session = WorkspaceSession(
            root=stage_root, stage=stage_root / "staging", destination=stage_root / "ready"
        )
        session.stage.mkdir()
        return pipeline, session

    def test_rebuild_preflight_requires_frozenset_of_exact_identifiers(self) -> None:
        cases = (
            (None, TypeError),
            (["002:custom-check"], TypeError),
            (frozenset({"custom-check"}), ValueError),
            (frozenset({"999:missing"}), ValueError),
            (frozenset({"001:prepare-workspace"}), ValueError),
            (frozenset({None}), TypeError),
        )
        for result, error_type in cases:
            with self.subTest(result=result):
                pipeline, session = self._preflight_validation_pipeline(result)
                with self.assertRaises(error_type):
                    pipeline.rebuild_execution_list(set(), session=session)
                self.assertFalse(session.stage.exists())

    def test_rebuild_execution_plan_is_immutable_and_bound_to_session(self) -> None:
        stage_root = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(stage_root))
        definition = StepDefinition(
            name="custom", parameters={}, requires=frozenset(), provides=frozenset(),
            repeatable=False, factory=lambda _p, _c, _r: _NoResultStep(),
            rebuild_execute=True,
        )
        plan = ExecutionPlan(
            SimpleNamespace(base=SimpleNamespace(), profile=SimpleNamespace()),
            SimpleNamespace(),
            (PlannedStep("001:custom", "custom", _NoResultStep(), {}, definition),),
            SimpleNamespace(),
        )
        pipeline = RebuildPipeline(plan)
        session = WorkspaceSession(
            root=stage_root, stage=stage_root / "staging", destination=stage_root / "ready"
        )
        session.stage.mkdir()
        token = pipeline.make_rebuild_plan({"custom"}, session=session)
        self.assertIsInstance(token, RebuildExecutionPlan)
        self.assertEqual(token.execution, ("001:custom",))
        with self.assertRaises(AttributeError):
            token.execution = ()
        session2 = WorkspaceSession(
            root=stage_root, stage=stage_root / "staging2", destination=stage_root / "ready2"
        )
        session2.stage.mkdir()
        with self.assertRaises(ValueError):
            pipeline._validate_execution_plan(token, {"custom"}, session2)
        with self.assertRaises(ValueError):
            pipeline._validate_execution_plan(replace(token), {"custom"}, session)
        with self.assertRaises(ValueError):
            pipeline._validate_execution_plan(token, set(), session)
        pipeline._validate_execution_plan(token, {"custom"}, session)
        with self.assertRaises(ValueError):
            pipeline._validate_execution_plan(token, {"custom"}, session)

        tampered = pipeline.make_rebuild_plan({"custom"}, session=session)
        object.__setattr__(tampered, "execution", ())
        with self.assertRaises(ValueError):
            pipeline._validate_execution_plan(tampered, {"custom"}, session)
        session.abort()
        session2.abort()

    def test_rebuild_plan_preflight_is_not_repeated_during_validation(self) -> None:
        stage_root = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(stage_root))
        calls = []

        def preflight(_parameters, _inspection):
            calls.append(True)
            return frozenset()

        definition = StepDefinition(
            name="custom", parameters={}, requires=frozenset(), provides=frozenset(),
            repeatable=False, factory=lambda _p, _c, _r: _NoResultStep(),
            rebuild_execute=True, rebuild_preflight=preflight,
        )
        plan = ExecutionPlan(
            SimpleNamespace(base=SimpleNamespace(), profile=SimpleNamespace()),
            SimpleNamespace(),
            (PlannedStep("001:custom", "custom", _NoResultStep(), {}, definition),),
            SimpleNamespace(),
        )
        pipeline = RebuildPipeline(plan)
        session = WorkspaceSession(
            root=stage_root, stage=stage_root / "staging", destination=stage_root / "ready"
        )
        session.stage.mkdir()
        token = pipeline.make_rebuild_plan({"custom"}, session=session)
        pipeline._validate_execution_plan(token, {"custom"}, session)
        self.assertEqual(calls, [True])
        session.abort()

    def test_rebuild_execution_list_invalid_request_cleans_staging(self) -> None:
        pipeline, session = self._preflight_validation_pipeline(frozenset())
        with self.assertRaises(TypeError):
            pipeline.rebuild_execution_list(None, session=session)
        self.assertFalse(session.stage.exists())
        self.assertTrue(session._finished)

    def test_rebuild_rejects_finished_session_before_running_steps(self) -> None:
        stage_root = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(stage_root))
        calls = []

        def preflight(_parameters, _inspection):
            calls.append("preflight")
            return frozenset()

        definition = StepDefinition(
            name="custom", parameters={}, requires=frozenset(),
            provides=frozenset(), repeatable=False,
            factory=lambda _p, _c, _r: _NoResultStep(),
            rebuild_execute=True, rebuild_preflight=preflight,
        )
        plan = ExecutionPlan(
            SimpleNamespace(base=SimpleNamespace(), profile=SimpleNamespace()),
            SimpleNamespace(),
            (PlannedStep("001:custom", "custom", _NoResultStep(), {}, definition),),
            SimpleNamespace(),
        )
        pipeline = RebuildPipeline(plan)
        session = WorkspaceSession(
            root=stage_root, stage=stage_root / "staging", destination=stage_root / "ready"
        )
        session.stage.mkdir()
        session.abort()
        with self.assertRaisesRegex(RuntimeError, "finished"):
            pipeline.make_rebuild_plan({"custom"}, session=session)
        self.assertEqual(calls, [])

    def test_rebuild_rejects_missing_staging_directory(self) -> None:
        stage_root = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(stage_root))
        pipeline, session = self._preflight_validation_pipeline(frozenset())
        __import__("shutil").rmtree(session.stage)
        with self.assertRaisesRegex(RuntimeError, "staging"):
            pipeline.make_rebuild_plan(set(), session=session)


if __name__ == "__main__":
    unittest.main()
