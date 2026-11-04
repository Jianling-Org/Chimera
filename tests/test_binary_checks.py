from __future__ import annotations

import tempfile
import unittest
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from chimera.elf_state import (
    CHECKED,
    PROBLEMATIC,
    REMEDIATED,
    ElfStateRegistry,
    sha256_of,
)
from chimera.preprocess.offline.analysis_profile.checks import (
    BinaryCheckOutcome,
    BinaryCheckRequest,
    build_check_plan,
    check_admission,
)
from chimera.preprocess.offline.analysis_profile.parser import ResolvedWorkflowStep


@dataclass(frozen=True)
class _Definition:
    name: str
    binary_check_factory: object | None = None


class BinaryCheckPlanTests(unittest.TestCase):
    def _configuration(self, *, profile_name="one"):
        return SimpleNamespace(
            profile=SimpleNamespace(
                name=profile_name,
                target_os="linux",
                target_arch="riscv64",
                target_arch_extension="rvv",
                runtime_scene="linux_riscv64_rvv_v1",
                runtime_abi=1,
            ),
            base=SimpleNamespace(tools=SimpleNamespace(objdump="objdump")),
        )

    def test_empty_workflow_checks_are_passed_without_runner(self):
        configuration = self._configuration()
        plan = build_check_plan(configuration, resolved_steps=())
        self.assertEqual(plan.requests, ())
        with tempfile.TemporaryDirectory() as directory:
            input_elf = Path(directory) / "app"
            input_elf.write_bytes(b"ELF payload")
            result = plan.run(input_elf)
        self.assertTrue(result.passed)
        self.assertEqual(result.decision["vector_gate"]["enabled"], False)
        self.assertIn("no binary checks", result.message)

    def test_duplicate_requests_are_deduplicated_and_retain_requesters(self):
        def factory(parameters):
            return BinaryCheckRequest(
                check_id="example.check",
                version=1,
                parameters=parameters,
                runner=lambda _path, _context: BinaryCheckOutcome(passed=True),
            )

        steps = (
            ResolvedWorkflowStep("001:first", "first", {"mode": "x"}, _Definition("first", factory)),
            ResolvedWorkflowStep("002:second", "second", {"mode": "x"}, _Definition("second", factory)),
        )
        plan = build_check_plan(self._configuration(), resolved_steps=steps)
        self.assertEqual(len(plan.requests), 1)
        self.assertEqual(plan.requests[0].requested_by, ("001:first", "002:second"))

    def test_fingerprint_excludes_profile_name_but_binds_scope(self):
        first = build_check_plan(self._configuration(profile_name="one"), resolved_steps=())
        second = build_check_plan(self._configuration(profile_name="renamed"), resolved_steps=())
        digest = "a" * 64
        self.assertEqual(first.fingerprint(digest), second.fingerprint(digest))

    def test_scope_fingerprint_treats_check_collection_as_order_independent(self):
        def factory(label):
            return lambda _parameters: BinaryCheckRequest(
                check_id=label,
                version=1,
                parameters={},
                runner=lambda _path, _context: BinaryCheckOutcome(passed=True),
            )

        first_steps = (
            ResolvedWorkflowStep("001:a", "a", {}, _Definition("a", factory("a"))),
            ResolvedWorkflowStep("002:b", "b", {}, _Definition("b", factory("b"))),
        )
        second_steps = tuple(reversed(first_steps))
        first = build_check_plan(self._configuration(), resolved_steps=first_steps)
        second = build_check_plan(self._configuration(), resolved_steps=second_steps)
        self.assertEqual(first.fingerprint("a" * 64), second.fingerprint("a" * 64))

    def test_prepare_admission_rejects_remediated_and_scope_mismatch(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            elf = root / "app"
            elf.write_bytes(b"ELF payload")
            registry = ElfStateRegistry(root / "states.json")
            request = BinaryCheckRequest(
                check_id="example.check",
                version=1,
                parameters={},
                runner=lambda _path, _context: BinaryCheckOutcome(passed=True),
            )
            steps = (ResolvedWorkflowStep("001:check", "check", {}, _Definition("check", lambda _p: request)),)
            plan = build_check_plan(self._configuration(), resolved_steps=steps)
            fingerprint = plan.fingerprint(sha256_of(elf))
            registry.set_status(elf, REMEDIATED, check_fingerprint=None)
            with self.assertRaisesRegex(RuntimeError, "re-run check-elf"):
                check_admission(elf, plan, registry=registry)
            registry.set_status(elf, CHECKED, check_fingerprint="b" * 64)
            with self.assertRaisesRegex(RuntimeError, "scope"):
                check_admission(elf, plan, registry=registry)

    def test_registry_persists_and_clears_check_credential(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            elf = root / "app"
            elf.write_bytes(b"ELF payload")
            registry = ElfStateRegistry(root / "states.json")
            scope = {"checks": [{"id": "example.check", "version": 1}]}
            record = registry.set_status(
                elf, CHECKED, check_fingerprint="a" * 64, check_scope=scope,
                check_input_fingerprint="b" * 64,
            )
            self.assertEqual(record.check_fingerprint, "a" * 64)
            self.assertEqual(registry.entry(elf).check_scope, scope)
            self.assertEqual(registry.entry(elf).check_input_fingerprint, "b" * 64)
            cleared = registry.set_status(elf, REMEDIATED)
            self.assertIsNone(cleared.check_fingerprint)
            self.assertIsNone(cleared.check_scope)
            self.assertIsNone(cleared.check_input_fingerprint)

    def test_dependency_replacement_and_added_provider_invalidate_admission(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            elf, provider = root / "app", root / "provider.so"
            elf.write_bytes(b"unchanged main ELF")
            provider.write_bytes(b"proved provider")
            selected = [provider]
            request = BinaryCheckRequest("native.check", 1, {},
                lambda _path, _context: BinaryCheckOutcome(passed=True),
                input_identity=lambda _path, _context: [
                    {"path": str(p), "sha256": sha256_of(p)} for p in selected])
            steps = (ResolvedWorkflowStep("001:check", "check", {},
                     _Definition("check", lambda _p: request)),)
            plan = build_check_plan(self._configuration(), resolved_steps=steps)
            registry = ElfStateRegistry(root / "registry.json")
            registry.set_status(elf, CHECKED,
                check_fingerprint=plan.fingerprint(sha256_of(elf)), check_scope=plan.scope,
                check_input_fingerprint=plan.input_fingerprint(elf))
            check_admission(elf, plan, registry=registry)
            provider.write_bytes(b"replacement that may call back")
            with self.assertRaisesRegex(RuntimeError, "inputs changed"):
                check_admission(elf, plan, registry=registry)
            provider.write_bytes(b"proved provider")
            interposer = root / "interposer.so"
            interposer.write_bytes(b"another provider")
            selected.append(interposer)
            with self.assertRaisesRegex(RuntimeError, "inputs changed"):
                check_admission(elf, plan, registry=registry)
            # --allow-problematic is not permission to reuse stale inputs.
            with self.assertRaisesRegex(RuntimeError, "inputs changed"):
                check_admission(elf, plan, registry=registry, allow_problematic=True)

    def test_missing_dependency_credential_requires_a_fresh_check(self):
        with tempfile.TemporaryDirectory() as directory:
            elf = Path(directory) / "app"
            elf.write_bytes(b"ELF")
            request = BinaryCheckRequest("native.check", 1, {},
                lambda _path, _context: BinaryCheckOutcome(passed=True),
                input_identity=lambda _path, _context: ["selected dependency identity"])
            step = ResolvedWorkflowStep("001:check", "check", {},
                        _Definition("check", lambda _p: request))
            plan = build_check_plan(self._configuration(), resolved_steps=(step,))
            registry = ElfStateRegistry(Path(directory) / "registry.json")
            registry.set_status(elf, CHECKED,
                check_fingerprint=plan.fingerprint(sha256_of(elf)), check_scope=plan.scope)
            with self.assertRaisesRegex(RuntimeError, "not bound"):
                check_admission(elf, plan, registry=registry)

    def test_dependency_changed_during_check_does_not_publish_a_credential(self):
        from chimera import cli as cli_module

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            elf, provider = root / "app", root / "provider.so"
            elf.write_bytes(b"ELF");provider.write_bytes(b"initial provider")

            def run(_path, _context):
                provider.write_bytes(b"provider changed while analysis was running")
                return BinaryCheckOutcome(passed=True)

            request = BinaryCheckRequest("native.check", 1, {}, run,
                input_identity=lambda _path, _context: sha256_of(provider))
            configuration = self._configuration()
            step = ResolvedWorkflowStep("001:check", "check", {},
                        _Definition("check", lambda _p: request))
            plan = build_check_plan(configuration, resolved_steps=(step,))
            args = SimpleNamespace(input_elf=elf, objdump="unused", strategy="auto",
                                   text_threshold=1, json=root / "report.json")
            with mock.patch.object(cli_module, "ElfStateRegistry") as registry:
                with self.assertRaisesRegex(RuntimeError, "inputs changed during analysis"):
                    cli_module._check_elf_one(args, configuration, plan)
            registry.assert_not_called()
            self.assertFalse(args.json.exists())

    def test_safety_identity_uses_actual_prepare_module_selection(self):
        from chimera.check_elf import safety_binary_check_request
        from chimera.preprocess.offline.analysis_profile.checks import BinaryCheckContext

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            elf, provider = root / "app", root / "provider.so"
            elf.write_bytes(b"ELF");provider.write_bytes(b"selected bytes")
            request = safety_binary_check_request({"min_vlen_bits": 256, "compiler_metadata": ()})
            modules = [SimpleNamespace(module_id="native", selected_path=provider,
                                       is_scalar=False, delivery="target")]
            configuration = self._configuration()
            with mock.patch("chimera.check_elf.selected_check_modules", return_value=modules) as select:
                identity = request.input_identity(elf, BinaryCheckContext(configuration))
            select.assert_called_once_with(elf, configuration)
            self.assertEqual(identity, [{"module": "native", "path": str(provider.resolve()),
                                         "is_scalar": False, "delivery": "target",
                                         "sha256": sha256_of(provider)}])

    def test_cli_empty_plan_does_not_require_or_invoke_objdump(self):
        from chimera import cli as cli_module

        class EmptyPlan:
            requests = ()
            scope = {"checks": []}

            def run(self, path, *, objdump_cmd=None, overrides=None):
                self.seen_path = Path(path).resolve()
                self.seen_objdump = objdump_cmd
                return SimpleNamespace(
                    passed=True, outcomes=(), decision={
                        "strategy": "none",
                        "vector_gate": {"enabled": False},
                        "stack_object_plugin": False,
                    }, message="current workflow has no binary checks; passed",
                )

            def fingerprint(self, digest):
                return digest

        plan = EmptyPlan()
        configuration = self._configuration()

        class NoProbeTools:
            @property
            def objdump(self):
                raise AssertionError("empty check plan must not inspect objdump")

        configuration.base.tools = NoProbeTools()
        with tempfile.TemporaryDirectory() as directory:
            elf = Path(directory) / "app"
            elf.write_bytes(b"ELF payload")
            report = Path(directory) / "report.json"
            arguments = SimpleNamespace(
                input_elf=elf,
                objdump=None,
                min_vlen_bits=None,
                strategy="auto",
                text_threshold=1,
                json=report,
                strict=False,
            )
            registry = mock.Mock()
            with mock.patch.object(cli_module, "_configuration", return_value=configuration), \
                mock.patch.object(cli_module, "build_check_plan", return_value=plan), \
                mock.patch.object(cli_module, "write_check_report", return_value=report), \
                mock.patch.object(cli_module, "write_latest_pointer"), \
                mock.patch.object(cli_module, "ElfStateRegistry", return_value=registry):
                self.assertEqual(cli_module._check_elf(arguments), 0)
        self.assertIsNone(plan.seen_objdump)

    def test_safety_request_uses_declared_metadata_and_reports_missing(self):
        from chimera.check_elf import DiagnosticsResult, safety_binary_check_request

        request = safety_binary_check_request({
            "min_vlen_bits": 512,
            "compiler_metadata": ("stack_access_ids",),
        })
        result = DiagnosticsResult(
            elf_path=Path("app"), strategy="none", strategy_reason="empty",
            text_bytes=0, findings=(), gate_names=(), counts={}, stack_object=False,
        )
        configuration = self._configuration()
        with tempfile.TemporaryDirectory() as directory:
            elf = Path(directory) / "app"
            elf.write_bytes(b"ELF payload")
            with mock.patch("chimera.check_elf.ChimeraMetadata.from_elf", return_value=mock.Mock(capabilities=frozenset())), \
                mock.patch("chimera.check_elf.collect_diagnostics", return_value=result) as collect, \
                mock.patch("chimera.check_elf.selected_check_modules", return_value=()):
                outcome = request.run(elf, __import__(
                    "chimera.preprocess.offline.analysis_profile.checks",
                    fromlist=["BinaryCheckContext"],
                ).BinaryCheckContext(configuration, objdump_cmd="objdump"))
        self.assertFalse(outcome.passed)
        self.assertEqual(outcome.diagnostics["missing_compiler_metadata"], ["stack_access_ids"])
        self.assertTrue(outcome.decision["stack_object_plugin"])
        self.assertEqual(collect.call_args.kwargs["min_vlen_bits"], 512)


if __name__ == "__main__":
    unittest.main()
