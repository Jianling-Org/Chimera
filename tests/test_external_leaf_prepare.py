"""Prepare publishes binding evidence without making live caller state safe."""
from hashlib import sha256
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from chimera.check_elf import collect_diagnostics
from chimera.preprocess.offline.analysis import AnalysisContext
from chimera.preprocess.offline.analysis.arch.riscv.rvv import RvvServices
from chimera.preprocess.offline.analysis.core.data_model import AnalysisModule, DELIVERY_TARGET
from chimera.preprocess.offline.analysis.core.workspace import WorkspaceSession
from chimera.preprocess.offline.analysis.safety.external_leaf import ExternalLeafBindings
from chimera.preprocess.offline.analysis.safety.stack_liveness.model import ChimeraMetadata
from chimera.preprocess.offline.analysis.safety.step import SafetyStep
from chimera.preprocess.offline.analysis.toolchain.artifact_emitter import GnuArtifactEmitter

from test_external_call_gate import _dump
from test_external_scalar_leaf import CONTRACT
from test_safepoint_patch import build_elf
from test_workspace_producer_registration import fake_platform


class PrepareLeafTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.app = self.root / "app"
        self.app.write_bytes(build_elf(b"\x13\x00\x00\x00"))
        self.stage = self.root / "stage"
        self.stage.mkdir()
        self.session = WorkspaceSession(root=self.root, stage=self.stage, destination=self.root / "ready")
        program = collect_diagnostics(self.app, objdump_cmd="objdump", min_vlen_bits=256,
            dump_text=_dump(inherited=False), strategy="gate", metadata=ChimeraMetadata.empty()).analysis.program
        module = AnalysisModule("app", self.app, self.app, False, True, DELIVERY_TARGET)
        platform = fake_platform()
        # Replace only the external compiler; liveness, classifier and exports
        # execute the real production implementations on the small program.
        platform.runner.run.side_effect = lambda _: (self.stage / "artifacts/libsafety_app.so").write_bytes(b"compiled")
        services = SimpleNamespace(platform=platform, architecture=SimpleNamespace(extension=RvvServices()),
            toolchain=SimpleNamespace(artifact_emitter=GnuArtifactEmitter(), compiler=Mock()))
        self.context = AnalysisContext(input_elf=self.app, stage=self.stage,
            config=SimpleNamespace(tools=SimpleNamespace(objdump="objdump")), target_os="linux",
            target_arch="riscv64", target_arch_extension="rvv", runtime_scene="linux_riscv64_rvv_v1",
            runtime_abi=1, services=services).put_global("modules", (module,)).put_global("programs", {"app": program}).put_global("workspace_session", self.session)

    def test_fresh_binding_is_published_and_the_caller_stays_unsafe(self):
        proof = {"target": 0x8000, **CONTRACT, "status": "verified-scalar-leaf"}
        with patch("chimera.preprocess.offline.analysis.safety.step.bind_external_scalar_leaves",
                   return_value=ExternalLeafBindings((proof,), ())) as binder:
            result = SafetyStep(min_vlen_bits=256, compiler_metadata=(),
                               external_scalar_leaf_contracts=[CONTRACT]).run(self.context)
        binder.assert_called_once()
        self.assertFalse(result.require_global("safety_analysis").safety.records[0x1008].safe)
        artifact = self.session.registry.artifacts["external-leaves-app"]
        document = json.loads((self.stage / artifact.path).read_text(encoding="utf-8"))
        self.assertEqual(document["elf_sha256"], sha256(self.app.read_bytes()).hexdigest())
        self.assertEqual(document["closed_calls"], {"4104": [0x8000]})
        self.assertEqual(artifact.required_by, frozenset({"launch"}))

    def test_binding_failure_stops_prepare_before_publishing_safety(self):
        with patch("chimera.preprocess.offline.analysis.safety.step.bind_external_scalar_leaves",
                   return_value=ExternalLeafBindings((), ({"reason": "hash changed"},))):
            with self.assertRaisesRegex(ValueError, "rebound during prepare"):
                SafetyStep(min_vlen_bits=256, compiler_metadata=(),
                           external_scalar_leaf_contracts=[CONTRACT]).run(self.context)
        self.assertEqual(self.session.registry.artifacts, {})


if __name__ == "__main__":
    unittest.main()
