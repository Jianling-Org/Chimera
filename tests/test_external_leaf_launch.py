from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest

from test_external_scalar_leaf import dynamic_elf
from chimera.runtime.launcher.external_leaf import validate_leaf_launch


CAPABILITY = "external-scalar-leaf-contracts"


class LeafLaunchTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        main, provider = self.root / "app", self.root / "libc.so.6"
        dynamic_elf(main)
        dynamic_elf(provider, provider=True)
        digest = lambda p: sha256(p.read_bytes()).hexdigest()
        self.resolved = {"app": main, "libc": provider}
        self.modules = [SimpleNamespace(module_id=name, runtime_name=path.name,
            role="main" if name == "app" else "dependency", sha256=digest(path)) for name, path in self.resolved.items()]
        self.document = {"format": "chimera-external-scalar-leaf-v1", "elf_sha256": digest(main),
            "proofs": [{"target": 0x1000, "symbol": "memset", "library": "libc.so.6",
                "sha256": digest(provider), "provider_module": "libc", "provider_address": 0x2000,
                "size": 6, "code_sha256": sha256(bytes.fromhex("2300b5008280")).hexdigest(),
                "got": 0x4010, "version": None, "status": "verified-scalar-leaf"}],
            "rejections": [], "closed_calls": {"16": [0x1000]}}
        self.path = self.root / "leaves.json"
        self.path.write_text(json.dumps(self.document), encoding="utf-8")
        self.artifact = SimpleNamespace(owner_kind="module", owner_id="app", abi=1,
            capability=CAPABILITY, representation="json", path="leaves.json", sha256=digest(self.path))
        self.manifest = SimpleNamespace(modules=self.modules, artifacts=[self.artifact])

    def validate(self, environment=None):
        return validate_leaf_launch(self.root, self.manifest, self.resolved,
            environment=environment or {}, system_preload=self.root / "no-preload")

    def test_content_pinned_leaf_is_still_bound_to_the_resolved_modules(self):
        self.assertTrue(self.validate())

    def configure_memcpy_interface(self):
        dynamic_elf(self.resolved["app"], symbol_name="memcpy")
        dynamic_elf(self.resolved["libc"], provider=True, ifunc=True, symbol_name="memcpy")
        self.modules[0].sha256 = sha256(self.resolved["app"].read_bytes()).hexdigest()
        self.modules[1].sha256 = sha256(self.resolved["libc"].read_bytes()).hexdigest()
        self.document = {
            "format": "chimera-external-call-contracts-v2",
            "elf_sha256": self.modules[0].sha256,
            "proofs": [], "rejections": [], "interface_rejections": [],
            "no_callback_interfaces": [{
                "target": 0x1000, "symbol": "memcpy", "provider_module": "libc",
                "provider_library": "libc.so.6", "provider_sha256": self.modules[1].sha256,
                "provider_address": 0x2000, "provider_size": 6, "provider_type": "STT_LOOS",
                "provider_version": None, "imported_version": None, "got": 0x4010,
                "status": "bound-standard-interface-no-application-callback",
                "semantic_basis": "standard-libc-memcpy-no-application-callback-v1",
            }],
            "closed_calls": {"16": [0x1000]},
        }
        self.path.write_text(json.dumps(self.document), encoding="utf-8")
        self.artifact.sha256 = sha256(self.path.read_bytes()).hexdigest()

    def test_standard_libc_memcpy_interface_is_rebound_at_launch(self):
        self.configure_memcpy_interface()
        self.assertTrue(self.validate())

    def test_workspace_capability_accepts_only_the_structured_memcpy_interface_contract(self):
        from chimera.runtime.artifacts.validate.chimera.validate.capabilities import (
            CapabilityVerificationError, verify_external_leaf_json,
        )
        self.configure_memcpy_interface()
        verify_external_leaf_json(self.path, self.artifact, self.manifest, None)
        self.document["no_callback_interfaces"][0]["semantic_basis"] = "machine-code-leaf-proof"
        self.path.write_text(json.dumps(self.document), encoding="utf-8")
        with self.assertRaisesRegex(CapabilityVerificationError, "incomplete"):
            verify_external_leaf_json(self.path, self.artifact, self.manifest, None)

    def test_memcpy_runtime_provider_identity_and_symbol_preemption_are_checked(self):
        self.configure_memcpy_interface()
        self.modules[1].runtime_name = "libshim.so"
        with self.assertRaisesRegex(ValueError, "libc.so.6"):
            self.validate()

        self.modules[1].runtime_name = "libc.so.6"
        shim = self.root / "shim.so"
        dynamic_elf(shim, provider=True, ifunc=True, symbol_name="memcpy")
        self.manifest.artifacts.append(SimpleNamespace(capability="runtime", representation="elf",
            path="shim.so", sha256=sha256(shim.read_bytes()).hexdigest()))
        self.resolved["shim"] = shim
        self.modules.append(SimpleNamespace(module_id="shim", runtime_name="shim.so",
            role="dependency", sha256=sha256(shim.read_bytes()).hexdigest()))
        with self.assertRaisesRegex(ValueError, "interposed"):
            self.validate()

    def round_tripped_manifest(self, *, owner="app"):
        from chimera.runtime.manifest import (
            ArtifactRecord, ModuleRecord, WorkspaceManifest,
            read_manifest, write_manifest,
        )
        modules = tuple(ModuleRecord(
            module_id=item.module_id,
            role="main" if item.module_id == "app" else "dependency",
            runtime_name=item.runtime_name,
            selected_kind="original", delivery="target", sha256=item.sha256,
        ) for item in self.modules)
        artifact = ArtifactRecord(
            artifact_id="external-leaves-app", owner_kind="module", owner_id=owner,
            capability=CAPABILITY, representation="json", abi=1,
            required_by=frozenset({"launch"}), path="leaves.json",
            sha256=self.artifact.sha256,
        )
        manifest = WorkspaceManifest(
            runtime_abi=1, target_os="linux", target_arch="riscv64",
            target_arch_extension="rvv", runtime_scene="linux_riscv64_rvv_v1",
            modules=modules, variants=(), variant_properties=(), artifacts=(artifact,),
        )
        path = self.root / "artifacts/modules.tsv"
        write_manifest(manifest, path)
        return read_manifest(path, workspace_root=self.root)

    def test_serialized_manifest_identifies_the_leaf_owner_by_main_role(self):
        self.manifest = self.round_tripped_manifest()
        self.assertFalse(hasattr(self.manifest.modules[0], "is_main"))
        self.assertTrue(self.validate())

    def test_dependency_cannot_own_the_main_leaf_contract(self):
        self.manifest = self.round_tripped_manifest(owner="libc")
        with self.assertRaisesRegex(ValueError, "owner"):
            self.validate()

    def test_real_manifest_register_and_run_execute_the_leaf_validator(self):
        from importlib import import_module
        from unittest.mock import patch
        launcher = import_module("chimera.runtime.launcher.run")
        self.round_tripped_manifest()
        adapter = SimpleNamespace(environment=lambda *_: {})
        with (
            patch.object(launcher, "_select_loader", return_value=self.root / "ld.so"),
            patch.object(launcher, "_search_paths", return_value=()),
            patch.object(launcher, "_run_loader", return_value=(0, "", "")),
            patch.object(launcher, "resolved_module_paths", return_value={"libc": self.resolved["libc"]}),
            patch.object(launcher, "registered_launch_adapters") as adapters,
        ):
            adapters.return_value.select.return_value = adapter
            settings = SimpleNamespace()
            registered = launcher.resolve_modules(self.root, self.resolved["app"], settings, verify=False)
            request = launcher.prepare_launch(self.root, self.resolved["app"], [], settings, verify=False)
        self.assertEqual(registered.resolved, self.resolved)
        self.assertEqual(request.environment["LD_BIND_NOW"], "1")

    def test_extra_preload_or_audit_is_rejected_only_for_a_contract_workspace(self):
        for key in ("LD_PRELOAD", "LD_AUDIT"):
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, key):
                self.validate({key: "/tmp/shim.so"})
        self.manifest.artifacts = []
        self.assertFalse(self.validate({"LD_PRELOAD": "/tmp/shim.so"}))

    def test_unresolved_or_changed_provider_does_not_reuse_the_proof(self):
        self.resolved.pop("libc")
        with self.assertRaisesRegex(ValueError, "unresolved"):
            self.validate()
        self.resolved["libc"] = self.root / "libc.so.6"
        self.resolved["libc"].write_bytes(self.resolved["libc"].read_bytes() + b"changed")
        with self.assertRaisesRegex(ValueError, "identity"):
            self.validate()

    def test_unrecorded_runtime_export_cannot_interpose_on_the_proved_name(self):
        runtime = self.root / "runtime.so"
        dynamic_elf(runtime, provider=True)
        self.manifest.artifacts.append(SimpleNamespace(capability="runtime", representation="elf",
            path="runtime.so", sha256=sha256(runtime.read_bytes()).hexdigest()))
        with self.assertRaisesRegex(ValueError, "interpos"):
            self.validate()

    def test_modified_proof_artifact_is_rejected_even_without_general_verify(self):
        self.path.write_text("{}", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "artifact identity"):
            self.validate()

    def test_system_preload_is_rejected(self):
        preload = self.root / "ld.so.preload"
        preload.write_text("# comment\n/tmp/shim.so\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "system preload"):
            validate_leaf_launch(self.root, self.manifest, self.resolved, environment={}, system_preload=preload)

    def test_elf_loader_hooks_are_rejected_at_launch_too(self):
        dynamic_elf(self.resolved["app"], dynamic_tag=0x6ffffefc)
        self.modules[0].sha256 = sha256(self.resolved["app"].read_bytes()).hexdigest()
        self.document["elf_sha256"] = self.modules[0].sha256
        self.path.write_text(json.dumps(self.document), encoding="utf-8")
        self.artifact.sha256 = sha256(self.path.read_bytes()).hexdigest()
        with self.assertRaisesRegex(ValueError, "loader hook"):
            self.validate()

    def test_register_and_run_rebind_even_when_general_verify_is_skipped(self):
        from importlib import import_module
        from unittest.mock import patch
        launcher = import_module("chimera.runtime.launcher.run")
        self.modules[0].role = "main"
        self.modules[0].delivery = "target"
        self.modules[0].runtime_name = "app"
        settings = SimpleNamespace()
        self.manifest.target_os, self.manifest.target_arch = "linux", "riscv64"
        self.manifest.target_arch_extension, self.manifest.runtime_scene = "rvv", "linux_riscv64_rvv_v1"
        adapter = SimpleNamespace(environment=lambda *_: {})
        with (
            patch.object(launcher, "read_manifest", return_value=self.manifest),
            patch.object(launcher, "_select_loader", return_value=self.root / "ld.so"),
            patch.object(launcher, "_search_paths", return_value=()),
            patch.object(launcher, "_precheck", return_value=self.resolved),
            patch.object(launcher, "resolved_module_paths", return_value=self.resolved),
            patch.object(launcher, "registered_launch_adapters") as adapters,
            patch.object(launcher, "validate_leaf_launch", return_value=True) as validate,
        ):
            adapters.return_value.select.return_value = adapter
            registered = launcher.resolve_modules(self.root, self.resolved["app"], settings, verify=False)
            request = launcher.prepare_launch(self.root, self.resolved["app"], [], settings, verify=False)
            self.assertEqual(registered.resolved, self.resolved)
            self.assertEqual(validate.call_count, 2)
            self.assertEqual(request.environment["LD_BIND_NOW"], "1")
            validate.side_effect = ValueError("binding changed")
            for call in (launcher.resolve_modules, launcher.prepare_launch):
                with self.subTest(call=call.__name__), self.assertRaisesRegex(launcher.LaunchError, "binding changed"):
                    if call == launcher.prepare_launch:
                        call(self.root, self.resolved["app"], [], settings, verify=False)
                    else:
                        call(self.root, self.resolved["app"], settings, verify=False)


if __name__ == "__main__":
    unittest.main()
