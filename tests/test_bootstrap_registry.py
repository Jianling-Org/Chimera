from pathlib import Path
import importlib.util
from hashlib import sha256
import tempfile
from types import SimpleNamespace as NS
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("bootstrap_registry", ROOT / "runtime/launcher/preload/chimera/preload/registry.py")
registry_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(registry_module)
launch_spec = importlib.util.spec_from_file_location("bootstrap_launch", ROOT / "runtime/launcher/preload/chimera/preload/bootstrap_launch.py")
launch_module = importlib.util.module_from_spec(launch_spec)
launch_spec.loader.exec_module(launch_module)

class RegistryTest(unittest.TestCase):
    def test_table_verifier_runs_once_per_receipt_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);(root/'artifacts').mkdir()
            receipt=root/'artifacts/verified-files.tsv';receipt.write_text('verified files')
            with patch('subprocess.run') as verify:
                registry_module.verify_tables(root,root/'app',root/'runtime.so',receipt)
                registry_module.verify_tables(root,root/'app',root/'runtime.so',receipt)
                self.assertEqual(verify.call_count,1)
                receipt.write_text('changed receipt')
                registry_module.verify_tables(root,root/'app',root/'runtime.so',receipt)
                self.assertEqual(verify.call_count,2)
    def test_cli_publication_without_pinned_bpf_map(self):
        from chimera import cli
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            program = root / "app"
            program.write_bytes(b"executable")
            runtime = root / "runtime.so"
            runtime.write_bytes(b"runtime")
            artifact = NS(owner_kind="workspace", owner_id="root", capability="runtime", representation="elf", path="runtime.so", sha256=sha256(runtime.read_bytes()).hexdigest())
            manifest = NS(modules=[NS(role="main", sha256=sha256(program.read_bytes()).hexdigest())], artifacts=[artifact])
            registry = root / "registry.tsv"
            def verify(workspace, settings, *, check_host=True):
                if check_host:
                    raise RuntimeError("cannot open pinned BPF map")
                return manifest
            with patch.object(cli, "load_user_settings", return_value=NS(workspace_root=root)), \
                 patch.object(cli, "_workspace", return_value=root), \
                 patch.object(cli, "verify_workspace_installation"), \
                 patch.object(cli, "verify_workspace", side_effect=verify) as checked, \
                 patch("chimera.runtime.preload.bootstrap_launch.launch_bootstrap") as launched:
                self.assertEqual(cli.main(["bootstrap-register", "--input", str(program), "--workspace", str(root), "--registry", str(registry)], command_group="user"), 0)
                self.assertIn(str(program), registry.read_text())
                self.assertEqual(cli.main(["run", "--input", str(program), "--workspace", str(root), "--registry", str(registry), "--bootstrap", str(runtime)], command_group="user"), 0)
                self.assertEqual(checked.call_count, 2)
                launched.assert_called_once()

    def test_static_tls_reserve_preserves_tunables(self):
        result = launch_module.bootstrap_tunables("glibc.malloc.check=1:glibc.rtld.optional_static_tls=4096")
        self.assertEqual(result, "glibc.malloc.check=1:glibc.rtld.optional_static_tls=65536")
        self.assertEqual(launch_module.bootstrap_tunables("glibc.rtld.optional_static_tls=131072"),
                         "glibc.rtld.optional_static_tls=131072")
        with self.assertRaises(ValueError):
            launch_module.bootstrap_tunables("glibc.rtld.optional_static_tls=invalid")

    def test_publish_replace_and_identity_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            program = root / "app"
            program.write_bytes(b"executable")
            runtime = root / "runtime.so"
            runtime.write_bytes(b"runtime")
            artifact = NS(owner_kind="workspace", owner_id="root", capability="runtime", representation="elf", path="runtime.so", sha256=sha256(runtime.read_bytes()).hexdigest())
            manifest = NS(modules=[NS(role="main", sha256=sha256(program.read_bytes()).hexdigest())], artifacts=[artifact])
            registry = root / "registry.tsv"
            registry_module.publish_registry(registry, program, root, manifest)
            first = registry.read_text()
            registry_module.publish_registry(registry, program, root, manifest)
            self.assertEqual(first, registry.read_text())
            program.write_bytes(b"changed")
            with self.assertRaises(ValueError):
                registry_module.publish_registry(registry, program, root, manifest)
            self.assertEqual(first, registry.read_text())

if __name__ == "__main__": unittest.main()
