from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from chimera.workspack import WorkspackError, install_workspack, pack_workspack


class WorkspackTests(unittest.TestCase):
    # A published Workspace carries only the package-delivered modules.  The
    # application itself ("app") is target-resolved, so it has no file here --
    # which is exactly what packing must not silently ship.
    _MAIN_LINE = "module\tmain\tmain\tapp\toriginal\ttarget\t" + "0" * 64
    _DEP_SHA = hashlib.sha256(b"libdep").hexdigest()

    def _workspace(self, root: Path, name: str = "demo") -> Path:
        workspace = root / name
        (workspace / "scalar").mkdir(parents=True)
        (workspace / "artifacts").mkdir()
        (workspace / "scalar" / "libdep.so").write_bytes(b"libdep")
        (workspace / "artifacts" / "modules.tsv").write_text(
            "# chimera-workspace-manifest-v2\n"
            "# runtime_abi=1\n"
            "# target_os=linux\n"
            "# target_arch=riscv64\n"
            "# target_arch_extension=rvv\n"
            "# runtime_scene=linux_riscv64_rvv_v1\n"
            f"{self._MAIN_LINE}\n"
            f"module\tdep\tdependency\tlibdep.so\tscalar\tpackage\t{self._DEP_SHA}\n",
            encoding="utf-8",
        )
        (workspace / "workspace.json").write_text(
            json.dumps(
                {
                    "workspace_id": name,
                    "created_at": "2026-01-01T00:00:00Z",
                    "input_elf_name": "app",
                    "input_elf_digest": hashlib.sha256(b"app").hexdigest(),
                    "input_fingerprint": hashlib.sha256(b"fingerprint").hexdigest(),
                }
            ),
            encoding="utf-8",
        )
        return workspace

    def test_pack_and_install_round_trip_without_source_inode(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = self._workspace(root)
            package = root / "demo.workspace"
            pack_workspack(source, package)
            target_root = root / "target"
            installed = install_workspack(package, target_root)
            self.assertEqual(installed, target_root / "demo")
            metadata = json.loads((installed / "workspace.json").read_text())
            # The source inode is a local binding, not part of the document.
            self.assertNotIn("input_elf_inode", metadata)
            self.assertEqual(metadata["input_elf_name"], "app")
            self.assertEqual(
                (installed / "scalar" / "libdep.so").read_bytes(), b"libdep"
            )
            # The application is never packaged.
            self.assertFalse((installed / "scalar" / "app").exists())

    def test_install_rejects_tampered_archive(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = self._workspace(root)
            package = root / "demo.workspace"
            pack_workspack(source, package)
            package.write_bytes(package.read_bytes() + b"tampered")
            with self.assertRaises(WorkspackError):
                install_workspack(package, root / "target")

    def test_public_extension_is_required_for_pack_and_install(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = self._workspace(root)
            legacy = root / "demo.workspack"
            with self.assertRaisesRegex(WorkspackError, r"\.workspace"):
                pack_workspack(source, legacy)
            package = root / "demo.workspace"
            pack_workspack(source, package)
            legacy.write_bytes(package.read_bytes())
            with self.assertRaisesRegex(WorkspackError, r"\.workspace"):
                install_workspack(legacy, root / "target")

    def test_explicit_resources_are_packaged(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = self._workspace(root)
            resource = root / "model.bin"
            resource.write_bytes(hashlib.sha256(b"resource").digest())
            package = root / "demo.workspace"
            pack_workspack(source, package, resources=((resource, "model/model.bin"),))
            installed = install_workspack(package, root / "target")
            self.assertEqual(
                (installed / "resources" / "model" / "model.bin").read_bytes(),
                resource.read_bytes(),
            )
