from __future__ import annotations

from pathlib import Path
import json
import tempfile
import unittest

from elf_fixture import write_elf
from chimera.preprocess.offline.config import load_toml, parse_base_config
from chimera.preprocess.offline.analysis.core.workspace import (
    WorkspaceError,
    WorkspaceRepository,
    read_workspace_metadata,
    resolve_clean_target,
    resolve_workspace_by_elf,
    update_workspace_metadata,
    workspace_name,
    write_workspace_metadata,
)


class ConfigAndWorkspaceTests(unittest.TestCase):
    def test_relative_paths_follow_selected_file(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            profile = root / "profiles" / "rvv.toml"
            profile.parent.mkdir()
            translator = root / "tools" / "translator.py"
            translator.parent.mkdir()
            translator.write_text("# external\n", encoding="utf-8")
            profile.write_text(
                """
[config]
workspace_root = "../workspaces"

[[config.translators]]
source = "riscv64;rvv;vlen=1024"
target = "riscv64;rvv;vlen=256"
translator_path = "../tools/translator.py"

[config.tools]
cc = "profile-cc"

[profile]
name = "linux-riscv64-rvv"
workflow = "rvv-offline-v1"
target_os = "linux"
target_arch = "riscv64"
analysis_backend = "riscv-rvv"
min_vlen_bits = 256
max_vlen_bits = 1024
runtime_abi = 1
""".strip()
                + "\n",
                encoding="utf-8",
            )
            document = load_toml(profile)
            settings = parse_base_config(
                document["config"],
                source=profile,
            )

            self.assertEqual(settings.tools.cc, "profile-cc")
            self.assertEqual(settings.workspace_root, (profile.parent / "../workspaces").resolve())
            self.assertEqual(settings.translators[0].translator_path, translator.resolve())

    def test_default_workspace_name_is_the_content_identity(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first_path = root / "one" / "a weird.elf"
            second_path = root / "two" / "renamed.elf"
            third_path = root / "three" / "a weird.elf"
            first = write_elf(first_path)
            second = write_elf(second_path)
            third = write_elf(third_path, b"\xbb" * 32)
            first_name = workspace_name(first)
            second_name = workspace_name(second)
            third_name = workspace_name(third)

        # Identity is content, not path or filename.
        self.assertRegex(first_name, r"^[0-9a-f]{64}$")
        self.assertEqual(first_name, second_name)
        self.assertNotEqual(first_name, third_name)

    def test_legacy_workspace_metadata_is_rejected(self) -> None:
        # No version number: an older document is recognised by its shape, and
        # the message has to say what to do about it.
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            elf = write_elf(root / "app.elf")
            digest = workspace_name(elf)
            workspace = root / "workspaces" / digest
            workspace.mkdir(parents=True)
            (workspace / "workspace.json").write_text(
                json.dumps(
                    {
                        "workspace_id": digest,
                        "created_at": "2026-01-01T00:00:00Z",
                        "input_elf_name": "app.elf",
                        "input_elf_inode": 123,
                        "input_elf_sha256": "0" * 64,
                    }
                ),
                encoding="utf-8",
            )

            with self.assertRaisesRegex(ValueError, "does not match the current format"):
                read_workspace_metadata(workspace)
            with self.assertRaisesRegex(WorkspaceError, "unusable"):
                resolve_workspace_by_elf(root / "workspaces", elf)

    def test_workspace_digest_conflict_is_reported(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            elf = write_elf(root / "app.elf")
            other = write_elf(root / "other.elf", b"\xbb" * 32)
            digest = workspace_name(elf)
            workspaces = root / "workspaces"
            workspace = workspaces / digest
            workspace.mkdir(parents=True)
            # The directory is addressed by ``elf``'s identity but records the
            # identity of a different file: a conflict, never a silent reuse.
            write_workspace_metadata(workspace, workspace_id=digest, input_elf=other)
            update_workspace_metadata(workspace, input_fingerprint="f" * 64)

            with self.assertRaisesRegex(WorkspaceError, "refusing to reuse"):
                resolve_workspace_by_elf(workspaces, elf)

    def test_missing_workspace_is_reported_with_identity(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            elf = write_elf(root / "app.elf")
            (root / "workspaces").mkdir()

            with self.assertRaisesRegex(WorkspaceError, "no workspace prepared"):
                resolve_workspace_by_elf(root / "workspaces", elf)

    def test_clean_target_must_be_below_workspace_root(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            target = root / "one"
            target.mkdir()
            self.assertEqual(resolve_clean_target(root, target), target)
            with self.assertRaises(WorkspaceError):
                resolve_clean_target(root, root)
            with self.assertRaises(WorkspaceError):
                resolve_clean_target(root, root.parent)

    def test_start_rejects_existing_workspace_name(self) -> None:
        # workspace 名按 ELF 身份摘要寻址：同内容同名 workspace 已存在时
        # 保持拒绝语义（重建/刷新由调用方先显式 clean）。
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            repository = WorkspaceRepository(root / "workspaces")
            elf = write_elf(root / "app.elf")
            first = repository.start(elf)
            first.destination.mkdir()      # 模拟发布态 workspace
            with self.assertRaises(FileExistsError):
                repository.start(elf)
            first.abort()


if __name__ == "__main__":
    unittest.main()
