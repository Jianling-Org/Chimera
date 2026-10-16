from __future__ import annotations

from pathlib import Path
import os
import tempfile
import unittest
from contextlib import redirect_stderr
from io import StringIO
from types import SimpleNamespace
from unittest.mock import patch

from chimera import installation
from chimera.installation import (
    _copy_missing_tree,
    _download_model,
    _model_cache_path,
    _model_is_valid,
    _repair_executable_modes,
)


class InstallationTests(unittest.TestCase):
    def test_model_cache_uses_content_addressed_path_and_validates_gguf(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary) / "home"
            with patch.object(installation.Path, "home", return_value=home):
                destination = _model_cache_path()
                self.assertIn(installation.MODEL_SHA256, str(destination))
                destination.parent.mkdir(parents=True)
                destination.write_bytes(b"bad")
                self.assertFalse(_model_is_valid(destination))
                payload = b"GGUF" + b"payload"
                digest = __import__("hashlib").sha256(payload).hexdigest()
                with patch.object(installation, "MODEL_SHA256", digest), patch.object(
                    installation, "MODEL_SIZE", len(payload)
                ):
                    destination = _model_cache_path()
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    destination.write_bytes(payload)
                    self.assertTrue(_model_is_valid(destination))

    def test_model_download_streams_to_atomic_cache_and_rejects_bad_payload(self) -> None:
        class Response:
            def __enter__(self):
                return self

            def __exit__(self, *_):
                return False

            def read(self, size=-1):
                if self.done:
                    return b""
                self.done = True
                return self.payload

            payload = b"GGUF" + b"payload"
            done = False

        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary) / "home"
            import hashlib
            digest = hashlib.sha256(Response.payload).hexdigest()
            with patch.object(installation.Path, "home", return_value=home), patch.object(
                installation, "MODEL_SHA256", digest
            ), patch.object(installation, "MODEL_SIZE", len(Response.payload)), patch.object(
                installation.urllib.request, "urlopen", return_value=Response()
            ):
                destination = _download_model()
            self.assertEqual(destination.read_bytes(), Response.payload)
            self.assertFalse(list(destination.parent.glob("*.tmp")))

            Response.done = False
            with patch.object(installation.Path, "home", return_value=home), patch.object(
                installation, "MODEL_SHA256", "0" * 64
            ), patch.object(installation, "MODEL_SIZE", len(Response.payload)), patch.object(
                installation.urllib.request, "urlopen", return_value=Response()
            ):
                with self.assertRaisesRegex(RuntimeError, "SHA-256"):
                    _download_model()
            self.assertEqual(destination.read_bytes(), Response.payload)

    def test_model_download_can_be_skipped_without_marking_cache_ready(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary) / "home"
            with patch.object(installation.Path, "home", return_value=home), patch.object(
                installation.sys,
                "stdin",
                SimpleNamespace(isatty=lambda: False),
            ), patch("builtins.input", side_effect=AssertionError("must not prompt")):
                self.assertIsNone(installation._maybe_download_model())
            self.assertFalse((home / ".chimera" / "models").exists())

    def test_model_download_prompt_decline_is_retriable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary) / "home"
            with patch.object(installation.Path, "home", return_value=home), patch.object(
                installation.sys,
                "stdin",
                SimpleNamespace(isatty=lambda: True),
            ), patch("builtins.input", side_effect=["", "n"]):
                self.assertIsNone(installation._maybe_download_model())
            self.assertFalse((home / ".chimera" / "models").exists())

    def test_model_init_accepts_local_path_before_download_prompt(self) -> None:
        payload = b"GGUF" + b"local-model"
        import hashlib

        digest = hashlib.sha256(payload).hexdigest()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            home = root / "home"
            source = root / "model.gguf"
            source.write_bytes(payload)
            with (
                patch.object(installation.Path, "home", return_value=home),
                patch.object(installation, "MODEL_SHA256", digest),
                patch.object(installation, "MODEL_SIZE", len(payload)),
                patch.object(
                    installation.sys, "stdin", SimpleNamespace(isatty=lambda: True)
                ),
                patch("builtins.input", return_value=str(source)),
                patch.object(
                    installation,
                    "_download_model",
                    side_effect=AssertionError("local model must avoid download"),
                ),
            ):
                destination = installation._maybe_download_model()
            self.assertIsNotNone(destination)
            assert destination is not None
            self.assertEqual(destination.read_bytes(), payload)
            self.assertEqual(destination, home / ".chimera" / "models" / digest / installation.MODEL_FILENAME)

    def test_invalid_local_model_path_is_reported_without_downloading(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            home = root / "home"
            source = root / "not-a-model"
            source.write_bytes(b"bad")
            with (
                patch.object(installation.Path, "home", return_value=home),
                patch.object(
                    installation.sys, "stdin", SimpleNamespace(isatty=lambda: True)
                ),
                patch("builtins.input", return_value=str(source)),
                patch.object(
                    installation,
                    "_download_model",
                    side_effect=AssertionError("invalid local model must not download"),
                ),
            ):
                with self.assertRaisesRegex(RuntimeError, "local model"):
                    installation._maybe_download_model()
            self.assertFalse(
                (home / ".chimera" / "models" / installation.MODEL_SHA256 / installation.MODEL_FILENAME).exists()
            )

    def test_repeated_init_repairs_existing_compiler_mode(self) -> None:
        if os.name == "nt":
            self.skipTest("POSIX executable mode semantics are unavailable")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            resource = root / "resource"
            home = root / "home"
            files = (
                "toolchain/llvm/bin/clang",
                "toolchain/llvm/bin/clang++",
                "toolchain/plugins/lib/chimera/llvm/ChimeraStackObject.so",
                "toolchain/plugins/lib/chimera/llvm/ChimeraVectorGate.so",
                "examples/llamacpp/system/llama-perplexity",
                "examples/llamacpp/remediated/llama-perplexity",
            )
            for relative in files:
                path = resource / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b"artifact")
            (resource / "release-config.json").write_text(
                '{"target_os":"linux","target_arch":"riscv64",'
                '"target_arch_extension":"rvv"}',
                encoding="utf-8",
            )
            toolchain = home / ".chimera/toolchain_build/llvm/bin/clang"
            toolchain.parent.mkdir(parents=True)
            toolchain.write_bytes(b"artifact")
            profile = home / ".config/chimera/system-profile.toml"
            profile.parent.mkdir(parents=True)
            profile.write_text("profile", encoding="utf-8")
            config_module = __import__(
                "chimera.preprocess.offline.config", fromlist=["system_profile_path"]
            )
            with (
                patch.object(installation, "_release_resource", return_value=resource),
                patch.object(installation, "_check_release_compatibility"),
                patch.object(installation, "_release_identity", return_value="id"),
                patch.object(installation.Path, "home", return_value=home),
                patch.object(config_module, "system_profile_path", return_value=profile),
            ):
                installation.ensure_user_layout()
                toolchain.chmod(0o644)
                self.assertFalse(installation.release_initialized())
                installation.ensure_user_layout()
                self.assertTrue(toolchain.stat().st_mode & 0o111)
                self.assertTrue(installation.release_initialized())

    def test_release_executables_are_repaired_without_touching_other_files(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            clang = root / "toolchain/llvm/bin/clang-21"
            other = root / "toolchain/llvm/lib/libLLVM.so"
            sample = root / "examples/llamacpp/system/llama-perplexity"
            clang.parent.mkdir(parents=True)
            sample.parent.mkdir(parents=True)
            clang.write_bytes(b"clang")
            sample.write_bytes(b"elf")
            other.parent.mkdir(parents=True)
            other.write_bytes(b"library")
            with patch("chimera.installation.os.name", "posix"), patch.object(
                Path, "chmod"
            ) as chmod:
                _repair_executable_modes(root)
            self.assertEqual(chmod.call_count, 2)

    def test_existing_toolchain_only_receives_missing_files(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "bundled"
            destination = root / "installed"
            source.mkdir()
            destination.mkdir()
            (source / "clang").write_text("bundled", encoding="utf-8")
            (destination / "clang").write_text("user", encoding="utf-8")
            (source / "plugin.so").write_text("plugin", encoding="utf-8")
            with redirect_stderr(StringIO()) as error:
                _copy_missing_tree(source, destination)
            self.assertIn(str(destination / "clang"), error.getvalue())
            self.assertEqual((destination / "clang").read_text(encoding="utf-8"), "user")
            self.assertEqual((destination / "plugin.so").read_text(encoding="utf-8"), "plugin")

    def test_init_repairs_missing_managed_release_payload(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            destination = root / "installed"
            (source / "examples/llamacpp/system").mkdir(parents=True)
            (source / "examples/llamacpp/system/llama-perplexity").write_bytes(b"elf")
            destination.mkdir(parents=True)
            (destination / "release-config.json").write_text("{}", encoding="utf-8")
            _sync = installation._sync_managed_release_tree
            _sync(source, destination)
            self.assertEqual(
                (destination / "examples/llamacpp/system/llama-perplexity").read_bytes(),
                b"elf",
            )

    def test_flattened_toolchain_repairs_paths_declared_from_release_root(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            clang = root / "llvm/bin/clang-21"
            clang.parent.mkdir(parents=True)
            clang.write_bytes(b"clang")
            config = {"executable_files": ["toolchain/llvm/bin/clang-21"]}
            with patch("chimera.installation.os.name", "posix"), patch.object(
                Path, "chmod"
            ) as chmod:
                _repair_executable_modes(root, config=config)
            chmod.assert_called_once()

    def test_flattened_toolchain_does_not_touch_unmanaged_bin_entries(self) -> None:
        if os.name == "nt":
            self.skipTest("POSIX executable mode semantics are unavailable")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            clang = root / "llvm/bin/clang-21"
            helper = root / "llvm/bin/user-helper"
            clang.parent.mkdir(parents=True)
            clang.write_bytes(b"clang")
            helper.write_bytes(b"helper")
            helper.chmod(0o644)
            (clang.parent / "clang").symlink_to("clang-21")
            _repair_executable_modes(root, scan_bin=False)
            self.assertFalse(helper.stat().st_mode & 0o111)
            self.assertTrue(clang.stat().st_mode & 0o111)


if __name__ == "__main__":
    unittest.main()
