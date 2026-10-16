from __future__ import annotations

import tempfile
import unittest
import os
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import zipfile

from chimera.example_capabilities import HostCapabilities
from chimera.release_wheel import (
    _make_package_staging,
    _retag_wheel_platform,
    _validate_wheel_payload,
    _validate_existing_release_inputs,
    main as release_wheel_main,
)
from chimera.release import (
    artifact_requirements,
    discover_example_artifacts,
    inspect_artifacts,
    profile_build_tag,
    ensure_release_artifacts,
    write_manifest,
    discover_toolchain_artifacts,
    stage_existing_artifacts,
)
from chimera.release_wheel import _collect_toolchain_sources


class ReleaseWheelTests(unittest.TestCase):
    def test_toolchain_discovery_accepts_overall_root(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "backup"
            (root / "llvm/bin").mkdir(parents=True)
            (root / "plugins/lib/chimera/llvm").mkdir(parents=True)
            for name in ("clang", "clang++"):
                path = root / "llvm/bin" / name
                path.write_bytes(name.encode())
                path.chmod(0o755)
            for name in ("ChimeraStackObject.so", "ChimeraVectorGate.so"):
                (root / "plugins/lib/chimera/llvm" / name).write_bytes(name.encode())
            found = discover_toolchain_artifacts(root)
            self.assertEqual(found.llvm_root, (root / "llvm").resolve())
            self.assertEqual(found.plugins_root, (root / "plugins").resolve())
            self.assertEqual(found.issues, ())

    def test_toolchain_prompt_stages_overall_root_once(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            backup = Path(temporary) / "backup"
            release = Path(temporary) / "release"
            (backup / "llvm/bin").mkdir(parents=True)
            (backup / "plugins/lib/chimera/llvm").mkdir(parents=True)
            for name in ("clang", "clang++"):
                path = backup / "llvm/bin" / name
                path.write_bytes(name.encode())
                path.chmod(0o755)
            for name in ("ChimeraStackObject.so", "ChimeraVectorGate.so"):
                (backup / "plugins/lib/chimera/llvm" / name).write_bytes(name.encode())
            prompts: list[str] = []
            sources = _collect_toolchain_sources(
                release,
                Path(temporary) / "missing",
                input_fn=lambda prompt: prompts.append(prompt) or str(backup),
            )
            self.assertEqual(set(sources), {"llvm", "plugins"})
            self.assertEqual(len(prompts), 1)
            self.assertTrue((release / "toolchain/llvm/bin/clang").is_file())
            self.assertTrue(
                (release / "toolchain/plugins/lib/chimera/llvm/ChimeraVectorGate.so").is_file()
            )

    def test_toolchain_discovery_accepts_release_root_with_toolchain_child(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            release = Path(temporary) / "release"
            (release / "toolchain/llvm/bin").mkdir(parents=True)
            (release / "toolchain/plugins/lib/chimera/llvm").mkdir(parents=True)
            for name in ("clang", "clang++"):
                path = release / "toolchain/llvm/bin" / name
                path.write_bytes(name.encode())
                path.chmod(0o755)
            for name in ("ChimeraStackObject.so", "ChimeraVectorGate.so"):
                (release / "toolchain/plugins/lib/chimera/llvm" / name).write_bytes(name.encode())
            found = discover_toolchain_artifacts(release)
            self.assertEqual(found.llvm_root, (release / "toolchain/llvm").resolve())
            self.assertEqual(found.plugins_root, (release / "toolchain/plugins").resolve())

    def test_toolchain_prompt_accepts_separate_prefixes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            llvm = Path(temporary) / "llvm"
            plugins = Path(temporary) / "plugins"
            (llvm / "bin").mkdir(parents=True)
            (plugins / "lib/chimera/llvm").mkdir(parents=True)
            for name in ("clang", "clang++"):
                path = llvm / "bin" / name
                path.write_bytes(name.encode())
                path.chmod(0o755)
            for name in ("ChimeraStackObject.so", "ChimeraVectorGate.so"):
                (plugins / "lib/chimera/llvm" / name).write_bytes(name.encode())
            answers = iter((str(llvm), str(plugins)))
            prompts: list[str] = []
            sources = _collect_toolchain_sources(
                Path(temporary) / "release",
                Path(temporary) / "missing",
                input_fn=lambda prompt: prompts.append(prompt) or next(answers),
            )
            self.assertEqual(set(sources), {"llvm", "plugins"})
            self.assertEqual(len(prompts), 2)

    def test_toolchain_prompt_only_asks_missing_plugin_prefix(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            release = Path(temporary) / "release"
            llvm = release / "toolchain/llvm/bin"
            llvm.mkdir(parents=True)
            for name in ("clang", "clang++"):
                path = llvm / name
                path.write_bytes(name.encode())
                path.chmod(0o755)
            plugin = Path(temporary) / "plugins/lib/chimera/llvm"
            plugin.mkdir(parents=True)
            (plugin / "ChimeraStackObject.so").write_bytes(b"stack")
            (plugin / "ChimeraVectorGate.so").write_bytes(b"gate")
            prompts: list[str] = []
            _collect_toolchain_sources(
                release,
                Path(temporary) / "missing",
                input_fn=lambda prompt: prompts.append(prompt) or str(plugin.parents[2]),
            )
            self.assertEqual(len(prompts), 1)
            self.assertIn("插件", prompts[0])
            self.assertTrue((release / "toolchain/llvm/bin/clang").is_file())

    def test_toolchain_prompt_retries_invalid_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            plugin = Path(temporary) / "plugins/lib/chimera/llvm"
            plugin.mkdir(parents=True)
            (plugin / "ChimeraStackObject.so").write_bytes(b"stack")
            (plugin / "ChimeraVectorGate.so").write_bytes(b"gate")
            answers = iter(("", str(Path(temporary) / "not-a-toolchain"), str(plugin.parents[2])))
            prompts: list[str] = []
            _collect_toolchain_sources(
                Path(temporary) / "release",
                Path(temporary) / "missing",
                input_fn=lambda prompt: prompts.append(prompt) or next(answers),
            )
            self.assertEqual(len(prompts), 3)
            self.assertTrue(
                (Path(temporary) / "release/toolchain/plugins/lib/chimera/llvm/ChimeraStackObject.so").is_file()
            )

    def test_partial_plugin_prefix_is_accepted_for_missing_plugin(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            prefix = Path(temporary) / "plugin-prefix"
            plugin_dir = prefix / "lib/chimera/llvm"
            plugin_dir.mkdir(parents=True)
            (plugin_dir / "ChimeraVectorGate.so").write_bytes(b"gate")
            found = discover_toolchain_artifacts(prefix)
            self.assertIsNone(found.llvm_root)
            self.assertEqual(found.plugins_root, prefix.resolve())

    def test_partial_plugin_selection_preserves_previous_plugin(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            first = Path(temporary) / "first"
            second = Path(temporary) / "second"
            release = Path(temporary) / "release"
            for prefix, name in ((first, "ChimeraStackObject.so"), (second, "ChimeraVectorGate.so")):
                directory = prefix / "lib/chimera/llvm"
                directory.mkdir(parents=True)
                (directory / name).write_bytes(name.encode())
            answers = iter(("", str(first), str(second)))
            _collect_toolchain_sources(
                release,
                Path(temporary) / "missing",
                input_fn=lambda _prompt: next(answers),
            )
            plugin_dir = release / "toolchain/plugins/lib/chimera/llvm"
            self.assertTrue((plugin_dir / "ChimeraStackObject.so").is_file())
            self.assertTrue((plugin_dir / "ChimeraVectorGate.so").is_file())

    def test_bundle_with_only_plugins_keeps_them_when_llvm_is_requested(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            bundle = Path(temporary) / "bundle"
            plugin_dir = bundle / "plugins/lib/chimera/llvm"
            plugin_dir.mkdir(parents=True)
            (plugin_dir / "ChimeraStackObject.so").write_bytes(b"stack")
            answers = iter((str(bundle), "", ""))
            prompts: list[str] = []
            _collect_toolchain_sources(
                Path(temporary) / "release",
                Path(temporary) / "missing",
                input_fn=lambda prompt: prompts.append(prompt) or next(answers),
            )
            self.assertEqual(len(prompts), 3)
            self.assertTrue(
                (Path(temporary) / "release/toolchain/plugins/lib/chimera/llvm/ChimeraStackObject.so").is_file()
            )

    def test_toolchain_source_equal_to_destination_is_left_untouched(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            release = Path(temporary) / "release"
            clang = release / "toolchain/llvm/bin/clang"
            clang.parent.mkdir(parents=True)
            clang.write_bytes(b"clang")
            clang.chmod(0o755)
            before = clang.read_bytes()
            stage_existing_artifacts(
                release,
                toolchain_sources={"llvm": release / "toolchain/llvm"},
            )
            self.assertEqual(clang.read_bytes(), before)

    def test_selected_elf_equal_to_destination_is_left_untouched(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            release = Path(temporary) / "release"
            elf = release / "examples/llamacpp/system/llama-perplexity"
            elf.parent.mkdir(parents=True)
            elf.write_bytes(b"elf")
            stage_existing_artifacts(
                release,
                toolchain_sources={},
                example_paths={"system": elf},
            )
            self.assertEqual(elf.read_bytes(), b"elf")

    def test_external_toolchain_link_is_rejected_before_replacement(self) -> None:
        if os.name == "nt":
            self.skipTest("symlink creation is unavailable on this host")
        with tempfile.TemporaryDirectory() as temporary:
            outside = Path(temporary) / "outside"
            outside.mkdir()
            (outside / "clang-21").write_bytes(b"clang")
            source = Path(temporary) / "source"
            (source / "bin").mkdir(parents=True)
            (source / "bin/clang++").write_bytes(b"clang++")
            (source / "bin/clang").symlink_to(outside / "clang-21")
            with self.assertRaisesRegex(ValueError, "external or dangling"):
                stage_existing_artifacts(
                    Path(temporary) / "release",
                    toolchain_sources={"llvm": source},
                )

    def test_dangling_toolchain_link_is_rejected(self) -> None:
        if os.name == "nt":
            self.skipTest("symlink creation is unavailable on this host")
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "source"
            (source / "bin").mkdir(parents=True)
            (source / "bin/clang++").write_bytes(b"clang++")
            (source / "bin/clang").symlink_to("clang-21")
            with self.assertRaisesRegex(ValueError, "external or dangling"):
                stage_existing_artifacts(
                    Path(temporary) / "release",
                    toolchain_sources={"llvm": source},
                )
    @unittest.skip("application release components are no longer built by chimera-dev wheel")
    def test_reused_elfs_do_not_run_workflow_checks(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "tools").mkdir()
            (root / "tools/run_chimera.py").write_text("# runner")
            paths = []
            for kind in ("system", "remediated"):
                elf = root / "examples/llamacpp" / kind / "llama-perplexity"
                elf.parent.mkdir(parents=True)
                elf.write_bytes(b"existing input")
                paths.append(elf)
            inspection = SimpleNamespace(found=tuple(
                (path.relative_to(root).as_posix(), path) for path in paths
            ))
            with patch("chimera.release_wheel.inspect_artifacts", return_value=inspection), \
                 patch("chimera.release_wheel.validate_elf") as validate, \
                 patch("chimera.release_wheel._validate_llama_dependencies"), \
                 patch("chimera.release_wheel.subprocess.run", side_effect=AssertionError("packaging must not run check-elf")) as run:
                _validate_existing_release_inputs(root)
            run.assert_not_called()
            self.assertEqual(validate.call_count, 2)
            self.assertTrue(all(path.read_bytes() == b"existing input" for path in paths))
            self.assertFalse((root / ".diagnostics").exists())

    def test_package_staging_excludes_stale_workspace_and_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "artifacts"
            (root / "toolchain/llvm/bin").mkdir(parents=True)
            (root / "toolchain/llvm/bin/clang-21").write_bytes(b"clang")
            try:
                (root / "toolchain/llvm/bin/clang").symlink_to("clang-21")
            except OSError:
                self.skipTest("symlink creation is unavailable on this host")
            (root / "examples/llamacpp/system").mkdir(parents=True)
            (root / "examples/llamacpp/system/llama-perplexity").write_bytes(b"elf")
            (root / "release-config.json").write_text("{}", encoding="utf-8")
            (root / "manifest.json").write_text("stale", encoding="utf-8")
            (root / "toolchain/intermediate/build.ninja").parent.mkdir(parents=True)
            (root / "toolchain/intermediate/build.ninja").write_text("stale")
            (root / "workspace/registry.json").parent.mkdir()
            (root / "workspace/registry.json").write_text("stale", encoding="utf-8")
            staging = _make_package_staging(root)
            try:
                self.assertTrue((staging / "toolchain/llvm/bin/clang").is_symlink())
                self.assertTrue((staging / "release-config.json").is_file())
                self.assertFalse((staging / "manifest.json").exists())
                self.assertFalse((staging / "toolchain/intermediate").exists())
                self.assertFalse((staging / "workspace").exists())
            finally:
                import shutil
                shutil.rmtree(staging)

    def test_package_staging_excludes_application_elfs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "artifacts"
            (root / "examples/llamacpp/system").mkdir(parents=True)
            (root / "examples/llamacpp/remediated").mkdir(parents=True)
            (root / "examples/llamacpp/system/llama-perplexity").write_bytes(b"system")
            (root / "examples/llamacpp/system/llama-perplexity.check.json").write_text("{}")
            (root / "examples/llamacpp/remediated/llama-perplexity").write_bytes(b"fixed")
            (root / "examples/llamacpp/workspace/registry.json").parent.mkdir()
            (root / "examples/llamacpp/workspace/registry.json").write_text("stale")
            staging = _make_package_staging(root)
            try:
                self.assertFalse(
                    (staging / "examples/llamacpp/system/llama-perplexity").exists()
                )
                self.assertFalse(
                    (staging / "examples/llamacpp/remediated/llama-perplexity").exists()
                )
                self.assertFalse(
                    (staging / "examples/llamacpp/system/llama-perplexity.check.json").exists()
                )
                self.assertFalse((staging / "examples/llamacpp/workspace").exists())
            finally:
                import shutil
                shutil.rmtree(staging)

    def test_package_staging_prunes_llvm_development_files_and_model(self) -> None:
        if os.name == "nt":
            self.skipTest("release payload symlink semantics are POSIX-only")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "artifacts"
            bindir = root / "toolchain/llvm/bin"
            bindir.mkdir(parents=True)
            (bindir / "clang-21").write_bytes(b"clang")
            (bindir / "clang-21").chmod(0o755)
            (bindir / "opt").write_bytes(b"unused")
            (bindir / "llc").write_bytes(b"unused")
            (bindir / "clang").write_bytes(b"duplicate")
            (bindir / "clang++").write_bytes(b"duplicate")
            (bindir / "ld.lld").write_bytes(b"lld")
            (bindir / "ld.lld").chmod(0o755)
            (bindir / "lld").write_bytes(b"duplicate")
            (root / "toolchain/llvm/lib").mkdir(parents=True)
            (root / "toolchain/llvm/lib/libLLVMCore.a").write_bytes(b"dev")
            (root / "toolchain/llvm/lib/clang/21/include").mkdir(parents=True)
            (root / "toolchain/llvm/lib/clang/21/include/stddef.h").write_bytes(b"header")
            (root / "toolchain/plugins/lib/chimera/llvm").mkdir(parents=True)
            (root / "toolchain/plugins/lib/chimera/llvm/ChimeraStackObject.so").write_bytes(b"stack")
            (root / "toolchain/plugins/lib/chimera/llvm/ChimeraVectorGate.so").write_bytes(b"gate")
            (root / "toolchain/plugins/lib/chimera/llvm/libLLVMPluginSupport.so").write_bytes(b"dev")
            (root / "toolchain/plugins/CMakeLists.txt").write_text("dev", encoding="utf-8")
            (root / "examples/llamacpp/system").mkdir(parents=True)
            (root / "examples/llamacpp/system/llama-perplexity").write_bytes(b"system")
            (root / "examples/llamacpp/remediated").mkdir(parents=True)
            (root / "examples/llamacpp/remediated/llama-perplexity").write_bytes(b"fixed")
            (root / "examples/applications/llama-cpp/model").mkdir(parents=True)
            (root / "examples/applications/llama-cpp/model/tinyllama.gguf").write_bytes(b"model")
            (root / "release-config.json").write_text("{}", encoding="utf-8")
            staging = _make_package_staging(root)
            try:
                self.assertTrue((staging / "toolchain/llvm/bin/clang-21").is_file())
                self.assertTrue((staging / "toolchain/llvm/bin/clang").is_symlink())
                self.assertTrue((staging / "toolchain/llvm/bin/clang++").is_symlink())
                self.assertTrue((staging / "toolchain/llvm/bin/ld.lld").is_file())
                self.assertTrue((staging / "toolchain/llvm/bin/lld").is_symlink())
                self.assertTrue((staging / "toolchain/llvm/lib/clang/21/include/stddef.h").is_file())
                self.assertFalse((staging / "toolchain/llvm/bin/opt").exists())
                self.assertFalse((staging / "toolchain/llvm/bin/llc").exists())
                self.assertFalse((staging / "toolchain/llvm/lib/libLLVMCore.a").exists())
                self.assertFalse(
                    (staging / "toolchain/plugins/lib/chimera/llvm/libLLVMPluginSupport.so").exists()
                )
                self.assertFalse((staging / "toolchain/plugins/CMakeLists.txt").exists())
                self.assertFalse(list(staging.rglob("*.gguf")))
            finally:
                shutil.rmtree(staging)

    def test_runtime_install_excludes_gguf_model_files(self) -> None:
        cmake = Path("runtime/CMakeLists.txt").read_text(encoding="utf-8")
        self.assertIn('PATTERN "model" EXCLUDE', cmake)
        self.assertIn('PATTERN "*.gguf" EXCLUDE', cmake)

    def test_final_wheel_payload_rejects_models_and_llvm_development_archives(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            wheel = Path(temporary) / "payload.whl"
            with zipfile.ZipFile(wheel, "w") as archive:
                archive.writestr("chimera/release/examples/model.gguf", b"model")
                archive.writestr("chimera/release/toolchain/llvm/lib/libLLVMCore.a", b"dev")
                archive.writestr("chimera/toolchain_source/plugins/CMakeLists.txt", b"dev")
            with self.assertRaisesRegex(RuntimeError, "excluded payloads"):
                _validate_wheel_payload(wheel)

            runtime_wheel = Path(temporary) / "runtime.whl"
            with zipfile.ZipFile(runtime_wheel, "w") as archive:
                archive.writestr(
                    "chimera/release/toolchain/llvm/lib/clang/21/lib/linux/libclang_rt.a",
                    b"runtime",
                )
            _validate_wheel_payload(runtime_wheel)

    def test_package_staging_restores_executable_modes(self) -> None:
        if os.name == "nt":
            self.skipTest("POSIX executable mode semantics are unavailable")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "artifacts"
            clang = root / "toolchain/llvm/bin/clang-21"
            clang.parent.mkdir(parents=True)
            clang.write_bytes(b"clang")
            clang.chmod(0o644)
            clang_link = clang.parent / "clang"
            clang_link.symlink_to("clang-21")
            for component in ("system", "remediated"):
                elf = root / "examples/llamacpp" / component / "llama-perplexity"
                elf.parent.mkdir(parents=True, exist_ok=True)
                elf.write_bytes(b"elf")
                elf.chmod(0o644)
            staging = _make_package_staging(root)
            try:
                self.assertTrue((staging / "toolchain/llvm/bin/clang-21").stat().st_mode & 0o111)
                for component in ("system", "remediated"):
                    self.assertTrue(
                        (staging / "examples/llamacpp" / component / "llama-perplexity")
                        .stat().st_mode & 0o111
                    )
            finally:
                import shutil
                shutil.rmtree(staging)

    @unittest.skip("llama.cpp is not part of the system wheel")
    def test_release_elf_rejects_build_tree_llama_dependencies(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            elf = Path(temporary) / "llama-perplexity"
            header = bytearray(20)
            header[:4] = b"\x7fELF"
            elf.write_bytes(header)
            completed = SimpleNamespace(
                returncode=0,
                stdout=" 0x0000000000000001 (NEEDED) Shared library: [libllama.so]",
            )
            with (
                patch("chimera.release_wheel.shutil.which", return_value="readelf"),
                patch("chimera.release_wheel.subprocess.run", return_value=completed),
            ):
                with self.assertRaisesRegex(RuntimeError, "libllama.so"):
                    _validate_llama_dependencies(elf)

    @unittest.skip("wheel publication no longer consumes application Profiles")
    def test_release_build_rejects_incompatible_host_before_artifact_discovery(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            profile = Path(temporary) / "profile.toml"
            profile.write_text("placeholder", encoding="utf-8")
            profile_data = SimpleNamespace(
                target_os="linux", target_arch="riscv64", target_arch_extension="rvv"
            )
            with (
                patch("chimera.release_wheel.load_configuration", return_value=SimpleNamespace(profile=profile_data)),
                patch(
                    "chimera.release_wheel.detect_host_capabilities",
                    return_value=HostCapabilities("linux", "x86_64", False),
                ),
            ):
                self.assertEqual(release_wheel_main(["--profile", str(profile)]), 1)

    def test_retagged_wheel_updates_platform_metadata_and_record(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            wheel = Path(temporary) / "chimera-1.0.0-py3-none-any.whl"
            with zipfile.ZipFile(wheel, "w") as archive:
                archive.writestr("chimera/__init__.py", b"value")
                archive.writestr(
                    "chimera-1.0.0.dist-info/WHEEL",
                    "Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
                )
                archive.writestr("chimera-1.0.0.dist-info/RECORD", "")
            _retag_wheel_platform(wheel, "linux_riscv64")
            with zipfile.ZipFile(wheel) as archive:
                wheel_text = archive.read("chimera-1.0.0.dist-info/WHEEL").decode()
                record_text = archive.read("chimera-1.0.0.dist-info/RECORD").decode()
            self.assertIn("Root-Is-Purelib: false", wheel_text)
            self.assertIn("Tag: py3-none-linux_riscv64", wheel_text)
            self.assertIn("chimera/__init__.py,sha256=", record_text)
            self.assertIn("chimera-1.0.0.dist-info/WHEEL,sha256=", record_text)
            self.assertTrue(record_text.endswith("chimera-1.0.0.dist-info/RECORD,,\n"))

    @unittest.skip("wheel identity no longer includes an application Profile")
    def test_profile_build_tag_is_wheel_safe_and_descriptive(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            profile = Path(temporary) / "profile.toml"
            profile.write_text(
                "[config]\nworkspace_root='w'\n[profile]\n"
                "name='linux-riscv64-rvv-1024-to-256'\n"
                "target_os='linux'\ntarget_arch='riscv64'\n"
                "target_arch_extension='rvv'\nruntime_scene='linux_riscv64_rvv_v1'\n"
                "runtime_abi=1\n[profile.workflow]\nsteps=[]\n",
                encoding="utf-8",
            )
            tag = profile_build_tag(profile)
            self.assertRegex(tag, r"^1linux_riscv64_rvv_linux_riscv64_rvv_v1_linux_riscv64_rvv_1024_to_256_[A-Za-z0-9_]+$")

    def test_files_are_reusable_without_release_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for relative in artifact_requirements():
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b"artifact")
                if path.name in {"clang", "clang++"}:
                    path.chmod(path.stat().st_mode | 0o111)
            self.assertTrue(inspect_artifacts(root).ready)

    def test_partial_release_reports_only_missing_binaries(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for relative in artifact_requirements()[:-2]:
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b"artifact")
                if path.name in {"clang", "clang++"}:
                    path.chmod(path.stat().st_mode | 0o111)
            result = inspect_artifacts(root)
            self.assertFalse(result.ready)
            self.assertEqual(
                {item.component for item in result.missing},
                {"StackObject plugin", "VectorGate plugin"},
            )

    def test_discovery_uses_exact_delivery_roles(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            system = root / "prebuilt" / "system" / "llama-perplexity"
            remediated = root / "build-remediated" / "bin" / "llama-perplexity"
            system.parent.mkdir(parents=True)
            remediated.parent.mkdir(parents=True)
            system.write_bytes(b"system")
            remediated.write_bytes(b"remediated")
            self.assertEqual(
                discover_example_artifacts(roots=(root,)),
                {"system": system.resolve(), "remediated": remediated.resolve()},
            )

    def test_discovery_reuses_main_delivery_as_remediated(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            delivered = root / "main" / "llama-perplexity"
            delivered.parent.mkdir(parents=True)
            delivered.write_bytes(b"remediated")
            self.assertEqual(
                discover_example_artifacts(roots=(root,)),
                {"remediated": delivered.resolve()},
            )

    def test_discovery_checks_nested_llama_checkout_builds(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            system = root / "llama.cpp" / "build-vanilla" / "bin" / "llama-perplexity"
            remediated = root / "llama.cpp" / "build-remediated" / "bin" / "llama-perplexity"
            system.parent.mkdir(parents=True)
            remediated.parent.mkdir(parents=True)
            system.write_bytes(b"system")
            remediated.write_bytes(b"remediated")
            self.assertEqual(
                discover_example_artifacts(roots=(root,)),
                {"system": system.resolve(), "remediated": remediated.resolve()},
            )

    def test_missing_artifacts_require_confirmation_before_builder(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            profile = Path(temporary) / "profile.toml"
            profile.write_text(
                "[config]\nworkspace_root='w'\n[profile]\nname='x'\n"
                "target_os='linux'\ntarget_arch='riscv64'\ntarget_arch_extension='rvv'\n"
                "runtime_scene='linux_riscv64_rvv_v1'\nruntime_abi=1\n"
                "[profile.workflow]\nsteps=[]\n",
                encoding="utf-8",
            )
            called = []
            def builder() -> int:
                called.append(True)
                for relative in artifact_requirements():
                    path = root / relative
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(b"artifact")
                write_manifest(root, profile=profile)
                return 0
            result = ensure_release_artifacts(
                profile, root=root, builder=builder, input_fn=lambda _: "y"
            )
            self.assertEqual(result, root.resolve())
            self.assertEqual(called, [True])

    @unittest.skip("application release components are no longer built by chimera-dev wheel")
    def test_component_builder_receives_only_missing_components(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            profile = Path(temporary) / "profile.toml"
            profile.write_text(
                "[config]\nworkspace_root='w'\n[profile]\nname='x'\n"
                "target_os='linux'\ntarget_arch='riscv64'\ntarget_arch_extension='rvv'\n"
                "runtime_scene='linux_riscv64_rvv_v1'\nruntime_abi=1\n"
                "[profile.workflow]\nsteps=[]\n",
                encoding="utf-8",
            )
            for relative in artifact_requirements()[:-1]:
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b"artifact")
                if path.name in {"clang", "clang++"}:
                    path.chmod(path.stat().st_mode | 0o111)
            received = []

            def builder(components):
                received.extend(components)
                path = root / artifact_requirements()[-1]
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b"artifact")
                return 0

            ensure_release_artifacts(
                profile, root=root, builder=builder, input_fn=lambda _: "y"
            )
            self.assertEqual(received, ["remediated llama.cpp ELF"])

    @unittest.skip("application release components are no longer built by chimera-dev wheel")
    def test_release_component_builder_never_dispatches_full_example_build(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "release-artifacts"
            profile = Path(temporary) / "profile.toml"
            profile.write_text(
                "[config]\nworkspace_root='w'\n[profile]\nname='x'\n"
                "target_os='linux'\ntarget_arch='riscv64'\ntarget_arch_extension='rvv'\n"
                "runtime_scene='linux_riscv64_rvv_v1'\nruntime_abi=1\n"
                "[profile.workflow]\nsteps=[]\n",
                encoding="utf-8",
            )
            script = Path(temporary) / "build_llamacpp.sh"
            script.write_text("#!/bin/sh\n", encoding="utf-8")
            calls = []

            def run(command, **kwargs):
                calls.append((command, kwargs))
                if "env" not in kwargs:
                    return SimpleNamespace(returncode=0, stdout="")
                output = Path(kwargs["env"]["CHIMERA_RELEASE_OUTPUT"])
                output.parent.mkdir(parents=True, exist_ok=True)
                header = bytearray(20)
                header[:4] = b"\x7fELF"
                header[4] = 2
                header[5] = 1
                header[18:20] = (243).to_bytes(2, "little")
                output.write_bytes(header)
                return SimpleNamespace(returncode=0)

            with patch("chimera.release_wheel.subprocess.run", side_effect=run):
                self.assertEqual(
                    build_release_components(
                        profile,
                        root=root,
                        components=("system", "remediated"),
                        script=script,
                    ),
                    0,
                )

            script_calls = [call for call in calls if "env" in call[1]]
            self.assertEqual(len(script_calls), 2)
            for _, options in script_calls:
                self.assertEqual(
                    options["env"].get("CHIMERA_EXAMPLE_DISPATCH_ROOT"),
                    str(options["cwd"]),
                    "release builds must pass the same checkout binding as example dispatch",
                )
            self.assertTrue(all("example" not in call[0] for call in script_calls))
            self.assertEqual(
                [call[1]["env"]["CHIMERA_RELEASE_COMPONENT"] for call in script_calls],
                ["system", "remediated"],
            )
            self.assertEqual(
                [call[1]["env"]["CHIMERA_RELEASE_OUTPUT"] for call in script_calls],
                [
                    str(root / "examples" / "llamacpp" / "system" / "llama-perplexity"),
                    str(root / "examples" / "llamacpp" / "remediated" / "llama-perplexity"),
                ],
            )



if __name__ == "__main__":
    unittest.main()
