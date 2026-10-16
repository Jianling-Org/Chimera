from __future__ import annotations

import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

import chimera.toolchain as toolchain_module
from chimera.cli import build_parser
from chimera.toolchain import (
    build_llvm_plugin,
    build_svf,
    llvm_build_dir,
    plugin_build_dir,
    resolve_build_root,
    resolve_llvm_src,
    resolve_svf_src,
    svf_build_dir,
    third_party_root,
    toolchain_build_root,
    toolchain_source_root,
    clean_patched_llvm,
)


def _mock_files(monkey: Path):
    return mock.patch.object(
        toolchain_module.importlib.resources, "files", return_value=monkey
    )


class ToolchainSourceRootTests(unittest.TestCase):
    def test_clean_aborts_real_am_without_user_git_identity(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            llvm = root / "llvm"
            llvm.mkdir()
            config = root / "gitconfig"
            config.write_text("[user]\n\tuseConfigOnly = true\n", encoding="utf-8")
            environment = {
                key: value for key, value in os.environ.items()
                if not key.startswith(("GIT_", "EMAIL"))
            }
            environment.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=str(config))
            with mock.patch.dict(os.environ, environment, clear=True):
                def git(*args):
                    return subprocess.run(
                        ["git", "-C", str(llvm), *args], check=True,
                        capture_output=True, text=True,
                    ).stdout

                git("init")
                tracked = llvm / "tracked.txt"
                tracked.write_text("base\n", encoding="utf-8")
                git("add", ".")
                git(*toolchain_module.GIT_AM_IDENTITY, "commit", "-m", "base")
                git(*toolchain_module.GIT_AM_IDENTITY, "tag", "-a",
                    toolchain_module.LLVM_TAG, "-m", "annotated LLVM release")
                tracked.write_text("patched\n", encoding="utf-8")
                git("add", ".")
                git(*toolchain_module.GIT_AM_IDENTITY, "commit", "-m", "patch")
                patch_text = git("format-patch", "-1", "--stdout")
                git("reset", "--hard", toolchain_module.LLVM_TAG)
                patch_file = root / "broken.patch"
                patch_file.write_text(patch_text.replace("-base\n", "-missing\n"), encoding="utf-8")
                failed = subprocess.run(
                    ["git", "-C", str(llvm), *toolchain_module.GIT_AM_IDENTITY,
                     "am", str(patch_file)], capture_output=True, text=True,
                )
                self.assertNotEqual(failed.returncode, 0)
                self.assertTrue(toolchain_module._llvm_am_in_progress(llvm))
                build = llvm / "build_patched"
                build.mkdir()
                clean_patched_llvm(llvm)
                self.assertFalse(toolchain_module._llvm_am_in_progress(llvm))
                self.assertEqual(git("status", "--porcelain"), "")
                self.assertEqual(tracked.read_text(encoding="utf-8"), "base\n")
                self.assertFalse(build.exists())
                # A release tag object differs from the commit it points to.
                self.assertNotEqual(git("rev-parse", "HEAD"), git("rev-parse", toolchain_module.LLVM_TAG))
                toolchain_module._require_clean_llvm_checkout(llvm)
                git(*toolchain_module.GIT_AM_IDENTITY, "commit", "--allow-empty", "-m", "unexpected commit")
                with self.assertRaisesRegex(ValueError, "not at pristine"):
                    toolchain_module._require_clean_llvm_checkout(llvm)

    def test_clean_toolchain_command_parses_explicit_llvm_source(self) -> None:
        parsed = build_parser().parse_args(
            ["toolchain", "clean", "patched-llvm", "--llvm-src", "/tmp/llvm"]
        )
        self.assertEqual(parsed.command, "toolchain")
        self.assertEqual(parsed.toolchain_action, "clean")
        self.assertEqual(parsed.target, "patched-llvm")
        self.assertEqual(parsed.llvm_src, Path("/tmp/llvm"))

    def _make_tree(self, temporary: Path, *, bundled: bool, with_third_party: bool) -> None:
        if bundled:
            plugins = temporary / "toolchain_source" / "plugins"
        else:
            plugins = (
                temporary / "preprocessing" / "offline" / "toolchain"
                / "llvm-21.1.0" / "plugins"
            )
        plugins.mkdir(parents=True)
        (plugins / "CMakeLists.txt").write_text("# cmake\n", encoding="utf-8")
        if with_third_party:
            (temporary / "third_party" / "llvm").mkdir(parents=True)

    def test_bundled_wheel_toolchain_source_is_used(self) -> None:
        # A built wheel ships the patch/plugin tree under toolchain_source/.
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self._make_tree(root, bundled=True, with_third_party=False)
            with _mock_files(root):
                self.assertEqual(toolchain_source_root(), root / "toolchain_source")

    def test_editable_checkout_toolchain_source_is_used(self) -> None:
        # An editable install exposes the repository root through the finder,
        # so the checkout modify-root is directly reachable.
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self._make_tree(root, bundled=False, with_third_party=False)
            with _mock_files(root):
                self.assertEqual(
                    toolchain_source_root(),
                    root / "preprocessing" / "offline" / "toolchain" / "llvm-21.1.0",
                )

    def test_missing_toolchain_source_raises(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            with _mock_files(Path(temporary)):
                with self.assertRaisesRegex(
                    FileNotFoundError, "toolchain source bundle is not installed"
                ):
                    toolchain_source_root()

    def test_clean_patched_llvm_resets_source_and_removes_build_tree(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            llvm = root / "llvm"
            llvm.mkdir()
            build = root / "build-root" / "llvm"
            build.mkdir(parents=True)
            commands: list[list[str]] = []

            def fake_run(command, **kwargs):
                commands.append([str(part) for part in command])
                if command[:2] == ["git", "-C"] and command[3:5] == ["rev-parse", "--git-dir"]:
                    return subprocess.CompletedProcess(command, 0, ".git\n", "")
                if command[:2] == ["git", "-C"] and command[3:5] == ["tag", "--list"]:
                    return subprocess.CompletedProcess(command, 0, toolchain_module.LLVM_TAG + "\n", "")
                if command[:2] == ["git", "-C"] and command[3:5] == ["rev-parse", "HEAD"]:
                    return subprocess.CompletedProcess(command, 0, "head\n", "")
                return subprocess.CompletedProcess(command, 0, "", "")

            with mock.patch.object(toolchain_module.subprocess, "run", side_effect=fake_run), \
                 mock.patch.object(toolchain_module.shutil, "rmtree") as rmtree:
                clean_patched_llvm(llvm, build_root=root / "build-root")

            self.assertTrue(any("reset" in command and "--hard" in command for command in commands))
            rmtree.assert_called_once_with(build)

    def test_third_party_root_is_used_and_missing_raises(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "third_party").mkdir()
            with _mock_files(root):
                self.assertEqual(third_party_root(), root / "third_party")

        with tempfile.TemporaryDirectory() as temporary:
            with _mock_files(Path(temporary)):
                with self.assertRaisesRegex(
                    FileNotFoundError, "third-party bundle is not installed"
                ):
                    third_party_root()

    def test_resolve_defaults_fall_back_to_third_party(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            third = root / "third_party"
            (third / "llvm").mkdir(parents=True)
            (third / "SVF").mkdir()
            with _mock_files(root):
                self.assertEqual(resolve_llvm_src(None), third / "llvm")
                self.assertEqual(resolve_svf_src(None), third / "SVF")

    def test_build_dirs_default_to_per_source_locations(self) -> None:
        root = Path("/src")
        self.assertEqual(
            llvm_build_dir(None, root / "llvm"), root / "llvm" / "build_patched"
        )
        self.assertEqual(svf_build_dir(None, root / "SVF"), root / "SVF" / "build")
        self.assertEqual(
            plugin_build_dir(None, root / "chimera"), root / "chimera" / "build-riscv"
        )

    def test_build_root_overrides_all_build_dirs(self) -> None:
        root = Path("/src")
        build_root = Path("/scratch")
        self.assertEqual(
            llvm_build_dir(build_root, root / "llvm"), build_root / "llvm"
        )
        self.assertEqual(svf_build_dir(build_root, root / "SVF"), build_root / "svf")
        self.assertEqual(
            plugin_build_dir(build_root, root / "chimera"), build_root / "plugins"
        )

    def test_resolve_build_root_prefers_flag_then_env(self) -> None:
        explicit = Path("/explicit-build")
        with mock.patch.dict(
            "os.environ", {"CHIMERA_BUILD_ROOT": "/env-build"}, clear=False
        ):
            self.assertEqual(resolve_build_root(explicit), explicit)
            self.assertEqual(resolve_build_root(None), Path("/env-build"))
        os.environ.pop("CHIMERA_BUILD_ROOT", None)
        self.assertIsNone(resolve_build_root(None))

    def test_resolve_prefers_flag_then_env_then_default(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            third = root / "third_party"
            (third / "llvm").mkdir(parents=True)
            explicit = root / "explicit-llvm"
            explicit.mkdir()
            with _mock_files(root), mock.patch.dict(
                "os.environ", {"CHIMERA_LLVM_SRC": str(root / "env-llvm")}
            ):
                self.assertEqual(resolve_llvm_src(explicit), explicit)
                self.assertEqual(resolve_llvm_src(None), root / "env-llvm")


class BuildToolchainCliTests(unittest.TestCase):
    def test_parser_accepts_each_target(self) -> None:
        parser = build_parser()
        for target in ("patched-llvm", "llvm-plugin", "svf"):
            arguments = parser.parse_args(["toolchain", "build", target])
            self.assertEqual(arguments.target, target)

    def test_parser_requires_exactly_one_target(self) -> None:
        with self.assertRaises(SystemExit):
            build_parser().parse_args(["toolchain", "build"])

    def test_parser_rejects_unknown_target(self) -> None:
        with self.assertRaises(SystemExit):
            build_parser().parse_args(["toolchain", "build", "all"])

    def test_parser_plugins_selection(self) -> None:
        parser = build_parser()
        arguments = parser.parse_args(["toolchain", "build", "llvm-plugin"])
        self.assertIsNone(arguments.plugins)
        arguments = parser.parse_args(
            ["toolchain", "build", "llvm-plugin", "--plugins", "stackobject"]
        )
        self.assertEqual(arguments.plugins, ["stackobject"])
        with self.assertRaises(SystemExit):
            parser.parse_args(["toolchain", "build", "llvm-plugin", "--plugins", "bogus"])

    def test_build_llvm_plugin_rejects_unknown_plugin(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with self.assertRaisesRegex(ValueError, "unknown plugins"):
                build_llvm_plugin(
                    root / "llvm", root / "svf", root / "plugins", ("bogus",)
                )

    def test_parser_full_flag(self) -> None:
        parser = build_parser()
        arguments = parser.parse_args(["toolchain", "build", "patched-llvm"])
        self.assertFalse(arguments.full)
        arguments = parser.parse_args(["toolchain", "build", "patched-llvm", "--full"])
        self.assertTrue(arguments.full)

    def test_llvm_library_components_from_built_archives(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            build = Path(temporary)
            (build / "lib").mkdir()
            (build / "lib" / "libLLVMCore.a").touch()
            (build / "lib" / "libLLVMSupport.a").touch()
            (build / "lib" / "libLLVM.so.21.1").touch()
            self.assertEqual(
                toolchain_module._llvm_library_components(build),
                ["LLVMCore", "LLVMSupport"],
            )

    def test_svf_rejects_directory_without_source(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bad = root / "not-svf"
            bad.mkdir()
            with self.assertRaisesRegex(ValueError, "SVF source checkout not found"):
                build_svf(bad, root / "llvm-prefix", root / "svf-prefix")

    def test_sanitize_llvm_exports_strips_missing_file_checks(self) -> None:
        # The minimal install omits targets the export set still references;
        # the trailing existence-check loop must go or find_package() fails.
        with tempfile.TemporaryDirectory() as temporary:
            prefix = Path(temporary)
            cmake_dir = prefix / "lib" / "cmake" / "llvm"
            cmake_dir.mkdir(parents=True)
            exports = cmake_dir / "LLVMExports.cmake"
            exports.write_text(
                "add_library(LLVMSupport STATIC IMPORTED)\n"
                "set(_cmake_import_check_files_for_LLVMSupport"
                " \"${_IMPORT_PREFIX}/lib/libLLVMSupport.a\" )\n"
                "# Loop over all imported files and verify that they"
                " actually exist\n"
                "foreach(_cmake_target IN LISTS _cmake_import_check_targets)\n"
                "  message(FATAL_ERROR \"missing file\")\n"
                "endforeach()\n"
                "unset(_cmake_import_check_targets)\n",
                encoding="utf-8",
            )
            untouched = cmake_dir / "LLVMConfig.cmake"
            untouched.write_text("# untouched\n", encoding="utf-8")

            toolchain_module._sanitize_cmake_exports(prefix)

            sanitized = exports.read_text(encoding="utf-8")
            self.assertIn("add_library(LLVMSupport STATIC IMPORTED)", sanitized)
            self.assertNotIn("FATAL_ERROR", sanitized)
            self.assertNotIn("_cmake_import_check_targets", sanitized)
            self.assertIn("existence checks stripped", sanitized)
            self.assertEqual(untouched.read_text(encoding="utf-8"), "# untouched\n")

    def test_svf_configure_disables_warn_as_error(self) -> None:
        # SVF defaults SVF_WARN_AS_ERROR=ON; newer compilers break the pinned
        # source with new diagnostics (GCC 15 unused-variable errors).
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            svf_src = root / "svf-src"
            svf_src.mkdir()
            (svf_src / "CMakeLists.txt").write_text("# svf\n", encoding="utf-8")
            llvm_prefix = root / "llvm-prefix"
            (llvm_prefix / "lib" / "cmake" / "llvm").mkdir(parents=True)

            commands: list[list[str]] = []
            with mock.patch.object(
                toolchain_module, "_git_ok",
                return_value=subprocess.CompletedProcess(
                    args=[], returncode=0, stdout="", stderr=""
                ),
            ), mock.patch.object(
                toolchain_module, "_run",
                side_effect=lambda command, **kwargs: commands.append(
                    [str(part) for part in command]
                ),
            ):
                build_svf(svf_src, llvm_prefix, root / "svf-prefix")

            configure = next(command for command in commands if "cmake" in command)
            self.assertIn("-DSVF_WARN_AS_ERROR=OFF", configure)

    def test_svf_build_enforces_pinned_commit(self) -> None:
        # Like LLVM, the SVF checkout is forced to the pinned commit before
        # building instead of adapting to whatever version is checked out.
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            svf_src = root / "svf-src"
            svf_src.mkdir()
            (svf_src / "CMakeLists.txt").write_text("# svf\n", encoding="utf-8")
            llvm_prefix = root / "llvm-prefix"
            (llvm_prefix / "lib" / "cmake" / "llvm").mkdir(parents=True)

            commands: list[list[str]] = []
            with mock.patch.object(
                toolchain_module, "_git_ok",
                return_value=subprocess.CompletedProcess(
                    args=[], returncode=0, stdout="", stderr=""
                ),
            ), mock.patch.object(
                toolchain_module, "_run",
                side_effect=lambda command, **kwargs: commands.append(
                    [str(part) for part in command]
                ),
            ):
                build_svf(svf_src, llvm_prefix, root / "svf-prefix")

            checkout = commands[0]
            self.assertEqual(
                checkout[:2], ["git", "checkout"]
            )
            self.assertIn(toolchain_module.SVF_COMMIT, checkout)

    def test_svf_applies_chimera_patches_and_restores_pristine(self) -> None:
        # Chimera SVF patches (svf-patches/*.patch) are applied after the
        # pinned checkout and the tree is reset to the pinned commit after
        # the install, so the submodule never stays dirty.
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            svf_src = root / "svf-src"
            svf_src.mkdir()
            (svf_src / "CMakeLists.txt").write_text("# svf\n", encoding="utf-8")
            llvm_prefix = root / "llvm-prefix"
            (llvm_prefix / "lib" / "cmake" / "llvm").mkdir(parents=True)
            source_root = root / "toolchain-src"
            patch_dir = source_root / "svf-patches"
            patch_dir.mkdir(parents=True)
            patch = patch_dir / "0001-example.patch"
            patch.write_text("diff --git a/x b/x\n", encoding="utf-8")

            commands: list[list[str]] = []
            with mock.patch.object(
                toolchain_module, "_git_ok",
                return_value=subprocess.CompletedProcess(
                    args=[], returncode=0, stdout="", stderr=""
                ),
            ), mock.patch.object(
                toolchain_module, "_run",
                side_effect=lambda command, **kwargs: commands.append(
                    [str(part) for part in command]
                ),
            ), mock.patch.object(
                toolchain_module, "toolchain_source_root",
                return_value=source_root,
            ):
                build_svf(svf_src, llvm_prefix, root / "svf-prefix")

            checkout = commands[0]
            self.assertEqual(checkout[:2], ["git", "checkout"])
            apply = next(
                command for command in commands if command[:2] == ["git", "apply"]
            )
            self.assertIn(str(patch), apply)
            self.assertLess(commands.index(checkout), commands.index(apply))
            reset = commands[-1]
            self.assertEqual(reset[:3], ["git", "reset", "--hard"])
            self.assertIn(toolchain_module.SVF_COMMIT, reset)

    def test_svf_checkout_rejected_when_dirty_or_missing_commit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            svf_src = Path(temporary)

            def fake_git_ok_missing(src: Path, *arguments: str):
                returncode = 1 if arguments[0] == "cat-file" else 0
                return subprocess.CompletedProcess(
                    args=list(arguments), returncode=returncode,
                    stdout="", stderr="",
                )

            with mock.patch.object(
                toolchain_module, "_git_ok", side_effect=fake_git_ok_missing
            ):
                with self.assertRaisesRegex(ValueError, "pinned commit"):
                    toolchain_module._require_clean_svf_checkout(svf_src)

            def fake_git_ok_dirty(src: Path, *arguments: str):
                stdout = " M file" if arguments[0] == "status" else ""
                return subprocess.CompletedProcess(
                    args=list(arguments), returncode=0, stdout=stdout, stderr=""
                )

            with mock.patch.object(
                toolchain_module, "_git_ok", side_effect=fake_git_ok_dirty
            ):
                with self.assertRaisesRegex(ValueError, "uncommitted changes"):
                    toolchain_module._require_clean_svf_checkout(svf_src)

    def test_build_all_llvm_libraries_builds_only_missing_archives(self) -> None:
        # Downstream export sets bake LLVM's full link closure into their
        # install checks; every libLLVM*.a must exist in the prefix.
        with tempfile.TemporaryDirectory() as temporary:
            build = Path(temporary)
            (build / "lib").mkdir()
            (build / "lib" / "libLLVMCore.a").touch()

            def fake_run(command, **kwargs):
                if "-t" in command:
                    return subprocess.CompletedProcess(
                        args=command,
                        returncode=0,
                        stdout=(
                            "lib/libLLVMCore.a: phony\n"
                            "lib/libLLVMTableGenBasic.a: phony\n"
                            "bin/opt: phony\n"
                        ),
                        stderr="",
                    )
                raise AssertionError(f"unexpected command: {command}")

            builds: list[list[str]] = []
            with mock.patch.object(
                toolchain_module.subprocess, "run", side_effect=fake_run
            ), mock.patch.object(
                toolchain_module, "_run",
                side_effect=lambda command, **kwargs: builds.append(command),
            ):
                toolchain_module._build_all_llvm_libraries(build)

            self.assertEqual(len(builds), 1)
            self.assertIn("lib/libLLVMTableGenBasic.a", builds[0])
            self.assertNotIn("lib/libLLVMCore.a", builds[0])

            with mock.patch.object(
                toolchain_module.subprocess, "run", side_effect=fake_run
            ), mock.patch.object(
                toolchain_module, "_run",
                side_effect=lambda command, **kwargs: builds.append(command),
            ):
                (build / "lib" / "libLLVMTableGenBasic.a").touch()
                toolchain_module._build_all_llvm_libraries(build)
            self.assertEqual(len(builds), 1)  # nothing new to build

    def test_install_components_fails_when_archive_missing_from_prefix(self) -> None:
        # The prefix must contain every built archive; a silently skipped
        # component resurfaces later as a downstream find_package() failure.
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            build = root / "build"
            (build / "lib").mkdir(parents=True)
            (build / "lib" / "libLLVMTableGenBasic.a").touch()
            prefix = root / "prefix"
            (prefix / "lib").mkdir(parents=True)
            with mock.patch.object(
                toolchain_module, "_run", side_effect=lambda *a, **k: None
            ):
                with self.assertRaisesRegex(RuntimeError, "libLLVMTableGenBasic"):
                    toolchain_module._install_llvm_components(build, prefix)
                # Once the archive lands in the prefix, install succeeds.
                (prefix / "lib" / "libLLVMTableGenBasic.a").touch()
                toolchain_module._install_llvm_components(build, prefix)

    def test_install_components_fails_when_tool_binary_missing(self) -> None:
        # llvm-readelf is a symlink alias of llvm-readobj; an install whose
        # component list skips llvm-readobj leaves bin/llvm-readelf dangling.
        # Tool binaries must be verified just like library archives.
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            build = root / "build"
            (build / "lib").mkdir(parents=True)
            (build / "cmake_install.cmake").write_text(
                'if(CMAKE_INSTALL_COMPONENT STREQUAL "llvm-readobj")\nendif()\n',
                encoding="utf-8",
            )
            prefix = root / "prefix"
            (prefix / "bin").mkdir(parents=True)
            with mock.patch.object(
                toolchain_module, "_run", side_effect=lambda *a, **k: None
            ):
                with self.assertRaisesRegex(RuntimeError, "llvm-readobj"):
                    toolchain_module._install_llvm_components(build, prefix)
                (prefix / "bin" / "llvm-readobj").touch()
                toolchain_module._install_llvm_components(build, prefix)

    def test_patched_llvm_git_am_carries_deterministic_identity(self) -> None:
        # git am creates commits; the build must not depend on the user's
        # global git identity (rootless CI containers often lack one).
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "toolchain_source"
            (source / "plugins").mkdir(parents=True)
            (source / "plugins" / "CMakeLists.txt").write_text(
                "# cmake\n", encoding="utf-8"
            )
            (source / "patches").mkdir()
            (source / "patches" / "0001-x.patch").write_text(
                "patch\n", encoding="utf-8"
            )
            llvm_src = root / "llvm-src"
            llvm_src.mkdir()
            vectorize_dir = (
                llvm_src / "llvm" / "lib" / "Transforms" / "Vectorize"
            )
            vectorize_dir.mkdir(parents=True)
            utils_dir = (
                llvm_src / "llvm" / "lib" / "Transforms" / "Utils"
            )
            utils_dir.mkdir(parents=True)
            lv_signature = (
                "PreservedAnalyses LoopVectorizePass::run(Function &F,\n"
                "                                         FunctionAnalysisManager &AM) {"
            )
            slp_signature = (
                # 与 llvmorg-21.1.0 真实源码一致：SLP 是单行签名
                "PreservedAnalyses SLPVectorizerPass::run(Function &F, "
                "FunctionAnalysisManager &AM) {"
            )
            # 与 llvmorg-21.1.0 真实源码一致的主工作入口签名
            inline_signature = (
                "llvm::InlineResult llvm::InlineFunction(CallBase &CB, "
                "InlineFunctionInfo &IFI,\n"
                "                                        bool MergeAttributes,\n"
                "                                        AAResults *CalleeAAR,\n"
                "                                        bool InsertLifetime,\n"
                "                                        Function *ForwardVarArgsTo,\n"
                "                                        OptimizationRemarkEmitter *ORE) {\n"
                "  assert(CB.getParent() && CB.getFunction() && "
                "\"Instruction not in function!\");"
            )
            (vectorize_dir / "LoopVectorize.cpp").write_text(
                lv_signature + "\n", encoding="utf-8"
            )
            (vectorize_dir / "SLPVectorizer.cpp").write_text(
                slp_signature + "\n", encoding="utf-8"
            )
            (utils_dir / "InlineFunction.cpp").write_text(
                inline_signature + "\n", encoding="utf-8"
            )

            def fake_git_ok(llvm: Path, *arguments: str):
                stdout = toolchain_module.LLVM_TAG if arguments[0] == "tag" else ""
                return subprocess.CompletedProcess(
                    args=list(arguments), returncode=0, stdout=stdout, stderr=""
                )

            commands: list[list[str]] = []
            with _mock_files(root), mock.patch.object(
                toolchain_module, "_git_ok", side_effect=fake_git_ok
            ), mock.patch.object(
                toolchain_module, "_run",
                side_effect=lambda command, **kwargs: commands.append(
                    [str(part) for part in command]
                ),
            ):
                toolchain_module.build_patched_llvm(
                    llvm_src, root / "prefix", full=True
                )

            am = next(command for command in commands if "am" in command)
            self.assertIn("-c", am)
            self.assertIn("user.name=Chimera Patch Builder", am)
            self.assertIn("user.email=chimera@example.invalid", am)
            self.assertLess(am.index("user.name=Chimera Patch Builder"), am.index("am"))
            # 守卫与 census 已改由 patches/*.patch 经 git am 注入（0009
            # 起，程序化编辑通道移除）：断言 am 的输入是 patches 目录的
            # 完整有序补丁集，源码不再被脚本改动。
            patch_dir = root / "toolchain_source" / "patches"
            self.assertEqual(
                [path.name for path in sorted(patch_dir.glob("*.patch"))],
                [Path(arg).name for arg in am if arg.endswith(".patch")],
            )

    def test_patched_llvm_interrupt_restores_source_and_state(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "toolchain_source"
            (source / "plugins").mkdir(parents=True)
            (source / "plugins" / "CMakeLists.txt").write_text("# cmake\n", encoding="utf-8")
            (source / "patches").mkdir()
            (source / "patches" / "0001-x.patch").write_text("patch\n", encoding="utf-8")
            llvm_src = root / "llvm-src"
            llvm_src.mkdir()
            calls: list[list[str]] = []

            def fake_git_ok(_llvm: Path, *arguments: str):
                if arguments == ("tag", "--list", toolchain_module.LLVM_TAG):
                    stdout = toolchain_module.LLVM_TAG + "\n"
                elif arguments in (("rev-parse", "HEAD"), ("rev-parse", f"{toolchain_module.LLVM_TAG}^{{commit}}")):
                    stdout = "baseline\n"
                elif arguments == ("rev-parse", "--git-dir"):
                    stdout = ".git\n"
                elif arguments[:2] == ("rev-parse", "--git-path"):
                    stdout = ".git/" + arguments[2] + "\n"
                else:
                    stdout = ""
                return subprocess.CompletedProcess(list(arguments), 0, stdout, "")

            def fake_run(command, **kwargs):
                calls.append([str(part) for part in command])
                if command and command[0] == "ninja":
                    raise KeyboardInterrupt()

            with _mock_files(root), mock.patch.object(
                toolchain_module, "_git_ok", side_effect=fake_git_ok
            ), mock.patch.object(toolchain_module, "_run", side_effect=fake_run):
                with self.assertRaises(KeyboardInterrupt):
                    toolchain_module.build_patched_llvm(
                        llvm_src, root / "prefix", full=True
                    )

            self.assertTrue(any(command[:3] == ["git", "reset", "--hard"] for command in calls))
            self.assertFalse((llvm_src / ".git" / "chimera-patched-llvm-state.json").exists())

    def test_toolchain_build_root_prefers_flag_then_env_then_default(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            explicit = root / "explicit-toolchain"
            with mock.patch.dict(
                "os.environ", {"CHIMERA_TOOLCHAIN_BUILD": str(root / "env-toolchain")}
            ):
                self.assertEqual(toolchain_build_root(explicit), explicit)
                self.assertEqual(
                    toolchain_build_root(None), root / "env-toolchain"
                )
            with mock.patch.dict("os.environ", {}, clear=False):
                os.environ.pop("CHIMERA_TOOLCHAIN_BUILD", None)
                self.assertEqual(
                    toolchain_build_root(None),
                    Path.home() / ".chimera" / "toolchain_build",
                )


if __name__ == "__main__":
    unittest.main()
