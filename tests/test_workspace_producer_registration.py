from __future__ import annotations

import errno
import json
from pathlib import Path
import sys
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import Mock, patch

from elf_fixture import write_elf
from chimera.preprocess.offline.analysis import AnalysisContext
from chimera.preprocess.offline.analysis.core.data_model import (
    DELIVERY_PACKAGE,
    DELIVERY_TARGET,
    AnalysisModule,
)
from chimera.preprocess.offline.analysis.core.workspace import (
    WorkspaceRepository,
    WorkspaceSession,
    write_workspace_metadata,
)
from chimera.preprocess.offline.analysis.prepare_workspace import PrepareWorkspaceStep
from chimera.preprocess.offline.analysis.platform.linux.dependencies import (
    _find_library,
    collect_dependencies,
)
from chimera.preprocess.offline.analysis.translation import (
    TranslationKey,
    TranslationStep,
)
from chimera.preprocess.offline.analysis.toolchain.artifact_emitter import (
    GnuArtifactEmitter,
)
from chimera.preprocess.offline.analysis_profile.target import RvvTranslationSemantics
from chimera.preprocess.offline.config import TranslationEndpoint
from chimera.runtime.manifest import ModuleRecord, WorkspaceManifest, write_manifest


def fake_platform(**overrides):
    """A stand-in that satisfies ``ElfModuleServices`` plus capability probing.

    The protocol grows a method whenever the pipeline needs a new ELF fact, and
    every test here needs a platform that satisfies all of it; one place keeps
    that list from being copied (and silently falling behind) several times.
    """

    fields = {
        "dependencies": Mock(return_value=()),
        "interpreter": Mock(return_value=None),
        "load_base": Mock(return_value=0),
        "load_segments": Mock(return_value=()),
        "virtual_to_file_offset": Mock(return_value=0),
        "dynamic_search_paths": Mock(return_value={}),
        "validate_capabilities": Mock(return_value={}),
        "runner": Mock(),
    }
    fields.update(overrides)
    return SimpleNamespace(**fields)


class WorkspaceProducerRegistrationTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.stage = self.root / ".ready.staging-test"
        self.stage.mkdir()
        self.destination = self.root / "ready"
        self.session = WorkspaceSession(
            root=self.root, stage=self.stage, destination=self.destination
        )

    def symlink_or_skip(self, target: Path, link: Path) -> None:
        try:
            link.symlink_to(target.name)
        except OSError as error:
            skippable_errnos = {errno.EPERM, errno.EACCES, errno.ENOSYS}
            if hasattr(errno, "EOPNOTSUPP"):
                skippable_errnos.add(errno.EOPNOTSUPP)
            unsupported = (
                error.errno in skippable_errnos
                or getattr(error, "winerror", None) == 1314
            )
            if sys.platform.startswith("linux") or not unsupported:
                raise
            self.skipTest(f"host cannot create file symlinks: {error}")

    def dependency_paths(
        self, source: Path, *needed: str
    ) -> tuple[Path, ...]:
        with (
            patch(
                "chimera.preprocess.offline.analysis.platform.linux.dependencies.needed_libraries",
                side_effect=lambda path: needed if path == source else (),
            ),
            patch(
                "chimera.preprocess.offline.analysis.platform.linux.dependencies.interpreter",
                return_value=None,
            ),
        ):
            return collect_dependencies(source, (self.root,))

    def context(self, services, config, *, target_bundle=None, **globals_: object) -> AnalysisContext:
        context = AnalysisContext(
            input_elf=self.root / "app",
            stage=self.stage,
            config=config,
            target_os="linux",
            target_arch="riscv64",
            target_arch_extension="rvv",
            runtime_scene="linux_riscv64_rvv_v1",
            runtime_abi=1,
            services=services,
            target_bundle=target_bundle,
        ).put_global("workspace_session", self.session)
        for name, value in globals_.items():
            context = context.put_global(name, value)
        return context

    def test_prepare_analyses_the_selected_files_and_copies_nothing_else(self) -> None:
        """The application is analysed where it is installed.

        Staging a copy is what broke applications that derive paths from their
        own location, and it meant the bytes analysed were not the bytes the
        application ships.  The scalar loader, by contrast, travels inside the
        package, so it *is* staged.
        """

        source = self.root / "app"
        loader = self.root / "ld-linux-riscv64-lp64d.so.1"
        write_elf(source, b"main")
        write_elf(loader, b"loader")
        scalar_root = self.root / "scalar"
        scalar_root.mkdir()
        write_elf(scalar_root / loader.name, b"scalar loader")
        platform = fake_platform(dependencies=Mock(return_value=(source, loader)))
        services = SimpleNamespace(
            platform=platform, toolchain=SimpleNamespace(), architecture=Mock()
        )
        config = SimpleNamespace(
            workspace_name="auto",
            scalar_root=scalar_root,
            target_files=SimpleNamespace(library_roots=()),
        )

        updated = PrepareWorkspaceStep().run(self.context(services, config))

        modules = updated.require_global("modules")
        main = next(item for item in modules if item.is_main)
        self.assertEqual(main.selected_path, source)
        self.assertEqual(main.delivery, DELIVERY_TARGET)
        self.assertFalse((self.stage / "scalar" / source.name).exists())
        packaged = next(item for item in modules if not item.is_main)
        self.assertEqual(packaged.delivery, DELIVERY_PACKAGE)
        self.assertEqual(
            packaged.selected_path, self.stage / "scalar" / loader.name
        )
        self.assertEqual(
            packaged.selected_path.read_bytes(),
            (scalar_root / loader.name).read_bytes(),
        )
        # Nothing is rewritten: no interpreter slot, no relocated loader.
        platform.runner.run.assert_not_called()

    def test_prepare_rejection_cleans_up_self_created_staging(self) -> None:
        """A failure after the session is allocated must not leak staging.

        ``DT_RPATH`` is the trigger here because it is rejected rather than
        tolerated: the loader searches it ahead of ``--library-path``, so the
        file that would run cannot be the file that was verified.
        """

        source = self.root / "app"
        write_elf(source, b"main")
        platform = fake_platform(
            dependencies=Mock(return_value=(source,)),
            dynamic_search_paths=Mock(return_value={"DT_RPATH": ("/opt/legacy/lib",)}),
        )
        services = SimpleNamespace(
            platform=platform, toolchain=SimpleNamespace(), architecture=Mock()
        )
        config = SimpleNamespace(
            workspace_name="auto",
            scalar_root=self.root / "scalar",
            target_files=SimpleNamespace(library_roots=()),
        )
        repository = WorkspaceRepository(self.root / "workspaces")
        context = AnalysisContext(
            input_elf=source,
            stage=None,
            config=config,
            target_os="linux",
            target_arch="riscv64",
            target_arch_extension="rvv",
            runtime_scene="linux_riscv64_rvv_v1",
            runtime_abi=1,
            services=services,
        )

        with self.assertRaisesRegex(ValueError, "DT_RPATH"):
            PrepareWorkspaceStep(repository).run(context)

        self.assertEqual([], list((self.root / "workspaces").glob(".*.staging-*")))

    def test_prepare_delivers_scalar_modules_and_leaves_originals_in_place(self) -> None:
        """``scalar`` selects a packaged copy; ``original`` stays on the machine."""

        source = self.root / "app"
        dependency = self.root / "libc.so.6"
        write_elf(source, b"main")
        write_elf(dependency, b"original")
        scalar_root = self.root / "scalar"
        scalar_root.mkdir()
        for scalar in (False, True):
            with self.subTest(scalar=scalar):
                self.session = WorkspaceSession(
                    root=self.root, stage=self.stage, destination=self.destination
                )
                write_workspace_metadata(
                    self.stage, workspace_id=self.stage.name, input_elf=source
                )
                staged = self.stage / "scalar" / dependency.name
                staged.unlink(missing_ok=True)
                (scalar_root / dependency.name).unlink(missing_ok=True)
                if scalar:
                    write_elf(scalar_root / dependency.name, b"scalar")
                platform = fake_platform(
                    dependencies=Mock(return_value=(source, dependency))
                )
                services = SimpleNamespace(
                    platform=platform, toolchain=SimpleNamespace(), architecture=Mock()
                )
                config = SimpleNamespace(
                    scalar_root=scalar_root,
                    target_files=SimpleNamespace(library_roots=()),
                )

                updated = PrepareWorkspaceStep().run(self.context(services, config))

                modules = updated.require_global("modules")
                selected = next(item for item in modules if item.source == dependency)
                self.assertEqual(scalar, selected.is_scalar)
                if scalar:
                    self.assertEqual(selected.delivery, DELIVERY_PACKAGE)
                    self.assertEqual(selected.selected_path, staged)
                    self.assertEqual(
                        staged.read_bytes(),
                        (scalar_root / dependency.name).read_bytes(),
                    )
                else:
                    self.assertEqual(selected.delivery, DELIVERY_TARGET)
                    self.assertEqual(selected.selected_path, dependency)
                    self.assertFalse(staged.exists())
                main = next(item for item in modules if item.is_main)
                self.assertEqual(main.selected_path, source)
                self.assertFalse((self.stage / "scalar" / source.name).exists())
                record = self.session.registry.modules[selected.module_id]
                self.assertEqual(
                    record.selected_kind, "scalar" if scalar else "original"
                )
                self.assertEqual(record.runtime_name, dependency.name)

    def test_prepare_checks_platform_capabilities_before_starting_session(self) -> None:
        source = self.root / "app"
        write_elf(source, b"main")
        platform = fake_platform()
        del platform.validate_capabilities
        services = SimpleNamespace(
            platform=platform,
            toolchain=SimpleNamespace(),
            architecture=Mock(),
        )
        config = SimpleNamespace(
            workspace_name="auto",
            scalar_root=self.root,
            target_files=SimpleNamespace(library_roots=()),
        )
        repository = Mock(spec=WorkspaceRepository)
        context = AnalysisContext(
            input_elf=source,
            stage=None,
            config=config,
            target_os="linux",
            target_arch="riscv64",
            target_arch_extension="rvv",
            runtime_scene="linux_riscv64_rvv_v1",
            runtime_abi=1,
            services=services,
        )

        with self.assertRaisesRegex(TypeError, "validate_capabilities"):
            PrepareWorkspaceStep(repository).run(context)
        repository.start.assert_not_called()

    def test_reopen_copies_writable_files_but_keeps_module_inode(self) -> None:
        published = self.root / "published"
        (published / "scalar").mkdir(parents=True)
        (published / "artifacts").mkdir()
        (published / "generated").mkdir()
        module = published / "scalar" / "app"
        artifact = published / "artifacts" / "report.json"
        generated = published / "generated" / "table.S"
        module.write_bytes(b"module")
        artifact.write_bytes(b"published artifact")
        generated.write_text("published generated\n", encoding="utf-8")
        write_manifest(
            WorkspaceManifest(
                runtime_abi=1,
                target_os="linux",
                target_arch="riscv64",
                target_arch_extension="rvv",
                runtime_scene="linux_riscv64_rvv_v1",
                modules=(ModuleRecord("main", "main", "app", "original", "target", "0" * 64),),
                variants=(),
                variant_properties=(),
                artifacts=(),
            ),
            published / "artifacts" / "modules.tsv",
        )
        module_inode = module.stat().st_ino
        repository = WorkspaceRepository(self.root)

        session = repository.reopen(published)
        self.assertEqual(module_inode, (session.stage / "scalar" / "app").stat().st_ino)
        self.assertNotEqual(
            artifact.stat().st_ino,
            (session.stage / "artifacts" / "report.json").stat().st_ino,
        )
        (session.stage / "artifacts" / "report.json").write_bytes(b"failed rebuild")
        (session.stage / "generated" / "table.S").write_text(
            "failed rebuild\n", encoding="utf-8"
        )
        session.abort()

        self.assertEqual(b"published artifact", artifact.read_bytes())
        self.assertEqual("published generated\n", generated.read_text(encoding="utf-8"))
        self.assertEqual(module_inode, module.stat().st_ino)

    def test_reopen_accepts_target_modules_without_a_payload(self) -> None:
        """Target-resolved modules legitimately have no file inside the package.

        Which modules those are is decided by the rebuild's own re-selection,
        not guessed from file presence, so reopen only insists that *some*
        payload exists.
        """

        published = self.root / "published-target-module"
        (published / "scalar").mkdir(parents=True)
        (published / "artifacts").mkdir()
        (published / "scalar" / "libc.so.6").write_bytes(b"payload")
        write_manifest(
            WorkspaceManifest(
                runtime_abi=1,
                target_os="linux",
                target_arch="riscv64",
                target_arch_extension="rvv",
                runtime_scene="linux_riscv64_rvv_v1",
                modules=(
                    ModuleRecord("main", "main", "app", "original", "target", "0" * 64),
                    ModuleRecord("dep", "dependency", "libc.so.6", "scalar", "package", "0" * 64),
                ),
                variants=(),
                variant_properties=(),
                artifacts=(),
            ),
            published / "artifacts" / "modules.tsv",
        )

        session = WorkspaceRepository(self.root).reopen(published)
        self.addCleanup(session.abort)
        self.assertTrue((session.stage / "scalar" / "libc.so.6").is_file())
        self.assertFalse((session.stage / "scalar" / "app").exists())

    def test_reopen_rejects_workspace_without_any_module_payload(self) -> None:
        published = self.root / "published-missing-module"
        (published / "artifacts").mkdir(parents=True)
        write_manifest(
            WorkspaceManifest(
                runtime_abi=1,
                target_os="linux",
                target_arch="riscv64",
                target_arch_extension="rvv",
                runtime_scene="linux_riscv64_rvv_v1",
                modules=(ModuleRecord("main", "main", "app", "original", "target", "0" * 64),),
                variants=(),
                variant_properties=(),
                artifacts=(),
            ),
            published / "artifacts" / "modules.tsv",
        )
        with self.assertRaisesRegex(ValueError, "no module payloads"):
            WorkspaceRepository(self.root).reopen(published)
        self.assertEqual([], list(self.root.glob(".published-missing-module.staging-*")))

    def test_reopen_rejects_workspace_outside_repository_root(self) -> None:
        outside = self.root.parent / f"{self.root.name}-outside"
        outside.mkdir()
        self.addCleanup(lambda: outside.rmdir())
        with self.assertRaisesRegex(ValueError, "child of the configured workspace root"):
            WorkspaceRepository(self.root).reopen(outside)

    def test_library_lookup_preserves_needed_basename(self) -> None:
        soname = self.root / "libfoo.so.1"
        versioned = self.root / "libfoo.so.1.2.3"
        soname.write_bytes(b"payload")
        versioned.write_bytes(b"payload")

        with patch.object(Path, "resolve", autospec=True) as resolve:
            resolve.side_effect = lambda path: (
                versioned if path == soname else path.absolute()
            )
            selected = _find_library(soname.name, (self.root,))

        self.assertEqual(selected, soname)

    def test_symlink_helper_propagates_unexpected_filesystem_errors(self) -> None:
        target = self.root / "libfoo.so.1.2.3"
        link = self.root / "libfoo.so.1"

        with patch.object(
            Path, "symlink_to", side_effect=OSError(errno.EIO, "I/O failure")
        ):
            with self.assertRaises(OSError) as raised:
                self.symlink_or_skip(target, link)

        self.assertEqual(raised.exception.errno, errno.EIO)

    def test_prepare_keeps_target_dependency_under_needed_soname(self) -> None:
        source = self.root / "app"
        write_elf(source, b"main")
        versioned = self.root / "libfoo.so.1.2.3"
        write_elf(versioned, b"real dependency")
        soname = self.root / "libfoo.so.1"
        self.symlink_or_skip(versioned, soname)
        dependencies = self.dependency_paths(source, soname.name)
        platform = fake_platform(dependencies=Mock(return_value=dependencies))
        services = SimpleNamespace(
            platform=platform,
            toolchain=SimpleNamespace(),
            architecture=Mock(),
        )
        scalar_root = self.root / "scalar"
        scalar_root.mkdir()
        config = SimpleNamespace(
            workspace_name="auto",
            scalar_root=scalar_root,
            target_files=SimpleNamespace(library_roots=(self.root,)),
        )

        updated = PrepareWorkspaceStep().run(self.context(services, config))

        self.assertEqual([path.name for path in dependencies], ["app", soname.name])
        # Mainline D2 keeps application dependencies at their installed path.
        # Only an explicit scalar replacement is shipped in scalar/.
        self.assertFalse((self.stage / "scalar" / soname.name).exists())
        self.assertFalse((self.stage / "scalar" / versioned.name).exists())
        dependency = next(
            module for module in updated.require_global("modules")
            if not module.is_main
        )
        self.assertEqual(dependency.selected_path.name, soname.name)
        self.assertEqual(dependency.selected_path, soname)
        self.assertEqual(dependency.selected_path.read_bytes(), versioned.read_bytes())
        self.assertEqual(dependency.delivery, DELIVERY_TARGET)
        self.assertEqual(
            self.session.registry.modules[dependency.module_id].runtime_name,
            soname.name,
        )

    def test_prepare_selects_scalar_dependency_by_soname(self) -> None:
        source = self.root / "app"
        write_elf(source, b"main")
        soname = self.root / "libfoo.so.1"
        write_elf(soname, b"original dependency")
        scalar_root = self.root / "scalar"
        scalar_root.mkdir()
        scalar = scalar_root / soname.name
        write_elf(scalar, b"scalar dependency")
        platform = fake_platform(
            dependencies=Mock(return_value=(source, soname))
        )
        services = SimpleNamespace(
            platform=platform,
            toolchain=SimpleNamespace(),
            architecture=Mock(),
        )
        config = SimpleNamespace(
            workspace_name="auto",
            scalar_root=scalar_root,
            target_files=SimpleNamespace(library_roots=(self.root,)),
        )

        updated = PrepareWorkspaceStep().run(self.context(services, config))

        dependency = next(
            module for module in updated.require_global("modules")
            if not module.is_main
        )
        self.assertTrue(dependency.is_scalar)
        self.assertEqual(dependency.selected_path.name, soname.name)
        self.assertEqual(dependency.selected_path.read_bytes(), scalar.read_bytes())
        self.assertEqual(dependency.selected_path, self.stage / "scalar" / soname.name)
        self.assertEqual(dependency.delivery, DELIVERY_PACKAGE)

    def test_dependency_collection_deduplicates_repeated_soname(self) -> None:
        source = self.root / "app"
        write_elf(source, b"main")
        soname = self.root / "libfoo.so.1"
        write_elf(soname, b"dependency")

        dependencies = self.dependency_paths(source, soname.name, soname.name)

        self.assertEqual([path.name for path in dependencies], ["app", soname.name])

    def test_dependency_collection_keeps_distinct_soname_aliases(self) -> None:
        source = self.root / "app"
        write_elf(source, b"main")
        versioned = self.root / "libfoo.so.1.2.3"
        write_elf(versioned, b"dependency")
        first = self.root / "libfoo.so.1"
        second = self.root / "libfoo-compat.so.1"
        self.symlink_or_skip(versioned, first)
        self.symlink_or_skip(versioned, second)

        dependencies = self.dependency_paths(source, first.name, second.name)

        self.assertEqual(
            [path.name for path in dependencies],
            ["app", first.name, second.name],
        )
        self.assertEqual(first.resolve(), second.resolve())

    def test_translate_registers_variant_and_translated_artifact(self) -> None:
        source = self.root / "app"
        write_elf(source, b"main")
        staged_main = self.stage / "scalar" / "app"
        staged_main.parent.mkdir()
        staged_main.write_bytes(b"main")
        native_dump = self.stage / "dump" / "main.dump"
        native_dump.parent.mkdir()
        native_dump.write_text("dump\n", encoding="utf-8")
        module = AnalysisModule(
            "main", source, staged_main, False, True, DELIVERY_TARGET
        )
        self.session.registry.register_module(
            ModuleRecord("main", "main", "app", "original", "target", "0" * 64)
        )

        def translate_command(request):
            request.assembly_output.write_text(".text\n", encoding="utf-8")
            return ("translate",)

        def compile_command(_sources, output, **_kwargs):
            output.write_bytes(b"translated elf")
            return ("compile",)

        def run(command, stdout_path=None):
            if stdout_path is not None:
                stdout_path.write_text("translated dump\n", encoding="utf-8")
            return SimpleNamespace(stdout="")

        services = SimpleNamespace(
            platform=SimpleNamespace(
                dependencies=lambda _module_path, _library_roots: (),
                interpreter=lambda _path: None,
                load_base=lambda _path: 0,
                load_segments=lambda _path: (),
                virtual_to_file_offset=lambda _segments, _address: 0,
                dynamic_search_paths=lambda _path: {},
                runner=SimpleNamespace(run=run),
            ),
            toolchain=SimpleNamespace(
                artifact_emitter=GnuArtifactEmitter(word_directive=".dword"),
                translator=SimpleNamespace(command=translate_command),
                compiler=SimpleNamespace(compile=compile_command),
                disassembler=SimpleNamespace(command=lambda _path: ("dump",)),
            ),
            architecture=Mock(),
        )
        config = SimpleNamespace()
        context = self.context(
            services,
            config,
            target_bundle=SimpleNamespace(
                translation_semantics=RvvTranslationSemantics()
            ),
            modules=(module,),
            native_dumps={"main": native_dump},
        )

        updated = TranslationStep(
            source_endpoint=TranslationEndpoint.parse(
                "riscv64;rvv;vlen=1024", field="source"
            ),
            target_endpoint=TranslationEndpoint.parse(
                "riscv64;rvv;vlen=256", field="target"
            ),
            translator_path=self.root / "external-translator.py",
        ).run(context)

        source = TranslationEndpoint.parse(
            "riscv64;rvv;vlen=1024", field="source"
        )
        target = TranslationEndpoint.parse(
            "riscv64;rvv;vlen=256", field="target"
        )
        key = TranslationKey("main", source, target)
        identifier = RvvTranslationSemantics().production_spec(
            "main", source, target, self.stage
        ).variant_id
        self.assertIn(key, updated.require_global("translations"))
        self.assertIn(identifier, self.session.registry.variants)
        artifact = self.session.registry.artifacts[
            "translated-code-main-vlen1024-to-vlen256"
        ]
        self.assertEqual(
            (artifact.capability, artifact.owner_kind, artifact.owner_id),
            ("translated-code", "variant", identifier),
        )
        self.assertEqual(artifact.abi, 1)
        self.assertEqual(artifact.required_by, frozenset({"runtime"}))
        self.assertEqual(len(self.session.registry.variant_properties), 6)


if __name__ == "__main__":
    unittest.main()
