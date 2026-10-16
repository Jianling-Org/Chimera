"""The loader's own answer to "what will this launch load?".

These are the samples measured on the target machine (K3), including the two
shapes a naive parser gets wrong: an object with no file behind it, and the
preloaded runtime printed as a bare absolute path.
"""

from __future__ import annotations

import unittest
from hashlib import sha256
from pathlib import Path
from types import SimpleNamespace

from chimera.runtime.launcher.precheck import (
    LoaderReportError,
    parse_loader_list,
)


SAMPLE = """        linux-vdso.so.1 (0x0000003fb84b4000)
        libc.so.6 => /root/chimera/scalar/libc.so.6 (0x0000003fb8359000)
        /lib/ld-linux-riscv64-lp64d.so.1 => /root/chimera/scalar/ld-linux-riscv64-lp64d.so.1 (0x0000003fb84b6000)
"""

PRELOAD_SAMPLE = """        linux-vdso.so.1 (0x0000003fad8f9000)
        /root/.chimera/workspaces/demo/artifacts/runtime/libchimera_inject.so (0x0000003fad8de000)
        libc.so.6 => /opt/glibc-scalar-2.42/lib/libc.so.6 (0x0000003fad788000)
"""


class LoaderListTests(unittest.TestCase):
    def test_resolved_objects_carry_their_path(self) -> None:
        loaded = parse_loader_list(SAMPLE)

        self.assertEqual(
            [item.name for item in loaded],
            ["linux-vdso.so.1", "libc.so.6", "ld-linux-riscv64-lp64d.so.1"],
        )
        self.assertIsNone(loaded[0].path)
        self.assertEqual(loaded[1].path.as_posix(), "/root/chimera/scalar/libc.so.6")
        self.assertEqual(
            loaded[2].path.as_posix(),
            "/root/chimera/scalar/ld-linux-riscv64-lp64d.so.1",
        )

    def test_object_printed_as_a_bare_path_is_that_path(self) -> None:
        loaded = parse_loader_list(PRELOAD_SAMPLE)

        self.assertEqual(loaded[1].name, "libchimera_inject.so")
        self.assertEqual(
            loaded[1].path.as_posix(),
            "/root/.chimera/workspaces/demo/artifacts/runtime/libchimera_inject.so",
        )

    def test_unresolved_dependency_is_a_failure(self) -> None:
        with self.assertRaisesRegex(LoaderReportError, "could not resolve"):
            parse_loader_list("libfoo.so.1 => not found\n")

    def test_unrecognised_shape_is_a_failure(self) -> None:
        # Skipping an unrecognised line is how a library ends up unverified.
        with self.assertRaisesRegex(LoaderReportError, "unrecognised"):
            parse_loader_list("libc.so.6 => /lib/libc.so.6\n")

    def test_relative_resolution_is_a_failure(self) -> None:
        with self.assertRaisesRegex(LoaderReportError, "non-absolute"):
            parse_loader_list("libc.so.6 => ./libc.so.6 (0x1000)\n")

    def test_blank_lines_are_ignored(self) -> None:
        self.assertEqual(len(parse_loader_list("\n" + SAMPLE + "\n")), 3)


class LoaderFailureReportTests(unittest.TestCase):
    """A failed precheck must carry the loader's own reason.

    The loader writes *why* it failed to stderr.  Discarding it leaves an exit
    status with no explanation, which is exactly what "--list exit 127" was.
    """

    def test_failure_carries_the_loader_reason(self) -> None:
        from unittest.mock import patch

        from chimera.runtime.launcher.run import (
            LaunchError,
            resolved_module_paths,
        )

        manifest = SimpleNamespace(modules=())
        with patch(
            "chimera.runtime.launcher.run._run_loader",
            return_value=(
                127,
                "",
                "libfoo.so.1: cannot open shared object file\n",
            ),
        ):
            with self.assertRaises(LaunchError) as caught:
                resolved_module_paths(
                    Path("/ws/scalar/ld.so"), Path("/app/app"), (), manifest
                )

        message = str(caught.exception)
        self.assertIn("--list exit 127", message)
        self.assertIn("cannot open shared object file", message)

    def test_failure_without_stderr_still_names_the_exit_status(self) -> None:
        from unittest.mock import patch

        from chimera.runtime.launcher.run import (
            LaunchError,
            resolved_module_paths,
        )

        manifest = SimpleNamespace(modules=())
        with patch(
            "chimera.runtime.launcher.run._run_loader",
            return_value=(1, "", ""),
        ):
            with self.assertRaisesRegex(LaunchError, r"\(--list exit 1\)"):
                resolved_module_paths(
                    Path("/ws/scalar/ld.so"), Path("/app/app"), (), manifest
                )


class SearchPathTests(unittest.TestCase):
    """Order is the contract: the package first, the machine only as a fallback.

    A dependency the package leaves on the machine is only resolvable if the
    machine's own library directories are reachable -- but they must never be
    able to shadow a file the package ships.
    """

    def test_package_directories_precede_machine_directories(self) -> None:
        from unittest.mock import patch

        from chimera.runtime.launcher.run import _search_paths

        with patch(
            "chimera.runtime.launcher.run._machine_library_paths",
            return_value=("/usr/lib/riscv64-linux-gnu", "/lib"),
        ):
            paths = _search_paths(Path("/ws"), Path("/opt/app/bin/prog"))

        self.assertEqual(
            paths[:4],
            (
                str(Path("/ws") / "scalar"),
                str(Path("/ws") / "artifacts"),
                str(Path("/ws") / "artifacts" / "runtime"),
                str(Path("/opt/app/bin")),
            ),
        )
        self.assertEqual(paths[4:], ("/usr/lib/riscv64-linux-gnu", "/lib"))

    def test_a_repeated_directory_keeps_its_package_position(self) -> None:
        from unittest.mock import patch

        from chimera.runtime.launcher.run import _search_paths

        shared = str(Path("/opt/app/bin"))
        with patch(
            "chimera.runtime.launcher.run._machine_library_paths",
            return_value=(shared, "/lib"),
        ):
            paths = _search_paths(Path("/ws"), Path("/opt/app/bin/prog"))

        self.assertEqual(paths.count(shared), 1)
        self.assertEqual(paths.index(shared), 3)


class MainModuleResolutionTests(unittest.TestCase):
    """``--list`` never names the program, so the main module needs its own path.

    Registration announces inodes, so a missing main module means "cannot
    register at all"; and without the identity check any ELF could be
    registered against any Workspace.
    """

    def _program(self, root: Path, name: str = "llama-perplexity") -> Path:
        program = root / name
        program.write_bytes(b"\x7fELF-synthetic")
        return program

    def _main(self, program: Path, **overrides):
        return SimpleNamespace(
            module_id="llama_perplexity",
            role="main",
            runtime_name=program.name,
            delivery="target",
            sha256=sha256(program.read_bytes()).hexdigest(),
            **overrides,
        )

    def test_main_module_comes_from_the_input_path(self) -> None:
        from unittest.mock import patch
        from importlib import import_module
        import tempfile

        from chimera.runtime.launcher.run import resolve_modules

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            program = self._program(root)
            manifest = SimpleNamespace(modules=(self._main(program),))
            module = import_module("chimera.runtime.launcher.run")
            with (
                patch.object(module, "verify_workspace", return_value=manifest),
                patch.object(module, "_select_loader", return_value=root / "ld.so"),
                patch.object(module, "resolved_module_paths", return_value={}),
            ):
                result = resolve_modules(root, program, SimpleNamespace())

        self.assertEqual(result.resolved["llama_perplexity"], program)

    def test_a_foreign_elf_is_rejected(self) -> None:
        from unittest.mock import patch
        from importlib import import_module
        import tempfile

        from chimera.runtime.launcher.run import LaunchError, resolve_modules

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            program = self._program(root)
            other = self._program(root, name="something-else")
            manifest = SimpleNamespace(modules=(self._main(program),))
            module = import_module("chimera.runtime.launcher.run")
            with (
                patch.object(module, "verify_workspace", return_value=manifest),
                patch.object(module, "_select_loader", return_value=root / "ld.so"),
                patch.object(module, "resolved_module_paths", return_value={}),
            ):
                with self.assertRaisesRegex(LaunchError, "not the application"):
                    resolve_modules(root, other, SimpleNamespace())

    def test_a_changed_elf_is_rejected(self) -> None:
        from unittest.mock import patch
        from importlib import import_module
        import tempfile

        from chimera.runtime.launcher.run import LaunchError, resolve_modules

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            program = self._program(root)
            main = self._main(program)
            main.sha256 = "0" * 64
            manifest = SimpleNamespace(modules=(main,))
            module = import_module("chimera.runtime.launcher.run")
            with (
                patch.object(module, "verify_workspace", return_value=manifest),
                patch.object(module, "_select_loader", return_value=root / "ld.so"),
                patch.object(module, "resolved_module_paths", return_value={}),
            ):
                with self.assertRaisesRegex(LaunchError, "does not match"):
                    resolve_modules(root, program, SimpleNamespace())


if __name__ == "__main__":
    unittest.main()
