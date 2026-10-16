from __future__ import annotations

from contextlib import redirect_stdout
from hashlib import sha256
from importlib import import_module
from io import StringIO
import os
from pathlib import Path
import struct
import subprocess
from types import MappingProxyType, SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

from chimera.preprocess.offline.analysis.build_runtime import BuildRuntimeStep
from chimera.preprocess.offline.analysis.build_runtime.model import (
    required_runtime_symbols,
)
from chimera.preprocess.offline.analysis.core.monitor import monitoring
from chimera.preprocess.offline.analysis_profile import PreparePipeline
from chimera.preprocess.offline.analysis_profile.plan import (
    ExecutionPlan,
    PlannedStep,
)
from chimera.runtime.scene_contracts import registered_runtime_artifact_contracts
from chimera.runtime.bpf.registry import PinnedUprobeMap, UprobeInfo
from chimera.runtime.bpf.syscall import BpfMapInfo
from chimera.runtime.bpf.transaction import PreparationRegistrar
from chimera.runtime.launcher import launch
from chimera.runtime.validate import verify_workspace
from chimera.runtime.validate.capabilities import (
    CapabilityVerificationError,
    verify_runtime_elf,
)


REQUIRED_RUNTIME_EXPORTS = frozenset({
    "chimera_runtime_abi_v1",
    "chimera_runtime_scene_linux_riscv64_rvv_v1",
    "query_original_translated_map",
    "simulated_cpu_state_riscv64_rvv_1024_riscv64_rvv_256",
    "simulated_cpu_state_riscv64_rvv_256_riscv64_rvv_1024",
    "get_simulated_cpu_state_addr_riscv64_rvv_1024_riscv64_rvv_256",
    "get_simulated_cpu_state_addr_riscv64_rvv_256_riscv64_rvv_1024",
})
FORBIDDEN_RUNTIME_EXPORTS = frozenset({
    "chimera_runtime_abi_v2",
    "chimera_runtime_scene_linux_riscv64_rvv_v2",
    "chimera_simulated_state",
    "simulated_cpu_state_ptr",
})
RUNTIME_TLS_EXPORTS = frozenset({
    "simulated_cpu_state_riscv64_rvv_1024_riscv64_rvv_256",
    "simulated_cpu_state_riscv64_rvv_256_riscv64_rvv_1024",
})


def _valid_runtime_elf() -> bytes:
    ident = b"\x7fELF\x02\x01\x01" + bytes(9)
    return struct.pack(
        "<16sHHIQQQIHHHHHH",
        ident, 3, 243, 1, 0, 0, 0, 0, 64, 56, 0, 64, 0, 0,
    )


def _readelf_dynamic_symbols(
    output: str,
) -> dict[str, list[tuple[str, str, str, str]]]:
    symbols: dict[str, list[tuple[str, str, str, str]]] = {}
    for line in output.splitlines():
        fields = line.split()
        if (
            len(fields) < 8
            or not fields[0].endswith(":")
            or not fields[0][:-1].isdecimal()
        ):
            continue
        name = fields[7].split("@", 1)[0]
        symbols.setdefault(name, []).append(
            (fields[3], fields[4], fields[5], fields[6])
        )
    return symbols


class _CaptureDebugStep:
    name = "capture-debug"

    def __init__(self) -> None:
        self.values: list[bool] = []

    def run(self, context):
        self.values.append(context.debug_enabled)
        return context.put_global("published_workspace", context.input_elf.parent)


class _Builder:
    def __init__(self) -> None:
        self.defines: dict[str, str] = {}

    def configure(self, _source, _build, *, defines, **_kwargs):
        self.defines = dict(defines)
        return ("configure",)

    @staticmethod
    def build(_build, *, target):
        return ("build", target)

    @staticmethod
    def install(_build):
        return ("install",)


class _Runner:
    @staticmethod
    def run(_command):
        return SimpleNamespace(
            stdout=(
                "T chimera_runtime_abi_v1\n"
                "T chimera_runtime_scene_linux_riscv64_rvv_v1\n"
                "B simulated_cpu_state_riscv64_rvv_1024_riscv64_rvv_256\n"
                "B simulated_cpu_state_riscv64_rvv_256_riscv64_rvv_1024\n"
                "T get_simulated_cpu_state_addr_riscv64_rvv_1024_riscv64_rvv_256\n"
                "T get_simulated_cpu_state_addr_riscv64_rvv_256_riscv64_rvv_1024\n"
                "T query_original_translated_map\n"
            )
        )


class _RunnerWithoutQuery:
    @staticmethod
    def run(_command):
        return SimpleNamespace(
            stdout=(
                "T chimera_runtime_abi_v1\n"
                "T chimera_runtime_scene_linux_riscv64_rvv_v1\n"
                "B simulated_cpu_state_riscv64_rvv_1024_riscv64_rvv_256\n"
                "B simulated_cpu_state_riscv64_rvv_256_riscv64_rvv_1024\n"
                "T get_simulated_cpu_state_addr_riscv64_rvv_1024_riscv64_rvv_256\n"
                "T get_simulated_cpu_state_addr_riscv64_rvv_256_riscv64_rvv_1024\n"
            )
        )


class RuntimeDebugMonitoringTests(unittest.TestCase):
    def test_readelf_dynamic_symbol_parser_preserves_tls_metadata(self) -> None:
        symbols = _readelf_dynamic_symbols(
            """
Symbol table '.dynsym' contains 3 entries:
   Num:    Value          Size Type    Bind   Vis      Ndx Name
     1: 0000000000000000  4192 TLS     GLOBAL DEFAULT   17 simulated_cpu_state_riscv64_rvv_1024_riscv64_rvv_256
     2: 0000000000000100    48 FUNC    GLOBAL DEFAULT   12 query_original_translated_map
"""
        )

        self.assertEqual(
            symbols[
                "simulated_cpu_state_riscv64_rvv_1024_riscv64_rvv_256"
            ],
            [("TLS", "GLOBAL", "DEFAULT", "17")],
        )
        self.assertNotIn("Name", symbols)

    def test_build_and_verifier_require_the_same_runtime_v1_exports(self) -> None:
        self.assertEqual(
            required_runtime_symbols("linux_riscv64_rvv_v1"),
            REQUIRED_RUNTIME_EXPORTS,
        )
        artifact = SimpleNamespace(
            owner_kind="workspace",
            owner_id="root",
            capability="runtime",
            representation="elf",
            abi=1,
        )
        manifest = SimpleNamespace(
            runtime_abi=1,
            runtime_scene="linux_riscv64_rvv_v1",
        )
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "runtime.so"
            path.write_bytes(_valid_runtime_elf())
            with patch(
                "chimera.runtime.validate.capabilities._require_symbols"
            ) as require_symbols:
                verify_runtime_elf(path, artifact, manifest, SimpleNamespace())

        self.assertEqual(
            require_symbols.call_args.args[2], set(REQUIRED_RUNTIME_EXPORTS)
        )

    def test_runtime_verifier_rejects_wrong_owner_shape_or_abi(self) -> None:
        contract = {
            "owner_kind": "workspace",
            "owner_id": "root",
            "capability": "runtime",
            "representation": "elf",
            "abi": 1,
        }
        cases = (
            ("owner_kind", "module"),
            ("owner_id", "main"),
            ("capability", "translated-code"),
            ("representation", "json"),
            ("abi", 2),
        )
        manifest = SimpleNamespace(
            runtime_abi=1,
            runtime_scene="linux_riscv64_rvv_v1",
        )
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "runtime.so"
            path.write_bytes(_valid_runtime_elf())
            for field, value in cases:
                with self.subTest(field=field, value=value):
                    artifact = SimpleNamespace(**(contract | {field: value}))
                    with self.assertRaisesRegex(
                        CapabilityVerificationError,
                        "invalid runtime ELF owner or ABI",
                    ):
                        verify_runtime_elf(
                            path, artifact, manifest, SimpleNamespace()
                        )

    def test_riscv_runtime_dynamic_symbol_contract(self) -> None:
        runtime_value = os.environ.get("CHIMERA_RUNTIME_DSO")
        if runtime_value is None:
            self.skipTest(
                "set CHIMERA_RUNTIME_DSO to inspect a target Runtime DSO"
            )
        runtime = Path(runtime_value)
        readelf = os.environ.get(
            "CHIMERA_READELF", "riscv64-linux-gnu-readelf"
        )
        completed = subprocess.run(
            [readelf, "--dyn-syms", "-W", str(runtime)],
            check=True,
            capture_output=True,
            text=True,
        )
        symbols = _readelf_dynamic_symbols(completed.stdout)
        defined = {
            name
            for name, records in symbols.items()
            if any(index != "UND" for _type, _bind, _visibility, index in records)
        }

        self.assertEqual(REQUIRED_RUNTIME_EXPORTS - defined, frozenset())
        self.assertEqual(FORBIDDEN_RUNTIME_EXPORTS & defined, frozenset())
        for name in RUNTIME_TLS_EXPORTS:
            with self.subTest(symbol=name):
                self.assertTrue(
                    any(
                        symbol_type == "TLS"
                        and binding == "GLOBAL"
                        and visibility == "DEFAULT"
                        and index != "UND"
                        for symbol_type, binding, visibility, index
                        in symbols.get(name, ())
                    ),
                    f"{name} must be a defined GLOBAL DEFAULT TLS symbol",
                )

    def test_pipeline_snapshots_monitor_state_into_context(self) -> None:
        step = _CaptureDebugStep()
        profile = SimpleNamespace(
            target_os="linux",
            target_arch="riscv64",
            target_arch_extension="rvv",
            runtime_scene="linux_riscv64_rvv_v1",
            runtime_abi=1,
        )
        plan = ExecutionPlan(
            configuration=SimpleNamespace(base=object(), profile=profile),
            services=object(),
            steps=(
                PlannedStep(
                    "001:capture-debug",
                    "capture-debug",
                    step,
                    MappingProxyType({}),
                ),
            ),
        )
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "app"
            source.write_bytes(b"elf")
            PreparePipeline(plan).prepare(source)
            with monitoring(enabled=True, stream=StringIO()):
                PreparePipeline(plan).prepare(source)

        self.assertEqual(step.values, [False, True])

    def test_build_runtime_passes_debug_cmake_define(self) -> None:
        values: list[str] = []
        for enabled in (False, True):
            with tempfile.TemporaryDirectory() as temporary:
                stage = Path(temporary)
                library = stage / "artifacts/runtime/libchimera_inject.so"
                library.parent.mkdir(parents=True)
                library.write_bytes(b"runtime")
                builder = _Builder()
                context = SimpleNamespace(
                    stage=stage,
                    global_results={"capabilities": {}},
                    platform=SimpleNamespace(runner=_Runner()),
                    toolchain=SimpleNamespace(
                        code_builder=builder,
                        symbols=SimpleNamespace(
                            exported_symbols=lambda _path: ("nm",)
                        ),
                    ),
                    config=SimpleNamespace(
                        tools=SimpleNamespace(cc="riscv64-linux-gnu-gcc"),
                        target_files=SimpleNamespace(
                            cmake_toolchain_file=None,
                            sysroot=None,
                        ),
                    ),
                    target_os="linux",
                    target_arch="riscv64",
                    target_arch_extension="rvv",
                    runtime_scene="linux_riscv64_rvv_v1",
                    debug_enabled=enabled,
                    target_bundle=SimpleNamespace(
                        runtime=SimpleNamespace(
                            system_name="Linux", system_processor="riscv64",
                            elf_machine=243, abi=1,
                            artifact_contract=registered_runtime_artifact_contracts().select(
                                ("linux", "riscv64", "rvv", "linux_riscv64_rvv_v1")
                            ),
                        )
                    ),
                )
                context.put_global = lambda _name, _value: context
                context.runtime_abi = 1
                registry = SimpleNamespace(register_artifact=lambda _record: None)
                context.require_global = lambda _name: SimpleNamespace(registry=registry)
                with (
                    patch(
                        "chimera.preprocess.offline.analysis.build_runtime.step.runtime_source_root",
                        return_value=stage / "source",
                    ),
                    patch(
                        "chimera.preprocess.offline.analysis.build_runtime.step.validate_runtime_elf"
                    ),
                ):
                    BuildRuntimeStep().run(context)
                values.append(builder.defines["CHIMERA_DEBUG"])

        self.assertEqual(values, ["OFF", "ON"])

    def test_build_runtime_rejects_missing_public_query_before_publication(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            stage = Path(temporary)
            library = stage / "artifacts/runtime/libchimera_inject.so"
            library.parent.mkdir(parents=True)
            library.write_bytes(b"runtime")
            builder = _Builder()
            registrations: list[object] = []
            context = SimpleNamespace(
                stage=stage,
                global_results={"capabilities": {}},
                platform=SimpleNamespace(runner=_RunnerWithoutQuery()),
                toolchain=SimpleNamespace(
                    code_builder=builder,
                    symbols=SimpleNamespace(exported_symbols=lambda _path: ("nm",)),
                ),
                config=SimpleNamespace(
                    tools=SimpleNamespace(cc="riscv64-linux-gnu-gcc"),
                    target_files=SimpleNamespace(
                        cmake_toolchain_file=None,
                        sysroot=None,
                    ),
                ),
                target_os="linux",
                target_arch="riscv64",
                target_arch_extension="rvv",
                runtime_scene="linux_riscv64_rvv_v1",
                runtime_abi=1,
                debug_enabled=False,
                target_bundle=SimpleNamespace(
                    runtime=SimpleNamespace(
                        system_name="Linux", system_processor="riscv64",
                        elf_machine=243, abi=1,
                        artifact_contract=registered_runtime_artifact_contracts().select(
                            ("linux", "riscv64", "rvv", "linux_riscv64_rvv_v1")
                        ),
                    )
                ),
            )
            registry = SimpleNamespace(register_artifact=registrations.append)
            context.require_global = lambda _name: SimpleNamespace(registry=registry)
            context.put_global = lambda _name, _value: context
            with (
                patch(
                    "chimera.preprocess.offline.analysis.build_runtime.step.runtime_source_root",
                    return_value=stage / "source",
                ),
                patch(
                    "chimera.preprocess.offline.analysis.build_runtime.step.validate_runtime_elf"
                ),
                self.assertRaisesRegex(ValueError, "query_original_translated_map"),
            ):
                BuildRuntimeStep().run(context)

        self.assertEqual(registrations, [])

    def test_runtime_verifier_rejects_missing_public_query_before_execution(self) -> None:
        symbols = {
            "chimera_runtime_abi_v1",
            "chimera_runtime_scene_linux_riscv64_rvv_v1",
            "simulated_cpu_state_riscv64_rvv_1024_riscv64_rvv_256",
            "simulated_cpu_state_riscv64_rvv_256_riscv64_rvv_1024",
            "get_simulated_cpu_state_addr_riscv64_rvv_1024_riscv64_rvv_256",
            "get_simulated_cpu_state_addr_riscv64_rvv_256_riscv64_rvv_1024",
        }
        artifact = SimpleNamespace(
            owner_kind="workspace",
            owner_id="root",
            capability="runtime",
            representation="elf",
            abi=1,
        )
        manifest = SimpleNamespace(
            runtime_abi=1,
            runtime_scene="linux_riscv64_rvv_v1",
        )
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "runtime.so"
            path.write_bytes(_valid_runtime_elf())
            with (
                patch(
                    "chimera.runtime.validate.capabilities._exported_symbols",
                    return_value=symbols,
                ),
                self.assertRaisesRegex(
                    CapabilityVerificationError, "query_original_translated_map"
                ),
            ):
                verify_runtime_elf(path, artifact, manifest, SimpleNamespace())

    def test_verify_workspace_emits_manifest_summary(self) -> None:
        variant = SimpleNamespace(
            variant_id="main_v1024_v256", module_id="main"
        )
        artifacts = (
            SimpleNamespace(
                owner_kind="workspace", owner_id="root",
                capability="runtime", representation="elf",
                required_by=frozenset(), path="runtime.so", abi=1,
            ),
            SimpleNamespace(
                owner_kind="variant", owner_id=variant.variant_id,
                capability="translated-code", representation="elf",
                required_by=frozenset(), path="translated.so", abi=1,
            ),
            SimpleNamespace(
                owner_kind="variant", owner_id=variant.variant_id,
                capability="offset-map", representation="elf",
                required_by=frozenset(), path="map.so", abi=1,
            ),
        )
        manifest = SimpleNamespace(
            target_os="linux",
            target_arch="riscv64",
            target_arch_extension="rvv",
            runtime_scene="linux_riscv64_rvv_v1",
            runtime_abi=1,
            modules=(SimpleNamespace(module_id="main"),),
            variants=(variant,),
            artifacts=artifacts,
        )
        manifest.property_record = lambda _variant, side, name: SimpleNamespace(
            value_kind="u64" if name == "vector_vlen_bits" else "token",
            value=(
                "riscv64" if name == "architecture"
                else "rvv" if name == "architecture_extension"
                else "1024" if side == "input" else "256"
            ),
        )
        settings = SimpleNamespace(nm="nm")
        output = StringIO()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "artifacts").mkdir()
            (root / "runtime.so").write_bytes(_valid_runtime_elf())
            module = import_module("chimera.runtime.validate.workspace")
            with (
                patch.object(module, "read_manifest", return_value=manifest),
                patch.dict(
                    module.VERIFIERS,
                    {key: (lambda *_args: None) for key in module.VERIFIERS},
                ),
                monitoring(enabled=True, stream=output),
            ):
                self.assertIs(
                    verify_workspace(root, settings, check_host=False), manifest
                )

        self.assertIn("[DEBUG] runtime.verify.start", output.getvalue())
        self.assertIn("[DEBUG] runtime.verify.finish", output.getvalue())
        self.assertIn("artifacts=3", output.getvalue())

    def test_run_emits_preparation_and_exec_events(self) -> None:
        class ExecCalled(RuntimeError):
            pass

        output = StringIO()
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            (workspace / "scalar").mkdir()
            loader = workspace / "scalar" / "ld-loader.so"
            loader.write_bytes(b"loader")
            # The application is target-resolved, so it lives outside the
            # Workspace and is handed to the launcher explicitly.
            program = workspace / "opt" / "app"
            program.parent.mkdir()
            program.write_bytes(b"elf")
            manifest = SimpleNamespace(
                modules=(
                    SimpleNamespace(
                        role="main", module_id="app", runtime_name="app",
                        delivery="target", sha256=sha256(b"elf").hexdigest(),
                    ),
                    SimpleNamespace(
                        role="dependency", module_id="ld_loader",
                        runtime_name="ld-loader.so", delivery="package",
                        sha256=sha256(b"loader").hexdigest(),
                    ),
                ),
                target_os="linux", target_arch="riscv64",
                target_arch_extension="rvv",
                runtime_scene="linux_riscv64_rvv_v1",
            )

            # Which files the loader maps is exercised against the real
            # measured output in test_launcher_precheck; here the resolution is
            # supplied so the launch flow itself is what is under test.
            resolved = {"app": program}
            module = import_module("chimera.runtime.launcher.run")
            with (
                patch.object(module, "verify_workspace", return_value=manifest),
                patch.object(module, "interpreter", return_value=str(loader)),
                patch.object(
                    module, "resolved_module_paths", return_value=resolved
                ),
                patch.object(module, "_run_loader", return_value=(0, "", "")),
                patch(
                    "chimera.runtime.launcher.adapters.runtime_environment",
                    return_value={
                        "CHIMERA_WORKSPACE": str(workspace),
                        "LD_PRELOAD": str(workspace / "runtime.so"),
                    },
                ),
                patch.object(module.os, "execve", side_effect=ExecCalled),
                monitoring(enabled=True, stream=output),
                self.assertRaises(ExecCalled),
            ):
                launch(workspace, program, ("--flag",), SimpleNamespace())

        text = output.getvalue()
        self.assertIn("[DEBUG] runtime.run.prepare.finish", text)
        self.assertIn("[DEBUG] runtime.run.exec.start", text)
        self.assertIn("argv=[", text)
        self.assertNotIn("runtime.run.exec.finish", text)

    def test_bpf_submit_and_migratable_registration(self) -> None:
        output = StringIO()
        transport = SimpleNamespace(
            info=lambda: BpfMapInfo(key_size=4, value_size=176),
            update=lambda _key, _value: None,
            close=lambda: None,
        )
        with monitoring(enabled=True, stream=output):
            queue = PinnedUprobeMap(
                "/sys/fs/bpf/chimera",
                _map_factory=lambda _path: transport,
            )
            key = queue.submit(
                UprobeInfo(inode=7, offsets=(4, 8)),
                chunk_index=0,
            )
            queue.close()
        self.assertIsInstance(key, int)

        submitted: list[Path] = []

        class FakeRegistry:
            @staticmethod
            def register_migratable_file(path):
                submitted.append(path)
                return 9

        registrar = PreparationRegistrar.__new__(PreparationRegistrar)
        registrar.registry = FakeRegistry()
        registrar._keys = []
        module = SimpleNamespace(
            module_id="app",
            runtime_name="app",
        )
        variant = SimpleNamespace(
            variant_id="app_vlen1024_to_vlen256",
            module_id="app",
        )
        manifest = SimpleNamespace(
            artifacts=(), modules=(module,), variants=(variant,),
        )
        with monitoring(enabled=True, stream=output):
            registrar.register(Path("workspace"), manifest)

        self.assertEqual(submitted, [Path("workspace") / "scalar" / "app"])
        self.assertEqual(registrar._keys, [9])
        text = output.getvalue()
        self.assertNotIn(" value hex ", text)

    def test_bpf_map_reports_actual_and_expected_layout(self) -> None:
        output = StringIO()
        transport = SimpleNamespace(
            info=lambda: BpfMapInfo(key_size=4, value_size=176),
            close=lambda: None,
        )
        with monitoring(enabled=True, stream=output):
            with PinnedUprobeMap(
                "/sys/fs/bpf/chimera",
                _map_factory=lambda _path: transport,
            ):
                pass

        text = output.getvalue()
        self.assertIn("[DEBUG] runtime.bpf.map.finish", text)
        self.assertIn("expected_key_size=4", text)
        self.assertIn("expected_value_size=176", text)
        self.assertIn("actual_key_size=4", text)
        self.assertIn("actual_value_size=176", text)

    def test_rollback_is_reverse_order_and_monitored(self) -> None:
        deleted: list[int] = []
        registrar = PreparationRegistrar.__new__(PreparationRegistrar)
        registrar.registry = SimpleNamespace(
            queue=SimpleNamespace(delete=deleted.append)
        )
        registrar._keys = [1, 2, 3]
        output = StringIO()

        with monitoring(enabled=True, stream=output):
            registrar.rollback()

        self.assertEqual(deleted, [3, 2, 1])
        self.assertIn("[DEBUG] runtime.bpf.rollback.finish", output.getvalue())

    def test_rollback_failure_reports_count_before_raising(self) -> None:
        deleted: list[int] = []

        def delete(key: int) -> None:
            deleted.append(key)
            if key == 2:
                raise OSError("delete failed")

        registrar = PreparationRegistrar.__new__(PreparationRegistrar)
        registrar.registry = SimpleNamespace(
            queue=SimpleNamespace(delete=delete)
        )
        registrar._keys = [1, 2, 3]
        output = StringIO()

        with monitoring(enabled=True, stream=output):
            with self.assertRaisesRegex(RuntimeError, "1 map key"):
                registrar.rollback()

        self.assertEqual(deleted, [3, 2, 1])
        self.assertIn("[DEBUG] runtime.bpf.rollback.finish", output.getvalue())
        self.assertIn("failures=1", output.getvalue())


if __name__ == "__main__":
    unittest.main()
