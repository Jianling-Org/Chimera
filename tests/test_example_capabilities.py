from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from chimera.example_capabilities import (
    HostCapabilities,
    detect_host_capabilities,
    profile_compatibility,
)
from chimera.installation import _check_release_compatibility
from chimera.examples import list_examples


class ExampleCapabilityTests(unittest.TestCase):
    def test_profile_compatibility_ignores_vlen_and_kernel_interfaces(self) -> None:
        profile = SimpleNamespace(
            target_os="linux", target_arch="riscv64", target_arch_extension="rvv",
            runtime_abi=1, workflow=SimpleNamespace(steps=()),
        )
        host = HostCapabilities(
            system="linux", machine="riscv64", rvv=True, vlen_bits=None,
            migration_control=False, bpf=False,
        )
        self.assertEqual(profile_compatibility(profile, host).status, "supported")

    def test_cpuinfo_rv64_prefix_does_not_count_as_rvv(self) -> None:
        with patch("chimera.example_capabilities.platform.system", return_value="Linux"), \
             patch("chimera.example_capabilities.platform.machine", return_value="riscv64"), \
             patch("chimera.example_capabilities._auxv_rvv", return_value=None), \
             patch("chimera.example_capabilities._cpuinfo", return_value="isa : rv64imafdc\n"):
            self.assertFalse(detect_host_capabilities().rvv)

    def test_cpuinfo_v_extension_is_detected(self) -> None:
        with patch("chimera.example_capabilities.platform.system", return_value="Linux"), \
             patch("chimera.example_capabilities.platform.machine", return_value="riscv64"), \
             patch("chimera.example_capabilities._auxv_rvv", return_value=None), \
             patch("chimera.example_capabilities._cpuinfo", return_value="isa : rv64imafdcv\n"):
            self.assertTrue(detect_host_capabilities().rvv)

    def test_cpuinfo_zve_extension_is_not_full_rvv(self) -> None:
        with patch("chimera.example_capabilities.platform.system", return_value="Linux"), \
             patch("chimera.example_capabilities.platform.machine", return_value="riscv64"), \
             patch("chimera.example_capabilities._auxv_rvv", return_value=None), \
             patch("chimera.example_capabilities._cpuinfo", return_value="isa : rv64imafdc_zve64d\n"):
            self.assertFalse(detect_host_capabilities().rvv)

    def test_cpuinfo_v_extension_token_is_detected_without_vlen(self) -> None:
        with patch("chimera.example_capabilities.platform.system", return_value="Linux"), \
             patch("chimera.example_capabilities.platform.machine", return_value="riscv64"), \
             patch("chimera.example_capabilities._auxv_rvv", return_value=None), \
             patch("chimera.example_capabilities._cpuinfo", return_value="isa : rv64imafdc_v\n"):
            capabilities = detect_host_capabilities()
            self.assertTrue(capabilities.rvv)
            self.assertEqual(capabilities.vlen_bits, None)
            self.assertIn("/proc/cpuinfo", capabilities.rvv_source)

    def test_unknown_rvv_keeps_detection_source_and_reason(self) -> None:
        with patch("chimera.example_capabilities.platform.system", return_value="Linux"), \
             patch("chimera.example_capabilities.platform.machine", return_value="riscv64"), \
             patch("chimera.example_capabilities._auxv_rvv", return_value=None), \
             patch("chimera.example_capabilities._cpuinfo", return_value="processor : 0\n"):
            capabilities = detect_host_capabilities()
            self.assertIsNone(capabilities.rvv)
            self.assertEqual(capabilities.rvv_source, "/proc/cpuinfo")
            self.assertIn("isa", capabilities.rvv_reason)

    def test_release_compatibility_checks_only_os_arch_and_rvv(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            resource = Path(temporary)
            (resource / "release-config.json").write_text(
                '{"target_os":"linux","target_arch":"riscv64","target_arch_extension":"rvv"}',
                encoding="utf-8",
            )
            host = HostCapabilities("linux", "riscv64", True, None, False, False)
            with patch("chimera.installation.detect_host_capabilities", return_value=host):
                _check_release_compatibility(resource)

    def test_release_compatibility_rejects_mismatched_host(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            resource = Path(temporary)
            (resource / "release-config.json").write_text(
                '{"target_os":"linux","target_arch":"riscv64","target_arch_extension":"rvv"}',
                encoding="utf-8",
            )
            host = HostCapabilities("linux", "x86_64", False, None, True, True)
            with patch("chimera.installation.detect_host_capabilities", return_value=host):
                with self.assertRaisesRegex(RuntimeError, "此 wheel 与当前系统／架构／RVV 能力不匹配"):
                    _check_release_compatibility(resource)

    def test_profile_requires_rvv_and_vlen(self) -> None:
        profile = SimpleNamespace(
            target_os="linux",
            target_arch="riscv64",
            target_arch_extension="rvv",
            runtime_scene="linux_riscv64_rvv_v1",
            runtime_abi=1,
            workflow=SimpleNamespace(
                steps=(
                    SimpleNamespace(
                        step="translate",
                        parameters={
                            "source": "riscv64;rvv;vlen=1024",
                            "target": "riscv64;rvv;vlen=256",
                        },
                    ),
                )
            ),
        )
        supported = HostCapabilities(
            system="linux",
            machine="riscv64",
            rvv=True,
            vlen_bits=frozenset({1024}),
            migration_control=True,
            bpf=True,
        )
        self.assertEqual(profile_compatibility(profile, supported).status, "supported")

        unknown = supported.__class__(
            system="linux",
            machine="riscv64",
            rvv=None,
            vlen_bits=None,
            migration_control=True,
            bpf=True,
        )
        self.assertEqual(profile_compatibility(profile, unknown).status, "unknown")

    def test_non_matching_examples_are_hidden_but_all_lists_reasons(self) -> None:
        unsupported = HostCapabilities(
            system="linux",
            machine="x86_64",
            rvv=False,
            vlen_bits=frozenset(),
            migration_control=False,
            bpf=False,
        )
        with tempfile.TemporaryDirectory() as temporary:
            profile = Path(temporary) / "profile.toml"
            profile.write_text(
                "[config]\n"
                "data_root='data'\nworkspace_root='workspaces'\nscalar_root='scalar'\n"
                "[profile]\nname='x'\ntarget_os='linux'\n"
                "target_arch='riscv64'\ntarget_arch_extension='rvv'\n"
                "runtime_scene='linux_riscv64_rvv_v1'\nruntime_abi=1\n"
                "[profile.workflow]\nsteps=[]\n",
                encoding="utf-8",
            )
            with patch("chimera.examples.detect_host_capabilities", return_value=unsupported), \
                 patch("chimera.examples._bundled_profile", return_value=profile):
                hidden = list_examples(profile=profile)
                self.assertEqual(hidden, [])
                shown = list_examples(profile=profile, all_examples=True)
                # The catalog still covers the source examples used by
                # developer/deployer workflows; public CLI dispatch is gone.
                self.assertEqual(len(shown), 8)
                self.assertTrue(all(item.status == "unsupported" for item in shown))


if __name__ == "__main__":
    unittest.main()
