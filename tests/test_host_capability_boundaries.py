from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from chimera.preprocess.offline.analysis.platform.linux.capabilities import (
    validate_offline_capabilities,
)
from chimera.runtime.bpf import register_workspace


class HostCapabilityBoundaryTests(unittest.TestCase):
    def test_linux_offline_capability_rejects_non_linux_host_first(self) -> None:
        config = SimpleNamespace(translator=None)

        with patch("platform.system", return_value="Windows"):
            with self.assertRaisesRegex(RuntimeError, "only on Linux hosts"):
                validate_offline_capabilities(config)

    def test_bpf_registration_rejects_non_linux_riscv_before_registrar(self) -> None:
        manifest = SimpleNamespace(
            entries=(), target_os="linux", target_arch="riscv64",
            target_arch_extension="rvv",
            runtime_scene="linux_riscv64_rvv_v1",
        )

        with (
            patch("platform.system", return_value="Linux"),
            patch("platform.machine", return_value="x86_64"),
            patch("chimera.runtime.bpf.PreparationRegistrar") as registrar,
        ):
            with self.assertRaisesRegex(RuntimeError, "unsupported on linux/x86_64"):
                register_workspace(Path("workspace"), manifest, map_path="map")

        registrar.assert_not_called()

    def test_linux_bpf_map_open_reaches_syscall_without_name_mangling(self) -> None:
        from chimera.runtime.bpf.syscall import LinuxBpfMap

        fake_libc = Mock()
        fake_libc.syscall.return_value = 3

        with (
            patch("platform.system", return_value="Linux"),
            patch("platform.machine", return_value="riscv64"),
            patch("ctypes.CDLL", return_value=fake_libc),
        ):
            handle = LinuxBpfMap.open("/sys/fs/bpf/chimera_uprobe")

        self.assertEqual(handle.fd, 3)


if __name__ == "__main__":
    unittest.main()
