from __future__ import annotations

from pathlib import Path
import struct
import tempfile
import unittest

from chimera.runtime.scene_contracts import (
    RuntimeArtifactContract,
    registered_runtime_artifact_contracts,
)
from chimera.preprocess.offline.analysis.build_runtime.model import validate_runtime_elf
from chimera.runtime.scene_contracts.composition import (
    registered_runtime_artifact_contracts as composed_catalog,
)


class RuntimeSceneContractTests(unittest.TestCase):
    @staticmethod
    def _write_elf(path: Path, *, elf_class: int = 2, elf_data: int = 1,
                   machine: int = 243, e_type: int = 3, version: int = 1,
                   e_shoff: int = 0, ehsize: int | None = None) -> None:
        order = "<" if elf_data == 1 else ">"
        ident = b"\x7fELF" + bytes((elf_class, elf_data, 1)) + bytes(9)
        if elf_class == 1:
            expected_ehsize = 52 if ehsize is None else ehsize
            data = struct.pack(
                order + "16sHHIIIIIHHHHHH",
                ident, e_type, machine, version, 0, 0, e_shoff, 0,
                expected_ehsize, 32, 0, 40, 0, 0,
            )
        else:
            expected_ehsize = 64 if ehsize is None else ehsize
            data = struct.pack(
                order + "16sHHIQQQIHHHHHH",
                ident, e_type, machine, version, 0, 0, e_shoff, 0,
                expected_ehsize, 56, 0, 64, 0, 0,
            )
        path.write_bytes(data)

    def test_package_and_composition_catalog_share_registered_scene(self) -> None:
        key = ("linux", "riscv64", "rvv", "linux_riscv64_rvv_v1")
        self.assertEqual(
            registered_runtime_artifact_contracts().select(key),
            composed_catalog().select(key),
        )

    def test_current_scene_contract_validates_runtime_elf_and_symbols(self) -> None:
        contract = registered_runtime_artifact_contracts().select(
            ("linux", "riscv64", "rvv", "linux_riscv64_rvv_v1")
        )
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "runtime.so"
            self._write_elf(path)
            contract.validate_elf(path)

        self.assertEqual(1, contract.runtime_abi)
        self.assertIn("chimera_runtime_abi_v1", contract.required_symbols)
        self.assertFalse(contract.missing_symbols(contract.required_symbols))

    def test_contract_rejects_wrong_machine(self) -> None:
        contract = RuntimeArtifactContract(
            target_os="test",
            target_arch="test-arch",
            target_arch_extension="test-ext",
            runtime_scene="test_scene",
            runtime_abi=7,
            elf_machine=243,
            required_symbols=frozenset(),
        )
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "runtime.so"
            self._write_elf(path, machine=62)
            with self.assertRaisesRegex(ValueError, "machine"):
                contract.validate_elf(path)

    def test_contract_rejects_truncated_and_invalid_elf_headers(self) -> None:
        contract = registered_runtime_artifact_contracts().select(
            ("linux", "riscv64", "rvv", "linux_riscv64_rvv_v1")
        )
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "runtime.so"
            path.write_bytes(b"\x7fELF\x02\x01" + b"\0" * 14)
            with self.assertRaisesRegex(ValueError, "header|ELF"):
                contract.validate_elf(path)
            self._write_elf(path, version=2)
            with self.assertRaisesRegex(ValueError, "version"):
                contract.validate_elf(path)
            self._write_elf(path, e_type=2)
            with self.assertRaisesRegex(ValueError, "ET_DYN|type"):
                contract.validate_elf(path)
            self._write_elf(path, ehsize=52)
            with self.assertRaisesRegex(ValueError, "header size"):
                contract.validate_elf(path)

    def test_elf64_reads_ehsize_at_elf64_field_offset(self) -> None:
        contract = registered_runtime_artifact_contracts().select(
            ("linux", "riscv64", "rvv", "linux_riscv64_rvv_v1")
        )
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "runtime.so"
            self._write_elf(path, e_shoff=0x1234, ehsize=64)
            contract.validate_elf(path)

            # Offset 40 belongs to e_shoff for ELF64.  A value there must not
            # make a malformed e_ehsize field pass validation.
            self._write_elf(path, e_shoff=64, ehsize=0)
            with self.assertRaisesRegex(ValueError, "header size"):
                contract.validate_elf(path)

    def test_runtime_validation_rejects_unknown_target_without_fallback(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "runtime.so"
            self._write_elf(path)
            with self.assertRaisesRegex(ValueError, "contract|target|supported"):
                validate_runtime_elf(
                    path,
                    expected_machine=243,
                    target=("unknown", "unknown", "unknown"),
                )

    def test_runtime_validation_checks_explicit_contract_identity(self) -> None:
        contract = registered_runtime_artifact_contracts().select(
            ("linux", "riscv64", "rvv", "linux_riscv64_rvv_v1")
        )
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "runtime.so"
            self._write_elf(path)
            with self.assertRaisesRegex(ValueError, "target|machine"):
                validate_runtime_elf(
                    path,
                    expected_machine=62,
                    target=("linux", "riscv64", "rvv"),
                    contract=contract,
                )

    def test_contract_supports_non_rvv_elf32_big_endian(self) -> None:
        contract = RuntimeArtifactContract(
            target_os="test", target_arch="test-arch", target_arch_extension="be",
            runtime_scene="test_scene", runtime_abi=1, elf_machine=8,
            required_symbols=frozenset(), elf_class=1, elf_data=2,
        )
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "runtime.so"
            self._write_elf(path, elf_class=1, elf_data=2, machine=8)
            contract.validate_elf(path)

    def test_contract_supports_elf64_big_endian(self) -> None:
        contract = RuntimeArtifactContract(
            target_os="test", target_arch="test-arch", target_arch_extension="be64",
            runtime_scene="test_scene_64", runtime_abi=1, elf_machine=8,
            required_symbols=frozenset(), elf_class=2, elf_data=2,
        )
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "runtime.so"
            self._write_elf(path, elf_class=2, elf_data=2, machine=8, e_shoff=0x1234)
            contract.validate_elf(path)


if __name__ == "__main__":
    unittest.main()
