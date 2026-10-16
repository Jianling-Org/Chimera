from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from chimera.preprocess.offline.analysis.offsetmap.codegen import export_asm
from chimera.preprocess.offline.analysis.arch.riscv.rvv import RvvArtifactEmitter
from chimera.runtime.bpf import UprobeInfo


class MetadataAndBpfAbiTests(unittest.TestCase):
    def test_offset_map_assembly_contains_version_and_independently_sorted_maps(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "metadata.S"
            export_asm(
                {0x30: 0x10, 0x10: 0x40},
                output,
                "main.so",
                emitter=RvvArtifactEmitter(),
            )
            assembly = output.read_text(encoding="utf-8")

        self.assertIn(".globl chimera_main_so_offset_map_abi", assembly)
        self.assertIn("chimera_main_so_forward_entries:", assembly)
        self.assertIn("chimera_main_so_reverse_entries:", assembly)
        forward = assembly.index(".dword 0x0000000000000010, 0x0000000000000040")
        forward_later = assembly.index(".dword 0x0000000000000030, 0x0000000000000010")
        self.assertLess(forward, forward_later)
        reverse_section = assembly.index("chimera_main_so_reverse_entries:")
        reverse_first = assembly.index(
            ".dword 0x0000000000000010, 0x0000000000000030", reverse_section
        )
        reverse_later = assembly.index(
            ".dword 0x0000000000000040, 0x0000000000000010", reverse_section
        )
        self.assertLess(reverse_first, reverse_later)

    def test_uprobe_info_matches_176_byte_little_endian_golden_sample(self) -> None:
        encoded = UprobeInfo(
            inode=0x0102030405060708,
            offsets=(0x1112131415161718,),
            is_attached=True,
        ).pack()

        self.assertEqual(len(encoded), 176)
        self.assertEqual(encoded[:8].hex(), "0807060504030201")
        self.assertEqual(encoded[8:16].hex(), "1817161514131211")
        self.assertEqual(encoded[168:176].hex(), "0100000001000000")


if __name__ == "__main__":
    unittest.main()
