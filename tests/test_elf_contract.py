from __future__ import annotations

from pathlib import Path
import struct
import tempfile
import unittest

from chimera.preprocess.offline.analysis.platform.linux.elf import interpreter, load_base


class ElfContractTests(unittest.TestCase):
    def test_load_base_and_interpreter_are_read_from_program_headers(self) -> None:
        data = bytearray(512)
        data[:6] = b"\x7fELF\x02\x01"
        struct.pack_into("<Q", data, 32, 64)
        struct.pack_into("<HH", data, 54, 56, 2)
        struct.pack_into(
            "<IIQQQQQQ",
            data,
            64,
            1,
            5,
            0,
            0x4000,
            0x4000,
            0x100,
            0x100,
            0x1000,
        )
        loader = b"/lib/ld-linux-riscv64-lp64d.so.1\0"
        struct.pack_into(
            "<IIQQQQQQ",
            data,
            120,
            3,
            4,
            256,
            0x4100,
            0x4100,
            len(loader),
            len(loader),
            1,
        )
        data[256 : 256 + len(loader)] = loader
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "sample.elf"
            path.write_bytes(data)

            self.assertEqual(load_base(path), 0x4000)
            self.assertEqual(
                interpreter(path),
                "/lib/ld-linux-riscv64-lp64d.so.1",
            )


if __name__ == "__main__":
    unittest.main()
