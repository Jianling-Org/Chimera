"""tests/register_file.py 的单元测试(mock bpf syscall,不触内核)。

除验证调用序列与 fd 生命周期外,还与生产编码器
chimera.runtime.bpf.registry(UprobeInfo/_compute_key)做 ABI 等价性交叉验证。
"""
from __future__ import annotations

import ctypes
import os
import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import register_file
from chimera.runtime.bpf.registry import UprobeInfo, _compute_key

MAP_PATH = "/sys/fs/bpf/chimera/uprobe_info"
FAKE_FD = 42


class RegisterFileTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.path = Path(temporary.name) / "app.so"
        self.path.write_bytes(b"\x7fELF")
        self.inode = os.stat(self.path).st_ino

    def _register(self):
        calls = []  # OBJ_GET: (7, path); UPDATE_ELEM: (2, map_fd, key_bytes, value_bytes, flags)

        def fake_bpf(cmd, attr):
            if cmd == 7:  # BPF_OBJ_GET
                calls.append((7, ctypes.string_at(attr.a).decode()))
                return FAKE_FD
            # 缓冲区随 register_file 返回即释放,必须在调用时就地拷贝
            calls.append((2, attr.a & 0xFFFFFFFF, ctypes.string_at(attr.b, 4),
                          ctypes.string_at(attr.c, 176), attr.d))
            return 0

        closed = []
        with patch.object(register_file, "_bpf", side_effect=fake_bpf), \
                patch.object(register_file.os, "close", side_effect=closed.append):
            key = register_file.register_file(self.path, MAP_PATH)
        return key, calls, closed

    def test_key_and_value_match_production_abi(self):
        key, calls, _ = self._register()

        self.assertEqual(key, _compute_key(self.inode, 1))
        self.assertEqual(struct.unpack("<I", calls[1][2])[0], key)
        self.assertEqual(calls[1][3], UprobeInfo.for_file(self.path, (0,)).pack())

    def test_value_is_zero_offset_form(self):
        _, calls, _ = self._register()

        inode, *offsets, count, attached = struct.unpack("<Q20QiB3x", calls[1][3])
        self.assertEqual(inode, self.inode)
        self.assertEqual(offsets, [0] * 20)
        self.assertEqual((count, attached), (1, 0))

    def test_syscall_sequence_and_fd_lifecycle(self):
        _, calls, closed = self._register()

        self.assertEqual([c[0] for c in calls], [7, 2])  # OBJ_GET -> UPDATE_ELEM
        self.assertEqual(calls[0][1], MAP_PATH)
        self.assertEqual(calls[1][1], FAKE_FD)  # map_fd = OBJ_GET 返回值
        self.assertEqual(calls[1][4], 0)        # flags = BPF_ANY
        self.assertEqual(closed, [FAKE_FD])     # fd 恰好关闭一次

    def test_fd_closed_when_update_fails(self):
        def fake_bpf(cmd, attr):
            if cmd == 7:
                return FAKE_FD
            raise OSError(28, "No space left on device")

        closed = []
        with patch.object(register_file, "_bpf", side_effect=fake_bpf), \
                patch.object(register_file.os, "close", side_effect=closed.append), \
                self.assertRaises(OSError):
            register_file.register_file(self.path, MAP_PATH)
        self.assertEqual(closed, [FAKE_FD])


if __name__ == "__main__":
    unittest.main()
