"""最小版 `chimera-user register`:把单个文件以零偏移形式注册进内核 pinned BPF map(仅 Linux)。

与 runtime/bpf/loader 生产实现等价的最小路径:
    key   = FNV-1a32(inode, chunk_index=1)          -> 4 字节
    value = struct uprobe_info 零偏移形式            -> 176 字节, 格式 <Q20QiB3x
    提交  = bpf(BPF_OBJ_GET) 开 map -> bpf(BPF_MAP_UPDATE_ELEM, BPF_ANY)

用法: python register_file.py <文件> [pinned_map路径]
      pinned_map路径 缺省为 /sys/fs/bpf/pid_uprobe_map
"""
import ctypes
import os
import struct
import sys

_libc = None  # 懒加载:仅真正发起 syscall 时需要(Windows 上跑单测 mock _bpf 即可)


class _Attr(ctypes.Structure):  # union bpf_attr 的前 32 字节(OBJ_GET / MAP_UPDATE_ELEM 共用)
    _fields_ = [("a", ctypes.c_uint64), ("b", ctypes.c_uint64),
                ("c", ctypes.c_uint64), ("d", ctypes.c_uint64)]


def _bpf(cmd, attr):  # __NR_bpf = 280 (riscv64)
    global _libc
    if _libc is None:
        _libc = ctypes.CDLL("libc.so.6", use_errno=True)
    result = _libc.syscall(280, cmd, ctypes.byref(attr), ctypes.sizeof(attr))
    if result == -1:
        raise OSError(ctypes.get_errno(), os.strerror(ctypes.get_errno()))
    return result


def register_file(path, map_path="/sys/fs/bpf/pid_uprobe_map"):
    """把 path 的 inode 注册到 map_path(默认 /sys/fs/bpf/pid_uprobe_map),返回 32-bit map key。"""
    inode = os.stat(path).st_ino
    key32 = 0x811C9DC5
    for byte in struct.pack("<QI", inode, 1):                # chunk_index=1
        key32 = ((key32 ^ byte) * 0x01000193) & 0xFFFFFFFF  # FNV-1a 32
    key = ctypes.create_string_buffer(struct.pack("<I", key32))
    value = ctypes.create_string_buffer(
        struct.pack("<Q20QiB3x", inode, *(0,) * 20, 1, 0))  # 零偏移形式
    name = ctypes.create_string_buffer(os.fsencode(map_path))
    fd = _bpf(7, _Attr(a=ctypes.addressof(name)))            # BPF_OBJ_GET
    try:
        _bpf(2, _Attr(a=fd, b=ctypes.addressof(key),         # BPF_MAP_UPDATE_ELEM
                      c=ctypes.addressof(value)))            # flags=0 即 BPF_ANY
    finally:
        os.close(fd)
    return key32


if __name__ == "__main__":
    map_path = sys.argv[2] if len(sys.argv) > 2 else "/sys/fs/bpf/pid_uprobe_map"
    print(f"registered key=0x{register_file(sys.argv[1], map_path):08x}")
