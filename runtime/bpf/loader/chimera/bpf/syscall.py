"""Minimal Linux/RISC-V BPF map syscall bindings used by registration."""

from __future__ import annotations

import ctypes
from dataclasses import dataclass
import errno
import os
import platform
from pathlib import Path


# Single underscore on purpose: a double-underscore name referenced from
# inside LinuxBpfMap methods would be mangled to _LinuxBpfMap__NR_BPF.
_NR_BPF = 280

BPF_MAP_UPDATE_ELEM = 2
BPF_MAP_DELETE_ELEM = 3
BPF_OBJ_GET = 7
BPF_OBJ_GET_INFO_BY_FD = 15
BPF_MAP_UPDATE_BATCH = 26

BPF_ANY = 0


class _BpfAttrMapElement(ctypes.Structure):
    _fields_ = (
        ("map_fd", ctypes.c_uint32),
        ("_padding", ctypes.c_uint32),
        ("key", ctypes.c_uint64),
        ("value", ctypes.c_uint64),
        ("flags", ctypes.c_uint64),
    )


class _BpfAttrObject(ctypes.Structure):
    _fields_ = (
        ("pathname", ctypes.c_uint64),
        ("bpf_fd", ctypes.c_uint32),
        ("file_flags", ctypes.c_uint32),
        ("path_fd", ctypes.c_int32),
    )


class _BpfAttrInfo(ctypes.Structure):
    _fields_ = (
        ("bpf_fd", ctypes.c_uint32),
        ("info_len", ctypes.c_uint32),
        ("info", ctypes.c_uint64),
    )


class _BpfAttrMapBatch(ctypes.Structure):
    _fields_ = (
        ("in_batch", ctypes.c_uint64),
        ("out_batch", ctypes.c_uint64),
        ("keys", ctypes.c_uint64),
        ("values", ctypes.c_uint64),
        ("count", ctypes.c_uint32),
        ("map_fd", ctypes.c_uint32),
        ("elem_flags", ctypes.c_uint64),
        ("flags", ctypes.c_uint64),
    )


class _BpfMapInfo(ctypes.Structure):
    _fields_ = (
        ("type", ctypes.c_uint32),
        ("id", ctypes.c_uint32),
        ("key_size", ctypes.c_uint32),
        ("value_size", ctypes.c_uint32),
        ("max_entries", ctypes.c_uint32),
        ("map_flags", ctypes.c_uint32),
    )


@dataclass(frozen=True)
class BpfMapInfo:
    key_size: int
    value_size: int


class BpfSyscallError(OSError):
    """A failed ``bpf(2)`` command, including batch progress when known."""

    def __init__(self, command: str, error_number: int, *, processed: int = 0):
        super().__init__(error_number, os.strerror(error_number))
        self.command = command
        self.processed = processed

    def __str__(self) -> str:
        return f"{self.command}: {super().__str__()}"


class LinuxBpfMap:
    """One open pinned BPF map file descriptor."""

    def __init__(self, fd: int, syscall_function):
        self.fd = fd
        self._syscall = syscall_function

    @classmethod
    def open(cls, pinned_path: str | Path) -> "LinuxBpfMap":
        system = platform.system().lower()
        machine = platform.machine().lower()
        if system != "linux" or machine not in {"riscv", "riscv64"}:
            raise BpfSyscallError("BPF_OBJ_GET", errno.ENOSYS)

        libc = ctypes.CDLL(None, use_errno=True)
        syscall_function = libc.syscall
        syscall_function.restype = ctypes.c_long
        path = ctypes.create_string_buffer(os.fsencode(pinned_path))
        attr = _BpfAttrObject(pathname=ctypes.addressof(path))
        result = syscall_function(
            ctypes.c_long(_NR_BPF),
            ctypes.c_int(BPF_OBJ_GET),
            ctypes.byref(attr),
            ctypes.c_uint(ctypes.sizeof(attr)),
        )
        if result == -1:
            raise BpfSyscallError("BPF_OBJ_GET", ctypes.get_errno())
        return cls(int(result), syscall_function)

    def __enter__(self) -> "LinuxBpfMap":
        return self

    def __exit__(self, _type, _value, _traceback) -> None:
        self.close()

    def _invoke(self, command: int, name: str, attr, *, processed: int = 0) -> None:
        result = self._syscall(
            ctypes.c_long(_NR_BPF),
            ctypes.c_int(command),
            ctypes.byref(attr),
            ctypes.c_uint(ctypes.sizeof(attr)),
        )
        if result == -1:
            raise BpfSyscallError(name, ctypes.get_errno(), processed=processed)

    def info(self) -> BpfMapInfo:
        info = _BpfMapInfo()
        attr = _BpfAttrInfo(
            bpf_fd=self.fd,
            info_len=ctypes.sizeof(info),
            info=ctypes.addressof(info),
        )
        self._invoke(BPF_OBJ_GET_INFO_BY_FD, "BPF_OBJ_GET_INFO_BY_FD", attr)
        return BpfMapInfo(key_size=int(info.key_size), value_size=int(info.value_size))

    def update(self, key: bytes, value: bytes) -> None:
        key_buffer = ctypes.create_string_buffer(key)
        value_buffer = ctypes.create_string_buffer(value)
        attr = _BpfAttrMapElement(
            map_fd=self.fd,
            key=ctypes.addressof(key_buffer),
            value=ctypes.addressof(value_buffer),
            flags=BPF_ANY,
        )
        self._invoke(BPF_MAP_UPDATE_ELEM, "BPF_MAP_UPDATE_ELEM", attr)

    def update_batch(self, keys: tuple[bytes, ...], values: tuple[bytes, ...]) -> int:
        if not keys or len(keys) != len(values):
            raise ValueError("batch keys and values must have the same non-zero length")
        requested = len(keys)
        key_buffer = ctypes.create_string_buffer(b"".join(keys))
        value_buffer = ctypes.create_string_buffer(b"".join(values))
        attr = _BpfAttrMapBatch(
            keys=ctypes.addressof(key_buffer),
            values=ctypes.addressof(value_buffer),
            count=len(keys),
            map_fd=self.fd,
            elem_flags=BPF_ANY,
        )
        try:
            self._invoke(BPF_MAP_UPDATE_BATCH, "BPF_MAP_UPDATE_BATCH", attr)
        except BpfSyscallError as error:
            reported = int(attr.count)
            error.processed = reported if 0 <= reported < requested else 0
            raise
        return int(attr.count)

    def delete(self, key: bytes) -> None:
        key_buffer = ctypes.create_string_buffer(key)
        attr = _BpfAttrMapElement(
            map_fd=self.fd,
            key=ctypes.addressof(key_buffer),
        )
        self._invoke(BPF_MAP_DELETE_ELEM, "BPF_MAP_DELETE_ELEM", attr)

    def close(self) -> None:
        if self.fd < 0:
            return
        fd = self.fd
        self.fd = -1
        os.close(fd)


__all__ = ["BpfMapInfo", "BpfSyscallError", "LinuxBpfMap"]
