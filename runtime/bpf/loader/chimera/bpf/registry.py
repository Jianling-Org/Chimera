"""Chimera BPF migratable-file registration queue ABI.

The kernel consumes one BPF-map value as::

    struct uprobe_info {
        __u64 inode;
        __u64 offsets[20];
        int   offset_cnt;
        bool  is_attached;
    };

All integer fields are encoded little-endian.  Only the zero-offset form is
submitted (``offsets[0] == 0``, ``offset_cnt == 1``), which announces one
migratable ELF inode to the kernel; safety points are patched into the
translated image as ebreak traps during prepare instead of being registered
here.  The map key is only an opaque request identifier used by the kernel
to iterate, look up, and delete entries; it has no migration semantics.
"""

from __future__ import annotations

from dataclasses import dataclass
import errno
import os
from pathlib import Path
import struct
import time
from typing import Callable, Iterable

from chimera.preprocess.offline.analysis.core.monitor import (
    argument,
    local,
    monitored,
)
from .syscall import BpfSyscallError, LinuxBpfMap


MAX_UPROBE_OFFSETS = 20
UPROBE_KEY_FORMAT = "<I"
UPROBE_INFO_FORMAT = "<Q20QiB3x"
UPROBE_KEY_SIZE = struct.calcsize(UPROBE_KEY_FORMAT)
UPROBE_INFO_SIZE = struct.calcsize(UPROBE_INFO_FORMAT)
BATCH_MAP_ENTRIES = 64


class RegistrationError(RuntimeError):
    """Raised when a registration request cannot be encoded or submitted."""


class RegistrationKeyNotFound(RegistrationError):
    """Raised when a key cannot be found in the BPF map (e.g. already consumed)."""


def _compute_key(inode: int, chunk_index: int) -> int:
    """Return a deterministic 32-bit map key from (inode, chunk_index).

    Uses FNV-1a 32-bit hash so that re-registering the same (file, chunk)
    pair always produces the same key.  Paired with ``BPF_ANY`` (update or
    create), this lets the kernel consumer drain entries between retries
    without consuming new map capacity.
    """

    payload = struct.pack("<QI", inode, chunk_index)
    h = 0x811C9DC5
    for byte in payload:
        h = ((h ^ byte) * 0x01000193) & 0xFFFFFFFF
    return h


@dataclass(frozen=True)
class UprobeInfo:
    """Python representation of the kernel's ``struct uprobe_info``."""

    inode: int
    offsets: tuple[int, ...]
    is_attached: bool = False

    def __post_init__(self) -> None:
        if not 1 <= len(self.offsets) <= MAX_UPROBE_OFFSETS:
            raise ValueError(
                f"offset count must be in 1..{MAX_UPROBE_OFFSETS}, "
                f"got {len(self.offsets)}"
            )
        if not 0 <= self.inode <= 0xFFFFFFFFFFFFFFFF:
            raise ValueError("inode does not fit in __u64")
        for offset in self.offsets:
            if not 0 <= offset <= 0xFFFFFFFFFFFFFFFF:
                raise ValueError(f"offset does not fit in __u64: {offset}")

    @classmethod
    def for_file(cls, elf_path: str | Path, offsets: Iterable[int]) -> "UprobeInfo":
        inode = os.stat(elf_path).st_ino
        return cls(inode=inode, offsets=tuple(int(offset) for offset in offsets))

    def pack(self) -> bytes:
        """Encode exactly 176 bytes using the kernel's little-endian layout."""

        padded_offsets = self.offsets + (0,) * (MAX_UPROBE_OFFSETS - len(self.offsets))
        encoded = struct.pack(
            UPROBE_INFO_FORMAT,
            self.inode,
            *padded_offsets,
            len(self.offsets),
            int(self.is_attached),
        )
        if len(encoded) != UPROBE_INFO_SIZE:
            raise AssertionError(
                f"encoded uprobe_info size is {len(encoded)}, "
                f"expected {UPROBE_INFO_SIZE}"
            )
        return encoded


@dataclass
class RegistrationMetrics:
    batch_calls: int = 0
    single_calls: int = 0
    fallbacks: int = 0
    retries: int = 0
    submitted: int = 0

    def snapshot(self) -> tuple[int, int, int, int, int]:
        return (
            self.batch_calls,
            self.single_calls,
            self.fallbacks,
            self.retries,
            self.submitted,
        )


@dataclass(frozen=True)
class _PreparedRequest:
    key_value: int
    key: bytes
    value: bytes
    chunk_index: int
    chunk_total: int


class PinnedUprobeMap:
    """Submit ``UprobeInfo`` requests through one pinned-map file descriptor."""

    def __init__(
        self,
        pinned_path: str | Path,
        *,
        dry_run: bool = False,
        _map_factory=LinuxBpfMap.open,
    ):
        self.pinned_path = Path(pinned_path)
        self.dry_run = dry_run
        self.metrics = RegistrationMetrics()
        self._map = None
        self._single_only = False
        self._dry_batch_index = 0
        if not dry_run:
            try:
                try:
                    self._map = _map_factory(self.pinned_path)
                except OSError as error:
                    raise RegistrationError(
                        f"cannot open pinned BPF map {self.pinned_path}: {error}"
                    ) from error
                self._validate_layout()
            except BaseException as error:
                try:
                    self.close()
                except BaseException as close_error:
                    error.add_note(
                        f"closing the BPF map also failed: {close_error}"
                    )
                raise

    def __enter__(self) -> "PinnedUprobeMap":
        return self

    def __exit__(self, _type, _value, _traceback) -> None:
        self.close()

    def close(self) -> None:
        if self._map is None:
            return
        map_handle = self._map
        self._map = None
        map_handle.close()

    @monitored(
        "runtime.bpf.map",
        variables=(
            argument("self", label="map_path", path=("pinned_path",)),
            local("expected_key_size"),
            local("expected_value_size"),
            local("actual_key_size"),
            local("actual_value_size"),
        ),
    )
    def _validate_layout(self) -> None:
        expected_key_size = UPROBE_KEY_SIZE
        expected_value_size = UPROBE_INFO_SIZE
        if self.dry_run:
            return
        try:
            info = self._require_map().info()
        except (OSError, BpfSyscallError) as error:
            raise RegistrationError(
                f"cannot inspect pinned BPF map {self.pinned_path}: {error}"
            ) from error
        actual_key_size = info.key_size
        actual_value_size = info.value_size
        if actual_key_size != expected_key_size or actual_value_size != expected_value_size:
            raise RegistrationError(
                "uprobe map ABI mismatch: "
                f"expected key_size={expected_key_size}, "
                f"value_size={expected_value_size}; "
                f"got key_size={actual_key_size}, "
                f"value_size={actual_value_size}"
            )

    def _require_map(self):
        if self._map is None:
            raise RegistrationError(f"BPF map {self.pinned_path} is closed")
        return self._map

    @staticmethod
    def _prepare(
        info: UprobeInfo,
        *,
        chunk_index: int,
        chunk_total: int,
    ) -> _PreparedRequest:
        key_value = _compute_key(info.inode, chunk_index)
        return _PreparedRequest(
            key_value=key_value,
            key=struct.pack(UPROBE_KEY_FORMAT, key_value),
            value=info.pack(),
            chunk_index=chunk_index,
            chunk_total=chunk_total,
        )

    def _confirm(
        self,
        requests: Iterable[_PreparedRequest],
        on_submit: Callable[[int], None] | None,
    ) -> list[int]:
        confirmed: list[int] = []
        for request in requests:
            self.metrics.submitted += 1
            confirmed.append(request.key_value)
            if on_submit is not None:
                on_submit(request.key_value)
            if (
                request.chunk_total > 1
                and request.chunk_index % 1000 == 0
            ):
                print(
                    f"chimera: registered chunk "
                    f"{request.chunk_index}/{request.chunk_total}",
                    flush=True,
                )
        return confirmed

    def _submit_one(
        self,
        request: _PreparedRequest,
        on_submit: Callable[[int], None] | None,
    ) -> int:
        retries = 0
        while True:
            self.metrics.single_calls += 1
            try:
                self._require_map().update(request.key, request.value)
                return self._confirm((request,), on_submit)[0]
            except BpfSyscallError as error:
                if error.errno != errno.E2BIG:
                    raise RegistrationError(
                        f"cannot update pinned BPF map {self.pinned_path}: {error}"
                    ) from error
                retries += 1
                self.metrics.retries += 1
                if retries > 300:
                    raise RegistrationError(
                        f"BPF map {self.pinned_path} is full "
                        f"(E2BIG after {retries} retries); ensure the kernel-side "
                        "uprobe consumer is running"
                    ) from error
                if retries >= 10:
                    print(
                        f"chimera: consumer slow, retry {retries} "
                        f"for chunk {request.chunk_index}",
                        flush=True,
                    )
                time.sleep(min(0.1 * retries, 1.0))

    def _submit_batch(
        self,
        requests: tuple[_PreparedRequest, ...],
        on_submit: Callable[[int], None] | None,
    ) -> list[int]:
        confirmed: list[int] = []
        remaining = requests
        no_progress_retries = 0
        unsupported = {errno.EINVAL, errno.EOPNOTSUPP}
        if hasattr(errno, "ENOTSUP"):
            unsupported.add(errno.ENOTSUP)

        while remaining:
            self.metrics.batch_calls += 1
            try:
                processed = self._require_map().update_batch(
                    tuple(request.key for request in remaining),
                    tuple(request.value for request in remaining),
                )
            except BpfSyscallError as error:
                if error.errno == errno.EFAULT:
                    raise RegistrationError(
                        f"cannot batch-update pinned BPF map {self.pinned_path}: "
                        f"{error}; the failing batch may contain unconfirmed updates"
                    ) from error

                processed = min(max(error.processed, 0), len(remaining))
                if processed:
                    confirmed.extend(self._confirm(remaining[:processed], on_submit))
                    remaining = remaining[processed:]
                    no_progress_retries = 0

                if error.errno == errno.E2BIG:
                    self.metrics.retries += 1
                    if not processed:
                        no_progress_retries += 1
                    if no_progress_retries > 300:
                        raise RegistrationError(
                            f"BPF map {self.pinned_path} is full "
                            f"(E2BIG after {no_progress_retries} retries without "
                            "progress); ensure the kernel-side uprobe consumer is running"
                        ) from error
                    if no_progress_retries >= 10:
                        print(
                            f"chimera: consumer slow, batch retry "
                            f"{no_progress_retries}",
                            flush=True,
                        )
                    time.sleep(min(0.1 * max(no_progress_retries, 1), 1.0))
                    continue

                if error.errno in unsupported and not processed and remaining:
                    self._submit_one(remaining[0], on_submit)
                    confirmed.append(remaining[0].key_value)
                    remaining = remaining[1:]
                    self._single_only = True
                    self.metrics.fallbacks += 1
                    for request in remaining:
                        confirmed.append(self._submit_one(request, on_submit))
                    return confirmed

                raise RegistrationError(
                    f"cannot batch-update pinned BPF map {self.pinned_path}: {error}"
                ) from error

            processed = min(max(processed, 0), len(remaining))
            if not processed:
                raise RegistrationError(
                    f"BPF batch update for {self.pinned_path} reported no progress"
                )
            confirmed.extend(self._confirm(remaining[:processed], on_submit))
            remaining = remaining[processed:]
        return confirmed

    def submit(
        self,
        info: UprobeInfo,
        *,
        chunk_index: int = 0,
        chunk_total: int | None = None,
    ) -> int:
        """Insert one queue request and return its deterministic 32-bit key.

        The key is a FNV-1a hash of (inode, chunk_index) so that retrying
        after an ``E2BIG`` (map full) error rewrites the same entry once the
        kernel consumer has drained older entries.  The update uses
        ``BPF_ANY`` (omit ``noexist``) for idempotent upsert semantics.
        """

        total = 1 if chunk_total is None else chunk_total
        return self.submit_many(
            ((info, chunk_index, total),),
        )[0]

    def submit_many(
        self,
        items: Iterable[tuple[UprobeInfo, int, int]],
        *,
        on_submit: Callable[[int], None] | None = None,
    ) -> list[int]:
        requests = tuple(
            self._prepare(info, chunk_index=chunk_index, chunk_total=chunk_total)
            for info, chunk_index, chunk_total in items
        )
        if not requests:
            return []
        if len(requests) > BATCH_MAP_ENTRIES:
            raise ValueError(
                f"one BPF submission window may contain at most {BATCH_MAP_ENTRIES} entries"
            )
        if self.dry_run:
            self._dry_batch_index += 1
            self.metrics.submitted += len(requests)
            print(
                "DRY-RUN: operation=update "
                f"batch={self._dry_batch_index} entries={len(requests)} "
                f"key_first=0x{requests[0].key_value:08x} "
                f"key_last=0x{requests[-1].key_value:08x} "
                f"key_size={UPROBE_KEY_SIZE} value_size={UPROBE_INFO_SIZE}"
            )
            keys = [request.key_value for request in requests]
            if on_submit is not None:
                for key in keys:
                    on_submit(key)
            return keys
        if self._single_only or len(requests) == 1:
            return [self._submit_one(request, on_submit) for request in requests]
        return self._submit_batch(requests, on_submit)

    @monitored(
        "runtime.bpf.delete",
        variables=(
            argument("self", label="map_path", path=("pinned_path",)),
            argument("key_value", label="key"),
        ),
    )
    def delete(self, key_value: int) -> None:
        """Delete a previously submitted key during transaction rollback."""

        key = struct.pack(UPROBE_KEY_FORMAT, key_value)
        if self.dry_run:
            print(f"DRY-RUN: operation=delete key=0x{key_value:08x}")
            return
        try:
            self._require_map().delete(key)
        except BpfSyscallError as error:
            if error.errno == errno.ENOENT:
                raise RegistrationKeyNotFound(
                    f"BPF key 0x{key_value:08x} not found (already consumed)"
                ) from error
            raise RegistrationError(
                f"cannot roll back BPF key 0x{key_value:08x}: {error}"
            ) from error


class ChimeraRegistry:
    """High-level registration operations backed by the uprobe queue map."""

    def __init__(self, map_path: str | Path, *, dry_run: bool = False):
        self.queue = PinnedUprobeMap(map_path, dry_run=dry_run)

    def __enter__(self) -> "ChimeraRegistry":
        return self

    def __exit__(self, _type, _value, _traceback) -> None:
        self.close()

    def close(self) -> None:
        self.queue.close()

    def metrics_snapshot(self) -> tuple[int, int, int, int, int]:
        return self.queue.metrics.snapshot()

    def register_migratable_file(self, elf_path: str | Path) -> int:
        """Tell the kernel about a migratable file using the zero-offset form.

        The encoded request contains the file inode, ``offsets[0] == 0``, all
        remaining offsets zero, and ``offset_cnt == 1``.
        """

        return self.queue.submit(
            UprobeInfo.for_file(elf_path, (0,)),
            chunk_index=1,
            chunk_total=1,
        )
