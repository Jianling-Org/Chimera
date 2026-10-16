"""ELF state registry shared by check-elf / llvm / prepare.

Every ELF that chimera has seen lives in one registry file keyed by its
canonical path.  The registry records the content hash observed at the time
of the last status transition so stale entries (binary rebuilt since) are
detectable: any consumer that finds a hash mismatch must treat the entry as
UNCHECKED.

States
------
UNCHECKED    default for unknown ELFs; nothing has been recorded.
CHECKED      check-elf found no actionable findings (verified clean).
PROBLEMATIC  check-elf found actionable findings; a decision file was written.
REMEDIATED   chimera-pkg llvm rebuilt this path under the decision file; the old
             check credential is cleared and prepare requires an explicit
             re-check before admission.
"""

from __future__ import annotations

import hashlib
import datetime
import json
import os
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from collections.abc import Mapping

UNCHECKED = "UNCHECKED"
CHECKED = "CHECKED"
PROBLEMATIC = "PROBLEMATIC"
REMEDIATED = "REMEDIATED"

STATUSES = (UNCHECKED, CHECKED, PROBLEMATIC, REMEDIATED)

DEFAULT_REGISTRY_PATH = Path.home() / ".chimera" / "elf_registry.json"


@dataclass(frozen=True)
class ElfStateRecord:
    path: Path                 # canonical path this record is keyed by
    content_hash: str          # sha256 of the file bytes at registration time
    status: str                # CHECKED / PROBLEMATIC / REMEDIATED
    decision_ref: str | None   # decision/report JSON written by check-elf
    updated_at: str
    # Credential for the exact workflow binary-check scope.  Older registry
    # entries omit these fields and therefore cannot satisfy a non-empty
    # check plan.
    check_fingerprint: str | None = None
    check_scope: Mapping | None = None


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical(path: Path | str) -> Path:
    return Path(path).expanduser().resolve()


@contextmanager
def _registry_lock(path: Path):
    """Serialize registry transactions using a stable, separate lock file.

    The JSON inode is replaced on publication, so locking that inode would
    not serialize later writers. Never unlink the lock file: waiters must
    continue to lock the same inode. The OS releases the lock on process exit.
    """
    lock_path = path.with_name(path.name + ".lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with lock_path.open("a+b") as stream:
        if os.name == "nt":
            import msvcrt

            # Windows permits locking a byte beyond EOF; do not write to a
            # byte that a different process may already have locked.
            stream.seek(0)
            msvcrt.locking(stream.fileno(), msvcrt.LK_LOCK, 1)
            try:
                yield
            finally:
                stream.seek(0)
                msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl

            fcntl.flock(stream.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(stream.fileno(), fcntl.LOCK_UN)


class ElfStateRegistry:
    """JSON registry with locked transactions and whole-file atomic replacement."""

    def __init__(self, registry_path: Path | None = None) -> None:
        self.path = canonical(registry_path if registry_path else DEFAULT_REGISTRY_PATH)

    # -- low-level ---------------------------------------------------------

    def _load(self) -> dict[str, dict]:
        if not self.path.is_file():
            return {}
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as error:
            raise RuntimeError(
                f"elf registry is corrupt: {self.path} ({error}); "
                "delete it or fix the file before continuing"
            ) from error
        if not isinstance(data, dict):
            raise RuntimeError(f"elf registry must be an object: {self.path}")
        return data

    def _save(self, data: dict[str, dict]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w", encoding="utf-8", dir=self.path.parent,
                prefix=f".{self.path.name}.", suffix=".tmp", delete=False,
            ) as stream:
                temporary = Path(stream.name)
                json.dump(data, stream, indent=2, sort_keys=True)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.path)
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)

    @staticmethod
    def _key(path: Path | str) -> str:
        return str(canonical(path))

    # -- public API --------------------------------------------------------

    def entry(self, path: Path | str) -> ElfStateRecord | None:
        key = self._key(path)
        # Readers also take the lock, avoiding an open reader obstructing
        # os.replace on Windows while another process publishes a record.
        with _registry_lock(self.path):
            raw = self._load().get(key)
        if raw is None:
            return None
        raw_scope = raw.get("check_scope")
        if not isinstance(raw_scope, Mapping):
            raw_scope = None
        return ElfStateRecord(
            path=canonical(path),
            content_hash=str(raw.get("content_hash", "")),
            status=str(raw.get("status", UNCHECKED)),
            decision_ref=raw.get("decision_ref"),
            updated_at=str(raw.get("updated_at", "")),
            check_fingerprint=raw.get("check_fingerprint"),
            check_scope=raw_scope,
        )

    def effective_status(self, path: Path | str) -> tuple[str, ElfStateRecord | None]:
        """Return the status that governs ``path`` right now.

        An existing record whose stored hash no longer matches the file on
        disk degrades to UNCHECKED — old conclusions must never clear a
        binary that changed since they were produced.
        """

        resolved = canonical(path)
        record = self.entry(resolved)
        if record is None:
            return UNCHECKED, None
        if not resolved.is_file():
            return UNCHECKED, record
        if sha256_of(resolved) != record.content_hash:
            return UNCHECKED, record
        return record.status, record

    def set_status(
        self,
        path: Path | str,
        status: str,
        *,
        decision_ref: str | None = None,
        check_fingerprint: str | None = None,
        check_scope: Mapping | None = None,
        expected_previous: str | None = None,
        require_file: bool = True,
    ) -> ElfStateRecord:
        if status not in STATUSES:
            raise ValueError(f"unknown elf state: {status}")
        resolved = canonical(path)
        exists = resolved.is_file()
        if require_file and not exists:
            raise FileNotFoundError(f"cannot register missing elf: {resolved}")
        # Hash large ELFs before taking the short registry transaction lock;
        # linker work and analysis must not run inside this critical section.
        content_hash = sha256_of(resolved) if exists else ""
        key = self._key(resolved)
        with _registry_lock(self.path):
            data = self._load()
            previous = data.get(key, {})
            previous_status = previous.get("status", UNCHECKED)
            if (
                expected_previous is not None
                and previous_status != expected_previous
            ):
                raise RuntimeError(
                    f"elf state transition expects {expected_previous}, "
                    f"registry says {previous_status!r}: {resolved}"
                )
            now = datetime.datetime.now().isoformat(timespec="seconds")
            record = {
                "content_hash": content_hash,
                "status": status,
                "decision_ref": decision_ref,
                "updated_at": now,
                "check_fingerprint": check_fingerprint,
                "check_scope": dict(check_scope) if check_scope is not None else None,
            }
            data[key] = record
            self._save(data)
        return ElfStateRecord(
            path=resolved,
            content_hash=record["content_hash"],
            status=status,
            decision_ref=decision_ref,
            updated_at=now,
            check_fingerprint=check_fingerprint,
            check_scope=record["check_scope"],
        )


__all__ = [
    "CHECKED",
    "PROBLEMATIC",
    "REMEDIATED",
    "UNCHECKED",
    "ElfStateRecord",
    "ElfStateRegistry",
    "canonical",
    "sha256_of",
]
