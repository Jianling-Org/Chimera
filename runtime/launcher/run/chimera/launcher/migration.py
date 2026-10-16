"""Scene-selected migration control semantics."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path
import re


SceneKey = tuple[str, str, str, str]


@dataclass(frozen=True)
class MigrationAdapter:
    """Encode a scene route and thread id for its control interface."""

    key: SceneKey
    routes: dict[str, Callable[[int], int]]
    required_signal_handlers: tuple[int, ...] = ()

    def encode(self, direction: str, tid: int) -> int:
        try:
            encoder = self.routes[direction]
        except KeyError as error:
            raise ValueError(
                f"migration route is unsupported for scene/target: {direction}"
            ) from error
        value = encoder(tid)
        if not isinstance(value, int) or isinstance(value, bool) or value == 0:
            raise ValueError(f"migration adapter returned an invalid control value: {value!r}")
        return value

    def require_ready(self, tgid: int, tids: Iterable[int], *, proc_root: Path) -> None:
        """Preflight every selected thread before the caller writes any request.

        The current Linux scene loads its Workspace before installing these
        handlers. A PID and CHIMERA_WORKSPACE can already exist before that
        installation; neither is permission to deliver a migration signal.
        This observes installed dispositions, not a migration-completion ACK.
        """
        if not self.required_signal_handlers:
            raise RuntimeError("migration readiness policy is missing for scene/target")
        for tid in tids:
            status = proc_root / str(tid) / "status"
            try:
                fields = {}
                # Task names can contain non-ASCII bytes; only the numeric
                # fields below participate in readiness and are parsed strictly.
                for line in status.read_text(encoding="utf-8", errors="replace").splitlines():
                    name, separator, value = line.partition(":")
                    if separator and name in {"Tgid", "SigCgt", "SigIgn", "SigBlk"}:
                        if name in fields:
                            raise ValueError(f"duplicate {name}")
                        fields[name] = value.strip()
                current_tgid = int(fields["Tgid"])
                masks = {}
                for name in ("SigCgt", "SigIgn", "SigBlk"):
                    value = fields[name]
                    if not re.fullmatch(r"[0-9a-fA-F]+", value):
                        raise ValueError(f"invalid {name}")
                    masks[name] = int(value, 16)
            except (OSError, UnicodeError, KeyError, ValueError) as error:
                raise RuntimeError(
                    f"cannot verify migration readiness from thread {tid} status: {status}"
                ) from error
            if current_tgid != tgid:
                raise RuntimeError(f"thread {tid} status no longer belongs to group {tgid}")
            uncaught = [
                number for number in self.required_signal_handlers
                if not masks["SigCgt"] & (1 << (number - 1))
                or masks["SigIgn"] & (1 << (number - 1))
            ]
            blocked = [
                number for number in self.required_signal_handlers
                if masks["SigBlk"] & (1 << (number - 1))
            ]
            if uncaught:
                raise RuntimeError(
                    f"migration not ready for thread {tid}: signal handlers "
                    f"{uncaught} are not installed; retry after Runtime initialization"
                )
            if blocked:
                raise RuntimeError(
                    f"migration not ready for thread {tid}: signals {blocked} are blocked"
                )


class MigrationAdapterCatalog:
    def __init__(self, adapters=()) -> None:
        self._adapters: dict[SceneKey, MigrationAdapter] = {}
        for adapter in adapters:
            if adapter.key in self._adapters:
                raise ValueError(f"duplicate migration adapter: {adapter.key}")
            self._adapters[adapter.key] = adapter

    def select(self, key: SceneKey) -> MigrationAdapter:
        try:
            return self._adapters[key]
        except KeyError as error:
            raise RuntimeError(
                "migration is unsupported for scene/target: " + "/".join(key)
            ) from error


def registered_migration_adapters() -> MigrationAdapterCatalog:
    # The route names and control values are scene-owned.  The generic CLI
    # only forwards a route and thread id to this adapter.
    return MigrationAdapterCatalog((MigrationAdapter(
        ("linux", "riscv64", "rvv", "linux_riscv64_rvv_v1"),
        routes={
            "1024-to-256": lambda tid: -tid,
            "256-to-1024": lambda tid: tid,
        },
        # Scene policy, matching signal_handlers.c: SIGTRAP exits translation
        # and signal 41 enters it. The latter is installed last at startup.
        required_signal_handlers=(5, 41),
    ),))


__all__ = ["MigrationAdapter", "MigrationAdapterCatalog", "registered_migration_adapters"]
