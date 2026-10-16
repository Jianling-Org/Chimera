"""Minimal runtime-only configuration used by :mod:`chimera-user`."""

from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10 source-test fallback
    import tomli as tomllib


@dataclass(frozen=True)
class UserRuntime:
    bpf_map: Path
    ai_thread_control: Path


@dataclass(frozen=True)
class UserSettings:
    workspace_root: Path
    runtime: UserRuntime

    @property
    def bpf_map(self) -> str:
        return str(self.runtime.bpf_map)

    @property
    def ai_thread_control(self) -> str:
        return str(self.runtime.ai_thread_control)


def user_config_path() -> Path:
    return Path(os.environ.get("CHIMERA_USER_CONFIG", str(Path.home() / ".chimera" / "user.toml"))).expanduser().resolve()


def _defaults() -> UserSettings:
    root = Path(os.environ.get("CHIMERA_WORKSPACE_ROOT", str(Path.home() / ".chimera" / "workspaces")))
    return UserSettings(
        root.resolve(),
        UserRuntime(
            Path(os.environ.get("CHIMERA_BPF_MAP", "/sys/fs/bpf/pid_uprobe_map")),
            Path(os.environ.get("CHIMERA_AI_THREAD_CONTROL", "/proc/set_ai_thread")),
        ),
    )


def init_user_config(*, workspace_root: str | Path | None = None,
                     bpf_map: str | Path | None = None,
                     ai_thread_control: str | Path | None = None) -> Path:
    """Create runtime directories and persist only runtime-facing settings."""
    defaults = _defaults()
    settings = UserSettings(
        Path(workspace_root or defaults.workspace_root).expanduser().resolve(),
        UserRuntime(
            Path(bpf_map or defaults.runtime.bpf_map).expanduser(),
            Path(ai_thread_control or defaults.runtime.ai_thread_control).expanduser(),
        ),
    )
    settings.workspace_root.mkdir(parents=True, exist_ok=True)
    path = user_config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "[runtime]\n"
        f"workspace_root = {json.dumps(settings.workspace_root.as_posix())}\n"
        f"bpf_map = {json.dumps(settings.runtime.bpf_map.as_posix())}\n"
        f"ai_thread_control = {json.dumps(settings.runtime.ai_thread_control.as_posix())}\n",
        encoding="utf-8",
    )
    return path


def load_user_settings() -> UserSettings:
    path = user_config_path()
    if not path.is_file():
        # Runtime commands are usable in a clean or read-only home.  Persist
        # the lightweight config when possible, but keep the documented
        # defaults in memory when the user has not granted write access.
        try:
            init_user_config()
        except OSError:
            defaults = _defaults()
            try:
                defaults.workspace_root.mkdir(parents=True, exist_ok=True)
            except OSError:
                # ``list`` and explicit-path consumers remain usable when
                # both the home and configured Workspace root are read-only.
                pass
            return defaults
    try:
        document = tomllib.loads(path.read_text(encoding="utf-8"))
        table = document.get("runtime", {})
        if not isinstance(table, dict):
            raise ValueError("[runtime] must be a table")
    except (OSError, ValueError) as error:
        raise RuntimeError(f"invalid user runtime configuration: {path}: {error}") from error
    defaults = _defaults()
    # Environment overrides are useful for isolated installs and tests and
    # must take precedence over a stale user.toml written by an older setup.
    root_value = os.environ.get(
        "CHIMERA_WORKSPACE_ROOT",
        table.get("workspace_root", defaults.workspace_root),
    )
    root = Path(root_value).expanduser().resolve()
    runtime = UserRuntime(
        Path(os.environ.get(
            "CHIMERA_BPF_MAP", table.get("bpf_map", defaults.runtime.bpf_map)
        )).expanduser(),
        Path(os.environ.get(
            "CHIMERA_AI_THREAD_CONTROL",
            table.get("ai_thread_control", defaults.runtime.ai_thread_control),
        )).expanduser(),
    )
    root.mkdir(parents=True, exist_ok=True)
    return UserSettings(root, runtime)


__all__ = ["UserRuntime", "UserSettings", "init_user_config", "load_user_settings", "user_config_path"]
