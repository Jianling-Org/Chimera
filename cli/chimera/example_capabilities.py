"""Host capability detection and Profile admission for examples."""

from __future__ import annotations

from dataclasses import dataclass
import platform
from pathlib import Path
import re
import struct
import sys
from typing import Any


_AT_HWCAP = 16
_HWCAP_ISA_V = 1 << 21


@dataclass(frozen=True)
class HostCapabilities:
    system: str
    machine: str
    rvv: bool | None
    # These legacy fields remain for callers that persist older capability
    # snapshots.  Example admission intentionally ignores them; hardware
    # compatibility is limited to OS, architecture and the V extension.
    vlen_bits: frozenset[int] | None = None
    migration_control: bool = False
    bpf: bool = False
    rvv_source: str | None = None
    rvv_reason: str | None = None


@dataclass(frozen=True)
class Compatibility:
    status: str
    reasons: tuple[str, ...] = ()


def _cpuinfo() -> str:
    try:
        return Path("/proc/cpuinfo").read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _auxv_rvv() -> bool | None:
    """Read the Linux process HWCAP V bit when the kernel exposes it."""

    try:
        raw = Path("/proc/self/auxv").read_bytes()
    except OSError:
        return None
    word_size = struct.calcsize("P")
    pair_size = word_size * 2
    if len(raw) < pair_size:
        return None
    fmt = ("<" if sys.byteorder == "little" else ">") + ("Q" if word_size == 8 else "I")
    found = False
    for offset in range(0, len(raw) - pair_size + 1, pair_size):
        key, value = struct.unpack_from(fmt + fmt[-1], raw, offset)
        if key == 0:
            break
        if key == _AT_HWCAP:
            found = True
            return bool(value & _HWCAP_ISA_V)
    return None if not found else False


def _cpuinfo_rvv(info: str) -> bool | None:
    """Parse an ISA token without treating the ``rv32``/``rv64`` prefix as V."""

    match = re.search(r"^\s*isa\s*:\s*(\S+)", info, re.MULTILINE | re.IGNORECASE)
    if match is None:
        return None
    token = match.group(1).lower()
    if not token.startswith(("rv32", "rv64")):
        return None
    extensions = token[4:].split("_")
    # The standard compact base-extension spelling uses ``...v``.  Accept a
    # standalone ``_v`` token as well, but never infer full RVV from ``zve*``.
    return "v" in extensions[0] or any(extension == "v" for extension in extensions[1:])


def detect_host_capabilities() -> HostCapabilities:
    """Read-only host probe; unknown values are never treated as supported."""

    system = platform.system().lower()
    machine = platform.machine().lower()
    if system != "linux" or machine not in {"riscv64", "riscv"}:
        return HostCapabilities(
            system,
            machine,
            False,
            frozenset(),
            False,
            False,
            "platform",
            "host is not a Linux/RISC-V system",
        )

    rvv = _auxv_rvv()
    source = "/proc/self/auxv"
    reason = "AT_HWCAP V bit is set" if rvv else "AT_HWCAP V bit is not available"
    if rvv is None:
        info = _cpuinfo()
        source = "/proc/cpuinfo"
        rvv = _cpuinfo_rvv(info)
        if rvv is True:
            reason = "isa field contains an independent V extension"
        elif rvv is False:
            reason = "isa field is readable but has no independent V extension"
        else:
            reason = "no parseable isa field was found"
    return HostCapabilities(
        system,
        machine,
        rvv,
        None,
        False,
        False,
        source,
        reason,
    )


def profile_compatibility(profile: Any, host: HostCapabilities) -> Compatibility:
    reasons: list[str] = []
    target_os = str(profile.target_os).lower()
    target_arch = str(profile.target_arch).lower()
    host_os = str(host.system).lower()
    host_arch = str(host.machine).lower()
    if target_os != host_os:
        reasons.append(f"requires {profile.target_os}, host is {host.system}")
    if target_arch == "riscv":
        target_arch = "riscv64"
    if host_arch == "riscv":
        host_arch = "riscv64"
    if target_arch != host_arch:
        reasons.append(f"requires {profile.target_arch}, host is {host.machine}")
    requires_rvv = str(profile.target_arch_extension).lower() == "rvv"
    unknown = requires_rvv and host.rvv is None
    if requires_rvv and host.rvv is False:
        detail = f" ({host.rvv_source}: {host.rvv_reason})" if host.rvv_source and host.rvv_reason else ""
        reasons.append(f"RVV is unavailable{detail}")
    if reasons:
        return Compatibility("unsupported", tuple(reasons))
    if unknown:
        detail = "host vector capability could not be confirmed"
        if host.rvv_source and host.rvv_reason:
            detail += f" from {host.rvv_source}: {host.rvv_reason}"
        return Compatibility("unknown", (detail,))
    return Compatibility("supported")


def profile_matches_host_profile(requirement: Any, actual: Any) -> Compatibility:
    """Compare an example's declared target with the installed system Profile."""

    reasons: list[str] = []
    for field in ("target_os", "target_arch", "target_arch_extension"):
        required_value = str(getattr(requirement, field)).lower()
        actual_value = str(getattr(actual, field)).lower()
        if field == "target_arch":
            required_value = "riscv64" if required_value == "riscv" else required_value
            actual_value = "riscv64" if actual_value == "riscv" else actual_value
        if required_value != actual_value:
            reasons.append(
                f"requires {field}={getattr(requirement, field)!r}, "
                f"system Profile has {getattr(actual, field)!r}"
            )
    if reasons:
        return Compatibility("unsupported", tuple(reasons))
    return Compatibility("supported")


__all__ = [
    "Compatibility",
    "HostCapabilities",
    "detect_host_capabilities",
    "profile_compatibility",
    "profile_matches_host_profile",
]
