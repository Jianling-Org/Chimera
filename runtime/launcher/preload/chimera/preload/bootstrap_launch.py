"""Launch an ordinary process tree with per-exec registry initialization."""
import os
from pathlib import Path

def bootstrap_tunables(prior: str) -> str:
    """Reserve static TLS for IE relocations in late-loaded translated DSOs.

    The current runtime needs 8384 bytes. Keep 64 KiB per thread available,
    preserving unrelated tunables and any larger explicit reservation.
    """
    key = "glibc.rtld.optional_static_tls"
    retained = []
    reserve = 65536
    for item in prior.split(":"):
        if not item:
            continue
        if item.startswith(key + "="):
            try:
                reserve = max(reserve, int(item.split("=", 1)[1], 0))
            except ValueError:
                raise ValueError("invalid glibc static TLS reservation") from None
        else:
            retained.append(item)
    retained.append(f"{key}={reserve}")
    return ":".join(retained)

def launch_bootstrap(program, arguments, bootstrap, registry, automigrate=False, preference=None):
    if preference not in (None, "prefer-x100", "prefer-a100"):
        raise ValueError("unknown migration preference")
    automigrate = automigrate or preference is not None
    program, bootstrap, registry = Path(program).resolve(), Path(bootstrap).resolve(), Path(registry).resolve()
    if not program.is_file() or not bootstrap.is_file() or not registry.is_file():
        raise ValueError("bootstrap launch requires an executable, bootstrap DSO and existing registry")
    if any(c in str(bootstrap) for c in ": \t\n"):
        raise ValueError("bootstrap path cannot contain loader preload separators")
    environment = dict(os.environ)
    prior = environment.get("LD_PRELOAD", "")
    parts = [str(bootstrap), *prior.replace(":", " ").split()]
    environment["LD_PRELOAD"] = ":".join(dict.fromkeys(parts))
    environment["CHIMERA_BOOTSTRAP"] = str(bootstrap)
    environment["CHIMERA_REGISTRY"] = str(registry)
    environment["CHIMERA_LAUNCH_PID"] = str(os.getpid())
    environment["GLIBC_TUNABLES"] = bootstrap_tunables(environment.get("GLIBC_TUNABLES", ""))
    environment.pop("CHIMERA_WORKSPACE", None)
    environment.pop("CHIMERA_RESOURCES", None)
    environment.pop("CHIMERA_AUTOMIGRATE", None)
    environment.pop("CHIMERA_VERIFY_TABLES_ONLY", None)
    if automigrate:
        # Preference-only opt-in. The new ELF must register readiness itself.
        with open("/proc/" + (preference or "prefer-a100").replace("-", "_"), "w") as control:
            control.write("inherit:" + str(os.getpid()) + "\n")
    os.execve(str(program), [str(program), *arguments], environment)
