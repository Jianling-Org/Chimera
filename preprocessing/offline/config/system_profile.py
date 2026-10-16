"""Select and atomically install the user-level Chimera profile."""

from __future__ import annotations

import json
import os
import platform
import shutil
import sys
from importlib import resources
from pathlib import Path
import tempfile
from typing import Mapping

from .loader import load_configuration
from .model import RuntimeConfig


_CROSS_TOOLCHAIN_PREFIX = "riscv64-linux-gnu-"

# Native distro gcc needs the extension set spelled out; the cross toolchain
# already targets the right ISA by default.
_NATIVE_CC_FLAGS = (
    "-march=rv64imafdc_zba_zbb_zbc_zbs_zfa_zfh_zicond_zicsr_zifencei_"
    "zihintpause_zihpm_zkt_zvbb_zvbc_zve32f_zve32x_zve64d_zve64f_zve64x_"
    "zvfh_zvfhmin_zvkb_zvkg_zvkned_zvknha_zvknhb_zvksed_zvksh_zvkt_zicbop_"
    "zihintntl",
    "-mabi=lp64d",
)

_LIBRARY_ROOT_CANDIDATES = ("/usr/lib/riscv64-linux-gnu", "/lib")

# (step, inline TOML parameters) pairs for the bidirectional default workflow.
_PROFILE_WORKFLOW_STEPS: tuple[tuple[str, str | None], ...] = (
    ("prepare-workspace", None),
    ("build-runtime", None),
    ("disassemble", None),
    ("build-program-model", None),
    ("safety", "min_vlen_bits = 256, compiler_metadata = []"),
    ("translate", 'source = "riscv64;rvv;vlen=1024", target = "riscv64;rvv;vlen=256"'),
    ("translate", 'source = "riscv64;rvv;vlen=256", target = "riscv64;rvv;vlen=1024"'),
    ("offset-map", None),
    ("patch-safepoints", None),
    ("finalize-workspace", None),
)


def profile_directory() -> Path:
    if os.name == "nt":
        return (
            Path(os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming"))
            / "Chimera"
        )
    return Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / "chimera"


def system_profile_path() -> Path:
    return profile_directory() / "system-profile.toml"


def _quote(value: object) -> str:
    return json.dumps(str(value))


def _toml_value(value: object) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        return repr(value)
    if isinstance(value, str):
        return _quote(value)
    if isinstance(value, Mapping):
        return "{" + ", ".join(
            f"{_quote(key)} = {_toml_value(nested)}"
            for key, nested in value.items()
        ) + "}"
    if isinstance(value, (list, tuple)):
        return "[" + ", ".join(_toml_value(item) for item in value) + "]"
    raise TypeError(f"unsupported workflow parameter type: {type(value).__name__}")


def _serialize(configuration) -> str:
    config = configuration.base
    profile = configuration.profile
    lines = [
        "[config]",
        f"data_root = {_quote(config.data_root)}",
        f"workspace_root = {_quote(config.workspace_root)}",
        f"scalar_root = {_quote(config.scalar_root)}",
        f"workspace_name = {_quote(config.workspace_name)}",
    ]
    for binding in config.translators:
        lines += [
            "",
            "[[config.translators]]",
            f"source = {_quote(binding.source.canonical)}",
            f"target = {_quote(binding.target.canonical)}",
            f"translator_path = {_quote(binding.translator_path)}",
        ]
    lines += ["", "[config.tools]"]
    for name in ("python", "cc", "objdump", "nm", "cmake"):
        value = getattr(config.tools, name)
        if value:
            lines.append(f"{name} = {_quote(value)}")
    lines.append(
        "cc_flags = ["
        + ", ".join(_quote(value) for value in config.tools.cc_flags)
        + "]"
    )
    lines += ["", "[config.target_files]"]
    if config.target_files.sysroot is not None:
        lines.append(f"sysroot = {_quote(config.target_files.sysroot)}")
    if config.target_files.cmake_toolchain_file is not None:
        lines.append(
            f"cmake_toolchain_file = {_quote(config.target_files.cmake_toolchain_file)}"
        )
    lines.append(
        "library_roots = ["
        + ", ".join(_quote(value) for value in config.target_files.library_roots)
        + "]"
    )
    lines += [
        "",
        "[config.runtime]",
        f"bpf_map = {_quote(config.runtime.bpf_map)}",
        f"ai_thread_control = {_quote(config.runtime.ai_thread_control)}",
        "",
        "[profile]",
        f"name = {_quote(profile.name)}",
        f"target_os = {_quote(profile.target_os)}",
        f"target_arch = {_quote(profile.target_arch)}",
        f"target_arch_extension = {_quote(profile.target_arch_extension)}",
        f"runtime_scene = {_quote(profile.runtime_scene)}",
        f"runtime_abi = {profile.runtime_abi}",
        "",
        "[profile.workflow]",
        "steps = []",
    ]
    if profile.workflow.steps:
        lines = lines[:-2]
        for step in profile.workflow.steps:
            lines += ["", "[[profile.workflow.steps]]", f"step = {_quote(step.step)}"]
            if step.parameters:
                values = ", ".join(
                    f"{name} = {_toml_value(value)}"
                    for name, value in step.parameters.items()
                )
                lines.append(f"parameters = {{ {values} }}")
    return "\n".join(lines) + "\n"


def install_system_profile(path: Path) -> Path:
    path = path.resolve()
    if not path.is_file():
        raise ValueError("--file must name an existing profile path")
    configuration = load_configuration(path)
    destination = system_profile_path()
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=destination.parent, delete=False
    ) as stream:
        stream.write(_serialize(configuration))
        temporary = Path(stream.name)
    os.replace(temporary, destination)
    return destination


def selected_profile(explicit: Path | None) -> Path:
    """Resolve only an explicitly supplied application/development Profile."""
    if explicit is None:
        raise FileNotFoundError("no Profile supplied; pass --profile PATH")
    path = Path(explicit).expanduser().resolve()
    if not path.is_file():
        raise FileNotFoundError(f"Profile does not exist: {path}")
    return path


def require_supported_host() -> None:
    """Refuse auto-generation on anything but a linux/riscv64 host.

    Use the same read-only capability probe as example admission when the
    package namespace is available.  Profile generation still only needs the
    platform identity here; RVV is recorded by the shared probe and enforced
    when examples or a release are actually selected.
    """
    try:
        from chimera.example_capabilities import detect_host_capabilities
    except ModuleNotFoundError:
        detect_host_capabilities = None
    if detect_host_capabilities is None:
        system = platform.system().lower()
        machine = platform.machine().lower()
    else:
        capabilities = detect_host_capabilities()
        system = capabilities.system
        machine = capabilities.machine
        if machine == "riscv":
            machine = "riscv64"
    if system != "linux" or machine != "riscv64":
        raise ValueError(
            "automatic profile generation requires a linux/riscv64 host "
            f"(detected: {system}/{machine}); this environment is not supported yet"
        )


def _detect_tool(names: tuple[str, ...], *, field: str, warnings: list[str]) -> str:
    """Pick the first name resolvable on PATH, preferring the bare one."""
    for name in names:
        if shutil.which(name):
            return name
    warnings.append(f"{field}: none of [{', '.join(names)}] found on PATH")
    return names[0]


def _bundled_translator_directory() -> Path:
    """Locate rvv_sbt_tool for both wheel and editable/source layouts."""
    candidates: list[Path] = []
    try:
        candidates.append(Path(str(resources.files("chimera.preprocess.translator"))))
    except (ModuleNotFoundError, TypeError, FileNotFoundError, ValueError):
        pass
    package_root = Path(__file__).resolve().parents[3]
    candidates.append(package_root / "preprocess" / "translator")
    candidates.append(package_root / "preprocessing" / "translator")
    for candidate in candidates:
        directory = candidate / "rvv_sbt_tool"
        if (directory / "rvv_sbt_rvv.py").is_file() and (
            directory / "rvv_sbt_rvv1024.py"
        ).is_file():
            return directory
    raise FileNotFoundError(
        "bundled translators (rvv_sbt_tool) are missing from the installation"
    )


def generate_profile_document() -> tuple[str, list[str]]:
    """Render a complete bidirectional profile from the detected environment."""
    require_supported_host()
    warnings: list[str] = []
    cc = _detect_tool(
        ("gcc", _CROSS_TOOLCHAIN_PREFIX + "gcc"),
        field="config.tools.cc",
        warnings=warnings,
    )
    objdump = _detect_tool(
        ("objdump", _CROSS_TOOLCHAIN_PREFIX + "objdump"),
        field="config.tools.objdump",
        warnings=warnings,
    )
    nm = _detect_tool(
        ("nm", _CROSS_TOOLCHAIN_PREFIX + "nm"),
        field="config.tools.nm",
        warnings=warnings,
    )
    cmake = _detect_tool(("cmake",), field="config.tools.cmake", warnings=warnings)
    cc_flags = _NATIVE_CC_FLAGS if cc == "gcc" else ()
    library_roots = tuple(
        root for root in _LIBRARY_ROOT_CANDIDATES if Path(root).is_dir()
    )
    translator_directory = _bundled_translator_directory()
    runtime_defaults = RuntimeConfig()
    home_root = Path.home() / ".chimera"
    lines = [
        "[config]",
        f"data_root = {_quote(home_root / 'data')}",
        f"workspace_root = {_quote(home_root / 'workspaces')}",
        f"scalar_root = {_quote(home_root / 'scalar')}",
        f"workspace_name = {_quote('auto')}",
        "",
        "[[config.translators]]",
        f"source = {_quote('riscv64;rvv;vlen=1024')}",
        f"target = {_quote('riscv64;rvv;vlen=256')}",
        f"translator_path = {_quote(translator_directory / 'rvv_sbt_rvv.py')}",
        "",
        "[[config.translators]]",
        f"source = {_quote('riscv64;rvv;vlen=256')}",
        f"target = {_quote('riscv64;rvv;vlen=1024')}",
        f"translator_path = {_quote(translator_directory / 'rvv_sbt_rvv1024.py')}",
        "",
        "[config.tools]",
        f"python = {_quote(sys.executable)}",
        f"cc = {_quote(cc)}",
        "cc_flags = [" + ", ".join(_quote(flag) for flag in cc_flags) + "]",
        f"objdump = {_quote(objdump)}",
        f"nm = {_quote(nm)}",
        f"cmake = {_quote(cmake)}",
        "",
        "[config.target_files]",
        'sysroot = "/"',
        "library_roots = ["
        + ", ".join(_quote(root) for root in library_roots)
        + "]",
        "",
        "[config.runtime]",
        f"bpf_map = {_quote(runtime_defaults.bpf_map)}",
        f"ai_thread_control = {_quote(runtime_defaults.ai_thread_control)}",
        "",
        "[profile]",
        f"name = {_quote('linux-riscv64-rvv-1024-256-bidirectional')}",
        'target_os = "linux"',
        'target_arch = "riscv64"',
        'target_arch_extension = "rvv"',
        'runtime_scene = "linux_riscv64_rvv_v1"',
        "runtime_abi = 1",
    ]
    for step, parameters in _PROFILE_WORKFLOW_STEPS:
        lines += ["", "[[profile.workflow.steps]]", f"step = {_quote(step)}"]
        if parameters:
            lines.append(f"parameters = {{ {parameters} }}")
    return "\n".join(lines) + "\n", warnings


def install_auto_profile(force: bool = False) -> Path | None:
    """Detect the environment and install the generated system profile.

    Returns the installed path, or None when an existing profile was kept.
    """
    document, warnings = generate_profile_document()
    for warning in warnings:
        print(f"chimera: warning: {warning}", file=sys.stderr)
    destination = system_profile_path()
    if destination.is_file() and not force:
        return None
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=destination.parent, delete=False, suffix=".toml"
    ) as stream:
        stream.write(document)
        temporary = Path(stream.name)
    try:
        return install_system_profile(temporary)
    finally:
        temporary.unlink(missing_ok=True)
