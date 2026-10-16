"""Parse a complete Chimera TOML document exactly once."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from types import MappingProxyType
from typing import Any
try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10 source-test fallback
    import tomli as tomllib

from .model import (
    BaseConfig,
    ChimeraConfiguration,
    ProfileConfig,
    RuntimeConfig,
    TargetFilesConfig,
    ToolConfig,
    TranslationEndpoint,
    TranslationRoute,
    TranslatorBinding,
    WorkflowConfig,
    WorkflowStepConfig,
)
from .paths import executable_reference, resolve_path, translator_reference
from .validation import reject_unknown, require_table, validate_workspace_name

_CONFIG_KEYS = {"data_root", "workspace_root", "scalar_root", "workspace_name", "translators", "tools", "target_files", "runtime"}
_TRANSLATOR_KEYS = {"source", "target", "translator_path"}
_TOOL_KEYS = {
    "python", "cc", "cc_flags", "objdump", "nm", "cmake",
}
_TARGET_FILE_KEYS = {"sysroot", "library_roots", "cmake_toolchain_file"}
_RUNTIME_KEYS = {"bpf_map", "ai_thread_control"}
_PROFILE_KEYS = {
    "name", "target_os", "target_arch", "target_arch_extension",
    "runtime_scene", "runtime_abi", "workflow",
}
_WORKFLOW_KEYS = {"steps"}
_STEP_KEYS = {"step", "parameters"}

_TRANSLATOR_MIGRATION_EXAMPLE = """\
[[config.translators]]
source = "riscv64;rvv;vlen=1024"
target = "riscv64;rvv;vlen=256"
translator_path = "/path/to/translator.py"

[[profile.workflow.steps]]
step = "translate"
parameters = { source = "riscv64;rvv;vlen=1024", target = "riscv64;rvv;vlen=256" }"""


def load_toml(path: str | Path) -> dict[str, Any]:
    source = Path(path).resolve()
    if not source.is_file():
        raise FileNotFoundError(f"profile file does not exist: {source}")
    with source.open("rb") as stream:
        document = tomllib.load(stream)
    if not isinstance(document, dict):
        raise TypeError("profile document root must be a TOML table")
    reject_unknown(document, {"config", "profile"}, name="document")
    for required in ("config", "profile"):
        if required not in document:
            raise ValueError(f"profile document is missing [{required}]")
        require_table(document[required], name=f"[{required}]")
    return document


def parse_base_config(table: Mapping[str, Any], *, source: str | Path) -> BaseConfig:
    profile_path = Path(source).resolve()
    values = dict(require_table(table, name="[config]"))
    if "translator" in values:
        raise ValueError(
            "legacy config.translator is unsupported; migrate the route and "
            "workflow request, for example:\n" + _TRANSLATOR_MIGRATION_EXAMPLE
        )
    reject_unknown(values, _CONFIG_KEYS, name="[config]")

    tools_table = require_table(values.get("tools", {}), name="[config.tools]")
    if "translator_command" in tools_table:
        raise ValueError(
            "legacy config.tools.translator_command is unsupported; translator argv "
            "is fixed; migrate the route and workflow request, for example:\n"
            + _TRANSLATOR_MIGRATION_EXAMPLE
        )
    reject_unknown(tools_table, _TOOL_KEYS, name="[config.tools]")
    raw_cc_flags = tools_table.get("cc_flags", [])
    if not isinstance(raw_cc_flags, list) or not all(
        isinstance(value, str) for value in raw_cc_flags
    ):
        raise TypeError("config.tools.cc_flags must be an array of strings")
    if any(not value for value in raw_cc_flags):
        raise ValueError("config.tools.cc_flags cannot contain empty strings")
    executable_values = {
        key: executable_reference(
            value,
            source=profile_path,
            field=f"config.tools.{key}",
        )
        for key, value in tools_table.items()
        if key != "cc_flags"
    }
    tools = ToolConfig(
        **executable_values,
        cc_flags=tuple(raw_cc_flags),
    )

    target_table = require_table(values.get("target_files", {}), name="[config.target_files]")
    reject_unknown(target_table, _TARGET_FILE_KEYS, name="[config.target_files]")
    raw_roots = target_table.get("library_roots", [])
    if not isinstance(raw_roots, list) or not all(isinstance(value, str) for value in raw_roots):
        raise TypeError("config.target_files.library_roots must be an array of paths")
    target_files = TargetFilesConfig(
        sysroot=resolve_path(target_table["sysroot"], source=profile_path, field="config.target_files.sysroot") if "sysroot" in target_table else None,
        library_roots=tuple(resolve_path(value, source=profile_path, field="config.target_files.library_roots") for value in raw_roots),
        cmake_toolchain_file=resolve_path(target_table["cmake_toolchain_file"], source=profile_path, field="config.target_files.cmake_toolchain_file") if "cmake_toolchain_file" in target_table else None,
    )
    runtime_table = require_table(values.get("runtime", {}), name="[config.runtime]")
    reject_unknown(runtime_table, _RUNTIME_KEYS, name="[config.runtime]")
    runtime_defaults = RuntimeConfig()
    runtime = RuntimeConfig(
        bpf_map=resolve_path(runtime_table.get("bpf_map", str(runtime_defaults.bpf_map)), source=profile_path, field="config.runtime.bpf_map"),
        ai_thread_control=resolve_path(runtime_table.get("ai_thread_control", str(runtime_defaults.ai_thread_control)), source=profile_path, field="config.runtime.ai_thread_control"),
    )
    raw_translators = values.get("translators", [])
    if not isinstance(raw_translators, list):
        raise TypeError("config.translators must be an array of tables")
    translators: list[TranslatorBinding] = []
    routes: set[TranslationRoute] = set()
    for index, raw in enumerate(raw_translators):
        field = f"config.translators[{index}]"
        item = require_table(raw, name=field)
        reject_unknown(item, _TRANSLATOR_KEYS, name=field)
        missing = sorted(_TRANSLATOR_KEYS - set(item))
        if missing:
            raise ValueError(f"{field} is missing key(s): {', '.join(missing)}")
        source_endpoint = TranslationEndpoint.parse(
            item["source"], field=f"{field}.source"
        )
        target_endpoint = TranslationEndpoint.parse(
            item["target"], field=f"{field}.target"
        )
        if source_endpoint == target_endpoint:
            raise ValueError(
                f"{field} source and target endpoints must be distinct"
            )
        route = TranslationRoute(source_endpoint, target_endpoint)
        if route in routes:
            raise ValueError(
                "duplicate translator route: "
                f"{source_endpoint.canonical} -> {target_endpoint.canonical}"
            )
        translator_path = translator_reference(
            item["translator_path"], source=profile_path,
            field=f"{field}.translator_path",
        )
        if not translator_path.is_file():
            raise FileNotFoundError(
                f"{field}.translator_path must name an existing file: "
                f"{translator_path}"
            )
        routes.add(route)
        translators.append(TranslatorBinding(
            source_endpoint, target_endpoint, translator_path
        ))
    return BaseConfig(
        data_root=resolve_path(values.get("data_root", "build/data"), source=profile_path, field="config.data_root"),
        workspace_root=resolve_path(values.get("workspace_root", "build/workspaces"), source=profile_path, field="config.workspace_root"),
        scalar_root=resolve_path(values.get("scalar_root", "build/scalar"), source=profile_path, field="config.scalar_root"),
        workspace_name=validate_workspace_name(values.get("workspace_name", "auto")),
        translators=tuple(translators),
        tools=tools,
        target_files=target_files,
        runtime=runtime,
        source=profile_path,
    )


def parse_profile_config(table: Mapping[str, Any], *, source: str | Path) -> ProfileConfig:
    values = dict(require_table(table, name="[profile]"))
    legacy_safety = sorted(
        set(values) & {"min_vlen_bits", "compiler_metadata"}
    )
    if legacy_safety:
        raise ValueError(
            "legacy Safety profile field(s) "
            + ", ".join(legacy_safety)
            + " must move to the safety step parameters; for example: "
            "[[profile.workflow.steps]] step = \"safety\" "
            "parameters = { min_vlen_bits = 256, compiler_metadata = [] }"
        )
    reject_unknown(values, _PROFILE_KEYS, name="[profile]")
    required = _PROFILE_KEYS - {"workflow"}
    missing = sorted(required - set(values))
    if missing:
        raise ValueError(f"missing [profile] key(s): {', '.join(missing)}")
    for field in (
        "name", "target_os", "target_arch", "target_arch_extension",
        "runtime_scene",
    ):
        if not isinstance(values[field], str) or not values[field]:
            raise TypeError(f"profile.{field} must be a non-empty string")
    for field in ("runtime_abi",):
        if not isinstance(values[field], int) or isinstance(values[field], bool):
            raise TypeError(f"profile.{field} must be an integer")
        if values[field] != 1:
            raise ValueError(f"only profile.{field}=1 is supported")
    workflow_table = require_table(values.get("workflow", {}), name="[profile.workflow]")
    reject_unknown(workflow_table, _WORKFLOW_KEYS, name="[profile.workflow]")
    raw_steps = workflow_table.get("steps", [])
    if not isinstance(raw_steps, list):
        raise TypeError("profile.workflow.steps must be an array of tables")
    steps: list[WorkflowStepConfig] = []
    for index, raw in enumerate(raw_steps):
        item = require_table(raw, name=f"profile.workflow.steps[{index}]")
        reject_unknown(item, _STEP_KEYS, name=f"profile.workflow.steps[{index}]")
        name = item.get("step")
        if not isinstance(name, str) or not name:
            raise TypeError(f"profile.workflow.steps[{index}].step must be a non-empty string")
        parameters = require_table(item.get("parameters", {}), name=f"profile.workflow.steps[{index}].parameters")
        steps.append(WorkflowStepConfig(name, MappingProxyType(dict(parameters))))
    return ProfileConfig(
        name=values["name"], target_os=values["target_os"], target_arch=values["target_arch"],
        target_arch_extension=values["target_arch_extension"],
        runtime_scene=values["runtime_scene"],
        runtime_abi=values["runtime_abi"], workflow=WorkflowConfig(tuple(steps)), source=Path(source).resolve(),
    )


def load_configuration(path: str | Path) -> ChimeraConfiguration:
    source = Path(path).resolve()
    document = load_toml(source)
    return ChimeraConfiguration(
        base=parse_base_config(document["config"], source=source),
        profile=parse_profile_config(document["profile"], source=source),
        source=source,
    )
