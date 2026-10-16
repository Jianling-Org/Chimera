"""Workflow-driven binary preflight checks.

The check planner only resolves workflow declarations and their optional
check factories.  It never constructs production steps, allocates a
workspace, or invokes a tool unless a declared check is executed.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
from pathlib import Path
from types import MappingProxyType
from typing import Any, Callable, Mapping

from chimera.elf_state import (
    CHECKED,
    PROBLEMATIC,
    REMEDIATED,
    UNCHECKED,
    ElfStateRegistry,
    sha256_of,
)


CheckRunner = Callable[[Path, "BinaryCheckContext"], "BinaryCheckOutcome"]


def _jsonable(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, Mapping):
        return {
            str(key): _jsonable(item)
            for key, item in sorted(value.items(), key=lambda item: str(item[0]))
        }
    if isinstance(value, (tuple, list, frozenset, set)):
        values = [_jsonable(item) for item in value]
        if isinstance(value, (frozenset, set)):
            return sorted(
                values,
                key=lambda item: json.dumps(item, sort_keys=True, default=str),
            )
        return values
    if isinstance(value, Path):
        return value.as_posix()
    canonical = getattr(value, "canonical", None)
    if canonical is not None:
        return str(canonical)
    return str(value)


def _canonical_json(value: Any) -> str:
    return json.dumps(
        _jsonable(value), ensure_ascii=False, sort_keys=True,
        separators=(",", ":"), default=str,
    )


@dataclass(frozen=True)
class BinaryCheckContext:
    configuration: Any
    objdump_cmd: str | None = None
    overrides: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "overrides", MappingProxyType(dict(self.overrides)))


@dataclass(frozen=True)
class BinaryCheckOutcome:
    passed: bool
    diagnostics: Mapping[str, Any] = field(default_factory=dict)
    decision: Mapping[str, Any] = field(default_factory=dict)
    message: str = ""
    actionable: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(self, "diagnostics", MappingProxyType(dict(self.diagnostics)))
        object.__setattr__(self, "decision", MappingProxyType(dict(self.decision)))


@dataclass(frozen=True)
class BinaryCheckRequest:
    check_id: str
    version: int
    parameters: Mapping[str, Any]
    runner: CheckRunner
    requested_by: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.check_id:
            raise ValueError("binary check ID cannot be empty")
        if (
            isinstance(self.version, bool)
            or not isinstance(self.version, int)
            or self.version <= 0
        ):
            raise ValueError("binary check version must be a positive integer")
        if not callable(self.runner):
            raise TypeError("binary check runner must be callable")
        object.__setattr__(self, "parameters", MappingProxyType(dict(self.parameters)))
        object.__setattr__(self, "requested_by", tuple(self.requested_by))

    @property
    def identity(self) -> tuple[str, int, str]:
        return self.check_id, self.version, _canonical_json(self.parameters)

    def add_requester(self, identifier: str) -> "BinaryCheckRequest":
        if identifier in self.requested_by:
            return self
        return BinaryCheckRequest(
            self.check_id, self.version, self.parameters, self.runner,
            (*self.requested_by, identifier),
        )

    def run(self, path: Path, context: BinaryCheckContext) -> BinaryCheckOutcome:
        result = self.runner(path, context)
        if not isinstance(result, BinaryCheckOutcome):
            raise TypeError(
                f"binary check {self.check_id} did not return BinaryCheckOutcome"
            )
        return result


@dataclass(frozen=True)
class BinaryCheckPlanResult:
    passed: bool
    outcomes: tuple[tuple[BinaryCheckRequest, BinaryCheckOutcome], ...]
    decision: Mapping[str, Any]
    message: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "decision", MappingProxyType(dict(self.decision)))


@dataclass(frozen=True)
class BinaryCheckPlan:
    configuration: Any
    target_key: tuple[str, str, str, str]
    runtime_abi: int
    requests: tuple[BinaryCheckRequest, ...] = ()

    @property
    def scope(self) -> dict[str, Any]:
        return {
            "target": {
                "os": self.target_key[0],
                "arch": self.target_key[1],
                "extension": self.target_key[2],
                "runtime_scene": self.target_key[3],
            },
            "runtime_abi": self.runtime_abi,
            "checks": [
                {
                    "id": request.check_id,
                    "version": request.version,
                    "parameters": _jsonable(request.parameters),
                }
                for request in sorted(self.requests, key=lambda item: item.identity)
            ],
        }

    def fingerprint(self, elf_sha256: str) -> str:
        payload = {"elf_sha256": elf_sha256, "scope": self.scope}
        return hashlib.sha256(_canonical_json(payload).encode("utf-8")).hexdigest()

    def run(
        self,
        input_elf: Path,
        *,
        objdump_cmd: str | None = None,
        overrides: Mapping[str, Any] | None = None,
    ) -> BinaryCheckPlanResult:
        input_elf = Path(input_elf).resolve()
        if not input_elf.is_file():
            raise FileNotFoundError(f"input ELF does not exist: {input_elf}")
        context = BinaryCheckContext(
            configuration=self.configuration,
            objdump_cmd=objdump_cmd,
            overrides={} if overrides is None else overrides,
        )
        if not self.requests:
            return BinaryCheckPlanResult(
                passed=True,
                outcomes=(),
                decision=empty_decision_block(),
                message="current workflow has no binary checks; passed",
            )
        outcomes = tuple(
            (request, request.run(input_elf, context))
            for request in self.requests
        )
        return BinaryCheckPlanResult(
            passed=all(outcome.passed for _request, outcome in outcomes),
            outcomes=outcomes,
            decision=merge_decisions(outcome.decision for _request, outcome in outcomes),
            message="; ".join(
                outcome.message for _request, outcome in outcomes if outcome.message
            ),
        )


def empty_decision_block() -> dict[str, Any]:
    return {
        "strategy": "none",
        "vector_gate": {
            "enabled": False,
            "names_source": "workflow:no-binary-checks",
        },
        "function_pointer_plugin": False,
        "stack_object_plugin": False,
        "gate": {"enabled": False, "names": []},
    }


def merge_decisions(decisions) -> dict[str, Any]:
    """Merge compatible check recommendations and reject route conflicts."""
    values = [dict(item) for item in decisions if item]
    if not values:
        return empty_decision_block()
    strategies = {
        item.get("strategy") for item in values
        if item.get("strategy") not in (None, "none")
    }
    if len(strategies) > 1:
        raise ValueError(
            "binary checks produced conflicting remediation strategies: "
            + ", ".join(sorted(strategies))
        )
    result = empty_decision_block()
    if strategies:
        result["strategy"] = next(iter(strategies))
    for item in values:
        for key in ("function_pointer_plugin", "stack_object_plugin"):
            result[key] = bool(result[key] or item.get(key, False))
        gate = item.get("gate")
        if isinstance(gate, Mapping):
            result["gate"]["enabled"] = bool(result["gate"]["enabled"] or gate.get("enabled", False))
            result["gate"]["names"] = sorted(
                set(result["gate"]["names"]) | set(gate.get("names", ()))
            )
        vector_gate = item.get("vector_gate")
        if isinstance(vector_gate, Mapping):
            result["vector_gate"]["enabled"] = bool(
                result["vector_gate"]["enabled"]
                or vector_gate.get("enabled", False)
            )
            if vector_gate.get("names_source"):
                result["vector_gate"]["names_source"] = vector_gate["names_source"]
    return result


def build_check_plan(configuration, *, resolved_steps=None) -> BinaryCheckPlan:
    if resolved_steps is None:
        from .parser import resolve_workflow_steps
        _, resolved_steps = resolve_workflow_steps(configuration)
    requests: dict[tuple[str, int, str], BinaryCheckRequest] = {}
    for step in resolved_steps:
        factory = getattr(step.definition, "binary_check_factory", None)
        if factory is None:
            continue
        request = factory(step.parameters)
        if not isinstance(request, BinaryCheckRequest):
            raise TypeError(
                f"{step.identifier} binary check factory did not return BinaryCheckRequest"
            )
        current = requests.get(request.identity)
        requests[request.identity] = (
            request.add_requester(step.identifier)
            if current is None
            else current.add_requester(step.identifier)
        )
    profile = configuration.profile
    return BinaryCheckPlan(
        configuration=configuration,
        target_key=(profile.target_os, profile.target_arch, profile.target_arch_extension, profile.runtime_scene),
        runtime_abi=profile.runtime_abi,
        requests=tuple(requests.values()),
    )


def check_admission(
    input_elf: Path,
    plan: BinaryCheckPlan,
    *,
    registry: ElfStateRegistry | None = None,
    allow_problematic: bool = False,
) -> None:
    """Require a current, matching check credential before a checked workflow."""
    if not plan.requests:
        return
    registry = registry or ElfStateRegistry()
    input_elf = Path(input_elf).resolve()
    expected = plan.fingerprint(sha256_of(input_elf))
    state, record = registry.effective_status(input_elf)
    if record is None:
        raise RuntimeError("workflow requires binary checks; run check-elf first")
    if state == REMEDIATED:
        raise RuntimeError("binary was remediated but not rechecked; re-run check-elf")
    if record.check_fingerprint != expected or record.check_scope != plan.scope:
        raise RuntimeError(
            "binary check scope does not match the current workflow; re-run check-elf"
        )
    if state == CHECKED:
        return
    if state == PROBLEMATIC and allow_problematic:
        return
    if state == PROBLEMATIC:
        raise RuntimeError(
            "binary checks reported actionable findings; re-run compiler remediation "
            "or use --allow-problematic"
        )
    if state == UNCHECKED:
        raise RuntimeError("binary check credential is stale or missing; re-run check-elf")
    raise RuntimeError(f"binary check admission failed: {state}")


__all__ = [
    "BinaryCheckContext", "BinaryCheckOutcome", "BinaryCheckPlan",
    "BinaryCheckPlanResult", "BinaryCheckRequest", "build_check_plan",
    "check_admission", "empty_decision_block", "merge_decisions",
]
