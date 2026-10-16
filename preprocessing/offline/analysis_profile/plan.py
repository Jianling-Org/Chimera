"""Materialized, prevalidated execution plans."""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Mapping

from chimera.preprocess.offline.analysis import AnalysisServices, AnalysisStep
from chimera.preprocess.offline.config import ChimeraConfiguration


@dataclass(frozen=True)
class PlannedStep:
    identifier: str
    name: str
    implementation: AnalysisStep
    parameters: Mapping[str, Any]
    definition: Any | None = None


@dataclass(frozen=True)
class ExecutionPlan:
    configuration: ChimeraConfiguration
    services: AnalysisServices
    steps: tuple[PlannedStep, ...]
    target_bundle: Any | None = None

    @property
    def base(self):
        return self.configuration.base

    @property
    def profile(self):
        return self.configuration.profile


def immutable_parameters(values: Mapping[str, Any]) -> Mapping[str, Any]:
    return MappingProxyType(dict(values))
