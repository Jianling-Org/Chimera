"""Execution contract shared by analysis-profile and analysis steps."""

from __future__ import annotations

from typing import Protocol
from .context import AnalysisContext


class AnalysisStep(Protocol):
    @property
    def name(self) -> str: ...
    def run(self, context: AnalysisContext) -> AnalysisContext: ...
