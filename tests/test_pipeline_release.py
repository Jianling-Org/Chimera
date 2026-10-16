"""Pipeline releases global results once their last requirer has run."""

from __future__ import annotations

from types import MappingProxyType, SimpleNamespace
import tempfile
import unittest
from pathlib import Path

from chimera.preprocess.offline.analysis_profile.pipeline import (
    PreparePipeline,
    _last_use_positions,
)
from chimera.preprocess.offline.analysis_profile.plan import (
    ExecutionPlan,
    PlannedStep,
)


class _Step:
    def __init__(self, produces=None, observe=None):
        self._produces = produces or {}
        self._observe = observe
        self.observed_keys = None

    def run(self, context):
        if self._observe:
            self.observed_keys = sorted(context.global_results)
        updated = context
        for key, value in self._produces.items():
            updated = updated.put_global(key, value)
        return updated


def _definition(requires=(), provides=()):
    return SimpleNamespace(
        requires=frozenset(requires),
        provides=frozenset(provides),
        postcondition=None,
        publication_validators=(),
    )


def _plan(steps) -> ExecutionPlan:
    profile = SimpleNamespace(
        target_os="linux",
        target_arch="riscv64",
        target_arch_extension="rvv",
        runtime_scene="linux_riscv64_rvv_v1",
        runtime_abi=1,
    )
    return ExecutionPlan(
        configuration=SimpleNamespace(base=object(), profile=profile),
        services=object(),
        steps=tuple(steps),
    )


class LastUsePositionTests(unittest.TestCase):
    def test_maps_global_to_last_requiring_position(self) -> None:
        steps = (
            PlannedStep("001:a", "a", _Step(), MappingProxyType({}),
                        _definition(provides={"heavy"})),
            PlannedStep("002:b", "b", _Step(), MappingProxyType({}),
                        _definition(requires={"heavy"}, provides={"mid"})),
            PlannedStep("003:c", "c", _Step(), MappingProxyType({}),
                        _definition(requires={"heavy", "mid"},
                                    provides={"published_workspace"})),
        )
        last_use = _last_use_positions(_plan(steps))
        self.assertEqual(last_use, {"heavy": 3, "mid": 3})


class PipelineReleaseTests(unittest.TestCase):
    def test_global_dropped_after_last_requirer(self) -> None:
        middle = _Step(produces={"mid": object()}, observe=True)
        final = _Step(produces={"published_workspace": "ws"}, observe=True)
        steps = (
            PlannedStep("001:produce", "produce",
                        _Step(produces={"heavy": object()}),
                        MappingProxyType({}),
                        _definition(provides={"heavy"})),
            PlannedStep("002:middle", "middle", middle, MappingProxyType({}),
                        _definition(requires={"heavy"}, provides={"mid"})),
            PlannedStep("003:final", "final", final, MappingProxyType({}),
                        _definition(requires={"mid"},
                                    provides={"published_workspace"})),
        )
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "app"
            source.write_bytes(b"elf")
            published = PreparePipeline(_plan(steps)).prepare(source)

        self.assertEqual(published, "ws")
        self.assertEqual(middle.observed_keys, ["heavy"])
        # heavy's last requirer was step 002: it must be gone by step 003.
        self.assertEqual(final.observed_keys, ["mid"])

    def test_unrequired_globals_survive_the_run(self) -> None:
        final = _Step(produces={"published_workspace": "ws"}, observe=True)
        steps = (
            PlannedStep("001:produce", "produce",
                        _Step(produces={"kept": object()}),
                        MappingProxyType({}),
                        _definition(provides={"kept"})),
            PlannedStep("002:final", "final", final, MappingProxyType({}),
                        _definition(provides={"published_workspace"})),
        )
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "app"
            source.write_bytes(b"elf")
            PreparePipeline(_plan(steps)).prepare(source)

        self.assertEqual(final.observed_keys, ["kept"])


if __name__ == "__main__":
    unittest.main()
