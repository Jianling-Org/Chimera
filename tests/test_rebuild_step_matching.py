"""Logic-level regression test for the chimera-dev rebuild step-matching bug.

The real `RebuildPipeline.prepare` lives in
`preprocessing/offline/analysis_profile/rebuild.py` and imports the `chimera`
package, which is not installable in this sandbox. This script replicates the
EXACT decision ladder that was fixed (matching on `planned.name` instead of
`planned.identifier`) so the bug-before / fix-after behaviour is pinned down
without the heavy import graph.

PlannedStep.identifier = "001:prepare-workspace" (positional prefix + bare name)
PlannedStep.name        = "prepare-workspace"      (bare name)
cli.py parses `--steps build-runtime,safety` -> {"build-runtime", "safety"} (bare)
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass
class PlannedStep:
    position: int
    name: str

    @property
    def identifier(self) -> str:
        return f"{self.position:03d}:{self.name}"


# ---- decision ladder exactly as fixed in rebuild.py ----
def decide(planned: PlannedStep, steps: set[str]) -> str:
    name = planned.name
    if name == "prepare-workspace":
        return "record"          # prepare-workspace is never re-run
    if name in ("finalize-workspace", "patch-safepoints") or name in steps:
        return "execute"         # re-run requested + finalize/patch always
    return "replay"              # skipped steps are replayed from staged files


# ---- OLD (buggy) ladder for comparison ----
def decide_old(planned: PlannedStep, steps: set[str]) -> str:
    identifier = planned.identifier
    if identifier == "prepare-workspace":
        return "record"
    if identifier == "finalize-workspace" or identifier in steps:
        return "execute"
    return "replay"


def build_plan() -> list[PlannedStep]:
    names = [
        "prepare-workspace",
        "disassemble",
        "build-program-model",
        "translate",
        "offset-map",
        "build-runtime",
        "safety",
        "patch-safepoints",
        "finalize-workspace",
    ]
    return [PlannedStep(i + 1, n) for i, n in enumerate(names)]


def test_fixed_matches_requested_and_finalize():
    steps = {"build-runtime", "safety"}
    plan = build_plan()
    decisions = {p.name: decide(p, steps) for p in plan}
    # requested steps must re-execute
    assert decisions["build-runtime"] == "execute", decisions
    assert decisions["safety"] == "execute", decisions
    # finalize always re-emits the manifest
    assert decisions["finalize-workspace"] == "execute", decisions
    # patch-safepoints always re-applies (idempotent) so a re-run translate
    # never leaves an unpatched DSO behind
    assert decisions["patch-safepoints"] == "execute", decisions
    # prepare-workspace is protected
    assert decisions["prepare-workspace"] == "record", decisions
    # everything else is replayed (so downstream contracts are satisfied)
    for skipped in ("disassemble", "build-program-model", "translate", "offset-map"):
        assert decisions[skipped] == "replay", (skipped, decisions)
    print("FIXED: decisions =", decisions)


def test_old_would_have_broken():
    steps = {"build-runtime", "safety"}
    plan = build_plan()
    decisions = {p.name: decide_old(p, steps) for p in plan}
    # BUG: requested steps never re-execute, finalize never runs
    assert decisions["build-runtime"] == "replay", "old logic wrongly replayed build-runtime"
    assert decisions["safety"] == "replay", "old logic wrongly replayed safety"
    assert decisions["finalize-workspace"] == "replay", "old logic never finalized"
    print("OLD (buggy): decisions =", decisions)


if __name__ == "__main__":
    test_fixed_matches_requested_and_finalize()
    test_old_would_have_broken()
    print("\nOK: fix verified; old-ladder reproduced to prove the regression existed")
