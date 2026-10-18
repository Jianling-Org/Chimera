"""Independent-audit tests: source enumeration, propagation, evidence grading.

The fixtures here are built two ways on purpose:

* a *synthetic* program (instructions plus explicit jump targets) fed straight
  into :func:`chimera.gate_source_audit.audit_program`, so the CFG - including a
  diamond whose two arms each allocate - is fully controlled; and
* the CLI entry point driven with a real subprocess standing in for objdump, so
  the temporary-file handling, the exit status and the bounded stderr read stay
  on the tested path.

Every test that asserts the audit reports a hole is paired with a
counter-example asserting it does not manufacture a conclusion out of missing
evidence.
"""

from __future__ import annotations

import csv
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from chimera.preprocess.offline.analysis.arch.riscv.rvv.services import RvvServices
from chimera.preprocess.offline.analysis.arch.riscv.services import RiscvServices
from chimera.preprocess.offline.analysis.core.data_model import (
    Function,
    Instruction,
    Program,
)
from chimera.preprocess.offline.analysis.safety.stack_liveness.analyzer import (
    StackLivenessAnalyzer,
)
from chimera.preprocess.offline.analysis.safety.stack_liveness.frame_liveness import (
    VLEN_STACK_FRAME,
    VLEN_STACK_SETUP,
)
from chimera.preprocess.offline.analysis.safety.stack_liveness.model import (
    AllocationOrigin,
    ChimeraMetadata,
    OriginProof,
    StackFunctionLiveness,
    StackLivenessResult,
    StackObjectId,
)
from chimera.preprocess.offline.analysis.toolchain.objdump import LinuxObjdump

from elf_fixture import build_elf

import chimera.gate_source_audit as audit

GATE_SHA = "a" * 64
#: The hash :func:`_audit` stamps on the fixture ELF; a manifest has to declare
#: exactly this to be bound to "this product".
ELF_SHA = "f" * 64
#: A declared toolchain identity is a digest, never a label.
TOOLCHAIN_SHA = "c" * 64


# region fixture construction


def _function(name: str, start: int, specs) -> Function:
    instructions = [
        Instruction(
            start + index * 4, 4, op, list(args), op + " " + ",".join(args)
        )
        for index, (op, args) in enumerate(specs)
    ]
    return Function(name, start, instructions)


def _program(*functions: Function) -> Program:
    instructions = [item for function in functions for item in function.insts]
    return Program(
        dump_lines=[],
        functions=list(functions),
        instructions=instructions,
        instruction_by_address={item.addr: item for item in instructions},
    )


def _build(program: Program) -> Program:
    return RiscvServices(RvvServices()).build_cfg(program)


def _resolve(program: Program, site: int, target: int) -> None:
    """Mark one call site as a resolved direct call (the CFG is already built)."""

    program.instruction_by_address[site].jump_targets.add(target)


def _analyze(program: Program, prover=None) -> StackLivenessResult:
    _build(program)
    configs = RvvServices().vector_configs(program)
    analyzer = StackLivenessAnalyzer(
        min_vlen_bits=256, semantics=RvvServices().stack_semantics
    )
    return analyzer.analyze_program(
        program,
        metadata=ChimeraMetadata.empty(),
        config_results=configs,
        prover=prover,
    )


class _StubProver:
    """Deterministic replacement for the on-demand origin prover.

    ``verdicts`` maps an adjustment address to
    ``(proven, proof_id, reason, proof_status_or_None)``.  The stub never
    searches: it exists so a fixture can pin "unproven", "proven" and
    "tracked through a load" without depending on the prover's heuristics.
    """

    budget_exhausted = False
    missing_callees = {}

    def __init__(self, verdicts=None):
        self._verdicts = dict(verdicts or {})
        self._nodes = []

    def prove_adjustment(self, function, address):
        spec = self._verdicts.get(address)
        if spec is None:
            return None
        proven, proof_id, reason, status = spec
        if status is not None:
            self._nodes.append(
                OriginProof(
                    id=proof_id,
                    status=status,
                    reason=reason,
                    function_start=function.start,
                    address=address,
                )
            )

        class _Verdict:
            pass

        verdict = _Verdict()
        verdict.proven = proven
        verdict.proof_id = proof_id
        verdict.reason = reason
        return verdict

    def proofs(self):
        return tuple(self._nodes)

    def gaps(self):
        return ()


def _stack_with_one_allocation(
    program: Program, starts, dependency: str = "vlen"
) -> StackLivenessResult:
    """One recorded VLEN adjustment per named function, and no call activity."""

    by_function = {}
    for start in starts:
        by_function[start] = StackFunctionLiveness(
            function_start=start,
            live_before={},
            accesses={},
            frame_origins=(
                AllocationOrigin(
                    source="vlen_stack_frame",
                    adjustment=start,
                    dependency=dependency,
                ),
            ),
        )
    return StackLivenessResult(
        by_function=by_function,
        inherited_functions=frozenset(),
        unresolved_live_calls=(),
    )


def _hand_built_stack(
    function: Function,
    *,
    frame_origins=(),
    live=None,
    unresolved=(),
    inherited=(),
) -> StackLivenessResult:
    """A ``StackLivenessResult`` whose local facts are stated explicitly.

    Used where a real analysis would have to guess: the exact live-set at a
    call site is the input this audit reads, so a fixture states it.
    """

    local = StackFunctionLiveness(
        function_start=function.start,
        live_before=dict(live or {}),
        accesses={},
        frame_origins=tuple(frame_origins),
    )
    return StackLivenessResult(
        by_function={function.start: local},
        inherited_functions=frozenset(inherited),
        unresolved_live_calls=tuple(unresolved),
    )


def _audit(
    program: Program,
    stack: StackLivenessResult,
    *,
    names=("diamond",),
    census=None,
    bound=frozenset(),
    census_paths=(),
    evidence=None,
    stage=audit.STAGE_BUILD_GATE2,
    expected=None,
    gate_sha=GATE_SHA,
    gate_info=None,
    metadata=None,
    consumed_decision=None,
):
    info = {
        "path": "decision.json",
        "sha256": gate_sha,
        "unique_names": len(names),
        "nonempty_lines": len(names),
        "duplicates_dropped": 0,
    }
    if gate_info:
        info.update(gate_info)
    return audit.audit_program(
        program,
        stack,
        metadata if metadata is not None else ChimeraMetadata.empty(),
        elf_path="fixture.elf",
        elf_sha256="f" * 64,
        min_vlen_bits=256,
        gate_names=list(names),
        gate_list_info=info,
        census=census or {},
        census_gaps=[],
        bound_paths=bound,
        census_paths=census_paths,
        evidence=evidence or {},
        stage=stage,
        expected_gate_count=expected,
        consumed_decision=consumed_decision,
    )


def _kinds(document) -> list[str]:
    return sorted(item["kind"] for item in document["candidates"])


def _gap_kinds(document) -> set[str]:
    return {gap["kind"] for gap in document["gaps"]}


def _entry(document, name: str) -> dict:
    for entry in document["gate_list"]["entries"]:
        if entry["name"] == name:
            return entry
    raise KeyError(name)


def _candidates_of(document, function: str) -> list[dict]:
    return [
        item for item in document["candidates"] if item["function"] == function
    ]


def _write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


# endregion


# region synthetic programs


def _diamond_program() -> Program:
    """Two arms, each its own VLEN allocation, merging at one call."""

    return _program(
        _function(
            "diamond",
            0x1000,
            [
                ("beqz", ["a0", "0x1010"]),
                ("csrr", ["a1", "vlenb"]),
                ("sub", ["sp", "sp", "a1"]),
                ("j", ["0x1018"]),
                ("csrr", ["a2", "vlenb"]),
                ("sub", ["sp", "sp", "a2"]),
                ("jalr", ["a3"]),
                ("ret", []),
            ],
        )
    )


def _unique_program() -> Program:
    return _program(
        _function(
            "unique",
            0x3000,
            [
                ("csrr", ["a0", "vlenb"]),
                ("slli", ["a1", "a0", "2"]),
                ("add", ["a0", "a0", "a1"]),
                ("sub", ["sp", "sp", "a0"]),
                ("jalr", ["a3"]),
                ("ret", []),
            ],
        )
    )


def _coexist_program() -> Program:
    """One UNKNOWN adjustment, one *proven* one, one VLEN one - in that order."""

    return _program(
        _function(
            "coexist",
            0x4000,
            [
                ("ld", ["a0", "0(s1)"]),
                ("sub", ["sp", "sp", "a0"]),
                ("ld", ["a2", "8(s1)"]),
                ("add", ["sp", "sp", "a2"]),
                ("csrr", ["a1", "vlenb"]),
                ("sub", ["sp", "sp", "a1"]),
                ("jalr", ["a3"]),
                ("ret", []),
            ],
        )
    )


def _tracked_program() -> Program:
    """A load-derived size the prover can be asked about."""

    return _program(
        _function(
            "tracked",
            0x2000,
            [
                ("ld", ["a0", "0(s1)"]),
                ("sub", ["sp", "sp", "a0"]),
                ("jalr", ["a3"]),
                ("ret", []),
            ],
        )
    )


def _sourced_and_clean_program() -> Program:
    return _program(
        _function("sourced", 0xC000, [("jalr", ["a3"]), ("ret", [])]),
        _function("clean", 0xC100, [("ret", [])]),
    )


class ScalarWidthAuditTests(unittest.TestCase):
    def test_dead_width_read_does_not_manufacture_a_gate_source(self):
        program = _program(_function('dead_width', 0x1000,
                                     [('csrr', ['t0', 'vlenb']), ('nop', []), ('ret', [])]))
        stack = _analyze(program)
        self.assertTrue(stack.by_function[0x1000].scalar_width_sources)
        document = _audit(program, stack, names=())
        self.assertNotIn(audit.SOURCE_SCALAR_WIDTH_CACHE, _kinds(document))
        self.assertEqual(document['answers']['sources_missing_from_list'], [])

    def test_return_does_not_invent_a_source_or_boundary(self):
        program = _program(_function('width_result', 0x1000,
                                     [('csrr', ['a0', 'vlenb']), ('ret', [])]))
        document = _audit(program, _analyze(program), names=('width_result',))
        self.assertNotIn(audit.SOURCE_SCALAR_WIDTH_CACHE, _kinds(document))
        self.assertEqual(document['affected_sites'], [])
        self.assertEqual(document['propagation']['call_instructions'], 0)
        self.assertEqual(document['propagation']['active_unresolved_sites'], 0)
        self.assertEqual(document['propagation']['active_width_escape_sites'], 0)
        self.assertEqual(document['propagation']['cross_check']['mismatches'], [])

    def test_real_local_cache_does_not_replace_external_target_evidence(self):
        program = _program(_function('width_call', 0x1000, [
            ('li', ['a0', '16']), ('csrr', ['s4', 'vlenb']),
            ('beqz', ['a2', '0x1010']), ('jal', ['ra', '0x9000']),
            ('mv', ['s1', 's4']), ('li', ['a0', '0']), ('ret', [])]))
        document = _audit(program, _analyze(program), names=('width_call',))
        site = next(item for item in document['affected_sites'] if item['call_site'] == '0x100c')
        self.assertEqual(site['resolution'], 'active-external-call')
        self.assertEqual(site['external_targets'], ['0x9000'])
        self.assertFalse(site['scalar_width_escape'])
        self.assertEqual(document['propagation']['active_unresolved_sites'], 0)
        self.assertEqual(document['propagation']['active_external_sites'], 1)

    def test_resolved_cache_live_call_propagates_without_becoming_a_boundary(self):
        program = _program(_function('width_call', 0x1000, [
            ('li', ['a0', '16']), ('csrr', ['s4', 'vlenb']),
            ('beqz', ['a2', '0x1010']), ('jal', ['ra', '0x2000']),
            ('mv', ['s1', 's4']), ('li', ['a0', '0']), ('ret', [])]),
            # Body effects do not require an additional cache-effect proof.
            _function('carrier', 0x2000, [('sd', ['a0', '0(a1)']), ('li', ['a0', '0']), ('ret', [])]))
        document = _audit(program, _analyze(program), names=('width_call',))
        self.assertEqual(document['affected_sites'], [])
        self.assertEqual(document['propagation']['resolved_relations'], 1)
        self.assertEqual(document['propagation']['active_width_escape_sites'], 0)
        self.assertEqual(document['propagation']['cross_check']['mismatches'], [])


class SourceEnumerationTests(unittest.TestCase):
    def test_unknown_allocation_and_vlen_source_coexist_without_contamination(self):
        program = _coexist_program()
        stack = _analyze(
            program,
            prover=_StubProver({0x400C: (True, "proof-p", "independent", None)}),
        )
        document = _audit(program, stack, names=("coexist",))
        items = _candidates_of(document, "coexist")
        by_kind = {item["kind"]: item for item in items}
        self.assertIn(audit.SOURCE_UNKNOWN_ALLOCATION, by_kind)
        self.assertIn(audit.SOURCE_VLEN_ALLOCATION, by_kind)
        self.assertTrue(
            by_kind[audit.SOURCE_UNKNOWN_ALLOCATION]["excluded_by_assumption"]
        )
        self.assertFalse(
            by_kind[audit.SOURCE_VLEN_ALLOCATION]["excluded_by_assumption"]
        )
        # The proven adjustment created no source at all: it never produced a
        # frame state, so listing it would invent one.
        self.assertEqual(
            sorted(item["addresses"]["allocation"] for item in items
                   if item["kind"] != audit.SOURCE_SCALAR_WIDTH_CACHE),
            ["0x4004", "0x4014"],
        )
        # The exclusion stays inside its own item: the shared call site is
        # reported with both contributors, and only one of them is excluded.
        site = document["affected_sites"][0]
        self.assertEqual(site["call_site"], "0x4018")
        self.assertEqual(3, len(site["contributors"]))
        self.assertEqual(1, len(site["contributors_excluded"]))
        self.assertEqual(
            by_kind[audit.SOURCE_UNKNOWN_ALLOCATION]["id"],
            site["contributors_excluded"][0],
        )

    def test_vlen_dependency_tracked_through_a_load_stays_a_vlen_source(self):
        program = _tracked_program()
        stack = _analyze(
            program,
            prover=_StubProver(
                {0x2004: (False, "proof-t", "tracked-through-a-load", "vlen")}
            ),
        )
        document = _audit(program, stack, names=("tracked",))
        item = _candidates_of(document, "tracked")[0]
        self.assertEqual(audit.SOURCE_VLEN_ALLOCATION, item["kind"])
        self.assertFalse(item["excluded_by_assumption"])
        self.assertEqual("origin-proof", item["evidence"]["tracked_via"])
        self.assertEqual("vlen", item["evidence"]["proof_status"])
        self.assertNotIn(audit.SOURCE_UNKNOWN_ALLOCATION, _kinds(document))

    def test_the_same_load_derived_size_without_a_proof_is_excluded(self):
        """Counter-example to the tracked case: no proof, no retention."""

        program = _tracked_program()
        stack = _analyze(program, prover=_StubProver())
        document = _audit(program, stack, names=("tracked",))
        item = _candidates_of(document, "tracked")[0]
        self.assertEqual(audit.SOURCE_UNKNOWN_ALLOCATION, item["kind"])
        self.assertTrue(item["excluded_by_assumption"])

    def test_a_single_allocation_at_a_call_is_attributed_uniquely(self):
        program = _unique_program()
        stack = _analyze(program)
        document = _audit(program, stack, names=("unique",))
        self.assertNotIn(audit.GAP_AMBIGUOUS_FRAME_ORIGIN, _gap_kinds(document))
        site = document["affected_sites"][0]
        self.assertEqual("0x3010", site["call_site"])
        self.assertEqual(1, len(site["contributors"]))

    def test_a_branch_merge_keeps_every_possible_allocation_not_the_nearest(self):
        program = _diamond_program()
        stack = _analyze(program)
        document = _audit(program, stack, names=("diamond",))
        self.assertEqual(
            ["0x1008", "0x1014"],
            sorted(
                item["addresses"]["allocation"]
                for item in _candidates_of(document, "diamond")
                if item["kind"] != audit.SOURCE_SCALAR_WIDTH_CACHE
            ),
        )
        gaps = [
            gap
            for gap in document["gaps"]
            if gap["kind"] == audit.GAP_AMBIGUOUS_FRAME_ORIGIN
        ]
        self.assertEqual(1, len(gaps))
        self.assertEqual(["0x1008", "0x1014"], gaps[0]["allocations"])
        # Both candidates stay contributors: dropping the "far" one would be a
        # tie-break, not an attribution.
        site = document["affected_sites"][0]
        self.assertEqual(3, len(site["contributors"]))
        self.assertEqual(
            sorted(gaps[0]["candidates"]),
            sorted(ident for ident in site["contributors"]
                   if audit.SOURCE_SCALAR_WIDTH_CACHE not in ident)
        )


class MarkerAttributionTests(unittest.TestCase):
    """Hand-built live sets: the shared markers, their holes and their ambiguity."""

    def setUp(self):
        self.function = _function(
            "markers",
            0x7000,
            [
                ("ld", ["a0", "0(s1)"]),
                ("sub", ["sp", "sp", "a0"]),
                ("ld", ["a2", "8(s1)"]),
                ("sub", ["sp", "sp", "a2"]),
                ("jalr", ["a3"]),
                ("ret", []),
            ],
        )
        self.program = _build(_program(self.function))

    def _origins(self, *addresses):
        return tuple(
            AllocationOrigin(
                source="vlen_stack_frame",
                adjustment=address,
                dependency="unknown",
                proof=None,
            )
            for address in addresses
        )

    def _setup_live(self):
        return {
            address: frozenset({VLEN_STACK_SETUP})
            for address in (0x7004, 0x7008, 0x700C, 0x7010)
        }

    def test_a_frame_marker_without_any_allocation_becomes_a_gap(self):
        stack = _hand_built_stack(
            self.function,
            frame_origins=(),
            live={0x7010: frozenset({VLEN_STACK_FRAME})},
            unresolved=(0x7010,),
        )
        document = _audit(self.program, stack, names=("markers",))
        self.assertIn(audit.GAP_UNATTRIBUTED_FRAME_MARKER, _gap_kinds(document))
        fallback = [
            item
            for item in document["candidates"]
            if item["kind"] == audit.SOURCE_UNATTRIBUTED_ACTIVITY
        ]
        self.assertEqual(1, len(fallback))
        self.assertFalse(fallback[0]["excluded_by_assumption"])

    def test_a_setup_marker_with_no_recorded_allocation_becomes_a_gap(self):
        stack = _hand_built_stack(
            self.function,
            frame_origins=(),
            live=self._setup_live(),
            unresolved=(0x7010,),
        )
        document = _audit(self.program, stack, names=("markers",))
        self.assertIn(audit.GAP_UNATTRIBUTED_SETUP_MARKER, _gap_kinds(document))
        self.assertIn(
            audit.SOURCE_UNATTRIBUTED_ACTIVITY, _kinds(document)
        )

    def test_an_activity_no_enumeration_claims_becomes_an_explicit_gap(self):
        mystery = StackObjectId("mystery", "payload")
        stack = _hand_built_stack(
            self.function,
            live={0x7010: frozenset({mystery})},
            unresolved=(0x7010,),
        )
        document = _audit(self.program, stack, names=("markers",))
        self.assertIn(audit.GAP_UNATTRIBUTED_LIVE_OBJECT, _gap_kinds(document))
        fallback = [
            item
            for item in document["candidates"]
            if item["kind"] == audit.SOURCE_UNATTRIBUTED_ACTIVITY
        ]
        self.assertEqual(1, len(fallback))
        self.assertIn(str(mystery), fallback[0]["objects"])
        self.assertEqual(["0x7010"], fallback[0]["affected_sites"])

    def test_an_audit_with_no_holes_records_no_hole(self):
        """Counter-example: a clean function must not produce gap noise."""

        stack = _hand_built_stack(
            self.function,
            frame_origins=self._origins(0x7004),
            live={0x7004: frozenset({VLEN_STACK_FRAME})},
            unresolved=(),
        )
        document = _audit(self.program, stack, names=("markers",))
        self.assertEqual([], document["gaps"])


class SetupRegionDirectionTests(unittest.TestCase):
    """The setup region lies *before* its adjustment, and must be traced that way.

    ``_setup_dependencies`` walks predecessors from an ``sp`` adjustment while
    the VLEN-tainted value is live, so the marker sits on the preparation
    instructions that lead *into* the adjustment.  Walking successors instead -
    as the first revision did - finds nothing, and the site then falls through
    to an un-excludable ``unattributed-activity`` source, which defeats this
    round's scope narrowing.  These fixtures use the real analyzer's live sets,
    not a hand-built ones, because the shape is exactly what the bug got wrong.
    """

    def _audit_function(self, function):
        program = _program(function)
        stack = _analyze(program, prover=_StubProver())
        document = _audit(program, stack, names=(function.name,))
        return stack, program, document

    def test_a_single_allocation_before_the_call_is_the_unique_origin(self):
        function = _function(
            "setup_unique",
            0x7000,
            [
                ("ld", ["s1", "0(s2)"]),
                ("jalr", ["a3"]),
                ("sub", ["sp", "sp", "s1"]),
                ("ret", []),
            ],
        )
        stack, _, document = self._audit_function(function)
        local = stack.by_function[0x7000]
        self.assertIn(
            str(VLEN_STACK_SETUP), {str(obj) for obj in local.live_before[0x7004]}
        )
        self.assertEqual(
            [hex(0x7008)],
            [item["addresses"]["allocation"] for item in document["candidates"]],
        )
        self.assertNotIn(audit.SOURCE_UNATTRIBUTED_ACTIVITY, _kinds(document))
        self.assertNotIn(audit.GAP_UNATTRIBUTED_SETUP_MARKER, _gap_kinds(document))
        self.assertNotIn(audit.GAP_AMBIGUOUS_SETUP_ORIGIN, _gap_kinds(document))
        # The site now belongs to the real (assumption-excluded) allocation
        # instead of being laundered into a source that cannot be excluded.
        site = document["affected_sites"][0]
        self.assertEqual("0x7004", site["call_site"])
        self.assertEqual(1, len(site["contributors"]))
        self.assertEqual(site["contributors"], site["contributors_excluded"])
        allocation = document["candidates"][0]
        self.assertTrue(allocation["excluded_by_assumption"])
        self.assertEqual(["0x7004"], allocation["affected_sites"])

    def test_two_reachable_allocations_keep_both_origins(self):
        function = _function(
            "setup_ambiguous",
            0x7200,
            [
                ("ld", ["s1", "0(s2)"]),
                ("jalr", ["a3"]),
                ("beqz", ["a0", "0x7214"]),
                ("sub", ["sp", "sp", "s1"]),
                ("j", ["0x7218"]),
                ("sub", ["sp", "sp", "s1"]),
                ("ret", []),
            ],
        )
        stack, _, document = self._audit_function(function)
        sites = [
            hex(origin.adjustment)
            for origin in stack.by_function[0x7200].frame_origins
        ]
        self.assertEqual(["0x720c", "0x7214"], sites)
        self.assertIn(audit.GAP_AMBIGUOUS_SETUP_ORIGIN, _gap_kinds(document))
        gap = [
            item
            for item in document["gaps"]
            if item["kind"] == audit.GAP_AMBIGUOUS_SETUP_ORIGIN
        ][0]
        self.assertEqual(["0x720c", "0x7214"], gap["allocations"])
        site = document["affected_sites"][0]
        self.assertEqual("0x7204", site["call_site"])
        self.assertEqual(2, len(site["contributors"]))
        self.assertEqual(sorted(gap["candidates"]), sorted(site["contributors"]))

    def test_the_frame_marker_still_runs_forward(self):
        """The counter-direction: a frame allocation *before* the call is found."""

        function = _function(
            "frame_after",
            0x7300,
            [
                ("csrr", ["a0", "vlenb"]),
                ("sub", ["sp", "sp", "a0"]),
                ("jalr", ["a3"]),
                ("ret", []),
            ],
        )
        _, _, document = self._audit_function(function)
        self.assertNotIn(audit.SOURCE_UNATTRIBUTED_ACTIVITY, _kinds(document))
        self.assertEqual(2, len(document["affected_sites"][0]["contributors"]))


class PropagationTests(unittest.TestCase):
    def _recursive_program(self) -> Program:
        return _program(
            _function(
                "rec_a",
                0x8000,
                [
                    ("addi", ["sp", "sp", "-128"]),
                    ("vsetivli", ["zero", "16", "e64", "m4", "ta", "ma"]),
                    ("mv", ["s1", "sp"]),
                    ("vs4r.v", ["v9", "(s1)"]),
                    ("jal", ["ra", "0x8100"]),
                    ("vl4re64.v", ["v10", "(s1)"]),
                    ("addi", ["sp", "sp", "128"]),
                    ("ret", []),
                ],
            ),
            _function("rec_b", 0x8100, [("jal", ["ra", "0x8000"]), ("ret", [])]),
        )

    def test_a_recursive_chain_converges_and_is_cross_checked(self):
        program = self._recursive_program()
        stack = _analyze(program)
        _resolve(program, 0x8010, 0x8100)
        _resolve(program, 0x8100, 0x8000)
        document = _audit(program, stack, names=("rec_a", "rec_b"))
        propagation = document["propagation"]
        self.assertTrue(propagation["fixpoint_converged"])
        self.assertLessEqual(
            propagation["fixpoint_iterations"], len(program.functions) + 1
        )
        self.assertEqual([], propagation["cross_check"]["mismatches"])
        self.assertTrue(propagation["cross_check"]["inherited_matches_analyzer"])
        self.assertTrue(propagation["cross_check"]["affected_matches_analyzer"])
        self.assertEqual(2, propagation["inherited_functions"])

    def test_a_locally_empty_but_inherited_call_site_counts_as_active(self):
        """A site with no local contributor is active when its caller is.

        Counting the local set alone would report this site as inactive, which
        is exactly the statistic the production analyzer disagrees with.
        """

        program = _program(
            _function(
                "caller",
                0x9000,
                [
                    ("addi", ["sp", "sp", "-128"]),
                    ("vsetivli", ["zero", "16", "e64", "m4", "ta", "ma"]),
                    ("mv", ["s1", "sp"]),
                    ("vs4r.v", ["v9", "(s1)"]),
                    ("jal", ["ra", "0x9100"]),
                    ("vl4re64.v", ["v10", "(s1)"]),
                    ("addi", ["sp", "sp", "128"]),
                    ("ret", []),
                ],
            ),
            _function("callee", 0x9100, [("jalr", ["a3"]), ("ret", [])]),
        )
        stack = _analyze(program)
        _resolve(program, 0x9010, 0x9100)
        document = _audit(program, stack, names=("caller",))
        propagation = document["propagation"]
        self.assertEqual(1, propagation["affected_sites"])
        self.assertEqual(0, propagation["inactive_unresolved_sites"])
        self.assertEqual(0, propagation["inactive_unresolved_sites_local_only"])
        self.assertEqual(
            ["0x9100"],
            [site["call_site"] for site in document["affected_sites"]],
        )
        self.assertTrue(propagation["cross_check"]["affected_matches_analyzer"])

    def test_a_closure_difference_is_reported_and_not_hidden(self):
        program = self._recursive_program()
        stack = _analyze(program)
        _resolve(program, 0x8010, 0x8100)
        _resolve(program, 0x8100, 0x8000)
        tampered = StackLivenessResult(
            by_function=stack.by_function,
            inherited_functions=frozenset(),
            unresolved_live_calls=stack.unresolved_live_calls,
        )
        document = _audit(program, tampered, names=("rec_a", "rec_b"))
        self.assertIn(audit.GAP_CLOSURE_MISMATCH, _gap_kinds(document))
        cross = document["propagation"]["cross_check"]
        self.assertFalse(cross["inherited_matches_analyzer"])
        self.assertIn("inherited-closure", cross["mismatches"])

    def test_two_callers_with_different_sources_both_reach_one_sink(self):
        program = _program(
            _function(
                "src_a",
                0xA000,
                [
                    ("addi", ["sp", "sp", "-128"]),
                    ("vsetivli", ["zero", "16", "e64", "m4", "ta", "ma"]),
                    ("mv", ["s1", "sp"]),
                    ("vs4r.v", ["v9", "(s1)"]),
                    ("jal", ["ra", "0xA100"]),
                    ("vl4re64.v", ["v10", "(s1)"]),
                    ("addi", ["sp", "sp", "128"]),
                    ("ret", []),
                ],
            ),
            _function(
                "src_b",
                0xA100,
                [
                    ("vsetivli", ["zero", "8", "e32", "m2", "ta", "ma"]),
                    ("mv", ["s1", "sp"]),
                    ("vs4r.v", ["v9", "(s1)"]),
                    ("jal", ["ra", "0xA200"]),
                    ("vl4re64.v", ["v10", "(s1)"]),
                    ("ret", []),
                ],
            ),
            _function("sink", 0xA200, [("jalr", ["a3"]), ("ret", [])]),
        )
        stack = _analyze(program)
        _resolve(program, 0xA010, 0xA100)
        _resolve(program, 0xA10C, 0xA200)
        document = _audit(program, stack, names=("src_a", "src_b"))
        self.assertEqual(
            ["0xa200"],
            [site["call_site"] for site in document["affected_sites"]],
        )
        owners = {
            item["id"]: item["function"] for item in document["candidates"]
        }
        contributors = document["affected_sites"][0]["contributors"]
        self.assertEqual(
            ["src_a", "src_b"],
            sorted({owners[ident] for ident in contributors}),
        )
        self.assertTrue(
            document["propagation"]["cross_check"]["affected_matches_analyzer"]
        )


# endregion


# region gate-list size and name matching


def _variant_program() -> Program:
    return _program(
        _function("_ZN1AC1Ev", 0xB000, [("ret", [])]),
        _function("_ZN1AC1Ev", 0xB100, [("ret", [])]),
        _function("clone_target", 0xB200, [("ret", [])]),
        _function("clone_target.isra.0", 0xB300, [("ret", [])]),
        _function("0xb400", 0xB400, [("ret", [])]),
    )


class GateListSizeTests(unittest.TestCase):
    def test_the_expected_gate2_size_is_the_documented_constant(self):
        self.assertEqual(1642, audit.EXPECTED_GATE2_LIST_SIZE)

    def test_both_decision_forms_load_and_report_their_dedup_count(self):
        program = _unique_program()
        stack = _analyze(program)
        names = [
            f"_Z3foo{index}v" for index in range(audit.EXPECTED_GATE2_LIST_SIZE)
        ]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            text_file = _write(root / "gate.gate_names.txt", "\n".join(names) + "\n")
            unique, info = audit.load_gate_list_file(text_file)
            self.assertEqual(audit.EXPECTED_GATE2_LIST_SIZE, len(unique))
            self.assertEqual("gate-names-text", info["source_kind"])
            self.assertEqual(0, info["duplicates_dropped"])

            decision = _write(
                root / "decision.json",
                json.dumps({"decision": {"gate": {"names": names}}}),
            )
            unique_json, info_json = audit.load_gate_list_file(decision)
            self.assertEqual(unique, unique_json)
            self.assertEqual("decision-json", info_json["source_kind"])
            self.assertEqual(
                audit.EXPECTED_GATE2_LIST_SIZE, info_json["unique_names"]
            )
        document = _audit(
            program,
            stack,
            names=names,
            expected=audit.EXPECTED_GATE2_LIST_SIZE,
            gate_info={"nonempty_lines": len(names)},
        )
        self.assertTrue(document["gate_list"]["size_check"]["matches_expected"])

    def test_a_duplicated_list_still_dedups_to_the_expected_size(self):
        program = _unique_program()
        stack = _analyze(program)
        names = [
            f"_Z3bar{index}v"
            for index in range(audit.EXPECTED_GATE2_LIST_SIZE - 1)
        ]
        names = names + [names[0]]
        document = _audit(
            program,
            stack,
            names=names,
            expected=audit.EXPECTED_GATE2_LIST_SIZE,
            gate_info={
                "nonempty_lines": len(names),
                "duplicates_dropped": 1,
                "unique_names": audit.EXPECTED_GATE2_LIST_SIZE,
            },
        )
        size_check = document["gate_list"]["size_check"]
        self.assertTrue(size_check["matches_expected"])
        self.assertEqual(1, size_check["duplicates_dropped"])
        self.assertNotIn(audit.GAP_GATE_LIST_SIZE_MISMATCH, _gap_kinds(document))

    def test_a_short_list_is_reported_as_a_size_mismatch(self):
        program = _unique_program()
        stack = _analyze(program)
        document = _audit(
            program,
            stack,
            names=["_Z3foo_v"],
            expected=audit.EXPECTED_GATE2_LIST_SIZE,
        )
        self.assertFalse(document["gate_list"]["size_check"]["matches_expected"])
        self.assertIn(audit.GAP_GATE_LIST_SIZE_MISMATCH, _gap_kinds(document))

    def test_a_list_without_an_expectation_is_not_judged(self):
        program = _unique_program()
        stack = _analyze(program)
        document = _audit(program, stack, names=["unique"], expected=None)
        self.assertIsNone(document["gate_list"]["size_check"]["matches_expected"])
        self.assertNotIn(audit.GAP_GATE_LIST_SIZE_MISMATCH, _gap_kinds(document))


class NameMatchingTests(unittest.TestCase):
    def setUp(self):
        self.program = _build(_variant_program())
        self.stack = _stack_with_one_allocation(
            self.program, [0xB000, 0xB100, 0xB200, 0xB300, 0xB400]
        )

    def test_c1_c2_and_d1_d2_variants_match(self):
        document = _audit(self.program, self.stack, names=("_ZN1AC2Ev",))
        self.assertEqual("variant", _entry(document, "_ZN1AC2Ev")["match"])
        candidate = _candidates_of(document, "_ZN1AC1Ev")[0]
        self.assertEqual("variant", candidate["evidence"]["list_status"])
        self.assertEqual(["_ZN1AC2Ev"], candidate["evidence"]["matched_entries"])

    def test_same_name_definitions_keep_both_and_stay_ambiguous(self):
        document = _audit(self.program, self.stack, names=("_ZN1AC2Ev",))
        entry = _entry(document, "_ZN1AC2Ev")
        self.assertTrue(entry["ambiguous"])
        self.assertEqual(2, len(entry["matched_functions"]))
        self.assertIn("同名/变体匹配到多个函数定义", " ".join(entry["notes"]))
        for candidate in _candidates_of(document, "_ZN1AC1Ev"):
            self.assertIn("同名函数存在于其他地址", " ".join(candidate["notes"]))
        self.assertIn(entry["status"], audit.PENDING_ENTRY_STATUSES)

    def test_ambiguity_alone_keeps_an_entry_pending(self):
        """A clean bound record does not verify two definitions it cannot tell apart."""

        sourceless = _stack_with_one_allocation(self.program, [])
        document = _audit(
            self.program,
            sourceless,
            names=("_ZN1AC2Ev",),
            census={"_ZN1AC2Ev": {"LV": {"blocked": {"c.tsv"}}}},
            bound=frozenset({"c.tsv"}),
            census_paths=["c.tsv"],
        )
        entry = _entry(document, "_ZN1AC2Ev")
        self.assertTrue(entry["ambiguous"])
        self.assertEqual(audit.ENTRY_BLOCKED_EVIDENCE, entry["status"])
        self.assertTrue(entry["pending"])
        self.assertEqual(1, document["gate_list"]["entries_pending"])
        self.assertEqual(1, document["gate_list"]["entries_pending_only_by_ambiguity"])
        pending = document["answers"]["listed_functions_pending_gate_verification"]
        self.assertEqual(["ambiguous-definitions"], [e["pending_reason"] for e in pending])

    def test_a_clone_is_not_covered_by_its_base_name(self):
        document = _audit(self.program, self.stack, names=("clone_target",))
        self.assertIn(
            "clone_target.isra.0", _entry(document, "clone_target")["unmatched_clones"]
        )
        cloned = _candidates_of(document, "clone_target.isra.0")[0]
        self.assertEqual("none", cloned["evidence"]["list_status"])
        self.assertIn("克隆符号", " ".join(cloned["notes"]))

    def test_a_hex_fallback_name_matches_a_hex_named_symbol_exactly(self):
        document = _audit(self.program, self.stack, names=("0xb400",))
        self.assertEqual("exact", _entry(document, "0xb400")["match"])

    def test_a_listed_name_without_a_symbol_is_never_a_success(self):
        document = _audit(self.program, self.stack, names=("_Z11not_presentv",))
        entry = _entry(document, "_Z11not_presentv")
        self.assertEqual(audit.ENTRY_NO_SYMBOL, entry["status"])
        self.assertIn(entry["status"], audit.PENDING_ENTRY_STATUSES)

    def test_the_aggregate_log_line_is_annotated_as_list_passed_only(self):
        document = _audit(self.program, self.stack, names=("clone_target",))
        self.assertIn(
            "只证明名单被传入编译", document["gate_list"]["aggregate_log_note"]
        )

    def test_a_candidate_outside_the_list_is_reported_as_missing(self):
        document = _audit(self.program, self.stack, names=("clone_target",))
        missing = document["answers"]["sources_missing_from_list"]
        self.assertEqual(
            ["0xb400", "_ZN1AC1Ev", "_ZN1AC1Ev", "clone_target.isra.0"],
            sorted(item["function"] for item in missing),
        )


# endregion


# region census and evidence binding


def _evidence_manifest(
    path: Path,
    *,
    census: Path,
    consumed_decision_sha: str,
    stage: str = audit.STAGE_BUILD_GATE2,
    census_sha: str | None = None,
    compile_unit: str | None = "libbackend.a",
    toolchain: str | None = TOOLCHAIN_SHA,
    artifact_sha256: str | None = ELF_SHA,
    compile_command: str | None = "-fpass-plugin=VectorGatePlugin.so -c foo.cc",
    declare_units: bool = True,
    unit_census: str | None = None,
) -> Path:
    """A manifest that binds by default; each argument breaks one link."""

    unit_name = compile_unit if compile_unit is not None else "libbackend.a"
    unit = {
        "name": unit_name,
        "compile_command": compile_command,
        "census": unit_census if unit_census is not None else str(census),
    }
    record = {
        "path": str(census),
        "sha256": census_sha if census_sha is not None else _sha256(census),
        "compile_unit": compile_unit,
        "toolchain": toolchain,
    }
    document = {
        "format": audit.EVIDENCE_FORMAT,
        "stage": stage,
        "decision": {
            "path": "build-gate2.decision.json",
            "sha256": consumed_decision_sha,
        },
        "artifact": (
            None
            if artifact_sha256 is None
            else {"path": "xgcc", "sha256": artifact_sha256}
        ),
        "toolchain": {
            "xgcc": toolchain,
            "xgcc_sha256": toolchain,
            "cc1": TOOLCHAIN_SHA,
            "version": "gcc version 15.0.0 (Chimera)",
        },
        "compile_units": [unit] if declare_units else [],
        "census": [record],
    }
    return _write(path, json.dumps(document, ensure_ascii=False, indent=2))


class EvidenceBindingTests(unittest.TestCase):
    """A census record only counts when it is bound to this build."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.program = _sourced_and_clean_program()
        self.stack = _stack_with_one_allocation(self.program, [0xC000])

    def _census(self, body: str) -> Path:
        return _write(self.root / "census.tsv", body)

    def _audit_with(
        self,
        census: Path,
        manifest: Path | None,
        names,
        *,
        stage: str = audit.STAGE_BUILD_GATE2,
        consumed_sha: str | None = GATE_SHA,
        consumed_decision: dict | None = None,
    ):
        loaded, _ = audit.load_census([str(census)], frozenset())
        evidence = (
            audit.load_evidence_manifest(manifest) if manifest is not None else {}
        )
        # Mirror audit_elf: the payload records the same decision the binding
        # consumed, so the row reports whether the two agree.
        if consumed_decision is None and consumed_sha is not None:
            consumed_decision = {
                "path": "consumed.decision.json",
                "sha256": consumed_sha,
                "role": "consumed-decision",
                "note": "",
            }
        gaps: list[dict] = []
        bound = audit._bind_evidence(
            [str(census)],
            evidence,
            stage=stage,
            consumed_decision_sha256=consumed_sha,
            artifact_sha256=ELF_SHA,
            gaps=gaps,
        )
        document = _audit(
            self.program,
            self.stack,
            names=names,
            census=loaded,
            bound=bound,
            census_paths=[str(census)],
            evidence=evidence,
            stage=stage,
            consumed_decision=consumed_decision,
        )
        document["gaps"] = gaps + document["gaps"]
        return document, bound

    def test_an_unbound_blocked_record_does_not_prove_the_gate_fired(self):
        census = self._census("implicit-vector-census\tLV\tsourced\tblocked\n")
        document, bound = self._audit_with(census, None, names=("sourced",))
        self.assertEqual(frozenset(), bound)
        entry = _entry(document, "sourced")
        self.assertNotEqual(audit.ENTRY_BLOCKED_EVIDENCE, entry["status"])
        self.assertEqual(audit.EVIDENCE_UNBOUND, entry["evidence_status"])
        self.assertIn(audit.GAP_CENSUS_UNBOUND, _gap_kinds(document))
        self.assertIn("不得据此证明 gate 生效", " ".join(entry["notes"]))

    def test_an_unbound_formed_record_does_not_prove_the_gate_was_bypassed(self):
        census = self._census("implicit-vector-census\tLV\tsourced\tformed\n")
        document, bound = self._audit_with(census, None, names=("sourced",))
        self.assertEqual(frozenset(), bound)
        entry = _entry(document, "sourced")
        self.assertNotEqual(audit.ENTRY_GATE_BYPASSED, entry["status"])
        self.assertEqual(audit.EVIDENCE_UNBOUND, entry["evidence_status"])
        self.assertIn("不得据此判定 gate 绕过", " ".join(entry["notes"]))

    def test_a_bound_blocked_record_without_residue_is_blocked_evidence(self):
        census = self._census("implicit-vector-census\tLV\tclean\tblocked\n")
        manifest = _evidence_manifest(
            self.root / "evidence.json", census=census, consumed_decision_sha=GATE_SHA
        )
        document, bound = self._audit_with(census, manifest, names=("clean",))
        self.assertEqual({str(census)}, set(bound))
        entry = _entry(document, "clean")
        self.assertEqual(audit.ENTRY_BLOCKED_EVIDENCE, entry["status"])
        self.assertNotIn(entry["status"], audit.PENDING_ENTRY_STATUSES)
        self.assertEqual(["LV"], entry["census_blocked_bound"])
        self.assertEqual(1, document["gate_list"]["entries_with_bound_blocked"])

    def test_a_bound_blocked_record_next_to_a_remaining_source_still_reports_the_source(self):
        census = self._census("implicit-vector-census\tLV\tsourced\tblocked\n")
        manifest = _evidence_manifest(
            self.root / "evidence.json", census=census, consumed_decision_sha=GATE_SHA
        )
        document, _ = self._audit_with(census, manifest, names=("sourced",))
        entry = _entry(document, "sourced")
        self.assertEqual(audit.ENTRY_SOURCE_REMAINS, entry["status"])
        self.assertEqual(["LV"], entry["census_blocked_bound"])
        self.assertIn("同时有已绑定 blocked 证据", " ".join(entry["notes"]))

    def test_a_bound_formed_record_is_reported_as_a_gate_bypass(self):
        census = self._census("implicit-vector-census\tLV\tsourced\tformed\n")
        manifest = _evidence_manifest(
            self.root / "evidence.json", census=census, consumed_decision_sha=GATE_SHA
        )
        document, _ = self._audit_with(census, manifest, names=("sourced",))
        entry = _entry(document, "sourced")
        self.assertEqual(audit.ENTRY_GATE_BYPASSED, entry["status"])
        self.assertEqual(["LV"], entry["census_formed_bound"])
        self.assertEqual(1, document["gate_list"]["entries_with_bound_formed"])

    def test_a_census_from_another_stage_cannot_bind(self):
        census = self._census("implicit-vector-census\tLV\tsourced\tformed\n")
        manifest = _evidence_manifest(
            self.root / "evidence.json",
            census=census,
            consumed_decision_sha=GATE_SHA,
            stage=audit.STAGE_BUILD_STACK,
        )
        document, bound = self._audit_with(census, manifest, names=("sourced",))
        self.assertEqual(frozenset(), bound)
        entry = _entry(document, "sourced")
        self.assertNotEqual(audit.ENTRY_GATE_BYPASSED, entry["status"])
        self.assertEqual(audit.EVIDENCE_UNBOUND, entry["evidence_status"])

    def test_a_census_from_another_decision_cannot_bind(self):
        census = self._census("implicit-vector-census\tLV\tsourced\tformed\n")
        manifest = _evidence_manifest(
            self.root / "evidence.json", census=census, consumed_decision_sha="b" * 64
        )
        _, bound = self._audit_with(census, manifest, names=("sourced",))
        self.assertEqual(frozenset(), bound)

    def test_a_census_whose_content_changed_cannot_bind(self):
        census = self._census("implicit-vector-census\tLV\tsourced\tformed\n")
        manifest = _evidence_manifest(
            self.root / "evidence.json",
            census=census,
            consumed_decision_sha=GATE_SHA,
            census_sha="c" * 64,
        )
        _, bound = self._audit_with(census, manifest, names=("sourced",))
        self.assertEqual(frozenset(), bound)

    def test_every_broken_link_keeps_the_record_unbound(self):
        """Each link is checked against something outside the record itself."""

        census = self._census("implicit-vector-census\tLV\tsourced\tformed\n")
        cases = {
            "no compile unit": {"compile_unit": None},
            "no toolchain": {"toolchain": None},
            "toolchain is a label": {"toolchain": "placeholder"},
            "unit not declared": {"declare_units": False},
            "unit has no command": {"compile_command": ""},
            "no artifact identity": {"artifact_sha256": None},
            "artifact is another build": {"artifact_sha256": "d" * 64},
            "unit points at another census": {"unit_census": "other.tsv"},
        }
        for label, kwargs in cases.items():
            with self.subTest(broken_link=label):
                manifest = _evidence_manifest(
                    self.root / f"evidence-{abs(hash(label))}.json",
                    census=census,
                    consumed_decision_sha=GATE_SHA,
                    **kwargs,
                )
                document, bound = self._audit_with(census, manifest, names=("sourced",))
                self.assertEqual(frozenset(), bound)
                self.assertIn(audit.GAP_CENSUS_UNBOUND, _gap_kinds(document))
                self.assertEqual(
                    audit.EVIDENCE_UNBOUND, _entry(document, "sourced")["evidence_status"]
                )

    def test_a_wholly_declared_manifest_binds(self):
        """Positive control: the same manifest without any break must bind."""

        census = self._census("implicit-vector-census\tLV\tsourced\tblocked\n")
        manifest = _evidence_manifest(
            self.root / "evidence.json", census=census, consumed_decision_sha=GATE_SHA
        )
        document, bound = self._audit_with(census, manifest, names=("sourced",))
        self.assertEqual({str(census.resolve())}, set(bound))
        self.assertNotIn(audit.GAP_CENSUS_UNBOUND, _gap_kinds(document))
        self.assertEqual(
            audit.EVIDENCE_BOUND_BLOCKED,
            _entry(document, "sourced")["evidence_status"],
        )

    def test_a_manifest_without_any_unit_or_artifact_cannot_bind(self):
        """The shape the review probe used: declared names, nothing resolved."""

        census = self._census("implicit-vector-census\tLV\tsourced\tformed\n")
        manifest = _write(
            self.root / "declared-only.json",
            json.dumps(
                {
                    "format": audit.EVIDENCE_FORMAT,
                    "stage": audit.STAGE_BUILD_GATE2,
                    "decision": {"path": "decision.json", "sha256": GATE_SHA},
                    "toolchain": {"xgcc": "placeholder", "version": "x"},
                    "census": [
                        {
                            "path": str(census),
                            "sha256": _sha256(census),
                            "compile_unit": "nonexistent.cc",
                            "toolchain": "placeholder",
                        }
                    ],
                },
                ensure_ascii=False,
            ),
        )
        document, bound = self._audit_with(census, manifest, names=("sourced",))
        self.assertEqual(frozenset(), bound)
        details = " ".join(gap["detail"] for gap in document["gaps"])
        for expected in (
            "产物哈希",
            "compile_units",
            "编译命令",
            "sha256 摘要",
        ):
            self.assertIn(expected, details, expected)

    def test_records_about_other_functions_imply_nothing_about_the_listed_one(self):
        census = self._census(
            "implicit-vector-census\tLV\t_Z11not_presentv\tblocked\n"
        )
        manifest = _evidence_manifest(
            self.root / "evidence.json", census=census, consumed_decision_sha=GATE_SHA
        )
        document, bound = self._audit_with(census, manifest, names=("clean",))
        self.assertEqual({str(census)}, set(bound))
        entry = _entry(document, "clean")
        self.assertEqual([], entry["census_blocked_bound"])
        self.assertEqual(audit.ENTRY_MISSING_COMPILE_EVIDENCE, entry["status"])

    def test_a_census_is_matched_by_resolved_path_not_by_spelling(self):
        """A different spelling of the same file must not fake missing evidence."""

        census = self._census("implicit-vector-census\tLV\tclean\tblocked\n")
        detour = census.parent / "detour"
        detour.mkdir()
        spelled = detour / ".." / census.name
        self.assertNotEqual(str(spelled), str(census))
        manifest = _evidence_manifest(
            self.root / "evidence.json", census=spelled, consumed_decision_sha=GATE_SHA
        )
        document, bound = self._audit_with(census, manifest, names=("clean",))
        self.assertEqual({str(census.resolve())}, set(bound))
        self.assertEqual(
            audit.ENTRY_BLOCKED_EVIDENCE, _entry(document, "clean")["status"]
        )

    def test_the_evidence_section_records_binding_per_file(self):
        census = self._census("implicit-vector-census\tLV\tclean\tblocked\n")
        manifest = _evidence_manifest(
            self.root / "evidence.json", census=census, consumed_decision_sha=GATE_SHA
        )
        document, _ = self._audit_with(census, manifest, names=("clean",))
        evidence = document["evidence"]
        self.assertEqual(1, evidence["bound_census_count"])
        self.assertEqual(0, evidence["unbound_census_count"])
        row = evidence["census_files"][0]
        self.assertTrue(row["bound"])
        self.assertEqual("libbackend.a", row["compile_unit"])
        self.assertTrue(row["compile_unit_declared"])
        self.assertEqual(TOOLCHAIN_SHA, row["toolchain"])
        self.assertEqual(ELF_SHA, row["artifact_sha256"])
        self.assertTrue(row["compile_command"])

    # --- the decision role used for binding --------------------------------
    #
    # The comparison list and the decision a build actually consumed are
    # different documents.  build-stack enables only the stack-object plugin
    # and consumed a stack-only decision, so an honest census record for it can
    # never match the gate-2 comparison list.  Binding on the comparison list
    # would therefore reject truthful baseline evidence *and* accept a record
    # from a different build that merely shares the stage name.

    def test_binding_uses_the_consumed_decision_not_the_comparison_list(self):
        stack_sha = "c" * 64
        census = self._census("implicit-vector-census\tLV\tclean\tblocked\n")
        manifest = _evidence_manifest(
            self.root / "evidence.json", census=census, consumed_decision_sha=stack_sha
        )
        # gate_list_info still carries GATE_SHA; the record declares stack_sha.
        document, bound = self._audit_with(
            census, manifest, names=("clean",), consumed_sha=stack_sha
        )
        self.assertEqual({str(census.resolve())}, set(bound))
        self.assertEqual(
            audit.ENTRY_BLOCKED_EVIDENCE, _entry(document, "clean")["status"]
        )
        row = document["evidence"]["census_files"][0]
        self.assertTrue(row["consumed_decision_matches"])
        self.assertEqual(stack_sha, row["declared_consumed_decision_sha256"])
        self.assertNotEqual(GATE_SHA, row["consumed_decision_sha256"])

    def test_the_comparison_list_is_never_substituted_for_the_consumed_one(self):
        stack_sha = "c" * 64
        census = self._census("implicit-vector-census\tLV\tclean\tblocked\n")
        manifest = _evidence_manifest(
            self.root / "evidence.json", census=census, consumed_decision_sha=stack_sha
        )
        document, bound = self._audit_with(
            census, manifest, names=("clean",), consumed_sha=GATE_SHA
        )
        self.assertEqual(frozenset(), bound)
        details = " ".join(gap["detail"] for gap in document["gaps"])
        self.assertIn("决策哈希与实际消费的决策不符", details)
        self.assertEqual(
            audit.ENTRY_UNBOUND_EVIDENCE, _entry(document, "clean")["status"]
        )

    def test_an_undeclared_consumed_decision_binds_nothing(self):
        census = self._census("implicit-vector-census\tLV\tclean\tblocked\n")
        manifest = _evidence_manifest(
            self.root / "evidence.json", census=census, consumed_decision_sha=GATE_SHA
        )
        document, bound = self._audit_with(
            census, manifest, names=("clean",), consumed_sha=None
        )
        self.assertEqual(frozenset(), bound)
        self.assertIn(audit.GAP_CONSUMED_DECISION_MISSING, _gap_kinds(document))
        details = " ".join(gap["detail"] for gap in document["gaps"])
        self.assertIn("不用对照名单替代", details)
        self.assertIn("不参与证据绑定", document["evidence"]["note"])
        self.assertEqual("unbound-evidence", _entry(document, "clean")["status"])

    def test_the_missing_decision_gap_counts_the_files_it_downgrades(self):
        census = self._census("implicit-vector-census\tLV\tclean\tblocked\n")
        manifest = _evidence_manifest(
            self.root / "evidence.json", census=census, consumed_decision_sha=GATE_SHA
        )
        document, bound = self._audit_with(
            census, manifest, names=("clean",), consumed_sha=None
        )
        gap = [
            item
            for item in document["gaps"]
            if item["kind"] == audit.GAP_CONSUMED_DECISION_MISSING
        ][0]
        self.assertIn("1 个 census 文件", gap["detail"])
        self.assertEqual(frozenset(), bound)

    def test_no_census_files_means_no_missing_decision_gap(self):
        """The gap is about records that exist and cannot be bound, not absence."""

        gaps: list[dict] = []
        bound = audit._bind_evidence(
            [],
            {},
            stage=audit.STAGE_BUILD_GATE2,
            consumed_decision_sha256=None,
            artifact_sha256=ELF_SHA,
            gaps=gaps,
        )
        self.assertEqual(frozenset(), bound)
        self.assertEqual([], gaps)

    # --- what a bound formed record is allowed to mean ---------------------

    def test_a_formed_record_in_the_gate_disabled_stage_is_not_a_bypass(self):
        census = self._census("implicit-vector-census\tLV\tsourced\tformed\n")
        manifest = _evidence_manifest(
            self.root / "evidence.json",
            census=census,
            consumed_decision_sha=GATE_SHA,
            stage=audit.STAGE_BUILD_STACK,
        )
        document, bound = self._audit_with(
            census,
            manifest,
            names=("sourced",),
            stage=audit.STAGE_BUILD_STACK,
        )
        self.assertEqual({str(census.resolve())}, set(bound))
        entry = _entry(document, "sourced")
        self.assertEqual(audit.ENTRY_FORMED_BEFORE_GATE, entry["status"])
        self.assertNotEqual(audit.ENTRY_GATE_BYPASSED, entry["status"])
        self.assertEqual(audit.EVIDENCE_BOUND_FORMED, entry["evidence_status"])
        # It is still not verified - the stage simply cannot verify it.
        self.assertTrue(entry["pending"])
        self.assertIn("未启用 gate", " ".join(entry["notes"]))

    def test_the_same_formed_record_is_a_bypass_once_the_gate_stage_forms_it(self):
        census = self._census("implicit-vector-census\tLV\tsourced\tformed\n")
        manifest = _evidence_manifest(
            self.root / "evidence.json", census=census, consumed_decision_sha=GATE_SHA
        )
        document, bound = self._audit_with(census, manifest, names=("sourced",))
        self.assertEqual({str(census.resolve())}, set(bound))
        entry = _entry(document, "sourced")
        self.assertEqual(audit.ENTRY_GATE_BYPASSED, entry["status"])
        self.assertTrue(entry["pending"])
        self.assertIn(
            1, document["gate_list"]["status_counts"].values()
        )

    def test_both_formed_statuses_are_counted_separately(self):
        census = self._census("implicit-vector-census\tLV\tsourced\tformed\n")
        manifest = _evidence_manifest(
            self.root / "evidence.json", census=census, consumed_decision_sha=GATE_SHA
        )
        document, _ = self._audit_with(census, manifest, names=("sourced",))
        counts = document["gate_list"]["status_counts"]
        for status in (audit.ENTRY_GATE_BYPASSED, audit.ENTRY_FORMED_BEFORE_GATE):
            self.assertIn(status, counts, status)
        self.assertEqual(1, counts[audit.ENTRY_GATE_BYPASSED])
        self.assertEqual(0, counts[audit.ENTRY_FORMED_BEFORE_GATE])


class CensusValidationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def _load(self, body: str):
        path = _write(self.root / "census.tsv", body)
        return audit.load_census([str(path)], frozenset())

    def test_malformed_records_are_rejected_with_a_reason(self):
        census, gaps = self._load(
            "implicit-vector-census\tLV\tonly_three_fields\n"
            "implicit-vector-census\tLV\tfoo\tmaybe\n"
            "not-a-census\tLV\tfoo\tblocked\n"
            "implicit-vector-census\tLV\t\tblocked\n"
            "implicit-vector-census\t\tfoo\tblocked\n"
        )
        self.assertEqual({}, census)
        self.assertEqual(
            5,
            len(
                [
                    gap
                    for gap in gaps
                    if gap["kind"] == audit.GAP_CENSUS_MALFORMED_LINE
                ]
            ),
        )
        self.assertIn(
            audit.GAP_CENSUS_WITHOUT_USABLE_LINES, {gap["kind"] for gap in gaps}
        )

    def test_an_unknown_mechanism_is_kept_and_flagged(self):
        census, gaps = self._load(
            "implicit-vector-census\tUNKNOWN_MECH\tfoo\tblocked\n"
        )
        self.assertEqual({"blocked"}, set(census["foo"]["UNKNOWN_MECH"]))
        self.assertIn(
            audit.GAP_CENSUS_UNKNOWN_MECHANISM, {gap["kind"] for gap in gaps}
        )

    def test_conflicting_actions_are_not_merged_away(self):
        census, gaps = self._load(
            "implicit-vector-census\tLV\tfoo\tformed\n"
            "implicit-vector-census\tLV\tfoo\tblocked\n"
        )
        self.assertEqual({"formed", "blocked"}, set(census["foo"]["LV"]))
        self.assertEqual(
            1,
            len(
                [
                    gap
                    for gap in gaps
                    if gap["kind"] == audit.GAP_CENSUS_ACTION_CONFLICT
                ]
            ),
        )

    def test_a_conflict_reaches_the_gate_entry_as_a_conflict(self):
        program = _unique_program()
        stack = _analyze(program)
        census, gaps = self._load(
            "implicit-vector-census\tLV\tunique\tformed\n"
            "implicit-vector-census\tLV\tunique\tblocked\n"
        )
        document = _audit(program, stack, names=("unique",), census=census)
        document["gaps"] = gaps + document["gaps"]
        entry = _entry(document, "unique")
        self.assertEqual(["LV@unique"], entry["census_conflicts"])
        self.assertEqual(1, document["gate_list"]["entries_with_census_conflict"])

    def test_a_conflict_does_not_upgrade_to_a_verdict(self):
        program = _unique_program()
        stack = _stack_with_one_allocation(program, [])
        document = _audit(
            program,
            stack,
            names=("unique",),
            census={"unique": {"LV": {"formed": {"c.tsv"}, "blocked": {"c.tsv"}}}},
            bound=frozenset({"c.tsv"}),
            census_paths=["c.tsv"],
        )
        entry = _entry(document, "unique")
        self.assertEqual(audit.EVIDENCE_CONFLICT, entry["evidence_status"])
        self.assertEqual([], entry["census_formed_bound"])
        self.assertEqual([], entry["census_blocked_bound"])
        self.assertEqual(["LV"], entry["census_conflicted_mechanisms"])
        # Neither conclusion may be drawn from a contradictory pair.
        self.assertNotEqual(audit.ENTRY_GATE_BYPASSED, entry["status"])
        self.assertNotEqual(audit.ENTRY_BLOCKED_EVIDENCE, entry["status"])
        self.assertEqual(audit.ENTRY_UNBOUND_EVIDENCE, entry["status"])

    def test_an_unrecognised_mechanism_does_not_upgrade_to_a_verdict(self):
        program = _unique_program()
        stack = _stack_with_one_allocation(program, [])
        document = _audit(
            program,
            stack,
            names=("unique",),
            census={"unique": {"BOGUS": {"blocked": {"c.tsv"}}}},
            bound=frozenset({"c.tsv"}),
            census_paths=["c.tsv"],
        )
        entry = _entry(document, "unique")
        self.assertEqual(audit.EVIDENCE_UNRECOGNISED, entry["evidence_status"])
        self.assertEqual(["BOGUS"], entry["census_unrecognised_mechanisms"])
        self.assertEqual([], entry["census_blocked_bound"])
        self.assertNotEqual(audit.ENTRY_BLOCKED_EVIDENCE, entry["status"])
        self.assertEqual(audit.ENTRY_UNBOUND_EVIDENCE, entry["status"])
        # The record itself survives (it is reported as an unrecognised
        # mechanism rather than disappearing): dropping it would turn
        # "unreadable evidence" into "no evidence", a different statement.
        self.assertIn("BOGUS", str(entry["census_unrecognised_mechanisms"]))

    def test_a_clean_mechanism_alongside_a_conflict_still_reports_its_mark(self):
        program = _unique_program()
        stack = _stack_with_one_allocation(program, [])
        document = _audit(
            program,
            stack,
            names=("unique",),
            census={
                "unique": {
                    "LV": {"formed": {"c.tsv"}},
                    "SLP": {"formed": {"c2.tsv"}, "blocked": {"c2.tsv"}},
                }
            },
            bound=frozenset({"c.tsv", "c2.tsv"}),
            census_paths=["c.tsv", "c2.tsv"],
        )
        entry = _entry(document, "unique")
        self.assertEqual(audit.EVIDENCE_CONFLICT, entry["evidence_status"])
        self.assertEqual(["LV"], entry["census_formed_bound"])
        self.assertEqual(["SLP"], entry["census_conflicted_mechanisms"])
        self.assertNotIn("SLP", entry["census_formed_bound"])
        self.assertNotIn("SLP", entry["census_blocked_bound"])

    def test_census_names_are_canonicalised_like_the_report_does(self):
        census, _ = self._load("implicit-vector-census\tLV\t_ZN1AC1Ev\tblocked\n")
        self.assertIn("_ZN1AC2Ev", census)

    def test_an_unreadable_census_is_a_gap_not_a_crash(self):
        census, gaps = audit.load_census(
            [str(self.root / "missing.tsv")], frozenset()
        )
        self.assertEqual({}, census)
        self.assertEqual([audit.GAP_CENSUS_UNREADABLE], [g["kind"] for g in gaps])

    def test_an_evidence_manifest_with_a_foreign_format_is_rejected(self):
        path = _write(self.root / "evidence.json", json.dumps({"format": "nope"}))
        with self.assertRaises(ValueError):
            audit.load_evidence_manifest(path)


# endregion


# region cross-build comparison


class CompareTests(unittest.TestCase):
    def _document(self, *, sha: str, stage: str) -> dict:
        program = _unique_program()
        stack = _analyze(program)
        document = _audit(program, stack, names=("unique",), stage=stage)
        # These tests compare allocation identities. The independent scalar
        # cache now enumerated from the same fixture is tested separately.
        document["candidates"] = [
            item for item in document["candidates"]
            if item["kind"] != audit.SOURCE_SCALAR_WIDTH_CACHE]
        document["elf"] = {
            "path": f"/tmp/{stage}.elf",
            "sha256": sha,
            "functions": 1,
            "instructions": 6,
        }
        return document

    def test_groups_pair_by_function_and_kind_with_both_address_lists(self):
        baseline = self._document(sha="1" * 64, stage=audit.STAGE_BUILD_STACK)
        audited = self._document(sha="2" * 64, stage=audit.STAGE_BUILD_GATE2)
        # Same symbol group, different addresses: both lists are kept instead
        # of pretending the addresses pair up.
        audited["candidates"][0]["addresses"] = {
            "allocation": "0x999c",
            "release": None,
        }
        compare = audit.compare_documents(baseline, audited)
        self.assertEqual(1, len(compare["sources_in_both"]))
        entry = compare["sources_in_both"][0]
        self.assertEqual(1, entry["baseline_count"])
        self.assertEqual(1, entry["audited_count"])
        self.assertNotEqual(entry["baseline_addresses"], entry["audited_addresses"])

    def test_a_missing_identity_link_forbids_claiming_an_allocation_was_removed(self):
        baseline = self._document(sha="1" * 64, stage=audit.STAGE_BUILD_STACK)
        audited = self._document(sha="2" * 64, stage=audit.STAGE_BUILD_GATE2)
        audited["candidates"] = [
            item for item in audited["candidates"] if item["function"] != "unique"
        ]
        compare = audit.compare_documents(baseline, audited)
        self.assertEqual(1, compare["summary"]["only_in_baseline"])
        self.assertFalse(compare["linkage"]["per_allocation_identity"])
        report = audit.render_compare_report(compare)
        self.assertIn("不能据此宣称某一处分配被精确消除", report)
        self.assertIn("不按地址配对", report)
        self.assertNotIn("精确消除", json.dumps(compare["summary"], ensure_ascii=False))

    def test_the_same_elf_on_both_sides_is_flagged(self):
        document = self._document(sha="3" * 64, stage=audit.STAGE_BUILD_GATE2)
        compare = audit.compare_documents(document, document)
        self.assertTrue(compare["linkage"]["same_elf_content"])

    def test_excluded_items_are_compared_separately(self):
        baseline = self._document(sha="1" * 64, stage=audit.STAGE_BUILD_STACK)
        audited = self._document(sha="2" * 64, stage=audit.STAGE_BUILD_GATE2)
        baseline["candidates"][0]["excluded_by_assumption"] = True
        audited["candidates"][0]["excluded_by_assumption"] = True
        compare = audit.compare_documents(baseline, audited)
        self.assertEqual(0, compare["summary"]["in_both"])
        self.assertEqual(1, len(compare["excluded_items"]))
        self.assertEqual(1, compare["excluded_items"][0]["baseline_items"])
        self.assertNotIn("eliminated", json.dumps(compare, ensure_ascii=False))


# endregion


# region CLI and process hygiene


def _adapter_for(script: Path):
    """A drop-in ``LinuxObjdump`` that serves a capture from a real process."""

    real = LinuxObjdump("objdump")

    class _Adapter:
        parse_format = real.parse_format

        def __init__(self, command="objdump"):
            self.command_name = command

        @staticmethod
        def is_external_trampoline(name):
            return real.is_external_trampoline(name)

        def command(self, path):
            return [sys.executable, str(script)]

    return _Adapter


class CliTests(unittest.TestCase):
    DUMP = (
        "0000000000010000 <leaf>:\n"
        "    10000:\t8082                \tret\n"
        "\n"
        "0000000000010004 <host>:\n"
        "    10004:\t7131                \taddi\tsp,sp,-16\n"
        "    10006:\tcd817057          \tvsetivli\tzero,4,e64,m4,ta,ma\n"
        "    1000a:\t84b2                \tmv\ts1,sp\n"
        "    1000c:\t0294302b          \tvs4r.v\tv9,(s1)\n"
        "    10010:\t9682                \tjalr\ta3\n"
        "    10012:\t2284b787          \tvl4re64.v\tv10,(s1)\n"
        "    10016:\t6145                \taddi\tsp,sp,16\n"
        "    10018:\t8082                \tret\n"
    )

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.elf = build_elf(self.root / "app.elf")
        self.script = _write(
            self.root / "fake_objdump.py",
            "import sys\nsys.stdout.write(" + repr(self.DUMP) + ")\n",
        )
        self.decision = _write(
            self.root / "decision.json",
            json.dumps({"decision": {"gate": {"names": ["host", "_Z11not_presentv"]}}}),
        )

    def _run(self, argv, script=None):
        adapter = _adapter_for(script or self.script)
        with mock.patch.object(audit, "LinuxObjdump", adapter):
            return audit.main(argv)

    def test_the_audit_command_completes_and_its_outputs_reload(self):
        argv = [
            "audit",
            "--input", str(self.elf),
            "--gate-list", str(self.decision),
            "--stage", audit.STAGE_BUILD_GATE2,
            "--expected-gate-count", "2",
            "--json", str(self.root / "audit.json"),
            "--candidates-csv", str(self.root / "candidates.csv"),
            "--gate-csv", str(self.root / "gates.csv"),
            "--report", str(self.root / "report.md"),
        ]
        self.assertEqual(0, self._run(argv))
        document = json.loads((self.root / "audit.json").read_text(encoding="utf-8"))
        self.assertEqual(audit.AUDIT_FORMAT, document["format"])
        self.assertEqual(
            ["host"], sorted({item["function"] for item in document["candidates"]})
        )
        with (self.root / "candidates.csv").open(
            encoding="utf-8", newline=""
        ) as handle:
            rows = list(csv.DictReader(handle))
        self.assertEqual(len(document["candidates"]), len(rows))
        with (self.root / "gates.csv").open(encoding="utf-8", newline="") as handle:
            gate_rows = list(csv.DictReader(handle))
        self.assertEqual(2, len(gate_rows))
        report = (self.root / "report.md").read_text(encoding="utf-8")
        self.assertIn("独立核对结论", report)
        self.assertIn("问题一", report)
        self.assertIn("问题二", report)

    def test_the_same_name_is_listed_but_the_decision_roles_stay_separate(self):
        """The baseline is audited against a list it never consumed - by design."""

        stack_decision = _write(
            self.root / "stack.decision.json",
            json.dumps(
                {
                    "decision": {
                        "strategy": "gate",
                        "vector_gate": {"enabled": True},
                        "stack_object_plugin": True,
                        "gate": {"enabled": False, "names": []},
                    }
                }
            ),
        )
        argv = [
            "audit",
            "--input", str(self.elf),
            "--gate-list", str(self.decision),
            "--stage", audit.STAGE_BUILD_STACK,
            "--expected-gate-count", "2",
            "--consumed-decision", str(stack_decision),
            "--json", str(self.root / "stack.json"),
        ]
        self.assertEqual(0, self._run(argv))
        document = json.loads((self.root / "stack.json").read_text(encoding="utf-8"))
        self.assertEqual("comparison-target-list", document["gate_list"]["role"])
        self.assertIn("build-stack 只启用 stack-object", document["gate_list"]["role_note"])
        consumed = document["parameters"]["consumed_decision"]
        self.assertEqual(str(stack_decision), consumed["path"])
        self.assertEqual(audit._sha256(stack_decision), consumed["sha256"])
        # The comparison list is still the gate-2 one, and it is a different
        # artifact from the decision this build consumed.
        self.assertNotEqual(
            document["gate_list"]["sha256"], consumed["sha256"]
        )
        self.assertEqual(2, document["gate_list"]["unique_names"])

    def _stack_scenario(self):
        """A census record that belongs to the baseline, not to gate-2."""

        stack_decision = _write(
            self.root / "consumed.decision.json",
            json.dumps(
                {"decision": {"stack_object_plugin": True, "gate": {"enabled": False}}}
            ),
        )
        census = _write(
            self.root / "stack.census.tsv",
            "implicit-vector-census\tLV\thost\tformed\n",
        )
        manifest = _evidence_manifest(
            self.root / "evidence.json",
            census=census,
            consumed_decision_sha=audit._sha256(stack_decision),
            stage=audit.STAGE_BUILD_STACK,
            artifact_sha256=audit._sha256(self.elf),
        )
        return stack_decision, census, manifest

    def test_the_cli_binds_to_the_consumed_decision_not_the_comparison_list(self):
        stack_decision, census, manifest = self._stack_scenario()
        out = self.root / "stack.json"
        argv = [
            "audit",
            "--input", str(self.elf),
            "--gate-list", str(self.decision),
            "--stage", audit.STAGE_BUILD_STACK,
            "--expected-gate-count", "2",
            "--consumed-decision", str(stack_decision),
            "--census", str(census),
            "--evidence", str(manifest),
            "--json", str(out),
        ]
        self.assertEqual(0, self._run(argv))
        document = json.loads(out.read_text(encoding="utf-8"))
        evidence = document["evidence"]
        self.assertEqual(1, evidence["bound_census_count"])
        row = evidence["census_files"][0]
        self.assertTrue(row["bound"])
        self.assertTrue(row["consumed_decision_matches"])
        # The two documents are genuinely different, and the binding used the
        # consumed one - not the list the names were matched against.
        self.assertNotEqual(
            row["consumed_decision_sha256"], evidence["comparison_list_sha256"]
        )
        self.assertEqual(
            audit._sha256(stack_decision), evidence["consumed_decision"]["sha256"]
        )
        self.assertEqual(2, document["gate_list"]["unique_names"])
        # ... and the source verdict is the stage-aware one.
        entry = [
            item
            for item in document["gate_list"]["entries"]
            if item["name"] == "host"
        ][0]
        self.assertEqual(audit.ENTRY_FORMED_BEFORE_GATE, entry["status"])

    def test_the_cli_without_the_consumed_decision_binds_nothing(self):
        _stack_decision, census, manifest = self._stack_scenario()
        out = self.root / "unbound.json"
        argv = [
            "audit",
            "--input", str(self.elf),
            "--gate-list", str(self.decision),
            "--stage", audit.STAGE_BUILD_STACK,
            "--expected-gate-count", "2",
            "--census", str(census),
            "--evidence", str(manifest),
            "--json", str(out),
        ]
        self.assertEqual(0, self._run(argv))
        document = json.loads(out.read_text(encoding="utf-8"))
        self.assertEqual(0, document["evidence"]["bound_census_count"])
        self.assertIn(
            audit.GAP_CONSUMED_DECISION_MISSING,
            {gap["kind"] for gap in document["gaps"]},
        )
        self.assertIsNone(document["parameters"]["consumed_decision"])

    def test_a_missing_input_exits_non_zero(self):
        argv = [
            "audit",
            "--input", str(self.root / "nope.elf"),
            "--gate-list", str(self.decision),
            "--expected-gate-count", "2",
        ]
        self.assertNotEqual(0, self._run(argv))

    def test_a_failing_objdump_exits_non_zero_and_leaves_no_temp_files(self):
        failing = _write(
            self.root / "fail_objdump.py",
            "import sys\n"
            "sys.stderr.write('objdump exploded: ' + 'x' * 5000)\n"
            "sys.exit(3)\n",
        )
        scratch = self.root / "scratch"
        scratch.mkdir()
        argv = [
            "audit",
            "--input", str(self.elf),
            "--gate-list", str(self.decision),
            "--expected-gate-count", "2",
        ]
        with mock.patch.object(tempfile, "tempdir", str(scratch)):
            self.assertNotEqual(0, self._run(argv, failing))
        self.assertEqual([], sorted(path.name for path in scratch.iterdir()))

    def test_the_reported_stderr_prefix_is_bounded(self):
        def fake_run(command, stdout=None, stderr=None, check=False):
            stderr.write(b"y" * 20000)
            stderr.flush()
            return subprocess.CompletedProcess(args=[], returncode=1)

        scratch = self.root / "scratch2"
        scratch.mkdir()
        with mock.patch.object(audit.subprocess, "run", fake_run), mock.patch.object(
            tempfile, "tempdir", str(scratch)
        ):
            with self.assertRaises(RuntimeError) as caught:
                audit.analyze_elf_once(self.elf, objdump_cmd="objdump")
        message = str(caught.exception)
        self.assertLess(len(message), audit.STDERR_PREFIX_BYTES + 200)
        self.assertIn("objdump", message)
        self.assertEqual([], sorted(path.name for path in scratch.iterdir()))

    def test_the_audit_never_touches_the_check_credentials(self):
        source = Path(audit.__file__).read_text(encoding="utf-8")
        self.assertNotIn("check_elf", source)
        self.assertNotIn("latest.json", source)
        self.assertNotIn("chimera.check", source)
        home = self.root / "home"
        home.mkdir()
        argv = [
            "audit",
            "--input", str(self.elf),
            "--gate-list", str(self.decision),
            "--expected-gate-count", "2",
            "--json", str(self.root / "a.json"),
        ]
        with mock.patch("pathlib.Path.home", return_value=home):
            self.assertEqual(0, self._run(argv))
        self.assertEqual([], sorted(path.name for path in home.rglob("*")))

    def test_compare_rejects_a_document_that_is_not_an_audit(self):
        other = _write(self.root / "other.json", json.dumps({"format": "other"}))
        document_path = self.root / "audit.json"
        program = _unique_program()
        stack = _analyze(program)
        audit._write_json(document_path, _audit(program, stack, names=("unique",)))
        with self.assertRaises(SystemExit):
            audit.main(
                [
                    "compare",
                    "--baseline", str(other),
                    "--audited", str(document_path),
                ]
            )

    def test_the_compare_command_writes_both_outputs(self):
        program = _unique_program()
        stack = _analyze(program)
        first = self.root / "first.json"
        second = self.root / "second.json"
        audit._write_json(first, _audit(program, stack, names=("unique",)))
        audit._write_json(second, _audit(program, stack, names=("unique",)))
        self.assertEqual(
            0,
            audit.main(
                [
                    "compare",
                    "--baseline", str(first),
                    "--audited", str(second),
                    "--json", str(self.root / "compare.json"),
                    "--report", str(self.root / "compare.md"),
                ]
            ),
        )
        compare = json.loads((self.root / "compare.json").read_text(encoding="utf-8"))
        self.assertEqual(audit.COMPARE_FORMAT, compare["format"])
        self.assertIn(
            "按符号与来源类型关联",
            (self.root / "compare.md").read_text(encoding="utf-8"),
        )

    def test_both_subcommands_advertise_their_help(self):
        for argv in (["--help"], ["audit", "--help"], ["compare", "--help"]):
            with self.subTest(argv=argv):
                with self.assertRaises(SystemExit) as caught:
                    audit.main(argv)
                self.assertEqual(0, caught.exception.code)


# endregion


# region K3 script contract


class K3ScriptContractTests(unittest.TestCase):
    """The K3 script runs on the target machine; here its contract is text.

    Executing it needs the RISC-V host, both GCC build trees and the release
    venv, so what is pinned instead is the *shape*: which builds it audits,
    which inputs it must verify, and the rule that a completed run never
    doubles as a safety verdict.
    """

    def setUp(self):
        self.text = (
            Path(__file__).resolve().parents[1] / "tools" / "k3-gate-source-audit.sh"
        ).read_text(encoding="utf-8")

    def test_it_audits_both_builds_and_compares_them(self):
        self.assertIn("build-stack/gcc/xgcc", self.text)
        self.assertIn("build-gate2/gcc/xgcc", self.text)
        self.assertIn("STAGE_STACK=build-stack", self.text)
        self.assertIn("STAGE_GATE2=build-gate2", self.text)
        self.assertIn("gate_source_audit compare", self.text)

    def test_it_verifies_its_inputs_and_records_hashes(self):
        for marker in (
            "sha256sum",
            "rev-parse HEAD",
            "objdump --version",
            'test -f "$GATE_DECISION"',
            "test -x /usr/bin/time",
            "sha256sum -c --status",
        ):
            self.assertIn(marker, self.text, marker)

    def test_it_creates_a_fresh_result_directory_under_the_run(self):
        self.assertRegex(self.text, r'mkdir -p "\$RUN/reports"')
        self.assertIn("mktemp -d", self.text)
        self.assertIn("last-gate-source-audit-reports.txt", self.text)

    def test_it_runs_the_two_audits_sequentially(self):
        self.assertNotIn("&\n", self.text)
        self.assertNotIn("wait\n", self.text)
        self.assertLess(
            self.text.index('audit_one "$STAGE_STACK"'),
            self.text.index('audit_one "$STAGE_GATE2"'),
        )

    def test_it_never_rewrites_production_inputs_or_credentials(self):
        for forbidden in (
            "check_elf",
            "latest.json",
            "rm -rf",
            "git checkout",
            "git reset",
            "--force",
        ):
            self.assertNotIn(forbidden, self.text, forbidden)

    def test_the_audit_module_that_runs_must_be_the_reviewed_revision(self):
        """Recording the repo HEAD is not enough when the venv executes the code."""

        for marker in (
            "audit_module_identity.py",
            "audit-module.txt",
            "audit-module.log",
            "installed-modules.tsv",
            "module-identity.txt",
            "all_modules_match_source",
            "all_modules_inside_venv",
            "source-tree-revision.txt",
        ):
            self.assertIn(marker, self.text, marker)
        self.assertNotIn("wheel-source-revision.txt", self.text)
        # The mismatch must stop the run *before* any audit starts.
        self.assertLess(
            self.text.index("module-identity.txt"),
            self.text.index('audit_one "$STAGE_STACK"'),
        )
        # Every input is an argument: the tool reads nothing from the ambient
        # environment, which is what broke the inline version.
        self.assertIn('--out-dir "$OUT"', self.text)
        self.assertIn('--source-root "$CHIMERA"', self.text)
        self.assertIn('--venv "$VENV"', self.text)
        self.assertNotIn("os.environ[", self.text)
        self.assertNotIn("<<'PY'", self.text)

    def test_the_comparison_list_and_the_consumed_decisions_are_kept_apart(self):
        self.assertIn("comparison_list=$GATE_DECISION", self.text)
        self.assertIn("build-stack=${STACK_DECISION", self.text)
        self.assertIn("decisions.txt", self.text)
        self.assertIn("--consumed-decision", self.text)

    def test_the_exit_code_never_means_safe(self):
        self.assertIn("不代表安全检查通过", self.text)
        self.assertIn("does NOT mean the application is", self.text)
        self.assertIn("exit 2", self.text)
        self.assertIn("Read-only is a claim", self.text)

    def test_missing_evidence_is_written_down_as_missing(self):
        self.assertIn("census-inventory.txt", self.text)
        self.assertIn("log-inventory.txt", self.text)
        self.assertIn("evidence-presence.txt", self.text)
        self.assertIn("MISSING", self.text)
        self.assertIn("UNBOUND", self.text)
        self.assertIn("--evidence", self.text)


def _load_identity_tool():
    """Import the identity tool by path so its default table is the real one."""

    path = Path(__file__).resolve().parents[1] / "tools" / "audit_module_identity.py"
    spec = importlib.util.spec_from_file_location("audit_module_identity", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_IDENTITY_TOOL_MODULE = _load_identity_tool()
_DEFAULT_IDENTITY_MODULES = _IDENTITY_TOOL_MODULE.DEFAULT_MODULES


class ModuleIdentityToolTests(unittest.TestCase):
    """Execute the identity tool for real, on a synthetic package.

    A text contract cannot catch the failure this tool exists to prevent, and
    it certainly cannot catch an input that is read from the ambient
    environment instead of being passed in.  So the tool is run as a
    subprocess, with ``OUT``/``VENV`` deliberately absent from the environment,
    against a fake installed package whose copies can be made to diverge from
    the "source tree" one module at a time.
    """

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.repo = Path(__file__).resolve().parents[1]
        self.tool = self.repo / "tools" / "audit_module_identity.py"
        self.assertIsNotNone(audit.__file__)

        # A "venv" whose site-packages holds the installed copy, and a "source
        # tree" that the check compares against.
        self.venv = self.root / "venv"
        self.installed = self.venv / "lib" / "site-packages"
        self.package = self.installed / "fakepkg"
        self.sources = self.root / "src"
        self.package.mkdir(parents=True)
        self.sources.mkdir()
        (self.package / "__init__.py").write_text("", encoding="utf-8")
        self.audit_body = "VALUE = 'audit-a'\n"
        self.analyzer_body = "VALUE = 'analyzer-a'\n"
        for name, body in (
            ("audit_side", self.audit_body),
            ("analyzer_side", self.analyzer_body),
        ):
            (self.package / f"{name}.py").write_text(body, encoding="utf-8")
            (self.sources / f"{name}.py").write_text(body, encoding="utf-8")

    def _run(self, *extra: str, env_overrides: dict | None = None):
        out_dir = self.root / "out"
        environment = {
            key: value
            for key, value in os.environ.items()
            if key not in ("OUT", "VENV", "PYTHONPATH", "PYTHONHOME")
        }
        environment["PYTHONPATH"] = str(self.installed)
        environment.update(env_overrides or {})
        # The condition the review reproduced: neither OUT nor VENV is exported
        # in the parent shell.
        self.assertNotIn("OUT", environment)
        self.assertNotIn("VENV", environment)
        command = [
            sys.executable,
            str(self.tool),
            "--out-dir", str(out_dir),
            "--source-root", str(self.sources),
            "--venv", str(self.venv),
            "--module", "fakepkg.audit_side=audit_side.py",
            "--module", "fakepkg.analyzer_side=analyzer_side.py",
            *extra,
        ]
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            env=environment,
            cwd=str(self.root),
        )
        return completed, out_dir

    def test_it_verifies_every_declared_module_not_just_one(self):
        completed, out_dir = self._run()
        self.assertEqual(0, completed.returncode, completed.stderr)
        transcript = (out_dir / "audit-module.txt").read_text(encoding="utf-8")
        self.assertIn("all_modules_match_source=True", transcript)
        self.assertIn("all_modules_inside_venv=True", transcript)
        rows = [
            line for line in (out_dir / "installed-modules.tsv")
            .read_text(encoding="utf-8")
            .splitlines()
            if line.strip()
        ]
        self.assertEqual(3, len(rows))  # header + two modules
        self.assertIn("fakepkg.analyzer_side", transcript)

    def test_replacing_only_the_analyzer_is_detected(self):
        """The whole point: one stale analysis module must fail the run."""

        (self.package / "analyzer_side.py").write_text(
            "VALUE = 'analyzer-b'\n", encoding="utf-8"
        )
        completed, out_dir = self._run()
        self.assertEqual(1, completed.returncode)
        transcript = (out_dir / "audit-module.txt").read_text(encoding="utf-8")
        self.assertIn("all_modules_match_source=False", transcript)
        self.assertIn("fakepkg.audit_side", transcript)
        verdict = (out_dir / "module-identity.txt").read_text(encoding="utf-8")
        self.assertIn("mismatch: fakepkg.analyzer_side", verdict)
        self.assertIn("build_release_wheel", verdict)

    def test_a_module_imported_from_outside_the_venv_is_detected(self):
        completed, out_dir = self._run(
            "--venv", str(self.root / "somewhere-else")
        )
        self.assertEqual(1, completed.returncode)
        verdict = (out_dir / "module-identity.txt").read_text(encoding="utf-8")
        self.assertIn("outside_venv", verdict)

    def test_a_module_with_no_source_counterpart_is_detected(self):
        (self.sources / "analyzer_side.py").unlink()
        completed, out_dir = self._run()
        self.assertEqual(1, completed.returncode)
        self.assertIn(
            "all_modules_match_source=False",
            (out_dir / "audit-module.txt").read_text(encoding="utf-8"),
        )

    def test_an_unimportable_module_is_reported_with_its_name(self):
        completed, out_dir = self._run(
            "--module", "fakepkg.missing_side=missing_side.py"
        )
        self.assertEqual(1, completed.returncode)
        transcript = (out_dir / "audit-module.txt").read_text(encoding="utf-8")
        self.assertIn("无法导入 fakepkg.missing_side", transcript)

    def test_a_source_path_escaping_the_root_is_a_usage_error(self):
        completed, out_dir = self._run("--module", "fakepkg.audit_side=../escape.py")
        self.assertEqual(2, completed.returncode)
        self.assertIn("越出源码根", completed.stderr)
        self.assertFalse((out_dir / "module-identity.txt").exists())

    def test_a_malformed_module_spec_is_a_usage_error(self):
        completed, _ = self._run("--module", "fakepkg.audit_side")
        self.assertEqual(2, completed.returncode)
        self.assertIn("--module", completed.stderr)

    def test_the_default_module_table_covers_every_deciding_module(self):
        """The defaults include scalar-width analysis and its operand contract."""

        expected = {
            "chimera.preprocess.offline.analysis.safety.stack_liveness.scalar_width",
            "chimera.preprocess.offline.analysis.arch.riscv.scalar_width_facts",
            "chimera.preprocess.offline.analysis.arch.riscv.scalar_width_vectors",
            "chimera.preprocess.offline.analysis.arch.riscv.stack_semantics",
            "chimera.preprocess.offline.analysis.core.contracts.services",
            "chimera.gate_source_audit",
            "chimera.preprocess.offline.analysis.safety.stack_liveness.analyzer",
            "chimera.preprocess.offline.analysis.safety.stack_liveness.frame_liveness",
            "chimera.preprocess.offline.analysis.safety.stack_liveness.liveness",
            "chimera.preprocess.offline.analysis.safety.stack_liveness.origins",
            "chimera.preprocess.offline.analysis.arch.riscv.control_flow",
            "chimera.preprocess.offline.analysis.program_model.parser",
        }
        declared = {name for name, _relative in _DEFAULT_IDENTITY_MODULES}
        self.assertEqual(expected, declared)
        for _name, relative in _DEFAULT_IDENTITY_MODULES:
            self.assertTrue(
                (self.repo / relative).is_file(), f"源码路径不存在：{relative}"
            )

    def test_the_k3_script_uses_the_tool_without_any_ambient_variables(self):
        text = (self.repo / "tools" / "k3-gate-source-audit.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn('"$PY" -I "$IDENTITY_TOOL"', text)
        self.assertNotIn("os.environ", text)
        self.assertIn('IDENTITY_TOOL="$CHIMERA/tools/audit_module_identity.py"', text)


# endregion


if __name__ == "__main__":
    unittest.main()
