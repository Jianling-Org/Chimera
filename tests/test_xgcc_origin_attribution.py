"""Origin attribution and on-demand size proofs on the real gate-2 disassembly.

Two things are pinned here, both against evidence rather than against prose:

* **attribution.**  ``driver::set_up_specs`` (0x17cec) and
  ``destringize_and_run`` (0x6ac3a) hold a *local* VLEN stack frame whose size
  is not proven.  They used to be reported as caller-inherited, which asked for
  an inheritance witness that does not exist; classification now reads
  structured origin records, so a local frame stays local whatever the
  human-readable sentence says.
* **proofs.**  An unproven adjustment is only discharged when the size's
  origin is established: a proven frame slot, a parameter range a callee
  provably overwrites, a static object.  Memory that may alias, a write that
  does not cover the range, a VLEN-derived value, an external or missing
  callee, a value selected by a branch that is not proven independent, and a
  budget that runs out all keep the mark.
"""

from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

import xgcc_stack_fixture as fixture

from chimera.check_elf import (
    ACTION_TRACE_SIZE_SOURCE,
    CAUSE_LOCAL,
    ORIGIN_STATUS_UNPROVEN,
    collect_diagnostics,
    export_inheritance_diagnostics,
)
from chimera.preprocess.offline.analysis.arch.riscv.rvv.services import (
    RiscvStackSemantics,
)
from chimera.preprocess.offline.analysis.core.data_model import (
    Function,
    Instruction,
    Program,
)
from chimera.preprocess.offline.analysis.safety.stack_liveness import (
    ChimeraMetadata,
)
from chimera.preprocess.offline.analysis.safety.stack_liveness.frame_liveness import (
    VLEN_STACK_FRAME,
    analyze_vlen_stack_liveness,
)
from chimera.preprocess.offline.analysis.safety.stack_liveness.model import (
    ACTIVE_EXTERNAL_CALL,
    UNRESOLVED_ACTIVE_CALL,
    ActiveOrigin,
    CallTargetEntry,
    AnalysisWarning,
    ORIGIN_INHERITED,
    ORIGIN_LOCAL_FRAME,
)
from chimera.preprocess.offline.analysis.safety.stack_liveness.origins import (
    G_ALIAS,
    G_BUDGET,
    G_CONTROL,
    G_ENTRY,
    G_NO_BODY,
    G_NO_WRITER,
    G_PARTIAL,
    G_RECURSION,
    OriginProver,
    PROVEN,
    R_CALLEE_VLEN,
    R_VECTOR_STORE,
    UNPROVEN,
    VLEN,
)
from chimera.preprocess.offline.analysis.safety.stack_liveness.solver import (
    _FunctionExpressionAnalyzer,
)

SEMANTICS = RiscvStackSemantics()


def build(specs, *, start: int = 0x1000, edges=None) -> Function:
    """A synthetic function from ``(mnemonic, operands)`` specs."""

    instructions = [
        Instruction(
            start + index * 4, 4, op, list(args), f"{op} " + ",".join(args)
        )
        for index, (op, args) in enumerate(specs)
    ]
    for instruction in instructions:
        if instruction.op in {"jal", "j"} and len(instruction.args) >= 2:
            target = instruction.args[-1]
            if target.startswith("0x"):
                instruction.jump_targets.add(int(target, 16))
    if edges is None:
        for current, following in zip(instructions, instructions[1:]):
            current.succ.add(following.addr)
    else:
        by_address = {item.addr: item for item in instructions}
        for source, destination in edges:
            by_address[source].succ.add(destination)
    return Function("probe", start, instructions)


def program(*functions) -> Program:
    instructions = [item for function in functions for item in function.insts]
    return Program(
        dump_lines=[],
        functions=list(functions),
        instructions=instructions,
        instruction_by_address={item.addr: item for item in instructions},
    )


def proof_chain(prover, node):
    """Every proof node the verdict rests on, however deep."""

    seen: set[str] = set()
    pending = [node]
    nodes = []
    while pending:
        item = pending.pop()
        if item.id in seen:
            continue
        seen.add(item.id)
        nodes.append(item)
        pending.extend(
            prover._proofs[proof_id]
            for proof_id in item.depends_on
            if proof_id in prover._proofs
        )
    return nodes


class ProofCase:
    """One prover query plus the verdict it must produce."""

    def __init__(self, label, functions, adjustment, status, reason=None):
        self.label = label
        self.functions = functions
        self.adjustment = adjustment
        self.status = status
        self.reason = reason

    def run(self, prover):
        owner = next(
            function
            for function in self.functions
            if self.adjustment in function.instruction_by_address
        )
        result = prover.prove_adjustment(owner, self.adjustment)
        node = prover._proofs[result.proof_id]
        return result, node


class RealAttributionTests(unittest.TestCase):
    """The two confirmed misclassifications, on the real disassembly."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.temporary = tempfile.TemporaryDirectory()
        stub = Path(cls.temporary.name) / "stub.elf"
        stub.write_bytes(b"\x7fELF\x02\x01\x01" + b"\x00" * 24)
        cls.stub = stub
        cls.result = collect_diagnostics(
            stub,
            objdump_cmd="objdump",
            strategy="gate",
            dump_text=fixture.FOLLOWUP_FUNCTIONS_DUMP,
            metadata=ChimeraMetadata.empty(),
        )
        cls.report_path = Path(cls.temporary.name) / "inheritance.json"
        export_inheritance_diagnostics(cls.result, cls.report_path, content_hash="0" * 64)
        cls.document = json.loads(cls.report_path.read_text(encoding="utf-8"))

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temporary.cleanup()

    def _finding(self, address: int):
        site = hex(address)
        for item in self.result.findings:
            if item.call_site == site:
                return item
        self.fail(f"no finding at {site}")

    def test_local_frame_at_set_up_specs_is_not_reported_as_inherited(self) -> None:
        finding = self._finding(fixture.SET_UP_SPECS_CALL)
        self.assertEqual(finding.function, fixture.SET_UP_SPECS)
        self.assertEqual(finding.kind, CAUSE_LOCAL)
        self.assertEqual(finding.origin_status, ORIGIN_STATUS_UNPROVEN)
        # The recommendation is to establish the size's origin - strlen has no
        # body and no contract here, so nothing about it is proven.
        self.assertEqual(finding.recommended_action, ACTION_TRACE_SIZE_SOURCE)
        origin = finding.origins[0]
        self.assertEqual(origin.origin, ORIGIN_LOCAL_FRAME)
        self.assertEqual(origin.allocation, fixture.SET_UP_SPECS_ALLOCATION)
        self.assertEqual(origin.dependency, "unknown")
        self.assertTrue(origin.gaps)

    def test_local_frame_at_destringize_and_run_is_local_too(self) -> None:
        finding = self._finding(fixture.DESTRINGIZE_CALL)
        self.assertEqual(finding.function, fixture.DESTRINGIZE_AND_RUN)
        self.assertEqual(finding.kind, CAUSE_LOCAL)
        self.assertEqual(finding.origin_status, ORIGIN_STATUS_UNPROVEN)
        self.assertEqual(finding.recommended_action, ACTION_TRACE_SIZE_SOURCE)
        origin = finding.origins[0]
        self.assertEqual(origin.allocation, fixture.DESTRINGIZE_ALLOCATION)
        # The size is loaded from the caller's ``cpp_string`` object: the value
        # has no writer anywhere in this binary.
        self.assertIn(G_NO_WRITER, origin.gaps)

    def test_local_findings_do_not_ask_for_an_inheritance_witness(self) -> None:
        for address in (fixture.SET_UP_SPECS_CALL, fixture.DESTRINGIZE_CALL):
            with self.subTest(address=hex(address)):
                entry = next(
                    item
                    for item in self.document["findings"]
                    if item["call_site"] == hex(address)
                )
                # No inheritance chain exists for a local source, and that is
                # not a diagnostic gap.
                self.assertFalse(entry["diagnostics_incomplete"])
                self.assertIn("not applicable", entry["witness_note"])
                self.assertTrue(entry["activity_origins"])
                self.assertEqual(entry["origin_status"], ORIGIN_STATUS_UNPROVEN)

    def test_unproven_size_stays_pending_without_a_real_local_cache_source(self) -> None:
        # "Not proven" is not a reason to de-vectorize a function: the size may
        # well be an ordinary scalar.  The hosts are named as pending proofs.
        # Selection and inferred return values do not establish a real local
        # cache in this fixture. They cannot turn UNKNOWN into a gate source.
        self.assertEqual(self.result.gate_names, ())
        self.assertEqual(
            set(self.result.pending_proof_starts),
            # v24 adds known external boundaries in close_at_file and the
            # demangler. Their unknown frames are also pending, never gates.
            {0x16E88, 0x6A9C8, 0x21C5E, 0x96C86},
        )
        self.assertEqual(self.result.counts["pending_proof"], 4)
        # All remaining findings in this partial Program are actual active
        # boundaries with UNKNOWN frame sizes, not width-value effects.
        self.assertEqual(self.result.counts["local_root"], 104)
        self.assertEqual(self.result.counts["local_vlen_source"], 0)
        self.assertEqual(self.result.counts["local_unproven"], 104)
        self.assertEqual(self.result.counts["active_external_calls"], 102)
        self.assertEqual(sum(item.diagnostic_code == UNRESOLVED_ACTIVE_CALL
                             for item in self.result.findings), 2)
        self.assertTrue(all(
            item.origin_status == ORIGIN_STATUS_UNPROVEN
            and item.recommended_action == ACTION_TRACE_SIZE_SOURCE
            and item.diagnostic_code in {ACTIVE_EXTERNAL_CALL, UNRESOLVED_ACTIVE_CALL}
            for item in self.result.findings
            if item.origin_status == ORIGIN_STATUS_UNPROVEN
        ))
        known = [item for item in self.result.findings
                 if any(origin.origin == "local-vlen-scalar" for origin in item.origins)]
        self.assertFalse(known)
        pending = {entry["name"] for entry in self.document["pending_proof_refs"]}
        self.assertEqual(
            pending, {fixture.SET_UP_SPECS, fixture.DESTRINGIZE_AND_RUN,
                      fixture.CLOSE_AT_FILE, fixture.DEMANGLE_PRINT_CALLBACK}
        )

    def test_demangle_report_names_both_allocations_and_the_gap(self) -> None:
        # The finding at 0x96d6a is inherited (its frame is already released),
        # but the two allocations of this function are still reported, with the
        # load range and the missing callee body.
        entry = next(
            item
            for item in self.document["functions"]
            if item["name"] == fixture.DEMANGLE_PRINT_CALLBACK
        )
        adjustments = {item["adjustment"] for item in entry["frame_origins"]}
        self.assertTrue(
            {hex(address) for address in fixture.DEMANGLE_ALLOCATIONS} <= adjustments
        )
        gaps = {
            gap
            for item in entry["frame_origins"]
            for gap in item["gaps"]
        }
        self.assertTrue(gaps)
        table = self.document["proof_table"]
        by_address = {
            node["address"]: node
            for node in table
            if node["function_start"] == hex(0x96C86)
        }
        self.assertTrue(
            any(
                node["reason"] in (G_NO_BODY, G_ALIAS, G_NO_WRITER)
                or "0x996fe" in node["detail"]
                for node in by_address.values()
            ),
            "the missing d_count_templates_scopes body must be named",
        )

    def test_followup_findings_are_all_local(self) -> None:
        # Every finding of this extract has a local origin: correcting the
        # attribution must not blur the two classes in the other direction
        # either (the genuinely inherited case is covered by the gate-2
        # fixture, where a real callback chain exists).
        self.assertTrue(self.result.findings)
        self.assertEqual(
            {item.kind for item in self.result.findings}, {CAUSE_LOCAL}
        )
        self.assertEqual(self.result.counts["inherited"], 0)
        for entry in self.document["findings"]:
            with self.subTest(call_site=entry["call_site"]):
                self.assertEqual(entry["kind"], CAUSE_LOCAL)
                self.assertFalse(entry["diagnostics_incomplete"])

    def test_fixture_agrees_with_the_gate2_extract(self) -> None:
        # Same ELF, same function: the duplicated body is byte-identical, which
        # is what makes the two extracts one evidence set.
        gate2 = fixture.load_program()
        gate2_body = [item.text for item in fixture.function(gate2, fixture.CLOSE_AT_FILE).insts]
        follow = fixture.load_followup_program()
        follow_body = [
            item.text
            for item in fixture.function(follow, fixture.CLOSE_AT_FILE).insts
        ]
        self.assertEqual(gate2_body, follow_body)

    def test_followup_functions_keep_addresses_and_boundaries(self) -> None:
        program = fixture.load_followup_program()
        sizes = {function.name: len(function.insts) for function in program.functions}
        self.assertEqual(sizes[fixture.DEMANGLE_PRINT_CALLBACK], 101)
        self.assertEqual(sizes[fixture.SET_UP_SPECS], 1162)
        self.assertEqual(sizes[fixture.DESTRINGIZE_AND_RUN], 227)
        self.assertEqual(
            fixture.function(program, fixture.SET_UP_SPECS).start, 0x16E88
        )

    def test_followup_fixture_carries_no_build_paths(self) -> None:
        self.assertNotIn("/root/yangzheng", fixture.FOLLOWUP_FUNCTIONS_DUMP)
        self.assertNotIn("文件格式", fixture.FOLLOWUP_FUNCTIONS_DUMP)


class StructuredClassificationTests(unittest.TestCase):
    """Classification reads records, never prose."""

    def setUp(self) -> None:
        class _Harness:
            def __init__(self, origins):
                self.origins = origins

        self.document = None
        self._harness = _Harness

    def test_prose_wording_cannot_change_the_attribution(self) -> None:
        from chimera.check_elf import _attribute
        from chimera.preprocess.offline.analysis.safety.stack_liveness.model import (
            ORIGIN_CONSERVATIVE,
        )

        # The record says "local VLEN frame"; the sentence *lies* and claims
        # inheritance.  The attribution must follow the record.
        local = _attribute(
            (
                ActiveOrigin(
                    origin=ORIGIN_LOCAL_FRAME,
                    object_source="vlen_stack_frame",
                    object_id="vlen_stack_frame:dynamic-sp",
                    detail="live caller-inherited stack data: earlier active call",
                    dependency="unknown",
                ),
            )
        )
        self.assertEqual(local.primary, CAUSE_LOCAL)
        self.assertTrue(local.is_root)
        self.assertEqual(local.origin_status, ORIGIN_STATUS_UNPROVEN)

        inherited = _attribute(
            (
                ActiveOrigin(
                    origin=ORIGIN_INHERITED,
                    object_source="caller",
                    object_id="caller:inherited-stack-data",
                    detail="live VLEN-dependent stack frame: local frame",
                ),
            )
        )
        self.assertEqual(inherited.primary, "inherited")
        self.assertFalse(inherited.is_root)

        # Local and inherited together: the local reason leads, both survive.
        mixed = _attribute(
            (
                ActiveOrigin(
                    origin=ORIGIN_LOCAL_FRAME,
                    object_source="vlen_stack_frame",
                    object_id="vlen_stack_frame:dynamic-sp",
                    detail="live VLEN-dependent stack frame",
                    dependency="unknown",
                ),
                ActiveOrigin(
                    origin=ORIGIN_INHERITED,
                    object_source="caller",
                    object_id="caller:inherited-stack-data",
                    detail="live caller-inherited stack data",
                ),
            )
        )
        self.assertEqual(mixed.primary, CAUSE_LOCAL)
        self.assertTrue(mixed.has_inherited)
        self.assertEqual(mixed.origin_status, ORIGIN_STATUS_UNPROVEN)

        conservative = _attribute(
            (
                ActiveOrigin(
                    origin=ORIGIN_CONSERVATIVE,
                    object_source="conservative",
                    object_id="conservative:possible-stack-data",
                    detail="live conservative marker",
                ),
            )
        )
        self.assertEqual(conservative.primary, "conservative")
        self.assertTrue(conservative.is_root)


class OriginProofTests(unittest.TestCase):
    """The size-origin prover: what it proves, and what it refuses to."""

    def _verdict(self, case: ProofCase):
        prover = OriginProver(program(*case.functions), SEMANTICS)
        result, node = case.run(prover)
        return prover, result, node

    def test_constant_written_to_a_frame_slot_is_proven(self) -> None:
        case = ProofCase(
            "constant slot",
            [
                build(
                    [
                        ("addi", ["sp", "sp", "-64"]),
                        ("li", ["a1", "32"]),
                        ("sd", ["a1", "16(sp)"]),
                        ("ld", ["a2", "16(sp)"]),
                        ("sub", ["sp", "sp", "a2"]),
                        ("ret", []),
                    ]
                )
            ],
            0x1010,
            PROVEN,
        )
        _, result, node = self._verdict(case)
        self.assertEqual(result.status, PROVEN)
        self.assertIn("frame-slot", node.reason)

    def test_vlenb_stored_to_memory_stays_a_vlen_source(self) -> None:
        case = ProofCase(
            "vlenb in memory",
            [
                build(
                    [
                        ("csrr", ["a0", "vlenb"]),
                        ("addi", ["sp", "sp", "-64"]),
                        ("sd", ["a0", "16(sp)"]),
                        ("ld", ["a2", "16(sp)"]),
                        ("sub", ["sp", "sp", "a2"]),
                        ("ret", []),
                    ]
                )
            ],
            0x1010,
            VLEN,
        )
        _, result, _ = self._verdict(case)
        self.assertEqual(result.status, VLEN)

    def test_partial_overwrite_is_not_a_proof(self) -> None:
        case = ProofCase(
            "partial write",
            [
                build(
                    [
                        ("li", ["a1", "32"]),
                        ("addi", ["sp", "sp", "-64"]),
                        ("sd", ["a1", "16(sp)"]),
                        ("li", ["a3", "7"]),
                        ("sw", ["a3", "20(sp)"]),
                        ("ld", ["a2", "16(sp)"]),
                        ("sub", ["sp", "sp", "a2"]),
                        ("ret", []),
                    ]
                )
            ],
            0x1018,
            UNPROVEN,
            G_PARTIAL,
        )
        _, result, node = self._verdict(case)
        self.assertEqual(result.status, UNPROVEN)
        self.assertIn(G_PARTIAL, {node.reason} | set(node.detail.split()))

    def test_one_sided_write_leaves_the_other_path_unproven(self) -> None:
        case = ProofCase(
            "one-sided write",
            [
                build(
                    [
                        ("addi", ["sp", "sp", "-64"]),
                        ("beqz", ["a7", "0x1010"]),
                        ("li", ["a1", "32"]),
                        ("sd", ["a1", "16(sp)"]),
                        ("ld", ["a2", "16(sp)"]),
                        ("sub", ["sp", "sp", "a2"]),
                        ("ret", []),
                    ],
                    edges=[
                        (0x1000, 0x1004),
                        (0x1004, 0x1008),
                        (0x1004, 0x1010),
                        (0x1008, 0x100C),
                        (0x100C, 0x1010),
                        (0x1010, 0x1014),
                        (0x1014, 0x1018),
                    ],
                )
            ],
            0x1014,
            UNPROVEN,
        )
        _, result, _ = self._verdict(case)
        self.assertEqual(result.status, UNPROVEN)

    def test_unknown_alias_write_invalidates_the_range(self) -> None:
        case = ProofCase(
            "aliasing store",
            [
                build(
                    [
                        ("li", ["a1", "32"]),
                        ("add", ["a3", "a4", "a5"]),
                        ("sd", ["a1", "0(a3)"]),
                        ("addi", ["sp", "sp", "-64"]),
                        ("ld", ["a2", "16(sp)"]),
                        ("sub", ["sp", "sp", "a2"]),
                        ("ret", []),
                    ]
                )
            ],
            0x1014,
            UNPROVEN,
            G_ALIAS,
        )
        _, result, _ = self._verdict(case)
        self.assertEqual(result.status, UNPROVEN)

    def test_control_dependent_constant_is_not_a_proof(self) -> None:
        case = ProofCase(
            "control dependent",
            [
                build(
                    [
                        ("beqz", ["a7", "0x100C"]),
                        ("addi", ["sp", "sp", "-64"]),
                        ("li", ["a2", "32"]),
                        ("sub", ["sp", "sp", "a2"]),
                        ("ret", []),
                    ],
                    edges=[
                        (0x1000, 0x1004),
                        (0x1000, 0x100C),
                        (0x1004, 0x1008),
                        (0x1008, 0x100C),
                        (0x100C, 0x1010),
                    ],
                )
            ],
            0x100C,
            UNPROVEN,
            G_CONTROL,
        )
        _, result, _ = self._verdict(case)
        self.assertEqual(result.status, UNPROVEN)

    def test_external_and_missing_callees_stay_unproven(self) -> None:
        for target, expected in (
            ("0x9000", G_NO_BODY),
            ("0x14030", G_NO_BODY),
        ):
            with self.subTest(target=target):
                case = ProofCase(
                    "external call",
                    [
                        build(
                            [
                                ("addi", ["sp", "sp", "-64"]),
                                ("jal", ["ra", target]),
                                ("sub", ["sp", "sp", "a0"]),
                                ("ret", []),
                            ]
                        )
                    ],
                    0x1008,
                    UNPROVEN,
                    expected,
                )
                prover, result, node = self._verdict(case)
                self.assertEqual(result.status, UNPROVEN)
                self.assertIn(node.reason, {G_NO_BODY, "external-callee"})

    def test_no_name_based_exemption(self) -> None:
        # A callee called ``strlen`` with no body in the analysis is exactly as
        # unproven as any other missing body.
        function = build(
            [
                ("addi", ["sp", "sp", "-64"]),
                ("jal", ["ra", "0x14030"]),
                ("addi", ["a0", "a0", "102"]),
                ("sub", ["sp", "sp", "a0"]),
                ("ret", []),
            ]
        )
        prover = OriginProver(program(function), SEMANTICS)
        result = prover.prove_adjustment(function, 0x100C)
        self.assertNotEqual(result.status, PROVEN)
        node = prover._proofs[result.proof_id]
        self.assertNotIn("strlen", node.detail)

    def test_callee_writes_are_summarised_per_call_site(self) -> None:
        callee = build([("sd", ["a1", "8(a0)"]), ("ret", [])], start=0x2000)

        def caller(value: str, extra):
            return build(
                [
                    ("addi", ["sp", "sp", "-64"]),
                    *( [("csrr", ["a1", "vlenb"])] if value == "vlen" else [("li", ["a1", "32"])] ),
                    ("addi", ["a0", "sp", "16"]),
                    ("jal", ["ra", "0x2000"]),
                    ("ld", ["a2", "24(sp)"]),
                    ("sub", ["sp", "sp", "a2"]),
                    ("ret", []),
                ]
            )

        independent = self._verdict(
            ProofCase("callee ok", [caller("const", None), callee], 0x1014, PROVEN)
        )[1]
        self.assertEqual(independent.status, PROVEN)

        vlen = self._verdict(
            ProofCase("callee vlen", [caller("vlen", None), callee], 0x1014, VLEN)
        )[1]
        self.assertEqual(vlen.status, VLEN)

    def test_summary_chain_of_direct_calls_is_proven(self) -> None:
        callee = build([("li", ["a0", "32"]), ("ret", [])], start=0x3000)
        caller = build(
            [
                ("addi", ["sp", "sp", "-64"]),
                ("jal", ["ra", "0x3000"]),
                ("mv", ["a2", "a0"]),
                ("sub", ["sp", "sp", "a2"]),
                ("ret", []),
            ]
        )
        _, result, _ = self._verdict(
            ProofCase("chain", [caller, callee], 0x100C, PROVEN)
        )
        self.assertEqual(result.status, PROVEN)

    def test_recursion_never_proves_its_own_result(self) -> None:
        recursive = build(
            [
                ("addi", ["sp", "sp", "-64"]),
                ("jal", ["ra", "0x1000"]),
                ("sub", ["sp", "sp", "a0"]),
                ("ret", []),
            ]
        )
        _, result, node = self._verdict(
            ProofCase("recursion", [recursive], 0x1008, UNPROVEN, G_RECURSION)
        )
        self.assertEqual(result.status, UNPROVEN)
        self.assertIn(G_RECURSION, node.detail + node.reason)

    def test_budget_exhaustion_is_reported_and_never_a_proof(self) -> None:
        callee = build([("li", ["a0", "32"]), ("ret", [])], start=0x3000)
        caller = build(
            [
                ("addi", ["sp", "sp", "-64"]),
                ("jal", ["ra", "0x3000"]),
                ("mv", ["a2", "a0"]),
                ("sub", ["sp", "sp", "a2"]),
                ("ret", []),
            ]
        )
        prover = OriginProver(program(caller, callee), SEMANTICS, node_budget=1)
        result = prover.prove_adjustment(caller, 0x100C)
        self.assertNotEqual(result.status, PROVEN)
        self.assertEqual(prover._proofs[result.proof_id].reason, G_BUDGET)
        self.assertTrue(prover.budget_exhausted)

    def test_proof_releases_only_the_frame_marker(self) -> None:
        # A function with a vector stack access *and* a provable adjustment:
        # the proof clears the frame mark and nothing else.
        function = build(
            [
                ("addi", ["sp", "sp", "-64"]),
                ("li", ["a1", "32"]),
                ("sd", ["a1", "16(sp)"]),
                ("ld", ["a2", "16(sp)"]),
                ("sub", ["sp", "sp", "a2"]),
                ("ret", []),
            ]
        )
        program_ = program(function)
        expressions = _FunctionExpressionAnalyzer(
            SEMANTICS, emit_warnings=False
        ).analyze(function, frozenset())
        plain, _ = analyze_vlen_stack_liveness(function, expressions, SEMANTICS)
        proven, _ = analyze_vlen_stack_liveness(
            function,
            expressions,
            SEMANTICS,
            prover=OriginProver(program_, SEMANTICS),
        )
        addresses = [item.addr for item in function.insts]
        marked_plain = [
            address
            for address in addresses
            if VLEN_STACK_FRAME in plain.get(address, frozenset())
        ]
        marked_proven = [
            address
            for address in addresses
            if VLEN_STACK_FRAME in proven.get(address, frozenset())
        ]
        self.assertEqual(marked_proven, [])
        del marked_plain

    def test_vector_stack_store_is_reported_as_a_vlen_source(self) -> None:
        function = build(
            [
                ("addi", ["sp", "sp", "-64"]),
                ("vsetivli", ["zero", "16", "e8", "m1"]),
                ("vse8.v", ["v8", "16(sp)"]),
                ("lbu", ["a2", "16(sp)"]),
                ("sub", ["sp", "sp", "a2"]),
                ("ret", []),
            ]
        )
        prover = OriginProver(program(function), SEMANTICS)
        result = prover.prove_adjustment(function, 0x1010)
        self.assertEqual(result.status, VLEN)
        self.assertEqual(prover._proofs[result.proof_id].reason, R_VECTOR_STORE)


class EveryPathCoverageTests(unittest.TestCase):
    """A proof has to hold on *every* path, not only on the one that was walked.

    Five shapes used to come back ``proven`` although nothing established the
    size: a register definition that covers one incoming path while the other
    keeps the caller's value, a callee result selected by a branch, a callee
    write that only happens on one branch, the *call itself* happening on one
    branch only (so its proven constant return covers that branch alone), and
    the *load* selected by a branch - each slot provable on its own while the
    choice between them tracks vlenb.  All of these are *silent* - the analysis
    simply discharges the frame marker - so each one is pinned here next to the
    positive control that must keep passing, which is what stops the correction
    from degenerating into refusing everything.
    """

    def _verdict(self, functions, adjustment, *, node_budget=None):
        prover = OriginProver(
            program(*functions),
            SEMANTICS,
            **({} if node_budget is None else {"node_budget": node_budget}),
        )
        owner = next(
            function
            for function in functions
            if adjustment in function.instruction_by_address
        )
        result = prover.prove_adjustment(owner, adjustment)
        return prover, result, prover._proofs[result.proof_id]

    _chain = staticmethod(proof_chain)

    # --- 1. the register walk must report the path with no definition --------

    @staticmethod
    def _one_sided_definition(filler=()):
        """``a0`` defined on the branch, the entry value kept on the fall-through.

        Returns the function and the address of the adjustment.  ``filler``
        sits on the branch that defines ``a0``, so a shape whose other path runs
        through a prologue is covered too.
        """

        specs = [
            ("andi", ["a1", "sp", "32"]),
            ("beqz", ["a1", "0x100C"]),
            ("li", ["a0", "16"]),
            *filler,
        ]
        merge = 0x1000 + len(specs) * 4
        specs[1] = ("beqz", ["a1", hex(merge)])
        specs += [("sub", ["sp", "sp", "a0"]), ("ret", [])]
        function = build(specs)
        # The branch skips the definition and rejoins at the adjustment.
        function.instruction_by_address[0x1004].succ.add(merge)
        return function, merge

    def test_path_that_keeps_the_entry_parameter_is_not_proven(self) -> None:
        for filler, label in (
            ((), "bare"),
            ((("nop", []),), "nop"),
            ((("addi", ["sp", "sp", "-16"]),), "prologue"),
            ((("mv", ["t0", "a0"]),), "unrelated move"),
        ):
            with self.subTest(prefix=label):
                function, merge = self._one_sided_definition(filler)
                _, result, node = self._verdict([function], merge)
                # The caller's value may survive to the adjustment, and the
                # caller may have derived it from vlenb.
                self.assertEqual(result.status, UNPROVEN)
                self.assertEqual(node.reason, G_ENTRY)

    def test_prologue_before_the_branch_is_not_a_definition(self) -> None:
        # A normal prologue, then the branch: the path that keeps the entry
        # value runs through the prologue, so "some earlier instruction was
        # analysed" must not be mistaken for "the value was defined here".
        function = build(
            [
                ("addi", ["sp", "sp", "-16"]),
                ("andi", ["a1", "sp", "32"]),
                ("beqz", ["a1", "0x1010"]),
                ("li", ["a0", "16"]),
                ("sub", ["sp", "sp", "a0"]),
                ("ret", []),
            ],
            edges=[
                (0x1000, 0x1004),
                (0x1004, 0x1008),
                (0x1008, 0x100C),
                (0x1008, 0x1010),
                (0x100C, 0x1010),
                (0x1010, 0x1014),
            ],
        )
        _, result, node = self._verdict([function], 0x1010)
        self.assertEqual(result.status, UNPROVEN)
        self.assertEqual(node.reason, G_ENTRY)

    def test_definitions_on_both_paths_are_still_proven(self) -> None:
        function = build(
            [
                ("andi", ["a1", "sp", "32"]),
                ("beqz", ["a1", "0x1010"]),
                ("li", ["a0", "16"]),
                ("j", ["0x1014"]),
                ("li", ["a0", "32"]),
                ("sub", ["sp", "sp", "a0"]),
                ("ret", []),
            ],
            edges=[
                (0x1000, 0x1004),
                (0x1004, 0x1008),
                (0x1004, 0x1010),
                (0x1008, 0x100C),
                (0x100C, 0x1014),
                (0x1010, 0x1014),
                (0x1014, 0x1018),
            ],
        )
        _, result, _ = self._verdict([function], 0x1014)
        self.assertEqual(result.status, PROVEN)

    def test_truncated_register_walk_is_not_a_proof(self) -> None:
        function, merge = self._one_sided_definition()
        prover, result, node = self._verdict([function], merge, node_budget=1)
        self.assertEqual(result.status, UNPROVEN)
        self.assertEqual(node.reason, G_BUDGET)
        self.assertTrue(prover.budget_exhausted)

    # --- 2. a callee result selected by a branch keeps that dependence -------

    def test_callee_return_selected_by_a_vlenb_branch_stays_vlen(self) -> None:
        callee = build(
            [
                ("csrr", ["a1", "vlenb"]),
                ("li", ["a0", "32"]),
                ("li", ["t0", "32"]),
                ("beq", ["a1", "t0", "0x3014"]),
                ("li", ["a0", "16"]),
                ("ret", []),
            ],
            start=0x3000,
            edges=[
                (0x3000, 0x3004),
                (0x3004, 0x3008),
                (0x3008, 0x300C),
                (0x300C, 0x3010),
                (0x300C, 0x3014),
                (0x3010, 0x3014),
            ],
        )
        caller = build(
            [
                ("addi", ["sp", "sp", "-64"]),
                ("jal", ["ra", "0x3000"]),
                ("mv", ["a2", "a0"]),
                ("sub", ["sp", "sp", "a2"]),
                ("ret", []),
            ]
        )
        prover, result, node = self._verdict([caller, callee], 0x100C)
        # Both returned constants are independent on their own; it is the
        # *selection* that depends on vlenb, and a size that switches with VLEN
        # is exactly the case this analysis exists for.
        self.assertEqual(result.status, VLEN)
        self.assertIn(
            R_CALLEE_VLEN,
            {item.reason for item in self._chain(prover, node)},
        )

    def test_guarded_call_return_is_not_a_proof(self) -> None:
        callee = build([("li", ["a0", "16"]), ("ret", [])], start=0x3000)
        caller = build(
            [
                ("li", ["a0", "32"]),  # 0x1000: the value the skipping path keeps
                ("csrr", ["t2", "vlenb"]),  # 0x1004
                ("li", ["t3", "32"]),  # 0x1008
                ("beq", ["t2", "t3", "0x1014"]),  # 0x100C: call only when vlenb == 32
                ("j", ["0x101C"]),  # 0x1010: skip the call
                ("jal", ["ra", "0x3000"]),  # 0x1014: C() returns 16
                ("j", ["0x101C"]),  # 0x1018
                ("sub", ["sp", "sp", "a0"]),  # 0x101C: 16 or 32, chosen by vlenb
                ("ret", []),  # 0x1020
            ],
            edges=[
                (0x1000, 0x1004),
                (0x1004, 0x1008),
                (0x1008, 0x100C),
                (0x100C, 0x1010),
                (0x100C, 0x1014),
                (0x1010, 0x101C),
                (0x1014, 0x1018),
                (0x1018, 0x101C),
                (0x101C, 0x1020),
            ],
        )
        prover, result, node = self._verdict([caller, callee], 0x101C)
        # The callee returns a constant, but only the vlenb-selected branch
        # executes the call; on the other one a0 keeps 32.  The size the
        # adjustment subtracts therefore switches with VLEN, so the
        # callee-return proof must carry the call-site guard - exactly the
        # rule the memory-write side applies to guarded calls.
        self.assertEqual(result.status, UNPROVEN)
        self.assertEqual(node.reason, G_CONTROL)
        self.assertIn(
            G_CONTROL,
            {item.reason for item in self._chain(prover, node)},
        )

    def test_independent_callsite_guard_keeps_the_return_proof(self) -> None:
        callee = build([("li", ["a0", "16"]), ("ret", [])], start=0x3000)
        caller = build(
            [
                ("li", ["a0", "32"]),  # 0x1000
                ("li", ["t2", "1"]),  # 0x1004: the guard is a proven constant
                ("beqz", ["t2", "0x1014"]),  # 0x1008: skips the call
                ("jal", ["ra", "0x3000"]),  # 0x100C: C() returns 16
                ("j", ["0x1014"]),  # 0x1010
                ("sub", ["sp", "sp", "a0"]),  # 0x1014: 16 or 32, chosen independently
                ("ret", []),  # 0x1018
            ],
            edges=[
                (0x1000, 0x1004),
                (0x1004, 0x1008),
                (0x1008, 0x100C),
                (0x1008, 0x1014),
                (0x100C, 0x1010),
                (0x1010, 0x1014),
                (0x1014, 0x1018),
            ],
        )
        _, result, _ = self._verdict([caller, callee], 0x1014)
        # A guard proven independent of vlenb does not poison the callee's
        # constant result: both possible sizes are fixed constants, so the
        # proof survives the very check the counterexample fails.
        self.assertEqual(result.status, PROVEN)

    def test_branch_selected_callee_result_is_instantiated_per_call_site(self) -> None:
        callee = build(
            [
                ("li", ["a0", "32"]),
                ("beqz", ["a1", "0x300C"]),
                ("li", ["a0", "16"]),
                ("ret", []),
            ],
            start=0x3000,
            edges=[
                (0x3000, 0x3004),
                (0x3004, 0x3008),
                (0x3004, 0x300C),
                (0x3008, 0x300C),
            ],
        )

        def caller(condition):
            # Same shape, only the condition's own provenance differs, so the
            # three verdicts below are about instantiation and nothing else.
            return build(
                [
                    ("addi", ["sp", "sp", "-64"]),
                    condition,
                    ("jal", ["ra", "0x3000"]),
                    ("mv", ["a2", "a0"]),
                    ("sub", ["sp", "sp", "a2"]),
                    ("ret", []),
                ]
            )

        independent, result, _ = self._verdict(
            [caller(("li", ["a1", "1"])), callee], 0x1010
        )
        del independent
        self.assertEqual(result.status, PROVEN)

        _, result, _ = self._verdict(
            [caller(("csrr", ["a1", "vlenb"])), callee], 0x1010
        )
        self.assertEqual(result.status, VLEN)

        # Nothing establishes the caller's own parameter, so the condition
        # cannot be discharged and the result stays unknown.
        _, result, _ = self._verdict([caller(("nop", [])), callee], 0x1010)
        self.assertEqual(result.status, UNPROVEN)

    # --- 4. a load selected by a branch keeps that dependence ---------------

    def test_vlen_selected_loads_are_not_a_proof(self) -> None:
        # Both slots hold proven constants, but *which* slot is loaded is
        # chosen by a branch on vlenb - so the size switches between 16 and 32
        # with the hardware VLEN even though every write is unconditional.
        function = build(
            [
                ("addi", ["sp", "sp", "-64"]),  # 0x1000
                ("li", ["t4", "16"]),  # 0x1004
                ("sd", ["t4", "16(sp)"]),  # 0x1008: slot A = 16
                ("li", ["t5", "32"]),  # 0x100C
                ("sd", ["t5", "24(sp)"]),  # 0x1010: slot B = 32
                ("csrr", ["t2", "vlenb"]),  # 0x1014
                ("li", ["t3", "32"]),  # 0x1018
                ("beq", ["t2", "t3", "0x1028"]),  # 0x101C: slot B when vlenb == 32
                ("ld", ["a0", "16(sp)"]),  # 0x1020: slot A
                ("j", ["0x102C"]),  # 0x1024
                ("ld", ["a0", "24(sp)"]),  # 0x1028: slot B
                ("sub", ["sp", "sp", "a0"]),  # 0x102C: 16 or 32, chosen by vlenb
                ("ret", []),  # 0x1030
            ],
            edges=[
                (0x1000, 0x1004),
                (0x1004, 0x1008),
                (0x1008, 0x100C),
                (0x100C, 0x1010),
                (0x1010, 0x1014),
                (0x1014, 0x1018),
                (0x1018, 0x101C),
                (0x101C, 0x1020),
                (0x101C, 0x1028),
                (0x1020, 0x1024),
                (0x1024, 0x102C),
                (0x1028, 0x102C),
                (0x102C, 0x1030),
            ],
        )
        prover, result, node = self._verdict([function], 0x102C)
        # The content proofs of the two slots are real; what they cannot
        # establish is *which* load executed.  A load definition carries the
        # control dependence of its own execution path, exactly like a call
        # return does.
        self.assertEqual(result.status, UNPROVEN)
        self.assertEqual(node.reason, G_CONTROL)
        self.assertIn(
            G_CONTROL,
            {item.reason for item in self._chain(prover, node)},
        )

    def test_independent_guard_keeps_the_load_proof(self) -> None:
        # Same two-slot shape, but the guard is a proven constant: both
        # possible sizes are fixed, so the load proof survives the very check
        # the counterexample fails.
        function = build(
            [
                ("addi", ["sp", "sp", "-64"]),  # 0x1000
                ("li", ["t4", "16"]),  # 0x1004
                ("sd", ["t4", "16(sp)"]),  # 0x1008: slot A = 16
                ("li", ["t5", "32"]),  # 0x100C
                ("sd", ["t5", "24(sp)"]),  # 0x1010: slot B = 32
                ("li", ["t2", "1"]),  # 0x1014: the guard is a proven constant
                ("beqz", ["t2", "0x1024"]),  # 0x1018
                ("ld", ["a0", "16(sp)"]),  # 0x101C: slot A
                ("j", ["0x1028"]),  # 0x1020
                ("ld", ["a0", "24(sp)"]),  # 0x1024: slot B
                ("sub", ["sp", "sp", "a0"]),  # 0x1028: 16 or 32, chosen independently
                ("ret", []),  # 0x102C
            ],
            edges=[
                (0x1000, 0x1004),
                (0x1004, 0x1008),
                (0x1008, 0x100C),
                (0x100C, 0x1010),
                (0x1010, 0x1014),
                (0x1014, 0x1018),
                (0x1018, 0x101C),
                (0x1018, 0x1024),
                (0x101C, 0x1020),
                (0x1020, 0x1028),
                (0x1024, 0x1028),
                (0x1028, 0x102C),
                (0x102C, 0x1030),
            ],
        )
        _, result, node = self._verdict([function], 0x1028)
        self.assertEqual(result.status, PROVEN)
        self.assertIn("frame-slot", node.reason)

    # --- 3. a write has to happen on every path to be coverage --------------

    @staticmethod
    def _calling_load(callee_start, *, caller_setup=()):
        """A caller that loads the slot it handed to the callee, then sizes ``sp``.

        Returns the function and the adjustment address, so the two shapes
        below stay correct when their setup grows.
        """

        specs = [
            ("addi", ["sp", "sp", "-64"]),
            *caller_setup,
            ("addi", ["a0", "sp", "16"]),
            ("jal", ["ra", hex(callee_start)]),
            ("ld", ["a4", "16(sp)"]),
            ("sub", ["sp", "sp", "a4"]),
            ("ret", []),
        ]
        return build(specs), 0x1000 + (len(specs) - 2) * 4

    def test_callee_write_on_one_branch_only_is_not_coverage(self) -> None:
        callee = build(
            [
                ("beqz", ["a2", "0x200C"]),
                ("li", ["a1", "32"]),
                ("sd", ["a1", "0(a0)"]),
                ("ret", []),
            ],
            start=0x2000,
            edges=[
                (0x2000, 0x2004),
                (0x2000, 0x200C),
                (0x2004, 0x2008),
                (0x2008, 0x200C),
            ],
        )
        caller, adjustment = self._calling_load(
            0x2000,
            # ``li a2,1`` discharges the callee's branch condition, so this
            # case is purely about coverage: the write happens on one path of
            # the callee and the other path keeps the pre-call bytes.
            caller_setup=(("li", ["a2", "1"]), ("li", ["a1", "32"])),
        )
        _, result, node = self._verdict([caller, callee], adjustment)
        # The skipping path leaves the slot holding whatever was there before
        # the call, and nothing in this binary wrote it.
        self.assertEqual(result.status, UNPROVEN)
        self.assertIn(node.reason, {G_NO_WRITER, G_PARTIAL, G_ALIAS})

    def test_callee_write_on_every_path_is_still_coverage(self) -> None:
        callee = build(
            [
                ("beqz", ["a2", "0x2008"]),
                ("addi", ["a3", "a3", "1"]),
                ("li", ["a1", "32"]),
                ("sd", ["a1", "0(a0)"]),
                ("ret", []),
            ],
            start=0x2000,
            edges=[
                (0x2000, 0x2004),
                (0x2000, 0x2008),
                (0x2004, 0x2008),
                (0x2008, 0x200C),
                (0x200C, 0x2010),
            ],
        )
        # ``li a2,0`` both proves the branch condition independent and gives the
        # callee's ``a1`` a proven value to store.
        caller, adjustment = self._calling_load(
            0x2000, caller_setup=(("li", ["a2", "0"]), ("li", ["a1", "32"]))
        )
        _, result, _ = self._verdict([caller, callee], adjustment)
        self.assertEqual(result.status, PROVEN)


class MemoryEffectCompletenessTests(unittest.TestCase):
    """A summary may only say "clean" about memory it fully accounted for.

    Three shapes used to hide a write from the summary, each letting the
    caller's own proven store stand in for a value the callee had replaced:
    a write performed by a *nested* call, a store whose address was moved by
    pointer arithmetic, and a vector store.  "Not modelled" is not "not
    written", so each counterexample is pinned next to the positive control
    that must stay provable.
    """

    @staticmethod
    def _initialised_caller(callee, *, middle=None):
        """Initialise a slot, hand it to ``callee``, load it back, size ``sp``.

        The caller's own store is proven and covering, which is exactly why the
        false verdicts below read ``frame-slot-proven``: the walk strolled past
        a call it believed clean and stopped at the initializer.  ``middle``
        forwards the call one level down (its ``a0`` still holds the pointer).
        """

        entry = 0x2000 if middle is not None else callee.start
        functions = [
            build(
                [
                    ("addi", ["sp", "sp", "-64"]),
                    ("li", ["a1", "16"]),
                    ("sd", ["a1", "16(sp)"]),
                    ("addi", ["a0", "sp", "16"]),
                    ("jal", ["ra", hex(entry)]),
                    ("ld", ["a2", "16(sp)"]),
                    ("sub", ["sp", "sp", "a2"]),
                    ("ret", []),
                ]
            )
        ]
        if middle is not None:
            functions.append(middle)
        functions.append(callee)
        return functions, 0x1000 + 6 * 4

    def _verdict(self, functions, adjustment):
        prover = OriginProver(program(*functions), SEMANTICS)
        result = prover.prove_adjustment(functions[0], adjustment)
        return prover, result, prover._proofs[result.proof_id]

    # --- 1. a nested call's memory effects reach the caller -----------------

    def test_nested_call_memory_effects_are_propagated(self) -> None:
        callee = build(
            [("csrr", ["t0", "vlenb"]), ("sd", ["t0", "0(a0)"]), ("ret", [])],
            start=0x3000,
        )
        # B only forwards the call: its ``a0`` still holds A's pointer, so C's
        # write lands on the slot A initialised and reads back.
        middle = build([("jal", ["ra", "0x3000"]), ("ret", [])], start=0x2000)
        functions, adjustment = self._initialised_caller(callee, middle=middle)
        prover, result, node = self._verdict(functions, adjustment)
        self.assertEqual(result.status, VLEN)
        self.assertIn(
            R_CALLEE_VLEN, {item.reason for item in proof_chain(prover, node)}
        )

    def test_nested_call_with_a_proven_value_stays_provable(self) -> None:
        callee = build(
            [("li", ["t0", "32"]), ("sd", ["t0", "0(a0)"]), ("ret", [])],
            start=0x3000,
        )
        middle = build([("jal", ["ra", "0x3000"]), ("ret", [])], start=0x2000)
        functions, adjustment = self._initialised_caller(callee, middle=middle)
        _, result, _ = self._verdict(functions, adjustment)
        # Both writes are proven constants, so the loaded size is genuinely
        # independent - propagation must not turn into blanket suspicion.
        self.assertEqual(result.status, PROVEN)

    # --- 2. the store address includes the pointer arithmetic ---------------

    def test_pointer_arithmetic_is_part_of_the_write_address(self) -> None:
        # ``addi a0,a0,8`` then ``sd t0,-8(a0)`` writes exactly ``a0+0``: the
        # register's dependence *name* is not an address.
        callee = build(
            [
                ("addi", ["a0", "a0", "8"]),
                ("csrr", ["t0", "vlenb"]),
                ("sd", ["t0", "-8(a0)"]),
                ("ret", []),
            ],
            start=0x3000,
        )
        functions, adjustment = self._initialised_caller(callee)
        _, result, _ = self._verdict(functions, adjustment)
        self.assertEqual(result.status, VLEN)

    def test_composed_offset_with_a_proven_value_stays_provable(self) -> None:
        callee = build(
            [
                ("addi", ["a0", "a0", "8"]),
                ("li", ["t0", "32"]),
                ("sd", ["t0", "-8(a0)"]),
                ("ret", []),
            ],
            start=0x3000,
        )
        functions, adjustment = self._initialised_caller(callee)
        _, result, _ = self._verdict(functions, adjustment)
        self.assertEqual(result.status, PROVEN)

    # --- 3. a vector store through a pointer is a memory effect -------------

    def test_vector_store_through_a_pointer_is_not_invisible(self) -> None:
        callee = build(
            [("vs1r.v", ["v8", "(a0)"]), ("ret", [])], start=0x3000
        )
        functions, adjustment = self._initialised_caller(callee)
        _, result, _ = self._verdict(functions, adjustment)
        # The byte range and the content of a vector store are not modelled,
        # so the loaded slot can no longer be proven independent.
        self.assertNotEqual(result.status, PROVEN)

    def test_vector_store_to_the_callees_own_frame_is_not_silently_ignored(
        self,
    ) -> None:
        callee = build(
            [
                ("addi", ["sp", "sp", "-16"]),
                ("vs1r.v", ["v8", "0(sp)"]),
                ("ret", []),
            ],
            start=0x3000,
        )
        functions, adjustment = self._initialised_caller(callee)
        _, result, _ = self._verdict(functions, adjustment)
        # A vector spill's extent is not modelled: with a VLEN larger than
        # the 16-byte frame it writes *past* the frame, into the caller's
        # stack.  Ownership of the touched region cannot be proven, so the
        # summary may not stay silent about it.
        self.assertNotEqual(result.status, PROVEN)

    def test_scalar_spill_into_an_allocated_frame_stays_provable(self) -> None:
        # The scalar counterpart of the privacy rule: a write provably inside
        # the region the callee itself allocated cannot reach the caller.
        callee = build(
            [
                ("addi", ["sp", "sp", "-32"]),
                ("li", ["t0", "8"]),
                ("sd", ["t0", "0(sp)"]),
                ("ret", []),
            ],
            start=0x3000,
        )
        functions, adjustment = self._initialised_caller(callee)
        _, result, _ = self._verdict(functions, adjustment)
        self.assertEqual(result.status, PROVEN)

    def test_a_write_outside_the_loaded_range_stays_provable(self) -> None:
        callee = build(
            [("li", ["t0", "32"]), ("sd", ["t0", "8(a0)"]), ("ret", [])],
            start=0x3000,
        )
        functions, adjustment = self._initialised_caller(callee)
        _, result, _ = self._verdict(functions, adjustment)
        # ``a0+8`` does not cover ``a0+0``: the caller's initializer survives.
        self.assertEqual(result.status, PROVEN)


class SummarySoundnessRulesTests(unittest.TestCase):
    """Three rules the summary must not negotiate away.

    * no non-alias proof between distinct formal parameters - the caller may
      pass the same pointer twice, and a pointer handed down from above may
      hold any static address;
    * no "clean" without a complete effect model - an atomic write is a write;
    * no dropping unknown targets from an indirect call - proving the internal
      subset of a target set says nothing about the rest.
    """

    def _verdict(self, functions, adjustment, *, metadata=None):
        prover = OriginProver(program(*functions), SEMANTICS, metadata=metadata)
        result = prover.prove_adjustment(functions[0], adjustment)
        return prover, result, prover._proofs[result.proof_id]

    # --- rule 1: distinct parameter names are not a non-alias proof ----------

    def test_distinct_formal_parameters_may_alias(self) -> None:
        callee = build(
            [("csrr", ["t0", "vlenb"]), ("sd", ["t0", "0(a0)"]), ("ret", [])],
            start=0x3000,
        )
        # ``a0``/``a1`` are caller-saved, so the caller parks the second
        # pointer in ``s1`` to load it back after the call.  That does not
        # weaken the counterexample: the loaded object is still the ``a1``
        # atom, the callee still writes through the ``a0`` atom, and the two
        # atoms have no non-alias proof between them.
        caller = build(
            [
                ("mv", ["s1", "a1"]),
                ("li", ["a3", "16"]),
                ("sd", ["a3", "0(s1)"]),
                ("jal", ["ra", "0x3000"]),
                ("ld", ["a2", "0(s1)"]),
                ("sub", ["sp", "sp", "a2"]),
                ("ret", []),
            ]
        )
        prover, result, node = self._verdict([caller, callee], 0x1014)
        # When the caller passed the same pointer as a0 and a1, the loaded
        # size really is vlenb-derived; the two names prove nothing.
        self.assertEqual(result.status, UNPROVEN)
        self.assertIn(
            G_ALIAS, {item.reason for item in proof_chain(prover, node)}
        )

    def test_the_same_pointer_through_a_saved_register_stays_provable(
        self,
    ) -> None:
        # ``a0`` is caller-saved, so the caller parks the pointer in ``s1``.
        # The location model keys an object by its address *atom*, and after
        # ``mv s1,a0`` both spellings are the same atom - so where the model
        # can prove the two accesses share an object, offset reasoning keeps
        # working and only the genuinely distinct atoms fail.
        callee = build(
            [("li", ["t0", "32"]), ("sd", ["t0", "0(a0)"]), ("ret", [])],
            start=0x3000,
        )
        caller = build(
            [
                ("mv", ["s1", "a0"]),
                ("li", ["a3", "16"]),
                ("sd", ["a3", "0(s1)"]),
                ("jal", ["ra", "0x3000"]),
                ("ld", ["a2", "0(s1)"]),
                ("sub", ["sp", "sp", "a2"]),
                ("ret", []),
            ]
        )
        _, result, _ = self._verdict([caller, callee], 0x1014)
        # Both writes are proven constants on one provably shared object.
        self.assertEqual(result.status, PROVEN)

    # --- rule 2: the effect model must cover every memory-writing instruction

    def test_atomic_write_is_accounted_for(self) -> None:
        callee = build(
            [
                ("csrr", ["t0", "vlenb"]),
                ("amoswap.d", ["zero", "t0", "(a0)"]),
                ("ret", []),
            ],
            start=0x3000,
        )
        functions, adjustment = (
            MemoryEffectCompletenessTests._initialised_caller(callee)
        )
        _, result, _ = self._verdict(functions, adjustment)
        self.assertEqual(result.status, VLEN)

    def test_atomic_write_of_a_proven_value_stays_provable(self) -> None:
        callee = build(
            [
                ("li", ["t0", "32"]),
                ("amoswap.d", ["zero", "t0", "(a0)"]),
                ("ret", []),
            ],
            start=0x3000,
        )
        functions, adjustment = (
            MemoryEffectCompletenessTests._initialised_caller(callee)
        )
        _, result, _ = self._verdict(functions, adjustment)
        self.assertEqual(result.status, PROVEN)

    # --- rule 3: an indirect call's target set may not be pruned -------------

    def test_mixed_indirect_targets_are_not_proven_by_the_internal_subset(
        self,
    ) -> None:
        internal = build([("li", ["a0", "16"]), ("ret", [])], start=0x3000)
        external = build([("ret", [])], start=0x9000)
        external.is_external_trampoline = True
        caller = build(
            [
                ("addi", ["sp", "sp", "-64"]),
                ("jalr", ["ra", "a2", "0"]),
                ("mv", ["a2", "a0"]),
                ("sub", ["sp", "sp", "a2"]),
                ("ret", []),
            ]
        )
        metadata = ChimeraMetadata(
            function_pointer={
                0x1004: CallTargetEntry(
                    callsite_rva=0x1004, targets=(0x3000, 0x9000)
                )
            }
        )
        _, result, _ = self._verdict(
            [caller, internal, external], 0x100C, metadata=metadata
        )
        # The external target has no contract here; proving the internal one
        # proves nothing about where the call may actually land.
        self.assertEqual(result.status, UNPROVEN)

    def test_internal_only_indirect_target_stays_provable(self) -> None:
        internal = build([("li", ["a0", "16"]), ("ret", [])], start=0x3000)
        caller = build(
            [
                ("addi", ["sp", "sp", "-64"]),
                ("jalr", ["ra", "a2", "0"]),
                ("mv", ["a2", "a0"]),
                ("sub", ["sp", "sp", "a2"]),
                ("ret", []),
            ]
        )
        metadata = ChimeraMetadata(
            function_pointer={
                0x1004: CallTargetEntry(callsite_rva=0x1004, targets=(0x3000,))
            }
        )
        _, result, _ = self._verdict(
            [caller, internal], 0x100C, metadata=metadata
        )
        self.assertEqual(result.status, PROVEN)


class AtomicSemanticsTests(unittest.TestCase):
    """An atomic write must be described, not just noticed.

    Recognising "this may write memory" is not enough: the proof has to say
    *what* is written and *whether* it happens.  A read-modify-write consumes
    the old memory content, and a store-conditional may not store at all -
    either one can leave vlenb-derived bytes in the slot.
    """

    def _verdict(self, functions, adjustment):
        prover = OriginProver(program(*functions), SEMANTICS)
        result = prover.prove_adjustment(functions[0], adjustment)
        return prover, result, prover._proofs[result.proof_id]

    @staticmethod
    def _vlenb_initialised_caller(callee=None, *, local_body=None):
        """Initialise a slot with ``vlenb``, hand it out, load it back, size ``sp``."""

        head = [
            ("addi", ["sp", "sp", "-64"]),
            ("csrr", ["a1", "vlenb"]),
            ("sd", ["a1", "16(sp)"]),
            ("addi", ["a0", "sp", "16"]),
        ]
        tail = [("ld", ["a2", "16(sp)"]), ("sub", ["sp", "sp", "a2"]), ("ret", [])]
        # The size adjustment is the ``sub``, one instruction past the ``ld``.
        if local_body is not None:
            specs = head + local_body + tail
            return build(specs), 0x1000 + (len(head) + len(local_body) + 1) * 4
        functions = [build(head + [("jal", ["ra", hex(callee.start)])] + tail)]
        functions.append(callee)
        return functions, 0x1000 + (len(head) + 2) * 4

    # --- rule: a read-modify-write consumes the old memory value -------------

    def test_rmw_atomic_write_consumes_the_old_memory_value(self) -> None:
        callee = build(
            [
                ("li", ["t0", "16"]),
                ("amoadd.d", ["t1", "t0", "(a0)"]),
                ("ret", []),
            ],
            start=0x3000,
        )
        functions, adjustment = self._vlenb_initialised_caller(callee)
        _, result, _ = self._verdict(functions, adjustment)
        # The slot ends up holding vlenb + 16: proving the ``16`` proves
        # nothing about the sum.
        self.assertNotEqual(result.status, PROVEN)

    def test_amoswap_writing_an_independent_constant_stays_provable(self) -> None:
        # ``amoswap`` discards the old value, so an independent constant is a
        # complete description of what the slot holds afterwards.
        callee = build(
            [
                ("li", ["t0", "16"]),
                ("amoswap.d", ["zero", "t0", "(a0)"]),
                ("ret", []),
            ],
            start=0x3000,
        )
        functions, adjustment = self._vlenb_initialised_caller(callee)
        _, result, _ = self._verdict(functions, adjustment)
        self.assertEqual(result.status, PROVEN)

    # --- rule: a store-conditional is not a guaranteed write -----------------

    def test_store_conditional_is_not_a_guaranteed_write(self) -> None:
        # Local walk: on SC failure the slot still holds vlenb, so the loaded
        # size is vlenb-derived whatever the successful path stores.
        function, adjustment = self._vlenb_initialised_caller(
            local_body=[
                ("li", ["t0", "16"]),
                ("sc.d", ["t1", "t0", "(a0)"]),
            ]
        )
        _, result, _ = self._verdict([function], adjustment)
        self.assertEqual(result.status, VLEN)

    def test_store_conditional_across_a_call_keeps_the_old_source(self) -> None:
        callee = build(
            [
                ("li", ["t0", "16"]),
                ("sc.d", ["t1", "t0", "(a0)"]),
                ("ret", []),
            ],
            start=0x3000,
        )
        functions, adjustment = self._vlenb_initialised_caller(callee)
        _, result, _ = self._verdict(functions, adjustment)
        self.assertNotEqual(result.status, PROVEN)


class SummaryPathConditionTests(unittest.TestCase):
    """Summary composition must not lose path conditions.

    Two shapes the reviewer reproduced once the atomic model was in place,
    plus the same rule one level up:

    * "some target of this call must-write" is not "this call must-write" -
      coverage has to be intersected over the *complete* target set, and a
      target that does not write keeps the pre-call value alive;
    * a nested write is re-expressed at the call site, so the condition that
      decides whether the call executes rides along with it - otherwise the
      pair "may write 16 / keeps 32" hides that the *selection* is
      vlenb-derived.
    """

    def _verdict(self, functions, adjustment, *, metadata=None):
        prover = OriginProver(program(*functions), SEMANTICS, metadata=metadata)
        result = prover.prove_adjustment(functions[0], adjustment)
        return prover, result, prover._proofs[result.proof_id]

    @staticmethod
    def _vlenb_initialised_caller(call_spec):
        """Initialise a slot with vlenb, hand it out, load it back, size sp.

        ``call_spec`` is the ``(mnemonic, args)`` pair placed at 0x1010.
        """

        specs = [
            ("addi", ["sp", "sp", "-64"]),
            ("csrr", ["a1", "vlenb"]),
            ("sd", ["a1", "16(sp)"]),
            ("addi", ["a0", "sp", "16"]),
            call_spec,
            ("ld", ["a2", "16(sp)"]),
            ("sub", ["sp", "sp", "a2"]),
            ("ret", []),
        ]
        # The size adjustment is the sub, one instruction past the ld.
        return build(specs), 0x1000 + 6 * 4

    @staticmethod
    def _constant_initialised_caller(call_spec):
        """Initialise a slot with the constant 32, then the same tail."""

        specs = [
            ("addi", ["sp", "sp", "-64"]),
            ("li", ["a1", "32"]),
            ("sd", ["a1", "16(sp)"]),
            ("addi", ["a0", "sp", "16"]),
            call_spec,
            ("ld", ["a2", "16(sp)"]),
            ("sub", ["sp", "sp", "a2"]),
            ("ret", []),
        ]
        return build(specs), 0x1000 + 6 * 4

    @staticmethod
    def _writer(start=0x3000, value="16"):
        return build(
            [("li", ["t0", value]), ("sd", ["t0", "0(a0)"]), ("ret", [])],
            start=start,
        )

    # --- rule 1: must-write is intersected over the whole target set --------

    def test_one_writing_target_does_not_make_the_call_must_write(self) -> None:
        # B indirectly calls C (writes 16) or D (writes nothing); the caller's
        # slot holds vlenb.  Choosing D keeps vlenb in the slot.
        caller, adjustment = self._vlenb_initialised_caller(
            ("jal", ["ra", "0x2000"])
        )
        middle = build([("jalr", ["ra", "a2", "0"]), ("ret", [])], start=0x2000)
        metadata = ChimeraMetadata(
            function_pointer={
                0x2000: CallTargetEntry(
                    callsite_rva=0x2000, targets=(0x3000, 0x4000)
                )
            }
        )
        functions = [
            caller,
            middle,
            self._writer(0x3000),
            build([("ret", [])], start=0x4000),
        ]
        _, result, _ = self._verdict(functions, adjustment, metadata=metadata)
        self.assertEqual(result.status, VLEN)

    def test_direct_multi_target_call_is_not_must_write_either(self) -> None:
        # The same rule at the consumption side: the walk meets the
        # multi-target call itself, and "C must-write" must not stop it.
        caller, adjustment = self._vlenb_initialised_caller(
            ("jalr", ["ra", "a2", "0"])
        )
        metadata = ChimeraMetadata(
            function_pointer={
                0x1010: CallTargetEntry(
                    callsite_rva=0x1010, targets=(0x3000, 0x4000)
                )
            }
        )
        functions = [
            caller,
            self._writer(0x3000),
            build([("ret", [])], start=0x4000),
        ]
        _, result, _ = self._verdict(functions, adjustment, metadata=metadata)
        self.assertEqual(result.status, VLEN)

    def test_every_target_writing_keeps_the_proof(self) -> None:
        # Positive control: both targets overwrite the slot with the same
        # proven constant, so the call really is a must-write.
        caller, adjustment = self._vlenb_initialised_caller(
            ("jal", ["ra", "0x2000"])
        )
        middle = build([("jalr", ["ra", "a2", "0"]), ("ret", [])], start=0x2000)
        metadata = ChimeraMetadata(
            function_pointer={
                0x2000: CallTargetEntry(
                    callsite_rva=0x2000, targets=(0x3000, 0x4000)
                )
            }
        )
        functions = [
            caller,
            middle,
            self._writer(0x3000),
            self._writer(0x4000),
        ]
        _, result, _ = self._verdict(functions, adjustment, metadata=metadata)
        self.assertEqual(result.status, PROVEN)

    # --- rule 2: a nested write carries the callsite's control dependencies -

    def test_nested_write_carries_the_callsite_control_dependencies(self) -> None:
        # The slot holds the constant 32; B calls C (which stores 16) only
        # when vlenb is zero.  The final value is selected by a vlenb-derived
        # branch, so "16 or 32" is not an independence proof.
        caller, adjustment = self._constant_initialised_caller(
            ("jal", ["ra", "0x2000"])
        )
        middle = build(
            [
                ("csrr", ["t0", "vlenb"]),
                ("beqz", ["t0", "0x200C"]),
                ("jal", ["ra", "0x3000"]),
                ("ret", []),
            ],
            start=0x2000,
            edges=[
                (0x2000, 0x2004),
                (0x2004, 0x2008),
                (0x2004, 0x200C),
                (0x2008, 0x200C),
            ],
        )
        functions = [caller, middle, self._writer(0x3000)]
        _, result, _ = self._verdict(functions, adjustment)
        self.assertEqual(result.status, VLEN)

    def test_independent_callsite_guard_keeps_the_proof(self) -> None:
        # Positive control: the same guarded call, but the guard reads a
        # register the caller loaded with a constant.  The selection is
        # proven independent, so the proof survives.
        caller, adjustment = self._constant_initialised_caller(
            ("jal", ["ra", "0x2000"])
        )
        caller = build(
            [
                ("addi", ["sp", "sp", "-64"]),
                ("li", ["a1", "32"]),
                ("sd", ["a1", "16(sp)"]),
                ("li", ["a3", "5"]),
                ("addi", ["a0", "sp", "16"]),
                ("jal", ["ra", "0x2000"]),
                ("ld", ["a2", "16(sp)"]),
                ("sub", ["sp", "sp", "a2"]),
                ("ret", []),
            ]
        )
        middle = build(
            [
                ("beqz", ["a3", "0x2008"]),
                ("jal", ["ra", "0x3000"]),
                ("ret", []),
            ],
            start=0x2000,
            edges=[
                (0x2000, 0x2004),
                (0x2000, 0x2008),
                (0x2004, 0x2008),
            ],
        )
        functions = [caller, middle, self._writer(0x3000)]
        _, result, _ = self._verdict(functions, adjustment)
        self.assertEqual(result.status, PROVEN)

    # --- the proof side: a guarded write source is not a guarantee ----------

    def test_guarded_call_is_not_a_guaranteed_write(self) -> None:
        # The slot holds 32; the caller calls C (which stores 16) only when
        # vlenb is zero.  C's write is unconditional *inside* C, but whether
        # the call happens at all is vlenb-selected.
        caller = build(
            [
                ("addi", ["sp", "sp", "-64"]),
                ("li", ["a1", "32"]),
                ("sd", ["a1", "16(sp)"]),
                ("addi", ["a0", "sp", "16"]),
                ("csrr", ["t0", "vlenb"]),
                ("beqz", ["t0", "0x101C"]),
                ("jal", ["ra", "0x3000"]),
                ("ld", ["a2", "16(sp)"]),
                ("sub", ["sp", "sp", "a2"]),
                ("ret", []),
            ],
            edges=[
                (0x1000, 0x1004),
                (0x1004, 0x1008),
                (0x1008, 0x100C),
                (0x100C, 0x1010),
                (0x1010, 0x1014),
                (0x1014, 0x1018),
                (0x1014, 0x101C),
                (0x1018, 0x101C),
                (0x101C, 0x1020),
                (0x1020, 0x1024),
            ],
        )
        functions = [caller, self._writer(0x3000)]
        prover, result, node = self._verdict(functions, 0x1020)
        self.assertNotEqual(result.status, PROVEN)
        self.assertIn(
            G_CONTROL, {item.reason for item in proof_chain(prover, node)}
        )

    def test_guarded_store_with_a_hoisted_value_is_not_proven(self) -> None:
        # The stored register is defined *before* the branch, so the value
        # proof passes - but the write itself only happens under a
        # vlenb-derived condition, and 32 survives on the other arm.
        function = build(
            [
                ("addi", ["sp", "sp", "-64"]),
                ("li", ["a1", "32"]),
                ("sd", ["a1", "16(sp)"]),
                ("li", ["a3", "16"]),
                ("csrr", ["t0", "vlenb"]),
                ("beqz", ["t0", "0x1018"]),
                ("sd", ["a3", "16(sp)"]),
                ("ld", ["a2", "16(sp)"]),
                ("sub", ["sp", "sp", "a2"]),
                ("ret", []),
            ],
            edges=[
                (0x1000, 0x1004),
                (0x1004, 0x1008),
                (0x1008, 0x100C),
                (0x100C, 0x1010),
                (0x1010, 0x1014),
                (0x1014, 0x1018),
                (0x1014, 0x1018),
                (0x1018, 0x101C),
                (0x101C, 0x1020),
                (0x1020, 0x1024),
            ],
        )
        prover, result, node = self._verdict([function], 0x1020)
        self.assertNotEqual(result.status, PROVEN)
        self.assertIn(
            G_CONTROL, {item.reason for item in proof_chain(prover, node)}
        )


class SummaryUnknownPropagationTests(unittest.TestCase):
    """The summary dataflow must keep UNKNOWN as UNKNOWN.

    Three states answer "what does this register depend on": absence means
    the *entry* value (the formal itself), an empty set means a proven
    constant, and ``None`` means unknown - typically "clobbered by a call".
    A join that drops the ``None`` entries makes a clobbered register look
    never-mentioned again, and "never mentioned" reads as the entry
    parameter downstream: the caller's constant flows back in through a
    register the callee had destroyed.
    """

    def _verdict(self, functions, adjustment):
        prover = OriginProver(program(*functions), SEMANTICS)
        result = prover.prove_adjustment(functions[0], adjustment)
        return prover, result, prover._proofs[result.proof_id]

    @staticmethod
    def _caller(call_spec):
        specs = [
            ("addi", ["sp", "sp", "-64"]),
            ("li", ["a1", "16"]),
            ("addi", ["a0", "sp", "16"]),
            call_spec,
            ("sub", ["sp", "sp", "a0"]),
            ("ret", []),
        ]
        return build(specs), 0x1000 + 4 * 4

    def test_call_clobbered_argument_is_not_the_entry_parameter(self) -> None:
        # C overwrites a1 with vlenb; B reads a1 *after* the call and returns
        # it.  The returned value is vlenb-derived, not the caller's 16.
        caller, adjustment = self._caller(("jal", ["ra", "0x2000"]))
        middle = build(
            [("jal", ["ra", "0x3000"]), ("mv", ["a0", "a1"]), ("ret", [])],
            start=0x2000,
        )
        callee = build([("csrr", ["a1", "vlenb"]), ("ret", [])], start=0x3000)
        _, result, _ = self._verdict([caller, middle, callee], adjustment)
        self.assertNotEqual(result.status, PROVEN)

    def test_constant_reassigned_after_the_call_restores_the_proof(self) -> None:
        # Positive control: the same shape, but B reassigns the constant
        # after the call, so the returned value really is independent.
        caller, adjustment = self._caller(("jal", ["ra", "0x2000"]))
        middle = build(
            [("jal", ["ra", "0x3000"]), ("li", ["a0", "16"]), ("ret", [])],
            start=0x2000,
        )
        callee = build([("csrr", ["a1", "vlenb"]), ("ret", [])], start=0x3000)
        _, result, _ = self._verdict([caller, middle, callee], adjustment)
        self.assertEqual(result.status, PROVEN)

    def test_callee_return_through_an_unmentioned_register_is_not_a_constant(
        self,
    ) -> None:
        # C returns its own formal a0 unchanged, but the caller B never
        # mentions a0.  Substituting C's dependence must answer "B's entry
        # a0" - not "constant", which is what an absent state entry used to
        # mean.  A hands B a vlenb-derived a0, so the size is VLEN-derived.
        caller = build(
            [
                ("addi", ["sp", "sp", "-64"]),
                ("csrr", ["a0", "vlenb"]),
                ("jal", ["ra", "0x2000"]),
                ("sub", ["sp", "sp", "a0"]),
                ("ret", []),
            ]
        )
        middle = build([("jal", ["ra", "0x3000"]), ("ret", [])], start=0x2000)
        callee = build([("addi", ["a0", "a0", "0"]), ("ret", [])], start=0x3000)
        _, result, _ = self._verdict([caller, middle, callee], 0x100C)
        self.assertNotEqual(result.status, PROVEN)


class SummaryValueChannelTests(unittest.TestCase):
    """Return provenance and each memory write are separate summary channels."""

    @staticmethod
    def _caller(inputs):
        return build([
            ("addi", ["sp", "sp", "-64"]),
            *inputs,
            ("li", ["a1", "8192"]),
            ("jal", ["ra", "0x2000"]),
            ("sub", ["sp", "sp", "a0"]),
            ("ret", []),
        ])

    @staticmethod
    def _prove(caller, *callees):
        prover = OriginProver(program(caller, *callees), SEMANTICS)
        # Derive the queried adjustment from specs, never a hand-copied PC.
        result = prover.prove_adjustment(caller, caller.insts[-2].addr)
        return prover, result

    def test_constant_write_cannot_erase_formal_return_dependency(self):
        caller = self._caller([("csrr", ["a0", "vlenb"])])
        callee = build([
            ("li", ["t0", "16"]), ("sd", ["t0", "0(a1)"]),
            ("addi", ["a0", "a0", "0"]), ("ret", []),
        ], start=0x2000)
        prover, result = self._prove(caller, callee)
        self.assertEqual(result.status, VLEN)
        summary = prover._summary(callee.start)
        self.assertEqual(summary.return_dependencies, frozenset({"a0"}))
        self.assertEqual(summary.writes[0].dependencies, frozenset())

    def test_width_write_does_not_taint_an_independent_return(self):
        caller = self._caller([("li", ["a0", "32"])])
        callee = build([
            ("csrr", ["t0", "vlenb"]), ("sd", ["t0", "0(a1)"]),
            ("li", ["a0", "16"]), ("ret", []),
        ], start=0x2000)
        prover, result = self._prove(caller, callee)
        self.assertEqual(result.status, PROVEN)
        summary = prover._summary(callee.start)
        self.assertEqual(summary.return_dependencies, frozenset())
        self.assertEqual(summary.writes[0].dependencies, frozenset({"vlenb"}))

    def test_write_order_cannot_select_the_return_dependency(self):
        for width_return in (True, False):
            for reverse in (True, False):
                with self.subTest(width_return=width_return, reverse=reverse):
                    inputs = [
                        ("csrr", ["a2" if width_return else "a3", "vlenb"]),
                        ("li", ["a3" if width_return else "a2", "16"]),
                    ]
                    caller = self._caller(inputs)
                    writes = [("sd", ["a3", "0(a1)"]), ("sd", ["t0", "8(a1)"])]
                    if reverse:
                        writes.reverse()
                    callee = build([
                        ("li", ["t0", "32"]), *writes,
                        ("mv", ["a0", "a2"]), ("ret", []),
                    ], start=0x2000)
                    prover, result = self._prove(caller, callee)
                    self.assertEqual(result.status, VLEN if width_return else PROVEN)
                    summary = prover._summary(callee.start)
                    self.assertEqual(summary.return_dependencies, frozenset({"a2"}))
                    self.assertEqual({w.offset: w.dependencies for w in summary.writes},
                                     {0: frozenset({"a3"}), 8: frozenset()})

    def test_rmw_memory_input_stays_on_the_write_channel(self):
        caller = self._caller([("csrr", ["a2", "vlenb"]), ("li", ["a3", "16"])])
        callee = build([
            ("amoadd.d", ["t0", "a2", "0(a1)"]),
            ("mv", ["a0", "a3"]), ("ret", []),
        ], start=0x2000)
        prover, result = self._prove(caller, callee)
        self.assertEqual(result.status, PROVEN)
        summary = prover._summary(callee.start)
        self.assertEqual(summary.return_dependencies, frozenset({"a3"}))
        self.assertEqual(summary.writes[0].dependencies, frozenset({"a2", "memory"}))
        self.assertFalse(summary.writes[0].on_every_path)

    def test_constant_write_cannot_erase_the_return_selection_guard(self):
        caller = self._caller([("csrr", ["a2", "vlenb"])])
        start = 0x2000
        at = lambda index: start + index * 4
        specs = [
            ("li", ["t0", "7"]), ("sd", ["t0", "0(a1)"]),
            ("beqz", ["a2", hex(at(5))]), ("li", ["a0", "16"]),
            ("j", ["zero", hex(at(6))]), ("li", ["a0", "32"]), ("ret", []),
        ]
        callee = build(specs, start=start, edges=[
            (at(0), at(1)), (at(1), at(2)), (at(2), at(3)), (at(2), at(5)),
            (at(3), at(4)), (at(4), at(6)), (at(5), at(6)),
        ])
        prover, result = self._prove(caller, callee)
        self.assertEqual(result.status, VLEN)
        summary = prover._summary(callee.start)
        self.assertEqual(summary.return_dependencies, frozenset({"a2"}))
        self.assertEqual(summary.writes[0].dependencies, frozenset())

    def test_separate_channels_survive_a_nested_summary(self):
        caller = self._caller([("csrr", ["a0", "vlenb"])])
        middle = build([("jal", ["ra", "0x3000"]), ("ret", [])], start=0x2000)
        callee = build([
            ("li", ["t0", "16"]), ("sd", ["t0", "0(a1)"]),
            ("addi", ["a0", "a0", "0"]), ("ret", []),
        ], start=0x3000)
        prover, result = self._prove(caller, middle, callee)
        self.assertEqual(result.status, VLEN)
        for function in (middle, callee):
            summary = prover._summary(function.start)
            self.assertEqual(summary.return_dependencies, frozenset({"a0"}))
            self.assertEqual(summary.writes[0].dependencies, frozenset())


class UniformRuleTests(unittest.TestCase):
    """The alias and substitution rules must hold on every path they apply to.

    Two rules were introduced for the summary-consumption side and then found
    missing on sibling branches:

    * the *local* reaching-write walk decides overlap by object key - but two
      distinct formal names, or a formal and a static address, may alias, so
      a store through one of them must participate in the verdict;
    * a *static* write needs no address rebasing across a call, but its
      *value* dependence is still expressed in the callee's variables and
      must be substituted at the call site like any other write's.
    """

    def _verdict(self, functions, adjustment):
        prover = OriginProver(program(*functions), SEMANTICS)
        result = prover.prove_adjustment(functions[0], adjustment)
        return prover, result, prover._proofs[result.proof_id]

    # --- the local walk applies the alias table ------------------------------

    def test_local_store_through_a_may_alias_pointer_participates(self) -> None:
        # *a1 = 16; *a0 = vlenb; size = *a1.  When a0 == a1 the loaded size is
        # vlenb; the walk used to stop at the covering a1 store and never let
        # the a0 store into the verdict.
        function = build(
            [
                ("li", ["a3", "16"]),
                ("sd", ["a3", "0(a1)"]),
                ("csrr", ["t0", "vlenb"]),
                ("sd", ["t0", "0(a0)"]),
                ("ld", ["a2", "0(a1)"]),
                ("sub", ["sp", "sp", "a2"]),
                ("ret", []),
            ]
        )
        _, result, _ = self._verdict([function], 0x1014)
        self.assertNotEqual(result.status, PROVEN)

    def test_local_frame_store_is_still_provably_disjoint(self) -> None:
        # Positive control: the second store lands in *this* function's frame,
        # which is provably distinct from every formal - the a1 store keeps
        # deciding the verdict.
        function = build(
            [
                ("addi", ["sp", "sp", "-64"]),
                ("li", ["a3", "16"]),
                ("sd", ["a3", "0(a1)"]),
                ("csrr", ["t0", "vlenb"]),
                ("sd", ["t0", "16(sp)"]),
                ("ld", ["a2", "0(a1)"]),
                ("sub", ["sp", "sp", "a2"]),
                ("ret", []),
            ]
        )
        _, result, _ = self._verdict([function], 0x1018)
        self.assertEqual(result.status, PROVEN)

    # --- static writes substitute their value dependencies too ---------------

    def test_static_write_substitutes_the_callee_value_dependencies(
        self,
    ) -> None:
        # A: a1 = 16; call B; size = static.  B: a1 = vlenb; call C.
        # C: static = a1.  C's dependence "a1" is C's formal, whose value at
        # the call site is B's vlenb - substituting it must yield vlenb, not
        # B's (unmentioned) entry a1, and certainly not A's constant.
        caller = build(
            [
                ("addi", ["sp", "sp", "-64"]),
                ("li", ["a1", "16"]),
                ("addi", ["a0", "sp", "16"]),
                ("jal", ["ra", "0x2000"]),
                ("ld", ["a2", "8192(zero)"]),
                ("sub", ["sp", "sp", "a2"]),
                ("ret", []),
            ]
        )
        middle = build(
            [
                ("csrr", ["a1", "vlenb"]),
                ("jal", ["ra", "0x3000"]),
                ("ret", []),
            ],
            start=0x2000,
        )
        callee = build(
            [("sd", ["a1", "8192(zero)"]), ("ret", [])], start=0x3000
        )
        _, result, _ = self._verdict([caller, middle, callee], 0x1014)
        self.assertNotEqual(result.status, PROVEN)

    def test_static_write_with_a_proven_value_stays_provable(self) -> None:
        # Positive control: the same chain, but B loads a constant into a1,
        # so the substituted dependence really is a proven constant.
        caller = build(
            [
                ("addi", ["sp", "sp", "-64"]),
                ("li", ["a1", "16"]),
                ("addi", ["a0", "sp", "16"]),
                ("jal", ["ra", "0x2000"]),
                ("ld", ["a2", "8192(zero)"]),
                ("sub", ["sp", "sp", "a2"]),
                ("ret", []),
            ]
        )
        middle = build(
            [
                ("li", ["a1", "32"]),
                ("jal", ["ra", "0x3000"]),
                ("ret", []),
            ],
            start=0x2000,
        )
        callee = build(
            [("sd", ["a1", "8192(zero)"]), ("ret", [])], start=0x3000
        )
        _, result, _ = self._verdict([caller, middle, callee], 0x1014)
        self.assertEqual(result.status, PROVEN)


class FrameOwnershipTests(unittest.TestCase):
    """An entry-``sp`` address is private only when the callee allocated it.

    Two forensic rules the reviewer reproduced:

    * a write through the entry ``sp`` used to be dropped from the summary as
      "the callee's own frame" - but a callee that never adjusts ``sp`` has
      its caller's ``sp`` as its entry ``sp``, so the write may land in the
      caller's frame.  Only a write provably inside the region the callee
      itself allocated may be ignored;
    * the missing-callee list was rebuilt for every summary, so a body the
      analysis could not read disappeared from the forensic list as soon as
      another function was summarised.
    """

    def _verdict(self, functions, adjustment, *, metadata=None):
        prover = OriginProver(program(*functions), SEMANTICS, metadata=metadata)
        result = prover.prove_adjustment(functions[0], adjustment)
        return prover, result, prover._proofs[result.proof_id]

    # --- the entry-sp region is not private by name --------------------------

    def test_unallocated_entry_sp_write_is_not_private(self) -> None:
        # A: allocate; [sp] = 16; call B; size = [sp].  B never adjusts sp,
        # so its entry sp *is* A's call-time sp: its [sp] = vlenb write may
        # hit the very slot A loads.
        caller = build(
            [
                ("addi", ["sp", "sp", "-64"]),
                ("li", ["a1", "16"]),
                ("sd", ["a1", "0(sp)"]),
                ("jal", ["ra", "0x2000"]),
                ("ld", ["a2", "0(sp)"]),
                ("sub", ["sp", "sp", "a2"]),
                ("ret", []),
            ]
        )
        callee = build(
            [
                ("csrr", ["t0", "vlenb"]),
                ("sd", ["t0", "0(sp)"]),
                ("ret", []),
            ],
            start=0x2000,
        )
        prover, result, _ = self._verdict([caller, callee], 0x1014)
        self.assertNotEqual(result.status, PROVEN)
        summary = prover._summary(0x2000)
        self.assertTrue(summary.unknown_memory)

    def test_allocated_frame_write_stays_private(self) -> None:
        # Positive control: the same callee, but it allocates its own frame
        # first - the write lands in provably new memory and the caller's
        # proof survives.
        caller = build(
            [
                ("addi", ["sp", "sp", "-64"]),
                ("li", ["a1", "16"]),
                ("sd", ["a1", "0(sp)"]),
                ("jal", ["ra", "0x2000"]),
                ("ld", ["a2", "0(sp)"]),
                ("sub", ["sp", "sp", "a2"]),
                ("ret", []),
            ]
        )
        callee = build(
            [
                ("addi", ["sp", "sp", "-64"]),
                ("csrr", ["t0", "vlenb"]),
                ("sd", ["t0", "0(sp)"]),
                ("ret", []),
            ],
            start=0x2000,
        )
        _, result, _ = self._verdict([caller, callee], 0x1014)
        self.assertEqual(result.status, PROVEN)

    # --- the missing-callee list accumulates across summaries ----------------

    def test_missing_callee_list_survives_other_summaries(self) -> None:
        # The direct call to a body-less address is recorded as missing;
        # summarising an unrelated function afterwards must not wipe the
        # forensic list.
        internal = build([("li", ["a0", "16"]), ("ret", [])], start=0x3000)
        caller = build(
            [
                ("addi", ["sp", "sp", "-64"]),
                ("jal", ["ra", "0x8000"]),
                ("sub", ["sp", "sp", "a0"]),
                ("ret", []),
            ]
        )
        prover, _, _ = self._verdict([caller, internal], 0x1008)
        self.assertIn(0x8000, prover.missing_callees)
        prover._summary(0x3000)
        self.assertIn(0x8000, prover.missing_callees)

    def test_missing_callee_list_does_not_depend_on_the_proof_path(self) -> None:
        # The guarded call's return proof stops before resolving its target,
        # and the callee that would only have been summarized through that
        # call holds the only reference to a body-less address.  The forensic
        # list is a property of the program, not of which proofs ran.
        nested = build(
            [
                ("jal", ["ra", "0x5000"]),  # the only reference to a missing body
                ("li", ["a0", "16"]),
                ("ret", []),
            ],
            start=0x3000,
        )
        caller = build(
            [
                ("addi", ["sp", "sp", "-64"]),  # 0x1000
                ("li", ["a0", "32"]),  # 0x1004
                ("csrr", ["t2", "vlenb"]),  # 0x1008
                ("li", ["t3", "32"]),  # 0x100C
                ("beq", ["t2", "t3", "0x1018"]),  # 0x1010: call only when vlenb == 32
                ("j", ["0x1020"]),  # 0x1014: skip the call
                ("jal", ["ra", "0x3000"]),  # 0x1018: the guarded call
                ("j", ["0x1020"]),  # 0x101C
                ("sub", ["sp", "sp", "a0"]),  # 0x1020
                ("ret", []),  # 0x1024
            ],
            edges=[
                (0x1000, 0x1004),
                (0x1004, 0x1008),
                (0x1008, 0x100C),
                (0x100C, 0x1010),
                (0x1010, 0x1014),
                (0x1010, 0x1018),
                (0x1014, 0x1020),
                (0x1018, 0x101C),
                (0x101C, 0x1020),
                (0x1020, 0x1024),
            ],
        )
        prover, result, node = self._verdict([caller, nested], 0x1020)
        self.assertEqual(result.status, UNPROVEN)
        self.assertEqual(node.reason, G_CONTROL)
        self.assertIn(0x5000, prover.missing_callees)
        self.assertEqual(prover.missing_callees[0x5000], G_NO_BODY)

    # --- the privacy proof applies to rebased nested writes too --------------

    def test_nested_write_through_the_frame_base_is_not_private(self) -> None:
        # A: allocate; [sp] = 16; call B; size = [sp].  B: a0 = sp; call C.
        # C: *a0 = vlenb.  B never allocated, so a0 points at A's call-time
        # sp: C's write, re-expressed at B's call site, lands on A's slot -
        # the merge used to drop it for being "frame-typed".
        caller = build(
            [
                ("addi", ["sp", "sp", "-64"]),
                ("li", ["a1", "16"]),
                ("sd", ["a1", "0(sp)"]),
                ("jal", ["ra", "0x2000"]),
                ("ld", ["a2", "0(sp)"]),
                ("sub", ["sp", "sp", "a2"]),
                ("ret", []),
            ]
        )
        middle = build(
            [
                ("mv", ["a0", "sp"]),
                ("jal", ["ra", "0x3000"]),
                ("ret", []),
            ],
            start=0x2000,
        )
        callee = build(
            [("csrr", ["t0", "vlenb"]), ("sd", ["t0", "0(a0)"]), ("ret", [])],
            start=0x3000,
        )
        prover, result, _ = self._verdict([caller, middle, callee], 0x1014)
        self.assertNotEqual(result.status, PROVEN)
        summary = prover._summary(0x2000)
        self.assertTrue(summary.unknown_memory)

    def test_nested_write_into_an_allocated_frame_is_private(self) -> None:
        # Positive control: B allocates its own frame and hands C a pointer
        # into it - C's write provably lands in new memory and cannot reach
        # the caller, so B's summary stays clean and the proof survives.
        caller = build(
            [
                ("addi", ["sp", "sp", "-64"]),
                ("li", ["a1", "16"]),
                ("sd", ["a1", "0(sp)"]),
                ("jal", ["ra", "0x2000"]),
                ("ld", ["a2", "0(sp)"]),
                ("sub", ["sp", "sp", "a2"]),
                ("ret", []),
            ]
        )
        middle = build(
            [
                ("addi", ["sp", "sp", "-64"]),
                ("mv", ["a0", "sp"]),
                ("jal", ["ra", "0x3000"]),
                ("ret", []),
            ],
            start=0x2000,
        )
        callee = build(
            [("csrr", ["t0", "vlenb"]), ("sd", ["t0", "0(a0)"]), ("ret", [])],
            start=0x3000,
        )
        _, result, _ = self._verdict([caller, middle, callee], 0x1014)
        self.assertEqual(result.status, PROVEN)

    # --- a rebased write may become a static object ---------------------------

    @staticmethod
    def _static_rebase_chain(callee):
        """A: call B; size = static.  B: a0 = static address; call C."""
        specs = [
            ("addi", ["sp", "sp", "-64"]),
            ("jal", ["ra", "0x2000"]),
            ("ld", ["a2", "8192(zero)"]),
            ("sub", ["sp", "sp", "a2"]),
            ("ret", []),
        ]
        caller = build(specs)
        # The size adjustment is the sub, computed from the specs - never
        # hand-copied.
        middle = build(
            [
                ("li", ["a0", "8192"]),
                ("jal", ["ra", "0x3000"]),
                ("ret", []),
            ],
            start=0x2000,
        )
        return [caller, middle, callee], 0x1000 + 3 * 4

    def test_static_rebased_write_of_a_proven_constant_stays_provable(
        self,
    ) -> None:
        # B loads a static address into a0; C stores a proven constant
        # through it.  Rebased at B's call site the write is a *static*
        # object - the summary must record it as such (absolute offset, no
        # base register) instead of crashing on the missing formal key.
        callee = build(
            [("li", ["t0", "16"]), ("sd", ["t0", "0(a0)"]), ("ret", [])],
            start=0x3000,
        )
        functions, adjustment = self._static_rebase_chain(callee)
        _, result, _ = self._verdict(functions, adjustment)
        self.assertEqual(result.status, PROVEN)

    def test_static_rebased_write_of_vlenb_is_not_provable(self) -> None:
        # The same chain, but C stores vlenb: the rebased static write must
        # carry the vlenb dependence through, so the caller's verdict keeps
        # the mark.  Either way, no exception.
        callee = build(
            [("csrr", ["t0", "vlenb"]), ("sd", ["t0", "0(a0)"]), ("ret", [])],
            start=0x3000,
        )
        functions, adjustment = self._static_rebase_chain(callee)
        _, result, _ = self._verdict(functions, adjustment)
        self.assertNotEqual(result.status, PROVEN)

    # --- the query point being the entry keeps the external path -------------

    def test_entry_register_query_keeps_the_external_entry_path(self) -> None:
        # entry: sub sp,sp,a0; li a0,16; j entry.  The back-edge constant
        # covers later iterations only: the FIRST execution's a0 is whatever
        # the caller passed, and it may be vlenb.
        function = build(
            [
                ("sub", ["sp", "sp", "a0"]),
                ("li", ["a0", "16"]),
                ("j", ["0x1000"]),
            ],
            edges=[
                (0x1000, 0x1004),
                (0x1004, 0x1008),
                (0x1008, 0x1000),
            ],
        )
        _, result, _ = self._verdict([function], 0x1000)
        self.assertNotEqual(result.status, PROVEN)

    def test_entry_memory_query_keeps_the_external_entry_path(self) -> None:
        # entry: ld a2,0(a0); sub sp,sp,a2; ...; sd t0,0(a0); j entry.  The
        # back-edge store covers later iterations; the first execution reads
        # what the caller's pointer refers to.
        function = build(
            [
                ("ld", ["a2", "0(a0)"]),
                ("sub", ["sp", "sp", "a2"]),
                ("li", ["t0", "16"]),
                ("sd", ["t0", "0(a0)"]),
                ("j", ["0x1000"]),
            ],
            edges=[
                (0x1000, 0x1004),
                (0x1004, 0x1008),
                (0x1008, 0x100C),
                (0x100C, 0x1010),
                (0x1010, 0x1000),
            ],
        )
        _, result, _ = self._verdict([function], 0x1004)
        self.assertNotEqual(result.status, PROVEN)

    def test_entry_constant_adjustment_stays_provable(self) -> None:
        # Positive control: an entry adjustment by a proven constant needs no
        # reaching definition at all and stays proven.
        function = build([("addi", ["sp", "sp", "-64"]), ("ret", [])])
        _, result, _ = self._verdict([function], 0x1000)
        self.assertEqual(result.status, PROVEN)
