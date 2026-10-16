"""check-elf diagnostics pipeline tests (fixture-driven, no objdump needed)."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from chimera.preprocess.offline.analysis.safety.stack_liveness.model import (
    AllocationOrigin,
    ActiveOrigin,
    ORIGIN_CONSERVATIVE,
    ORIGIN_INHERITED,
    ORIGIN_IRREDUCIBLE,
    ORIGIN_LOCAL_FRAME,
    ORIGIN_LOCAL_SETUP,
    ORIGIN_VECTOR_DATA,
    StackObjectId,
)
from chimera.check_elf import (
    ACTION_DISABLE_AUTOVEC,
    ACTION_STACK_OBJECT,
    ACTION_TRACE_SOURCE,
    CAUSE_INHERITED,
    CAUSE_IRREDUCIBLE,
    DEFAULT_TEXT_THRESHOLD,
    IRREDUCIBLE_DEGRADED,
    STRATEGY_GATE,
    STRATEGY_NONE,
    STRATEGY_SVF,
    build_decision_block,
    collect_diagnostics,
    export_inheritance_diagnostics,
    has_actionable_findings,
    write_report,
)
from chimera.preprocess.offline.analysis.safety.stack_liveness import (
    AnalysisWarning,
    ChimeraMetadata,
)

# Minimal objdump-style disassembly exercising the three roles:
#   seed_host : whole-register spill (DEF) -> two direct calls -> reloads;
#               both calls are locally active (the reload keeps the object
#               alive across each of them), so the host is a seed source.
#   victim    : entered under that live context and hosts an unresolved
#               jalr -> the single INHERITED-attributed finding.
#   quiet     : hosts an unresolved jalr at a point with no activity at all
#               -> must NOT produce a finding (liveness filter).
DUMP = """\
0000000000010000 <leaf>:
    10000:	8082                	ret

0000000000010004 <callee>:
    10004:	8082                	ret

0000000000010008 <victim>:
    10008:	8faa                	mv	a5,a0
    1000a:	9682                	jalr	a3
    1000c:	8082                	ret

0000000000010010 <quiet>:
    10010:	9682                	jalr	a2
    10012:	8082                	ret

0000000000010014 <seed_host>:
    10014:	7131                	addi	sp,sp,-128
    10016:	f406                	sd	ra,120(sp)
    10018:	cd817057          	vsetivli	zero,16,e64,m4,ta,ma
    1001c:	84b2                	mv	s1,sp
    1001e:	0294302b          	vs4r.v	v9,(s1)
    10022:	e05ff0ef          	jal	ra,10004 <callee>
    10026:	2284b787          	vl4re64.v	v10,(s1)
    1002a:	e09ff0ef          	jal	ra,10008 <victim>
    1002e:	2284d787          	vl4re64.v	v11,(s1)
    10032:	60a6                	ld	ra,120(sp)
    10034:	6145                	addi	sp,sp,128
    10036:	8082                	ret
"""

ELF_STUB_BYTES = b"\x7fELF\x02\x01\x01" + b"\x00" * 24

#: The prose prefix each structured origin is carried by in this fixture.
#: Tests build both from the same detail line so a reworded sentence can
#: never change an attribution.
def _origin_of_detail(detail: str) -> str:
    """The structured origin a crafted prose line stands for."""

    for prefix, kind in _ORIGIN_FOR_DETAIL.items():
        if detail.startswith(prefix):
            return kind
    raise KeyError(detail)


_ORIGIN_FOR_DETAIL = {
    "live stack object": ORIGIN_VECTOR_DATA,
    "live conservative marker": ORIGIN_CONSERVATIVE,
    "live irreducible-loop marker": ORIGIN_IRREDUCIBLE,
    "live caller-inherited stack data": ORIGIN_INHERITED,
    "live VLEN-dependent stack frame": ORIGIN_LOCAL_FRAME,
    "live VLEN-dependent stack setup": ORIGIN_LOCAL_SETUP,
}


class CheckElfCollectTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.elf = Path(self.tmp.name) / "app.elf"
        self.elf.write_bytes(ELF_STUB_BYTES)

    def _collect(self, *, strategy="gate", text_bytes=None):
        result = collect_diagnostics(
            self.elf,
            objdump_cmd="objdump",
            min_vlen_bits=256,
            strategy=strategy,
            text_threshold=DEFAULT_TEXT_THRESHOLD,
            dump_text=DUMP,
            metadata=ChimeraMetadata.empty(),
        )
        if text_bytes is not None:
            result = type(result)(
                elf_path=result.elf_path,
                strategy=result.strategy,
                strategy_reason=result.strategy_reason,
                text_bytes=text_bytes,
                findings=result.findings,
                gate_names=result.gate_names,
                seed_host_starts=result.seed_host_starts,
                counts=result.counts,
                stack_object=result.stack_object,
            )
        return result

    def _collect_actionable(self, *, strategy="auto"):
        """Collect a non-residual warning for strategy-routing tests."""

        warning = AnalysisWarning(
            code="unresolved-active-indirect-call",
            message="unresolved active indirect call",
            function_start=0x10014,
            addresses=(0x10022,),
            details=("live stack object 0x1001E",),
        )
        stack_stub = SimpleNamespace(
            inherited_functions=set(),
            warnings=(warning,),
            inheritance_trace=SimpleNamespace(seed_edges=()),
        )
        with mock.patch("chimera.check_elf.StackLivenessAnalyzer") as analyzer:
            analyzer.return_value.analyze_program.return_value = stack_stub
            return collect_diagnostics(
                self.elf,
                objdump_cmd="objdump",
                min_vlen_bits=256,
                strategy=strategy,
                text_threshold=DEFAULT_TEXT_THRESHOLD,
                dump_text=DUMP,
                metadata=ChimeraMetadata.empty(),
            )

    def test_seed_edge_callers_are_gate_listed(self):
        # victim is an inherited carrier without vector code of its own, so
        # it stays off the gate list; only the seed-edge host is gated.  The
        # finding itself is still actionable under the corrected rule.
        result = self._collect()
        self.assertEqual(list(result.gate_names), ["seed_host"])
        self.assertIn(0x10014, result.seed_host_starts)

    def test_inherited_dispatch_is_attributed_to_victim(self):
        result = self._collect()
        kinds = {(finding.function, finding.kind) for finding in result.findings}
        self.assertIn(("victim", CAUSE_INHERITED), kinds)

    def test_inherited_host_without_vector_code_is_actionable_trace_target(self):
        # Corrected rule: "gating this host is a no-op" only proves the
        # finding must be traced back to its source — the finding stays
        # actionable, residual stays false, and the recommended action is
        # tracing the inheritance chain instead of gating this function.
        result = self._collect()
        self.assertNotIn("victim", result.gate_names)
        self.assertNotIn(0x10008, result.seed_host_starts)  # not a root
        self.assertEqual(result.counts["residual"], 0)
        self.assertEqual(result.counts["actionable"], 1)
        victim = next(f for f in result.findings if f.function == "victim")
        self.assertFalse(victim.residual)
        self.assertEqual(victim.recommended_action, ACTION_TRACE_SOURCE)
        self.assertTrue(has_actionable_findings(result))

    def test_quiet_function_is_not_gate_listed(self):
        result = self._collect()
        self.assertNotIn("quiet", result.gate_names)

    def test_plt_stubs_are_excluded_from_gate_list(self):
        # PLT stubs have no compilable definition; they must not enter the
        # gate list because global ELF validation can never apply them.
        plt_dump = DUMP.replace(
            "0000000000010008 <victim>:",
            "0000000000010008 <memcpy@plt>:",
        )
        result = collect_diagnostics(
            self.elf,
            objdump_cmd="objdump",
            min_vlen_bits=256,
            strategy="gate",
            text_threshold=DEFAULT_TEXT_THRESHOLD,
            dump_text=plt_dump,
            metadata=ChimeraMetadata.empty(),
        )
        self.assertEqual(list(result.gate_names), ["seed_host"])

    def test_plt_call_under_live_state_is_external_boundary(self):
        # A direct call into a PLT trampoline resolves to the external
        # symbol (build_log7: 39 of the 44 findings were trampolines whose
        # GOT-jump was misread as an unresolved indirect call).  Expected
        # Nothing propagates into the trampoline and its internal jalr is
        # not actionable. The stack-active caller now reports the external
        # boundary itself, while retaining its resolvable internal seed.
        plt_call_dump = DUMP.replace(
            "10008 <victim>", "10008 <memcpy@plt>"
        )
        result = collect_diagnostics(
            self.elf,
            objdump_cmd="objdump",
            min_vlen_bits=256,
            strategy="gate",
            text_threshold=DEFAULT_TEXT_THRESHOLD,
            dump_text=plt_call_dump,
            metadata=ChimeraMetadata.empty(),
        )
        self.assertEqual(len(result.findings), 1)
        self.assertEqual(result.findings[0].diagnostic_code, "active-external-call")
        self.assertEqual(result.findings[0].function, "seed_host")
        self.assertEqual(result.findings[0].external_targets, (0x10008,))
        self.assertEqual(list(result.gate_names), ["seed_host"])
        self.assertIn(0x10014, result.seed_host_starts)
        self.assertNotIn(0x10008, result.seed_host_starts)

    def test_quiet_function_never_warns(self):
        result = self._collect()
        self.assertTrue(all(f.function != "quiet" for f in result.findings))

    def test_strategy_gate_marks_disable_autovec_action(self):
        result = self._collect(strategy="gate")
        self.assertTrue(all(
            f.recommended_action == (
                ACTION_TRACE_SOURCE if f.kind == CAUSE_INHERITED
                else ACTION_DISABLE_AUTOVEC
            )
            for f in result.findings
        ))

    def test_strategy_svf_marks_metadata_action(self):
        result = self._collect(strategy="svf")
        self.assertTrue(all(
            f.recommended_action == (
                ACTION_TRACE_SOURCE if f.kind == CAUSE_INHERITED
                else ACTION_SVF_METADATA
            )
            for f in result.findings
        ))

    def test_decision_block_reflects_strategy(self):
        result = self._collect(strategy="gate")
        block = build_decision_block(result)
        self.assertTrue(block["vector_gate"]["enabled"])
        self.assertFalse(block["function_pointer_plugin"])
        self.assertFalse(block["stack_object_plugin"])
        self.assertIn("seed_host", block["gate"]["names"])

    def test_auto_strategy_uses_text_threshold(self):
        with mock.patch("chimera.check_elf._text_size", return_value=512):
            small = self._collect_actionable(strategy="auto")
        with mock.patch(
            "chimera.check_elf._text_size", return_value=2_000_000
        ):
            large = self._collect_actionable(strategy="auto")
        self.assertEqual(small.strategy, STRATEGY_SVF)
        self.assertEqual(large.strategy, STRATEGY_GATE)

    def test_report_preserves_actionable_counts(self):
        result = self._collect()
        report_path = Path(self.tmp.name) / "check.json"
        write_report(result, report_path, elf_identity={})
        report = json.loads(report_path.read_text())
        self.assertEqual(report["summary"]["findings_total"], 1)
        # Corrected rule: the pure-inherited finding is actionable too.
        self.assertEqual(report["summary"]["actionable"], 1)
        self.assertEqual(report["summary"]["residual"], 0)
        victim = next(
            finding for finding in report["findings"] if finding["function"] == "victim"
        )
        self.assertFalse(victim["residual"])
        self.assertEqual(victim["recommended_action"], ACTION_TRACE_SOURCE)


# Degradation/intrinsics side of the decision: irreducible-loop findings must
# switch on the StackObject metadata route, orthogonally to the pointer route.
QUIET_DUMP = """\
0000000000010000 <quiet>:
    10000:	9682                	jalr	a2
    10002:	8082                	ret
"""


class CheckElfStackObjectTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.elf = Path(self.tmp.name) / "app.elf"
        self.elf.write_bytes(ELF_STUB_BYTES)

    def _collect_with_stack(self, warnings, *, dump_text=DUMP):
        """Run collect_diagnostics against a crafted stack-liveness result."""

        stack_stub = SimpleNamespace(
            inherited_functions=set(),
            warnings=tuple(warnings),
            by_function={},
            inheritance_trace=SimpleNamespace(seed_edges=(), first_cause={}),
        )
        with mock.patch("chimera.check_elf.StackLivenessAnalyzer") as analyzer:
            analyzer.return_value.analyze_program.return_value = stack_stub
            return collect_diagnostics(
                self.elf,
                objdump_cmd="objdump",
                min_vlen_bits=256,
                strategy="auto",
                text_threshold=DEFAULT_TEXT_THRESHOLD,
                dump_text=dump_text,
                metadata=ChimeraMetadata.empty(),
            )

    @staticmethod
    def _degraded(function_start=0x10014, store=0x1001E):
        return AnalysisWarning(
            code=IRREDUCIBLE_DEGRADED,
            message="analysis degraded",
            function_start=function_start,
            addresses=(store,),
        )

    @staticmethod
    def _call(function_start, address, details, *, dependency="unknown"):
        """A crafted unresolved-call warning.

        ``details`` stays the human-readable prose; the structured origin next
        to it is what classification reads, and both are built together here
        exactly as the analysis builds them.
        """

        origins = []
        for detail in details:
            kind = _origin_of_detail(detail)
            origins.append(
                ActiveOrigin(
                    origin=kind,
                    object_source=kind,
                    object_id=detail,
                    detail=detail,
                    dependency=(
                        dependency if kind == ORIGIN_LOCAL_FRAME else None
                    ),
                )
            )
        origins = tuple(origins)
        return AnalysisWarning(
            code="unresolved-active-indirect-call",
            message="unresolved active indirect call",
            function_start=function_start,
            addresses=(address,),
            details=details,
            origins=origins,
        )

    def test_no_findings_select_none_route(self):
        result = self._collect_with_stack([], dump_text=QUIET_DUMP)
        self.assertEqual(result.findings, ())
        self.assertEqual(result.strategy, STRATEGY_NONE)
        self.assertFalse(result.stack_object)
        block = build_decision_block(result)
        self.assertFalse(block["vector_gate"]["enabled"])
        self.assertFalse(block["function_pointer_plugin"])
        self.assertFalse(block["stack_object_plugin"])

    def test_degradation_alone_switches_stack_object_on(self):
        result = self._collect_with_stack([self._degraded()])
        self.assertTrue(result.stack_object)
        block = build_decision_block(result)
        self.assertTrue(block["stack_object_plugin"])

    def test_existing_metadata_keeps_stack_object_sticky(self):
        # 迭代修复的防振荡不变量：产物已携带 stackobj_map（元数据模式生效，
        # 无降级警告）时决策必须保持插件开启，否则下一轮重编丢元数据、
        # 分析退化回 conservative/irreducible，决策在开/关间振荡。
        result = collect_diagnostics(
            self.elf,
            objdump_cmd="objdump",
            min_vlen_bits=256,
            strategy="gate",
            text_threshold=DEFAULT_TEXT_THRESHOLD,
            dump_text=QUIET_DUMP,
            metadata=ChimeraMetadata(
                stack_ids={0x10000: 1},
                has_stackobj_map_section=True,
            ),
        )
        self.assertTrue(result.stack_object)
        block = build_decision_block(result)
        self.assertTrue(block["stack_object_plugin"])

    def test_irreducible_only_findings_skip_pointer_route(self):
        result = self._collect_with_stack([
            self._degraded(),
            self._call(
                0x10008,
                0x1000A,
                ("live irreducible-loop marker: vector store(s) inside an "
                 "irreducible loop were degraded to conservative liveness",),
            ),
        ])
        self.assertEqual(len(result.findings), 1)
        finding = result.findings[0]
        self.assertEqual(finding.kind, CAUSE_IRREDUCIBLE)
        self.assertEqual(finding.recommended_action, ACTION_STACK_OBJECT)
        self.assertEqual(result.strategy, STRATEGY_NONE)
        self.assertTrue(result.stack_object)
        block = build_decision_block(result)
        self.assertFalse(block["vector_gate"]["enabled"])
        self.assertFalse(block["function_pointer_plugin"])
        self.assertTrue(block["stack_object_plugin"])

    def test_inherited_only_findings_still_route_pointer_analysis(self):
        # Corrected rule: a pure-inherited finding is actionable; the pointer
        # route must stay engaged (gate for large code), and the recommended
        # action is tracing the source rather than gating the quiet host.
        with mock.patch(
            "chimera.check_elf._text_size", return_value=2_000_000
        ):
            result = self._collect_with_stack([
                self._call(0x10000, 0x10000, ()),
            ], dump_text=QUIET_DUMP)
        self.assertEqual(result.strategy, STRATEGY_GATE)
        self.assertTrue(has_actionable_findings(result))
        self.assertEqual(result.gate_names, ())
        self.assertEqual(
            result.findings[0].recommended_action, ACTION_TRACE_SOURCE
        )

    def test_inherited_seed_with_only_unknown_setup_stays_pending(self):
        start, site = 0x10014, 0x10022
        for source in ("vlen_stack_frame", "vlen_stack_setup"):
            with self.subTest(source=source):
                local = SimpleNamespace(
                    live_before={site: frozenset({
                        StackObjectId("caller", 0), StackObjectId(source, 0),
                    })},
                    frame_origins=(AllocationOrigin(
                        source="vlen_stack_frame", adjustment=site + 6,
                        dependency="unknown",
                    ),),
                )
                edge = SimpleNamespace(caller_function_start=start, call_site=site)
                stack_stub = SimpleNamespace(
                    inherited_functions={0x10004}, warnings=(),
                    by_function={start: local},
                    inheritance_trace=SimpleNamespace(seed_edges=(edge,), first_cause={}),
                )
                with mock.patch("chimera.check_elf.StackLivenessAnalyzer") as analyzer:
                    analyzer.return_value.analyze_program.return_value = stack_stub
                    result = collect_diagnostics(
                        self.elf, objdump_cmd="objdump", strategy="gate",
                        text_threshold=DEFAULT_TEXT_THRESHOLD, dump_text=DUMP,
                        metadata=ChimeraMetadata.empty(),
                    )
                self.assertNotIn(start, result.seed_host_starts)
                self.assertNotIn("seed_host", result.gate_names)
                self.assertEqual(result.counts["pending_proof"], 1)

    def test_known_local_seed_sources_remain_gate_eligible(self):
        start, site = 0x10014, 0x10022
        for source in ("compiler", "irreducible", "known-vlen-setup"):
            with self.subTest(source=source):
                object_source = (
                    "vlen_stack_setup" if source == "known-vlen-setup" else source
                )
                local = SimpleNamespace(
                    live_before={site: frozenset({StackObjectId(object_source, 1)})},
                    frame_origins=(
                        (AllocationOrigin(
                            source="vlen_stack_frame", adjustment=0x10028,
                            dependency="vlen",
                        ),)
                        if source == "known-vlen-setup" else ()
                    ),
                )
                edge = SimpleNamespace(caller_function_start=start, call_site=site)
                stack_stub = SimpleNamespace(
                    inherited_functions=set(), warnings=(), by_function={start: local},
                    inheritance_trace=SimpleNamespace(seed_edges=(edge,), first_cause={}),
                )
                with mock.patch("chimera.check_elf.StackLivenessAnalyzer") as analyzer:
                    analyzer.return_value.analyze_program.return_value = stack_stub
                    result = collect_diagnostics(
                        self.elf, objdump_cmd="objdump", strategy="gate",
                        text_threshold=DEFAULT_TEXT_THRESHOLD, dump_text=DUMP,
                        metadata=ChimeraMetadata.empty(),
                    )
                self.assertIn(start, result.seed_host_starts)

    def test_real_analysis_collects_local_seed_on_inherited_caller(self):
        dump = """\
0000000000010000 <a_source>:
    10000: 0d007057           vsetivli zero,16,e64,m4,ta,ma
    10004: 7131                 addi sp,sp,-128
    10006: 84b2                 mv s1,sp
    10008: 0294302b           vs4r.v v9,(s1)
    1000c: 015000ef           jal ra,10020 <b_source>
    10010: 2284b787           vl4re64.v v10,(s1)
    10014: 8082                 ret

0000000000010020 <b_source>:
    10020: 0d007057           vsetivli zero,16,e64,m4,ta,ma
    10024: 7131                 addi sp,sp,-128
    10026: 84b2                 mv s1,sp
    10028: 0294302b           vs4r.v v9,(s1)
    1002c: 015000ef           jal ra,10040 <c_unknown>
    10030: 2284b787           vl4re64.v v10,(s1)
    10034: 8082                 ret

0000000000010040 <c_unknown>:
    10040: 9682                 jalr a2
    10042: 8082                 ret
"""
        result = collect_diagnostics(
            self.elf, objdump_cmd="objdump", strategy="gate",
            text_threshold=DEFAULT_TEXT_THRESHOLD, dump_text=dump,
            metadata=ChimeraMetadata.empty(),
        )
        self.assertEqual(result.seed_host_starts, (0x10000, 0x10020))
        self.assertEqual(result.gate_names, ("a_source", "b_source"))
        self.assertEqual(result.counts["actionable"], 1)

    def test_mixed_findings_combine_gate_and_stack_object(self):
        with mock.patch(
            "chimera.check_elf._text_size", return_value=2_000_000
        ):
            result = self._collect_with_stack([
                self._degraded(),
                self._call(
                    0x10014, 0x10022, ("live stack object 0x1001E",),
                ),
                self._call(
                    0x10008,
                    0x1000A,
                    ("live irreducible-loop marker: degraded",),
                ),
            ])
        actions = {f.kind: f.recommended_action for f in result.findings}
        # Deliberate change: under the gate strategy an irreducible source
        # whose host this run put on the gate list is discharged by that
        # decision, so the action names the gate step instead of "re-add the
        # stack-object plugin".  The stack-object decision switch itself is
        # unaffected (asserted below).
        self.assertEqual(actions[CAUSE_IRREDUCIBLE], ACTION_DISABLE_AUTOVEC)
        self.assertTrue(result.findings[
            [f.kind for f in result.findings].index(CAUSE_IRREDUCIBLE)
        ].gate_listed)
        self.assertEqual(len(result.findings), 2)
        self.assertEqual(result.strategy, STRATEGY_GATE)
        self.assertTrue(result.stack_object)
        block = build_decision_block(result)
        self.assertTrue(block["vector_gate"]["enabled"])
        self.assertTrue(block["stack_object_plugin"])
        self.assertFalse(block["function_pointer_plugin"])
        non_irreducible = [
            f for f in result.findings if f.kind != CAUSE_IRREDUCIBLE
        ]
        self.assertTrue(all(
            f.recommended_action == ACTION_DISABLE_AUTOVEC
            for f in non_irreducible
        ))

class ReportRegressionTests(unittest.TestCase):
    """Pin the full diagnostic output against a fixed expected report.

    The reference below intentionally encodes the CORRECTED residual
    semantics: pure caller-inherited findings are actionable
    (residual=False, recommended_action=trace-inheritance-source) and the
    actionable count equals the findings count.  This replaces the legacy
    accept-residual expectation as a deliberate semantic correction.
    """

    # Reference output of the corrected implementation on the DUMP fixture.
    EXPECTED = {
        "strategy": "gate",
        "strategy_reason": "forced via --strategy",
        "text_bytes": None,
        "findings": [
            {
                "kind": "inherited",
                "function": "victim",
                "call_site": "0x1000a",
                "recommended_action": "trace-inheritance-source",
                "support": [
                    "live caller-inherited stack data: an earlier active "
                    "call propagated live vector stack state into this frame"
                ],
                "origin_status": "inherited",
                "residual": False,
            }
        ],
        "gate_names": ["seed_host"],
        "seed_host_starts": [65556],
        "counts": {
            "active_external_calls": 0,
        "closed_external_calls": 0,
            "local_root": 0,
            "inherited": 1,
            "conservative": 0,
            "irreducible": 0,
            # "a VLEN source exists" and "the source is not proven" are
            # reported separately; both keep the finding.
            "local_vlen_source": 0,
            "local_unproven": 0,
            "pending_proof": 0,
            "residual": 0,
            "actionable": 1,
            "proof_nodes": 0,
            "proof_gaps": 0,
            "proof_budget_exhausted": False,
        },
        "stack_object": False,
        "decision": {
            "strategy": "gate",
            "vector_gate": {
                "enabled": True,
                "names_source": "report:findings(root-hosts+inherited-hosts)",
            },
            "function_pointer_plugin": False,
            "stack_object_plugin": False,
            "gate": {"enabled": True, "names": ["seed_host"]},
        },
    }

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.elf = Path(self.tmp.name) / "app.elf"
        self.elf.write_bytes(ELF_STUB_BYTES)

    def _payload(self, result):
        return {
            "strategy": result.strategy,
            "strategy_reason": result.strategy_reason,
            "text_bytes": result.text_bytes,
            "findings": [
                {
                    "kind": f.kind,
                    "function": f.function,
                    "call_site": f.call_site,
                    "recommended_action": f.recommended_action,
                    "support": list(f.support),
                    "origin_status": f.origin_status,
                    "residual": f.residual,
                }
                for f in result.findings
            ],
            "gate_names": list(result.gate_names),
            "counts": dict(result.counts),
            "stack_object": result.stack_object,
            "seed_host_starts": list(result.seed_host_starts),
            "decision": build_decision_block(result),
        }

    def test_report_matches_legacy_reference(self):
        result = collect_diagnostics(
            self.elf,
            objdump_cmd="objdump",
            min_vlen_bits=256,
            strategy="gate",
            text_threshold=DEFAULT_TEXT_THRESHOLD,
            dump_text=DUMP,
            metadata=ChimeraMetadata.empty(),
        )
        self.assertEqual(self._payload(result), self.EXPECTED)




class CheckElfInheritanceDiagnosticsTests(unittest.TestCase):
    """Regression tests for the corrected residual rule + --inheritance-report."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.elf = Path(self.tmp.name) / "app.elf"
        self.elf.write_bytes(ELF_STUB_BYTES)

    def _collect(self, dump_text=DUMP, strategy="gate"):
        return collect_diagnostics(
            self.elf,
            objdump_cmd="objdump",
            min_vlen_bits=256,
            strategy=strategy,
            text_threshold=DEFAULT_TEXT_THRESHOLD,
            dump_text=dump_text,
            metadata=ChimeraMetadata.empty(),
        )

    # --- A: active state + vectorless B with unresolved call => must fail ----
    def test_pure_inherited_finding_fails_check(self):
        result = self._collect()
        self.assertTrue(has_actionable_findings(result))
        victim = next(f for f in result.findings if f.function == "victim")
        self.assertFalse(victim.residual)
        self.assertEqual(victim.kind, CAUSE_INHERITED)

    def test_check_fails_and_strict_sets_nonzero(self):
        from chimera.check_elf import safety_binary_check_request

        request = safety_binary_check_request(
            {"min_vlen_bits": 256, "compiler_metadata": ()}
        )
        context = SimpleNamespace(
            configuration=SimpleNamespace(base=SimpleNamespace(tools=None)),
            objdump_cmd="objdump",
            overrides={"strategy": "gate", "text_threshold": DEFAULT_TEXT_THRESHOLD},
        )
        with mock.patch(
            "chimera.check_elf.collect_diagnostics",
            return_value=self._collect(),
        ), mock.patch(
            "chimera.check_elf.ChimeraMetadata.from_elf",
            return_value=ChimeraMetadata.empty(),
        ):
            outcome = request.runner(self.elf, context)
        self.assertFalse(outcome.passed)
        self.assertTrue(outcome.actionable)
        self.assertEqual(outcome.diagnostics["summary"]["residual"], 0)
        self.assertEqual(outcome.diagnostics["summary"]["actionable"], 1)

    # --- B: source active state removed => propagation finding disappears ----
    def test_removing_seed_activity_clears_inherited_finding(self):
        quiet = DUMP.replace(
            "    10018:\tcd817057          \tvsetivli\tzero,16,e64,m4,ta,ma\n",
            "",
        ).replace(
            "    1001e:\t0294302b          \tvs4r.v\tv9,(s1)\n", ""
        ).replace(
            "    10026:\t2284b787          \tvl4re64.v\tv10,(s1)\n", ""
        ).replace(
            "    1002e:\t2284d787          \tvl4re64.v\tv11,(s1)\n", ""
        )
        result = self._collect(dump_text=quiet)
        self.assertEqual(result.findings, ())
        self.assertFalse(has_actionable_findings(result))
    # --- two converging sources: removing only one still fails ----------------
    def test_two_sources_removing_one_keeps_finding(self):
        second_seed = (
            "\n0000000000010040 <seed_host2>:\n"
            "    10040:\t7131                \taddi\tsp,sp,-128\n"
            "    10042:\tf406                \tsd\tra,120(sp)\n"
            "    10044:\tcd817057          \tvsetivli\tzero,16,e64,m4,ta,ma\n"
            "    10048:\t84b2                \tmv\ts1,sp\n"
            "    1004a:\t0294302b          \tvs4r.v\tv9,(s1)\n"
            "    1004e:\te05ff0ef          \tjal\tra,10004 <callee>\n"
            "    10052:\t2284b787          \tvl4re64.v\tv10,(s1)\n"
            "    10056:\te09ff0ef          \tjal\tra,10008 <victim>\n"
            "    1005a:\t2284d787          \tvl4re64.v\tv11,(s1)\n"
            "    1005e:\t60a6                \tld\tra,120(sp)\n"
            "    10060:\t6145                \taddi\tsp,sp,128\n"
            "    10062:\t8082                \tret\n"
        )
        result = self._collect(dump_text=DUMP + second_seed)
        self.assertTrue(has_actionable_findings(result))
        self.assertIn("seed_host2", result.gate_names)
        victim = next(f for f in result.findings if f.function == "victim")
        self.assertFalse(victim.residual)

    # --- recursion / multi-layer propagation terminates ----------------------
    def test_recursive_inheritance_terminates(self):
        dump = DUMP.replace(
            "    1000a:\t9682                \tjalr\ta3",
            "    1000a:\te05ff0ef          \tjal\tra,10008 <victim>",
        )
        result = self._collect(dump_text=dump)
        # Direct recursive call resolves; the analysis must terminate.
        self.assertEqual(result.counts["inherited"], 0)

    def test_export_inheritance_report(self):
        from chimera.elf_state import sha256_of

        result = self._collect()
        report_path = Path(self.tmp.name) / "inheritance.json"
        export_inheritance_diagnostics(
            result,
            report_path,
            content_hash=sha256_of(self.elf),
        )
        document = json.loads(report_path.read_text(encoding="utf-8"))
        self.assertEqual(
            document["format"], "chimera-inheritance-diagnostics-v2"
        )
        # The compatibility block spells out what a v1 consumer must handle
        # instead of leaving it to guess from the version string.
        self.assertEqual(
            document["format_compatibility"]["from"],
            "chimera-inheritance-diagnostics-v1",
        )
        for key in (
            "proof_table",
            "proof_gaps",
            "proof_budget_exhausted",
            "pending_proof_refs",
        ):
            with self.subTest(key=key):
                self.assertIn(key, document)
        self.assertIn("activity_origins", document["findings"][0])
        self.assertIn("origin_status", document["findings"][0])
        self.assertEqual(document["closure_size"], 2)
        self.assertEqual(len(document["seed_edges"]), 2)
        seed = next(
            e for e in document["seed_edges"] if e["call_site"] == "0x1002a"
        )
        self.assertEqual(seed["reason"], "seed")
        self.assertTrue(seed["local_active_objects"])
        self.assertEqual(len(document["findings"]), 1)
        finding = document["findings"][0]
        self.assertEqual(finding["function"], "victim")
        self.assertEqual(finding["call_site"], "0x1000a")
        self.assertFalse(finding["diagnostics_incomplete"])
        witness = finding["witness_path"]
        self.assertEqual(len(witness), 1)
        self.assertEqual(document["seed_edges"][witness[0]]["call_site"], "0x1002a")
        functions = {entry["name"] for entry in document["functions"]}
        self.assertIn("seed_host", functions)
        self.assertIn("victim", functions)

    def test_inheritance_report_does_not_change_analysis(self):
        from chimera.elf_state import sha256_of

        base = self._collect()
        out = Path(self.tmp.name) / "inheritance.json"
        export_inheritance_diagnostics(
            base, out, content_hash=sha256_of(self.elf)
        )
        self.assertTrue(out.is_file())
        self.assertEqual(len(base.findings), 1)
        self.assertEqual(base.counts["actionable"], 1)

    # --- P2: a non-empty witness path that never reaches a seed is incomplete -
    def test_broken_chain_witness_is_marked_incomplete(self):
        from chimera.check_elf import (
            _InheritanceAnalysis,
            _build_inheritance_diagnostics,
        )
        from chimera.preprocess.offline.analysis.safety.stack_liveness.model import (
            InheritanceEdge,
        )

        result = self._collect()
        stack = result.analysis.stack
        # Break the chain: replace every seed-reason first-cause edge with a
        # pure-inherited edge, so walking the trace never reaches a seed.
        broken_trace = type(stack.inheritance_trace)(
            seed_edges=(),
            first_cause={
                start: InheritanceEdge(
                    caller_function_start=edge.caller_function_start,
                    call_site=edge.call_site,
                    reason="inherited",
                    depth=edge.depth,
                )
                for start, edge in stack.inheritance_trace.first_cause.items()
            },
        )
        broken_stack = type(stack)(
            by_function=stack.by_function,
            inherited_functions=stack.inherited_functions,
            warnings=stack.warnings,
            unresolved_live_calls=stack.unresolved_live_calls,
            inheritance_trace=broken_trace,
        )
        broken = type(result)(
            elf_path=result.elf_path,
            strategy=result.strategy,
            strategy_reason=result.strategy_reason,
            text_bytes=result.text_bytes,
            findings=result.findings,
            gate_names=result.gate_names,
            seed_host_starts=result.seed_host_starts,
            counts=result.counts,
            stack_object=result.stack_object,
            pure_inherited_starts=result.pure_inherited_starts,
            analysis=_InheritanceAnalysis(
                program=result.analysis.program,
                stack=broken_stack,
                metadata=result.analysis.metadata,
                warning_starts_by_site=result.analysis.warning_starts_by_site,
                warning_details_by_site=result.analysis.warning_details_by_site,
            ),
        )
        document = _build_inheritance_diagnostics(broken, "0" * 64)
        self.assertEqual(len(document["findings"]), 1)
        finding = document["findings"][0]
        # The path is non-empty but never reaches a seed: must be incomplete.
        self.assertTrue(finding["witness_path"])
        self.assertFalse(finding["witness_reached_seed"])
        self.assertTrue(finding["diagnostics_incomplete"])
        # The incomplete diagnostic never softens the check itself.
        self.assertTrue(has_actionable_findings(broken))

    def test_local_root_witness_is_complete_by_construction(self):
        from chimera.check_elf import _build_inheritance_diagnostics

        document = _build_inheritance_diagnostics(self._collect(), "0" * 64)
        for finding in document["findings"]:
            self.assertIn("witness_reached_seed", finding)
        # The DUMP fixture has one inherited finding with a complete witness.
        inherited = [f for f in document["findings"] if f["kind"] == "inherited"]
        self.assertEqual(len(inherited), 1)
        self.assertTrue(inherited[0]["witness_reached_seed"])
        self.assertFalse(inherited[0]["diagnostics_incomplete"])

    # --- P1: credentials recorded under the old check version must be rejected -
    def test_previous_version_credential_is_rejected(self):
        from chimera.check_elf import safety_binary_check_request
        from chimera.elf_state import CHECKED, ElfStateRegistry, sha256_of
        from chimera.preprocess.offline.analysis_profile.checks import (
            BinaryCheckPlan,
            check_admission,
        )

        request = safety_binary_check_request(
            {"min_vlen_bits": 256, "compiler_metadata": ()}
        )
        # ... and now the per-function metadata-coverage rule: a
        # VLEN-sensitive access without a stack-object record is no longer
        # dropped, so a half-instrumented product does not look clean any
        # more.  Sources v18 discarded reappear, so the credential version
        # moved from 18 to 19, and local seed provenance now has its own
        # version boundary for inheritance and unknown-only VLEN setup.
        from chimera.preprocess.offline.analysis.safety.stack_liveness.origins import (
            ORIGIN_ANALYSIS_VERSION,
        )

        self.assertEqual(ORIGIN_ANALYSIS_VERSION, "origins-v16")
        self.assertEqual(request.version, 31)

        registry = ElfStateRegistry(Path(self.tmp.name) / "states.json")
        elf_path = self.elf.resolve()
        content_hash = sha256_of(elf_path)

        configuration = SimpleNamespace(
            profile=SimpleNamespace(
                target_os="linux",
                target_arch="riscv64",
                target_arch_extension="rvv",
                runtime_scene="linux_riscv64_rvv_v1",
                runtime_abi=1,
            )
        )
        old_request = type(request)(
            check_id=request.check_id,
            version=30,
            parameters=request.parameters,
            runner=request.runner,
        )
        old_plan = BinaryCheckPlan(
            configuration=configuration,
            target_key=("linux", "riscv64", "rvv", "linux_riscv64_rvv_v1"),
            runtime_abi=1,
            requests=(old_request,),
        )
        # Version 31 corrects the synthetic all-cache use at complete internal
        # ABI exits. Version 30 credentials cannot admit this different
        # classification without an actual fresh check.
        registry.set_status(
            elf_path,
            CHECKED,
            decision_ref="legacy-report.json",
            check_fingerprint=old_plan.fingerprint(content_hash),
            check_scope=old_plan.scope,
            require_file=True,
        )
        new_plan = BinaryCheckPlan(
            configuration=configuration,
            target_key=("linux", "riscv64", "rvv", "linux_riscv64_rvv_v1"),
            runtime_abi=1,
            requests=(request,),
        )
        # The old CHECKED credential must NOT admit the new-rule workflow.
        with self.assertRaises(RuntimeError):
            check_admission(elf_path, new_plan, registry=registry)

    def test_check_fingerprint_binds_unknown_stack_size_policy(self):
        from chimera.check_elf import safety_binary_check_request
        from chimera.elf_state import CHECKED, ElfStateRegistry, sha256_of
        from chimera.preprocess.offline.analysis_profile.checks import BinaryCheckPlan
        from chimera.preprocess.offline.analysis_profile.checks import check_admission

        conservative = safety_binary_check_request(
            {"min_vlen_bits": 256, "compiler_metadata": ()}
        )
        self.assertIn("unknown_stack_size_policy", conservative.parameters)
        scoped = safety_binary_check_request(
            {
                "min_vlen_bits": 256,
                "compiler_metadata": (),
                "unknown_stack_size_policy": "assume-scalar-independent",
            }
        )
        configuration = SimpleNamespace(
            profile=SimpleNamespace(
                target_os="linux",
                target_arch="riscv64",
                target_arch_extension="rvv",
                runtime_scene="linux_riscv64_rvv_v1",
                runtime_abi=1,
            )
        )

        conservative_plan = BinaryCheckPlan(
            configuration=configuration,
            target_key=("linux", "riscv64", "rvv", "linux_riscv64_rvv_v1"),
            runtime_abi=1,
            requests=(conservative,),
        )
        scoped_plan = BinaryCheckPlan(
            configuration=configuration,
            target_key=("linux", "riscv64", "rvv", "linux_riscv64_rvv_v1"),
            runtime_abi=1,
            requests=(scoped,),
        )

        self.assertEqual(conservative.version, 31)
        self.assertEqual(conservative.parameters["unknown_stack_size_policy"], "conservative")
        self.assertNotEqual(
            conservative_plan.fingerprint("0" * 64),
            scoped_plan.fingerprint("0" * 64),
        )
        registry = ElfStateRegistry(Path(self.tmp.name) / "states.json")
        registry.set_status(
            self.elf,
            CHECKED,
            decision_ref="conservative-report.json",
            check_fingerprint=conservative_plan.fingerprint(sha256_of(self.elf)),
            check_scope=conservative_plan.scope,
            require_file=True,
        )
        with self.assertRaisesRegex(RuntimeError, "scope does not match"):
            check_admission(self.elf, scoped_plan, registry=registry)
        reverse_registry = ElfStateRegistry(Path(self.tmp.name) / "reverse-states.json")
        reverse_registry.set_status(
            self.elf,
            CHECKED,
            decision_ref="scoped-report.json",
            check_fingerprint=scoped_plan.fingerprint(sha256_of(self.elf)),
            check_scope=scoped_plan.scope,
            require_file=True,
        )
        with self.assertRaisesRegex(RuntimeError, "scope does not match"):
            check_admission(self.elf, conservative_plan, registry=reverse_registry)

    def test_unknown_only_function_is_reported_as_conditional_scope_exclusion(self):
        from chimera.check_elf import (
            DiagnosticsResult,
            _InheritanceAnalysis,
            _build_inheritance_diagnostics,
        )
        from chimera.preprocess.offline.analysis.core.data_model import (
            Function,
            Instruction,
            Program,
        )
        from chimera.preprocess.offline.analysis.safety.stack_liveness.model import (
            InheritanceTrace,
        )

        instruction = Instruction(0x1000, 4, "sub", ["sp", "sp", "a0"], "sub sp,sp,a0")
        function = Function("unknown_only", 0x1000, [instruction])
        program = Program(
            dump_lines=[], functions=[function], instructions=[instruction],
            instruction_by_address={instruction.addr: instruction},
        )
        exclusion = SimpleNamespace(
            source="vlen_stack_frame",
            function_start=0x1000,
            adjustment=0x1000,
            dependency="unknown",
            size_register="a0",
            disposition="assumption",
            assumption="assume-scalar-independent",
            proof=None,
            gaps=("unproven",),
        )
        local = SimpleNamespace(
            frame_origins=(),
            scope_exclusions=(exclusion,),
            live_before={},
        )
        stack = SimpleNamespace(
            by_function={function.start: local},
            inherited_functions=frozenset(),
            warnings=(),
            inheritance_trace=InheritanceTrace(),
            origin_proofs={},
            origin_gaps=(),
            proof_budget_exhausted=False,
            unknown_stack_size_policy="assume-scalar-independent",
            assumption="Unknown scalar stack sizes are assumed independent of VLEN.",
            conditional=True,
        )
        analysis = _InheritanceAnalysis(program, stack, ChimeraMetadata.empty())
        diagnostics = DiagnosticsResult(
            elf_path=self.elf,
            strategy="none",
            strategy_reason="no findings",
            text_bytes=None,
            findings=(),
            gate_names=(),
            analysis=analysis,
        )

        document = _build_inheritance_diagnostics(diagnostics, "0" * 64)

        self.assertIn("conditional", document)
        self.assertTrue(document["conditional"])
        self.assertEqual(
            document["unknown_stack_size_policy"], "assume-scalar-independent"
        )
        self.assertEqual(document["scope_exclusion_count"], 1)
        self.assertEqual(len(document["functions"]), 1)
        self.assertEqual(
            document["functions"][0]["scope_exclusions"][0]["dependency"],
            "unknown",
        )

    def test_check_report_promotes_scope_fields_from_diagnostics(self):
        from chimera.check_elf import write_check_report
        from chimera.preprocess.offline.analysis_profile.checks import (
            BinaryCheckOutcome,
            BinaryCheckPlan,
            BinaryCheckPlanResult,
            BinaryCheckRequest,
        )

        request = BinaryCheckRequest(
            "safety.stack-liveness",
            21,
            {"unknown_stack_size_policy": "assume-scalar-independent"},
            lambda _path, _context: None,
        )
        outcome = BinaryCheckOutcome(
            passed=True,
            diagnostics={
                "unknown_stack_size_policy": "assume-scalar-independent",
                "assumption": "Unknown scalar stack sizes are assumed independent of VLEN.",
                "conditional": True,
                "scope_exclusion_count": 1,
            },
        )
        result = BinaryCheckPlanResult(True, ((request, outcome),), {})
        profile = SimpleNamespace(
            target_os="linux",
            target_arch="riscv64",
            target_arch_extension="rvv",
            runtime_scene="linux_riscv64_rvv_v1",
        )
        plan = BinaryCheckPlan(
            configuration=SimpleNamespace(profile=profile),
            target_key=("linux", "riscv64", "rvv", "linux_riscv64_rvv_v1"),
            runtime_abi=1,
            requests=(request,),
        )

        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "check.json"
            write_check_report(
                plan,
                result,
                path,
                elf_identity={"path": "fixture.elf", "content_sha256": "0" * 64},
            )
            report = json.loads(path.read_text(encoding="utf-8"))

        self.assertIn("conditional", report)
        self.assertTrue(report["conditional"])
        self.assertEqual(
            report["unknown_stack_size_policy"], "assume-scalar-independent"
        )

    def test_version_17_credential_is_rejected(self):
        """A version-17 credential is rejected for the same reason.

        17 is the version that predates the CFG-input-semantics change; it is
        pinned separately from 18 so that the "one version back" case and the
        "two versions back" case stay distinguishable if either regresses.
        """

        from chimera.check_elf import safety_binary_check_request
        from chimera.elf_state import CHECKED, ElfStateRegistry, sha256_of
        from chimera.preprocess.offline.analysis_profile.checks import (
            BinaryCheckPlan,
            check_admission,
        )

        request = safety_binary_check_request(
            {"min_vlen_bits": 256, "compiler_metadata": ()}
        )
        registry = ElfStateRegistry(Path(self.tmp.name) / "states-v17.json")
        elf_path = self.elf.resolve()
        configuration = SimpleNamespace(
            profile=SimpleNamespace(
                target_os="linux",
                target_arch="riscv64",
                target_arch_extension="rvv",
                runtime_scene="linux_riscv64_rvv_v1",
                runtime_abi=1,
            )
        )
        old_request = type(request)(
            check_id=request.check_id,
            version=17,
            parameters=request.parameters,
            runner=request.runner,
        )
        old_plan = BinaryCheckPlan(
            configuration=configuration,
            target_key=("linux", "riscv64", "rvv", "linux_riscv64_rvv_v1"),
            runtime_abi=1,
            requests=(old_request,),
        )
        registry.set_status(
            elf_path,
            CHECKED,
            decision_ref="legacy-report.json",
            check_fingerprint=old_plan.fingerprint(sha256_of(elf_path)),
            check_scope=old_plan.scope,
            require_file=True,
        )
        new_plan = BinaryCheckPlan(
            configuration=configuration,
            target_key=("linux", "riscv64", "rvv", "linux_riscv64_rvv_v1"),
            runtime_abi=1,
            requests=(request,),
        )
        with self.assertRaises(RuntimeError):
            check_admission(elf_path, new_plan, registry=registry)

    def test_oldest_version_credential_is_rejected(self):
        """A version-1 credential is rejected for the same reason."""

        from chimera.check_elf import safety_binary_check_request
        from chimera.elf_state import CHECKED, ElfStateRegistry, sha256_of
        from chimera.preprocess.offline.analysis_profile.checks import (
            BinaryCheckPlan,
            check_admission,
        )

        request = safety_binary_check_request(
            {"min_vlen_bits": 256, "compiler_metadata": ()}
        )
        registry = ElfStateRegistry(Path(self.tmp.name) / "states-v1.json")
        elf_path = self.elf.resolve()
        configuration = SimpleNamespace(
            profile=SimpleNamespace(
                target_os="linux",
                target_arch="riscv64",
                target_arch_extension="rvv",
                runtime_scene="linux_riscv64_rvv_v1",
                runtime_abi=1,
            )
        )
        old_request = type(request)(
            check_id=request.check_id,
            version=1,
            parameters=request.parameters,
            runner=request.runner,
        )
        old_plan = BinaryCheckPlan(
            configuration=configuration,
            target_key=("linux", "riscv64", "rvv", "linux_riscv64_rvv_v1"),
            runtime_abi=1,
            requests=(old_request,),
        )
        registry.set_status(
            elf_path,
            CHECKED,
            decision_ref="legacy-report.json",
            check_fingerprint=old_plan.fingerprint(sha256_of(elf_path)),
            check_scope=old_plan.scope,
            require_file=True,
        )
        new_plan = BinaryCheckPlan(
            configuration=configuration,
            target_key=("linux", "riscv64", "rvv", "linux_riscv64_rvv_v1"),
            runtime_abi=1,
            requests=(request,),
        )
        with self.assertRaises(RuntimeError):
            check_admission(elf_path, new_plan, registry=registry)

    # --- P3: --strict actually drives the CLI exit code -----------------------
    def test_cli_strict_exit_codes(self):
        from chimera import cli as cli_module

        class _Plan:
            scope = {"checks": []}
            target_key = ("linux", "riscv64", "rvv", "linux_riscv64_rvv_v1")
            runtime_abi = 1
            requests = (SimpleNamespace(
                check_id="safety.stack-liveness",
                version=15,
                parameters={"min_vlen_bits": 256, "compiler_metadata": ()},
                requested_by=("005:safety",),
            ),)

            def __init__(self, passed):
                self._passed = passed

            def run(self, path, *, objdump_cmd=None, overrides=None):
                outcome = SimpleNamespace(
                    passed=self._passed,
                    actionable=not self._passed,
                    diagnostics={"summary": {}, "strategy_reason": "test"},
                    message="",
                )
                decision = {
                    "strategy": "gate",
                    "vector_gate": {"enabled": True},
                    "function_pointer_plugin": False,
                    "stack_object_plugin": False,
                    "gate": {"enabled": True, "names": []},
                }
                return SimpleNamespace(
                    passed=self._passed,
                    outcomes=((self.requests[0], outcome),),
                    decision=decision,
                    message="",
                )

            def fingerprint(self, digest):
                return digest

        def run_cli(passed, strict):
            arguments = SimpleNamespace(
                profile=None,
                input_elf=self.elf,
                strategy="gate",
                min_vlen_bits=None,
                text_threshold=DEFAULT_TEXT_THRESHOLD,
                objdump=None,
                json=Path(self.tmp.name) / "report.json",
                inheritance_report=None,
                strict=strict,
            )
            with mock.patch.object(
                cli_module, "_configuration", return_value=SimpleNamespace()
            ), mock.patch.object(
                cli_module, "build_check_plan", return_value=_Plan(passed)
            ), mock.patch(
                "chimera.elf_state.ElfStateRegistry.set_status", return_value=None
            ), mock.patch(
                "chimera.cli.write_latest_pointer", return_value=None
            ):
                return cli_module._check_elf(arguments)

        self.assertEqual(run_cli(passed=False, strict=True), 1)
        self.assertEqual(run_cli(passed=False, strict=False), 0)
        self.assertEqual(run_cli(passed=True, strict=True), 0)


if __name__ == "__main__":
    unittest.main()
