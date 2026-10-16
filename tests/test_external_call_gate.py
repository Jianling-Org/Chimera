"""Static boundary checks use production propagation and ELF diagnostics."""

from __future__ import annotations

import io
import tempfile
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from unittest import mock

from chimera.check_elf import (
    ACTION_DISABLE_AUTOVEC, ACTION_TRACE_SIZE_SOURCE, ACTION_TRACE_SOURCE,
    _build_inheritance_diagnostics, _diagnostics_payload, build_decision_block,
    collect_diagnostics, has_actionable_findings, write_report,
)
from chimera.preprocess.offline.analysis.arch.riscv.rvv import RvvServices
from chimera.preprocess.offline.analysis.core.data_model import Function, Instruction, Program
from chimera.preprocess.offline.analysis.safety.stack_liveness.liveness import (
    _CallerStackContextPropagator,
)
from chimera.preprocess.offline.analysis.safety.stack_liveness.model import (
    CallTargetEntry, ChimeraMetadata, ORIGIN_INHERITED, ORIGIN_VECTOR_DATA,
    StackFunctionLiveness, StackObjectId,
)
from chimera.preprocess.offline.analysis.safety.step import _emit_stack_warnings


EXTERNAL = "active-external-call"
UNKNOWN = "unresolved-active-indirect-call"


def _call(address, target=None, *, op="jal", args=None):
    args = args if args is not None else ["ra", hex(target)] if target is not None else ["t2"]
    return Instruction(address, 4, op, args, op + " " + ",".join(args),
                       jump_targets={target} if target is not None else set())


def _function(start, *instructions, plt=False):
    return Function(f"f_{start:x}", start, list(instructions), is_external_trampoline=plt)


def _propagate(functions, activity, metadata=None):
    instructions = [inst for function in functions for inst in function.insts]
    program = Program([], list(functions), instructions,
                      {inst.addr: inst for inst in instructions})
    obj = StackObjectId("compiler", 1)
    local = {
        f.start: StackFunctionLiveness(f.start,
            {site: frozenset({obj}) for site in activity.get(f.start, ())}, {})
        for f in functions
    }
    return _CallerStackContextPropagator(RvvServices().stack_semantics).propagate(
        program, local, metadata or ChimeraMetadata.empty())


def _dump(*, inherited=True, active=True, unknown_size=False, boundary="plt", tail=False,
          another_source=False, carrier_source=False):
    """All addresses come from instruction specifications, not manual offsets."""
    size = ("mv", ["s1", "a0"]) if unknown_size else (
        ("csrr", ["s1", "vlenb"]) if active else ("li", ["s1", "32"]))
    transfer = ("j", ["8000 <external@plt>"]) if tail else (
        "jal", ["ra", "8000 <external@plt>"])
    specs = [(0x1000, "source", [size, ("sub", ["sp", "sp", "s1"]),
              ("jal", ["ra", "2000 <carrier>"]) if inherited else transfer,
              ("add", ["sp", "sp", "s1"]), ("ret", [])])]
    if inherited:
        body = ([size, ("sub", ["sp", "sp", "s1"]), transfer,
                 ("add", ["sp", "sp", "s1"]), ("ret", [])]
                if carrier_source else [transfer, ("ret", [])])
        specs.append((0x2000, "carrier", body))
    if another_source:
        specs.append((0x4000, "other_source", [size, ("sub", ["sp", "sp", "s1"]),
            ("jal", ["ra", "2000 <carrier>"]), ("add", ["sp", "sp", "s1"]), ("ret", [])]))
    if boundary == "plt":
        specs.append((0x8000, "external@plt", [("jr", ["t3"])]))
    specs.append((0x9000, "callback", [("ret", [])]))
    lines = []
    for start, name, instructions in specs:
        lines.append(f"{start:016x} <{name}>:")
        for index, (op, args) in enumerate(instructions):
            lines.append(f" {start + index * 4:x}:\t00000013\t{op}\t{','.join(args)}")
        lines.append("")
    return "\n".join(lines)


class ExternalPropagationTests(unittest.TestCase):
    def test_active_plt_warns_at_caller_without_analyzing_stub_as_a_callee(self):
        source = _function(0x1000, _call(0x1000, 0x8000))
        stub = _function(0x8000, _call(0x8000, op="jalr"), plt=True)
        result = _propagate([source, stub], {0x1000: (0x1000,)})
        self.assertEqual([(w.code, w.addresses) for w in result.warnings],
                         [(EXTERNAL, (0x1000,))])
        self.assertEqual(result.warnings[0].external_targets, (0x8000,))
        self.assertEqual(result.warnings[0].origins[0].origin, ORIGIN_VECTOR_DATA)
        self.assertFalse(result.inherited_functions)
        self.assertEqual(result.active_external_calls, (0x1000,))
        self.assertEqual(result.unresolved_live_calls, ())

    def test_known_target_outside_program_is_a_boundary_not_unknown_pointer(self):
        source = _function(0x1000, _call(0x1000, 0xdead))
        result = _propagate([source], {0x1000: (0x1000,)})
        self.assertEqual([w.code for w in result.warnings], [EXTERNAL])
        self.assertEqual(result.warnings[0].external_targets, (0xdead,))

    def test_inactive_external_calls_stay_quiet(self):
        source = _function(0x1000, _call(0x1000, 0xdead))
        result = _propagate([source], {})
        self.assertEqual(result.warnings, ())
        self.assertEqual(result.active_external_calls, ())

    def test_unknown_target_still_has_its_own_diagnostic(self):
        source = _function(0x1000, _call(0x1000, op="jalr"))
        result = _propagate([source], {0x1000: (0x1000,)})
        self.assertEqual([w.code for w in result.warnings], [UNKNOWN])
        self.assertEqual(result.active_external_calls, ())

    def test_mixed_targets_keep_boundary_and_internal_propagation(self):
        for external_in_program in (True, False):
            with self.subTest(plt=external_in_program):
                source = _function(0x1000, _call(0x1000, op="jalr"))
                internal = _function(0x2000, _call(0x2000, op="jalr"))
                functions = [source, internal]
                if external_in_program:
                    functions.append(_function(0x8000, plt=True))
                metadata = ChimeraMetadata(function_pointer={
                    0x1000: CallTargetEntry(0x1000, (0x2000, 0x8000))})
                result = _propagate(functions, {0x1000: (0x1000,)}, metadata)
                self.assertEqual(result.inherited_functions, frozenset({0x2000}))
                self.assertEqual({(w.code, w.addresses[0]) for w in result.warnings},
                                 {(EXTERNAL, 0x1000), (UNKNOWN, 0x2000)})
                self.assertEqual(result.inheritance_trace.first_cause[0x2000].call_site, 0x1000)

    def test_multiple_external_alternatives_produce_one_site_with_all_targets(self):
        source = _function(0x1000, _call(0x1000, op="jalr"))
        metadata = ChimeraMetadata(function_pointer={
            0x1000: CallTargetEntry(0x1000, (0xb000, 0xa000))})
        result = _propagate([source], {0x1000: (0x1000,)}, metadata)
        self.assertEqual(len(result.warnings), 1)
        self.assertEqual(result.warnings[0].external_targets, (0xa000, 0xb000))

    def test_inherited_scalar_carrier_reports_upstream_activity(self):
        source = _function(0x1000, _call(0x1000, 0x2000))
        carrier = _function(0x2000, _call(0x2000, 0xdead))
        result = _propagate([carrier, source], {0x1000: (0x1000,)})
        self.assertEqual([(w.code, w.function_start) for w in result.warnings],
                         [(EXTERNAL, 0x2000)])
        self.assertEqual(result.warnings[0].origins[0].origin, ORIGIN_INHERITED)

    def test_recursive_carrier_still_reaches_boundary(self):
        source = _function(0x1000, _call(0x1000, 0x2000))
        carrier = _function(0x2000, _call(0x2000, 0x2000), _call(0x2004, 0xdead))
        result = _propagate([source, carrier], {0x1000: (0x1000,)})
        self.assertEqual([w.code for w in result.warnings], [EXTERNAL])
        self.assertEqual(len(result.inheritance_trace.first_cause), 1)

    def test_external_tail_jump_does_not_bypass_boundary_check(self):
        source = _function(0x1000, _call(0x1000, 0xdead, op="j", args=["dead"]))
        result = _propagate([source], {0x1000: (0x1000,)})
        self.assertEqual([w.code for w in result.warnings], [EXTERNAL])

    def test_internal_tail_jump_carries_ancestor_to_external_call(self):
        source = _function(0x1000, _call(0x1000, 0x2000))
        carrier = _function(0x2000, _call(0x2000, 0x3000, op="jal", args=["zero", "3000"]))
        leaf = _function(0x3000, _call(0x3000, 0xdead))
        result = _propagate([source, carrier, leaf], {0x1000: (0x1000,)})
        self.assertEqual(result.inherited_functions, frozenset({0x2000, 0x3000}))
        self.assertEqual([(w.code, w.function_start) for w in result.warnings],
                         [(EXTERNAL, 0x3000)])

    def test_local_jump_and_return_are_not_external_transfers(self):
        local_jump = _call(0x1000, 0x1004, op="j", args=["1004"])
        ret = _call(0x1004, op="jr", args=["ra"])
        source = _function(0x1000, local_jump, ret)
        result = _propagate([source], {0x1000: (0x1000, 0x1004)})
        self.assertEqual(result.warnings, ())

    def test_zero_link_return_forms_are_not_boundary_calls(self):
        for args in (["zero", "0(ra)"], ["x0", "0(x1)"], ["zero", "ra", "0"]):
            with self.subTest(args=args):
                source = _function(0x1000, _call(0x1000, op="jalr", args=args))
                result = _propagate([source], {0x1000: (0x1000,)})
                self.assertEqual(result.warnings, ())

    def test_unresolved_non_return_tail_jump_cannot_silently_drop_context(self):
        source = _function(0x1000, _call(0x1000, op="jalr", args=["zero", "0(t0)"]))
        result = _propagate([source], {0x1000: (0x1000,)})
        self.assertEqual([w.code for w in result.warnings], [UNKNOWN])

    def test_empty_pointer_metadata_is_not_a_proof_of_no_external_target(self):
        source = _function(0x1000, _call(0x1000, op="jalr"))
        metadata = ChimeraMetadata(function_pointer={0x1000: CallTargetEntry(0x1000, ())})
        result = _propagate([source], {0x1000: (0x1000,)}, metadata)
        self.assertIn(UNKNOWN, [w.code for w in result.warnings])
        self.assertIn("empty-call-target-set", [w.code for w in result.warnings])
        self.assertEqual(result.unresolved_live_calls, (0x1000,))

    def test_conditional_nonlocal_branch_preserves_ancestor_at_external_boundary(self):
        source = _function(0x1000, _call(0x1000, 0x2000))
        carrier = _function(0x2000, _call(0x2000, 0x3000, op="bnez", args=["a0", "3000"]))
        cold = _function(0x3000, _call(0x3000, 0xdead))
        result = _propagate([source, carrier, cold], {0x1000: (0x1000,)})
        self.assertEqual(result.inherited_functions, frozenset({0x2000, 0x3000}))
        self.assertEqual([(w.code, w.function_start) for w in result.warnings],
                         [(EXTERNAL, 0x3000)])


class ExternalGateDiagnosticsTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.elf = Path(self.temporary.name) / "application.elf"
        self.elf.write_bytes(b"\x7fELF\x02\x01\x01" + b"\0" * 24)

    def collect(self, *, strategy="gate", policy="conservative", **fixture):
        return collect_diagnostics(self.elf, objdump_cmd="objdump", min_vlen_bits=256,
            strategy=strategy, text_threshold=1, dump_text=_dump(**fixture),
            metadata=ChimeraMetadata.empty(), unknown_stack_size_policy=policy)

    @staticmethod
    def external_findings(result):
        # Informational cache observations are exported separately. Only an
        # actual active boundary contributes a finding.
        return [f for f in result.findings if f.diagnostic_code == EXTERNAL]

    @staticmethod
    def external_sites(relations, affected):
        return {r.call_site for r in relations if r.resolution == EXTERNAL and r.call_site in affected}

    def test_real_plt_analysis_gates_source_not_scalar_carrier_or_trampoline(self):
        result = self.collect()
        self.assertTrue(has_actionable_findings(result))
        self.assertEqual(result.gate_names, ("source",))
        self.assertEqual([(f.function, f.kind, f.recommended_action) for f in self.external_findings(result)],
                         [("carrier", "inherited", ACTION_TRACE_SOURCE)])
        self.assertFalse(any(f.diagnostic_code == 'escaping-vlen-scalar-value' for f in result.findings))
        self.assertEqual(result.counts["active_external_calls"], 1)

    def test_real_direct_external_local_source_is_gate_eligible(self):
        result = self.collect(inherited=False, boundary="outside")
        self.assertEqual(len(self.external_findings(result)), 1)
        self.assertEqual(self.external_findings(result)[0].recommended_action, ACTION_DISABLE_AUTOVEC)
        self.assertEqual(result.gate_names, ("source",))

    def test_direct_call_tail_and_nonlocal_branch_use_production_target(self):
        for alias in ("call\t8000 <external@plt>", "tail\t8000 <external@plt>",
                      "bnez\ta0,8000 <external@plt>"):
            with self.subTest(alias=alias):
                dump = _dump().replace("jal\tra,8000 <external@plt>", alias)
                result = collect_diagnostics(self.elf, objdump_cmd="objdump", min_vlen_bits=256,
                    strategy="gate", dump_text=dump, metadata=ChimeraMetadata.empty())
                self.assertEqual(len(self.external_findings(result)), 1)
                self.assertEqual(self.external_findings(result)[0].external_targets, (0x8000,))
                self.assertEqual(result.gate_names, ("source",))

    def test_external_inherited_finding_has_complete_source_witness(self):
        report = _build_inheritance_diagnostics(self.collect(), "0" * 64)
        boundaries = [f for f in report['findings'] if f['diagnostic_code'] == EXTERNAL]
        self.assertEqual(len(boundaries), 1)
        finding = boundaries[0]
        self.assertTrue(finding["witness_reached_seed"])
        self.assertFalse(finding["diagnostics_incomplete"])
        edge = report["seed_edges"][finding["witness_path"][-1]]
        self.assertEqual(report["functions"][edge["caller_function_ref"]]["name"], "source")

    def test_all_converging_ancestor_sources_enter_gate_list(self):
        result = self.collect(another_source=True)
        self.assertEqual(set(result.gate_names), {"source", "other_source"})
        self.assertEqual(len(result.analysis.stack.inheritance_trace.seed_edges), 2)
        self.assertEqual(len(self.external_findings(result)), 1)

    def test_external_finding_keeps_both_inherited_and_local_source(self):
        result = self.collect(carrier_source=True)
        self.assertEqual(set(result.gate_names), {"source", "carrier"})
        self.assertEqual(len(self.external_findings(result)), 1)
        # Status retains the established VLEN-source precedence; the
        # structured origins preserve both sources independently.
        finding = self.external_findings(result)[0]
        self.assertEqual(finding.origin_status, "vlen-source")
        self.assertIn(ORIGIN_INHERITED, {origin.origin for origin in finding.origins})

    def test_all_report_forms_distinguish_external_from_unknown_calls(self):
        import json
        result = self.collect()
        path = Path(self.temporary.name) / "report.json"
        write_report(result, path, elf_identity={"content_sha256": "0" * 64})
        reports = [_diagnostics_payload(result), _build_inheritance_diagnostics(result, "0" * 64),
                   json.loads(path.read_text(encoding="utf-8"))]
        for report in reports:
            with self.subTest(format=report.get("format", "check")):
                boundaries = [f for f in report['findings'] if f['diagnostic_code'] == EXTERNAL]
                self.assertEqual(len(boundaries), 1)
                self.assertEqual(boundaries[0]["external_targets"], ["0x8000"])

    def test_auto_external_remediation_does_not_pretend_svf_closes_boundary(self):
        with mock.patch("chimera.check_elf._text_size", side_effect=AssertionError("not needed")):
            result = self.collect(strategy="auto", inherited=False)
        self.assertEqual(result.strategy, "gate")
        self.assertTrue(build_decision_block(result)["gate"]["enabled"])
        self.assertFalse(build_decision_block(result)["function_pointer_plugin"])

    def test_explicit_svf_only_request_cannot_close_external_boundary(self):
        with self.assertRaisesRegex(ValueError, "external.*gate"):
            self.collect(strategy="svf")

    def test_unchanged_vector_source_still_fails_recheck(self):
        first, repeated = self.collect(), self.collect()
        self.assertEqual(first.gate_names, repeated.gate_names)
        self.assertTrue(has_actionable_findings(repeated))
        self.assertEqual(repeated.counts["actionable"], len(repeated.findings))
        self.assertEqual(len(self.external_findings(repeated)), 1)

    def test_removing_upstream_source_clears_boundary_without_enumerating_callback(self):
        before, after = self.collect(), self.collect(active=False)
        self.assertTrue(before.findings)
        self.assertEqual(after.findings, ())
        self.assertFalse(after.gate_names)
        self.assertNotIn(0x9000, before.analysis.stack.inherited_functions)

    def test_unknown_only_boundary_remains_pending_not_a_gate_claim(self):
        result = self.collect(inherited=False, unknown_size=True)
        self.assertEqual(len(result.findings), 1)
        self.assertEqual(result.findings[0].recommended_action, ACTION_TRACE_SIZE_SOURCE)
        self.assertFalse(result.gate_names)
        self.assertEqual(result.pending_proof_starts, (0x1000,))

    def test_explicit_scalar_scope_does_not_suppress_known_vlen_source(self):
        unknown = self.collect(inherited=False, unknown_size=True, policy="assume-scalar-independent")
        known = self.collect(inherited=False, policy="assume-scalar-independent")
        self.assertEqual(unknown.findings, ())
        self.assertEqual(len(self.external_findings(known)), 1)

    def test_external_warning_has_separate_remedy_without_svf_advice(self):
        result = self.collect()
        output = io.StringIO()
        with redirect_stderr(output):
            _emit_stack_warnings(result.analysis.stack.warnings, {0x2000: "carrier"})
        self.assertIn(EXTERNAL, output.getvalue())
        self.assertIn("carrier", output.getvalue())
        self.assertNotIn("svf/full", output.getvalue())

    def test_independent_audit_attributes_external_sink_to_real_source(self):
        from chimera.gate_source_audit import enumerate_candidates, propagate_sources
        analysis = self.collect().analysis
        candidates = enumerate_candidates(analysis.program, analysis.stack, elf_sha256="0" * 64)
        candidates, relations, affected, gaps, stats = propagate_sources(
            analysis.program, analysis.stack, candidates, analysis.metadata,
            RvvServices().stack_semantics, elf_sha256="0" * 64)
        self.assertEqual(self.external_sites(relations, affected), {0x2000})
        self.assertEqual(stats["cross_check"]["mismatches"], [])
        self.assertEqual(stats["active_external_sites"], 1)
        self.assertEqual(stats["active_unresolved_sites"], 0)
        upstream = [c for c in candidates if c.id in affected[0x2000]]
        self.assertEqual({c.function_start for c in upstream}, {0x1000})
        external = next(r for r in relations if r.call_site == 0x2000)
        self.assertEqual(external.resolution, EXTERNAL)
        self.assertEqual(external.external_targets, (0x8000,))

    def test_independent_audit_keeps_mixed_internal_and_external_edges(self):
        from chimera.gate_source_audit import enumerate_candidates, propagate_sources
        dump = _dump(inherited=False).replace("jal\tra,8000 <external@plt>", "jalr\tt2")
        dump += "\n0000000000004000 <internal>:\n 4000:\t00000013\tjalr\tt2\n 4004:\t00000013\tret\n"
        metadata = ChimeraMetadata(function_pointer={
            0x1008: CallTargetEntry(0x1008, (0x4000, 0x8000))})
        result = collect_diagnostics(self.elf, objdump_cmd="objdump", min_vlen_bits=256,
            strategy="gate", text_threshold=1, dump_text=dump, metadata=metadata)
        analysis = result.analysis
        candidates = enumerate_candidates(analysis.program, analysis.stack, elf_sha256="0" * 64)
        _, relations, affected, _, stats = propagate_sources(
            analysis.program, analysis.stack, candidates, metadata,
            RvvServices().stack_semantics, elf_sha256="0" * 64)
        self.assertEqual(self.external_sites(relations, affected), {0x1008})
        self.assertIn(0x4000, affected)
        self.assertEqual(stats["cross_check"]["mismatches"], [])
        self.assertEqual((stats["active_external_sites"], stats["active_unresolved_sites"]), (1, 1))
        self.assertEqual(next(r for r in relations if r.call_site == 0x1008).targets, (0x4000,))

    def test_independent_audit_includes_inherited_tail_boundary(self):
        from chimera.gate_source_audit import enumerate_candidates, propagate_sources
        analysis = self.collect(tail=True).analysis
        candidates = enumerate_candidates(analysis.program, analysis.stack, elf_sha256="0" * 64)
        _, relations, affected, _, stats = propagate_sources(
            analysis.program, analysis.stack, candidates, analysis.metadata,
            RvvServices().stack_semantics, elf_sha256="0" * 64)
        self.assertEqual(self.external_sites(relations, affected), {0x2000})
        self.assertEqual(stats["cross_check"]["mismatches"], [])

    def test_audit_json_exports_external_targets_with_source_contributors(self):
        from chimera.gate_source_audit import audit_elf
        report = audit_elf(self.elf, gate_names=["source"], expected_gate_count=None,
            dump_text=_dump(), metadata=ChimeraMetadata.empty())
        boundaries = [site for site in report['affected_sites'] if site['resolution'] == EXTERNAL]
        self.assertEqual(len(boundaries), 1)
        boundary = boundaries[0]
        self.assertEqual(boundary["external_targets"], ["0x8000"])
        self.assertEqual(boundary["internal_targets"], [])
        self.assertTrue(boundary["contributors"])


if __name__ == "__main__":
    unittest.main()
