"""Informational cache observations must not become boundary findings."""
from dataclasses import replace
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from chimera.check_elf import (
    collect_diagnostics, has_actionable_findings, _diagnostics_payload,
    _build_inheritance_diagnostics, safety_binary_check_request,
)
from chimera.preprocess.offline.analysis.safety.stack_liveness import (
    ChimeraMetadata, StackLivenessAnalyzer, AnalysisWarning,
)
from chimera.preprocess.offline.analysis.safety.stack_liveness.model import (
    ActiveOrigin, ORIGIN_LOCAL_SCALAR, VLEN_SCALAR_ESCAPE, UNRESOLVED_ACTIVE_CALL,
)
from test_scalar_width_call_effects import make_program
from test_gate_source_audit import _audit


class CacheWarningReportTests(unittest.TestCase):
    def test_real_boundary_carries_the_actual_live_local_copy_evidence(self):
        program, _ = make_program([
            ('csrr', 's4,vlenb'), ('jalr', 't2'),
            ('add', 't1,s4,zero'), ('ret', ''),
        ])
        call = program.functions[0].insts[1].addr
        with tempfile.TemporaryDirectory() as directory:
            elf = Path(directory) / 'fixture.elf'
            elf.write_bytes(b'\x7fELF\x02\x01\x01' + b'\0' * 24)
            result = collect_diagnostics(elf, objdump_cmd='objdump', strategy='gate',
                dump_text='\n'.join(program.dump_lines), metadata=ChimeraMetadata.empty())
        self.assertTrue(has_actionable_findings(result))
        findings = [f for f in result.findings if f.call_site == hex(call)]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].diagnostic_code, UNRESOLVED_ACTIVE_CALL)
        origins = [o for o in findings[0].origins if o.origin == ORIGIN_LOCAL_SCALAR]
        self.assertEqual(len(origins), 1)
        self.assertIsNotNone(origins[0].width_evidence)
        self.assertEqual(origins[0].width_evidence.live_width_registers, ('s4',))
        self.assertEqual(origins[0].width_evidence.call_effect.status, 'not-requested')

    def build(self):
        program, rvv = make_program([('nop', ''), ('ret', '')])
        stack = StackLivenessAnalyzer(semantics=rvv.stack_semantics, emit_warnings=False).analyze_program(
            program, metadata=ChimeraMetadata.empty(), config_results=rvv.vector_configs(program))
        warning = AnalysisWarning(VLEN_SCALAR_ESCAPE, 'width selection: warning-only',
            program.functions[0].start, (program.functions[0].insts[0].addr,),
            origins=(ActiveOrigin(ORIGIN_LOCAL_SCALAR, 'vlen_scalar',
                                 'vlen_scalar:hardware-width-cache', 'selection'),))
        stack = replace(stack, warnings=(warning,))
        with tempfile.TemporaryDirectory() as directory:
            elf = Path(directory) / 'fixture.elf'
            elf.write_bytes(b'\x7fELF\x02\x01\x01' + b'\0' * 24)
            with patch.object(StackLivenessAnalyzer, 'analyze_program', return_value=stack):
                result = collect_diagnostics(elf, objdump_cmd='objdump', strategy='gate',
                    dump_text='\n'.join(program.dump_lines), metadata=ChimeraMetadata.empty())
        return program, stack, result

    def test_warning_does_not_become_actionable_or_create_gate_names(self):
        _, _, result = self.build()
        self.assertFalse(has_actionable_findings(result))
        self.assertEqual(result.findings, ())
        self.assertEqual(result.gate_names, ())

    def test_warning_and_origin_are_exported_by_both_report_consumers(self):
        _, _, result = self.build()
        main = _diagnostics_payload(result)
        inheritance = _build_inheritance_diagnostics(result, 'a' * 64)
        self.assertIn('warnings', main)
        self.assertEqual(main['warnings'], inheritance['warnings'])
        warning = main['warnings'][0]
        self.assertEqual(warning['diagnostic_code'], VLEN_SCALAR_ESCAPE)
        self.assertEqual(warning['addresses'], ['0x1000'])
        self.assertFalse(warning['actionable'])
        self.assertEqual(warning['severity'], 'warning')
        self.assertTrue(warning['activity_origins'])

    def test_source_audit_does_not_invent_a_boundary_for_a_warning(self):
        program, stack, _ = self.build()
        document = _audit(program, stack, names=())
        self.assertEqual(document['affected_sites'], [])
        self.assertEqual(document['propagation']['scalar_width_escape_sites'], 0)
        self.assertEqual(document['propagation']['cross_check']['mismatches'], [])

    def test_scope_version_is_31(self):
        request = safety_binary_check_request({'min_vlen_bits': 256, 'compiler_metadata': ()})
        self.assertEqual(request.version, 31)


if __name__ == '__main__':
    unittest.main()
