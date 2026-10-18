from __future__ import annotations

from pathlib import Path
import tempfile
import unittest
import gc
import weakref
from dataclasses import fields

from chimera.preprocess.offline.analysis.safety import SAFETY_ABI_VERSION
from chimera.preprocess.offline.analysis.safety.classifier import (
    SafetyAnalysisResult,
    SafetyRecord,
)
from chimera.preprocess.offline.analysis.safety.exporters import export_asm_table, export_json
from chimera.preprocess.offline.analysis.safety.stack_liveness.scope import (
    UNKNOWN_SCALAR_INDEPENDENCE_ASSUMPTION,
)
from chimera.preprocess.offline.analysis.arch.riscv.rvv import RvvArtifactEmitter
from chimera.preprocess.offline.analysis.core.data_model import Function, Instruction, Program


class SafetyArtifactTests(unittest.TestCase):
    def test_patch_facts_pack_only_safe_addresses_without_keeping_records(self):
        from chimera.preprocess.offline.analysis.safety.result import SafetyPipelineResult
        original = SafetyAnalysisResult(records={
            0x1000: SafetyRecord(0x1000, True, frozenset(), frozenset()),
            0x1004: SafetyRecord(0x1004, False, frozenset({2}), frozenset()),
            0x1008: SafetyRecord(0x1008, True, frozenset(), frozenset()),
        }, vector=None, stack=None)
        ref = weakref.ref(original)
        full = SafetyPipelineResult("main", None, None, None, original, (), {"safe": 2})
        compact = full.for_patching()
        self.assertEqual(list(compact.iter_safe_addresses()), list(full.iter_safe_addresses()))
        self.assertEqual(len(compact.patch_addresses), 16)
        self.assertIsNone(compact.safety)
        self.assertIs(compact.summary, full.summary)
        self.assertIs(compact.for_patching(), compact)
        del original, full
        gc.collect()
        self.assertIsNone(ref())

    def test_workflow_facts_release_intermediates_and_preserve_admission_scope(self):
        class WorkGraph:
            pass

        vector, stack = WorkGraph(), WorkGraph()
        refs = weakref.ref(vector), weakref.ref(stack)
        record = SafetyRecord(0x1000, False, frozenset({3}), frozenset(), ("vector",))
        original = SafetyAnalysisResult(
            records={record.address: record}, vector=vector, stack=stack,
            unknown_stack_size_policy="conservative", assumption="test scope",
            conditional=False, scope_exclusions=("retained sentinel",),
        )
        compact = original.without_intermediates()
        self.assertIs(compact.records, original.records)
        self.assertIs(compact.records[0x1000], record)
        self.assertEqual(compact.unknown_stack_size_policy, original.unknown_stack_size_policy)
        self.assertEqual(compact.assumption, original.assumption)
        self.assertEqual(compact.conditional, original.conditional)
        self.assertEqual(compact.scope_exclusions, original.scope_exclusions)
        self.assertIs(original.vector, vector)
        self.assertIs(original.stack, stack)
        del original, vector, stack
        gc.collect()
        self.assertTrue(all(ref() is None for ref in refs))

    def test_safety_json_identifies_conditional_unknown_size_scope(self) -> None:
        field_names = {item.name for item in fields(SafetyAnalysisResult)}
        self.assertIn("unknown_stack_size_policy", field_names)
        result = SafetyAnalysisResult(
            records={0x1000: SafetyRecord(0x1000, True, frozenset(), frozenset())},
            vector=None,
            stack=None,
            unknown_stack_size_policy="assume-scalar-independent",
            assumption=UNKNOWN_SCALAR_INDEPENDENCE_ASSUMPTION,
            conditional=True,
        )
        instruction = Instruction(0x1000, 4, "ret", [], "ret")
        function = Function("main", 0x1000, [instruction])
        program = Program(
            dump_lines=[], functions=[function], instructions=[instruction],
            instruction_by_address={instruction.addr: instruction},
        )

        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "main.safety.json"
            export_json(program, result, output)
            document = __import__("json").loads(output.read_text(encoding="utf-8"))

        self.assertTrue(document["conditional"])
        self.assertEqual(
            document["unknown_stack_size_policy"], "assume-scalar-independent"
        )
        self.assertEqual(document["assumption"], UNKNOWN_SCALAR_INDEPENDENCE_ASSUMPTION)

    def test_safety_assembly_requires_an_explicit_emitter(self) -> None:
        result = SafetyAnalysisResult(records={}, vector=object(), stack=object())
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "main.safety.S"
            with self.assertRaisesRegex(RuntimeError, "artifact emitter"):
                export_asm_table(result, output, "main")

    def test_safety_assembly_contains_only_original_rva_and_state(self) -> None:
        result = SafetyAnalysisResult(
            records={
                0x1004: SafetyRecord(
                    0x1004, True, frozenset(), frozenset()
                )
            },
            vector=object(),
            stack=object(),
        )
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "main.safety.S"

            export_asm_table(
                result,
                output,
                "main",
                original_base=0x1000,
                emitter=RvvArtifactEmitter(),
            )

            text = output.read_text(encoding="utf-8")
        self.assertEqual(SAFETY_ABI_VERSION, 1)
        self.assertIn("chimera_main_safety_abi", text)
        self.assertIn(".dword 0x0000000000000004, 1", text)
        self.assertNotIn("translated", text)
        self.assertNotIn("metadata_abi", text)


if __name__ == "__main__":
    unittest.main()
