from __future__ import annotations

import unittest
import inspect
from dataclasses import replace
from types import SimpleNamespace

from chimera.preprocess.offline.analysis.arch.riscv.rvv.services import (
    RiscvStackSemantics,
)
from chimera.preprocess.offline.analysis.core.data_model import Function, Instruction, Program
from chimera.preprocess.offline.analysis.safety.stack_liveness.frame_liveness import (
    analyze_vlen_stack_liveness, VLEN_STACK_FRAME, VLEN_STACK_SETUP,
)
from chimera.preprocess.offline.analysis.safety.stack_liveness.analyzer import (
    StackLivenessAnalyzer,
)
from chimera.preprocess.offline.analysis.safety.stack_liveness.model import (
    ChimeraMetadata,
    StackObjectId,
)
from chimera.preprocess.offline.analysis.safety.classifier import classify_liveness
from chimera.preprocess.offline.analysis.safety.stack_liveness.solver import (
    _FunctionExpressionAnalyzer,
)


def _function(*specs: tuple[str, list[str]], start: int = 0x1000) -> Function:
    instructions = [
        Instruction(start + index * 4, 4, op, args, f"{op} " + ",".join(args))
        for index, (op, args) in enumerate(specs)
    ]
    for current, following in zip(instructions, instructions[1:]):
        current.succ.add(following.addr)
    return Function("fixture", start, instructions)


def _frame_liveness(function: Function):
    semantics = RiscvStackSemantics()
    expressions = _FunctionExpressionAnalyzer(semantics).analyze(
        function, frozenset()
    )
    return analyze_vlen_stack_liveness(function, expressions, semantics)


def _program(*functions: Function) -> Program:
    instructions = [instruction for function in functions for instruction in function.insts]
    return Program(
        dump_lines=[],
        functions=list(functions),
        instructions=instructions,
        instruction_by_address={instruction.addr: instruction for instruction in instructions},
    )


def _analyze(function: Function, policy: str = "conservative"):
    return _analyze_program((function,), policy)


def _analyze_program(functions: tuple[Function, ...], policy: str):
    assert "unknown_stack_size_policy" in inspect.signature(
        StackLivenessAnalyzer.__init__
    ).parameters, "StackLivenessAnalyzer must expose the scoped policy"
    return StackLivenessAnalyzer(
        semantics=RiscvStackSemantics(),
        emit_warnings=False,
        unknown_stack_size_policy=policy,
    ).analyze_program(
        _program(*functions),
        metadata=ChimeraMetadata.empty(),
        config_results={
            function.start: SimpleNamespace(at=lambda _address: frozenset())
            for function in functions
        },
    )


class VlenStackFrameLivenessTests(unittest.TestCase):
    def test_noop_vlen_diamond_does_not_taint_unknown_allocation_after_join(self):
        function = _function(
            ("csrr", ["t0", "vlenb"]),
            ("li", ["t1", "8"]),
            ("bltu", ["t0", "t1", "0x1018"]),
            ("nop", []),
            ("j", ["0x101C"]),
            ("nop", []),
            ("sub", ["sp", "sp", "a0"]),
            ("ret", []),
        )
        for instruction in function.insts:
            instruction.succ.clear()
        edges = ((0, (1,)), (1, (2,)), (2, (3, 5)), (3, (4,)),
                 (4, (6,)), (5, (6,)), (6, (7,)))
        for source, targets in edges:
            function.insts[source].succ.update(
                function.insts[target].addr for target in targets
            )

        result = _analyze(function, "assume-scalar-independent")
        local = result.by_function[function.start]

        self.assertFalse(local.live_before[0x1018])
        self.assertEqual([item.adjustment for item in local.scope_exclusions], [0x1018])
        self.assertEqual(local.frame_origins, ())

    def test_postjoin_call_result_is_not_vlen_control_selected(self):
        function = _function(
            ("csrr", ["t0", "vlenb"]),
            ("li", ["t1", "8"]),
            ("bltu", ["t0", "t1", "0x1018"]),
            ("nop", []),
            ("j", ["0x101C"]),
            ("nop", []),
            ("jal", ["ra", "0x3000"]),
            ("sub", ["sp", "sp", "a0"]),
            ("ret", []),
        )
        for instruction in function.insts:
            instruction.succ.clear()
        edges = ((0, (1,)), (1, (2,)), (2, (3, 5)), (3, (4,)),
                 (4, (6,)), (5, (6,)), (6, (7,)), (7, (8,)))
        for source, targets in edges:
            function.insts[source].succ.update(
                function.insts[target].addr for target in targets
            )

        result = _analyze(function, "assume-scalar-independent")
        local = result.by_function[function.start]

        # The post-join call is not control-selected, so the UNKNOWN size
        # remains excluded under the declared scope. A dead volatile value
        # is not imported through the call's inferred return registers.
        self.assertFalse({VLEN_STACK_FRAME, VLEN_STACK_SETUP} & local.live_before[0x101C])
        self.assertFalse(any(obj.source == 'vlen_scalar' for obj in local.live_before[0x101C]))
        self.assertEqual([item.adjustment for item in local.scope_exclusions], [0x101C])
        self.assertEqual(local.frame_origins, ())

    def test_unresolved_branch_fallback_is_explicit_and_conservative(self):
        from chimera.preprocess.offline.analysis.safety.stack_liveness.dependencies import (
            analyze_register_dependencies,
        )

        function = _function(
            ("csrr", ["t0", "vlenb"]),
            ("beqz", ["t0", "0x9000"]),
            ("sub", ["sp", "sp", "a0"]),
            ("ret", []),
        )
        for instruction in function.insts:
            instruction.succ.clear()
        function.insts[0].succ.add(function.insts[1].addr)
        # The taken target is absent from this function; only fallthrough is
        # represented, so the branch cannot prove a structured join.
        function.insts[1].succ.add(function.insts[2].addr)
        function.insts[2].succ.add(function.insts[3].addr)

        dependencies = analyze_register_dependencies(
            function,
            RiscvStackSemantics(),
            capture_known_vlen_control=True,
        )
        result = _analyze(function, "assume-scalar-independent")
        local = result.by_function[function.start]

        self.assertTrue(dependencies.known_control_fallback)
        self.assertTrue(local.live_before[0x1008])
        self.assertEqual(local.scope_exclusions, ())

    def test_unknown_unresolved_guard_fallback_does_not_create_vlen_evidence(self):
        function = _function(
            ("beqz", ["a2", "0x9000"]),
            ("sub", ["sp", "sp", "a0"]),
            ("ret", []),
        )
        for instruction in function.insts:
            instruction.succ.clear()
        function.insts[0].succ.add(function.insts[1].addr)
        function.insts[1].succ.add(function.insts[2].addr)

        result = _analyze(function, "assume-scalar-independent")
        local = result.by_function[function.start]

        self.assertFalse(local.live_before[0x1004])
        self.assertEqual([item.adjustment for item in local.scope_exclusions], [0x1004])
        self.assertEqual(local.frame_origins, ())

    def test_unknown_scalar_adjustment_is_conditional_and_excluded_only_by_opt_in(self):
        function = _function(
            ("sub", ["sp", "sp", "a0"]),
            ("jalr", ["ra", "a2", "0"]),
            ("ret", []),
        )

        conservative = _analyze(function)
        scoped = _analyze(function, "assume-scalar-independent")

        self.assertTrue(conservative.by_function[function.start].live_before[0x1000])
        local = scoped.by_function[function.start]
        self.assertTrue(all(not values for values in local.live_before.values()))
        self.assertEqual(len(local.scope_exclusions), 1)
        self.assertEqual(local.scope_exclusions[0].adjustment, 0x1000)
        self.assertEqual(local.scope_exclusions[0].dependency, "unknown")
        self.assertEqual(local.scope_exclusions[0].disposition, "assumption")

    def test_known_vlen_adjustment_stays_active_under_opt_in(self):
        function = _function(
            ("csrr", ["a0", "vlenb"]),
            ("sub", ["sp", "sp", "a0"]),
            ("ret", []),
        )

        result = _analyze(function, "assume-scalar-independent")

        self.assertTrue(result.by_function[function.start].live_before[0x1000])
        self.assertEqual(result.by_function[function.start].frame_origins[0].dependency, "vlen")
        self.assertEqual(result.by_function[function.start].scope_exclusions, ())

    def test_scope_exclusion_does_not_mask_a_later_known_vlen_allocation(self):
        function = _function(
            ("sub", ["sp", "sp", "a1"]),
            ("csrr", ["a0", "vlenb"]),
            ("sub", ["sp", "sp", "a0"]),
            ("jalr", ["ra", "a3", "0"]),
            ("ret", []),
        )

        result = _analyze(function, "assume-scalar-independent")
        local = result.by_function[function.start]

        self.assertEqual([item.adjustment for item in local.scope_exclusions], [0x1000])
        self.assertTrue(local.live_before[0x1008])
        self.assertEqual([item.adjustment for item in local.frame_origins], [0x1008])
        self.assertEqual(local.frame_origins[0].dependency, "vlen")

    def test_unknown_adjustment_does_not_clear_preexisting_known_frame(self):
        function = _function(
            ("csrr", ["a0", "vlenb"]),
            ("sub", ["sp", "sp", "a0"]),
            ("mv", ["sp", "a1"]),
            ("ret", []),
        )

        result = _analyze(function, "assume-scalar-independent")
        local = result.by_function[function.start]

        self.assertTrue(all(local.live_before[address] for address in local.live_before))
        self.assertEqual([item.adjustment for item in local.frame_origins], [0x1004])
        self.assertEqual([item.adjustment for item in local.scope_exclusions], [0x1008])

    def test_proven_constant_allocation_is_not_recorded_as_excluded(self):
        function = _function(
            ("li", ["a0", "64"]),
            ("sub", ["sp", "sp", "a0"]),
            ("ret", []),
        )

        result = _analyze(function, "assume-scalar-independent")

        self.assertTrue(all(not values for values in result.by_function[function.start].live_before.values()))
        self.assertEqual(result.by_function[function.start].scope_exclusions, ())

    def test_unknown_memory_and_external_call_sizes_are_scoped(self):
        cases = (
            ("memory", (("ld", ["a0", "0(s0)"]), ("sub", ["sp", "sp", "a0"])), 0x1004),
            ("call", (("jal", ["ra", "0x3000"]), ("sub", ["sp", "sp", "a0"])), 0x1004),
        )
        for name, specs, adjustment in cases:
            with self.subTest(source=name):
                function = _function(*specs, ("ret", []))
                result = _analyze(function, "assume-scalar-independent")
                local = result.by_function[function.start]
                self.assertEqual(
                    [item.adjustment for item in local.scope_exclusions],
                    [adjustment],
                )
                self.assertEqual(local.scope_exclusions[0].dependency, "unknown")

    def test_vlen_proof_beneath_unproven_root_prevents_exclusion(self):
        from chimera.preprocess.offline.analysis.safety.stack_liveness.origins import (
            OriginProver,
        )

        function = _function(
            ("sub", ["sp", "sp", "a0"]),
            ("ret", []),
        )
        program = _program(function)
        semantics = RiscvStackSemantics()
        prover = OriginProver(program, semantics, metadata=ChimeraMetadata.empty())
        leaf = prover._record(
            "vlen", "vlenb-read", function.start, 0x1000, "a0", "known VLEN evidence"
        )
        root = prover._record(
            "unproven", "external-callee", function.start, 0x1000, "a0",
            "unknown proof root retaining known VLEN evidence", (leaf,),
        )
        prover.prove_adjustment = lambda _function, _address: SimpleNamespace(
            proven=False,
            status="unproven",
            reason="external-callee",
            proof_id=root,
        )
        config = SimpleNamespace(at=lambda _address: frozenset())

        result = StackLivenessAnalyzer(
            semantics=semantics,
            emit_warnings=False,
            unknown_stack_size_policy="assume-scalar-independent",
        ).analyze_program(
            program,
            metadata=ChimeraMetadata.empty(),
            config_results={function.start: config},
            prover=prover,
        )
        local = result.by_function[function.start]

        self.assertTrue(local.live_before[0x1000])
        self.assertEqual(local.frame_origins[0].dependency, "vlen")
        self.assertEqual(local.frame_origins[0].proof, root)
        self.assertEqual(local.scope_exclusions, ())

    def test_classification_keeps_unrelated_conservative_activity_under_scope(self):
        function = _function(
            ("sub", ["sp", "sp", "a0"]),
            ("addi", ["t0", "t0", "1"]),
            ("ret", []),
        )
        result = _analyze(function, "assume-scalar-independent")
        local = result.by_function[function.start]
        conservative = StackObjectId("conservative", "possible-stack-data")
        states = {
            address: values
            for address, values in local.live_before.items()
            if values
        }
        states[0x1004] = frozenset({conservative})
        scoped_local = replace(local, live_before=states)
        scoped_result = replace(
            result, by_function={function.start: scoped_local}
        )

        safety = classify_liveness(
            _program(function),
            SimpleNamespace(by_function={}),
            scoped_result,
        )

        self.assertTrue(safety.records[0x1000].safe)
        self.assertFalse(safety.records[0x1004].safe)
        self.assertIn("live_stack_vector_data", safety.records[0x1004].reasons)
        self.assertTrue(safety.conditional)

    def test_vlen_dependency_at_join_overrides_unknown_alternate_path(self):
        function = _function(
            ("beqz", ["a2", "0x1010"]),
            ("csrr", ["a0", "vlenb"]),
            ("j", ["0x1010"]),
            ("addi", ["t0", "t0", "1"]),
            ("sub", ["sp", "sp", "a0"]),
            ("ret", []),
        )
        for instruction in function.insts:
            instruction.succ.clear()
        edges = ((0, (1, 3)), (1, (2,)), (2, (4,)), (3, (4,)), (4, (5,)))
        for source, targets in edges:
            function.insts[source].succ.update(function.insts[target].addr for target in targets)

        result = _analyze(function, "assume-scalar-independent")
        local = result.by_function[function.start]

        self.assertTrue(local.live_before[0x1010])
        self.assertEqual(local.frame_origins[0].dependency, "vlen")
        self.assertEqual(local.scope_exclusions, ())

    def test_unknown_guard_does_not_become_known_vlen_control_evidence(self):
        function = _function(
            ("beqz", ["a2", "0x100C"]),
            ("li", ["a0", "16"]),
            ("j", ["0x1010"]),
            ("li", ["a0", "32"]),
            ("sub", ["sp", "sp", "a0"]),
            ("jalr", ["ra", "a3", "0"]),
            ("ret", []),
        )
        for instruction in function.insts:
            instruction.succ.clear()
        edges = ((0, (1, 3)), (1, (2,)), (2, (4,)), (3, (4,)), (4, (5,)), (5, (6,)))
        for source, targets in edges:
            function.insts[source].succ.update(
                function.insts[target].addr for target in targets
            )

        result = _analyze(function, "assume-scalar-independent")
        local = result.by_function[function.start]

        self.assertFalse(local.live_before[0x1010])
        self.assertEqual([item.adjustment for item in local.scope_exclusions], [0x1010])

    def test_known_vlen_guard_selecting_scalar_constants_stays_active(self):
        function = _function(
            ("csrr", ["t2", "vlenb"]),
            ("beqz", ["t2", "0x1010"]),
            ("li", ["a0", "16"]),
            ("j", ["0x1014"]),
            ("li", ["a0", "32"]),
            ("sub", ["sp", "sp", "a0"]),
            ("jalr", ["ra", "a3", "0"]),
            ("ret", []),
        )
        for instruction in function.insts:
            instruction.succ.clear()
        edges = ((0, (1,)), (1, (2, 4)), (2, (3,)), (3, (5,)), (4, (5,)), (5, (6,)), (6, (7,)))
        for source, targets in edges:
            function.insts[source].succ.update(
                function.insts[target].addr for target in targets
            )

        result = _analyze(function, "assume-scalar-independent")
        local = result.by_function[function.start]

        self.assertTrue(local.live_before[0x1014])
        self.assertEqual(local.frame_origins[0].dependency, "vlen")
        self.assertEqual(local.scope_exclusions, ())

    def test_loop_carried_value_selected_under_vlen_guard_stays_active(self):
        function = _function(
            ("csrr", ["t2", "vlenb"]),
            ("beqz", ["t2", "0x101C"]),
            ("li", ["a0", "16"]),
            ("addi", ["t1", "t1", "1"]),
            ("bltu", ["t1", "t2", "0x100C"]),
            ("j", ["0x101C"]),
            ("nop", []),
            ("sub", ["sp", "sp", "a0"]),
            ("ret", []),
        )
        for instruction in function.insts:
            instruction.succ.clear()
        edges = ((0, (1,)), (1, (2, 7)), (2, (3,)), (3, (4,)),
                 (4, (3, 5)), (5, (7,)), (7, (8,)))
        for source, targets in edges:
            function.insts[source].succ.update(
                function.insts[target].addr for target in targets
            )

        result = _analyze(function, "assume-scalar-independent")
        local = result.by_function[function.start]

        self.assertTrue(local.live_before[0x101C])
        self.assertEqual(local.frame_origins[0].dependency, "vlen")
        self.assertEqual(local.scope_exclusions, ())

    def test_known_guard_taint_survives_nested_diamond_inside_outer_arm(self):
        function = _function(
            ("csrr", ["t2", "vlenb"]),
            ("beqz", ["t2", "0x1024"]),
            ("beqz", ["a3", "0x1014"]),
            ("addi", ["t1", "t1", "1"]),
            ("j", ["0x1018"]),
            ("addi", ["t3", "t3", "1"]),
            ("mv", ["a0", "a1"]),
            ("j", ["0x1040"]),
            ("nop", []),
            ("beqz", ["a4", "0x1030"]),
            ("addi", ["t5", "t5", "1"]),
            ("j", ["0x1034"]),
            ("addi", ["t6", "t6", "1"]),
            ("mv", ["a0", "a2"]),
            ("j", ["0x1040"]),
            ("nop", []),
            ("sub", ["sp", "sp", "a0"]),
            ("jalr", ["ra", "a3", "0"]),
            ("ret", []),
        )
        for instruction in function.insts:
            instruction.succ.clear()
        edges = ((0, (1,)), (1, (2, 9)), (2, (3, 5)), (3, (4,)),
                 (4, (6,)), (5, (6,)), (6, (7,)), (7, (16,)),
                 (9, (10, 12)), (10, (11,)), (11, (13,)), (12, (13,)),
                 (13, (14,)), (14, (16,)), (16, (17,)), (17, (18,)))
        for source, targets in edges:
            function.insts[source].succ.update(
                function.insts[target].addr for target in targets
            )

        result = _analyze(function, "assume-scalar-independent")
        local = result.by_function[function.start]

        self.assertTrue(local.live_before[0x1040])
        self.assertEqual(local.frame_origins[0].dependency, "vlen")
        self.assertEqual(local.scope_exclusions, ())

    def test_callee_vlen_return_overrides_unknown_call_expression(self):
        caller = _function(
            ("jal", ["ra", "0x2000"]),
            ("sub", ["sp", "sp", "a0"]),
            ("ret", []),
            start=0x1000,
        )
        callee = _function(
            ("csrr", ["a0", "vlenb"]),
            ("ret", []),
            start=0x2000,
        )
        caller.insts[0].jump_targets.add(callee.start)

        result = _analyze_program((caller, callee), "assume-scalar-independent")
        local = result.by_function[caller.start]

        self.assertTrue(local.live_before[0x1004])
        self.assertEqual(local.frame_origins[0].dependency, "vlen")
        self.assertEqual(local.scope_exclusions, ())

    def test_dynamic_frame_setup_and_teardown_stay_unsafe_until_sp_is_restored(self):
        function = _function(
            ("addi", ["t0", "t0", "1"]),
            ("csrr", ["a0", "vlenb"]),
            ("slli", ["a1", "a0", "2"]),
            ("add", ["a0", "a0", "a1"]),
            ("sub", ["sp", "sp", "a0"]),
            ("csrr", ["a0", "vlenb"]),
            ("slli", ["a1", "a0", "2"]),
            ("add", ["a0", "a0", "a1"]),
            ("add", ["sp", "sp", "a0"]),
            ("ret", []),
        )

        live_before, _ = _frame_liveness(function)

        self.assertFalse(live_before[0x1000])
        for address in range(0x1004, 0x1024, 4):
            self.assertTrue(live_before[address], hex(address))
        self.assertFalse(live_before[0x1024])

    def test_dead_vlenb_read_does_not_create_frame_activity(self):
        function = _function(
            ("csrr", ["a0", "vlenb"]),
            ("addi", ["a1", "a1", "1"]),
            ("ret", []),
        )

        live_before, _ = _frame_liveness(function)

        self.assertEqual(live_before, {0x1000: frozenset(), 0x1004: frozenset(), 0x1008: frozenset()})

    def test_vlen_setup_remains_live_across_unrelated_instructions(self):
        function = _function(
            ("csrr", ["a0", "vlenb"]),
            ("addi", ["t0", "t0", "1"]),
            ("sub", ["sp", "sp", "a0"]),
            ("add", ["sp", "sp", "a0"]),
            ("ret", []),
        )

        live_before, _ = _frame_liveness(function)

        self.assertTrue(live_before[0x1004])

    def test_fixed_size_stack_adjustment_is_not_vlen_activity(self):
        function = _function(
            ("addi", ["sp", "sp", "-32"]),
            ("addi", ["sp", "sp", "32"]),
            ("ret", []),
        )

        live_before, _ = _frame_liveness(function)

        self.assertTrue(all(not values for values in live_before.values()))

    def test_frame_pointer_restore_reopens_safety_after_restore(self):
        function = _function(
            ("addi", ["s0", "sp", "0"]),
            ("csrr", ["a0", "vlenb"]),
            ("sub", ["sp", "sp", "a0"]),
            ("mv", ["sp", "s0"]),
            ("ret", []),
        )

        live_before, _ = _frame_liveness(function)

        self.assertTrue(live_before[0x100C])
        self.assertFalse(live_before[0x1010])

    def test_fixed_outer_frame_restore_is_safe_after_dynamic_frame_restore(self):
        function = _function(
            ("addi", ["sp", "sp", "-32"]),
            ("csrr", ["a0", "vlenb"]),
            ("sub", ["sp", "sp", "a0"]),
            ("add", ["sp", "sp", "a0"]),
            ("addi", ["sp", "sp", "32"]),
            ("ret", []),
        )

        live_before, _ = _frame_liveness(function)

        self.assertTrue(live_before[0x100C])
        self.assertFalse(live_before[0x1010])
        self.assertFalse(live_before[0x1014])

    def test_unknown_vlen_stack_adjustment_is_conservative_through_return(self):
        function = _function(
            ("csrr", ["a0", "vlenb"]),
            ("sub", ["sp", "sp", "a0"]),
            ("div", ["sp", "sp", "a1"]),
            ("ret", []),
        )

        live_before, warnings = _frame_liveness(function)

        self.assertTrue(all(live_before[address] for address in live_before))
        self.assertIn("unknown-vlen-stack-adjustment", {warning.code for warning in warnings})

    def test_unproven_non_vlen_restore_remains_conservative(self):
        # The restore value is proven independent of ``vlenb`` - ``a1`` is
        # written from a constant inside this function - but it is not the
        # function-entry base, so the proof is not enough to release the frame.
        function = _function(
            ("csrr", ["a0", "vlenb"]),
            ("sub", ["sp", "sp", "a0"]),
            ("li", ["a1", "0"]),
            ("mv", ["sp", "a1"]),
            ("ret", []),
        )

        live_before, warnings = _frame_liveness(function)

        self.assertTrue(all(live_before[address] for address in live_before))
        self.assertIn("unproven-vlen-stack-restoration", {warning.code for warning in warnings})

    def test_caller_supplied_restore_value_is_not_proven_independent(self):
        # The same shape with a caller-supplied value.  Nothing proves it
        # independent of ``vlenb``, so it stays an unproven adjustment instead
        # of being reported as an independent (but wrong) stack base.
        function = _function(
            ("csrr", ["a0", "vlenb"]),
            ("sub", ["sp", "sp", "a0"]),
            ("mv", ["sp", "a1"]),
            ("ret", []),
        )

        live_before, warnings = _frame_liveness(function)

        self.assertTrue(all(live_before[address] for address in live_before))
        self.assertIn(
            "unknown-vlen-stack-adjustment",
            {warning.code for warning in warnings},
        )

    def test_whole_program_analyzer_runs_frame_stage_without_vector_accesses(self):
        function = _function(
            ("csrr", ["a0", "vlenb"]),
            ("sub", ["sp", "sp", "a0"]),
            ("add", ["sp", "sp", "a0"]),
            ("ret", []),
        )
        config = SimpleNamespace(at=lambda _address: frozenset())

        result = StackLivenessAnalyzer(
            semantics=RiscvStackSemantics(), emit_warnings=False
        ).analyze_program(
            _program(function),
            metadata=ChimeraMetadata.empty(),
            config_results={function.start: config},
        )

        self.assertTrue(result.by_function[function.start].live_before[0x1000])

    def test_frame_stage_also_runs_with_stack_object_metadata_mode(self):
        function = _function(
            ("csrr", ["a0", "vlenb"]),
            ("sub", ["sp", "sp", "a0"]),
            ("add", ["sp", "sp", "a0"]),
            ("ret", []),
        )
        config = SimpleNamespace(at=lambda _address: frozenset())

        result = StackLivenessAnalyzer(
            semantics=RiscvStackSemantics(), emit_warnings=False
        ).analyze_program(
            _program(function),
            metadata=ChimeraMetadata(has_stackobj_map_section=True),
            config_results={function.start: config},
        )

        self.assertTrue(result.by_function[function.start].live_before[0x1000])


if __name__ == "__main__":
    unittest.main()
