"""CFG classification: a call is never an in-function control-flow edge."""

from __future__ import annotations

import unittest

from chimera.preprocess.offline.analysis.arch.riscv.control_flow import (
    build_cfg,
    is_call_instruction,
)
from chimera.preprocess.offline.analysis.core.data_model import (
    BasicBlock,
    Function,
    Instruction,
    Program,
)


def _instruction(address: int, op: str, args=(), operand: str | None = None):
    text = f"{op} " + ",".join(args) if args else op
    return Instruction(
        address,
        4,
        op,
        list(args),
        text,
        operand=operand if operand is not None else text,
    )


def _program(*functions: Function) -> Program:
    instructions = [
        instruction for function in functions for instruction in function.insts
    ]
    return Program(
        dump_lines=[],
        functions=list(functions),
        instructions=instructions,
        instruction_by_address={
            instruction.addr: instruction for instruction in instructions
        },
        source_path=None,
    )


def _block_of(function: Function, address: int) -> BasicBlock:
    return next(
        block
        for block in function.blocks
        if any(instruction.addr == address for instruction in block.instructions)
    )


def _starts(blocks) -> list[int]:
    return [block.start for block in blocks]


class ClassificationTableTests(unittest.TestCase):
    def test_call_forms(self) -> None:
        calls = [
            ("jal", ["0x1004"], None),
            ("jal", ["ra", "0x1004"], None),
            ("jal", ["t1", "0x1004"], None),
            ("jalr", ["1124(ra)"], "1124(ra) # 2000 <callee>"),
            ("jalr", ["a3"], None),
            ("jalr", ["ra", "0(a2)"], None),
            ("call", [], None),
        ]
        for op, args, operand in calls:
            with self.subTest(op=op, args=args):
                self.assertTrue(
                    is_call_instruction(_instruction(0x1000, op, args, operand))
                )

    def test_jump_forms(self) -> None:
        jumps = [
            ("j", ["0x1004"]),
            ("jal", ["zero", "0x1004"]),
            ("jal", ["x0", "0x1004"]),
            ("jalr", ["zero", "0(a2)"]),
            ("jr", ["a2"]),
            ("ret", []),
            ("beqz", ["a0", "0x1004"]),
        ]
        for op, args in jumps:
            with self.subTest(op=op, args=args):
                self.assertFalse(
                    is_call_instruction(_instruction(0x1000, op, args))
                )


class RecursiveCallCfgTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.function = Function(
            "recursive",
            0x1000,
            [
                _instruction(0x1000, "addi", ["sp", "sp", "-16"]),
                _instruction(0x1004, "jal", ["ra", "0x1000"]),
                _instruction(0x1008, "ret"),
            ],
        )
        build_cfg(_program(cls.function))

    def test_entry_has_no_call_site_predecessor(self) -> None:
        self.assertEqual(
            _starts(_block_of(self.function, 0x1000).predecessors), []
        )

    def test_call_keeps_the_sequential_return_successor(self) -> None:
        call_block = _block_of(self.function, 0x1004)
        self.assertEqual(_starts(call_block.successors), [0x1008])
        self.assertEqual(
            self.function.instruction_by_address[0x1004].succ, {0x1008}
        )

    def test_call_target_stays_resolvable(self) -> None:
        call = self.function.instruction_by_address[0x1004]
        self.assertEqual(call.jump_targets, {0x1000})
        self.assertEqual(
            self.function.instruction_by_address[0x1000].jump_sources, {0x1004}
        )

    def test_entry_is_not_a_loop_header(self) -> None:
        self.assertEqual(
            _starts(_block_of(self.function, 0x1000).predecessors), []
        )
        self.assertEqual(
            _starts(_block_of(self.function, 0x1008).predecessors), [0x1000]
        )


class CallFormCfgTests(unittest.TestCase):
    def _function(self, specs):
        function = Function("caller", 0x1000, list(specs))
        build_cfg(_program(function))
        return function

    def test_plain_call_outside_the_function(self) -> None:
        function = self._function(
            [
                _instruction(0x1000, "addi", ["sp", "sp", "-16"]),
                _instruction(0x1004, "jal", ["ra", "0x9000"]),
                _instruction(0x1008, "ret"),
            ]
        )
        self.assertEqual(_starts(_block_of(function, 0x1004).successors), [0x1008])
        self.assertEqual(
            function.instruction_by_address[0x1004].jump_targets, {0x9000}
        )

    def test_resolved_jalr_call_to_an_internal_target(self) -> None:
        function = self._function(
            [
                _instruction(0x1000, "addi", ["sp", "sp", "-16"]),
                _instruction(
                    0x1004,
                    "jalr",
                    ["1124(ra)"],
                    operand="1124(ra) # 1000 <caller>",
                ),
                _instruction(0x1008, "ret"),
            ]
        )
        self.assertEqual(_starts(_block_of(function, 0x1000).predecessors), [])
        self.assertEqual(_starts(_block_of(function, 0x1004).successors), [0x1008])
        call = function.instruction_by_address[0x1004]
        self.assertEqual(call.jump_targets, {0x1000})

    def test_implicit_and_explicit_link_forms_agree(self) -> None:
        for args in (["0x100C"], ["ra", "0x100C"], ["t1", "0x100C"]):
            with self.subTest(args=args):
                function = self._function(
                    [
                        _instruction(0x1000, "addi", ["sp", "sp", "-16"]),
                        _instruction(0x1004, "jal", args),
                        _instruction(0x1008, "ret"),
                        _instruction(0x100C, "ret"),
                    ]
                )
                self.assertEqual(
                    _starts(_block_of(function, 0x1004).successors), [0x1008]
                )
                self.assertEqual(
                    function.instruction_by_address[0x1004].succ, {0x1008}
                )
                self.assertEqual(
                    function.instruction_by_address[0x1004].jump_targets,
                    {0x100C},
                )
                self.assertEqual(
                    _starts(_block_of(function, 0x100C).predecessors), []
                )


class JumpFormCfgTests(unittest.TestCase):
    def _function(self, specs):
        function = Function("jumps", 0x1000, list(specs))
        build_cfg(_program(function))
        return function

    def test_unconditional_jump_keeps_only_the_target(self) -> None:
        function = self._function(
            [
                _instruction(0x1000, "addi", ["a0", "a0", "1"]),
                _instruction(0x1004, "j", ["0x100C"]),
                _instruction(0x1008, "ret"),
                _instruction(0x100C, "ret"),
            ]
        )
        self.assertEqual(_starts(_block_of(function, 0x1004).successors), [0x100C])
        self.assertEqual(
            function.instruction_by_address[0x1004].succ, {0x100C}
        )

    def test_explicit_zero_link_jump_keeps_only_the_target(self) -> None:
        for args in (["zero", "0x100C"], ["x0", "0x100C"]):
            with self.subTest(args=args):
                function = self._function(
                    [
                        _instruction(0x1000, "addi", ["a0", "a0", "1"]),
                        _instruction(0x1004, "jal", args),
                        _instruction(0x1008, "ret"),
                        _instruction(0x100C, "ret"),
                    ]
                )
                self.assertEqual(
                    _starts(_block_of(function, 0x1004).successors), [0x100C]
                )
                self.assertEqual(
                    function.instruction_by_address[0x1004].succ, {0x100C}
                )

    def test_conditional_branch_keeps_both_edges(self) -> None:
        function = self._function(
            [
                _instruction(0x1000, "addi", ["a0", "a0", "1"]),
                _instruction(0x1004, "beqz", ["a0", "0x100C"]),
                _instruction(0x1008, "ret"),
                _instruction(0x100C, "ret"),
            ]
        )
        self.assertEqual(
            sorted(_starts(_block_of(function, 0x1004).successors)),
            [0x1008, 0x100C],
        )
        self.assertEqual(
            function.instruction_by_address[0x1004].succ, {0x1008, 0x100C}
        )


class EntryBackEdgeTests(unittest.TestCase):
    def _function(self, specs):
        function = Function("entry_loop", 0x1000, list(specs))
        build_cfg(_program(function))
        return function

    def test_conditional_back_edge_to_the_entry(self) -> None:
        function = self._function(
            [
                _instruction(0x1000, "addi", ["a0", "a0", "1"]),
                _instruction(0x1004, "addi", ["t0", "t0", "-1"]),
                _instruction(0x1008, "bnez", ["t0", "0x1000"]),
                _instruction(0x100C, "ret"),
            ]
        )
        self.assertEqual(
            _starts(_block_of(function, 0x1000).predecessors), [0x1000]
        )
        self.assertEqual(
            function.instruction_by_address[0x1008].succ, {0x1000, 0x100C}
        )

    def test_unconditional_jump_back_to_the_entry(self) -> None:
        function = self._function(
            [
                _instruction(0x1000, "addi", ["a0", "a0", "1"]),
                _instruction(0x1004, "addi", ["t0", "t0", "-1"]),
                _instruction(0x1008, "bnez", ["t0", "0x100C"]),
                _instruction(0x100C, "j", ["0x1000"]),
                _instruction(0x1010, "ret"),
            ]
        )
        self.assertEqual(
            _starts(_block_of(function, 0x1000).predecessors), [0x100C]
        )
        self.assertEqual(
            function.instruction_by_address[0x100C].succ, {0x1000}
        )

    def test_explicit_zero_link_jump_back_to_the_entry(self) -> None:
        function = self._function(
            [
                _instruction(0x1000, "addi", ["a0", "a0", "1"]),
                _instruction(0x1004, "addi", ["t0", "t0", "-1"]),
                _instruction(0x1008, "bnez", ["t0", "0x100C"]),
                _instruction(0x100C, "jal", ["zero", "0x1000"]),
                _instruction(0x1010, "ret"),
            ]
        )
        self.assertEqual(
            _starts(_block_of(function, 0x1000).predecessors), [0x100C]
        )
        self.assertEqual(
            function.instruction_by_address[0x100C].succ, {0x1000}
        )


class IdempotencyTests(unittest.TestCase):
    def test_repeated_build_is_stable(self) -> None:
        function = Function(
            "mixed",
            0x1000,
            [
                _instruction(0x1000, "addi", ["sp", "sp", "-16"]),
                _instruction(0x1004, "jal", ["ra", "0x1000"]),
                _instruction(0x1008, "beqz", ["a0", "0x1010"]),
                _instruction(0x100C, "j", ["0x1010"]),
                _instruction(0x1010, "ret"),
            ],
        )
        program = _program(function)
        build_cfg(program)
        first = (
            {
                block.start: (
                    _starts(block.predecessors),
                    _starts(block.successors),
                )
                for block in function.blocks
            },
            sorted(
                (
                    i.addr,
                    sorted(i.succ),
                    sorted(i.jump_targets),
                    sorted(i.jump_sources),
                )
                for i in function.insts
            ),
        )
        build_cfg(program)
        second = (
            {
                block.start: (
                    _starts(block.predecessors),
                    _starts(block.successors),
                )
                for block in function.blocks
            },
            sorted(
                (
                    i.addr,
                    sorted(i.succ),
                    sorted(i.jump_targets),
                    sorted(i.jump_sources),
                )
                for i in function.insts
            ),
        )
        self.assertEqual(first, second)


if __name__ == "__main__":
    unittest.main()
