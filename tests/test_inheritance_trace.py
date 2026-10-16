"""Inherited-closure provenance (inheritance trace) tests.

The trace records, for every function entering the inherited closure, the
first call edge that pulled it in (caller, call site, reason, depth), plus
the full list of seed edges.  It is observational only: the closure itself
must remain identical to the pre-trace behaviour.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from chimera.preprocess.offline.analysis.arch.riscv.rvv import RvvServices
from chimera.preprocess.offline.analysis.core.data_model import (
    Function,
    Instruction,
    Program,
)
from chimera.preprocess.offline.analysis.safety.exporters import (
    export_inheritance_trace,
)
from chimera.preprocess.offline.analysis.safety.stack_liveness.liveness import (
    _CallerStackContextPropagator,
)
from chimera.preprocess.offline.analysis.safety.stack_liveness.model import (
    ChimeraMetadata,
    StackFunctionLiveness,
    StackObjectId,
)

_OBJ = StackObjectId("compiler", 1)


def _call(addr: int, target: int | None) -> Instruction:
    return Instruction(
        addr=addr,
        size=4,
        op="jal",
        args=["ra", hex(target or 0)],
        text=f"jal ra, {hex(target or 0)}",
        jump_targets=set() if target is None else {target},
    )


def _function(start: int, *instructions: Instruction) -> Function:
    return Function(name=f"f_{start:x}", start=start, insts=list(instructions))


def _liveness(start: int, live_sites: tuple[int, ...] = ()) -> StackFunctionLiveness:
    return StackFunctionLiveness(
        function_start=start,
        live_before={site: frozenset({_OBJ}) for site in live_sites},
        accesses={},
    )


def _program(functions: list[Function]) -> Program:
    instructions = [inst for function in functions for inst in function.insts]
    return Program(
        dump_lines=[],
        functions=functions,
        instructions=instructions,
        instruction_by_address={inst.addr: inst for inst in instructions},
    )


def _propagate(program: Program, local_results):
    propagator = _CallerStackContextPropagator(RvvServices().stack_semantics)
    return propagator.propagate(program, local_results, ChimeraMetadata.empty())


class InheritanceTraceTests(unittest.TestCase):
    def test_seed_edge_pulls_callee_at_depth_one(self) -> None:
        a = _function(0x1000, _call(0x1010, 0x2000))
        b = _function(0x2000)
        result = _propagate(
            _program([a, b]), {0x1000: _liveness(0x1000, (0x1010,)), 0x2000: _liveness(0x2000)}
        )
        trace = result.inheritance_trace
        self.assertEqual(result.inherited_functions, frozenset({0x2000}))
        self.assertEqual(len(trace.seed_edges), 1)
        seed = trace.seed_edges[0]
        self.assertEqual((seed.caller_function_start, seed.call_site), (0x1000, 0x1010))
        self.assertEqual((seed.reason, seed.depth), ("seed", 1))
        cause = trace.first_cause[0x2000]
        self.assertEqual((cause.caller_function_start, cause.call_site), (0x1000, 0x1010))
        self.assertEqual((cause.reason, cause.depth), ("seed", 1))
        self.assertEqual(trace.max_depth, 1)

    def test_inherited_chain_increments_depth(self) -> None:
        a = _function(0x1000, _call(0x1010, 0x2000))
        b = _function(0x2000, _call(0x2010, 0x3000))
        c = _function(0x3000)
        result = _propagate(
            _program([a, b, c]),
            {
                0x1000: _liveness(0x1000, (0x1010,)),
                0x2000: _liveness(0x2000),  # purely inherited
                0x3000: _liveness(0x3000),
            },
        )
        trace = result.inheritance_trace
        self.assertEqual(result.inherited_functions, frozenset({0x2000, 0x3000}))
        self.assertEqual(len(trace.seed_edges), 1)
        cause = trace.first_cause[0x3000]
        self.assertEqual((cause.caller_function_start, cause.call_site), (0x2000, 0x2010))
        self.assertEqual((cause.reason, cause.depth), ("inherited", 2))
        self.assertEqual(trace.max_depth, 2)

    def test_locally_active_inherited_call_is_seed_in_either_order(self) -> None:
        a = _function(0x1000, _call(0x1010, 0x2000))
        b = _function(0x2000, _call(0x2010, 0x3000))
        c = _function(0x3000, _call(0x3010, None))
        local = {0x1000: _liveness(0x1000, (0x1010,)),
                 0x2000: _liveness(0x2000, (0x2010,))}

        traces = [
            _propagate(_program(order), {**local, 0x3000: _liveness(0x3000)}).inheritance_trace
            for order in ([a, b, c], [b, a, c])
        ]
        for trace in traces:
            self.assertEqual(
                {(edge.caller_function_start, edge.call_site) for edge in trace.seed_edges},
                {(0x1000, 0x1010), (0x2000, 0x2010)},
            )
            self.assertEqual(set(trace.first_cause), {0x2000, 0x3000})
            self.assertIn(trace.max_depth, (1, 2))
        self.assertEqual(
            _propagate(_program([a, b, c]), {**local, 0x3000: _liveness(0x3000)}).inherited_functions,
            _propagate(_program([b, a, c]), {**local, 0x3000: _liveness(0x3000)}).inherited_functions,
        )
        self.assertEqual(
            [_propagate(_program(order), {**local, 0x3000: _liveness(0x3000)}).unresolved_live_calls for order in ([a, b, c], [b, a, c])],
            [(0x3010,), (0x3010,)],
        )

    def test_upstream_local_source_removal_exposes_only_downstream_seed(self) -> None:
        a = _function(0x1000, _call(0x1010, 0x2000))
        b = _function(0x2000, _call(0x2010, 0x3000))
        c = _function(0x3000)
        result = _propagate(
            _program([a, b, c]),
            {0x1000: _liveness(0x1000),
             0x2000: _liveness(0x2000, (0x2010,)),
             0x3000: _liveness(0x3000)},
        )
        self.assertEqual(result.inherited_functions, frozenset({0x3000}))
        self.assertEqual(
            [(edge.caller_function_start, edge.call_site) for edge in result.inheritance_trace.seed_edges],
            [(0x2000, 0x2010)],
        )

    def test_recursive_locally_active_call_has_finite_seed_witness(self) -> None:
        recursive = _function(0x1000, _call(0x1010, 0x1000))
        result = _propagate(
            _program([recursive]), {0x1000: _liveness(0x1000, (0x1010,))}
        )
        self.assertEqual(result.inherited_functions, frozenset({0x1000}))
        self.assertEqual(len(result.inheritance_trace.seed_edges), 1)
        self.assertEqual(len(result.inheritance_trace.first_cause), 1)
        self.assertEqual(result.inheritance_trace.first_cause[0x1000].depth, 1)

    def test_first_cause_is_unique_and_deterministic(self) -> None:
        a = _function(0x1000, _call(0x1010, 0x3000))
        a2 = _function(0x2000, _call(0x2010, 0x3000))
        b = _function(0x3000)
        result = _propagate(
            _program([a, a2, b]),
            {
                0x1000: _liveness(0x1000, (0x1010,)),
                0x2000: _liveness(0x2000, (0x2010,)),
                0x3000: _liveness(0x3000),
            },
        )
        trace = result.inheritance_trace
        # Both seed edges are listed, but only the first (program order)
        # is recorded as B's first cause.
        self.assertEqual(len(trace.seed_edges), 2)
        self.assertEqual(len(trace.first_cause), 1)
        cause = trace.first_cause[0x3000]
        self.assertEqual(cause.caller_function_start, 0x1000)
        self.assertEqual(cause.depth, 1)

    def test_unresolved_call_creates_no_seed_edge(self) -> None:
        a = _function(0x1000, _call(0x1010, None))  # indirect, no metadata
        result = _propagate(
            _program([a]), {0x1000: _liveness(0x1000, (0x1010,))}
        )
        self.assertEqual(result.inherited_functions, frozenset())
        self.assertEqual(result.inheritance_trace.seed_edges, ())
        self.assertEqual(result.inheritance_trace.first_cause, {})
        self.assertEqual(result.unresolved_live_calls, (0x1010,))

    def test_propagation_is_deterministic_across_runs(self) -> None:
        a = _function(0x1000, _call(0x1010, 0x2000))
        b = _function(0x2000, _call(0x2010, 0x3000))
        c = _function(0x3000)
        local = {
            0x1000: _liveness(0x1000, (0x1010,)),
            0x2000: _liveness(0x2000),
            0x3000: _liveness(0x3000),
        }
        first = _propagate(_program([a, b, c]), local).inheritance_trace
        second = _propagate(_program([a, b, c]), local).inheritance_trace
        self.assertEqual(first.seed_edges, second.seed_edges)
        self.assertEqual(first.first_cause, second.first_cause)
        self.assertEqual(first.max_depth, second.max_depth)

    def test_export_writes_seed_edges_and_first_cause(self) -> None:
        a = _function(0x1000, _call(0x1010, 0x2000))
        b = _function(0x2000, _call(0x2010, 0x3000))
        c = _function(0x3000)
        trace = _propagate(
            _program([a, b, c]),
            {
                0x1000: _liveness(0x1000, (0x1010,)),
                0x2000: _liveness(0x2000),
                0x3000: _liveness(0x3000),
            },
        ).inheritance_trace
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "trace.json"
            export_inheritance_trace(trace, path, original_base=0x1000, module_id="main")
            document = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(document["format"], "chimera-inheritance-trace-v1")
        self.assertEqual(document["module_id"], "main")
        self.assertEqual(document["closure_size"], 2)
        self.assertEqual(document["seed_edge_count"], 1)
        self.assertEqual(document["max_depth"], 2)
        self.assertEqual(len(document["seed_edges"]), 1)
        self.assertEqual(document["seed_edges"][0]["call_site"], 0x1010)
        self.assertEqual(document["seed_edges"][0]["caller_rva"], 0x1000 - 0x1000)
        inherited = {
            entry["function_start"]: entry
            for entry in document["inherited_functions"]
        }
        self.assertEqual(inherited[0x2000]["depth"], 1)
        self.assertEqual(inherited[0x2000]["reason"], "seed")
        self.assertEqual(inherited[0x3000]["depth"], 2)
        self.assertEqual(inherited[0x3000]["reason"], "inherited")
        self.assertEqual(inherited[0x3000]["caller_function_start"], 0x2000)


if __name__ == "__main__":
    unittest.main()
