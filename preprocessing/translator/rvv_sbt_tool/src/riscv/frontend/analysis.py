"""Build reusable RISC-V structure before any extension analysis."""

from riscv.frontend.cfg import CFGBuilder
from riscv.frontend.call_graph import CallGraphBuilder
from riscv.frontend.text_index import TextProgramIndex
from riscv.frontend.model import (
    FunctionStructure,
    ProgramStructure,
    StructureMetrics,
    compute_program_fingerprint,
)
from riscv.frontend.model import CFGEntryKind
from riscv.frontend.model import RVProgram


def analyze_structure(program: RVProgram) -> ProgramStructure:
    index = TextProgramIndex.build(program)
    cfgs = CFGBuilder().build_program_cfg(program, text_index=index)
    call_graph = CallGraphBuilder().build(program, text_index=index)
    functions = {}
    for function in program.functions:
        if not function.instructions:
            continue
        cfg = cfgs.functions[function.start_addr]
        unreachable = frozenset(cfg.unreachable_addresses())
        for address in unreachable:
            block = cfg.instruction_to_block.get(address)
            if block is not None:
                cfg.entry_kinds.setdefault(block, CFGEntryKind.UNREACHABLE)
        functions[function.start_addr] = FunctionStructure(
            cfg, cfg.entry_points(), cfg.secondary_entry_addresses, unreachable,
        )
    metrics = StructureMetrics(
        direct_edge_count=sum(
            edge.resolved and edge.kind.value in {
                "conditional-branch", "unconditional-jump", "direct-call", "tail-call",
            }
            for function in functions.values() for edge in function.cfg.edges
        ),
        unresolved_control_transfer_count=sum(len(f.cfg.unknown_exit_addresses) for f in functions.values()),
        secondary_entry_count=sum(len(f.secondary_entry_addresses) for f in functions.values()),
        unreachable_count=sum(len(f.unreachable_addresses) for f in functions.values()),
    )
    return ProgramStructure(
        functions, call_graph, compute_program_fingerprint(program), metrics,
        index.plt_call_candidates(),
    )


def validate_structure(program: RVProgram, structure: ProgramStructure) -> None:
    """Check structure once before emission, without recomputing its fingerprint."""
    if not structure.input_fingerprint:
        raise ValueError("ProgramAnalysis 缺少输入指纹，拒绝程序级发射")

    for function in program.functions:
        if not function.instructions:
            continue
        function_structure = structure.functions.get(function.start_addr)
        if function_structure is None:
            raise ValueError(
                f"函数 {function.name}@0x{function.start_addr:x} 缺少 FunctionStructure"
            )
        if function_structure.cfg is None:
            raise ValueError(
                f"函数 {function.name}@0x{function.start_addr:x} 缺少 ControlFlowGraph"
            )

        for edge in function_structure.cfg.edges:
            if edge.target_address is None:
                if edge.resolved and edge.kind.value in {
                    "conditional-branch",
                    "unconditional-jump",
                    "direct-call",
                    "tail-call",
                }:
                    raise ValueError(
                        f"函数 {function.name} 的控制流边缺少已声明目标: "
                        f"0x{edge.source_address:x}"
                    )
