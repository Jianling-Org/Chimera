"""Export module-scoped Safety ABI artifacts."""

from __future__ import annotations

import json
from pathlib import Path

from ..core.data_model import Program
from .classifier import SafetyAnalysisResult
from .stack_liveness import InheritanceEdge, InheritanceTrace
from .stack_liveness.scope import (
    CONSERVATIVE,
    assumption_for_policy,
    is_conditional_policy,
    normalize_unknown_stack_size_policy,
)

SAFETY_ABI_VERSION = 1


def export_json(
    program: Program,
    result: SafetyAnalysisResult,
    output_path: str | Path,
    *,
    original_base: int = 0,
    module_id: str | None = None,
) -> None:
    policy = normalize_unknown_stack_size_policy(
        getattr(result, "unknown_stack_size_policy", CONSERVATIVE)
    )
    assumption = getattr(result, "assumption", assumption_for_policy(policy))
    conditional = getattr(result, "conditional", is_conditional_policy(policy))
    if (
        assumption != assumption_for_policy(policy)
        or not isinstance(conditional, bool)
        or conditional != is_conditional_policy(policy)
    ):
        raise ValueError("safety result scope metadata is inconsistent with its policy")
    scope_exclusions = tuple(getattr(result, "scope_exclusions", ()))
    if policy == CONSERVATIVE and scope_exclusions:
        raise ValueError("conservative safety results cannot contain scoped exclusions")
    # Stream entries one at a time: serialising a ~1M-entry document with a
    # single json.dumps call would hold the entire text in memory on top of
    # the records themselves.
    entries = [record for _, record in sorted(result.records.items())]
    exclusions = [
        {
            "source": item.source,
            "function_start": item.function_start,
            "function_start_hex": hex(item.function_start),
            "adjustment": item.adjustment,
            "adjustment_hex": hex(item.adjustment),
            "dependency": item.dependency,
            "size_register": item.size_register,
            "disposition": item.disposition,
            "assumption": item.assumption,
            "proof": item.proof,
            "gaps": list(item.gaps),
        }
        for item in scope_exclusions
    ]
    with Path(output_path).open("w", encoding="utf-8") as destination:
        document_prefix = {
            "format": "chimera-safety-v1",
            "unknown_stack_size_policy": policy,
            "assumption": assumption,
            "conditional": conditional,
            "scope_exclusion_count": len(exclusions),
            "scope_exclusions": exclusions,
        }
        destination.write(json.dumps(document_prefix, ensure_ascii=False, indent=2)[:-2])
        destination.write(',\n  "entries": [')
        for index, record in enumerate(entries):
            entry = {
                "address": record.address,
                "address_hex": hex(record.address),
                "original_rva": record.address - original_base,
                "safe": record.safe,
                "unsafe_reasons": list(record.reasons),
                "vector_live": sorted(record.vector_live),
                "stack_live": sorted(str(value) for value in record.stack_live),
            }
            text = json.dumps(entry, ensure_ascii=False, indent=4)
            destination.write("\n" if index == 0 else ",\n")
            destination.write("    " + text.replace("\n", "\n    "))
        destination.write("\n  ]\n}\n" if entries else "]\n}\n")


def export_inheritance_trace(
    trace: InheritanceTrace,
    output_path: str | Path,
    *,
    original_base: int = 0,
    module_id: str | None = None,
) -> None:
    """Export the inherited-closure provenance as a JSON document.

    Purely observational: explains why each function entered the inherited
    closure (which call edge pulled it in, at what depth) and lists all
    seed edges.  Entries follow discovery order, which is deterministic.
    """

    def edge_entry(edge: InheritanceEdge) -> dict[str, object]:
        return {
            "caller_function_start": edge.caller_function_start,
            "caller_function_start_hex": hex(edge.caller_function_start),
            "caller_rva": edge.caller_function_start - original_base,
            "call_site": edge.call_site,
            "call_site_hex": hex(edge.call_site),
            "reason": edge.reason,
            "depth": edge.depth,
        }

    document = {
        "format": "chimera-inheritance-trace-v1",
        "module_id": module_id,
        "closure_size": len(trace.first_cause),
        "seed_edge_count": len(trace.seed_edges),
        "max_depth": trace.max_depth,
        "seed_edges": [edge_entry(edge) for edge in trace.seed_edges],
        "inherited_functions": [
            {"function_start": function_start, "function_start_hex": hex(function_start)}
            | edge_entry(edge)
            for function_start, edge in trace.first_cause.items()
        ],
    }
    with Path(output_path).open("w", encoding="utf-8") as destination:
        json.dump(document, destination, ensure_ascii=False, indent=2)
        destination.write("\n")


def export_asm_table(
    result: SafetyAnalysisResult,
    output_path: str | Path,
    module_name: str,
    *,
    original_base: int = 0,
    emitter=None,
) -> None:
    policy = normalize_unknown_stack_size_policy(
        getattr(result, "unknown_stack_size_policy", CONSERVATIVE)
    )
    assumption = getattr(result, "assumption", assumption_for_policy(policy))
    conditional = getattr(result, "conditional", is_conditional_policy(policy))
    if (
        assumption != assumption_for_policy(policy)
        or not isinstance(conditional, bool)
        or conditional != is_conditional_policy(policy)
    ):
        raise ValueError("safety result scope metadata is inconsistent with its policy")
    scope_exclusions = tuple(getattr(result, "scope_exclusions", ()))
    if policy == CONSERVATIVE and scope_exclusions:
        raise ValueError("conservative safety results cannot contain scoped exclusions")
    symbol = "".join(character if character.isalnum() else "_" for character in module_name)
    prefix = f"chimera_{symbol}"
    records = [
        (address - original_base, record)
        for address, record in sorted(result.records.items())
        if address >= original_base
    ]
    if emitter is None or not callable(getattr(emitter, "emit_u64_table", None)):
        raise RuntimeError(
            "safety artifact emitter capability is required"
        )
    selected = emitter
    selected.emit_u64_table(output_path, (
        (f"{prefix}_safety_abi", ((SAFETY_ABI_VERSION,),)),
        (f"{prefix}_safety_entries", (
            (original, 1 if record.safe else 0)
            for original, record in records
        )),
        (f"{prefix}_safety_count", ((len(records),),)),
    ))


__all__ = [
    "SAFETY_ABI_VERSION",
    "export_asm_table",
    "export_inheritance_trace",
    "export_json",
]
