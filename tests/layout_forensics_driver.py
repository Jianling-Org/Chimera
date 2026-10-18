"""K3 forensics driver: bounded logging, parse-once, strong + weak paths.

This is the testable half of ``tools/k3-forensics-layout-metadata.sh``'s
inline Python.  Two field costs are designed out:

1. **no object-graph expansion** -- every log line prints scalars only.  A
   ``Function`` owns all its instructions; formatting one walks the whole
   body.  The exact allocation responsible for the field OOM is unconfirmed.
2. **parse once** -- the Program, CFG and call edges are built exactly once
   and handed to :func:`layout_propagation_trace.trace_from_bound_edges`.
   The previous driver called ``trace_from_elf`` afterwards, which loaded
   and parsed the same ELF a second time.

Stage events name the phase, the PID, a monotonic elapsed time and the
``VmRSS``/``VmHWM``/``VmSwap`` counters in KiB.  A failed ``/proc`` read
only omits the counters; it never breaks the run.  Nothing here measures
object size.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path
from time import perf_counter

# Reused lightweight sampler: VmRSS/VmHWM/VmSwap in KiB, {} on failure.
from chimera.preprocess.offline.analysis.program_model.parser import (  # noqa: E402
    _memory_fields,
)

from layout_propagation_trace import (  # noqa: E402
    call_edges_from_objdump,
    describe,
    function_at,
    function_containing,
    function_summary,
    load_production_program,
    parse_objdump_line,
    resolve_call_target,
    resolved_call_edges,
    trace_from_bound_edges,
)

__all__ = ["run_trace", "function_summary", "stage_event"]


class _Tee:
    """One log line to two sinks: the caller's stream and the artifact file."""

    __slots__ = ("_stream", "_file")

    def __init__(self, stream, file) -> None:
        self._stream = stream
        self._file = file

    def write(self, message: str) -> int:
        self._stream.write(message)
        self._file.write(message)
        return len(message)

    def flush(self) -> None:
        self._stream.flush()
        self._file.flush()


def _log(log, message: str) -> None:
    stream = sys.stdout if log is None else log
    stream.write(message + "\n")
    stream.flush()


def stage_event(log, stage: str, phase: str, started: float) -> None:
    """One flushed observability line: ``stage=<name> <begin|end> ...``.

    Fields: ``pid``, ``elapsed_s`` (monotonic, from ``started``), and the
    KiB memory counters when readable.  Failure to sample omits the
    counters.  This function must never format analysis objects.
    """

    elapsed = perf_counter() - started
    parts = [
        f"stage={stage} {phase}",
        f"pid={os.getpid()}",
        f"elapsed_s={elapsed:.3f}",
    ]
    try:
        fields = _memory_fields()
    except Exception:  # noqa: BLE001 -- observability must not break the run
        fields = {}
    for key in ("vmrss", "vmhwm", "vmswap"):
        if key in fields:
            parts.append(f"{key}_kib={fields[key]}")
    _log(log, " ".join(parts))


class _Stage:
    """Context manager emitting ``begin`` / ``end`` for one named stage."""

    __slots__ = ("_log", "name", "_started")

    def __init__(self, log, name: str) -> None:
        self._log = log
        self.name = name
        self._started = 0.0

    def __enter__(self):
        self._started = perf_counter()
        stage_event(self._log, self.name, "begin", self._started)
        return self

    def __exit__(self, exc_type, exc, tb):
        suffix = " status=ok" if exc_type is None else f" status=error error={exc_type.__name__}"
        stage_event(self._log, self.name, "end" + suffix, self._started)
        return False


def _sha256(path: Path) -> str:
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def run_trace(
    *,
    elf: str | Path | None,
    out: Path,
    site: int,
    layout_symbol: str,
    inheritance: str | None = None,
    max_depth: int = 8,
    dump_text: str | None = None,
    metadata=None,
    objdump_cmd: str = "objdump",
    expected_sha256: str | None = None,
    log=None,
) -> dict:
    """Collect the forward propagation trace.  Returns the payload dict.

    ``dump_text`` / ``metadata`` / ``expected_sha256`` are test seams; the
    K3 script leaves them at their defaults so the real ELF is disassembled
    and hashed.  The payload is also written to ``out / "smallest-site-trace.json"``.
    Every log line is flushed per line to ``log`` (default ``sys.stdout``)
    and persisted to ``out / "smallest-site-trace.log"``.
    """

    log = sys.stdout if log is None else log
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    log_file = (out / "smallest-site-trace.log").open("w", encoding="utf-8")
    log = _Tee(log, log_file)
    try:
        payload: dict = {
            "format": "chimera-layout-propagation-trace-v3",
            "direction": "layout -> callees -> affected-site host (FORWARD)",
            "note": (
                "the affected site is a descendant of layout's active calls, not "
                "a caller of it; per-ELF addresses, compare across builds by "
                "symbol and call context only; only the production "
                "_CallTargetResolver path may authorise analysis-trace"
            ),
            "site": hex(site),
        }

        # ---------------------------------------------------- audit identity
        if expected_sha256 is None and elf is not None:
            with _Stage(log, "identity"):
                audit_sha = _sha256(Path(elf))
        else:
            audit_sha = expected_sha256 or ""
        payload["audit_elf_sha256"] = audit_sha
        payload["inheritance"] = inheritance

        # ------------------------------------------- STRONG path, parse once
        source_object_id = "irreducible:?"
        production_edges: list = []
        program = None
        metadata_obj = metadata
        host_entry = None
        layout_entry = None

        try:
            if metadata_obj is None and elf is not None:
                with _Stage(log, "metadata"):
                    from chimera.preprocess.offline.analysis.safety.stack_liveness.model import (
                        ChimeraMetadata,
                    )

                    metadata_obj = ChimeraMetadata.from_elf(elf)

            program, metadata_obj = load_production_program(
                elf,
                objdump_cmd=objdump_cmd,
                dump_text=dump_text,
                metadata=metadata_obj,
                stage_factory=lambda name: _Stage(log, name),
            )
            n_insts = len(program.instructions)
            n_funcs = len(program.functions)
            _log(log, f"program functions={n_funcs} instructions={n_insts}")
            with _Stage(log, "call_edges"):
                production_edges = resolved_call_edges(program, metadata=metadata_obj)
            host_entry = function_containing(program, site)
            layout_entry = next(
                (f for f in program.functions if f.name == layout_symbol), None
            )
            _log(
                log,
                "production call_edges="
                f"{len(production_edges)} host={host_entry} "
                f"layout={function_summary(layout_entry) if layout_entry else None}",
            )
        except Exception as error:  # noqa: BLE001 -- diagnosis must not abort the run
            _log(log, f"production pipeline unavailable: {error}")
            program = None
            production_edges = []

        if layout_entry is not None:
            source_object_id = f"irreducible:{layout_entry.start:x}"
        payload["source_object_id"] = source_object_id

        strong_result = None
        if layout_entry is not None and host_entry is not None and production_edges:
            try:
                strong_result = trace_from_bound_edges(
                    production_edges,
                    inheritance_path=inheritance,
                    expected_sha256=audit_sha,
                    source_object_id=source_object_id,
                    source_start=layout_entry.start,
                    host_start=host_entry[0],
                    max_depth=max_depth,
                    stage_factory=lambda name: _Stage(log, name),
                )
                _log(
                    log,
                    "strong grade="
                    f"{strong_result.grade} "
                    f"is_propagation_evidence={strong_result.is_propagation_evidence}",
                )
            except Exception as error:  # noqa: BLE001 -- diagnosis must not abort the run
                _log(log, f"strong pipeline unavailable: {error}")
                strong_result = None

        # Save the bounded scalars we still need, then release every reference to
        # the Program / metadata / Function objects / edge list before the weak
        # path.  The weak path must not be able to keep the whole CFG alive.
        production_edges_count = len(production_edges) if production_edges else 0
        strong_describe = describe(strong_result) if strong_result is not None else None
        del program, metadata_obj, production_edges, layout_entry, host_entry, strong_result

        # ------------------------------------------------- WEAK path, degraded
        _log(log, "--- weak path: disassembly-suspected edges (reachability only) ---")
        weak_result = None
        weak_edges_count = 0
        if elf is not None:
            try:
                nm = subprocess.check_output(
                    ["nm", "-n", str(elf)], text=True, errors="replace"
                )
                functions = []
                external_trampolines = set()
                for line in nm.splitlines():
                    parts = line.split()
                    if len(parts) >= 3 and parts[1] in "tTwW":
                        try:
                            start = int(parts[0], 16)
                        except ValueError:
                            continue
                        functions.append((start, parts[2]))
                        if "@plt" in parts[2]:
                            external_trampolines.add(start)
                functions.sort()
                names = {name: start for start, name in functions}
                functions_by_start = {start: name for start, name in functions}

                host = function_at(functions, site)
                layout_entry_nm = next(
                    (item for item in functions if item[1] == layout_symbol), None
                )
                _log(
                    log,
                    f"nm host {site:#x} -> {host} external_trampolines="
                    f"{len(external_trampolines)}",
                )

                line_by_caller: dict[str, list[str]] = {}
                if layout_entry_nm is not None:
                    frontier = [layout_symbol]
                    seen: set[str] = set()
                    while frontier and len(seen) < 64:
                        current = frontier.pop()
                        if current in seen:
                            continue
                        seen.add(current)
                        dump = subprocess.check_output(
                            ["objdump", "-d", f"--disassemble={current}", str(elf)],
                            text=True,
                            errors="replace",
                        )
                        rows = [
                            line
                            for line in dump.splitlines()
                            if parse_objdump_line(line, names)
                        ]
                        line_by_caller[current] = rows
                        for line in rows:
                            candidate = parse_objdump_line(line, names)
                            if candidate is None or not candidate.is_call:
                                continue
                            target = resolve_call_target(
                                functions_by_start,
                                candidate.target_address,
                                external_trampolines=external_trampolines,
                            )
                            if target is not None and target not in seen:
                                frontier.append(functions_by_start[target])

                weak_edges = call_edges_from_objdump(
                    functions, line_by_caller, external_trampolines=external_trampolines
                )
                weak_edges_count = len(weak_edges)
                _log(log, f"suspected call edges={weak_edges_count}")

                if layout_entry_nm is not None and host is not None:
                    weak_result = trace_from_bound_edges(
                        weak_edges,
                        inheritance_path=inheritance,
                        expected_sha256=audit_sha,
                        source_object_id=source_object_id,
                        source_start=layout_entry_nm[0],
                        host_start=host[0],
                        max_depth=max_depth,
                    )
                    _log(
                        log,
                        f"weak grade={weak_result.grade} "
                        f"is_propagation_evidence={weak_result.is_propagation_evidence}",
                    )
                del functions, line_by_caller, weak_edges
            except Exception as error:  # noqa: BLE001 -- diagnosis must not abort the run
                _log(log, f"weak pipeline unavailable: {error}")
                weak_result = None
                weak_edges_count = 0

        # ------------------------------------------------------------- payload
        if strong_describe is not None:
            result_fields = strong_describe
            path_grade = "production"
            selected = "strong"
        elif weak_result is not None:
            result_fields = describe(weak_result)
            path_grade = "disassembly-suspected"
            selected = "weak"
        else:
            result_fields = {
                "grade": "insufficient-evidence",
                "is_propagation_evidence": False,
                "first_edge_carried_object": None,
                "source_id": source_object_id,
                "source_object_id": source_object_id,
                "inheritance_bound": False,
                "reason": "neither the production pipeline nor the disassembly path ran",
                "steps": [],
            }
            path_grade = "none"
            selected = "none"

        payload.update(result_fields)
        payload["path_grade"] = path_grade
        payload["selected_path"] = selected
        # The two edge counts are scalars captured before the objects were freed.
        payload["production_call_edges"] = production_edges_count
        payload["suspected_call_edges"] = weak_edges_count
        payload["weak_grade"] = None if weak_result is None else weak_result.grade
        payload["weak_is_propagation_evidence"] = (
            False if weak_result is None else weak_result.is_propagation_evidence
        )
        payload["g2_filled"] = bool(
            payload["is_propagation_evidence"] and path_grade == "production"
        )

        out.mkdir(parents=True, exist_ok=True)
        (out / "smallest-site-trace.json").write_text(
            json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8"
        )
        _log(log, f"wrote {out / 'smallest-site-trace.json'}")
        _log(log, f"path_grade: {path_grade}")
        _log(log, f"grade: {payload['grade']}")
        _log(log, f"is_propagation_evidence: {payload['is_propagation_evidence']}")
        _log(log, f"inheritance_bound: {payload.get('inheritance_bound')}")
        _log(log, f"g2_filled: {payload['g2_filled']}")
        return payload
    finally:
        log_file.close()
