"""Safety-analysis memory benchmark: dense state vs compact per-address state.

The benchmark runs the same synthetic program through two variants, each in its
own process on the same input:

* ``legacy`` — the analysis as of :data:`BASELINE_COMMIT`, materialised with
  ``git show <sha>:<path>`` and force-loaded before the package is imported, so
  the *actual* pre-change dense solvers run, not a switch inside the current
  code;
* ``optimized`` — the working tree.

Four stages are measured separately, because they grow for different reasons:
``program_model`` (parse + CFG), ``vector_configs`` (per-instruction
configuration results), ``stack_local`` (per-function stack liveness
accumulated over the whole program) and ``call_propagation`` (inherited-closure
propagation).  A fifth ``classification`` stage is measured for completeness.

The baseline is pinned by commit hash on purpose: ``HEAD`` moves with every
commit, so a report written against it stops meaning anything as soon as the
next commit lands.

Besides peak RSS, each stage reports the number of *retained sparse state
entries* it holds, which is the quantity this optimisation targets, and a
semantic digest over the per-address results, warnings and final
classification.  The digests of the two variants must match: a memory win that
changes the answer is not a win.  A synthetic benchmark proves the allocation
reduction; it is not a substitute for the K3 acceptance run.

Usage:
    python tools/bench_analysis_memory.py [--instructions N] [--json PATH]

Exit code is non-zero when the digests differ, or when the analysis-phase peak
RSS of the optimized variant is not at least ``--threshold`` (default 0.50)
lower than the legacy variant's.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

#: Frozen pre-change revision used as the long-lived baseline.
BASELINE_COMMIT = "93419dd7513befb00a1d8a3c2853c4001ffea9b0"

#: Files whose pre-change implementation is force-loaded for the ``legacy``
#: variant, in dependency order (leaves first, package ``__init__`` last).
_LEGACY_PATHS = (
    "preprocessing/offline/analysis/core/algorithm/dataflow.py",
    "preprocessing/offline/analysis/arch/riscv/rvv/config.py",
    "preprocessing/offline/analysis/arch/riscv/rvv/liveness.py",
    "preprocessing/offline/analysis/arch/riscv/rvv/services.py",
    "preprocessing/offline/analysis/arch/riscv/rvv/__init__.py",
    "preprocessing/offline/analysis/safety/stack_liveness/model.py",
    "preprocessing/offline/analysis/safety/stack_liveness/frame_liveness.py",
    "preprocessing/offline/analysis/safety/stack_liveness/liveness.py",
    "preprocessing/offline/analysis/safety/stack_liveness/analyzer.py",
    "preprocessing/offline/analysis/safety/stack_liveness/__init__.py",
)


def _module_name(relative_path: str) -> str:
    """Source path -> wheel package name (``preprocessing/`` -> ``preprocess/``)."""

    path = relative_path[: -len(".py")] if relative_path.endswith(".py") else relative_path
    parts = path.split("/")
    if parts[-1] == "__init__":
        parts = parts[:-1]
    if parts and parts[0] == "preprocessing":
        parts[0] = "preprocess"
    return "chimera." + ".".join(parts)


#: ``[relative path, module name]`` pairs handed to the worker so the legacy
#: loader does not have to re-derive the wheel package layout.
_LEGACY_MODULES = [[path, _module_name(path)] for path in _LEGACY_PATHS]

#: One in this many functions contains auto-vectorized code at all; the rest
#: never see a ``vset*``, so their per-instruction configuration stays at the
#: shared unknown default.
_VECTOR_FUNCTION_PERIOD = 4


_WORKER = r"""
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

REPO_ROOT = Path(sys.argv[1])
DUMP = Path(sys.argv[2])
VARIANT = sys.argv[3]
LEGACY_MODULES = json.loads(sys.argv[4])

MIN_VLEN = 256


def _load_legacy_modules() -> None:
    # Import the real package first so every parent package exists and the
    # current submodules are fully initialised; only then swap the changed
    # submodules for their baseline versions.  The list is dependency ordered
    # (leaves first, package ``__init__`` last), so each baseline module binds
    # its own baseline collaborators.
    import chimera.preprocess.offline.analysis.safety.stack_liveness  # noqa: F401

    commit = os.environ["CHIMERA_BASELINE"]
    directory = Path(tempfile.mkdtemp(prefix="chimera-analysis-legacy-"))
    for relative_path, name in LEGACY_MODULES:
        source = subprocess.run(
            ["git", "-C", str(REPO_ROOT), "show", f"{commit}:{relative_path}"],
            capture_output=True,
            check=True,
        ).stdout
        file_path = directory / relative_path.replace("/", "_")
        file_path.write_bytes(source)
        if relative_path.endswith("/__init__.py"):
            # A package module must keep its own name as ``__package__`` so its
            # relative imports resolve through the real package directory.  The
            # modules that changed are already in ``sys.modules`` (they are
            # force-loaded first, in dependency order) and therefore win; only
            # the untouched siblings are resolved from the working tree.
            spec = importlib.util.spec_from_file_location(
                name,
                file_path,
                submodule_search_locations=[
                    str(REPO_ROOT / Path(relative_path).parent)
                ],
            )
        else:
            spec = importlib.util.spec_from_file_location(name, file_path)
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)


def _peak_rss_bytes() -> int:
    try:
        with open("/proc/self/status", encoding="ascii") as status:
            for line in status:
                if line.startswith("VmHWM"):
                    return int(line.split()[1]) * 1024
    except OSError:
        pass
    if sys.platform == "win32":
        import ctypes
        from ctypes import wintypes

        class PROCESS_MEMORY_COUNTERS(ctypes.Structure):
            _fields_ = [
                ("cb", wintypes.DWORD),
                ("PageFaultCount", wintypes.DWORD),
                ("PeakWorkingSetSize", ctypes.c_size_t),
                ("WorkingSetSize", ctypes.c_size_t),
                ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                ("PagefileUsage", ctypes.c_size_t),
                ("PeakPagefileUsage", ctypes.c_size_t),
            ]

        counters = PROCESS_MEMORY_COUNTERS()
        counters.cb = ctypes.sizeof(PROCESS_MEMORY_COUNTERS)
        psapi = ctypes.windll.psapi
        kernel32 = ctypes.windll.kernel32
        psapi.GetProcessMemoryInfo.restype = wintypes.BOOL
        psapi.GetProcessMemoryInfo.argtypes = [
            wintypes.HANDLE,
            ctypes.POINTER(PROCESS_MEMORY_COUNTERS),
            wintypes.DWORD,
        ]
        kernel32.GetCurrentProcess.restype = wintypes.HANDLE
        if psapi.GetProcessMemoryInfo(
            kernel32.GetCurrentProcess(), ctypes.byref(counters), counters.cb
        ):
            return counters.PeakWorkingSetSize
    return 0


def _stored_slots(states) -> int:
    # Per-address mapping slots actually kept alive.  A dense dictionary holds
    # one slot per instruction; the compact mapping holds one per exception
    # entry, so the two numbers are the allocation difference under test.
    counter = getattr(states, "entry_count", None)
    return int(counter) if counter is not None else len(states)


def _nonempty(states) -> int:
    # Strictly non-empty states; identical for both representations.
    counter = getattr(states, "entry_count", None)
    if counter is not None:
        return int(counter)
    return sum(1 for value in states.values() if value)


def _digest_states(hasher, label, states, render) -> None:
    addresses = sorted(states)
    hasher.update(f"{label}:{len(addresses)}\n".encode())
    for address in addresses:
        value = states[address]
        if value:
            hasher.update(f"{address}={sorted(render(item) for item in value)}\n".encode())


if VARIANT == "legacy":
    _load_legacy_modules()

from chimera.preprocess.offline.analysis.arch.riscv.rvv.services import RvvServices
from chimera.preprocess.offline.analysis.arch.riscv.services import RiscvServices
from chimera.preprocess.offline.analysis.program_model.parser import parse_dump
from chimera.preprocess.offline.analysis.safety.classifier import classify_liveness
from chimera.preprocess.offline.analysis.safety.stack_liveness import (
    ChimeraMetadata,
    StackLivenessAnalyzer,
)
from chimera.preprocess.offline.analysis.safety.stack_liveness.liveness import (
    _CallerStackContextPropagator,
    _FunctionStackLivenessAnalyzer,
)
from chimera.preprocess.offline.analysis.toolchain.objdump import LinuxObjdump

adapter = LinuxObjdump("objdump")
extension = RvvServices()
architecture = RiscvServices(extension)
metadata = ChimeraMetadata.empty()
stages = []


def _stage(name, started, stored=0, nonempty=0):
    stages.append({
        "name": name,
        "elapsed_s": round(time.perf_counter() - started, 3),
        "peak_rss_bytes": _peak_rss_bytes(),
        "stored_slots": stored,
        "nonempty_states": nonempty,
    })


started = time.perf_counter()
program = architecture.build_cfg(
    parse_dump(
        DUMP,
        adapter.parse_format,
        is_external_trampoline=adapter.is_external_trampoline,
        retain_dump_lines=False,
    )
)
_stage("program_model", started)

started = time.perf_counter()
configs = extension.vector_configs(program)
_stage(
    "vector_configs",
    started,
    sum(_stored_slots(result.before_by_address) for result in configs.values()),
    sum(_nonempty(result.before_by_address) for result in configs.values()),
)

started = time.perf_counter()
local_analyzer = _FunctionStackLivenessAnalyzer(
    MIN_VLEN, semantics=extension.stack_semantics, emit_warnings=False
)
local_results = {
    function.start: local_analyzer.analyze(
        function, metadata=metadata, config_result=configs[function.start]
    )
    for function in program.functions
}
_stage(
    "stack_local",
    started,
    sum(_stored_slots(result.live_before) for result in local_results.values()),
    sum(_nonempty(result.live_before) for result in local_results.values()),
)

started = time.perf_counter()
propagator = _CallerStackContextPropagator(extension.stack_semantics)
stack = propagator.propagate(program, local_results, metadata)
_stage(
    "call_propagation",
    started,
    sum(_stored_slots(result.live_before) for result in stack.by_function.values()),
    sum(_nonempty(result.live_before) for result in stack.by_function.values()),
)

started = time.perf_counter()
vector = extension.vector_liveness(program)
records = classify_liveness(
    program, vector, stack, vector_classifier=extension.classify_vector_liveness
).records
_stage("classification", started)

hasher = hashlib.sha256()
for function in program.functions:
    key = str(function.start)
    result = configs[function.start]
    _digest_states(
        hasher,
        f"config:{key}",
        result.before_by_address,
        lambda config: config.display(),
    )
for function in program.functions:
    key = str(function.start)
    _digest_states(
        hasher,
        f"vector:{key}",
        vector.by_function[function.start].live_before,
        str,
    )
for function in program.functions:
    key = str(function.start)
    _digest_states(
        hasher,
        f"stack:{key}",
        stack.by_function[function.start].live_before,
        str,
    )
hasher.update(f"inherited={sorted(stack.inherited_functions)}\n".encode())
hasher.update(f"unresolved={list(stack.unresolved_live_calls)}\n".encode())
for warning in stack.warnings:
    hasher.update(
        f"warning={warning.code}|{warning.message}|{warning.function_start}"
        f"|{list(warning.addresses)}|{list(warning.details)}\n".encode()
    )
unsafe = sorted(
    (address, tuple(record.reasons))
    for address, record in records.items()
    if not record.safe
)
hasher.update(f"unsafe={len(unsafe)}\n".encode())
for address, reasons in unsafe:
    hasher.update(f"record={address}|{reasons}\n".encode())

print(json.dumps({
    "variant": VARIANT,
    "instructions": len(program.instructions),
    "functions": len(program.functions),
    "stages": stages,
    "peak_rss_bytes": _peak_rss_bytes(),
    "digest": hasher.hexdigest(),
}))
"""


def _pythonpath() -> str:
    return os.pathsep.join(
        [str(REPO_ROOT / "cli"), str(REPO_ROOT)]
    )


def generate_dump(path: Path, count: int) -> None:
    """Write ``count`` objdump-style instructions spread over functions.

    The mix follows a cc1-like profile: mostly straight-line scalar code with a
    modest share of branches, calls and returns, and auto-vectorized code in
    only a fraction of the functions (``_VECTOR_FUNCTION_PERIOD``), which is
    what makes the per-instruction configuration result sparse — most
    instructions are never reached by a ``vset*`` at all.
    """

    straight = (
        ("addi", "sp,sp,-64"),
        ("sd", "ra,56(sp)"),
        ("mv", "a5,a0"),
        ("ld", "ra,56(sp)"),
        ("slli", "a5,a5,2"),
        ("add", "a0,a5,a1"),
        ("lw", "a4,12(a5)"),
        ("sw", "a4,16(a5)"),
        ("li", "a5,1"),
        ("nop", ""),
    )
    with path.open("w", encoding="utf-8", newline="\n") as out:
        out.write("\nDisassembly of section .text:\n\n")
        written = 0
        fn = 0
        addr = 0x10000
        per_function = 120
        while written < count:
            out.write(f"{addr:016x} <f{fn}>:\n")
            vector_function = fn % _VECTOR_FUNCTION_PERIOD == 0
            for i in range(per_function):
                if written >= count:
                    break
                slot = i % 100
                if slot == 0:
                    op, operand = "beq", f"a5,a1,{addr + 16:x} <f{fn}+0x10>"
                elif slot == 1:
                    op, operand = "jal", f"ra,{addr + 32:x} <f{fn}+0x20>"
                elif slot == 2:
                    op, operand = "ret", ""
                elif slot == 60:
                    op, operand = "jalr", "a3"
                elif vector_function and slot == 8:
                    op, operand = "vsetivli", "zero,4,e32,m1,ta,ma"
                elif vector_function and slot == 10:
                    op, operand = "vs2r.v", "v0,(sp)"
                elif vector_function and slot == 14:
                    op, operand = "vl4re64.v", "v10,(sp)"
                elif vector_function and slot == 20:
                    op, operand = "vadd.vv", "v1,v2,v3"
                else:
                    op, operand = straight[i % len(straight)]
                if operand:
                    out.write(f"    {addr:05x}:\t{0x8082:04x}                \t{op}\t{operand}\n")
                else:
                    out.write(f"    {addr:05x}:\t{0x8082:04x}                \t{op}\n")
                addr += 4
                written += 1
            out.write("\n")
            fn += 1


def run_variant(worker_path: Path, dump_path: Path, variant: str) -> dict:
    environment = dict(os.environ, PYTHONPATH=_pythonpath())
    environment["CHIMERA_BASELINE"] = BASELINE_COMMIT
    completed = subprocess.run(
        [
            sys.executable,
            str(worker_path),
            str(REPO_ROOT),
            str(dump_path),
            variant,
            json.dumps(_LEGACY_MODULES),
        ],
        capture_output=True,
        text=True,
        env=environment,
        cwd=str(REPO_ROOT),
    )
    if completed.returncode != 0:
        raise RuntimeError(
            f"{variant} analysis worker failed (exit {completed.returncode}):\n"
            f"{completed.stderr.strip()}"
        )
    return json.loads(completed.stdout.strip().splitlines()[-1])


def _mib(value: int) -> float:
    return value / 1_048_576


def _stage_peak(result: dict, name: str) -> int:
    for stage in result["stages"]:
        if stage["name"] == name:
            return stage["peak_rss_bytes"]
    raise KeyError(name)


def main() -> int:
    argument_parser = argparse.ArgumentParser(description=__doc__)
    argument_parser.add_argument(
        "--instructions", type=int, default=150_000,
        help="number of synthetic instructions (default: 150000)",
    )
    argument_parser.add_argument(
        "--json", type=Path, default=None,
        help="optional path to write the benchmark report",
    )
    argument_parser.add_argument(
        "--threshold", type=float, default=0.50,
        help="required relative reduction of the analysis-phase peak RSS "
             "(measured from the program model to the end of call "
             "propagation) of the optimized variant over the baseline "
             "(default: 0.50)",
    )
    args = argument_parser.parse_args()

    with tempfile.TemporaryDirectory() as tmp:
        dump_path = Path(tmp) / "synthetic.dump"
        print(f"[bench] generating {args.instructions} instructions...", flush=True)
        generate_dump(dump_path, args.instructions)
        print(
            f"[bench] dump file: {_mib(dump_path.stat().st_size):.1f} MiB",
            flush=True,
        )

        worker_path = Path(tmp) / "analysis_worker.py"
        worker_path.write_text(_WORKER, encoding="utf-8")
        print(f"[bench] running LEGACY implementation ({BASELINE_COMMIT[:12]})...", flush=True)
        legacy = run_variant(worker_path, dump_path, "legacy")
        print(f"[bench] running OPTIMIZED implementation (working tree)...", flush=True)
        optimized = run_variant(worker_path, dump_path, "optimized")

    for label, result in (("legacy", legacy), ("optimized", optimized)):
        print(f"[bench] {label}: {result['instructions']} instructions, "
              f"{result['functions']} functions", flush=True)
        for stage in result["stages"]:
            print(
                f"[bench]   {stage['name']:<17} "
                f"peak {_mib(stage['peak_rss_bytes']):8.1f} MiB  "
                f"{stage['elapsed_s']:8.3f}s  "
                f"slots {stage['stored_slots']:>9}  "
                f"nonempty {stage['nonempty_states']:>9}",
                flush=True,
            )

    assert legacy["instructions"] == optimized["instructions"] == args.instructions
    assert legacy["functions"] == optimized["functions"]

    legacy_model = _stage_peak(legacy, "program_model")
    optimized_model = _stage_peak(optimized, "program_model")
    legacy_analysis = _stage_peak(legacy, "call_propagation") - legacy_model
    optimized_analysis = _stage_peak(optimized, "call_propagation") - optimized_model
    analysis_reduction = (
        1.0 - (optimized_analysis / legacy_analysis) if legacy_analysis > 0 else 0.0
    )
    total_reduction = (
        1.0 - (_stage_peak(optimized, "call_propagation")
               / _stage_peak(legacy, "call_propagation"))
    )
    _stateful = {"vector_configs", "stack_local", "call_propagation"}
    legacy_slots = sum(
        stage["stored_slots"]
        for stage in legacy["stages"]
        if stage["name"] in _stateful
    )
    optimized_slots = sum(
        stage["stored_slots"]
        for stage in optimized["stages"]
        if stage["name"] in _stateful
    )
    legacy_nonempty = sum(
        stage["nonempty_states"]
        for stage in legacy["stages"]
        if stage["name"] in _stateful
    )
    optimized_nonempty = sum(
        stage["nonempty_states"]
        for stage in optimized["stages"]
        if stage["name"] in _stateful
    )

    report = {
        "baseline_commit": BASELINE_COMMIT,
        "instructions": args.instructions,
        "legacy": legacy,
        "optimized": optimized,
        "legacy_analysis_peak_rss_bytes": legacy_analysis,
        "optimized_analysis_peak_rss_bytes": optimized_analysis,
        "analysis_peak_rss_reduction": round(analysis_reduction, 4),
        "total_peak_rss_reduction": round(total_reduction, 4),
        "legacy_stored_slots": legacy_slots,
        "optimized_stored_slots": optimized_slots,
        "legacy_nonempty_states": legacy_nonempty,
        "optimized_nonempty_states": optimized_nonempty,
        "digest_match": legacy["digest"] == optimized["digest"],
        "semantic_digest": legacy["digest"],
        "threshold": args.threshold,
        "passed": (
            legacy["digest"] == optimized["digest"]
            and analysis_reduction >= args.threshold
        ),
        "note": (
            "synthetic benchmark: proves the sparse-state allocation reduction "
            "and the unchanged semantic digest, and does not replace the K3 "
            "acceptance run"
        ),
    }

    print(f"[bench] analysis-phase peak RSS: legacy {_mib(legacy_analysis):.1f} MiB "
          f"-> optimized {_mib(optimized_analysis):.1f} MiB "
          f"({analysis_reduction:.1%} lower, target >= {args.threshold:.0%})",
          flush=True)
    print(f"[bench] end-to-end peak RSS reduction: {total_reduction:.1%}", flush=True)
    print(f"[bench] retained mapping slots: legacy {legacy_slots} "
          f"-> optimized {optimized_slots} "
          f"(same {legacy_nonempty} non-empty states)", flush=True)
    print(f"[bench] semantic digest {'matches' if report['digest_match'] else 'DIFFERS'}: "
          f"{legacy['digest'][:16]} vs {optimized['digest'][:16]}", flush=True)
    if args.json:
        args.json.write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"[bench] report written to {args.json}", flush=True)
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
