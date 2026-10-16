"""Parse-phase memory benchmark: legacy HEAD implementation vs optimized.

Compares the *actual* pre-fix implementation (parser + instruction model
taken from git HEAD) against the current working tree, each in a separate
Python process, on the same synthetic objdump text.  The legacy variant is
materialised from ``git show HEAD:...`` so both the old parser (which
reads every line into ``dump_lines``) and the old ``Instruction`` model
(plain ``set`` for ``succ``/``jump_targets``/``jump_sources``, ``list``
for ``args``) are measured — not merely the ``retain_dump_lines`` switch.

Usage:
    python tools/bench_parse_memory.py [--instructions N] [--json PATH]

Exit code is non-zero when the optimized implementation does not cut the
parse-phase peak RSS by at least --threshold (default 0.30) against the
legacy implementation.  Only relative ratios are asserted, never absolute
platform-specific memory values.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

# Files of the legacy implementation, relative to the repository root.
_LEGACY_FILES = {
    "program.py": "preprocessing/offline/analysis/core/data_model/program.py",
    "parser.py": "preprocessing/offline/analysis/program_model/parser.py",
    "control_flow.py": "preprocessing/offline/analysis/arch/riscv/control_flow.py",
}


# Worker executed in a fresh process.  For the "legacy" variant the modules
# from git HEAD are force-loaded into sys.modules *before* the real package
# is imported, so ``chimera...parser`` and the models it drags in resolve to
# the old code.  For the "optimized" variant nothing is overridden.
_WORKER = r"""
import json, subprocess, sys, tempfile, time
from pathlib import Path

REPO_ROOT = Path(sys.argv[1])
DUMP = Path(sys.argv[2])
VARIANT = sys.argv[3]

LEGACY_FILES = {
    "chimera.preprocess.offline.analysis.core.data_model.program":
        "preprocessing/offline/analysis/core/data_model/program.py",
    "chimera.preprocess.offline.analysis.program_model.parser":
        "preprocessing/offline/analysis/program_model/parser.py",
    "chimera.preprocess.offline.analysis.arch.riscv.control_flow":
        "preprocessing/offline/analysis/arch/riscv/control_flow.py",
}


def _load_legacy_modules() -> None:
    import importlib.util
    tmp = Path(tempfile.mkdtemp(prefix="chimera-legacy-src-"))
    for module_name, relpath in LEGACY_FILES.items():
        source = subprocess.run(
            ["git", "-C", str(REPO_ROOT), "show", f"HEAD:{relpath}"],
            capture_output=True, check=True,
        ).stdout
        file_path = tmp / relpath.replace("/", "_")
        file_path.write_bytes(source)
        spec = importlib.util.spec_from_file_location(module_name, file_path)
        module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = module
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
            wintypes.HANDLE, ctypes.POINTER(PROCESS_MEMORY_COUNTERS),
            wintypes.DWORD,
        ]
        kernel32.GetCurrentProcess.restype = wintypes.HANDLE
        if psapi.GetProcessMemoryInfo(
            kernel32.GetCurrentProcess(), ctypes.byref(counters), counters.cb
        ):
            return counters.PeakWorkingSetSize
    return 0


if VARIANT == "legacy":
    _load_legacy_modules()

from chimera.preprocess.offline.analysis.program_model.parser import parse_dump
from chimera.preprocess.offline.analysis.toolchain.objdump import LinuxObjdump
from chimera.preprocess.offline.analysis.arch.riscv.services import RiscvServices
from chimera.preprocess.offline.analysis.arch.riscv.rvv.services import RvvServices

adapter = LinuxObjdump("objdump")
architecture = RiscvServices(RvvServices())
kwargs = {}
if VARIANT == "optimized":
    kwargs["retain_dump_lines"] = False

start = time.perf_counter()
program = parse_dump(
    DUMP,
    adapter.parse_format,
    is_external_trampoline=adapter.is_external_trampoline,
    **kwargs,
)
parse_elapsed = time.perf_counter() - start
parse_peak = _peak_rss_bytes()

cfg_start = time.perf_counter()
program = architecture.build_cfg(program)
cfg_elapsed = time.perf_counter() - cfg_start
cfg_peak = _peak_rss_bytes()

print(json.dumps({
    "variant": VARIANT,
    "instructions": len(program.instructions),
    "functions": len(program.functions),
    "parse_elapsed_s": round(parse_elapsed, 3),
    "cfg_elapsed_s": round(cfg_elapsed, 3),
    "elapsed_s": round(parse_elapsed + cfg_elapsed, 3),
    "parse_peak_rss_bytes": parse_peak,
    "cfg_peak_rss_bytes": cfg_peak,
}))
"""


def _pythonpath() -> str:
    parts = [
        "cli",
        "preprocessing/offline/analysis",
        "preprocessing/offline/analysis_profile",
        "preprocessing/translator",
        "runtime/artifacts/manifest",
        "runtime/artifacts/scene_contracts",
        "runtime/artifacts/validate",
        "runtime/bpf/loader",
        "runtime/env/verify",
        "runtime/launcher/run",
        "runtime/launcher/preload",
    ]
    return os.pathsep.join(str(REPO_ROOT / part) for part in parts)


def generate_dump(path: Path, count: int) -> None:
    """Write ``count`` objdump-style instructions spread over functions.

    The mix follows a cc1-like profile: mostly straight-line arithmetic /
    load / store with a modest share of branches, calls, and returns.
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
            for i in range(per_function):
                if written >= count:
                    break
                # ~3 in 100 lines are control-flow, rest straight-line.
                slot = i % 100
                if slot == 0:
                    op, operand = "beq", f"a5,a1,{addr + 16:x} <f{fn}+0x10>"
                elif slot == 1:
                    op, operand = "jal", f"ra,{addr + 32:x} <f{fn}+0x20>"
                elif slot == 2:
                    op, operand = "ret", ""
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


def run_variant(dump_path: Path, variant: str) -> dict:
    env = dict(os.environ, PYTHONPATH=_pythonpath())
    completed = subprocess.run(
        [sys.executable, "-c", _WORKER, str(REPO_ROOT), str(dump_path), variant],
        capture_output=True,
        text=True,
        env=env,
        check=True,
    )
    return json.loads(completed.stdout.strip().splitlines()[-1])


def _mib(value: int) -> float:
    return value / 1_048_576


def main() -> int:
    argument_parser = argparse.ArgumentParser(description=__doc__)
    argument_parser.add_argument(
        "--instructions", type=int, default=500_000,
        help="number of synthetic instructions (default: 500000)",
    )
    argument_parser.add_argument(
        "--json", type=Path, default=None,
        help="optional path to write the benchmark report",
    )
    argument_parser.add_argument(
        "--threshold", type=float, default=0.30,
        help="required relative parse-phase peak-RSS reduction of the "
             "optimized implementation over legacy HEAD (default: 0.30)",
    )
    args = argument_parser.parse_args()

    with tempfile.TemporaryDirectory() as tmp:
        dump_path = Path(tmp) / "synthetic.dump"
        print(f"[bench] generating {args.instructions} instructions...", flush=True)
        generate_dump(dump_path, args.instructions)
        size_mb = dump_path.stat().st_size / 1_048_576
        print(f"[bench] dump file: {size_mb:.1f} MiB", flush=True)

        print("[bench] running LEGACY implementation (git HEAD)...", flush=True)
        old = run_variant(dump_path, "legacy")
        print(f"[bench]   parse peak {_mib(old['parse_peak_rss_bytes']):.1f} MiB, "
              f"post-CFG peak {_mib(old['cfg_peak_rss_bytes']):.1f} MiB, "
              f"{old['elapsed_s']}s, {old['instructions']} instructions", flush=True)

        print("[bench] running OPTIMIZED implementation (working tree)...", flush=True)
        new = run_variant(dump_path, "optimized")
        print(f"[bench]   parse peak {_mib(new['parse_peak_rss_bytes']):.1f} MiB, "
              f"post-CFG peak {_mib(new['cfg_peak_rss_bytes']):.1f} MiB, "
              f"{new['elapsed_s']}s, {new['instructions']} instructions", flush=True)

    assert old["instructions"] == new["instructions"] == args.instructions
    assert old["functions"] == new["functions"]

    def _ratio(field: str) -> float:
        base = old[field]
        return 1.0 - (new[field] / base) if base else 0.0

    parse_reduction = _ratio("parse_peak_rss_bytes")
    total_reduction = _ratio("cfg_peak_rss_bytes")
    report = {
        "instructions": args.instructions,
        "legacy": old,
        "optimized": new,
        "parse_peak_rss_reduction": round(parse_reduction, 4),
        "total_peak_rss_reduction": round(total_reduction, 4),
        "threshold": args.threshold,
        "passed": parse_reduction >= args.threshold,
    }
    print(f"[bench] parse-phase peak-RSS reduction: {parse_reduction:.1%} "
          f"(target >= {args.threshold:.0%})", flush=True)
    print(f"[bench] end-to-end peak-RSS reduction:  {total_reduction:.1%}",
          flush=True)
    if args.json:
        args.json.write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"[bench] report written to {args.json}", flush=True)
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

