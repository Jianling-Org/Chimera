#!/usr/bin/env python3
"""Build and measure a small correctness-gated hardware operator set."""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import time

HERE = Path(__file__).resolve().parent
OPERATORS = ("f32", "f16", "q5")
GEOMETRY = {"forward": (128, 32, 0), "reverse": (32, 128, 8)}
ARCH = "rv64gcv_zfh_zvfh_zba_zbb_zbs_zfa_zicond_zihintntl"


def run(command, **kwargs):
    return subprocess.run(command, cwd=HERE, text=True, check=True, **kwargs)


def command(direction, op, mode, n, samples, sample_ms, check_only=False):
    cpu = GEOMETRY[direction][2]
    args = ["timeout", "180s", "taskset", "-c", str(cpu),
            str(HERE / f"bench-{direction}"), op, mode, str(n), str(samples),
            str(sample_ms), str(cpu), str(int(check_only))]
    # The kernel narrows ordinary processes to X100; opt out before exec on A100.
    if direction == "reverse":
        return ["sh", "-c", 'printf 0 > /proc/set_ai_thread; exec "$@"', "sh", *args]
    return args


def build():
    flags = ["gcc", "-O2", "-g", "-fno-tree-vectorize", f"-march={ARCH}", "-mabi=lp64d"]
    for direction, (source, target, _) in GEOMETRY.items():
        run([*flags, f"-DSOURCE_VLENB={source}", f"-DTARGET_VLENB={target}",
             "bench.c", *(f"native_{op}.S" for op in OPERATORS),
             *(f"{direction}_{op}.S" for op in OPERATORS), "-lm", "-o", f"bench-{direction}"])
        run(["objdump", "-d", f"bench-{direction}"], stdout=(HERE / f"{direction}.dis").open("w"))
    env = {"uname": run(["uname", "-a"], capture_output=True).stdout.strip(),
           "gcc": run(["gcc", "--version"], capture_output=True).stdout.splitlines()[0],
           "perf": run(["perf", "--version"], capture_output=True).stdout.strip(),
           "architecture": ARCH,
           "binaries": {d: hashlib.sha256((HERE / f"bench-{d}").read_bytes()).hexdigest() for d in GEOMETRY}}
    (HERE / "environment.json").write_text(json.dumps(env, indent=2) + "\n")


def measure(action, samples, sample_ms):
    output = HERE / f"{action}.jsonl"
    with output.open("w") as log:
        for direction in GEOMETRY:
            for op in OPERATORS:
                sizes = (2048,) if action in {"pilot", "check"} else (256, 2048, 8192)
                for n in sizes:
                    for mode in ("native", "translated"):
                        start = time.monotonic()
                        result = run(command(direction, op, mode, n, samples, sample_ms, action == "check"), capture_output=True)
                        record = json.loads(result.stdout)
                        record.update(direction=direction, process_seconds=time.monotonic() - start)
                        log.write(json.dumps(record) + "\n"); log.flush()
                        print(json.dumps(record), flush=True)


def profile(changed_only, selected_direction=None, selected_operators=None):
    for direction in GEOMETRY:
        if selected_direction and direction != selected_direction:
            continue
        for op in OPERATORS:
            if selected_operators and op not in selected_operators:
                continue
            if changed_only and not selected_operators and direction == "forward" and op != "f16":
                continue
            prefix = HERE / f"perf-{direction}-{op}"
            args = command(direction, op, "translated", 2048, 3, 400)
            with prefix.with_suffix(".stat").open("w") as err:
                run(["perf", "stat", "-x", ",", "-e", "cycles:u,instructions:u,branches:u,branch-misses:u", "--", *args], stdout=prefix.with_suffix(".stat.json").open("w"), stderr=err)
            run(["perf", "record", "-e", "cycles:u", "-F", "999", "-o", str(prefix.with_suffix(".data")), "--", *args], stdout=prefix.with_suffix(".record.json").open("w"), stderr=prefix.with_suffix(".record.stderr").open("w"))
            run(["perf", "report", "--stdio", "--no-children", "-i", str(prefix.with_suffix(".data"))], stdout=prefix.with_suffix(".report").open("w"))
            run(["perf", "annotate", "--stdio", "--no-source", "--symbol", f"translated_{op}", "-i", str(prefix.with_suffix(".data"))], stdout=prefix.with_suffix(".annotate").open("w"))
            print(json.dumps({"profiled": str(prefix)}), flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("build", "check", "pilot", "measure", "profile"))
    parser.add_argument("--samples", type=int, default=50)
    parser.add_argument("--sample-ms", type=float, default=100)
    parser.add_argument("--changed-only", action="store_true")
    parser.add_argument("--direction", choices=tuple(GEOMETRY))
    parser.add_argument("--operators", nargs="+", choices=OPERATORS)
    args = parser.parse_args()
    if args.action == "build": build()
    elif args.action == "profile": profile(args.changed_only, args.direction, args.operators)
    else: measure(args.action, args.samples, args.sample_ms)
