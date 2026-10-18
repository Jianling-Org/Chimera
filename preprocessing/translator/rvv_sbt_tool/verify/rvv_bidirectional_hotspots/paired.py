#!/usr/bin/env python3
"""Interleave baseline/candidate samples for only the changed kernels."""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--baseline", type=Path, required=True)
parser.add_argument("--candidate", type=Path, required=True)
parser.add_argument("--samples", type=int, default=50)
parser.add_argument("--sample-ms", type=float, default=100)
parser.add_argument("--direction", choices=("forward", "reverse"))
parser.add_argument("--n", type=int)
parser.add_argument("--operators", nargs="+", choices=("f32", "f16", "q5"))
args = parser.parse_args()
args.baseline = args.baseline.resolve(); args.candidate = args.candidate.resolve()
sys.path.insert(0, str(args.baseline))
from run import command

manifest = {"samples": args.samples, "sample_ms": args.sample_ms,
            "binary_sha256": {f"{variant}/{direction}": hashlib.sha256((path / f"bench-{direction}").read_bytes()).hexdigest()
                              for variant, path in (("baseline", args.baseline), ("candidate", args.candidate))
                              for direction in ("forward", "reverse")}}
(args.candidate / "paired-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
with (args.candidate / "paired.jsonl").open("w") as output:
    for direction, operators in (("forward", ("f16",)), ("reverse", ("f32", "f16", "q5"))):
        if args.direction and direction != args.direction:
            continue
        for op in (args.operators or operators):
            for n in ((args.n,) if args.n is not None else (256, 2048, 8192)):
                for pair in range(args.samples):
                    order = ("baseline", "candidate") if pair % 2 == 0 else ("candidate", "baseline")
                    references = []
                    for variant in order:
                        path = args.baseline if variant == "baseline" else args.candidate
                        cmd = command(direction, op, "translated", n, 1, args.sample_ms)
                        cmd = [str(path / f"bench-{direction}") if item == str(args.baseline / f"bench-{direction}") else item for item in cmd]
                        started_ns = time.time_ns()
                        result = subprocess.run(cmd, cwd=path, text=True, capture_output=True, check=True)
                        record = json.loads(result.stdout)
                        if record["validation"] != "PASS": raise ValueError("Invalid performance result")
                        references.append((record["expected"], record["input_hash"]))
                        record.update(direction=direction, variant=variant, pair=pair,
                                      started_ns=started_ns, finished_ns=time.time_ns())
                        output.write(json.dumps(record) + "\n"); output.flush()
                    if references[0] != references[1]: raise ValueError("Paired inputs/results differ")
                    if (pair + 1) % 10 == 0:
                        print(json.dumps({"direction": direction, "operator": op, "n": n, "pairs": pair + 1}), flush=True)
