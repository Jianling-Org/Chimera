#!/usr/bin/env python3
"""Validate and summarize the primary Q3 GEMM hardware baseline."""

import argparse
import json
from pathlib import Path
import statistics
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1]))
from verify.ime_q3_gemm.summarize import kde_mode


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    workload = json.loads((HERE / "workload.json").read_text())
    rows = []
    for case in workload["cases"]:
        for direction in ("forward", "reverse"):
            path = args.directory / f"{case['name']}-{direction}-full.json"
            record = json.loads(path.read_text())
            profile = workload["paths"][direction]
            assert record["validation"] == "PASS" and record["max_abs_error"] == 0
            assert record["canaries_and_inputs_intact"] and record["translation_state_intact"]
            assert (record["M"], record["N"], record["K"]) == (case["M"], case["N"], case["K"])
            assert record["source_vlenb"] * 8 == profile["source_vlen_bits"]
            assert record["target_vlenb"] * 8 == profile["target_vlen_bits"]
            assert record["source_state_vlenb"] == [record["source_vlenb"]] * 8
            assert record["threads"] == len(record["worker_environment"]) == 8
            assert record["affinity_masks"] == [1 << cpu for cpu in profile["worker_cpus"]]
            for cpu, worker in zip(profile["worker_cpus"], record["worker_environment"]):
                assert worker["cpu_before"] == worker["cpu_after"] == cpu
                assert worker["vlenb_before"] * 8 == worker["vlenb_after"] * 8 == profile["target_vlen_bits"]
                assert worker["frequency_before_khz"] == worker["frequency_after_khz"] == profile["frequency_khz"]
            samples = record["seconds_per_call"]
            assert record["samples"] == len(samples) == 50 and all(value > 0 for value in samples)
            rows.append({"case": case["name"], "use": case["use"], "direction": direction,
                         "M": case["M"], "N": case["N"], "K": case["K"],
                         "samples": len(samples), "kde_ms": kde_mode(samples) * 1000,
                         "median_ms": statistics.median(samples) * 1000,
                         "mean_ms": statistics.mean(samples) * 1000,
                         "min_ms": min(samples) * 1000, "max_ms": max(samples) * 1000})
    summary = {"operator": workload["primary_symbol"],
               "method": "Gaussian KDE global mode, Scott bandwidth, all 50 samples",
               "boundary": "Current primary baseline; no before/after optimization claim",
               "rows": rows}
    (args.directory / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    for row in rows:
        print(json.dumps(row))
