#!/usr/bin/env python3
"""Require complete validated runs before summarizing the three kernel timings."""

import argparse
from collections import Counter, defaultdict
import json
import math
from pathlib import Path
import re
import statistics


def kde_mode(values):
    deviation = statistics.stdev(values)
    if not deviation:
        return values[0]
    bandwidth = deviation * len(values) ** -0.2
    low, high = min(values) - 2 * bandwidth, max(values) + 2 * bandwidth
    grid = [low + (high - low) * i / 10000 for i in range(10001)]
    return max(grid, key=lambda x: sum(math.exp(-0.5 * ((x - v) / bandwidth) ** 2) for v in values))


def summarize(directory):
    rows = [json.loads(line) for line in (directory / "results.jsonl").read_text().splitlines() if line.strip()]
    config = next(row for row in rows if row["event"] == "config")
    environment = next(row for row in rows if row["event"] == "environment")
    checks = [row for row in rows if row["event"] == "validation"]
    equal = [row for row in rows if row["event"] == "native_translated_bitwise"]
    if environment["vlenb"] != 128 or len(checks) != 78 or any(row["bad"] for row in checks):
        raise ValueError("incomplete or failed independent-reference/canary validation")
    if len(equal) != 26 or not all(row["equal"] for row in equal):
        raise ValueError("incomplete or failed native/translated bitwise validation")
    if (directory / "exit-status.txt").read_text().strip() != "0":
        raise ValueError("benchmark did not exit successfully")
    timing = defaultdict(list)
    samples = defaultdict(list)
    for row in rows:
        if row["event"] == "timing":
            timing[row["impl"]].append(row["ns_per_call"])
            samples[row["impl"]].append(row["sample"])
    names = ("ime_native", "ime_translated_rvv", "rvv_baseline")
    if set(timing) != set(names) or any(sorted(samples[name]) != list(range(config["samples"])) for name in names):
        raise ValueError("missing or duplicate timing samples")
    audit = {}
    for name in ("ime_native", "ime_translated", "rvv_baseline"):
        text = (directory / f"{name}.dis").read_text()
        audit[name] = dict(Counter(re.findall(r"\b(smt\.[a-z0-9_.]+)\b", text)))
    if audit["ime_native"] != {"smt.vmadot": 16, "smt.vpack.vv": 19} or audit["ime_translated"] or audit["rvv_baseline"]:
        raise ValueError(f"unexpected final binary instruction inventory: {audit}")
    stats = {}
    for name in names:
        values = timing[name]
        stats[name] = dict(samples=len(values), mean_ns=statistics.mean(values),
                           median_ns=statistics.median(values), kde_mode_ns=kde_mode(values),
                           min_ns=min(values), max_ns=max(values))
    packing = {row["layout"]: row["ns_per_call"] for row in rows if row["event"] == "packing"}
    if set(packing) != {"ime", "rvv"}:
        raise ValueError("missing packing measurements")
    return dict(environment=environment, config=config, stats=stats, packing_ns=packing,
                native_ime_instructions=audit["ime_native"], validation_cases=24,
                validation_max_abs_error=max(row["max_abs_error"] for row in checks),
                ratios={"translated_over_ime":stats[names[1]]["kde_mode_ns"]/stats[names[0]]["kde_mode_ns"],
                        "translated_over_rvv":stats[names[1]]["kde_mode_ns"]/stats[names[2]]["kde_mode_ns"],
                        "rvv_over_ime":stats[names[2]]["kde_mode_ns"]/stats[names[0]]["kde_mode_ns"]})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    result = summarize(args.directory)
    (args.directory / "summary.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
