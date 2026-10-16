#!/usr/bin/env python3
"""Summarize complete hardware samples without dropping observations."""

import argparse
from collections import defaultdict
import json
import math
from pathlib import Path
import re
import statistics
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from verify.ime_q3_gemm.summarize import kde_mode


def stats(values):
    if len(values) != 50 or any(value <= 0 for value in values):
        raise ValueError("Require 50 positive raw samples")
    return {"samples": len(values), "kde_ns": kde_mode(values),
            "median_ns": statistics.median(values), "mean_ns": statistics.mean(values),
            "min_ns": min(values), "max_ns": max(values)}


def valid(record):
    if record["direction"] not in {"forward", "reverse"}:
        raise ValueError(f"unknown direction: {record['direction']!r}")
    cpu, source, hardware, frequency = (0, 128, 32, 2200000) if record["direction"] == "forward" else (8, 32, 128, 1800000)
    if (record["validation"] != "PASS" or record["cpu"] != cpu or
        record["source_vlenb"] != source or record["hardware_vlenb"] != hardware or
        set(record["frequency_khz"]) != {frequency}):
        raise ValueError("Invalid hardware configuration or result")


def profile(directory):
    result = {}
    for path in sorted(directory.glob("perf-*.stat")):
        counters = {}
        for line in path.read_text().splitlines():
            columns = line.split(",")
            if len(columns) > 2 and columns[0].isdigit(): counters[columns[2]] = int(columns[0])
        if not {"cycles:u", "instructions:u"} <= counters.keys(): raise ValueError("Incomplete perf counters")
        if counters["cycles:u"] <= 0:
            raise ValueError(f"{path}: perf counters require positive cycles")
        hotspots = []
        for line in path.with_suffix(".annotate").read_text().splitlines():
            match = re.match(r"\s*([0-9.]+)\s*:\s*([0-9a-f]+):\s*(\S+)(.*)", line)
            if match and float(match[1]) > 0:
                hotspots.append({"sample_percent": float(match[1]), "pc": match[2], "instruction": match[3] + match[4]})
        result[path.stem] = {"counters": counters, "ipc": counters["instructions:u"] / counters["cycles:u"],
                             "top_sample_locations": sorted(hotspots, key=lambda r: r["sample_percent"], reverse=True)[:12]}
    return result


def summarize(directory):
    baseline = [json.loads(line) for line in (directory / "baseline/measure.jsonl").read_text().splitlines()]
    if len(baseline) != 36: raise ValueError("Incomplete initial operator set")
    original = {}
    for record in baseline:
        valid(record)
        key = (record["direction"], record["operator"], record["n"], record["mode"])
        if key in original: raise ValueError("Duplicate initial measurement")
        original[key] = stats(record["samples_ns"])
    expected_keys = {(direction, op, n, mode)
                     for direction in ("forward", "reverse")
                     for op in ("f32", "f16", "q5") for n in (256, 2048, 8192)
                     for mode in ("native", "translated")}
    if original.keys() != expected_keys:
        raise ValueError(f"baseline combinations: missing={sorted(expected_keys-original.keys())}, unexpected={sorted(original.keys()-expected_keys)}")
    grouped, pairs = defaultdict(list), defaultdict(list)
    for line in (directory / "optimized/paired.jsonl").read_text().splitlines():
        record = json.loads(line); valid(record)
        grouped[(record["direction"], record["operator"], record["n"], record["variant"])].append(record)
        pairs[(record["direction"], record["operator"], record["n"], record["pair"])].append(record)
    if len(grouped) != 24 or len(pairs) != 600: raise ValueError("Incomplete paired experiment")
    for records in pairs.values():
        if len(records) != 2 or {r["variant"] for r in records} != {"baseline", "candidate"}: raise ValueError("Incomplete pair")
        if records[0]["input_hash"] != records[1]["input_hash"] or records[0]["expected"] != records[1]["expected"]:
            raise ValueError("Input or reference mismatch")
    measured = {}
    for key, records in grouped.items():
        if sorted(r["pair"] for r in records) != list(range(50)): raise ValueError("Missing or repeated pair")
        for record in records:
            values = record["samples_ns"]
            if len(values) != 1 or not math.isfinite(values[0]) or values[0] <= 0:
                raise ValueError(f"{key}: each pair record requires one positive finite sample")
        measured[key] = stats([r["samples_ns"][0] for r in records])
    rows = []
    for direction in ("forward", "reverse"):
        for op in ("f32", "f16", "q5"):
            for n in (256, 2048, 8192):
                row = {"direction": direction, "operator": op, "n": n,
                       "native": original[(direction, op, n, "native")],
                       "original_translation": original[(direction, op, n, "translated")]}
                key = (direction, op, n)
                if (*key, "candidate") in measured:
                    row.update(paired_baseline=measured[(*key, "baseline")], optimized=measured[(*key, "candidate")])
                    row["speedup"] = row["paired_baseline"]["kde_ns"] / row["optimized"]["kde_ns"]
                rows.append(row)
    summary = {"method": "Gaussian KDE global mode, Scott bandwidth, all 50 observations",
               "rows": rows, "baseline_profile": profile(directory / "baseline"),
               "optimized_profile": profile(directory / "optimized")}
    (directory / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    for row in rows:
        if row["n"] == 2048:
            print(json.dumps({k: v for k, v in row.items() if k in ("direction", "operator", "n", "speedup", "paired_baseline", "optimized")}, ensure_ascii=False))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    summarize(parser.parse_args().directory)
