#!/usr/bin/env python3
"""Summarize the full-size A100 runs using the historical KDE calculation."""

import argparse
import json
import math
from pathlib import Path
import statistics

CASES = {"ffn_up_m32":(32,5632,2048), "ffn_down_m32":(32,2048,5632),
         "attn_q_m32":(32,2048,2048), "attn_kv_m32":(32,256,2048)}
NAMES = ("ime_native", "ime_translated_rvv", "rvv_baseline")


def kde_mode(values, bandwidth):
    if not bandwidth:
        return values[0]
    def density(x):
        return math.fsum(math.exp(-0.5*((x-value)/bandwidth)**2) for value in values)
    low, high = min(values), max(values)
    points = [low+(high-low)*i/4096 for i in range(4097)]
    densities = [density(x) for x in points]
    peaks = []
    ratio = (math.sqrt(5)-1)/2
    for i in range(1,4096):
        if densities[i] < densities[i-1] or densities[i] < densities[i+1]:
            continue
        a,b=points[i-1],points[i+1]
        c,d=b-ratio*(b-a),a+ratio*(b-a)
        fc,fd=density(c),density(d)
        for _ in range(80):
            if fc>fd:
                b,d,fd=d,c,fc; c=b-ratio*(b-a); fc=density(c)
            else:
                a,c,fc=c,d,fd; d=a+ratio*(b-a); fd=density(d)
        x=(a+b)/2
        peaks.append((density(x),x))
    if not peaks:
        raise ValueError("KDE peak was not bracketed")
    return max(peaks)[1]


def summarize_measurement(data, shape):
    if (tuple(data[key] for key in ("M", "N", "K")) != shape
            or data["validation"] != "PASS" or data["max_abs_error"] != 0
            or not data["canaries_and_inputs_intact"] or data["vlenb"] != 128
            or data["affinity_masks"] != [1 << cpu for cpu in range(8, 16)]):
        raise ValueError("invalid measurement")
    values = [v * 1000 for v in data["seconds_per_call"]]
    if len(values) != 50 or any(not math.isfinite(v) or v <= 0 for v in values):
        raise ValueError("invalid samples")
    bandwidth = statistics.stdev(values) * len(values) ** -0.2
    return {"kde_mode_ms": kde_mode(values, bandwidth),
            "median_ms": statistics.median(values), "mean_ms": statistics.mean(values),
            "min_ms": min(values), "max_ms": max(values), "bandwidth_ms": bandwidth,
            "half_bandwidth_mode_ms": kde_mode(values, bandwidth / 2),
            "double_bandwidth_mode_ms": kde_mode(values, bandwidth * 2),
            "iterations": data["iterations_per_sample"], "samples": 50}


def summarize(directory, candidate_results=None):
    if (directory/"full-done").read_text() != "complete\n":
        raise ValueError("run is incomplete")
    records=json.loads((directory/"full-results.json").read_text())
    indexed={(r["case"],r["implementation"]):r for r in records}
    if len(records)!=12 or set(indexed)!={(c,n) for c in CASES for n in NAMES}:
        raise ValueError("missing or duplicate cases")
    summary={}
    for case,shape in CASES.items():
        per_case={}
        for name in NAMES:
            per_case[name] = summarize_measurement(indexed[case, name]["measurement"], shape)
        if indexed[case,NAMES[0]]["output_sha256"] != indexed[case,NAMES[1]]["output_sha256"]:
            raise ValueError("native and translated output hashes differ")
        per_case["shape"]=shape
        per_case["translated_over_rvv"]=per_case[NAMES[1]]["kde_mode_ms"]/per_case[NAMES[2]]["kde_mode_ms"]
        per_case["translated_over_ime"]=per_case[NAMES[1]]["kde_mode_ms"]/per_case[NAMES[0]]["kde_mode_ms"]
        summary[case]=per_case
    if candidate_results is not None:
        candidates = json.loads(candidate_results.read_text())
        names = {record["implementation"] for record in candidates}
        if (len(candidates) != len(CASES) or {r["case"] for r in candidates} != set(CASES)
                or len(names) != 1 or names & set(NAMES)):
            raise ValueError("missing, duplicate, or ambiguous candidate results")
        for record in candidates:
            case, name = record["case"], record["implementation"]
            if record["output_sha256"] != indexed[case, NAMES[0]]["output_sha256"]:
                raise ValueError((case, "candidate and native outputs differ"))
            row = summary[case]
            row[name] = summarize_measurement(record["measurement"], CASES[case])
            row["candidate_over_rvv"] = row[name]["kde_mode_ms"] / row[NAMES[2]]["kde_mode_ms"]
            row["translation_speedup"] = row[NAMES[1]]["kde_mode_ms"] / row[name]["kde_mode_ms"]
    return summary


if __name__ == "__main__":
    p=argparse.ArgumentParser(description=__doc__); p.add_argument("directory",type=Path)
    p.add_argument("--candidate-results", type=Path, help="append one verified four-shape run to retained baselines")
    args=p.parse_args(); result=summarize(args.directory, args.candidate_results)
    output = (args.candidate_results.with_name("comparison-summary.json") if args.candidate_results
              else args.directory/"full-summary.json")
    output.write_text(json.dumps(result,indent=2)+"\n")
    print(json.dumps(result,indent=2))
