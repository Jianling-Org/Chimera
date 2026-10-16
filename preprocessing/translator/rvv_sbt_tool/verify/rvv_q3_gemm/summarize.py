#!/usr/bin/env python3
"""Validate and summarize the primary Q3 GEMM hardware baseline."""

import argparse
import json
from pathlib import Path
import statistics
import sys

from validation import read_json, require_fields

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1]))
from verify.ime_q3_gemm.summarize import kde_mode


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    workload = read_json(HERE / "workload.json")
    rows = []
    for case in workload["cases"]:
        for direction in ("forward", "reverse"):
            path = args.directory / f"{case['name']}-{direction}-full.json"
            record = read_json(path)
            require_fields(record, ('K', 'M', 'N', 'affinity_masks', 'canaries_and_inputs_intact', 'max_abs_error', 'samples', 'seconds_per_call', 'source_state_vlenb', 'source_vlenb', 'target_vlenb', 'threads', 'translation_state_intact', 'validation', 'worker_environment'), path)
            profile = workload["paths"][direction]
            if not (record['validation'] == 'PASS' and record['max_abs_error'] == 0):
                raise ValueError(f"{path}: validation failed: validation={record['validation']!r}; max_abs_error={record['max_abs_error']!r}")
            if not (record['canaries_and_inputs_intact'] and record['translation_state_intact']):
                raise ValueError(f"{path}: validation failed: canaries_and_inputs_intact={record['canaries_and_inputs_intact']!r}; translation_state_intact={record['translation_state_intact']!r}")
            if (record['M'], record['N'], record['K']) != (case['M'], case['N'], case['K']):
                raise ValueError(f"{path}: validation failed: M={record['M']!r}; N={record['N']!r}; K={record['K']!r}; expected_M={case['M']!r}; expected_N={case['N']!r}; expected_K={case['K']!r}")
            if record['source_vlenb'] * 8 != profile['source_vlen_bits']:
                raise ValueError(f"{path}: validation failed: source_vlenb={record['source_vlenb']!r}; profile_source_vlen_bits={profile['source_vlen_bits']!r}")
            if record['target_vlenb'] * 8 != profile['target_vlen_bits']:
                raise ValueError(f"{path}: validation failed: target_vlenb={record['target_vlenb']!r}; profile_target_vlen_bits={profile['target_vlen_bits']!r}")
            if record['source_state_vlenb'] != [record['source_vlenb']] * 8:
                raise ValueError(f"{path}: validation failed: source_state_vlenb={record['source_state_vlenb']!r}; source_vlenb={record['source_vlenb']!r}")
            if not record['threads'] == len(record['worker_environment']) == 8:
                raise ValueError(f"{path}: validation failed: threads={record['threads']!r}; len(worker_environment)={len(record['worker_environment'])!r}")
            if record['affinity_masks'] != [1 << cpu for cpu in profile['worker_cpus']]:
                raise ValueError(f"{path}: validation failed: affinity_masks={record['affinity_masks']!r}; profile_worker_cpus={profile['worker_cpus']!r}")
            if len(profile["worker_cpus"]) != len(record["worker_environment"]) or len(profile["worker_cpus"]) != 8:
                raise ValueError(f"{path}: worker/CPU count must equal eight")
            for cpu, worker in zip(profile["worker_cpus"], record["worker_environment"]):
                if not worker['cpu_before'] == worker['cpu_after'] == cpu:
                    raise ValueError(f"{path}: validation failed: worker_cpu_before={worker['cpu_before']!r}; worker_cpu_after={worker['cpu_after']!r}; cpu={cpu!r}")
                if not worker['vlenb_before'] * 8 == worker['vlenb_after'] * 8 == profile['target_vlen_bits']:
                    raise ValueError(f"{path}: validation failed: worker_vlenb_before={worker['vlenb_before']!r}; worker_vlenb_after={worker['vlenb_after']!r}; profile_target_vlen_bits={profile['target_vlen_bits']!r}")
                if not worker['frequency_before_khz'] == worker['frequency_after_khz'] == profile['frequency_khz']:
                    raise ValueError(f"{path}: validation failed: worker_frequency_before_khz={worker['frequency_before_khz']!r}; worker_frequency_after_khz={worker['frequency_after_khz']!r}; profile_frequency_khz={profile['frequency_khz']!r}")
            samples = record["seconds_per_call"]
            if not (record['samples'] == len(samples) == 50 and all((value > 0 for value in samples))):
                raise ValueError(f"{path}: validation failed: samples={record['samples']!r}; len(samples)={len(samples)!r}")
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
