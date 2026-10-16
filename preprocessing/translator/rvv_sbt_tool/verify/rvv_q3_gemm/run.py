#!/usr/bin/env python3
"""Run the four main GEMM shapes serially after building a pilot or full harness."""

import argparse
import json
from pathlib import Path
import subprocess

from validation import read_json, require_fields

HERE = Path(__file__).resolve().parent


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--implementations", nargs="+", required=True,
                        choices=("native256", "native1024", "forward", "reverse"))
    parser.add_argument("--phase", required=True, choices=("pilot", "full"))
    args = parser.parse_args()
    workload = read_json(HERE / "workload.json")
    require_fields(workload, ("cases",), HERE / "workload.json")
    for case in workload["cases"]:
        require_fields(case, ("name", "M", "N", "K"), HERE / "workload.json")
        for implementation in args.implementations:
            a100 = implementation in {"native1024", "reverse"}
            cpu_first, vlenb, frequency = (8, 128, 1800000) if a100 else (0, 32, 2200000)
            command = ["timeout", "180s", "taskset", "-c", f"{cpu_first}-{cpu_first + 7}",
                       str(HERE / f"bench-{implementation}"), "measure",
                       str(case["M"]), str(case["N"]), str(case["K"]),
                       str(HERE / f"{case['name']}.ref")]
            if a100:
                command = ["sh", "-c", 'printf 0 > /proc/set_ai_thread && exec "$@"', "sh", *command]
            prefix = HERE / f"{case['name']}-{implementation}-{args.phase}"
            with prefix.with_suffix(".stderr").open("w") as error:
                result = subprocess.run(command, cwd=HERE, stdout=subprocess.PIPE,
                                        stderr=error, text=True, check=True)
            prefix.with_suffix(".json").write_text(result.stdout)
            record = read_json(prefix.with_suffix(".json"))
            require_fields(record, ('K', 'M', 'N', 'affinity_masks', 'canaries_and_inputs_intact', 'max_abs_error', 'samples', 'seconds_per_call', 'source_vlenb', 'target_vlenb', 'threads', 'validation', 'vlenb', 'worker_environment'), prefix)
            expected_samples = 3 if args.phase == "pilot" else 50
            if not (record['validation'] == 'PASS' and record['max_abs_error'] == 0):
                raise ValueError(f"{prefix}: validation failed: validation={record['validation']!r}; max_abs_error={record['max_abs_error']!r}")
            if record['samples'] != expected_samples:
                raise ValueError(f"{prefix}: validation failed: samples={record['samples']!r}; expected_samples={expected_samples!r}")
            if len(record['seconds_per_call']) != expected_samples:
                raise ValueError(f"{prefix}: validation failed: len(seconds_per_call)={len(record['seconds_per_call'])!r}; expected_samples={expected_samples!r}")
            if (record['M'], record['N'], record['K']) != (case['M'], case['N'], case['K']):
                raise ValueError(f"{prefix}: validation failed: M={record['M']!r}; N={record['N']!r}; K={record['K']!r}; expected_M={case['M']!r}; expected_N={case['N']!r}; expected_K={case['K']!r}")
            if not record['canaries_and_inputs_intact']:
                raise ValueError(f"{prefix}: validation failed: canaries_and_inputs_intact={record['canaries_and_inputs_intact']!r}")
            source_vlenb = 128 if implementation in {"forward", "native1024"} else 32
            if record['source_vlenb'] != source_vlenb:
                raise ValueError(f"{prefix}: validation failed: source_vlenb={record['source_vlenb']!r}")
            if not record['target_vlenb'] == record['vlenb'] == vlenb:
                raise ValueError(f"{prefix}: validation failed: target_vlenb={record['target_vlenb']!r}; vlenb={record['vlenb']!r}")
            if not record['threads'] == len(record['worker_environment']) == 8:
                raise ValueError(f"{prefix}: validation failed: threads={record['threads']!r}; len(worker_environment)={len(record['worker_environment'])!r}")
            if record['affinity_masks'] != [1 << cpu_first + worker for worker in range(8)]:
                raise ValueError(f"{prefix}: validation failed: affinity_masks={record['affinity_masks']!r}; cpu_first={cpu_first!r}")
            for worker, environment in enumerate(record["worker_environment"]):
                if not environment['cpu_before'] == environment['cpu_after'] == cpu_first + worker:
                    raise ValueError(f"{prefix}: validation failed: worker_cpu_before={environment['cpu_before']!r}; worker_cpu_after={environment['cpu_after']!r}; cpu_first={cpu_first!r}")
                if not environment['vlenb_before'] == environment['vlenb_after'] == vlenb:
                    raise ValueError(f"{prefix}: validation failed: worker_vlenb_before={environment['vlenb_before']!r}; worker_vlenb_after={environment['vlenb_after']!r}; vlenb={vlenb!r}")
                if not environment['frequency_before_khz'] == environment['frequency_after_khz'] == frequency:
                    raise ValueError(f"{prefix}: validation failed: worker_frequency_before_khz={environment['frequency_before_khz']!r}; worker_frequency_after_khz={environment['frequency_after_khz']!r}; frequency={frequency!r}")
            if implementation in {"forward", "reverse"}:
                require_fields(record, ("source_state_vlenb", "translation_state_intact"), prefix)
                if not record['translation_state_intact']:
                    raise ValueError(f"{prefix}: validation failed: translation_state_intact={record['translation_state_intact']!r}")
                if record['source_state_vlenb'] != [source_vlenb] * 8:
                    raise ValueError(f"{prefix}: validation failed: source_state_vlenb={record['source_state_vlenb']!r}; source_vlenb={source_vlenb!r}")
            print(json.dumps({"case": case["name"], "implementation": implementation,
                              "validation": record["validation"], "samples": expected_samples}), flush=True)
