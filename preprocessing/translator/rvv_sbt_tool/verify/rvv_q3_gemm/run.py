#!/usr/bin/env python3
"""Run the four main GEMM shapes serially after building a pilot or full harness."""

import argparse
import json
from pathlib import Path
import subprocess

HERE = Path(__file__).resolve().parent


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--implementations", nargs="+", required=True,
                        choices=("native256", "native1024", "forward", "reverse"))
    parser.add_argument("--phase", required=True, choices=("pilot", "full"))
    args = parser.parse_args()
    workload = json.loads((HERE / "workload.json").read_text())
    for case in workload["cases"]:
        for implementation in args.implementations:
            a100 = implementation in {"native1024", "reverse"}
            cpu_first, vlenb, frequency = (8, 128, 1800000) if a100 else (0, 32, 2200000)
            command = ["timeout", "180s", "taskset", "-c", f"{cpu_first}-{cpu_first + 7}",
                       str(HERE / f"bench-{implementation}"), "measure",
                       str(case["M"]), str(case["N"]), str(case["K"]),
                       str(HERE / f"{case['name']}.ref")]
            if a100:
                command = ["sh", "-c", 'printf 0 > /proc/set_ai_thread; exec "$@"', "sh", *command]
            prefix = HERE / f"{case['name']}-{implementation}-{args.phase}"
            with prefix.with_suffix(".stderr").open("w") as error:
                result = subprocess.run(command, cwd=HERE, stdout=subprocess.PIPE,
                                        stderr=error, text=True, check=True)
            prefix.with_suffix(".json").write_text(result.stdout)
            record = json.loads(result.stdout)
            expected_samples = 3 if args.phase == "pilot" else 50
            assert record["validation"] == "PASS" and record["max_abs_error"] == 0
            assert record["samples"] == expected_samples
            assert len(record["seconds_per_call"]) == expected_samples
            assert (record["M"], record["N"], record["K"]) == (case["M"], case["N"], case["K"])
            assert record["canaries_and_inputs_intact"]
            source_vlenb = 128 if implementation in {"forward", "native1024"} else 32
            assert record["source_vlenb"] == source_vlenb
            assert record["target_vlenb"] == record["vlenb"] == vlenb
            assert record["threads"] == len(record["worker_environment"]) == 8
            assert record["affinity_masks"] == [1 << (cpu_first + worker) for worker in range(8)]
            for worker, environment in enumerate(record["worker_environment"]):
                assert environment["cpu_before"] == environment["cpu_after"] == cpu_first + worker
                assert environment["vlenb_before"] == environment["vlenb_after"] == vlenb
                assert environment["frequency_before_khz"] == environment["frequency_after_khz"] == frequency
            if implementation in {"forward", "reverse"}:
                assert record["translation_state_intact"]
                assert record["source_state_vlenb"] == [source_vlenb] * 8
            print(json.dumps({"case": case["name"], "implementation": implementation,
                              "validation": record["validation"], "samples": expected_samples}), flush=True)
