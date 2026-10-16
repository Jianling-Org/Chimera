#!/usr/bin/env python3
"""Run the historical full-matrix shapes on eight A100 cores, preserving samples."""

import hashlib
import json
import os
from pathlib import Path
import subprocess
import threading
import time

ROOT = Path.cwd()
CASES = [("attn_kv_m32",32,256,2048), ("attn_q_m32",32,2048,2048),
         ("ffn_up_m32",32,5632,2048), ("ffn_down_m32",32,2048,5632)]
NAMES = ("ime_native", "ime_translated_rvv", "rvv_baseline")


def environment():
    return {"time": time.time(), "load": os.getloadavg(), "cpu_frequency": {
        str(cpu): {name: Path(f"/sys/devices/system/cpu/cpu{cpu}/cpufreq/{name}").read_text().strip()
                   for name in ("scaling_governor", "scaling_cur_freq")}
        for cpu in range(8,16)}}


def main():
    (ROOT/"full-done").unlink(missing_ok=True)
    env = os.environ.copy()
    for key in list(env):
        if key.startswith(("OMP_", "KMP_", "QEMU_", "LLAMA_")) or key in ("LD_PRELOAD", "LD_LIBRARY_PATH"):
            del env[key]
    env.update(OMP_NUM_THREADS="8", LC_ALL="C")
    results = []
    for case_index,(case,m,n,k) in enumerate(CASES):
        order = [2,0,1] if case_index % 2 == 0 else [0,2,1]
        outputs = {}
        for implementation in order:
            name = NAMES[implementation]
            print(json.dumps({"event":"started", "case":case, "implementation":name}), flush=True)
            observation = [environment()]
            stopped = threading.Event()
            observation_errors = []
            def observe():
                while not stopped.wait(5):
                    try:
                        observation.append(environment())
                    except Exception as error:
                        observation_errors.append({"time": time.time(), "error": str(error)})
                        return
            watcher = threading.Thread(target=observe)
            watcher.start()
            start = time.monotonic()
            try:
                # 900 s is a per-shape bound for the slow translation path;
                # the smallest shape is run first to expose failures early.
                proc = subprocess.run(["taskset","-c","8-15","./bench-full","measure",str(m),str(n),str(k),
                                       str(ROOT/(case+".ref")),str(implementation)],
                                      env=env,capture_output=True,text=True,timeout=900)
            except subprocess.TimeoutExpired as error:
                for suffix, value in (("stdout", error.stdout), ("stderr", error.stderr)):
                    (ROOT/f"{case}-{name}.{suffix}").write_bytes(
                        value if isinstance(value, bytes) else (value or "").encode())
                raise RuntimeError(f"{case}/{name}: timed out after 900s; partial output saved") from error
            finally:
                stopped.set(); watcher.join()
                if observation_errors:
                    (ROOT/f"{case}-{name}.environment-errors.json").write_text(
                        json.dumps(observation_errors, indent=2)+"\n")
            (ROOT/f"{case}-{name}.stdout").write_text(proc.stdout)
            (ROOT/f"{case}-{name}.stderr").write_text(proc.stderr)
            if observation_errors:
                raise RuntimeError(f"{case}/{name}: environment sampling failed: {observation_errors}")
            if proc.returncode:
                raise RuntimeError((case,name,proc.returncode,proc.stdout,proc.stderr))
            data = json.loads(proc.stdout)
            if (data["validation"] != "PASS" or data["max_abs_error"] != 0
                    or not data["canaries_and_inputs_intact"] or data["vlenb"] != 128
                    or data["affinity_masks"] != [1 << cpu for cpu in range(8,16)]
                    or len(data["seconds_per_call"]) != 50):
                raise ValueError((case,name,data))
            output = (ROOT/f"{case}.ref.{implementation}.out").read_bytes()
            outputs[name] = output
            result = {"case":case,"implementation":name,"measurement":data,
                      "wall_seconds":time.monotonic()-start,"environment":observation+[environment()],
                      "output_sha256":hashlib.sha256(output).hexdigest()}
            results.append(result)
            (ROOT/"full-results.json").write_text(json.dumps(results,indent=2)+"\n")
            print(json.dumps({"event":"finished","case":case,"implementation":name,
                              "pilot_ms":data["pilot_seconds"]*1000,"iterations":data["iterations_per_sample"],
                              "samples":50,"validation":"PASS"}),flush=True)
        if outputs["ime_native"] != outputs["ime_translated_rvv"]:
            raise ValueError(f"native/translated outputs differ: {case}")
    (ROOT/"full-done").write_text("complete\n")


if __name__ == "__main__":
    main()
