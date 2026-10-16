#!/bin/sh
set -eu
if [ "$#" -lt 3 ] || [ "$#" -gt 4 ]; then
    echo 'usage: build_paired.sh <forward|reverse> <absolute-baseline-kernel.o> <absolute-candidate-kernel.o> [samples=50]' >&2
    exit 2
fi
direction=$1
baseline_object=$2
candidate_object=$3
samples=${4:-50}
case "$direction" in
    forward) source_vlenb=128; target_vlenb=32; cpu_first=0; state_symbol=simulated_cpu_state_riscv64_rvv_1024_riscv64_rvv_256 ;;
    reverse) source_vlenb=32; target_vlenb=128; cpu_first=8; state_symbol=simulated_cpu_state_riscv64_rvv_256_riscv64_rvv_1024 ;;
    *) exit 2 ;;
esac
case "$samples" in 20|50) ;; *) echo 'samples must be 20 or 50' >&2; exit 2 ;; esac
for object in "$baseline_object" "$candidate_object"; do
    case "$object" in /*) ;; *) echo "object path must be absolute: $object" >&2; exit 2 ;; esac
    test -f "$object" || { echo "object not found: $object" >&2; exit 2; }
done
cd "$(dirname "$0")"
objcopy --redefine-sym bench_kernel=bench_kernel_baseline --redefine-sym "$state_symbol=${state_symbol}_baseline" "$baseline_object" "baseline-$direction.o"
objcopy --redefine-sym bench_kernel=bench_kernel_candidate --redefine-sym "$state_symbol=${state_symbol}_candidate" "$candidate_object" "candidate-$direction.o"
for variant in baseline candidate; do
    object="$variant-$direction.o"
    nm "$object" | awk -v kernel="bench_kernel_$variant" -v state="${state_symbol}_$variant" -v old="$state_symbol" '
        $NF == kernel && $(NF-1) ~ /^[Tt]$/ { defined = 1 }
        $NF == state && $(NF-1) == "U" { referenced = 1 }
        $NF == "bench_kernel" || $NF == old { stale = 1 }
        END { exit !(defined && referenced && !stale) }
    ' || { echo "invalid kernel/TLS symbols: $object" >&2; exit 1; }
    readelf -rW "$object" | awk -v state="${state_symbol}_$variant" '
        /R_RISCV_TLS_GOT_HI20/ && index($0, state) { found = 1 }
        END { exit !found }
    ' || { echo "missing initial-exec TLS relocation: $object" >&2; exit 1; }
done
objcopy --set-section-alignment .text=64 "baseline-$direction.o"
objcopy --set-section-alignment .text=64 "candidate-$direction.o"
clang -O3 -march=rv64gc -mabi=lp64d -fopenmp -fno-vectorize -fno-slp-vectorize -Wall -Wextra -DBENCH_SAMPLES="$samples" -DSOURCE_VLENB="$source_vlenb" -DTARGET_VLENB="$target_vlenb" -DCPU_FIRST="$cpu_first" -c paired.c -o "paired-driver-$direction.o"
clang -march=rv64gc -mabi=lp64d -fopenmp "paired-driver-$direction.o" "baseline-$direction.o" "candidate-$direction.o" -lm -o "bench-paired-$direction"
sha256sum paired.c "$baseline_object" "$candidate_object" "baseline-$direction.o" "candidate-$direction.o" "paired-driver-$direction.o" "bench-paired-$direction" > "build-$direction.sha256"
python3 - "$direction" "$samples" "$baseline_object" "$candidate_object" <<'PY'
import hashlib,json,sys
from pathlib import Path
def sha(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()
direction,samples,baseline,candidate=sys.argv[1:]
record={'direction':direction,'default_samples':int(samples),'baseline_object':baseline,'candidate_object':candidate,
        'original_baseline_sha256':sha(baseline),'original_candidate_sha256':sha(candidate),
        'renamed_baseline_sha256':sha(f'baseline-{direction}.o'),'renamed_candidate_sha256':sha(f'candidate-{direction}.o'),
        'driver_sha256':sha('paired.c'),'binary_sha256':sha(f'bench-paired-{direction}'),
        'symbol_names':['bench_kernel_baseline','bench_kernel_candidate'],'state_mode':'independent TLS per variant','function_entry_alignment_bytes':64}
Path(f'build-{direction}.json').write_text(json.dumps(record,indent=2)+'\n')
print(json.dumps(record))
PY
