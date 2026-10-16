#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
CC=${CC:-clang}
# Main retains normal FP semantics for validation; only the kernel enables
# reassociation for RVV vectorization. No LTO: preserve real kernel calls.
"$CC" -std=c11 -O3 -g -fno-lto -march=rv64gcv -mabi=lp64d \
  -fopenmp=libomp -c probe.c -o probe.o
"$CC" -std=c11 -O3 -g -ffast-math -fno-lto -march=rv64gcv -mabi=lp64d \
  -c kernel.c -o kernel.o
"$CC" -fno-lto -fopenmp=libomp probe.o kernel.o -lm -o omp-kernel-probe
echo 'Built omp-kernel-probe. Verify libomp and RVV before timing (see README.md).'
