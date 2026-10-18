#!/bin/sh
set -eu
# Run in the prepared directory after ime_native.S has been translated locally.
gcc -O2 -fno-tree-vectorize -fno-tree-slp-vectorize -fno-lto -march=rv64gc -mabi=lp64d -c bench.c -o bench.o
gcc -march=rv64gcv_zvfh_xsmtvdotii -mabi=lp64d -c ime_native.S -o ime_native.o
gcc -march=rv64gcv_zvfh -mabi=lp64d -c ime_translated.S rvv_baseline.S
gcc bench.o ime_native.o ime_translated.o rvv_baseline.o -lm -o bench
for name in ime_native ime_translated rvv_baseline; do
    if test "$name" = rvv_baseline; then symbol=gemm_rvv_baseline; else symbol=gemm_$name; fi
    objdump -d --disassemble="$symbol" bench > "$name.dis"
done
sha256sum bench *.o > binaries.sha256
