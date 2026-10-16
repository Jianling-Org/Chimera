#!/bin/sh
set -eu
# Run in the prepared directory after ime_native.S has been translated locally.
gcc -O2 -fno-tree-vectorize -fno-tree-slp-vectorize -fno-lto -march=rv64gc -mabi=lp64d -c bench.c -o bench.o
gcc -march=rv64gcv_zvfh_xsmtvdotii -mabi=lp64d -c ime_native.S -o ime_native.o
gcc -march=rv64gcv_zvfh -mabi=lp64d -c ime_translated.S rvv_baseline.S
gcc -march=rv64gcv_zvfh -mabi=lp64d bench.o ime_native.o ime_translated.o rvv_baseline.o -lm -o bench
for name in ime_native ime_translated rvv_baseline; do
    symbol=gemm_$name
    objdump -d --disassemble="$symbol" bench > "$name.dis"
    awk -v symbol="$symbol" '
        index($0, "<" symbol ">:") { found = 1; next }
        found && /^[[:space:]]*[[:xdigit:]]+:[[:space:]]+[[:xdigit:]]+[[:space:]]/ { instruction = 1 }
        END { exit !(found && instruction) }
    ' "$name.dis" || { echo "missing instructions for $symbol" >&2; exit 1; }
done
sha256sum bench bench.o ime_native.o ime_translated.o rvv_baseline.o > binaries.sha256
