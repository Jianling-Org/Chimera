# A100 Q3_K GEMM: native IME, translated RVV, original RVV

This directory extracts SpacemiT `gemm_kernel_i8i3k_m4` and compares native IME,
the current optimized IME-to-RVV lowering, and the pinned original
`ggml_gemm_q3_K_64x1_q8_K` RVV operator. There is one production translation
strategy; the benchmark implementation selector chooses these three operators,
not optimization versions. Historical A100 measurements are not included. The scripts require the external inputs below; importing the source does not revalidate hardware performance.

## Inputs and scope

- The IME source is the existing llama.cpp `ggml/src/ggml-cpu/spacemit/ime2_kernels.cpp`.
  Only C linkage/name and canonical `smt.` prefixes are changed during extraction.
- The original RVV symbol is extracted from `--rvv-elf`, with instruction-local
  branches relabeled. Unexpected external calls or AUIPC references are rejected.
- The compiled m4 kernel has 16 `smt.vmadot` and 19 `smt.vpack.vv` sites. No new
  translator opcode was required. The single-row `.hp` path is not selected.
- All three kernels consume the same logical Q3/Q8 quantized values. RVV uses
  Q3_Kx64/Q8_Kx4; IME uses its 32-column and four-row layouts. The independent
  reference uses the logical values, not either packed layout or a kernel output.

## Preparation

```sh
python3 verify/ime_q3_gemm/prepare.py \
  --llama-root /path/to/llama.cpp \
  --rvv-elf /path/to/pinned/llama-perplexity \
  --objdump /path/to/llvm-objdump --out /path/to/build
```

In the prepared directory on K3, compile the IME source to assembly:

```sh
g++ -S -O2 -fno-tree-vectorize -fno-tree-slp-vectorize -fno-lto \
  -fno-asynchronous-unwind-tables -fno-unwind-tables \
  -march=rv64gcv_zvfh_xsmtvdotii -mabi=lp64d ime_kernel.cpp -o ime_native.S
```

Translate that assembly with this checkout and copy the result back:

```sh
python3 verify/ime_q3_gemm/prepare.py --out /path/to/build \
  --assembly /path/to/build/ime_native.S
```

Copy `bench.c`, `build.sh`, `run-board.sh`, `ime_native.S`, `ime_translated.S`,
and `rvv_baseline.S` into the same isolated board directory. No password is
stored in any script or artifact.

```sh
sh build.sh
sh run-board.sh --k 256 --n 64 --samples 50 --rounds 32
```

`run-board.sh` uses the board's `/proc/set_ai_thread` launch procedure and pins
CPU 8. The process checks its single-CPU affinity, CPU id and vlenb=128 before
and during measurements. It does not change the CPU governor or frequency.

## Validation and timing

The correctness suite uses M=4, N=64/128, K=256/512/1024 and four deterministic
seeds (24 cases). Signed Q8 covers -128..127, Q3 covers -4..3, block scales
cover -32..31, and global scales are finite signed binary powers. It checks the
independent double reference with tolerance `2e-5*(1+abs(reference))`, exact
native/translated output equality, read-only input hashes, buffer canaries and
row-stride padding. Any failure prohibits timings. Historical results are not included; evaluate correctness from the current run before interpreting its timings.

Kernel timing uses CLOCK_MONOTONIC_RAW, five warm-up passes and fifty retained
passes. All implementations use the same repetitions per pass; their order
rotates. Outputs are consumed and checked after measurement. Packing is timed
separately using this harness's scalar conversion routines, which are not
llama.cpp's optimized production repackers. Model execution, Runtime migration,
OpenMP scheduling and input generation are not included.

Fetch results, exit status, environment logs and per-symbol disassemblies, then:

```sh
python3 verify/ime_q3_gemm/summarize.py verify/ime_q3_gemm/results
```

The summary refuses incomplete/failed runs, missing or duplicate samples,
non-identical native/translated output, or unexpected final IME instruction
counts. KDE uses Gaussian kernels and Scott bandwidth; it estimates the most
common time, not an expectation or confidence interval. All retained samples,
including slow ones, are used.

## Historical full-matrix workload

`prepare_full.py` verifies the SHA-256 of the historical 50-sample driver before
adapting it. It preserves the four M=32 shapes, logical quantized data and seed,
the RVV packed inputs, PAD=16, static worker partition, LLVM OpenMP timed region,
three warmup calls, pilot calibration to 0.1-second batches, and fifty samples.
The original RVV machine-code blob and independent reference files are copied
unchanged. Only the core range/VLEN and IME layout/row adapter are changed.

```sh
python3 verify/ime_q3_gemm/prepare_full.py \
  --historical /path/to/reference-bundle --out /path/to/full-build
```

On the board, put the generated files, the already validated `ime_native.o` /
`ime_translated.o`, and `run_full.py` in one isolated directory:

```sh
clang -O3 -march=rv64gc -mabi=lp64d -fopenmp -fno-vectorize -fno-slp-vectorize \
  -Wall -Wextra -c full-bench.c -o full-bench.o
clang -march=rv64gcv_zvfh -c kernel.S -o historical-kernel.o
clang -fopenmp full-bench.o historical-kernel.o ime_native.o ime_translated.o -lm -o bench-full
printf 0 > /proc/set_ai_thread
taskset -c 8-15 python3 run_full.py
```

The wrapper calls m4 once per four rows within each worker's original rectangle.
The RVV baseline retains the original nr/nc call shape. Packing and reference
work remain outside the timer. Native IME and translated outputs are compared
byte-for-byte after each shape, in addition to the original exact reference,
input-hash, padding and canary checks. Each implementation uses the historical
independent pilot-based repetition calibration, not the microbenchmark's fixed 32.

Fetch `full-results.json`, `full-done` and `full-manifest.json`, then run:

```sh
python3 verify/ime_q3_gemm/summarize_full.py /path/to/results
```

The full-size summary uses the historical Gaussian KDE + Scott bandwidth,
4097-point peak bracketing and golden-section refinement. A100 core 8-15 results
must be labeled separately from historical X100 core 0-7 results even though the
workload and timing method match. No historical QEMU/scalar/translation columns
are rerun or overwritten.

### Active measurement protocol revisions

New small-harness records identify `slowest-calibration-v2`: automatic calibration
uses the slowest of the three implementations to bound the common batch length.
Explicit `--rounds` still overrides calibration. Existing results keep their
original protocol and have not been recomputed.

The full-matrix summary identifies its KDE search as `endpoint-brackets-v2`.
Gaussian density, Scott bandwidth and all retained samples are unchanged; the
search now includes modes closer to a boundary than one grid step. A KDE requires
at least two positive finite samples. Duplicate packing observations are rejected.
Timeout output and background environment-sampling errors remain available even
when a run fails, and such runs never receive `full-done`.

## External reference bundle

Full-shape preparation requires an external reference bundle. Supply `--historical` with a directory containing `native.c`, `kernel.S`, `kernel.bin`, `ffn_up_m32.ref`, `ffn_down_m32.ref`, `attn_q_m32.ref`, and `attn_kv_m32.ref`. The driver hash remains pinned by `HISTORICAL_SHA`; renaming a different driver to `native.c` does not satisfy the contract. No dated private directory layout is required.

These historical inputs are not distributed here, and a public acquisition or regeneration recipe remains to be supplied. This benchmark is therefore conditional on obtaining the matching bundle; it is not a self-contained reproduction of historical hardware results.
