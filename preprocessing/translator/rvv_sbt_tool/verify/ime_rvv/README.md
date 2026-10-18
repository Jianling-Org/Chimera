# IME execution and full-state verification

The runner generates symbolic source and lowers it through the public entry.
The emitted RVV is executed, not interpreted by a Python model of the lowerer.
An independent C matrix loop checks all 64 accumulated Int32 outputs modulo
2^32. All twenty forms (base Int4/Int8 and slide 1/2/3 Int8, each with four
signedness combinations) use six register arrangements; Int8 adds collision cases and covers every even
destination, including direct accumulation at v8-v30. These exercise
destination/temporary collisions, v30/v31 boundaries, identical sources, and
vs2 sharing the second A register. Three three-instruction sequences additionally
feed previous results into subsequent IME inputs across changing frame sizes.
The six layout instructions add four immediates and six register arrangements
each, including in-place and partial overlaps, odd single-register destinations,
and v31. Two further sequences combine layout transforms with matrix operations.

```sh
python3 verify/ime_rvv/run_verify.py \
  --cc /path/to/riscv64-elf-gcc \
  --qemu /path/to/qemu-system-riscv64 \
  --build-dir /tmp/ime-rvv-check
```

QEMU uses `virt`, one hart, RVV with VLEN=1024 and no vendor IME. The freestanding
program checks 130,050 cases: e8/e16/e32/e64, all tail/mask policy combinations,
zero/one/full vl, five data patterns, and nonzero-vstart/m2/vill rejections. The
reference extracts Int4 elements by bit index; the lowerer instead processes
two products per packed byte. Patterns cover signed nibble boundaries, distinct
high/low halves, row markers, random values, and accumulator wraparound. It compares
all 32 whole vector registers, 32 GPR slots (including sp), all 32 FPRs, and
vl/vtype/vstart/vcsr/fcsr. A native RVV prefix modifies v31 before the IME input
snapshot; native RVV stores observe results afterwards. Rejection tests resume
only after catching the intended illegal-instruction trap and compare unchanged
architectural state. Stack canaries bound the deepest expansion frame. No
throughput claim is made.

Layout references use output-index mappings for pack/unpack and scalar bit
extraction for narrowing. Pack lowering copies aligned scalar chunks; the other transforms use
RVV narrowing/strided nibble extraction. Each saturated source is tested below,
at, and above its signed output limits. Initial vcsr varies through all eight
values, so accidentally setting vxsat or using vxrm is observable. Unsupported
widths reject with preserved state. The final report separates completed and
rejected cases. These tests validate the explicit layout interpretation in
`docs/IME_RVV.md`, not an independently established A100 hardware model.

## A100 Linux differential comparison

On an A100 core, with a vendor compiler supporting `xsmtvdotii` and the explicit
`i4`/`i8` assembly syntax:

```sh
python3 verify/ime_rvv/run_verify.py --native --cc gcc \
  --integer-only --build-dir /tmp/ime-rvv-a100
```

Arrange A100 affinity using the board's existing launch procedure. The program
reports its CPU and requires `vlenb=128`; the caller must ensure it remains on
A100. The native mode links both original IME and translated RVV wrappers and
compares each with the same independent reference and full-state checks.
The integer-only run uses 58,080 wrapper executions (29,040 paired cases), covering
all twenty integer forms and three dependent sequences. It is restricted to full
vl, LMUL=1 and zero vstart, with e8/e16/e32/e64 and all tail/mask policies.
All eight initial vcsr values are covered. Negative configuration tests remain
in the QEMU mode.

Without `--integer-only`, the native suite includes layout operations.
On the tested A100, the native overlapping
`smt.vpack.vv v0,v0,v1,0` raises SIGILL. This is a known hardware boundary of the
broader native comparison, not a successful native layout validation. The full
130,050-case translated QEMU suite still includes layout and overlap contracts.

The native mode requires real A100 IME support. Merely compiling it is not a
native pass. The generated `input.s`, `translated.s`, `native.s`, `cases.h` and
ELF are retained in the build directory for inspection.

## A100 translated-oracle comparison

```sh
python3 verify/ime_rvv/run_verify.py --linux --cc gcc \
  --build-dir /tmp/ime-rvv-a100-oracle
```

With the same A100 launch/affinity procedure, this executes 109,980 supported
positive configurations using only translated RVV and the independent C oracle.
It includes all integer/layout forms, overlaps, zero/one/full vl, every policy,
and all eight vcsr values. Native IME instructions are not linked in this mode;
it validates the software contract on A100 without asserting native behavior
for the known layout boundary or short vl. Rejection cases remain in QEMU.
`case-counts.json` records the exact expected counts for each execution mode.

A three-pack dependency sequence covers independent expansion boundaries with
changing chunk sizes. A host test also checks that translating adjacent pack
instructions together produces the same code as independent translation,
apart from fresh labels, including an intervening native RVV instruction.
