target triple = "riscv64-unknown-linux-gnu"

declare <vscale x 8 x i8>
@llvm.riscv.vle.nxv8i8.p0.i64(
    <vscale x 8 x i8>,
    ptr,
    i64)

define <vscale x 8 x i8>
@test_optimized_multiple(i64 %which, i64 %vl) {
entry:
  %buf = alloca [128 x i8], align 1
  %base = getelementptr inbounds [128 x i8],
          ptr %buf, i64 0, i64 0

  switch i64 %which, label %case2 [
    i64 0, label %case0
    i64 1, label %case1
  ]

case0:
  %p32a = getelementptr inbounds i8,
          ptr %base, i64 32
  %v0 = call <vscale x 8 x i8>
      @llvm.riscv.vle.nxv8i8.p0.i64(
          <vscale x 8 x i8> poison,
          ptr %p32a,
          i64 %vl)
  ret <vscale x 8 x i8> %v0

case1:
  %p32b = getelementptr inbounds i8,
          ptr %base, i64 32
  %v1 = call <vscale x 8 x i8>
      @llvm.riscv.vle.nxv8i8.p0.i64(
          <vscale x 8 x i8> poison,
          ptr %p32b,
          i64 1)
  ret <vscale x 8 x i8> %v1

case2:
  %p64 = getelementptr inbounds i8,
         ptr %base, i64 64
  %v2 = call <vscale x 8 x i8>
      @llvm.riscv.vle.nxv8i8.p0.i64(
          <vscale x 8 x i8> poison,
          ptr %p64,
          i64 %vl)
  ret <vscale x 8 x i8> %v2
}