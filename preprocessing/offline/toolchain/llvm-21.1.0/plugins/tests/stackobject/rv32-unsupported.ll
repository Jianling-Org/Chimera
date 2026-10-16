; Deliberately use 64-bit pointers so this regression proves that checking
; pointer size alone is insufficient: the triple itself must be riscv64.
target datalayout = "e-m:e-p:64:64-i64:64-n32-S128"
target triple = "riscv32-unknown-linux-gnu"

declare <vscale x 8 x i8>
@llvm.riscv.vle.nxv8i8.p0.i64(
    <vscale x 8 x i8>,
    ptr,
    i64)

define <vscale x 8 x i8> @test_rv32_is_rejected(i64 %vl) {
entry:
  %buf = alloca [32 x i8], align 16
  %v = call <vscale x 8 x i8>
      @llvm.riscv.vle.nxv8i8.p0.i64(
          <vscale x 8 x i8> poison,
          ptr %buf,
          i64 %vl)
  ret <vscale x 8 x i8> %v
}
