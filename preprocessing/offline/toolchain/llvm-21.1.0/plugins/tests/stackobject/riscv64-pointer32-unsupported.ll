; The target triple is correct, but Chimera's 12-byte map contract requires
; 64-bit pointers in the default address space as well.
target datalayout = "e-m:e-p:32:32-i64:64-n32:64-S128"
target triple = "riscv64-unknown-linux-gnu"

declare <vscale x 8 x i8>
@llvm.riscv.vle.nxv8i8.p0.i64(
    <vscale x 8 x i8>,
    ptr,
    i64)

define <vscale x 8 x i8> @test_pointer32_is_rejected(i64 %vl) {
entry:
  %buf = alloca [32 x i8], align 16
  %v = call <vscale x 8 x i8>
      @llvm.riscv.vle.nxv8i8.p0.i64(
          <vscale x 8 x i8> poison,
          ptr %buf,
          i64 %vl)
  ret <vscale x 8 x i8> %v
}
