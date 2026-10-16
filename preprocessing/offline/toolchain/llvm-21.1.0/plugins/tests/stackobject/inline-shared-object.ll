target triple = "riscv64-unknown-linux-gnu"

declare <vscale x 8 x i8>
@llvm.riscv.vle.nxv8i8.p0.i64(
    <vscale x 8 x i8>,
    ptr,
    i64)

define <vscale x 8 x i8>
@test_inline_shared(i64 %vl) {
entry:
  %buf = alloca [128 x i8], align 1

  %p = getelementptr inbounds [128 x i8],
      ptr %buf, i64 0, i64 32

  ; Path 1: LLVM RVV intrinsic
  %v = call <vscale x 8 x i8>
      @llvm.riscv.vle.nxv8i8.p0.i64(
          <vscale x 8 x i8> poison,
          ptr %p,
          i64 %vl)

  ; Path 2: inline asm
  ; Same exact stack location: (%buf, +32)
  call void asm sideeffect
      "vle8.v v9, ($0)",
      "r"(ptr %p)

  ret <vscale x 8 x i8> %v
}
