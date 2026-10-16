target triple = "riscv64-unknown-linux-gnu"

declare <vscale x 8 x i8>
@llvm.riscv.vle.nxv8i8.p0.i64(
    <vscale x 8 x i8>,
    ptr,
    i64)

define <vscale x 8 x i8>
@test_unknown(ptr %slot, i64 %vl) {
entry:
  ; %p 的 provenance 无法确定
  %p = load ptr, ptr %slot

  %v = call <vscale x 8 x i8>
      @llvm.riscv.vle.nxv8i8.p0.i64(
          <vscale x 8 x i8> poison,
          ptr %p,
          i64 %vl)

  ret <vscale x 8 x i8> %v
}