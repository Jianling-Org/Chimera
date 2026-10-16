target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n64-S128"
target triple = "riscv64-unknown-linux-gnu"

declare void @clobber()

declare <vscale x 1 x i64> @llvm.riscv.vle.nxv1i64(
    <vscale x 1 x i64>, ptr, i64)

declare void @llvm.riscv.vse.nxv1i64(
    <vscale x 1 x i64>, ptr, i64)

define void @backend_spill(ptr %in, ptr %out, i64 %vl) {
entry:
  %v = call <vscale x 1 x i64> @llvm.riscv.vle.nxv1i64(
      <vscale x 1 x i64> poison, ptr %in, i64 %vl)
  call void @clobber()
  call void @llvm.riscv.vse.nxv1i64(
      <vscale x 1 x i64> %v, ptr %out, i64 %vl)
  ret void
}
