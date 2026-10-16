target triple = "riscv64-unknown-linux-gnu"

@global_buf = global [128 x i8] zeroinitializer

declare <vscale x 8 x i8>
@llvm.riscv.vle.nxv8i8.p0.i64(
    <vscale x 8 x i8>,
    ptr,
    i64)

define void @test_argument(ptr %p, i64 %vl) {
entry:
  %v = call <vscale x 8 x i8>
      @llvm.riscv.vle.nxv8i8.p0.i64(
          <vscale x 8 x i8> poison,
          ptr %p,
          i64 %vl)
  ret void
}

define void @test_global(i64 %vl) {
entry:
  %p = getelementptr inbounds [128 x i8],
       ptr @global_buf, i64 0, i64 32

  %v = call <vscale x 8 x i8>
      @llvm.riscv.vle.nxv8i8.p0.i64(
          <vscale x 8 x i8> poison,
          ptr %p,
          i64 %vl)

  ret void
}
