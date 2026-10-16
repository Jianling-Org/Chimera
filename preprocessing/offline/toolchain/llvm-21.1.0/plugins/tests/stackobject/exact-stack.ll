target triple = "riscv64-unknown-linux-gnu"

declare <vscale x 8 x i8>
@llvm.riscv.vle.nxv8i8.p0.i64(
    <vscale x 8 x i8>,
    ptr,
    i64)

define <vscale x 8 x i8> @test_exact(i64 %vl) {
entry:
  %buf = alloca [128 x i8], align 1
  %p0 = getelementptr inbounds [128 x i8], ptr %buf, i64 0, i64 0
  %p32 = getelementptr inbounds i8, ptr %p0, i64 32

  %v = call <vscale x 8 x i8>
      @llvm.riscv.vle.nxv8i8.p0.i64(
          <vscale x 8 x i8> poison,
          ptr %p32,
          i64 %vl)

  ret <vscale x 8 x i8> %v
}
