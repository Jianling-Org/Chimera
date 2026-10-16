target triple = "riscv64-unknown-linux-gnu"

declare <vscale x 8 x i8>
@llvm.riscv.vle.nxv8i8.p0.i64(
    <vscale x 8 x i8>,
    ptr,
    i64)

define <vscale x 8 x i8> @test_multiple(i64 %idx, i64 %vl) {
entry:
  %buf = alloca [128 x i8], align 1
  %base = getelementptr inbounds [128 x i8],
          ptr %buf, i64 0, i64 0

  ; 可能是 buf+0 / buf+1 / ...
  %p = getelementptr inbounds i8,
       ptr %base, i64 %idx

  %v = call <vscale x 8 x i8>
      @llvm.riscv.vle.nxv8i8.p0.i64(
          <vscale x 8 x i8> poison,
          ptr %p,
          i64 %vl)

  ret <vscale x 8 x i8> %v
}