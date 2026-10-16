target triple = "riscv64-unknown-linux-gnu"

declare <vscale x 8 x i8>
@llvm.riscv.vle.nxv8i8.p0.i64(
    <vscale x 8 x i8>,
    ptr,
    i64)

define <vscale x 8 x i8> @test_merge(i64 %vl) {
entry:
  %buf = alloca [128 x i8], align 1

  %p = getelementptr inbounds [128 x i8],
      ptr %buf, i64 0, i64 32

  %v = call <vscale x 8 x i8>
      @llvm.riscv.vle.nxv8i8.p0.i64(
          <vscale x 8 x i8> poison,
          ptr %p,
          i64 %vl),
      !pcsections !0

  ret <vscale x 8 x i8> %v
}

!0 = distinct !{!".other_map", !1}
!1 = !{i32 123}
