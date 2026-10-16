target triple = "riscv64-unknown-linux-gnu"

define void @test_unsupported_after_target() {
entry:
  %buf = alloca [128 x i8], align 16
  %p = getelementptr inbounds [128 x i8], ptr %buf, i64 0, i64 32

  ; The whole block is relevant. The vector arithmetic after the unique
  ; memory target is not in the scalar address-calculation whitelist.
  call void asm sideeffect
      "vle8.v v8, ($0)\0A\09vadd.vv v9, v10, v11",
      "r"(ptr %p)

  ret void
}
