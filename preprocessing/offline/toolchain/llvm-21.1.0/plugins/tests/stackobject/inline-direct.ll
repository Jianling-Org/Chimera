target triple = "riscv64-unknown-linux-gnu"

define void @test_inline_direct() {
entry:
  %buf = alloca [128 x i8], align 1

  %p = getelementptr inbounds [128 x i8],
      ptr %buf, i64 0, i64 32

  call void asm sideeffect
      "vle8.v v8, ($0)",
      "r"(ptr %p)

  ret void
}
