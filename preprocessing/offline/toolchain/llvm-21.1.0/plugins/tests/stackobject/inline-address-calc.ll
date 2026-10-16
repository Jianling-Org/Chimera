target triple = "riscv64-unknown-linux-gnu"

define void @test_inline_address_calc() {
entry:
  %buf = alloca [128 x i8], align 1

  %p = getelementptr inbounds [128 x i8],
      ptr %buf, i64 0, i64 16

  call void asm sideeffect
      "mv t0, $0\0A\09addi t0, t0, 16\0A\09vle8.v v8, (t0)",
      "r"(ptr %p)

  ret void
}
