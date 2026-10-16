target triple = "riscv64-unknown-linux-gnu"

define void @test_inline_no_target(i64 %x) {
entry:
  call void asm sideeffect
      "mv t0, $0\0A\09addi t0, t0, 16",
      "r"(i64 %x)

  ret void
}
