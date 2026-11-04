target datalayout = "e-p:64:64"

declare void @llvm.memset.p0.i64(ptr, i8, i64, i1 immarg)
declare void @llvm.memset.p0.i32(ptr, i8, i32, i1 immarg)
declare ptr @memset(ptr, i32, i64)

define void @gated_fill(ptr %dst, i8 %value, i64 %length) "chimera-no-vectorize" {
  call void @llvm.memset.p0.i64(ptr align 1 %dst, i8 %value, i64 %length, i1 false)
  ret void
}

define void @gated_volatile_fill(ptr %dst, i8 %value, i64 %length) "chimera-no-vectorize" {
  call void @llvm.memset.p0.i64(ptr align 1 %dst, i8 %value, i64 %length, i1 true)
  ret void
}

define void @gated_fill32(ptr %dst, i8 %value, i32 %length) "chimera-no-vectorize" {
  call void @llvm.memset.p0.i32(ptr %dst, i8 %value, i32 %length, i1 false)
  ret void
}

define void @gated_zero_length(ptr %dst) "chimera-no-vectorize" {
  call void @llvm.memset.p0.i64(ptr %dst, i8 0, i64 0, i1 false)
  ret void
}

define void @open_fill(ptr %dst, i8 %value, i64 %length) {
  call void @llvm.memset.p0.i64(ptr %dst, i8 %value, i64 %length, i1 false)
  ret void
}

; A real call is not necessarily a compiler-owned memory intrinsic. In
; particular, -fno-builtin and interposable application definitions retain
; their call semantics and must still pass the ordinary strict safety check.
define ptr @gated_real_call(ptr %dst, i32 %value, i64 %length) "chimera-no-vectorize" {
  %result = call ptr @memset(ptr %dst, i32 %value, i64 %length)
  ret ptr %result
}
