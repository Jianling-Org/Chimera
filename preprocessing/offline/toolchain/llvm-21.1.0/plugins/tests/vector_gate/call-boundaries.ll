; The late memory pass must preserve all existing inlining, explicit RVV,
; callback-table specialization, symbol interposition and function identity.
declare i64 @llvm.vscale.i64()

define internal void @vector_leaf(ptr %dst, ptr %src) alwaysinline {
  %value = load <vscale x 4 x i32>, ptr %src, align 4
  store <vscale x 4 x i32> %value, ptr %dst, align 4
  ret void
}

define internal void @wrapper(ptr %dst, ptr %src) alwaysinline {
  call void @vector_leaf(ptr %dst, ptr %src)
  ret void
}

define internal void @scalar_helper(ptr %dst) alwaysinline {
  %value = load i32, ptr %dst, align 4
  %next = add i32 %value, 1
  store i32 %next, ptr %dst, align 4
  ret void
}

define internal i64 @width_query() alwaysinline {
  %width = call i64 @llvm.vscale.i64()
  ret i64 %width
}

define void @gated_caller(ptr %dst, ptr %src, ptr %callback) "chimera-no-vectorize" {
  call void @vector_leaf(ptr %dst, ptr %src) alwaysinline
  call void %callback(ptr %dst)
  call void @scalar_helper(ptr %dst)
  ret void
}

define void @open_caller(ptr %dst, ptr %src) {
  call void @vector_leaf(ptr %dst, ptr %src)
  ret void
}

define void @gated_wrapper(ptr %dst, ptr %src, ptr %callback) "chimera-no-vectorize" {
  call void @wrapper(ptr %dst, ptr %src)
  call void %callback(ptr %dst)
  ret void
}

define void @gated_compute(ptr %dst, ptr %src) "chimera-no-vectorize" {
  call void @vector_leaf(ptr %dst, ptr %src)
  ret void
}

define internal void @call_callback(ptr %dst, ptr %callback) alwaysinline {
  call void %callback(ptr %dst)
  ret void
}

define void @gated_transitive(ptr %dst, ptr %src, ptr %callback) "chimera-no-vectorize" {
  call void @vector_leaf(ptr %dst, ptr %src)
  call void @call_callback(ptr %dst, ptr %callback)
  ret void
}

define i64 @gated_width_query() "chimera-no-vectorize" {
  %width = call i64 @width_query()
  ret i64 %width
}

define internal void @scalar_callback(ptr %dst) alwaysinline {
  %value = load i32, ptr %dst
  %next = add i32 %value, 2
  store i32 %next, ptr %dst
  ret void
}

@callbacks = internal constant [1 x ptr] [ptr @scalar_callback]

define internal void @callback_wrapper(ptr %dst, ptr %src, i64 %index) alwaysinline {
  call void @vector_leaf(ptr %dst, ptr %src)
  %slot = getelementptr inbounds [1 x ptr], ptr @callbacks, i64 0, i64 %index
  %target = load ptr, ptr %slot
  call void %target(ptr %dst)
  ret void
}

define void @gated_callback_wrapper(ptr %dst, ptr %src) "chimera-no-vectorize" {
  call void @callback_wrapper(ptr %dst, ptr %src, i64 0)
  ret void
}

define void @preemptable_vector(ptr %dst, ptr %src) {
  %value = load <vscale x 4 x i32>, ptr %src, align 4
  store <vscale x 4 x i32> %value, ptr %dst, align 4
  ret void
}

define void @gated_preemptable(ptr %dst, ptr %src, ptr %callback) "chimera-no-vectorize" {
  call void @preemptable_vector(ptr %dst, ptr %src)
  call void %callback(ptr %dst)
  ret void
}

define internal ptr @self_vector(ptr %dst, ptr %src) {
  %value = load <vscale x 4 x i32>, ptr %src, align 4
  store <vscale x 4 x i32> %value, ptr %dst, align 4
  ret ptr @self_vector
}

define ptr @gated_self_pointer(ptr %dst, ptr %src, ptr %callback) "chimera-no-vectorize" {
  %self = call ptr @self_vector(ptr %dst, ptr %src)
  call void %callback(ptr %dst)
  ret ptr %self
}

declare void @side_effect() noduplicate
define internal void @vector_nodup(ptr %dst, ptr %src) {
  %value = load <vscale x 4 x i32>, ptr %src, align 4
  call void @side_effect() noduplicate
  store <vscale x 4 x i32> %value, ptr %dst, align 4
  ret void
}

define void @gated_nodup(ptr %dst, ptr %src, ptr %callback) "chimera-no-vectorize" {
  call void @vector_nodup(ptr %dst, ptr %src)
  call void %callback(ptr %dst)
  ret void
}

define internal i64 @self_bits_vector(ptr %dst, ptr %src) {
  %value = load <vscale x 4 x i32>, ptr %src, align 4
  store <vscale x 4 x i32> %value, ptr %dst, align 4
  ret i64 ptrtoint (ptr @self_bits_vector to i64)
}

define i64 @gated_self_bits(ptr %dst, ptr %src, ptr %callback) "chimera-no-vectorize" {
  %bits = call i64 @self_bits_vector(ptr %dst, ptr %src)
  call void %callback(ptr %dst)
  ret i64 %bits
}

define internal <vscale x 4 x i32> @vector_value(ptr %src) alwaysinline {
  %value = load <vscale x 4 x i32>, ptr %src, align 4
  ret <vscale x 4 x i32> %value
}

define void @gated_vector_abi(ptr %dst, ptr %src, ptr %callback) "chimera-no-vectorize" {
  %value = call <vscale x 4 x i32> @vector_value(ptr %src)
  store <vscale x 4 x i32> %value, ptr %dst, align 4
  call void %callback(ptr %dst)
  ret void
}
