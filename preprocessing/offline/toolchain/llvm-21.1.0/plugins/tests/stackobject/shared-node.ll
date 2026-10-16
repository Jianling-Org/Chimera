; Regression input for the shared-MDNode wire-format bug (LLVM patch 0008).
;
; All three stores deliberately reference ONE shared distinct !pcsections
; node. This is the post-LTO-inlining/unrolling state of the plugin's
; per-instruction nodes: cloned instructions keep the original MDNode.
; Additionally each store expands into an li/sw MachineInstr pair, so one
; node legitimately covers six MIs.
;
; Upstream PCSections emission groups every PC of a shared node ahead of a
; single aux payload (6*8+4 = 52 bytes), which is not a multiple of the
; 12-byte record size. Patch 0008 makes every MI emit its own record
; (6*12 = 72 bytes) and check_stackobj_map.py accepts the ELF again.

target triple = "riscv64-unknown-linux-gnu"

define void @shared_node(ptr %p) {
entry:
  store volatile i32 1, ptr %p, !pcsections !0
  store volatile i32 2, ptr %p, !pcsections !0
  store volatile i32 3, ptr %p, !pcsections !0
  ret void
}

!0 = distinct !{!".chimera.stackobj_map!A", !1}
!1 = !{i32 7}
