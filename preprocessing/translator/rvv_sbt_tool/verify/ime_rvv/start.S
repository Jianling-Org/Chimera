.option norelax
.section .text.init
.globl _start
_start:
    la sp, stack_top
    la t0, trap
    csrw mtvec, t0
    li t0, 0x6600
    csrs mstatus, t0
    call main
    li t0, 0x100000
    li t1, 0x5555
    sw t1, 0(t0)
1:  wfi
    j 1b

.balign 4
trap:
    addi sp, sp, -16
    sd t0, 0(sp)
    sd t1, 8(sp)
    csrr t0, mcause
    li t1, 2
    bne t0, t1, fatal
    la t0, trap_expected
    ld t1, 0(t0)
    beqz t1, fatal
    la t0, trapped
    li t1, 1
    sd t1, 0(t0)
    la t0, trap_resume
    ld t1, 0(t0)
    csrw mepc, t1
    ld t0, 0(sp)
    ld t1, 8(sp)
    addi sp, sp, 16
    mret
fatal:
    li t0, 0x100000
    li t1, 0x13333
    sw t1, 0(t0)
    j fatal

.section .bss
.balign 16
stack_bottom:
    .skip 65536
stack_top:
