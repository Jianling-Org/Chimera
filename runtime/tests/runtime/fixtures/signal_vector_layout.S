/* Load all 32 registers with caller-provided bytes, then deliver SIGTRAP
 * by ebreak.  A syscall must not be used here: Linux discards vector state
 * at syscall entry, making it unsuitable for a signal-frame contract test.
 * Arguments: compact bytes, vlenb, pre-trap observation.
 * This is a test fixture only. */
    .text
    .align 2
    .global chimera_test_raise_vector_signal
    .type chimera_test_raise_vector_signal, @function
chimera_test_raise_vector_signal:
    .option push
    .option arch, +v
    .option norvc
    mv t1, a0
    slli t2, a1, 3
    vsetvli t0, zero, e8, m8, ta, ma
    vle8.v v0, (t1)
    add t1, t1, t2
    vle8.v v8, (t1)
    add t1, t1, t2
    vle8.v v16, (t1)
    add t1, t1, t2
    vle8.v v24, (t1)
    /* Observe live registers and CSRs before asking the kernel to save
     * them.  A bad signal frame is not attributed to runtime if the
     * source state was already different before signal delivery. */
    mv t1, a2
    vse8.v v0, (t1)
    add t1, t1, t2
    vse8.v v8, (t1)
    add t1, t1, t2
    vse8.v v16, (t1)
    add t1, t1, t2
    vse8.v v24, (t1)
    li t1, 4096
    add t1, a2, t1
    csrr t0, vl
    sd t0, 0(t1)
    csrr t0, vtype
    sd t0, 8(t1)
    ebreak
    li a0, 0
    ret
    .option pop
    .size chimera_test_raise_vector_signal, .-chimera_test_raise_vector_signal
    .section .note.GNU-stack,"",@progbits
