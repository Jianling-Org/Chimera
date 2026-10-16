    .option pic
    .text
    .align 2
    .globl chimera_translator_contract_256_to_1024
    .type chimera_translator_contract_256_to_1024, @function
chimera_translator_contract_256_to_1024:
    addi sp, sp, -16
    sd ra, 8(sp)
    sd a0, 0(sp)

    la.tls.ie t6, simulated_cpu_state_riscv64_rvv_256_riscv64_rvv_1024
    add t6, t6, tp

    li a0, 0
    ld a1, 0(sp)
    call query_original_translated_map@plt
    sd a0, 0(sp)
    call get_simulated_cpu_state_addr_riscv64_rvv_256_riscv64_rvv_1024@plt

    ld a0, 0(sp)
    ld ra, 8(sp)
    addi sp, sp, 16
    ret
    .size chimera_translator_contract_256_to_1024, .-chimera_translator_contract_256_to_1024

    .section .note.GNU-stack,"",@progbits
