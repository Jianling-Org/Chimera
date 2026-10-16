#include "translator_state.h"

#include <stddef.h>

#include "runtime_v1.h"

_Alignas(uint64_t) __attribute__((visibility("default"))) __thread uint8_t
simulated_cpu_state_riscv64_rvv_1024_riscv64_rvv_256[
    CHIMERA_SIMULATED_CPU_STATE_SIZE];

_Alignas(uint64_t) __attribute__((visibility("default"))) __thread uint8_t
simulated_cpu_state_riscv64_rvv_256_riscv64_rvv_1024[
    CHIMERA_SIMULATED_CPU_STATE_SIZE];

__attribute__((visibility("default")))
uint8_t *get_simulated_cpu_state_addr_riscv64_rvv_1024_riscv64_rvv_256(void) {
    return simulated_cpu_state_riscv64_rvv_1024_riscv64_rvv_256;
}

__attribute__((visibility("default")))
uint8_t *get_simulated_cpu_state_addr_riscv64_rvv_256_riscv64_rvv_1024(void) {
    return simulated_cpu_state_riscv64_rvv_256_riscv64_rvv_1024;
}

uint8_t *chimera_direction_state(enum chimera_direction direction) {
    switch (direction) {
    case CHIMERA_DIR_1024_TO_256:
        return simulated_cpu_state_riscv64_rvv_1024_riscv64_rvv_256;
    case CHIMERA_DIR_256_TO_1024:
        return simulated_cpu_state_riscv64_rvv_256_riscv64_rvv_1024;
    default:
        return NULL;
    }
}
