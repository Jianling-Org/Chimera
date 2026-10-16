#ifndef CHIMERA_LINUX_RISCV64_RVV_V1_H
#define CHIMERA_LINUX_RISCV64_RVV_V1_H

#include <stdint.h>

#include "chimera_runtime.h"

#define CHIMERA_SIMULATED_CPU_STATE_SIZE 4192u

/* Scene-owned body tags and directions. The numeric contract (0=original via
 * CHIMERA_CODE_ORIGINAL, 1/2=translated bodies, two directions) is shared
 * with translated-code generation and must not be renumbered. */
enum chimera_scene_code_body {
    CHIMERA_CODE_TRANSLATED_1024_TO_256 = 1,
    CHIMERA_CODE_TRANSLATED_256_TO_1024 = 2,
};

enum chimera_direction {
    CHIMERA_DIR_1024_TO_256 = 0,
    CHIMERA_DIR_256_TO_1024 = 1,
};

/* Single derivation point for RVV route identifiers: both the manifest load
 * path (capabilities.c) and the migration decision path
 * (translation_control.c) must call this function instead of deriving route
 * ids locally, and it is injective over (source_vlen_bits, target_vlen_bits). */
uint64_t chimera_rvv_route_id(uint64_t source_vlen_bits, uint64_t target_vlen_bits);

extern const uint64_t chimera_runtime_abi_v1;
extern const uint64_t chimera_runtime_scene_linux_riscv64_rvv_v1;

uint64_t query_original_translated_map(int target_type, uint64_t addr_in);

extern __thread uint8_t
simulated_cpu_state_riscv64_rvv_1024_riscv64_rvv_256[
    CHIMERA_SIMULATED_CPU_STATE_SIZE];
extern __thread uint8_t
simulated_cpu_state_riscv64_rvv_256_riscv64_rvv_1024[
    CHIMERA_SIMULATED_CPU_STATE_SIZE];

uint8_t *get_simulated_cpu_state_addr_riscv64_rvv_1024_riscv64_rvv_256(void);
uint8_t *get_simulated_cpu_state_addr_riscv64_rvv_256_riscv64_rvv_1024(void);

int chimera_scene_load_workspace(const char *workspace);
const struct chimera_registry *chimera_scene_registry(void);

#endif
