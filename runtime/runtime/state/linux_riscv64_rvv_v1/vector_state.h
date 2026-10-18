#ifndef CHIMERA_VECTOR_STATE_V1_H
#define CHIMERA_VECTOR_STATE_V1_H

#include <stdint.h>

#include "runtime_v1.h"

int chimera_scene_context_pc(const void *raw_context, uint64_t *pc);
int chimera_scene_context_gpr(const void *raw_context, uint64_t number,
                            uint64_t *value);
int chimera_scene_set_context_sp(void *raw_context, uint64_t sp);
int chimera_scene_set_context_pc(void *raw_context, uint64_t pc);
int chimera_scene_commit_migration_context(void *raw_context, uint64_t pc);
int chimera_scene_context_vlen_bits(const void *raw_context, uint64_t *vlen_bits);
/* Pre-ACK proposal save: rejects nonzero vstart before modifying either
 * translator TLS or the interrupted context.  Retry after source progress. */
int chimera_scene_save_vector_state(
    enum chimera_direction direction, void *raw_context);

/* siginfo.si_ptr 携带的 32 位打包值：低 14 位 vlenb，bit 14~30 vl。
 * Legacy post-migration entry uses these source values. Pre-ACK proposals
 * use the freshly saved source signal context instead of queued snapshots. */
int chimera_vector_packed_unpack(uint32_t packed, uint64_t *vlenb, uint64_t *vl);
int chimera_scene_vlen_bits_from_packed(uint32_t packed, uint64_t *vlen_bits);
/* Returns 0 without modifying translator state when the context/payload
 * cannot be saved.  Callers must not publish a translated PC on failure. */
int chimera_scene_save_vector_state_packed(
    enum chimera_direction direction, void *raw_context, uint32_t packed);

#endif
