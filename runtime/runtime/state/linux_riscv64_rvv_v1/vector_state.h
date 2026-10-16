#ifndef CHIMERA_VECTOR_STATE_V1_H
#define CHIMERA_VECTOR_STATE_V1_H

#include <stdint.h>

#include "runtime_v1.h"

int chimera_scene_context_pc(const void *raw_context, uint64_t *pc);
int chimera_scene_set_context_pc(void *raw_context, uint64_t pc);
int chimera_scene_context_vlen_bits(const void *raw_context, uint64_t *vlen_bits);
void chimera_scene_save_vector_state(
    enum chimera_direction direction, void *raw_context);

/* siginfo.si_ptr 携带的 32 位打包值：低 14 位 vlenb，bit 14~30 vl。
 * vlen/vl 不能从 OS 上下文直读，迁移入口与向量状态保存都以此为准。 */
int chimera_vector_packed_unpack(uint32_t packed, uint64_t *vlenb, uint64_t *vl);
int chimera_scene_vlen_bits_from_packed(uint32_t packed, uint64_t *vlen_bits);
/* Returns 0 without modifying translator state when the context/payload
 * cannot be saved.  Callers must not publish a translated PC on failure. */
int chimera_scene_save_vector_state_packed(
    enum chimera_direction direction, void *raw_context, uint32_t packed);

#endif
