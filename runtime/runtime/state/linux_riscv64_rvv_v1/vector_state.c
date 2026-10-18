#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "vector_state.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#ifndef CHIMERA_PORTABLE_TEST_CONTEXT
#include "chimera_context.h"
#endif
#include "runtime_v1.h"
#include "translator_state.h"
#ifdef CHIMERA_DEBUG
#include "chimera_debug.h"
#endif

#define CHIMERA_MAX_VLENB 128
#define CHIMERA_SIGNAL_VECTOR_GROUPS 4U
#define CHIMERA_SIGNAL_VECTOR_SLOT_BYTES 1024U

#ifdef CHIMERA_PORTABLE_TEST_CONTEXT
struct chimera_portable_vector_context {
    uint64_t pc;
    uint64_t vlenb;
    uint64_t vstart;
    uint64_t vcsr;
    uint64_t vl;
    uint64_t vtype;
    const uint8_t *datap;
};
typedef struct chimera_portable_vector_context chimera_vector_context;
#else
typedef struct __riscv_v_ext_state chimera_vector_context;
#endif

static void store_u64(uint8_t *destination, size_t offset, uint64_t value) {
    memcpy(destination + offset, &value, sizeof(value));
}

static void write_state(
    uint8_t *simulated_state,
    const void *registers,
    uint64_t vlenb,
    uint64_t vstart,
    uint64_t vcsr,
    uint64_t vl,
    uint64_t vtype
) {
    const uint8_t *signal_registers = registers;
    size_t group;
    size_t group_bytes = (size_t)(8U * vlenb);

    /* The HMP kernel saves v0/v8/v16/v24 at fixed 1024-byte strides.
     * Each group contains eight physical registers; the translator's
     * register array instead uses the source vlenb as its register stride.
     * These layouts coincide only when source vlenb is 128. */
    memset(simulated_state, 0,
        CHIMERA_SIGNAL_VECTOR_GROUPS * CHIMERA_SIGNAL_VECTOR_SLOT_BYTES);
    for (group = 0; group < CHIMERA_SIGNAL_VECTOR_GROUPS; ++group) {
        memcpy(simulated_state + group * group_bytes,
            signal_registers + group * CHIMERA_SIGNAL_VECTOR_SLOT_BYTES,
            group_bytes);
    }
    store_u64(simulated_state, 0x1000, vstart);
    store_u64(simulated_state, 0x1018, vcsr);
    store_u64(simulated_state, 0x1020, vl);
    store_u64(simulated_state, 0x1028, vtype);
    store_u64(simulated_state, 0x1030, vlenb);
}

#ifndef CHIMERA_PORTABLE_TEST_CONTEXT
static const chimera_vector_context *vector_context(
    const void *raw_context
) {
    const chimera_linux_context *context = raw_context;
    if (!context) return NULL;
    struct __riscv_extra_ext_header *header =
        (struct __riscv_extra_ext_header *)&context->uc_mcontext.__fpregs;
    if (header->hdr.magic != 0x53465457) return NULL;
    return (struct __riscv_v_ext_state *)((char *)header + sizeof(*header));
}

int chimera_scene_context_pc(const void *raw_context, uint64_t *pc) {
    const chimera_linux_context *context = raw_context;
    if (!context || !pc) return 0;
    *pc = (uint64_t)context->uc_mcontext.__gregs[REG_PC];
    return 1;
}

int chimera_scene_context_gpr(const void *raw_context, uint64_t number,
                            uint64_t *value) {
    const chimera_linux_context *context = raw_context;
    if (!context || !value || number > 31U) return 0;
    *value = number ? (uint64_t)context->uc_mcontext.__gregs[number] : 0;
    return 1;
}

int chimera_scene_set_context_sp(void *raw_context, uint64_t sp) {
    chimera_linux_context *context = raw_context;
    if (!context) return 0;
    context->uc_mcontext.__gregs[2] = sp;
    return 1;
}

int chimera_scene_set_context_pc(void *raw_context, uint64_t pc) {
    chimera_linux_context *context = raw_context;
    if (!context) return 0;
    context->uc_mcontext.__gregs[REG_PC] = pc;
    return 1;
}

int chimera_scene_commit_migration_context(void *raw_context, uint64_t pc) {
    chimera_linux_context *context = raw_context;
    struct __riscv_extra_ext_header *header;
    if (!context) return 0;
    header = (struct __riscv_extra_ext_header *)&context->uc_mcontext.__fpregs;
    /* The kernel ACK has restored the live vector state.  Prevent
     * rt_sigreturn from restoring the stale source-width vector record,
     * then publish the translated PC. */
    header->hdr.magic = 0;
    header->hdr.size = 0;
    __asm__ __volatile__("" ::: "memory");
    context->uc_mcontext.__gregs[REG_PC] = pc;
    return 1;
}

#else
static const chimera_vector_context *vector_context(const void *raw_context) {
    return raw_context;
}

int chimera_scene_set_context_sp(void *raw_context, uint64_t sp) {
    (void)raw_context; (void)sp;
    return 0;
}

int chimera_scene_context_gpr(const void *raw_context, uint64_t number,
                            uint64_t *value) {
    /* The portable vector fixture has no scalar register bank. */
    if (!raw_context || !value || number != 0U) return 0;
    *value = 0;
    return 1;
}

int chimera_scene_context_pc(const void *raw_context, uint64_t *pc) {
    const struct chimera_portable_vector_context *context = raw_context;
    if (!context || !pc) return 0;
    *pc = context->pc;
    return 1;
}

int chimera_scene_set_context_pc(void *raw_context, uint64_t pc) {
    struct chimera_portable_vector_context *context = raw_context;
    if (!context) return 0;
    context->pc = pc;
    return 1;
}

int chimera_scene_commit_migration_context(void *raw_context, uint64_t pc) {
    return chimera_scene_set_context_pc(raw_context, pc);
}

#endif

int chimera_scene_context_vlen_bits(const void *raw_context, uint64_t *vlen_bits) {
    const chimera_vector_context *context = vector_context(raw_context);
    if (!context || !vlen_bits || !context->vlenb
        || context->vlenb > CHIMERA_MAX_VLENB) return 0;
    *vlen_bits = context->vlenb * UINT64_C(8);
    return 1;
}

static int save_context(
    const void *raw_context,
    uint8_t *simulated_state
) {
    const chimera_vector_context *context = vector_context(raw_context);
    if (!context || !context->datap || !context->vlenb
        || context->vlenb > CHIMERA_MAX_VLENB) return 0;
    /* Proposal entry can interrupt a partially executed vector instruction.
     * The translated memory paths require vstart == 0.  Reject before writing
     * TLS or committing the CPU; sigreturn must resume the source instruction
     * with its original restart index, never silently clear that index. */
    if (context->vstart != 0) {
#ifdef CHIMERA_DEBUG
        const struct chimera_debug_field fields[] = {
            CHIMERA_DEBUG_U64("vstart", context->vstart),
            CHIMERA_DEBUG_U64("vlenb", context->vlenb),
            CHIMERA_DEBUG_U64("vl", context->vl),
        };
        CHIMERA_DEBUG_EVENT("runtime.state.vector-reject-vstart", fields, 3U);
#endif
        return 0;
    }
    write_state(
        simulated_state,
        context->datap,
        context->vlenb,
        context->vstart,
        context->vcsr,
        context->vl,
        context->vtype);
    return 1;
}

/* The legacy, post-migration signal carries source vlenb/vl in si_ptr.
 * The context's width may already describe the destination CPU.  Keep
 * the packed values authoritative; do not import the proposal/ACK ABI. */
int chimera_scene_save_vector_state_packed(
    enum chimera_direction direction,
    void *raw_context,
    uint32_t packed
) {
    uint8_t *state = chimera_direction_state(direction);
    const chimera_vector_context *context = vector_context(raw_context);
    uint64_t vlenb, vl;
    if (!state || !context || !context->datap
        || !chimera_vector_packed_unpack(packed, &vlenb, &vl)) return 0;
    write_state(state, context->datap, vlenb,
        context->vstart, context->vcsr, vl, context->vtype);
#ifdef CHIMERA_DEBUG
    {
        const struct chimera_debug_field fields[] = {
            CHIMERA_DEBUG_U64("direction", (uint64_t)direction),
            CHIMERA_DEBUG_U64("payload_vlenb", vlenb),
            CHIMERA_DEBUG_U64("payload_vl", vl),
            CHIMERA_DEBUG_U64("frame_vlenb", context->vlenb),
            CHIMERA_DEBUG_U64("frame_vl", context->vl),
            CHIMERA_DEBUG_U64("vstart", context->vstart),
            CHIMERA_DEBUG_U64("vcsr", context->vcsr),
            CHIMERA_DEBUG_HEX("vtype", context->vtype),
        };
        CHIMERA_DEBUG_EVENT("runtime.state.vector-save", fields, 8U);
    }
#endif
    return 1;
}

int chimera_scene_save_vector_state(
    enum chimera_direction direction,
    void *raw_context
) {
    uint8_t *state = chimera_direction_state(direction);
    if (!state) return 0;
    return save_context(raw_context, state);
}

int chimera_vector_packed_unpack(uint32_t packed, uint64_t *vlenb, uint64_t *vl) {
    uint64_t unpacked_vlenb;
    if (!vlenb || !vl) return 0;
    unpacked_vlenb = (uint64_t)(packed & UINT32_C(0x3fff));
    if (!unpacked_vlenb || unpacked_vlenb > CHIMERA_MAX_VLENB) return 0;
    *vlenb = unpacked_vlenb;
    *vl = (uint64_t)((packed >> 14) & UINT32_C(0x1ffff));
    return 1;
}

int chimera_scene_vlen_bits_from_packed(uint32_t packed, uint64_t *vlen_bits) {
    uint64_t vlenb;
    uint64_t vl;
    if (!vlen_bits) return 0;
    if (!chimera_vector_packed_unpack(packed, &vlenb, &vl)) return 0;
    *vlen_bits = vlenb * UINT64_C(8);
    return 1;
}
