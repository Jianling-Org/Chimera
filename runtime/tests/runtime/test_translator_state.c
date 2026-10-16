#include <assert.h>
#include <pthread.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "runtime_v1.h"
#include "vector_state.h"

struct chimera_portable_vector_context {
    uint64_t pc;
    uint64_t vlenb;
    uint64_t vstart;
    uint64_t vcsr;
    uint64_t vl;
    uint64_t vtype;
    const uint8_t *datap;
};

static void *worker(void *ignored) {
    uint8_t *forward =
        get_simulated_cpu_state_addr_riscv64_rvv_1024_riscv64_rvv_256();
    (void)ignored;
    assert(forward ==
        simulated_cpu_state_riscv64_rvv_1024_riscv64_rvv_256);
    forward[0] = UINT8_C(0x5a);
    return forward;
}

static uint64_t load_u64(const uint8_t *source, size_t offset) {
    uint64_t value;
    memcpy(&value, source + offset, sizeof(value));
    return value;
}

static void assert_state_layout(
    const uint8_t *state,
    const uint8_t *vector_bytes
) {
    assert(!memcmp(state, vector_bytes, 32U * 128U));
    assert(load_u64(state, 0x1000) == UINT64_C(11));
    assert(load_u64(state, 0x1018) == UINT64_C(12));
    assert(load_u64(state, 0x1020) == UINT64_C(13));
    assert(load_u64(state, 0x1028) == UINT64_C(14));
    assert(load_u64(state, 0x1030) == UINT64_C(128));
}

static void test_grouped_signal_frame(
    uint64_t vlenb, enum chimera_direction direction
) {
    uint8_t signal_frame[4096];
    uint8_t expected[4096];
    uint8_t other_before[CHIMERA_SIMULATED_CPU_STATE_SIZE];
    uint8_t *state = direction == CHIMERA_DIR_1024_TO_256
        ? get_simulated_cpu_state_addr_riscv64_rvv_1024_riscv64_rvv_256()
        : get_simulated_cpu_state_addr_riscv64_rvv_256_riscv64_rvv_1024();
    uint8_t *other = direction == CHIMERA_DIR_1024_TO_256
        ? get_simulated_cpu_state_addr_riscv64_rvv_256_riscv64_rvv_1024()
        : get_simulated_cpu_state_addr_riscv64_rvv_1024_riscv64_rvv_256();
    struct chimera_portable_vector_context context = {
        UINT64_C(0x1234), vlenb, 11, 12, 13, 14, signal_frame,
    };
    size_t reg, byte;

    /* The HMP kernel stores four LMUL=8 groups at a fixed 1024-byte
     * stride, even when the physical register width is only 32 bytes.
     * Poison padding and give every register distinct bytes so a compact
     * memcpy cannot accidentally satisfy this contract. */
    memset(signal_frame, 0xee, sizeof(signal_frame));
    memset(expected, 0, sizeof(expected));
    for (reg = 0; reg < 32; ++reg) {
        for (byte = 0; byte < vlenb; ++byte) {
            uint8_t value = (uint8_t)(reg * 7 + byte);
            signal_frame[(reg / 8) * 1024 + (reg % 8) * vlenb + byte] = value;
            expected[reg * vlenb + byte] = value;
        }
    }
    memset(state, 0xa5, CHIMERA_SIMULATED_CPU_STATE_SIZE);
    memset(other, 0x5a, CHIMERA_SIMULATED_CPU_STATE_SIZE);
    memcpy(other_before, other, sizeof(other_before));
    chimera_scene_save_vector_state(direction, &context);
    assert(!memcmp(state, expected, sizeof(expected)));
    assert(!memcmp(other, other_before, sizeof(other_before)));
    assert(load_u64(state, 0x1000) == 11);
    assert(load_u64(state, 0x1018) == 12);
    assert(load_u64(state, 0x1020) == 13);
    assert(load_u64(state, 0x1028) == 14);
    assert(load_u64(state, 0x1030) == vlenb);

    /* Exercise the actual entry API as well.  Packed source vl/vlenb is
     * authoritative in the legacy signal, not the context's destination
     * width or vl.  Deliberately make those fields disagree. */
    context.vlenb = vlenb == 128 ? 32 : 128;
    context.vl = 17;
    memset(state, 0xa5, CHIMERA_SIMULATED_CPU_STATE_SIZE);
    assert(chimera_scene_save_vector_state_packed(direction, &context,
        (uint32_t)vlenb | (UINT32_C(99) << 14)));
    assert(!memcmp(state, expected, sizeof(expected)));
    assert(!memcmp(other, other_before, sizeof(other_before)));
    assert(load_u64(state, 0x1000) == 11);
    assert(load_u64(state, 0x1018) == 12);
    assert(load_u64(state, 0x1020) == 99);
    assert(load_u64(state, 0x1028) == 14);
    assert(load_u64(state, 0x1030) == vlenb);
}

static void test_rejected_packed_save_keeps_both_states(void) {
    uint8_t signal_frame[4096] = {0};
    uint8_t before_forward[CHIMERA_SIMULATED_CPU_STATE_SIZE];
    uint8_t before_reverse[CHIMERA_SIMULATED_CPU_STATE_SIZE];
    uint8_t *forward =
        get_simulated_cpu_state_addr_riscv64_rvv_1024_riscv64_rvv_256();
    uint8_t *reverse =
        get_simulated_cpu_state_addr_riscv64_rvv_256_riscv64_rvv_1024();
    struct chimera_portable_vector_context context = {
        0x1234, 128, 11, 12, 13, 14, signal_frame,
    };
    memset(forward, 0x5a, sizeof(before_forward));
    memset(reverse, 0xa5, sizeof(before_reverse));
    memcpy(before_forward, forward, sizeof(before_forward));
    memcpy(before_reverse, reverse, sizeof(before_reverse));
    assert(!chimera_scene_save_vector_state_packed(
        CHIMERA_DIR_1024_TO_256, &context, 0));
    assert(!chimera_scene_save_vector_state_packed(
        CHIMERA_DIR_1024_TO_256, &context, 129));
    assert(!chimera_scene_save_vector_state_packed(
        CHIMERA_DIR_1024_TO_256, NULL, 128));
    assert(!chimera_scene_save_vector_state_packed(
        (enum chimera_direction)99, &context, 128));
    context.datap = NULL;
    assert(!chimera_scene_save_vector_state_packed(
        CHIMERA_DIR_1024_TO_256, &context, 128));
    assert(!memcmp(forward, before_forward, sizeof(before_forward)));
    assert(!memcmp(reverse, before_reverse, sizeof(before_reverse)));
}

int main(void) {
    static uint8_t vector_bytes[32U * 128U];
    static uint8_t before_forward[CHIMERA_SIMULATED_CPU_STATE_SIZE];
    static uint8_t before_reverse[CHIMERA_SIMULATED_CPU_STATE_SIZE];
    struct chimera_portable_vector_context context = {
        UINT64_C(0x1234), UINT64_C(128), UINT64_C(11), UINT64_C(12),
        UINT64_C(13), UINT64_C(14), vector_bytes,
    };
    pthread_t thread;
    void *other_thread_forward = NULL;
    uint8_t *forward =
        get_simulated_cpu_state_addr_riscv64_rvv_1024_riscv64_rvv_256();
    uint8_t *reverse =
        get_simulated_cpu_state_addr_riscv64_rvv_256_riscv64_rvv_1024();
    assert(forward ==
        simulated_cpu_state_riscv64_rvv_1024_riscv64_rvv_256);
    assert(reverse ==
        simulated_cpu_state_riscv64_rvv_256_riscv64_rvv_1024);
    assert(forward != reverse);
    assert(!pthread_create(&thread, NULL, worker, NULL));
    assert(!pthread_join(thread, &other_thread_forward));
    assert(other_thread_forward != forward);
    assert(forward[0] == 0);

    memset(vector_bytes, 0x3c, sizeof(vector_bytes));
    memset(forward, 0, CHIMERA_SIMULATED_CPU_STATE_SIZE);
    memset(reverse, 0xa5, CHIMERA_SIMULATED_CPU_STATE_SIZE);
    memcpy(before_reverse, reverse, CHIMERA_SIMULATED_CPU_STATE_SIZE);
    chimera_scene_save_vector_state(CHIMERA_DIR_1024_TO_256, &context);
    assert_state_layout(forward, vector_bytes);
    assert(!memcmp(
        reverse, before_reverse, CHIMERA_SIMULATED_CPU_STATE_SIZE));

    memset(forward, 0x5a, CHIMERA_SIMULATED_CPU_STATE_SIZE);
    memset(reverse, 0, CHIMERA_SIMULATED_CPU_STATE_SIZE);
    memcpy(before_forward, forward, CHIMERA_SIMULATED_CPU_STATE_SIZE);
    chimera_scene_save_vector_state(CHIMERA_DIR_256_TO_1024, &context);
    assert_state_layout(reverse, vector_bytes);
    assert(!memcmp(
        forward, before_forward, CHIMERA_SIMULATED_CPU_STATE_SIZE));

    memset(forward, 0x5a, CHIMERA_SIMULATED_CPU_STATE_SIZE);
    memset(reverse, 0xa5, CHIMERA_SIMULATED_CPU_STATE_SIZE);
    memcpy(before_forward, forward, CHIMERA_SIMULATED_CPU_STATE_SIZE);
    memcpy(before_reverse, reverse, CHIMERA_SIMULATED_CPU_STATE_SIZE);
    chimera_scene_save_vector_state((enum chimera_direction)99, &context);
    assert(!memcmp(
        forward, before_forward, CHIMERA_SIMULATED_CPU_STATE_SIZE));
    assert(!memcmp(
        reverse, before_reverse, CHIMERA_SIMULATED_CPU_STATE_SIZE));

    test_grouped_signal_frame(128, CHIMERA_DIR_1024_TO_256);
    test_grouped_signal_frame(32, CHIMERA_DIR_256_TO_1024);
    test_grouped_signal_frame(64, CHIMERA_DIR_1024_TO_256);
    test_rejected_packed_save_keeps_both_states();

    {
        uint64_t pc = UINT64_C(0);
        assert(chimera_scene_context_pc(&context, &pc));
        assert(pc == UINT64_C(0x1234));
        assert(chimera_scene_set_context_pc(&context, UINT64_C(0x5678)));
        assert(context.pc == UINT64_C(0x5678));
        assert(!chimera_scene_context_pc(NULL, &pc));
        assert(!chimera_scene_context_pc(&context, NULL));
        assert(!chimera_scene_set_context_pc(NULL, UINT64_C(1)));
    }
    return 0;
}
