/* Native RISC-V/HMP signal-frame contract.  No AI registration/migration,
 * model, translator body or application Workspace is needed. */
#define _GNU_SOURCE
#include <errno.h>
#include <inttypes.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "chimera_context.h"
#include "runtime_v1.h"
#include "vector_state.h"

extern long chimera_test_raise_vector_signal(
    const uint8_t *, uint64_t, uint8_t *);

static uint8_t expected[4096];
static uint8_t live_observation[4112] __attribute__((aligned(8)));
static volatile sig_atomic_t completed;
static uint64_t saved_vlenb, saved_vl, saved_vtype;
static size_t grouped_mismatches, contiguous_mismatches, runtime_mismatches;
static int save_succeeded;
static int proposal_restart_rejected, rejection_unchanged;
static uint8_t rejection_forward[CHIMERA_SIMULATED_CPU_STATE_SIZE];
static uint8_t rejection_reverse[CHIMERA_SIMULATED_CPU_STATE_SIZE];
static uint8_t rejection_vectors[4096];
static chimera_linux_context rejection_context;

static void inspect(int number, siginfo_t *info, void *raw_context) {
    chimera_linux_context *context = raw_context;
    struct __riscv_extra_ext_header *header =
        (struct __riscv_extra_ext_header *)&context->uc_mcontext.__fpregs;
    struct __riscv_v_ext_state *state =
        (struct __riscv_v_ext_state *)((char *)header + sizeof(*header));
    const uint8_t *bytes;
    const uint8_t *runtime;
    size_t reg, byte;
    (void)number;
    (void)info;
    /* The fixture's explicit, uncompressed ebreak is the sole trap. */
    context->uc_mcontext.__gregs[REG_PC] += 4;
    if (header->hdr.magic != 0x53465457 || !state->datap
        || !state->vlenb || state->vlenb > 128) {
        completed = -1;
        return;
    }
    saved_vlenb = state->vlenb;
    saved_vl = state->vl;
    saved_vtype = state->vtype;
    bytes = state->datap;
    /* Exercise production parsing against a real HMP signal record.  Inject
     * a restart index only for the save calls, then restore it before actual
     * sigreturn.  Neither direction may publish any TLS/context changes. */
    {
        uint64_t original_vstart = state->vstart;
        struct __riscv_v_ext_state before_state;
        uint8_t *forward = get_simulated_cpu_state_addr_riscv64_rvv_1024_riscv64_rvv_256();
        uint8_t *reverse = get_simulated_cpu_state_addr_riscv64_rvv_256_riscv64_rvv_1024();
        int a, b;
        state->vstart = 1;
        memcpy(&rejection_context, context, sizeof(rejection_context));
        memcpy(&before_state, state, sizeof(before_state));
        memcpy(rejection_vectors, bytes, sizeof(rejection_vectors));
        memcpy(rejection_forward, forward, sizeof(rejection_forward));
        memcpy(rejection_reverse, reverse, sizeof(rejection_reverse));
        a = chimera_scene_save_vector_state(CHIMERA_DIR_1024_TO_256, raw_context);
        b = chimera_scene_save_vector_state(CHIMERA_DIR_256_TO_1024, raw_context);
        proposal_restart_rejected = !a && !b;
        rejection_unchanged = !memcmp(&rejection_context, context, sizeof(rejection_context))
            && !memcmp(&before_state, state, sizeof(before_state))
            && !memcmp(rejection_vectors, bytes, sizeof(rejection_vectors))
            && !memcmp(rejection_forward, forward, sizeof(rejection_forward))
            && !memcmp(rejection_reverse, reverse, sizeof(rejection_reverse));
        state->vstart = original_vstart;
    }
    for (reg = 0; reg < 32; ++reg) {
        for (byte = 0; byte < saved_vlenb; ++byte) {
            size_t compact = reg * saved_vlenb + byte;
            size_t grouped = (reg / 8) * 1024 + (reg % 8) * saved_vlenb + byte;
            grouped_mismatches += bytes[grouped] != expected[compact];
            contiguous_mismatches += bytes[compact] != expected[compact];
        }
    }
    save_succeeded = chimera_scene_save_vector_state_packed(
        saved_vlenb == 128 ? CHIMERA_DIR_1024_TO_256 : CHIMERA_DIR_256_TO_1024,
        raw_context, (uint32_t)saved_vlenb | ((uint32_t)saved_vl << 14));
    runtime = saved_vlenb == 128
        ? get_simulated_cpu_state_addr_riscv64_rvv_1024_riscv64_rvv_256()
        : get_simulated_cpu_state_addr_riscv64_rvv_256_riscv64_rvv_1024();
    for (byte = 0; byte < 32 * saved_vlenb; ++byte) {
        runtime_mismatches += runtime[byte] != expected[byte];
    }
    completed = 1;
}

int main(int argc, char **argv) {
    uint64_t vlenb;
    uint64_t live_vl, live_vtype;
    size_t live_mismatches = 0;
    size_t reg, byte;
    struct sigaction action = {0};
    if (argc == 2) {
        char *end;
        long cpu;
        cpu_set_t affinity;
        errno = 0;
        cpu = strtol(argv[1], &end, 10);
        if (errno || *end || cpu < 0 || cpu >= CPU_SETSIZE) return 2;
        CPU_ZERO(&affinity);
        CPU_SET(cpu, &affinity);
        if (sched_setaffinity(0, sizeof(affinity), &affinity)) return 2;
    } else if (argc != 1) {
        return 2;
    }
    __asm__ volatile(".option push\n.option arch, +v\ncsrr %0, vlenb\n.option pop"
        : "=r"(vlenb));
    if (!vlenb || vlenb > 128) return 2;
    for (reg = 0; reg < 32; ++reg) {
        for (byte = 0; byte < vlenb; ++byte) {
            expected[reg * vlenb + byte] = (uint8_t)(reg * 7 + byte);
        }
    }
    action.sa_sigaction = inspect;
    action.sa_flags = SA_SIGINFO;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGTRAP, &action, NULL)) return 2;
    if (chimera_test_raise_vector_signal(expected, vlenb, live_observation)) return 2;
    memcpy(&live_vl, live_observation + 4096, sizeof(live_vl));
    memcpy(&live_vtype, live_observation + 4104, sizeof(live_vtype));
    for (byte = 0; byte < 32 * vlenb; ++byte) {
        live_mismatches += live_observation[byte] != expected[byte];
    }
    printf("{\"cpu\":%d,\"physical_vlenb\":%" PRIu64
        ",\"context_vlenb\":%" PRIu64 ",\"vl\":%" PRIu64
        ",\"vtype\":%" PRIu64 ",\"signal_observed\":%d"
        ",\"grouped_mismatches\":%zu,\"old_contiguous_mismatches\":%zu"
        ",\"runtime_mismatches\":%zu,\"save_succeeded\":%d"
        ",\"proposal_restart_rejected\":%d,\"rejection_unchanged\":%d}\n",
        sched_getcpu(), vlenb, saved_vlenb, saved_vl, saved_vtype,
        (int)completed, grouped_mismatches, contiguous_mismatches,
        runtime_mismatches, save_succeeded, proposal_restart_rejected, rejection_unchanged);
    printf("{\"live_vl\":%" PRIu64 ",\"live_vtype\":%" PRIu64
        ",\"pre_trap_mismatches\":%zu}\n", live_vl, live_vtype, live_mismatches);
    return completed != 1 || saved_vlenb != vlenb || grouped_mismatches
        || runtime_mismatches || !save_succeeded || live_mismatches
        || !proposal_restart_rejected || !rejection_unchanged
        || saved_vl != live_vl || saved_vtype != live_vtype;
}
