#define _POSIX_C_SOURCE 200809L
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>

#if defined(__riscv_vector)
#include <riscv_vector.h>
#endif

static volatile sig_atomic_t keep_running = 1;
static void stop(int signal_number) { (void)signal_number; keep_running = 0; }

static uint64_t vector_step(uint32_t seed) {
    uint32_t values[32];
    for (uint32_t i = 0; i < 32; ++i) values[i] = seed + i;
#if defined(__riscv_vector)
    uint64_t total = 0;
    for (size_t offset = 0; offset < 32;) {
        size_t vl = __riscv_vsetvl_e32m1(32 - offset);
        vint32m1_t vector = __riscv_vle32_v_i32m1((const int32_t *)&values[offset], vl);
        vector = __riscv_vadd_vx_i32m1(vector, 1, vl);
        int32_t out[32] = {0};
        __riscv_vse32_v_i32m1(out, vector, vl);
        for (size_t i = 0; i < vl; ++i) total += (uint32_t)out[i];
        offset += vl;
    }
    return total;
#else
    uint64_t total = 0;
    for (uint32_t i = 0; i < 32; ++i) total += (uint64_t)values[i] + 1;
    return total;
#endif
}

int main(void) {
    signal(SIGTERM, stop);
    signal(SIGINT, stop);
    printf("Hello World\n");
    printf("chimera_thread=%ld\n", (long)getpid());
#if defined(__riscv_vector)
    printf("CHIMERA_HELLO_VECTOR=rvv\n");
#else
    printf("CHIMERA_HELLO_VECTOR=portable\n");
#endif
    printf("CHIMERA_HELLO_READY=1\n");
    fflush(stdout);
    uint64_t checksum = 0;
    uint32_t rounds = 0;
    int announced_active = 0;
    struct timespec pause = {.tv_sec = 0, .tv_nsec = 1000000};
    for (uint32_t round = 0; keep_running && round < 10000; ++round) {
        checksum += vector_step(round);
        if (!announced_active) {
            printf("CHIMERA_HELLO_ACTIVE=1\n");
            fflush(stdout);
            announced_active = 1;
        }
        rounds = round + 1;
        nanosleep(&pause, NULL);
    }
    uint64_t reference = 0;
    for (uint32_t round = 0; round < rounds; ++round)
        reference += 32ULL * (round + 1) + 496ULL;
    printf("CHIMERA_HELLO_CHECKSUM=%llu\n", (unsigned long long)checksum);
    printf("CHIMERA_HELLO_REFERENCE=%llu\n", (unsigned long long)reference);
    return checksum == reference ? 0 : 1;
}
