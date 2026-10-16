#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "cases.h"

#define STATE_SIZE 0x1040
#define MEMORY_SIZE 4096
#define RECORD_SIZE (STATE_SIZE + MEMORY_SIZE + 512 + 16)
struct { uint8_t pre[64], payload[STATE_SIZE], post[64]; } state_box __attribute__((aligned(64)));
struct { uint8_t pre[64], payload[MEMORY_SIZE], post[64]; } memory_box __attribute__((aligned(64)));
__asm__(".globl simulated_cpu_state\n.set simulated_cpu_state, state_box + 64\n"
        ".globl simulated_cpu_state_riscv64_rvv_1024_riscv64_rvv_256\n"
        ".set simulated_cpu_state_riscv64_rvv_1024_riscv64_rvv_256, state_box + 64\n"
        ".globl simulated_cpu_state_riscv64_rvv_256_riscv64_rvv_1024\n"
        ".set simulated_cpu_state_riscv64_rvv_256_riscv64_rvv_1024, state_box + 64\n"
        ".globl memory_data\n.set memory_data, memory_box + 64\n");
#define simulated_cpu_state state_box.payload
#define state_pre state_box.pre
#define state_post state_box.post
#define memory_data memory_box.payload
uint64_t input_vl, input_vtype, input_vcsr, input_fcsr, actual_fcsr, actual_vcsr;
uint64_t fp_seed[32], register_before[64], register_after[64], stack_guard[8];

static void put(size_t offset, uint64_t value) { memcpy(simulated_cpu_state + offset, &value, 8); }
static void die(const char *message, unsigned index, unsigned vl, unsigned vcsr, unsigned frm) {
    fprintf(stderr, "%s case=%u vl=%u vcsr=%u frm=%u\n", message, index, vl, vcsr, frm); exit(1);
}
int main(int argc, char **argv) {
    if (argc != 2) return 2;
    unsigned long hardware; __asm__ volatile("csrr %0, vlenb" : "=r"(hardware));
#ifdef NATIVE
    if (hardware != SOURCE_VLENB) return 3;
    FILE *reference = fopen(argv[1], "wb");
#else
    if (hardware != TARGET_VLENB) return 3;
    FILE *reference = fopen(argv[1], "rb");
#endif
    if (!reference) return 4;
    uint8_t record[RECORD_SIZE], expected[RECORD_SIZE]; unsigned count = 0;
    const unsigned controls[] = {0, 3, 7}, roundings[] = {0, 2, 4};
    for (unsigned index = 0; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        const struct Case *test = &cases[index];
        unsigned block = TARGET_VLENB * 8 * 8 / test->sew;
        const unsigned requested[] = {0, 1, block / 2 - 1, block / 2, block / 2 + 1,
            block - 1, block, block + 1,
            2 * block - 1, 2 * block, 2 * block + 1, test->vlmax - 1, test->vlmax};
        unsigned lengths[sizeof(requested) / sizeof(requested[0])], length_count = 0;
        for (unsigned i = 0; i < sizeof(requested) / sizeof(requested[0]); ++i) {
            if (requested[i] > test->vlmax) continue;
            unsigned j = 0;
            while (j < length_count && lengths[j] != requested[i]) ++j;
            if (j == length_count) lengths[length_count++] = requested[i];
        }
        for (unsigned seed = 1; seed <= 2; ++seed)
            for (unsigned li = 0; li < length_count; ++li)
                for (unsigned ri = 0; ri < 3; ++ri)
                    for (unsigned ci = 0; ci < 3; ++ci) {
                        unsigned vl = lengths[li], frm = roundings[ri], vcsr = controls[ci];
                        uint32_t random = 0x9e3779b9u * seed;
                        for (unsigned j = 0; j < STATE_SIZE; ++j) {
                            random = random * 1664525u + 1013904223u;
                            simulated_cpu_state[j] = random >> 24;
                        }
                        memset(state_pre, 0xc3, sizeof(state_pre)); memset(state_post, 0x3c, sizeof(state_post));
                        memset(memory_box.pre, 0x6d, 64); memset(memory_box.post, 0xd6, 64);
                        for (unsigned j = 0; j < MEMORY_SIZE; ++j) memory_data[j] = (j * 13 + seed * 7) & 255;
                        input_vl = vl; input_vtype = test->vtype; input_vcsr = vcsr; input_fcsr = (frm << 5) | 1;
                        put(0x1000, 0); put(0x1018, vcsr); put(0x1020, vl); put(0x1028, test->vtype); put(0x1030, SOURCE_VLENB);
                        for (unsigned j = 0; j < 32; ++j)
                            fp_seed[j] = test->sew == 16 ? UINT64_C(0xffffffffffff3555) :
                                         test->sew == 32 ? UINT64_C(0xffffffff3eaaaaab) : UINT64_C(0x3fd5555555555555);
                        test->run();
                        for (unsigned j = 0; j < 64; ++j) {
                            uint32_t mask = j < 32 ? test->gpr : test->fpr;
                            if (!(mask & (UINT32_C(1) << (j & 31))) && register_before[j] != register_after[j])
                                die("GPR/FPR preservation failed", index, vl, vcsr, frm);
                            if (!(mask & (UINT32_C(1) << (j & 31)))) register_after[j] = 0;
                        }
                        for (unsigned j = 0; j < 8; ++j)
                            if (stack_guard[j] != UINT64_C(0x9191919191919191)) die("stack canary failed", index, vl, vcsr, frm);
                        for (unsigned j = 0; j < 64; ++j)
                            if (state_pre[j] != 0xc3 || state_post[j] != 0x3c || memory_box.pre[j] != 0x6d || memory_box.post[j] != 0xd6) die("state/memory canary failed", index, vl, vcsr, frm);
                        memcpy(record, simulated_cpu_state, STATE_SIZE); memcpy(record + STATE_SIZE, memory_data, MEMORY_SIZE);
                        memcpy(record + STATE_SIZE + MEMORY_SIZE, register_after, 512);
                        memcpy(record + RECORD_SIZE - 16, &actual_fcsr, 8); memcpy(record + RECORD_SIZE - 8, &actual_vcsr, 8);
#ifdef NATIVE
                        if (fwrite(record, sizeof(record), 1, reference) != 1) return 5;
#else
                        if (fread(expected, sizeof(expected), 1, reference) != 1) return 5;
                        if (memcmp(record, expected, sizeof(record))) {
                            for (unsigned j = 0; j < sizeof(record); ++j)
                                if (record[j] != expected[j]) {
                                    fprintf(stderr, "byte=0x%x got=%02x expected=%02x\n", j, record[j], expected[j]); break;
                                }
                            die("native source state differs", index, vl, vcsr, frm);
                        }
#endif
                        ++count;
                    }
    }
#ifndef NATIVE
    if (fgetc(reference) != EOF) return 6;
#endif
    fclose(reference);
    printf("{\"cases\":%u,\"source_vlenb\":%d,\"hardware_vlenb\":%lu,\"full_state\":\"PASS\"}\n", count, SOURCE_VLENB, hardware);
    return 0;
}
