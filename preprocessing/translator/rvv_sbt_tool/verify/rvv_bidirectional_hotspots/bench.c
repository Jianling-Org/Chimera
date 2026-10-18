#define _GNU_SOURCE
#include <errno.h>
#include <math.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifndef SOURCE_VLENB
#error SOURCE_VLENB must be supplied by the build
#endif
#ifndef TARGET_VLENB
#error TARGET_VLENB must be supplied by the build
#endif

typedef void (*kernel_fn)(int, float *, size_t, const void *, size_t,
                          const void *, size_t, int);
#define DECLARE(name) extern void name(int, float *, size_t, const void *, size_t, const void *, size_t, int)
DECLARE(native_f32); DECLARE(native_f16); DECLARE(native_q5);
DECLARE(translated_f32); DECLARE(translated_f16); DECLARE(translated_q5);

struct state_fixture { uint8_t pre[64], payload[0x1040], post[64]; };
static __thread struct state_fixture translation_state __attribute__((aligned(64)));
#if SOURCE_VLENB == 128
__asm__(".globl simulated_cpu_state_riscv64_rvv_1024_riscv64_rvv_256\n"
        ".set simulated_cpu_state_riscv64_rvv_1024_riscv64_rvv_256, translation_state + 64\n");
#else
__asm__(".globl simulated_cpu_state_riscv64_rvv_256_riscv64_rvv_1024\n"
        ".set simulated_cpu_state_riscv64_rvv_256_riscv64_rvv_1024, translation_state + 64\n");
#endif

struct q5_block { uint16_t d; uint8_t qh[4], qs[16]; };
struct q8_block { uint16_t d; int8_t qs[32]; };
_Static_assert(sizeof(struct q5_block) == 22, "Q5_0 layout");
_Static_assert(sizeof(struct q8_block) == 34, "Q8_0 layout");
struct buffer { uint8_t *allocation, *data; size_t bytes; uint64_t hash; };
static struct { uint8_t pre[64]; float value; uint8_t post[64]; } output;
static volatile float sink;
static int timing_active;

static void fail(const char *message) { fprintf(stderr, "%s\n", message); exit(1); }
static uint64_t hash_bytes(const uint8_t *data, size_t bytes) {
    uint64_t hash = UINT64_C(14695981039346656037);
    for (size_t i = 0; i < bytes; ++i) hash = (hash ^ data[i]) * UINT64_C(1099511628211);
    return hash;
}
static void put_csr(size_t offset, uint64_t value) { memcpy(translation_state.payload + offset, &value, 8); }
static uint64_t get_csr(size_t offset) { uint64_t v; memcpy(&v, translation_state.payload + offset, 8); return v; }
static void init_state(unsigned vcsr, unsigned frm) {
    memset(&translation_state, 0xa5, sizeof(translation_state));
    memset(translation_state.payload, 0, sizeof(translation_state.payload));
    put_csr(0x1008, vcsr & 1); put_csr(0x1010, vcsr >> 1);
    put_csr(0x1018, vcsr); put_csr(0x1030, SOURCE_VLENB);
    __asm__ volatile("csrw fcsr, %0" : : "r"((unsigned long)frm << 5));
    memset(output.pre, 0xc3, sizeof(output.pre));
    memset(output.post, 0x3c, sizeof(output.post));
    output.value = NAN;
}
static struct buffer allocate(size_t bytes) {
    struct buffer result = {0};
    if (posix_memalign((void **)&result.allocation, 64, bytes + 128)) fail("allocation failed");
    result.data = result.allocation + 64; result.bytes = bytes;
    memset(result.allocation, 0x6d, bytes + 128);
    return result;
}
static uint16_t half_quarters(int quarters) {
    _Float16 value = (_Float16)((float)quarters * 0.25f);
    uint16_t bits; memcpy(&bits, &value, 2); return bits;
}
static float decode_half(uint16_t bits) {
    unsigned sign = bits >> 15, exponent = (bits >> 10) & 31, fraction = bits & 1023;
    float value = exponent ? ldexpf((float)(1024 + fraction), (int)exponent - 25)
                           : ldexpf((float)fraction, -24);
    return sign ? -value : value;
}
static void inputs(const char *op, int n, unsigned seed, struct buffer *x, struct buffer *y, float *expected) {
    *expected = 0;
    if (!strcmp(op, "q5")) {
        *x = allocate((size_t)(n / 32) * sizeof(struct q5_block));
        *y = allocate((size_t)(n / 32) * sizeof(struct q8_block));
        struct q5_block *a = (void *)x->data; struct q8_block *b = (void *)y->data;
        for (int block = 0; block < n / 32; ++block) {
            a[block].d = 0x3800; b[block].d = 0x3400;
            uint32_t high = 0; memset(a[block].qs, 0, 16);
            for (int k = 0; k < 32; ++k) {
                unsigned quant = ((unsigned)(block * 13 + k * 7) + seed * 11) & 31;
                high |= (quant >> 4) << k;
                a[block].qs[k & 15] |= (quant & 15) << ((k >> 4) * 4);
                b[block].qs[k] = (int8_t)(((unsigned)(block * 3 + k * 5) + seed) % 16) - 8;
            }
            memcpy(a[block].qh, &high, 4);
        }
        for (int block = 0; block < n / 32; ++block) {
            uint32_t high; memcpy(&high, a[block].qh, 4);
            int sum = 0;
            for (int k = 0; k < 32; ++k) {
                int q = ((a[block].qs[k & 15] >> ((k >> 4) * 4)) & 15) | (((high >> k) & 1) << 4);
                sum += (q - 16) * b[block].qs[k];
            }
            *expected += decode_half(a[block].d) * decode_half(b[block].d) * (float)sum;
        }
    } else {
        size_t element = !strcmp(op, "f16") ? 2 : 4;
        *x = allocate((size_t)n * element); *y = allocate((size_t)n * element);
        for (int i = 0; i < n; ++i) {
            int a = (int)(((unsigned)i * 7 + seed * 3) % 17) - 8;
            int b = (int)(((unsigned)i * 11 + seed * 5) % 19) - 9;
            if (element == 2) {
                ((uint16_t *)x->data)[i] = half_quarters(a);
                ((uint16_t *)y->data)[i] = half_quarters(b);
                *expected += decode_half(((uint16_t *)x->data)[i]) * decode_half(((uint16_t *)y->data)[i]);
            } else {
                ((float *)x->data)[i] = a * 0.25f; ((float *)y->data)[i] = b * 0.25f;
                *expected += ((float *)x->data)[i] * ((float *)y->data)[i];
            }
        }
    }
    x->hash = hash_bytes(x->data, x->bytes); y->hash = hash_bytes(y->data, y->bytes);
}
static int buffer_ok(const struct buffer *buffer) {
    for (size_t i = 0; i < 64; ++i)
        if (buffer->allocation[i] != 0x6d || buffer->data[buffer->bytes + i] != 0x6d) return 0;
    return hash_bytes(buffer->data, buffer->bytes) == buffer->hash;
}
static void check(const struct buffer *x, const struct buffer *y, float expected, int translated, unsigned vcsr, unsigned frm) {
    if (output.value != expected) {
        fprintf(stderr, "result mismatch: got=%.9g expected=%.9g\n", output.value, expected); exit(1);
    }
    if (!buffer_ok(x) || !buffer_ok(y)) fail("input or canary changed");
    for (size_t i = 0; i < 64; ++i)
        if (output.pre[i] != 0xc3 || output.post[i] != 0x3c ||
            translation_state.pre[i] != 0xa5 || translation_state.post[i] != 0xa5) fail("output/state canary changed");
    if (translated && (get_csr(0x1000) != 0 || get_csr(0x1018) != vcsr || get_csr(0x1030) != SOURCE_VLENB)) fail("state CSR changed");
    unsigned long fcsr; __asm__ volatile("csrr %0, fcsr" : "=r"(fcsr));
    /* Clock conversion/calibration uses FP; exact fflags are checked before timing. */
    if ((fcsr >> 5) != frm || (!timing_active && (fcsr & 31))) fail("unexpected FCSR/rounding change for exact inputs");
}
static kernel_fn select_kernel(const char *op, int translated) {
    if (!strcmp(op, "f32")) return translated ? translated_f32 : native_f32;
    if (!strcmp(op, "f16")) return translated ? translated_f16 : native_f16;
    if (!strcmp(op, "q5")) return translated ? translated_q5 : native_q5;
    fail("unknown operator"); return NULL;
}
static double now(void) {
    struct timespec ts; if (clock_gettime(CLOCK_MONOTONIC_RAW, &ts)) fail("clock_gettime failed");
    return ts.tv_sec + ts.tv_nsec * 1e-9;
}
static double batch(kernel_fn fn, int n, const struct buffer *x, const struct buffer *y, unsigned long calls) {
    double start = now();
    for (unsigned long i = 0; i < calls; ++i) fn(n, &output.value, 0, x->data, 0, y->data, 0, 1);
    double elapsed = now() - start; sink = output.value; return elapsed;
}
static unsigned long frequency(int cpu) {
    char path[128]; snprintf(path, sizeof(path), "/sys/devices/system/cpu/cpu%d/cpufreq/scaling_cur_freq", cpu);
    FILE *file = fopen(path, "r"); unsigned long value = 0;
    if (!file || fscanf(file, "%lu", &value) != 1) fail("frequency unavailable");
    fclose(file); return value;
}
int main(int argc, char **argv) {
    if (argc != 8) fail("usage: bench OP MODE N SAMPLES SAMPLE_MS CPU CHECK_ONLY");
    const char *op = argv[1]; int translated = !strcmp(argv[2], "translated");
    if (!translated && strcmp(argv[2], "native")) fail("unknown mode");
    int n = atoi(argv[3]), samples = atoi(argv[4]), cpu = atoi(argv[6]);
    double sample_seconds = atof(argv[5]) / 1000.0; int check_only = atoi(argv[7]);
    if (n < 0 || n > 1048576 || samples < 1 || samples > 1000 || sample_seconds <= 0 ||
        (!strcmp(op, "q5") && n % 32)) fail("invalid benchmark dimensions");
    cpu_set_t mask; if (sched_getaffinity(0, sizeof(mask), &mask) || CPU_COUNT(&mask) != 1 || !CPU_ISSET(cpu, &mask) || sched_getcpu() != cpu) fail("affinity mismatch");
    unsigned long hardware_vlenb; __asm__ volatile("csrr %0, vlenb" : "=r"(hardware_vlenb));
    if (hardware_vlenb != TARGET_VLENB) fail("hardware VLEN mismatch");
    kernel_fn fn = select_kernel(op, translated);
    if (check_only) {
        const int sizes[] = {0, 1, 7, 15, 16, 31, 32, 33, 63, 64, 65, 127, 128, 129, 256, 257, 2048};
        unsigned cases = 0;
        for (size_t k = 0; k < sizeof(sizes) / sizeof(sizes[0]); ++k) {
            if (!strcmp(op, "q5") && sizes[k] % 32) continue;
            for (unsigned seed = 1; seed <= 4; ++seed) {
                struct buffer x, y; float expected; inputs(op, sizes[k], seed, &x, &y, &expected);
                for (unsigned frm = 0; frm < 5; ++frm)
                    for (unsigned vcsr = 0; vcsr < 8; ++vcsr) {
                        init_state(vcsr, frm); fn(sizes[k], &output.value, 0, x.data, 0, y.data, 0, 1);
                        check(&x, &y, expected, translated, vcsr, frm); ++cases;
                    }
                free(x.allocation); free(y.allocation);
            }
        }
        printf("{\"operator\":\"%s\",\"mode\":\"%s\",\"cpu\":%d,\"vlenb\":%lu,\"cases\":%u,\"validation\":\"PASS\"}\n", op, argv[2], cpu, hardware_vlenb, cases);
        return 0;
    }
    struct buffer x, y; float expected; inputs(op, n, 1, &x, &y, &expected); init_state(0, 0);
    fn(n, &output.value, 0, x.data, 0, y.data, 0, 1); check(&x, &y, expected, translated, 0, 0);
    for (unsigned i = 0; i < 10; ++i) fn(n, &output.value, 0, x.data, 0, y.data, 0, 1);
    timing_active = 1;
    unsigned long calls = 1; double pilot;
    do { pilot = batch(fn, n, &x, &y, calls); if (pilot < 0.005) calls *= 2; } while (pilot < 0.005);
    calls = (unsigned long)fmax(1, ceil(calls * sample_seconds / pilot));
    printf("{\"operator\":\"%s\",\"mode\":\"%s\",\"n\":%d,\"cpu\":%d,\"source_vlenb\":%d,\"hardware_vlenb\":%lu,\"calls\":%lu,\"expected\":%.9g,\"input_hash\":[\"%016llx\",\"%016llx\"],\"samples_ns\":[", op, argv[2], n, cpu, SOURCE_VLENB, hardware_vlenb, calls, expected, (unsigned long long)x.hash, (unsigned long long)y.hash);
    unsigned long frequencies[1000];
    for (int sample = 0; sample < samples; ++sample) {
        frequencies[sample] = frequency(cpu); double elapsed = batch(fn, n, &x, &y, calls);
        if (frequency(cpu) != frequencies[sample] || sched_getcpu() != cpu) fail("frequency or CPU changed");
        check(&x, &y, expected, translated, 0, 0);
        printf("%s%.9f", sample ? "," : "", elapsed * 1e9 / calls);
    }
    printf("],\"frequency_khz\":[");
    for (int sample = 0; sample < samples; ++sample) printf("%s%lu", sample ? "," : "", frequencies[sample]);
    printf("],\"validation\":\"PASS\"}\n"); free(x.allocation); free(y.allocation); return 0;
}
