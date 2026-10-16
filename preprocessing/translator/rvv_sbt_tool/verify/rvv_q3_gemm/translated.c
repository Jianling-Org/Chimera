#define _GNU_SOURCE
#include <math.h>
#include <omp.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifndef BENCH_SAMPLES
#define BENCH_SAMPLES 50
#endif
#if !defined(SOURCE_VLENB) || !defined(TARGET_VLENB) || !defined(CPU_FIRST)
#error SOURCE_VLENB, TARGET_VLENB and CPU_FIRST are required
#endif
#if TARGET_VLENB == 32 && CPU_FIRST == 0
#define TARGET_FREQ_KHZ 2200000ul
#elif TARGET_VLENB == 128 && CPU_FIRST == 8
#define TARGET_FREQ_KHZ 1800000ul
#else
#error Unsupported target VLEN and CPU range
#endif
#if defined(BENCH_NATIVE)
#if SOURCE_VLENB != TARGET_VLENB
#error Native reference must execute at its source VLEN
#endif
#define IMPLEMENTATION "native"
#elif SOURCE_VLENB == 128 && TARGET_VLENB == 32
#define IMPLEMENTATION "rvv1024_to_rvv256"
#define SOURCE_STATE "simulated_cpu_state_riscv64_rvv_1024_riscv64_rvv_256"
#elif SOURCE_VLENB == 32 && TARGET_VLENB == 128
#define IMPLEMENTATION "rvv256_to_rvv1024"
#define SOURCE_STATE "simulated_cpu_state_riscv64_rvv_256_riscv64_rvv_1024"
#else
#error Unsupported translation direction
#endif
enum { THREADS = 8, GUARD = 64, PAD = 16, SAMPLES = BENCH_SAMPLES };
_Static_assert(SAMPLES == 3 || SAMPLES == 50, "supported sample counts: pilot=3, full=50");
enum { GATE_NONE, GATE_INIT, GATE_BEFORE, GATE_AFTER };
typedef struct { uint16_t d[64]; uint8_t hmask[32*64], qs[64*64], scales[12*64]; } Q3;
typedef struct { float d[4]; int8_t qs[256*4]; int16_t bsums[64]; } Q8;
_Static_assert(sizeof(Q3) == 7040, "Q3 layout");
_Static_assert(sizeof(Q8) == 1168, "Q8 layout");
extern void bench_kernel(int, float *, size_t, const void *, const void *, int, int);

typedef struct { uint8_t * base, * data; size_t size; } Buffer;
static int m, n, k, stride, blocks, failure;
static Q3 * weights;
static Q8 * inputs;
static float * output;
static int8_t * raw_w, * raw_x;
static unsigned long observed_vlenb[THREADS], affinity[THREADS];
static unsigned long final_vlenb[THREADS], frequency_before[THREADS], frequency_after[THREADS];
static int cpu_before[THREADS], cpu_after[THREADS];

#if !defined(BENCH_NATIVE)
typedef struct { uint8_t pre[64], payload[0x1040], post[64]; } TranslationState;
static __thread TranslationState translation_state __attribute__((aligned(64)));
static TranslationState * state_addresses[THREADS];
__asm__(".globl " SOURCE_STATE "\n.set " SOURCE_STATE ", translation_state + 64\n");

static int state_guard(const TranslationState * state) {
    __asm__ volatile ("" ::: "memory");
    if (!state || *(const uint64_t *)(state->payload + 0x1030) != SOURCE_VLENB) return 0;
    for (int i = 0; i < GUARD; ++i)
        if (state->pre[i] != 0xa5 || state->post[i] != 0xa5) return 0;
    return 1;
}

static int translation_guards(void) {
    for (int t = 0; t < THREADS; ++t) {
        if (!state_guard(state_addresses[t])) return 0;
        for (int previous = 0; previous < t; ++previous)
            if (state_addresses[t] == state_addresses[previous]) return 0;
    }
    return 1;
}
#endif

static unsigned long frequency_khz(int cpu) {
    char path[128];
    snprintf(path, sizeof(path), "/sys/devices/system/cpu/cpu%d/cpufreq/scaling_cur_freq", cpu);
    FILE * stream = fopen(path, "r");
    unsigned long value;
    if (!stream) { fprintf(stderr, "cannot read CPU frequency: %s\n", path); exit(1); }
    int parsed = fscanf(stream, "%lu", &value);
    int closed = fclose(stream);
    if (parsed != 1 || closed) { fprintf(stderr, "invalid CPU frequency: %s\n", path); exit(1); }
    return value;
}

static double now(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC_RAW, &ts)) abort();
    return ts.tv_sec + ts.tv_nsec * 1e-9;
}

static Buffer buffer(size_t size) {
    Buffer b = {.size = size};
    if (posix_memalign((void **)&b.base, 64, size + 2*GUARD)) abort();
    memset(b.base, 0xa5, size + 2*GUARD);
    b.data = b.base + GUARD;
    return b;
}

static int guards(Buffer b) {
    for (int i = 0; i < GUARD; ++i)
        if (b.base[i] != 0xa5 || b.data[b.size+i] != 0xa5) return 0;
    return 1;
}

static uint64_t hash(const void * data, size_t length) {
    const uint8_t * p = data;
    uint64_t h = UINT64_C(14695981039346656037);
    for (size_t i = 0; i < length; ++i) h = (h ^ p[i]) * UINT64_C(1099511628211);
    return h;
}

static uint32_t random_u32(uint32_t * state) {
    *state = *state * UINT32_C(1664525) + UINT32_C(1013904223);
    return *state;
}

static void prepare(void) {
    uint32_t seed = 0x7134b8d9;
    memset(weights, 0, (size_t)(n/64)*blocks*sizeof(Q3));
    memset(inputs, 0, (size_t)(m/4)*blocks*sizeof(Q8));
    for (int c = 0; c < n; ++c) {
        for (int b = 0; b < blocks; ++b) {
            Q3 * q = weights + (c/64)*blocks + b;
            q->d[c%64] = 0x2400; /* 2^-6; zero scale bytes decode to -32. */
            for (int x = 0; x < 256; ++x) {
                int value = (int)((random_u32(&seed) >> 16) & 7) - 4;
                raw_w[(size_t)c*k+b*256+x] = value;
                int phase = x/128, group = (x%128)/32, lane = x%32;
                q->qs[(phase*32+lane)*64+c%64] |= (value&3) << (2*group);
                q->hmask[lane*64+c%64] |= (value >= 0) << (phase*4+group);
            }
        }
    }
    for (int r = 0; r < m; ++r) {
        for (int b = 0; b < blocks; ++b) {
            Q8 * q = inputs + (r/4)*blocks+b;
            q->d[r%4] = 0.03125f;
            for (int x = 0; x < 256; ++x) {
                int value = (int)((random_u32(&seed) >> 16) & 15) - 8;
                raw_x[(size_t)r*k+b*256+x] = value;
                q->qs[x*4+r%4] = value;
                q->bsums[(x/16)*4+r%4] += value;
            }
        }
    }
}

static void compute(int iterations, int check_environment) {
    #pragma omp parallel num_threads(THREADS)
    {
        int t = omp_get_thread_num(), tiles = n/64;
        int first_col, cols, first_row, rows;
        if (tiles >= THREADS) {
            first_col = (tiles*t/THREADS)*64;
            cols = (tiles*(t+1)/THREADS)*64-first_col;
            first_row = 0; rows = m;
        } else {
            int groups = THREADS/tiles, group = t/tiles;
            first_col = (t%tiles)*64; cols = 64;
            first_row = ((m/4)*group/groups)*4;
            rows = ((m/4)*(group+1)/groups)*4-first_row;
        }
        if (check_environment != GATE_NONE) {
            int expected_cpu = CPU_FIRST + t;
            cpu_set_t set;
            if (check_environment == GATE_INIT) {
#if !defined(BENCH_NATIVE)
                memset(&translation_state, 0xa5, sizeof(translation_state));
                memset(translation_state.payload, 0, sizeof(translation_state.payload));
                *(uint64_t *)(translation_state.payload + 0x1030) = SOURCE_VLENB;
                state_addresses[t] = &translation_state;
#endif
                CPU_ZERO(&set);
                CPU_SET(expected_cpu, &set);
                if (sched_setaffinity(0, sizeof(set), &set)) abort();
            }
#if !defined(BENCH_NATIVE)
            if (state_addresses[t] != &translation_state || !state_guard(&translation_state)) abort();
#endif
            if (omp_get_num_threads() != THREADS || sched_getaffinity(0, sizeof(set), &set)) abort();
            unsigned long mask = 0, hardware_vlenb;
            for (int cpu = 0; cpu < CPU_SETSIZE; ++cpu)
                if (CPU_ISSET(cpu, &set)) {
                    if (cpu < CPU_FIRST || cpu >= CPU_FIRST + THREADS) abort();
                    mask |= 1ul << cpu;
                }
            int actual_cpu = sched_getcpu();
            __asm__ volatile ("csrr %0, vlenb" : "=r"(hardware_vlenb));
            unsigned long frequency = frequency_khz(expected_cpu);
            if (actual_cpu != expected_cpu || mask != (1ul << expected_cpu) ||
                hardware_vlenb != TARGET_VLENB || frequency != TARGET_FREQ_KHZ || !rows || !cols) {
                fprintf(stderr, "worker=%d cpu=%d expected_cpu=%d affinity=%lu vlenb=%lu expected_vlenb=%d frequency_khz=%lu expected_frequency_khz=%lu rows=%d cols=%d\n",
                        t, actual_cpu, expected_cpu, mask, hardware_vlenb, TARGET_VLENB,
                        frequency, TARGET_FREQ_KHZ, rows, cols);
                exit(1);
            }
            if (check_environment == GATE_AFTER) {
                cpu_after[t] = actual_cpu;
                final_vlenb[t] = hardware_vlenb;
                frequency_after[t] = frequency;
            } else {
                cpu_before[t] = actual_cpu;
                observed_vlenb[t] = hardware_vlenb;
                frequency_before[t] = frequency;
                affinity[t] = mask;
            }
        }
        for (int i = 0; i < iterations; ++i)
            bench_kernel(k, output+(size_t)first_row*stride+first_col, stride,
                         weights+(first_col/64)*blocks, inputs+(first_row/4)*blocks, rows, cols);
    }
}

static float * reference(const char * mode, const char * path) {
    size_t count = (size_t)m*n;
    float * ref = malloc(count*sizeof(float));
    if (!ref) abort();
    uint32_t header[3] = {m,n,k};
    if (!strcmp(mode, "prepare")) {
        /* This reference uses the original integer matrices, not the packed data or RVV kernel. */
        #pragma omp parallel for num_threads(THREADS) schedule(static)
        for (int r = 0; r < m; ++r) {
            for (int c = 0; c < n; ++c) {
                int64_t sum = 0;
                for (int x = 0; x < k; ++x) sum += (int)raw_x[(size_t)r*k+x] * (int)raw_w[(size_t)c*k+x];
                ref[(size_t)r*n+c] = (float)sum * (-1.0f/64.0f);
            }
        }
        FILE * f = fopen(path, "wb");
        if (!f || fwrite(header, sizeof(header), 1, f) != 1 || fwrite(ref, sizeof(float), count, f) != count || fclose(f)) abort();
    } else {
        uint32_t got[3];
        FILE * f = fopen(path, "rb");
        if (!f || fread(got, sizeof(got), 1, f) != 1 || memcmp(got, header, sizeof(got)) || fread(ref, sizeof(float), count, f) != count || fgetc(f) != EOF || fclose(f)) abort();
    }
    return ref;
}

static double validate(const float * ref) {
    double max_error = 0;
    for (int r = 0; r < m; ++r) {
        for (int c = 0; c < n; ++c) {
            float actual = output[(size_t)r*stride+c], expected = ref[(size_t)r*n+c];
            double error = fabs((double)actual-expected);
            if (!isfinite(actual) || error != 0) failure = 1;
            if (error > max_error) max_error = error;
        }
        uint8_t * padding = (uint8_t *)(output+(size_t)r*stride+n);
        for (int c = 0; c < PAD*(int)sizeof(float); ++c) if (padding[c] != 0xa5) failure = 1;
    }
    return max_error;
}

int main(int argc, char ** argv) {
    if (argc != 6 || (strcmp(argv[1], "prepare") && strcmp(argv[1], "measure"))) return 2;
    m = atoi(argv[2]); n = atoi(argv[3]); k = atoi(argv[4]);
    if (m < 8 || m > 64 || m%8 || n < 256 || n > 5632 || n%64 || k < 256 || k > 5632 || k%256) return 2;
    if (n / 64 < THREADS && THREADS % (n / 64)) {
        fputs("column tiles must divide the eight workers when N < 512\n", stderr);
        return 2;
    }
    stride = n+PAD; blocks = k/256;
    Buffer wb = buffer((size_t)(n/64)*blocks*sizeof(Q3));
    Buffer xb = buffer((size_t)(m/4)*blocks*sizeof(Q8));
    Buffer yb = buffer((size_t)m*stride*sizeof(float));
    weights = (Q3 *)wb.data; inputs = (Q8 *)xb.data; output = (float *)yb.data;
    raw_w = malloc((size_t)n*k); raw_x = malloc((size_t)m*k);
    if (!raw_w || !raw_x) abort();
    prepare();
    float * ref = reference(argv[1], argv[5]);
    uint64_t wh = hash(wb.data, wb.size), xh = hash(xb.data, xb.size);
    compute(1, GATE_INIT);
    double error = validate(ref);
#if !defined(BENCH_NATIVE)
    if (!translation_guards()) abort();
#endif
    if (failure || !guards(wb) || !guards(xb) || !guards(yb)) {
        printf("{\"validation\":\"FAIL\",\"max_abs_error\":%.9g}\n", error); return 1;
    }
    compute(3, 0);
    double start = now(); compute(1, 0); double pilot = now()-start;
    int iterations = (int)ceil(0.1/pilot);
    if (iterations < 1) iterations = 1;
    if (iterations > 2048) iterations = 2048;
    compute(0, GATE_BEFORE);
    double elapsed[SAMPLES];
    for (int i = 0; i < SAMPLES; ++i) {
        start = now(); compute(iterations, 0); elapsed[i] = (now()-start)/iterations;
    }
    compute(0, GATE_AFTER);
    error = validate(ref);
#if !defined(BENCH_NATIVE)
    if (!translation_guards()) abort();
#endif
    int intact = guards(wb) && guards(xb) && guards(yb) && wh == hash(wb.data, wb.size) && xh == hash(xb.data, xb.size);
    printf("{\"validation\":\"%s\",\"max_abs_error\":%.9g,\"canaries_and_inputs_intact\":%s,\"threads\":8,\"vlenb\":%d,\"M\":%d,\"N\":%d,\"K\":%d,\"macs\":%lld,\"iterations_per_sample\":%d,\"pilot_seconds\":%.9g,\"seconds_per_call\":[",
           (!failure && intact)?"PASS":"FAIL",error,intact?"true":"false",TARGET_VLENB,m,n,k,(long long)m*n*k,iterations,pilot);
    for (int i = 0; i < SAMPLES; ++i) printf("%s%.9g",i?",":"",elapsed[i]);
    printf("],\"affinity_masks\":[");
    for (int i = 0; i < THREADS; ++i) printf("%s%lu",i?",":"",affinity[i]);
    printf("],\"worker_environment\":[");
    for (int t = 0; t < THREADS; ++t)
        printf("%s{\"worker\":%d,\"cpu_before\":%d,\"cpu_after\":%d,\"vlenb_before\":%lu,\"vlenb_after\":%lu,\"frequency_before_khz\":%lu,\"frequency_after_khz\":%lu}",
               t?",":"",t,cpu_before[t],cpu_after[t],observed_vlenb[t],final_vlenb[t],frequency_before[t],frequency_after[t]);
    printf("],\"implementation\":\"%s\",\"source_vlenb\":%d,\"target_vlenb\":%d,\"samples\":%d",
           IMPLEMENTATION,SOURCE_VLENB,TARGET_VLENB,SAMPLES);
#if !defined(BENCH_NATIVE)
    printf(",\"source_state_vlenb\":[");
    for (int t = 0; t < THREADS; ++t)
        printf("%s%lu",t?",":"",(unsigned long)*(const uint64_t *)(state_addresses[t]->payload+0x1030));
    printf("],\"translation_state_intact\":%s",translation_guards()?"true":"false");
#endif
    printf("}\n");
    return failure || !intact;
}
