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
enum { GATE_NONE, GATE_INIT, GATE_BEFORE, GATE_AFTER };
typedef struct { uint16_t d[64]; uint8_t hmask[32*64], qs[64*64], scales[12*64]; } Q3;
typedef struct { float d[4]; int8_t qs[256*4]; int16_t bsums[64]; } Q8;
_Static_assert(sizeof(Q3) == 7040, "Q3 layout");
_Static_assert(sizeof(Q8) == 1168, "Q8 layout");
extern void bench_kernel_baseline(int, float *, size_t, const void *, const void *, int, int);
extern void bench_kernel_candidate(int, float *, size_t, const void *, const void *, int, int);
typedef void (*Kernel)(int, float *, size_t, const void *, const void *, int, int);
static const Kernel kernels[2] = {bench_kernel_baseline, bench_kernel_candidate};
static const char * const names[2] = {"baseline", "candidate"};

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
static __thread TranslationState translation_state_baseline __attribute__((aligned(64)));
static __thread TranslationState translation_state_candidate __attribute__((aligned(64)));
static TranslationState * state_addresses[2][THREADS];
__asm__(".globl " SOURCE_STATE "_baseline\n.set " SOURCE_STATE "_baseline, translation_state_baseline + 64\n");
__asm__(".globl " SOURCE_STATE "_candidate\n.set " SOURCE_STATE "_candidate, translation_state_candidate + 64\n");

static int state_guard(const TranslationState * state) {
    __asm__ volatile ("" ::: "memory");
    if (!state || *(const uint64_t *)(state->payload + 0x1030) != SOURCE_VLENB) return 0;
    for (int i = 0; i < GUARD; ++i)
        if (state->pre[i] != 0xa5 || state->post[i] != 0xa5) return 0;
    return 1;
}

static int translation_guards(int variant) {
    for (int t = 0; t < THREADS; ++t) {
        if (!state_guard(state_addresses[variant][t])) return 0;
        for (int previous = 0; previous < t; ++previous)
            if (state_addresses[variant][t] == state_addresses[variant][previous]) return 0;
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

static void compute(int variant, int iterations, int check_environment) {
    #pragma omp parallel num_threads(THREADS)
    {
        int t = omp_get_thread_num(), tiles = n/64;
#if !defined(BENCH_NATIVE)
        TranslationState * local_state = variant ? &translation_state_candidate : &translation_state_baseline;
#endif
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
                memset(local_state, 0xa5, sizeof(*local_state));
                memset(local_state->payload, 0, sizeof(local_state->payload));
                *(uint64_t *)(local_state->payload + 0x1030) = SOURCE_VLENB;
                state_addresses[variant][t] = local_state;
#endif
                CPU_ZERO(&set);
                CPU_SET(expected_cpu, &set);
                if (sched_setaffinity(0, sizeof(set), &set)) abort();
            }
#if !defined(BENCH_NATIVE)
            if (state_addresses[variant][t] != local_state || !state_guard(local_state)) abort();
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
            kernels[variant](k, output+(size_t)first_row*stride+first_col, stride,
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



typedef struct {
    int cpu_before, cpu_after;
    unsigned long vlenb_before, vlenb_after, frequency_before, frequency_after;
} Environment;
typedef struct {
    double elapsed, per_call, error;
    Environment worker[THREADS];
} Measurement;
static int initialized[2];

static double gate(int variant, const char * phase, int pair, const float * ref,
                   Buffer wb, Buffer xb, Buffer yb, uint64_t wh, uint64_t xh) {
    double error = validate(ref);
    int intact = guards(wb) && guards(xb) && guards(yb) &&
                 hash(wb.data, wb.size) == wh && hash(xb.data, xb.size) == xh;
    for (int v = 0; v < 2; ++v) {
        if (!initialized[v]) continue;
        intact = intact && translation_guards(v);
        for (int t = 0; t < THREADS; ++t)
            if (initialized[1-v] && state_addresses[v][t] == state_addresses[1-v][t]) intact = 0;
    }
    if (failure || !intact) {
        printf("{\"validation\":\"FAIL\",\"variant\":\"%s\",\"phase\":\"%s\",\"pair\":%d,\"max_abs_error\":%.17g,\"canaries_and_inputs_intact\":%s}\n",
               names[variant], phase, pair, error, intact ? "true" : "false");
        fflush(stdout);
        exit(1);
    }
    return error;
}

static void snapshot(Environment environment[THREADS]) {
    for (int t = 0; t < THREADS; ++t)
        environment[t] = (Environment){cpu_before[t], cpu_after[t], observed_vlenb[t], final_vlenb[t], frequency_before[t], frequency_after[t]};
}

static void print_environment(const Environment environment[THREADS]) {
    printf("[");
    for (int t = 0; t < THREADS; ++t)
        printf("%s{\"worker\":%d,\"cpu_before\":%d,\"cpu_after\":%d,\"vlenb_before\":%lu,\"vlenb_after\":%lu,\"frequency_before_khz\":%lu,\"frequency_after_khz\":%lu}",
               t ? "," : "", t, environment[t].cpu_before, environment[t].cpu_after,
               environment[t].vlenb_before, environment[t].vlenb_after,
               environment[t].frequency_before, environment[t].frequency_after);
    printf("]");
}

int main(int argc, char ** argv) {
    if ((argc != 6 && argc != 7) || strcmp(argv[1], "measure")) return 2;
    int samples = argc == 7 ? atoi(argv[6]) : SAMPLES;
    if (samples < 1 || samples > 50) return 2;
    m = atoi(argv[2]); n = atoi(argv[3]); k = atoi(argv[4]);
    if (m < 8 || m > 64 || m%8 || n < 256 || n > 5632 || n%64 || k < 256 || k > 5632 || k%256) return 2;
    omp_set_dynamic(0);
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
    Measurement * measurements = calloc((size_t)samples*2, sizeof(*measurements));
    if (!raw_w || !raw_x || !measurements) abort();
    prepare();
    float * ref = reference("measure", argv[5]);
    uint64_t wh = hash(wb.data, wb.size), xh = hash(xb.data, xb.size);
    double pilots[2], initial_errors[2];
    int iterations[2];
    for (int variant = 0; variant < 2; ++variant) {
        memset(yb.data, 0xa5, yb.size);
        compute(variant, 1, GATE_INIT);
        initialized[variant] = 1;
        initial_errors[variant] = gate(variant, "initial", -1, ref, wb, xb, yb, wh, xh);
        compute(variant, 3, GATE_NONE);
        gate(variant, "warmup", -1, ref, wb, xb, yb, wh, xh);
        compute(variant, 0, GATE_BEFORE);
        double start = now();
        compute(variant, 1, GATE_NONE);
        pilots[variant] = now()-start;
        compute(variant, 0, GATE_AFTER);
        gate(variant, "pilot", -1, ref, wb, xb, yb, wh, xh);
        if (!isfinite(pilots[variant]) || pilots[variant] <= 0) abort();
        iterations[variant] = (int)ceil(0.1/pilots[variant]);
        if (iterations[variant] < 1) iterations[variant] = 1;
        if (iterations[variant] > 2048) iterations[variant] = 2048;
    }
    for (int pair = 0; pair < samples; ++pair) {
        for (int position = 0; position < 2; ++position) {
            int variant = pair%2 ? 1-position : position;
            Measurement * result = measurements + 2*pair + variant;
            memset(yb.data, 0xa5, yb.size);
            compute(variant, 0, GATE_BEFORE);
            double start = now();
            compute(variant, iterations[variant], GATE_NONE);
            result->elapsed = now()-start;
            result->per_call = result->elapsed/iterations[variant];
            compute(variant, 0, GATE_AFTER);
            snapshot(result->worker);
            result->error = gate(variant, "sample", pair, ref, wb, xb, yb, wh, xh);
        }
    }
    printf("{\"validation\":\"PASS\",\"canaries_and_inputs_intact\":true,\"translation_state_intact\":true,\"max_abs_error\":0,\"implementation\":\"%s\",\"source_vlenb\":%d,\"target_vlenb\":%d,\"vlenb\":%d,\"threads\":8,\"M\":%d,\"N\":%d,\"K\":%d,\"macs\":%lld,\"samples\":%d,\"warmups_per_variant\":3,\"sample_target_seconds\":0.1,\"clock\":\"CLOCK_MONOTONIC_RAW\",\"state_mode\":\"independent TLS per variant\",\"input_hashes\":{\"weights_fnv1a64\":\"%016llx\",\"inputs_fnv1a64\":\"%016llx\"},\"iterations_per_sample_baseline\":%d,\"iterations_per_sample_candidate\":%d,\"pilot_seconds_baseline\":%.17g,\"pilot_seconds_candidate\":%.17g,\"initial_gate_errors\":[%.17g,%.17g],\"seconds_per_call_baseline\":[",
           IMPLEMENTATION,SOURCE_VLENB,TARGET_VLENB,TARGET_VLENB,m,n,k,(long long)m*n*k,samples,
           (unsigned long long)wh,(unsigned long long)xh,iterations[0],iterations[1],pilots[0],pilots[1],initial_errors[0],initial_errors[1]);
    for (int p = 0; p < samples; ++p) printf("%s%.17g",p ? "," : "",measurements[2*p].per_call);
    printf("],\"seconds_per_call_candidate\":[");
    for (int p = 0; p < samples; ++p) printf("%s%.17g",p ? "," : "",measurements[2*p+1].per_call);
    printf("],\"pair_orders\":[");
    for (int p = 0; p < samples; ++p) printf("%s\"%s\"",p ? "," : "",p%2 ? "BA" : "AB");
    printf("],\"affinity_masks\":[");
    for (int t = 0; t < THREADS; ++t) printf("%s%lu",t ? "," : "",affinity[t]);
    printf("],\"source_state_vlenb_baseline\":[");
    for (int t = 0; t < THREADS; ++t) printf("%s%lu",t ? "," : "",(unsigned long)*(uint64_t *)(state_addresses[0][t]->payload+0x1030));
    printf("],\"source_state_vlenb_candidate\":[");
    for (int t = 0; t < THREADS; ++t) printf("%s%lu",t ? "," : "",(unsigned long)*(uint64_t *)(state_addresses[1][t]->payload+0x1030));
    printf("],\"pairs\":[");
    for (int p = 0; p < samples; ++p) {
        printf("%s{\"pair\":%d,\"order\":\"%s\",\"gain\":%.17g",p ? "," : "",p,p%2 ? "BA" : "AB",measurements[2*p].per_call/measurements[2*p+1].per_call);
        for (int v = 0; v < 2; ++v) {
            Measurement * result = measurements+2*p+v;
            printf(",\"%s\":{\"elapsed_seconds\":%.17g,\"seconds_per_call\":%.17g,\"validation\":\"PASS\",\"max_abs_error\":%.17g,\"canaries_and_inputs_intact\":true,\"worker_environment\":",names[v],result->elapsed,result->per_call,result->error);
            print_environment(result->worker);
            printf("}");
        }
        printf("}");
    }
    printf("]}\n");
    free(measurements);
    return 0;
}
