#define _GNU_SOURCE
#include "kernel.h"
#include <errno.h>
#include <inttypes.h>
#include <math.h>
#include <omp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <windows.h>
#else
#include <sched.h>
#include <sys/syscall.h>
#include <unistd.h>
#endif

typedef struct {
    uint64_t tid, chunks, rows;
    double loop_s, wait_s;
    int cpu_begin, cpu_end;
    char padding[80];
} Worker;
_Static_assert(sizeof(Worker) == 128, "separate worker cache lines");
_Alignas(128) static Worker workers[256];

static uint64_t thread_id(void) {
#ifdef _WIN32
    return (uint64_t)GetCurrentThreadId();
#else
    return (uint64_t)syscall(SYS_gettid);
#endif
}
static unsigned process_id(void) {
#ifdef _WIN32
    return (unsigned)GetCurrentProcessId();
#else
    return (unsigned)getpid();
#endif
}
static int cpu_id(void) {
#ifdef _WIN32
    return -1;
#else
    return sched_getcpu();
#endif
}
static int positive(const char *s) {
    char *end;
    errno = 0;
    long n = strtol(s, &end, 10);
    if (errno || !*s || *end || n < 1 || n > 1000000) {
        fprintf(stderr, "invalid positive integer: %s\n", s);
        exit(2);
    }
    return (int)n;
}
static void usage(void) {
    puts("probe [--mode serial|omp] [--schedule static|dynamic]\n"
         "      [--threads 16] [--rows 1024] [--cols 4096] [--chunk 8]\n"
         "      [--rounds 32] [--passes 20]\n"
         "Each pass repeats identical GEMV work. Discard initial/migration passes.\n"
         "JSON lines: config, pass, worker. No logging in the timed work loop.");
}

int main(int argc, char **argv) {
    int threads = 16, rows = 1024, cols = 4096, chunk = 8;
    int rounds = 32, passes = 20, parallel = 1, dynamic = 1;
    for (int i = 1; i < argc; ++i) {
        const char *key = argv[i];
        if (!strcmp(key, "--help")) { usage(); return 0; }
        if (++i == argc) { fprintf(stderr, "missing value for %s\n", key); return 2; }
        const char *v = argv[i];
        if (!strcmp(key, "--mode")) {
            if (!strcmp(v, "serial")) parallel = 0;
            else if (!strcmp(v, "omp")) parallel = 1;
            else return 2;
        } else if (!strcmp(key, "--schedule")) {
            if (!strcmp(v, "static")) dynamic = 0;
            else if (!strcmp(v, "dynamic")) dynamic = 1;
            else return 2;
        } else if (!strcmp(key, "--threads")) threads = positive(v);
        else if (!strcmp(key, "--rows")) rows = positive(v);
        else if (!strcmp(key, "--cols")) cols = positive(v);
        else if (!strcmp(key, "--chunk")) chunk = positive(v);
        else if (!strcmp(key, "--rounds")) rounds = positive(v);
        else if (!strcmp(key, "--passes")) passes = positive(v);
        else { fprintf(stderr, "unknown option: %s\n", key); return 2; }
    }
    if (threads > 256) { fprintf(stderr, "maximum threads is 256\n"); return 2; }
    size_t cells = (size_t)rows * (size_t)cols;
    if (cells > SIZE_MAX / sizeof(float)) return 2;
    float *a = malloc(cells * sizeof(float));
    float *x = malloc((size_t)cols * sizeof(float));
    float *y = calloc((size_t)rows, sizeof(float));
    double *reference = calloc((size_t)rows, sizeof(double));
    if (!a || !x || !y || !reference) {
        fprintf(stderr, "allocation failed\n");
        free(a); free(x); free(y); free(reference); return 2;
    }
    for (int k = 0; k < cols; ++k) x[k] = (float)((k * 11 % 17) - 8) / 16.0f;
    for (int r = 0; r < rows; ++r) {
        for (int k = 0; k < cols; ++k) {
            size_t i = (size_t)r * cols + k;
            a[i] = (float)(((r * 13 + k * 7) % 31) - 15) / 32.0f;
            reference[r] += (double)a[i] * x[k];
        }
    }
    omp_set_dynamic(0);
    const int chunks = (rows + chunk - 1) / chunk;
    printf("{\"event\":\"config\",\"pid\":%u,\"mode\":\"%s\","
           "\"schedule\":\"%s\",\"requested_threads\":%d,\"rows\":%d,"
           "\"cols\":%d,\"chunk\":%d,\"rounds\":%d,\"passes\":%d}\n",
           process_id(), parallel ? "omp" : "serial", dynamic ? "dynamic" : "static",
           threads, rows, cols, chunk, rounds, passes);
    fflush(stdout);
    int failed = 0;
    for (int pass = 1; pass <= passes; ++pass) {
        memset(workers, 0, sizeof(workers));
        int team = 1, next = 0;
        double start = omp_get_wtime();
        if (!parallel) {
            Worker *s = &workers[0];
            s->tid = thread_id(); s->cpu_begin = cpu_id();
            double begin = omp_get_wtime();
            for (int round = 0; round < rounds; ++round) {
                for (int c = 0; c < chunks; ++c) {
                    size_t first = (size_t)c * chunk;
                    size_t end = first + chunk < (size_t)rows ? first + chunk : (size_t)rows;
                    probe_kernel(a, x, y, first, end, (size_t)cols);
                    ++s->chunks; s->rows += end - first;
                }
            }
            s->loop_s = omp_get_wtime() - begin; s->cpu_end = cpu_id();
        } else {
            /* Clang + LLVM libomp produces __kmpc_fork_call and an outlined
             * callback. The real library invokes that callback on workers. */
            #pragma omp parallel num_threads(threads) shared(team, next)
            {
                int ith = omp_get_thread_num();
                int nth = omp_get_num_threads();
                Worker *s = &workers[ith];
                if (ith == 0) team = nth;
                s->tid = thread_id(); s->cpu_begin = cpu_id();
                for (int round = 0; round < rounds; ++round) {
                    #pragma omp single
                    { next = nth; }
                    /* As in ggml: one initial chunk per worker, then fetch
                     * more from a shared counter. Static is the control. */
                    double begin = omp_get_wtime();
                    int c = ith;
                    while (c < chunks) {
                        size_t first = (size_t)c * chunk;
                        size_t end = first + chunk < (size_t)rows ? first + chunk : (size_t)rows;
                        probe_kernel(a, x, y, first, end, (size_t)cols);
                        ++s->chunks; s->rows += end - first;
                        c = dynamic ? __atomic_fetch_add(&next, 1, __ATOMIC_RELAXED) : c + nth;
                    }
                    double finish = omp_get_wtime();
                    s->loop_s += finish - begin;
                    #pragma omp barrier
                    s->wait_s += omp_get_wtime() - finish;
                }
                s->cpu_end = cpu_id();
            }
        }
        double elapsed = omp_get_wtime() - start;
        double checksum = 0;
        int valid = 1;
        uint64_t total_rows = 0, total_chunks = 0;
        for (int r = 0; r < rows; ++r) {
            checksum += y[r];
            if (!isfinite(y[r]) || fabs((double)y[r] - reference[r]) > 1e-4 * (1 + fabs(reference[r]))) valid = 0;
        }
        for (int t = 0; t < team; ++t) { total_rows += workers[t].rows; total_chunks += workers[t].chunks; }
        if (total_rows != (uint64_t)rows * rounds || total_chunks != (uint64_t)chunks * rounds) valid = 0;
        failed |= !valid;
        printf("{\"event\":\"pass\",\"pass\":%d,\"seconds\":%.9f,\"threads\":%d,"
               "\"elements\":%" PRIu64 ",\"checksum\":%.9g,\"valid\":%s}\n",
               pass, elapsed, team, (uint64_t)rows * cols * rounds, checksum, valid ? "true" : "false");
        for (int t = 0; t < team; ++t) {
            Worker *s = &workers[t];
            printf("{\"event\":\"worker\",\"pass\":%d,\"ith\":%d,\"tid\":%" PRIu64
                   ",\"cpu_begin\":%d,\"cpu_end\":%d,\"chunks\":%" PRIu64
                   ",\"rows\":%" PRIu64 ",\"loop_seconds\":%.9f,\"finish_wait_seconds\":%.9f}\n",
                   pass, t, s->tid, s->cpu_begin, s->cpu_end, s->chunks, s->rows, s->loop_s, s->wait_s);
        }
        fflush(stdout);
    }
    free(a); free(x); free(y); free(reference);
    return failed ? 1 : 0;
}
