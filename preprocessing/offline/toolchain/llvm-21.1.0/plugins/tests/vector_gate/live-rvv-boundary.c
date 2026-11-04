#define _GNU_SOURCE
#include <riscv_vector.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>

// No source noinline/Gate annotations: the compiler plugin owns the boundary.
static void vector_leaf(float *restrict dst, const float *restrict src,
                        float *restrict scalar_dst, size_t count) {
    size_t vl = __riscv_vsetvl_e32m1(count);
    vfloat32m1_t value = __riscv_vle32_v_f32m1(src, vl);
    // Positive, explicit vector state must survive this register clobber.
    // A memory clobber prevents moving the source load below the barrier.
    __asm__ volatile ("" ::: "memory", "v0", "v1", "v2", "v3", "v4", "v5",
        "v6", "v7", "v8", "v9", "v10", "v11", "v12", "v13", "v14", "v15",
        "v16", "v17", "v18", "v19", "v20", "v21", "v22", "v23", "v24",
        "v25", "v26", "v27", "v28", "v29", "v30", "v31");
    value = __riscv_vfadd_vf_f32m1(value, 0.5f, vl);
    __riscv_vse32_v_f32m1(dst, value, vl);
    // The inherited Gate policy must still prohibit independent SLP here.
    for (size_t i = 0; i < 4; ++i)
        scalar_dst[i] = src[i] + 2.0f;
}

void gated_control(void (*callback)(unsigned *), unsigned *calls,
                   float *dst, const float *src, float *scalar_dst, size_t count) {
    callback(calls);
    vector_leaf(dst, src, scalar_dst, count);
}

static void bump(unsigned *calls) { ++*calls; }

int main(void) {
    unsigned calls = 0;
    for (size_t count = 0; count <= 64; ++count) {
        float src[66], dst[66], scalar_dst[6];
        for (size_t i = 0; i < 66; ++i) {
            src[i] = (float)i/4;
            dst[i] = -17.0f;
        }
        for (size_t i = 0; i < 6; ++i) scalar_dst[i] = -19.0f;
        size_t vl = __riscv_vsetvl_e32m1(count);
        gated_control(bump, &calls, dst+1, src+1, scalar_dst+1, count);
        if (calls != count+1) return 20;
        for (size_t i = 0; i < 66; ++i)
            if (dst[i] != (i >= 1 && i <= vl ? src[i]+0.5f : -17.0f)) return 21;
        if (scalar_dst[0] != -19.0f || scalar_dst[5] != -19.0f) return 22;
        for (size_t i = 1; i <= 4; ++i)
            if (scalar_dst[i] != src[i]+2.0f) return 23;
    }
    printf("{\"passed\":true,\"cases\":65,\"callbacks\":%u,\"cpu\":%d,\"vlenb\":%zu}\n",
           calls, sched_getcpu(), __riscv_vlenb());
    return 0;
}
