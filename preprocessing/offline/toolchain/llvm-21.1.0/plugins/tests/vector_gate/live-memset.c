#define _GNU_SOURCE
#include <riscv_vector.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

__attribute__((noinline))
void gated_live_memset(float *dst, const float *src, void *zeros,
                      size_t count, size_t bytes) {
    size_t vl = __riscv_vsetvl_e32m1(count);
    vfloat32m1_t value = __riscv_vle32_v_f32m1(src, vl);
    __builtin_memset(zeros, 0, bytes);
    __riscv_vse32_v_f32m1(dst, value, vl);
}

int main(void) {
    static const size_t sizes[] = {0, 1, 2, 7, 16, 31, 63, 255, 1025};
    size_t cases = 0;
    for (size_t count = 1; count <= 64; count *= 2) {
        for (size_t k = 0; k < sizeof(sizes)/sizeof(sizes[0]); ++k) {
            float src[66], dst[66];
            unsigned char zeros[1027];
            for (size_t i = 0; i < 66; ++i) {
                src[i] = (float)i/4;
                dst[i] = -17.0f;
            }
            memset(zeros, 0xcc, sizeof(zeros));
            zeros[0] = 0xa5;
            zeros[sizes[k]+1] = 0x5a;
            size_t vl = __riscv_vsetvl_e32m1(count);
            gated_live_memset(dst+1, src+1, zeros+1, count, sizes[k]);
            for (size_t i = 0; i < 66; ++i)
                if (dst[i] != (i >= 1 && i <= vl ? src[i] : -17.0f))
                    return 10;
            if (zeros[0] != 0xa5 || zeros[sizes[k]+1] != 0x5a)
                return 11;
            for (size_t i = 1; i <= sizes[k]; ++i)
                if (zeros[i] != 0)
                    return 12;
            for (size_t i = sizes[k]+2; i < sizeof(zeros); ++i)
                if (zeros[i] != 0xcc)
                    return 13;
            ++cases;
        }
    }
    printf("{\"passed\":true,\"cases\":%zu,\"cpu\":%d,\"vlenb\":%zu}\n",
           cases, sched_getcpu(), __riscv_vlenb());
    return 0;
}
