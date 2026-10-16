#include <stdio.h>
#include <stdint.h>
#include <string.h>

#define N 64
#define STRIDE 2
#define COMPLEX_WIDTH 2

/*
 * OpenBLAS `ccopy_k` 的内部 kernel 接口。
 *
 * 对 complex single 而言：
 * - `x` / `y` 都是“实部、虚部交错”的 float 标量数组；
 * - `inc_x` / `inc_y` 按“复数元素”计数，
 *   而不是按底层 float 标量个数计数。
 */
extern int ccopy_k(long n, float *x, long inc_x, float *y, long inc_y);


int main(void) {
    /*
     * 这里仍然使用 stride=2：
     * - 每个逻辑 complex 元素之间故意留下一个 complex 空洞；
     * - 这样可以同时验证 complex copy 主语义和 stride 路径的内存安全性。
     */
    enum { GUARD = 16, LENGTH = N * STRIDE * COMPLEX_WIDTH };
    float x_storage[LENGTH + 2 * GUARD], y_storage[LENGTH + 2 * GUARD];
    float initial_x[LENGTH];
    float *x = x_storage + GUARD, *y = y_storage + GUARD;
    for (int i = 0; i < LENGTH + 2 * GUARD; ++i)
        x_storage[i] = y_storage[i] = 12345.0f;

    const float untouched_sentinel = 555.0f;

    /*
     * 先将整片区域写成容易识别的值，
     * 再仅初始化逻辑上真正会参与 copy 的 complex 槽位。
     */
    for (int i = 0; i < N * STRIDE * COMPLEX_WIDTH; i++) {
        x[i] = -222.0f;
        y[i] = untouched_sentinel;
    }

    for (int i = 0; i < N; i++) {
        int base = i * STRIDE * COMPLEX_WIDTH;
        x[base] = (float)(i + 1);
        x[base + 1] = (float)(100 - i);
        y[base] = -10.0f;
        y[base + 1] = -20.0f;
    }

    memcpy(initial_x, x, sizeof(initial_x));
    int rc = ccopy_k(N, x, STRIDE, y, STRIDE);
    for (int i = 0; i < GUARD; ++i) {
        if (x_storage[i] != 12345.0f || y_storage[i] != 12345.0f ||
            x_storage[GUARD + LENGTH + i] != 12345.0f ||
            y_storage[GUARD + LENGTH + i] != 12345.0f) {
            puts("CCOPY verification FAILED: boundary canary changed");
            return 1;
        }
    }
    if (memcmp(initial_x, x, sizeof(initial_x))) {
        puts("CCOPY verification FAILED: input changed");
        return 1;
    }
    if (rc != 0) {
        printf("CCOPY verification FAILED: return code = %d\n", rc);
        return 1;
    }

    /*
     * 逐个检查每个逻辑 complex 元素的实部 / 虚部是否都被原样复制。
     */
    for (int i = 0; i < N; i++) {
        int base = i * STRIDE * COMPLEX_WIDTH;
        if (y[base] != x[base] || y[base + 1] != x[base + 1]) {
            printf("Mismatch at logical complex index %d:\n", i);
            printf(
                "Expected = (%.2f, %.2f), Got = (%.2f, %.2f)\n",
                x[base],
                x[base + 1],
                y[base],
                y[base + 1]
            );
            return 1;
        }
    }

    /*
     * 再检查 stride 额外留下的 complex 空洞是否未被写坏。
     */
    for (int i = 0; i < N; i++) {
        int base = i * STRIDE * COMPLEX_WIDTH;
        for (int gap = COMPLEX_WIDTH; gap < STRIDE * COMPLEX_WIDTH; gap++) {
            int raw_index = base + gap;
            if (y[raw_index] != untouched_sentinel) {
                printf(
                    "Memory corruption at untouched raw index %d: Got = %.2f\n",
                    raw_index,
                    y[raw_index]
                );
                return 1;
            }
        }
    }

    printf("CCOPY verification PASSED.\n");
    return 0;
}
