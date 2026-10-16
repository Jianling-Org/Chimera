#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#define N 64
#define STRIDE 2
#define COMPLEX_WIDTH 2

/*
 * OpenBLAS `zaxpy_k` 的内部 kernel 接口。
 *
 * 对 complex double 而言：
 * - `alpha` 以 `(da_r, da_i)` 两个双精度参数传入；
 * - `x` / `y` 都是“实部、虚部交错”的 double 数组；
 * - `inc_x` / `inc_y` 以“复数元素”为单位计数。
 */
extern int zaxpy_k(
    long n,
    long dummy0,
    long dummy1,
    double da_r,
    double da_i,
    double *x,
    long inc_x,
    double *y,
    long inc_y,
    double *dummy,
    long dummy2
);


int main(void) {
    double x[N * STRIDE * COMPLEX_WIDTH];
    double y[N * STRIDE * COMPLEX_WIDTH];

    const double alpha_r = 2.0;
    const double alpha_i = 0.5;
    const double untouched_sentinel = 777.0;

    /*
     * 仍然使用 stride=2，确保：
     * 1. 会走到 kernel 的 stride 路径；
     * 2. 可以检查未触碰槽位不会被误写。
     */
    for (int i = 0; i < N * STRIDE * COMPLEX_WIDTH; i++) {
        x[i] = -111.0;
        y[i] = untouched_sentinel;
    }

    for (int i = 0; i < N; i++) {
        int base = i * STRIDE * COMPLEX_WIDTH;
        x[base] = (double)(i + 1);
        x[base + 1] = (double)(i + 2);
        y[base] = 10.0;
        y[base + 1] = -3.0;
    }

    zaxpy_k(N, 0, 0, alpha_r, alpha_i, x, STRIDE, y, STRIDE, NULL, 0);

    int pass = 1;

    /*
     * complex double AXPY 的数学语义与 single 版本一致，只是元素宽度变成了 64-bit。
     */
    for (int i = 0; i < N; i++) {
        int base = i * STRIDE * COMPLEX_WIDTH;

        double x_r = x[base];
        double x_i = x[base + 1];
        double expected_r = 10.0 + alpha_r * x_r - alpha_i * x_i;
        double expected_i = -3.0 + alpha_r * x_i + alpha_i * x_r;

        if (y[base] != expected_r || y[base + 1] != expected_i) {
            printf("Mismatch at logical complex index %d:\n", i);
            printf(
                "Expected = (%.2f, %.2f), Got = (%.2f, %.2f)\n",
                expected_r,
                expected_i,
                y[base],
                y[base + 1]
            );
            pass = 0;
            break;
        }
    }

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
                pass = 0;
                break;
            }
        }
        if (!pass) {
            break;
        }
    }

    if (pass) {
        printf("ZAXPY verification PASSED.\n");
        return 0;
    }

    printf("ZAXPY verification FAILED.\n");
    return 1;
}
