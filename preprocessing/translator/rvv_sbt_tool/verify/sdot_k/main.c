#include <stdio.h>
#include <stdint.h>

#define N 64
#define STRIDE 2
#define EPSILON 1e-4f

/*
 * sdot_k 的 OpenBLAS 内核签名：
 *   float sdot_k(long n, float *x, long inc_x, float *y, long inc_y);
 *
 * 这里使用一个带 stride 的小型 case 做语义验证，重点检查：
 * 1. 逻辑元素是否按 inc_x / inc_y 正确访问；
 * 2. widening 累加路径（vfwmacc.vv + vfredusum.vs + vfmv.f.s）是否给出正确结果。
 */
extern float sdot_k(long n, float *x, long inc_x, float *y, long inc_y);

int main() {
    float x[N * STRIDE];
    float y[N * STRIDE];

    /*
     * 使用可重复、幅度适中的输入，避免结果过大，也避免完全依赖 bit-exact 比较。
     * 奇数槽位故意写入无关值，用来确认 stride 路径不会错误读到“未触及”的位置。
     */
    for (int i = 0; i < N * STRIDE; i++) {
        x[i] = -99.0f;
        y[i] = -77.0f;
    }

    for (int i = 0; i < N; i++) {
        int logical_idx = i * STRIDE;
        x[logical_idx] = (float)(i + 1) * 0.5f;
        y[logical_idx] = (float)((i % 7) + 1) * 0.25f;
    }

    /*
     * 参考值按“先用 double 累加，最后截回 float”的方式计算，
     * 对齐 OpenBLAS `sdot_k` 当前 RVV 路径的 widening 语义。
     */
    double expected_double = 0.0;
    for (int i = 0; i < N; i++) {
        int logical_idx = i * STRIDE;
        expected_double += (double)x[logical_idx] * (double)y[logical_idx];
    }
    float expected = (float)expected_double;

    float result = sdot_k(N, x, STRIDE, y, STRIDE);

    float diff = result - expected;
    if (diff < 0.0f) {
        diff = -diff;
    }

    if (diff > EPSILON) {
        printf("SDOT verification FAILED:\n");
        printf("Expected = %.6f, Got = %.6f, Diff = %.6f\n", expected, result, diff);
        return 1;
    }

    printf("SDOT verification PASSED.\n");
    return 0;
}
