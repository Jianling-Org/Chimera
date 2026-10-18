#include <stdio.h>
#include <stdint.h>

#define N 64
#define STRIDE 2
#define EPSILON 1e-9

/*
 * ddot_k 的 OpenBLAS 内核签名：
 *   double ddot_k(long n, double *x, long inc_x, double *y, long inc_y);
 *
 * 验证重点：
 * 1. 跨步读取是否正确；
 * 2. vfmacc.vv 的双精度累加路径是否正确；
 * 3. vfredusum.vs + vfmv.f.s 的归约结果是否正确返回到 fa0。
 */
extern double ddot_k(long n, double *x, long inc_x, double *y, long inc_y);

int main() {
    double x[N * STRIDE];
    double y[N * STRIDE];

    /*
     * 先把所有槽位填成哨兵值，再仅在逻辑位置写入有效输入，
     * 这样一旦 stride 访问错位，结果会非常明显。
     */
    for (int i = 0; i < N * STRIDE; i++) {
        x[i] = -999.0;
        y[i] = -777.0;
    }

    for (int i = 0; i < N; i++) {
        int logical_idx = i * STRIDE;
        x[logical_idx] = (double)(i + 1) * 0.5;
        y[logical_idx] = (double)((i % 11) + 1) * 0.125;
    }

    /*
     * 参考值直接按双精度逐项累加，与 ddot_k 当前目标语义保持一致。
     */
    double expected = 0.0;
    for (int i = 0; i < N; i++) {
        int logical_idx = i * STRIDE;
        expected += x[logical_idx] * y[logical_idx];
    }

    double result = ddot_k(N, x, STRIDE, y, STRIDE);
    double diff = result - expected;
    if (diff < 0.0) {
        diff = -diff;
    }

    if (diff > EPSILON) {
        printf("DDOT verification FAILED:\n");
        printf("Expected = %.12f, Got = %.12f, Diff = %.12f\n", expected, result, diff);
        return 1;
    }

    printf("DDOT verification PASSED.\n");
    return 0;
}
