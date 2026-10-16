#include <stdio.h>
#include <stdint.h>

#define N 100
#define STRIDE 2

/*
 * dscal_k 的签名是双精度 SCAL：
 *   int dscal_k(long n, double alpha, double *x, long inc_x);
 *
 * 这里同时覆盖两类路径：
 * 1. alpha 非零时的 vfmul.vf 缩放路径；
 * 2. stride=2 时的跨步内存访问与未触及槽位保持不变。
 */
extern int dscal_k(long n, double alpha, double *x, long inc_x);

int main() {
    double x[N * STRIDE];
    double alpha = 2.5;

    /*
     * 初始化为易读的连续值，方便缩放后的参考值直接按公式推导。
     */
    for (int i = 0; i < N * STRIDE; i++) {
        x[i] = (double)(i + 1) * 0.75;
    }

    int rc = dscal_k(N, alpha, x, STRIDE);
    if (rc != 0) {
        printf("DSCAL verification FAILED: return code = %d\n", rc);
        return 1;
    }

    /*
     * 逻辑元素应该按 alpha 被精确缩放。
     */
    for (int i = 0; i < N; i++) {
        int logical_idx = i * STRIDE;
        double expected = alpha * ((double)(logical_idx + 1) * 0.75);
        if (x[logical_idx] != expected) {
            printf("Mismatch at logical index %d (array index %d):\n", i, logical_idx);
            printf("Expected = %.6f, Got = %.6f\n", expected, x[logical_idx]);
            return 1;
        }
    }

    /*
     * 间隔槽位不应被写到。
     */
    for (int i = 0; i < N; i++) {
        int untouched_idx = i * STRIDE + 1;
        if (untouched_idx < N * STRIDE) {
            double expected = (double)(untouched_idx + 1) * 0.75;
            if (x[untouched_idx] != expected) {
                printf("Memory corruption at untouched index %d: Got = %.6f\n", untouched_idx, x[untouched_idx]);
                return 1;
            }
        }
    }

    printf("DSCAL verification PASSED.\n");
    return 0;
}
