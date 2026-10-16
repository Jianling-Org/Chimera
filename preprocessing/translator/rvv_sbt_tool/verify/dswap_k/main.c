#include <stdio.h>
#include <stdint.h>

#define N 100
#define STRIDE 2

/*
 * dswap_k 的 OpenBLAS 内核签名与 sswap_k 基本一致，只是元素类型变成 double。
 *
 * 这里继续使用 stride=2 的布局做验证，原因有两个：
 * 1. 它能直接覆盖 vlse64.v / vsse64.v 的跨步访问语义；
 * 2. 它还能顺手检查未触及槽位是否保持不变，避免“逻辑元素正确、物理布局被写坏”的假通过。
 */
extern int dswap_k(long n, long dummy0, long dummy1, double dummy3,
                   double *x, long inc_x, double *y, long inc_y,
                   double *dummy, long dummy2);

int main() {
    double x[N * STRIDE];
    double y[N * STRIDE];

    /*
     * 将逻辑槽位和未触及槽位初始化为容易分辨的数值模式，
     * 这样在出错时可以更快定位到底是 swap 逻辑错误，还是 stride/越界写问题。
     */
    for (int i = 0; i < N * STRIDE; i++) {
        x[i] = (double)(i + 1) * 1.25;
        y[i] = (double)(1000 + i) * 0.5;
    }

    int rc = dswap_k(N, 0, 0, 0.0, x, STRIDE, y, STRIDE, NULL, 0);
    if (rc != 0) {
        printf("DSWAP verification FAILED: return code = %d\n", rc);
        return 1;
    }

    /*
     * 逻辑元素必须完成交换。
     */
    for (int i = 0; i < N; i++) {
        int logical_idx = i * STRIDE;
        double expected_x = (double)(1000 + logical_idx) * 0.5;
        double expected_y = (double)(logical_idx + 1) * 1.25;
        if (x[logical_idx] != expected_x || y[logical_idx] != expected_y) {
            printf("Mismatch at logical index %d (array index %d):\n", i, logical_idx);
            printf("Expected x = %.6f, Got x = %.6f\n", expected_x, x[logical_idx]);
            printf("Expected y = %.6f, Got y = %.6f\n", expected_y, y[logical_idx]);
            return 1;
        }
    }

    /*
     * 未触及的间隔槽位必须保持原值，确保 stride 路径没有误写相邻元素。
     */
    for (int i = 0; i < N; i++) {
        int untouched_idx = i * STRIDE + 1;
        if (untouched_idx < N * STRIDE) {
            double expected_x = (double)(untouched_idx + 1) * 1.25;
            double expected_y = (double)(1000 + untouched_idx) * 0.5;
            if (x[untouched_idx] != expected_x || y[untouched_idx] != expected_y) {
                printf("Memory corruption at untouched index %d\n", untouched_idx);
                return 1;
            }
        }
    }

    printf("DSWAP verification PASSED.\n");
    return 0;
}
