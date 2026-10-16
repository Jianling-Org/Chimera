#include <stdio.h>
#include <stdint.h>

#define N 100
#define STRIDE 2

/*
 * OpenBLAS `dcopy_k` 的内部 kernel 接口。
 *
 * 这个 kernel 的语义很直接：
 * - 从 `x` 读取 `n` 个逻辑 double 元素；
 * - 按 `inc_x` / `inc_y` 指定的逻辑 stride，
 *   将它们复制到 `y`；
 * - 返回值为 0 表示执行成功。
 */
extern int dcopy_k(long n, double *x, long inc_x, double *y, long inc_y);


int main(void) {
    /*
     * 这里沿用和 `scopy_k` 一样的验证策略：
     * - 使用 stride=2 迫使 kernel 走带步长路径；
     * - 逻辑元素之间留出一个未触碰槽位，
     *   既能验证复制结果，也能验证没有写坏相邻内存。
     */
    double x[N * STRIDE];
    double y[N * STRIDE];

    for (int i = 0; i < N * STRIDE; i++) {
        x[i] = (double)(i + 1) * 1.25;
        y[i] = -1.0;
    }

    int rc = dcopy_k(N, x, STRIDE, y, STRIDE);
    if (rc != 0) {
        printf("DCOPY verification FAILED: return code = %d\n", rc);
        return 1;
    }

    /*
     * 检查所有逻辑元素是否被正确复制。
     */
    for (int i = 0; i < N; i++) {
        int logical_idx = i * STRIDE;
        if (y[logical_idx] != x[logical_idx]) {
            printf("Mismatch at logical index %d (array index %d):\n", i, logical_idx);
            printf("Expected = %.2f, Got = %.2f\n", x[logical_idx], y[logical_idx]);
            return 1;
        }
    }

    /*
     * 检查 stride 留下的空洞位置是否仍保持初始哨兵值。
     */
    for (int i = 0; i < N; i++) {
        int untouched_idx = i * STRIDE + 1;
        if (untouched_idx < N * STRIDE && y[untouched_idx] != -1.0) {
            printf(
                "Memory corruption at untouched index %d: Got = %.2f\n",
                untouched_idx,
                y[untouched_idx]
            );
            return 1;
        }
    }

    printf("DCOPY verification PASSED.\n");
    return 0;
}
