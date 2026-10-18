#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#define N 64
#define STRIDE 2
#define COMPLEX_WIDTH 2

/*
 * OpenBLAS `caxpy_k` 的内部 kernel 接口。
 *
 * 对 complex single 而言：
 * - `alpha` 以 `(da_r, da_i)` 两个标量参数传入；
 * - `x` / `y` 都是“实部、虚部交错”的标量数组；
 * - `inc_x` / `inc_y` 按“复数元素”计数，而不是按标量 float 计数。
 */
extern int caxpy_k(
    long n,
    long dummy0,
    long dummy1,
    float da_r,
    float da_i,
    float *x,
    long inc_x,
    float *y,
    long inc_y,
    float *dummy,
    long dummy2
);


int main(void) {
    /*
     * 这里故意使用 stride=2：
     * - 每个逻辑 complex 元素之间会留下一个“未触碰的 complex 空洞”；
     * - 这样可以同时验证 kernel 的主计算语义和 stride 路径没有写坏旁边的数据。
     */
    float x[N * STRIDE * COMPLEX_WIDTH];
    float y[N * STRIDE * COMPLEX_WIDTH];

    const float alpha_r = 2.0f;
    const float alpha_i = 0.5f;
    const float untouched_sentinel = 777.0f;

    /*
     * 先将整片数组都填成哨兵值，
     * 再只初始化每个逻辑元素真正会访问到的实部 / 虚部位置。
     */
    for (int i = 0; i < N * STRIDE * COMPLEX_WIDTH; i++) {
        x[i] = -111.0f;
        y[i] = untouched_sentinel;
    }

    for (int i = 0; i < N; i++) {
        int base = i * STRIDE * COMPLEX_WIDTH;
        x[base] = (float)(i + 1);
        x[base + 1] = (float)(i + 2);
        y[base] = 10.0f;
        y[base + 1] = -3.0f;
    }

    caxpy_k(N, 0, 0, alpha_r, alpha_i, x, STRIDE, y, STRIDE, NULL, 0);

    int pass = 1;

    /*
     * complex AXPY 语义：
     * y = y + (alpha_r + i * alpha_i) * (x_r + i * x_i)
     *
     * 展开后：
     * - real = y_r + alpha_r * x_r - alpha_i * x_i
     * - imag = y_i + alpha_r * x_i + alpha_i * x_r
     */
    for (int i = 0; i < N; i++) {
        int base = i * STRIDE * COMPLEX_WIDTH;

        float x_r = x[base];
        float x_i = x[base + 1];
        float expected_r = 10.0f + alpha_r * x_r - alpha_i * x_i;
        float expected_i = -3.0f + alpha_r * x_i + alpha_i * x_r;

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

    /*
     * 再检查 stride 留下的空洞位置是否保持原样。
     * 对于 STRIDE=2，每个逻辑 complex 元素后面都还会有一对不该被写到的槽位。
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
                pass = 0;
                break;
            }
        }
        if (!pass) {
            break;
        }
    }

    if (pass) {
        printf("CAXPY verification PASSED.\n");
        return 0;
    }

    printf("CAXPY verification FAILED.\n");
    return 1;
}
