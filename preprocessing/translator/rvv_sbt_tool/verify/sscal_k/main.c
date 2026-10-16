#include <stdio.h>
#include <stdint.h>

#define N 100
#define STRIDE 2

/* OpenBLAS v0.3.28 kernel/riscv64/scal_rvv.c internal ABI:
 * x/stride occupy a3/a4; dummy2 is the first stack argument. */
extern int sscal_k(long n, long dummy0, long dummy1, float alpha,
                   float *x, long inc_x, float *y, long inc_y,
                   float *dummy, long dummy2);

int main() {
    float x[N * STRIDE];
    float alpha = 2.5f;

    for (int i = 0; i < N * STRIDE; i++) {
        x[i] = (float)(i + 1);
    }

    int rc = sscal_k(N, 0, 0, alpha, x, STRIDE, NULL, 0, NULL, 0);
    if (rc != 0) {
        printf("SSCAL verification FAILED: return code = %d\n", rc);
        return 1;
    }

    for (int i = 0; i < N; i++) {
        int logical_idx = i * STRIDE;
        float expected = alpha * (float)(logical_idx + 1);
        if (x[logical_idx] != expected) {
            printf("Mismatch at logical index %d (array index %d):\n", i, logical_idx);
            printf("Expected = %.2f, Got = %.2f\n", expected, x[logical_idx]);
            return 1;
        }
    }

    for (int i = 0; i < N; i++) {
        int untouched_idx = i * STRIDE + 1;
        if (untouched_idx < N * STRIDE) {
            float expected = (float)(untouched_idx + 1);
            if (x[untouched_idx] != expected) {
                printf("Memory corruption at untouched index %d: Got = %.2f\n", untouched_idx, x[untouched_idx]);
                return 1;
            }
        }
    }

    printf("SSCAL verification PASSED.\n");
    return 0;
}
