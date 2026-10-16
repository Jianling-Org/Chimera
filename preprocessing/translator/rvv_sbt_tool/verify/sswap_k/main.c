#include <stdio.h>
#include <stdint.h>

#define N 100
#define STRIDE 2

extern int sswap_k(long n, long dummy0, long dummy1, float dummy3,
                   float *x, long inc_x, float *y, long inc_y,
                   float *dummy, long dummy2);

int main() {
    float x[N * STRIDE];
    float y[N * STRIDE];

    for (int i = 0; i < N * STRIDE; i++) {
        x[i] = (float)(i + 1);
        y[i] = (float)(1000 + i);
    }

    int rc = sswap_k(N, 0, 0, 0.0f, x, STRIDE, y, STRIDE, NULL, 0);
    if (rc != 0) {
        printf("SSWAP verification FAILED: return code = %d\n", rc);
        return 1;
    }

    for (int i = 0; i < N; i++) {
        int logical_idx = i * STRIDE;
        float expected_x = (float)(1000 + logical_idx);
        float expected_y = (float)(logical_idx + 1);
        if (x[logical_idx] != expected_x || y[logical_idx] != expected_y) {
            printf("Mismatch at logical index %d (array index %d):\n", i, logical_idx);
            printf("Expected x = %.2f, Got x = %.2f\n", expected_x, x[logical_idx]);
            printf("Expected y = %.2f, Got y = %.2f\n", expected_y, y[logical_idx]);
            return 1;
        }
    }

    for (int i = 0; i < N; i++) {
        int untouched_idx = i * STRIDE + 1;
        if (untouched_idx < N * STRIDE) {
            float expected_x = (float)(untouched_idx + 1);
            float expected_y = (float)(1000 + untouched_idx);
            if (x[untouched_idx] != expected_x || y[untouched_idx] != expected_y) {
                printf("Memory corruption at untouched index %d\n", untouched_idx);
                return 1;
            }
        }
    }

    printf("SSWAP verification PASSED.\n");
    return 0;
}
