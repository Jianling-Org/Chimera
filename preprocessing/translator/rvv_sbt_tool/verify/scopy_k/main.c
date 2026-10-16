#include <stdio.h>
#include <stdint.h>

#define N 100
#define STRIDE 2

extern int scopy_k(long n, float *x, long inc_x, float *y, long inc_y);

int main() {
    float x[N * STRIDE];
    float y[N * STRIDE];

    for (int i = 0; i < N * STRIDE; i++) {
        x[i] = (float)(i + 1);
        y[i] = -1.0f;
    }

    int rc = scopy_k(N, x, STRIDE, y, STRIDE);
    if (rc != 0) {
        printf("SCOPY verification FAILED: return code = %d\n", rc);
        return 1;
    }

    for (int i = 0; i < N; i++) {
        int logical_idx = i * STRIDE;
        if (y[logical_idx] != x[logical_idx]) {
            printf("Mismatch at logical index %d (array index %d):\n", i, logical_idx);
            printf("Expected = %.2f, Got = %.2f\n", x[logical_idx], y[logical_idx]);
            return 1;
        }
    }

    for (int i = 0; i < N; i++) {
        int untouched_idx = i * STRIDE + 1;
        if (untouched_idx < N * STRIDE && y[untouched_idx] != -1.0f) {
            printf("Memory corruption at untouched index %d: Got = %.2f\n", untouched_idx, y[untouched_idx]);
            return 1;
        }
    }

    printf("SCOPY verification PASSED.\n");
    return 0;
}
