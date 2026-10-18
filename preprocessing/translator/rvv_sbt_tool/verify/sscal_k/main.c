#include <stdio.h>
#include <stdint.h>

#define N 100
#define STRIDE 2

extern int sscal_k(long n, float alpha, float *x, long inc_x);

int main() {
    float x[N * STRIDE];
    float alpha = 2.5f;

    for (int i = 0; i < N * STRIDE; i++) {
        x[i] = (float)(i + 1);
    }

    int rc = sscal_k(N, alpha, x, STRIDE);
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
