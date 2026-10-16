#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#define N 100
#define STRIDE 2

/* Internal kernel ABI: a1/a2 are padding; x/stride/y/stride use a3..a6. */
extern void saxpy_k(long n, long dummy1, long dummy2, float alpha, float *x, long inc_x, float *y, long inc_y);

int main() {
    float x[N * STRIDE];
    float y[N * STRIDE];
    float alpha = 2.5f;

    for (int i = 0; i < N * STRIDE; i++) {
        x[i] = (float)i;
        y[i] = 10.0f;
    }

    saxpy_k(N, 0, 0, alpha, x, STRIDE, y, STRIDE);

    int pass = 1;
    for (int i = 0; i < N; i++) {
        float expected = alpha * x[i * STRIDE] + 10.0f;
        float actual = y[i * STRIDE];

        if (actual != expected) {
            printf("Mismatch at logical index %d (array index %d):\n", i, i * STRIDE);
            printf("Expected = %.2f, Got = %.2f\n", expected, actual);
            pass = 0;
            break;
        }
    }

    for (int i = 0; i < N; i++) {
        int odd_idx = i * STRIDE + 1;
        if (odd_idx < N * STRIDE && y[odd_idx] != 10.0f) {
            printf("Memory corruption at untouched index %d: Got = %.2f\n", odd_idx, y[odd_idx]);
            pass = 0;
            break;
        }
    }

    if (pass) {
        printf("SAXPY verification PASSED.\n");
        return 0;
    }

    printf("SAXPY verification FAILED.\n");
    return 1;
}
