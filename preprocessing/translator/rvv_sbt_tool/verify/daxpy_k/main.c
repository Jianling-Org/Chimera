#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#define N 100
#define STRIDE 2

extern void daxpy_k(long n, long dummy1, long dummy2, double alpha, double *x, long inc_x, double *y, long inc_y);

int main() {
    double x[N * STRIDE];
    double y[N * STRIDE];
    double alpha = 2.5;

    for (int i = 0; i < N * STRIDE; i++) {
        x[i] = i;
        y[i] = 10.0;
    }

    daxpy_k(N, 0, 0, alpha, x, STRIDE, y, STRIDE);

    int pass = 1;
    for (int i = 0; i < N; i++) {
        double expected = alpha * x[i * STRIDE] + 10.0;
        double actual = y[i * STRIDE];

        if (actual != expected) {
            printf("Mismatch at logical index %d (array index %d):\n", i, i * STRIDE);
            printf("Expected = %.2f, Got = %.2f\n", expected, actual);
            pass = 0;
            break;
        }
    }

    for (int i = 0; i < N; i++) {
        int odd_idx = i * STRIDE + 1;
        if (odd_idx < N * STRIDE && y[odd_idx] != 10.0) {
            printf("Memory corruption at untouched index %d: Got = %.2f\n", odd_idx, y[odd_idx]);
            pass = 0;
            break;
        }
    }

    if (pass) {
        printf("DAXPY verification PASSED.\n");
        return 0;
    }

    printf("DAXPY verification FAILED.\n");
    return 1;
}
