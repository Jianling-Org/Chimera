#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#define N 100

extern void vadd_rvv(int32_t *a, int32_t *b, int32_t *c, size_t n);

int main() {
    int32_t a[N], b[N], c[N];

    for (int i = 0; i < N; i++) {
        a[i] = 3 * i + 1;
        b[i] = i * i - 2 * i + 7;
        c[i] = 0;
    }

    vadd_rvv(a, b, c, N);

    int pass = 1;
    for (int i = 0; i < N; i++) {
        int32_t expected = i * i + i + 8;
        if (c[i] != expected) {
            printf("Error at index %d: Expected %d, Got %d\n", i, expected, c[i]);
            pass = 0;
            break;
        }
    }

    if (pass) {
        printf("VADD verification PASSED.\n");
        return 0;
    }

    printf("VADD verification FAILED.\n");
    return 1;
}
