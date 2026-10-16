#include "kernel.h"

/* A small GEMV-like stand-in, NOT the llama q3_K quantized operator.
 * On K3, check the disassembly for RVV instructions after compiling. */
__attribute__((noinline))
void probe_kernel(const float *restrict a, const float *restrict x,
                  float *restrict y, size_t first, size_t end, size_t cols) {
    for (size_t row = first; row < end; ++row) {
        float sum = 0.0f;
        for (size_t k = 0; k < cols; ++k)
            sum += a[row * cols + k] * x[k];
        y[row] = sum;
    }
}
