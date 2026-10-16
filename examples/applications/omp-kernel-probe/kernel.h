#ifndef OMP_KERNEL_PROBE_KERNEL_H
#define OMP_KERNEL_PROBE_KERNEL_H
#include <stddef.h>
/* Replace this implementation to measure your actual operator. Keep this TU
 * separate and disable LTO so repeated calls cannot be hoisted away. */
void probe_kernel(const float *a, const float *x, float *y,
                  size_t first, size_t end, size_t cols);
#endif
