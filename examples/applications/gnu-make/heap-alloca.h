/* Use GNU make's bundled automatically reclaimed heap alloca implementation.
 * Include the platform header first so later includes cannot restore the builtin.
 * Build with CHIMERA_MAKE_HEAP_ALLOCA and STACK_DIRECTION=-1 on RISC-V.
 */
#ifndef CHIMERA_MAKE_HEAP_ALLOCA_HEADER
#define CHIMERA_MAKE_HEAP_ALLOCA_HEADER
#include <stddef.h>
#include <alloca.h>
#undef alloca
void *chimera_make_heap_alloca(size_t);
#define alloca chimera_make_heap_alloca
#endif
