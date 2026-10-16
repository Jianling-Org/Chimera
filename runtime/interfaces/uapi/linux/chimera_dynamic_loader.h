#ifndef CHIMERA_LINUX_DYNAMIC_LOADER_H
#define CHIMERA_LINUX_DYNAMIC_LOADER_H

#include <stdint.h>

void *chimera_linux_open_workspace_library(const char *workspace,
                                           const char *relative_name);
void *chimera_linux_lookup_symbol(void *handle, const char *symbol);
int chimera_linux_module_range(const char *runtime_name, int is_main,
                               uint64_t *base, uint64_t *end);

#endif /* CHIMERA_LINUX_DYNAMIC_LOADER_H */
