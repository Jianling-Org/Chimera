#ifndef CHIMERA_RUNTIME_CAPABILITIES_H
#define CHIMERA_RUNTIME_CAPABILITIES_H

#include "chimera_runtime.h"
#include "module_manifest.h"

int chimera_capabilities_load(const char *workspace,
                              const struct chimera_manifest *manifest,
                              struct chimera_registry *registry);
void chimera_capabilities_destroy(struct chimera_registry *registry);

#endif
