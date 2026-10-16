#include "runtime_v1.h"

#include <string.h>

#include "capabilities.h"
#include "manifest_v1.h"

static struct chimera_registry loaded_registry;

struct scene_handler {
    const char *target_os;
    const char *target_arch;
    const char *extension;
    const char *scene;
    int (*load)(const char *, const struct chimera_manifest *, struct chimera_registry *);
};

static const struct scene_handler scene_handlers[] = {{
    "linux", "riscv64", "rvv", "linux_riscv64_rvv_v1",
    chimera_capabilities_load,
}};

int chimera_scene_load_workspace(const char *workspace) {
    struct chimera_manifest manifest;
    const struct scene_handler *handler = NULL;
    size_t index;
    if (!workspace || !chimera_manifest_v1_read(workspace, &manifest)) return 0;
    for (index = 0; index < sizeof(scene_handlers) / sizeof(scene_handlers[0]); ++index) {
        const struct scene_handler *candidate = &scene_handlers[index];
        if (!strcmp(manifest.target_os, candidate->target_os)
            && !strcmp(manifest.target_arch, candidate->target_arch)
            && !strcmp(manifest.target_arch_extension, candidate->extension)
            && !strcmp(manifest.runtime_scene, candidate->scene)) {
            handler = candidate; break;
        }
    }
    chimera_capabilities_destroy(&loaded_registry);
    if (!handler || !handler->load(workspace, &manifest, &loaded_registry)) {
        chimera_manifest_v1_destroy(&manifest);
        return 0;
    }
    chimera_manifest_v1_destroy(&manifest);
    return 1;
}

const struct chimera_registry *chimera_scene_registry(void) {
    return loaded_registry.modules ? &loaded_registry : NULL;
}
