#define _GNU_SOURCE
#include <link.h>
#include <string.h>
#include "integrity.h"
#include "manifest_v1.h"

struct image_query { const struct chimera_manifest_module *module; int found; int valid; const char *workspace; };
static int check_image(struct dl_phdr_info *info, size_t size, void *data) {
    struct image_query *query = data;
    int main = !strcmp(query->module->role, "main");
    const char *name = info->dlpi_name;
    int is_main = !name || !*name;
    (void)size;
    if (main != is_main) return 0;
    if (!main) {
        const char *slash = strrchr(name, '/');
        if (strcmp(slash ? slash + 1 : name, query->module->runtime_name)) return 0;
    }
    struct chimera_manifest_artifact artifact = {0};
    const char *path = main ? "/proc/self/exe" : name;
    query->found++;
    if (strlen(path) >= sizeof(artifact.path)) { query->valid = 0; return 0; }
    strcpy(artifact.path, path);
    strcpy(artifact.sha256, query->module->sha256);
    if (!chimera_artifact_matches(query->workspace, &artifact)) query->valid = 0;
    return 0;
}

int chimera_bootstrap_validate_images(const char *workspace) {
    struct chimera_manifest manifest;
    if (!chimera_manifest_v1_read(workspace, &manifest)) return 0;
    int valid = manifest.module_count != 0;
    for (size_t i = 0; i < manifest.module_count; ++i) {
        struct image_query query = { &manifest.modules[i], 0, 1, workspace };
        dl_iterate_phdr(check_image, &query);
        if (query.found != 1 || !query.valid) { valid = 0; break; }
    }
    chimera_manifest_v1_destroy(&manifest);
    return valid;
}
