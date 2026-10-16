#ifndef CHIMERA_MANIFEST_V1_H
#define CHIMERA_MANIFEST_V1_H

#include "module_manifest.h"

int chimera_manifest_v1_read(const char *workspace, struct chimera_manifest *manifest);
void chimera_manifest_v1_destroy(struct chimera_manifest *manifest);
const struct chimera_manifest_module *chimera_manifest_module_find(
    const struct chimera_manifest *manifest, const char *module_id);
const struct chimera_manifest_variant *chimera_manifest_variant_find(
    const struct chimera_manifest *manifest, const char *variant_id);
const struct chimera_manifest_variant_property *chimera_manifest_property_find(
    const struct chimera_manifest *manifest, const char *variant_id,
    const char *side, const char *name);
const struct chimera_manifest_artifact *chimera_manifest_artifact_find(
    const struct chimera_manifest *manifest, const char *owner_kind,
    const char *owner_id, const char *capability, const char *representation);
int chimera_manifest_artifact_requires(
    const struct chimera_manifest_artifact *artifact, const char *consumer);

#endif
