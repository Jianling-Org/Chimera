#ifndef CHIMERA_ARTIFACT_INTEGRITY_H
#define CHIMERA_ARTIFACT_INTEGRITY_H

#include "module_manifest.h"

int chimera_artifact_matches(
    const char *workspace,
    const struct chimera_manifest_artifact *artifact);
int chimera_variant_fingerprint(
    const struct chimera_manifest *manifest,
    const struct chimera_manifest_variant *variant,
    char output[CHIMERA_SHA256_TEXT_SIZE]);

#endif
