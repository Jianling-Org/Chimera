#ifndef CHIMERA_CAPABILITY_REGISTRY_H
#define CHIMERA_CAPABILITY_REGISTRY_H

#include <stddef.h>
#include <stdint.h>

#include "chimera_runtime.h"
#include "module_manifest.h"

enum chimera_owner_kind {
    CHIMERA_OWNER_WORKSPACE,
    CHIMERA_OWNER_MODULE,
    CHIMERA_OWNER_VARIANT,
};

struct chimera_capability_context {
    const char *workspace;
    const struct chimera_manifest *manifest;
    struct chimera_registry *registry;
    struct chimera_module *module;
    struct chimera_translation_variant *variant;
    const struct chimera_manifest_module *module_record;
    const struct chimera_manifest_variant *variant_record;
    const struct chimera_manifest_artifact *artifact;
};

typedef int (*chimera_capability_loader)(
    const struct chimera_capability_context *context);

struct chimera_capability_registration {
    enum chimera_owner_kind owner;
    const char *capability;
    const char *representation;
    uint64_t abi;
    size_t minimum;
    /* Zero means no artifacts are allowed; use SIZE_MAX for no upper bound. */
    size_t maximum;
    /* Loader registrations require a callback; support-only entries use NULL. */
    chimera_capability_loader load;
};

int chimera_capability_validate_manifest(
    const struct chimera_capability_registration *registrations,
    size_t registration_count,
    const struct chimera_capability_registration *supported,
    size_t supported_count,
    const struct chimera_manifest *manifest);

int chimera_capability_dispatch(
    const struct chimera_capability_registration *registrations,
    size_t registration_count,
    const struct chimera_capability_registration *supported,
    size_t supported_count,
    enum chimera_owner_kind owner,
    const char *owner_id,
    const struct chimera_capability_context *context);

const struct chimera_capability_registration *
chimera_scene_capability_registrations(size_t *count);
const struct chimera_capability_registration *
chimera_scene_supported_capabilities(size_t *count);

#endif
