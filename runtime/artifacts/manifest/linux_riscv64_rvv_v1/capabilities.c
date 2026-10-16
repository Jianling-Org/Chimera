#include "capabilities.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "capability_registry.h"
#include "chimera_dynamic_loader.h"
#include "integrity.h"
#include "manifest_v1.h"
#include "module_registry.h"
#include "runtime_v1.h"

static size_t artifact_count(
    const struct chimera_manifest *manifest,
    const char *owner_kind,
    const char *owner_id,
    const char *capability,
    const char *representation) {
    size_t index, count = 0;
    for (index = 0; index < manifest->artifact_count; ++index) {
        const struct chimera_manifest_artifact *artifact =
            &manifest->artifacts[index];
        if (!strcmp(artifact->owner_kind, owner_kind)
            && !strcmp(artifact->owner_id, owner_id)
            && !strcmp(artifact->capability, capability)
            && !strcmp(artifact->representation, representation)) ++count;
    }
    return count;
}

static size_t module_variant_count(const struct chimera_manifest *manifest,
                                   const char *module_id) {
    size_t index, count = 0;
    for (index = 0; index < manifest->variant_count; ++index)
        if (!strcmp(manifest->variants[index].module_id, module_id)) ++count;
    return count;
}

static int canonical_endpoint_u64(const char *text, uint64_t *value) {
    uint64_t parsed = 0;
    const char *cursor;
    if (!text[0] || (text[0] == '0' && text[1])) return 0;
    for (cursor = text; *cursor; ++cursor) {
        uint64_t digit;
        if (*cursor < '0' || *cursor > '9') return 0;
        digit = (uint64_t)(*cursor - '0');
        if (parsed > (UINT64_MAX - digit) / UINT64_C(10)) return 0;
        parsed = parsed * UINT64_C(10) + digit;
    }
    *value = parsed;
    return 1;
}

static int supported_route(uint64_t source, uint64_t target) {
    return (source == UINT64_C(1024) && target == UINT64_C(256))
        || (source == UINT64_C(256) && target == UINT64_C(1024));
}

static int load_variant_properties(
    const struct chimera_manifest *manifest,
    const struct chimera_manifest_variant *descriptor,
    struct chimera_translation_variant *variant) {
    const struct chimera_manifest_variant_property *source_property;
    const struct chimera_manifest_variant_property *target_property;
    const struct chimera_manifest_variant_property *source_architecture;
    const struct chimera_manifest_variant_property *target_architecture;
    const struct chimera_manifest_variant_property *source_extension;
    const struct chimera_manifest_variant_property *target_extension;
    uint64_t source_vlen, target_vlen;
    source_property = chimera_manifest_property_find(
        manifest, descriptor->variant_id, "input", "vector_vlen_bits");
    target_property = chimera_manifest_property_find(
        manifest, descriptor->variant_id, "output", "vector_vlen_bits");
    source_architecture = chimera_manifest_property_find(
        manifest, descriptor->variant_id, "input", "architecture");
    target_architecture = chimera_manifest_property_find(
        manifest, descriptor->variant_id, "output", "architecture");
    source_extension = chimera_manifest_property_find(
        manifest, descriptor->variant_id, "input", "architecture_extension");
    target_extension = chimera_manifest_property_find(
        manifest, descriptor->variant_id, "output", "architecture_extension");
    if (!source_property || !target_property
        || !source_architecture || !target_architecture
        || !source_extension || !target_extension
        || strcmp(source_property->value_kind, "u64")
        || strcmp(target_property->value_kind, "u64")
        || strcmp(source_architecture->value_kind, "token")
        || strcmp(target_architecture->value_kind, "token")
        || strcmp(source_extension->value_kind, "token")
        || strcmp(target_extension->value_kind, "token")
        || strcmp(source_architecture->value, "riscv64")
        || strcmp(target_architecture->value, "riscv64")
        || strcmp(source_extension->value, "rvv")
        || strcmp(target_extension->value, "rvv")
        || !canonical_endpoint_u64(source_property->value, &source_vlen)
        || !canonical_endpoint_u64(target_property->value, &target_vlen)
        || !supported_route(source_vlen, target_vlen)) return 0;
    variant->route_id = chimera_rvv_route_id(source_vlen, target_vlen);
    if (source_vlen == UINT64_C(1024)) {
        variant->body = CHIMERA_CODE_TRANSLATED_1024_TO_256;
        variant->body_label = "1024-to-256";
    } else {
        variant->body = CHIMERA_CODE_TRANSLATED_256_TO_1024;
        variant->body_label = "256-to-1024";
    }
    return 1;
}

static int dispatch_owner(
    enum chimera_owner_kind owner,
    const char *owner_id,
    const struct chimera_capability_context *context) {
    const struct chimera_capability_registration *registrations, *supported;
    size_t registration_count, supported_count;
    registrations = chimera_scene_capability_registrations(&registration_count);
    supported = chimera_scene_supported_capabilities(&supported_count);
    return chimera_capability_dispatch(
        registrations, registration_count, supported, supported_count,
        owner, owner_id, context);
}

static int validate_artifact_contracts(
    const struct chimera_manifest *manifest) {
    const struct chimera_capability_registration *registrations, *supported;
    size_t registration_count, supported_count;
    registrations = chimera_scene_capability_registrations(&registration_count);
    supported = chimera_scene_supported_capabilities(&supported_count);
    return chimera_capability_validate_manifest(
        registrations, registration_count, supported, supported_count, manifest);
}

static int chimera_load_variant(
    const struct chimera_manifest *manifest,
    const struct chimera_manifest_variant *variant_record,
    struct chimera_translation_variant *variant,
    struct chimera_capability_context *context) {
    if (!load_variant_properties(manifest, variant_record, variant)) return 0;
    context->variant = variant;
    context->variant_record = variant_record;
    return dispatch_owner(CHIMERA_OWNER_VARIANT,
                          variant_record->variant_id, context);
}

static int chimera_load_module(
    const char *workspace,
    const struct chimera_manifest *manifest,
    struct chimera_registry *registry,
    const struct chimera_manifest_module *descriptor,
    struct chimera_module *module) {
    struct chimera_capability_context context;
    size_t count = module_variant_count(manifest, descriptor->module_id);
    size_t vi;
    int module_id_length = snprintf(
        module->module_id, sizeof(module->module_id), "%s", descriptor->module_id);
    int runtime_name_length = snprintf(
        module->runtime_name, sizeof(module->runtime_name), "%s",
        descriptor->runtime_name);
    if (!count || module_id_length < 0
        || (size_t)module_id_length >= sizeof(module->module_id)
        || runtime_name_length < 0
        || (size_t)runtime_name_length >= sizeof(module->runtime_name)
        || !chimera_linux_module_range(descriptor->runtime_name,
                                       !strcmp(descriptor->role, "main"),
                                       &module->original_base,
                                       &module->original_end)) return 0;
    memset(&context, 0, sizeof(context));
    context.workspace = workspace;
    context.manifest = manifest;
    context.registry = registry;
    context.module = module;
    context.module_record = descriptor;
    if (!dispatch_owner(CHIMERA_OWNER_MODULE, descriptor->module_id, &context))
        return 0;
    module->variants = calloc(count, sizeof(*module->variants));
    if (!module->variants) return 0;
    for (vi = 0; vi < manifest->variant_count; ++vi) {
        const struct chimera_manifest_variant *variant_record =
            &manifest->variants[vi];
        struct chimera_translation_variant *variant;
        if (strcmp(variant_record->module_id, descriptor->module_id)) continue;
        variant = &module->variants[module->variant_count];
        if (!chimera_load_variant(manifest, variant_record, variant, &context))
            return 0;
        ++module->variant_count;
    }
    return 1;
}

void chimera_capabilities_destroy(struct chimera_registry *registry) {
    size_t index;
    if (!registry) return;
    for (index = 0; registry->modules && index < registry->module_count; ++index)
        free(registry->modules[index].variants);
    free((void *)registry->modules);
    memset(registry, 0, sizeof(*registry));
}

int chimera_capabilities_load(const char *workspace,
                              const struct chimera_manifest *manifest,
                              struct chimera_registry *registry) {
    struct chimera_module *modules;
    size_t ai, mi;
    memset(registry, 0, sizeof(*registry));
    if (strcmp(manifest->target_os, "linux")
        || strcmp(manifest->target_arch, "riscv64")
        || strcmp(manifest->target_arch_extension, "rvv")
        || strcmp(manifest->runtime_scene, "linux_riscv64_rvv_v1")) return 0;
    for (ai = 0; ai < manifest->artifact_count; ++ai)
        if (!chimera_artifact_matches(workspace, &manifest->artifacts[ai])) return 0;
    if (!validate_artifact_contracts(manifest)) return 0;
    if (manifest->runtime_abi != CHIMERA_RUNTIME_ABI_V1) return 0;
    {
        const struct chimera_manifest_artifact *runtime_artifact =
            chimera_manifest_artifact_find(manifest, "workspace", "root",
                                           "runtime", "elf");
        if (!runtime_artifact
            || artifact_count(manifest, "workspace", "root", "runtime", "elf") != 1
            || runtime_artifact->abi != CHIMERA_RUNTIME_ABI_V1) return 0;
    }
    modules = calloc(manifest->module_count, sizeof(*modules));
    if (!modules) return 0;
    registry->modules = modules;
    registry->module_count = manifest->module_count;
    for (mi = 0; mi < manifest->module_count; ++mi) {
        const struct chimera_manifest_module *descriptor = &manifest->modules[mi];
        struct chimera_module *module = &modules[mi];
        if (!chimera_load_module(workspace, manifest, registry,
                                 descriptor, module)) goto fail;
    }
    if (!chimera_registry_validate(registry)) goto fail;
    return 1;
fail:
    chimera_capabilities_destroy(registry);
    return 0;
}
