#include "capability_registry.h"

#include <ctype.h>
#include <stdio.h>
#include <string.h>

#include "chimera_dynamic_loader.h"
#include "integrity.h"

static int symbol_prefix(char *output, size_t capacity, const char *owner) {
    size_t source, target = 0;
    int written = snprintf(output, capacity, "chimera_");
    if (written < 0 || (size_t)written >= capacity) return 0;
    target = (size_t)written;
    for (source = 0; owner[source]; ++source) {
        if (target + 1 >= capacity) return 0;
        output[target++] = isalnum((unsigned char)owner[source])
            ? owner[source] : '_';
    }
    output[target] = '\0';
    return 1;
}

static void *lookup(void *handle, const char *prefix, const char *suffix) {
    char symbol[768];
    int written = snprintf(symbol, sizeof(symbol), "%s_%s", prefix, suffix);
    if (written < 0 || (size_t)written >= sizeof(symbol)) return NULL;
    return chimera_linux_lookup_symbol(handle, symbol);
}

static int load_safety(const struct chimera_capability_context *context) {
    const uint64_t *abi, *count;
    const struct chimera_safety_entry *entries;
    char prefix[512];
    void *handle;
    if (!context->module || !context->module_record
        || !symbol_prefix(prefix, sizeof(prefix),
                          context->module_record->module_id)) return 0;
    handle = chimera_linux_open_workspace_library(
        context->workspace, context->artifact->path);
    if (!handle) return 0;
    abi = lookup(handle, prefix, "safety_abi");
    count = lookup(handle, prefix, "safety_count");
    entries = lookup(handle, prefix, "safety_entries");
    if (!abi || *abi != CHIMERA_SAFETY_ABI_V1 || !count || !entries
        || *count > (uint64_t)SIZE_MAX) return 0;
    context->module->safety = entries;
    context->module->safety_count = (size_t)*count;
    return 1;
}

static int load_translated_code(
    const struct chimera_capability_context *context) {
    const uint64_t *translated_abi;
    uint64_t translated_base, translated_end;
    uint64_t *base_slot;
    char prefix[512], base_symbol[768], fingerprint[CHIMERA_SHA256_TEXT_SIZE];
    char fingerprint_symbol[1024];
    void *translated;
    int written;
    if (!context->module || !context->variant || !context->variant_record
        || !symbol_prefix(prefix, sizeof(prefix),
                          context->variant_record->variant_id)
        || !chimera_variant_fingerprint(context->manifest,
                                        context->variant_record,
                                        fingerprint)) return 0;
    translated = chimera_linux_open_workspace_library(
        context->workspace, context->artifact->path);
    if (!translated) return 0;
    translated_abi = lookup(translated, prefix, "translated_code_abi_v1");
    written = snprintf(fingerprint_symbol, sizeof(fingerprint_symbol),
                       "%s_translation_fingerprint_%s", prefix, fingerprint);
    if (!translated_abi || *translated_abi != UINT64_C(1)
        || written < 0 || (size_t)written >= sizeof(fingerprint_symbol)
        || !chimera_linux_lookup_symbol(translated, fingerprint_symbol)
        || !chimera_linux_module_range(context->artifact->path, 0,
                                       &translated_base, &translated_end)) return 0;
    written = snprintf(base_symbol, sizeof(base_symbol),
                       "%s_original_base_addr",
                       context->variant_record->variant_id);
    if (written < 0 || (size_t)written >= sizeof(base_symbol)) return 0;
    base_slot = chimera_linux_lookup_symbol(translated, base_symbol);
    if (!base_slot) return 0;
    *base_slot = context->module->original_base;
    context->variant->translated_base = translated_base;
    context->variant->translated_end = translated_end;
    /* Optional v1 extension. Older DSOs keep their fail-closed guard traps. */
    const uint64_t *jump_abi = lookup(translated, prefix, "no_link_abi");
    const uint64_t *jump_count = lookup(translated, prefix, "no_link_count");
    const struct chimera_no_link_entry *jumps =
        lookup(translated, prefix, "no_link_entries");
    if (jump_abi || jump_count || jumps) {
        if (!jump_abi || !jump_count || !jumps || *jump_abi != UINT64_C(1)
            || *jump_count > SIZE_MAX / sizeof(*jumps)
            || (uint64_t)(uintptr_t)jumps < translated_base
            || (uint64_t)(uintptr_t)jumps > translated_end
            || *jump_count > (translated_end - (uint64_t)(uintptr_t)jumps)
                              / sizeof(*jumps)) return 0;
        context->variant->no_link = jumps;
        context->variant->no_link_count = (size_t)*jump_count;
    }
    return 1;
}

static int load_offset_map(const struct chimera_capability_context *context) {
    const uint64_t *abi, *forward_count, *reverse_count;
    const struct chimera_offset_entry *forward;
    const struct chimera_reverse_entry *reverse;
    char prefix[512];
    void *map;
    if (!context->variant || !context->variant_record
        || !symbol_prefix(prefix, sizeof(prefix),
                          context->variant_record->variant_id)) return 0;
    map = chimera_linux_open_workspace_library(
        context->workspace, context->artifact->path);
    if (!map) return 0;
    abi = lookup(map, prefix, "offset_map_abi");
    forward_count = lookup(map, prefix, "forward_count");
    reverse_count = lookup(map, prefix, "reverse_count");
    forward = lookup(map, prefix, "forward_entries");
    reverse = lookup(map, prefix, "reverse_entries");
    if (!abi || *abi != CHIMERA_OFFSET_MAP_ABI_V1
        || !forward_count || !reverse_count || !forward || !reverse
        || *forward_count > (uint64_t)SIZE_MAX
        || *reverse_count > (uint64_t)SIZE_MAX) return 0;
    context->variant->forward = forward;
    context->variant->forward_count = (size_t)*forward_count;
    context->variant->reverse = reverse;
    context->variant->reverse_count = (size_t)*reverse_count;
    return 1;
}

static const struct chimera_capability_registration registrations[] = {
    {CHIMERA_OWNER_VARIANT, "translated-code", "elf", UINT64_C(1),
     1u, 1u, load_translated_code},
    {CHIMERA_OWNER_VARIANT, "offset-map", "elf", UINT64_C(1),
     1u, 1u, load_offset_map},
    {CHIMERA_OWNER_MODULE, "safety", "elf", UINT64_C(1),
     0u, 1u, load_safety},
};

static const struct chimera_capability_registration supported[] = {
    {CHIMERA_OWNER_WORKSPACE, "runtime", "elf", CHIMERA_RUNTIME_ABI_V1,
     1u, 1u, NULL},
};

const struct chimera_capability_registration *
chimera_scene_capability_registrations(size_t *count) {
    if (count) *count = sizeof(registrations) / sizeof(registrations[0]);
    return registrations;
}

const struct chimera_capability_registration *
chimera_scene_supported_capabilities(size_t *count) {
    if (count) *count = sizeof(supported) / sizeof(supported[0]);
    return supported;
}
