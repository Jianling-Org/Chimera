#include "module_registry.h"

#include <stddef.h>
#include <stdlib.h>

static int contains(uint64_t base, uint64_t end, uint64_t address) { return base <= address && address < end; }

struct body_range {
    uint64_t base;
    uint64_t end;
};

static int append_body_range(struct body_range *ranges,
                             size_t *range_count,
                             uint64_t base,
                             uint64_t end) {
    size_t index;
    if (base >= end) return 0;
    for (index = 0; index < *range_count; ++index)
        if (base < ranges[index].end && ranges[index].base < end) return 0;
    ranges[*range_count].base = base;
    ranges[*range_count].end = end;
    ++*range_count;
    return 1;
}

static int forward_lookup(const struct chimera_offset_entry *entries, size_t count, uint64_t key, uint64_t *value) {
    size_t left = 0, right = count;
    while (left < right) { size_t middle = left + (right - left) / 2; if (entries[middle].original_rva < key) left = middle + 1; else right = middle; }
    if (left == count || entries[left].original_rva != key) return 0;
    *value = entries[left].translated_rva; return 1;
}

static int reverse_lookup(const struct chimera_reverse_entry *entries, size_t count, uint64_t key, uint64_t *value) {
    size_t left = 0, right = count;
    while (left < right) { size_t middle = left + (right - left) / 2; if (entries[middle].translated_rva < key) left = middle + 1; else right = middle; }
    if (left == count || entries[left].translated_rva != key) return 0;
    *value = entries[left].original_rva; return 1;
}

static int safety_lookup(const struct chimera_safety_entry *entries, size_t count, uint64_t key, const struct chimera_safety_entry **value) {
    size_t left = 0, right = count;
    while (left < right) { size_t middle = left + (right - left) / 2; if (entries[middle].original_rva < key) left = middle + 1; else right = middle; }
    if (left == count || entries[left].original_rva != key) return 0;
    *value = &entries[left]; return 1;
}

static int validate_variant(const struct chimera_translation_variant *variant,
                            uint64_t original_span) {
    size_t index;
    uint64_t translated_span;
    if (!variant || !variant->body
        || variant->translated_base >= variant->translated_end
        || variant->forward_count != variant->reverse_count
        || (!variant->forward && variant->forward_count)
        || (!variant->reverse && variant->reverse_count)
        || (!variant->no_link && variant->no_link_count)) return 0;
    translated_span = variant->translated_end - variant->translated_base;
    for (index = 0; index < variant->no_link_count; ++index) {
        const struct chimera_no_link_entry *site = &variant->no_link[index];
        if (site->trap_pc < variant->translated_base
            || site->trap_pc >= variant->translated_end
            || (site->trap_pc & UINT64_C(1))
            || !site->frame_bytes || site->frame_bytes > 4096U
            || (site->frame_bytes & 15U) || (site->target_slot & 7U)
            || site->target_slot > site->frame_bytes - 8U
            || site->original_rva >= original_span
            || (index && variant->no_link[index - 1].trap_pc >= site->trap_pc)) return 0;
    }
    for (index = 0; index < variant->forward_count; ++index) {
        if (variant->forward[index].original_rva >= original_span
            || variant->forward[index].translated_rva >= translated_span
            || (index && variant->forward[index - 1].original_rva
                >= variant->forward[index].original_rva)) return 0;
    }
    for (index = 0; index < variant->reverse_count; ++index) {
        if (variant->reverse[index].original_rva >= original_span
            || variant->reverse[index].translated_rva >= translated_span
            || (index && variant->reverse[index - 1].translated_rva
                >= variant->reverse[index].translated_rva)) return 0;
    }
    for (index = 0; index < variant->forward_count; ++index) {
        uint64_t original;
        if (!reverse_lookup(variant->reverse, variant->reverse_count, variant->forward[index].translated_rva, &original)
            || original != variant->forward[index].original_rva) return 0;
    }
    return 1;
}

int chimera_registry_validate(const struct chimera_registry *registry) {
    struct body_range *ranges = NULL;
    size_t mi, vi, capacity, range_count = 0;
    if (!registry || (!registry->modules && registry->module_count)) return 0;
    capacity = registry->module_count;
    for (mi = 0; mi < registry->module_count; ++mi) {
        if (registry->modules[mi].variant_count > SIZE_MAX - capacity) return 0;
        capacity += registry->modules[mi].variant_count;
    }
    if (capacity > SIZE_MAX / sizeof(*ranges)) return 0;
    if (capacity) {
        ranges = malloc(capacity * sizeof(*ranges));
        if (!ranges) return 0;
    }
    for (mi = 0; mi < registry->module_count; ++mi) {
        const struct chimera_module *module = &registry->modules[mi];
        uint64_t original_span;
        if (!module->module_id[0] || !module->runtime_name[0]
            || (!module->safety && module->safety_count)
            || !module->variants || !module->variant_count
            || !append_body_range(ranges, &range_count,
                                  module->original_base,
                                  module->original_end)) goto fail;
        original_span = module->original_end - module->original_base;
        for (vi = 0; vi < module->safety_count; ++vi) {
            if (module->safety[vi].is_safe > 1
                || (vi && module->safety[vi - 1].original_rva
                    >= module->safety[vi].original_rva)) goto fail;
        }
        for (vi = 0; vi < module->variant_count; ++vi) {
            size_t ov;
            if (!validate_variant(&module->variants[vi], original_span)) goto fail;
            for (ov = 0; ov < vi; ++ov)
                if (module->variants[ov].route_id
                    == module->variants[vi].route_id) goto fail;
            if (!append_body_range(ranges, &range_count,
                                   module->variants[vi].translated_base,
                                   module->variants[vi].translated_end)) goto fail;
        }
    }
    free(ranges);
    return 1;
fail:
    free(ranges);
    return 0;
}

const struct chimera_module *chimera_registry_find_original_module(
    const struct chimera_registry *registry, uint64_t original_pc) {
    size_t mi;
    if (!registry) return NULL;
    for (mi = 0; mi < registry->module_count; ++mi) {
        const struct chimera_module *module = &registry->modules[mi];
        if (contains(module->original_base, module->original_end, original_pc))
            return module;
    }
    return NULL;
}

const struct chimera_translation_variant *chimera_module_find_variant_by_route(
    const struct chimera_module *module, uint64_t route_id) {
    size_t vi;
    if (!module) return NULL;
    for (vi = 0; vi < module->variant_count; ++vi)
        if (module->variants[vi].route_id == route_id)
            return &module->variants[vi];
    return NULL;
}

int chimera_module_address_is_safe(
    const struct chimera_module *module, uint64_t original_pc) {
    const struct chimera_safety_entry *entry;
    if (!module
        || !contains(module->original_base, module->original_end, original_pc)
        || !safety_lookup(module->safety, module->safety_count,
                          original_pc - module->original_base, &entry)) return 0;
    return entry->is_safe == UINT64_C(1);
}

const struct chimera_no_link_entry *chimera_registry_find_no_link(
    const struct chimera_registry *registry, uint64_t pc,
    chimera_code_body *body) {
    if (!registry || !body) return NULL;
    for (size_t mi = 0; mi < registry->module_count; ++mi) {
        const struct chimera_module *module = &registry->modules[mi];
        for (size_t vi = 0; vi < module->variant_count; ++vi) {
            const struct chimera_translation_variant *v = &module->variants[vi];
            if (!contains(v->translated_base, v->translated_end, pc)) continue;
            size_t left = 0, right = v->no_link_count;
            while (left < right) {
                size_t middle = left + (right - left) / 2;
                if (v->no_link[middle].trap_pc < pc) left = middle + 1;
                else right = middle;
            }
            if (left == v->no_link_count || v->no_link[left].trap_pc != pc)
                return NULL;
            *body = v->body;
            return &v->no_link[left];
        }
    }
    return NULL;
}

static int locate_address(
    const struct chimera_registry *registry,
    uint64_t address,
    chimera_code_body *body,
    const struct chimera_module **owner_module,
    const struct chimera_translation_variant **owner_variant) {
    size_t mi, vi;
    if (!registry || !body) return 0;
    for (mi = 0; mi < registry->module_count; ++mi) {
        const struct chimera_module *module = &registry->modules[mi];
        if (contains(module->original_base, module->original_end, address)) {
            *body = CHIMERA_CODE_ORIGINAL;
            if (owner_module) *owner_module = module;
            if (owner_variant) *owner_variant = NULL;
            return 1;
        }
        for (vi = 0; vi < module->variant_count; ++vi) {
            const struct chimera_translation_variant *variant = &module->variants[vi];
            if (variant->body
                && contains(variant->translated_base,
                            variant->translated_end,
                            address)) {
                *body = variant->body;
                if (owner_module) *owner_module = module;
                if (owner_variant) *owner_variant = variant;
                return 1;
            }
        }
    }
    return 0;
}

int chimera_registry_locate_body(
    const struct chimera_registry *registry,
    uint64_t address,
    chimera_code_body *body) {
    return locate_address(registry, address, body, NULL, NULL);
}

int chimera_registry_describe_address(
    const struct chimera_registry *registry,
    uint64_t address,
    struct chimera_address_info *out) {
    chimera_code_body body;
    const struct chimera_module *module;
    const struct chimera_translation_variant *variant;
    if (!out || !locate_address(registry, address, &body, &module, &variant))
        return 0;
    out->body = body;
    out->body_label = body == CHIMERA_CODE_ORIGINAL
        ? "original" : variant->body_label;
    out->runtime_name = module->runtime_name;
    out->region_base = body == CHIMERA_CODE_ORIGINAL
        ? module->original_base : variant->translated_base;
    return 1;
}

int chimera_map_to_translated(const struct chimera_registry *registry, uint64_t route_id, uint64_t original_pc, uint64_t *translated_pc) {
    const struct chimera_module *module;
    const struct chimera_translation_variant *variant;
    uint64_t rva;
    if (!translated_pc) return 0;
    module = chimera_registry_find_original_module(registry, original_pc);
    if (!module) return 0;
    variant = chimera_module_find_variant_by_route(module, route_id);
    if (!variant
        || !forward_lookup(variant->forward, variant->forward_count,
                           original_pc - module->original_base, &rva)) return 0;
    *translated_pc = variant->translated_base + rva;
    return 1;
}

int chimera_map_to_original(const struct chimera_registry *registry, uint64_t translated_pc, uint64_t *original_pc) {
    const struct chimera_module *module;
    const struct chimera_translation_variant *variant;
    chimera_code_body body;
    uint64_t rva;
    if (!original_pc
        || !locate_address(registry, translated_pc, &body, &module, &variant)
        || body == CHIMERA_CODE_ORIGINAL || !variant
        || !reverse_lookup(variant->reverse, variant->reverse_count,
                           translated_pc - variant->translated_base, &rva)) return 0;
    *original_pc = module->original_base + rva;
    return 1;
}

int chimera_query_safety(const struct chimera_registry *registry, uint64_t original_pc, struct chimera_safety_decision *decision) {
    const struct chimera_module *module;
    const struct chimera_safety_entry *entry;
    if (!registry || !decision) return 0;
    module = chimera_registry_find_original_module(registry, original_pc);
    if (!module
        || !safety_lookup(module->safety, module->safety_count,
                          original_pc - module->original_base, &entry)) return 0;
    decision->is_safe = entry->is_safe != 0;
    return 1;
}
