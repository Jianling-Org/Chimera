#ifndef CHIMERA_MODULE_REGISTRY_H
#define CHIMERA_MODULE_REGISTRY_H

#include <stdint.h>

#include "chimera_runtime.h"

struct chimera_address_info {
    chimera_code_body body;
    const char *body_label;
    const char *runtime_name;
    uint64_t region_base;
};

int chimera_registry_describe_address(
    const struct chimera_registry *registry,
    uint64_t address,
    struct chimera_address_info *out);

int chimera_registry_validate(const struct chimera_registry *registry);
const struct chimera_module *chimera_registry_find_original_module(
    const struct chimera_registry *registry, uint64_t original_pc);
const struct chimera_translation_variant *chimera_module_find_variant_by_route(
    const struct chimera_module *module, uint64_t route_id);
int chimera_module_address_is_safe(
    const struct chimera_module *module, uint64_t original_pc);
int chimera_registry_locate_body(
    const struct chimera_registry *registry,
    uint64_t address,
    chimera_code_body *body);
int chimera_map_to_translated(const struct chimera_registry *registry,
                              uint64_t route_id,
                              uint64_t original_pc,
                              uint64_t *translated_pc);
int chimera_map_to_original(const struct chimera_registry *registry,
                            uint64_t translated_pc,
                            uint64_t *original_pc);
int chimera_query_safety(const struct chimera_registry *registry,
                         uint64_t original_pc,
                         struct chimera_safety_decision *decision);

#endif
