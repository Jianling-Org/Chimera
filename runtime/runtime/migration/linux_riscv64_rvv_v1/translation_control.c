#include "translation_control.h"

#include "module_registry.h"

__attribute__((visibility("default")))
uint64_t query_original_translated_map(int target_type, uint64_t addr_in) {
    const struct chimera_registry *registry = chimera_scene_registry();
    chimera_code_body source;
    uint64_t mapped = UINT64_C(0);

    if (target_type < (int)CHIMERA_CODE_ORIGINAL
        || target_type > (int)CHIMERA_CODE_TRANSLATED_256_TO_1024) return UINT64_C(0);
    if (!registry || !chimera_registry_locate_body(registry, addr_in, &source))
        return addr_in;
    if (source == (chimera_code_body)target_type) return addr_in;
    if (source != CHIMERA_CODE_ORIGINAL
        && target_type != (int)CHIMERA_CODE_ORIGINAL) return UINT64_C(0);
    if (source == CHIMERA_CODE_ORIGINAL) {
        /* Scene routing table: target_type 1 is the 1024->256 body, so the
         * original side must be mapped through the 1024->256 route; the same
         * holds for 256->1024. */
        uint64_t source_vlen_bits =
            target_type == (int)CHIMERA_CODE_TRANSLATED_1024_TO_256
                ? UINT64_C(1024) : UINT64_C(256);
        uint64_t route_id = chimera_rvv_route_id(
            source_vlen_bits,
            source_vlen_bits == UINT64_C(1024)
                ? UINT64_C(256) : UINT64_C(1024));
        return chimera_map_to_translated(registry, route_id, addr_in, &mapped)
            ? mapped : addr_in;
    }
    return chimera_map_to_original(registry, addr_in, &mapped)
        ? mapped : UINT64_C(0);
}

int chimera_decide_migration(
    const struct chimera_registry *registry,
    uint64_t original_pc,
    uint64_t source_vlen_bits,
    struct chimera_migration_decision *out
) {
    const struct chimera_module *module;
    const struct chimera_translation_variant *variant;
    struct chimera_migration_decision decision;
    uint64_t target_vlen_bits;

    if (!registry || !out) return 0;
    module = chimera_registry_find_original_module(registry, original_pc);
    if (!module || chimera_module_address_is_safe(module, original_pc)) return 0;
    if (source_vlen_bits == UINT64_C(1024)) {
        decision.direction = CHIMERA_DIR_1024_TO_256;
        decision.target_type = CHIMERA_CODE_TRANSLATED_1024_TO_256;
        target_vlen_bits = UINT64_C(256);
    } else if (source_vlen_bits == UINT64_C(256)) {
        decision.direction = CHIMERA_DIR_256_TO_1024;
        decision.target_type = CHIMERA_CODE_TRANSLATED_256_TO_1024;
        target_vlen_bits = UINT64_C(1024);
    } else {
        return 0;
    }
    decision.route_id = chimera_rvv_route_id(source_vlen_bits, target_vlen_bits);
    variant = chimera_module_find_variant_by_route(module, decision.route_id);
    if (!variant) return 0;
    *out = decision;
    return 1;
}
