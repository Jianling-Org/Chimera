#include "translation_control.h"

#include "module_registry.h"

#ifdef CHIMERA_DEBUG
#include "chimera_debug.h"
#endif

#ifdef CHIMERA_DEBUG
static void debug_map_reject(
    int target_type, uint64_t addr_in, chimera_code_body source,
    const char *reason
) {
    const struct chimera_debug_field fields[] = {
        CHIMERA_DEBUG_U64("target_type", (uint64_t)target_type),
        CHIMERA_DEBUG_HEX("addr_in", addr_in),
        CHIMERA_DEBUG_U64("source_body", (uint64_t)source),
        CHIMERA_DEBUG_TEXT("reason", reason),
    };
    CHIMERA_DEBUG_EVENT("runtime.map.reject", fields, 4U);
}
#else
#define debug_map_reject(target_type, addr_in, source, reason) ((void)0)
#endif

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
        && target_type != (int)CHIMERA_CODE_ORIGINAL) {
        debug_map_reject(target_type, addr_in, source, "translated-to-translated");
        return UINT64_C(0);
    }
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
    if (chimera_map_to_original(registry, addr_in, &mapped)) return mapped;
    debug_map_reject(
        target_type, addr_in, source, "translated-without-reverse-map");
    return UINT64_C(0);
}

enum chimera_migration_decision_status chimera_decide_migration_status(
    const struct chimera_registry *registry,
    uint64_t current_pc,
    uint64_t source_vlen_bits,
    struct chimera_migration_decision *out
) {
    const struct chimera_module *module;
    const struct chimera_translation_variant *variant;
    struct chimera_migration_decision decision;
    chimera_code_body body;
    uint64_t target_vlen_bits;

    if (!registry || !out) return CHIMERA_MIGRATION_PREPARE_FAILED;
    if (chimera_registry_locate_body(registry, current_pc, &body)
        && body != CHIMERA_CODE_ORIGINAL)
        return CHIMERA_MIGRATION_TRANSLATED;
    module = chimera_registry_find_original_module(registry, current_pc);
    if (!module) return CHIMERA_MIGRATION_PREPARE_FAILED;
    /* A route map alone does not provide any original-body exit points.
     * Scalar dependencies may carry translated variants without a safety
     * table; entering one can reach a no-link return that cannot be remapped.
     * Refuse before saving/committing the signal context instead. */
    if (!module->safety || !module->safety_count)
        return CHIMERA_MIGRATION_PREPARE_FAILED;
    if (chimera_module_address_is_safe(module, current_pc))
        return CHIMERA_MIGRATION_NOT_MIGRATABLE;
    if (source_vlen_bits == UINT64_C(1024)) {
        decision.direction = CHIMERA_DIR_1024_TO_256;
        decision.target_type = CHIMERA_CODE_TRANSLATED_1024_TO_256;
        target_vlen_bits = UINT64_C(256);
    } else if (source_vlen_bits == UINT64_C(256)) {
        decision.direction = CHIMERA_DIR_256_TO_1024;
        decision.target_type = CHIMERA_CODE_TRANSLATED_256_TO_1024;
        target_vlen_bits = UINT64_C(1024);
    } else {
        return CHIMERA_MIGRATION_PREPARE_FAILED;
    }
    decision.route_id = chimera_rvv_route_id(source_vlen_bits, target_vlen_bits);
    variant = chimera_module_find_variant_by_route(module, decision.route_id);
    if (!variant) return CHIMERA_MIGRATION_MISSING_ROUTE;
    *out = decision;
    return CHIMERA_MIGRATION_READY;
}

int chimera_decide_migration(
    const struct chimera_registry *registry,
    uint64_t original_pc,
    uint64_t source_vlen_bits,
    struct chimera_migration_decision *out
) {
    return chimera_decide_migration_status(
        registry, original_pc, source_vlen_bits, out)
        == CHIMERA_MIGRATION_READY;
}
