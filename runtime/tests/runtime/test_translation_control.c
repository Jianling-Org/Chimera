#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "module_registry.h"
#include "runtime_v1.h"
#include "translation_control.h"

static const struct chimera_registry *active_registry;

const struct chimera_registry *chimera_scene_registry(void) {
    return active_registry;
}

static void assert_decision_unchanged(
    const struct chimera_registry *registry,
    uint64_t original_pc,
    uint64_t source_vlen_bits
) {
    struct chimera_migration_decision decision;
    unsigned char before[sizeof(decision)];
    memset(&decision, 0xa5, sizeof(decision));
    memcpy(before, &decision, sizeof(decision));
    assert(!chimera_decide_migration(
        registry, original_pc, source_vlen_bits, &decision));
    assert(memcmp(before, &decision, sizeof(decision)) == 0);
}

int main(void) {
    static const struct chimera_offset_entry forward[] = {
        {UINT64_C(0x10), UINT64_C(0x10)},
        {UINT64_C(0x20), UINT64_C(0x20)},
        {UINT64_C(0x30), UINT64_C(0x30)},
    };
    static const struct chimera_reverse_entry reverse[] = {
        {UINT64_C(0x10), UINT64_C(0x10)},
        {UINT64_C(0x20), UINT64_C(0x20)},
        {UINT64_C(0x30), UINT64_C(0x30)},
    };
    static const struct chimera_safety_entry safety[] = {
        {UINT64_C(0x10), UINT64_C(1)},
        {UINT64_C(0x20), UINT64_C(0)},
    };
    static struct chimera_translation_variant variants[] = {
        {
            (UINT64_C(1024) << 32) | UINT64_C(256),
            CHIMERA_CODE_TRANSLATED_1024_TO_256, "1024-to-256",
            UINT64_C(0x5000), UINT64_C(0x5100),
            forward, 3, reverse, 3, NULL, 0,
        },
        {
            (UINT64_C(256) << 32) | UINT64_C(1024),
            CHIMERA_CODE_TRANSLATED_256_TO_1024, "256-to-1024",
            UINT64_C(0x7000), UINT64_C(0x7100),
            forward, 3, reverse, 3, NULL, 0,
        },
    };
    static const struct chimera_module modules[] = {
        {
            "main", "app", UINT64_C(0x1000), UINT64_C(0x1100),
            safety, 2, variants, 2,
        },
    };
    static const struct chimera_registry registry = {modules, 1};
    static const struct chimera_registry empty_registry = {NULL, 0};
    static const struct chimera_module one_way_modules[] = {
        {
            "main", "app", UINT64_C(0x1000), UINT64_C(0x1100),
            safety, 2, variants, 1,
        },
    };
    static const struct chimera_registry one_way_registry = {
        one_way_modules, 1,
    };
    static const struct chimera_module no_safety_modules[] = {
        {
            "dependency", "libc.so.6", UINT64_C(0x1000), UINT64_C(0x1100),
            NULL, 0, variants, 2,
        },
    };
    static const struct chimera_registry no_safety_registry = {
        no_safety_modules, 1,
    };
    struct chimera_migration_decision decision;
    struct query_case {
        int target;
        uint64_t input;
        uint64_t expected;
    };
    static const struct query_case cases[] = {
        {CHIMERA_CODE_ORIGINAL, UINT64_C(0x1010), UINT64_C(0x1010)},
        {CHIMERA_CODE_TRANSLATED_1024_TO_256, UINT64_C(0x1010), UINT64_C(0x5010)},
        {CHIMERA_CODE_TRANSLATED_256_TO_1024, UINT64_C(0x1010), UINT64_C(0x7010)},
        {CHIMERA_CODE_ORIGINAL, UINT64_C(0x5010), UINT64_C(0x1010)},
        {CHIMERA_CODE_ORIGINAL, UINT64_C(0x7010), UINT64_C(0x1010)},
        {CHIMERA_CODE_TRANSLATED_256_TO_1024, UINT64_C(0x5010), UINT64_C(0)},
        {CHIMERA_CODE_TRANSLATED_1024_TO_256, UINT64_C(0x7010), UINT64_C(0)},
        {CHIMERA_CODE_TRANSLATED_1024_TO_256, UINT64_C(0x10f0), UINT64_C(0x10f0)},
        {CHIMERA_CODE_ORIGINAL, UINT64_C(0x50f0), UINT64_C(0)},
        {CHIMERA_CODE_ORIGINAL, UINT64_C(0x9000), UINT64_C(0x9000)},
        {99, UINT64_C(0x1010), UINT64_C(0)},
    };
    size_t index;

    active_registry = &registry;
    assert(chimera_registry_validate(&no_safety_registry));
    assert(chimera_decide_migration_status(
        &no_safety_registry, UINT64_C(0x1020), UINT64_C(256), &decision)
        == CHIMERA_MIGRATION_PREPARE_FAILED);
    assert_decision_unchanged(&no_safety_registry, UINT64_C(0x1020), UINT64_C(256));
    assert_decision_unchanged(&no_safety_registry, UINT64_C(0x1020), UINT64_C(1024));
    assert(variants[0].route_id == chimera_rvv_route_id(1024, 256));
    assert(variants[1].route_id == chimera_rvv_route_id(256, 1024));
    assert(chimera_registry_validate(active_registry));
    for (index = 0; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        assert(query_original_translated_map(cases[index].target, cases[index].input)
               == cases[index].expected);
    }

    assert(chimera_decide_migration(
        &registry, UINT64_C(0x1020), UINT64_C(1024), &decision));
    assert(decision.direction == CHIMERA_DIR_1024_TO_256);
    assert(decision.target_type == CHIMERA_CODE_TRANSLATED_1024_TO_256);
    assert(decision.route_id == chimera_rvv_route_id(1024, 256));
    assert(chimera_decide_migration(
        &registry, UINT64_C(0x1020), UINT64_C(256), &decision));
    assert(decision.direction == CHIMERA_DIR_256_TO_1024);
    assert(decision.target_type == CHIMERA_CODE_TRANSLATED_256_TO_1024);
    assert(decision.route_id == chimera_rvv_route_id(256, 1024));
    assert(chimera_decide_migration_status(
        &registry, UINT64_C(0x5020), UINT64_C(256), &decision)
        == CHIMERA_MIGRATION_TRANSLATED);
    assert(chimera_decide_migration_status(
        &one_way_registry, UINT64_C(0x1020), UINT64_C(256), &decision)
        == CHIMERA_MIGRATION_MISSING_ROUTE);
    assert(chimera_decide_migration_status(
        &registry, UINT64_C(0x1010), UINT64_C(1024), &decision)
        == CHIMERA_MIGRATION_NOT_MIGRATABLE);
    assert(chimera_decide_migration_status(
        &registry, UINT64_C(0x1020), UINT64_C(512), &decision)
        == CHIMERA_MIGRATION_PREPARE_FAILED);

    /* Missing Safety entries, and an entirely absent Safety table, are unsafe. */
    assert(chimera_decide_migration(
        &registry, UINT64_C(0x1030), UINT64_C(1024), &decision));
    assert(chimera_decide_migration(
        &one_way_registry, UINT64_C(0x1030), UINT64_C(1024), &decision));

    assert_decision_unchanged(
        &registry, UINT64_C(0x1010), UINT64_C(1024));
    assert_decision_unchanged(
        &empty_registry, UINT64_C(0x1020), UINT64_C(1024));
    assert_decision_unchanged(
        &one_way_registry, UINT64_C(0x1020), UINT64_C(256));
    assert_decision_unchanged(
        &registry, UINT64_C(0x1020), UINT64_C(512));
    assert_decision_unchanged(NULL, UINT64_C(0x1020), UINT64_C(1024));
    assert(!chimera_decide_migration(
        &registry, UINT64_C(0x1020), UINT64_C(1024), NULL));

    active_registry = NULL;
    for (index = CHIMERA_CODE_ORIGINAL;
         index <= CHIMERA_CODE_TRANSLATED_256_TO_1024;
         ++index) {
        assert(query_original_translated_map((int)index, UINT64_C(0x1010))
               == UINT64_C(0x1010));
    }
    return 0;
}
