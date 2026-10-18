#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "capabilities.h"
#include "integrity.h"
#include "manifest_v1.h"
#include "module_registry.h"
#include "runtime_v1.h"

/* Fictional routes and body tags used by the generic-registry tests: the
 * generic layer must work without any knowledge of RVV VLEN pairs. */
#define TEST_ROUTE_A UINT64_C(0xaaaa555500000001)
#define TEST_ROUTE_B UINT64_C(0xbbbb333300000002)
#define TEST_BODY_A UINT32_C(7)
#define TEST_BODY_B UINT32_C(9)

/* Exercise the scene loader in this portable test without loading host DSOs. */
void *chimera_linux_open_workspace_library(const char *workspace,
                                           const char *relative_name);
void *chimera_linux_lookup_symbol(void *handle, const char *symbol);
int chimera_linux_module_range(const char *runtime_name, int is_main,
                               uint64_t *base, uint64_t *end);

static const struct chimera_offset_entry loader_forward[] = {{0, 0}};
static const struct chimera_reverse_entry loader_reverse[] = {{0, 0}};
static const struct chimera_safety_entry loader_safety[] = {{0, 1}};
static uint64_t loader_original_base;
static size_t loader_open_count;
static const char *loader_fail_symbol;

int chimera_artifact_matches(
    const char *workspace,
    const struct chimera_manifest_artifact *artifact) {
    (void)workspace;
    (void)artifact;
    return 1;
}

int chimera_variant_fingerprint(
    const struct chimera_manifest *manifest,
    const struct chimera_manifest_variant *variant,
    char output[CHIMERA_SHA256_TEXT_SIZE]) {
    (void)manifest;
    (void)variant;
    memset(output, 'a', CHIMERA_SHA256_TEXT_SIZE - 1);
    output[CHIMERA_SHA256_TEXT_SIZE - 1] = '\0';
    return 1;
}

void *chimera_linux_open_workspace_library(
    const char *workspace,
    const char *relative_name) {
    (void)workspace;
    ++loader_open_count;
    return (void *)(uintptr_t)(!strcmp(relative_name, "translated.so") ? 1 : 2);
}

void *chimera_linux_lookup_symbol(void *handle, const char *symbol) {
    static const uint64_t one = UINT64_C(1);
    static const uint64_t zero = UINT64_C(0);
    (void)handle;
    if (loader_fail_symbol && strstr(symbol, loader_fail_symbol)) return NULL;
    if (strstr(symbol, "translated_code_abi_v1")
        || strstr(symbol, "translation_fingerprint_")
        || strstr(symbol, "offset_map_abi")
        || strstr(symbol, "safety_abi")
        || strstr(symbol, "safety_count")) return (void *)&one;
    if (strstr(symbol, "forward_count")
        || strstr(symbol, "reverse_count")) return (void *)&zero;
    if (strstr(symbol, "forward_entries")) return (void *)loader_forward;
    if (strstr(symbol, "reverse_entries")) return (void *)loader_reverse;
    if (strstr(symbol, "safety_entries")) return (void *)loader_safety;
    if (strstr(symbol, "original_base_addr")) return &loader_original_base;
    return NULL;
}

int chimera_linux_module_range(
    const char *runtime_name,
    int is_main,
    uint64_t *base,
    uint64_t *end) {
    if (is_main && !strcmp(runtime_name, "app")) {
        *base = UINT64_C(0x1000);
        *end = UINT64_C(0x1100);
        return 1;
    }
    if (!is_main && !strcmp(runtime_name, "translated.so")) {
        *base = UINT64_C(0x5000);
        *end = UINT64_C(0x5100);
        return 1;
    }
    return 0;
}

struct loader_fixture {
    struct chimera_manifest_module modules[1];
    struct chimera_manifest_variant variants[1];
    struct chimera_manifest_variant_property properties[6];
    struct chimera_manifest_artifact artifacts[6];
    struct chimera_manifest manifest;
};

static void fixture_text(char *output, size_t capacity, const char *value) {
    int written = snprintf(output, capacity, "%s", value);
    assert(written >= 0 && (size_t)written < capacity);
}

static void initialize_loader_fixture(
    struct loader_fixture *fixture,
    const char *source_vlen,
    const char *target_vlen) {
    static const char *const sides[] = {"input", "output"};
    static const char *const names[] = {
        "architecture", "architecture_extension", "vector_vlen_bits",
    };
    static const char *const kinds[] = {"token", "token", "u64"};
    size_t side, property;
    memset(fixture, 0, sizeof(*fixture));
    loader_open_count = 0;
    loader_fail_symbol = NULL;
    fixture_text(fixture->modules[0].module_id,
                 sizeof(fixture->modules[0].module_id), "main");
    fixture_text(fixture->modules[0].role,
                 sizeof(fixture->modules[0].role), "main");
    fixture_text(fixture->modules[0].runtime_name,
                 sizeof(fixture->modules[0].runtime_name), "app");
    fixture_text(fixture->modules[0].selected_kind,
                 sizeof(fixture->modules[0].selected_kind), "original");
    fixture_text(fixture->variants[0].variant_id,
                 sizeof(fixture->variants[0].variant_id), "variant");
    fixture_text(fixture->variants[0].module_id,
                 sizeof(fixture->variants[0].module_id), "main");
    for (side = 0; side < 2; ++side) {
        for (property = 0; property < 3; ++property) {
            struct chimera_manifest_variant_property *record =
                &fixture->properties[side * 3 + property];
            const char *value = property == 0 ? "riscv64"
                : property == 1 ? "rvv"
                : side == 0 ? source_vlen : target_vlen;
            fixture_text(record->variant_id, sizeof(record->variant_id), "variant");
            fixture_text(record->side, sizeof(record->side), sides[side]);
            fixture_text(record->name, sizeof(record->name), names[property]);
            fixture_text(record->value_kind, sizeof(record->value_kind), kinds[property]);
            fixture_text(record->value, sizeof(record->value), value);
        }
    }
    {
        struct chimera_manifest_artifact *runtime = &fixture->artifacts[0];
        struct chimera_manifest_artifact *translated = &fixture->artifacts[1];
        struct chimera_manifest_artifact *map = &fixture->artifacts[2];
        fixture_text(runtime->artifact_id, sizeof(runtime->artifact_id), "runtime");
        fixture_text(runtime->owner_kind, sizeof(runtime->owner_kind), "workspace");
        fixture_text(runtime->owner_id, sizeof(runtime->owner_id), "root");
        fixture_text(runtime->capability, sizeof(runtime->capability), "runtime");
        fixture_text(runtime->representation, sizeof(runtime->representation), "elf");
        fixture_text(runtime->required_by, sizeof(runtime->required_by), "runtime");
        fixture_text(runtime->path, sizeof(runtime->path), "runtime.so");
        runtime->abi = UINT64_C(1);
        fixture_text(translated->artifact_id, sizeof(translated->artifact_id), "translated");
        fixture_text(translated->owner_kind, sizeof(translated->owner_kind), "variant");
        fixture_text(translated->owner_id, sizeof(translated->owner_id), "variant");
        fixture_text(translated->capability, sizeof(translated->capability), "translated-code");
        fixture_text(translated->representation, sizeof(translated->representation), "elf");
        fixture_text(translated->required_by, sizeof(translated->required_by), "runtime");
        fixture_text(translated->path, sizeof(translated->path), "translated.so");
        translated->abi = UINT64_C(1);
        fixture_text(map->artifact_id, sizeof(map->artifact_id), "map");
        fixture_text(map->owner_kind, sizeof(map->owner_kind), "variant");
        fixture_text(map->owner_id, sizeof(map->owner_id), "variant");
        fixture_text(map->capability, sizeof(map->capability), "offset-map");
        fixture_text(map->representation, sizeof(map->representation), "elf");
        fixture_text(map->required_by, sizeof(map->required_by), "runtime");
        fixture_text(map->path, sizeof(map->path), "map.so");
        map->abi = UINT64_C(1);
    }
    fixture->manifest.runtime_abi = UINT64_C(1);
    fixture_text(fixture->manifest.target_os,
                 sizeof(fixture->manifest.target_os), "linux");
    fixture_text(fixture->manifest.target_arch,
                 sizeof(fixture->manifest.target_arch), "riscv64");
    fixture_text(fixture->manifest.target_arch_extension,
                 sizeof(fixture->manifest.target_arch_extension), "rvv");
    fixture_text(fixture->manifest.runtime_scene,
                 sizeof(fixture->manifest.runtime_scene), "linux_riscv64_rvv_v1");
    fixture->manifest.modules = fixture->modules;
    fixture->manifest.module_count = 1;
    fixture->manifest.variants = fixture->variants;
    fixture->manifest.variant_count = 1;
    fixture->manifest.variant_properties = fixture->properties;
    fixture->manifest.variant_property_count = 6;
    fixture->manifest.artifacts = fixture->artifacts;
    fixture->manifest.artifact_count = 3;
}

static struct chimera_manifest_artifact *append_artifact(
    struct loader_fixture *fixture,
    const char *artifact_id,
    const char *owner_kind,
    const char *owner_id,
    const char *capability,
    const char *representation,
    uint64_t abi,
    const char *required_by,
    const char *path) {
    struct chimera_manifest_artifact *record;
    assert(fixture->manifest.artifact_count
           < sizeof(fixture->artifacts) / sizeof(fixture->artifacts[0]));
    record = &fixture->artifacts[fixture->manifest.artifact_count++];
    memset(record, 0, sizeof(*record));
    fixture_text(record->artifact_id, sizeof(record->artifact_id), artifact_id);
    fixture_text(record->owner_kind, sizeof(record->owner_kind), owner_kind);
    fixture_text(record->owner_id, sizeof(record->owner_id), owner_id);
    fixture_text(record->capability, sizeof(record->capability), capability);
    fixture_text(record->representation, sizeof(record->representation),
                 representation);
    fixture_text(record->required_by, sizeof(record->required_by), required_by);
    fixture_text(record->path, sizeof(record->path), path);
    record->abi = abi;
    return record;
}

static int load_fixture_into(
    struct loader_fixture *fixture,
    struct chimera_registry *registry) {
    return chimera_capabilities_load("workspace", &fixture->manifest, registry);
}

static int load_fixture(struct loader_fixture *fixture) {
    struct chimera_registry registry;
    int loaded = load_fixture_into(fixture, &registry);
    if (loaded) chimera_capabilities_destroy(&registry);
    return loaded;
}

static struct chimera_translation_variant make_variant(
    uint64_t route_id,
    chimera_code_body body,
    const char *body_label,
    uint64_t translated_base,
    uint64_t translated_end) {
    struct chimera_translation_variant variant = {
        route_id, body, body_label,
        translated_base, translated_end,
        NULL, 0, NULL, 0, NULL, 0,
    };
    return variant;
}

static struct chimera_module make_module(
    const char *module_id,
    uint64_t original_base,
    uint64_t original_end,
    struct chimera_translation_variant *variants,
    size_t variant_count) {
    struct chimera_module module = {
        "", "app", original_base, original_end,
        NULL, 0, variants, variant_count,
    };
    size_t index;
    for (index = 0; module_id[index] != '\0'; ++index)
        module.module_id[index] = module_id[index];
    return module;
}

int main(void) {
    static const struct chimera_offset_entry forward[] = {
        {0x10, 0x80},
        {0x20, 0x10},
    };
    static const struct chimera_reverse_entry reverse[] = {
        {0x10, 0x20},
        {0x80, 0x10},
    };
    static const struct chimera_safety_entry safety[] = {
        {0x10, 0},
        {0x20, 1},
    };
    static struct chimera_translation_variant variants[] = {
        {
            TEST_ROUTE_A, TEST_BODY_A, "route-a", 0x5000, 0x5100,
            forward, 2, reverse, 2, NULL, 0,
        },
    };
    static const struct chimera_module modules[] = {
        {
            "main", "app", 0x1000, 0x1100,
            safety, 2, variants, 1,
        },
    };
    const struct chimera_registry registry = {modules, 1};
    struct chimera_safety_decision decision;
    uint64_t mapped = UINT64_C(0xfeedface);

    assert(chimera_registry_validate(&registry));
    {
        struct chimera_no_link_entry sites[] = {
            {0x5030, 320, 296, 0x10}, {0x5040, 320, 296, 0x20},
        };
        chimera_code_body body = 0;
        variants[0].no_link = sites;
        variants[0].no_link_count = 2;
        assert(chimera_registry_validate(&registry));
        assert(chimera_registry_find_no_link(&registry, 0x5030, &body) == &sites[0]);
        assert(body == TEST_BODY_A);
        assert(chimera_registry_find_no_link(&registry, 0x5040, &body) == &sites[1]);
        assert(!chimera_registry_find_no_link(&registry, 0x5032, &body));
        assert(!chimera_registry_find_no_link(&registry, 0x1010, &body));
        sites[1].frame_bytes = 17;
        assert(!chimera_registry_validate(&registry));
        sites[1].frame_bytes = 320;
        sites[1].target_slot = 320;
        assert(!chimera_registry_validate(&registry));
        sites[1].target_slot = 296;
        sites[1].trap_pc = sites[0].trap_pc;
        assert(!chimera_registry_validate(&registry));
        sites[1].trap_pc = 0x5100;
        assert(!chimera_registry_validate(&registry));
        variants[0].no_link = NULL;
        variants[0].no_link_count = 0;
    }
    assert(chimera_map_to_translated(&registry, TEST_ROUTE_A, 0x1010, &mapped));
    assert(mapped == 0x5080);
    assert(chimera_map_to_original(&registry, 0x5010, &mapped));
    assert(mapped == 0x1020);
    assert(chimera_query_safety(&registry, 0x1010, &decision));
    assert(!decision.is_safe);
    assert(chimera_query_safety(&registry, 0x1020, &decision));
    assert(decision.is_safe);

    mapped = UINT64_C(0xfeedface);
    assert(!chimera_map_to_translated(&registry, TEST_ROUTE_A, 0x1100, &mapped));
    assert(mapped == UINT64_C(0xfeedface));
    assert(!chimera_query_safety(&registry, 0x1030, &decision));

    {
        struct offset_bounds_case {
            uint64_t original_rva;
            uint64_t translated_rva;
            int valid;
        };
        static const struct offset_bounds_case cases[] = {
            {UINT64_C(0xff), UINT64_C(0xff), 1},
            {UINT64_C(0x100), UINT64_C(0x10), 0},
            {UINT64_C(0x101), UINT64_C(0x10), 0},
            {UINT64_MAX, UINT64_C(0x10), 0},
            {UINT64_C(0x10), UINT64_C(0x100), 0},
            {UINT64_C(0x10), UINT64_C(0x101), 0},
            {UINT64_C(0x10), UINT64_MAX, 0},
        };
        size_t index;
        for (index = 0; index < sizeof(cases) / sizeof(cases[0]); ++index) {
            const struct chimera_offset_entry bounded_forward[] = {
                {cases[index].original_rva, cases[index].translated_rva},
            };
            const struct chimera_reverse_entry bounded_reverse[] = {
                {cases[index].translated_rva, cases[index].original_rva},
            };
            struct chimera_translation_variant bounded_variant = {
                TEST_ROUTE_A, TEST_BODY_A, "route-a", 0x5000, 0x5100,
                bounded_forward, 1, bounded_reverse, 1, NULL, 0,
            };
            struct chimera_module bounded_module =
                make_module("bounds", 0x1000, 0x1100, &bounded_variant, 1);
            const struct chimera_registry bounded_registry = {
                &bounded_module, 1,
            };
            uint64_t bounded_mapped = UINT64_C(0);

            assert(chimera_registry_validate(&bounded_registry) == cases[index].valid);
            if (!cases[index].valid) continue;
            assert(chimera_map_to_translated(
                &bounded_registry, TEST_ROUTE_A,
                bounded_module.original_base + cases[index].original_rva,
                &bounded_mapped));
            assert(bounded_mapped
                   == bounded_variant.translated_base + cases[index].translated_rva);
            assert(bounded_mapped >= bounded_variant.translated_base);
            assert(bounded_mapped < bounded_variant.translated_end);
            assert(chimera_map_to_original(
                &bounded_registry, bounded_mapped, &bounded_mapped));
            assert(bounded_mapped
                   == bounded_module.original_base + cases[index].original_rva);
            assert(bounded_mapped >= bounded_module.original_base);
            assert(bounded_mapped < bounded_module.original_end);
        }
    }

    assert(chimera_registry_find_original_module(&registry, 0x1010) == &modules[0]);
    assert(chimera_registry_find_original_module(&registry, 0x1100) == NULL);
    assert(chimera_module_find_variant_by_route(&modules[0], TEST_ROUTE_A)
           == &variants[0]);
    assert(chimera_module_find_variant_by_route(&modules[0], TEST_ROUTE_B)
           == NULL);
    assert(!chimera_module_address_is_safe(&modules[0], 0x1010));
    assert(chimera_module_address_is_safe(&modules[0], 0x1020));
    assert(!chimera_module_address_is_safe(&modules[0], 0x1030));
    {
        chimera_code_body body = CHIMERA_CODE_ORIGINAL;
        assert(chimera_registry_locate_body(&registry, 0x1010, &body));
        assert(body == CHIMERA_CODE_ORIGINAL);
        assert(chimera_registry_locate_body(&registry, 0x5010, &body));
        assert(body == TEST_BODY_A);
        assert(!chimera_registry_locate_body(&registry, 0x5100, &body));
    }
    {
        struct chimera_address_info info;
        assert(chimera_registry_describe_address(&registry, 0x1010, &info));
        assert(info.body == CHIMERA_CODE_ORIGINAL);
        assert(!strcmp(info.body_label, "original"));
        assert(!strcmp(info.runtime_name, "app"));
        assert(info.region_base == UINT64_C(0x1000));
        assert(chimera_registry_describe_address(&registry, 0x5010, &info));
        assert(info.body == TEST_BODY_A);
        assert(!strcmp(info.body_label, "route-a"));
        assert(!strcmp(info.runtime_name, "app"));
        assert(info.region_base == UINT64_C(0x5000));
        assert(!chimera_registry_describe_address(&registry, 0x5100, &info));
        assert(!chimera_registry_describe_address(&registry, 0x1010, NULL));
    }

    {
        struct chimera_translation_variant overlap_variant =
            make_variant(TEST_ROUTE_A, TEST_BODY_A, "route-a", 0x1080, 0x1180);
        struct chimera_module overlap_module =
            make_module("same", 0x1000, 0x1100, &overlap_variant, 1);
        const struct chimera_registry overlap_registry = {&overlap_module, 1};
        assert(!chimera_registry_validate(&overlap_registry));
    }
    {
        struct chimera_translation_variant overlap_variants[] = {
            make_variant(TEST_ROUTE_A, TEST_BODY_A, "route-a", 0x3000, 0x3100),
            make_variant(TEST_ROUTE_B, TEST_BODY_B, "route-b", 0x4000, 0x4100),
        };
        struct chimera_module overlap_modules[] = {
            make_module("first", 0x1000, 0x1100, &overlap_variants[0], 1),
            make_module("second", 0x1080, 0x1180, &overlap_variants[1], 1),
        };
        const struct chimera_registry overlap_registry = {overlap_modules, 2};
        assert(!chimera_registry_validate(&overlap_registry));
    }
    {
        struct chimera_translation_variant overlap_variants[] = {
            make_variant(TEST_ROUTE_A, TEST_BODY_A, "route-a", 0x3000, 0x3100),
            make_variant(TEST_ROUTE_B, TEST_BODY_B, "route-b", 0x3080, 0x3180),
        };
        struct chimera_module overlap_modules[] = {
            make_module("first", 0x1000, 0x1100, &overlap_variants[0], 1),
            make_module("second", 0x2000, 0x2100, &overlap_variants[1], 1),
        };
        const struct chimera_registry overlap_registry = {overlap_modules, 2};
        assert(!chimera_registry_validate(&overlap_registry));
    }
    {
        /* Duplicate route_id within one module is rejected generically. */
        struct chimera_translation_variant duplicate_variants[] = {
            make_variant(TEST_ROUTE_A, TEST_BODY_A, "route-a", 0x3000, 0x3100),
            make_variant(TEST_ROUTE_A, TEST_BODY_B, "route-b", 0x4000, 0x4100),
        };
        struct chimera_module duplicate_module =
            make_module("dup", 0x1000, 0x1100, duplicate_variants, 2);
        const struct chimera_registry duplicate_registry = {
            &duplicate_module, 1,
        };
        assert(!chimera_registry_validate(&duplicate_registry));
    }
    {
        struct chimera_translation_variant touching_variants[] = {
            make_variant(TEST_ROUTE_A, TEST_BODY_A, "route-a", 0x1100, 0x1200),
            make_variant(TEST_ROUTE_B, TEST_BODY_B, "route-b", 0x1300, 0x1400),
        };
        struct chimera_module touching_modules[] = {
            make_module("first", 0x1000, 0x1100, &touching_variants[0], 1),
            make_module("second", 0x1200, 0x1300, &touching_variants[1], 1),
        };
        const struct chimera_registry touching_registry = {touching_modules, 2};
        assert(chimera_registry_validate(&touching_registry));
        assert(!chimera_module_address_is_safe(&touching_modules[0], 0x1000));
    }
    {
        /* Body tag 0 is reserved for CHIMERA_CODE_ORIGINAL and rejected. */
        struct chimera_translation_variant invalid_variant =
            make_variant(TEST_ROUTE_A, 0, NULL, 0x2000, 0x2100);
        struct chimera_module invalid_module =
            make_module("invalid", 0x1000, 0x1100,
                        &invalid_variant, 1);
        const struct chimera_registry invalid_registry = {
            &invalid_module, 1,
        };
        chimera_code_body body = TEST_BODY_A;
        assert(!chimera_registry_validate(&invalid_registry));
        assert(!chimera_registry_locate_body(
            &invalid_registry, 0x2010, &body));
    }
    {
        struct route_case {
            const char *source;
            const char *target;
            int valid;
        };
        static const struct route_case cases[] = {
            {"1024", "256", 1},
            {"256", "1024", 1},
            {"1024", "512", 0},
            {"512", "256", 0},
            {"256", "256", 0},
            {"1024", "1024", 0},
        };
        size_t index;
        for (index = 0; index < sizeof(cases) / sizeof(cases[0]); ++index) {
            struct loader_fixture fixture;
            initialize_loader_fixture(
                &fixture, cases[index].source, cases[index].target);
            assert(load_fixture(&fixture) == cases[index].valid);
            assert((loader_open_count != 0) == cases[index].valid);
        }
    }
    {
        struct loader_fixture fixture;
        initialize_loader_fixture(&fixture, "1024", "256");
        fixture.manifest.runtime_abi = UINT64_C(2);
        assert(!load_fixture(&fixture));
        assert(loader_open_count == 0);

        initialize_loader_fixture(&fixture, "1024", "256");
        fixture.artifacts[0].abi = UINT64_C(2);
        assert(!load_fixture(&fixture));
        assert(loader_open_count == 0);

        initialize_loader_fixture(&fixture, "1024", "256");
        fixture_text(fixture.properties[2].value_kind,
                     sizeof(fixture.properties[2].value_kind), "token");
        assert(!load_fixture(&fixture));
        assert(loader_open_count == 0);

        initialize_loader_fixture(&fixture, "1024", "256");
        fixture_text(fixture.properties[0].value,
                     sizeof(fixture.properties[0].value), "riscv32");
        assert(!load_fixture(&fixture));
        assert(loader_open_count == 0);

        initialize_loader_fixture(&fixture, "1024", "256");
        fixture_text(fixture.properties[1].value,
                     sizeof(fixture.properties[1].value), "rvv2");
        assert(!load_fixture(&fixture));
        assert(loader_open_count == 0);

        initialize_loader_fixture(&fixture, "1024", "256");
        fixture.properties[5].name[0] = '\0';
        assert(!load_fixture(&fixture));
        assert(loader_open_count == 0);

        initialize_loader_fixture(&fixture, "01024", "256");
        assert(!load_fixture(&fixture));
        assert(loader_open_count == 0);

        initialize_loader_fixture(
            &fixture, "18446744073709552640", "256");
        assert(!load_fixture(&fixture));
        assert(loader_open_count == 0);

        initialize_loader_fixture(
            &fixture, "1024", "18446744073709551872");
        assert(!load_fixture(&fixture));
        assert(loader_open_count == 0);
    }
    {
        struct loader_fixture fixture;
        struct chimera_registry loaded_registry;
        initialize_loader_fixture(&fixture, "1024", "256");
        append_artifact(&fixture, "safety", "module", "main", "safety", "elf",
                        UINT64_C(1), "runtime", "safety.so");
        assert(load_fixture_into(&fixture, &loaded_registry));
        assert(loaded_registry.module_count == 1);
        assert(loaded_registry.modules[0].safety == loader_safety);
        assert(loaded_registry.modules[0].safety_count == 1);
        assert(loader_open_count == 3);
        chimera_capabilities_destroy(&loaded_registry);
    }
    {
        /* The load path must store exactly what the scene derivation
         * function produces, so loader and decision path cannot drift. */
        struct loader_fixture fixture;
        struct chimera_registry loaded_registry;
        const struct chimera_translation_variant *loaded_variant;
        initialize_loader_fixture(&fixture, "1024", "256");
        assert(load_fixture_into(&fixture, &loaded_registry));
        loaded_variant = &loaded_registry.modules[0].variants[0];
        assert(loaded_variant->route_id == chimera_rvv_route_id(1024, 256));
        assert(loaded_variant->body == CHIMERA_CODE_TRANSLATED_1024_TO_256);
        assert(!strcmp(loaded_variant->body_label, "1024-to-256"));
        chimera_capabilities_destroy(&loaded_registry);

        initialize_loader_fixture(&fixture, "256", "1024");
        assert(load_fixture_into(&fixture, &loaded_registry));
        loaded_variant = &loaded_registry.modules[0].variants[0];
        assert(loaded_variant->route_id == chimera_rvv_route_id(256, 1024));
        assert(loaded_variant->body == CHIMERA_CODE_TRANSLATED_256_TO_1024);
        assert(!strcmp(loaded_variant->body_label, "256-to-1024"));
        chimera_capabilities_destroy(&loaded_registry);
    }
    {
        struct loader_fixture fixture;
        struct chimera_registry failed_registry;
        initialize_loader_fixture(&fixture, "1024", "256");
        loader_fail_symbol = "offset_map_abi";
        assert(!load_fixture_into(&fixture, &failed_registry));
        assert(failed_registry.modules == NULL);
        assert(failed_registry.module_count == 0);
        assert(loader_open_count == 2);
        loader_fail_symbol = NULL;
    }
    {
        struct loader_fixture fixture;
        initialize_loader_fixture(&fixture, "1024", "256");
        append_artifact(&fixture, "custom", "module", "main", "custom-analysis",
                        "json", UINT64_C(9), "verifier", "custom.json");
        assert(load_fixture(&fixture));
        assert(loader_open_count == 2);

        initialize_loader_fixture(&fixture, "1024", "256");
        append_artifact(&fixture, "custom", "module", "main", "custom-analysis",
                        "json", UINT64_C(9), "runtime", "custom.json");
        assert(!load_fixture(&fixture));
        assert(loader_open_count == 0);
    }
    {
        struct loader_fixture fixture;
        initialize_loader_fixture(&fixture, "1024", "256");
        append_artifact(&fixture, "translated-duplicate", "variant", "variant",
                        "translated-code", "elf", UINT64_C(1), "runtime",
                        "translated-duplicate.so");
        assert(!load_fixture(&fixture));
        assert(loader_open_count == 0);

        initialize_loader_fixture(&fixture, "1024", "256");
        append_artifact(&fixture, "safety-a", "module", "main", "safety", "elf",
                        UINT64_C(1), "runtime", "safety-a.so");
        append_artifact(&fixture, "safety-b", "module", "main", "safety", "elf",
                        UINT64_C(1), "runtime", "safety-b.so");
        assert(!load_fixture(&fixture));
        assert(loader_open_count == 0);
    }
    return 0;
}
