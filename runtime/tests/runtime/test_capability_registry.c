#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "capability_registry.h"

struct callback_log {
    const char *artifact_ids[8];
    size_t count;
    size_t fail_at;
};

static struct callback_log callback_log;

static void copy_text(char *output, size_t capacity, const char *value) {
    int written = snprintf(output, capacity, "%s", value);
    assert(written >= 0 && (size_t)written < capacity);
}

static struct chimera_manifest_artifact artifact(
    const char *artifact_id,
    const char *owner_kind,
    const char *owner_id,
    const char *capability,
    const char *representation,
    uint64_t abi,
    const char *required_by) {
    struct chimera_manifest_artifact value;
    memset(&value, 0, sizeof(value));
    copy_text(value.artifact_id, sizeof(value.artifact_id), artifact_id);
    copy_text(value.owner_kind, sizeof(value.owner_kind), owner_kind);
    copy_text(value.owner_id, sizeof(value.owner_id), owner_id);
    copy_text(value.capability, sizeof(value.capability), capability);
    copy_text(value.representation, sizeof(value.representation), representation);
    copy_text(value.required_by, sizeof(value.required_by), required_by);
    value.abi = abi;
    return value;
}

static int fake_loader(const struct chimera_capability_context *context) {
    assert(context);
    assert(context->workspace && !strcmp(context->workspace, "workspace"));
    assert(context->manifest);
    assert(context->registry);
    assert(context->module);
    assert(context->variant);
    assert(context->module_record);
    assert(context->variant_record);
    assert(context->artifact);
    assert(callback_log.count < sizeof(callback_log.artifact_ids)
           / sizeof(callback_log.artifact_ids[0]));
    callback_log.artifact_ids[callback_log.count++] =
        context->artifact->artifact_id;
    return callback_log.fail_at == 0 || callback_log.count != callback_log.fail_at;
}

static struct chimera_capability_context context_for(
    const struct chimera_manifest *manifest) {
    static struct chimera_registry registry;
    static struct chimera_module module;
    static struct chimera_translation_variant variant;
    static struct chimera_manifest_module module_record;
    static struct chimera_manifest_variant variant_record;
    struct chimera_capability_context context = {
        "workspace", manifest, &registry, &module, &variant,
        &module_record, &variant_record, NULL,
    };
    return context;
}

static int dispatch(
    const struct chimera_capability_registration *registrations,
    size_t registration_count,
    const struct chimera_capability_registration *supported,
    size_t supported_count,
    enum chimera_owner_kind owner,
    const char *owner_id,
    struct chimera_manifest_artifact *artifacts,
    size_t artifact_count) {
    struct chimera_manifest manifest;
    struct chimera_capability_context context;
    memset(&manifest, 0, sizeof(manifest));
    manifest.artifacts = artifacts;
    manifest.artifact_count = artifact_count;
    context = context_for(&manifest);
    memset(&callback_log, 0, sizeof(callback_log));
    return chimera_capability_dispatch(
        registrations, registration_count, supported, supported_count,
        owner, owner_id, &context);
}

static void test_exactly_one(void) {
    const struct chimera_capability_registration registrations[] = {
        {CHIMERA_OWNER_VARIANT, "translated-code", "elf", UINT64_C(1),
         1u, 1u, fake_loader},
    };
    struct chimera_manifest_artifact artifacts[] = {
        artifact("translated", "variant", "v", "translated-code", "elf", 1,
                 "runtime"),
    };
    assert(dispatch(registrations, 1, NULL, 0, CHIMERA_OWNER_VARIANT, "v",
                    artifacts, 1));
    assert(callback_log.count == 1);
    assert(!strcmp(callback_log.artifact_ids[0], "translated"));
    assert(!dispatch(registrations, 1, NULL, 0, CHIMERA_OWNER_VARIANT, "v",
                     NULL, 0));
    assert(callback_log.count == 0);
    artifacts[0] = artifact(
        "translated-a", "variant", "v", "translated-code", "elf", 1,
        "runtime");
    {
        struct chimera_manifest_artifact duplicates[] = {
            artifacts[0],
            artifact("translated-b", "variant", "v", "translated-code",
                     "elf", 1, "runtime"),
        };
        assert(!dispatch(registrations, 1, NULL, 0, CHIMERA_OWNER_VARIANT, "v",
                         duplicates, 2));
        assert(callback_log.count == 0);
    }
}

static void test_zero_or_one_and_maximum_zero(void) {
    struct chimera_manifest_artifact safety[] = {
        artifact("safety-a", "module", "m", "safety", "elf", 1, "runtime"),
        artifact("safety-b", "module", "m", "safety", "elf", 1, "runtime"),
    };
    const struct chimera_capability_registration optional[] = {
        {CHIMERA_OWNER_MODULE, "safety", "elf", UINT64_C(1),
         0u, 1u, fake_loader},
    };
    const struct chimera_capability_registration forbidden[] = {
        {CHIMERA_OWNER_MODULE, "safety", "elf", UINT64_C(1),
         0u, 0u, fake_loader},
    };
    assert(dispatch(optional, 1, NULL, 0, CHIMERA_OWNER_MODULE, "m", NULL, 0));
    assert(callback_log.count == 0);
    assert(dispatch(optional, 1, NULL, 0, CHIMERA_OWNER_MODULE, "m", safety, 1));
    assert(callback_log.count == 1);
    assert(!dispatch(optional, 1, NULL, 0, CHIMERA_OWNER_MODULE, "m", safety, 2));
    assert(callback_log.count == 0);
    assert(dispatch(forbidden, 1, NULL, 0, CHIMERA_OWNER_MODULE, "m", NULL, 0));
    assert(!dispatch(forbidden, 1, NULL, 0, CHIMERA_OWNER_MODULE, "m", safety, 1));
    assert(callback_log.count == 0);
}

static void test_registered_pair_failures_happen_before_callback(void) {
    const struct chimera_capability_registration registrations[] = {
        {CHIMERA_OWNER_VARIANT, "translated-code", "elf", UINT64_C(1),
         1u, 1u, fake_loader},
    };
    struct chimera_manifest_artifact wrong_owner[] = {
        artifact("wrong-owner", "module", "v", "translated-code", "elf", 1,
                 "-"),
    };
    struct chimera_manifest_artifact wrong_abi[] = {
        artifact("wrong-abi", "variant", "v", "translated-code", "elf", 2,
                 "-"),
    };
    assert(!dispatch(registrations, 1, NULL, 0, CHIMERA_OWNER_VARIANT, "v",
                     wrong_owner, 1));
    assert(callback_log.count == 0);
    assert(!dispatch(registrations, 1, NULL, 0, CHIMERA_OWNER_VARIANT, "v",
                     wrong_abi, 1));
    assert(callback_log.count == 0);
}

static void test_pair_first_optional_representations(void) {
    const struct chimera_capability_registration registrations[] = {
        {CHIMERA_OWNER_VARIANT, "translated-code", "elf", UINT64_C(1),
         1u, 1u, fake_loader},
        {CHIMERA_OWNER_VARIANT, "offset-map", "elf", UINT64_C(1),
         0u, 0u, fake_loader},
        {CHIMERA_OWNER_MODULE, "safety", "elf", UINT64_C(1),
         0u, 0u, fake_loader},
    };
    struct chimera_manifest_artifact optional[] = {
        artifact("translated-json", "variant", "v", "translated-code", "json",
                 1, "register"),
        artifact("offset-json", "variant", "v", "offset-map", "json", 1,
                 "register"),
        artifact("safety-json", "module", "m", "safety", "json", 1,
                 "register"),
        artifact("translated", "variant", "v", "translated-code", "elf", 1,
                 "runtime"),
    };
    struct chimera_manifest_artifact required_offset[] = {
        artifact("offset-json", "variant", "v", "offset-map", "json", 1,
                 "runtime"),
        artifact("translated", "variant", "v", "translated-code", "elf", 1,
                 "runtime"),
    };
    struct chimera_manifest_artifact required_safety[] = {
        artifact("safety-json", "module", "m", "safety", "json", 1,
                 "runtime"),
        artifact("translated", "variant", "v", "translated-code", "elf", 1,
                 "runtime"),
    };
    assert(dispatch(registrations, 3, NULL, 0, CHIMERA_OWNER_VARIANT, "v",
                    optional, 4));
    assert(callback_log.count == 1);
    assert(!dispatch(registrations, 3, NULL, 0, CHIMERA_OWNER_VARIANT, "v",
                     required_offset, 2));
    assert(callback_log.count == 0);
    assert(!dispatch(registrations, 3, NULL, 0, CHIMERA_OWNER_VARIANT, "v",
                     required_safety, 2));
    assert(callback_log.count == 0);
}

static void test_unknown_optional_and_required(void) {
    const struct chimera_capability_registration registrations[] = {
        {CHIMERA_OWNER_VARIANT, "translated-code", "elf", UINT64_C(1),
         1u, 1u, fake_loader},
    };
    struct chimera_manifest_artifact optional[] = {
        artifact("custom", "variant", "v", "custom-analysis", "json", 9,
                 "verifier"),
        artifact("translated", "variant", "v", "translated-code", "elf", 1,
                 "runtime"),
    };
    struct chimera_manifest_artifact required[] = {
        artifact("custom", "variant", "v", "custom-analysis", "json", 9,
                 "runtime"),
        artifact("translated", "variant", "v", "translated-code", "elf", 1,
                 "runtime"),
    };
    assert(dispatch(registrations, 1, NULL, 0, CHIMERA_OWNER_VARIANT, "v",
                    optional, 2));
    assert(callback_log.count == 1);
    assert(!dispatch(registrations, 1, NULL, 0, CHIMERA_OWNER_VARIANT, "v",
                     required, 2));
    assert(callback_log.count == 0);
}

static void test_supported_entry_without_callback(void) {
    const struct chimera_capability_registration registrations[] = {
        {CHIMERA_OWNER_VARIANT, "translated-code", "elf", UINT64_C(1),
         1u, 1u, fake_loader},
    };
    const struct chimera_capability_registration supported[] = {
        {CHIMERA_OWNER_WORKSPACE, "runtime", "elf", UINT64_C(1),
         1u, 1u, NULL},
    };
    struct chimera_manifest_artifact artifacts[] = {
        artifact("runtime", "workspace", "root", "runtime", "elf", 1,
                 "runtime"),
        artifact("translated", "variant", "v", "translated-code", "elf", 1,
                 "runtime"),
    };
    assert(dispatch(registrations, 1, supported, 1, CHIMERA_OWNER_VARIANT, "v",
                    artifacts, 2));
    assert(callback_log.count == 1);
}

static void test_required_by_is_canonical(void) {
    const struct chimera_capability_registration registrations[] = {
        {CHIMERA_OWNER_VARIANT, "translated-code", "elf", UINT64_C(1),
         1u, 1u, fake_loader},
    };
    struct chimera_manifest_artifact malformed[] = {
        artifact("translated", "variant", "v", "translated-code", "elf", 1,
                 "runtime,invalid token"),
    };
    struct chimera_manifest_artifact unsorted[] = {
        artifact("translated", "variant", "v", "translated-code", "elf", 1,
                 "runtime,host"),
    };
    struct chimera_manifest_artifact empty[] = {
        artifact("translated", "variant", "v", "translated-code", "elf", 1,
                 ""),
    };
    struct chimera_manifest_artifact trailing_comma[] = {
        artifact("translated", "variant", "v", "translated-code", "elf", 1,
                 "runtime,"),
    };
    assert(!dispatch(registrations, 1, NULL, 0, CHIMERA_OWNER_VARIANT, "v",
                     malformed, 1));
    assert(callback_log.count == 0);
    assert(!dispatch(registrations, 1, NULL, 0, CHIMERA_OWNER_VARIANT, "v",
                     unsorted, 1));
    assert(callback_log.count == 0);
    assert(!dispatch(registrations, 1, NULL, 0, CHIMERA_OWNER_VARIANT, "v",
                     empty, 1));
    assert(callback_log.count == 0);
    assert(!dispatch(registrations, 1, NULL, 0, CHIMERA_OWNER_VARIANT, "v",
                     trailing_comma, 1));
    assert(callback_log.count == 0);
}

static void test_callback_failure_and_manifest_order(void) {
    const struct chimera_capability_registration registrations[] = {
        {CHIMERA_OWNER_VARIANT, "trace", "elf", UINT64_C(1),
         2u, SIZE_MAX, fake_loader},
    };
    struct chimera_manifest_artifact artifacts[] = {
        artifact("first", "variant", "v", "trace", "elf", 1, "runtime"),
        artifact("other-owner", "variant", "other", "trace", "elf", 1,
                 "runtime"),
        artifact("second", "variant", "v", "trace", "elf", 1, "runtime"),
    };
    assert(dispatch(registrations, 1, NULL, 0, CHIMERA_OWNER_VARIANT, "v",
                    artifacts, 3));
    assert(callback_log.count == 2);
    assert(!strcmp(callback_log.artifact_ids[0], "first"));
    assert(!strcmp(callback_log.artifact_ids[1], "second"));

    callback_log.fail_at = 1;
    {
        struct chimera_manifest manifest;
        struct chimera_capability_context context;
        memset(&manifest, 0, sizeof(manifest));
        manifest.artifacts = artifacts;
        manifest.artifact_count = 3;
        context = context_for(&manifest);
        callback_log.count = 0;
        assert(!chimera_capability_dispatch(
            registrations, 1, NULL, 0, CHIMERA_OWNER_VARIANT, "v", &context));
        assert(callback_log.count == 1);
        assert(!strcmp(callback_log.artifact_ids[0], "first"));
    }
}

int main(void) {
    test_exactly_one();
    test_zero_or_one_and_maximum_zero();
    test_registered_pair_failures_happen_before_callback();
    test_pair_first_optional_representations();
    test_unknown_optional_and_required();
    test_supported_entry_without_callback();
    test_required_by_is_canonical();
    test_callback_failure_and_manifest_order();
    return 0;
}
