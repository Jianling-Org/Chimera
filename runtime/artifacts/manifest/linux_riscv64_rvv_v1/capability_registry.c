#include "capability_registry.h"

#include <ctype.h>
#include <string.h>

static const char *owner_name(enum chimera_owner_kind owner) {
    switch (owner) {
        case CHIMERA_OWNER_WORKSPACE: return "workspace";
        case CHIMERA_OWNER_MODULE: return "module";
        case CHIMERA_OWNER_VARIANT: return "variant";
    }
    return NULL;
}

static int requires_runtime(const struct chimera_manifest_artifact *artifact) {
    const char *cursor = artifact->required_by;
    const size_t wanted = sizeof("runtime") - 1u;
    if (!strcmp(cursor, "-")) return 0;
    while (*cursor) {
        const char *comma = strchr(cursor, ',');
        size_t length = comma ? (size_t)(comma - cursor) : strlen(cursor);
        if (length == wanted && !strncmp(cursor, "runtime", wanted)) return 1;
        if (!comma) break;
        cursor = comma + 1;
    }
    return 0;
}

static int identifier(const char *value) {
    size_t index;
    if (!value[0]
        || (!isalpha((unsigned char)value[0]) && value[0] != '_')) return 0;
    for (index = 1; value[index]; ++index)
        if (!isalnum((unsigned char)value[index]) && value[index] != '_'
            && value[index] != '.' && value[index] != '-') return 0;
    return 1;
}

static int valid_required_by(const char *value) {
    const char *cursor = value;
    char previous[CHIMERA_MANIFEST_TEXT_SIZE] = {0};
    if (!value[0]) return 0;
    if (!strcmp(value, "-")) return 1;
    while (*cursor) {
        const char *comma = strchr(cursor, ',');
        size_t length = comma ? (size_t)(comma - cursor) : strlen(cursor);
        char token[CHIMERA_MANIFEST_TEXT_SIZE];
        if (!length || length >= sizeof(token)) return 0;
        memcpy(token, cursor, length);
        token[length] = '\0';
        if (!identifier(token)
            || (previous[0] && strcmp(previous, token) >= 0)) return 0;
        memcpy(previous, token, length + 1u);
        if (!comma) break;
        if (!comma[1]) return 0;
        cursor = comma + 1;
    }
    return 1;
}

static int valid_registration(
    const struct chimera_capability_registration *registration,
    int loader_registration) {
    return registration && owner_name(registration->owner)
        && registration->capability && registration->capability[0]
        && registration->representation && registration->representation[0]
        && registration->minimum <= registration->maximum
        && (loader_registration
            ? registration->load != NULL
            : registration->load == NULL);
}

static int same_registration_key(
    const struct chimera_capability_registration *left,
    const struct chimera_capability_registration *right) {
    return left->owner == right->owner
        && left->abi == right->abi
        && !strcmp(left->capability, right->capability)
        && !strcmp(left->representation, right->representation);
}

static int valid_registration_tables(
    const struct chimera_capability_registration *registrations,
    size_t registration_count,
    const struct chimera_capability_registration *supported,
    size_t supported_count) {
    size_t left, right;
    if ((!registrations && registration_count) || (!supported && supported_count))
        return 0;
    for (left = 0; left < registration_count; ++left)
        if (!valid_registration(&registrations[left], 1)) return 0;
    for (left = 0; left < supported_count; ++left)
        if (!valid_registration(&supported[left], 0)) return 0;
    for (left = 0; left < registration_count; ++left) {
        for (right = left + 1; right < registration_count; ++right)
            if (same_registration_key(&registrations[left],
                                      &registrations[right])) return 0;
        for (right = 0; right < supported_count; ++right)
            if (same_registration_key(&registrations[left],
                                      &supported[right])) return 0;
    }
    for (left = 0; left < supported_count; ++left) {
        for (right = left + 1; right < supported_count; ++right)
            if (same_registration_key(&supported[left],
                                      &supported[right])) return 0;
    }
    return 1;
}

static int same_capability(
    const struct chimera_capability_registration *registration,
    const struct chimera_manifest_artifact *artifact) {
    return !strcmp(registration->capability, artifact->capability);
}

static int same_pair(
    const struct chimera_capability_registration *registration,
    const struct chimera_manifest_artifact *artifact) {
    return same_capability(registration, artifact)
        && !strcmp(registration->representation, artifact->representation);
}

static int artifact_contract(
    const struct chimera_capability_registration *registrations,
    size_t registration_count,
    const struct chimera_capability_registration *supported,
    size_t supported_count,
    const struct chimera_manifest_artifact *artifact) {
    size_t index;
    size_t pair_matches = 0;
    size_t owner_matches = 0;
    size_t contract_matches = 0;
    if (!valid_required_by(artifact->required_by)) return 0;
    for (index = 0; index < registration_count + supported_count; ++index) {
        const int loader_registration = index < registration_count;
        const struct chimera_capability_registration *registration =
            loader_registration ? &registrations[index]
                : &supported[index - registration_count];
        if (!valid_registration(registration, loader_registration)) return 0;
        if (!same_pair(registration, artifact)) continue;
        ++pair_matches;
        if (strcmp(owner_name(registration->owner), artifact->owner_kind)) continue;
        ++owner_matches;
        if (registration->abi == artifact->abi) ++contract_matches;
    }
    if (!pair_matches)
        return !requires_runtime(artifact);
    return owner_matches && contract_matches == 1u;
}

static int registration_count_for_owner(
    const struct chimera_capability_registration *registration,
    const struct chimera_manifest *manifest,
    const char *owner_id,
    size_t *count) {
    const char *kind = owner_name(registration->owner);
    size_t index;
    *count = 0;
    for (index = 0; index < manifest->artifact_count; ++index) {
        const struct chimera_manifest_artifact *artifact =
            &manifest->artifacts[index];
        if (!strcmp(artifact->owner_kind, kind)
            && !strcmp(artifact->owner_id, owner_id)
            && same_pair(registration, artifact)
            && artifact->abi == registration->abi) ++*count;
    }
    return *count >= registration->minimum && *count <= registration->maximum;
}

int chimera_capability_validate_manifest(
    const struct chimera_capability_registration *registrations,
    size_t registration_count,
    const struct chimera_capability_registration *supported,
    size_t supported_count,
    const struct chimera_manifest *manifest) {
    size_t index;
    if (!manifest || (manifest->artifact_count && !manifest->artifacts)
        || !valid_registration_tables(registrations, registration_count,
                                      supported, supported_count)) return 0;
    for (index = 0; index < manifest->artifact_count; ++index)
        if (!artifact_contract(registrations, registration_count,
                               supported, supported_count,
                               &manifest->artifacts[index])) return 0;
    return 1;
}

int chimera_capability_dispatch(
    const struct chimera_capability_registration *registrations,
    size_t registration_count,
    const struct chimera_capability_registration *supported,
    size_t supported_count,
    enum chimera_owner_kind owner,
    const char *owner_id,
    const struct chimera_capability_context *context) {
    const struct chimera_manifest *manifest;
    size_t index;
    if (!owner_name(owner) || !owner_id || !context || !context->manifest)
        return 0;
    manifest = context->manifest;
    if (!chimera_capability_validate_manifest(
            registrations, registration_count, supported, supported_count,
            manifest)) return 0;
    for (index = 0; index < registration_count; ++index) {
        size_t count;
        if (!valid_registration(&registrations[index], 1)) return 0;
        if (registrations[index].owner == owner
            && !registration_count_for_owner(&registrations[index], manifest,
                                              owner_id, &count)) return 0;
    }
    for (index = 0; index < manifest->artifact_count; ++index) {
        const struct chimera_manifest_artifact *artifact =
            &manifest->artifacts[index];
        size_t registration_index;
        if (strcmp(artifact->owner_kind, owner_name(owner))
            || strcmp(artifact->owner_id, owner_id)) continue;
        for (registration_index = 0;
             registration_index < registration_count;
             ++registration_index) {
            const struct chimera_capability_registration *registration =
                &registrations[registration_index];
            struct chimera_capability_context call_context;
            if (registration->owner != owner
                || !same_pair(registration, artifact)
                || registration->abi != artifact->abi) continue;
            call_context = *context;
            call_context.artifact = artifact;
            if (!registration->load(&call_context)) return 0;
            break;
        }
    }
    return 1;
}
