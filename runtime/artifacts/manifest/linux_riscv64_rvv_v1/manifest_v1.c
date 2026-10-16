#include "manifest_v1.h"

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHIMERA_MANIFEST_MAGIC "# chimera-workspace-manifest-v2"
#define CHIMERA_PACKAGE_MODULE_DIR "scalar/"

static int copy_text(char *destination, size_t capacity, const char *source) {
    size_t length = strlen(source);
    if (!length || length >= capacity) return 0;
    memcpy(destination, source, length + 1);
    return 1;
}

static int identifier(const char *value) {
    size_t index;
    if (!value[0] || (!isalpha((unsigned char)value[0]) && value[0] != '_')) return 0;
    for (index = 1; value[index]; ++index)
        if (!isalnum((unsigned char)value[index]) && value[index] != '_'
            && value[index] != '.' && value[index] != '-') return 0;
    return 1;
}

static int sha256_text(const char *value) {
    size_t index;
    if (strlen(value) != 64) return 0;
    for (index = 0; index < 64; ++index)
        if (!isdigit((unsigned char)value[index])
            && (value[index] < 'a' || value[index] > 'f')) return 0;
    return 1;
}

static int safe_path(const char *value) {
    const char *part = value;
    if (!value[0] || value[0] == '/' || strchr(value, '\\')) return 0;
    while (*part) {
        const char *end = strchr(part, '/');
        size_t length = end ? (size_t)(end - part) : strlen(part);
        if (!length || (length == 1 && part[0] == '.')
            || (length == 2 && part[0] == '.' && part[1] == '.')) return 0;
        if (!end) break;
        part = end + 1;
    }
    return 1;
}

static int canonical_u64(const char *text, uint64_t *value, int positive) {
    char *end = NULL;
    unsigned long long parsed;
    const char *cursor;
    if (!text[0] || (text[0] == '0' && text[1])) return 0;
    for (cursor = text; *cursor; ++cursor)
        if (!isdigit((unsigned char)*cursor)) return 0;
    errno = 0; parsed = strtoull(text, &end, 10);
    if (errno || !end || *end || (positive && !parsed)) return 0;
    *value = (uint64_t)parsed; return 1;
}

static int canonical_i64(const char *text) {
    char *end = NULL;
    const char *cursor = text;
    if (!text[0] || (text[0] == '0' && text[1])
        || (text[0] == '-' && (text[1] == '0' || !text[1]))) return 0;
    if (*cursor == '-') ++cursor;
    for (; *cursor; ++cursor)
        if (!isdigit((unsigned char)*cursor)) return 0;
    errno = 0; (void)strtoll(text, &end, 10);
    return !errno && end && !*end;
}

static size_t fields(char *line, char **values, size_t capacity) {
    size_t count = 0; char *cursor = line;
    line[strcspn(line, "\r\n")] = '\0';
    while (count < capacity) {
        char *tab; values[count++] = cursor; tab = strchr(cursor, '\t');
        if (!tab) break;
        if (count == capacity) return capacity + 1;
        *tab = '\0';
        cursor = tab + 1;
    }
    return count;
}

static int grow(void **items, size_t count, size_t item_size) {
    if (!item_size || count == SIZE_MAX
        || count + 1 > SIZE_MAX / item_size) return 0;
    void *resized = realloc(*items, (count + 1) * item_size);
    if (!resized) return 0;
    *items = resized;
    return 1;
}

static int parse_module(char **f, struct chimera_manifest *manifest) {
    struct chimera_manifest_module item;
    memset(&item, 0, sizeof(item));
    if (!identifier(f[1]) || (strcmp(f[2], "main") && strcmp(f[2], "dependency"))
        || !f[3][0] || strchr(f[3], '/') || strchr(f[3], '\\')
        || !strcmp(f[3], ".") || !strcmp(f[3], "..")
        || (strcmp(f[4], "original") && strcmp(f[4], "scalar"))
        || (strcmp(f[5], "package") && strcmp(f[5], "target"))
        || !sha256_text(f[6])) return 0;
    if (!copy_text(item.module_id, sizeof(item.module_id), f[1])
        || !copy_text(item.role, sizeof(item.role), f[2])
        || !copy_text(item.runtime_name, sizeof(item.runtime_name), f[3])
        || !copy_text(item.selected_kind, sizeof(item.selected_kind), f[4])
        || !copy_text(item.delivery, sizeof(item.delivery), f[5])
        || !copy_text(item.sha256, sizeof(item.sha256), f[6])
        || !grow((void **)&manifest->modules, manifest->module_count, sizeof(item))) return 0;
    manifest->modules[manifest->module_count++] = item; return 1;
}

static int parse_variant(char **f, struct chimera_manifest *manifest) {
    struct chimera_manifest_variant item;
    memset(&item, 0, sizeof(item));
    if (!identifier(f[1]) || !identifier(f[2])
        || !copy_text(item.variant_id, sizeof(item.variant_id), f[1])
        || !copy_text(item.module_id, sizeof(item.module_id), f[2])
        || !grow((void **)&manifest->variants, manifest->variant_count, sizeof(item))) return 0;
    manifest->variants[manifest->variant_count++] = item; return 1;
}

static int parse_property(char **f, struct chimera_manifest *manifest) {
    struct chimera_manifest_variant_property item;
    uint64_t ignored;
    memset(&item, 0, sizeof(item));
    if (!identifier(f[1]) || (strcmp(f[2], "input") && strcmp(f[2], "output"))
        || !identifier(f[3])) return 0;
    if ((!strcmp(f[4], "u64") && !canonical_u64(f[5], &ignored, 0))
        || (!strcmp(f[4], "i64") && !canonical_i64(f[5]))
        || (!strcmp(f[4], "bool") && strcmp(f[5], "true") && strcmp(f[5], "false"))
        || (!strcmp(f[4], "token") && !identifier(f[5]))
        || (strcmp(f[4], "u64") && strcmp(f[4], "i64")
            && strcmp(f[4], "bool") && strcmp(f[4], "token"))) return 0;
    if (!copy_text(item.variant_id, sizeof(item.variant_id), f[1])
        || !copy_text(item.side, sizeof(item.side), f[2])
        || !copy_text(item.name, sizeof(item.name), f[3])
        || !copy_text(item.value_kind, sizeof(item.value_kind), f[4])
        || !copy_text(item.value, sizeof(item.value), f[5])
        || !grow((void **)&manifest->variant_properties,
                 manifest->variant_property_count, sizeof(item))) return 0;
    manifest->variant_properties[manifest->variant_property_count++] = item; return 1;
}

static int required_by(const char *value) {
    const char *cursor = value; char previous[CHIMERA_MANIFEST_TEXT_SIZE] = {0};
    if (!strcmp(value, "-")) return 1;
    while (*cursor) {
        const char *comma = strchr(cursor, ',');
        size_t length = comma ? (size_t)(comma - cursor) : strlen(cursor);
        char token[CHIMERA_MANIFEST_TEXT_SIZE];
        if (!length || length >= sizeof(token)) return 0;
        memcpy(token, cursor, length); token[length] = '\0';
        if (!identifier(token) || (previous[0] && strcmp(previous, token) >= 0)
            || !copy_text(previous, sizeof(previous), token)) return 0;
        if (!comma) break;
        cursor = comma + 1;
    }
    return 1;
}

static int parse_artifact(char **f, struct chimera_manifest *manifest) {
    struct chimera_manifest_artifact item;
    memset(&item, 0, sizeof(item));
    if (!identifier(f[1])
        || (strcmp(f[2], "workspace") && strcmp(f[2], "module") && strcmp(f[2], "variant"))
        || !identifier(f[3]) || !identifier(f[4]) || !identifier(f[5])
        || !canonical_u64(f[6], &item.abi, 1) || !required_by(f[7])
        || !safe_path(f[8]) || !sha256_text(f[9])) return 0;
    if (!copy_text(item.artifact_id, sizeof(item.artifact_id), f[1])
        || !copy_text(item.owner_kind, sizeof(item.owner_kind), f[2])
        || !copy_text(item.owner_id, sizeof(item.owner_id), f[3])
        || !copy_text(item.capability, sizeof(item.capability), f[4])
        || !copy_text(item.representation, sizeof(item.representation), f[5])
        || !copy_text(item.required_by, sizeof(item.required_by), f[7])
        || !copy_text(item.path, sizeof(item.path), f[8])
        || !copy_text(item.sha256, sizeof(item.sha256), f[9])
        || !grow((void **)&manifest->artifacts, manifest->artifact_count, sizeof(item))) return 0;
    manifest->artifacts[manifest->artifact_count++] = item; return 1;
}

const struct chimera_manifest_module *chimera_manifest_module_find(
    const struct chimera_manifest *manifest, const char *module_id) {
    size_t i; for (i = 0; i < manifest->module_count; ++i)
        if (!strcmp(manifest->modules[i].module_id, module_id)) return &manifest->modules[i];
    return NULL;
}

const struct chimera_manifest_variant *chimera_manifest_variant_find(
    const struct chimera_manifest *manifest, const char *variant_id) {
    size_t i; for (i = 0; i < manifest->variant_count; ++i)
        if (!strcmp(manifest->variants[i].variant_id, variant_id)) return &manifest->variants[i];
    return NULL;
}

const struct chimera_manifest_variant_property *chimera_manifest_property_find(
    const struct chimera_manifest *manifest, const char *variant_id,
    const char *side, const char *name) {
    size_t i; for (i = 0; i < manifest->variant_property_count; ++i) {
        const struct chimera_manifest_variant_property *p = &manifest->variant_properties[i];
        if (!strcmp(p->variant_id, variant_id) && !strcmp(p->side, side)
            && !strcmp(p->name, name)) return p;
    }
    return NULL;
}

const struct chimera_manifest_artifact *chimera_manifest_artifact_find(
    const struct chimera_manifest *manifest, const char *owner_kind,
    const char *owner_id, const char *capability, const char *representation) {
    size_t i; for (i = 0; i < manifest->artifact_count; ++i) {
        const struct chimera_manifest_artifact *a = &manifest->artifacts[i];
        if (!strcmp(a->owner_kind, owner_kind) && !strcmp(a->owner_id, owner_id)
            && !strcmp(a->capability, capability)
            && !strcmp(a->representation, representation)) return a;
    }
    return NULL;
}

int chimera_manifest_artifact_requires(
    const struct chimera_manifest_artifact *artifact, const char *consumer) {
    const char *cursor = artifact->required_by; size_t wanted = strlen(consumer);
    if (!strcmp(cursor, "-")) return 0;
    while (*cursor) {
        const char *comma = strchr(cursor, ',');
        size_t length = comma ? (size_t)(comma - cursor) : strlen(cursor);
        if (length == wanted && !strncmp(cursor, consumer, length)) return 1;
        if (!comma) break;
        cursor = comma + 1;
    }
    return 0;
}

static int validate(const struct chimera_manifest *manifest) {
    size_t i, j, mains = 0;
    if (!manifest->runtime_abi || !manifest->module_count
        || !identifier(manifest->target_os)
        || !identifier(manifest->target_arch)
        || !identifier(manifest->target_arch_extension)
        || !identifier(manifest->runtime_scene)) return 0;
    for (i = 0; i < manifest->module_count; ++i) {
        if (!strcmp(manifest->modules[i].role, "main")) {
            ++mains;
            /* The application is never packaged: it must run from where it is
               installed so its own path derivation keeps working. */
            if (strcmp(manifest->modules[i].delivery, "target")) return 0;
        }
        for (j = 0; j < i; ++j)
            if (!strcmp(manifest->modules[i].module_id, manifest->modules[j].module_id)
                || !strcmp(manifest->modules[i].runtime_name, manifest->modules[j].runtime_name)) return 0;
    }
    if (mains != 1) return 0;
    for (i = 0; i < manifest->variant_count; ++i) {
        if (!chimera_manifest_module_find(manifest, manifest->variants[i].module_id)) return 0;
        for (j = 0; j < i; ++j)
            if (!strcmp(manifest->variants[i].variant_id, manifest->variants[j].variant_id)) return 0;
    }
    for (i = 0; i < manifest->variant_property_count; ++i) {
        const struct chimera_manifest_variant_property *p = &manifest->variant_properties[i];
        if (!chimera_manifest_variant_find(manifest, p->variant_id)) return 0;
        for (j = 0; j < i; ++j) {
            const struct chimera_manifest_variant_property *q = &manifest->variant_properties[j];
            if (!strcmp(p->variant_id, q->variant_id) && !strcmp(p->side, q->side)
                && !strcmp(p->name, q->name)) return 0;
        }
    }
    for (i = 0; i < manifest->artifact_count; ++i) {
        const struct chimera_manifest_artifact *a = &manifest->artifacts[i];
        size_t module_index;
        if ((!strcmp(a->owner_kind, "workspace") && strcmp(a->owner_id, "root"))
            || (!strcmp(a->owner_kind, "module") && !chimera_manifest_module_find(manifest, a->owner_id))
            || (!strcmp(a->owner_kind, "variant") && !chimera_manifest_variant_find(manifest, a->owner_id))) return 0;
        if (!strncmp(a->path, CHIMERA_PACKAGE_MODULE_DIR,
                     sizeof(CHIMERA_PACKAGE_MODULE_DIR) - 1U)) {
            for (module_index = 0; module_index < manifest->module_count; ++module_index) {
                /* Only packaged modules occupy a path here; a target-resolved
                   module has no file inside the Workspace at all. */
                if (strcmp(manifest->modules[module_index].delivery, "package"))
                    continue;
                if (!strcmp(
                        a->path + (sizeof(CHIMERA_PACKAGE_MODULE_DIR) - 1U),
                        manifest->modules[module_index].runtime_name
                    )) return 0;
            }
        }
        for (j = 0; j < i; ++j)
            if (!strcmp(a->artifact_id, manifest->artifacts[j].artifact_id)
                || !strcmp(a->path, manifest->artifacts[j].path)) return 0;
    }
    return 1;
}

static int header(FILE *source, char *line, size_t capacity,
                  const char *prefix, char *output, size_t output_capacity) {
    size_t prefix_length = strlen(prefix);
    if (!fgets(line, (int)capacity, source) || strncmp(line, prefix, prefix_length)) return 0;
    line[strcspn(line, "\r\n")] = '\0';
    return copy_text(output, output_capacity, line + prefix_length);
}

int chimera_manifest_v1_read(const char *workspace, struct chimera_manifest *manifest) {
    char path[4096], line[4096], *f[10]; FILE *source = NULL; int written;
    memset(manifest, 0, sizeof(*manifest));
    written = snprintf(path, sizeof(path), "%s/artifacts/modules.tsv", workspace);
    if (written < 0 || (size_t)written >= sizeof(path)) return 0;
    source = fopen(path, "r");
    if (!source || !fgets(line, sizeof(line), source)) goto fail;
    line[strcspn(line, "\r\n")] = '\0';
    if (strcmp(line, CHIMERA_MANIFEST_MAGIC)) goto fail;
    if (!fgets(line, sizeof(line), source) || strncmp(line, "# runtime_abi=", 14)) goto fail;
    line[strcspn(line, "\r\n")] = '\0';
    if (!canonical_u64(line + 14, &manifest->runtime_abi, 1)) goto fail;
    if (!header(source, line, sizeof(line), "# target_os=", manifest->target_os, sizeof(manifest->target_os))
        || !header(source, line, sizeof(line), "# target_arch=", manifest->target_arch, sizeof(manifest->target_arch))
        || !header(source, line, sizeof(line), "# target_arch_extension=", manifest->target_arch_extension, sizeof(manifest->target_arch_extension))
        || !header(source, line, sizeof(line), "# runtime_scene=", manifest->runtime_scene, sizeof(manifest->runtime_scene))) goto fail;
    while (fgets(line, sizeof(line), source)) {
        size_t count;
        if (line[0] == '\n' || line[0] == '#') continue;
        count = fields(line, f, 10);
        if ((count == 7 && !strcmp(f[0], "module") && parse_module(f, manifest))
            || (count == 3 && !strcmp(f[0], "variant") && parse_variant(f, manifest))
            || (count == 6 && !strcmp(f[0], "variant-property") && parse_property(f, manifest))
            || (count == 10 && !strcmp(f[0], "artifact") && parse_artifact(f, manifest))) continue;
        goto fail;
    }
    fclose(source); source = NULL;
    if (validate(manifest)) return 1;
fail:
    if (source) fclose(source);
    chimera_manifest_v1_destroy(manifest); return 0;
}

void chimera_manifest_v1_destroy(struct chimera_manifest *manifest) {
    free(manifest->modules); free(manifest->variants);
    free(manifest->variant_properties); free(manifest->artifacts);
    memset(manifest, 0, sizeof(*manifest));
}
