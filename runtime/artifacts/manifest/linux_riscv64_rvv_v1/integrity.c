#include "integrity.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct sha256_context {
    uint8_t data[64];
    uint32_t data_length;
    uint64_t bit_length;
    uint32_t state[8];
};

static const uint32_t constants[64] = {
    0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U,
    0x3956c25bU, 0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U,
    0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U,
    0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U, 0xc19bf174U,
    0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU,
    0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU,
    0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U,
    0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U,
    0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU, 0x53380d13U,
    0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U,
    0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U,
    0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U,
    0x19a4c116U, 0x1e376c08U, 0x2748774cU, 0x34b0bcb5U,
    0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
    0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U,
    0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U,
};

static uint32_t rotate_right(uint32_t value, uint32_t count) {
    return (value >> count) | (value << (32U - count));
}

static void transform(struct sha256_context *context) {
    uint32_t words[64], a, b, c, d, e, f, g, h;
    size_t index;
    for (index = 0; index < 16; ++index) {
        size_t offset = index * 4;
        words[index] = ((uint32_t)context->data[offset] << 24)
            | ((uint32_t)context->data[offset + 1] << 16)
            | ((uint32_t)context->data[offset + 2] << 8)
            | context->data[offset + 3];
    }
    for (index = 16; index < 64; ++index) {
        uint32_t s0 = rotate_right(words[index - 15], 7)
            ^ rotate_right(words[index - 15], 18) ^ (words[index - 15] >> 3);
        uint32_t s1 = rotate_right(words[index - 2], 17)
            ^ rotate_right(words[index - 2], 19) ^ (words[index - 2] >> 10);
        words[index] = words[index - 16] + s0 + words[index - 7] + s1;
    }
    a = context->state[0]; b = context->state[1];
    c = context->state[2]; d = context->state[3];
    e = context->state[4]; f = context->state[5];
    g = context->state[6]; h = context->state[7];
    for (index = 0; index < 64; ++index) {
        uint32_t s1 = rotate_right(e, 6) ^ rotate_right(e, 11) ^ rotate_right(e, 25);
        uint32_t choice = (e & f) ^ ((~e) & g);
        uint32_t s0 = rotate_right(a, 2) ^ rotate_right(a, 13) ^ rotate_right(a, 22);
        uint32_t majority = (a & b) ^ (a & c) ^ (b & c);
        uint32_t first = h + s1 + choice + constants[index] + words[index];
        uint32_t second = s0 + majority;
        h = g; g = f; f = e; e = d + first;
        d = c; c = b; b = a; a = first + second;
    }
    context->state[0] += a; context->state[1] += b;
    context->state[2] += c; context->state[3] += d;
    context->state[4] += e; context->state[5] += f;
    context->state[6] += g; context->state[7] += h;
}

static void initialize(struct sha256_context *context) {
    memset(context, 0, sizeof(*context));
    context->state[0] = 0x6a09e667U; context->state[1] = 0xbb67ae85U;
    context->state[2] = 0x3c6ef372U; context->state[3] = 0xa54ff53aU;
    context->state[4] = 0x510e527fU; context->state[5] = 0x9b05688cU;
    context->state[6] = 0x1f83d9abU; context->state[7] = 0x5be0cd19U;
}

static void update(struct sha256_context *context,
                   const uint8_t *data, size_t length) {
    size_t index;
    for (index = 0; index < length; ++index) {
        context->data[context->data_length++] = data[index];
        if (context->data_length == 64) {
            transform(context);
            context->bit_length += UINT64_C(512);
            context->data_length = 0;
        }
    }
}

static void finish(struct sha256_context *context, uint8_t digest[32]) {
    uint32_t index = context->data_length;
    size_t state_index;
    context->data[index++] = 0x80;
    if (index > 56) {
        while (index < 64) context->data[index++] = 0;
        transform(context); index = 0;
    }
    while (index < 56) context->data[index++] = 0;
    context->bit_length += (uint64_t)context->data_length * UINT64_C(8);
    for (index = 0; index < 8; ++index)
        context->data[63U - index] = (uint8_t)(context->bit_length >> (index * 8U));
    transform(context);
    for (state_index = 0; state_index < 8; ++state_index) {
        digest[state_index * 4] = (uint8_t)(context->state[state_index] >> 24);
        digest[state_index * 4 + 1] = (uint8_t)(context->state[state_index] >> 16);
        digest[state_index * 4 + 2] = (uint8_t)(context->state[state_index] >> 8);
        digest[state_index * 4 + 3] = (uint8_t)context->state[state_index];
    }
}

int chimera_artifact_matches(
    const char *workspace,
    const struct chimera_manifest_artifact *artifact) {
    struct sha256_context context;
    uint8_t input[4096], digest[32];
    char path[4096], actual[CHIMERA_SHA256_TEXT_SIZE];
    FILE *source;
    size_t length, index;
    int written = snprintf(path, sizeof(path), "%s/%s", workspace, artifact->path);
    if (written < 0 || (size_t)written >= sizeof(path)) return 0;
    source = fopen(path, "rb");
    if (!source) return 0;
    initialize(&context);
    while ((length = fread(input, 1, sizeof(input), source)) != 0)
        update(&context, input, length);
    if (ferror(source)) { fclose(source); return 0; }
    fclose(source); finish(&context, digest);
    for (index = 0; index < sizeof(digest); ++index)
        (void)snprintf(actual + index * 2, 3, "%02x", digest[index]);
    actual[64] = '\0';
    return strcmp(actual, artifact->sha256) == 0;
}

static int compare_properties(const void *left, const void *right) {
    const struct chimera_manifest_variant_property *const *a = left;
    const struct chimera_manifest_variant_property *const *b = right;
    int side = strcmp((*a)->side, (*b)->side);
    return side ? side : strcmp((*a)->name, (*b)->name);
}

int chimera_variant_fingerprint(
    const struct chimera_manifest *manifest,
    const struct chimera_manifest_variant *variant,
    char output[CHIMERA_SHA256_TEXT_SIZE]) {
    struct chimera_manifest_variant_property **properties = NULL;
    struct sha256_context context;
    uint8_t digest[32];
    char line[2048];
    size_t count = 0, index;
    int written;
    for (index = 0; index < manifest->variant_property_count; ++index) {
        if (!strcmp(manifest->variant_properties[index].variant_id,
                    variant->variant_id)) {
            if (count == SIZE_MAX
                || count + 1 > SIZE_MAX / sizeof(*properties)) {
                free(properties); return 0;
            }
            void *resized = realloc(properties, (count + 1) * sizeof(*properties));
            if (!resized) { free(properties); return 0; }
            properties = resized;
            properties[count++] = &manifest->variant_properties[index];
        }
    }
    if (count > 1)
        qsort(properties, count, sizeof(*properties), compare_properties);
    initialize(&context);
    written = snprintf(line, sizeof(line), "variant\t%s\t%s\n",
                       variant->variant_id, variant->module_id);
    if (written < 0 || (size_t)written >= sizeof(line)) goto fail;
    update(&context, (const uint8_t *)line, (size_t)written);
    for (index = 0; index < count; ++index) {
        const struct chimera_manifest_variant_property *property = properties[index];
        written = snprintf(
            line, sizeof(line), "variant-property\t%s\t%s\t%s\t%s\t%s\n",
            property->variant_id, property->side, property->name,
            property->value_kind, property->value);
        if (written < 0 || (size_t)written >= sizeof(line)) goto fail;
        update(&context, (const uint8_t *)line, (size_t)written);
    }
    finish(&context, digest);
    for (index = 0; index < sizeof(digest); ++index)
        (void)snprintf(output + index * 2, 3, "%02x", digest[index]);
    output[64] = '\0';
    free(properties); return 1;
fail:
    free(properties); return 0;
}
