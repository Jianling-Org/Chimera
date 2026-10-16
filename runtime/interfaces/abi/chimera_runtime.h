#ifndef CHIMERA_RUNTIME_ABI_H
#define CHIMERA_RUNTIME_ABI_H

#include <stddef.h>
#include <stdint.h>

#define CHIMERA_RUNTIME_ABI_V1 UINT64_C(1)
#define CHIMERA_SAFETY_ABI_V1 UINT64_C(1)
#define CHIMERA_OFFSET_MAP_ABI_V1 UINT64_C(1)
#define CHIMERA_MODULE_ID_SIZE 256
#define CHIMERA_RUNTIME_NAME_SIZE 256

/* Body tag of the original (untranslated) code. Non-zero body tags are
 * opaque identifiers assigned by the owning scene; the generic layers only
 * compare them for equality and never interpret their meaning. */
#define CHIMERA_CODE_ORIGINAL UINT32_C(0)

/* A translated body tag; scenes assign values >= 1. */
typedef uint32_t chimera_code_body;

struct chimera_offset_entry { uint64_t original_rva; uint64_t translated_rva; };
struct chimera_reverse_entry { uint64_t translated_rva; uint64_t original_rva; };
struct chimera_safety_entry { uint64_t original_rva; uint64_t is_safe; };

/* One translated body of a module. route_id is an opaque route identifier:
 * scenes own its derivation and must guarantee that, within one module,
 * route_id is unique and the derivation is injective over the endpoint
 * properties it encodes. Generic layers only compare route_id for equality
 * and never parse it. body_label is a scene-owned static string (never a
 * pointer into a manifest parse buffer) kept for debug printing. */
struct chimera_translation_variant {
    uint64_t route_id;
    chimera_code_body body;
    const char *body_label;
    uint64_t translated_base;
    uint64_t translated_end;
    const struct chimera_offset_entry *forward;
    size_t forward_count;
    const struct chimera_reverse_entry *reverse;
    size_t reverse_count;
};

struct chimera_module {
    char module_id[CHIMERA_MODULE_ID_SIZE];
    char runtime_name[CHIMERA_RUNTIME_NAME_SIZE];
    uint64_t original_base;
    uint64_t original_end;
    const struct chimera_safety_entry *safety;
    size_t safety_count;
    struct chimera_translation_variant *variants;
    size_t variant_count;
};

struct chimera_registry { const struct chimera_module *modules; size_t module_count; };
struct chimera_safety_decision { int is_safe; };

#endif
