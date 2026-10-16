#ifndef CHIMERA_LINUX_DEBUG_H
#define CHIMERA_LINUX_DEBUG_H

#include <stddef.h>
#include <stdint.h>

enum chimera_debug_field_kind {
    CHIMERA_DEBUG_FIELD_TEXT = 0,
    CHIMERA_DEBUG_FIELD_U64 = 1,
    CHIMERA_DEBUG_FIELD_HEX = 2
};

struct chimera_debug_field {
    const char *name;
    enum chimera_debug_field_kind kind;
    union {
        const char *text;
        uint64_t number;
    } value;
};

#define CHIMERA_DEBUG_TEXT(field_name, field_value) \
    { (field_name), CHIMERA_DEBUG_FIELD_TEXT, { .text = (field_value) } }
#define CHIMERA_DEBUG_U64(field_name, field_value) \
    { (field_name), CHIMERA_DEBUG_FIELD_U64, { .number = (field_value) } }
#define CHIMERA_DEBUG_HEX(field_name, field_value) \
    { (field_name), CHIMERA_DEBUG_FIELD_HEX, { .number = (field_value) } }

#ifdef CHIMERA_DEBUG
void chimera_linux_debug_emit(
    const char *event,
    const struct chimera_debug_field *fields,
    size_t field_count
);
#define CHIMERA_DEBUG_EVENT(event, fields, field_count) \
    chimera_linux_debug_emit((event), (fields), (field_count))
#else
#define CHIMERA_DEBUG_EVENT(event, fields, field_count) \
    ((void)sizeof(event), (void)sizeof(fields), (void)sizeof(field_count))
#endif

#endif
