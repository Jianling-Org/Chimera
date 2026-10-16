#include "chimera_debug.h"

#ifdef CHIMERA_DEBUG

#include <errno.h>
#include <unistd.h>

#define CHIMERA_DEBUG_BUFFER_SIZE 2048U
#define CHIMERA_DEBUG_RESERVE 32U

struct debug_buffer {
    char data[CHIMERA_DEBUG_BUFFER_SIZE];
    size_t length;
    size_t limit;
    int truncated;
};

static void append_character(struct debug_buffer *buffer, char value) {
    if (buffer->length >= buffer->limit) {
        buffer->truncated = 1;
        return;
    }
    buffer->data[buffer->length++] = value;
}

static void append_literal(struct debug_buffer *buffer, const char *value) {
    if (!value) return;
    while (*value) append_character(buffer, *value++);
}

static void append_quoted(struct debug_buffer *buffer, const char *value) {
    const unsigned char *cursor = (const unsigned char *)value;
    if (!value) {
        append_literal(buffer, "null");
        return;
    }
    append_character(buffer, '"');
    while (*cursor) {
        switch (*cursor) {
            case '\n': append_literal(buffer, "\\n"); break;
            case '\r': append_literal(buffer, "\\r"); break;
            case '\t': append_literal(buffer, "\\t"); break;
            case '"': append_literal(buffer, "\\\""); break;
            case '\\': append_literal(buffer, "\\\\"); break;
            default:
                append_character(buffer, *cursor < 0x20U ? '?' : (char)*cursor);
                break;
        }
        ++cursor;
    }
    append_character(buffer, '"');
}

static void append_decimal(struct debug_buffer *buffer, uint64_t value) {
    char digits[20];
    size_t count = 0;
    do {
        digits[count++] = (char)('0' + value % UINT64_C(10));
        value /= UINT64_C(10);
    } while (value && count < sizeof(digits));
    while (count) append_character(buffer, digits[--count]);
}

static void append_hex(struct debug_buffer *buffer, uint64_t value) {
    static const char digits[] = "0123456789abcdef";
    char encoded[16];
    size_t count = 0;
    append_literal(buffer, "0x");
    do {
        encoded[count++] = digits[value & UINT64_C(0xf)];
        value >>= 4;
    } while (value && count < sizeof(encoded));
    while (count) append_character(buffer, encoded[--count]);
}

void chimera_linux_debug_emit(
    const char *event,
    const struct chimera_debug_field *fields,
    size_t field_count
) {
    struct debug_buffer buffer = {
        {0},
        0,
        CHIMERA_DEBUG_BUFFER_SIZE - CHIMERA_DEBUG_RESERVE,
        0
    };
    size_t index;
    int saved_errno = errno;

    append_literal(&buffer, "[DEBUG] ");
    append_literal(&buffer, event ? event : "runtime.unknown");
    for (index = 0; fields && index < field_count; ++index) {
        append_character(&buffer, ' ');
        append_literal(&buffer, fields[index].name);
        append_character(&buffer, '=');
        if (fields[index].kind == CHIMERA_DEBUG_FIELD_TEXT) {
            append_quoted(&buffer, fields[index].value.text);
        } else if (fields[index].kind == CHIMERA_DEBUG_FIELD_U64) {
            append_decimal(&buffer, fields[index].value.number);
        } else {
            append_hex(&buffer, fields[index].value.number);
        }
    }
    if (buffer.truncated) {
        buffer.limit = CHIMERA_DEBUG_BUFFER_SIZE - 1U;
        append_literal(&buffer, " truncated=true");
    }
    buffer.limit = CHIMERA_DEBUG_BUFFER_SIZE;
    append_character(&buffer, '\n');
    if (buffer.length) {
        ssize_t ignored = write(STDOUT_FILENO, buffer.data, buffer.length);
        (void)ignored;
    }
    errno = saved_errno;
}

#endif
