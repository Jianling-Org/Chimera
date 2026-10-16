#include <errno.h>
#include <stdint.h>

#include "chimera_debug.h"

int main(void) {
    char long_text[4096];
    size_t index;
    int evaluated = 0;
    const struct chimera_debug_field fields[] = {
        CHIMERA_DEBUG_TEXT("decision", "rewrite"),
        CHIMERA_DEBUG_U64("source_vlen_bits", UINT64_C(1024)),
        CHIMERA_DEBUG_HEX("current_pc", UINT64_C(0x1234)),
    };

    errno = EDOM;
    CHIMERA_DEBUG_EVENT("runtime.signal.enter", fields, 3U);
    if (errno != EDOM) return 1;

    for (index = 0; index + 1U < sizeof(long_text); ++index) {
        long_text[index] = 'x';
    }
    long_text[sizeof(long_text) - 1U] = '\0';
    {
        const struct chimera_debug_field long_field[] = {
            CHIMERA_DEBUG_TEXT("value", long_text),
        };
        CHIMERA_DEBUG_EVENT("runtime.debug.long", long_field, 1U);
    }

#ifndef CHIMERA_DEBUG
    (void)fields;
    CHIMERA_DEBUG_EVENT("disabled", evaluated++, 0U);
    if (evaluated != 0) return 2;
#else
    (void)evaluated;
#endif
    return 0;
}
