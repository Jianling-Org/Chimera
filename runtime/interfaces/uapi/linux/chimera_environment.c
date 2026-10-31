#define _GNU_SOURCE

#include "chimera_environment.h"

#include <stdlib.h>

int chimera_linux_prepare_environment(void) {
    /* Generic bootstrap must survive ordinary exec. Legacy inject remains one-shot. */
    return getenv("CHIMERA_REGISTRY") ? 1 : unsetenv("LD_PRELOAD") == 0;
}
