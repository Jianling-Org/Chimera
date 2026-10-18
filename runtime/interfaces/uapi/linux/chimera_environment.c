#define _GNU_SOURCE

#include "chimera_environment.h"

#include <stdlib.h>

int chimera_linux_prepare_environment(void) {
    return unsetenv("LD_PRELOAD") == 0;
}
