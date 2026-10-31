#define _GNU_SOURCE

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include "scene_lifecycle.h"

__attribute__((visibility("default")))
const uint64_t chimera_runtime_abi_v1 = UINT64_C(1);

static void announce_launch_ready(void) {
    const char *launch_pid = getenv("CHIMERA_LAUNCH_PID");
    char current_pid[32];
    char notice[64];
    int length;
    size_t offset = 0;

    if (!launch_pid) return;
    length = snprintf(current_pid, sizeof(current_pid), "%ld", (long)getpid());
    if (length <= 0 || (size_t)length >= sizeof(current_pid)) return;
    if (strcmp(launch_pid, current_pid) != 0) return;
    length = snprintf(notice, sizeof(notice), "parent_thread_id=%s\n", current_pid);
    if (length <= 0 || (size_t)length >= sizeof(notice)) return;

    /* No stdio buffering: the notice must reach the terminal/pipe before
     * application code runs, and must not be duplicated after fork. */
    while (offset < (size_t)length) {
        ssize_t written = write(STDOUT_FILENO, notice + offset, (size_t)length - offset);
        if (written < 0 && errno == EINTR) continue;
        if (written <= 0) return;
        offset += (size_t)written;
    }
}

__attribute__((visibility("default")))
int chimera_runtime_initialize_v1(const char *workspace) {
    extern int chimera_bootstrap_validate_images(const char *);
    if (!chimera_bootstrap_validate_images(workspace)) return 0;
    if (!chimera_scene_initialize_runtime(workspace)) return 0;
    announce_launch_ready();
    return 1;
}

__attribute__((constructor))
static void initialize_chimera_runtime(void) {
    if (getenv("CHIMERA_VERIFY_TABLES_ONLY")) {
        _exit(chimera_scene_initialize_runtime(getenv("CHIMERA_WORKSPACE")) ? 0 : 125);
    }
    if (getenv("CHIMERA_REGISTRY")) return;
    const char *workspace = getenv("CHIMERA_WORKSPACE");
    if (chimera_scene_initialize_runtime(workspace)) {
        announce_launch_ready();
    }
}
