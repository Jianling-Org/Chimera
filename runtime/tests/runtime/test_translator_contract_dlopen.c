#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>

#include "runtime_v1.h"

static void *open_fixture(const char *path) {
    void *handle;
    const char *error;

    dlerror();
    handle = dlopen(path, RTLD_NOW | RTLD_LOCAL);
    if (handle) return handle;
    error = dlerror();
    fprintf(stderr, "cannot load translator contract fixture %s: %s\n",
            path, error ? error : "unknown dlopen error");
    return NULL;
}

int main(int argc, char **argv) {
    volatile uint8_t *startup_tls;
    void *forward;
    void *reverse;

    if (argc != 3) {
        fprintf(stderr, "usage: %s FORWARD_FIXTURE REVERSE_FIXTURE\n", argv[0]);
        return 2;
    }

    startup_tls =
        get_simulated_cpu_state_addr_riscv64_rvv_1024_riscv64_rvv_256();
    if (!startup_tls) {
        fputs("Runtime TLS getter returned null\n", stderr);
        return 1;
    }

    forward = open_fixture(argv[1]);
    if (!forward) return 1;
    reverse = open_fixture(argv[2]);
    if (!reverse) {
        dlclose(forward);
        return 1;
    }

    dlclose(reverse);
    dlclose(forward);
    return 0;
}
