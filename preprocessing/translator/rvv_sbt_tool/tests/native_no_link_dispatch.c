#define _GNU_SOURCE
#include <assert.h>
#include <dlfcn.h>
#include <link.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ucontext.h>
#include "chimera_runtime.h"
#include "module_registry.h"
#include "signal_handlers.h"
#include "runtime_v1.h"

static struct chimera_registry registry;
static unsigned traps, acknowledgements;
static uint64_t expected_target;
const struct chimera_registry *chimera_scene_registry(void) { return &registry; }
int chimera_test_proposal_ack(uint32_t generation, uint32_t action) {
    (void)generation; (void)action; ++acknowledgements; return 1;
}
static void trap(int sig, siginfo_t *info, void *raw) {
    (void)sig; (void)info;
    ucontext_t *context = raw;
    ucontext_t before;
    memcpy(&before, context, sizeof(before));
    chimera_code_body body;
    const struct chimera_no_link_entry *site = chimera_registry_find_no_link(
        &registry, context->uc_mcontext.__gregs[0], &body);
    assert(site);
    before.uc_mcontext.__gregs[2] += site->frame_bytes;
    chimera_linux_handle_exit_translation(raw);
    assert(context->uc_mcontext.__gregs[0] == expected_target);
    uint64_t redirected = context->uc_mcontext.__gregs[0];
    context->uc_mcontext.__gregs[0] = before.uc_mcontext.__gregs[0];
    assert(memcmp(&before, context, sizeof(before)) == 0);
    context->uc_mcontext.__gregs[0] = redirected;
    ++traps;
}
extern long native_call(void *function);
extern char native_original_return[];
__asm__(".text\n.balign 4\n.globl native_call\nnative_call:\n"
        "addi sp,sp,-16\nsd ra,0(sp)\njalr ra,0(a0)\n"
        ".globl native_original_return\nnative_original_return:\n"
        "ld ra,0(sp)\naddi sp,sp,16\nret\n");
static int range(struct dl_phdr_info *info, size_t size, void *raw) {
    (void)size;
    uint64_t *values = raw;
    if (info->dlpi_addr != values[0]) return 0;
    for (unsigned i = 0; i < info->dlpi_phnum; ++i) {
        if (info->dlpi_phdr[i].p_type != PT_LOAD) continue;
        uint64_t end = info->dlpi_addr + info->dlpi_phdr[i].p_vaddr + info->dlpi_phdr[i].p_memsz;
        if (end > values[1]) values[1] = end;
    }
    return 1;
}
int main(int argc, char **argv) {
    assert(argc == 4);
    unsigned body = (unsigned)strtoul(argv[3], NULL, 10);
    assert(body == 1 || body == 2);
    void *dso = dlopen(argv[1], RTLD_LAZY | RTLD_LOCAL);
    if (!dso) { fprintf(stderr, "%s\n", dlerror()); return 2; }
    void *function = dlsym(dso, "foo_translated");
    void *destination = dlsym(dso, "native_mapped_return");
    assert(function && destination);
    char symbol[256];
    snprintf(symbol, sizeof(symbol), "chimera_%s_no_link_entries", argv[2]);
    const struct chimera_no_link_entry *sites = dlsym(dso, symbol);
    snprintf(symbol, sizeof(symbol), "chimera_%s_no_link_count", argv[2]);
    const uint64_t *count = dlsym(dso, symbol);
    assert(sites && count && *count == 1);
    Dl_info main_info, translated_info;
    assert(dladdr(native_original_return, &main_info) && dladdr(function, &translated_info));
    uint64_t original_range[2] = {(uintptr_t)main_info.dli_fbase, 0};
    uint64_t translated_range[2] = {(uintptr_t)translated_info.dli_fbase, 0};
    dl_iterate_phdr(range, original_range);
    dl_iterate_phdr(range, translated_range);
    struct chimera_offset_entry forward = {(uintptr_t)native_original_return-original_range[0], (uintptr_t)destination-translated_range[0]};
    struct chimera_reverse_entry reverse = {forward.translated_rva, forward.original_rva};
    struct chimera_translation_variant variant = {
        .route_id = body == 1 ? ((UINT64_C(1024)<<32)|256) : ((UINT64_C(256)<<32)|1024),
        .body = body, .body_label = "native-test",
        .translated_base = translated_range[0], .translated_end = translated_range[1],
        .forward = &forward, .forward_count = 1, .reverse = &reverse, .reverse_count = 1,
        .no_link = sites, .no_link_count = *count,
    };
    struct chimera_module module = {.module_id="main", .runtime_name="native-test",
        .original_base=original_range[0], .original_end=original_range[1], .variants=&variant, .variant_count=1};
    registry = (struct chimera_registry){&module, 1};
    assert(chimera_registry_validate(&registry));
    struct sigaction action = {.sa_sigaction=trap, .sa_flags=SA_SIGINFO};
    sigemptyset(&action.sa_mask);
    assert(sigaction(SIGTRAP, &action, NULL) == 0);
    expected_target = (uintptr_t)destination;
    assert(native_call(function) == 77);
    assert(traps == 1 && acknowledgements == 0);
    return 0;
}
